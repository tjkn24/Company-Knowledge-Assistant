"""
rag/rag_service.py — Unified RAG Service
==========================================
RAG = Retrieval-Augmented Generation.

Instead of answering from training data alone, the agent first searches
your documents (in docs/*.txt) for relevant passages, then uses those
passages as context when generating the answer.

THREE MODES:

  STANDARD (fast, predictable):
    1. Embed the user's query
    2. FAISS finds the top-3 most similar document chunks
    3. Stuff chunks + query into a prompt
    4. LLM generates answer in one call
    Best for: short FAQs, simple lookups, when speed matters.

  AGENTIC (smarter, flexible):
    The LLM gets a retrieve_knowledge() tool and runs a ReAct loop:
    1. LLM decides what to search for and calls retrieve_knowledge("phrase")
    2. LLM reads the results
    3. If not satisfied, calls retrieve_knowledge() again with a different phrase
    4. Writes the final answer when it has enough information
    Best for: complex multi-part questions, synthesis across documents.

  AUTO (default):
    Counts words in the query. Short → standard. Long or multi-part → agentic.

VECTOR SEARCH EXPLAINED:
  Traditional search matches keywords. Vector search matches MEANING.
  "annual leave" and "holiday entitlement" are far apart in keywords
  but close in vector space — they mean the same thing.

  Process:
  1. Each document chunk is converted to a 384-number vector by a
     sentence-transformer model (HuggingFace all-MiniLM-L6-v2).
  2. At query time, the query is also converted to a vector.
  3. FAISS finds the 3 chunks whose vectors are closest to the query vector.
  4. These chunks are the "most relevant" passages — regardless of exact wording.

INDEX CACHING:
  Building the index (embedding all chunks) takes 10-60 seconds the first time.
  The index is saved to /app/data/faiss_index_<provider>/.
  Subsequent starts load from disk — near-instant.
  To rebuild: delete the faiss_index_* folder and restart the server.
"""

import os
import glob
from typing import Optional, Literal

from langchain_community.vectorstores import FAISS
from langchain_core.vectorstores import VectorStoreRetriever
from langchain_core.documents import Document
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from langchain_core.tools import tool
from langchain_text_splitters import RecursiveCharacterTextSplitter

from config import get_settings

cfg = get_settings()

CHUNK_SIZE = 600  # characters per chunk — balance between context and precision
CHUNK_OVERLAP = 100  # overlap between chunks — prevents cutting sentences in half
INDEX_DIR = "faiss_index"


# ── Embeddings ────────────────────────────────────────────────────────────────


def _get_embeddings(provider: str = "auto"):
    """
    Return the embedding model appropriate for the provider setting.

    HuggingFace (local mode):
      - Model: all-MiniLM-L6-v2 — 384-dimensional embeddings
      - No API key needed, runs entirely on your machine
      - ~100MB download on first use, cached in ~/.cache/huggingface/

    OpenAI (cloud mode):
      - Model: text-embedding-ada-002 — 1536-dimensional embeddings
      - Requires OPENAI_API_KEY
      - Better quality but costs a small amount per document embedded

    The index is keyed by provider (faiss_index_local vs faiss_index_cloud)
    because the vector dimensions differ — you can't mix them.
    """
    use_openai = provider in ("cloud",) and cfg.openai_api_key
    if use_openai:
        from langchain_openai import OpenAIEmbeddings

        print("[RAG] Using OpenAI embeddings")
        return OpenAIEmbeddings(api_key=cfg.openai_api_key)
    else:
        from langchain_huggingface import HuggingFaceEmbeddings

        print("[RAG] Using HuggingFace embeddings (all-MiniLM-L6-v2) — free, local")
        return HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")


# ── Document loading ──────────────────────────────────────────────────────────


def load_documents(docs_dir: str) -> list[Document]:
    """
    Load all .txt files from the docs/ directory.

    Each file becomes a LangChain Document with:
      page_content: the full text of the file
      metadata:     {"source": "filename.txt"} — used for citations
    """
    txt_files = glob.glob(os.path.join(docs_dir, "*.txt"))
    if not txt_files:
        print(
            f"[RAG] Warning: No .txt files found in '{docs_dir}'. "
            "Knowledge base retrieval will be empty."
        )
        return []
    documents = []
    for fp in sorted(txt_files):
        with open(fp, "r", encoding="utf-8") as f:
            text = f.read()
        documents.append(
            Document(
                page_content=text,
                metadata={"source": os.path.basename(fp)},
            )
        )
        print(f"  [RAG] Loaded: {os.path.basename(fp)} ({len(text):,} chars)")
    return documents


# ── Vector store ──────────────────────────────────────────────────────────────


def build_vector_store(docs_dir: str, provider: str = "auto") -> FAISS:
    """
    Build or load the FAISS vector store.

    FIRST RUN: reads docs, splits into chunks, embeds all chunks, saves index.
    LATER RUNS: loads saved index from disk (fast).

    The index path is keyed by provider so local and cloud embeddings
    don't overwrite each other.
    """
    embeddings = _get_embeddings(provider)
    index_path = f"{INDEX_DIR}_{provider}"

    # Use /app/data/ in Docker, local path otherwise
    data_dir = "/app/data" if os.path.exists("/app/data") else "."
    full_index_path = os.path.join(data_dir, index_path)

    if os.path.exists(full_index_path):
        print(f"[RAG] Loading existing index from {full_index_path}/")
        return FAISS.load_local(
            full_index_path,
            embeddings,
            allow_dangerous_deserialization=True,  # safe — we wrote this index ourselves
        )

    print("[RAG] Building vector store (first run — embedding all documents)...")
    documents = load_documents(docs_dir)

    # Split documents into overlapping chunks.
    # RecursiveCharacterTextSplitter tries to split at paragraph → sentence → word
    # boundaries before falling back to character splits.
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        add_start_index=True,
    )
    chunks = splitter.split_documents(documents)

    if not chunks:
        print("  [RAG] No documents to index. Creating empty vector store.")
        # Create a dummy document so FAISS doesn't crash on empty input
        chunks = [
            Document(
                page_content="Knowledge base is empty.", metadata={"source": "system"}
            )
        ]

    # Build FAISS index from the chunks + embeddings
    vs = FAISS.from_documents(chunks, embeddings)
    vs.save_local(full_index_path)
    print(f"  [RAG] Index saved to {full_index_path}/ ({len(chunks)} chunks)\n")
    return vs


def get_retriever(vector_store: FAISS, k: int = 3) -> VectorStoreRetriever:
    """
    Return a retriever that fetches the top-k most relevant chunks.
    k=3 is a good default — enough context without flooding the LLM prompt.
    """
    return vector_store.as_retriever(search_kwargs={"k": k})


# ── Standard RAG ──────────────────────────────────────────────────────────────


async def standard_rag_answer(
    query: str,
    retriever: VectorStoreRetriever,
) -> str:
    """
    Standard RAG: one search call → one LLM call.

    The user's query is used directly as the search phrase.
    Simple, fast, and predictable — the same query always returns the same answer.

    LIMITATION: If the user asks a vague question, the search phrase may not
    match the best documents. Agentic RAG solves this by letting the LLM
    choose its own search phrases.
    """
    print(f"[RAG:standard] Searching for: {query[:60]}...")
    docs = retriever.invoke(query)

    if not docs:
        return "No relevant information found in the knowledge base."

    # Build context string from retrieved chunks, with source citations
    context = "\n\n".join(
        f"[Source: {d.metadata.get('source', 'unknown')}]\n{d.page_content}"
        for d in docs
    )

    prompt = (
        "You are a helpful assistant. Answer the question using ONLY the context below.\n"
        "If the context does not contain the answer, say: 'I don't have that information.'\n"
        "Always cite which source(s) you used.\n\n"
        f"Context:\n{context}\n\n"
        f"Question: {query}\n\nAnswer:"
    )

    # Standard RAG does not use tool-binding — one plain LLM invocation
    from llm_service import get_llm

    plain_llm, _ = await get_llm()
    response = plain_llm.invoke([HumanMessage(content=prompt)])
    return response.content


# ── Agentic RAG ───────────────────────────────────────────────────────────────


def make_rag_tool(retriever: VectorStoreRetriever):
    """
    Create a LangChain @tool wrapping the FAISS retriever.

    In agentic mode, the LLM receives this as a callable tool.
    The LLM writes its own search phrase, calls this tool, reads
    the results, and decides whether to search again with a different phrase.

    This is the key difference from standard RAG:
      Standard: search phrase = user's exact question
      Agentic:  search phrase = whatever the LLM decides is best
    """

    @tool
    def retrieve_from_knowledge_base(search_phrase: str) -> str:
        """
        Search the internal knowledge base for information relevant to
        the given search phrase. Returns the most relevant text chunks.
        Call this multiple times with different phrases if the first result
        is insufficient.

        Args:
            search_phrase: A focused keyword phrase. Examples:
                           "annual leave policy", "product pricing 2025"
        """
        print(f"  [AgenticRAG] retrieve_from_knowledge_base('{search_phrase}')")
        docs = retriever.invoke(search_phrase)
        if not docs:
            return "No relevant chunks found. Try a different search phrase."
        parts = [
            f"--- Chunk {i} (source: {d.metadata.get('source', 'unknown')}) ---\n"
            f"{d.page_content.strip()}"
            for i, d in enumerate(docs, 1)
        ]
        return "\n\n".join(parts)

    return retrieve_from_knowledge_base


async def agentic_rag_answer(
    query: str,
    retriever: VectorStoreRetriever,
    max_steps: int = 6,
) -> str:
    """
    Agentic RAG: the LLM drives the retrieval loop.

    Builds a mini LangGraph inside the main agent:
      llm → (has tool calls?) → tools → llm → ... → final answer

    The LLM receives the retrieve_knowledge tool and reasons:
      "I need to find information about X → call retrieve_knowledge('X')
       → read results → I also need Y → call retrieve_knowledge('Y')
       → read results → I have enough → write the answer"

    max_steps prevents the loop from running forever (cost guard).
    """
    from langgraph.graph import StateGraph, END
    from langgraph.prebuilt import ToolNode
    from langgraph.graph.message import add_messages
    from typing import Annotated
    from typing_extensions import TypedDict

    rag_tool = make_rag_tool(retriever)

    from llm_service import get_llm

    llm, provider = await get_llm(bind_tools=[rag_tool])
    print(f"[RAG:agentic] Running with {provider} LLM, max {max_steps} steps")

    class RagState(TypedDict):
        messages: Annotated[list, add_messages]
        steps: int

    system = SystemMessage(
        content=(
            "You are a precise research assistant. Your only tool is retrieve_from_knowledge_base. "
            "Use it to find information relevant to the user's question. "
            "You may call it multiple times with different search phrases if needed. "
            "Once you have enough information, write a final answer and STOP. "
            "Always cite the source of each fact (e.g. 'source: hr_policy.txt')."
        )
    )

    def rag_llm_node(state: RagState) -> dict:
        step = state["steps"] + 1
        print(f"  [AgenticRAG step {step}]")
        msgs = state["messages"]
        # Add system message if not already present
        if not any(isinstance(m, SystemMessage) for m in msgs):
            msgs = [system] + msgs
        response = llm.invoke(msgs)
        return {"messages": [response], "steps": step}

    def rag_should_continue(state: RagState) -> str:
        if state["steps"] >= max_steps:
            return END
        last = state["messages"][-1]
        if isinstance(last, AIMessage) and last.tool_calls:
            return "tools"
        return END

    graph = StateGraph(RagState)
    graph.add_node("llm", rag_llm_node)
    graph.add_node("tools", ToolNode([rag_tool]))
    graph.set_entry_point("llm")
    graph.add_conditional_edges(
        "llm", rag_should_continue, {"tools": "tools", END: END}
    )
    graph.add_edge("tools", "llm")
    rag_graph = graph.compile()

    result = rag_graph.invoke(
        {
            "messages": [HumanMessage(content=query)],
            "steps": 0,
        }
    )

    last = result["messages"][-1]
    if isinstance(last, AIMessage) and last.content:
        return last.content
    return "Agentic RAG could not produce a final answer."


# ── Auto routing ──────────────────────────────────────────────────────────────


def _decide_rag_mode(query: str) -> Literal["standard", "agentic"]:
    """
    Decide standard vs agentic RAG based on query characteristics.

    Heuristics (in order):
      1. Multiple question marks → multiple sub-questions → agentic
      2. Contains comparison keywords → multi-concept synthesis → agentic
      3. Word count > threshold → complex question → agentic
      4. Otherwise → standard (fast)

    The threshold is configurable: RAG_AUTO_THRESHOLD_WORDS in .env (default 15).
    Set lower (e.g. 10) to use agentic RAG more aggressively.
    Set higher (e.g. 25) to prefer standard RAG for cost savings.
    """
    word_count = len(query.split())
    multi_q = query.count("?") > 1
    multi_concept = any(
        w in query.lower()
        for w in [
            "compare",
            "difference",
            "vs",
            "versus",
            "and",
            "both",
            "all",
            "summarise",
            "summarize",
        ]
    )

    if multi_q or multi_concept or word_count > cfg.rag_auto_threshold_words:
        chosen = "agentic"
    else:
        chosen = "standard"

    print(
        f"[RAG:auto] {word_count} words, multi_q={multi_q}, "
        f"multi_concept={multi_concept} → {chosen}"
    )
    return chosen


# ── Public entry point ────────────────────────────────────────────────────────


async def retrieve_and_answer(
    query: str,
    retriever: VectorStoreRetriever,
    mode: Optional[str] = None,
) -> tuple[str, str]:
    """
    Main entry point for all RAG calls.

    Args:
        query:     The user's question.
        retriever: FAISS retriever (from get_retriever()).
        mode:      "standard" | "agentic" | "auto" | None.
                   None means use cfg.rag_mode (from .env).

    Returns:
        (answer_text, mode_used) — mode_used is in the API response
        so callers know which strategy was actually used.
    """
    effective_mode = mode or cfg.rag_mode

    if effective_mode == "auto":
        effective_mode = _decide_rag_mode(query)

    print(f"[RAG] Mode: {effective_mode}")

    if effective_mode == "agentic":
        answer = await agentic_rag_answer(query, retriever)
    else:
        answer = await standard_rag_answer(query, retriever)

    return answer, effective_mode
