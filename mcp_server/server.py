"""
mcp_server/server.py — MCP Server for the Agent Platform
===========================================================
Exposes a curated set of the platform's tools over the Model Context
Protocol (MCP), so any MCP client (Claude Desktop, Claude Code, n8n's
MCP node, another agent, etc.) can call them directly.

WHY A SEPARATE SERVICE (not just stdio on your laptop)?
  The previous attempt at this ran the MCP server as a local stdio
  process on the Mac Mini. That coupled the server's lifetime to a
  terminal window / IDE process, made the Ollama dependency invisible
  until a tool call failed deep inside a client, and meant "restart
  everything" any time the laptop slept or the process was killed.

  This version runs the MCP server as its own Dockerized service on
  the same network as `ollama`, `agent`, and the other containers —
  the same pattern already used for the rest of the platform. It is
  reachable over streamable-HTTP at a stable URL
  (http://localhost:8800/mcp by default), so it survives client
  restarts and is debuggable with `docker compose logs mcp_server`
  exactly like every other service.

  Local stdio is still supported (MCP_TRANSPORT=stdio) for Claude
  Desktop integration — see mcp_server/README.md — but it is no longer
  the only way to run this.

TOOLS EXPOSED (deliberately split by dependency, see README "Why split"):
  No-LLM, no-Ollama-dependency (fast, fail independently of the model):
    - search_knowledge_base   : direct FAISS similarity search
    - calculator              : safe arithmetic
    - get_weather             : Open-Meteo lookup
    - review_code_security    : static OWASP scan

  Needs an LLM backend (Ollama or OpenAI) — the part that broke before:
    - ask_agent                : full LangGraph agent run (reasoning + tools)

  Side-effecting (use with care; these actually send things):
    - send_email                : SMTP send

Each tool returns plain text/Markdown — easy for any MCP client to render.
"""

import os
import sys
import asyncio

from mcp.server.fastmcp import FastMCP

from config import get_settings

cfg = get_settings()

mcp = FastMCP(
    name="company-knowledge-assistant",
    instructions=(
        "Tools for the Company Knowledge Assistant platform: search the "
        "internal knowledge base, run safe calculations, check weather, "
        "run a static OWASP security review on code, send email, and "
        "(if an LLM backend is configured) ask the full LangGraph agent "
        "a question that may require multi-step tool use."
    ),
    host=cfg.mcp_host,
    port=cfg.mcp_port,
    stateless_http=True,
)


# ── Knowledge base retriever (independent of the LangGraph agent) ────────────
# We do NOT reuse agent.tools.retrieve_from_knowledge_base here because that
# tool expects LangGraph's InjectedState (rag_mode_used etc.), which only
# exists inside a running graph. MCP tool calls have no such state, so we
# build/own a plain retriever instead. This also means knowledge-base search
# works even if the LangGraph/Ollama side is broken.
_retriever = None
_retriever_lock = asyncio.Lock()


async def _get_kb_retriever():
    global _retriever
    if _retriever is not None:
        return _retriever
    async with _retriever_lock:
        if _retriever is not None:
            return _retriever
        from rag import build_vector_store, get_retriever

        project_dir = os.path.dirname(os.path.abspath(__file__))
        project_dir = os.path.dirname(project_dir)  # parent of mcp_server/
        docs_dir = os.path.join(project_dir, "docs")
        if not os.path.exists(docs_dir):
            raise RuntimeError(f"docs/ directory not found at {docs_dir}")

        # build_vector_store does blocking embedding work — run off the event loop.
        vs = await asyncio.to_thread(build_vector_store, docs_dir, cfg.llm_provider)
        _retriever = get_retriever(vs, k=3)
        return _retriever


@mcp.tool()
async def search_knowledge_base(query: str) -> str:
    """
    Search the internal knowledge base (docs/*.txt) with vector similarity
    search and return the most relevant passages. Does not call an LLM —
    pure retrieval, so it works even if Ollama/OpenAI are unavailable.

    Args:
        query: A short, focused search phrase, e.g. "annual leave entitlement".
    """
    retriever = await _get_kb_retriever()
    docs = await asyncio.to_thread(retriever.invoke, query)
    if not docs:
        return "No relevant documents found. Try rephrasing the query."
    parts = []
    for i, doc in enumerate(docs, 1):
        src = doc.metadata.get("source", "unknown")
        parts.append(f"--- Chunk {i} (source: {src}) ---\n{doc.page_content.strip()}")
    return "\n\n".join(parts)


@mcp.tool()
async def calculator(expression: str) -> str:
    """
    Evaluate a safe arithmetic expression (+ - * / and parentheses only).
    No LLM involved.

    Args:
        expression: e.g. "2500 * 0.15" or "(100 + 200) / 3"
    """
    from agent.tools import calculator as _calculator_tool

    return await _calculator_tool.ainvoke({"expression": expression})


@mcp.tool()
async def get_weather(city: str) -> str:
    """
    Fetch current weather for a city via Open-Meteo (no API key required).
    No LLM involved.

    Args:
        city: City name in English, e.g. "Jakarta", "Singapore".
    """
    from agent.tools import get_weather as _weather_tool

    return await _weather_tool.ainvoke({"city": city})


@mcp.tool()
async def review_code_security(code: str, filename: str = "submitted_code") -> str:
    """
    Run a static OWASP-aligned security review (LLM Top 10, Agentic AI Top 10,
    API Security Top 10) on the given source/config text. No LLM involved —
    pure pattern-based static analysis, so it's fast and deterministic.

    Args:
        code:     Source code or config text to review.
        filename: Name to show in the report header.
    """
    from agent.tools import review_code_security as _review_tool

    return await _review_tool.ainvoke({"code": code, "filename": filename})


@mcp.tool()
async def send_email(to: str, subject: str, body: str) -> str:
    """
    Send an email via the configured SMTP account. This actually sends mail —
    only call it when explicitly asked to notify someone.

    Args:
        to:      Recipient email address.
        subject: Email subject line.
        body:    Plain text email body.
    """
    from agent.tools import send_email as _email_tool

    return await _email_tool.ainvoke({"to": to, "subject": subject, "body": body})


@mcp.tool()
async def ask_agent(
    question: str,
    workflow: str = "general",
    llm_mode: str = "",
) -> str:
    """
    Run the full LangGraph agent: multi-step reasoning, tool selection,
    OWASP/Agentic security guardrails, and RAG. Use this for anything that
    needs judgement or might require several tool calls in sequence.

    REQUIRES a working LLM backend (Ollama reachable at OLLAMA_BASE_URL with
    OLLAMA_MODEL pulled, or OPENAI_API_KEY set). If this tool errors, the
    other tools in this server are unaffected — check `docker compose logs
    ollama` and confirm the model in .env (OLLAMA_MODEL) has been pulled with
    `docker compose exec ollama ollama pull <model>`.

    Args:
        question: The question or instruction for the agent.
        workflow: Named workflow controlling system prompt + allowed tools
                  (e.g. "general", "support", "security_review"). Default "general".
        llm_mode: Override provider for this call: "local" | "cloud" | "auto".
                  Leave empty to use the server default.
    """
    from agent.graph import run_agent

    answer, tokens_used, metadata = await run_agent(
        user_input=question,
        username="mcp_client",
        workflow=workflow,
        llm_mode=llm_mode or None,
    )
    footer = (
        f"\n\n_(llm_provider={metadata.get('llm_provider')}, "
        f"rag_mode={metadata.get('rag_mode_used')}, tokens={tokens_used})_"
    )
    return answer + footer


# ── HTTP transport: optional shared-secret auth + /health for Docker ─────────


def _build_http_app():
    """
    Wrap FastMCP's Starlette app with:
      - a simple bearer-token check (MCP_API_KEY), if set
      - a /health endpoint for the Docker healthcheck

    IMPORTANT: FastMCP's streamable-HTTP transport needs its session
    manager's task group running, which it normally starts via its own
    app's `lifespan`. Mounting the sub-app under another Starlette app
    does NOT propagate that lifespan automatically, so we build our own
    top-level lifespan that enters `mcp.session_manager.run()` directly —
    otherwise every request fails with "Task group is not initialized."
    """
    from contextlib import asynccontextmanager

    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, PlainTextResponse
    from starlette.routing import Route, Mount

    api_key = cfg.mcp_api_key

    class ApiKeyMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if not api_key:
                return await call_next(request)
            if request.url.path == "/health":
                return await call_next(request)
            header = request.headers.get("authorization", "")
            expected = f"Bearer {api_key}"
            if header != expected:
                return JSONResponse(
                    {"error": "unauthorized — missing/invalid Authorization header"},
                    status_code=401,
                )
            return await call_next(request)

    async def health(_request):
        return PlainTextResponse("ok")

    mcp_asgi = mcp.streamable_http_app()  # also lazily creates mcp.session_manager

    @asynccontextmanager
    async def lifespan(_app):
        async with mcp.session_manager.run():
            yield

    app = Starlette(
        routes=[
            Route("/health", health),
            Mount("/", app=mcp_asgi),
        ],
        middleware=[Middleware(ApiKeyMiddleware)],
        lifespan=lifespan,
    )
    return app


def main():
    transport = cfg.mcp_transport

    if transport == "stdio":
        # For Claude Desktop / local MCP clients launched as a subprocess.
        # No network port, no auth — the client owns the process lifetime.
        print("[MCP] Starting in stdio mode.", file=sys.stderr)
        mcp.run(transport="stdio")
        return

    # streamable-http: run as a long-lived network service (Docker-friendly).
    import uvicorn

    app = _build_http_app()
    print(
        f"[MCP] Starting streamable-http on {cfg.mcp_host}:{cfg.mcp_port} "
        f"(auth={'on' if cfg.mcp_api_key else 'off'})",
        file=sys.stderr,
    )
    uvicorn.run(app, host=cfg.mcp_host, port=cfg.mcp_port, log_level="info")


if __name__ == "__main__":
    main()
