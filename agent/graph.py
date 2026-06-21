"""
agent/graph.py — Production LangGraph Agent
=============================================
This is the brain of the application. It defines a LangGraph state machine
that drives the AI reasoning loop:

    START → call_model → should_continue → tools → call_model → ... → END

WHAT IS LANGGRAPH?
  LangGraph lets you build AI agents as a directed graph of nodes.
  Each node is a Python function. Edges connect nodes. Conditional
  edges let the graph branch (e.g. "call a tool" vs "give final answer").
  Think of it as a flowchart where the AI decides which path to take.

STATE:
  Every node receives an AgentState dict and returns a dict of updates.
  LangGraph merges the updates automatically. It's a shared whiteboard
  all nodes can read and write.

SECURITY INSIDE THE LOOP (all mapped to OWASP IDs):
  • ContextIntegrityCheck — Agentic-A05 (no injected system messages)
  • AgencyLimiter         — LLM06       (max 12 steps, no runaway loops)
  • CostGuard             — Agentic-A03 (token + USD limits per run)
  • ToolCallValidator     — Agentic-A01/A07 (safe tool args, workflow scope)

PER-REQUEST LLM AND RAG OVERRIDES:
  run_agent() accepts optional llm_mode and rag_mode parameters.
  Channels (Telegram, WhatsApp, Slack) pass per-chat session settings here.
  The REST API exposes them as request body fields.
"""

import os
from typing import Annotated, Optional

from langchain_core.messages import HumanMessage, SystemMessage, AIMessage, BaseMessage
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from typing_extensions import TypedDict

from config import get_settings
from agent.tools import ALL_TOOLS, TOOL_MAP, set_retriever
from rag import build_vector_store, get_retriever
from workflows import get_workflow
from security import (
    SecurityResult,
    CostGuard,
    AgencyLimiter,
    ContextIntegrityCheck,
    PromptInjectionGuard,
    PIIRedactor,
    ToolCallValidator,
    SecurityAuditLogger,
)

cfg = get_settings()

# Maximum steps in a single agent run.
# Without this, a confused or adversarially prompted model could loop forever.
# 12 is enough for even complex multi-tool tasks.
MAX_STEPS = 12

BASE_SYSTEM_PROMPT = """
You are a production AI assistant with access to a knowledge base, external APIs,
and communication tools (email, Slack).

CORE RULES:
1. For domain-specific questions, ALWAYS call retrieve_from_knowledge_base first.
2. For weather questions, use get_weather.
3. For math, use calculator.
4. When asked to notify someone, use send_email or send_slack_message_tool.
5. Cite your sources when answering from the knowledge base.
6. If you cannot help, say so clearly — do not guess or make up information.
""".strip()


class AgentState(TypedDict):
    """
    The shared state dict that flows through every node in the graph.

    messages:        Full conversation history (user + assistant + tool messages).
                     LangGraph appends to this list automatically (add_messages).
    steps:           How many call_model iterations have run this session.
    tokens_used:     Running total of tokens consumed this run (for cost guard).
    username:        Who triggered this run — used in audit logs.
    workflow:        Which named workflow is active (controls tool access).
    guardrail_abort: Set to True by any security guard that wants to stop the run.
    llm_provider:    "local" or "cloud" — recorded for the audit trail.
    rag_mode_used:   Which RAG strategy was actually used — returned in response.
    security_events: List of audit records collected during this run.
    """

    messages: Annotated[list[BaseMessage], add_messages]
    steps: int
    tokens_used: int
    username: str
    workflow: str
    guardrail_abort: bool
    llm_provider: str
    rag_mode_used: str
    security_events: list
    initial_input: str  # original user message — used by AgencyLimiter


# ── RAG initialisation (runs once at startup) ─────────────────────────────────

_rag_initialised = False


def _initialise_rag():
    """
    Build (or load from disk) the FAISS vector store from docs/*.txt files.

    Called once during build_graph() at startup.
    On first run: reads all .txt files, splits into chunks, embeds with
    HuggingFace, saves to /app/data/faiss_index_<provider>/.
    On subsequent starts: loads from disk (fast, no re-embedding).

    BEGINNER TIP:
      If you add new documents to docs/, delete the faiss_index_* folder
      and restart to rebuild. The folder is in the Docker volume so it
      persists between container restarts.
    """
    global _rag_initialised
    if _rag_initialised:
        return
    agent_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(agent_dir)
    docs_dir = os.path.join(project_dir, "docs")
    if not os.path.exists(docs_dir):
        print("[RAG] docs/ directory not found — knowledge base tools will fail.")
        return
    vs = build_vector_store(docs_dir, provider=cfg.llm_provider)
    retriever = get_retriever(vs, k=3)
    set_retriever(retriever)
    _rag_initialised = True


# ── Nodes ─────────────────────────────────────────────────────────────────────


async def call_model(state: AgentState) -> dict:
    """
    The main reasoning node — called on every iteration of the agent loop.

    Step by step:
      1. Increment step counter
      2. Context integrity check (Agentic-A05)
      3. Step limit check (LLM06)
      4. Build the system prompt (base + workflow suffix)
      5. Filter tools to those allowed by this workflow (Agentic-A07)
      6. Route to the right LLM (local/cloud/auto)
      7. Invoke the LLM — it returns either a final answer or tool_calls
      8. Track token usage
      9. Cost guard check (Agentic-A03)
      10. Validate any tool calls before they execute (Agentic-A01)

    Returns a dict of state updates — LangGraph merges these into state.
    """
    step = state["steps"] + 1
    wf = get_workflow(state.get("workflow", "general"))
    username = state.get("username", "anonymous")
    events = list(state.get("security_events", []))
    messages = state["messages"]

    print(f"[Agent step {step}] workflow={wf.name} user={username}")

    # ── 1. Agentic-A05: Context integrity ─────────────────────────────────────
    # Detects if someone injected a fake SystemMessage into the conversation
    # history to override the agent's behaviour.
    ctx_check = ContextIntegrityCheck.validate_message_history(messages)
    events.append(
        SecurityAuditLogger.build_record(
            username, "context_integrity", ctx_check, str(messages[-1].content)
        )
    )
    if not ctx_check.passed:
        return {
            "messages": [
                AIMessage(content=f"⚠️ Security violation: {ctx_check.reason}")
            ],
            "steps": step,
            "guardrail_abort": True,
            "security_events": events,
        }

    # ── 2. LLM06: Step limit ──────────────────────────────────────────────────
    # Prevents infinite loops from confused models or adversarial inputs.
    step_check = AgencyLimiter.check_step_count(step, MAX_STEPS)
    if not step_check.passed:
        return {
            "messages": [AIMessage(content=f"⚠️ {step_check.reason}")],
            "steps": step,
            "guardrail_abort": True,
            "security_events": events,
        }

    # ── 3. Build system prompt ────────────────────────────────────────────────
    # The workflow suffix customises the agent's behaviour for the use case.
    # Example: the "support" workflow adds "ONLY use the knowledge base".
    system_content = BASE_SYSTEM_PROMPT + "\n\n" + wf.system_prompt_suffix
    if not any(isinstance(m, SystemMessage) for m in messages):
        messages = [SystemMessage(content=system_content)] + messages

    # ── 4. Filter tools to workflow's allowed set ─────────────────────────────
    # Each workflow declares which tools it may use.
    # allowed_tools=None means "all tools" (the general workflow).
    # The "support" workflow only allows retrieve_from_knowledge_base.
    if wf.allowed_tools:
        tools = [TOOL_MAP[name] for name in wf.allowed_tools if name in TOOL_MAP]
    else:
        tools = ALL_TOOLS

    # ── 5. Route to the right LLM ─────────────────────────────────────────────
    # get_llm() receives state["llm_provider"] — the effective provider for
    # THIS specific run, resolved in run_agent() without mutating global config.
    # Concurrent runs each carry their own provider in their own state dict.
    from llm_service import get_llm

    # Pass the per-run provider from state — not the global cfg.
    # This is the core of the thread-safety fix: each concurrent run
    # carries its own provider choice in its own state dict.
    llm, provider = await get_llm(
        bind_tools=tools,
        provider=state["llm_provider"],
    )

    # ── 6. Invoke the LLM ─────────────────────────────────────────────────────
    # The LLM reads the full message history and returns either:
    #   a) AIMessage with .content — the final answer, no tool use
    #   b) AIMessage with .tool_calls — the LLM wants to call one or more tools
    response: AIMessage = llm.invoke(messages)

    # ── 7. Track token usage ──────────────────────────────────────────────────
    # Some providers report usage in response.usage_metadata.
    # Others don't (e.g. Ollama). We estimate from string length as fallback.
    tokens_used = state.get("tokens_used", 0)
    if hasattr(response, "usage_metadata") and response.usage_metadata:
        tokens_used += response.usage_metadata.get("total_tokens", 0)
    else:
        # Improved estimate: count only actual text content, not Python
        # object representations. str(messages) was including class names,
        # metadata, and brackets — inflating the count by 3–5x and causing
        # the CostGuard to trigger prematurely on legitimate runs.
        content_len = sum(
            len(m.content)
            for m in messages
            if hasattr(m, "content") and isinstance(m.content, str)
        )
        content_len += len(response.content) if isinstance(response.content, str) else 0
        tokens_used += content_len // 4

    # ── 8. Agentic-A03 / LLM10: Cost guard ───────────────────────────────────
    # Abort if this run has exceeded the token or USD limit.
    # Limits are set by COST_LIMIT_TOKENS_PER_RUN and COST_LIMIT_USD_PER_RUN in .env.
    cost_check = CostGuard.check(tokens_used)
    events.append(SecurityAuditLogger.build_record(username, "cost_guard", cost_check))
    if not cost_check.passed:
        return {
            "messages": [AIMessage(content=f"⚠️ Run aborted: {cost_check.reason}")],
            "steps": step,
            "tokens_used": tokens_used,
            "guardrail_abort": True,
            "security_events": events,
        }

    # ── 9. Security checks before tool execution ─────────────────────────────
    if response.tool_calls:
        print(f"  → tool call: {response.tool_calls[0]['name']}")

        # ── LLM06: Excessive Agency guard ────────────────────────────────────
        # Verifies the user's original message explicitly requested this action.
        # Prevents the agent from sending emails or posting to Slack when the
        # user never asked for it ("Excessive Agency" — OWASP LLM06).
        # Example: user asks "draft an email" → agent must NOT auto-send it.
        planned_tools = [tc["name"] for tc in response.tool_calls]
        agency_check = AgencyLimiter.check_pre_run(
            user_input=state.get("initial_input", ""),
            planned_tools=planned_tools,
        )
        if not agency_check.passed:
            events.append(
                SecurityAuditLogger.build_record(
                    username, "excessive_agency", agency_check
                )
            )
            return {
                "messages": [AIMessage(content=f"⚠️ {agency_check.reason}")],
                "steps": step,
                "tokens_used": tokens_used,
                "guardrail_abort": True,
                "security_events": events,
            }

        # ── Agentic-A01 / A07: Tool call validation ───────────────────────────
        # Before any tool executes, verify:
        #   - The tool name is in this workflow's allowed list
        #   - The arguments don't contain command injection patterns
        #   - The tool isn't in the HIGH_RISK_TOOLS list (delete_record etc.)
        for tc in response.tool_calls:
            tool_check = ToolCallValidator.validate_tool_call(
                tool_name=tc["name"],
                tool_args=tc.get("args", {}),
                allowed_tools=wf.allowed_tools,
            )
            events.append(
                SecurityAuditLogger.build_record(
                    username, f"tool_call:{tc['name']}", tool_check
                )
            )
            if not tool_check.passed:
                return {
                    "messages": [
                        AIMessage(content=f"⚠️ Tool blocked: {tool_check.reason}")
                    ],
                    "steps": step,
                    "tokens_used": tokens_used,
                    "guardrail_abort": True,
                    "security_events": events,
                }
    else:
        print(f"  → final answer")

    return {
        "messages": [response],
        "steps": step,
        "tokens_used": tokens_used,
        "llm_provider": provider,
        "security_events": events,
    }


def should_continue(state: AgentState) -> str:
    """
    Edge function: decides what happens after call_model.

    Returns:
      "tools"  — the LLM wants to call a tool (execute it)
      END      — the LLM wrote a final answer, or a guard aborted the run
    """
    if state.get("guardrail_abort"):
        return END
    if state["steps"] >= MAX_STEPS:
        return END
    last = state["messages"][-1]
    if isinstance(last, AIMessage) and last.tool_calls:
        return "tools"
    return END


# ── Graph assembly ────────────────────────────────────────────────────────────


def build_graph():
    """
    Compile the LangGraph state machine.

    Graph structure:
      call_model → (should_continue) → tools → call_model  [loop]
                                     → END                  [done]

    ToolNode is a prebuilt LangGraph node that:
      1. Reads tool_calls from the last AIMessage
      2. Calls the corresponding @tool function
      3. Wraps the result in a ToolMessage
      4. Adds it to state["messages"]
    Then the edge from "tools" → "call_model" sends us back to reason again.
    """
    _initialise_rag()

    tool_node = ToolNode(ALL_TOOLS)

    graph = StateGraph(AgentState)
    graph.add_node("call_model", call_model)
    graph.add_node("tools", tool_node)
    graph.set_entry_point("call_model")
    graph.add_conditional_edges(
        "call_model",
        should_continue,
        {"tools": "tools", END: END},
    )
    graph.add_edge("tools", "call_model")

    return graph.compile()


# Lazy graph — built on first call to run_agent(), not at import time.
# This avoids triggering RAG index building (which needs sentence-transformers)
# just by importing the module. The graph is cached after first build.
_GRAPH = None


def _get_graph():
    global _GRAPH
    if _GRAPH is None:
        _GRAPH = build_graph()
    return _GRAPH


# Keep GRAPH as a convenience alias for external code that references it
class _LazyGraph:
    """Proxy that builds the graph on first access."""

    def __getattr__(self, name):
        return getattr(_get_graph(), name)

    async def ainvoke(self, *args, **kwargs):
        return await _get_graph().ainvoke(*args, **kwargs)


GRAPH = _LazyGraph()


# ── Public API ────────────────────────────────────────────────────────────────


async def run_agent(
    user_input: str,
    username: str = "anonymous",
    workflow: str = "general",
    rag_mode: Optional[str] = None,
    llm_mode: Optional[str] = None,
) -> tuple[str, int, dict]:
    """
    Run the production agent and return (answer, tokens_used, metadata).

    This is the single entry point called by:
      - api/routes.py   (REST API — JWT users)
      - api/routes.py   (/n8n/trigger — n8n workflows)
      - integrations/telegram_integration.py
      - integrations/whatsapp_integration.py
      - integrations/slack_integration.py

    Args:
        user_input: The user's question or message.
        username:   Who is asking — stored in audit log.
                    Channel prefix convention:
                      "tg_<username>"    for Telegram
                      "wa_<number>"      for WhatsApp
                      "slack_<username>" for Slack
                      "n8n_<source>"     for n8n
        workflow:   Named workflow to use (controls tools + system prompt).
        rag_mode:   Override RAG mode for this call ("standard"|"agentic"|"auto"|None).
        llm_mode:   Override LLM provider for this call ("local"|"cloud"|"auto"|None).

    Returns:
        (answer, tokens_used, metadata)
        metadata contains: llm_provider, rag_mode_used, security_events
    """
    # Thread-safe: resolve effective modes without mutating global cfg
    effective_llm = llm_mode or cfg.llm_provider
    effective_rag = rag_mode or cfg.rag_mode

    # ── Bug 4 fix: Centralized injection guard ────────────────────────────────
    # PromptInjectionGuard runs here in run_agent() — the single entry point
    # called by ALL channels (Telegram, WhatsApp, Slack, n8n, REST API).
    # Previously it was only called in channel-specific code, so a new channel
    # or direct API call could bypass it. Now it is guaranteed for every run.
    # We skip strict injection checks for the security_review workflow because
    # users are expected to submit potentially malicious code for analysis.
    inj_check = (
        PromptInjectionGuard.check(user_input)
        if workflow != "security_review"
        else SecurityResult(passed=True)
    )
    if not inj_check.passed:
        inj_event = SecurityAuditLogger.build_record(
            username, "input_injection", inj_check, user_input
        )
        return (
            f"⚠️ Security blocked: {inj_check.reason}",
            0,
            {
                "llm_provider": effective_llm,
                "rag_mode_used": effective_rag,
                "security_events": [inj_event],
            },
        )

    initial_state: AgentState = {
        "messages": [HumanMessage(content=user_input)],
        "steps": 0,
        "tokens_used": 0,
        "username": username,
        "workflow": workflow,
        "guardrail_abort": False,
        "llm_provider": effective_llm,
        "rag_mode_used": effective_rag,
        "initial_input": user_input,  # stored for AgencyLimiter.check_pre_run
        "security_events": [],
    }

    final_state = await GRAPH.ainvoke(initial_state)

    # Extract the final answer from the last message
    last = final_state["messages"][-1]
    answer = (
        last.content
        if isinstance(last, AIMessage) and last.content
        else "The agent could not produce a final answer."
    )

    # ── Bug Fix: Centralised PII Redaction ────────────────────────────────────
    # By running this here, we protect all channels (API, WhatsApp, Slack, etc)
    # without needing to duplicate logic in every route/integration file.
    pii_check = PIIRedactor.check(answer)
    if not pii_check.passed:
        pii_event = SecurityAuditLogger.build_record(
            username, "output_pii", pii_check, answer
        )
        final_state["security_events"].append(pii_event)
        answer = "⚠️ Response blocked by safety filter (potential PII detected)."

    # Execute post-run workflow action (e.g. auto-post to Slack)
    wf = get_workflow(workflow)
    if wf.post_run:
        try:
            await wf.post_run(user_input, answer, username)
        except Exception as e:
            print(f"[Workflow] post_run failed (non-fatal): {e}")

    metadata = {
        "llm_provider": final_state.get("llm_provider", "unknown"),
        "rag_mode_used": final_state.get("rag_mode_used", "unknown"),
        "security_events": final_state.get("security_events", []),
    }

    return answer, final_state.get("tokens_used", 0), metadata
