"""
llm_service.py — LLM Provider Router
======================================
Routes to the right LLM backend (Ollama or OpenAI) based on the
requested provider mode.

THREAD-SAFETY FIX (Gemini was correct):
  Previously get_llm() read cfg.llm_provider — a global singleton that
  graph.py was mutating per-request. Under concurrent load this caused
  race conditions where User A's "cloud" setting could bleed into User B's
  request that expected "local".

  Fix: get_llm() now accepts an explicit `provider` parameter. The caller
  (call_model in graph.py) reads state["llm_provider"] which is set once
  per run from the effective_llm value computed in run_agent() — immutable
  for the lifetime of that run.

  cfg.llm_provider is now used ONLY as the server-level default when no
  per-request override is given. It is never mutated at runtime.

HOW IT WORKS:
  "local"  → ChatOllama pointing at the Ollama server
  "cloud"  → ChatOpenAI using your OpenAI API key
  "auto"   → Pings Ollama; uses it if responsive, falls back to OpenAI
"""

import httpx
from typing import Optional

from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from langchain_core.language_models import BaseChatModel

from config import get_settings

cfg = get_settings()


async def _is_ollama_available() -> bool:
    """
    Ping the Ollama server to check if it is running.
    Used by 'auto' routing to decide the backend at request time.
    Fast: typically <10ms on localhost.
    """
    try:
        async with httpx.AsyncClient(timeout=cfg.ollama_timeout_seconds) as client:
            resp = await client.get(f"{cfg.ollama_base_url}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False


def get_cloud_llm(bind_tools: Optional[list] = None) -> BaseChatModel:
    """Return a ChatOpenAI instance, optionally with tools bound."""
    if not cfg.openai_api_key:
        raise EnvironmentError(
            "OPENAI_API_KEY is not set. "
            "Add it to .env or set LLM_PROVIDER=local."
        )
    llm = ChatOpenAI(
        model=cfg.openai_model,
        api_key=cfg.openai_api_key,
        temperature=0,
    )
    return llm.bind_tools(bind_tools) if bind_tools else llm


def get_local_llm(bind_tools: Optional[list] = None) -> BaseChatModel:
    """Return a ChatOllama instance. Run: ollama pull mistral first."""
    llm = ChatOllama(
        model=cfg.ollama_model,
        base_url=cfg.ollama_base_url,
        temperature=0,
    )
    return llm.bind_tools(bind_tools) if bind_tools else llm


async def get_llm(
    bind_tools: Optional[list] = None,
    provider:   Optional[str]  = None,
) -> tuple[BaseChatModel, str]:
    """
    Return (llm_instance, resolved_provider_name).

    Args:
        bind_tools: List of @tool functions to bind to the LLM.
                    The LLM will know it can call these tools.
        provider:   "local" | "cloud" | "auto" | None.
                    If None, falls back to cfg.llm_provider (.env default).

                    THREAD-SAFETY: callers should always pass the effective
                    provider resolved in run_agent() rather than relying on
                    the global cfg value. This makes every run independent.

    Returns:
        (llm, provider_name)
        provider_name is "local" or "cloud" — used in audit logs and the
        metadata footer shown to users on Telegram/WhatsApp/Slack.
    """
    # Use the explicitly passed provider; fall back to the .env default.
    # cfg.llm_provider is the server default — read once here, never mutated.
    effective = provider or cfg.llm_provider

    if effective == "local":
        print("[LLM] Provider: local (Ollama)")
        return get_local_llm(bind_tools), "local"

    elif effective == "cloud":
        print("[LLM] Provider: cloud (OpenAI)")
        return get_cloud_llm(bind_tools), "cloud"

    else:  # "auto"
        ollama_up = await _is_ollama_available()
        if ollama_up:
            print("[LLM] Provider: auto → local (Ollama available)")
            return get_local_llm(bind_tools), "local"
        else:
            print("[LLM] Provider: auto → cloud (Ollama not available)")
            return get_cloud_llm(bind_tools), "cloud"
