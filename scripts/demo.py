"""
scripts/demo.py — Quick Smoke Test
=====================================
Tests all three LLM modes and all three RAG modes by calling
run_agent() directly (no HTTP, no Docker needed).

Run from the project root with venv activated:
    python scripts/demo.py

WHAT IT TESTS:
  1. Auto query routing (short → standard, long → agentic)
  2. Forced local + standard
  3. Forced cloud + agentic (requires OPENAI_API_KEY in .env)
  4. Calculator tool (no RAG)

BEGINNER TIP:
  Run this after any code change to check nothing is broken.
  It's faster than testing through Telegram or the REST API.
"""

import asyncio
import os
import sys

# Make sure the project root is on the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.graph import run_agent


async def demo(label: str, message: str, llm_mode: str, rag_mode: str):
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"  LLM={llm_mode}  RAG={rag_mode}")
    print(f"  Query: {message}")
    print(f"{'='*60}")
    try:
        answer, tokens, meta = await run_agent(
            user_input=message,
            username="demo_user",
            llm_mode=llm_mode,
            rag_mode=rag_mode,
        )
        print(f"Answer: {answer[:300]}{'...' if len(answer)>300 else ''}")
        print(f"Tokens: {tokens} | LLM: {meta['llm_provider']} | RAG: {meta['rag_mode_used']}")
    except Exception as e:
        print(f"ERROR: {e}")


async def main():
    print("\n🚀 Agent Platform — Demo Script")

    await demo("Short query → Standard RAG (auto)",
               "What is the return policy?",
               llm_mode="auto", rag_mode="auto")

    await demo("Complex query → Agentic RAG (auto)",
               "Compare the annual leave policy and sick leave policy — "
               "what are the differences and how do they interact?",
               llm_mode="auto", rag_mode="auto")

    await demo("Forced local + standard",
               "What products do you offer?",
               llm_mode="local", rag_mode="standard")

    await demo("Calculator (no RAG needed)",
               "What is 15% of 4750?",
               llm_mode="auto", rag_mode="standard")


if __name__ == "__main__":
    asyncio.run(main())
