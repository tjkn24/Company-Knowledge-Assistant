"""
scripts/test_mcp.py — MCP Server Smoke Test
==============================================
Connects to the running mcp_server service over streamable-HTTP and:
  1. Lists all available tools (confirms the server is reachable and the
     tool registry loaded correctly).
  2. Calls each "safe" tool (no side effects, no LLM dependency) with a
     sample input and prints the result.
  3. Optionally calls ask_agent() — the one tool that needs Ollama/OpenAI —
     separately, so an LLM failure doesn't hide whether the other 4 tools
     are healthy.

USAGE:
    # 1. Make sure the service is up:
    docker compose up -d mcp_server

    # 2. Run this from the project root (needs the `mcp` package — already
    #    in requirements.txt, or: pip install mcp --break-system-packages):
    python scripts/test_mcp.py

    # Test against a non-default host/port or with an API key:
    MCP_URL=http://localhost:8800/mcp MCP_API_KEY=yourkey python scripts/test_mcp.py

    # Skip the LLM-dependent tool (useful while debugging Ollama separately):
    python scripts/test_mcp.py --skip-agent
"""

import os
import sys
import asyncio
import argparse

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

DEFAULT_URL = os.environ.get("MCP_URL", "http://localhost:8800/mcp")
API_KEY = os.environ.get("MCP_API_KEY", "")


async def run(url: str, skip_agent: bool) -> int:
    headers = {"Authorization": f"Bearer {API_KEY}"} if API_KEY else None

    print(f"Connecting to {url} ...")
    try:
        async with streamablehttp_client(url, headers=headers) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()

                tools = await session.list_tools()
                names = sorted(t.name for t in tools.tools)
                print(f"✅ Connected. {len(names)} tools available: {names}\n")

                safe_calls = [
                    ("calculator", {"expression": "(100 + 200) / 3"}),
                    ("get_weather", {"city": "Jakarta"}),
                    (
                        "review_code_security",
                        {"code": "password = 'hardcoded123'", "filename": "demo.py"},
                    ),
                    ("search_knowledge_base", {"query": "annual leave"}),
                ]

                failures = 0
                for name, args in safe_calls:
                    print(f"── {name}({args}) ──")
                    try:
                        result = await session.call_tool(name, args)
                        text = "".join(
                            block.text
                            for block in result.content
                            if hasattr(block, "text")
                        )
                        preview = text[:300] + ("..." if len(text) > 300 else "")
                        status = "❌ TOOL ERROR" if result.isError else "✅ OK"
                        print(f"{status}\n{preview}\n")
                        if result.isError:
                            failures += 1
                    except Exception as e:
                        print(f"❌ EXCEPTION: {e}\n")
                        failures += 1

                if skip_agent:
                    print("Skipping ask_agent (--skip-agent passed).")
                else:
                    print("── ask_agent({'question': 'What is 12 * 8?'}) ──")
                    print("(requires Ollama/OpenAI — if this fails, the 4 tools")
                    print(" above are still healthy; check the LLM backend.)")
                    try:
                        result = await session.call_tool(
                            "ask_agent", {"question": "What is 12 * 8?"}
                        )
                        text = "".join(
                            block.text
                            for block in result.content
                            if hasattr(block, "text")
                        )
                        status = "❌ TOOL ERROR" if result.isError else "✅ OK"
                        print(f"{status}\n{text}\n")
                        if result.isError:
                            failures += 1
                    except Exception as e:
                        print(f"❌ EXCEPTION: {e}")
                        print(
                            "Hint: pull the model and confirm OLLAMA_MODEL in .env, e.g.\n"
                            "  docker compose exec ollama ollama pull qwen2.5:3b\n"
                            "then restart: docker compose restart mcp_server agent"
                        )
                        failures += 1

                print(f"\n{'='*50}")
                if failures == 0:
                    print("All tested tools passed.")
                else:
                    print(f"{failures} tool(s) failed — see output above.")
                print(f"{'='*50}")
                return 1 if failures else 0
    except Exception as e:
        print(f"❌ Could not connect to MCP server at {url}: {e}")
        print(
            "Hint: is the service running? `docker compose up -d mcp_server`\n"
            "      then check: docker compose logs mcp_server"
        )
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL, help="MCP streamable-HTTP URL")
    parser.add_argument(
        "--skip-agent",
        action="store_true",
        help="Skip the ask_agent tool (the one that needs Ollama/OpenAI)",
    )
    args = parser.parse_args()
    sys.exit(asyncio.run(run(args.url, args.skip_agent)))
