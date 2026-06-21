# MCP Layer

This exposes a curated set of the platform's tools over the
[Model Context Protocol](https://modelcontextprotocol.io) (MCP), so any MCP
client — Claude Desktop, Claude Code, n8n's MCP node, another agent — can
call them directly.

## Why this is different from the last attempt

The earlier version ran the MCP server as a **local stdio process** on the
Mac Mini. That tied the server's lifetime to a terminal window, hid Ollama
failures behind a generic tool-call error, and meant a laptop sleep or a
closed terminal silently took the server down.

This version runs MCP as **its own Docker service** (`mcp_server`), on the
same `platform` network as `ollama`, `agent`, and everything else — the same
pattern the rest of this project already uses. It's reachable at a stable
URL (`http://localhost:8800/mcp`), survives client restarts, and you debug
it the normal way: `docker compose logs mcp_server`.

Local stdio is still available (for Claude Desktop, which launches MCP
servers as subprocesses) — see "Claude Desktop" below — but it's now an
option, not the only path.

## Why the tools are split the way they are

| Tool | Needs Ollama/OpenAI? |
|---|---|
| `search_knowledge_base` | No — direct FAISS lookup |
| `calculator` | No |
| `get_weather` | No |
| `review_code_security` | No — static pattern scan |
| `send_email` | No |
| `ask_agent` | **Yes** — full LangGraph reasoning loop |

Only `ask_agent` touches the LLM backend. This is deliberate: last time, a
broken Ollama model silently took down *every* tool because everything went
through `run_agent()`. Now if Ollama is misconfigured, `ask_agent` fails
loudly with a hint, while the other five tools keep working — so you can
tell "the MCP layer is broken" apart from "the LLM backend is broken."

## Run it

```bash
# from the project root
cp .env.example .env   # if you haven't already
docker compose up -d mcp_server
```

Check it's healthy:

```bash
curl http://localhost:8800/health
# → ok
```

Smoke-test every tool (the 5 that don't need an LLM, plus `ask_agent`):

```bash
pip install mcp --break-system-packages   # if not already installed
python scripts/test_mcp.py
```

Run it without `ask_agent` while you're debugging Ollama separately:

```bash
python scripts/test_mcp.py --skip-agent
```

If `ask_agent` fails, that confirms the issue is the LLM backend, not MCP —
check:

```bash
docker compose logs ollama
docker compose exec ollama ollama pull "${OLLAMA_MODEL:-mistral}"
docker compose restart mcp_server agent
```

## Securing it

By default `MCP_API_KEY` is blank — fine for local development. Before
exposing port 8800 beyond `localhost`, set a key in `.env`:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
# paste the output into MCP_API_KEY= in .env
docker compose up -d mcp_server   # restart to pick it up
```

Clients then need:

```
Authorization: Bearer <MCP_API_KEY>
```

## Connecting Claude Desktop (stdio)

Claude Desktop launches MCP servers as a local subprocess rather than
connecting over HTTP, so it needs the `stdio` transport and a Python
environment with `requirements.txt` installed (the conda env you already
use for this project, e.g. `cka-app`).

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "company-knowledge-assistant": {
      "command": "conda",
      "args": ["run", "-n", "cka-app", "python", "-m", "mcp_server.server"],
      "cwd": "/absolute/path/to/company-knowledge-assistant-rev3",
      "env": { "MCP_TRANSPORT": "stdio" }
    }
  }
}
```

Restart Claude Desktop. The platform's tools should appear under the 🔌 icon.

Note: in stdio mode, `ollama_base_url` in `.env` must point somewhere
reachable from your laptop directly (e.g. `http://localhost:11434`), not
`http://ollama:11434` (that hostname only resolves inside the Docker
network) — unless you're running Ollama outside Docker too.

## Connecting other HTTP-based MCP clients

Point the client at:

```
http://localhost:8800/mcp
```

with the `Authorization: Bearer <MCP_API_KEY>` header if you've set one.
