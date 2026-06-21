# Agent Platform — Production AI Agent with Messaging Channels

A production-ready AI agent that users interact with through
**Telegram**, **WhatsApp**, and **Slack** — not a web browser.

## Architecture

```
USER
 ├── Telegram message  ──────────────────────────┐
 ├── WhatsApp message ────────────────────────── │
 └── Slack /ask command ──────────────────────── │
                                                  ▼
                                        FastAPI (port 8000)
                                        Security Pipeline
                                        LangGraph Agent
                                        LLM (Ollama / OpenAI)
                                        RAG (FAISS)
                                          │
                                          ▼ reply
 ├── back to Telegram ◀──────────────────┤
 ├── back to WhatsApp ◀──────────────────┤
 └── back to Slack    ◀──────────────────┘

n8n (port 5678) = Traffic Manager
 Any source → n8n workflow → POST /n8n/trigger → agent → n8n → reply
```

## What Streamlit is NOT

The Streamlit UI at port 8501 is an **operator dashboard** — for YOU.
Users never see it. It shows: live stats, security events, recent runs,
channel setup instructions, and a direct agent test interface.

## Quick Start

```bash
# 1. Copy and fill in config
cp .env.example .env
# Edit .env: add your Telegram token, Twilio creds, Slack token

# 2. Start all services
docker compose up -d

# 3. Download local AI model (once — ~4GB)
docker compose exec ollama ollama pull mistral

# 4. Register Telegram webhook
# Visit http://localhost:8501 → Channel Setup → Register Telegram Webhook
# (requires TELEGRAM_WEBHOOK_URL set to a public HTTPS URL)

# 5. Message your bot on Telegram!
```

## Ports

| Port | Service | Who uses it |
|------|---------|-------------|
| 8000 | FastAPI agent | Webhooks from Telegram/WhatsApp/Slack, n8n |
| 8501 | Streamlit dashboard | Operator only |
| 8800 | MCP server | MCP clients (Claude Desktop, Claude Code, etc.) |
| 5678 | n8n | Operator builds workflows |
| 3000 | Grafana | Operator monitors metrics |
| 9090 | Prometheus | Internal metrics scraping |
| 11434 | Ollama | Internal — agent uses this |

## MCP Layer

The platform's tools (knowledge base search, calculator, weather, OWASP
code review, email, and the full agent) are also exposed over the [Model
Context Protocol](https://modelcontextprotocol.io) so MCP clients like
Claude Desktop or Claude Code can call them directly:

```bash
docker compose up -d mcp_server
python scripts/test_mcp.py   # smoke test every tool
```

See [`mcp_server/README.md`](mcp_server/README.md) for full setup,
including why it runs as a Docker service instead of a local stdio
process, and how to connect Claude Desktop.

## User Commands (per channel)

### Telegram
- Just send any message → AI answers
- `/start` — welcome message
- `/help` — show commands
- `/mode local|cloud|auto` — change LLM
- `/rag standard|agentic|auto` — change RAG mode
- `/status` — show current settings

### WhatsApp
- Just send any message → AI answers
- `!help` — show commands
- `!mode local|cloud|auto` — change LLM
- `!rag standard|agentic|auto` — change RAG mode
- `!status` — show current settings

### Slack
- `/ask <question>` → AI answers in thread
- `/ask --mode cloud <question>` — override LLM for this query
- `/ask --rag agentic <question>` — override RAG for this query

## Security
All requests through all channels pass through:
- LLM01: Prompt injection guard (30+ patterns)
- LLM06: Agency limiter (max 12 steps)
- LLM08: PII redactor on output
- LLM10: Rate limiter (20 req/min per user)
- Agentic-A01: Tool call validator
- Agentic-A03: Cost guard (token + USD limits)
- Agentic-A05: Context integrity check
- Agentic-A07: Workflow boundary enforcement
