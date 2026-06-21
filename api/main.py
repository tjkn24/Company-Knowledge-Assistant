"""
api/main.py — FastAPI Application Entry Point
===============================================
Creates the app, registers middleware, and mounts all routes.

Start the server:
    uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

Or with Docker Compose (recommended):
    docker compose up

Then open:
    http://localhost:8000/docs   ← Swagger UI (interactive API docs)
    http://localhost:8501        ← Streamlit chat UI
    http://localhost:5678        ← n8n workflow editor
    http://localhost:3000        ← Grafana monitoring dashboard
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from database import init_db
from api.routes import router
from config import get_settings

cfg = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Code before yield = startup. Code after yield = shutdown.

    On startup we:
      1. Create database tables (if they don't exist)
      2. Print helpful startup info

    The RAG vector store is built lazily on first request
    (in agent/graph.py → _initialise_rag()) to keep startup fast.
    """
    await init_db()
    print(f"\n{'='*50}")
    print(f"  Agent Platform — Started")
    print(f"  LLM provider : {cfg.llm_provider}")
    print(f"  RAG mode     : {cfg.rag_mode}")
    print(f"  API docs     : http://localhost:{cfg.api_port}/docs")
    print(f"  Health check : http://localhost:{cfg.api_port}/health")
    print(f"{'='*50}\n")
    yield
    print("[Shutdown] Goodbye.")


app = FastAPI(
    title="Agent Platform",
    description=(
        "Production AI agent with:\n"
        "- **Channels**: Telegram, WhatsApp, Slack + Streamlit UI\n"
        "- **Traffic manager**: n8n workflows\n"
        "- **LLM routing**: local (Ollama) / cloud (OpenAI) / auto\n"
        "- **RAG**: standard / agentic / auto\n"
        "- **Security**: OWASP LLM Top 10 + Agentic Top 10\n"
        "- **Docker**: all services containerised"
    ),
    version="3.0.0",
    lifespan=lifespan,
)

# ── Middleware ────────────────────────────────────────────────────────────────
# CORS: allow all origins in dev. In production, restrict to your frontend domains.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # change to ["https://yourapp.com"] in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# TrustedHost: prevents Host header injection attacks
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"],        # change to ["yourapp.com", "localhost"] in production
)

app.include_router(router)
