"""
config.py — Central Configuration for Agent Platform
======================================================
All settings live here. Every module reads from this one place:
    from config import get_settings
    cfg = get_settings()

HOW SETTINGS WORK:
  - pydantic-settings reads every variable from your .env file automatically.
  - If a required variable is missing, the app crashes at startup with a
    clear error — much better than a mysterious bug deep inside a running agent.
  - @lru_cache means the Settings object is created only once. All modules
    share the exact same instance — no repeated .env file reads.

NEW IN THIS VERSION (on top of secure-agent):
  • TELEGRAM_BOT_TOKEN / TELEGRAM_WEBHOOK_SECRET — Telegram bot integration
  • N8N_WEBHOOK_SECRET / N8N_BASE_URL — authenticate calls from n8n
  • CHANNEL_SYSTEM_USERNAME — shared service account for channel messages
"""

import os
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Literal


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── LLM Provider Switch ───────────────────────────────────────────────────
    # "local"  = Ollama on your machine (free, private, no API cost)
    # "cloud"  = OpenAI GPT-4o-mini (better quality, costs money)
    # "auto"   = tries local first, falls back to cloud if Ollama is offline
    llm_provider: Literal["local", "cloud", "auto"] = "auto"

    # ── Local LLM (Ollama) ────────────────────────────────────────────────────
    # In Docker the service is named "ollama", so the URL is http://ollama:11434
    # For local dev outside Docker: http://localhost:11434
    ollama_base_url: str = "http://ollama:11434"
    ollama_model: str = "mistral"
    ollama_timeout_seconds: int = 30

    # ── Cloud LLM (OpenAI) ────────────────────────────────────────────────────
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"

    # ── RAG Mode Switch ───────────────────────────────────────────────────────
    rag_mode: Literal["standard", "agentic", "auto"] = "auto"
    rag_auto_threshold_words: int = 15

    # ── Auth ──────────────────────────────────────────────────────────────────
    jwt_secret_key: str = "dev-secret-CHANGE-IN-PRODUCTION"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./data/agent.db"

    # ── Telegram Bot ──────────────────────────────────────────────────────────
    # Get from @BotFather on Telegram
    telegram_bot_token: str = ""
    # Random secret to validate webhook calls are really from Telegram
    telegram_webhook_secret: str = ""
    # Public HTTPS URL for Telegram to POST updates to
    # Development: use ngrok → ngrok http 8000 → copy https URL
    telegram_webhook_url: str = ""

    # ── Slack ─────────────────────────────────────────────────────────────────
    slack_bot_token: str = ""
    slack_signing_secret: str = ""
    slack_default_channel: str = "#general"

    # ── WhatsApp / Twilio ─────────────────────────────────────────────────────
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    twilio_whatsapp_from: str = "whatsapp:+14155238886"

    # ── Email ─────────────────────────────────────────────────────────────────
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    email_from: str = ""

    # ── n8n Traffic Manager ───────────────────────────────────────────────────
    # n8n is a free, self-hosted workflow automation tool.
    # It routes messages from external channels to this FastAPI agent.
    # The webhook secret ensures only your n8n instance can call the agent.
    n8n_webhook_secret: str = ""
    n8n_base_url: str = "http://n8n:5678"

    # ── Channel System Account ────────────────────────────────────────────────
    # Telegram/WhatsApp/n8n messages don't carry a JWT token.
    # We attribute them to this username in audit logs.
    channel_system_username: str = "channel_bot"

    # ── External APIs ─────────────────────────────────────────────────────────
    weather_api_key: str = ""

    # ── Monitoring ────────────────────────────────────────────────────────────
    prometheus_port: int = 9090
    log_level: str = "INFO"

    # ── Security limits ───────────────────────────────────────────────────────
    cost_limit_tokens_per_run: int = 4000
    cost_limit_usd_per_run: float = 0.05
    rate_limit_per_minute: int = 20
    max_input_length: int = 2000
    enable_semantic_guardrail: bool = True
    output_confidence_threshold: float = 0.7
    audit_log_retention_days: int = 90

    # ── API Server ────────────────────────────────────────────────────────────
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # ── MCP Server ────────────────────────────────────────────────────────────
    # "streamable-http" = runs as a Docker service, reachable at a stable URL.
    #                     Use this unless you specifically need stdio.
    # "stdio"           = launched as a subprocess by a local MCP client
    #                     (e.g. Claude Desktop's claude_desktop_config.json).
    mcp_transport: Literal["stdio", "streamable-http"] = "streamable-http"
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8800
    # Optional shared secret. If set, streamable-http requests must send
    # "Authorization: Bearer <MCP_API_KEY>". Leave blank for local-only dev.
    mcp_api_key: str = ""


@lru_cache()
def get_settings() -> Settings:
    """
    Return the shared Settings singleton.
    @lru_cache means this runs only once — .env is read once at startup.
    """
    return Settings()
