"""
integrations/telegram_integration.py
======================================
Telegram bidirectional channel — receive messages, run agent, send replies.

COMMANDS (updated with security review):
  /start              — welcome message
  /help               — show all commands
  /mode local|cloud|auto  — change LLM for this chat
  /rag standard|agentic|auto  — change RAG mode
  /status             — show current settings
  /review             — switch to security review mode
  /review <code>      — review pasted code inline
  /review https://... — review a GitHub URL

SECURITY REVIEW USAGE:
  User types /review then pastes code → agent runs security_review workflow.
  User types /review https://github.com/owner/repo → repo review.
  User types /review https://github.com/owner/repo/blob/main/file.py → file review.

HOW TELEGRAM WEBHOOKS WORK:
  Your bot is registered with Telegram via setWebhook.
  Every message → Telegram POSTs to /webhooks/telegram → handle_telegram_update().
  You reply via the Telegram Bot API (sendMessage).

SETUP:
  1. @BotFather → /newbot → copy token → TELEGRAM_BOT_TOKEN in .env
  2. python scripts/setup_telegram.py  (or POST /webhooks/telegram/setup)
"""

import hmac
import httpx
from config import get_settings
from monitoring import log_integration

cfg = get_settings()

TELEGRAM_API = f"https://api.telegram.org/bot{cfg.telegram_bot_token}"

# Per-chat session settings: llm_mode, rag_mode, active_workflow
_chat_sessions: dict[int, dict] = {}

# Per-chat asyncio locks — ensures messages from the same chat are
# processed one at a time. Without this, two rapid messages start two
# background tasks simultaneously, producing out-of-order or duplicate replies.
import asyncio as _asyncio

_chat_locks: dict[int, _asyncio.Lock] = {}


def _get_lock(chat_id: int) -> "_asyncio.Lock":
    if chat_id not in _chat_locks:
        _chat_locks[chat_id] = _asyncio.Lock()
    return _chat_locks[chat_id]


def _get_session(chat_id: int) -> dict:
    if chat_id not in _chat_sessions:
        _chat_sessions[chat_id] = {
            "llm_mode": cfg.llm_provider,
            "rag_mode": cfg.rag_mode,
            "workflow": "general",
        }
    return _chat_sessions[chat_id]


# ── SEND ──────────────────────────────────────────────────────────────────────


async def send_telegram_message(chat_id: int | str, text: str) -> bool:
    """
    Send a reply to a Telegram chat.
    Splits messages longer than 4096 chars (Telegram's hard limit).
    Falls back to plain text if Markdown parsing fails.
    """
    if not cfg.telegram_bot_token:
        print("[Telegram] BOT_TOKEN not set — skipping send.")
        return False

    MAX_LEN = 4096
    chunks = [text[i : i + MAX_LEN] for i in range(0, max(len(text), 1), MAX_LEN)]

    success = True
    async with httpx.AsyncClient(timeout=10) as client:
        for chunk in chunks:
            resp = await client.post(
                f"{TELEGRAM_API}/sendMessage",
                json={"chat_id": chat_id, "text": chunk, "parse_mode": "Markdown"},
            )
            ok = resp.status_code == 200 and resp.json().get("ok", False)
            if not ok:
                # Retry without Markdown if parsing failed
                resp2 = await client.post(
                    f"{TELEGRAM_API}/sendMessage",
                    json={"chat_id": chat_id, "text": chunk},
                )
                ok = resp2.status_code == 200 and resp2.json().get("ok", False)
            success = success and ok

    log_integration("telegram", "send_message", str(chat_id), success)
    return success


async def send_typing(chat_id: int | str) -> None:
    """Show 'typing...' indicator while the agent thinks."""
    if not cfg.telegram_bot_token:
        return
    async with httpx.AsyncClient(timeout=5) as client:
        await client.post(
            f"{TELEGRAM_API}/sendChatAction",
            json={"chat_id": chat_id, "action": "typing"},
        )


# ── COMMAND HANDLER ───────────────────────────────────────────────────────────


async def _handle_command(chat_id: int, text: str, username: str) -> bool:
    """
    Handle /commands. Returns True if handled (skip agent processing).

    NEW: /review command switches to security_review workflow and can
    accept inline code or a GitHub URL directly.
    """
    session = _get_session(chat_id)

    # ── /start ────────────────────────────────────────────────────────────────
    if text.startswith("/start"):
        await send_telegram_message(
            chat_id,
            (
                "👋 *Welcome to Agent Platform!*\n\n"
                "I'm an AI assistant with built-in security review.\n\n"
                "*Commands:*\n"
                "• Just type any question — I'll answer it\n"
                "• `/mode local|cloud|auto` — change AI model\n"
                "• `/rag standard|agentic|auto` — change retrieval mode\n"
                "• `/review` — switch to OWASP security review mode\n"
                "• `/review <code>` — review pasted code immediately\n"
                "• `/review https://github.com/...` — review a GitHub file or repo\n"
                "• `/general` — switch back to general assistant mode\n"
                "• `/status` — show current settings\n"
                "• `/help` — show this message"
            ),
        )
        return True

    # ── /help ─────────────────────────────────────────────────────────────────
    if text.startswith("/help"):
        await send_telegram_message(
            chat_id,
            (
                "*Commands:*\n\n"
                "`/mode local` — free local AI (Ollama)\n"
                "`/mode cloud` — OpenAI GPT-4o-mini\n"
                "`/mode auto` — try local, fall back to cloud\n\n"
                "`/rag standard` — one search, fast\n"
                "`/rag agentic` — multi-hop, thorough\n"
                "`/rag auto` — auto-pick (default)\n\n"
                "*Security Review:*\n"
                "`/review` — switch to security review mode\n"
                "`/review <code>` — review code immediately\n"
                "`/review https://github.com/owner/repo` — review repo\n"
                "`/review https://github.com/owner/repo/blob/main/file.py` — review file\n\n"
                "`/general` — switch back to general mode\n"
                "`/status` — show current settings"
            ),
        )
        return True

    # ── /status ───────────────────────────────────────────────────────────────
    if text.startswith("/status"):
        wf = session["workflow"]
        wf_label = "🔒 Security Review" if wf == "security_review" else f"⚙️ {wf}"
        await send_telegram_message(
            chat_id,
            (
                f"*Your current settings:*\n\n"
                f"🧠 LLM mode: `{session['llm_mode']}`\n"
                f"📚 RAG mode: `{session['rag_mode']}`\n"
                f"⚙️ Workflow: `{wf_label}`\n\n"
                f"Change: `/mode local|cloud|auto` · `/rag standard|agentic|auto`\n"
                f"Security review: `/review` or `/review <code>`"
            ),
        )
        return True

    # ── /general ──────────────────────────────────────────────────────────────
    if text.startswith("/general"):
        session["workflow"] = "general"
        await send_telegram_message(
            chat_id, "✅ Switched to *general assistant* mode.\nAsk me anything!"
        )
        return True

    # ── /mode ─────────────────────────────────────────────────────────────────
    if text.startswith("/mode "):
        mode = text.split(" ", 1)[1].strip().lower()
        if mode in ("local", "cloud", "auto"):
            session["llm_mode"] = mode
            icons = {"local": "💻", "cloud": "☁️", "auto": "🔄"}
            descs = {
                "local": "Using *local Ollama* — free and private.",
                "cloud": "Using *OpenAI* — better quality, uses tokens.",
                "auto": "Using *auto* — tries local first.",
            }
            await send_telegram_message(chat_id, f"{icons[mode]} {descs[mode]}")
        else:
            await send_telegram_message(
                chat_id, "❌ Usage: `/mode local`, `/mode cloud`, or `/mode auto`"
            )
        return True

    # ── /rag ──────────────────────────────────────────────────────────────────
    if text.startswith("/rag "):
        mode = text.split(" ", 1)[1].strip().lower()
        if mode in ("standard", "agentic", "auto"):
            session["rag_mode"] = mode
            descs = {
                "standard": "⚡ *Standard RAG* — one search, fast.",
                "agentic": "🧠 *Agentic RAG* — multi-hop, thorough.",
                "auto": "🔄 *Auto RAG* — picks based on complexity.",
            }
            await send_telegram_message(chat_id, descs[mode])
        else:
            await send_telegram_message(
                chat_id, "❌ Usage: `/rag standard`, `/rag agentic`, or `/rag auto`"
            )
        return True

    # ── /review ───────────────────────────────────────────────────────────────
    if text.startswith("/review"):
        # /review with inline content — run immediately
        inline = text[len("/review") :].strip()

        if inline:
            # User passed code or URL inline with the command
            # Route to the agent directly with the security_review workflow
            session["workflow"] = "security_review"
            return False  # let the main handler process with the inline text as query

        # /review alone — switch mode and prompt
        session["workflow"] = "security_review"
        await send_telegram_message(
            chat_id,
            (
                "🔒 *Security Review Mode activated.*\n\n"
                "Send me:\n"
                "• *Pasted code* — I'll review it for OWASP issues\n"
                "• *A GitHub repo URL* — I'll scan the key files\n"
                "  `https://github.com/owner/repo`\n"
                "• *A specific file URL* — I'll fetch and review it\n"
                "  `https://github.com/owner/repo/blob/main/config.py`\n\n"
                "Frameworks: OWASP LLM Top 10 · Agentic AI Top 10 · API Security Top 10\n\n"
                "_Type `/general` to return to normal mode._"
            ),
        )
        return True

    return False  # not a recognised command


# ── MAIN UPDATE HANDLER ───────────────────────────────────────────────────────


async def handle_telegram_update(update: dict) -> str:
    """
    Process one Telegram update (one incoming event).

    For /review with inline content, we pass the inline content as the
    user_input so the agent receives it directly.
    """
    message = update.get("message") or update.get("edited_message") or {}
    text = message.get("text", "").strip()
    chat_id = message.get("chat", {}).get("id")
    user_obj = message.get("from", {})
    username = (
        user_obj.get("username")
        or user_obj.get("first_name")
        or str(user_obj.get("id", "tg_user"))
    )

    if not text or not chat_id:
        return "ignored"

    # Handle commands — may modify session and return True (skip agent)
    # For /review <inline>, _handle_command returns False so we process below
    if text.startswith("/"):
        handled = await _handle_command(chat_id, text, username)
        if handled:
            return "command"
        # If /review <inline> — strip the "/review" prefix so agent sees just the content
        if text.startswith("/review "):
            text = text[len("/review ") :].strip()

    if len(text) > cfg.max_input_length:
        # Security review may need more room for pasted code
        # Allow up to 20,000 chars for the security_review workflow
        session = _get_session(chat_id)
        limit = (
            20_000 if session["workflow"] == "security_review" else cfg.max_input_length
        )
        if len(text) > limit:
            await send_telegram_message(
                chat_id,
                f"⚠️ Input too long ({len(text):,} chars). Max {limit:,} for this mode.",
            )
            return "blocked_length"

    # ── Per-chat lock: process one message at a time per chat ──────────────
    # Prevents two rapid messages from the same user running the agent
    # simultaneously and producing interleaved or duplicate replies.
    # ── Per-chat lock: entire agent run inside ─────────────────────────────
    # Wraps typing → run_agent → reply. If a user sends two messages quickly,
    # the second waits until the first completes. No duplicate or interleaved replies.
    async with _get_lock(chat_id):

        await send_typing(chat_id)

        session = _get_session(chat_id)
        llm_mode = session["llm_mode"]
        rag_mode = session["rag_mode"]
        workflow = session["workflow"]

        from agent.graph import run_agent

        try:
            answer, tokens, metadata = await run_agent(
                user_input=text,
                username=f"tg_{username}",
                workflow=workflow,
                llm_mode=llm_mode,
                rag_mode=rag_mode,
            )
        except Exception as e:
            await send_telegram_message(chat_id, f"⚠️ Agent error: {e}")
            return f"error: {e}"

        # Metadata footer
        provider = metadata.get("llm_provider", llm_mode)
        rag_used = metadata.get("rag_mode_used", rag_mode)
        tok = tokens
        cost = round(tok * 0.000001, 5)
        icon_llm = "💻" if provider == "local" else "☁️"
        icon_rag = "🧠" if rag_used == "agentic" else "⚡"
        icon_wf = "🔒" if workflow == "security_review" else "⚙️"
        footer = (
            f"\n\n─────────────────\n"
            f"{icon_wf} `{workflow}` · {icon_llm} `{provider}` · "
            f"{icon_rag} `{rag_used}` · 🔢 `{tok:,} tok` · 💰 `${cost}`"
        )
        await send_telegram_message(chat_id, answer + footer)
        return answer


# ── WEBHOOK MANAGEMENT ────────────────────────────────────────────────────────


async def register_webhook() -> dict:
    """Register our webhook URL with Telegram (call once after deployment)."""
    if not cfg.telegram_bot_token:
        return {"error": "TELEGRAM_BOT_TOKEN not set in .env"}
    if not cfg.telegram_webhook_url:
        return {"error": "TELEGRAM_WEBHOOK_URL not set in .env"}
    if not cfg.telegram_webhook_secret:
        return {"error": "TELEGRAM_WEBHOOK_SECRET not set in .env"}

    webhook_url = f"{cfg.telegram_webhook_url.rstrip('/')}/webhooks/telegram"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            f"{TELEGRAM_API}/setWebhook",
            json={
                "url": webhook_url,
                "secret_token": cfg.telegram_webhook_secret,
                "allowed_updates": ["message", "edited_message"],
                "drop_pending_updates": True,
            },
        )
    result = resp.json()
    print(f"[Telegram] Webhook registration → {result}")
    return result


async def get_webhook_info() -> dict:
    """Check the registered webhook URL and status."""
    if not cfg.telegram_bot_token:
        return {"error": "TELEGRAM_BOT_TOKEN not set"}
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{TELEGRAM_API}/getWebhookInfo")
    return resp.json()


async def delete_webhook() -> dict:
    """Remove the webhook (switch back to polling mode for local dev)."""
    if not cfg.telegram_bot_token:
        return {"error": "TELEGRAM_BOT_TOKEN not set"}
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(f"{TELEGRAM_API}/deleteWebhook")
    return resp.json()
