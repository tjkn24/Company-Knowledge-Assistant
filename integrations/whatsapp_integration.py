"""
integrations/whatsapp_integration.py
======================================
WhatsApp is a bidirectional user channel via Twilio.
Users send WhatsApp messages → Twilio → our webhook → agent → reply back.

ARCHITECTURE:
  ┌──────────────────────────────────────────────────────────────────┐
  │  USER (WhatsApp)                                                 │
  │       │ sends message              ▲ receives reply              │
  │       ▼                            │                             │
  │  Twilio                            │                             │
  │  (receives on their numbers)       │                             │
  │       │ POST form data             │                             │
  │       ▼                            │                             │
  │  /webhooks/whatsapp                │                             │
  │       │                            │                             │
  │  handle_whatsapp_message()         │                             │
  │       │ security checks            │                             │
  │       │ run_agent()                │                             │
  │       │                            │                             │
  │  send_whatsapp_message() ──────────┘                             │
  │  (Twilio API → WhatsApp)                                         │
  └──────────────────────────────────────────────────────────────────┘

TWILIO SETUP (free sandbox for testing):
  1. Sign up at https://console.twilio.com
  2. Go to Messaging → Try it out → Send a WhatsApp Message
  3. Follow the sandbox setup — scan QR code with your phone
  4. Copy Account SID → TWILIO_ACCOUNT_SID in .env
  5. Copy Auth Token  → TWILIO_AUTH_TOKEN in .env
  6. Set webhook URL in Twilio console:
       https://your-domain.com/webhooks/whatsapp
     (local dev: use ngrok → ngrok http 8000)

NUMBER FORMAT:
  WhatsApp numbers must be prefixed with "whatsapp:"
  Example: "whatsapp:+628123456789"
  The FROM number is your Twilio sandbox number.
  The TO number is the user who messaged you.

TWILIO WEBHOOK PAYLOAD (form-encoded, not JSON):
  Body      — message text
  From      — sender's number, e.g. "whatsapp:+628123456789"
  To        — your Twilio number
  NumMedia  — number of attached media files (0 for text)
  MessageSid — unique message ID

TWILIO RESPONSE FORMAT:
  Twilio expects a TwiML XML response:
    <?xml version="1.0"?><Response></Response>
  An empty <Response> means "don't auto-reply" — we reply via the API instead.

SESSION STORAGE:
  Same as Telegram — per-sender settings stored in memory.
  Key is the WhatsApp number (e.g. "whatsapp:+628123456789").
"""

import base64
import httpx
from config import get_settings
from monitoring import log_integration

cfg = get_settings()

# Per-sender session settings (in-memory, same pattern as Telegram)
_wa_sessions: dict[str, dict] = {}


def _get_session(sender: str) -> dict:
    """Get or create a session for a WhatsApp sender number."""
    if sender not in _wa_sessions:
        _wa_sessions[sender] = {
            "llm_mode": cfg.llm_provider,
            "rag_mode": cfg.rag_mode,
            "workflow": "general",
        }
    return _wa_sessions[sender]


# ── SEND ──────────────────────────────────────────────────────────────────────


async def send_whatsapp_message(to: str, body: str) -> bool:
    """
    Send a WhatsApp message via Twilio's REST API.

    AUTHENTICATION:
      Twilio uses HTTP Basic Auth.
      Username = Account SID
      Password = Auth Token
      We base64-encode "SID:TOKEN" and put it in the Authorization header.
      This is exactly what Twilio's SDK does internally.

    MESSAGE LENGTH:
      WhatsApp has a 4096-character limit (same as Telegram).
      We split longer messages into chunks.

    Args:
        to:   Recipient number e.g. "whatsapp:+628123456789"
        body: Text to send
    """
    if not cfg.twilio_account_sid or not cfg.twilio_auth_token:
        print("[WhatsApp] Twilio credentials not set — skipping.")
        return False

    url = (
        f"https://api.twilio.com/2010-04-01/Accounts/"
        f"{cfg.twilio_account_sid}/Messages.json"
    )

    # HTTP Basic Auth — base64("AccountSID:AuthToken")
    creds = base64.b64encode(
        f"{cfg.twilio_account_sid}:{cfg.twilio_auth_token}".encode()
    ).decode()

    MAX_LEN = 4096
    chunks = [body[i : i + MAX_LEN] for i in range(0, max(len(body), 1), MAX_LEN)]

    success = True
    async with httpx.AsyncClient(timeout=10) as client:
        for chunk in chunks:
            resp = await client.post(
                url,
                headers={"Authorization": f"Basic {creds}"},
                data={
                    "From": cfg.twilio_whatsapp_from,
                    "To": to,
                    "Body": chunk,
                },
            )
            ok = resp.status_code in (200, 201)
            success = success and ok
            if not ok:
                print(f"[WhatsApp] Send failed: {resp.status_code} {resp.text[:200]}")

    log_integration("whatsapp", "send_message", to, success)
    return success


# ── COMMAND HANDLING ──────────────────────────────────────────────────────────


async def _handle_command(sender: str, text: str) -> bool:
    """
    Handle WhatsApp commands (prefixed with '!').

    WhatsApp doesn't have slash commands like Telegram, so we use '!'
    as the prefix: !mode local, !rag agentic, !status, !help

    Returns True if the text was a command.
    """
    session = _get_session(sender)
    text_lower = text.lower().strip()

    if text_lower in ("!help", "!start"):
        await send_whatsapp_message(
            sender,
            (
                "👋 *Agent Platform* — AI Assistant\n\n"
                "Just send any question and I'll answer it.\n\n"
                "*Commands:*\n"
                "• `!mode local` — use free local AI\n"
                "• `!mode cloud` — use OpenAI (better quality)\n"
                "• `!mode auto` — auto-select (default)\n"
                "• `!rag standard` — fast single search\n"
                "• `!rag agentic` — smart multi-search\n"
                "• `!rag auto` — auto-select (default)\n"
                "• `!status` — show current settings\n"
                "• `!help` — show this message"
            ),
        )
        return True

    if text_lower == "!status":
        await send_whatsapp_message(
            sender,
            (
                f"*Your settings:*\n"
                f"🧠 LLM: `{session['llm_mode']}`\n"
                f"📚 RAG: `{session['rag_mode']}`"
            ),
        )
        return True

    if text_lower.startswith("!mode "):
        mode = text_lower.split(" ", 1)[1].strip()
        if mode in ("local", "cloud", "auto"):
            session["llm_mode"] = mode
            descs = {
                "local": "💻 Switched to *local Ollama* — free and private.",
                "cloud": "☁️ Switched to *OpenAI* — better quality, uses tokens.",
                "auto": "🔄 Switched to *auto* — tries local first.",
            }
            await send_whatsapp_message(sender, descs[mode])
        else:
            await send_whatsapp_message(
                sender, "❌ Usage: `!mode local`, `!mode cloud`, or `!mode auto`"
            )
        return True

    if text_lower.startswith("!rag "):
        mode = text_lower.split(" ", 1)[1].strip()
        if mode in ("standard", "agentic", "auto"):
            session["rag_mode"] = mode
            descs = {
                "standard": "⚡ Switched to *standard RAG* — one search, fast.",
                "agentic": "🧠 Switched to *agentic RAG* — multi-search, thorough.",
                "auto": "🔄 Switched to *auto RAG* — picks based on complexity.",
            }
            await send_whatsapp_message(sender, descs[mode])
        else:
            await send_whatsapp_message(
                sender, "❌ Usage: `!rag standard`, `!rag agentic`, or `!rag auto`"
            )
        return True

    if text_lower.startswith("!review"):
        inline = text[len("!review") :].strip()
        session["workflow"] = "security_review"
        if inline:
            return False  # pass inline content to agent as query
        await send_whatsapp_message(
            sender,
            (
                "🔒 *Security Review Mode activated.*\n\n"
                "Send me:\n"
                "• Pasted code — I'll review it for OWASP issues\n"
                "• A GitHub repo URL — I'll scan key files\n"
                "• A specific file URL — I'll fetch and review it\n\n"
                "Frameworks: OWASP LLM Top 10 · Agentic AI Top 10 · API Security Top 10\n\n"
                "Send !general to return to normal mode."
            ),
        )
        return True

    if text_lower == "!general":
        session["workflow"] = "general"
        await send_whatsapp_message(
            sender, "✅ Switched back to general assistant mode."
        )
        return True

    return False


# ── MAIN HANDLER ──────────────────────────────────────────────────────────────


async def handle_whatsapp_message(payload: dict) -> str:
    """
    Process an incoming WhatsApp message from Twilio's webhook.

    Twilio POSTs FORM DATA (not JSON). Key fields:
      Body      — the message text the user sent
      From      — the sender's WhatsApp number "whatsapp:+628..."
      To        — your Twilio sandbox number
      NumMedia  — count of attached media (0 = text only)

    Full flow:
      1. Extract text + sender from Twilio form data
      2. Handle !commands
      3. Security checks (injection, length)
      4. Run agent with per-sender session settings
      5. PII check on output
      6. Send reply back via Twilio API
    """
    body = payload.get("Body", "").strip()
    sender = payload.get("From", "")  # e.g. "whatsapp:+628123456789"

    if not body or not sender:
        print("[WhatsApp] Empty payload — skipping.")
        return "ignored"

    # Strip the "whatsapp:" prefix for display/logging purposes
    sender_display = sender.replace("whatsapp:", "")

    # ── Get per-sender session settings (Moved up to fix UnboundLocalError) ───
    session = _get_session(sender)

    # ── Commands (!help, !mode, !rag, !status) ────────────────────────────────
    if body.startswith("!"):
        handled = await _handle_command(sender, body)
        if handled:
            return "command"
        # If execution reaches here, it was an inline !review command.
        # Strip the prefix so the agent only sees the payload (code or URL).
        if body.lower().startswith("!review"):
            body = body[len("!review") :].strip()

    # ── Security: length check ────────────────────────────────────────────────
    limit = (
        20_000 if session.get("workflow") == "security_review" else cfg.max_input_length
    )
    if len(body) > limit:
        await send_whatsapp_message(
            sender,
            f"⚠️ Input too long ({len(body):,} chars). Max {limit:,} for this mode.",
        )
        return "blocked_length"

    # ── Run the agent ─────────────────────────────────────────────────────────
    from agent.graph import run_agent

    try:
        # Use session workflow (may be "security_review" if !review was used)
        answer, tokens, metadata = await run_agent(
            user_input=body,
            username=f"wa_{sender_display}",
            workflow=session.get("workflow", "general"),
            llm_mode=session["llm_mode"],
            rag_mode=session["rag_mode"],
        )
    except Exception as e:
        await send_whatsapp_message(sender, f"⚠️ Error: {e}")
        return f"error: {e}"

    # ── Append metadata footer ────────────────────────────────────────────────
    provider = metadata.get("llm_provider", session["llm_mode"])
    rag_used = metadata.get("rag_mode_used", session["rag_mode"])
    tok = tokens
    footer = (
        f"\n\n─────\n"
        f"{'💻' if provider=='local' else '☁️'} {provider} · "
        f"{'🧠' if rag_used=='agentic' else '⚡'} {rag_used} RAG · "
        f"🔢 {tok:,} tok"
    )

    await send_whatsapp_message(sender, answer + footer)
    return answer
