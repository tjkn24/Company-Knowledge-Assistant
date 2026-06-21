"""
integrations/slack_integration.py
====================================
Slack is a bidirectional user channel.
Users interact via slash commands or @mentions → agent replies in-thread.

ARCHITECTURE:
  ┌───────────────────────────────────────────────────────────────────┐
  │  USER (Slack)                                                     │
  │  Types: /ask What is the leave policy?   ▲ sees answer in Slack  │
  │       │                                   │                      │
  │       ▼                                   │                      │
  │  Slack servers ──POST──▶ /webhooks/slack  │                      │
  │                               │           │                      │
  │                    verify signature (HMAC)│                      │
  │                               │           │                      │
  │                    handle_slack_event()   │                      │
  │                               │ security  │                      │
  │                               │ run_agent()                      │
  │                               │           │                      │
  │                    send_slack_message() ──┘                      │
  │                    (Slack Web API)                                │
  └───────────────────────────────────────────────────────────────────┘

SETUP (one-time, ~10 minutes):
  1. Go to https://api.slack.com/apps → Create New App → From Scratch
  2. Name it (e.g. "Agent Platform") and pick your workspace
  3. Under OAuth & Permissions → Bot Token Scopes, add:
       chat:write     — post messages
       commands       — receive slash commands
       app_mentions:read — receive @mentions (optional)
  4. Install app to workspace → copy Bot User OAuth Token
       → SLACK_BOT_TOKEN=xoxb-... in .env
  5. Under Basic Information → App Credentials → copy Signing Secret
       → SLACK_SIGNING_SECRET=... in .env
  6. Under Slash Commands → Create New Command:
       Command: /ask
       Request URL: https://your-domain.com/webhooks/slack
       Description: Ask the AI agent a question
  7. Reinstall the app after adding scopes

SLASH COMMAND:
  /ask What is our parental leave policy?
  /ask --mode cloud What is the weather in Jakarta?
  /ask --rag agentic Summarise all HR policies

INLINE FLAGS:
  Users can override LLM/RAG mode per-request inline:
    /ask --mode local <question>
    /ask --rag agentic <question>
    /ask --mode cloud --rag standard <question>

WORKSPACE-LEVEL SESSIONS:
  Slack doesn't have individual user sessions in the same way.
  We store per-user settings keyed by Slack user_id.

SECURITY — Slack signature verification:
  Slack signs every webhook request with your Signing Secret using HMAC-SHA256.
  The signature is in the X-Slack-Signature header.
  We MUST verify this before processing — otherwise anyone who discovers
  your webhook URL can trigger agent runs for free.
  The signature is: v0=HMAC-SHA256(signing_secret, "v0:{timestamp}:{body}")
"""

import hashlib
import hmac
import time
import re
import httpx
from config import get_settings
from monitoring import log_integration

cfg = get_settings()

# Per-user Slack session settings (keyed by Slack user_id)
_slack_sessions: dict[str, dict] = {}


def _get_session(user_id: str) -> dict:
    """Get or create per-user settings."""
    if user_id not in _slack_sessions:
        _slack_sessions[user_id] = {
            "llm_mode": cfg.llm_provider,
            "rag_mode": cfg.rag_mode,
            "workflow": "general",
        }
    return _slack_sessions[user_id]


def _parse_flags(text: str) -> tuple[str, dict]:
    """
    Parse inline flags from the slash command text.

    Input:  "--mode cloud --rag agentic What is the leave policy?"
    Output: ("What is the leave policy?", {"mode": "cloud", "rag": "agentic"})

    This lets users override settings for a single query without
    changing their persistent session settings.
    """
    flags = {}

    # Extract --mode flag
    mode_match = re.search(r"--mode\s+(local|cloud|auto)", text, re.IGNORECASE)
    if mode_match:
        flags["llm_mode"] = mode_match.group(1).lower()
        text = text.replace(mode_match.group(0), "").strip()

    # Extract --rag flag
    rag_match = re.search(r"--rag\s+(standard|agentic|auto)", text, re.IGNORECASE)
    if rag_match:
        flags["rag_mode"] = rag_match.group(1).lower()
        text = text.replace(rag_match.group(0), "").strip()

    # Extract --workflow flag
    wf_match = re.search(r"--workflow\s+(\w+)", text, re.IGNORECASE)
    if wf_match:
        flags["workflow"] = wf_match.group(1).lower()
        text = text.replace(wf_match.group(0), "").strip()

    # Shorthand: --review flag → security_review workflow
    if "--review" in text.lower():
        flags["workflow"] = "security_review"
        text = re.sub(r"--review", "", text, flags=re.IGNORECASE).strip()

    return text.strip(), flags


# ── SEND ──────────────────────────────────────────────────────────────────────


async def send_slack_message(
    text: str,
    channel: str = "",
    thread_ts: str = "",
    user_id: str = "",
) -> bool:
    """
    Post a message to a Slack channel.

    Args:
        text:      Message text (Slack markdown supported: *bold*, `code`, >quote)
        channel:   Channel ID or name. Falls back to SLACK_DEFAULT_CHANNEL.
        thread_ts: If set, post as a reply in this thread.
                   thread_ts is the timestamp of the parent message.
                   Posting in-thread keeps channels clean — only the person
                   who asked sees the full answer, others see a thread summary.
        user_id:   If set, also send an ephemeral (private) message to this user.

    IMPORTANT SLACK QUIRK:
      Slack returns HTTP 200 even when the API call FAILS.
      You MUST check response["ok"] to know if it actually worked.
      If ok=False, response["error"] contains the reason.
    """
    if not cfg.slack_bot_token:
        print("[Slack] SLACK_BOT_TOKEN not set — skipping.")
        return False

    target = channel or cfg.slack_default_channel

    # Build the API payload
    payload: dict = {"channel": target, "text": text}
    if thread_ts:
        # Reply in-thread instead of posting to the channel
        payload["thread_ts"] = thread_ts

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            "https://slack.com/api/chat.postMessage",
            headers={"Authorization": f"Bearer {cfg.slack_bot_token}"},
            json=payload,
        )

    data = resp.json()
    success = data.get("ok", False)

    if not success:
        print(f"[Slack] Send failed: {data.get('error', 'unknown')}")

    log_integration(
        "slack", "send_message", target, success, detail=data.get("error", "")
    )
    return success


async def send_slack_ephemeral(channel: str, user_id: str, text: str) -> bool:
    """
    Send a message visible ONLY to a specific user in a channel.
    Useful for showing settings/status without cluttering the channel.
    """
    if not cfg.slack_bot_token:
        return False
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            "https://slack.com/api/chat.postEphemeral",
            headers={"Authorization": f"Bearer {cfg.slack_bot_token}"},
            json={"channel": channel, "user": user_id, "text": text},
        )
    return resp.json().get("ok", False)


# ── SECURITY ──────────────────────────────────────────────────────────────────


def verify_slack_signature(body: bytes, timestamp: str, signature: str) -> bool:
    """
    Verify that a webhook request genuinely came from Slack.

    HOW SLACK SIGNING WORKS:
      1. Slack creates a base string: "v0:{timestamp}:{raw_body}"
      2. Slack signs it with your Signing Secret using HMAC-SHA256
      3. Slack includes the signature in X-Slack-Signature header
      4. We recreate the signature on our side and compare

    REPLAY ATTACK PREVENTION:
      We also check that the timestamp is within 5 minutes of now.
      Without this, an attacker could capture a valid request and
      replay it hours later.

    CONSTANT-TIME COMPARISON:
      hmac.compare_digest() prevents timing attacks.
      A regular string comparison (==) takes longer if the strings
      match for more characters — this leaks info about the secret.
      compare_digest always takes the same time regardless of match.
    """
    if not cfg.slack_signing_secret:
        return True  # skip verification in development if secret not set

    # Reject stale requests (replay attack prevention)
    try:
        if abs(time.time() - float(timestamp)) > 300:  # 5 minutes
            print("[Slack] Rejected: request timestamp too old.")
            return False
    except (ValueError, TypeError):
        return False

    # Recreate the expected signature
    base_string = f"v0:{timestamp}:{body.decode('utf-8')}"
    expected_sig = (
        "v0="
        + hmac.new(
            cfg.slack_signing_secret.encode("utf-8"),
            base_string.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
    )

    # Constant-time comparison — never use == for secrets
    return hmac.compare_digest(expected_sig, signature)


# ── MAIN HANDLER ──────────────────────────────────────────────────────────────


async def handle_slack_event(payload: dict) -> str:
    """
    Process a Slack slash command or event.

    SLASH COMMAND PAYLOAD (from Slack):
      {
        "command":      "/ask",
        "text":         "What is the annual leave policy?",
        "user_id":      "U12345678",
        "user_name":    "tj",
        "channel_id":   "C12345678",
        "channel_name": "general",
        "response_url": "https://hooks.slack.com/..."  (for delayed responses)
      }

    FLOW:
      1. Extract command text and user info
      2. Parse any inline flags (--mode, --rag)
      3. Security checks
      4. Run agent with effective settings
      5. Reply in-thread (keeps the channel clean)
    """
    command = payload.get("command", "")
    raw_text = payload.get("text", "").strip()
    user_id = payload.get("user_id", "")
    user_name = payload.get("user_name", "slack_user")
    channel = payload.get("channel_id", cfg.slack_default_channel)
    thread_ts = payload.get("thread_ts", "")  # set if the /ask was in a thread

    # Support both /ask command and event-based mentions
    if not raw_text:
        await send_slack_message(
            "👋 Use `/ask <your question>` to ask me anything!\n"
            "Add flags to override settings: `--mode local|cloud|auto`, `--rag standard|agentic|auto`",
            channel=channel,
        )
        return "empty"

    # ── Parse inline flags ────────────────────────────────────────────────────
    question, flags = _parse_flags(raw_text)
    if not question:
        await send_slack_message(
            "Please provide a question after the command.\n"
            "Example: `/ask What is the annual leave policy?`",
            channel=channel,
            thread_ts=thread_ts,
        )
        return "no_question"

    # ── Determine effective settings ──────────────────────────────────────────
    session = _get_session(user_id)
    llm_mode = flags.get("llm_mode", session["llm_mode"])
    rag_mode = flags.get("rag_mode", session["rag_mode"])

    effective_wf_for_limit = flags.get("workflow", session.get("workflow", "general"))
    length_limit = (
        20_000 if effective_wf_for_limit == "security_review" else cfg.max_input_length
    )
    if len(question) > length_limit:
        await send_slack_message(
            f"⚠️ Input too long ({len(question):,} chars). Max {length_limit:,} for this mode.",
            channel=channel,
            thread_ts=thread_ts,
        )
        return "blocked_length"

    # ── Post an immediate acknowledgement (Slack times out after 3 seconds) ───
    # Slack requires a response within 3 seconds or shows an error to the user.
    # We send an immediate "thinking..." message, then reply with the actual answer.
    await send_slack_message(
        f"🤔 *@{user_name} asked:* _{question}_\nThinking...",
        channel=channel,
        thread_ts=thread_ts,
    )

    # ── Run the agent ─────────────────────────────────────────────────────────
    from agent.graph import run_agent

    try:
        effective_workflow = flags.get("workflow", session.get("workflow", "general"))
        answer, tokens, metadata = await run_agent(
            user_input=question,
            username=f"slack_{user_name}",
            workflow=effective_workflow,
            llm_mode=llm_mode,
            rag_mode=rag_mode,
        )
    except Exception as e:
        await send_slack_message(
            f"⚠️ Agent error: {e}",
            channel=channel,
            thread_ts=thread_ts,
        )
        return f"error: {e}"

    # ── Format and send the answer ────────────────────────────────────────────
    provider = metadata.get("llm_provider", llm_mode)
    rag_used = metadata.get("rag_mode_used", rag_mode)
    tok = tokens
    cost = round(tok * 0.000001, 5)

    full_reply = (
        f"*Answer for <@{user_id}>:*\n\n"
        f"{answer}\n\n"
        f"─────────────────\n"
        f"{'💻' if provider=='local' else '☁️'} `{provider}` · "
        f"{'🧠' if rag_used=='agentic' else '⚡'} `{rag_used} RAG` · "
        f"🔢 `{tok:,} tok` · 💰 `${cost}`"
    )

    # Reply in-thread — keeps the channel tidy
    await send_slack_message(full_reply, channel=channel, thread_ts=thread_ts)
    return answer
