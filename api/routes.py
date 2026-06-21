"""
api/routes.py — All HTTP Endpoints
=====================================
Defines every URL the application responds to.

ENDPOINT GROUPS:
  /auth/*            — register + login (no auth required)
  /agent/*           — run the agent (JWT required)
  /n8n/trigger       — receive triggers from n8n traffic manager (shared secret)
  /webhooks/telegram — Telegram bot webhook (HMAC secret header)
  /webhooks/slack    — Slack slash commands (HMAC-SHA256 signature)
  /webhooks/whatsapp — WhatsApp via Twilio (form data)
  /admin/*           — usage stats, security log, recent runs (JWT required)
  /health            — liveness check (no auth)
  /metrics           — Prometheus scrape (no auth, firewall in production)

SECURITY PIPELINE on /agent/run (in order):
  1. RateLimiter            (LLM10 — max 20 req/min per user)
  2. PromptInjectionGuard   (LLM01 — 30+ patterns)
  3. Input length check     (Agentic-A03 — max 2000 chars)
  4. JWT auth               (identity verification)
  5. Agent runs             (internal: step limit, cost guard, tool validation)
  6. PIIRedactor on output  (LLM08 — credit cards, SSNs, API keys)
  7. Audit log write

WEBHOOK CHANNELS:
  Each channel verifies authenticity BEFORE running the agent:
  - Telegram: X-Telegram-Bot-Api-Secret-Token header
  - Slack:    HMAC-SHA256 signature of the request body
  - WhatsApp: Twilio sender (body contains From number)
  - n8n:      X-N8N-Secret header (shared secret)
"""

import time
import hmac
from datetime import datetime

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Request,
    Header,
    status,
)
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional, Literal

from auth import hash_password, verify_password, create_access_token, get_current_user
from database import get_db, User, AgentRun, AuditLog
from agent import run_agent
from monitoring import RunTracker, get_metrics, log_integration, guardrail_blocks_total
from workflows import WORKFLOWS
from integrations import (
    handle_slack_event,
    handle_whatsapp_message,
    verify_slack_signature,
    handle_telegram_update,
    register_telegram_webhook,
    get_telegram_webhook_info,
    delete_telegram_webhook,
)
from security import PromptInjectionGuard, RateLimiter, PIIRedactor, SecurityAuditLogger
from config import get_settings

cfg = get_settings()
router = APIRouter()

# One rate limiter instance shared across all requests in this process.
# In a multi-process deployment, move this to Redis.
_rate_limiter = RateLimiter()


# ══════════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════════


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/auth/register", tags=["Auth"])
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """
    Create a new user account.
    Password is hashed with bcrypt (work factor 12) before storage.
    Never stored in plaintext — even if the database is stolen.
    """
    existing = await db.execute(select(User).where(User.username == req.username))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already taken.")
    user = User(
        username=req.username,
        email=req.email,
        hashed_pw=hash_password(req.password),
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return {"message": "User created.", "user_id": user.id}


@router.post("/auth/login", tags=["Auth"])
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    """
    Verify credentials and return a JWT token.
    Include this token in all subsequent requests:
        Authorization: Bearer <token>
    """
    result = await db.execute(select(User).where(User.username == req.username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(req.password, user.hashed_pw):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    token = create_access_token(user.id, user.username)
    return {"access_token": token, "token_type": "bearer"}


# ══════════════════════════════════════════════════════════════════════════════
# AGENT (JWT-authenticated REST endpoint)
# ══════════════════════════════════════════════════════════════════════════════


class AgentRequest(BaseModel):
    message: str
    workflow: str = "general"
    # Optional per-request overrides — if omitted, .env defaults are used
    llm_mode: Optional[Literal["local", "cloud", "auto"]] = None
    rag_mode: Optional[Literal["standard", "agentic", "auto"]] = None


@router.post("/agent/run", tags=["Agent"])
async def agent_run(
    req: AgentRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Run the AI agent. Requires JWT in Authorization header.

    FULL SECURITY PIPELINE runs on every call (see module docstring).

    EXAMPLE:
        POST /agent/run
        Authorization: Bearer <token>
        {
          "message":  "What is the annual leave policy?",
          "workflow": "support",
          "llm_mode": "local",
          "rag_mode": "agentic"
        }
    """
    client_ip = request.client.host if request.client else "unknown"

    # ── Guard 1: Rate limit ───────────────────────────────────────────────────
    rate_check = _rate_limiter.check(str(user.id))
    if not rate_check.passed:
        guardrail_blocks_total.labels(stage="rate_limit").inc()
        db.add(
            AuditLog(
                actor=user.username,
                action="rate_limit_block",
                target=client_ip,
                detail=rate_check.reason,
                success=False,
            )
        )
        raise HTTPException(status_code=429, detail=rate_check.reason)

    # ── Guard 3: Input length ─────────────────────────────────────────────────
    if len(req.message) > cfg.max_input_length:
        guardrail_blocks_total.labels(stage="input_length").inc()
        raise HTTPException(
            status_code=400,
            detail=f"Input too long ({len(req.message)} chars). Max {cfg.max_input_length}.",
        )

    # ── Create DB record before running (captures crash mid-run) ─────────────
    run_record = AgentRun(
        user_id=user.id, user_input=req.message, workflow=req.workflow
    )
    db.add(run_record)
    await db.flush()

    # ── Run the agent ──────────────────────────────────────────────────────────
    start_ms = int(time.time() * 1000)
    with RunTracker(workflow=req.workflow, username=user.username) as tracker:
        try:
            answer, tokens_used, metadata = await run_agent(
                user_input=req.message,
                username=user.username,
                workflow=req.workflow,
                rag_mode=req.rag_mode,
                llm_mode=req.llm_mode,
            )
            tracker.record_tokens(
                tokens_in=tokens_used // 2, tokens_out=tokens_used // 2
            )
        except Exception as e:
            tracker.set_error(str(e))
            run_record.error = str(e)
            raise HTTPException(status_code=500, detail=f"Agent error: {e}")

    # ── Update DB record ───────────────────────────────────────────────────────
    run_record.agent_output = answer
    run_record.tokens_in = tokens_used // 2
    run_record.tokens_out = tokens_used // 2
    run_record.cost_usd = tokens_used * 0.000001
    run_record.duration_ms = int(time.time() * 1000) - start_ms

    return {
        "answer": answer,
        "workflow": req.workflow,
        "llm_provider": metadata.get("llm_provider", "unknown"),
        "rag_mode_used": metadata.get("rag_mode_used", "unknown"),
        "tokens_used": tokens_used,
        "cost_usd": round(tokens_used * 0.000001, 6),
        "duration_ms": run_record.duration_ms,
        "security_events": len(metadata.get("security_events", [])),
    }


@router.get("/agent/workflows", tags=["Agent"])
async def list_workflows(user: User = Depends(get_current_user)):
    """List all available workflows with their names, descriptions, and tools."""
    return [
        {
            "name": w.name,
            "description": w.description,
            "tools": w.allowed_tools or "all",
        }
        for w in WORKFLOWS.values()
    ]


@router.get("/agent/modes", tags=["Agent"])
async def list_modes(user: User = Depends(get_current_user)):
    """Return available LLM and RAG mode options with current server defaults."""
    return {
        "llm_modes": {
            "local": "Ollama on your machine — free, private, no API cost",
            "cloud": "OpenAI GPT-4o-mini — better quality, costs money",
            "auto": "Try local first, fall back to cloud if Ollama is down",
        },
        "rag_modes": {
            "standard": "One retrieval call + one LLM call (fast, cheap)",
            "agentic": "LLM drives the retrieval loop (smarter, more tokens)",
            "auto": f"Agentic for queries >{cfg.rag_auto_threshold_words} words or multi-part",
        },
        "current_defaults": {
            "llm_mode": cfg.llm_provider,
            "rag_mode": cfg.rag_mode,
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# n8n TRAFFIC MANAGER
# ══════════════════════════════════════════════════════════════════════════════


class N8nTriggerRequest(BaseModel):
    """
    Payload shape for messages arriving from n8n.

    n8n acts as the traffic manager — it receives events from ANY external
    source and normalises them into this format before calling the agent.

    source tells the agent and audit log where the message originated.
    user_id is the original identifier from the source channel (e.g. Telegram chat_id).
    """

    message: str
    source: str = "n8n"
    user_id: str = ""
    workflow: str = "general"
    llm_mode: Optional[Literal["local", "cloud", "auto"]] = None
    rag_mode: Optional[Literal["standard", "agentic", "auto"]] = None
    metadata: dict = {}


@router.post("/n8n/trigger", tags=["n8n"])
async def n8n_trigger(
    req: N8nTriggerRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_n8n_secret: str = Header(default="", alias="X-N8N-Secret"),
):
    """
    Receive a trigger from n8n and run the agent.

    AUTHENTICATION:
      n8n sends X-N8N-Secret: <value> in every request.
      We verify it matches N8N_WEBHOOK_SECRET from .env.
      If the secret is not set in .env, validation is skipped (dev mode).

    n8n WORKFLOW SETUP:
      In n8n, add an HTTP Request node:
        Method:  POST
        URL:     http://agent:8000/n8n/trigger
        Headers: X-N8N-Secret = {{ $env.N8N_AGENT_SECRET }}
        Body:    { "message": "{{$json.text}}", "source": "telegram", "user_id": "{{$json.chat_id}}" }
    """
    # Verify shared secret — reject requests not from n8n
    if cfg.n8n_webhook_secret:
        if not hmac.compare_digest(x_n8n_secret, cfg.n8n_webhook_secret):
            raise HTTPException(status_code=401, detail="Invalid n8n webhook secret.")

    # ── Added Rate Limiting to n8n ────────────────────────────────────────────
    rate_check = _rate_limiter.check(f"n8n_{req.user_id or 'anon'}")
    if not rate_check.passed:
        return {"error": rate_check.reason, "blocked": True}

    if len(req.message) > cfg.max_input_length:
        return {
            "error": f"Message too long ({len(req.message)} chars)",
            "blocked": True,
        }

    # Build a descriptive username for the audit log
    # e.g. "n8n_telegram_111222333" makes it easy to trace back to origin
    username = f"n8n_{req.source}_{req.user_id or 'anon'}"

    run_record = AgentRun(user_input=req.message, workflow=req.workflow)
    db.add(run_record)
    await db.flush()

    start_ms = int(time.time() * 1000)
    try:
        answer, tokens_used, metadata = await run_agent(
            user_input=req.message,
            username=username,
            workflow=req.workflow,
            rag_mode=req.rag_mode,
            llm_mode=req.llm_mode,
        )
    except Exception as e:
        return {"error": str(e), "source": req.source, "user_id": req.user_id}

    run_record.agent_output = answer
    run_record.tokens_in = tokens_used // 2
    run_record.tokens_out = tokens_used // 2
    run_record.cost_usd = tokens_used * 0.000001
    run_record.duration_ms = int(time.time() * 1000) - start_ms

    # Return the answer to n8n — n8n sends it to the original channel
    return {
        "answer": answer,
        "source": req.source,
        "user_id": req.user_id,
        "llm_provider": metadata.get("llm_provider", "unknown"),
        "rag_mode_used": metadata.get("rag_mode_used", "unknown"),
        "tokens_used": tokens_used,
        "cost_usd": round(tokens_used * 0.000001, 6),
        "duration_ms": run_record.duration_ms,
    }


# ══════════════════════════════════════════════════════════════════════════════
# TELEGRAM WEBHOOK
# ══════════════════════════════════════════════════════════════════════════════

# In-memory set of already-processed update_ids.
# Telegram retries the same update if it doesn't get 200 quickly enough.
# This set prevents the agent from running twice for the same message.
# It holds the last 1000 update IDs (older ones are evicted to save memory).
_seen_update_ids: set[int] = set()
_SEEN_MAX = 1000


@router.post("/webhooks/telegram", tags=["Channels"])
async def telegram_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_telegram_bot_api_secret_token: str = Header(
        default="", alias="X-Telegram-Bot-Api-Secret-Token"
    ),
):
    """
    Receive updates from Telegram Bot API.

    WHY BACKGROUND TASK?
      The agent can take 5–30 seconds to respond (especially with a local
      LLM). Telegram only waits ~10 seconds for a 200 OK before retrying
      the same update. If we run the agent synchronously, slow responses
      cause Telegram to retry, which runs the agent again — producing
      duplicate replies.

      Fix: return 200 immediately so Telegram is satisfied, then process
      the update in the background. The user sees one reply, not many.

    DEDUPLICATION:
      Even with background tasks, network hiccups can occasionally cause
      Telegram to retry before we've finished. _seen_update_ids catches
      any duplicate update_id and skips it.

    DATA FLOW:
      POST /webhooks/telegram
        → verify secret (401 if wrong)
        → deduplicate by update_id
        → return 200 immediately          ← Telegram is satisfied
        → background: handle_telegram_update()
             → security checks
             → run_agent()
             → send_telegram_message()    ← user sees reply
    """
    # ── Auth: verify the request came from Telegram ───────────────────────────
    if cfg.telegram_webhook_secret:
        if not hmac.compare_digest(
            x_telegram_bot_api_secret_token,
            cfg.telegram_webhook_secret,
        ):
            raise HTTPException(
                status_code=401, detail="Invalid Telegram webhook secret."
            )

    update = await request.json()

    # ── Deduplication: skip if we already processed this update ───────────────
    # update_id is a monotonically increasing integer Telegram assigns to each
    # event. If we've seen it before, Telegram is retrying — ignore it.
    update_id = update.get("update_id")
    if update_id is not None:
        if update_id in _seen_update_ids:
            # Already processed — return 200 so Telegram stops retrying
            return {"ok": True, "note": "duplicate skipped"}
        _seen_update_ids.add(update_id)
        # Evict oldest entries if the set grows too large
        if len(_seen_update_ids) > _SEEN_MAX:
            # Remove the smallest (oldest) IDs
            oldest = sorted(_seen_update_ids)[: _SEEN_MAX // 2]
            for uid in oldest:
                _seen_update_ids.discard(uid)

    # ── Return 200 IMMEDIATELY — then process in background ──────────────────
    # BackgroundTasks runs handle_telegram_update() AFTER this function
    # returns the response. Telegram receives 200 in milliseconds.
    # The agent runs in the background without Telegram waiting for it.
    background_tasks.add_task(handle_telegram_update, update)
    return {"ok": True}


@router.post("/webhooks/telegram/setup", tags=["Channels"])
async def setup_telegram_webhook():
    """
    Register our webhook URL with Telegram.
    Call this ONCE after deployment or when your URL changes.
    Requires TELEGRAM_WEBHOOK_URL in .env to be a public HTTPS URL.
    """
    return await register_telegram_webhook()


@router.get("/webhooks/telegram/info", tags=["Channels"])
async def telegram_info():
    """Check the registered Telegram webhook URL and pending update count."""
    return await get_telegram_webhook_info()


@router.post("/webhooks/telegram/delete", tags=["Channels"])
async def telegram_delete_webhook():
    """Remove the Telegram webhook (switch to polling mode — useful for local dev)."""
    return await delete_telegram_webhook()


# ══════════════════════════════════════════════════════════════════════════════
# SLACK WEBHOOK
# ══════════════════════════════════════════════════════════════════════════════


@router.post("/webhooks/slack", tags=["Channels"])
async def slack_webhook(request: Request):
    """
    Receive Slack slash commands (/ask) and event callbacks.

    AUTHENTICATION:
      Slack signs every request with HMAC-SHA256 using your Signing Secret.
      verify_slack_signature() reconstructs the signature and compares.
      Also checks the request timestamp is within 5 minutes (replay protection).

    URL VERIFICATION:
      When you first configure the webhook in Slack, Slack sends a
      challenge request. We return the challenge value to verify ownership.
    """
    body = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")

    if not verify_slack_signature(body, timestamp, signature):
        raise HTTPException(status_code=401, detail="Invalid Slack signature.")

    form = await request.form()
    payload = dict(form)

    # URL verification handshake — required when first setting up the Slack app
    if "challenge" in payload:
        return {"challenge": payload["challenge"]}

    await handle_slack_event(payload)
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# WHATSAPP WEBHOOK
# ══════════════════════════════════════════════════════════════════════════════


@router.post("/webhooks/whatsapp", tags=["Channels"])
async def whatsapp_webhook(request: Request):
    """
    Receive WhatsApp messages from Twilio.

    Twilio POSTs form-encoded data (not JSON) to this URL.
    Response must be TwiML XML — an empty <Response> means 'no auto-reply'
    (we send replies separately via the Twilio REST API).

    TWILIO WEBHOOK SETUP:
      Twilio console → Messaging → Sandbox Settings:
        When a message comes in: https://your-domain.com/webhooks/whatsapp
    """
    form = await request.form()
    payload = dict(form)
    await handle_whatsapp_message(payload)
    # Twilio requires this XML response format — empty = no TwiML auto-reply
    return Response(
        content='<?xml version="1.0" encoding="UTF-8"?><Response></Response>',
        media_type="text/xml",
    )


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN
# ══════════════════════════════════════════════════════════════════════════════


@router.get("/admin/stats", tags=["Admin"])
async def usage_stats(
    user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    """Return aggregate usage statistics for the current user."""
    result = await db.execute(
        select(
            func.count(AgentRun.id).label("total_runs"),
            func.sum(AgentRun.tokens_in + AgentRun.tokens_out).label("total_tokens"),
            func.sum(AgentRun.cost_usd).label("total_cost_usd"),
            func.avg(AgentRun.duration_ms).label("avg_duration_ms"),
        ).where(AgentRun.user_id == user.id)
    )
    row = result.one()
    return {
        "user": user.username,
        "total_runs": row.total_runs or 0,
        "total_tokens": int(row.total_tokens or 0),
        "total_cost_usd": round(float(row.total_cost_usd or 0), 4),
        "avg_duration_ms": int(row.avg_duration_ms or 0),
    }


@router.get("/admin/runs", tags=["Admin"])
async def recent_runs(
    limit: int = 10,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the most recent agent runs for the current user."""
    result = await db.execute(
        select(AgentRun)
        .where(AgentRun.user_id == user.id)
        .order_by(AgentRun.created_at.desc())
        .limit(limit)
    )
    runs = result.scalars().all()
    return [
        {
            "id": r.id,
            "workflow": r.workflow,
            "input": r.user_input[:80],
            "output": (r.agent_output or "")[:80],
            "tokens": (r.tokens_in or 0) + (r.tokens_out or 0),
            "cost_usd": r.cost_usd,
            "duration_ms": r.duration_ms,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in runs
    ]


@router.get("/admin/security", tags=["Admin"])
async def security_overview(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Return recent security events — blocked requests, injection attempts, PII triggers.
    This is your evidence trail for security reviews and client demos.
    """
    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.actor == user.username, AuditLog.success == False)  # noqa: E712
        .order_by(AuditLog.created_at.desc())
        .limit(50)
    )
    events = result.scalars().all()
    return {
        "user": user.username,
        "blocked_count": len(events),
        "recent_blocks": [
            {
                "action": e.action,
                "detail": e.detail,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in events
        ],
        "threat_coverage": [
            "LLM01  — Prompt Injection       (PromptInjectionGuard)",
            "LLM06  — Excessive Agency        (AgencyLimiter + step cap)",
            "LLM08  — PII Disclosure          (PIIRedactor on all outputs)",
            "LLM10  — Model DoS               (RateLimiter, sliding window)",
            "A01    — Unsafe Tool Execution   (ToolCallValidator)",
            "A03    — Resource Exhaustion     (CostGuard: tokens + USD)",
            "A05    — Context Spoofing        (ContextIntegrityCheck)",
            "A07    — Workflow Hijacking      (ToolCallValidator + workflow scope)",
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM
# ══════════════════════════════════════════════════════════════════════════════


@router.get("/health", tags=["System"])
async def health():
    """
    Liveness check for Docker health checks and load balancers.
    Returns 200 OK if the server is running.
    Does NOT check if Ollama or the database is available.
    """
    return {
        "status": "ok",
        "llm_provider": cfg.llm_provider,
        "rag_mode": cfg.rag_mode,
    }


@router.get("/metrics", tags=["System"], include_in_schema=False)
async def prometheus_metrics():
    """Prometheus scrape endpoint. Firewall this in production."""
    data, content_type = get_metrics()
    return Response(content=data, media_type=content_type)
