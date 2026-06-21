"""
monitoring/monitor.py — Metrics, Logging & Cost Tracking
==========================================================
Production agents need observability. Without it you're flying blind:
you don't know which endpoints are slow, how much you're spending on
tokens, or when errors spike.

THREE PILLARS OF OBSERVABILITY:
  1. METRICS  — numbers over time (Prometheus counters/histograms).
                Scraped by Prometheus, displayed in Grafana dashboards.
  2. LOGS     — structured JSON events (structlog).
                Shipped to Datadog, CloudWatch, or Loki.
  3. TRACES   — (not in this app) request flow across microservices (OpenTelemetry).

METRICS EXPOSED (at GET /metrics):
  agent_runs_total           — counter: total runs by workflow and status
  agent_tokens_total         — counter: total tokens consumed
  agent_cost_usd_total       — counter: total estimated spend in USD
  agent_run_duration_seconds — histogram: latency distribution per workflow
  guardrail_blocks_total     — counter: how often guardrails fire

BEGINNER TIP:
  Prometheus scrapes /metrics every 15 seconds. Grafana queries Prometheus
  and shows dashboards. You don't need to set these up to use the app —
  the metrics are still collected and logged even without Prometheus running.
"""

import time
import structlog
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

# ── Structured logger ─────────────────────────────────────────────────────────
# structlog outputs JSON lines — easy to filter in Datadog/CloudWatch.
# Example log line:
#   {"event": "agent_run_complete", "user": "tj", "tokens": 312, "cost_usd": 0.0003}
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger()


# ── Prometheus metrics ────────────────────────────────────────────────────────

agent_runs_total = Counter(
    "agent_runs_total",
    "Total number of agent runs",
    ["workflow", "status"],   # labels allow filtering by workflow name and success/error
)

agent_tokens_total = Counter(
    "agent_tokens_total",
    "Total tokens consumed by the agent",
    ["direction"],            # "in" or "out"
)

agent_cost_usd_total = Counter(
    "agent_cost_usd_total",
    "Total estimated USD cost of all agent runs",
)

agent_run_duration_seconds = Histogram(
    "agent_run_duration_seconds",
    "Agent run duration in seconds",
    ["workflow"],
    buckets=[0.5, 1, 2, 5, 10, 20, 30],  # latency buckets in seconds
)

guardrail_blocks_total = Counter(
    "guardrail_blocks_total",
    "Number of requests blocked by guardrails",
    ["stage"],               # "input" or "output"
)

integration_calls_total = Counter(
    "integration_calls_total",
    "Number of external integration calls",
    ["service", "status"],   # service: slack/email/whatsapp/api; status: ok/error
)


# ── Helper context manager ────────────────────────────────────────────────────

class RunTracker:
    """
    Context manager that automatically records metrics for one agent run.

    Usage:
        with RunTracker(workflow="support", username="tj") as tracker:
            result = run_agent(user_input)
            tracker.record_tokens(tokens_in=200, tokens_out=150)

    On exit it records duration, increments counters, and emits a log line.
    """

    def __init__(self, workflow: str = "general", username: str = "anonymous"):
        self.workflow   = workflow
        self.username   = username
        self.tokens_in  = 0
        self.tokens_out = 0
        self.status     = "ok"
        self._start     = None

    def __enter__(self):
        self._start = time.perf_counter()
        logger.info("agent_run_start", workflow=self.workflow, user=self.username)
        return self

    def record_tokens(self, tokens_in: int, tokens_out: int):
        self.tokens_in  = tokens_in
        self.tokens_out = tokens_out

    def set_error(self, msg: str):
        self.status = "error"
        logger.error("agent_run_error", workflow=self.workflow, user=self.username, error=msg)

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.perf_counter() - self._start
        if exc_type is not None:
            self.status = "error"

        # gpt-4o-mini blended rate: $0.000001 per token
        cost_usd = (self.tokens_in + self.tokens_out) * 0.000001

        # Record Prometheus metrics
        agent_runs_total.labels(workflow=self.workflow, status=self.status).inc()
        agent_tokens_total.labels(direction="in").inc(self.tokens_in)
        agent_tokens_total.labels(direction="out").inc(self.tokens_out)
        agent_cost_usd_total.inc(cost_usd)
        agent_run_duration_seconds.labels(workflow=self.workflow).observe(duration)

        # Emit structured log
        logger.info(
            "agent_run_complete",
            workflow=self.workflow,
            user=self.username,
            status=self.status,
            tokens_in=self.tokens_in,
            tokens_out=self.tokens_out,
            cost_usd=round(cost_usd, 6),
            duration_seconds=round(duration, 3),
        )

        return False  # don't suppress exceptions


def get_metrics() -> tuple[bytes, str]:
    """Return Prometheus metrics in text exposition format for GET /metrics."""
    return generate_latest(), CONTENT_TYPE_LATEST


def log_integration(service: str, action: str, target: str, success: bool, detail: str = ""):
    """Log and record metrics for an external integration call."""
    status = "ok" if success else "error"
    integration_calls_total.labels(service=service, status=status).inc()
    logger.info(
        "integration_call",
        service=service,
        action=action,
        target=target,
        success=success,
        detail=detail,
    )
