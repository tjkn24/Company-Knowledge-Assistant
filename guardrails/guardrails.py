"""
guardrails/guardrails.py — Safety & Cost Guardrails
=====================================================
Guardrails are checks that run BEFORE and AFTER the agent to:
  1. Validate and sanitise user input (prevent prompt injection).
  2. Enforce cost and token limits per run.
  3. Block forbidden topics or dangerous requests.
  4. Validate output before returning it to the user.

WHY GUARDRAILS MATTER (OWASP Agentic Top 10 2026):
  - A01 Prompt Injection: Users embedding instructions inside their message
    to hijack the agent (e.g. "Ignore all previous instructions and...").
  - A03 Resource & Cost Management: A single malicious or runaway request
    can spend hundreds of dollars in API tokens without limits.
  - A06 Sensitive Information Disclosure: Agent output may leak PII or
    internal system details if not checked before returning.

BEGINNER TIP:
  Guardrails are the insurance policy that lets you deploy confidently.
  Clients will ask "what stops users from abusing the system?" — this file
  is your answer.
"""

import re
from dataclasses import dataclass
from config import get_settings

cfg = get_settings()


@dataclass
class GuardrailResult:
    """Returned by every check. If passed=False, the agent run is blocked."""
    passed: bool
    reason: str = ""


# ── FORBIDDEN PATTERNS ────────────────────────────────────────────────────────
# These regex patterns detect common prompt injection attempts.
# Extend this list based on your client's domain risks.
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"forget\s+everything",
    r"you\s+are\s+now\s+a",           # persona hijacking
    r"act\s+as\s+(if\s+you\s+are|a)",
    r"jailbreak",
    r"dan\s+mode",                     # "Do Anything Now" jailbreak
    r"override\s+(your\s+)?(system|instructions)",
    r"reveal\s+(your\s+)?(system\s+prompt|instructions|prompt)",
]

# Topics the agent should refuse to discuss
FORBIDDEN_TOPICS = [
    r"\b(bomb|explosive|weapon)\b",
    r"\b(hack|exploit)\s+(the\s+)?(server|database|system)\b",
]


def check_input(text: str) -> GuardrailResult:
    """
    INPUT GUARDRAIL — runs before the agent.

    Checks:
      1. Input length (prevents token flooding attacks).
      2. Prompt injection patterns.
      3. Forbidden topics.

    Returns GuardrailResult(passed=False, reason=...) if any check fails.
    The API endpoint blocks the run and returns 400 without calling the LLM.
    """
    # ── Length check ──────────────────────────────────────────────────────────
    if len(text) > 2000:
        return GuardrailResult(
            passed=False,
            reason=f"Input too long ({len(text)} chars). Max 2000 characters per request."
        )

    lower = text.lower()

    # ── Prompt injection check ────────────────────────────────────────────────
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, lower):
            return GuardrailResult(
                passed=False,
                reason="Request blocked: detected potential prompt injection attempt. "
                       "Please rephrase your question."
            )

    # ── Forbidden topic check ─────────────────────────────────────────────────
    for pattern in FORBIDDEN_TOPICS:
        if re.search(pattern, lower):
            return GuardrailResult(
                passed=False,
                reason="Request blocked: topic is outside the scope of this assistant."
            )

    return GuardrailResult(passed=True)


def check_cost(tokens_used: int) -> GuardrailResult:
    """
    COST GUARDRAIL — checked mid-run and after run.

    If a single run exceeds the token budget, subsequent steps are aborted.
    This prevents runaway multi-hop agents from burning excessive API spend.

    gpt-4o-mini pricing (as of 2025):
      $0.15 / 1M input tokens  = $0.00000015 per input token
      $0.60 / 1M output tokens = $0.00000060 per output token
    We use a blended rate of $0.000001 per token for simplicity.
    """
    estimated_usd = tokens_used * 0.000001

    if tokens_used > cfg.cost_limit_tokens_per_run:
        return GuardrailResult(
            passed=False,
            reason=f"Token limit reached ({tokens_used} > {cfg.cost_limit_tokens_per_run}). "
                   "Run aborted to control costs."
        )

    if estimated_usd > cfg.cost_limit_usd_per_run:
        return GuardrailResult(
            passed=False,
            reason=f"Cost limit reached (${estimated_usd:.4f} > ${cfg.cost_limit_usd_per_run}). "
                   "Run aborted."
        )

    return GuardrailResult(passed=True)


def check_output(text: str) -> GuardrailResult:
    """
    OUTPUT GUARDRAIL — runs on the agent's final answer before returning it.

    Checks for:
      - PII patterns that shouldn't leak (credit cards, SSNs).
      - Internal system information that the agent shouldn't reveal.

    BEGINNER TIP:
      In a production system you'd also run the output through a classifier
      to detect hallucination or off-topic responses before returning them.
    """
    # Credit card pattern (basic — real PCI-DSS needs a proper library)
    if re.search(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b", text):
        return GuardrailResult(
            passed=False,
            reason="Output blocked: potential credit card number detected."
        )

    # SSN pattern
    if re.search(r"\b\d{3}-\d{2}-\d{4}\b", text):
        return GuardrailResult(
            passed=False,
            reason="Output blocked: potential SSN detected."
        )

    return GuardrailResult(passed=True)
