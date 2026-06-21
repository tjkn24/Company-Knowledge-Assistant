"""
security/owasp_reviewer.py — AI Security Review Engine
========================================================
This module implements the OWASP-aligned security code review.
It is used by the security_review workflow when a user submits
code or configuration for analysis.

FRAMEWORKS COVERED:
  • OWASP LLM Top 10 (2025)         — for AI/LLM applications
  • OWASP Agentic AI Top 10 (2026)  — for agentic systems specifically
  • OWASP API Security Top 10       — for REST API code
  • OWASP Top 10 (general)          — for general application code
  • MAESTRO                         — for multi-agent threat modelling
  • MITRE ATLAS                     — for adversarial ML

HOW IT WORKS:
  1. The agent receives code/config text from the user (pasted in chat
     or as a file path / GitHub URL).
  2. analyze_code() runs a fast static pattern scan — no LLM needed —
     to find obvious issues immediately.
  3. The results are structured as a list of Finding objects, each with
     an OWASP ID, severity, description, and remediation advice.
  4. The agent's system prompt then instructs it to also reason about
     the code semantically (using the LLM) for deeper issues the regex
     scan can't catch.
  5. The final report is formatted as Markdown and sent back to the user
     on their channel (Telegram/WhatsApp/Slack).

BEGINNER TIP — why both static scan AND LLM analysis?
  Static scan (regex) is fast, deterministic, and catches known bad patterns
  instantly (hardcoded secrets, missing rate limits, etc.).
  LLM analysis catches logic-level issues the regex can't see
  (e.g. "the agent has send_email but never asks the user to confirm").
  Together they cover more ground than either alone.
"""

import re
from dataclasses import dataclass, field
from typing import Literal


Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass
class Finding:
    """
    One security finding from the review.

    owasp_id:    The OWASP or MITRE reference (e.g. "LLM01", "API3:2023").
    framework:   Which framework the ID belongs to.
    severity:    CRITICAL / HIGH / MEDIUM / LOW / INFO.
    title:       Short one-line description.
    description: What the issue is and why it matters.
    evidence:    The specific code snippet or pattern that triggered this.
    remediation: Concrete steps to fix it.
    line_hint:   Approximate line number if detectable (0 = unknown).
    """
    owasp_id:    str
    framework:   str
    severity:    Severity
    title:       str
    description: str
    evidence:    str
    remediation: str
    line_hint:   int = 0


# ── Static scan rules ─────────────────────────────────────────────────────────
# Each rule is:  (regex_pattern, owasp_id, framework, severity, title, description, remediation)
# Patterns are compiled once at import time for speed.

_RULES = [

    # ── LLM / Agentic AI ──────────────────────────────────────────────────────

    (r"f[\"'].*\{.*input.*\}.*[\"']",
     "LLM01", "OWASP LLM Top 10", "HIGH",
     "Potential Prompt Injection — f-string with user input",
     "User input is directly interpolated into an f-string that may become an LLM prompt. "
     "An attacker can break out of the intended prompt and inject arbitrary instructions.",
     "Sanitise user input with PromptInjectionGuard before interpolating. "
     "Use a template that separates the system instruction from user content."),

    (r"(ignore|disregard|forget).*(previous|prior|above|all)\s+instruction",
     "LLM01", "OWASP LLM Top 10", "CRITICAL",
     "Hardcoded Injection Phrase in Prompt",
     "A known prompt injection phrase appears in the source. "
     "This may be a test string left in production, or a backdoor.",
     "Remove this phrase. Never hardcode injection-style language in prompts."),

    (r"(system_prompt|SYSTEM_PROMPT)\s*=\s*[\"']",
     "LLM01", "OWASP LLM Top 10", "MEDIUM",
     "System Prompt Stored in Source Code",
     "The system prompt is hardcoded in source. If this repo is public or the "
     "file leaks, the full instruction set is exposed, making injection easier.",
     "Move system prompts to environment variables or a secure config store. "
     "Never commit prompt content to version control."),

    (r"max_steps\s*=\s*(\d+)",
     "LLM06", "OWASP LLM Top 10", "MEDIUM",
     "Agent Step Limit — verify it is low enough",
     "A max_steps value is set. If this number is very high (>20), "
     "a confused or adversarially prompted agent could loop expensively.",
     "Keep max_steps ≤ 12 for most use cases. Add a CostGuard check on tokens used."),

    (r"(eval|exec)\s*\(",
     "LLM06", "OWASP LLM Top 10 / Agentic-A01", "CRITICAL",
     "Unsafe Code Execution — eval() or exec()",
     "eval() or exec() allows arbitrary code execution. If an LLM agent can "
     "call a tool that uses eval/exec with LLM-generated input, an attacker "
     "can achieve remote code execution through prompt injection.",
     "Replace eval/exec with a safe expression evaluator (e.g. numexpr, sympy). "
     "If code execution is genuinely needed, sandbox it in a subprocess with "
     "restricted permissions and a timeout."),

    (r"(llm|model|chat)\.invoke\(.*input",
     "LLM02", "OWASP LLM Top 10", "MEDIUM",
     "Unvalidated User Input Passed to LLM",
     "User input appears to be passed directly to an LLM invoke call "
     "without visible sanitisation. This risks prompt injection and "
     "insecure output handling.",
     "Wrap in PromptInjectionGuard.check() before passing to the LLM. "
     "Also validate the LLM's output before acting on it."),

    (r"(send_email|smtp|sendmail).*\{.*",
     "LLM06", "OWASP LLM Top 10", "HIGH",
     "Irreversible Action (Email) Without Confirmation Check",
     "An email send call is made with dynamic content. If an LLM agent "
     "can call this tool without explicit user confirmation, it may send "
     "emails the user did not intend (Excessive Agency).",
     "Add an AgencyLimiter pre-run check: verify the user's message "
     "contains an explicit send/email/notify intent verb before allowing "
     "the send_email tool to be called."),

    (r"(delete|drop|truncate|remove)\s*\(",
     "Agentic-A01", "OWASP Agentic AI Top 10", "CRITICAL",
     "Destructive Operation in Agent Scope",
     "A destructive operation (delete/drop/truncate) is callable by the agent. "
     "If an LLM can trigger this through tool use, a single confused or "
     "manipulated run could cause irreversible data loss.",
     "Add this tool to HIGH_RISK_TOOLS in ToolCallValidator. "
     "Require explicit human approval before execution. "
     "Implement soft-delete patterns where possible."),

    # ── API Security ──────────────────────────────────────────────────────────

    (r"@(app|router)\.(get|post|put|delete|patch)\s*\([^\)]+\)\s*\nasync def \w+\([^\)]*\)\s*:",
     "API2:2023", "OWASP API Security Top 10", "MEDIUM",
     "API Endpoint — verify authentication is applied",
     "An API endpoint is defined. Confirm that authentication (JWT, API key) "
     "is enforced via a Depends() or middleware. Unauthenticated endpoints "
     "are the most common API vulnerability.",
     "Add Depends(get_current_user) to any endpoint that accesses user data. "
     "Use FastAPI's security utilities rather than manual token checking."),

    (r"allow_origins\s*=\s*\[.*\*.*\]",
     "API7:2023", "OWASP API Security Top 10", "MEDIUM",
     "CORS Wildcard Origin",
     "CORS is configured with allow_origins=['*']. This allows any website "
     "to make authenticated requests to your API if the user's browser has "
     "a valid session cookie.",
     "In production, replace '*' with your specific frontend domain(s). "
     "Example: allow_origins=['https://yourapp.com']"),

    (r"(timeout\s*=\s*None|timeout\s*=\s*0)",
     "API4:2023", "OWASP API Security Top 10", "MEDIUM",
     "No Timeout on External HTTP Call",
     "An HTTP client call has no timeout (or timeout=0). This means a slow "
     "or unresponsive external service can hang your server indefinitely, "
     "causing a denial of service.",
     "Always set a reasonable timeout: httpx.AsyncClient(timeout=10). "
     "For LLM calls, use OLLAMA_TIMEOUT_SECONDS in config."),

    # ── Secrets & Credentials ─────────────────────────────────────────────────

    (r"(api_key|secret|password|token)\s*=\s*[\"'][A-Za-z0-9+/=_\-]{8,}[\"']",
     "LLM08", "OWASP LLM Top 10", "CRITICAL",
     "Hardcoded Secret / Credential",
     "A secret, API key, or password appears to be hardcoded in source. "
     "If this code is committed to version control (even a private repo), "
     "the secret is permanently exposed in git history.",
     "Move all secrets to environment variables. "
     "Use python-dotenv to load from .env. "
     "Add .env to .gitignore immediately. "
     "Rotate any already-committed secrets."),

    (r"(sk-[A-Za-z0-9]{20,}|xoxb-[A-Za-z0-9\-]{20,}|AIza[A-Za-z0-9_\-]{30,})",
     "LLM08", "OWASP LLM Top 10", "CRITICAL",
     "Live API Key Detected in Code",
     "An active API key (OpenAI, Slack, Google) is present in the source. "
     "This will be exposed to anyone with access to the repository.",
     "Revoke this key immediately at the provider dashboard. "
     "Generate a new key. Store it only in .env or a secrets manager."),

    (r"JWT_SECRET\s*=\s*[\"'][^\"']{1,20}[\"']",
     "LLM08", "OWASP LLM Top 10", "HIGH",
     "Weak or Hardcoded JWT Secret",
     "JWT_SECRET appears to be hardcoded and/or short. Short secrets are "
     "vulnerable to brute-force attacks. Hardcoded secrets are exposed "
     "in source control.",
     "Generate a 64-character random secret: "
     "python -c \"import secrets; print(secrets.token_hex(32))\". "
     "Store in .env, never in code."),

    # ── Input Validation ──────────────────────────────────────────────────────

    (r"request\.body\(\)|request\.json\(\)",
     "API3:2023", "OWASP API Security Top 10", "LOW",
     "Raw Request Body Access — verify input validation",
     "Raw request body is read directly. Ensure the content is validated "
     "with Pydantic models before use. Unvalidated input is a common "
     "injection vector.",
     "Use FastAPI's Pydantic model parameter binding instead of reading "
     "the raw body. Pydantic validates types and lengths automatically."),

    (r"(shell\s*=\s*True|subprocess\.call|os\.system)",
     "Agentic-A01", "OWASP Agentic AI Top 10", "CRITICAL",
     "Shell Command Execution",
     "Code executes shell commands. If an LLM agent can trigger this "
     "through a tool call, prompt injection could lead to arbitrary "
     "command execution on the server.",
     "Never run shell commands with shell=True. "
     "Use subprocess.run with a list of arguments and shell=False. "
     "If the agent needs shell access, sandbox it in a Docker container "
     "with no network access and read-only filesystem."),

    # ── Rate Limiting ─────────────────────────────────────────────────────────

    (r"@(app|router)\.(post|get)\s*\(.*\)\s*\nasync def.*\n(?!.*rate|.*limit|.*RateLimiter)",
     "LLM10", "OWASP LLM Top 10", "MEDIUM",
     "Endpoint May Lack Rate Limiting",
     "An endpoint is defined but no rate limiter reference is visible nearby. "
     "Without rate limiting, a single user can trigger thousands of LLM calls, "
     "running up large API bills (model denial of service).",
     "Add _rate_limiter.check(user_id) at the top of every LLM-calling endpoint. "
     "Use a sliding-window counter keyed by user ID."),

    # ── Logging / Information Disclosure ─────────────────────────────────────

    (r"print\s*\(.*password|logging\.(info|debug).*password",
     "LLM08", "OWASP LLM Top 10", "HIGH",
     "Password or Sensitive Data in Log Output",
     "A password or sensitive value may be printed to stdout or logs. "
     "Log files are often stored unencrypted and accessed by more people "
     "than the application itself.",
     "Never log passwords, tokens, or personal data. "
     "Use structured logging (structlog) and configure log level carefully."),

    (r"(traceback\.print_exc|raise.*Exception.*str\(e\))",
     "API3:2023", "OWASP API Security Top 10", "LOW",
     "Full Exception Detail Exposed to Client",
     "Full exception tracebacks may be returned to API clients. "
     "This leaks internal implementation details (file paths, library versions, "
     "stack frames) that aid attackers in crafting targeted exploits.",
     "Catch exceptions and return a generic error message to clients. "
     "Log the full traceback server-side only. "
     "Use FastAPI's exception handlers to standardise error responses."),
]

# Compile all patterns once at module load
_COMPILED_RULES = [
    (re.compile(pattern, re.IGNORECASE | re.MULTILINE), *rest)
    for pattern, *rest in _RULES
]


# ── Main Analysis Function ────────────────────────────────────────────────────

def analyze_code(code: str, filename: str = "submitted_code") -> list[Finding]:
    """
    Run the static security scan on a code string.

    Goes through every rule, searches for the pattern in the code,
    and records a Finding for each match found.

    This is FAST (milliseconds) because it uses compiled regex, not an LLM.
    The LLM is used separately for semantic analysis (inside the agent).

    Args:
        code:     The source code or config to analyse.
        filename: Name of the file (for display in the report).

    Returns:
        List of Finding objects, sorted by severity (CRITICAL first).
    """
    findings = []

    for compiled, owasp_id, framework, severity, title, description, remediation in _COMPILED_RULES:
        for match in compiled.finditer(code):
            # Find the approximate line number
            line_num = code[:match.start()].count("\n") + 1

            # Truncate the evidence to a readable length
            evidence = match.group(0).strip()[:120]

            findings.append(Finding(
                owasp_id=owasp_id,
                framework=framework,
                severity=severity,
                title=title,
                description=description,
                evidence=evidence,
                remediation=remediation,
                line_hint=line_num,
            ))

    # Deduplicate: same rule firing on the same line is one finding
    seen = set()
    unique = []
    for f in findings:
        key = (f.owasp_id, f.line_hint)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Sort: CRITICAL first, then HIGH, MEDIUM, LOW, INFO
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    unique.sort(key=lambda f: order.get(f.severity, 5))

    return unique


def format_report(
    findings: list[Finding],
    filename: str = "submitted_code",
    include_remediation: bool = True,
) -> str:
    """
    Format the findings list as a Markdown security report.

    The report is structured to be readable in Telegram/WhatsApp/Slack
    (uses bold, code blocks, and emoji compatible with those platforms).

    Args:
        findings:            The list of Finding objects from analyze_code().
        filename:            The name of the file reviewed.
        include_remediation: Whether to include remediation steps (True for full report).

    Returns:
        A Markdown-formatted string ready to send to the user.
    """
    if not findings:
        return (
            f"✅ *Security Review — {filename}*\n\n"
            "No issues detected by the static scanner.\n\n"
            "_Note: Static analysis catches known patterns. "
            "Manual review and LLM semantic analysis may find additional issues._"
        )

    severity_icons = {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🔵",
        "INFO":     "⚪",
    }

    # Summary counts
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    summary_parts = [
        f"{severity_icons.get(sev,'•')} {count} {sev}"
        for sev, count in sorted(counts.items(), key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x[0]))
    ]

    lines = [
        f"🔒 *Security Review — {filename}*",
        f"*{len(findings)} issue(s) found:* {' · '.join(summary_parts)}",
        "",
        "─────────────────────────────",
        "",
    ]

    for i, f in enumerate(findings, 1):
        icon = severity_icons.get(f.severity, "•")
        lines += [
            f"{icon} *[{f.owasp_id}] {f.title}*",
            f"Severity: `{f.severity}` · Framework: {f.framework}",
        ]
        if f.line_hint:
            lines.append(f"Line ~{f.line_hint}: `{f.evidence}`")
        else:
            lines.append(f"Pattern: `{f.evidence}`")

        lines += [
            "",
            f.description,
            "",
        ]

        if include_remediation:
            lines += [
                f"*Fix:* {f.remediation}",
                "",
            ]

        lines.append("─────────────────────────────")
        lines.append("")

    lines += [
        "_Frameworks: OWASP LLM Top 10 · OWASP Agentic AI Top 10 · OWASP API Security Top 10_",
        "_Static scan only. Ask for deeper analysis for semantic/logic-level review._",
    ]

    return "\n".join(lines)


def get_severity_score(findings: list[Finding]) -> tuple[str, int]:
    """
    Return an overall risk label and numeric score (0-100) for the findings.

    Score calculation:
      CRITICAL = 40 pts each (capped)
      HIGH     = 20 pts each
      MEDIUM   = 8 pts each
      LOW      = 2 pts each
    Maximum score = 100 (very high risk).

    Returns:
        (label, score) e.g. ("HIGH RISK", 72)
    """
    weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 2, "INFO": 0}
    raw_score = sum(weights.get(f.severity, 0) for f in findings)
    score = min(raw_score, 100)

    if score >= 80:   label = "CRITICAL RISK"
    elif score >= 50: label = "HIGH RISK"
    elif score >= 25: label = "MEDIUM RISK"
    elif score > 0:   label = "LOW RISK"
    else:             label = "CLEAN"

    return label, score
