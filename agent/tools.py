"""
agent/tools.py — All Agent Tools
==================================
Every @tool-decorated function the agent can call lives here.

TOOLS IN THIS APP:
  retrieve_from_knowledge_base  — RAG retrieval (FAISS vector search)
  get_weather                   — live weather via Open-Meteo (free, no key)
  send_email                    — send email via SMTP
  send_slack_message_tool       — post to a Slack channel
  create_jira_ticket            — create a Jira issue
  calculator                    — safe math expression evaluator
  review_code_security          — OWASP security review of submitted code
  fetch_github_file             — fetch a file from a public GitHub repo
  review_github_repo_security   — full OWASP review of a GitHub repo's Python files

TOOL SELECTION REMINDER:
  The LLM reads each tool's docstring to decide which to call.
  Clear docstrings → correct tool selection.
  Vague docstrings → wrong tool called → bad answers → unhappy clients.
"""

from typing import Annotated
from langchain_core.tools import tool
from langchain_core.vectorstores import VectorStoreRetriever
from langgraph.prebuilt import InjectedState

# ── Retriever injection ───────────────────────────────────────────────────────
_retriever: VectorStoreRetriever | None = None


def set_retriever(r: VectorStoreRetriever):
    global _retriever
    _retriever = r


# ── Existing tools (unchanged) ────────────────────────────────────────────────


@tool
async def retrieve_from_knowledge_base(
    query: str, state: Annotated[dict, InjectedState]
) -> str:
    """
    Search the internal knowledge base and return the most relevant passages.
    Use this tool FIRST for any question about company policies, product
    information, technical documentation, or any proprietary internal topic.
    Do NOT use for general knowledge or math.

    Args:
        query: A short, focused search phrase. e.g. "annual leave entitlement"
    """
    if _retriever is None:
        return "ERROR: Retriever not initialised."

    mode = state.get("rag_mode_used", "standard")
    print(f"  [Tool] retrieve_from_knowledge_base('{query}') [mode={mode}]")

    if mode == "agentic":
        # Use the smarter, multi-step retrieval loop if requested
        from rag.rag_service import agentic_rag_answer

        return await agentic_rag_answer(query, _retriever)

    # Default to standard similarity search
    docs = _retriever.invoke(query)
    if not docs:
        return "No relevant documents found. Try rephrasing."
    parts = []
    for i, doc in enumerate(docs, 1):
        src = doc.metadata.get("source", "unknown")
        parts.append(f"--- Chunk {i} (source: {src}) ---\n{doc.page_content.strip()}")
    return "\n\n".join(parts)


@tool
async def get_weather(city: str) -> str:
    """
    Fetch the current weather for a given city.
    Use when the user asks about weather, temperature, or conditions.

    Args:
        city: City name in English. e.g. "Jakarta", "Singapore", "London"
    """
    print(f"  [Tool] get_weather('{city}')")
    from integrations.external_api import get_weather as _get_weather

    result = await _get_weather(city)
    if "error" in result:
        return f"Could not get weather for {city}: {result['error']}"
    return (
        f"Weather in {result['city']}: "
        f"{result['temperature_c']}°C, "
        f"Wind {result['windspeed_kmh']} km/h, "
        f"{result['condition']}"
    )


@tool
async def send_email(to: str, subject: str, body: str) -> str:
    """
    Send an email to a given address with the specified subject and body.
    Use when the user explicitly asks to email results or notify someone.

    Args:
        to:      Recipient email address. e.g. "user@example.com"
        subject: Email subject line.
        body:    Plain text email body.
    """
    print(f"  [Tool] send_email(to='{to}')")
    from integrations.email_integration import send_email as _send_email

    success = await _send_email(to, subject, body)
    return (
        "Email sent successfully."
        if success
        else "Email send failed — check SMTP config."
    )


@tool
async def send_slack_message_tool(message: str, channel: str = "") -> str:
    """
    Post a message to a Slack channel.
    Use when the user asks to notify a channel or post an update.

    Args:
        message: The text to post.
        channel: Slack channel name e.g. #general. Uses default if not specified.
    """
    print(f"  [Tool] send_slack_message(channel='{channel or 'default'}')")
    from integrations.slack_integration import send_slack_message

    success = await send_slack_message(message, channel)
    return (
        "Slack message posted."
        if success
        else "Slack send failed — check SLACK_BOT_TOKEN."
    )


@tool
async def create_jira_ticket(summary: str, description: str) -> str:
    """
    Create a Jira issue with the given summary and description.
    Use when the user asks to log a bug, create a ticket, or triage a request.

    Args:
        summary:     Short one-line issue title.
        description: Detailed description of the issue.
    """
    print(f"  [Tool] create_jira_ticket(summary='{summary[:50]}')")
    from integrations.external_api import create_jira_ticket as _create

    result = await _create(summary, description)
    if result.get("stub"):
        return result["message"]
    return f"Jira ticket created: {result.get('key', 'unknown')}"


@tool
def calculator(expression: str) -> str:
    """
    Evaluate a mathematical expression and return the result.
    Use for any arithmetic calculation.

    Args:
        expression: A safe math expression. e.g. "2500 * 0.15" or "(100 + 200) / 3"
    """
    print(f"  [Tool] calculator('{expression}')")
    try:
        import ast
        import operator

        # Map AST nodes to safe operators
        safe_operators = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv,
            # ast.Pow is removed to prevent CPU exhaustion DoS attacks (e.g. 999**999)
            ast.USub: operator.neg,
        }

        def eval_node(node):
            # ast.Constant is preferred in Python 3.8+
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                return node.value
            # Fallback for older python versions
            elif isinstance(node, ast.Num):
                return node.n
            elif isinstance(node, ast.BinOp):
                return safe_operators[type(node.op)](
                    eval_node(node.left), eval_node(node.right)
                )
            elif isinstance(node, ast.UnaryOp):
                return safe_operators[type(node.op)](eval_node(node.operand))
            elif isinstance(node, ast.Expression):
                return eval_node(node.body)
            raise TypeError(f"Unsupported syntax: {type(node)}")

        tree = ast.parse(expression, mode="eval")
        result = eval_node(tree)
        return f"Result: {result}"
    except Exception as e:
        return f"Error: Could not evaluate math expression. {e}"


# ── NEW: Security Review Tools ────────────────────────────────────────────────


@tool
def review_code_security(code: str, filename: str = "submitted_code") -> str:
    """
    Perform an OWASP-aligned static security review on submitted source code
    or configuration. Checks against:
      - OWASP LLM Top 10 (2025) — prompt injection, excessive agency, PII, etc.
      - OWASP Agentic AI Top 10 (2026) — unsafe tool execution, context hijacking
      - OWASP API Security Top 10 — auth, rate limiting, input validation
      - General security — hardcoded secrets, unsafe eval, shell injection

    Use this tool when the user pastes code, config, or any text they want
    reviewed for security issues. Returns a structured Markdown report with
    findings, severity ratings, OWASP IDs, and remediation steps.

    Args:
        code:     The full source code or config text to review.
                  Can be Python, YAML, JSON, .env, docker-compose, etc.
        filename: The name of the file being reviewed (for the report header).
                  e.g. "config.py", "docker-compose.yml", "agent/graph.py"
    """
    print(f"  [Tool] review_code_security(filename='{filename}', chars={len(code)})")

    # Import here to avoid circular imports at module load time
    from security.owasp_reviewer import analyze_code, format_report, get_severity_score

    # Run the static scan
    findings = analyze_code(code, filename)

    # Get the overall risk score
    label, score = get_severity_score(findings)

    # Build the report
    report = format_report(findings, filename, include_remediation=True)

    # Prepend the risk score summary
    header = (
        f"*Overall Risk: {label}* (score {score}/100)\n"
        f"*File reviewed:* `{filename}` ({len(code):,} chars)\n\n"
    )

    return header + report


@tool
async def fetch_github_file(github_url: str) -> str:
    """
    Fetch the raw content of a single file from a public GitHub repository.
    Use this when the user provides a GitHub URL to a specific file they
    want reviewed for security.

    Supported URL formats:
      https://github.com/owner/repo/blob/main/path/to/file.py
      https://raw.githubusercontent.com/owner/repo/main/path/to/file.py

    Args:
        github_url: The GitHub URL of the file to fetch.
    """
    print(f"  [Tool] fetch_github_file('{github_url[:80]}')")

    import httpx, re

    # Convert github.com/blob URL to raw.githubusercontent.com URL
    raw_url = github_url
    blob_pattern = re.compile(r"https://github\.com/([^/]+)/([^/]+)/blob/(.+)")
    match = blob_pattern.match(github_url)
    if match:
        owner, repo, path = match.groups()
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{path}"

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(raw_url)
        if resp.status_code != 200:
            return f"Error: could not fetch file (HTTP {resp.status_code}). Is the repo public?"
        content = resp.text
        if len(content) > 50_000:
            content = content[:50_000] + "\n\n[...truncated at 50,000 chars...]"
        return content
    except Exception as e:
        return f"Error fetching file: {e}"


@tool
async def review_github_repo_security(repo_url: str, max_files: int = 5) -> str:
    """
    Fetch and review multiple Python files from a public GitHub repository
    for OWASP security issues. Checks the most important files (agent code,
    routes, config, security modules).

    Use this when the user provides a GitHub repo URL and wants a full
    security review of their project.

    Args:
        repo_url:  GitHub repo URL. e.g. https://github.com/owner/repo
        max_files: Maximum number of files to review (default 5, max 10).
                   Keeps token usage reasonable.
    """
    print(f"  [Tool] review_github_repo_security('{repo_url}')")

    import httpx, re
    from security.owasp_reviewer import (
        analyze_code,
        format_report,
        get_severity_score,
        Finding,
    )

    # Extract owner/repo from URL
    match = re.match(r"https://github\.com/([^/]+)/([^/?#]+)", repo_url)
    if not match:
        return "Invalid GitHub URL. Format: https://github.com/owner/repo"
    owner, repo = match.groups()
    repo = repo.rstrip("/")

    # Files to prioritise for security review (in order of importance)
    priority_files = [
        "config.py",
        "agent/graph.py",
        "agent/tools.py",
        "api/routes.py",
        "api/main.py",
        "security/threat_model.py",
        "auth/auth.py",
        "docker-compose.yml",
        ".env.example",
        "requirements.txt",
        "Dockerfile",
        "docker/Dockerfile.agent",
    ]

    all_findings: list[Finding] = []
    reviewed_files = []
    errors = []

    max_files = min(max_files, 10)  # hard cap

    async with httpx.AsyncClient(timeout=15) as client:
        for filepath in priority_files:
            if len(reviewed_files) >= max_files:
                break
            raw_url = (
                f"https://raw.githubusercontent.com/{owner}/{repo}/main/{filepath}"
            )
            try:
                resp = await client.get(raw_url)
                if resp.status_code == 404:
                    # Try 'master' branch
                    raw_url = raw_url.replace("/main/", "/master/")
                    resp = await client.get(raw_url)
                if resp.status_code != 200:
                    continue  # file doesn't exist in this repo, skip silently

                content = resp.text[:30_000]  # cap per file
                findings = analyze_code(content, filepath)
                all_findings.extend(findings)
                reviewed_files.append(f"{filepath} ({len(findings)} issues)")

            except Exception as e:
                errors.append(f"{filepath}: {e}")

    if not reviewed_files:
        return (
            f"Could not fetch any files from {repo_url}. "
            "Make sure the repository is public and the URL is correct."
        )

    # Aggregate report
    label, score = get_severity_score(all_findings)

    # Sort all findings by severity
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda f: order.get(f.severity, 5))

    # Build summary header
    lines = [
        f"🔒 *Repo Security Review — {owner}/{repo}*",
        f"*Overall Risk: {label}* (score {score}/100)",
        f"*Files reviewed:* {len(reviewed_files)}",
        "",
        "*Files scanned:*",
    ]
    for f in reviewed_files:
        lines.append(f"  • {f}")
    lines += ["", "─────────────────────────────", ""]

    # Show top findings (cap at 15 to avoid flooding the chat)
    shown = all_findings[:15]
    severity_icons = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
        "INFO": "⚪",
    }
    for finding in shown:
        icon = severity_icons.get(finding.severity, "•")
        lines += [
            f"{icon} *[{finding.owasp_id}] {finding.title}*",
            f"`{finding.severity}` · {finding.framework} · ~line {finding.line_hint}",
            f"Pattern: `{finding.evidence[:80]}`",
            f"*Fix:* {finding.remediation}",
            "",
        ]

    if len(all_findings) > 15:
        lines.append(
            f"_...and {len(all_findings)-15} more findings. Request a full report for details._"
        )

    lines += [
        "─────────────────────────────",
        "_Frameworks: OWASP LLM Top 10 · OWASP Agentic AI Top 10 · OWASP API Security Top 10_",
    ]

    return "\n".join(lines)


# ── Tool registry ─────────────────────────────────────────────────────────────
ALL_TOOLS = [
    retrieve_from_knowledge_base,
    get_weather,
    send_email,
    send_slack_message_tool,
    create_jira_ticket,
    calculator,
    review_code_security,
    fetch_github_file,
    review_github_repo_security,
]

TOOL_MAP = {t.name: t for t in ALL_TOOLS}
