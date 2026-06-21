"""
workflows/workflows.py — Named Workflow Router
===============================================
A "workflow" is a named, pre-configured agent run for a specific use case.
Each workflow defines:
  - system_prompt_suffix: extra instructions appended to the base prompt
  - allowed_tools:        which tools this workflow may use (None = all)
  - post_run:             optional async action after every run

WORKFLOWS:
  general          — default: all tools, general assistant
  support          — customer support: RAG-grounded only
  weather_report   — fetches weather, emails result
  slack_notify     — runs agent, auto-posts to Slack
  jira_triage      — analyses ticket, creates Jira issue
  security_review  — NEW: OWASP security review of submitted code

BEGINNER TIP:
  Each workflow is a product you can sell to a client.
  "HR knowledge bot" = support workflow + HR docs in docs/.
  "AI security auditor" = security_review workflow.
  Same codebase, different configuration.
"""

from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class Workflow:
    name:                 str
    description:          str
    system_prompt_suffix: str
    allowed_tools:        Optional[list] = None   # None = all tools
    post_run:             Optional[Callable] = None


# ── Post-run actions ──────────────────────────────────────────────────────────

async def _post_run_slack(user_input: str, agent_output: str, username: str):
    from integrations import send_slack_message
    msg = f"*Workflow result for @{username}*\n*Q:* {user_input}\n*A:* {agent_output}"
    await send_slack_message(msg)


async def _post_run_email(user_input: str, agent_output: str, username: str):
    if "@" in username:
        from integrations import send_agent_result_email
        await send_agent_result_email(username, user_input, agent_output)


# ── Workflow registry ─────────────────────────────────────────────────────────

WORKFLOWS: dict[str, Workflow] = {

    "general": Workflow(
        name="general",
        description="General-purpose assistant with all tools.",
        system_prompt_suffix=(
            "You have access to all tools. Use whichever is most appropriate. "
            "Retrieve from the knowledge base first for domain-specific questions."
        ),
    ),

    "support": Workflow(
        name="support",
        description="Customer support — answers grounded in the knowledge base only.",
        system_prompt_suffix=(
            "You are a customer support assistant. ONLY answer questions using the "
            "knowledge base. If the answer is not in the knowledge base, say: "
            "'I don't have information about that — please contact support@company.com.' "
            "Do NOT use web search or make up answers."
        ),
        allowed_tools=["retrieve_from_knowledge_base"],
    ),

    "weather_report": Workflow(
        name="weather_report",
        description="Fetch current weather and optionally email the result.",
        system_prompt_suffix=(
            "The user wants weather information. Use the get_weather tool to fetch it. "
            "Present the result clearly with temperature, wind speed, and conditions. "
            "If the user provided an email address, use send_email to send them the report."
        ),
        allowed_tools=["get_weather", "send_email"],
    ),

    "slack_notify": Workflow(
        name="slack_notify",
        description="Run the agent and post results to Slack automatically.",
        system_prompt_suffix=(
            "Answer the user's question using any available tool. "
            "Your answer will be automatically posted to Slack after you respond."
        ),
        post_run=_post_run_slack,
    ),

    "jira_triage": Workflow(
        name="jira_triage",
        description="Analyse a support ticket and create a Jira issue.",
        system_prompt_suffix=(
            "You are a support triage assistant. Analyse the ticket, identify the "
            "priority (P1/P2/P3/P4) and category (bug/feature/question/billing), "
            "write a concise Jira-ready summary and description, then use the "
            "create_jira_ticket tool to create the issue."
        ),
        allowed_tools=["retrieve_from_knowledge_base", "create_jira_ticket"],
    ),

    # ── NEW: Security Review Workflow ─────────────────────────────────────────
    "security_review": Workflow(
        name="security_review",
        description=(
            "OWASP-aligned AI security review. Analyses submitted code or a GitHub "
            "repo for LLM Top 10, Agentic AI Top 10, and API Security Top 10 issues."
        ),
        system_prompt_suffix=(
            "You are an expert AI security engineer specialising in agentic AI systems.\n"
            "Your frameworks: OWASP LLM Top 10 (2025), OWASP Agentic AI Top 10 (2026), "
            "OWASP API Security Top 10, MAESTRO, MITRE ATLAS.\n\n"

            "WHEN THE USER SUBMITS CODE (pasted text):\n"
            "  1. Call review_code_security(code=<the code>, filename=<filename if mentioned>)\n"
            "  2. The tool returns a structured static-scan report.\n"
            "  3. ADD your own semantic analysis on top:\n"
            "     - Are there logic-level agency issues the regex missed?\n"
            "     - Does the system prompt architecture look safe?\n"
            "     - Is the tool scope appropriate for the stated use case?\n"
            "  4. Conclude with a PRIORITY FIXES section: top 3 things to fix first.\n\n"

            "WHEN THE USER SUBMITS A GITHUB REPO URL:\n"
            "  1. Call review_github_repo_security(repo_url=<url>)\n"
            "  2. Add semantic observations about the overall architecture.\n"
            "  3. Conclude with a PRIORITY FIXES section.\n\n"

            "WHEN THE USER SUBMITS A GITHUB FILE URL:\n"
            "  1. Call fetch_github_file(github_url=<url>) to get the content.\n"
            "  2. Call review_code_security(code=<fetched content>, filename=<path>)\n"
            "  3. Add semantic analysis and PRIORITY FIXES.\n\n"

            "REPORT FORMAT:\n"
            "  Use the tool output as the base. Add your semantic findings clearly labelled "
            "  as 'Semantic Analysis:' so the user knows which findings are AI-reasoned "
            "  vs statically detected.\n\n"

            "ALWAYS end with:\n"
            "  - An overall risk verdict (CRITICAL/HIGH/MEDIUM/LOW/CLEAN)\n"
            "  - Top 3 priority fixes\n"
            "  - Offer to do a deeper review of any specific file or issue\n\n"

            "TONE: professional, specific, actionable. No vague advice."
        ),
        allowed_tools=[
            "review_code_security",
            "fetch_github_file",
            "review_github_repo_security",
            "retrieve_from_knowledge_base",  # for OWASP knowledge base lookups
            "create_jira_ticket",            # to log findings as tickets
            "send_email",                    # to email the full report
            "send_slack_message_tool",       # to post report to Slack
        ],
    ),
}


def get_workflow(name: str) -> Workflow:
    """Look up a workflow by name. Returns 'general' if not found."""
    return WORKFLOWS.get(name, WORKFLOWS["general"])
