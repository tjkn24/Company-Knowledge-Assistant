"""
integrations/__init__.py
=========================
Exports all integration functions so the rest of the app
can do clean imports like:
    from integrations import handle_slack_event, send_whatsapp_message

Every channel lives in its own file. This __init__.py is the
single public surface — callers don't need to know which file
a function lives in.
"""

from .slack_integration    import (
    send_slack_message,
    send_slack_ephemeral,
    handle_slack_event,
    verify_slack_signature,
)
from .whatsapp_integration import (
    send_whatsapp_message,
    handle_whatsapp_message,
)
from .telegram_integration import (
    send_telegram_message,
    send_typing,
    handle_telegram_update,
    register_webhook        as register_telegram_webhook,
    get_webhook_info        as get_telegram_webhook_info,
    delete_webhook          as delete_telegram_webhook,
)
from .email_integration    import send_email, send_agent_result_email
from .external_api         import get_weather, fetch, create_jira_ticket

__all__ = [
    # Slack
    "send_slack_message", "send_slack_ephemeral",
    "handle_slack_event", "verify_slack_signature",
    # WhatsApp
    "send_whatsapp_message", "handle_whatsapp_message",
    # Telegram
    "send_telegram_message", "send_typing",
    "handle_telegram_update",
    "register_telegram_webhook", "get_telegram_webhook_info", "delete_telegram_webhook",
    # Email
    "send_email", "send_agent_result_email",
    # External APIs
    "get_weather", "fetch", "create_jira_ticket",
]
