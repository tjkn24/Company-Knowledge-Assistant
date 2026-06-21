"""
integrations/email_integration.py — Email via SMTP
====================================================
Sends emails using Python's built-in smtplib via async wrapper.
Works with Gmail, SendGrid, Mailgun, or any SMTP provider.

GMAIL SETUP:
  1. Enable 2-Factor Authentication on your Google account.
  2. Go to Google Account → Security → App Passwords.
  3. Generate a password for "Mail" → copy it to SMTP_PASSWORD in .env.
  4. Set SMTP_USER to your Gmail address.
  Note: Use your App Password, NOT your regular Gmail password.

PRODUCTION ALTERNATIVE:
  For high-volume email, use SendGrid or Mailgun instead of Gmail.
  They have better deliverability, analytics, and bounce handling.
  Only the SMTP host/port/credentials change — this code stays the same.
"""

import smtplib
import asyncio
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from config import get_settings
from monitoring import log_integration

cfg = get_settings()


def _send_email_sync(to: str, subject: str, body: str, html: bool = False) -> bool:
    """
    Synchronous SMTP send (runs in a thread via asyncio.to_thread).

    WHY SYNC IN AN ASYNC APP?
      smtplib is synchronous. To avoid blocking the FastAPI event loop,
      we run it in a thread pool using asyncio.to_thread().
      This is the standard pattern for using sync libraries in async code.
    """
    if not cfg.smtp_user or not cfg.smtp_password:
        print("[Email] SMTP credentials not configured — skipping send.")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = cfg.email_from or cfg.smtp_user
    msg["To"]      = to

    content_type = "html" if html else "plain"
    msg.attach(MIMEText(body, content_type))

    try:
        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port) as server:
            server.ehlo()
            server.starttls()                              # encrypt the connection
            server.login(cfg.smtp_user, cfg.smtp_password)
            server.sendmail(cfg.email_from or cfg.smtp_user, to, msg.as_string())
        return True
    except Exception as e:
        print(f"[Email] Send failed: {e}")
        return False


async def send_email(to: str, subject: str, body: str, html: bool = False) -> bool:
    """
    Async wrapper — runs smtplib in a thread so it doesn't block FastAPI.

    Args:
        to:      Recipient email address.
        subject: Email subject line.
        body:    Email body (plain text or HTML).
        html:    If True, body is treated as HTML.
    """
    success = await asyncio.to_thread(_send_email_sync, to, subject, body, html)
    log_integration("email", "send", to, success)
    return success


async def send_agent_result_email(to: str, question: str, answer: str) -> bool:
    """
    Convenience function: send a nicely formatted email with the agent's answer.
    Called by the 'email_result' workflow tool.
    """
    subject = f"Agent Answer: {question[:60]}..."
    body = f"""
    <h2>Your Question</h2>
    <p>{question}</p>

    <h2>Agent Answer</h2>
    <p>{answer.replace(chr(10), '<br>')}</p>

    <hr>
    <small>Sent by Production Agent</small>
    """
    return await send_email(to, subject, body, html=True)
