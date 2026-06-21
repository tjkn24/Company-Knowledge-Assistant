# n8n Workflow Templates

These JSON files are ready-to-import n8n workflows.

## How to import
1. Open http://localhost:5678
2. Click the top-left menu → Import from file
3. Select one of these JSON files

## Workflows included

### telegram_to_agent.json
Receives Telegram messages via n8n's Telegram Trigger node
and forwards them to the FastAPI agent.

**Flow:** Telegram message → n8n → POST /n8n/trigger → agent reply → Telegram

### whatsapp_to_agent.json
Receives WhatsApp messages via Twilio webhook in n8n
and forwards them to the agent.

### scheduled_report.json
Runs the agent on a schedule (e.g. every morning at 8am)
to generate a daily summary and post it to Slack.

### crm_webhook.json
Receives webhooks from CRM systems (HubSpot, Salesforce, etc.)
and creates a Jira ticket via the agent's jira_triage workflow.

## Environment variables needed in n8n
Set these in n8n's Credentials or environment:
  N8N_AGENT_URL    = http://agent:8000
  N8N_AGENT_SECRET = (same as N8N_WEBHOOK_SECRET in .env)
