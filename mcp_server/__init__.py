"""mcp_server/ — MCP (Model Context Protocol) layer for the Agent Platform.

Exposes a subset of the platform's capabilities as MCP tools so that any
MCP-compatible client (Claude Desktop, Claude Code, other agents) can call
them directly — without going through the Telegram/WhatsApp/Slack channels
or the REST API's JWT auth.

See mcp_server/server.py for the tool definitions and mcp_server/README.md
for setup instructions.
"""
