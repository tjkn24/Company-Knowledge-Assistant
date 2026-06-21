"""
ui/app.py — Streamlit Ops/Admin Dashboard
===========================================
NOTE: This is NOT the user interface.
      Users interact via Telegram, WhatsApp, and Slack.
      This dashboard is for YOU (the developer/operator) to:
        - Monitor live agent runs, token usage, and costs
        - View security events and blocked requests
        - Test the agent directly (dev/QA only)
        - Manage channel webhook registrations
        - View recent runs across all channels

RUN:
    streamlit run ui/app.py
    (or via Docker Compose — access at http://localhost:8501)

HOW TO USE:
    Bookmark http://localhost:8501 for your daily ops check.
    Share http://localhost:3000 (Grafana) with clients for live metrics.
"""

import requests
import streamlit as st
from datetime import datetime

API_BASE = "http://agent:8000"   # Docker network — change to localhost if running outside Docker

st.set_page_config(
    page_title="Agent Platform — Ops Dashboard",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
.stApp { background: #F0F4F8; }
.metric-card {
    background: white; padding: 16px; border-radius: 10px;
    border: 1px solid #E2E8F0; margin-bottom: 10px;
}
.channel-badge {
    display: inline-block; padding: 3px 10px; border-radius: 999px;
    font-size: 12px; font-weight: 600; margin-right: 6px;
}
.tg  { background: #E3F2FD; color: #1565C0; }
.wa  { background: #E8F5E9; color: #2E7D32; }
.sl  { background: #F3E5F5; color: #6A1B9A; }
.n8n { background: #FFF3E0; color: #E65100; }
.api { background: #ECEFF1; color: #37474F; }
</style>
""", unsafe_allow_html=True)


def api_get(path, token=None):
    h = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r = requests.get(f"{API_BASE}{path}", headers=h, timeout=10)
        return (r.json(), None) if r.ok else (None, r.text)
    except requests.ConnectionError:
        return None, "Backend offline"
    except Exception as e:
        return None, str(e)


def api_post(path, body, token=None):
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    try:
        r = requests.post(f"{API_BASE}{path}", json=body, headers=h, timeout=120)
        return (r.json(), None) if r.ok else (None, r.json().get("detail", r.text))
    except requests.ConnectionError:
        return None, "Backend offline — run: docker compose up"
    except Exception as e:
        return None, str(e)


def init():
    for k, v in {"token": None, "username": None}.items():
        if k not in st.session_state:
            st.session_state[k] = v

init()


# ── Auth ──────────────────────────────────────────────────────────────────────
def auth():
    try:
        ok = requests.get(f"{API_BASE}/health", timeout=3).ok
    except:
        ok = False

    _, col, _ = st.columns([1, 1.2, 1])
    with col:
        st.markdown("## 📊 Agent Platform — Ops Dashboard")
        st.caption("Operator access only. Users interact via Telegram / WhatsApp / Slack.")
        if not ok:
            st.error("**Backend offline.**\n\nRun: `docker compose up`")
            st.stop()
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Sign In", type="primary", use_container_width=True):
            data, err = api_post("/auth/login", {"username": u, "password": p})
            if err:
                st.error(err)
            else:
                st.session_state.token    = data["access_token"]
                st.session_state.username = u
                st.rerun()


# ── Main dashboard ────────────────────────────────────────────────────────────
def dashboard():
    tok = st.session_state.token

    with st.sidebar:
        st.markdown(f"### 📊 Ops Dashboard")
        st.caption(f"Operator: **{st.session_state.username}**")
        if st.button("Sign Out", use_container_width=True):
            st.session_state.clear(); st.rerun()
        st.divider()
        page = st.radio("", [
            "📈 Overview",
            "💬 Test Agent",
            "🔒 Security Events",
            "📜 Recent Runs",
            "🔗 Channel Setup",
        ], label_visibility="collapsed")

    # ── Overview ──────────────────────────────────────────────────────────────
    if page == "📈 Overview":
        st.markdown("## 📈 System Overview")

        health, _ = api_get("/health")
        if health:
            c1, c2, c3 = st.columns(3)
            c1.metric("Status",       "🟢 Online")
            c2.metric("LLM Provider", health.get("llm_provider", "—"))
            c3.metric("RAG Mode",     health.get("rag_mode", "—"))

        st.divider()
        stats, err = api_get("/admin/stats", tok)
        if stats:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Total Runs",    stats.get("total_runs", 0))
            c2.metric("Total Tokens",  f"{stats.get('total_tokens', 0):,}")
            c3.metric("Total Cost",    f"${stats.get('total_cost_usd', 0):.4f}")
            c4.metric("Avg Latency",   f"{stats.get('avg_duration_ms', 0):,} ms")
        elif err:
            st.warning(f"Stats: {err}")

        st.divider()
        st.markdown("### 📡 Active Channels")
        st.markdown("""
| Channel | Direction | How it works |
|---------|-----------|-------------|
| 🔵 **Telegram** | ↔️ Bidirectional | Users message the bot → agent replies in chat |
| 🟢 **WhatsApp** | ↔️ Bidirectional | Users send WhatsApp → agent replies via Twilio |
| 🟣 **Slack** | ↔️ Bidirectional | `/ask` slash command → agent replies in-thread |
| 🟠 **n8n** | → Inbound only | n8n workflows route from any source → agent |
| ⚪ **REST API** | ↔️ Bidirectional | Direct JWT-authenticated API calls |
| 🔒 **Security Review** | Via all channels | `/review <code/url>` on Telegram, `!review` on WhatsApp, `/ask --review` on Slack |
| 📊 **This dashboard** | Admin only | Operator monitoring — NOT user-facing |
""")

        st.info(
            "**Users never see this dashboard.**\n\n"
            "All user interaction happens through Telegram, WhatsApp, and Slack. "
            "This dashboard is for you to monitor the system."
        )

    # ── Test Agent ────────────────────────────────────────────────────────────
    elif page == "💬 Test Agent":
        st.markdown("## 💬 Test Agent (Dev / QA Only)")
        st.info("Use this to test the agent directly. Users interact via Telegram/WhatsApp/Slack.")

        col1, col2, col3 = st.columns(3)
        with col1:
            llm = st.selectbox("LLM Mode",
                ["auto", "local", "cloud"], key="t_llm")
        with col2:
            rag = st.selectbox("RAG Mode",
                ["auto", "standard", "agentic"], key="t_rag")
        with col3:
            wf = st.selectbox("Workflow",
                ["general", "support", "weather_report"], key="t_wf")

        q = st.text_area("Question", placeholder="What is the annual leave policy?", height=80)
        if st.button("Run Agent", type="primary") and q.strip():
            with st.spinner("Running agent..."):
                data, err = api_post(
                    "/agent/run",
                    {"message": q, "workflow": wf, "llm_mode": llm, "rag_mode": rag},
                    token=tok,
                )
            if err:
                st.error(err)
            else:
                st.success("**Answer:**")
                st.write(data.get("answer", ""))
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("LLM Used",    data.get("llm_provider", "—"))
                c2.metric("RAG Used",    data.get("rag_mode_used", "—"))
                c3.metric("Tokens",      data.get("tokens_used", 0))
                c4.metric("Cost",        f"${data.get('cost_usd', 0):.5f}")

    # ── Security Events ───────────────────────────────────────────────────────
    elif page == "🔒 Security Events":
        st.markdown("## 🔒 Security Events")
        data, err = api_get("/admin/security", tok)
        if err:
            st.error(err)
        elif data:
            st.metric("Total blocked requests", data.get("blocked_count", 0))
            st.divider()

            st.markdown("**OWASP Controls Active:**")
            for ctrl in data.get("threat_coverage", []):
                st.markdown(f"✅ {ctrl}")

            st.divider()
            st.markdown("**Recent Blocks:**")
            blocks = data.get("recent_blocks", [])
            if blocks:
                for b in blocks:
                    ts = b.get("created_at", "")
                    st.markdown(
                        f"🚫 `{b['action']}` — {b['detail'][:80]}"
                        f"  <small style='color:grey'>{ts[:19]}</small>",
                        unsafe_allow_html=True,
                    )
            else:
                st.success("No blocked requests yet.")

    # ── Recent Runs ───────────────────────────────────────────────────────────
    elif page == "📜 Recent Runs":
        st.markdown("## 📜 Recent Runs")
        n = st.slider("Show last N runs", 5, 50, 10)
        data, err = api_get(f"/admin/runs?limit={n}", tok)
        if err:
            st.error(err)
        elif data:
            for run in data:
                ts  = (run.get("created_at") or "")[:19]
                wfl = run.get("workflow", "—")
                inp = run.get("input", "")[:60]
                out = run.get("output", "")[:80]
                tok = run.get("tokens", 0)
                ms  = run.get("duration_ms", 0)
                with st.expander(f"`{ts}` · {wfl} · {tok} tok · {ms}ms"):
                    st.markdown(f"**Input:** {inp}")
                    st.markdown(f"**Output:** {out}")

    # ── Channel Setup ─────────────────────────────────────────────────────────
    elif page == "🔗 Channel Setup":
        st.markdown("## 🔗 Channel Setup")

        st.markdown("### 🔵 Telegram")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Register Telegram Webhook", use_container_width=True):
                data, err = api_post("/webhooks/telegram/setup", {}, tok)
                if err:
                    st.error(err)
                else:
                    st.json(data)
        with col2:
            if st.button("Check Telegram Webhook Status", use_container_width=True):
                data, err = api_get("/webhooks/telegram/info")
                if data:
                    st.json(data)
                else:
                    st.error(err)

        st.markdown("**Setup instructions:**")
        st.code("""
1. Message @BotFather → /newbot → copy token
2. Add to .env: TELEGRAM_BOT_TOKEN=123456:ABCdef...
3. Generate: python -c "import secrets; print(secrets.token_hex(16))"
4. Add to .env: TELEGRAM_WEBHOOK_SECRET=<that value>
5. Run ngrok: ngrok http 8000 (or use your production domain)
6. Add to .env: TELEGRAM_WEBHOOK_URL=https://xxxx.ngrok.io
7. Click 'Register Telegram Webhook' above
        """, language="bash")

        st.divider()
        st.markdown("### 🟢 WhatsApp (Twilio)")
        st.markdown("**Setup instructions:**")
        st.code("""
1. Sign up at console.twilio.com
2. Messaging → Try it out → Send a WhatsApp message
3. Scan the QR code with your phone (sandbox activation)
4. Set webhook URL in Twilio console:
     https://your-domain.com/webhooks/whatsapp
5. Add to .env:
     TWILIO_ACCOUNT_SID=ACxxx
     TWILIO_AUTH_TOKEN=xxx
     TWILIO_WHATSAPP_FROM=whatsapp:+14155238886
        """, language="bash")

        st.divider()
        st.markdown("### 🟣 Slack")
        st.markdown("**Setup instructions:**")
        st.code("""
1. https://api.slack.com/apps → Create New App
2. OAuth & Permissions → Bot Token Scopes: chat:write, commands
3. Install to workspace → copy Bot User OAuth Token
4. Add to .env: SLACK_BOT_TOKEN=xoxb-...
5. Basic Information → Signing Secret → add to .env: SLACK_SIGNING_SECRET=...
6. Slash Commands → Create /ask → URL: https://your-domain.com/webhooks/slack
7. Reinstall app after adding scopes
        """, language="bash")

        st.divider()
        st.markdown("### 🟠 n8n")
        st.markdown("**n8n is the traffic manager. Import these workflows:**")
        st.code("""
1. Open http://localhost:5678
2. Menu → Import from file
3. Import: n8n_workflows/telegram_to_agent.json
4. Import: n8n_workflows/whatsapp_to_agent.json
5. Add credential: X-N8N-Secret = (your N8N_WEBHOOK_SECRET from .env)
6. Activate the workflows
        """, language="bash")

        st.info(
            "n8n can receive from ANY source (Telegram, WhatsApp, CRM webhooks, "
            "scheduled jobs, Gmail, etc.) and forward to the agent at /n8n/trigger. "
            "The agent always replies JSON back to n8n, which then sends it to the "
            "right channel."
        )


# ── Entry point ───────────────────────────────────────────────────────────────
if not st.session_state.token:
    auth()
else:
    dashboard()
