"""
database/models.py — Database Tables (ORM Models)
===================================================
SQLAlchemy ORM models define the shape of every table in the database.
We use SQLite by default (no install needed), but swapping to Postgres
only requires changing DATABASE_URL in .env — the models stay identical.

WHAT IS AN ORM?
  Object-Relational Mapper. It lets you work with database rows as Python
  objects instead of writing raw SQL. SQLAlchemy is the industry standard.

TABLES IN THIS APP:
  users        — registered users who can call the API
  sessions     — JWT session log (who logged in, when)
  agent_runs   — every run of the agent: input, output, cost, duration
  audit_log    — every action (for compliance and debugging)
"""

from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Boolean,
    DateTime, Text, ForeignKey
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """All models inherit from this — SQLAlchemy requires one shared Base."""
    pass


class User(Base):
    """
    Registered API users.
    Passwords are stored as bcrypt hashes — NEVER plaintext.
    """
    __tablename__ = "users"

    id           = Column(Integer, primary_key=True, index=True)
    username     = Column(String(64),  unique=True, index=True, nullable=False)
    email        = Column(String(128), unique=True, index=True, nullable=False)
    hashed_pw    = Column(String(256), nullable=False)
    is_active    = Column(Boolean, default=True)
    created_at   = Column(DateTime, default=datetime.utcnow)

    # One user → many agent runs
    runs = relationship("AgentRun", back_populates="user")


class AgentRun(Base):
    """
    One row per call to run_agent().
    Records the input, output, token usage, estimated cost, and duration.
    This is the foundation for cost monitoring and billing.

    MONITORING VALUE:
      - dashboard.py queries this table to build cost/usage charts.
      - If a client's bill is too high, you can trace exactly which
        queries consumed the most tokens.
    """
    __tablename__ = "agent_runs"

    id              = Column(Integer, primary_key=True, index=True)
    user_id         = Column(Integer, ForeignKey("users.id"), nullable=True)
    session_id      = Column(String(64), index=True)     # groups messages in one session
    user_input      = Column(Text, nullable=False)
    agent_output    = Column(Text, nullable=True)
    workflow        = Column(String(64), default="general")  # which workflow was triggered
    tokens_in       = Column(Integer, default=0)
    tokens_out      = Column(Integer, default=0)
    cost_usd        = Column(Float, default=0.0)
    duration_ms     = Column(Integer, default=0)
    guardrail_hit   = Column(Boolean, default=False)     # was a guardrail triggered?
    error           = Column(Text, nullable=True)
    created_at      = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="runs")


class AuditLog(Base):
    """
    Append-only log of significant events.
    Used for compliance, debugging, and security forensics.

    Every integration action (email sent, Slack posted, API called)
    gets an audit entry. This is your evidence trail for client disputes.
    """
    __tablename__ = "audit_log"

    id         = Column(Integer, primary_key=True, index=True)
    actor      = Column(String(64))   # username or "system"
    action     = Column(String(128))  # e.g. "send_email", "slack_post"
    target     = Column(String(256))  # e.g. email address, channel name
    detail     = Column(Text)         # JSON blob of extra context
    success    = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
