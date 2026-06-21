"""
database/db.py — Async Database Engine & Session Factory
==========================================================
Sets up the SQLAlchemy async engine and provides get_db(),
a FastAPI dependency that yields a database session per request
and automatically closes it when the request is done.

BEGINNER TIP — Why async?
  FastAPI is async. If you use a synchronous DB driver, your server
  blocks (freezes) while waiting for the database. An async driver
  lets the server handle other requests while waiting for the DB.
  aiosqlite is the async driver for SQLite.
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import text
from config import get_settings
from database.models import Base

cfg = get_settings()

# ── Engine ────────────────────────────────────────────────────────────────────
# echo=False in production — don't log every SQL query (it's noisy and slow).
# Set echo=True temporarily when debugging a query.
engine = create_async_engine(
    cfg.database_url,
    echo=False,
    connect_args={"check_same_thread": False} if "sqlite" in cfg.database_url else {},
)

# ── Session factory ───────────────────────────────────────────────────────────
# expire_on_commit=False: don't expire objects after commit — lets us read
# attributes after the session closes (common source of bugs for beginners).
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db() -> None:
    """
    Create all tables if they don't exist.
    Called once at app startup in api/main.py's lifespan handler.
    In production with Postgres you'd use Alembic migrations instead.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("[DB] Tables created (or already exist).")


async def get_db():
    """
    FastAPI dependency — yields an async DB session.
    Usage in a route:
        async def my_route(db: AsyncSession = Depends(get_db)):
            result = await db.execute(select(User))

    The session is automatically closed when the request ends,
    even if an exception is raised (the finally block guarantees it).
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
