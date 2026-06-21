"""
auth/auth.py — JWT Authentication
===================================
Handles user registration, login, and per-request token verification.

FLOW:
  1. Client calls POST /auth/register → creates a User row in the DB.
  2. Client calls POST /auth/login    → verifies password, returns JWT token.
  3. Client sends token in every request header:
         Authorization: Bearer <token>
  4. FastAPI routes that need auth use:  Depends(get_current_user)
     This calls verify_token() which decodes the JWT and returns the User.

WHY JWT?
  JSON Web Tokens are stateless — the server doesn't need to store sessions.
  The token itself encodes the user ID and expiry. Clients include it in
  every request header. This scales horizontally: any server can verify
  any token without a shared session store.

SECURITY NOTES (OWASP LLM Top 10 / Agentic Top 10):
  - Passwords are hashed with bcrypt (never stored plaintext).
  - Tokens expire (default: 60 minutes).
  - The secret key must be at least 32 random bytes (see .env.example).
  - Use HTTPS in production — tokens in headers are plaintext over HTTP.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from config import get_settings
from database.db import get_db
from database.models import User

cfg = get_settings()

# ── Password hashing ──────────────────────────────────────────────────────────
# bcrypt automatically salts hashes — no two hashes of the same password match.
# This protects users even if the database is leaked.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── Token extraction from request header ─────────────────────────────────────
bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(user_id: int, username: str) -> str:
    """
    Create a signed JWT token encoding the user's ID and expiry.
    The token is signed with JWT_SECRET_KEY — anyone with that key can
    verify (but not forge) tokens. Keep the secret key private.
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=cfg.jwt_expire_minutes)
    payload = {
        "sub": str(user_id),  # subject: who the token is for
        "username": username,
        "exp": expire,  # expiry: token rejected after this time
        "iat": datetime.now(timezone.utc),  # issued-at: for audit logging
    }
    return jwt.encode(payload, cfg.jwt_secret_key, algorithm=cfg.jwt_algorithm)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    FastAPI dependency: extract and verify the JWT from the Authorization header.
    Raises HTTP 401 if the token is missing, expired, or tampered with.

    Usage in a route:
        @router.get("/protected")
        async def protected(user: User = Depends(get_current_user)):
            return {"hello": user.username}
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. Include: Authorization: Bearer <token>",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not credentials:
        raise credentials_exception

    try:
        payload = jwt.decode(
            credentials.credentials,
            cfg.jwt_secret_key,
            algorithms=[cfg.jwt_algorithm],
        )
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == int(user_id)))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise credentials_exception

    return user
