"""Server-side sessions: opaque random tokens, SHA-256 stored, idle + absolute expiry, rotation."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.config import Settings
from angel_engine.core.clock import utcnow
from angel_engine.core.enums import SessionState, UserStatus
from angel_engine.core.ids import new_id
from angel_engine.db.models import User, UserSession

LAST_SEEN_WRITE_INTERVAL = timedelta(seconds=60)


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


@dataclass(slots=True)
class ResolvedSession:
    session: UserSession
    user: User

    @property
    def idle_expires_in(self) -> int:
        return max(0, int((self.session.idle_expires_at - utcnow()).total_seconds()))

    @property
    def absolute_expires_in(self) -> int:
        return max(0, int((self.session.absolute_expires_at - utcnow()).total_seconds()))


def _ua_family(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    ua = user_agent.lower()
    for name in ("firefox", "edg", "chrome", "safari", "playwright", "python", "curl"):
        if name in ua:
            return {"edg": "edge"}.get(name, name)
    return "other"


async def create_session(
    db: AsyncSession,
    settings: Settings,
    user: User,
    *,
    state: SessionState,
    ip_pseudonym: str | None,
    user_agent: str | None,
) -> tuple[str, UserSession]:
    now = utcnow()
    token = secrets.token_urlsafe(32)
    idle_minutes = settings.idle_timeout_minutes if state == SessionState.ACTIVE else 5
    absolute = now + (
        timedelta(hours=settings.session_absolute_hours) if state == SessionState.ACTIVE else timedelta(minutes=15)
    )
    row = UserSession(
        token_hash=hash_token(token),
        public_id=new_id(),
        user_id=user.id,
        state=state.value,
        csrf_key=secrets.token_bytes(32),
        last_seen_at=now,
        idle_expires_at=min(now + timedelta(minutes=idle_minutes), absolute),
        absolute_expires_at=absolute,
        ip_pseudonym=ip_pseudonym,
        ua_family=_ua_family(user_agent),
    )
    db.add(row)
    await db.flush()
    await _enforce_session_cap(db, settings, user.id, keep=row.token_hash)
    return token, row


async def _enforce_session_cap(db: AsyncSession, settings: Settings, user_id: uuid.UUID, *, keep: bytes) -> None:
    rows = (
        (
            await db.execute(
                select(UserSession)
                .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
                .order_by(UserSession.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    for extra in [r for r in rows if r.token_hash != keep][settings.max_sessions_per_user - 1 :]:
        extra.revoked_at = utcnow()
        extra.revoke_reason = "session_limit"


async def resolve(
    db: AsyncSession, settings: Settings, token: str | None, *, background: bool = False
) -> ResolvedSession | None:
    """Return the live session for ``token`` or None. Slides the idle timer unless ``background``."""
    if not token or len(token) > 128:
        return None
    row = (
        await db.execute(select(UserSession).where(UserSession.token_hash == hash_token(token)))
    ).scalar_one_or_none()
    if row is None or row.revoked_at is not None:
        return None
    now = utcnow()
    if now >= row.idle_expires_at or now >= row.absolute_expires_at:
        row.revoked_at = now
        row.revoke_reason = "expired"
        return None
    user = await db.get(User, row.user_id)
    if user is None or user.status != UserStatus.ACTIVE.value:
        row.revoked_at = now
        row.revoke_reason = "user_inactive"
        return None
    if not background and row.state == SessionState.ACTIVE.value and now - row.last_seen_at >= LAST_SEEN_WRITE_INTERVAL:
        row.last_seen_at = now
        row.idle_expires_at = min(now + timedelta(minutes=settings.idle_timeout_minutes), row.absolute_expires_at)
    return ResolvedSession(row, user)


async def rotate(db: AsyncSession, row: UserSession) -> str:
    """Issue a new token for an existing session (after login steps or privilege changes)."""
    token = secrets.token_urlsafe(32)
    row.token_hash = hash_token(token)
    row.csrf_key = secrets.token_bytes(32)
    await db.flush()
    return token


async def promote(db: AsyncSession, settings: Settings, row: UserSession, state: SessionState) -> str:
    """Move a session to a new state (e.g. mfa_pending → active) with a fresh token and full lifetime."""
    now = utcnow()
    row.state = state.value
    if state == SessionState.ACTIVE:
        row.absolute_expires_at = now + timedelta(hours=settings.session_absolute_hours)
        row.idle_expires_at = min(now + timedelta(minutes=settings.idle_timeout_minutes), row.absolute_expires_at)
        row.reauth_at = now
    row.last_seen_at = now
    return await rotate(db, row)


async def revoke(db: AsyncSession, row: UserSession, reason: str) -> None:
    row.revoked_at = utcnow()
    row.revoke_reason = reason


async def revoke_all(db: AsyncSession, user_id: uuid.UUID, *, reason: str, except_hash: bytes | None = None) -> int:
    stmt = (
        update(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=utcnow(), revoke_reason=reason)
    )
    if except_hash is not None:
        stmt = stmt.where(UserSession.token_hash != except_hash)
    result = await db.execute(stmt)
    return int(getattr(result, "rowcount", 0) or 0)


def recently_reauthenticated(row: UserSession, settings: Settings, now: datetime | None = None) -> bool:
    if row.reauth_at is None:
        return False
    return (now or utcnow()) - row.reauth_at <= timedelta(minutes=settings.reauth_window_minutes)
