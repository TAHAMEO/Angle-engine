"""The signed-in user's profile, preferences and sessions."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field
from sqlalchemy import select

from angel_engine.api.deps import CurrentPrincipal, DbSession
from angel_engine.api.v1.routers.auth import UserOut
from angel_engine.auth.sessions import revoke
from angel_engine.core.problems import NotFound
from angel_engine.db.models import UserSession

router = APIRouter(prefix="/me", tags=["me"])


class Preferences(BaseModel):
    theme: Literal["dark", "light", "system"] | None = None
    density: Literal["comfortable", "compact"] | None = None


class ProfilePatch(BaseModel):
    display_name: str | None = Field(default=None, min_length=2, max_length=120)
    preferences: Preferences | None = None


class SessionInfo(BaseModel):
    id: str
    created_at: datetime
    last_seen_at: datetime
    absolute_expires_at: datetime
    ua_family: str | None
    current: bool


@router.get("")
async def me(principal: CurrentPrincipal) -> UserOut:
    return UserOut.of(principal.user)


@router.patch("")
async def update_me(body: ProfilePatch, principal: CurrentPrincipal, db: DbSession) -> UserOut:
    user = principal.user
    if body.display_name is not None:
        user.display_name = body.display_name.strip()
    if body.preferences is not None:
        merged = dict(user.preferences or {})
        merged.update({k: v for k, v in body.preferences.model_dump().items() if v is not None})
        user.preferences = merged
    principal.audit(db, "me.profile_updated")
    return UserOut.of(user)


@router.get("/sessions")
async def my_sessions(principal: CurrentPrincipal, db: DbSession) -> list[SessionInfo]:
    rows = (
        (
            await db.execute(
                select(UserSession)
                .where(UserSession.user_id == principal.user_id, UserSession.revoked_at.is_(None))
                .order_by(UserSession.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [
        SessionInfo(
            id=str(r.public_id),
            created_at=r.created_at,
            last_seen_at=r.last_seen_at,
            absolute_expires_at=r.absolute_expires_at,
            ua_family=r.ua_family,
            current=r.token_hash == principal.session.token_hash,
        )
        for r in rows
    ]


@router.delete("/sessions/{session_id}")
async def revoke_session(session_id: uuid.UUID, principal: CurrentPrincipal, db: DbSession) -> dict[str, str]:
    row = (
        await db.execute(
            select(UserSession).where(UserSession.public_id == session_id, UserSession.user_id == principal.user_id)
        )
    ).scalar_one_or_none()
    if row is None or row.revoked_at is not None:
        raise NotFound()
    await revoke(db, row, "user_revoked")
    principal.audit(db, "me.session_revoked", target_type="session", target_id=str(session_id))
    return {"status": "revoked"}
