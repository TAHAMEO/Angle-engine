"""Audit log browsing and chain verification (admins and auditors)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select

from angel_engine.api.deps import DbSession, Principal, require
from angel_engine.audit.chain import verify_chain
from angel_engine.authz.permissions import Perm
from angel_engine.core.pagination import clamp_limit
from angel_engine.db.models import AuditLog

router = APIRouter(prefix="/audit-events", tags=["audit"])

AuditReader = Annotated[Principal, Depends(require(Perm.AUDIT_READ))]
AuditVerifier = Annotated[Principal, Depends(require(Perm.AUDIT_VERIFY))]


class AuditEventOut(BaseModel):
    seq: int
    occurred_at: datetime
    actor_id: str | None
    actor_role: str | None
    actor_type: str
    action: str
    outcome: str
    investigation_id: str | None
    target_type: str | None
    target_id: str | None
    request_id: str | None
    details: dict[str, Any]
    row_hash: str


class AuditPage(BaseModel):
    items: list[AuditEventOut]
    next_before_seq: int | None


def _out(row: AuditLog) -> AuditEventOut:
    return AuditEventOut(
        seq=row.seq,
        occurred_at=row.occurred_at,
        actor_id=str(row.actor_id) if row.actor_id else None,
        actor_role=row.actor_role,
        actor_type=row.actor_type,
        action=row.action,
        outcome=row.outcome,
        investigation_id=str(row.investigation_id) if row.investigation_id else None,
        target_type=row.target_type,
        target_id=row.target_id,
        request_id=row.request_id,
        details=row.details,
        row_hash=row.row_hash.hex(),
    )


@router.get("")
async def list_events(
    principal: AuditReader,
    db: DbSession,
    before_seq: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int | None, Query(ge=1, le=100)] = None,
    action: Annotated[str | None, Query(max_length=80)] = None,
    actor_id: uuid.UUID | None = None,
    investigation_id: uuid.UUID | None = None,
    outcome: Annotated[str | None, Query(pattern="^(success|denied|failure)$")] = None,
) -> AuditPage:
    n = clamp_limit(limit)
    stmt = select(AuditLog).order_by(AuditLog.seq.desc()).limit(n + 1)
    if before_seq is not None:
        stmt = stmt.where(AuditLog.seq < before_seq)
    if action:
        stmt = stmt.where(AuditLog.action.startswith(action))
    if actor_id:
        stmt = stmt.where(AuditLog.actor_id == actor_id)
    if investigation_id:
        stmt = stmt.where(AuditLog.investigation_id == investigation_id)
    if outcome:
        stmt = stmt.where(AuditLog.outcome == outcome)
    rows = (await db.execute(stmt)).scalars().all()
    more = len(rows) > n
    rows = rows[:n]
    return AuditPage(items=[_out(r) for r in rows], next_before_seq=rows[-1].seq if more and rows else None)


class VerifyOut(BaseModel):
    ok: bool
    checked: int
    last_seq: int
    first_broken_seq: int | None
    reason: str | None


@router.get("/verify")
async def verify(principal: AuditVerifier, db: DbSession) -> VerifyOut:
    result = await verify_chain(db, principal.services.audit_key)
    principal.audit(
        db,
        "audit.chain_verified",
        outcome="success" if result.ok else "failure",
        details={"checked": result.checked, "ok": result.ok},
    )
    return VerifyOut(
        ok=result.ok,
        checked=result.checked,
        last_seq=result.last_seq,
        first_broken_seq=result.first_broken_seq,
        reason=result.reason,
    )
