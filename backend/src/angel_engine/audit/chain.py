"""Hash-chained, append-only audit log.

Each row stores ``row_hash = HMAC(audit_key, prev_hash ‖ canonical_json(record))``. Writers lock the single
``audit_chain_head`` row, so chain order equals commit order and rolled-back transactions leave no gaps.
Events are buffered on the session and written as the *last* step before commit (short lock hold).
Events that must survive a rollback (denials, failed logins) are written in their own transaction.

Details are content-free: identifiers, counts, categories — never evidence text, queries or secrets.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.core.canonical_json import canonical_bytes
from angel_engine.core.clock import utcnow
from angel_engine.db.models import AuditAnchor, AuditChainHead, AuditLog

GENESIS_HASH = b"\x00" * 32
_PENDING_KEY = "angel_audit_pending"


@dataclass(slots=True)
class AuditEvent:
    action: str
    outcome: str = "success"
    actor_id: uuid.UUID | None = None
    actor_role: str | None = None
    actor_type: str = "user"
    investigation_id: uuid.UUID | None = None
    target_type: str | None = None
    target_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    session_pseudonym: str | None = None
    ip_pseudonym: str | None = None
    request_id: str | None = None


def _record(seq: int, occurred_at: datetime, ev: AuditEvent) -> dict[str, Any]:
    return {
        "seq": seq,
        "occurred_at": occurred_at.isoformat(),
        "actor_id": str(ev.actor_id) if ev.actor_id else None,
        "actor_role": ev.actor_role,
        "actor_type": ev.actor_type,
        "session_pseudonym": ev.session_pseudonym,
        "ip_pseudonym": ev.ip_pseudonym,
        "action": ev.action,
        "outcome": ev.outcome,
        "investigation_id": str(ev.investigation_id) if ev.investigation_id else None,
        "target_type": ev.target_type,
        "target_id": ev.target_id,
        "request_id": ev.request_id,
        "details": ev.details,
    }


def _row_record(row: AuditLog) -> dict[str, Any]:
    return {
        "seq": row.seq,
        "occurred_at": row.occurred_at.isoformat(),
        "actor_id": str(row.actor_id) if row.actor_id else None,
        "actor_role": row.actor_role,
        "actor_type": row.actor_type,
        "session_pseudonym": row.session_pseudonym,
        "ip_pseudonym": row.ip_pseudonym,
        "action": row.action,
        "outcome": row.outcome,
        "investigation_id": str(row.investigation_id) if row.investigation_id else None,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "request_id": row.request_id,
        "details": row.details,
    }


def chain_hash(key: bytes, prev_hash: bytes, record: dict[str, Any]) -> bytes:
    return hmac.new(key, prev_hash + canonical_bytes(record), hashlib.sha256).digest()


def record(session: AsyncSession, event: AuditEvent) -> None:
    """Buffer an event; it is written by :func:`flush_pending` right before the transaction commits."""
    session.info.setdefault(_PENDING_KEY, []).append(event)


def discard_pending(session: AsyncSession) -> None:
    session.info.pop(_PENDING_KEY, None)


async def append_now(session: AsyncSession, key: bytes, events: Sequence[AuditEvent]) -> int:
    """Append events to the chain inside the current transaction. Returns the last sequence number."""
    if not events:
        return 0
    head = (await session.execute(select(AuditChainHead).where(AuditChainHead.id == 1).with_for_update())).scalar_one()
    seq, prev = head.last_seq, head.last_hash
    for ev in events:
        seq += 1
        occurred_at = utcnow()
        row_hash = chain_hash(key, prev, _record(seq, occurred_at, ev))
        session.add(
            AuditLog(
                seq=seq,
                occurred_at=occurred_at,
                actor_id=ev.actor_id,
                actor_role=ev.actor_role,
                actor_type=ev.actor_type,
                session_pseudonym=ev.session_pseudonym,
                ip_pseudonym=ev.ip_pseudonym,
                action=ev.action,
                outcome=ev.outcome,
                investigation_id=ev.investigation_id,
                target_type=ev.target_type,
                target_id=ev.target_id,
                request_id=ev.request_id,
                details=ev.details,
                prev_hash=prev,
                row_hash=row_hash,
            )
        )
        prev = row_hash
    head.last_seq, head.last_hash = seq, prev
    await session.flush()
    return seq


async def flush_pending(session: AsyncSession, key: bytes) -> int:
    events: list[AuditEvent] = session.info.pop(_PENDING_KEY, [])
    return await append_now(session, key, events)


@dataclass(frozen=True, slots=True)
class VerificationResult:
    ok: bool
    checked: int
    last_seq: int
    first_broken_seq: int | None = None
    reason: str | None = None


async def verify_chain(session: AsyncSession, key: bytes, *, batch: int = 2000) -> VerificationResult:
    """Recompute the chain from the oldest retained row (or genesis) and compare with the head."""
    prev: bytes | None = None
    checked = 0
    last_seq = 0
    after = -1
    while True:
        rows = (
            (await session.execute(select(AuditLog).where(AuditLog.seq > after).order_by(AuditLog.seq).limit(batch)))
            .scalars()
            .all()
        )
        if not rows:
            break
        for row in rows:
            if prev is None:
                prev = row.prev_hash  # trimmed history starts at a retained checkpoint
            elif row.seq != last_seq + 1:
                return VerificationResult(False, checked, last_seq, row.seq, "gap in sequence numbers")
            if row.prev_hash != prev:
                return VerificationResult(False, checked, last_seq, row.seq, "previous-hash link mismatch")
            if not hmac.compare_digest(chain_hash(key, prev, _row_record(row)), row.row_hash):
                return VerificationResult(False, checked, last_seq, row.seq, "row content does not match its hash")
            prev, last_seq, after = row.row_hash, row.seq, row.seq
            checked += 1
    head = (await session.execute(select(AuditChainHead).where(AuditChainHead.id == 1))).scalar_one()
    if head.last_seq != last_seq or (checked and head.last_hash != prev):
        return VerificationResult(False, checked, last_seq, last_seq + 1, "chain head does not match the last row")
    return VerificationResult(True, checked, last_seq)


async def write_anchor(session: AsyncSession, anchor_key: bytes, *, kind: str = "daily") -> AuditAnchor | None:
    head = (await session.execute(select(AuditChainHead).where(AuditChainHead.id == 1))).scalar_one()
    if head.last_seq == 0:
        return None
    mac = hmac.new(anchor_key, f"{head.last_seq}|{head.last_hash.hex()}".encode(), hashlib.sha256).digest()
    anchor = AuditAnchor(seq=head.last_seq, row_hash=head.last_hash, anchor_mac=mac, kind=kind)
    session.add(anchor)
    await session.flush()
    return anchor


def pseudonymize_ip(ip: str | None, key_for_period: Any) -> str | None:
    """Monthly-keyed IP pseudonym ``YYYY-MM:<hex>``; the monthly key is destroyed after 90 days."""
    if not ip:
        return None
    try:
        normalized = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return None
    period = utcnow().strftime("%Y-%m")
    digest = hmac.new(key_for_period(period), normalized.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{period}:{digest}"
