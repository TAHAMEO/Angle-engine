"""Timeline events: dated occurrences, each tied to evidence, with explicit date precision.

Event times always say what they are based on (EXIF capture time, publication date, registry date,
archive snapshot, …) and how precise they are; EXIF times carry the "metadata is editable" caveat.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.core.enums import Provenance, VerificationStatus
from angel_engine.core.ids import new_id
from angel_engine.core.problems import ConflictState, ValidationProblem
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.db.models import EvidenceItem, Investigation, TimelineEvent, TimelineEventEvidence
from angel_engine.db.session import allow_status_transition
from angel_engine.evidence.service import redaction_mode
from angel_engine.guard import RedactionContext, SourceKind, redact_text

V = VerificationStatus
PRECISIONS = ("exact", "minute", "hour", "day", "month", "year", "approximate")
KINDS = (
    "capture_time",       # image metadata (editable — caveated)
    "publication",        # article / page / document published
    "first_archived",     # first archive snapshot
    "registration",       # domain/company registration, certificate issuance
    "corporate_event",    # founding, filing, merger …
    "public_statement",
    "event",              # generic public event
    "manual",
)  # fmt: skip
CAVEATS = {
    "capture_time": "Image metadata is editable; its presence or absence proves nothing on its own.",
    "first_archived": "The first archive snapshot shows when a page was archived, not when it was created.",
}
#: Status changes available for timeline events (they inherit verification from evidence review).
EVENT_TARGETS = (V.CONFIRMED_BY_SOURCE.value, V.UNVERIFIED.value, V.CONTRADICTED.value, V.AI_HYPOTHESIS.value)


@dataclass(frozen=True, slots=True)
class EventInput:
    occurred_start: datetime
    precision: str
    kind: str
    title: str
    evidence_ids: tuple[uuid.UUID, ...]
    occurred_end: datetime | None = None
    description: str | None = None
    finding_id: uuid.UUID | None = None
    provenance: str = Provenance.SOURCE_REPORTED.value
    created_via: str = "system"
    created_by: uuid.UUID | None = None


async def create_event(db: AsyncSession, cipher: FieldCipher, inv: Investigation, data: EventInput) -> TimelineEvent:
    if data.precision not in PRECISIONS:
        raise ValidationProblem("Unknown date precision.", code="invalid_precision")
    if data.kind not in KINDS:
        raise ValidationProblem("Unknown event kind.", code="invalid_event_kind")
    if not data.evidence_ids:
        raise ValidationProblem("A timeline event must cite at least one evidence item.", code="evidence_required")
    if data.occurred_end is not None and data.occurred_end < data.occurred_start:
        raise ValidationProblem("The end of an event cannot be before its start.", code="invalid_range")
    found = set(
        (
            await db.execute(
                select(EvidenceItem.id).where(
                    EvidenceItem.investigation_id == inv.id, EvidenceItem.id.in_(data.evidence_ids)
                )
            )
        ).scalars()
    )
    missing = [str(e) for e in data.evidence_ids if e not in found]
    if missing:
        raise ValidationProblem(
            "Some cited evidence items do not exist in this investigation.",
            code="unknown_evidence",
            evidence_ids=missing,
        )
    mode, ctx = redaction_mode(inv), RedactionContext(source_kind=SourceKind.USER_NOTE)
    title = redact_text(data.title[:300], mode=mode, context=ctx).text.strip()
    if not title:
        raise ValidationProblem("The event title is empty after redaction.", code="empty_title")
    description = redact_text(data.description[:4000], mode=mode, context=ctx).text if data.description else None
    eid = new_id()
    status = V.AI_HYPOTHESIS.value if data.provenance == Provenance.AI_HYPOTHESIS.value else V.UNVERIFIED.value
    event = TimelineEvent(
        id=eid,
        investigation_id=inv.id,
        occurred_start=data.occurred_start,
        occurred_end=data.occurred_end,
        precision=data.precision,
        kind=data.kind,
        title=cipher.seal(title, table="timeline_events", column="title", row_id=eid),
        description=cipher.seal_optional(description, table="timeline_events", column="description", row_id=eid),
        finding_id=data.finding_id,
        provenance=data.provenance,
        verification_status=status,
        created_by=data.created_by,
        created_via=data.created_via,
    )
    db.add(event)
    await db.flush()
    for evidence_id in dict.fromkeys(data.evidence_ids):
        db.add(TimelineEventEvidence(id=new_id(), investigation_id=inv.id, event_id=eid, evidence_id=evidence_id))
    await db.flush()
    return event


async def find_event(
    db: AsyncSession, inv: Investigation, kind: str, start: datetime, evidence_id: uuid.UUID
) -> TimelineEvent | None:
    """Existing event of ``kind`` at ``start`` that already cites ``evidence_id`` (idempotent ingestion)."""
    stmt = (
        select(TimelineEvent)
        .join(TimelineEventEvidence, TimelineEventEvidence.event_id == TimelineEvent.id)
        .where(
            TimelineEvent.investigation_id == inv.id,
            TimelineEvent.kind == kind,
            TimelineEvent.occurred_start == start,
            TimelineEventEvidence.evidence_id == evidence_id,
        )
        .limit(1)
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def set_status(db: AsyncSession, event: TimelineEvent, to_status: str, justification: str) -> str:
    if to_status not in EVENT_TARGETS:
        raise ValidationProblem("Unknown status for a timeline event.", code="invalid_status")
    if to_status == V.AI_HYPOTHESIS.value and event.provenance != Provenance.AI_HYPOTHESIS.value:
        raise ConflictState(
            "Only AI-proposed events can carry the AI-hypothesis status.", code="transition_not_allowed"
        )
    if to_status == event.verification_status:
        raise ConflictState("The event already has this status.", code="transition_not_allowed")
    if len(justification.strip()) < 20:
        raise ValidationProblem("Explain the change in at least 20 characters.", code="justification_required")
    previous = event.verification_status
    await allow_status_transition(db)
    event.verification_status = to_status
    await db.flush()
    await db.execute(text("SELECT set_config('ae.transition', 'off', true)"))
    return previous


async def event_evidence(db: AsyncSession, event_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, list[uuid.UUID]]:
    if not event_ids:
        return {}
    rows = (
        await db.execute(
            select(TimelineEventEvidence.event_id, TimelineEventEvidence.evidence_id).where(
                TimelineEventEvidence.event_id.in_(event_ids)
            )
        )
    ).all()
    out: dict[uuid.UUID, list[uuid.UUID]] = {}
    for event_id, evidence_id in rows:
        out.setdefault(event_id, []).append(evidence_id)
    return out


def event_view(cipher: FieldCipher, event: TimelineEvent, evidence_ids: Sequence[uuid.UUID]) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "occurred_start": event.occurred_start,
        "occurred_end": event.occurred_end,
        "precision": event.precision,
        "kind": event.kind,
        "title": cipher.open(event.title, table="timeline_events", column="title", row_id=event.id),
        "description": cipher.open_optional(
            event.description, table="timeline_events", column="description", row_id=event.id
        ),
        "caveat": CAVEATS.get(event.kind),
        "finding_id": str(event.finding_id) if event.finding_id else None,
        "provenance": event.provenance,
        "verification_status": event.verification_status,
        "evidence_ids": [str(e) for e in evidence_ids],
        "created_via": event.created_via,
        "created_at": event.created_at,
    }
