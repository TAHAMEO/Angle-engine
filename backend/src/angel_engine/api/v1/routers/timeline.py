"""Timeline of dated, evidence-backed events (each with date precision and, where needed, a caveat)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal, get_args

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field
from sqlalchemy import select

from angel_engine.api.v1.routers._common import ReadCtx, VerifyCtx, WriteCtx, get_scoped
from angel_engine.core.enums import Provenance, VerificationStatus
from angel_engine.db.models import EvidenceItem, Finding, TimelineEvent
from angel_engine.timeline import service as timeline
from angel_engine.timeline.service import KINDS, PRECISIONS, EventInput

router = APIRouter(tags=["timeline"])
BASE = "/investigations/{investigation_id}/timeline-events"
Kind = Literal[
    "capture_time", "publication", "first_archived", "registration", "corporate_event", "public_statement", "event",
    "manual",
]  # fmt: skip
Precision = Literal["exact", "minute", "hour", "day", "month", "year", "approximate"]
assert set(get_args(Kind)) == set(KINDS) and set(get_args(Precision)) == set(PRECISIONS)


class EventOut(BaseModel):
    id: str
    occurred_start: datetime
    occurred_end: datetime | None
    precision: str
    kind: str
    title: str
    description: str | None
    caveat: str | None
    finding_id: str | None
    finding_label: str | None = None
    provenance: str
    verification_status: str
    evidence_ids: list[str]
    evidence_labels: list[str] = []
    created_via: str
    created_at: datetime


class EventCreate(BaseModel):
    occurred_start: datetime
    occurred_end: datetime | None = None
    precision: Precision = "day"
    kind: Kind = "manual"
    title: str = Field(min_length=3, max_length=300)
    description: str | None = Field(default=None, max_length=4000)
    evidence_ids: list[uuid.UUID] = Field(min_length=1, max_length=50)
    finding_id: uuid.UUID | None = None


class EventStatusIn(BaseModel):
    to_status: Literal["confirmed_by_source", "unverified", "contradicted", "ai_hypothesis"]
    justification: str = Field(min_length=20, max_length=4000)


async def event_views(ctx: Any, events: list[TimelineEvent]) -> list[EventOut]:
    cipher = await ctx.cipher()
    evidence = await timeline.event_evidence(ctx.db, [e.id for e in events])
    all_ids = {i for ids in evidence.values() for i in ids}
    labels = (
        dict(
            (
                await ctx.db.execute(
                    select(EvidenceItem.id, EvidenceItem.label_seq).where(EvidenceItem.id.in_(all_ids))
                )
            ).all()
        )
        if all_ids
        else {}
    )
    finding_ids = {e.finding_id for e in events if e.finding_id}
    finding_labels = (
        dict((await ctx.db.execute(select(Finding.id, Finding.label_seq).where(Finding.id.in_(finding_ids)))).all())
        if finding_ids
        else {}
    )
    out = []
    for event in events:
        ids = evidence.get(event.id, [])
        view = timeline.event_view(cipher, event, ids)
        view["evidence_labels"] = [f"E-{labels[i]}" for i in ids if i in labels]
        view["finding_label"] = f"F-{finding_labels[event.finding_id]}" if event.finding_id in finding_labels else None
        out.append(EventOut(**view))
    return out


@router.get(BASE)
async def list_events(
    ctx: ReadCtx,
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    kind: Annotated[list[str] | None, Query()] = None,
    status: Annotated[list[VerificationStatus] | None, Query()] = None,
    provenance: Annotated[list[Provenance] | None, Query()] = None,
) -> list[EventOut]:
    stmt = select(TimelineEvent).where(TimelineEvent.investigation_id == ctx.id)
    if start:
        stmt = stmt.where(TimelineEvent.occurred_start >= start)
    if end:
        stmt = stmt.where(TimelineEvent.occurred_start <= end)
    if kind:
        stmt = stmt.where(TimelineEvent.kind.in_(kind))
    if status:
        stmt = stmt.where(TimelineEvent.verification_status.in_([s.value for s in status]))
    if provenance:
        stmt = stmt.where(TimelineEvent.provenance.in_([p.value for p in provenance]))
    events = list(
        (await ctx.db.execute(stmt.order_by(TimelineEvent.occurred_start, TimelineEvent.id).limit(2000))).scalars()
    )
    return await event_views(ctx, events)


@router.post(BASE, status_code=201)
async def create_event(body: EventCreate, ctx: WriteCtx) -> EventOut:
    if body.finding_id is not None:
        await get_scoped(ctx.db, Finding, ctx, body.finding_id)
    event = await timeline.create_event(
        ctx.db,
        await ctx.cipher(),
        ctx.investigation,
        EventInput(
            occurred_start=body.occurred_start,
            occurred_end=body.occurred_end,
            precision=body.precision,
            kind=body.kind,
            title=body.title,
            description=body.description,
            evidence_ids=tuple(body.evidence_ids),
            finding_id=body.finding_id,
            provenance=Provenance.ANALYST_INFERENCE.value,
            created_via="manual",
            created_by=ctx.principal.user_id,
        ),
    )
    ctx.audit(
        "timeline_event.created",
        target_type="timeline_event",
        target_id=str(event.id),
        details={"kind": event.kind, "evidence": len(body.evidence_ids)},
    )
    return (await event_views(ctx, [event]))[0]


@router.get(BASE + "/{event_id}")
async def get_event(event_id: uuid.UUID, ctx: ReadCtx) -> EventOut:
    event = await get_scoped(ctx.db, TimelineEvent, ctx, event_id)
    return (await event_views(ctx, [event]))[0]


@router.post(BASE + "/{event_id}/status")
async def change_event_status(event_id: uuid.UUID, body: EventStatusIn, ctx: VerifyCtx) -> EventOut:
    event = await get_scoped(ctx.db, TimelineEvent, ctx, event_id)
    previous = await timeline.set_status(ctx.db, event, body.to_status, body.justification)
    ctx.audit(
        "timeline_event.status_changed",
        target_type="timeline_event",
        target_id=str(event.id),
        details={"from": previous, "to": body.to_status},
    )
    return (await event_views(ctx, [event]))[0]


@router.delete(BASE + "/{event_id}")
async def delete_event(event_id: uuid.UUID, ctx: WriteCtx) -> dict[str, str]:
    event = await get_scoped(ctx.db, TimelineEvent, ctx, event_id)
    await ctx.db.delete(event)
    await ctx.db.flush()
    ctx.audit("timeline_event.deleted", target_type="timeline_event", target_id=str(event_id))
    return {"status": "deleted"}
