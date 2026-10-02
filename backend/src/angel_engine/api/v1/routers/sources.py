"""Sources: where evidence came from (URL, publisher, capture times, reliability, access status)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from angel_engine.api.v1.routers._common import Keyset, Page, ReadCtx, WriteCtx, get_scoped
from angel_engine.crypto.blind_index import query_tokens
from angel_engine.db.models import EvidenceItem, Source
from angel_engine.db.models.evidence import ACCESS_STATUSES, SOURCE_CATEGORIES
from angel_engine.evidence.service import evidence_view, source_view

router = APIRouter(tags=["sources"])
BASE = "/investigations/{investigation_id}/sources"


class SourceOut(BaseModel):
    id: str
    label: str
    url: str
    title: str | None
    host: str
    registrable_domain: str
    category: str
    connector_id: str
    publisher: str | None
    ownership_group: str | None
    published_at: datetime | None
    first_captured_at: datetime
    last_captured_at: datetime
    reliability: str | None
    archived_url: str | None
    access_status: str
    evidence_count: int = 0


class SourceDetail(SourceOut):
    evidence: list[dict[str, Any]]


class SourcePatch(BaseModel):
    reliability: Literal["A", "B", "C", "D", "E", "F"] | None = None
    clear_reliability: bool = False
    publisher: str | None = Field(default=None, max_length=200)
    ownership_group: str | None = Field(default=None, max_length=200)


@router.get(BASE)
async def list_sources(
    ctx: ReadCtx,
    category: Annotated[list[str] | None, Query()] = None,
    domain: Annotated[str | None, Query(max_length=253)] = None,
    connector: Annotated[str | None, Query(max_length=64)] = None,
    access_status: Annotated[list[str] | None, Query()] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int | None, Query(ge=1, le=100)] = None,
    cursor: Annotated[str | None, Query(max_length=600)] = None,
) -> Page[SourceOut]:
    filters = {
        "category": sorted(category or []),
        "domain": domain,
        "connector": connector,
        "access_status": sorted(access_status or []),
        "q": bool(q),
    }
    keyset = Keyset(ctx, filters, limit, cursor)
    stmt = select(Source).where(Source.investigation_id == ctx.id)
    if category:
        stmt = stmt.where(Source.source_category.in_([c for c in category if c in SOURCE_CATEGORIES]))
    if access_status:
        stmt = stmt.where(Source.access_status.in_([a for a in access_status if a in ACCESS_STATUSES]))
    if domain:
        stmt = stmt.where(Source.registrable_domain == domain.strip().lower())
    if connector:
        stmt = stmt.where(Source.connector_id == connector)
    cipher = await ctx.cipher()
    if q:
        wanted = query_tokens(cipher, q)
        if wanted:
            stmt = stmt.where(Source.title_tokens.contains(wanted))
    rows = list((await ctx.db.execute(keyset.apply(stmt, Source.last_captured_at, Source.id))).scalars())
    rows, next_cursor = keyset.page(rows, lambda s: (s.last_captured_at, s.id))
    counts = await _evidence_counts(ctx, [s.id for s in rows])
    items = [SourceOut(**source_view(cipher, s), evidence_count=counts.get(s.id, 0)) for s in rows]
    return Page(items=items, next_cursor=next_cursor, has_more=next_cursor is not None)


async def _evidence_counts(ctx: Any, ids: list[uuid.UUID]) -> dict[uuid.UUID, int]:
    if not ids:
        return {}
    rows = (
        await ctx.db.execute(
            select(EvidenceItem.source_id, func.count())
            .where(EvidenceItem.source_id.in_(ids))
            .group_by(EvidenceItem.source_id)
        )
    ).all()
    return {sid: int(n) for sid, n in rows}


@router.get(BASE + "/{source_id}")
async def get_source(source_id: uuid.UUID, ctx: ReadCtx) -> SourceDetail:
    source = await get_scoped(ctx.db, Source, ctx, source_id)
    cipher = await ctx.cipher()
    evidence = (
        (
            await ctx.db.execute(
                select(EvidenceItem)
                .where(EvidenceItem.source_id == source.id)
                .order_by(EvidenceItem.captured_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return SourceDetail(
        **source_view(cipher, source),
        evidence_count=len(evidence),
        evidence=[evidence_view(cipher, e) for e in evidence],
    )


@router.patch(BASE + "/{source_id}")
async def update_source(source_id: uuid.UUID, body: SourcePatch, ctx: WriteCtx) -> SourceOut:
    """Annotate a source. Ownership groups affect corroboration: sources in one group count as one origin."""
    source = await get_scoped(ctx.db, Source, ctx, source_id)
    changed: list[str] = []
    if body.clear_reliability:
        source.reliability = None
        changed.append("reliability")
    elif body.reliability is not None:
        source.reliability = body.reliability
        changed.append("reliability")
    if body.publisher is not None:
        source.publisher = body.publisher.strip() or None
        changed.append("publisher")
    if body.ownership_group is not None:
        source.ownership_group = body.ownership_group.strip() or None
        changed.append("ownership_group")
    await ctx.db.flush()
    ctx.audit("source.updated", target_type="source", target_id=str(source.id), details={"fields": changed})
    cipher = await ctx.cipher()
    counts = await _evidence_counts(ctx, [source.id])
    return SourceOut(**source_view(cipher, source), evidence_count=counts.get(source.id, 0))
