"""Evidence items: immutable observations and quotations, with manual capture and reviewer annotations."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select

from angel_engine.api.v1.routers._common import (
    Keyset,
    Page,
    ReadCtx,
    SourceMini,
    WriteCtx,
    get_scoped,
    snippet,
    source_mini,
)
from angel_engine.core.enums import FindingCategory
from angel_engine.core.problems import ValidationProblem
from angel_engine.crypto.blind_index import query_tokens
from angel_engine.db.models import (
    EvidenceItem,
    Finding,
    FindingEvidence,
    RelationshipEvidence,
    Source,
    TimelineEventEvidence,
)
from angel_engine.db.models.evidence import EVIDENCE_TYPES, SOURCE_CATEGORIES
from angel_engine.evidence.service import EvidenceInput, SourceInput, add_evidence, evidence_view, upsert_source
from angel_engine.evidence.urls import UrlError
from angel_engine.findings import service as findings
from angel_engine.findings.service import FindingInput, LinkInput

router = APIRouter(tags=["evidence"])
BASE = "/investigations/{investigation_id}/evidence"
_ISO_REGION = re.compile(r"^[A-Z]{2}-[A-Z0-9]{1,3}$")


class EvidenceOut(BaseModel):
    id: str
    label: str
    evidence_type: str
    provenance: str
    excerpt: str | None
    excerpt_hidden: bool
    excerpt_truncated: bool = False
    extra: dict[str, Any] | None = None
    captured_at: datetime
    published_at: datetime | None
    country: str | None
    region: str | None
    credibility: int | None
    sensitivity_flags: list[str]
    redaction_counts: dict[str, int]
    source: SourceMini | None
    origin_image_id: str | None
    collection_run_id: str | None
    syndication_cluster_id: str | None


class LinkedFinding(BaseModel):
    id: str
    label: str
    statement: str
    verification_status: str
    provenance: str
    stance: str
    directly_states: bool
    dismissed: bool


class EvidenceDetail(EvidenceOut):
    findings: list[LinkedFinding]
    relationship_ids: list[str]
    timeline_event_ids: list[str]


class ManualCaptureIn(BaseModel):
    """Record a quotation the investigator copied from a public page they viewed themselves."""

    url: str = Field(max_length=2000)
    excerpt: str = Field(min_length=10, max_length=20000)
    title: str | None = Field(default=None, max_length=500)
    category: str = "websites"
    published_at: datetime | None = None
    publisher: str | None = Field(default=None, max_length=200)
    #: Optionally record the claim this quotation supports as a new finding.
    statement: str | None = Field(default=None, min_length=10, max_length=2000)
    directly_states: bool = False

    @field_validator("category")
    @classmethod
    def _category(cls, value: str) -> str:
        if value not in SOURCE_CATEGORIES:
            raise ValueError("unknown source category")
        return value


class ManualCaptureOut(BaseModel):
    evidence: EvidenceOut
    created: bool
    finding_id: str | None = None


class EvidencePatch(BaseModel):
    credibility: int | None = Field(default=None, ge=1, le=6)
    country: str | None = Field(default=None, pattern=r"^[A-Z]{2}$")
    region: str | None = Field(default=None, max_length=10)
    clear_location: bool = False


def _out(cipher: Any, item: EvidenceItem, source: Source | None, *, full: bool, reveal: bool = False) -> dict[str, Any]:
    view = evidence_view(cipher, item, reveal_sensitive=reveal)
    excerpt = view["excerpt"]
    truncated = False
    if not full and excerpt is not None:
        short = snippet(excerpt, 600)
        truncated = short != excerpt
        excerpt = short
    view.update(
        excerpt=excerpt, excerpt_truncated=truncated, source=source_mini(cipher, source) if source is not None else None
    )
    if not full:
        view["extra"] = None
    return view


@router.get(BASE)
async def list_evidence(
    ctx: ReadCtx,
    source_id: uuid.UUID | None = None,
    image_id: uuid.UUID | None = None,
    evidence_type: Annotated[list[str] | None, Query()] = None,
    provenance: Annotated[list[str] | None, Query()] = None,
    category: Annotated[list[str] | None, Query()] = None,
    domain: Annotated[str | None, Query(max_length=253)] = None,
    captured_from: datetime | None = None,
    captured_to: datetime | None = None,
    published_from: datetime | None = None,
    published_to: datetime | None = None,
    country: Annotated[str | None, Query(pattern=r"^[A-Z]{2}$")] = None,
    region: Annotated[str | None, Query(max_length=10)] = None,
    flagged: bool | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int | None, Query(ge=1, le=100)] = None,
    cursor: Annotated[str | None, Query(max_length=600)] = None,
) -> Page[EvidenceOut]:
    filters = {
        k: (sorted(v) if isinstance(v, list) else str(v) if v is not None else None)
        for k, v in {
            "source_id": source_id,
            "image_id": image_id,
            "evidence_type": evidence_type,
            "provenance": provenance,
            "category": category,
            "domain": domain,
            "captured_from": captured_from,
            "captured_to": captured_to,
            "published_from": published_from,
            "published_to": published_to,
            "country": country,
            "region": region,
            "flagged": flagged,
            "q": bool(q),
        }.items()
    }
    keyset = Keyset(ctx, filters, limit, cursor)
    stmt = (
        select(EvidenceItem, Source)
        .outerjoin(Source, Source.id == EvidenceItem.source_id)
        .where(EvidenceItem.investigation_id == ctx.id)
    )
    if source_id:
        stmt = stmt.where(EvidenceItem.source_id == source_id)
    if image_id:
        stmt = stmt.where(EvidenceItem.origin_image_id == image_id)
    if evidence_type:
        stmt = stmt.where(EvidenceItem.evidence_type.in_([t for t in evidence_type if t in EVIDENCE_TYPES]))
    if provenance:
        stmt = stmt.where(EvidenceItem.provenance.in_(provenance))
    if category:
        stmt = stmt.where(Source.source_category.in_(category))
    if domain:
        stmt = stmt.where(Source.registrable_domain == domain.strip().lower())
    if captured_from:
        stmt = stmt.where(EvidenceItem.captured_at >= captured_from)
    if captured_to:
        stmt = stmt.where(EvidenceItem.captured_at <= captured_to)
    if published_from:
        stmt = stmt.where(EvidenceItem.published_at >= published_from)
    if published_to:
        stmt = stmt.where(EvidenceItem.published_at <= published_to)
    if country:
        stmt = stmt.where(EvidenceItem.country == country)
    if region:
        stmt = stmt.where(EvidenceItem.region == region)
    if flagged is not None:
        flag_count = func.cardinality(EvidenceItem.sensitivity_flags)
        stmt = stmt.where(flag_count > 0 if flagged else flag_count == 0)
    cipher = await ctx.cipher()
    if q:
        wanted = query_tokens(cipher, q)
        if wanted:
            stmt = stmt.where(EvidenceItem.search_tokens.contains(wanted))
    rows = list((await ctx.db.execute(keyset.apply(stmt, EvidenceItem.captured_at, EvidenceItem.id))).all())
    rows, next_cursor = keyset.page(rows, lambda r: (r[0].captured_at, r[0].id))
    items = [EvidenceOut(**_out(cipher, item, source, full=False)) for item, source in rows]
    return Page(items=items, next_cursor=next_cursor, has_more=next_cursor is not None)


@router.post(BASE, status_code=201)
async def manual_capture(body: ManualCaptureIn, ctx: WriteCtx) -> ManualCaptureOut:
    """Manual capture: the investigator viewed a public page themselves and records a quotation from it.

    Angel Engine does not fetch the page; the quotation is redacted like any other collected text.
    """
    cipher = await ctx.cipher()
    inv = ctx.investigation
    try:
        upsert = await upsert_source(
            ctx.db,
            cipher,
            inv,
            SourceInput(
                url=body.url,
                category=body.category,
                connector_id="manual",
                title=body.title,
                publisher=body.publisher,
                published_at=body.published_at,
                created_by=ctx.principal.user_id,
            ),
        )
    except UrlError as exc:
        raise ValidationProblem(str(exc).capitalize() + ".", code="invalid_url") from exc
    added = await add_evidence(
        ctx.db,
        cipher,
        inv,
        EvidenceInput(
            excerpt=body.excerpt,
            evidence_type="manual_capture",
            provenance="source_reported",
            source_id=upsert.source.id,
            published_at=body.published_at,
            created_by=ctx.principal.user_id,
        ),
    )
    finding_id = None
    if body.statement:
        category = body.category if body.category in {c.value for c in FindingCategory} else "analysis"
        finding = await findings.create_finding(
            ctx.db,
            cipher,
            inv,
            FindingInput(
                statement=body.statement,
                category=category,
                provenance="source_reported",
                links=(LinkInput(added.item.id, directly_states=body.directly_states),),
                created_via="manual",
                created_by=ctx.principal.user_id,
            ),
        )
        finding_id = str(finding.id)
        ctx.audit(
            "finding.created",
            target_type="finding",
            target_id=finding_id,
            details={"provenance": "source_reported", "links": 1, "via": "manual_capture"},
        )
    ctx.audit(
        "evidence.created",
        target_type="evidence",
        target_id=str(added.item.id),
        details={
            "via": "manual_capture",
            "created": added.created,
            "source_created": upsert.created,
            "redactions": dict(added.item.redaction_counts),
        },
    )
    return ManualCaptureOut(
        evidence=EvidenceOut(**_out(cipher, added.item, upsert.source, full=True)),
        created=added.created,
        finding_id=finding_id,
    )


@router.get(BASE + "/{evidence_id}")
async def get_evidence(evidence_id: uuid.UUID, ctx: ReadCtx, reveal: bool = False) -> EvidenceDetail:
    item = await get_scoped(ctx.db, EvidenceItem, ctx, evidence_id)
    source = await ctx.db.get(Source, item.source_id) if item.source_id else None
    cipher = await ctx.cipher()
    if reveal and item.sensitivity_flags:
        ctx.audit(
            "evidence.sensitive_revealed",
            target_type="evidence",
            target_id=str(item.id),
            details={"flags": list(item.sensitivity_flags)},
        )
    links = (
        await ctx.db.execute(
            select(FindingEvidence, Finding)
            .join(Finding, Finding.id == FindingEvidence.finding_id)
            .where(FindingEvidence.evidence_id == item.id)
            .order_by(Finding.label_seq)
        )
    ).all()
    rel_ids = (
        (
            await ctx.db.execute(
                select(RelationshipEvidence.relationship_id).where(RelationshipEvidence.evidence_id == item.id)
            )
        )
        .scalars()
        .all()
    )
    event_ids = (
        (
            await ctx.db.execute(
                select(TimelineEventEvidence.event_id).where(TimelineEventEvidence.evidence_id == item.id)
            )
        )
        .scalars()
        .all()
    )
    return EvidenceDetail(
        **_out(cipher, item, source, full=True, reveal=reveal),
        findings=[
            LinkedFinding(
                id=str(f.id),
                label=f"F-{f.label_seq}",
                statement=findings.open_statement(cipher, f),
                verification_status=f.verification_status,
                provenance=f.provenance,
                stance=link.stance,
                directly_states=link.directly_states,
                dismissed=link.dismissed_at is not None,
            )
            for link, f in links
        ],
        relationship_ids=[str(r) for r in dict.fromkeys(rel_ids)],
        timeline_event_ids=[str(e) for e in dict.fromkeys(event_ids)],
    )


@router.patch(BASE + "/{evidence_id}")
async def annotate_evidence(evidence_id: uuid.UUID, body: EvidencePatch, ctx: WriteCtx) -> EvidenceOut:
    """Reviewer annotations only; the captured content itself is immutable."""
    item = await get_scoped(ctx.db, EvidenceItem, ctx, evidence_id)
    changed: list[str] = []
    if body.credibility is not None:
        item.credibility = body.credibility
        changed.append("credibility")
    if body.clear_location:
        item.country, item.region = None, None
        changed.append("location")
    else:
        if body.country is not None:
            item.country = body.country
            changed.append("country")
        if body.region is not None:
            if not _ISO_REGION.match(body.region) or (item.country and not body.region.startswith(item.country)):
                raise ValidationProblem("Use an ISO 3166-2 region code matching the country.", code="invalid_region")
            item.region = body.region
            changed.append("region")
    await ctx.db.flush()
    ctx.audit("evidence.annotated", target_type="evidence", target_id=str(item.id), details={"fields": changed})
    source = await ctx.db.get(Source, item.source_id) if item.source_id else None
    return EvidenceOut(**_out(await ctx.cipher(), item, source, full=True))


@router.delete(BASE + "/{evidence_id}")
async def delete_evidence(evidence_id: uuid.UUID, ctx: WriteCtx) -> dict[str, Any]:
    """Delete an evidence item. Unsupported graph edges disappear; affected findings are re-checked."""
    item = await get_scoped(ctx.db, EvidenceItem, ctx, evidence_id)
    stats = await findings.delete_evidence(ctx.db, await ctx.cipher(), ctx.investigation, [item])
    details = stats.as_dict()
    details.pop("evidence_deleted")
    ctx.audit("evidence.deleted", target_type="evidence", target_id=str(evidence_id), details=details)
    return {"status": "deleted", **details}
