"""Findings: claims backed by evidence, shown as Source → Finding → Evidence → Timestamp → Confidence →
Verification Status, with human-only, precondition-checked status transitions and a full history."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import exists, or_, select

from angel_engine.api.deps import InvCtx
from angel_engine.api.v1.routers._common import (
    IfMatch,
    Keyset,
    Page,
    ReadCtx,
    SourceMini,
    VerifyCtx,
    WriteCtx,
    get_scoped,
    require_version,
    snippet,
    source_mini,
)
from angel_engine.core.clock import utcnow
from angel_engine.core.enums import Confidence, FindingCategory, Provenance, Stance, VerificationStatus
from angel_engine.core.problems import ConflictState, ValidationProblem
from angel_engine.crypto.blind_index import query_tokens
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.db.models import (
    EntityMention,
    EvidenceItem,
    Finding,
    FindingEvidence,
    FindingStatusHistory,
    Source,
    User,
)
from angel_engine.evidence.service import evidence_view
from angel_engine.findings import service as svc
from angel_engine.findings.service import FindingInput, LinkInput, TransitionRequest

router = APIRouter(tags=["findings"])
BASE = "/investigations/{investigation_id}/findings"
CATEGORIES = frozenset(c.value for c in FindingCategory)


# --------------------------------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------------------------------
class ConfidenceOut(BaseModel):
    level: str
    basis: str | None


class EvidenceSnippet(BaseModel):
    id: str
    label: str
    excerpt: str | None
    stance: str


class EvidenceSummary(BaseModel):
    count: int
    supporting: int
    contradicting: int
    context: int
    items: list[EvidenceSnippet]


class Timestamps(BaseModel):
    captured_at: datetime | None
    published_at: datetime | None
    event_time: datetime | None
    event_precision: str | None
    status_changed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class FindingRow(BaseModel):
    id: str
    label: str
    source: SourceMini | None
    statement: str
    evidence: EvidenceSummary
    timestamps: Timestamps
    confidence: ConfidenceOut | None
    verification_status: str
    provenance: str
    category: str
    importance: str
    sensitive: bool
    has_active_contradiction: bool
    retracted: bool
    evidence_removed: bool
    version: int


class LinkOut(BaseModel):
    id: str
    stance: str
    directly_states: bool
    dismissed: bool
    dismissed_at: datetime | None
    dismissed_reason: str | None
    created_at: datetime
    evidence: dict[str, Any]
    source: SourceMini | None


class HistoryOut(BaseModel):
    from_status: str | None
    to_status: str
    actor_name: str | None
    automatic: bool
    justification: str | None
    evidence_ids: list[str]
    precondition_snapshot: dict[str, Any]
    created_at: datetime


class FindingDetail(FindingRow):
    links: list[LinkOut]
    allowed_transitions: list[str]
    failed_preconditions: dict[str, list[str]]
    history: list[HistoryOut]


class LinkIn(BaseModel):
    evidence_id: uuid.UUID
    stance: Literal["supports", "contradicts", "context"] = "supports"
    directly_states: bool = False


class FindingCreate(BaseModel):
    statement: str = Field(min_length=10, max_length=2000)
    category: str
    provenance: Literal["observed", "source_reported", "analyst_inference"] = "source_reported"
    #: The claim came from an external AI tool: it is stored with AI provenance and the AI-hypothesis status.
    from_external_ai: bool = False
    links: list[LinkIn] = Field(default_factory=list, max_length=50)
    confidence: Confidence | None = None
    confidence_basis: str | None = Field(default=None, max_length=500)
    sensitive: bool = False
    importance: Literal["key", "normal"] = "normal"
    event_time: datetime | None = None
    event_precision: Literal["exact", "minute", "hour", "day", "month", "year", "approximate"] | None = None

    @field_validator("category")
    @classmethod
    def _category(cls, value: str) -> str:
        if value not in CATEGORIES:
            raise ValueError("unknown category")
        return value


class FindingPatch(BaseModel):
    importance: Literal["key", "normal"] | None = None
    confidence: Confidence | None = None
    confidence_basis: str | None = Field(default=None, max_length=500)
    clear_confidence: bool = False
    sensitive: bool | None = None
    event_time: datetime | None = None
    event_precision: Literal["exact", "minute", "hour", "day", "month", "year", "approximate"] | None = None
    clear_event_time: bool = False


class LinksIn(BaseModel):
    links: list[LinkIn] = Field(min_length=1, max_length=50)


class DismissIn(BaseModel):
    reason: str = Field(min_length=20, max_length=2000)


class LinkPatch(BaseModel):
    directly_states: bool


class TransitionIn(BaseModel):
    to_status: VerificationStatus
    justification: str = Field(min_length=20, max_length=4000)
    evidence_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    independence_attested: bool = False


class RetractIn(BaseModel):
    justification: str = Field(min_length=20, max_length=4000)


class TransitionsOut(BaseModel):
    current: str
    allowed_transitions: list[str]
    failed_preconditions: dict[str, list[str]]
    snapshot: dict[str, Any]


# --------------------------------------------------------------------------------------------------
# Row building
# --------------------------------------------------------------------------------------------------
async def links_for(ctx: InvCtx, finding_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, list[Any]]:
    if not finding_ids:
        return {}
    rows = (
        await ctx.db.execute(
            select(FindingEvidence, EvidenceItem, Source)
            .join(EvidenceItem, EvidenceItem.id == FindingEvidence.evidence_id)
            .outerjoin(Source, Source.id == EvidenceItem.source_id)
            .where(FindingEvidence.finding_id.in_(finding_ids))
            .order_by(FindingEvidence.created_at)
        )
    ).all()
    out: dict[uuid.UUID, list[Any]] = {}
    for link, ev, src in rows:
        out.setdefault(link.finding_id, []).append((link, ev, src))
    return out


def finding_row(cipher: FieldCipher, finding: Finding, links: list[Any]) -> dict[str, Any]:
    active = [(lk, ev, src) for lk, ev, src in links if lk.dismissed_at is None]
    support = [x for x in active if x[0].stance == Stance.SUPPORTS.value]
    contra = [x for x in active if x[0].stance == Stance.CONTRADICTS.value]
    primary = (
        next((x for x in support if x[0].directly_states and x[2] is not None), None)
        or next((x for x in support if x[2] is not None), None)
        or next((x for x in active if x[2] is not None), None)
    )
    captured = [ev.captured_at for _, ev, _ in support] or [ev.captured_at for _, ev, _ in active]
    published = [
        d
        for d in (
            [ev.published_at for _, ev, _ in support] + [src.published_at for _, _, src in support if src is not None]
        )
        if d is not None
    ]
    snippets = []
    for link, ev, _ in active[:3]:
        hidden = bool(ev.sensitivity_flags)
        text = None if hidden else cipher.open(ev.excerpt, table="evidence_items", column="excerpt", row_id=ev.id)
        snippets.append(
            EvidenceSnippet(id=str(ev.id), label=f"E-{ev.label_seq}", excerpt=snippet(text, 200), stance=link.stance)
        )
    confidence = svc.confidence_view(cipher, finding)
    return {
        "id": str(finding.id),
        "label": f"F-{finding.label_seq}",
        "source": source_mini(cipher, primary[2]) if primary else None,
        "statement": svc.open_statement(cipher, finding),
        "evidence": EvidenceSummary(
            count=len(active),
            supporting=len(support),
            contradicting=len(contra),
            context=sum(1 for x in active if x[0].stance == Stance.CONTEXT.value),
            items=snippets,
        ),
        "timestamps": Timestamps(
            captured_at=min(captured) if captured else None,
            published_at=min(published) if published else None,
            event_time=finding.event_time,
            event_precision=finding.event_precision,
            status_changed_at=finding.status_changed_at,
            created_at=finding.created_at,
            updated_at=finding.updated_at,
        ),
        "confidence": ConfidenceOut(**confidence) if confidence else None,
        "verification_status": finding.verification_status,
        "provenance": finding.provenance,
        "category": finding.category,
        "importance": finding.importance,
        "sensitive": finding.sensitive,
        "has_active_contradiction": bool(contra),
        "retracted": finding.retracted_at is not None,
        "evidence_removed": finding.evidence_removed,
        "version": finding.version,
    }


async def _detail(ctx: InvCtx, finding: Finding, response: Response | None = None) -> FindingDetail:
    await ctx.db.flush()  # pending changes bump the row version; report the version the client must send next
    cipher = await ctx.cipher()
    links = (await links_for(ctx, [finding.id])).get(finding.id, [])
    infos = await svc.load_links(ctx.db, finding.id)
    evaluation = svc.evaluate(
        finding,
        infos,
        restricted_mode=ctx.investigation.restricted_mode,
        actor_role=ctx.principal.role,
        actor_id=ctx.principal.user_id,
    )
    history = (
        (
            await ctx.db.execute(
                select(FindingStatusHistory)
                .where(FindingStatusHistory.finding_id == finding.id)
                .order_by(FindingStatusHistory.created_at)
            )
        )
        .scalars()
        .all()
    )
    actors = {h.actor_id for h in history if h.actor_id}
    names = (
        dict((await ctx.db.execute(select(User.id, User.display_name).where(User.id.in_(actors)))).all())
        if actors
        else {}
    )
    if response is not None:
        response.headers["ETag"] = f'"{finding.version}"'
    return FindingDetail(
        **finding_row(cipher, finding, links),
        links=[
            LinkOut(
                id=str(link.id),
                stance=link.stance,
                directly_states=link.directly_states,
                dismissed=link.dismissed_at is not None,
                dismissed_at=link.dismissed_at,
                dismissed_reason=cipher.open_optional(
                    link.dismissed_reason, table="finding_evidence", column="dismissed_reason", row_id=link.id
                ),
                created_at=link.created_at,
                evidence=evidence_view(cipher, ev),
                source=source_mini(cipher, src) if src is not None else None,
            )
            for link, ev, src in links
        ],
        allowed_transitions=list(evaluation.allowed),
        failed_preconditions=evaluation.failed,
        history=[
            HistoryOut(
                from_status=h.from_status,
                to_status=h.to_status,
                actor_name=names.get(h.actor_id) if h.actor_id else None,
                automatic=h.automatic,
                justification=cipher.open_optional(
                    h.justification, table="finding_status_history", column="justification", row_id=h.id
                ),
                evidence_ids=[str(e) for e in h.evidence_ids],
                precondition_snapshot=h.precondition_snapshot,
                created_at=h.created_at,
            )
            for h in history
        ],
    )


# --------------------------------------------------------------------------------------------------
# List / create / read / edit
# --------------------------------------------------------------------------------------------------
@router.get(BASE)
async def list_findings(
    ctx: ReadCtx,
    status: Annotated[list[VerificationStatus] | None, Query()] = None,
    provenance: Annotated[list[Provenance] | None, Query()] = None,
    category: Annotated[list[str] | None, Query()] = None,
    confidence: Annotated[list[Literal["low", "moderate", "high", "none"]] | None, Query()] = None,
    importance: Literal["key", "normal"] | None = None,
    source_id: uuid.UUID | None = None,
    source_category: Annotated[list[str] | None, Query()] = None,
    domain: Annotated[str | None, Query(max_length=253)] = None,
    connector: Annotated[str | None, Query(max_length=64)] = None,
    evidence_type: Annotated[list[str] | None, Query()] = None,
    entity_id: uuid.UUID | None = None,
    captured_from: datetime | None = None,
    captured_to: datetime | None = None,
    published_from: datetime | None = None,
    published_to: datetime | None = None,
    country: Annotated[str | None, Query(pattern=r"^[A-Z]{2}$")] = None,
    region: Annotated[str | None, Query(max_length=10)] = None,
    has_contradictions: bool | None = None,
    include_retracted: bool = True,
    q: Annotated[str | None, Query(max_length=200)] = None,
    sort: Literal["updated", "created"] = "updated",
    limit: Annotated[int | None, Query(ge=1, le=100)] = None,
    cursor: Annotated[str | None, Query(max_length=600)] = None,
) -> Page[FindingRow]:
    raw = {
        "status": status,
        "provenance": provenance,
        "category": category,
        "confidence": confidence,
        "importance": importance,
        "source_id": source_id,
        "source_category": source_category,
        "domain": domain,
        "connector": connector,
        "evidence_type": evidence_type,
        "entity_id": entity_id,
        "captured_from": captured_from,
        "captured_to": captured_to,
        "published_from": published_from,
        "published_to": published_to,
        "country": country,
        "region": region,
        "has_contradictions": has_contradictions,
        "include_retracted": include_retracted,
        "q": bool(q),
        "sort": sort,
    }
    keyset = Keyset(
        ctx,
        {
            k: sorted(map(str, v)) if isinstance(v, list) else (str(v) if v is not None else None)
            for k, v in raw.items()
        },
        limit,
        cursor,
    )
    stmt = select(Finding).where(Finding.investigation_id == ctx.id)
    if status:
        stmt = stmt.where(Finding.verification_status.in_([s.value for s in status]))
    if provenance:
        stmt = stmt.where(Finding.provenance.in_([p.value for p in provenance]))
    if category:
        stmt = stmt.where(Finding.category.in_(category))
    if confidence:
        levels = [c for c in confidence if c != "none"]
        clauses = [Finding.confidence.in_(levels)] if levels else []
        if "none" in confidence:
            clauses.append(Finding.confidence.is_(None))
        stmt = stmt.where(or_(*clauses))
    if importance:
        stmt = stmt.where(Finding.importance == importance)
    if not include_retracted:
        stmt = stmt.where(Finding.retracted_at.is_(None))

    evidence_clauses: list[Any] = []
    if source_id:
        evidence_clauses.append(EvidenceItem.source_id == source_id)
    if source_category:
        evidence_clauses.append(Source.source_category.in_(source_category))
    if domain:
        evidence_clauses.append(Source.registrable_domain == domain.strip().lower())
    if connector:
        evidence_clauses.append(Source.connector_id == connector)
    if evidence_type:
        evidence_clauses.append(EvidenceItem.evidence_type.in_(evidence_type))
    if captured_from:
        evidence_clauses.append(EvidenceItem.captured_at >= captured_from)
    if captured_to:
        evidence_clauses.append(EvidenceItem.captured_at <= captured_to)
    if published_from:
        evidence_clauses.append(EvidenceItem.published_at >= published_from)
    if published_to:
        evidence_clauses.append(EvidenceItem.published_at <= published_to)
    if country:
        evidence_clauses.append(EvidenceItem.country == country)
    if region:
        evidence_clauses.append(EvidenceItem.region == region)
    if evidence_clauses:
        stmt = stmt.where(
            exists(
                select(FindingEvidence.id)
                .join(EvidenceItem, EvidenceItem.id == FindingEvidence.evidence_id)
                .outerjoin(Source, Source.id == EvidenceItem.source_id)
                .where(
                    FindingEvidence.finding_id == Finding.id, FindingEvidence.dismissed_at.is_(None), *evidence_clauses
                )
            )
        )
    if entity_id:
        stmt = stmt.where(
            exists(
                select(FindingEvidence.id)
                .join(EntityMention, EntityMention.evidence_id == FindingEvidence.evidence_id)
                .where(FindingEvidence.finding_id == Finding.id, EntityMention.entity_id == entity_id)
            )
        )
    if has_contradictions is not None:
        contra = exists(
            select(FindingEvidence.id).where(
                FindingEvidence.finding_id == Finding.id,
                FindingEvidence.stance == Stance.CONTRADICTS.value,
                FindingEvidence.dismissed_at.is_(None),
            )
        )
        stmt = stmt.where(contra if has_contradictions else ~contra)
    cipher = await ctx.cipher()
    if q:
        wanted = query_tokens(cipher, q)
        if wanted:
            stmt = stmt.where(
                or_(
                    Finding.statement_tokens.contains(wanted),
                    exists(
                        select(FindingEvidence.id)
                        .join(EvidenceItem, EvidenceItem.id == FindingEvidence.evidence_id)
                        .where(FindingEvidence.finding_id == Finding.id, EvidenceItem.search_tokens.contains(wanted))
                    ),
                )
            )
    ts_col = Finding.updated_at if sort == "updated" else Finding.created_at
    rows = list((await ctx.db.execute(keyset.apply(stmt, ts_col, Finding.id))).scalars())
    rows, next_cursor = keyset.page(rows, lambda f: (f.updated_at if sort == "updated" else f.created_at, f.id))
    links = await links_for(ctx, [f.id for f in rows])
    items = [FindingRow(**finding_row(cipher, f, links.get(f.id, []))) for f in rows]
    return Page(items=items, next_cursor=next_cursor, has_more=next_cursor is not None)


@router.post(BASE, status_code=201)
async def create_finding(body: FindingCreate, ctx: WriteCtx, response: Response) -> FindingDetail:
    cipher = await ctx.cipher()
    provenance = Provenance.AI_HYPOTHESIS.value if body.from_external_ai else body.provenance
    if provenance == Provenance.AI_HYPOTHESIS.value and body.confidence is not None:
        raise ValidationProblem("AI hypotheses do not carry a confidence level.", code="confidence_not_allowed")
    finding = await svc.create_finding(
        ctx.db,
        cipher,
        ctx.investigation,
        FindingInput(
            statement=body.statement,
            category=body.category,
            provenance=provenance,
            links=tuple(LinkInput(link.evidence_id, link.stance, link.directly_states) for link in body.links),
            confidence=body.confidence.value if body.confidence else None,
            confidence_basis=body.confidence_basis,
            sensitive=body.sensitive,
            importance=body.importance,
            event_time=body.event_time,
            event_precision=body.event_precision,
            created_via="import" if body.from_external_ai else "manual",
            created_by=ctx.principal.user_id,
        ),
    )
    ctx.audit(
        "finding.created",
        target_type="finding",
        target_id=str(finding.id),
        details={"provenance": provenance, "links": len(body.links), "category": body.category},
    )
    return await _detail(ctx, finding, response)


@router.get(BASE + "/{finding_id}")
async def get_finding(finding_id: uuid.UUID, ctx: ReadCtx, response: Response) -> FindingDetail:
    finding = await get_scoped(ctx.db, Finding, ctx, finding_id)
    return await _detail(ctx, finding, response)


@router.patch(BASE + "/{finding_id}")
async def update_finding(
    finding_id: uuid.UUID, body: FindingPatch, ctx: WriteCtx, response: Response, if_match: IfMatch = None
) -> FindingDetail:
    """Edit annotations. The statement itself is not editable — retract it and record a new finding."""
    finding = await get_scoped(ctx.db, Finding, ctx, finding_id)
    require_version(if_match, finding.version)
    cipher = await ctx.cipher()
    changed: list[str] = []
    if body.importance is not None:
        finding.importance = body.importance
        changed.append("importance")
    sensitive = finding.sensitive if body.sensitive is None else body.sensitive
    if body.clear_confidence:
        finding.confidence, finding.confidence_basis = None, None
        changed.append("confidence")
    elif body.confidence is not None:
        if sensitive:
            raise ValidationProblem(
                "Confidence levels are not recorded for sensitive findings.", code="confidence_not_allowed"
            )
        if finding.provenance == Provenance.AI_HYPOTHESIS.value:
            raise ValidationProblem("AI hypotheses do not carry a confidence level.", code="confidence_not_allowed")
        basis = (body.confidence_basis or "").strip()
        if not basis:
            raise ValidationProblem("State the basis for the confidence level.", code="confidence_basis_required")
        finding.confidence = body.confidence.value
        finding.confidence_basis = cipher.seal(basis, table="findings", column="confidence_basis", row_id=finding.id)
        changed.append("confidence")
    if body.sensitive is not None:
        if body.sensitive and finding.confidence is not None:
            finding.confidence, finding.confidence_basis = None, None
        finding.sensitive = body.sensitive
        changed.append("sensitive")
    if body.clear_event_time:
        finding.event_time, finding.event_precision = None, None
        changed.append("event_time")
    elif body.event_time is not None:
        finding.event_time, finding.event_precision = body.event_time, body.event_precision or "day"
        changed.append("event_time")
    finding.updated_at = utcnow()
    await ctx.db.flush()
    ctx.audit("finding.updated", target_type="finding", target_id=str(finding.id), details={"fields": changed})
    return await _detail(ctx, finding, response)


@router.post(BASE + "/{finding_id}/retract")
async def retract_finding(
    finding_id: uuid.UUID, body: RetractIn, ctx: VerifyCtx, response: Response, if_match: IfMatch = None
) -> FindingDetail:
    finding = await get_scoped(ctx.db, Finding, ctx, finding_id)
    require_version(if_match, finding.version)
    if finding.retracted_at is not None:
        raise ConflictState("This finding is already retracted.", code="already_retracted")
    cipher = await ctx.cipher()
    finding.retracted_at = utcnow()
    to_status = (
        VerificationStatus.AI_HYPOTHESIS.value
        if finding.provenance == Provenance.AI_HYPOTHESIS.value
        else VerificationStatus.UNVERIFIED.value
    )
    await svc.record_status(
        ctx.db,
        cipher,
        finding,
        to_status,
        actor_id=ctx.principal.user_id,
        justification=body.justification.strip(),
        evidence_ids=(),
        snapshot={"event": "retracted"},
        automatic=False,
    )
    ctx.audit("finding.retracted", target_type="finding", target_id=str(finding.id))
    return await _detail(ctx, finding, response)


# --------------------------------------------------------------------------------------------------
# Evidence links
# --------------------------------------------------------------------------------------------------
def _audit_downgrade(ctx: InvCtx, finding: Finding, result: str | None) -> None:
    if result:
        ctx.audit(
            "finding.status_downgraded",
            target_type="finding",
            target_id=str(finding.id),
            details={"to": result, "automatic": True},
        )


@router.post(BASE + "/{finding_id}/evidence-links", status_code=201)
async def add_evidence_links(finding_id: uuid.UUID, body: LinksIn, ctx: WriteCtx, response: Response) -> FindingDetail:
    finding = await get_scoped(ctx.db, Finding, ctx, finding_id)
    created = await svc.add_links(
        ctx.db,
        ctx.investigation,
        finding,
        [LinkInput(x.evidence_id, x.stance, x.directly_states) for x in body.links],
        ctx.principal.user_id,
    )
    finding.updated_at = utcnow()
    await ctx.db.flush()
    ctx.audit(
        "finding.links_added",
        target_type="finding",
        target_id=str(finding.id),
        details={"added": len(created), "stances": sorted({x.stance for x in body.links})},
    )
    # A new contradicting link may invalidate a promotion.
    _audit_downgrade(ctx, finding, await svc.recheck(ctx.db, await ctx.cipher(), ctx.investigation, finding))
    return await _detail(ctx, finding, response)


@router.post(BASE + "/{finding_id}/evidence-links/{link_id}/dismiss")
async def dismiss_evidence_link(
    finding_id: uuid.UUID, link_id: uuid.UUID, body: DismissIn, ctx: VerifyCtx, response: Response
) -> FindingDetail:
    finding = await get_scoped(ctx.db, Finding, ctx, finding_id)
    result = await svc.dismiss_link(
        ctx.db, await ctx.cipher(), ctx.investigation, finding, link_id, body.reason, ctx.principal.user_id
    )
    finding.updated_at = utcnow()
    ctx.audit(
        "finding.link_dismissed", target_type="finding", target_id=str(finding.id), details={"link_id": str(link_id)}
    )
    _audit_downgrade(ctx, finding, result)
    return await _detail(ctx, finding, response)


@router.patch(BASE + "/{finding_id}/evidence-links/{link_id}")
async def update_evidence_link(
    finding_id: uuid.UUID, link_id: uuid.UUID, body: LinkPatch, ctx: WriteCtx, response: Response
) -> FindingDetail:
    finding = await get_scoped(ctx.db, Finding, ctx, finding_id)
    result = await svc.set_directly_states(
        ctx.db, await ctx.cipher(), ctx.investigation, finding, link_id, body.directly_states
    )
    ctx.audit(
        "finding.link_updated",
        target_type="finding",
        target_id=str(finding.id),
        details={"link_id": str(link_id), "directly_states": body.directly_states},
    )
    _audit_downgrade(ctx, finding, result)
    return await _detail(ctx, finding, response)


@router.delete(BASE + "/{finding_id}/evidence-links/{link_id}")
async def remove_evidence_link(
    finding_id: uuid.UUID, link_id: uuid.UUID, ctx: WriteCtx, response: Response
) -> FindingDetail:
    finding = await get_scoped(ctx.db, Finding, ctx, finding_id)
    result = await svc.remove_link(ctx.db, await ctx.cipher(), ctx.investigation, finding, link_id)
    finding.updated_at = utcnow()
    ctx.audit(
        "finding.link_removed", target_type="finding", target_id=str(finding.id), details={"link_id": str(link_id)}
    )
    _audit_downgrade(ctx, finding, result)
    return await _detail(ctx, finding, response)


# --------------------------------------------------------------------------------------------------
# Verification status
# --------------------------------------------------------------------------------------------------
@router.get(BASE + "/{finding_id}/allowed-transitions")
async def allowed_transitions(finding_id: uuid.UUID, ctx: ReadCtx) -> TransitionsOut:
    finding = await get_scoped(ctx.db, Finding, ctx, finding_id)
    evaluation = svc.evaluate(
        finding,
        await svc.load_links(ctx.db, finding.id),
        restricted_mode=ctx.investigation.restricted_mode,
        actor_role=ctx.principal.role,
        actor_id=ctx.principal.user_id,
    )
    return TransitionsOut(
        current=finding.verification_status,
        allowed_transitions=list(evaluation.allowed),
        failed_preconditions=evaluation.failed,
        snapshot=evaluation.snapshot,
    )


@router.post(BASE + "/{finding_id}/transitions")
async def change_status(
    finding_id: uuid.UUID, body: TransitionIn, ctx: VerifyCtx, response: Response, if_match: IfMatch = None
) -> FindingDetail:
    """Change the verification status (explicit human action with justification and cited evidence)."""
    finding = await get_scoped(ctx.db, Finding, ctx, finding_id)
    require_version(if_match, finding.version)
    previous = await svc.transition(
        ctx.db,
        await ctx.cipher(),
        ctx.investigation,
        finding,
        TransitionRequest(
            body.to_status.value, body.justification, tuple(body.evidence_ids), body.independence_attested
        ),
        actor_id=ctx.principal.user_id,
        actor_role=ctx.principal.role,
    )
    ctx.audit(
        "finding.status_changed",
        target_type="finding",
        target_id=str(finding.id),
        details={
            "from": previous,
            "to": body.to_status.value,
            "evidence_cited": len(body.evidence_ids),
            "independence_attested": body.independence_attested,
        },
    )
    return await _detail(ctx, finding, response)


@router.get(BASE + "/{finding_id}/history")
async def finding_history(finding_id: uuid.UUID, ctx: ReadCtx) -> list[HistoryOut]:
    finding = await get_scoped(ctx.db, Finding, ctx, finding_id)
    return (await _detail(ctx, finding)).history
