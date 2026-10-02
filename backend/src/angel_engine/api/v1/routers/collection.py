"""Public-source collection: connector catalogue, collection runs, transient search leads, page captures and
review suggestions (syndication, corroboration, contradiction)."""

from __future__ import annotations

import uuid
from dataclasses import asdict
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Header, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from angel_engine.api.deps import CurrentPrincipal, InvCtx
from angel_engine.api.v1.routers._common import ReadCtx, VerifyCtx, WriteCtx, get_scoped
from angel_engine.authz.permissions import Perm, role_allows
from angel_engine.core.clock import utcnow
from angel_engine.core.problems import ConflictState, Forbidden
from angel_engine.db.models import CollectionRun, EvidenceItem, Finding, Job, PolicyDecision, Suggestion
from angel_engine.findings import service as findings_service
from angel_engine.findings.service import LinkInput
from angel_engine.osint import collection
from angel_engine.osint.registry import ConnectorStatus

router = APIRouter(tags=["collection"])
BASE = "/investigations/{investigation_id}"


class ConnectorOut(BaseModel):
    id: str
    name: str
    category: str
    category_label: str
    description: str
    input_types: list[str]
    status: str
    reason: str | None
    person_oriented: bool
    allowed_in_restricted_mode: bool
    docs_url: str
    terms_note: str
    requires_key: bool
    available_here: bool | None = None
    needs_purpose_note: bool | None = None
    needs_approval: bool | None = None


class RunIn(BaseModel):
    connector_id: str = Field(max_length=64)
    input_type: Literal["keyword", "domain", "url", "username", "organization", "place"]
    query: str = Field(min_length=1, max_length=500)
    params: dict[str, str] = Field(default_factory=dict, max_length=10)
    purpose_note: str | None = Field(default=None, max_length=1000)
    acknowledge_policy_notices: bool = False
    origin_image_id: uuid.UUID | None = None
    origin_clue_id: uuid.UUID | None = None


class RunOut(BaseModel):
    id: str
    connector_id: str
    input_type: str
    query: str
    status: str
    records_count: int
    references_count: int
    warnings: list[str]
    error_code: str | None
    has_leads: bool
    leads_expire_at: datetime | None
    requested_by_me: bool
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    progress: dict[str, Any] = {}
    policy_decision: str | None = None


class CaptureIn(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=20)


class Lead(BaseModel):
    url: str
    title: str
    snippet: str | None
    publisher: str | None


class SuggestionOut(BaseModel):
    id: str
    kind: str
    status: str
    message: str
    evidence_ids: list[str]
    finding_ids: list[str]
    rule_id: str
    created_at: datetime


class SuggestionDecision(BaseModel):
    note: str | None = Field(default=None, max_length=1000)


def _connector_out(status: ConnectorStatus, ctx: InvCtx | None = None) -> ConnectorOut:
    out = ConnectorOut(**{**asdict(status), "input_types": list(status.input_types)})
    if ctx is not None:
        restricted = ctx.investigation.restricted_mode
        out.available_here = status.status == "ready" and (status.allowed_in_restricted_mode or not restricted)
        out.needs_purpose_note = status.person_oriented
        out.needs_approval = status.person_oriented and restricted
    return out


async def _run_out(ctx: InvCtx, run: CollectionRun) -> RunOut:
    cipher = await ctx.cipher()
    job = (
        await ctx.db.execute(select(Job.progress).where(Job.idempotency_key == f"run:{run.id}"))
    ).scalar_one_or_none()
    decision = None
    if run.policy_decision_id:
        decision = (
            await ctx.db.execute(select(PolicyDecision.decision).where(PolicyDecision.id == run.policy_decision_id))
        ).scalar_one_or_none()
    return RunOut(
        id=str(run.id),
        connector_id=run.connector_id,
        input_type=run.input_type,
        query=cipher.open(run.query, table="collection_runs", column="query", row_id=run.id),
        status=run.status,
        records_count=run.records_count,
        references_count=run.references_count,
        warnings=list(run.warnings),
        error_code=run.error_code,
        has_leads=run.leads is not None and (run.leads_expire_at is None or run.leads_expire_at > utcnow()),
        leads_expire_at=run.leads_expire_at,
        requested_by_me=run.requested_by == ctx.principal.user_id,
        created_at=run.created_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
        progress=job or {},
        policy_decision=decision,
    )


# --------------------------------------------------------------------------------------------------
# Connectors
# --------------------------------------------------------------------------------------------------
@router.get("/connectors")
async def list_connectors(principal: CurrentPrincipal) -> list[ConnectorOut]:
    reg = collection.registry(principal.services)
    return [_connector_out(s) for s in reg.statuses()]


@router.get(BASE + "/connectors")
async def investigation_connectors(ctx: ReadCtx) -> list[ConnectorOut]:
    reg = collection.registry(ctx.principal.services)
    return [_connector_out(s, ctx) for s in reg.statuses()]


# --------------------------------------------------------------------------------------------------
# Runs
# --------------------------------------------------------------------------------------------------
@router.post(BASE + "/collection-runs", status_code=202)
async def create_collection_run(
    body: RunIn, ctx: WriteCtx, idempotency_key: Annotated[str | None, Header(max_length=100)] = None
) -> RunOut:
    cipher = await ctx.cipher()
    run, decision = await collection.create_run(
        ctx.principal.services,
        ctx.db,
        cipher,
        ctx.investigation,
        ctx.principal.user,
        connector_id=body.connector_id,
        input_type=body.input_type,
        query=body.query,
        params=body.params,
        purpose_note=body.purpose_note,
        acknowledge_policy_notices=body.acknowledge_policy_notices,
        origin_image_id=body.origin_image_id,
        origin_clue_id=body.origin_clue_id,
        idempotency_key=idempotency_key,
        actor_event=ctx.principal.event(""),
    )
    ctx.audit(
        "collection.requested",
        target_type="collection_run",
        target_id=str(run.id),
        details={
            "connector": run.connector_id,
            "input_type": run.input_type,
            "status": run.status,
            "policy": decision.value,
            "query_ref": collection.query_fingerprint(cipher, body.query),
        },
    )
    return await _run_out(ctx, run)


@router.get(BASE + "/collection-runs")
async def list_collection_runs(
    ctx: ReadCtx,
    status: Annotated[list[str] | None, Query()] = None,
    connector_id: Annotated[str | None, Query(max_length=64)] = None,
) -> list[RunOut]:
    stmt = select(CollectionRun).where(CollectionRun.investigation_id == ctx.id)
    if status:
        stmt = stmt.where(CollectionRun.status.in_(status))
    if connector_id:
        stmt = stmt.where(CollectionRun.connector_id == connector_id)
    runs = (await ctx.db.execute(stmt.order_by(CollectionRun.created_at.desc()).limit(100))).scalars().all()
    return [await _run_out(ctx, r) for r in runs]


@router.get(BASE + "/collection-runs/{run_id}")
async def get_collection_run(run_id: uuid.UUID, ctx: ReadCtx) -> RunOut:
    run = await get_scoped(ctx.db, CollectionRun, ctx, run_id)
    return await _run_out(ctx, run)


@router.post(BASE + "/collection-runs/{run_id}/cancel")
async def cancel_collection_run(run_id: uuid.UUID, ctx: WriteCtx) -> RunOut:
    run = await get_scoped(ctx.db, CollectionRun, ctx, run_id)
    if run.status not in ("queued", "pending_review"):
        raise ConflictState("Only queued or pending runs can be cancelled.", code="run_state")
    run.status, run.finished_at = "cancelled", utcnow()
    await ctx.db.execute(
        update(Job)
        .where(Job.idempotency_key == f"run:{run.id}", Job.status == "queued")
        .values(status="cancelled", finished_at=utcnow())
    )
    ctx.audit("collection.cancelled", target_type="collection_run", target_id=str(run.id))
    return await _run_out(ctx, run)


def _require_reviewer(ctx: InvCtx, run: CollectionRun) -> None:
    if not role_allows(ctx.principal.role, Perm.POLICY_REVIEW):
        raise Forbidden("A supervisor must review this request.", code="supervisor_required")
    if run.requested_by == ctx.principal.user_id:
        raise Forbidden("You cannot approve your own request.", code="self_review")
    if run.status != "pending_review":
        raise ConflictState("This run is not awaiting review.", code="run_state")


@router.post(BASE + "/collection-runs/{run_id}/approve")
async def approve_collection_run(run_id: uuid.UUID, ctx: ReadCtx, body: SuggestionDecision | None = None) -> RunOut:
    """A supervisor (not the requester) approves a collection run that is waiting for review."""
    run = await get_scoped(ctx.db, CollectionRun, ctx, run_id)
    _require_reviewer(ctx, run)
    if ctx.investigation.status != "active":
        raise ConflictState("The investigation is not active.", code="investigation_state")
    await collection.queue_run(ctx.db, run, ctx.principal.user_id)
    ctx.audit("collection.approved", target_type="collection_run", target_id=str(run.id))
    return await _run_out(ctx, run)


@router.post(BASE + "/collection-runs/{run_id}/reject")
async def reject_collection_run(run_id: uuid.UUID, ctx: ReadCtx, body: SuggestionDecision | None = None) -> RunOut:
    run = await get_scoped(ctx.db, CollectionRun, ctx, run_id)
    _require_reviewer(ctx, run)
    run.status, run.finished_at, run.error_code = "refused", utcnow(), "rejected_by_reviewer"
    ctx.audit("collection.rejected", target_type="collection_run", target_id=str(run.id))
    return await _run_out(ctx, run)


@router.get(BASE + "/collection-runs/{run_id}/leads")
async def collection_leads(run_id: uuid.UUID, ctx: ReadCtx) -> list[Lead]:
    """Transient search-engine leads (kept 24 hours). Capture the ones you need to keep them as evidence."""
    run = await get_scoped(ctx.db, CollectionRun, ctx, run_id)
    if run.leads is None or (run.leads_expire_at is not None and run.leads_expire_at <= utcnow()):
        return []
    cipher = await ctx.cipher()
    data = cipher.open_json(run.leads, table="collection_runs", column="leads", row_id=run.id)
    return [Lead(**item) for item in data]


@router.post(BASE + "/captures", status_code=202)
async def capture_pages(body: CaptureIn, ctx: WriteCtx) -> list[RunOut]:
    """Capture selected public pages (e.g. chosen search leads). Each URL becomes a page-capture run."""
    cipher = await ctx.cipher()
    runs = []
    for url in dict.fromkeys(u.strip() for u in body.urls if u.strip()):
        run, decision = await collection.create_run(
            ctx.principal.services,
            ctx.db,
            cipher,
            ctx.investigation,
            ctx.principal.user,
            connector_id="web_capture",
            input_type="url",
            query=url,
            actor_event=ctx.principal.event(""),
            acknowledge_policy_notices=True,
        )
        ctx.audit(
            "collection.requested",
            target_type="collection_run",
            target_id=str(run.id),
            details={
                "connector": "web_capture",
                "status": run.status,
                "policy": decision.value,
                "query_ref": collection.query_fingerprint(cipher, url),
            },
        )
        runs.append(await _run_out(ctx, run))
    return runs


# --------------------------------------------------------------------------------------------------
# Suggestions
# --------------------------------------------------------------------------------------------------
async def _suggestion_out(ctx: InvCtx, s: Suggestion) -> SuggestionOut:
    cipher = await ctx.cipher()
    return SuggestionOut(
        id=str(s.id),
        kind=s.kind,
        status=s.status,
        message=cipher.open(s.message, table="suggestions", column="message", row_id=s.id),
        evidence_ids=[str(e) for e in s.evidence_ids],
        finding_ids=[str(f) for f in s.finding_ids],
        rule_id=s.rule_id,
        created_at=s.created_at,
    )


@router.get(BASE + "/suggestions")
async def list_suggestions(
    ctx: ReadCtx,
    status: Literal["open", "accepted", "dismissed"] | None = "open",
    kind: Annotated[list[str] | None, Query()] = None,
) -> list[SuggestionOut]:
    stmt = select(Suggestion).where(Suggestion.investigation_id == ctx.id)
    if status:
        stmt = stmt.where(Suggestion.status == status)
    if kind:
        stmt = stmt.where(Suggestion.kind.in_(kind))
    rows = (await ctx.db.execute(stmt.order_by(Suggestion.created_at.desc()).limit(200))).scalars().all()
    return [await _suggestion_out(ctx, s) for s in rows]


@router.post(BASE + "/suggestions/{suggestion_id}/dismiss")
async def dismiss_suggestion(
    suggestion_id: uuid.UUID, ctx: VerifyCtx, body: SuggestionDecision | None = None
) -> SuggestionOut:
    suggestion = await get_scoped(ctx.db, Suggestion, ctx, suggestion_id)
    if suggestion.status != "open":
        raise ConflictState("This suggestion was already decided.", code="suggestion_state")
    suggestion.status, suggestion.decided_by, suggestion.decided_at = "dismissed", ctx.principal.user_id, utcnow()
    if suggestion.kind == "syndication" and len(suggestion.evidence_ids) == 2:
        # The reviewer says these are independent copies: take them out of the shared cluster.
        await ctx.db.execute(
            update(EvidenceItem).where(EvidenceItem.id.in_(suggestion.evidence_ids)).values(syndication_cluster_id=None)
        )
    ctx.audit(
        "suggestion.dismissed",
        target_type="suggestion",
        target_id=str(suggestion.id),
        details={"kind": suggestion.kind},
    )
    return await _suggestion_out(ctx, suggestion)


@router.post(BASE + "/suggestions/{suggestion_id}/accept")
async def accept_suggestion(
    suggestion_id: uuid.UUID, ctx: VerifyCtx, body: SuggestionDecision | None = None
) -> SuggestionOut:
    """Accepting a contradiction links each side's evidence to the other side's findings as contradicting
    (which may downgrade them); accepting a corroboration adds the agreeing evidence as support."""
    suggestion = await get_scoped(ctx.db, Suggestion, ctx, suggestion_id)
    if suggestion.status != "open":
        raise ConflictState("This suggestion was already decided.", code="suggestion_state")
    cipher = await ctx.cipher()
    if suggestion.kind in ("contradiction", "corroboration") and suggestion.finding_ids:
        stance = "contradicts" if suggestion.kind == "contradiction" else "supports"
        for finding in (await ctx.db.execute(select(Finding).where(Finding.id.in_(suggestion.finding_ids)))).scalars():
            cited = {link.evidence.id for link in await findings_service.load_links(ctx.db, finding.id)}
            others = [e for e in suggestion.evidence_ids if e not in cited]
            if others and cited & set(suggestion.evidence_ids):
                await findings_service.add_links(
                    ctx.db, ctx.investigation, finding, [LinkInput(e, stance) for e in others], ctx.principal.user_id
                )
                await findings_service.recheck(ctx.db, cipher, ctx.investigation, finding)
    suggestion.status, suggestion.decided_by, suggestion.decided_at = "accepted", ctx.principal.user_id, utcnow()
    ctx.audit(
        "suggestion.accepted", target_type="suggestion", target_id=str(suggestion.id), details={"kind": suggestion.kind}
    )
    return await _suggestion_out(ctx, suggestion)


# --------------------------------------------------------------------------------------------------
# Manual search links (opened by the investigator; never fetched by Angel Engine)
# --------------------------------------------------------------------------------------------------
class ManualLink(BaseModel):
    provider: str
    label: str
    url: str


MANUAL_SEARCH_PROVIDERS: tuple[tuple[str, str, str], ...] = (
    ("google", "Google", "https://www.google.com/search?q={q}"),
    ("bing", "Bing", "https://www.bing.com/search?q={q}"),
    ("duckduckgo", "DuckDuckGo", "https://duckduckgo.com/?q={q}"),
    ("brave", "Brave Search", "https://search.brave.com/search?q={q}"),
    ("google_news", "Google News", "https://news.google.com/search?q={q}"),
    ("wayback", "Wayback Machine", "https://web.archive.org/web/*/{q}*"),
)


@router.get(BASE + "/manual-search-links")
async def manual_search_links(ctx: ReadCtx, q: Annotated[str, Query(min_length=2, max_length=300)]) -> list[ManualLink]:
    """Search links the investigator opens in their own browser (no automated scraping of search engines).

    The query is screened like any collection query; a refusal is recorded and returned as a problem.
    """
    from urllib.parse import quote_plus

    from angel_engine.policy.types import PolicyContext, Surface
    from angel_engine.policy_gate import preflight

    await preflight(
        ctx.principal.services,
        ctx.db,
        ctx.principal.user,
        q,
        PolicyContext(
            surface=Surface.COLLECTION_QUERY,
            subject_type=ctx.investigation.subject_type,
            restricted_mode=ctx.investigation.restricted_mode,
        ),
        actor_event=ctx.principal.event("", investigation_id=ctx.id),
    )
    encoded = quote_plus(q.strip())
    return [
        ManualLink(provider=p, label=label, url=template.format(q=encoded))
        for p, label, template in MANUAL_SEARCH_PROVIDERS
    ]
