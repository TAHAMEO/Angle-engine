"""Investigation dashboard: summary, statistics, recent findings, mini timeline, mini graph and warnings."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import func, select

from angel_engine.api.v1.routers._common import ReadCtx
from angel_engine.api.v1.routers.findings import FindingRow, finding_row, links_for
from angel_engine.api.v1.routers.timeline import EventOut, event_views
from angel_engine.core.enums import InvestigationStatus, Stance, VerificationStatus
from angel_engine.db.models import (
    Entity,
    EvidenceItem,
    Finding,
    FindingEvidence,
    Image,
    Job,
    Relationship,
    Source,
    Suggestion,
    TimelineEvent,
)
from angel_engine.graph.service import subgraph

router = APIRouter(tags=["dashboard"])
FACE_NOTICE = "A face was detected in the image. Angel Engine does not perform facial identification."


class Warning(BaseModel):
    kind: str
    severity: str  # info | caution | critical
    message: str
    count: int | None = None


class DashboardSummary(BaseModel):
    id: str
    ref: str
    title: str
    status: str
    subject_type: str
    purpose_category: str
    restricted_mode: bool
    created_at: datetime
    updated_at: datetime


class Stats(BaseModel):
    evidence: int
    sources: int
    findings: int
    images: int
    entities: int
    relationships: int
    timeline_events: int
    by_status: dict[str, int]
    by_provenance: dict[str, int]
    by_category: dict[str, int]
    sources_by_category: dict[str, int]


class Dashboard(BaseModel):
    summary: DashboardSummary
    stats: Stats
    recent_findings: list[FindingRow]
    timeline: list[EventOut]
    graph: dict[str, Any]
    warnings: list[Warning]
    jobs: dict[str, int]


async def _count(ctx: Any, model: Any) -> int:
    stmt = select(func.count()).select_from(model).where(model.investigation_id == ctx.id)
    return int((await ctx.db.execute(stmt)).scalar_one())


async def _group(ctx: Any, column: Any, model: Any) -> dict[str, int]:
    rows = (
        await ctx.db.execute(select(column, func.count()).where(model.investigation_id == ctx.id).group_by(column))
    ).all()
    return {str(k): int(v) for k, v in rows}


@router.get("/investigations/{investigation_id}/dashboard")
async def dashboard(ctx: ReadCtx) -> Dashboard:
    inv = ctx.investigation
    settings = ctx.principal.services.settings
    cipher = await ctx.cipher()
    by_status = await _group(ctx, Finding.verification_status, Finding)
    stats = Stats(
        evidence=await _count(ctx, EvidenceItem),
        sources=await _count(ctx, Source),
        findings=sum(by_status.values()),
        images=await _count(ctx, Image),
        entities=await _count(ctx, Entity),
        relationships=await _count(ctx, Relationship),
        timeline_events=await _count(ctx, TimelineEvent),
        by_status=by_status,
        by_provenance=await _group(ctx, Finding.provenance, Finding),
        by_category=await _group(ctx, Finding.category, Finding),
        sources_by_category=await _group(ctx, Source.source_category, Source),
    )
    recent = list(
        (
            await ctx.db.execute(
                select(Finding).where(Finding.investigation_id == ctx.id).order_by(Finding.updated_at.desc()).limit(6)
            )
        ).scalars()
    )
    links = await links_for(ctx, [f.id for f in recent])
    recent_rows = [FindingRow(**finding_row(cipher, f, links.get(f.id, []))) for f in recent]
    events = list(
        (
            await ctx.db.execute(
                select(TimelineEvent)
                .where(TimelineEvent.investigation_id == ctx.id)
                .order_by(TimelineEvent.occurred_start.desc())
                .limit(10)
            )
        ).scalars()
    )
    events.reverse()
    mini_graph = await subgraph(ctx.db, cipher, inv, depth=2)
    mini_graph["nodes"] = mini_graph["nodes"][:40]
    keep = {n["id"] for n in mini_graph["nodes"]}
    mini_graph["edges"] = [e for e in mini_graph["edges"] if e["from"] in keep and e["to"] in keep][:80]

    warnings: list[Warning] = []
    if inv.status == InvestigationStatus.PENDING_REVIEW.value:
        warnings.append(
            Warning(
                kind="pending_review",
                severity="caution",
                message="Awaiting supervisor approval — the investigation is read-only until then.",
            )
        )
    if inv.restricted_mode:
        warnings.append(
            Warning(
                kind="restricted_mode",
                severity="caution",
                message="Individual subject: restricted mode is on. Contact and location details are "
                "removed, reverse image search is off and promotions need a second approver.",
            )
        )
    faces = int(
        (
            await ctx.db.execute(
                select(func.count()).select_from(Image).where(Image.investigation_id == ctx.id, Image.face_count > 0)
            )
        ).scalar_one()
    )
    if faces:
        warnings.append(Warning(kind="faces_detected", severity="info", message=FACE_NOTICE, count=faces))
    ai_open = by_status.get(VerificationStatus.AI_HYPOTHESIS.value, 0)
    if ai_open:
        warnings.append(
            Warning(
                kind="ai_hypotheses",
                severity="info",
                count=ai_open,
                message="AI hypotheses are unverified suggestions, not established facts.",
            )
        )
    contradictions = int(
        (
            await ctx.db.execute(
                select(func.count(func.distinct(FindingEvidence.finding_id))).where(
                    FindingEvidence.investigation_id == ctx.id,
                    FindingEvidence.stance == Stance.CONTRADICTS.value,
                    FindingEvidence.dismissed_at.is_(None),
                )
            )
        ).scalar_one()
    )
    open_suggestions = int(
        (
            await ctx.db.execute(
                select(func.count())
                .select_from(Suggestion)
                .where(
                    Suggestion.investigation_id == ctx.id,
                    Suggestion.kind == "contradiction",
                    Suggestion.status == "open",
                )
            )
        ).scalar_one()
    )
    if contradictions or open_suggestions:
        warnings.append(
            Warning(
                kind="contradictions",
                severity="caution",
                count=contradictions + open_suggestions,
                message="Some findings have contradicting evidence that needs review.",
            )
        )
    if settings.scanner != "clamd":
        warnings.append(
            Warning(
                kind="scanning_degraded",
                severity="critical",
                message="Malware scanning is running in degraded development mode.",
            )
        )
    if not settings.ai_available or not inv.ai_enabled:
        warnings.append(
            Warning(
                kind="ai_unavailable", severity="info", message="The AI assistant is turned off for this investigation."
            )
        )
    if inv.legal_hold:
        warnings.append(
            Warning(
                kind="legal_hold", severity="info", message="A legal hold is in place: retention deletion is paused."
            )
        )
    elif inv.closed_at is not None:
        days = inv.closed_retention_days or settings.closed_investigation_delete_days
        due = inv.closed_at + timedelta(days=days)
        warnings.append(
            Warning(
                kind="retention",
                severity="caution",
                message=f"Scheduled for deletion on {due.date().isoformat()} under the retention policy.",
            )
        )
    job_rows = (
        await ctx.db.execute(
            select(Job.status, func.count())
            .where(Job.investigation_id == ctx.id, Job.status.in_(["queued", "running"]))
            .group_by(Job.status)
        )
    ).all()
    return Dashboard(
        summary=DashboardSummary(
            id=str(inv.id),
            ref=inv.public_ref,
            title=inv.title,
            status=inv.status,
            subject_type=inv.subject_type,
            purpose_category=inv.purpose_category,
            restricted_mode=inv.restricted_mode,
            created_at=inv.created_at,
            updated_at=inv.updated_at,
        ),
        stats=stats,
        recent_findings=recent_rows,
        timeline=await event_views(ctx, events),
        graph=mini_graph,
        warnings=warnings,
        jobs={str(k): int(v) for k, v in job_rows},
    )
