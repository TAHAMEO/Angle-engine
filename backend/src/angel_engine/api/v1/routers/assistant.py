"""Source-grounded AI assistant: requests (answered asynchronously by the egress worker), validated answers with
citations, and proposals that a person accepts or rejects. Without evidence the answer is exactly
"Insufficient public evidence to establish this conclusion."."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Header, Query
from pydantic import BaseModel, Field
from sqlalchemy import select

from angel_engine.ai import service
from angel_engine.ai.types import INSUFFICIENT, UNCITED_LABEL, Task
from angel_engine.api.deps import CurrentPrincipal, InvCtx
from angel_engine.api.v1.routers._common import ReadCtx, WriteCtx, get_scoped
from angel_engine.db.models import AIInteraction, AIProposal, EvidenceItem

router = APIRouter(tags=["assistant"])
BASE = "/investigations/{investigation_id}/assistant"
GROUNDING_LABELS = {
    "grounded": "Every statement cites evidence",
    "partial": "Some statements are uncited AI commentary",
    "insufficient_evidence": "Insufficient public evidence",
    "policy_refused": "Refused under the acceptable-use policy",
    "provider_refused": "The AI provider declined",
}
TaskName = Literal[
    "summarize",
    "compare",
    "check_conclusion",
    "chat",
    "contradictions",
    "gaps",
    "suggest_queries",
    "extract",
    "timeline",
    "vision_clues",
]


class AssistantIn(BaseModel):
    task: TaskName
    question: str | None = Field(default=None, max_length=2000)
    conclusion: str | None = Field(default=None, max_length=2000)
    topic: str | None = Field(default=None, max_length=500)
    evidence_ids: list[uuid.UUID] = Field(default_factory=list, max_length=200)
    finding_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    image_id: uuid.UUID | None = None
    acknowledge_policy_notices: bool = False


class CitationOut(BaseModel):
    evidence_id: str
    label: str
    cited_text: str


class SegmentOut(BaseModel):
    text: str
    kind: Literal["cited", "uncited", "plain", "notice"]
    citations: list[CitationOut]


class EvidenceRef(BaseModel):
    id: str
    label: str


class ProposalOut(BaseModel):
    id: str
    interaction_id: str
    kind: str
    payload: dict[str, Any]
    evidence: list[EvidenceRef]
    status: str
    decided_at: datetime | None
    result_id: str | None
    created_at: datetime


class InteractionOut(BaseModel):
    id: str
    task: str
    status: str
    grounding: str | None
    grounding_label: str | None
    request: dict[str, Any] | None
    segments: list[SegmentOut]
    verdict: str | None
    provider: str
    provider_label: str | None
    model: str | None
    requested_by_me: bool
    cited_evidence: list[EvidenceRef]
    context_documents: int
    validation: dict[str, Any]
    proposals: list[ProposalOut]
    error_code: str | None
    expired: bool
    created_at: datetime
    completed_at: datetime | None
    poll_after_ms: int | None
    uncited_label: str = UNCITED_LABEL
    insufficient_text: str = INSUFFICIENT


class AcceptOut(BaseModel):
    proposal: ProposalOut
    result: dict[str, Any]


class StatusOut(BaseModel):
    available: bool
    provider: str | None
    label: str | None
    model: str | None


async def _labels(ctx: InvCtx, ids: list[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not ids:
        return {}
    rows = await ctx.db.execute(
        select(EvidenceItem.id, EvidenceItem.label_seq).where(
            EvidenceItem.investigation_id == ctx.id, EvidenceItem.id.in_(ids)
        )
    )
    return {i: f"E-{seq}" for i, seq in rows}


async def _proposals(ctx: InvCtx, rows: list[AIProposal]) -> list[ProposalOut]:
    cipher = await ctx.cipher()
    labels = await _labels(ctx, list({e for p in rows for e in p.evidence_ids}))
    return [ProposalOut(**service.proposal_view(cipher, p, labels)) for p in rows]


async def _out(ctx: InvCtx, interaction: AIInteraction) -> InteractionOut:
    cipher = await ctx.cipher()
    request = None
    segments: list[dict[str, Any]] = []
    verdict = label = None
    expired = interaction.prompt is None and interaction.status == "completed"
    if interaction.prompt is not None:
        request = cipher.open_json(interaction.prompt, table="ai_interactions", column="prompt", row_id=interaction.id)
    if interaction.response is not None:
        response = cipher.open_json(
            interaction.response, table="ai_interactions", column="response", row_id=interaction.id
        )
        segments, verdict, label = response["segments"], response.get("verdict"), response.get("provider_label")
    elif expired:
        segments = [
            {"text": "This conversation has expired under the retention policy.", "kind": "notice", "citations": []}
        ]
    proposals = (
        (await ctx.db.execute(select(AIProposal).where(AIProposal.interaction_id == interaction.id))).scalars().all()
    )
    labels = await _labels(ctx, list(interaction.cited_evidence_ids))
    return InteractionOut(
        id=str(interaction.id),
        task=interaction.task,
        status=interaction.status,
        grounding=interaction.grounding,
        grounding_label=GROUNDING_LABELS.get(interaction.grounding or ""),
        request=request,
        segments=[SegmentOut(**s) for s in segments],
        verdict=verdict,
        provider=interaction.provider,
        provider_label=label,
        model=interaction.model,
        requested_by_me=interaction.user_id == ctx.principal.user_id,
        cited_evidence=[EvidenceRef(id=str(e), label=labels.get(e, "deleted")) for e in interaction.cited_evidence_ids],
        context_documents=len(interaction.context_evidence_ids),
        validation=dict(interaction.validation or {}),
        proposals=await _proposals(ctx, list(proposals)),
        error_code=interaction.error_code,
        expired=expired,
        created_at=interaction.created_at,
        completed_at=interaction.completed_at,
        poll_after_ms=1000 if interaction.status in ("pending", "running") else None,
    )


@router.get("/assistant/status")
async def assistant_status(principal: CurrentPrincipal) -> StatusOut:
    llm = principal.services.get("llm")
    available = llm is not None and principal.services.settings.ai_available
    return StatusOut(
        available=available,
        provider=getattr(llm, "name", None) if available else None,
        label=getattr(llm, "label", None) if available else None,
        model=getattr(llm, "model", None) if available else None,
    )


@router.post(BASE + "/requests", status_code=202)
async def create_request(
    body: AssistantIn, ctx: WriteCtx, idempotency_key: Annotated[str | None, Header(max_length=100)] = None
) -> InteractionOut:
    """Ask the assistant. The request is screened by the acceptable-use policy; the answer arrives asynchronously
    (poll the returned request) and every statement in it cites evidence or is labelled uncited commentary."""
    cipher = await ctx.cipher()
    interaction = await service.create_request(
        ctx.principal.services,
        ctx.db,
        cipher,
        ctx.investigation,
        ctx.principal.user,
        service.Request(
            task=Task(body.task),
            question=body.question,
            conclusion=body.conclusion,
            topic=body.topic,
            evidence_ids=tuple(body.evidence_ids),
            finding_ids=tuple(body.finding_ids),
            image_id=body.image_id,
        ),
        acknowledge=body.acknowledge_policy_notices,
        idempotency_key=idempotency_key,
        actor_event=ctx.principal.event(""),
    )
    ctx.audit(
        "ai.requested",
        target_type="ai_interaction",
        target_id=str(interaction.id),
        details={"task": body.task, "evidence": len(body.evidence_ids), "findings": len(body.finding_ids)},
    )
    return await _out(ctx, interaction)


@router.get(BASE + "/requests")
async def list_requests(
    ctx: ReadCtx, task: Annotated[TaskName | None, Query()] = None, mine: bool = False
) -> list[InteractionOut]:
    stmt = select(AIInteraction).where(AIInteraction.investigation_id == ctx.id)
    if task:
        stmt = stmt.where(AIInteraction.task == task)
    if mine:
        stmt = stmt.where(AIInteraction.user_id == ctx.principal.user_id)
    rows = (await ctx.db.execute(stmt.order_by(AIInteraction.created_at.desc()).limit(50))).scalars().all()
    return [await _out(ctx, row) for row in rows]


@router.get(BASE + "/requests/{interaction_id}")
async def get_request(interaction_id: uuid.UUID, ctx: ReadCtx) -> InteractionOut:
    return await _out(ctx, await get_scoped(ctx.db, AIInteraction, ctx, interaction_id))


@router.get(BASE + "/proposals")
async def list_proposals(
    ctx: ReadCtx, status: Annotated[Literal["pending", "accepted", "rejected"] | None, Query()] = "pending"
) -> list[ProposalOut]:
    stmt = select(AIProposal).where(AIProposal.investigation_id == ctx.id)
    if status:
        stmt = stmt.where(AIProposal.status == status)
    rows = (await ctx.db.execute(stmt.order_by(AIProposal.created_at.desc()).limit(200))).scalars().all()
    return await _proposals(ctx, list(rows))


@router.post(BASE + "/proposals/{proposal_id}/accept")
async def accept_proposal(proposal_id: uuid.UUID, ctx: WriteCtx) -> AcceptOut:
    """Record an AI proposal as an AI hypothesis (it keeps that label until a person verifies it)."""
    proposal = await get_scoped(ctx.db, AIProposal, ctx, proposal_id)
    result = await service.accept_proposal(ctx.db, await ctx.cipher(), ctx.investigation, proposal, ctx.principal.user)
    await ctx.db.flush()
    ctx.audit(
        "ai.proposal_accepted",
        target_type="ai_proposal",
        target_id=str(proposal.id),
        details={"kind": proposal.kind, "result_id": result.get("result_id")},
    )
    return AcceptOut(proposal=(await _proposals(ctx, [proposal]))[0], result=result)


@router.post(BASE + "/proposals/{proposal_id}/reject")
async def reject_proposal(proposal_id: uuid.UUID, ctx: WriteCtx) -> ProposalOut:
    proposal = await get_scoped(ctx.db, AIProposal, ctx, proposal_id)
    service.reject_proposal(proposal, ctx.principal.user)
    await ctx.db.flush()
    ctx.audit(
        "ai.proposal_rejected", target_type="ai_proposal", target_id=str(proposal.id), details={"kind": proposal.kind}
    )
    return (await _proposals(ctx, [proposal]))[0]
