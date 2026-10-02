"""Assistant requests: screening, budgets, context, provider calls, validation and proposals.

A request is screened by the acceptable-use policy before anything is sent anywhere; the provider call runs on the
egress worker; the answer is validated (:mod:`angel_engine.ai.grounding`) before it is stored or shown. Structured
results become *proposals* that a person must accept; accepted items are AI hypotheses that cite their evidence.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.ai import prompts
from angel_engine.ai.context import build_context
from angel_engine.ai.grounding import PROVIDER_REFUSED_TEXT, Draft, validate_answer, validate_structured
from angel_engine.ai.types import (
    CITATION_TASKS,
    INSUFFICIENT,
    ContextDoc,
    Grounding,
    LLMProvider,
    RawAnswer,
    RawBlock,
    RawStructured,
    Segment,
    Task,
    Usage,
)
from angel_engine.app_state import Services
from angel_engine.core.clock import utcnow
from angel_engine.core.enums import JobQueue
from angel_engine.core.ids import new_id
from angel_engine.core.problems import ConflictState, RateLimited, ServiceUnavailable, ValidationProblem
from angel_engine.crypto.blind_index import tokens
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.db.models import (
    AIInteraction,
    AIProposal,
    EvidenceItem,
    Image,
    ImageAnalysis,
    ImageClue,
    Investigation,
    Job,
    User,
)
from angel_engine.entities.service import EntityInput, upsert_entity
from angel_engine.evidence.service import redaction_mode
from angel_engine.findings import service as findings
from angel_engine.findings.service import FindingInput, LinkInput
from angel_engine.graph.service import RelationshipInput, upsert_relationship
from angel_engine.guard import SourceKind
from angel_engine.images import service as images
from angel_engine.images.types import ClueType
from angel_engine.infra.ratelimit.gcra import AI_USER
from angel_engine.jobs.queue import enqueue
from angel_engine.policy.types import Decision, PolicyContext, Surface
from angel_engine.policy_gate import require_acknowledgement, screen
from angel_engine.timeline.service import EventInput, create_event

MAX_TEXT = 2000
TEXT_FIELD = {Task.CHAT: "question", Task.CHECK_CONCLUSION: "conclusion"}


@dataclass(frozen=True, slots=True)
class Request:
    task: Task
    question: str | None = None
    conclusion: str | None = None
    topic: str | None = None
    evidence_ids: tuple[uuid.UUID, ...] = ()
    finding_ids: tuple[uuid.UUID, ...] = ()
    image_id: uuid.UUID | None = None

    def screened_text(self) -> str:
        return " ".join(p for p in (self.question, self.conclusion, self.topic) if p).strip()

    def as_dict(self) -> dict[str, Any]:
        return {
            "task": self.task.value,
            "question": self.question,
            "conclusion": self.conclusion,
            "topic": self.topic,
            "evidence_ids": [str(e) for e in self.evidence_ids],
            "finding_ids": [str(f) for f in self.finding_ids],
            "image_id": str(self.image_id) if self.image_id else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Request:
        return cls(
            task=Task(data["task"]),
            question=data.get("question"),
            conclusion=data.get("conclusion"),
            topic=data.get("topic"),
            evidence_ids=tuple(uuid.UUID(e) for e in data.get("evidence_ids", [])),
            finding_ids=tuple(uuid.UUID(f) for f in data.get("finding_ids", [])),
            image_id=uuid.UUID(data["image_id"]) if data.get("image_id") else None,
        )


def provider(svc: Services) -> LLMProvider:
    llm = svc.get("llm")
    if llm is None or not svc.settings.ai_available:
        raise ServiceUnavailable(
            "The AI assistant is not configured on this server (set ANGEL_ANTHROPIC_API_KEY).", code="ai_unavailable"
        )
    return llm  # type: ignore[no-any-return]


async def tokens_used_today(svc: Services, user_id: uuid.UUID) -> int:
    """Tokens used by this user in the last 24 hours, across investigations (content-free aggregate)."""
    async with svc.db.session("maintenance") as db:
        total = (
            await db.execute(
                select(func.coalesce(func.sum(AIInteraction.input_tokens + AIInteraction.output_tokens), 0)).where(
                    AIInteraction.user_id == user_id, AIInteraction.created_at >= utcnow() - timedelta(days=1)
                )
            )
        ).scalar_one()
    return int(total)


def _clean(text: str | None) -> str | None:
    text = " ".join((text or "").split())
    return text[:MAX_TEXT] or None


async def create_request(
    svc: Services,
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    user: User,
    request: Request,
    *,
    acknowledge: bool = False,
    idempotency_key: str | None = None,
    actor_event: Any = None,
) -> AIInteraction:
    llm = provider(svc)
    if not inv.ai_enabled:
        raise ConflictState("The AI assistant is turned off for this investigation.", code="ai_disabled")
    if idempotency_key:
        job = (
            await db.execute(select(Job).where(Job.idempotency_key == f"ai-request:{inv.id}:{idempotency_key}"))
        ).scalar_one_or_none()
        if job is not None and (existing := await db.get(AIInteraction, uuid.UUID(job.payload["interaction_id"]))):
            return existing
    request = Request(
        task=request.task,
        question=_clean(request.question),
        conclusion=_clean(request.conclusion),
        topic=_clean(request.topic),
        evidence_ids=request.evidence_ids[:200],
        finding_ids=request.finding_ids[:50],
        image_id=request.image_id,
    )
    if (needed := TEXT_FIELD.get(request.task)) and not getattr(request, needed):
        raise ValidationProblem(f"This task needs a {needed}.", code=f"{needed}_required")
    face_count = 0
    if request.task == Task.VISION_CLUES or request.image_id:
        if request.image_id is None:
            raise ValidationProblem("Choose an image.", code="image_required")
        image = (
            await db.execute(select(Image).where(Image.id == request.image_id, Image.investigation_id == inv.id))
        ).scalar_one_or_none()
        if image is None:
            raise ValidationProblem("Unknown image.", code="unknown_image")
        face_count = image.face_count
        if request.task == Task.VISION_CLUES:
            gate = images.search_gate(inv, image)  # same gate as any external image provider
            if not gate.allowed:
                raise ConflictState(gate.reason or "AI image analysis is not available.", code=gate.code or "gated")
    from angel_engine.api.deps import enforce_rate_limit

    await enforce_rate_limit(svc, f"ai:user:{user.id}", AI_USER)
    if await tokens_used_today(svc, user.id) >= svc.settings.ai_daily_token_budget_per_user:
        raise RateLimited(3600, "Your daily AI usage budget is spent; it renews over the next 24 hours.")
    text = request.screened_text()
    decision_id = None
    if text:
        result, decision = await screen(
            svc,
            db,
            user,
            text,
            PolicyContext(
                surface=Surface.ASSISTANT_PROMPT,
                subject_type=inv.subject_type,
                restricted_mode=inv.restricted_mode,
                face_count=face_count,
            ),
            investigation_id=inv.id,
            target_type="ai_interaction",
            actor_event=actor_event,
        )
        require_acknowledgement(result, acknowledge)
        if result.decision == Decision.REVIEW:
            raise ConflictState(
                "This request needs a supervisor's review before the assistant can run it.",
                code="policy_review_required",
                policy={
                    "decision": result.decision.value,
                    "categories": [c.value for c in result.categories],
                    "rationale": result.rationale,
                },
            )
        decision_id = decision.id
    interaction_id = new_id()
    interaction = AIInteraction(
        id=interaction_id,
        investigation_id=inv.id,
        user_id=user.id,
        task=request.task.value,
        prompt=cipher.seal_json(request.as_dict(), table="ai_interactions", column="prompt", row_id=interaction_id),
        provider=llm.name,
        model=llm.model,
        status="pending",
        policy_decision_id=decision_id,
        expires_at=utcnow() + timedelta(days=svc.settings.ai_transcript_retention_days),
    )
    db.add(interaction)
    await db.flush()
    if decision_id is not None:
        decision.target_id = interaction_id
    await enqueue(
        db,
        queue=JobQueue.EGRESS,
        kind="ai.run",
        payload={"interaction_id": str(interaction_id), "investigation_id": str(inv.id)},
        investigation_id=inv.id,
        idempotency_key=f"ai-request:{inv.id}:{idempotency_key}" if idempotency_key else f"ai:{interaction_id}",
        max_attempts=3,
        created_by=user.id,
    )
    return interaction


# --------------------------------------------------------------------------------------------------
# Running a request (egress worker)
# --------------------------------------------------------------------------------------------------
@dataclass(slots=True)
class Prepared:
    request: Request
    docs: list[ContextDoc]
    image_jpeg: bytes | None = None
    ocr_text: str | None = None
    restricted: bool = False
    face_count: int = 0


@dataclass(slots=True)
class Outcome:
    segments: list[Segment]
    grounding: Grounding
    cited: list[uuid.UUID]
    stats: dict[str, int]
    drafts: list[Draft] = field(default_factory=list)
    verdict: str | None = None
    model: str | None = None
    usage: Usage = field(default_factory=Usage)


async def prepare(
    svc: Services, db: AsyncSession, cipher: FieldCipher, inv: Investigation, interaction: AIInteraction
) -> tuple[Prepared, tuple[str, bytes] | None]:
    request = Request.from_dict(
        cipher.open_json(interaction.prompt or b"", table="ai_interactions", column="prompt", row_id=interaction.id)
    )
    query = request.screened_text() or request.task.value
    docs = await build_context(
        db,
        cipher,
        inv,
        query=query,
        evidence_ids=request.evidence_ids,
        finding_ids=request.finding_ids,
        image_id=request.image_id if request.task != Task.VISION_CLUES else None,
        limit=svc.settings.ai_max_context_documents,
    )
    prepared = Prepared(request, docs, restricted=inv.restricted_mode)
    preview = None
    if request.task == Task.VISION_CLUES and request.image_id:
        image = await db.get(Image, request.image_id)
        if image is not None and image.preview_key and images.search_gate(inv, image).allowed:
            preview = (image.preview_key, images.preview_file_key(cipher, image))
            prepared.face_count = image.face_count
            ocr = (
                await db.execute(
                    select(ImageAnalysis).where(ImageAnalysis.image_id == image.id, ImageAnalysis.analyzer == "ocr")
                )
            ).scalar_one_or_none()
            if ocr is not None and ocr.result is not None:
                data = cipher.open_json(ocr.result, table="image_analyses", column="result", row_id=ocr.id)
                prepared.ocr_text = None if data.get("flags") else str(data.get("text") or "")
            prepared.docs = []
    return prepared, preview


async def call(llm: LLMProvider, prepared: Prepared) -> RawAnswer | RawStructured:
    request = prepared.request
    task = request.task
    instruction = prompts.instruction(
        task, topic=request.topic, question=request.question, conclusion=request.conclusion, ocr_text=prepared.ocr_text
    )
    effort = prompts.EFFORT[task]
    max_tokens = prompts.MAX_TOKENS.get(task, prompts.DEFAULT_MAX_TOKENS)
    if task in CITATION_TASKS:
        if not prepared.docs:
            return RawAnswer((RawBlock(INSUFFICIENT),), llm.model)
        return await llm.grounded_answer(
            prepared.docs, prompts.SYSTEM, instruction, effort=effort, max_tokens=max_tokens
        )
    if task == Task.VISION_CLUES:
        if prepared.image_jpeg is None:
            return RawStructured(None, llm.model)
    elif not prepared.docs:
        return RawStructured(None, llm.model)
    return await llm.structured(
        prepared.docs,
        prompts.SYSTEM,
        instruction,
        prompts.SCHEMAS[task],
        effort=effort,
        max_tokens=max_tokens,
        image_jpeg=prepared.image_jpeg,
    )


def validate(prepared: Prepared, raw: RawAnswer | RawStructured, inv: Investigation) -> Outcome:
    mode = redaction_mode(inv)
    task = prepared.request.task
    if isinstance(raw, RawAnswer):
        checked = validate_answer(raw, prepared.docs, task=task, mode=mode)
        return Outcome(
            checked.segments,
            checked.grounding,
            checked.cited_evidence_ids,
            checked.stats,
            verdict=checked.verdict,
            model=raw.model,
            usage=raw.usage,
        )
    outcome = validate_structured(task, raw, prepared.docs, mode=mode)
    if outcome.grounding == Grounding.PROVIDER_REFUSED:
        segments = [Segment(PROVIDER_REFUSED_TEXT, "notice")]
    elif not outcome.drafts:
        segments = [Segment(INSUFFICIENT, "notice")]
    else:
        segments = [
            Segment(
                f"{len(outcome.drafts)} suggestion(s) for review. Nothing is recorded until a person "
                "accepts it; accepted items are labelled AI hypothesis.",
                "notice",
            )
        ]
    cited = list(dict.fromkeys(e for d in outcome.drafts for e in d.evidence_ids))
    return Outcome(segments, outcome.grounding, cited, outcome.stats, outcome.drafts, model=raw.model, usage=raw.usage)


async def store(
    svc: Services,
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    interaction: AIInteraction,
    user: User | None,
    prepared: Prepared,
    outcome: Outcome,
) -> int:
    """Persist the validated answer and its proposals. Returns the number of proposals created."""
    created = 0
    engine = svc.get("policy")
    for draft in outcome.drafts:
        if draft.kind == "query":
            # AI-suggested queries are re-screened; refusals and review-level suggestions are dropped.
            ctx = PolicyContext(
                surface=Surface.AI_SUGGESTED_QUERY, subject_type=inv.subject_type, restricted_mode=inv.restricted_mode
            )
            result = engine.evaluate(draft.payload["query"], ctx) if engine is not None else None
            if result is None or result.decision in (Decision.REFUSE, Decision.REVIEW):
                outcome.stats["queries_refused_by_policy"] = outcome.stats.get("queries_refused_by_policy", 0) + 1
                continue
            draft.payload["policy_notices"] = list(result.notices) if result.decision == Decision.WARN else []
        if draft.kind == "clue":
            created += await _store_vision_clue(db, cipher, inv, prepared, draft)
            continue
        pid = new_id()
        db.add(
            AIProposal(
                id=pid,
                investigation_id=inv.id,
                interaction_id=interaction.id,
                kind=draft.kind,
                payload=cipher.seal_json(draft.payload, table="ai_proposals", column="payload", row_id=pid),
                evidence_ids=draft.evidence_ids,
                status="pending",
            )
        )
        created += 1
    llm = svc.get("llm")
    response = {
        "segments": [s.as_dict() for s in outcome.segments],
        "verdict": outcome.verdict,
        "provider_label": getattr(llm, "label", None),
    }
    interaction.response = cipher.seal_json(response, table="ai_interactions", column="response", row_id=interaction.id)
    interaction.context_evidence_ids = [d.evidence_id for d in prepared.docs]
    interaction.cited_evidence_ids = outcome.cited
    interaction.grounding = outcome.grounding.value
    interaction.validation = {**outcome.stats, "proposals": created, "context_documents": len(prepared.docs)}
    interaction.model = outcome.model or interaction.model
    interaction.input_tokens, interaction.output_tokens = outcome.usage.input_tokens, outcome.usage.output_tokens
    interaction.status, interaction.completed_at = "completed", utcnow()
    await db.flush()
    return created


async def _store_vision_clue(
    db: AsyncSession, cipher: FieldCipher, inv: Investigation, prepared: Prepared, draft: Draft
) -> int:
    image_id = prepared.request.image_id
    if image_id is None:
        return 0
    payload = draft.payload
    clue_type = ClueType(payload["type"])
    normalized = payload["value"].casefold()
    mac = cipher.mac(images.CLUE_PURPOSE, f"{clue_type.value}|{normalized}|ai")
    exists = await db.execute(
        select(ImageClue.id).where(ImageClue.image_id == image_id, ImageClue.normalized_mac == mac)
    )
    if exists.first() is not None:
        return 0
    cid = new_id()
    db.add(
        ImageClue(
            id=cid,
            investigation_id=inv.id,
            image_id=image_id,
            clue_type=clue_type.value,
            value=cipher.seal(payload["value"], table="image_clues", column="value", row_id=cid),
            normalized=cipher.seal(normalized, table="image_clues", column="normalized", row_id=cid),
            normalized_mac=mac,
            tokens=tokens(cipher, payload["value"]),
            confidence=payload["confidence"],
            confidence_basis=f"AI vision suggestion: {payload['basis']}"[:300],
            provenance="ai_hypothesis",
            source="ai",
        )
    )
    return 1


# --------------------------------------------------------------------------------------------------
# Proposals
# --------------------------------------------------------------------------------------------------
NEEDS_EVIDENCE = frozenset({"entity", "relationship", "timeline_event", "contradiction"})


async def _existing_evidence(db: AsyncSession, inv: Investigation, ids: list[uuid.UUID]) -> tuple[uuid.UUID, ...]:
    if not ids:
        return ()
    found = set(
        (
            await db.execute(
                select(EvidenceItem.id).where(EvidenceItem.investigation_id == inv.id, EvidenceItem.id.in_(ids))
            )
        ).scalars()
    )
    return tuple(i for i in ids if i in found)


async def accept_proposal(
    db: AsyncSession, cipher: FieldCipher, inv: Investigation, proposal: AIProposal, user: User
) -> dict[str, Any]:
    """Turn a proposal into an AI-hypothesis item that cites its evidence. Returns a small result description."""
    if proposal.status != "pending":
        raise ConflictState("This proposal has already been decided.", code="proposal_decided")
    payload = cipher.open_json(proposal.payload, table="ai_proposals", column="payload", row_id=proposal.id)
    evidence = await _existing_evidence(db, inv, list(proposal.evidence_ids))
    if proposal.kind in NEEDS_EVIDENCE and not evidence:
        raise ConflictState("The evidence this proposal cites no longer exists.", code="evidence_missing")
    result: dict[str, Any] = {"kind": proposal.kind}
    ref: uuid.UUID | None = None
    if proposal.kind == "entity":
        entity, _ = await upsert_entity(
            db, cipher, inv, EntityInput(type=payload["type"], name=payload["name"], created_via="ai_proposal")
        )
        ref = entity.id
    elif proposal.kind == "relationship":
        source, _ = await upsert_entity(
            db,
            cipher,
            inv,
            EntityInput(type=payload["from"]["type"], name=payload["from"]["name"], created_via="ai_proposal"),
        )
        target, _ = await upsert_entity(
            db,
            cipher,
            inv,
            EntityInput(type=payload["to"]["type"], name=payload["to"]["name"], created_via="ai_proposal"),
        )
        rel, _ = await upsert_relationship(
            db,
            inv,
            RelationshipInput(
                from_entity_id=source.id,
                rel_type=payload["rel_type"],
                to_entity_id=target.id,
                evidence_ids=evidence,
                provenance="ai_hypothesis",
                created_via="ai_proposal",
                created_by=user.id,
            ),
        )
        ref = rel.id
    elif proposal.kind == "timeline_event":
        event = await create_event(
            db,
            cipher,
            inv,
            EventInput(
                occurred_start=datetime.fromisoformat(payload["date"]),
                precision=payload["precision"],
                kind=payload["kind"],
                title=payload["title"],
                evidence_ids=evidence,
                provenance="ai_hypothesis",
                created_via="ai_proposal",
                created_by=user.id,
            ),
        )
        ref = event.id
    elif proposal.kind == "contradiction":
        aspect = f" ({payload['aspect']})" if payload.get("aspect") else ""
        finding = await findings.create_finding(
            db,
            cipher,
            inv,
            FindingInput(
                statement=f"Sources disagree{aspect}: {payload['description']}",
                category="analysis",
                provenance="ai_hypothesis",
                links=tuple(LinkInput(e) for e in evidence),
                created_via="ai_proposal",
                created_by=user.id,
                ai_interaction_id=proposal.interaction_id,
                source_kind=SourceKind.AI_OUTPUT,
            ),
        )
        ref = finding.id
        result["finding_label"] = f"F-{finding.label_seq}"
    elif proposal.kind == "query":
        result["prefill"] = {"query": payload["query"], "input_type": payload["input_type"]}
    proposal.status, proposal.decided_by, proposal.decided_at, proposal.result_ref = "accepted", user.id, utcnow(), ref
    result["result_id"] = str(ref) if ref else None
    return result


def reject_proposal(proposal: AIProposal, user: User) -> None:
    if proposal.status != "pending":
        raise ConflictState("This proposal has already been decided.", code="proposal_decided")
    proposal.status, proposal.decided_by, proposal.decided_at = "rejected", user.id, utcnow()


def proposal_view(cipher: FieldCipher, proposal: AIProposal, labels: dict[uuid.UUID, str]) -> dict[str, Any]:
    return {
        "id": str(proposal.id),
        "interaction_id": str(proposal.interaction_id),
        "kind": proposal.kind,
        "payload": cipher.open_json(proposal.payload, table="ai_proposals", column="payload", row_id=proposal.id),
        "evidence": [{"id": str(e), "label": labels.get(e, "?")} for e in proposal.evidence_ids],
        "status": proposal.status,
        "decided_at": proposal.decided_at,
        "result_id": str(proposal.result_ref) if proposal.result_ref else None,
        "created_at": proposal.created_at,
    }
