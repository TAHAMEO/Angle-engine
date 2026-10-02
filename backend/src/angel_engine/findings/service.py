"""Findings (claims), their evidence links and human-only verification-status transitions.

Rules (enforced here and backed by database triggers):

* Provenance never changes. Evidence can never be AI-generated, so AI output can never become evidence.
* New findings start as ``unverified`` (or ``ai_hypothesis`` when they came from an AI).
* Every status change is an explicit human action with a justification, cited evidence and an
  append-only history row; preconditions are checked against the current evidence links:

  - ``confirmed_by_source`` — at least one active supporting link that directly states the claim, and no
    active contradicting link;
  - ``corroborated`` — supporting links from at least two independent origins, no active contradicting
    link, and the investigator attests that the sources do not cite each other;
  - ``contradicted`` — at least one active contradicting link;
  - ``unverified`` — always available;
  - ``ai_hypothesis`` — only for findings whose provenance is ``ai_hypothesis``.

* In restricted mode (individual subjects) promotions need a supervisor who did not create the finding.
* When a status's preconditions stop holding (e.g. its only supporting link is dismissed) the system
  downgrades the finding to ``unverified`` and records an automatic history entry.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.core.clock import utcnow
from angel_engine.core.enums import Provenance, Role, Stance, VerificationStatus
from angel_engine.core.ids import new_id
from angel_engine.core.problems import ConflictState, Forbidden, ValidationProblem
from angel_engine.crypto.blind_index import tokens
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.db.models import (
    EvidenceItem,
    Finding,
    FindingEvidence,
    FindingStatusHistory,
    Investigation,
    Source,
)
from angel_engine.db.session import allow_status_transition
from angel_engine.evidence.independence import origin_key
from angel_engine.evidence.labels import next_label
from angel_engine.evidence.service import redaction_mode
from angel_engine.guard import RedactionContext, SourceKind, redact_text

V = VerificationStatus
PROMOTIONS = frozenset({V.CONFIRMED_BY_SOURCE.value, V.CORROBORATED.value})
MIN_JUSTIFICATION = 20
MAX_STATEMENT = 2000

STATUS_LABELS = {
    V.CONFIRMED_BY_SOURCE.value: "Confirmed by source",
    V.CORROBORATED.value: "Corroborated",
    V.UNVERIFIED.value: "Unverified",
    V.CONTRADICTED.value: "Contradicted",
    V.AI_HYPOTHESIS.value: "AI hypothesis",
}


# --------------------------------------------------------------------------------------------------
# Evidence links
# --------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class LinkInput:
    evidence_id: uuid.UUID
    stance: str = Stance.SUPPORTS.value
    directly_states: bool = False


@dataclass(slots=True)
class LinkInfo:
    link: FindingEvidence
    evidence: EvidenceItem
    source: Source | None

    @property
    def active(self) -> bool:
        return self.link.dismissed_at is None

    @property
    def origin_key(self) -> str:
        """Groups evidence that shares one origin (same publisher, owner, syndicated copy or image)."""
        return origin_key(self.evidence, self.source)


async def load_links(db: AsyncSession, finding_id: uuid.UUID) -> list[LinkInfo]:
    rows = (
        await db.execute(
            select(FindingEvidence, EvidenceItem, Source)
            .join(EvidenceItem, EvidenceItem.id == FindingEvidence.evidence_id)
            .outerjoin(Source, Source.id == EvidenceItem.source_id)
            .where(FindingEvidence.finding_id == finding_id)
            .order_by(FindingEvidence.created_at)
        )
    ).all()
    return [LinkInfo(link, ev, src) for link, ev, src in rows]


async def _evidence_in_investigation(
    db: AsyncSession, inv_id: uuid.UUID, ids: Iterable[uuid.UUID]
) -> dict[uuid.UUID, EvidenceItem]:
    wanted = list(dict.fromkeys(ids))
    if not wanted:
        return {}
    rows = (
        await db.execute(
            select(EvidenceItem).where(EvidenceItem.investigation_id == inv_id, EvidenceItem.id.in_(wanted))
        )
    ).scalars()
    found = {e.id: e for e in rows}
    missing = [str(i) for i in wanted if i not in found]
    if missing:
        raise ValidationProblem(
            "Some cited evidence items do not exist in this investigation.",
            code="unknown_evidence",
            evidence_ids=missing,
        )
    return found


async def add_links(
    db: AsyncSession, inv: Investigation, finding: Finding, links: Sequence[LinkInput], actor_id: uuid.UUID | None
) -> list[FindingEvidence]:
    await _evidence_in_investigation(db, inv.id, (link.evidence_id for link in links))
    existing = {
        (fe.evidence_id, fe.stance)
        for fe in (await db.execute(select(FindingEvidence).where(FindingEvidence.finding_id == finding.id))).scalars()
    }
    created: list[FindingEvidence] = []
    for link in links:
        if link.stance not in {s.value for s in Stance}:
            raise ValidationProblem("Unknown stance.", code="invalid_stance")
        if (link.evidence_id, link.stance) in existing:
            continue
        row = FindingEvidence(
            id=new_id(),
            investigation_id=inv.id,
            finding_id=finding.id,
            evidence_id=link.evidence_id,
            stance=link.stance,
            directly_states=link.directly_states and link.stance == Stance.SUPPORTS.value,
            created_by=actor_id,
        )
        db.add(row)
        existing.add((link.evidence_id, link.stance))
        created.append(row)
    await db.flush()
    return created


# --------------------------------------------------------------------------------------------------
# Creation
# --------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class FindingInput:
    statement: str
    category: str
    provenance: str
    links: tuple[LinkInput, ...] = ()
    confidence: str | None = None
    confidence_basis: str | None = None
    sensitive: bool = False
    importance: str = "normal"
    event_time: datetime | None = None
    event_precision: str | None = None
    created_via: str = "manual"
    created_by: uuid.UUID | None = None
    ai_interaction_id: uuid.UUID | None = None
    source_kind: SourceKind = SourceKind.USER_NOTE


def _validate(data: FindingInput) -> None:
    if data.provenance not in {p.value for p in Provenance}:
        raise ValidationProblem("Unknown provenance.", code="invalid_provenance")
    if data.provenance != Provenance.AI_HYPOTHESIS.value and not data.links:
        raise ValidationProblem("A finding must cite at least one evidence item.", code="evidence_required")
    if data.sensitive and data.confidence is not None:
        raise ValidationProblem(
            "Confidence levels are not recorded for sensitive findings.", code="confidence_not_allowed"
        )
    if data.confidence is not None and not (data.confidence_basis or "").strip():
        raise ValidationProblem("State the basis for the confidence level.", code="confidence_basis_required")


async def create_finding(db: AsyncSession, cipher: FieldCipher, inv: Investigation, data: FindingInput) -> Finding:
    _validate(data)
    red = redact_text(
        data.statement[:MAX_STATEMENT], mode=redaction_mode(inv), context=RedactionContext(source_kind=data.source_kind)
    )
    statement = red.text.strip()
    if not statement:
        raise ValidationProblem("The statement is empty after redaction.", code="empty_statement")
    await _evidence_in_investigation(db, inv.id, (link.evidence_id for link in data.links))
    fid = new_id()
    seq = await next_label(db, inv.id, "finding_seq")
    status = V.AI_HYPOTHESIS.value if data.provenance == Provenance.AI_HYPOTHESIS.value else V.UNVERIFIED.value
    finding = Finding(
        id=fid,
        investigation_id=inv.id,
        label_seq=seq,
        statement=cipher.seal(statement, table="findings", column="statement", row_id=fid),
        statement_tokens=tokens(cipher, statement),
        category=data.category,
        provenance=data.provenance,
        verification_status=status,
        confidence=data.confidence,
        confidence_basis=cipher.seal_optional(
            data.confidence_basis, table="findings", column="confidence_basis", row_id=fid
        ),
        sensitive=data.sensitive,
        importance=data.importance,
        event_time=data.event_time,
        event_precision=data.event_precision,
        ai_interaction_id=data.ai_interaction_id,
        created_by=data.created_by,
        created_via=data.created_via,
    )
    db.add(finding)
    await db.flush()
    await add_links(db, inv, finding, data.links, data.created_by)
    db.add(
        FindingStatusHistory(
            id=new_id(),
            investigation_id=inv.id,
            finding_id=fid,
            from_status=None,
            to_status=status,
            actor_id=data.created_by,
            evidence_ids=[link.evidence_id for link in data.links],
            automatic=True,
            precondition_snapshot={"event": "created", "created_via": data.created_via},
        )
    )
    await db.flush()
    return finding


# --------------------------------------------------------------------------------------------------
# Transitions
# --------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Evaluation:
    allowed: tuple[str, ...]
    failed: dict[str, list[str]]
    snapshot: dict[str, Any] = field(default_factory=dict)


def evaluate(
    finding: Finding, links: Sequence[LinkInfo], *, restricted_mode: bool, actor_role: str, actor_id: uuid.UUID | None
) -> Evaluation:
    support = [li for li in links if li.active and li.link.stance == Stance.SUPPORTS.value]
    contra = [li for li in links if li.active and li.link.stance == Stance.CONTRADICTS.value]
    origins = {li.origin_key for li in support}
    failed: dict[str, list[str]] = {}

    def need(target: str, ok: bool, message: str) -> None:
        if not ok:
            failed.setdefault(target, []).append(message)

    need(
        V.CONFIRMED_BY_SOURCE.value,
        any(li.link.directly_states for li in support),
        "Needs at least one supporting evidence item that directly states the claim.",
    )
    need(
        V.CORROBORATED.value,
        len(origins) >= 2,
        "Needs supporting evidence from at least two independent origins (different publishers or owners, "
        "not syndicated copies).",
    )
    for target in PROMOTIONS:
        need(target, not contra, "Active contradicting evidence must be reviewed and dismissed first.")
        if restricted_mode:
            need(
                target,
                actor_role == Role.SUPERVISOR.value and actor_id != finding.created_by,
                "Restricted mode: a supervisor other than the finding's creator must approve this promotion.",
            )
    need(V.CONTRADICTED.value, bool(contra), "Needs at least one contradicting evidence item.")
    need(
        V.AI_HYPOTHESIS.value,
        finding.provenance == Provenance.AI_HYPOTHESIS.value,
        "Only findings that originated from an AI can carry the AI-hypothesis status.",
    )
    if finding.retracted_at is not None:
        for target in (V.CONFIRMED_BY_SOURCE.value, V.CORROBORATED.value, V.CONTRADICTED.value):
            need(target, False, "Retracted findings cannot be promoted.")
    current = finding.verification_status
    allowed = tuple(s.value for s in V if s.value != current and s.value not in failed)
    snapshot = {
        "supporting_links": len(support),
        "directly_stating_links": sum(1 for li in support if li.link.directly_states),
        "independent_origins": len(origins),
        "contradicting_links": len(contra),
        "restricted_mode": restricted_mode,
    }
    return Evaluation(allowed, failed, snapshot)


@dataclass(frozen=True, slots=True)
class TransitionRequest:
    to_status: str
    justification: str
    evidence_ids: tuple[uuid.UUID, ...] = ()
    independence_attested: bool = False


async def record_status(
    db: AsyncSession,
    cipher: FieldCipher,
    finding: Finding,
    to_status: str,
    *,
    actor_id: uuid.UUID | None,
    justification: str | None,
    evidence_ids: Sequence[uuid.UUID],
    snapshot: dict[str, Any],
    automatic: bool,
) -> str:
    previous = finding.verification_status
    await allow_status_transition(db)
    finding.verification_status = to_status
    finding.status_changed_at = utcnow()
    await db.flush()
    await db.execute(text("SELECT set_config('ae.transition', 'off', true)"))
    hid = new_id()
    db.add(
        FindingStatusHistory(
            id=hid,
            investigation_id=finding.investigation_id,
            finding_id=finding.id,
            from_status=previous,
            to_status=to_status,
            actor_id=actor_id,
            justification=cipher.seal_optional(
                justification, table="finding_status_history", column="justification", row_id=hid
            ),
            evidence_ids=list(evidence_ids),
            automatic=automatic,
            precondition_snapshot=snapshot,
        )
    )
    await db.flush()
    return previous


async def transition(
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    finding: Finding,
    request: TransitionRequest,
    *,
    actor_id: uuid.UUID,
    actor_role: str,
) -> str:
    """Apply a human verification-status change. Returns the previous status."""
    target = request.to_status
    if target not in STATUS_LABELS:
        raise ValidationProblem("Unknown verification status.", code="invalid_status")
    justification = request.justification.strip()
    if len(justification) < MIN_JUSTIFICATION:
        raise ValidationProblem(
            f"Explain the change in at least {MIN_JUSTIFICATION} characters.", code="justification_required"
        )
    links = await load_links(db, finding.id)
    result = evaluate(finding, links, restricted_mode=inv.restricted_mode, actor_role=actor_role, actor_id=actor_id)
    if target not in result.allowed:
        if target in result.failed and any("Restricted mode" in m for m in result.failed[target]):
            raise Forbidden(result.failed[target][-1], code="second_approver_required")
        raise ConflictState(
            f"This finding cannot move to “{STATUS_LABELS[target]}” yet.",
            code="transition_not_allowed",
            allowed_transitions=list(result.allowed),
            failed_preconditions=result.failed.get(target, ["The finding already has this status."]),
        )
    active_ids = {li.evidence.id for li in links if li.active}
    cited = tuple(dict.fromkeys(request.evidence_ids))
    unknown = [str(e) for e in cited if e not in active_ids]
    if unknown:
        raise ValidationProblem(
            "Cite evidence items that are actively linked to this finding.",
            code="evidence_not_linked",
            evidence_ids=unknown,
        )
    if target in (*PROMOTIONS, V.CONTRADICTED.value) and not cited:
        raise ValidationProblem("Cite the evidence that supports this change.", code="evidence_required")
    if target == V.CORROBORATED.value and not request.independence_attested:
        raise ValidationProblem(
            "Confirm that the corroborating sources are independent of each other.",
            code="independence_attestation_required",
        )
    snapshot = {**result.snapshot, "independence_attested": request.independence_attested}
    return await record_status(
        db,
        cipher,
        finding,
        target,
        actor_id=actor_id,
        justification=justification,
        evidence_ids=cited,
        snapshot=snapshot,
        automatic=False,
    )


async def recheck(db: AsyncSession, cipher: FieldCipher, inv: Investigation, finding: Finding) -> str | None:
    """Downgrade to ``unverified`` when the current status's evidence requirements no longer hold."""
    status = finding.verification_status
    if status not in (*PROMOTIONS, V.CONTRADICTED.value):
        return None
    links = await load_links(db, finding.id)
    # Evaluate the evidence-based preconditions only (not who may approve).
    result = evaluate(finding, links, restricted_mode=False, actor_role=Role.SUPERVISOR.value, actor_id=None)
    if status not in result.failed:
        return None
    await record_status(
        db,
        cipher,
        finding,
        V.UNVERIFIED.value,
        actor_id=None,
        justification=f"Automatic: the linked evidence no longer meets the requirements for “{STATUS_LABELS[status]}”.",
        evidence_ids=(),
        snapshot={**result.snapshot, "reason": result.failed[status]},
        automatic=True,
    )
    return V.UNVERIFIED.value


async def dismiss_link(
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    finding: Finding,
    link_id: uuid.UUID,
    reason: str,
    actor_id: uuid.UUID,
) -> str | None:
    link = (
        await db.execute(
            select(FindingEvidence).where(FindingEvidence.id == link_id, FindingEvidence.finding_id == finding.id)
        )
    ).scalar_one_or_none()
    if link is None:
        from angel_engine.core.problems import NotFound

        raise NotFound()
    if link.dismissed_at is not None:
        raise ConflictState("This evidence link is already dismissed.", code="already_dismissed")
    if len(reason.strip()) < MIN_JUSTIFICATION:
        raise ValidationProblem(
            f"Explain the dismissal in at least {MIN_JUSTIFICATION} characters.", code="reason_required"
        )
    link.dismissed_at, link.dismissed_by = utcnow(), actor_id
    link.dismissed_reason = cipher.seal(
        reason.strip(), table="finding_evidence", column="dismissed_reason", row_id=link.id
    )
    await db.flush()
    return await recheck(db, cipher, inv, finding)


async def set_directly_states(
    db: AsyncSession, cipher: FieldCipher, inv: Investigation, finding: Finding, link_id: uuid.UUID, value: bool
) -> str | None:
    """Mark whether a supporting link states the claim directly (re-checks the status when unset)."""
    link = (
        await db.execute(
            select(FindingEvidence).where(FindingEvidence.id == link_id, FindingEvidence.finding_id == finding.id)
        )
    ).scalar_one_or_none()
    if link is None:
        from angel_engine.core.problems import NotFound

        raise NotFound()
    if value and link.stance != Stance.SUPPORTS.value:
        raise ValidationProblem("Only supporting evidence can state a claim directly.", code="invalid_stance")
    link.directly_states = value
    await db.flush()
    return None if value else await recheck(db, cipher, inv, finding)


async def remove_link(
    db: AsyncSession, cipher: FieldCipher, inv: Investigation, finding: Finding, link_id: uuid.UUID
) -> str | None:
    link = (
        await db.execute(
            select(FindingEvidence).where(FindingEvidence.id == link_id, FindingEvidence.finding_id == finding.id)
        )
    ).scalar_one_or_none()
    if link is None:
        from angel_engine.core.problems import NotFound

        raise NotFound()
    if finding.provenance != Provenance.AI_HYPOTHESIS.value:
        remaining = (
            await db.execute(
                select(func.count())
                .select_from(FindingEvidence)
                .where(FindingEvidence.finding_id == finding.id, FindingEvidence.id != link.id)
            )
        ).scalar_one()
        if remaining == 0:
            raise ConflictState(
                "A finding must keep at least one evidence link; retract the finding instead.",
                code="last_evidence_link",
            )
    await db.delete(link)
    await db.flush()
    return await recheck(db, cipher, inv, finding)


# --------------------------------------------------------------------------------------------------
# Views
# --------------------------------------------------------------------------------------------------
def open_statement(cipher: FieldCipher, finding: Finding) -> str:
    return cipher.open(finding.statement, table="findings", column="statement", row_id=finding.id)


def confidence_view(cipher: FieldCipher, finding: Finding) -> dict[str, Any] | None:
    if finding.confidence is None or finding.sensitive:
        return None
    return {
        "level": finding.confidence,
        "basis": cipher.open_optional(
            finding.confidence_basis, table="findings", column="confidence_basis", row_id=finding.id
        ),
    }
