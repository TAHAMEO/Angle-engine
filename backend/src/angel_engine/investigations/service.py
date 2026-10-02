"""Investigation lifecycle: creation (attestation + policy screening), review, transitions, deletion."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.app_state import Services
from angel_engine.audit.chain import record
from angel_engine.core.clock import utcnow
from angel_engine.core.enums import InvestigationStatus, MemberRole, SubjectType
from angel_engine.core.ids import new_id
from angel_engine.core.problems import ConflictState, Forbidden, ValidationProblem
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.db.models import Attestation, Investigation, InvestigationMember, Job, User
from angel_engine.jobs.queue import enqueue
from angel_engine.legal.documents import current_versions
from angel_engine.policy.types import Decision, PolicyContext, PolicyResult, Surface
from angel_engine.policy_gate import require_acknowledgement, screen

S = InvestigationStatus
REQUIRED_ATTESTATIONS = (
    "lawful_purpose",
    "no_harassment_or_stalking",
    "no_discrimination",
    "no_impersonation",
    "understand_audit",
)
AUTHORIZATION_REQUIRED_CATEGORIES = ("law_enforcement", "legal_proceedings")

#: action → (allowed from-states, to-state)
TRANSITIONS: dict[str, tuple[frozenset[str], str]] = {
    "close": (frozenset({S.ACTIVE, S.SUSPENDED}), S.CLOSED),
    "reopen": (frozenset({S.CLOSED}), S.ACTIVE),
    "archive": (frozenset({S.CLOSED}), S.ARCHIVED),
    "restore": (frozenset({S.ARCHIVED}), S.CLOSED),
    "suspend": (frozenset({S.ACTIVE}), S.SUSPENDED),
    "resume": (frozenset({S.SUSPENDED}), S.ACTIVE),
}


@dataclass(frozen=True, slots=True)
class NewInvestigation:
    title: str
    description: str | None
    purpose: str
    purpose_category: str
    lawful_basis: str
    authorization_ref: str | None
    jurisdiction: str | None
    subject_type: str
    attestations: dict[str, bool]
    terms_version: str
    acceptable_use_version: str
    acknowledge_policy_notices: bool = False


def validate_new(data: NewInvestigation) -> None:
    versions = current_versions()
    if data.terms_version != versions["terms"] or data.acceptable_use_version != versions["acceptable_use"]:
        raise ValidationProblem(
            "Please accept the current Terms of Use and Acceptable Use Policy.", code="stale_document_version"
        )
    missing = [k for k in REQUIRED_ATTESTATIONS if not data.attestations.get(k)]
    if missing:
        raise ValidationProblem("All attestations must be confirmed.", code="attestation_required", missing=missing)
    if (
        data.purpose_category in AUTHORIZATION_REQUIRED_CATEGORIES
        or data.lawful_basis == "law_enforcement_authorization"
    ) and not (data.authorization_ref or "").strip():
        raise ValidationProblem(
            "An authorization reference is required for this purpose.", code="authorization_required"
        )
    from angel_engine.guard import redact_text

    if redact_text(data.title).redacted:
        raise ValidationProblem(
            "Remove personal or sensitive data (emails, phone numbers, IDs) from the title.", code="sensitive_title"
        )


async def allocate_ref(db: AsyncSession) -> tuple[int, int]:
    year = utcnow().year
    seq = (
        await db.execute(
            text(
                "INSERT INTO investigation_ref_counters (year, last_seq) VALUES (:y, 1) "
                "ON CONFLICT (year) DO UPDATE SET last_seq = investigation_ref_counters.last_seq + 1 "
                "RETURNING last_seq"
            ),
            {"y": year},
        )
    ).scalar_one()
    return year, int(seq)


def _screen_text(data: NewInvestigation) -> str:
    parts = [data.title, data.purpose]
    if data.description:
        parts.append(data.description)
    return "\n\n".join(parts)


def initial_status(subject_type: str, result: PolicyResult) -> str:
    if result.decision == Decision.REVIEW or subject_type == SubjectType.INDIVIDUAL.value:
        return S.PENDING_REVIEW.value
    return S.ACTIVE.value


async def create(
    svc: Services, db: AsyncSession, user: User, data: NewInvestigation, *, ip_pseudonym: str | None, actor_event: Any
) -> tuple[Investigation, PolicyResult, uuid.UUID]:
    validate_new(data)
    if user.refusal_flag_level >= 3:
        raise Forbidden("This account is suspended pending review.", code="account_suspended")
    ctx = PolicyContext(
        surface=Surface.INVESTIGATION_PURPOSE,
        subject_type=data.subject_type,
        restricted_mode=data.subject_type == SubjectType.INDIVIDUAL.value,
    )
    result, decision_row = await screen(
        svc, db, user, _screen_text(data), ctx, target_type="investigation", actor_event=actor_event
    )
    require_acknowledgement(result, data.acknowledge_policy_notices)
    year, seq = await allocate_ref(db)
    inv_id = new_id()
    status = initial_status(data.subject_type, result)
    now = utcnow()
    inv = Investigation(
        id=inv_id,
        ref_year=year,
        ref_seq=seq,
        title=data.title.strip(),
        purpose=b"",
        purpose_category=data.purpose_category,
        lawful_basis=data.lawful_basis,
        jurisdiction=data.jurisdiction,
        subject_type=data.subject_type,
        restricted_mode=data.subject_type == SubjectType.INDIVIDUAL.value,
        status=status,
        owner_id=user.id,
        last_policy_decision_id=decision_row.id,
        submitted_at=now,
        activated_at=now if status == S.ACTIVE.value else None,
    )
    db.add(inv)
    await db.flush()
    cipher = await svc.vault.create_investigation_key(db, inv_id)
    seal = _sealer(cipher, inv_id)
    inv.purpose = seal("purpose", data.purpose.strip())
    inv.description = seal("description", data.description.strip()) if data.description else None
    inv.authorization_ref = (
        seal("authorization_ref", data.authorization_ref.strip()) if data.authorization_ref else None
    )
    db.add(InvestigationMember(investigation_id=inv_id, user_id=user.id, role=MemberRole.OWNER.value))
    db.add(
        Attestation(
            user_id=user.id,
            investigation_id=inv_id,
            kind="investigation_purpose",
            document_versions=current_versions(),
            statements=sorted(k for k, v in data.attestations.items() if v),
            ip_pseudonym=ip_pseudonym,
        )
    )
    decision_row.investigation_id = inv_id
    decision_row.target_id = inv_id
    user.last_active_investigation_id = inv_id
    await db.flush()
    return inv, result, decision_row.id


def _sealer(cipher: FieldCipher, inv_id: uuid.UUID) -> Any:
    def seal(column: str, value: str) -> bytes:
        return cipher.seal(value, table="investigations", column=column, row_id=inv_id)

    return seal


async def resubmit(
    svc: Services,
    db: AsyncSession,
    user: User,
    inv: Investigation,
    cipher: FieldCipher,
    actor_event: Any,
    *,
    acknowledged: bool = False,
) -> tuple[PolicyResult, uuid.UUID]:
    if inv.status != S.DRAFT.value:
        raise ConflictState("Only draft investigations can be submitted.", code="investigation_state")
    purpose = cipher.open(inv.purpose, table="investigations", column="purpose", row_id=inv.id)
    description = cipher.open_optional(inv.description, table="investigations", column="description", row_id=inv.id)
    ctx = PolicyContext(
        surface=Surface.INVESTIGATION_PURPOSE, subject_type=inv.subject_type, restricted_mode=inv.restricted_mode
    )
    text_value = "\n\n".join(p for p in (inv.title, purpose, description) if p)
    result, row = await screen(
        svc,
        db,
        user,
        text_value,
        ctx,
        investigation_id=inv.id,
        target_type="investigation",
        target_id=inv.id,
        actor_event=actor_event,
    )
    require_acknowledgement(result, acknowledged)
    inv.status = initial_status(inv.subject_type, result)
    inv.submitted_at = utcnow()
    inv.last_policy_decision_id = row.id
    if inv.status == S.ACTIVE.value:
        inv.activated_at = utcnow()
    return result, row.id


def apply_transition(inv: Investigation, action: str) -> str:
    allowed, target = TRANSITIONS[action]
    if inv.status not in allowed:
        raise ConflictState(
            f"Cannot {action} an investigation that is {inv.status.replace('_', ' ')}.",
            code="investigation_state",
            allowed_from=sorted(allowed),
        )
    if action in ("close",) and inv.status == S.ACTIVE.value:
        inv.closed_at = utcnow()
    if action == "archive":
        inv.archived_at = utcnow()
    if action == "reopen":
        inv.closed_at = None
    inv.status = target
    return target


async def review(
    svc: Services, db: AsyncSession, reviewer: User, inv: Investigation, decision: str, note: str | None
) -> str:
    if inv.status != S.PENDING_REVIEW.value:
        raise ConflictState("This investigation is not awaiting review.", code="investigation_state")
    if inv.owner_id == reviewer.id:
        raise Forbidden("Reviewers cannot approve their own investigations.", code="self_review")
    cipher = await svc.vault.investigation_cipher(db, inv.id)
    now = utcnow()
    inv.reviewed_by, inv.reviewed_at = reviewer.id, now
    if note:
        inv.review_note = cipher.seal(note, table="investigations", column="review_note", row_id=inv.id)
    if decision == "approve":
        inv.status = S.ACTIVE.value
        inv.activated_at = now
    elif decision == "reject":
        inv.status = S.REFUSED.value
    else:
        inv.status = S.DRAFT.value
    return inv.status


async def delete_investigation(svc: Services, db: AsyncSession, inv: Investigation, reason: str) -> uuid.UUID:
    """Tombstone + crypto-shred now; the purge job removes the remaining rows and blobs."""
    if inv.legal_hold:
        raise ConflictState("This investigation is under legal hold and cannot be deleted.", code="legal_hold")
    now = utcnow()
    inv.status = S.DELETED.value
    inv.deleted_at = now
    inv.title = f"Deleted investigation {inv.public_ref}"
    inv.description = None
    inv.purpose = b""
    inv.authorization_ref = None
    inv.review_note = None
    inv.legal_hold_reason = None
    inv.purge_after = now
    await svc.vault.destroy_investigation_keys(db, inv.id)
    await db.execute(
        update(Job)
        .where(Job.investigation_id == inv.id, Job.status == "queued")
        .values(status="cancelled", finished_at=now)
    )
    from sqlalchemy import delete

    await db.execute(delete(InvestigationMember).where(InvestigationMember.investigation_id == inv.id))
    job = await enqueue(
        db,
        queue="maintenance",
        kind="investigations.purge",
        payload={"investigation_id": str(inv.id), "reason_length": len(reason)},
        idempotency_key=f"purge:{inv.id}",
    )
    return job.id


async def content_counts(db: AsyncSession, investigation_ids: list[uuid.UUID]) -> dict[uuid.UUID, dict[str, int]]:
    """Per-investigation counts (caller must have set the RLS scope to ``investigation_ids``)."""
    out: dict[uuid.UUID, dict[str, int]] = {
        i: {"evidence": 0, "sources": 0, "findings": 0, "images": 0} for i in investigation_ids
    }
    if not investigation_ids:
        return out
    for key, table in (
        ("evidence", "evidence_items"),
        ("sources", "sources"),
        ("findings", "findings"),
        ("images", "images"),
    ):
        rows = (
            await db.execute(text(f"SELECT investigation_id, count(*) FROM {table} GROUP BY investigation_id"))  # noqa: S608
        ).all()
        for inv_id, count in rows:
            if inv_id in out:
                out[inv_id][key] = int(count)
    return out


async def member_investigation_ids(db: AsyncSession, user_id: uuid.UUID) -> list[uuid.UUID]:
    rows = (
        (await db.execute(select(InvestigationMember.investigation_id).where(InvestigationMember.user_id == user_id)))
        .scalars()
        .all()
    )
    return list(rows)


async def pending_review_count(db: AsyncSession) -> int:
    return int(
        (
            await db.execute(
                select(func.count()).select_from(Investigation).where(Investigation.status == S.PENDING_REVIEW.value)
            )
        ).scalar_one()
    )


def purge_due(inv: Investigation, *, archive_days: int, delete_days: int) -> str | None:
    """Return "archive" / "delete" when a closed investigation's retention period has elapsed."""
    if inv.legal_hold or inv.closed_at is None:
        return None
    age = utcnow() - inv.closed_at
    days = inv.closed_retention_days or delete_days
    if inv.status in (S.CLOSED.value, S.ARCHIVED.value) and age >= timedelta(days=days):
        return "delete"
    if inv.status == S.CLOSED.value and age >= timedelta(days=archive_days):
        return "archive"
    return None


__all__ = [
    "TRANSITIONS",
    "NewInvestigation",
    "apply_transition",
    "content_counts",
    "create",
    "delete_investigation",
    "member_investigation_ids",
    "pending_review_count",
    "purge_due",
    "record",
    "resubmit",
    "review",
]
