"""Investigations: create (with attestation and policy screening), list, detail, lifecycle, review, deletion,
retention, legal hold, members, oversight grants and activity."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select

from angel_engine.api.deps import (
    CurrentPrincipal,
    DbSession,
    InvCtx,
    Principal,
    audit_separately,
    effective_permissions,
    investigation_scope,
    ip_pseudonym,
    load_investigation_access,
    require,
    require_recent_reauth,
)
from angel_engine.api.v1.routers._common import contains_pattern
from angel_engine.authz.permissions import Perm, authorize, role_allows
from angel_engine.core.clock import utcnow
from angel_engine.core.enums import (
    InvestigationStatus,
    LawfulBasis,
    MemberRole,
    PurposeCategory,
    Role,
    SubjectType,
    UserStatus,
)
from angel_engine.core.ids import new_id
from angel_engine.core.problems import (
    BadRequest,
    ConflictState,
    Forbidden,
    NotFound,
    PreconditionFailed,
    ValidationProblem,
)
from angel_engine.db.models import (
    AuditLog,
    Investigation,
    InvestigationMember,
    OversightGrant,
    PolicyDecision,
    User,
)
from angel_engine.db.session import set_investigation_scope
from angel_engine.investigations import service

router = APIRouter(tags=["investigations"])
S = InvestigationStatus


# --------------------------------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------------------------------
class AttestationIn(BaseModel):
    lawful_purpose: bool
    no_harassment_or_stalking: bool
    no_discrimination: bool
    no_impersonation: bool
    understand_audit: bool
    terms_version: str = Field(max_length=40)
    acceptable_use_version: str = Field(max_length=40)


class InvestigationCreate(BaseModel):
    title: str = Field(min_length=3, max_length=140)
    description: str | None = Field(default=None, max_length=4000)
    purpose: str = Field(min_length=50, max_length=4000)
    purpose_category: PurposeCategory
    lawful_basis: LawfulBasis
    authorization_ref: str | None = Field(default=None, max_length=200)
    jurisdiction: str | None = Field(default=None, max_length=80)
    subject_type: SubjectType
    attestations: AttestationIn
    acknowledge_policy_notices: bool = False


class InvestigationPatch(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=140)
    description: str | None = Field(default=None, max_length=4000)
    #: Only while the investigation is a draft (e.g. after a reviewer requested changes); re-screened on submit.
    purpose: str | None = Field(default=None, min_length=50, max_length=4000)
    ai_enabled: bool | None = None


class SubmitIn(BaseModel):
    acknowledge_policy_notices: bool = False


class Counts(BaseModel):
    evidence: int = 0
    sources: int = 0
    findings: int = 0
    images: int = 0


class InvestigationSummary(BaseModel):
    id: str
    ref: str
    title: str
    status: str
    subject_type: str
    restricted_mode: bool
    purpose_category: str
    role: str | None
    owner_name: str | None
    created_at: datetime
    updated_at: datetime
    counts: Counts


class PolicySummary(BaseModel):
    decision_id: str | None = None
    decision: str
    categories: list[str] = []
    notices: list[str] = []
    rationale: str = ""


class InvestigationDetail(InvestigationSummary):
    description: str | None
    purpose: str
    lawful_basis: str
    authorization_ref: str | None
    jurisdiction: str | None
    permissions: list[str]
    legal_hold: bool
    ai_enabled: bool
    image_original_retention_hours: int | None
    closed_retention_days: int | None
    reviewed_at: datetime | None
    review_note: str | None
    closed_at: datetime | None
    version: int
    oversight: bool = False


class InvestigationCreated(BaseModel):
    investigation: InvestigationDetail
    policy: PolicySummary


class ActionOut(BaseModel):
    status: str


class ReviewIn(BaseModel):
    decision: Literal["approve", "reject", "request_changes"]
    note: str | None = Field(default=None, max_length=2000)


class DeletionIn(BaseModel):
    confirm_ref: str = Field(max_length=20)
    reason: str = Field(min_length=5, max_length=1000)


class RetentionIn(BaseModel):
    image_original_retention_hours: int | None = Field(default=None, ge=0, le=24 * 30)
    closed_retention_days: int | None = Field(default=None, ge=1, le=3650)


class LegalHoldIn(BaseModel):
    enabled: bool
    reason: str | None = Field(default=None, max_length=1000)


class MemberIn(BaseModel):
    email: str = Field(max_length=254)
    role: Literal["editor", "viewer"]


class MemberPatch(BaseModel):
    role: Literal["editor", "viewer"]


class MemberOut(BaseModel):
    user_id: str
    display_name: str
    email: str
    role: str
    added_at: datetime


class OversightIn(BaseModel):
    reason: str = Field(min_length=20, max_length=1000)
    hours: int = Field(default=24, ge=1, le=72)


class ActivityOut(BaseModel):
    seq: int
    occurred_at: datetime
    action: str
    outcome: str
    actor_name: str | None
    target_type: str | None
    target_id: str | None
    details: dict[str, Any]


class PolicyDecisionOut(BaseModel):
    id: str
    surface: str
    decision: str
    categories: list[str]
    rationale: str
    created_at: datetime
    investigation_id: str | None
    review_outcome: str | None


# --------------------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------------------
async def _owner_name(db: DbSession, owner_id: uuid.UUID) -> str | None:
    return (await db.execute(select(User.display_name).where(User.id == owner_id))).scalar_one_or_none()


async def _detail(
    ctx_db: DbSession, principal: Principal, inv: Investigation, membership: str | None, oversight: bool = False
) -> InvestigationDetail:
    svc = principal.services
    await set_investigation_scope(ctx_db, [inv.id])
    counts = (await service.content_counts(ctx_db, [inv.id]))[inv.id]
    cipher = await svc.vault.investigation_cipher(ctx_db, inv.id)

    def open_(column: str, value: bytes | None) -> str | None:
        return cipher.open_optional(value, table="investigations", column=column, row_id=inv.id)

    can_see_authorization = membership in (MemberRole.OWNER.value, MemberRole.EDITOR.value)
    return InvestigationDetail(
        id=str(inv.id),
        ref=inv.public_ref,
        title=inv.title,
        status=inv.status,
        subject_type=inv.subject_type,
        restricted_mode=inv.restricted_mode,
        purpose_category=inv.purpose_category,
        role=membership,
        owner_name=await _owner_name(ctx_db, inv.owner_id),
        created_at=inv.created_at,
        updated_at=inv.updated_at,
        counts=Counts(**counts),
        description=open_("description", inv.description),
        purpose=open_("purpose", inv.purpose) or "",
        lawful_basis=inv.lawful_basis,
        authorization_ref=open_("authorization_ref", inv.authorization_ref) if can_see_authorization else None,
        jurisdiction=inv.jurisdiction,
        permissions=effective_permissions(principal.role, membership, inv.status, oversight=oversight),
        legal_hold=inv.legal_hold,
        ai_enabled=inv.ai_enabled,
        image_original_retention_hours=inv.image_original_retention_hours,
        closed_retention_days=inv.closed_retention_days,
        reviewed_at=inv.reviewed_at,
        review_note=open_("review_note", inv.review_note),
        closed_at=inv.closed_at,
        version=inv.version,
        oversight=oversight,
    )


def _check_if_match(if_match: str | None, inv: Investigation) -> None:
    if if_match is not None and if_match.strip('"W/ ') != str(inv.version):
        raise PreconditionFailed(code="version_mismatch", current_version=inv.version)


Reviewer = Annotated[Principal, Depends(require(Perm.INVESTIGATION_REVIEW))]
Creator = Annotated[Principal, Depends(require(Perm.INVESTIGATION_CREATE))]
ReadCtx = Annotated[InvCtx, Depends(investigation_scope(Perm.CONTENT_READ))]
ManageCtx = Annotated[InvCtx, Depends(investigation_scope(Perm.INVESTIGATION_MANAGE))]
MembersCtx = Annotated[InvCtx, Depends(investigation_scope(Perm.MEMBERS_MANAGE))]


# --------------------------------------------------------------------------------------------------
# Create / list / detail
# --------------------------------------------------------------------------------------------------
@router.post("/investigations", status_code=201)
async def create_investigation(
    body: InvestigationCreate, request: Request, principal: Creator, db: DbSession
) -> InvestigationCreated:
    data = service.NewInvestigation(
        title=body.title,
        description=body.description,
        purpose=body.purpose,
        purpose_category=body.purpose_category.value,
        lawful_basis=body.lawful_basis.value,
        authorization_ref=body.authorization_ref,
        jurisdiction=body.jurisdiction,
        subject_type=body.subject_type.value,
        attestations=body.attestations.model_dump(exclude={"terms_version", "acceptable_use_version"}),
        terms_version=body.attestations.terms_version,
        acceptable_use_version=body.attestations.acceptable_use_version,
        acknowledge_policy_notices=body.acknowledge_policy_notices,
    )
    inv, result, decision_id = await service.create(
        principal.services,
        db,
        principal.user,
        data,
        ip_pseudonym=ip_pseudonym(request),
        actor_event=principal.event(""),
    )
    principal.audit(
        db,
        "investigation.created",
        investigation_id=inv.id,
        target_type="investigation",
        target_id=str(inv.id),
        details={"status": inv.status, "subject_type": inv.subject_type, "policy_decision": result.decision.value},
    )
    detail = await _detail(db, principal, inv, MemberRole.OWNER.value)
    return InvestigationCreated(
        investigation=detail,
        policy=PolicySummary(
            decision_id=str(decision_id),
            decision=result.decision.value,
            categories=[c.value for c in result.categories],
            notices=list(result.notices),
            rationale=result.rationale,
        ),
    )


@router.get("/investigations")
async def list_investigations(
    principal: CurrentPrincipal,
    db: DbSession,
    status: Annotated[list[InvestigationStatus] | None, Query()] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[InvestigationSummary]:
    stmt = (
        select(Investigation, InvestigationMember.role)
        .join(
            InvestigationMember,
            and_(
                InvestigationMember.investigation_id == Investigation.id,
                InvestigationMember.user_id == principal.user_id,
            ),
        )
        .where(Investigation.status != S.DELETED.value)
        .order_by(Investigation.updated_at.desc())
        .limit(limit)
    )
    if status:
        stmt = stmt.where(Investigation.status.in_([s.value for s in status]))
    if q:
        like = contains_pattern(q)
        stmt = stmt.where(
            or_(Investigation.title.ilike(like, escape="\\"), Investigation.public_ref.ilike(like, escape="\\"))
        )
    rows = (await db.execute(stmt)).all()
    ids = [inv.id for inv, _ in rows]
    await set_investigation_scope(db, ids)
    counts = await service.content_counts(db, ids)
    owners = (
        dict(
            (
                await db.execute(
                    select(User.id, User.display_name).where(User.id.in_({inv.owner_id for inv, _ in rows}))
                )
            ).all()
        )
        if rows
        else {}
    )
    return [
        InvestigationSummary(
            id=str(inv.id),
            ref=inv.public_ref,
            title=inv.title,
            status=inv.status,
            subject_type=inv.subject_type,
            restricted_mode=inv.restricted_mode,
            purpose_category=inv.purpose_category,
            role=role,
            owner_name=owners.get(inv.owner_id),
            created_at=inv.created_at,
            updated_at=inv.updated_at,
            counts=Counts(**counts[inv.id]),
        )
        for inv, role in rows
    ]


@router.get("/investigations/by-ref/{ref}")
async def investigation_by_ref(ref: str, principal: CurrentPrincipal, db: DbSession) -> InvestigationDetail:
    inv = (await db.execute(select(Investigation).where(Investigation.public_ref == ref.upper()))).scalar_one_or_none()
    if inv is None:
        raise NotFound()
    found, membership, oversight = await load_investigation_access(db, inv.id, principal.user_id)
    if found is None or inv.status == S.DELETED.value or (membership is None and not oversight):
        raise NotFound()
    return await _detail(db, principal, inv, membership, oversight)


@router.get("/investigations/{investigation_id}")
async def get_investigation(ctx: ReadCtx, response: Response) -> InvestigationDetail:
    ctx.principal.user.last_active_investigation_id = ctx.id
    response.headers["ETag"] = f'"{ctx.investigation.version}"'
    return await _detail(ctx.db, ctx.principal, ctx.investigation, ctx.membership, ctx.oversight)


@router.patch("/investigations/{investigation_id}")
async def update_investigation(
    body: InvestigationPatch, ctx: ManageCtx, if_match: Annotated[str | None, Header()] = None
) -> InvestigationDetail:
    inv = ctx.investigation
    _check_if_match(if_match, inv)
    if inv.status not in (S.DRAFT.value, S.ACTIVE.value, S.PENDING_REVIEW.value):
        raise ConflictState("Closed investigations cannot be edited.", code="investigation_state")
    changes: list[str] = []
    if body.title is not None and body.title.strip() != inv.title:
        from angel_engine.guard import redact_text

        if redact_text(body.title).redacted:
            raise ValidationProblem("Remove personal or sensitive data from the title.", code="sensitive_title")
        from angel_engine.policy.types import PolicyContext, Surface
        from angel_engine.policy_gate import screen

        await screen(
            ctx.principal.services,
            ctx.db,
            ctx.principal.user,
            body.title,
            PolicyContext(
                surface=Surface.INVESTIGATION_PURPOSE,
                subject_type=inv.subject_type,
                restricted_mode=inv.restricted_mode,
            ),
            investigation_id=inv.id,
            target_type="investigation",
            target_id=inv.id,
            actor_event=ctx.principal.event(""),
        )
        inv.title = body.title.strip()
        changes.append("title")
    if body.description is not None:
        cipher = await ctx.cipher()
        inv.description = cipher.seal(body.description, table="investigations", column="description", row_id=inv.id)
        changes.append("description")
    if body.purpose is not None:
        if inv.status != S.DRAFT.value:
            raise ConflictState(
                "The purpose can only be changed while the investigation is a draft.", code="investigation_state"
            )
        cipher = await ctx.cipher()
        inv.purpose = cipher.seal(body.purpose.strip(), table="investigations", column="purpose", row_id=inv.id)
        changes.append("purpose")
    if body.ai_enabled is not None:
        inv.ai_enabled = body.ai_enabled
        changes.append("ai_enabled")
    ctx.audit("investigation.updated", target_type="investigation", target_id=str(inv.id), details={"fields": changes})
    await ctx.db.flush()
    return await _detail(ctx.db, ctx.principal, inv, ctx.membership, ctx.oversight)


# --------------------------------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------------------------------
@router.post("/investigations/{investigation_id}/submit")
async def submit_investigation(ctx: ManageCtx, body: SubmitIn | None = None) -> InvestigationCreated:
    if ctx.membership != MemberRole.OWNER.value:
        raise Forbidden("Only the owner can submit the investigation.", code="owner_only")
    result, decision_id = await service.resubmit(
        ctx.principal.services,
        ctx.db,
        ctx.principal.user,
        ctx.investigation,
        await ctx.cipher(),
        ctx.principal.event(""),
        acknowledged=bool(body and body.acknowledge_policy_notices),
    )
    ctx.audit(
        "investigation.submitted",
        target_type="investigation",
        target_id=str(ctx.id),
        details={"status": ctx.investigation.status, "policy_decision": result.decision.value},
    )
    detail = await _detail(ctx.db, ctx.principal, ctx.investigation, ctx.membership)
    return InvestigationCreated(
        investigation=detail,
        policy=PolicySummary(
            decision_id=str(decision_id),
            decision=result.decision.value,
            categories=[c.value for c in result.categories],
            notices=list(result.notices),
            rationale=result.rationale,
        ),
    )


SUPERVISOR_ACTIONS = frozenset({"suspend", "resume", "restore"})


def _lifecycle_endpoint(action: str) -> Any:
    async def endpoint(ctx: ReadCtx) -> ActionOut:
        principal = ctx.principal
        inv = ctx.investigation
        if action in SUPERVISOR_ACTIONS or (action == "reopen" and inv.restricted_mode):
            # Supervisors act on investigations they can see (membership or an active oversight grant).
            if not role_allows(principal.role, Perm.INVESTIGATION_REVIEW):
                raise Forbidden("A supervisor must perform this action.", code="supervisor_required")
        elif not authorize(principal.role, ctx.membership, Perm.INVESTIGATION_MANAGE):
            raise Forbidden(code="missing_permission", permission=Perm.INVESTIGATION_MANAGE.value)
        status = service.apply_transition(inv, action)
        ctx.audit(
            f"investigation.{action}", target_type="investigation", target_id=str(inv.id), details={"status": status}
        )
        return ActionOut(status=status)

    endpoint.__name__ = f"{action}_investigation"
    endpoint.__doc__ = f"Lifecycle transition: {action}."
    return endpoint


for _action in service.TRANSITIONS:
    router.add_api_route(
        f"/investigations/{{investigation_id}}/{_action}",
        _lifecycle_endpoint(_action),
        methods=["POST"],
        response_model=ActionOut,
        name=f"{_action}_investigation",
    )


@router.post("/investigations/{investigation_id}/review")
async def review_investigation(
    investigation_id: uuid.UUID, body: ReviewIn, principal: Reviewer, db: DbSession
) -> ActionOut:
    inv = await db.get(Investigation, investigation_id)
    if inv is None or inv.status == S.DELETED.value:
        raise NotFound()
    status = await service.review(principal.services, db, principal.user, inv, body.decision, body.note)
    if body.decision == "approve" and inv.last_policy_decision_id:
        decision = await db.get(PolicyDecision, inv.last_policy_decision_id)
        if decision is not None:
            decision.review_outcome, decision.reviewed_by, decision.reviewed_at = (
                "approved",
                principal.user_id,
                utcnow(),
            )
    principal.audit(
        db,
        "investigation.reviewed",
        investigation_id=inv.id,
        target_type="investigation",
        target_id=str(inv.id),
        details={"decision": body.decision, "status": status},
    )
    return ActionOut(status=status)


class ReviewItem(BaseModel):
    id: str
    ref: str
    title: str
    subject_type: str
    purpose_category: str
    lawful_basis: str
    purpose: str
    authorization_ref: str | None
    jurisdiction: str | None
    requested_by: str | None
    submitted_at: datetime | None
    policy_categories: list[str]
    policy_rationale: str


@router.get("/reviews")
async def pending_reviews(principal: Reviewer, db: DbSession) -> list[ReviewItem]:
    """Investigations awaiting supervisor approval (purpose and basis only — no investigation content)."""
    rows = (
        (
            await db.execute(
                select(Investigation)
                .where(Investigation.status == S.PENDING_REVIEW.value)
                .order_by(Investigation.submitted_at)
            )
        )
        .scalars()
        .all()
    )
    out: list[ReviewItem] = []
    for inv in rows:
        cipher = await principal.services.vault.investigation_cipher(db, inv.id)
        decision = await db.get(PolicyDecision, inv.last_policy_decision_id) if inv.last_policy_decision_id else None
        out.append(
            ReviewItem(
                id=str(inv.id),
                ref=inv.public_ref,
                title=inv.title,
                subject_type=inv.subject_type,
                purpose_category=inv.purpose_category,
                lawful_basis=inv.lawful_basis,
                purpose=cipher.open(inv.purpose, table="investigations", column="purpose", row_id=inv.id),
                authorization_ref=cipher.open_optional(
                    inv.authorization_ref, table="investigations", column="authorization_ref", row_id=inv.id
                ),
                jurisdiction=inv.jurisdiction,
                requested_by=await _owner_name(db, inv.owner_id),
                submitted_at=inv.submitted_at,
                policy_categories=list(decision.categories) if decision else [],
                policy_rationale=decision.rationale if decision else "",
            )
        )
    principal.audit(db, "investigation.review_queue_viewed", details={"count": len(out)})
    return out


@router.post("/investigations/{investigation_id}/deletion", status_code=202)
async def delete_investigation(
    investigation_id: uuid.UUID, body: DeletionIn, principal: CurrentPrincipal, db: DbSession
) -> dict[str, str]:
    require_recent_reauth(principal)
    inv, membership, _ = await load_investigation_access(db, investigation_id, principal.user_id)
    is_admin = role_allows(principal.role, Perm.USER_MANAGE)
    if inv is None or inv.status == S.DELETED.value or (membership != MemberRole.OWNER.value and not is_admin):
        raise NotFound()
    if body.confirm_ref.strip().upper() != inv.public_ref:
        raise ValidationProblem(
            "Type the investigation reference exactly to confirm deletion.", code="confirm_mismatch"
        )
    if not authorize(principal.role, membership, Perm.INVESTIGATION_MANAGE) and not is_admin:
        raise Forbidden(code="missing_permission")
    ref = inv.public_ref
    job_id = await service.delete_investigation(principal.services, db, inv, body.reason)
    principal.audit(
        db,
        "investigation.deleted",
        investigation_id=inv.id,
        target_type="investigation",
        target_id=str(inv.id),
        details={"by_admin": membership != MemberRole.OWNER.value},
    )
    return {
        "status": "deleted",
        "ref": ref,
        "purge_job_id": str(job_id),
        "detail": "The investigation's encryption key was destroyed; remaining records are being purged.",
    }


# --------------------------------------------------------------------------------------------------
# Retention & legal hold
# --------------------------------------------------------------------------------------------------
class RetentionOut(BaseModel):
    image_original_retention_hours: int
    image_original_retention_max_hours: int
    closed_retention_days: int
    archive_after_days: int
    legal_hold: bool
    deletion_scheduled_for: datetime | None


def _retention_out(svc_settings: Any, inv: Investigation) -> RetentionOut:
    closed_days = inv.closed_retention_days or svc_settings.closed_investigation_delete_days
    scheduled = inv.closed_at + timedelta(days=closed_days) if inv.closed_at and not inv.legal_hold else None
    return RetentionOut(
        image_original_retention_hours=inv.image_original_retention_hours
        if inv.image_original_retention_hours is not None
        else svc_settings.image_original_retention_hours,
        image_original_retention_max_hours=svc_settings.image_original_retention_max_hours,
        closed_retention_days=closed_days,
        archive_after_days=svc_settings.closed_investigation_archive_days,
        legal_hold=inv.legal_hold,
        deletion_scheduled_for=scheduled,
    )


@router.get("/investigations/{investigation_id}/retention")
async def get_retention(ctx: ReadCtx) -> RetentionOut:
    return _retention_out(ctx.principal.services.settings, ctx.investigation)


@router.put("/investigations/{investigation_id}/retention")
async def set_retention(body: RetentionIn, ctx: ManageCtx) -> RetentionOut:
    settings = ctx.principal.services.settings
    inv = ctx.investigation
    if body.image_original_retention_hours is not None:
        if body.image_original_retention_hours > settings.image_original_retention_max_hours:
            raise ValidationProblem(
                f"Image originals can be kept for at most {settings.image_original_retention_max_hours} hours.",
                code="retention_above_maximum",
            )
        inv.image_original_retention_hours = body.image_original_retention_hours
    if body.closed_retention_days is not None:
        if body.closed_retention_days > settings.closed_investigation_delete_days:
            raise ValidationProblem("This exceeds the platform's maximum retention.", code="retention_above_maximum")
        inv.closed_retention_days = body.closed_retention_days
    ctx.audit("investigation.retention_updated", details=body.model_dump(exclude_none=True))
    return _retention_out(settings, inv)


@router.put("/investigations/{investigation_id}/legal-hold")
async def set_legal_hold(
    investigation_id: uuid.UUID,
    body: LegalHoldIn,
    principal: Annotated[Principal, Depends(require(Perm.LEGAL_HOLD_SET))],
    db: DbSession,
) -> RetentionOut:
    require_recent_reauth(principal)
    inv = await db.get(Investigation, investigation_id)
    if inv is None or inv.status == S.DELETED.value:
        raise NotFound()
    if body.enabled and not (body.reason or "").strip():
        raise ValidationProblem("A reason is required to place a legal hold.", code="reason_required")
    inv.legal_hold = body.enabled
    cipher = await principal.services.vault.investigation_cipher(db, inv.id)
    inv.legal_hold_reason = (
        cipher.seal(body.reason, table="investigations", column="legal_hold_reason", row_id=inv.id)
        if body.enabled and body.reason
        else None
    )
    principal.audit(db, "investigation.legal_hold", investigation_id=inv.id, details={"enabled": body.enabled})
    return _retention_out(principal.services.settings, inv)


# --------------------------------------------------------------------------------------------------
# Members, oversight, activity
# --------------------------------------------------------------------------------------------------
@router.get("/investigations/{investigation_id}/members")
async def list_members(ctx: ReadCtx) -> list[MemberOut]:
    rows = (
        await ctx.db.execute(
            select(InvestigationMember, User)
            .join(User, User.id == InvestigationMember.user_id)
            .where(InvestigationMember.investigation_id == ctx.id)
            .order_by(InvestigationMember.created_at)
        )
    ).all()
    return [
        MemberOut(user_id=str(u.id), display_name=u.display_name, email=u.email, role=m.role, added_at=m.created_at)
        for m, u in rows
    ]


@router.post("/investigations/{investigation_id}/members", status_code=201)
async def add_member(body: MemberIn, ctx: MembersCtx) -> MemberOut:
    user = (await ctx.db.execute(select(User).where(User.email == body.email.strip()))).scalar_one_or_none()
    if user is None or user.status != UserStatus.ACTIVE.value:
        raise BadRequest("No active user with this email address.", code="unknown_user")
    if user.role in (Role.ADMIN.value, Role.AUDITOR.value):
        raise BadRequest(
            "Administrators and auditors cannot be investigation members (separation of duties).",
            code="role_not_allowed",
        )
    existing = await ctx.db.get(InvestigationMember, (ctx.id, user.id))
    if existing is not None:
        raise BadRequest("This user is already a member.", code="already_member")
    member = InvestigationMember(
        investigation_id=ctx.id, user_id=user.id, role=body.role, added_by=ctx.principal.user_id
    )
    ctx.db.add(member)
    await ctx.db.flush()
    ctx.audit("investigation.member_added", target_type="user", target_id=str(user.id), details={"role": body.role})
    return MemberOut(
        user_id=str(user.id),
        display_name=user.display_name,
        email=user.email,
        role=body.role,
        added_at=member.created_at,
    )


@router.patch("/investigations/{investigation_id}/members/{user_id}")
async def change_member(user_id: uuid.UUID, body: MemberPatch, ctx: MembersCtx) -> ActionOut:
    member = await ctx.db.get(InvestigationMember, (ctx.id, user_id))
    if member is None:
        raise NotFound()
    if member.role == MemberRole.OWNER.value:
        raise BadRequest("The owner's role cannot be changed.", code="owner_role")
    member.role = body.role
    ctx.audit(
        "investigation.member_role_changed", target_type="user", target_id=str(user_id), details={"role": body.role}
    )
    return ActionOut(status=body.role)


@router.delete("/investigations/{investigation_id}/members/{user_id}")
async def remove_member(user_id: uuid.UUID, ctx: MembersCtx) -> ActionOut:
    member = await ctx.db.get(InvestigationMember, (ctx.id, user_id))
    if member is None:
        raise NotFound()
    if member.role == MemberRole.OWNER.value:
        raise BadRequest("The owner cannot be removed.", code="owner_role")
    await ctx.db.delete(member)
    ctx.audit("investigation.member_removed", target_type="user", target_id=str(user_id))
    return ActionOut(status="removed")


@router.post("/investigations/{investigation_id}/oversight-grants", status_code=201)
async def grant_oversight(
    investigation_id: uuid.UUID,
    body: OversightIn,
    principal: Annotated[Principal, Depends(require(Perm.INVESTIGATION_OVERSIGHT))],
    db: DbSession,
) -> dict[str, str]:
    """A supervisor grants themselves time-boxed, read-only, audited access to an investigation."""
    require_recent_reauth(principal)
    inv = await db.get(Investigation, investigation_id)
    if inv is None or inv.status == S.DELETED.value:
        raise NotFound()
    grant_id = new_id()
    cipher = await principal.services.vault.investigation_cipher(db, inv.id)
    now = utcnow()
    grant = OversightGrant(
        id=grant_id,
        investigation_id=inv.id,
        grantee_id=principal.user_id,
        granted_by=principal.user_id,
        created_at=now,
        reason=cipher.seal(body.reason, table="oversight_grants", column="reason", row_id=grant_id),
        expires_at=now + timedelta(hours=body.hours),
    )
    db.add(grant)
    await db.flush()
    await audit_separately(
        principal.services,
        principal.event(
            "investigation.oversight_granted",
            investigation_id=inv.id,
            target_type="oversight_grant",
            target_id=str(grant_id),
            details={"hours": body.hours},
        ),
    )
    return {"status": "granted", "expires_at": grant.expires_at.isoformat()}


@router.get("/investigations/{investigation_id}/activity")
async def investigation_activity(
    ctx: ReadCtx,
    before_seq: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> list[ActivityOut]:
    stmt = select(AuditLog).where(AuditLog.investigation_id == ctx.id).order_by(AuditLog.seq.desc()).limit(limit)
    if before_seq is not None:
        stmt = stmt.where(AuditLog.seq < before_seq)
    rows = (await ctx.db.execute(stmt)).scalars().all()
    names = (
        dict(
            (
                await ctx.db.execute(
                    select(User.id, User.display_name).where(User.id.in_({r.actor_id for r in rows if r.actor_id}))
                )
            ).all()
        )
        if rows
        else {}
    )
    return [
        ActivityOut(
            seq=r.seq,
            occurred_at=r.occurred_at,
            action=r.action,
            outcome=r.outcome,
            actor_name=names.get(r.actor_id) if r.actor_id else ("System" if r.actor_type != "anonymous" else None),
            target_type=r.target_type,
            target_id=r.target_id,
            details=r.details,
        )
        for r in rows
    ]


@router.get("/me/policy-decisions")
async def my_policy_decisions(
    principal: CurrentPrincipal,
    db: DbSession,
    decision: Annotated[str | None, Query(pattern="^(refuse|review|warn|allow)$")] = None,
) -> list[PolicyDecisionOut]:
    """The signed-in user's own screened requests (the "Refused requests" view). Text is never echoed back."""
    stmt = (
        select(PolicyDecision)
        .where(PolicyDecision.user_id == principal.user_id)
        .order_by(PolicyDecision.created_at.desc())
        .limit(200)
    )
    if decision:
        stmt = stmt.where(PolicyDecision.decision == decision)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        PolicyDecisionOut(
            id=str(r.id),
            surface=r.surface,
            decision=r.decision,
            categories=list(r.categories),
            rationale=r.rationale,
            created_at=r.created_at,
            investigation_id=str(r.investigation_id) if r.investigation_id else None,
            review_outcome=r.review_outcome,
        )
        for r in rows
    ]
