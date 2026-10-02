"""Administration: user approvals and roles, platform settings, dead jobs and account flags.

Administrators manage the platform but cannot read investigation content (separation of duties).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select

from angel_engine.api.deps import DbSession, Principal, require, require_recent_reauth
from angel_engine.auth.sessions import revoke_all
from angel_engine.authz.permissions import Perm
from angel_engine.core.enums import Role, UserStatus
from angel_engine.core.problems import BadRequest, NotFound
from angel_engine.db.models import Job, User

router = APIRouter(prefix="/admin", tags=["admin"])

UserManager = Annotated[Principal, Depends(require(Perm.USER_MANAGE))]
JobsManager = Annotated[Principal, Depends(require(Perm.JOBS_MANAGE))]


class AdminUserOut(BaseModel):
    id: str
    email: str
    display_name: str
    role: str
    status: str
    mfa_enabled: bool
    organization_unit: str | None
    refusal_flag_level: int
    locked: bool
    created_at: datetime
    last_login_at: datetime | None
    access_justification: str | None = None


class ApproveIn(BaseModel):
    role: Role = Role.INVESTIGATOR


class RolePatch(BaseModel):
    role: Role


async def _user_out(
    db: DbSession, principal: Principal, user: User, *, include_justification: bool = False
) -> AdminUserOut:
    justification = None
    if include_justification and user.access_justification:
        cipher = await principal.services.vault.system_cipher(db, "system_secrets")
        justification = cipher.open(
            user.access_justification, table="users", column="access_justification", row_id=user.id
        )
    from angel_engine.core.clock import utcnow

    return AdminUserOut(
        id=str(user.id),
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        status=user.status,
        mfa_enabled=user.mfa_enabled,
        organization_unit=user.organization_unit,
        refusal_flag_level=user.refusal_flag_level,
        locked=bool(user.locked_until and user.locked_until > utcnow()),
        created_at=user.created_at,
        last_login_at=user.last_login_at,
        access_justification=justification,
    )


async def _get_user(db: DbSession, user_id: uuid.UUID) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise NotFound()
    return user


@router.get("/users")
async def list_users(
    principal: UserManager, db: DbSession, status: Annotated[UserStatus | None, Query()] = None
) -> list[AdminUserOut]:
    stmt = select(User).order_by(User.created_at.desc()).limit(500)
    if status is not None:
        stmt = stmt.where(User.status == status.value)
    users = (await db.execute(stmt)).scalars().all()
    return [
        await _user_out(db, principal, u, include_justification=u.status == UserStatus.PENDING.value) for u in users
    ]


@router.post("/users/{user_id}/approve")
async def approve_user(user_id: uuid.UUID, body: ApproveIn, principal: UserManager, db: DbSession) -> AdminUserOut:
    user = await _get_user(db, user_id)
    if user.status != UserStatus.PENDING.value:
        raise BadRequest("Only pending accounts can be approved.", code="not_pending")
    from angel_engine.core.clock import utcnow

    user.status = UserStatus.ACTIVE.value
    user.role = body.role.value
    user.approved_by = principal.user_id
    user.approved_at = utcnow()
    principal.audit(db, "admin.user_approved", target_type="user", target_id=str(user.id), details={"role": user.role})
    return await _user_out(db, principal, user)


@router.post("/users/{user_id}/disable")
async def disable_user(user_id: uuid.UUID, principal: UserManager, db: DbSession) -> AdminUserOut:
    if user_id == principal.user_id:
        raise BadRequest("You cannot disable your own account.", code="self_action")
    user = await _get_user(db, user_id)
    from angel_engine.core.clock import utcnow

    user.status = UserStatus.DISABLED.value
    user.disabled_at = utcnow()
    await revoke_all(db, user.id, reason="account_disabled")
    principal.audit(db, "admin.user_disabled", target_type="user", target_id=str(user.id))
    return await _user_out(db, principal, user)


@router.post("/users/{user_id}/enable")
async def enable_user(user_id: uuid.UUID, principal: UserManager, db: DbSession) -> AdminUserOut:
    user = await _get_user(db, user_id)
    if user.status != UserStatus.DISABLED.value:
        raise BadRequest("Only disabled accounts can be re-enabled.", code="not_disabled")
    user.status = UserStatus.ACTIVE.value
    user.disabled_at = None
    principal.audit(db, "admin.user_enabled", target_type="user", target_id=str(user.id))
    return await _user_out(db, principal, user)


@router.post("/users/{user_id}/unlock")
async def unlock_user(user_id: uuid.UUID, principal: UserManager, db: DbSession) -> AdminUserOut:
    user = await _get_user(db, user_id)
    user.locked_until = None
    user.failed_logins = 0
    user.lockout_count = 0
    principal.audit(db, "admin.user_unlocked", target_type="user", target_id=str(user.id))
    return await _user_out(db, principal, user)


@router.post("/users/{user_id}/reset-mfa")
async def reset_mfa(user_id: uuid.UUID, principal: UserManager, db: DbSession) -> AdminUserOut:
    require_recent_reauth(principal)
    if user_id == principal.user_id:
        raise BadRequest("Use your own security settings to change your authenticator.", code="self_action")
    user = await _get_user(db, user_id)
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_last_timestep = None
    await revoke_all(db, user.id, reason="mfa_reset")
    principal.audit(db, "admin.user_mfa_reset", target_type="user", target_id=str(user.id))
    return await _user_out(db, principal, user)


@router.post("/users/{user_id}/clear-flag")
async def clear_refusal_flag(user_id: uuid.UUID, principal: UserManager, db: DbSession) -> AdminUserOut:
    user = await _get_user(db, user_id)
    previous = user.refusal_flag_level
    user.refusal_flag_level = 0
    principal.audit(
        db, "admin.user_flag_cleared", target_type="user", target_id=str(user.id), details={"previous_level": previous}
    )
    return await _user_out(db, principal, user)


@router.patch("/users/{user_id}")
async def change_role(user_id: uuid.UUID, body: RolePatch, principal: UserManager, db: DbSession) -> AdminUserOut:
    require_recent_reauth(principal)
    if user_id == principal.user_id:
        raise BadRequest("You cannot change your own role.", code="self_action")
    user = await _get_user(db, user_id)
    previous = user.role
    user.role = body.role.value
    await revoke_all(db, user.id, reason="role_changed")
    principal.audit(
        db,
        "admin.user_role_changed",
        target_type="user",
        target_id=str(user.id),
        details={"from": previous, "to": user.role},
    )
    return await _user_out(db, principal, user)


@router.get("/flags")
async def flagged_users(principal: UserManager, db: DbSession) -> list[AdminUserOut]:
    users = (
        (await db.execute(select(User).where(User.refusal_flag_level > 0).order_by(User.refusal_flag_level.desc())))
        .scalars()
        .all()
    )
    return [await _user_out(db, principal, u) for u in users]


class JobOut(BaseModel):
    id: str
    queue: str
    kind: str
    status: str
    attempts: int
    last_error: str | None
    created_at: datetime
    finished_at: datetime | None


@router.get("/jobs")
async def list_jobs(principal: JobsManager, db: DbSession, status: str = "dead") -> list[JobOut]:
    rows = (
        (await db.execute(select(Job).where(Job.status == status).order_by(Job.created_at.desc()).limit(200)))
        .scalars()
        .all()
    )
    return [
        JobOut(
            id=str(j.id),
            queue=j.queue,
            kind=j.kind,
            status=j.status,
            attempts=j.attempts,
            last_error=j.last_error,
            created_at=j.created_at,
            finished_at=j.finished_at,
        )
        for j in rows
    ]


@router.post("/jobs/{job_id}/requeue")
async def requeue_job(job_id: uuid.UUID, principal: JobsManager, db: DbSession) -> JobOut:
    job = await db.get(Job, job_id)
    if job is None or job.status != "dead":
        raise NotFound()
    from angel_engine.core.clock import utcnow

    job.status, job.attempts, job.run_after, job.last_error = "queued", 0, utcnow(), None
    principal.audit(db, "admin.job_requeued", target_type="job", target_id=str(job.id), details={"kind": job.kind})
    return JobOut(
        id=str(job.id),
        queue=job.queue,
        kind=job.kind,
        status=job.status,
        attempts=job.attempts,
        last_error=job.last_error,
        created_at=job.created_at,
        finished_at=job.finished_at,
    )
