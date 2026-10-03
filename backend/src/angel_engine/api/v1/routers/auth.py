"""Authentication: login with mandatory TOTP, enrollment, re-authentication, logout, registration requests."""

from __future__ import annotations

import hashlib
import re
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, update

from angel_engine.api.deps import (
    CurrentPrincipal,
    DbSession,
    PendingSession,
    ServicesDep,
    anonymous_csrf,
    audit_separately,
    clear_session_cookies,
    enforce_rate_limit,
    get_services,
    ip_pseudonym,
    request_id,
    set_session_cookies,
)
from angel_engine.app_state import Services
from angel_engine.audit.chain import AuditEvent
from angel_engine.auth import csrf, mfa, passwords, sessions
from angel_engine.core.clock import utcnow
from angel_engine.core.enums import Role, SessionState, UserStatus
from angel_engine.core.problems import BadRequest, Forbidden, Unauthenticated, ValidationProblem
from angel_engine.db.models import Attestation, RecoveryCode, User, UserSession
from angel_engine.infra.ratelimit.gcra import LOGIN_ACCOUNT, LOGIN_IP, MFA_ACCOUNT, REGISTRATION_IP
from angel_engine.legal.documents import current_versions

router = APIRouter(prefix="/auth", tags=["auth"])

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}\.[^@\s]{2,63}$")
GENERIC_LOGIN_ERROR = "Invalid email or password."


def _check_email(value: str) -> str:
    value = value.strip()
    if not EMAIL_RE.match(value) or len(value) > 254:
        raise ValueError("Enter a valid email address.")
    return value


class UserOut(BaseModel):
    id: str
    email: str
    display_name: str
    role: str
    status: str
    mfa_enabled: bool
    organization_unit: str | None
    terms_version_accepted: str | None
    preferences: dict[str, object]
    last_active_investigation_id: str | None

    @classmethod
    def of(cls, user: User) -> UserOut:
        return cls(
            id=str(user.id),
            email=user.email,
            display_name=user.display_name,
            role=user.role,
            status=user.status,
            mfa_enabled=user.mfa_enabled,
            organization_unit=user.organization_unit,
            terms_version_accepted=user.terms_version_accepted,
            preferences=user.preferences or {},
            last_active_investigation_id=str(user.last_active_investigation_id)
            if user.last_active_investigation_id
            else None,
        )


class SessionOut(BaseModel):
    state: Literal["active", "mfa_pending", "mfa_enroll"]
    user: UserOut | None = None
    csrf_token: str
    idle_expires_in: int
    absolute_expires_in: int
    terms_current: bool = True
    current_terms_version: str


class LoginIn(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=1, max_length=256)

    _email = field_validator("email")(_check_email)


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=32)


class PasswordIn(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class RegistrationIn(BaseModel):
    email: str = Field(max_length=254)
    display_name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=1, max_length=256)
    organization_unit: str | None = Field(default=None, max_length=200)
    justification: str = Field(min_length=30, max_length=2000)
    accept_terms: bool
    attest_lawful_use: bool
    attest_no_misuse: bool
    #: Honeypot field: must be empty (bots fill every field).
    website: str | None = Field(default=None, max_length=200)

    _email = field_validator("email")(_check_email)


class EnrollmentOut(BaseModel):
    secret: str
    otpauth_uri: str
    qr_data_uri: str


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]


async def _record_login_failure(svc: Services, user_id: object) -> None:
    """Count a failed login (own transaction, so it persists although the request fails)."""
    async with svc.db.session("app") as s2:
        user = (await s2.execute(select(User).where(User.id == user_id).with_for_update())).scalar_one()
        user.failed_logins += 1
        if user.failed_logins >= svc.settings.login_lockout_threshold:
            minutes = min(svc.settings.login_lockout_minutes * (2**user.lockout_count), 24 * 60)
            user.locked_until = utcnow() + timedelta(minutes=minutes)
            user.lockout_count += 1
            user.failed_logins = 0


async def _record_mfa_failure(svc: Services, token_hash: bytes) -> None:
    async with svc.db.session("app") as s2:
        row = (
            await s2.execute(select(UserSession).where(UserSession.token_hash == token_hash).with_for_update())
        ).scalar_one_or_none()
        if row is not None:
            row.mfa_attempts += 1
            if row.mfa_attempts >= 5:
                row.revoked_at = utcnow()
                row.revoke_reason = "mfa_attempts"


def _session_out(svc_terms: str, resolved: sessions.ResolvedSession, csrf_token: str) -> SessionOut:
    user = resolved.user
    active = resolved.session.state == SessionState.ACTIVE.value
    return SessionOut(
        state=resolved.session.state,  # type: ignore[arg-type,unused-ignore]
        user=UserOut.of(user) if active else None,
        csrf_token=csrf_token,
        idle_expires_in=resolved.idle_expires_in,
        absolute_expires_in=resolved.absolute_expires_in,
        terms_current=user.terms_version_accepted == svc_terms,
        current_terms_version=svc_terms,
    )


@router.get("/csrf", openapi_extra={"x-public": True})
async def anonymous_csrf_token(response: Response, svc: ServicesDep) -> dict[str, str]:
    """Issue a server-signed CSRF token for unauthenticated forms (login, access request, abuse report).

    Fetch a new token for each submission. It is paired with its own HttpOnly cookie, so it neither replaces nor
    depends on the CSRF token of a session the browser may still hold.
    """
    from angel_engine.api.deps import form_csrf_cookie_name

    token = csrf.issue(svc.keys.secret("csrf"))
    response.set_cookie(
        form_csrf_cookie_name(svc.settings),
        token,
        max_age=3600,
        path="/",
        secure=svc.settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )
    return {"csrf_token": token}


@router.post("/login", dependencies=[Depends(anonymous_csrf)], openapi_extra={"x-public": True})
async def login(body: LoginIn, request: Request, response: Response, db: DbSession, svc: ServicesDep) -> SessionOut:
    email_key = hashlib.sha256(body.email.casefold().encode()).hexdigest()[:24]
    ipp = ip_pseudonym(request)
    await enforce_rate_limit(svc, f"login:ip:{ipp}", LOGIN_IP)
    await enforce_rate_limit(svc, f"login:acct:{email_key}", LOGIN_ACCOUNT)
    user = (await db.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    now = utcnow()
    ok, rehash = await passwords.verify_password(user.password_hash if user else None, body.password)
    rid = request_id(request)
    if user is not None and user.locked_until is not None and user.locked_until > now:
        await audit_separately(
            svc,
            AuditEvent(
                action="auth.login",
                outcome="denied",
                actor_id=user.id,
                details={"reason": "locked"},
                actor_type="anonymous",
                ip_pseudonym=ipp,
                request_id=rid,
            ),
        )
        raise Unauthenticated("Too many failed attempts. Try again later.", code="account_locked")
    if user is None or not ok:
        if user is not None:
            await _record_login_failure(svc, user.id)
        await audit_separately(
            svc,
            AuditEvent(
                action="auth.login",
                outcome="failure",
                actor_id=user.id if user else None,
                details={"reason": "bad_credentials"},
                actor_type="anonymous",
                ip_pseudonym=ipp,
                request_id=rid,
            ),
        )
        raise Unauthenticated(GENERIC_LOGIN_ERROR, code="invalid_credentials")
    if user.status == UserStatus.PENDING.value:
        raise Forbidden("Your access request is awaiting administrator approval.", code="account_pending")
    if user.status != UserStatus.ACTIVE.value:
        raise Forbidden("This account is disabled.", code="account_disabled")
    if user.refusal_flag_level >= 3:
        raise Forbidden("This account is suspended pending review.", code="account_suspended")

    user.failed_logins = 0
    user.locked_until = None
    if rehash:
        user.password_hash = rehash
    if user.mfa_enabled:
        state = SessionState.MFA_PENDING
    elif svc.settings.mfa_required:
        state = SessionState.MFA_ENROLL
    else:
        state = SessionState.ACTIVE
    token, row = await sessions.create_session(
        db, svc.settings, user, state=state, ip_pseudonym=ipp, user_agent=request.headers.get("user-agent")
    )
    if state == SessionState.ACTIVE:
        user.last_login_at = now
        row.reauth_at = now
    csrf_token = csrf.issue(row.csrf_key)
    set_session_cookies(response, svc.settings, token, csrf_token)
    from angel_engine.audit.chain import record

    record(
        db,
        AuditEvent(
            action="auth.login",
            outcome="success",
            actor_id=user.id,
            actor_role=user.role,
            actor_type="user",
            session_pseudonym=str(row.public_id),
            ip_pseudonym=ipp,
            request_id=request_id(request),
            details={"next_state": state.value},
        ),
    )
    return _session_out(current_versions()["terms"], sessions.ResolvedSession(row, user), csrf_token)


async def _complete_login(
    request: Request, response: Response, db: DbSession, resolved: sessions.ResolvedSession, action: str
) -> SessionOut:
    svc = get_services(request)
    token = await sessions.promote(db, svc.settings, resolved.session, SessionState.ACTIVE)
    resolved.user.last_login_at = utcnow()
    csrf_token = csrf.issue(resolved.session.csrf_key)
    set_session_cookies(response, svc.settings, token, csrf_token)
    from angel_engine.audit.chain import record

    record(
        db,
        AuditEvent(
            action=action,
            actor_id=resolved.user.id,
            actor_role=resolved.user.role,
            session_pseudonym=str(resolved.session.public_id),
            ip_pseudonym=ip_pseudonym(request),
            request_id=request_id(request),
        ),
    )
    return _session_out(current_versions()["terms"], resolved, csrf_token)


@router.post("/mfa/verify")
async def verify_mfa(
    body: CodeIn, request: Request, response: Response, db: DbSession, resolved: PendingSession
) -> SessionOut:
    svc = get_services(request)
    if resolved.session.state != SessionState.MFA_PENDING.value:
        raise BadRequest("No multi-factor verification is pending.", code="mfa_not_pending")
    await enforce_rate_limit(svc, f"mfa:{resolved.user.id}", MFA_ACCOUNT)
    user = resolved.user
    cipher = await svc.vault.system_cipher(db, "system_secrets")
    secret = (
        cipher.open(user.mfa_secret, table="users", column="mfa_secret", row_id=user.id) if user.mfa_secret else None
    )
    code = body.code.strip()
    accepted = False
    if secret and len("".join(c for c in code if c.isdigit())) == 6 and "-" not in code:
        step = mfa.verify_totp(secret, code, last_timestep=user.mfa_last_timestep)
        if step is not None:
            result = await db.execute(
                update(User)
                .where(User.id == user.id, (User.mfa_last_timestep.is_(None)) | (User.mfa_last_timestep < step))
                .values(mfa_last_timestep=step)
            )
            accepted = bool(getattr(result, "rowcount", 0))
    else:
        mac = mfa.recovery_code_mac(svc.keys.secret("recovery_pepper"), code)
        rc = (
            await db.execute(
                select(RecoveryCode).where(
                    RecoveryCode.user_id == user.id, RecoveryCode.code_mac == mac, RecoveryCode.used_at.is_(None)
                )
            )
        ).scalar_one_or_none()
        if rc is not None:
            rc.used_at = utcnow()
            accepted = True
    if not accepted:
        await _record_mfa_failure(svc, resolved.session.token_hash)
        await audit_separately(
            svc,
            AuditEvent(
                action="auth.mfa",
                outcome="failure",
                actor_id=user.id,
                ip_pseudonym=ip_pseudonym(request),
                request_id=request_id(request),
            ),
        )
        raise Unauthenticated("The code is not valid.", code="invalid_mfa_code")
    return await _complete_login(request, response, db, resolved, "auth.mfa_verified")


@router.post("/mfa/enroll")
async def start_enrollment(request: Request, db: DbSession, resolved: PendingSession) -> EnrollmentOut:
    svc = get_services(request)
    user = resolved.user
    if resolved.session.state != SessionState.MFA_ENROLL.value and user.mfa_enabled:
        raise BadRequest("Multi-factor authentication is already enabled.", code="mfa_already_enabled")
    secret = mfa.new_secret()
    cipher = await svc.vault.system_cipher(db, "system_secrets")
    user.mfa_secret = cipher.seal(secret, table="users", column="mfa_secret", row_id=user.id)
    user.mfa_enabled = False
    user.mfa_last_timestep = None
    uri = mfa.provisioning_uri(secret, user.email)
    return EnrollmentOut(secret=secret, otpauth_uri=uri, qr_data_uri=mfa.qr_png_data_uri(uri))


class EnrollmentDone(SessionOut):
    recovery_codes: list[str]


@router.post("/mfa/enroll/confirm")
async def confirm_enrollment(
    body: CodeIn, request: Request, response: Response, db: DbSession, resolved: PendingSession
) -> EnrollmentDone:
    svc = get_services(request)
    user = resolved.user
    await enforce_rate_limit(svc, f"mfa:{user.id}", MFA_ACCOUNT)
    if user.mfa_secret is None or user.mfa_enabled:
        raise BadRequest("Start enrollment first.", code="mfa_enrollment_missing")
    cipher = await svc.vault.system_cipher(db, "system_secrets")
    secret = cipher.open(user.mfa_secret, table="users", column="mfa_secret", row_id=user.id)
    step = mfa.verify_totp(secret, body.code, last_timestep=None)
    if step is None:
        raise ValidationProblem("The code is not valid. Check your authenticator app's clock.", code="invalid_mfa_code")
    user.mfa_enabled = True
    user.mfa_last_timestep = step
    codes = await _replace_recovery_codes(db, svc.keys.secret("recovery_pepper"), user)
    if resolved.session.state == SessionState.ACTIVE.value:
        token = await sessions.rotate(db, resolved.session)
        csrf_token = csrf.issue(resolved.session.csrf_key)
        set_session_cookies(response, svc.settings, token, csrf_token)
        out = _session_out(current_versions()["terms"], resolved, csrf_token)
    else:
        out = await _complete_login(request, response, db, resolved, "auth.mfa_enrolled")
    return EnrollmentDone(**out.model_dump(), recovery_codes=codes)


async def _replace_recovery_codes(db: DbSession, pepper: bytes, user: User) -> list[str]:
    from sqlalchemy import delete

    await db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    codes = mfa.new_recovery_codes()
    for code in codes:
        db.add(RecoveryCode(user_id=user.id, code_mac=mfa.recovery_code_mac(pepper, code)))
    await db.flush()
    return codes


@router.post("/mfa/recovery-codes")
async def regenerate_recovery_codes(principal: CurrentPrincipal, db: DbSession) -> RecoveryCodesOut:
    from angel_engine.api.deps import require_recent_reauth

    require_recent_reauth(principal)
    codes = await _replace_recovery_codes(db, principal.services.keys.secret("recovery_pepper"), principal.user)
    principal.audit(db, "auth.recovery_codes_regenerated")
    return RecoveryCodesOut(recovery_codes=codes)


@router.get("/session")
async def get_session(request: Request, response: Response, resolved: PendingSession) -> SessionOut:
    from angel_engine.api.deps import cookie_names, set_csrf_cookie

    svc = get_services(request)
    _, csrf_name = cookie_names(svc.settings)
    token = request.cookies.get(csrf_name)
    if not token or not csrf.valid(resolved.session.csrf_key, token):
        # A missing or foreign CSRF cookie would make every write fail; replace it.
        token = csrf.issue(resolved.session.csrf_key)
        set_csrf_cookie(response, svc.settings, token)
    return _session_out(current_versions()["terms"], resolved, token)


@router.post("/reauth")
async def reauthenticate(
    body: PasswordIn, request: Request, db: DbSession, principal: CurrentPrincipal
) -> dict[str, int]:
    svc = get_services(request)
    await enforce_rate_limit(svc, f"reauth:{principal.user_id}", MFA_ACCOUNT)
    ok, _ = await passwords.verify_password(principal.user.password_hash, body.password)
    if not ok:
        await audit_separately(svc, principal.event("auth.reauth", outcome="failure"))
        raise Unauthenticated("The password is not correct.", code="invalid_credentials")
    principal.session.reauth_at = utcnow()
    principal.audit(db, "auth.reauth")
    return {"reauth_valid_for": svc.settings.reauth_window_minutes * 60}


@router.put("/password")
async def change_password(
    body: ChangePasswordIn, request: Request, response: Response, db: DbSession, principal: CurrentPrincipal
) -> dict[str, str]:
    svc = get_services(request)
    user = principal.user
    # Same budget as re-authentication: a stolen session must not become a password-guessing oracle.
    await enforce_rate_limit(svc, f"reauth:{principal.user_id}", MFA_ACCOUNT)
    ok, _ = await passwords.verify_password(user.password_hash, body.current_password)
    if not ok:
        await audit_separately(svc, principal.event("auth.password_change", outcome="failure"))
        raise Unauthenticated("The current password is not correct.", code="invalid_credentials")
    problems = passwords.policy_violations(
        body.new_password, context_words=(user.email.split("@")[0], user.display_name, "angel engine")
    )
    if problems:
        raise ValidationProblem(" ".join(problems), code="weak_password")
    user.password_hash = await passwords.hash_password(body.new_password)
    user.password_changed_at = utcnow()
    await sessions.revoke_all(db, user.id, reason="password_changed", except_hash=principal.session.token_hash)
    token = await sessions.rotate(db, principal.session)
    set_session_cookies(response, svc.settings, token, csrf.issue(principal.session.csrf_key))
    principal.audit(db, "auth.password_changed")
    return {"status": "changed"}


@router.post("/logout")
async def logout(request: Request, response: Response, db: DbSession, resolved: PendingSession) -> dict[str, str]:
    svc = get_services(request)
    await sessions.revoke(db, resolved.session, "logout")
    clear_session_cookies(response, svc.settings)
    from angel_engine.audit.chain import record

    record(
        db,
        AuditEvent(
            action="auth.logout",
            actor_id=resolved.user.id,
            actor_role=resolved.user.role,
            session_pseudonym=str(resolved.session.public_id),
            ip_pseudonym=ip_pseudonym(request),
            request_id=request_id(request),
        ),
    )
    return {"status": "signed_out"}


@router.post(
    "/registration-requests", status_code=202, dependencies=[Depends(anonymous_csrf)], openapi_extra={"x-public": True}
)
async def request_access(body: RegistrationIn, request: Request, db: DbSession, svc: ServicesDep) -> dict[str, str]:
    """Request an account. Every request is reviewed by an administrator before access is granted."""
    accepted = {
        "status": "received",
        "detail": (
            "If the request is valid, an administrator will review it. You will be able to sign in once approved."
        ),
    }
    await enforce_rate_limit(svc, f"register:{ip_pseudonym(request)}", REGISTRATION_IP)
    if body.website:  # honeypot
        return accepted
    if not svc.settings.registration_open:
        raise Forbidden("Access requests are currently closed.", code="registration_closed")
    if not (body.accept_terms and body.attest_lawful_use and body.attest_no_misuse):
        raise ValidationProblem(
            "You must accept the Terms of Use and the Acceptable Use Policy.", code="attestation_required"
        )
    problems = passwords.policy_violations(
        body.password, context_words=(body.email.split("@")[0], body.display_name, "angel engine")
    )
    if problems:
        raise ValidationProblem(" ".join(problems), code="weak_password")
    exists = (await db.execute(select(User.id).where(User.email == body.email))).first()
    if exists is not None:
        # Do not reveal whether an account exists, not even through timing: hash as a new request would.
        await passwords.hash_password(body.password)
        return accepted
    versions = current_versions()
    user = User(
        email=body.email,
        display_name=body.display_name.strip(),
        password_hash=await passwords.hash_password(body.password),
        role=Role.INVESTIGATOR.value,
        status=UserStatus.PENDING.value,
        organization_unit=body.organization_unit,
        terms_version_accepted=versions["terms"],
        terms_accepted_at=utcnow(),
    )
    db.add(user)
    await db.flush()
    cipher = await svc.vault.system_cipher(db, "system_secrets")
    user.access_justification = cipher.seal(
        body.justification, table="users", column="access_justification", row_id=user.id
    )
    db.add(
        Attestation(
            user_id=user.id,
            kind="account",
            document_versions=versions,
            statements=["accept_terms", "attest_lawful_use", "attest_no_misuse"],
            ip_pseudonym=ip_pseudonym(request),
        )
    )
    from angel_engine.audit.chain import record

    record(
        db,
        AuditEvent(
            action="auth.registration_requested",
            actor_id=user.id,
            actor_type="anonymous",
            ip_pseudonym=ip_pseudonym(request),
            request_id=request_id(request),
        ),
    )
    return accepted
