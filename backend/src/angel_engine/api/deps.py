"""Shared FastAPI dependencies: transactions, sessions, CSRF, rate limits and investigation scoping."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Callable, Coroutine
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastapi import Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.app_state import Services
from angel_engine.audit.chain import AuditEvent, append_now, discard_pending, flush_pending, pseudonymize_ip
from angel_engine.audit.chain import record as audit_record
from angel_engine.auth import csrf
from angel_engine.auth.sessions import ResolvedSession, recently_reauthenticated, resolve
from angel_engine.authz.permissions import INVESTIGATION_SCOPED, Perm, authorize, role_allows
from angel_engine.config import Settings
from angel_engine.core.clock import utcnow
from angel_engine.core.enums import InvestigationStatus, SessionState
from angel_engine.core.problems import (
    CsrfFailed,
    Forbidden,
    MfaRequired,
    NotFound,
    RateLimited,
    ReauthRequired,
    ServiceUnavailable,
    Unauthenticated,
)
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.db.models import Investigation, InvestigationMember, OversightGrant, User, UserSession
from angel_engine.db.session import set_investigation_scope
from angel_engine.infra.ratelimit.gcra import READS_USER, WRITES_USER, Limit, RateLimiterUnavailable

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def get_services(request: Request) -> Services:
    return request.app.state.services  # type: ignore[no-any-return]


ServicesDep = Annotated[Services, Depends(get_services)]


def get_settings_dep(request: Request) -> Settings:
    return get_services(request).settings


def cookie_names(settings: Settings) -> tuple[str, str]:
    prefix = "__Host-" if settings.cookie_secure else ""
    return f"{prefix}ae_sid", f"{prefix}ae_csrf"


def set_session_cookies(response: Response, settings: Settings, token: str, csrf_token: str) -> None:
    sid_name, csrf_name = cookie_names(settings)
    max_age = settings.session_absolute_hours * 3600
    response.set_cookie(
        sid_name, token, max_age=max_age, path="/", secure=settings.cookie_secure, httponly=True, samesite="strict"
    )
    response.set_cookie(
        csrf_name,
        csrf_token,
        max_age=max_age,
        path="/",
        secure=settings.cookie_secure,
        httponly=False,
        samesite="strict",
    )


def clear_session_cookies(response: Response, settings: Settings) -> None:
    sid_name, csrf_name = cookie_names(settings)
    for name in (sid_name, csrf_name):
        response.delete_cookie(
            name, path="/", secure=settings.cookie_secure, httponly=name == sid_name, samesite="strict"
        )


# --------------------------------------------------------------------------------------------------
# Transactions
# --------------------------------------------------------------------------------------------------
async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    """Unit of work: one transaction per request; buffered audit events are chained right before commit."""
    svc = get_services(request)
    async with svc.db.sessionmaker("app")() as session, session.begin():
        try:
            yield session
        except BaseException:
            discard_pending(session)
            raise
        await flush_pending(session, svc.audit_key)


DbSession = Annotated[AsyncSession, Depends(get_db, scope="function")]


async def audit_separately(svc: Services, event: AuditEvent) -> None:
    """Write an audit event in its own transaction (survives the request's rollback)."""
    async with svc.db.session("app") as session:
        await append_now(session, svc.audit_key, [event])


# --------------------------------------------------------------------------------------------------
# Request context
# --------------------------------------------------------------------------------------------------
def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def ip_pseudonym(request: Request) -> str | None:
    svc = get_services(request)
    return pseudonymize_ip(client_ip(request), svc.keys.ip_key)


async def enforce_rate_limit(svc: Services, key: str, limit: Limit) -> None:
    if not svc.settings.rate_limit_enabled:
        return
    try:
        allowed, retry_after = await svc.limiter.hit(key, limit)
    except RateLimiterUnavailable as exc:
        if limit.fail_closed:
            raise ServiceUnavailable("Rate limiting is temporarily unavailable; please retry shortly.") from exc
        return
    if not allowed:
        raise RateLimited(retry_after)


@dataclass(slots=True)
class Principal:
    user: User
    session: UserSession
    ip_pseudonym: str | None
    request_id: str | None
    services: Services = field(repr=False)

    @property
    def user_id(self) -> uuid.UUID:
        return self.user.id

    @property
    def role(self) -> str:
        return self.user.role

    @property
    def session_pseudonym(self) -> str:
        return str(self.session.public_id)

    def event(self, action: str, **kwargs: Any) -> AuditEvent:
        return AuditEvent(
            action=action,
            actor_id=self.user.id,
            actor_role=self.user.role,
            actor_type="user",
            session_pseudonym=self.session_pseudonym,
            ip_pseudonym=self.ip_pseudonym,
            request_id=self.request_id,
            **kwargs,
        )

    def audit(self, db: AsyncSession, action: str, **kwargs: Any) -> None:
        audit_record(db, self.event(action, **kwargs))


def _verify_csrf(request: Request, settings: Settings, key: bytes) -> None:
    _, csrf_name = cookie_names(settings)
    header = request.headers.get("x-csrf-token")
    cookie = request.cookies.get(csrf_name)
    if not header or header != cookie or not csrf.valid(key, header):
        raise CsrfFailed(code="csrf_token_invalid")


async def _resolve(request: Request, db: AsyncSession) -> ResolvedSession | None:
    svc = get_services(request)
    sid_name, _ = cookie_names(svc.settings)
    background = request.headers.get("x-angel-activity") == "background"
    return await resolve(db, svc.settings, request.cookies.get(sid_name), background=background)


def _expiry_headers(response: Response, resolved: ResolvedSession) -> None:
    response.headers["X-Session-Idle-Expires-In"] = str(resolved.idle_expires_in)
    response.headers["X-Session-Absolute-Expires-In"] = str(resolved.absolute_expires_in)


async def current_principal(request: Request, response: Response, db: DbSession) -> Principal:
    svc = get_services(request)
    resolved = await _resolve(request, db)
    if resolved is None:
        raise Unauthenticated(code="session_expired" if request.cookies.get(cookie_names(svc.settings)[0]) else None)
    if resolved.session.state != SessionState.ACTIVE.value:
        raise MfaRequired(code=resolved.session.state)
    if request.method not in SAFE_METHODS:
        _verify_csrf(request, svc.settings, resolved.session.csrf_key)
    _expiry_headers(response, resolved)
    limit = READS_USER if request.method in SAFE_METHODS else WRITES_USER
    await enforce_rate_limit(svc, f"user:{resolved.user.id}:{'r' if request.method in SAFE_METHODS else 'w'}", limit)
    return Principal(resolved.user, resolved.session, ip_pseudonym(request), request_id(request), svc)


CurrentPrincipal = Annotated[Principal, Depends(current_principal)]


async def pending_session(request: Request, response: Response, db: DbSession) -> ResolvedSession:
    """A session in any state (used by MFA verification/enrollment and the session endpoint)."""
    svc = get_services(request)
    resolved = await _resolve(request, db)
    if resolved is None:
        raise Unauthenticated(code="session_expired")
    if request.method not in SAFE_METHODS:
        _verify_csrf(request, svc.settings, resolved.session.csrf_key)
    _expiry_headers(response, resolved)
    return resolved


PendingSession = Annotated[ResolvedSession, Depends(pending_session)]


def anonymous_csrf(request: Request) -> None:
    """CSRF check for unauthenticated forms (token signed with the server CSRF key)."""
    svc = get_services(request)
    _verify_csrf(request, svc.settings, svc.keys.secret("csrf"))


def require(perm: Perm) -> Callable[[Principal], Coroutine[Any, Any, Principal]]:
    async def dependency(principal: CurrentPrincipal) -> Principal:
        if not role_allows(principal.role, perm):
            raise Forbidden(code="missing_permission", permission=perm.value)
        return principal

    dependency.__name__ = f"require_{perm.value.replace(':', '_')}"
    return dependency


def require_recent_reauth(principal: Principal) -> None:
    if not recently_reauthenticated(principal.session, principal.services.settings):
        raise ReauthRequired()


# --------------------------------------------------------------------------------------------------
# Investigation scope
# --------------------------------------------------------------------------------------------------
STATE_RULES: dict[Perm, frozenset[str]] = {
    Perm.CONTENT_READ: frozenset(s.value for s in InvestigationStatus if s != InvestigationStatus.DELETED),
    Perm.CONTENT_WRITE: frozenset({InvestigationStatus.ACTIVE.value}),
    Perm.FINDING_VERIFY: frozenset({InvestigationStatus.ACTIVE.value}),
    Perm.REPORT_EXPORT: frozenset(
        {InvestigationStatus.ACTIVE.value, InvestigationStatus.CLOSED.value, InvestigationStatus.ARCHIVED.value}
    ),
    Perm.MEMBERS_MANAGE: frozenset(
        {
            InvestigationStatus.DRAFT.value,
            InvestigationStatus.PENDING_REVIEW.value,
            InvestigationStatus.ACTIVE.value,
            InvestigationStatus.SUSPENDED.value,
            InvestigationStatus.CLOSED.value,
        }
    ),
    Perm.INVESTIGATION_MANAGE: frozenset(s.value for s in InvestigationStatus if s != InvestigationStatus.DELETED),
}


def effective_permissions(role: str, membership: str | None, status: str, *, oversight: bool = False) -> list[str]:
    """Investigation-scoped permissions the user can exercise right now (role ∧ membership ∧ state)."""
    return sorted(
        p.value
        for p in INVESTIGATION_SCOPED
        if authorize(role, membership, p, oversight=oversight) and status in STATE_RULES.get(p, frozenset({status}))
    )


@dataclass(slots=True)
class InvCtx:
    investigation: Investigation
    membership: str | None
    principal: Principal
    db: AsyncSession
    oversight: bool = False
    _cipher: FieldCipher | None = None

    @property
    def id(self) -> uuid.UUID:
        return self.investigation.id

    async def cipher(self) -> FieldCipher:
        if self._cipher is None:
            self._cipher = await self.principal.services.vault.investigation_cipher(self.db, self.investigation.id)
        return self._cipher

    def audit(self, action: str, **kwargs: Any) -> None:
        kwargs.setdefault("investigation_id", self.investigation.id)
        self.principal.audit(self.db, action, **kwargs)


async def load_investigation_access(
    db: AsyncSession, investigation_id: uuid.UUID, user_id: uuid.UUID
) -> tuple[Investigation | None, str | None, bool]:
    inv = await db.get(Investigation, investigation_id)
    if inv is None:
        return None, None, False
    membership = (
        await db.execute(
            select(InvestigationMember.role).where(
                InvestigationMember.investigation_id == investigation_id, InvestigationMember.user_id == user_id
            )
        )
    ).scalar_one_or_none()
    oversight = False
    if membership is None:
        oversight = (
            await db.execute(
                select(OversightGrant.id)
                .where(
                    OversightGrant.investigation_id == investigation_id,
                    OversightGrant.grantee_id == user_id,
                    OversightGrant.revoked_at.is_(None),
                    OversightGrant.expires_at > utcnow(),
                )
                .limit(1)
            )
        ).first() is not None
    return inv, membership, oversight


def investigation_scope(perm: Perm) -> Callable[..., Coroutine[Any, Any, InvCtx]]:
    async def dependency(investigation_id: uuid.UUID, principal: CurrentPrincipal, db: DbSession) -> InvCtx:
        svc = principal.services
        inv, membership, oversight = await load_investigation_access(db, investigation_id, principal.user_id)
        if inv is None or inv.status == InvestigationStatus.DELETED.value or (membership is None and not oversight):
            await audit_separately(
                svc,
                principal.event(
                    "investigation.access_denied",
                    outcome="denied",
                    # Recorded against the investigation (when it exists) so its owners can see attempts.
                    investigation_id=inv.id if inv is not None else None,
                    target_type="investigation",
                    target_id=str(investigation_id),
                    details={"permission": perm.value},
                ),
            )
            raise NotFound()
        if not authorize(principal.role, membership, perm, oversight=oversight):
            raise Forbidden(code="missing_permission", permission=perm.value)
        allowed_states = STATE_RULES.get(perm)
        if allowed_states is not None and inv.status not in allowed_states:
            from angel_engine.core.problems import ConflictState

            raise ConflictState(
                f"This action is not available while the investigation is {inv.status.replace('_', ' ')}.",
                code="investigation_state",
                investigation_status=inv.status,
            )
        await set_investigation_scope(db, [inv.id])
        if oversight and membership is None:
            principal.audit(db, "investigation.oversight_read", investigation_id=inv.id)
        return InvCtx(inv, membership, principal, db, oversight)

    dependency.__name__ = f"investigation_scope_{perm.value.replace(':', '_')}"
    return dependency
