"""Role-based access control with per-investigation membership and separation of duties.

Effective permission for investigation content = role grant ∧ membership grant (or an unexpired,
read-only oversight grant). Admins administer the platform but cannot read investigation content;
auditors see audit metadata only.
"""

from __future__ import annotations

from enum import StrEnum

from angel_engine.core.enums import MemberRole, Role


class Perm(StrEnum):
    # platform
    USER_MANAGE = "user:manage"
    SETTINGS_MANAGE = "settings:manage"
    RETENTION_MANAGE = "retention:manage"
    LEGAL_HOLD_SET = "legal_hold:set"
    JOBS_MANAGE = "jobs:manage"
    AUDIT_READ = "audit:read"
    AUDIT_VERIFY = "audit:verify"
    ABUSE_TRIAGE = "abuse:triage"
    POLICY_REVIEW = "policy:review"
    INVESTIGATION_REVIEW = "investigation:review"
    INVESTIGATION_OVERSIGHT = "investigation:oversight"
    INVESTIGATION_CREATE = "investigation:create"
    # investigation-scoped
    CONTENT_READ = "content:read"
    CONTENT_WRITE = "content:write"
    FINDING_VERIFY = "finding:verify"
    REPORT_EXPORT = "report:export"
    MEMBERS_MANAGE = "members:manage"
    INVESTIGATION_MANAGE = "investigation:manage"  # close/reopen/archive/delete/retention (owner)


ROLE_GRANTS: dict[Role, frozenset[Perm]] = {
    Role.ADMIN: frozenset(
        {
            Perm.USER_MANAGE,
            Perm.SETTINGS_MANAGE,
            Perm.RETENTION_MANAGE,
            Perm.LEGAL_HOLD_SET,
            Perm.JOBS_MANAGE,
            Perm.AUDIT_READ,
            Perm.AUDIT_VERIFY,
            Perm.ABUSE_TRIAGE,
        }
    ),
    Role.SUPERVISOR: frozenset(
        {
            Perm.INVESTIGATION_CREATE,
            Perm.INVESTIGATION_REVIEW,
            Perm.POLICY_REVIEW,
            Perm.INVESTIGATION_OVERSIGHT,
            Perm.ABUSE_TRIAGE,
            Perm.CONTENT_READ,
            Perm.CONTENT_WRITE,
            Perm.FINDING_VERIFY,
            Perm.REPORT_EXPORT,
            Perm.MEMBERS_MANAGE,
            Perm.INVESTIGATION_MANAGE,
        }
    ),
    Role.INVESTIGATOR: frozenset(
        {
            Perm.INVESTIGATION_CREATE,
            Perm.CONTENT_READ,
            Perm.CONTENT_WRITE,
            Perm.FINDING_VERIFY,
            Perm.REPORT_EXPORT,
            Perm.MEMBERS_MANAGE,
            Perm.INVESTIGATION_MANAGE,
        }
    ),
    Role.VIEWER: frozenset({Perm.CONTENT_READ}),
    Role.AUDITOR: frozenset({Perm.AUDIT_READ, Perm.AUDIT_VERIFY}),
}

MEMBERSHIP_GRANTS: dict[MemberRole, frozenset[Perm]] = {
    MemberRole.OWNER: frozenset(
        {
            Perm.CONTENT_READ,
            Perm.CONTENT_WRITE,
            Perm.FINDING_VERIFY,
            Perm.REPORT_EXPORT,
            Perm.MEMBERS_MANAGE,
            Perm.INVESTIGATION_MANAGE,
        }
    ),
    MemberRole.EDITOR: frozenset({Perm.CONTENT_READ, Perm.CONTENT_WRITE, Perm.FINDING_VERIFY, Perm.REPORT_EXPORT}),
    MemberRole.VIEWER: frozenset({Perm.CONTENT_READ}),
}

INVESTIGATION_SCOPED = frozenset(
    {
        Perm.CONTENT_READ,
        Perm.CONTENT_WRITE,
        Perm.FINDING_VERIFY,
        Perm.REPORT_EXPORT,
        Perm.MEMBERS_MANAGE,
        Perm.INVESTIGATION_MANAGE,
    }
)


def role_allows(role: str, perm: Perm) -> bool:
    try:
        return perm in ROLE_GRANTS[Role(role)]
    except ValueError:
        return False


def authorize(role: str, membership: str | None, perm: Perm, *, oversight: bool = False) -> bool:
    """Decide an investigation-scoped permission."""
    if not role_allows(role, perm):
        return False
    if perm not in INVESTIGATION_SCOPED:
        return True
    if membership is not None:
        try:
            return perm in MEMBERSHIP_GRANTS[MemberRole(membership)]
        except ValueError:
            return False
    return oversight and perm == Perm.CONTENT_READ
