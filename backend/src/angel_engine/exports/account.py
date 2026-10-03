"""Export my data: an encrypted archive of what Angel Engine holds about an account.

The archive contains the account profile, sessions (browser family and times only), attestations, the
acceptable-use decisions about the person's requests (metadata, not the screened text), investigation memberships
and the person's own audit-log entries. Investigation content (evidence, notes, reports) belongs to the
investigation, not to the account, and is exported through reports instead. The archive is encrypted at rest, can
be downloaded once within the export window and needs a recent password confirmation.
"""

from __future__ import annotations

import asyncio
import io
import json
import uuid
import zipfile
from datetime import datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select

from angel_engine.audit.chain import AuditEvent, append_now
from angel_engine.core.clock import utcnow
from angel_engine.core.enums import JobQueue
from angel_engine.core.ids import new_id
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.db.models import (
    Attestation,
    AuditLog,
    DataExport,
    Investigation,
    InvestigationMember,
    PolicyDecision,
    User,
    UserSession,
)
from angel_engine.jobs.queue import PermanentJobError, enqueue
from angel_engine.jobs.registry import JobContext, handler

log = structlog.get_logger(__name__)

AUDIT_LIMIT = 50_000
README = """Angel Engine — export of your account data
==========================================

Files
-----
account.json            Your profile, role, status and the policy versions you accepted.
sessions.json           Sign-in sessions: browser family and times (IP addresses are never stored).
attestations.json       The statements you attested and the document versions they referred to.
policy_decisions.json   Acceptable-use decisions about your requests (decision, categories, explanation, dates).
investigations.json     Investigations you are or were a member of, with your role.
audit_events.json       Audit-log entries for actions you performed (who/what/when; never content).

Not included
------------
- Your password hash, two-factor secret and recovery codes (security secrets).
- The text of screened requests: it is kept encrypted for abuse review for a limited time and may contain other
  people's personal data.
- Investigation content (evidence, notes, findings, reports): it belongs to the investigation. Members can export
  cited reports from the investigation's Reports page.

Questions or corrections: use the Privacy & Data Controls page or contact your administrator.
"""


def account_export_key(user_id: uuid.UUID, export_id: uuid.UUID) -> str:
    return f"exports/{user_id}/{export_id}"


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


async def collect(db: Any, user_id: uuid.UUID) -> dict[str, Any]:
    user = await db.get(User, user_id)
    if user is None:
        raise PermanentJobError("account missing")
    sessions = (await db.execute(select(UserSession).where(UserSession.user_id == user_id))).scalars().all()
    attestations = (
        (await db.execute(select(Attestation).where(Attestation.user_id == user_id).order_by(Attestation.accepted_at)))
        .scalars()
        .all()
    )
    decisions = (
        (
            await db.execute(
                select(PolicyDecision).where(PolicyDecision.user_id == user_id).order_by(PolicyDecision.created_at)
            )
        )
        .scalars()
        .all()
    )
    memberships = (
        await db.execute(
            select(InvestigationMember, Investigation)
            .join(Investigation, Investigation.id == InvestigationMember.investigation_id)
            .where(InvestigationMember.user_id == user_id)
            .order_by(InvestigationMember.created_at)
        )
    ).all()
    audit = (
        (
            await db.execute(
                select(AuditLog).where(AuditLog.actor_id == user_id).order_by(AuditLog.seq).limit(AUDIT_LIMIT)
            )
        )
        .scalars()
        .all()
    )
    return {
        "account.json": {
            "id": str(user.id),
            "email": user.email,
            "display_name": user.display_name,
            "organization_unit": user.organization_unit,
            "role": user.role,
            "status": user.status,
            "mfa_enabled": user.mfa_enabled,
            "created_at": _iso(getattr(user, "created_at", None)),
            "approved_at": _iso(user.approved_at),
            "terms_version_accepted": user.terms_version_accepted,
            "terms_accepted_at": _iso(user.terms_accepted_at),
            "preferences": dict(getattr(user, "preferences", None) or {}),
        },
        "sessions.json": [
            {
                "id": str(s.public_id),
                "state": s.state,
                "browser": getattr(s, "ua_family", None),
                "created_at": _iso(s.created_at),
                "last_seen_at": _iso(s.last_seen_at),
                "absolute_expires_at": _iso(s.absolute_expires_at),
                "revoked_at": _iso(getattr(s, "revoked_at", None)),
            }
            for s in sessions
        ],
        "attestations.json": [
            {
                "kind": a.kind,
                "investigation_id": str(a.investigation_id) if a.investigation_id else None,
                "document_versions": a.document_versions,
                "statements": list(a.statements),
                "accepted_at": _iso(a.accepted_at),
            }
            for a in attestations
        ],
        "policy_decisions.json": [
            {
                "id": str(d.id),
                "created_at": _iso(getattr(d, "created_at", None)),
                "surface": d.surface,
                "decision": d.decision,
                "categories": list(d.categories),
                "explanation": d.rationale,
                "review_outcome": d.review_outcome,
                "investigation_id": str(d.investigation_id) if d.investigation_id else None,
            }
            for d in decisions
        ],
        "investigations.json": [
            {
                "investigation_id": str(inv.id),
                "reference": inv.public_ref,
                "title": inv.title if inv.status != "deleted" else None,
                "status": inv.status,
                "your_role": member.role,
                "member_since": _iso(member.created_at),
            }
            for member, inv in memberships
        ],
        "audit_events.json": [
            {
                "seq": e.seq,
                "occurred_at": _iso(e.occurred_at),
                "action": e.action,
                "outcome": e.outcome,
                "investigation_id": str(e.investigation_id) if e.investigation_id else None,
                "target_type": e.target_type,
            }
            for e in audit
        ],
    }


def build_archive(files: dict[str, Any], generated_at: datetime) -> bytes:
    """A deterministic ZIP (fixed member order and timestamps) of pretty-printed JSON plus a README."""
    stamp = generated_at.timetuple()[:6]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        members = {
            "README.txt": README,
            **{name: json.dumps(data, indent=2, ensure_ascii=False) for name, data in files.items()},
        }
        for name in sorted(members):
            info = zipfile.ZipInfo(f"angel-engine-account-export/{name}", date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, members[name].encode("utf-8") + b"\n")
    return buffer.getvalue()


async def request_export(svc: Any, db: Any, user_id: uuid.UUID) -> DataExport:
    """Create (or return the still-valid) export for an account and queue its job."""
    now = utcnow()
    active = (
        await db.execute(
            select(DataExport)
            .where(
                DataExport.user_id == user_id, DataExport.status.in_(["pending", "ready"]), DataExport.expires_at > now
            )
            .order_by(DataExport.created_at.desc())
        )
    ).scalar_one_or_none()
    if active is not None:
        return active  # type: ignore[no-any-return]
    export = DataExport(
        id=new_id(),
        user_id=user_id,
        status="pending",
        expires_at=now + timedelta(hours=svc.settings.export_retention_hours),
    )
    db.add(export)
    await db.flush()
    await enqueue(
        db,
        queue=JobQueue.MAINTENANCE,
        kind="account.export",
        payload={"export_id": str(export.id)},
        idempotency_key=f"account.export:{export.id}",
        max_attempts=3,
        created_by=user_id,
    )
    return export


@handler("account.export")
async def export_account(ctx: JobContext, payload: dict[str, Any]) -> dict[str, Any]:
    svc = ctx.services
    try:
        export_id = uuid.UUID(payload["export_id"])
    except (KeyError, ValueError) as exc:
        raise PermanentJobError("invalid payload") from exc
    async with svc.db.session("worker") as db:
        export = await db.get(DataExport, export_id)
        if export is None or export.status != "pending" or export.expires_at <= utcnow():
            return {"skipped": "not pending"}
        user_id = export.user_id
        files = await collect(db, user_id)
    content = await asyncio.to_thread(build_archive, files, utcnow())
    key = account_export_key(user_id, export_id)
    async with svc.db.session("worker") as db:
        system = await svc.vault.system_cipher(db, "system_secrets")
        file_key = system.new_file_key()
        await svc.get("storage").put(key, FieldCipher.encrypt_blob(file_key, content, object_key=key))
        export = await db.get(DataExport, export_id, with_for_update=True)
        if export is None or export.status != "pending":
            return {"skipped": "changed"}
        export.status, export.object_key = "ready", key
        export.file_key = system.seal(file_key, table="data_exports", column="file_key", row_id=export.id)
        await append_now(
            db,
            svc.audit_key,
            [
                AuditEvent(
                    action="account.data_export_ready",
                    actor_type="worker",
                    target_type="data_export",
                    target_id=str(export.id),
                    details={"bytes": len(content), "files": len(files) + 1},
                )
            ],
        )
    log.info("account_export_ready", bytes=len(content))
    return {"status": "ready", "bytes": len(content)}
