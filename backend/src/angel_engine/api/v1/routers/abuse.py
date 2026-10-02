"""Public abuse reporting (including removal requests) and the triage queue."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from angel_engine.api.deps import (
    DbSession,
    Principal,
    ServicesDep,
    anonymous_csrf,
    enforce_rate_limit,
    ip_pseudonym,
    request_id,
    require,
)
from angel_engine.audit.chain import AuditEvent, record
from angel_engine.authz.permissions import Perm
from angel_engine.core.clock import utcnow
from angel_engine.core.enums import AbuseCategory, AbuseStatus
from angel_engine.core.ids import new_id
from angel_engine.core.problems import NotFound
from angel_engine.db.models import AbuseReport
from angel_engine.infra.ratelimit.gcra import ABUSE_REPORT_IP

router = APIRouter(tags=["abuse"])
Triager = Annotated[Principal, Depends(require(Perm.ABUSE_TRIAGE))]


class AbuseReportIn(BaseModel):
    category: AbuseCategory
    description: str = Field(min_length=20, max_length=5000)
    contact: str | None = Field(default=None, max_length=320)
    target_ref: str | None = Field(default=None, max_length=64)
    website: str | None = Field(default=None, max_length=200)  # honeypot


@router.post(
    "/abuse-reports", status_code=202, dependencies=[Depends(anonymous_csrf)], openapi_extra={"x-public": True}
)
async def submit_abuse_report(body: AbuseReportIn, request: Request, db: DbSession, svc: ServicesDep) -> dict[str, str]:
    received = {
        "status": "received",
        "detail": "Thank you. The report has been recorded and will be reviewed by the platform's administrators.",
    }
    ipp = ip_pseudonym(request)
    await enforce_rate_limit(svc, f"abuse:{ipp}", ABUSE_REPORT_IP)
    if body.website:
        return received
    report = AbuseReport(
        id=new_id(),
        category=body.category.value,
        description=b"",
        ip_pseudonym=ipp,
        target_ref=(body.target_ref or "").strip().upper() or None,
    )
    cipher = await svc.vault.system_cipher(db, "system_abuse")
    report.description = cipher.seal(body.description, table="abuse_reports", column="description", row_id=report.id)
    report.contact = cipher.seal_optional(body.contact, table="abuse_reports", column="contact", row_id=report.id)
    db.add(report)
    record(
        db,
        AuditEvent(
            action="abuse.report_received",
            actor_type="anonymous",
            ip_pseudonym=ipp,
            request_id=request_id(request),
            target_type="abuse_report",
            target_id=str(report.id),
            details={"category": report.category},
        ),
    )
    return received


class AbuseReportOut(BaseModel):
    id: str
    category: str
    description: str
    contact: str | None
    target_ref: str | None
    status: str
    triage_notes: str | None
    created_at: datetime
    resolved_at: datetime | None


class AbusePatch(BaseModel):
    status: AbuseStatus
    triage_note: str | None = Field(default=None, max_length=5000)


async def _out(db: DbSession, svc_principal: Principal, r: AbuseReport) -> AbuseReportOut:
    cipher = await svc_principal.services.vault.system_cipher(db, "system_abuse")
    return AbuseReportOut(
        id=str(r.id),
        category=r.category,
        description=cipher.open(r.description, table="abuse_reports", column="description", row_id=r.id),
        contact=cipher.open_optional(r.contact, table="abuse_reports", column="contact", row_id=r.id),
        target_ref=r.target_ref,
        status=r.status,
        triage_notes=cipher.open_optional(r.triage_notes, table="abuse_reports", column="triage_notes", row_id=r.id),
        created_at=r.created_at,
        resolved_at=r.resolved_at,
    )


@router.get("/admin/abuse-reports")
async def list_abuse_reports(
    principal: Triager, db: DbSession, status: AbuseStatus | None = None
) -> list[AbuseReportOut]:
    stmt = select(AbuseReport).order_by(AbuseReport.created_at.desc()).limit(200)
    if status is not None:
        stmt = stmt.where(AbuseReport.status == status.value)
    rows = (await db.execute(stmt)).scalars().all()
    principal.audit(db, "abuse.reports_viewed", details={"count": len(rows)})
    return [await _out(db, principal, r) for r in rows]


@router.patch("/admin/abuse-reports/{report_id}")
async def update_abuse_report(
    report_id: uuid.UUID, body: AbusePatch, principal: Triager, db: DbSession
) -> AbuseReportOut:
    report = await db.get(AbuseReport, report_id)
    if report is None:
        raise NotFound()
    report.status = body.status.value
    report.handled_by = principal.user_id
    if body.status in (AbuseStatus.ACTIONED, AbuseStatus.DISMISSED):
        report.resolved_at = utcnow()
    if body.triage_note:
        cipher = await principal.services.vault.system_cipher(db, "system_abuse")
        existing = cipher.open_optional(
            report.triage_notes, table="abuse_reports", column="triage_notes", row_id=report.id
        )
        stamp = utcnow().strftime("%Y-%m-%d %H:%M UTC")
        merged = f"{existing}\n\n[{stamp}] {body.triage_note}" if existing else f"[{stamp}] {body.triage_note}"
        report.triage_notes = cipher.seal(merged, table="abuse_reports", column="triage_notes", row_id=report.id)
    principal.audit(
        db,
        "abuse.report_updated",
        target_type="abuse_report",
        target_id=str(report.id),
        details={"status": report.status},
    )
    return await _out(db, principal, report)
