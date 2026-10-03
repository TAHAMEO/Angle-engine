"""``report.export`` (analysis queue): render a report, encrypt the file and store it until it expires."""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from typing import Any

import structlog
from sqlalchemy import select

from angel_engine.audit.chain import AuditEvent, append_now
from angel_engine.core.enums import InvestigationStatus
from angel_engine.crypto.envelope import FieldCipher, KeyDestroyedError
from angel_engine.db.models import Investigation, Report, ReportExport
from angel_engine.db.session import set_investigation_scope
from angel_engine.infra.storage.objects import investigation_object_key
from angel_engine.jobs.queue import PermanentJobError
from angel_engine.jobs.registry import JobContext, handler
from angel_engine.reports.render import render
from angel_engine.reports.service import read_document

log = structlog.get_logger(__name__)


def _ids(payload: dict[str, Any]) -> tuple[uuid.UUID, uuid.UUID]:
    try:
        return uuid.UUID(payload["export_id"]), uuid.UUID(payload["investigation_id"])
    except (KeyError, ValueError) as exc:
        raise PermanentJobError("invalid payload") from exc


async def _load(svc: Any, db: Any, export_id: uuid.UUID, inv_id: uuid.UUID) -> tuple[Any, Any, Any]:
    await set_investigation_scope(db, [inv_id])
    export = (
        await db.execute(
            select(ReportExport)
            .where(ReportExport.id == export_id, ReportExport.investigation_id == inv_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    inv = await db.get(Investigation, inv_id)
    if export is None or inv is None or inv.status == InvestigationStatus.DELETED.value:
        return None, None, None
    try:
        return export, inv, await svc.vault.investigation_cipher(db, inv_id)
    except KeyDestroyedError:
        return None, None, None


@handler("report.export")
async def export_report(ctx: JobContext, payload: dict[str, Any]) -> dict[str, Any]:
    svc = ctx.services
    export_id, inv_id = _ids(payload)
    async with svc.db.session("worker") as db:
        export, _inv, cipher = await _load(svc, db, export_id, inv_id)
        if export is None or cipher is None:
            return {"skipped": "missing"}
        if export.status != "pending":
            return {"skipped": export.status}
        report = await db.get(Report, export.report_id)
        doc = read_document(cipher, report) if report is not None else None
        fmt = export.format
    if doc is None:
        async with svc.db.session("worker") as db:
            export, _, _ = await _load(svc, db, export_id, inv_id)
            if export is not None:
                export.status = "failed"
        return {"status": "failed"}
    await ctx.progress("rendering", format=fmt)
    try:
        content = await asyncio.to_thread(render, doc, fmt)
    except Exception as exc:  # rendering errors are permanent for this export
        log.warning("report_render_failed", error_type=type(exc).__name__)
        async with svc.db.session("worker") as db:
            export, _, _ = await _load(svc, db, export_id, inv_id)
            if export is not None:
                export.status = "failed"
        return {"status": "failed"}
    key = investigation_object_key(inv_id, "exports", export_id)
    file_key = cipher.new_file_key()
    await svc.get("storage").put(key, FieldCipher.encrypt_blob(file_key, content, object_key=key))
    async with svc.db.session("worker") as db:
        export, _inv, cipher = await _load(svc, db, export_id, inv_id)
        if export is None or cipher is None:
            return {"skipped": "deleted"}
        export.status, export.object_key = "ready", key
        export.file_key = cipher.seal(file_key, table="report_exports", column="file_key", row_id=export.id)
        export.byte_size, export.sha256 = len(content), hashlib.sha256(content).hexdigest()
        await append_now(
            db,
            svc.audit_key,
            [
                AuditEvent(
                    action="report.exported",
                    actor_type="worker",
                    investigation_id=inv_id,
                    target_type="report_export",
                    target_id=str(export.id),
                    details={"format": fmt, "bytes": len(content), "report_id": str(export.report_id)},
                )
            ],
        )
    return {"status": "ready", "bytes": len(content)}
