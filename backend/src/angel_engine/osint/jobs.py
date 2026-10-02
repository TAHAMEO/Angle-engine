"""Collection jobs.

* ``collection.run`` (egress queue) — runs one connector query. Network I/O happens outside any database
  transaction. Page captures are encrypted into object storage and handed to the analysis queue; the
  egress worker never parses documents.
* ``capture.parse`` (analysis queue) — decrypts a capture, extracts text in the document sandbox and
  ingests the result. Captures marked ``noarchive`` are deleted right after parsing.
"""

from __future__ import annotations

import base64
import uuid
from datetime import datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select

from angel_engine.app_state import Services
from angel_engine.audit.chain import AuditEvent, append_now
from angel_engine.core.clock import utcnow
from angel_engine.core.enums import InvestigationStatus, JobQueue
from angel_engine.core.ids import new_id
from angel_engine.crypto.envelope import FieldCipher, KeyDestroyedError
from angel_engine.db.models import BlobDeletion, CollectionRun, Investigation
from angel_engine.db.session import set_investigation_scope
from angel_engine.infra.http.safe_client import CircuitOpen, HttpFetchError, HttpPolicyError
from angel_engine.infra.storage.objects import investigation_object_key
from angel_engine.jobs.queue import PermanentJobError, enqueue
from angel_engine.jobs.registry import JobContext, handler
from angel_engine.osint.connectors.base import ConnectorContext, ConnectorError
from angel_engine.osint.connectors.web import capture_record
from angel_engine.osint.ingestion import ingest
from angel_engine.osint.sandbox import ExtractionFailed, extract_document
from angel_engine.osint.types import (
    AccessStatus,
    ConnectorQuery,
    InputType,
    ManualReference,
    RawCapture,
    SourceCategory,
)

log = structlog.get_logger(__name__)
LEAD_TTL = timedelta(hours=24)
CAPTURE_AAD = ("captures", "file_key")


def _system(action: str, **kwargs: Any) -> AuditEvent:
    return AuditEvent(action=action, actor_type="worker", **kwargs)


async def _load(
    svc: Services, db: Any, run_id: uuid.UUID, inv_id: uuid.UUID, *, lock: bool = False
) -> tuple[CollectionRun | None, Investigation | None, FieldCipher | None]:
    await set_investigation_scope(db, [inv_id])
    stmt = select(CollectionRun).where(CollectionRun.id == run_id, CollectionRun.investigation_id == inv_id)
    run = (await db.execute(stmt.with_for_update() if lock else stmt)).scalar_one_or_none()
    inv = await db.get(Investigation, inv_id)
    if run is None or inv is None or inv.status == InvestigationStatus.DELETED.value:
        return run, inv, None
    try:
        cipher = await svc.vault.investigation_cipher(db, inv_id)
    except KeyDestroyedError:
        return run, inv, None
    return run, inv, cipher


def _ids(payload: dict[str, Any]) -> tuple[uuid.UUID, uuid.UUID]:
    try:
        return uuid.UUID(payload["run_id"]), uuid.UUID(payload["investigation_id"])
    except (KeyError, ValueError) as exc:
        raise PermanentJobError("invalid payload") from exc


async def _finish(
    svc: Services,
    run_id: uuid.UUID,
    inv_id: uuid.UUID,
    *,
    status: str,
    error_code: str | None = None,
    warnings: list[str] | None = None,
    records: int = 0,
    references: int = 0,
    details: dict[str, Any] | None = None,
) -> None:
    async with svc.db.session("worker") as db:
        run, _inv, _ = await _load(svc, db, run_id, inv_id, lock=True)
        if run is None:
            return
        run.status, run.error_code, run.finished_at = status, error_code, utcnow()
        run.records_count += records
        run.references_count += references
        if warnings:
            run.warnings = list(dict.fromkeys([*run.warnings, *warnings]))[:30]
        await append_now(
            db,
            svc.audit_key,
            [
                _system(
                    "collection.completed",
                    investigation_id=inv_id,
                    target_type="collection_run",
                    target_id=str(run_id),
                    outcome="success" if status in ("succeeded", "partial") else "failure",
                    details={"connector": run.connector_id, "status": status, "error": error_code, **(details or {})},
                )
            ],
        )


@handler("collection.run")
async def run_collection(ctx: JobContext, payload: dict[str, Any]) -> dict[str, Any]:
    svc = ctx.services
    run_id, inv_id = _ids(payload)
    async with svc.db.session("worker") as db:
        run, inv, cipher = await _load(svc, db, run_id, inv_id, lock=True)
        if run is None or inv is None or cipher is None:
            return {"skipped": "missing"}
        if run.status != "queued" or inv.status != InvestigationStatus.ACTIVE.value:
            if run.status == "queued":
                run.status, run.error_code, run.finished_at = "cancelled", "investigation_not_active", utcnow()
            return {"skipped": run.status}
        run.status, run.started_at = "running", utcnow()
        query = cipher.open(run.query, table="collection_runs", column="query", row_id=run.id)
        params = (
            cipher.open_json(run.params, table="collection_runs", column="params", row_id=run.id) if run.params else {}
        )
        connector_id, input_type, restricted = run.connector_id, run.input_type, inv.restricted_mode
    registry = svc.get("connectors")
    connector = registry.get(connector_id) if registry else None
    if connector is None:
        await _finish(svc, run_id, inv_id, status="failed", error_code="unknown_connector")
        return {"status": "failed"}
    cctx = ConnectorContext(
        http=svc.get("http"), robots=svc.get("robots"), settings=svc.settings, restricted_mode=restricted
    )
    await ctx.progress("querying", connector=connector_id)
    try:
        result = await connector.search(ConnectorQuery(InputType(input_type), query, 20, dict(params)), cctx)
    except ConnectorError as exc:
        await _finish(svc, run_id, inv_id, status="failed", error_code=exc.code)
        return {"status": "failed", "error": exc.code}
    except HttpPolicyError:
        await _finish(
            svc,
            run_id,
            inv_id,
            status="failed",
            error_code="blocked_url",
            warnings=["The address is not publicly reachable or not allowed."],
        )
        return {"status": "failed", "error": "blocked_url"}
    except (CircuitOpen, HttpFetchError) as exc:
        await _finish(
            svc,
            run_id,
            inv_id,
            status="failed",
            error_code="source_unavailable",
            warnings=["The source could not be reached; try again later."],
        )
        return {"status": "failed", "error": type(exc).__name__}

    await ctx.progress("saving")
    async with svc.db.session("worker") as db:
        run, inv, cipher = await _load(svc, db, run_id, inv_id, lock=True)
        if run is None or inv is None or cipher is None:
            return {"skipped": "deleted"}
        captures_queued = 0
        storage = svc.get("storage")
        for capture in result.captures:
            capture_id = new_id()
            key = investigation_object_key(inv.id, "captures", capture_id)
            file_key = cipher.new_file_key()
            await storage.put(key, FieldCipher.encrypt_blob(file_key, capture.content, object_key=key))
            wrapped = cipher.seal(file_key, table=CAPTURE_AAD[0], column=CAPTURE_AAD[1], row_id=capture_id)
            await enqueue(
                db,
                queue=JobQueue.ANALYSIS,
                kind="capture.parse",
                investigation_id=inv.id,
                payload={
                    "run_id": str(run.id),
                    "investigation_id": str(inv.id),
                    "capture_id": str(capture_id),
                    "object_key": key,
                    "file_key": base64.b64encode(wrapped).decode(),
                    "url": capture.url,
                    "final_url": capture.final_url,
                    "content_type": capture.content_type,
                    "retrieved_at": capture.retrieved_at.isoformat(),
                    "no_archive": capture.no_archive,
                },
                max_attempts=2,
            )
            captures_queued += 1
        stats, leads = await ingest(
            db,
            cipher,
            inv,
            connector_id=connector_id,
            category=connector.info.category,
            records=result.records,
            references=result.references,
            run_id=run.id,
            actor_id=run.requested_by,
        )
        if leads:
            run.leads = cipher.seal_json(
                [
                    {"url": lead.url, "title": lead.title, "snippet": lead.excerpt, "publisher": lead.publisher}
                    for lead in leads
                ],
                table="collection_runs",
                column="leads",
                row_id=run.id,
            )
            run.leads_expire_at = utcnow() + LEAD_TTL
        run.records_count += stats.evidence_created
        run.references_count += stats.references
        run.warnings = list(dict.fromkeys([*run.warnings, *result.warnings, *stats.warnings]))[:30]
        if not captures_queued:
            run.status = "partial" if result.partial else "succeeded"
            run.finished_at = utcnow()
        await append_now(
            db,
            svc.audit_key,
            [
                _system(
                    "collection.completed" if not captures_queued else "collection.captured",
                    investigation_id=inv.id,
                    target_type="collection_run",
                    target_id=str(run.id),
                    details={
                        "connector": connector_id,
                        "leads": len(leads),
                        "captures": captures_queued,
                        **stats.as_dict(),
                    },
                )
            ],
        )
    return {"status": "ok", "captures": captures_queued, "leads": len(leads), **stats.as_dict()}


@handler("capture.parse")
async def parse_capture(ctx: JobContext, payload: dict[str, Any]) -> dict[str, Any]:
    svc = ctx.services
    run_id, inv_id = _ids(payload)
    storage = svc.get("storage")
    key = str(payload["object_key"])
    async with svc.db.session("worker") as db:
        run, inv, cipher = await _load(svc, db, run_id, inv_id)
        if run is None or inv is None or cipher is None:
            return {"skipped": "deleted"}
        file_key = cipher.open_bytes(
            base64.b64decode(payload["file_key"]),
            table=CAPTURE_AAD[0],
            column=CAPTURE_AAD[1],
            row_id=payload["capture_id"],
        )
    content = FieldCipher.decrypt_blob(file_key, await storage.get(key), object_key=key)
    capture = RawCapture(
        url=payload["url"],
        final_url=payload["final_url"],
        status=200,
        content_type=payload.get("content_type"),
        content=content,
        retrieved_at=datetime.fromisoformat(payload["retrieved_at"]),
        no_archive=bool(payload.get("no_archive")),
    )
    await ctx.progress("extracting")
    try:
        extracted = await extract_document(
            content, capture.content_type, capture.final_url, sandbox=svc.settings.document_sandbox
        )
        outcome: Any = capture_record(capture, extracted)
    except ExtractionFailed as exc:
        log.warning("capture_extraction_failed", reason=str(exc))
        outcome = ManualReference(
            capture.final_url,
            AccessStatus.REFERENCE_ONLY,
            "The document could not be read safely; open it yourself to review it.",
        )
    async with svc.db.session("worker") as db:
        run, inv, cipher = await _load(svc, db, run_id, inv_id)
        if run is None or inv is None or cipher is None:
            return {"skipped": "deleted"}
        records = [outcome] if not isinstance(outcome, ManualReference) else []
        references = [outcome] if isinstance(outcome, ManualReference) else []
        category = records[0].category if records else SourceCategory.WEBSITES
        stats, _ = await ingest(
            db,
            cipher,
            inv,
            connector_id="web_capture",
            category=category,
            records=records,
            references=references,
            run_id=run.id,
            actor_id=run.requested_by,
        )
        if capture.no_archive:
            db.add(BlobDeletion(object_key=key, reason="noarchive_capture"))
    await _finish(
        svc,
        run_id,
        inv_id,
        status="succeeded",
        records=stats.evidence_created,
        references=stats.references,
        details=stats.as_dict(),
    )
    return {"status": "ok", **stats.as_dict()}
