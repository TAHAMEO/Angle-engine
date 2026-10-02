"""Image jobs (analysis queue — the worker that runs them has no internet access).

* ``image.scan`` — malware-scan the encrypted original. Fails closed: while the scanner is unreachable the
  job retries with backoff and the image never becomes ``clean``; infected or unscannable files are purged at
  once and never analyzed.
* ``image.analyze`` — run the sandboxed pipeline on a clean original and persist the results (evidence,
  findings, graph, timeline, duplicates). Polyglot files found by the pipeline are quarantined and purged.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import structlog
from sqlalchemy import select

from angel_engine.app_state import Services
from angel_engine.audit.chain import AuditEvent, append_now
from angel_engine.core.clock import utcnow
from angel_engine.core.enums import ImageStatus, InvestigationStatus, JobQueue
from angel_engine.core.ids import new_id
from angel_engine.crypto.envelope import FieldCipher, KeyDestroyedError
from angel_engine.db.models import Image, ImageAnalysis, Investigation
from angel_engine.db.session import set_investigation_scope
from angel_engine.images import service
from angel_engine.images.sandbox.runner import SandboxFailed, analyze
from angel_engine.images.scanning import ScannerUnavailable, ScanVerdict
from angel_engine.images.types import PipelineResult, StageStatus
from angel_engine.jobs.queue import PermanentJobError, enqueue
from angel_engine.jobs.registry import JobContext, handler

log = structlog.get_logger(__name__)
ANALYZE_ATTEMPTS = 2


def _event(
    action: str, image: Image, outcome: str = "success", counts: dict[str, int] | None = None, **details: Any
) -> AuditEvent:
    return AuditEvent(
        action=action,
        actor_type="worker",
        investigation_id=image.investigation_id,
        target_type="image",
        target_id=str(image.id),
        outcome=outcome,
        details={**details, **(counts or {})},
    )


def _ids(payload: dict[str, Any]) -> tuple[uuid.UUID, uuid.UUID]:
    try:
        return uuid.UUID(payload["image_id"]), uuid.UUID(payload["investigation_id"])
    except (KeyError, ValueError) as exc:
        raise PermanentJobError("invalid payload") from exc


async def _load(
    svc: Services, db: Any, image_id: uuid.UUID, inv_id: uuid.UUID
) -> tuple[Image | None, Investigation | None, FieldCipher | None]:
    await set_investigation_scope(db, [inv_id])
    image = (
        await db.execute(select(Image).where(Image.id == image_id, Image.investigation_id == inv_id).with_for_update())
    ).scalar_one_or_none()
    inv = await db.get(Investigation, inv_id)
    if image is None or inv is None or inv.status == InvestigationStatus.DELETED.value:
        return None, None, None
    try:
        return image, inv, await svc.vault.investigation_cipher(db, inv_id)
    except KeyDestroyedError:
        return None, None, None


async def _read_original(svc: Services, cipher: FieldCipher, image: Image) -> tuple[str, bytes]:
    key = image.original_key or ""
    return key, service.original_file_key(cipher, image)


async def _on_last_attempt(
    ctx: JobContext, image_id: uuid.UUID, inv_id: uuid.UUID, status: ImageStatus, code: str
) -> bool:
    """Mark the image failed when this was the job's last attempt (the caller then stops retrying)."""
    if ctx.job.attempts < ctx.job.max_attempts:
        return False
    svc = ctx.services
    async with svc.db.session("worker") as db:
        image, _, _ = await _load(svc, db, image_id, inv_id)
        if image is None:
            return True
        image.status = status.value
        if status == ImageStatus.SCAN_FAILED:
            service.purge_original(db, image, "scan_failed")
        await append_now(db, svc.audit_key, [_event(f"image.{status.value}", image, "failure", error=code)])
    return True


async def _guarded(
    ctx: JobContext, image_id: uuid.UUID, inv_id: uuid.UUID, status: ImageStatus,
    body: Callable[[], Awaitable[dict[str, Any]]],
) -> dict[str, Any]:  # fmt: skip
    try:
        return await body()
    except PermanentJobError:
        raise
    except Exception as exc:
        code = "scanner_unavailable" if isinstance(exc, ScannerUnavailable) else type(exc).__name__
        log.warning("image_job_error", kind=ctx.job.kind, error_type=type(exc).__name__)
        if await _on_last_attempt(ctx, image_id, inv_id, status, code):
            return {"status": status.value, "error": code}
        raise


# --------------------------------------------------------------------------------------------------
# Scan
# --------------------------------------------------------------------------------------------------
@handler("image.scan")
async def scan_image(ctx: JobContext, payload: dict[str, Any]) -> dict[str, Any]:
    image_id, inv_id = _ids(payload)
    return await _guarded(ctx, image_id, inv_id, ImageStatus.SCAN_FAILED, lambda: _scan(ctx, image_id, inv_id))


async def _scan(ctx: JobContext, image_id: uuid.UUID, inv_id: uuid.UUID) -> dict[str, Any]:
    svc = ctx.services
    async with svc.db.session("worker") as db:
        image, _inv, cipher = await _load(svc, db, image_id, inv_id)
        if image is None or cipher is None:
            return {"skipped": "missing"}
        if image.status not in (ImageStatus.UPLOADED.value, ImageStatus.SCANNING.value) or not image.original_key:
            return {"skipped": image.status}
        image.status = ImageStatus.SCANNING.value
        key, file_key = await _read_original(svc, cipher, image)
    scanner = svc.get("scanner")
    if scanner is None:
        raise ScannerUnavailable("no scanner configured")
    data = FieldCipher.decrypt_blob(file_key, await svc.get("storage").get(key), object_key=key)
    await ctx.progress("scanning")
    result = await scanner.scan(data)  # ScannerUnavailable ⇒ retry later (fail closed)
    del data
    async with svc.db.session("worker") as db:
        image, _inv, cipher = await _load(svc, db, image_id, inv_id)
        if image is None:
            return {"skipped": "deleted"}
        image.scan_engine, image.scan_signature, image.scan_completed_at = result.engine, result.signature, utcnow()
        if result.verdict == ScanVerdict.CLEAN:
            image.status = ImageStatus.CLEAN.value
            await enqueue(
                db,
                queue=JobQueue.ANALYSIS,
                kind="image.analyze",
                payload={"image_id": str(image.id), "investigation_id": str(inv_id)},
                investigation_id=inv_id,
                idempotency_key=f"image-analyze:{image.id}",
                max_attempts=ANALYZE_ATTEMPTS,
            )
            event = _event("image.scanned", image, engine=result.engine, degraded=result.degraded)
        elif result.verdict == ScanVerdict.INFECTED:
            image.status = ImageStatus.INFECTED.value
            service.purge_original(db, image, "infected_upload")
            event = _event("image.infected", image, "failure", engine=result.engine, signature=result.signature,
                           heuristic=result.heuristic)  # fmt: skip
        else:
            image.status = ImageStatus.SCAN_FAILED.value
            service.purge_original(db, image, "scan_failed")
            event = _event("image.scan_failed", image, "failure", engine=result.engine, error="scanner_error")
        await append_now(db, svc.audit_key, [event])
    return {"status": image.status, "engine": result.engine}


# --------------------------------------------------------------------------------------------------
# Analyze
# --------------------------------------------------------------------------------------------------
@handler("image.analyze")
async def analyze_image(ctx: JobContext, payload: dict[str, Any]) -> dict[str, Any]:
    image_id, inv_id = _ids(payload)
    return await _guarded(ctx, image_id, inv_id, ImageStatus.ANALYSIS_FAILED, lambda: _analyze(ctx, image_id, inv_id))


def _sandbox_failure(image: Image, code: str) -> ImageAnalysis:
    return ImageAnalysis(
        id=new_id(),
        investigation_id=image.investigation_id,
        image_id=image.id,
        analyzer="sandbox",
        analyzer_version="1",
        status=StageStatus.TIMEOUT.value if code == "timeout" else StageStatus.FAILED.value,
        metrics={"error_code": code},
    )


async def _analyze(ctx: JobContext, image_id: uuid.UUID, inv_id: uuid.UUID) -> dict[str, Any]:
    svc = ctx.services
    async with svc.db.session("worker") as db:
        image, inv, cipher = await _load(svc, db, image_id, inv_id)
        if image is None or inv is None or cipher is None:
            return {"skipped": "missing"}
        if image.status not in (ImageStatus.CLEAN.value, ImageStatus.ANALYZING.value) or not image.original_key:
            return {"skipped": image.status}
        image.status, image.analysis_started_at = ImageStatus.ANALYZING.value, utcnow()
        key, file_key = await _read_original(svc, cipher, image)
        config = service.pipeline_config(svc.settings, inv, cipher)
        declared = image.declared_mime or image.mime
    data = FieldCipher.decrypt_blob(file_key, await svc.get("storage").get(key), object_key=key)
    await ctx.progress("analyzing")
    result: PipelineResult | None = None
    failure = None
    try:
        result = await analyze(data, declared, config)
    except SandboxFailed as exc:
        failure = exc.code
    del data
    await ctx.progress("saving")
    async with svc.db.session("worker") as db:
        image, inv, cipher = await _load(svc, db, image_id, inv_id)
        if image is None or inv is None or cipher is None:
            return {"skipped": "deleted"}
        if image.status != ImageStatus.ANALYZING.value:
            return {"skipped": image.status}
        await service.clear_results(db, image)
        if result is None:
            image.status = ImageStatus.ANALYSIS_FAILED.value
            db.add(_sandbox_failure(image, failure or "failed"))
            event = _event("image.analysis_failed", image, "failure", error=failure)
        elif result.quarantine_reason:
            image.status, image.quarantine_reason = ImageStatus.QUARANTINED.value, result.quarantine_reason
            service.record_stages(db, cipher, image, result)
            service.purge_original(db, image, "quarantined_upload")
            event = _event("image.quarantined", image, "failure", reason=result.quarantine_reason)
        elif result.status != StageStatus.OK:
            image.status = ImageStatus.ANALYSIS_FAILED.value
            service.record_stages(db, cipher, image, result)
            failed = sorted(s.analyzer for s in result.stages if s.status != StageStatus.OK)
            event = _event("image.analysis_failed", image, "failure", stages=failed)
        else:
            counts = await service.persist_analysis(svc, db, cipher, inv, image, result)
            event = _event("image.analyzed", image, counts=counts, faces=image.face_count, persons=image.person_count)
        await append_now(db, svc.audit_key, [event])
    return {"status": image.status}
