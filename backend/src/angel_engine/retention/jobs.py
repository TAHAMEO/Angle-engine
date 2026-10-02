"""Retention and deletion jobs.

* ``investigations.purge`` — after an investigation is deleted (its keys are already destroyed), remove
  every remaining row and blob. The investigation row stays as a scrubbed tombstone (reference and
  timestamps only) so audit records keep resolving.
* ``retention.sweep`` — hourly: archive/delete closed investigations, delete stale drafts and refused
  requests, drop expired policy text and AI transcripts, trim old abuse reports and audit history.
* ``retention.purge_image_originals`` — every 15 minutes: delete image originals past their retention.
* ``retention.expire_exports`` — hourly: expire report exports and personal data exports.
* ``maintenance.blob_deletions`` — every 10 minutes: drain the blob-deletion outbox.

All jobs use the maintenance database role (bypasses row-level security) and record content-free audit
events with counts only.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import structlog
from sqlalchemy import and_, delete, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.app_state import Services
from angel_engine.audit.chain import AuditEvent, append_now
from angel_engine.core.clock import utcnow
from angel_engine.core.enums import AbuseStatus, ImageStatus, InvestigationStatus
from angel_engine.db.models import (
    AbuseReport,
    AIInteraction,
    BlobDeletion,
    DataExport,
    Image,
    Investigation,
    PolicyDecision,
    ReportExport,
)
from angel_engine.infra.storage.objects import investigation_prefix
from angel_engine.jobs.queue import PermanentJobError
from angel_engine.jobs.registry import JobContext, handler
from angel_engine.retention.policy import load_policy

log = structlog.get_logger(__name__)
S = InvestigationStatus
BATCH = 500
MAX_BLOB_ATTEMPTS = 10

#: Child tables purged for a deleted investigation, children before parents (FK order). Accountability
#: records are kept: attestations, policy decisions (their text expires separately), the audit log and
#: the destroyed key rows that document the crypto-shred.
PURGE_TABLES: tuple[str, ...] = (
    "timeline_event_evidence",
    "relationship_status_history",
    "relationship_evidence",
    "image_clues",
    "finding_evidence",
    "facts",
    "entity_mentions",
    "timeline_events",
    "report_exports",
    "relationships",
    "image_hashes",
    "image_analyses",
    "finding_status_history",
    "evidence_items",
    "ai_proposals",
    "suggestions",
    "sources",
    "reports",
    "oversight_grants",
    "notes",
    "investigation_members",
    "images",
    "findings",
    "entities",
    "collection_runs",
    "ai_interactions",
)


def _system_event(action: str, **kwargs: Any) -> AuditEvent:
    return AuditEvent(action=action, actor_type="system", **kwargs)


async def _queue_blob_deletions(db: AsyncSession, keys: list[str], reason: str) -> int:
    unique = sorted({k for k in keys if k})
    for key in unique:
        db.add(BlobDeletion(object_key=key, reason=reason))
    return len(unique)


# --------------------------------------------------------------------------------------------------
# Investigation purge
# --------------------------------------------------------------------------------------------------
async def _delete_batch(svc: Services, table: str, investigation_id: uuid.UUID) -> int:
    async with svc.db.session("maintenance") as db:
        await db.execute(text("SELECT set_config('ae.purge', 'on', true)"))
        result = await db.execute(
            text(
                f"DELETE FROM {table} WHERE ctid IN "  # noqa: S608 - table names come from PURGE_TABLES
                f"(SELECT ctid FROM {table} WHERE investigation_id = :inv LIMIT :n)"
            ),
            {"inv": investigation_id, "n": BATCH},
        )
        return int(getattr(result, "rowcount", 0) or 0)


async def purge_investigation_rows(svc: Services, investigation_id: uuid.UUID) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in PURGE_TABLES:
        total = 0
        while True:
            deleted = await _delete_batch(svc, table, investigation_id)
            total += deleted
            if deleted < BATCH:
                break
        if total:
            counts[table] = total
    async with svc.db.session("maintenance") as db:
        result = await db.execute(
            text("DELETE FROM jobs WHERE investigation_id = :inv AND status <> 'running'"), {"inv": investigation_id}
        )
        jobs = int(getattr(result, "rowcount", 0) or 0)
        if jobs:
            counts["jobs"] = jobs
    return counts


@handler("investigations.purge")
async def purge_investigation(ctx: JobContext, payload: dict[str, Any]) -> dict[str, Any]:
    svc = ctx.services
    try:
        investigation_id = uuid.UUID(str(payload["investigation_id"]))
    except (KeyError, ValueError) as exc:
        raise PermanentJobError("invalid payload") from exc
    async with svc.db.session("maintenance") as db:
        inv = await db.get(Investigation, investigation_id)
        if inv is None or inv.status != S.DELETED.value:
            return {"skipped": "not_deleted"}
        await svc.vault.destroy_investigation_keys(db, investigation_id)  # idempotent safety net
        image_keys = (
            await db.execute(select(Image.original_key, Image.preview_key).where(Image.investigation_id == inv.id))
        ).all()
        export_keys = (
            (await db.execute(select(ReportExport.object_key).where(ReportExport.investigation_id == inv.id)))
            .scalars()
            .all()
        )
        keys = [k for row in image_keys for k in row if k] + [k for k in export_keys if k]
        keys.append(investigation_prefix(inv.id))
        blobs = await _queue_blob_deletions(db, keys, "investigation_purge")
    await ctx.progress("rows")
    counts = await purge_investigation_rows(svc, investigation_id)
    async with svc.db.session("maintenance") as db:
        await db.execute(update(Investigation).where(Investigation.id == investigation_id).values(purge_after=None))
        await append_now(
            db,
            svc.audit_key,
            [
                _system_event(
                    "investigation.purged",
                    investigation_id=investigation_id,
                    target_type="investigation",
                    target_id=str(investigation_id),
                    details={"rows": sum(counts.values()), "tables": len(counts), "blob_deletions": blobs},
                )
            ],
        )
    return {"rows": counts, "blob_deletions": blobs}


# --------------------------------------------------------------------------------------------------
# Hourly sweep
# --------------------------------------------------------------------------------------------------
async def _delete_for_retention(svc: Services, db: AsyncSession, inv: Investigation, reason: str) -> None:
    from angel_engine.investigations.service import delete_investigation

    await delete_investigation(svc, db, inv, reason)
    await append_now(
        db,
        svc.audit_key,
        [
            _system_event(
                "investigation.deleted",
                investigation_id=inv.id,
                target_type="investigation",
                target_id=str(inv.id),
                details={"reason": reason, "automatic": True},
            )
        ],
    )


async def _sweep_investigations(svc: Services) -> dict[str, int]:
    out = {"archived": 0, "deleted_closed": 0, "deleted_drafts": 0, "deleted_refused": 0}
    async with svc.db.session("maintenance") as db:
        policy = await load_policy(db, svc.settings)
        now = utcnow()
        candidates = (
            (
                await db.execute(
                    select(Investigation)
                    .where(
                        Investigation.legal_hold.is_(False),
                        or_(
                            and_(
                                Investigation.status.in_([S.CLOSED.value, S.ARCHIVED.value]),
                                Investigation.closed_at.is_not(None),
                            ),
                            and_(
                                Investigation.status == S.DRAFT.value,
                                Investigation.updated_at < now - timedelta(days=policy.draft_inactive_days),
                            ),
                            and_(
                                Investigation.status == S.REFUSED.value,
                                Investigation.updated_at < now - timedelta(days=policy.refused_investigation_days),
                            ),
                        ),
                    )
                    .with_for_update(skip_locked=True)
                    .limit(BATCH)
                )
            )
            .scalars()
            .all()
        )
        for inv in candidates:
            if inv.status == S.DRAFT.value:
                await _delete_for_retention(svc, db, inv, "inactive_draft")
                out["deleted_drafts"] += 1
            elif inv.status == S.REFUSED.value:
                await _delete_for_retention(svc, db, inv, "refused_request_expired")
                out["deleted_refused"] += 1
            else:
                assert inv.closed_at is not None
                age = now - inv.closed_at
                if age >= timedelta(days=policy.closed_delete_days_for(inv)):
                    await _delete_for_retention(svc, db, inv, "closed_retention_elapsed")
                    out["deleted_closed"] += 1
                elif inv.status == S.CLOSED.value and age >= timedelta(days=policy.closed_archive_days):
                    inv.status, inv.archived_at = S.ARCHIVED.value, now
                    await append_now(
                        db,
                        svc.audit_key,
                        [
                            _system_event(
                                "investigation.archive",
                                investigation_id=inv.id,
                                target_type="investigation",
                                target_id=str(inv.id),
                                details={"status": inv.status, "automatic": True},
                            )
                        ],
                    )
                    out["archived"] += 1
    return out


async def _sweep_records(svc: Services) -> dict[str, int]:
    out: dict[str, int] = {}
    async with svc.db.session("maintenance") as db:
        policy = await load_policy(db, svc.settings)
        now = utcnow()
        result = await db.execute(
            update(PolicyDecision)
            .where(
                PolicyDecision.input.is_not(None),
                or_(
                    PolicyDecision.input_expires_at < now,
                    PolicyDecision.created_at < now - timedelta(days=policy.policy_text_days),
                ),
            )
            .values(input=None)
        )
        out["policy_text_expired"] = int(getattr(result, "rowcount", 0) or 0)
        result = await db.execute(
            update(AIInteraction)
            .where(
                or_(AIInteraction.prompt.is_not(None), AIInteraction.response.is_not(None)),
                or_(
                    AIInteraction.expires_at < now,
                    AIInteraction.created_at < now - timedelta(days=policy.ai_transcript_days),
                ),
            )
            .values(prompt=None, response=None)
        )
        out["ai_transcripts_expired"] = int(getattr(result, "rowcount", 0) or 0)
        result = await db.execute(
            delete(AbuseReport).where(
                AbuseReport.status.in_([AbuseStatus.ACTIONED.value, AbuseStatus.DISMISSED.value]),
                AbuseReport.created_at < now - timedelta(days=policy.abuse_report_days),
            )
        )
        out["abuse_reports_deleted"] = int(getattr(result, "rowcount", 0) or 0)
        out["audit_rows_trimmed"] = await _trim_audit(db, now - timedelta(days=policy.audit_days))
    return out


async def _trim_audit(db: AsyncSession, cutoff: Any) -> int:
    """Drop the oldest audit rows (a contiguous prefix of the chain; verification restarts there)."""
    first_kept = (
        await db.execute(text("SELECT min(seq) FROM audit_log WHERE occurred_at >= :cutoff"), {"cutoff": cutoff})
    ).scalar_one_or_none()
    if first_kept is None:
        return 0
    await db.execute(text("SELECT set_config('ae.audit_purge', 'on', true)"))
    result = await db.execute(text("DELETE FROM audit_log WHERE seq < :seq"), {"seq": first_kept})
    await db.execute(text("SELECT set_config('ae.audit_purge', 'off', true)"))
    return int(getattr(result, "rowcount", 0) or 0)


@handler("retention.sweep")
async def retention_sweep(ctx: JobContext, payload: dict[str, Any]) -> dict[str, Any]:
    svc = ctx.services
    counts = await _sweep_investigations(svc)
    counts.update(await _sweep_records(svc))
    if any(counts.values()):
        async with svc.db.session("maintenance") as db:
            await append_now(db, svc.audit_key, [_system_event("retention.sweep", details=counts)])
    return counts


# --------------------------------------------------------------------------------------------------
# Image originals, exports, blob outbox
# --------------------------------------------------------------------------------------------------
@handler("retention.purge_image_originals")
async def purge_image_originals(ctx: JobContext, payload: dict[str, Any]) -> dict[str, Any]:
    svc = ctx.services
    async with svc.db.session("maintenance") as db:
        now = utcnow()
        images = (
            (
                await db.execute(
                    select(Image)
                    .where(Image.original_purged_at.is_(None), Image.original_purge_after <= now)
                    .with_for_update(skip_locked=True)
                    .limit(BATCH)
                )
            )
            .scalars()
            .all()
        )
        await _queue_blob_deletions(db, [i.original_key for i in images if i.original_key], "image_original_retention")
        by_investigation: dict[uuid.UUID, int] = {}
        for image in images:
            image.original_key, image.original_file_key, image.original_purged_at = None, None, now
            if image.status == ImageStatus.ANALYZED.value:
                image.status = ImageStatus.ORIGINAL_PURGED.value
            by_investigation[image.investigation_id] = by_investigation.get(image.investigation_id, 0) + 1
        await append_now(
            db,
            svc.audit_key,
            [
                _system_event("image.original_purged", investigation_id=inv_id, details={"count": count})
                for inv_id, count in by_investigation.items()
            ],
        )
    return {"purged": sum(by_investigation.values())}


@handler("retention.expire_exports")
async def expire_exports(ctx: JobContext, payload: dict[str, Any]) -> dict[str, Any]:
    svc = ctx.services
    async with svc.db.session("maintenance") as db:
        now = utcnow()
        report_exports = (
            (
                await db.execute(
                    select(ReportExport)
                    .where(ReportExport.expires_at < now, ReportExport.status != "expired")
                    .limit(BATCH)
                )
            )
            .scalars()
            .all()
        )
        data_exports = (
            (
                await db.execute(
                    select(DataExport)
                    .where(
                        DataExport.expires_at < now, DataExport.status.in_(["pending", "ready", "failed", "downloaded"])
                    )
                    .limit(BATCH)
                )
            )
            .scalars()
            .all()
        )
        keys = [e.object_key for e in report_exports if e.object_key] + [
            e.object_key for e in data_exports if e.object_key
        ]
        await _queue_blob_deletions(db, [k for k in keys if k], "export_expired")
        for export in report_exports:
            export.status, export.object_key, export.file_key = "expired", None, None
        for data_export in data_exports:
            data_export.status, data_export.object_key, data_export.file_key = "expired", None, None
    return {"report_exports": len(report_exports), "data_exports": len(data_exports)}


@handler("maintenance.blob_deletions")
async def drain_blob_deletions(ctx: JobContext, payload: dict[str, Any]) -> dict[str, Any]:
    svc = ctx.services
    store = svc.get("storage")
    if store is None:
        raise PermanentJobError("object storage is not configured")
    done = failed = 0
    async with svc.db.session("maintenance") as db:
        rows = (
            (
                await db.execute(
                    select(BlobDeletion)
                    .where(BlobDeletion.done_at.is_(None), BlobDeletion.attempts < MAX_BLOB_ATTEMPTS)
                    .order_by(BlobDeletion.created_at)
                    .with_for_update(skip_locked=True)
                    .limit(BATCH)
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            try:
                if row.object_key.endswith("/"):
                    await store.delete_prefix(row.object_key)
                else:
                    await store.delete(row.object_key)
            except Exception as exc:  # storage outages are retried on the next run
                row.attempts += 1
                failed += 1
                log.warning("blob_deletion_failed", error_type=type(exc).__name__, attempts=row.attempts)
                continue
            row.done_at = utcnow()
            done += 1
        await db.execute(delete(BlobDeletion).where(BlobDeletion.done_at < utcnow() - timedelta(days=7)))
    return {"deleted": done, "failed": failed}
