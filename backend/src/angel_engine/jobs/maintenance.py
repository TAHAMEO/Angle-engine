"""Platform maintenance jobs: session cleanup, audit anchoring, key rotation."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import structlog
from sqlalchemy import delete, text

from angel_engine.audit.chain import AuditEvent, append_now, verify_chain, write_anchor
from angel_engine.core.clock import utcnow
from angel_engine.db.models import IdempotencyKey, UserSession
from angel_engine.jobs.registry import JobContext, handler

log = structlog.get_logger(__name__)


@handler("maintenance.session_cleanup")
async def session_cleanup(ctx: JobContext, payload: dict[str, Any]) -> dict[str, Any]:
    cutoff = utcnow() - timedelta(days=7)
    async with ctx.services.db.session("maintenance") as db:
        sessions = await db.execute(
            delete(UserSession).where((UserSession.revoked_at < cutoff) | (UserSession.absolute_expires_at < cutoff))
        )
        keys = await db.execute(delete(IdempotencyKey).where(IdempotencyKey.expires_at < utcnow()))
        jobs = await db.execute(
            text(
                "DELETE FROM jobs WHERE (status = 'succeeded' AND finished_at < now() - interval '7 days') "
                "OR (status IN ('dead','cancelled') AND finished_at < now() - interval '30 days')"
            )
        )
    return {
        "sessions": getattr(sessions, "rowcount", 0),
        "idempotency_keys": getattr(keys, "rowcount", 0),
        "jobs": getattr(jobs, "rowcount", 0),
    }


@handler("audit.anchor_and_verify")
async def anchor_and_verify(ctx: JobContext, payload: dict[str, Any]) -> dict[str, Any]:
    svc = ctx.services
    async with svc.db.session("maintenance") as db:
        result = await verify_chain(db, svc.audit_key)
        anchor = await write_anchor(db, svc.keys.secret("anchor"))
        await append_now(
            db,
            svc.audit_key,
            [
                AuditEvent(
                    action="audit.chain_verified",
                    actor_type="system",
                    outcome="success" if result.ok else "failure",
                    details={
                        "checked": result.checked,
                        "ok": result.ok,
                        "anchored_seq": anchor.seq if anchor else None,
                    },
                )
            ],
        )
    if not result.ok:
        log.error("audit_chain_broken", first_broken_seq=result.first_broken_seq, reason=result.reason)
    return {"ok": result.ok, "checked": result.checked}


@handler("keys.destroy_old_ip_keys")
async def destroy_old_ip_keys(ctx: JobContext, payload: dict[str, Any]) -> dict[str, Any]:
    cutoff = (utcnow() - timedelta(days=90)).strftime("%Y-%m")
    removed = ctx.services.keys.destroy_ip_keys_before(cutoff)
    return {"destroyed": removed}


@handler("keys.rotate_kek")
async def rotate_kek(ctx: JobContext, payload: dict[str, Any]) -> dict[str, Any]:
    svc = ctx.services
    new_id = svc.keys.rotate_kek()
    async with svc.db.session("maintenance") as db:
        rewrapped = await svc.vault.rewrap_all(db)
        await append_now(
            db,
            svc.audit_key,
            [
                AuditEvent(
                    action="keys.kek_rotated",
                    actor_type="system",
                    details={"kek_id": new_id, "rewrapped": rewrapped},
                )
            ],
        )
    return {"kek_id": new_id, "rewrapped": rewrapped}
