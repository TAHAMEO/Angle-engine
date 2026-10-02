"""PostgreSQL job queue: transactional enqueue, SKIP LOCKED claims, leases, retries and dead-lettering."""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from angel_engine.core.clock import utcnow
from angel_engine.core.enums import JobQueue, JobStatus
from angel_engine.db.models import Job, PeriodicSchedule

NOTIFY_CHANNEL = "ae_jobs"
MAX_BACKOFF_S = 600


class PermanentJobError(Exception):
    """A failure that must not be retried (validation, policy refusal, unsupported input)."""


async def enqueue(
    db: AsyncSession,
    *,
    queue: JobQueue | str,
    kind: str,
    payload: dict[str, Any] | None = None,
    investigation_id: uuid.UUID | None = None,
    priority: int = 0,
    run_after: datetime | None = None,
    idempotency_key: str | None = None,
    max_attempts: int = 5,
    created_by: uuid.UUID | None = None,
) -> Job:
    """Enqueue within the caller's transaction; workers are notified only if it commits."""
    if idempotency_key is not None:
        existing = (await db.execute(select(Job).where(Job.idempotency_key == idempotency_key))).scalar_one_or_none()
        if existing is not None:
            return existing
    job = Job(
        queue=str(queue),
        kind=kind,
        payload=payload or {},
        investigation_id=investigation_id,
        priority=priority,
        run_after=run_after or utcnow(),
        idempotency_key=idempotency_key,
        max_attempts=max_attempts,
        created_by=created_by,
        status=JobStatus.QUEUED.value,
        attempts=0,
        progress={},
    )
    db.add(job)
    await db.flush()
    await db.execute(text("SELECT pg_notify(:channel, :queue)"), {"channel": NOTIFY_CHANNEL, "queue": str(queue)})
    return job


@dataclass(frozen=True, slots=True)
class ClaimedJob:
    id: uuid.UUID
    queue: str
    kind: str
    payload: dict[str, Any]
    investigation_id: uuid.UUID | None
    attempts: int
    max_attempts: int
    created_by: uuid.UUID | None


_CLAIM_SQL = text(
    """
    WITH c AS (
        SELECT id FROM jobs
         WHERE status = 'queued' AND queue = ANY(:queues) AND run_after <= now()
         ORDER BY priority DESC, run_after, id
         LIMIT :n
         FOR UPDATE SKIP LOCKED
    )
    UPDATE jobs j
       SET status = 'running', attempts = j.attempts + 1, lease_owner = :worker,
           lease_expires_at = now() + make_interval(secs => :lease), heartbeat_at = now(),
           started_at = coalesce(j.started_at, now())
      FROM c
     WHERE j.id = c.id
    RETURNING j.id, j.queue, j.kind, j.payload, j.investigation_id, j.attempts, j.max_attempts, j.created_by
    """
)


async def claim(
    engine: AsyncEngine, queues: list[str], worker_id: str, *, n: int = 1, lease_s: int = 120
) -> list[ClaimedJob]:
    async with engine.begin() as conn:
        rows = (await conn.execute(_CLAIM_SQL, {"queues": queues, "worker": worker_id, "n": n, "lease": lease_s})).all()
    return [
        ClaimedJob(r.id, r.queue, r.kind, r.payload or {}, r.investigation_id, r.attempts, r.max_attempts, r.created_by)
        for r in rows
    ]


async def heartbeat(engine: AsyncEngine, job_id: uuid.UUID, worker_id: str, *, lease_s: int = 120) -> bool:
    async with engine.begin() as conn:
        result = await conn.execute(
            text(
                "UPDATE jobs SET heartbeat_at = now(), lease_expires_at = now() + make_interval(secs => :lease) "
                "WHERE id = :id AND lease_owner = :worker AND status = 'running'"
            ),
            {"id": job_id, "worker": worker_id, "lease": lease_s},
        )
    return bool(getattr(result, "rowcount", 0))


async def set_progress(engine: AsyncEngine, job_id: uuid.UUID, progress: dict[str, Any]) -> None:
    async with engine.begin() as conn:
        await conn.execute(update(Job).where(Job.id == job_id).values(progress=progress))


async def complete(engine: AsyncEngine, job_id: uuid.UUID, worker_id: str, result: dict[str, Any] | None) -> bool:
    async with engine.begin() as conn:
        res = await conn.execute(
            update(Job)
            .where(Job.id == job_id, Job.lease_owner == worker_id, Job.status == JobStatus.RUNNING.value)
            .values(
                status=JobStatus.SUCCEEDED.value,
                finished_at=utcnow(),
                result=result,
                lease_owner=None,
                lease_expires_at=None,
            )
        )
    return bool(getattr(res, "rowcount", 0))


def backoff_seconds(attempts: int, *, base: float = 5.0) -> float:
    return float(min(MAX_BACKOFF_S, base * (2 ** max(0, attempts - 1))) * random.uniform(0.5, 1.0))  # noqa: S311


async def fail(engine: AsyncEngine, job: ClaimedJob, worker_id: str, error: str, *, permanent: bool) -> str:
    dead = permanent or job.attempts >= job.max_attempts
    values: dict[str, Any] = {"last_error": error[:500], "lease_owner": None, "lease_expires_at": None}
    if dead:
        values.update(status=JobStatus.DEAD.value, finished_at=utcnow())
    else:
        values.update(
            status=JobStatus.QUEUED.value, run_after=utcnow() + timedelta(seconds=backoff_seconds(job.attempts))
        )
    async with engine.begin() as conn:
        await conn.execute(update(Job).where(Job.id == job.id, Job.lease_owner == worker_id).values(**values))
    return str(values["status"])


async def reap_expired_leases(engine: AsyncEngine) -> int:
    async with engine.begin() as conn:
        result = await conn.execute(
            text(
                "UPDATE jobs SET status = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'queued' END, "
                "lease_owner = NULL, lease_expires_at = NULL, last_error = 'lease expired', run_after = now() "
                "WHERE status = 'running' AND lease_expires_at < now()"
            )
        )
    return int(getattr(result, "rowcount", 0) or 0)


async def schedule_periodic(engine: AsyncEngine) -> int:
    """Enqueue due periodic jobs exactly once per slot (safe with several workers)."""
    created = 0
    async with AsyncSession(engine, expire_on_commit=False) as db, db.begin():
        due = (
            (
                await db.execute(
                    select(PeriodicSchedule)
                    .where(PeriodicSchedule.enabled.is_(True), PeriodicSchedule.next_run_at <= utcnow())
                    .with_for_update(skip_locked=True)
                )
            )
            .scalars()
            .all()
        )
        for sched in due:
            slot = int(sched.next_run_at.timestamp()) // max(1, sched.every_seconds)
            await enqueue(
                db,
                queue=sched.queue,
                kind=sched.kind,
                payload={"schedule": sched.name},
                idempotency_key=f"periodic:{sched.name}:{slot}",
                max_attempts=3,
            )
            now = utcnow()
            nxt = sched.next_run_at + timedelta(seconds=sched.every_seconds)
            sched.next_run_at = nxt if nxt > now else now + timedelta(seconds=sched.every_seconds)
            sched.last_run_at = now
            created += 1
    return created
