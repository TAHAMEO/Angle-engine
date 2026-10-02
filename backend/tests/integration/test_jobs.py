"""Job queue: claims, retries, dead-lettering, lease reaping, periodic scheduling and the worker loop."""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
from sqlalchemy import select, text, update

from angel_engine.core.clock import utcnow
from angel_engine.db.models import Job, PeriodicSchedule
from angel_engine.jobs import queue as q
from angel_engine.jobs.registry import JobContext, handler
from angel_engine.jobs.worker import Worker

pytestmark = pytest.mark.db
CALLS: list[str] = []


@handler("test.echo")
async def _echo(ctx: JobContext, payload: dict) -> dict:
    CALLS.append(payload["value"])
    await ctx.progress("echoed")
    return {"echo": payload["value"]}


@handler("test.flaky")
async def _flaky(ctx: JobContext, payload: dict) -> dict:
    raise RuntimeError("boom")


@handler("test.permanent")
async def _permanent(ctx: JobContext, payload: dict) -> dict:
    raise q.PermanentJobError("invalid input")


async def _job(services, job_id) -> Job:
    async with services.db.session("worker") as db:
        return (await db.execute(select(Job).where(Job.id == job_id))).scalar_one()


async def test_enqueue_claim_complete_and_idempotency(services):
    async with services.db.session("app") as db:
        job = await q.enqueue(db, queue="egress", kind="test.echo", payload={"value": "a"}, idempotency_key="echo-a")
        again = await q.enqueue(db, queue="egress", kind="test.echo", payload={"value": "a"}, idempotency_key="echo-a")
        assert again.id == job.id
    worker = Worker(services, ["egress"])
    assert await worker.run_until_idle() >= 1
    done = await _job(services, job.id)
    assert done.status == "succeeded" and done.result == {"echo": "a"} and done.progress["stage"] == "echoed"


async def test_retries_then_dead_letter(services):
    async with services.db.session("app") as db:
        job = await q.enqueue(db, queue="ai", kind="test.flaky", max_attempts=2)
    worker = Worker(services, ["ai"])
    await worker.run_until_idle()
    first = await _job(services, job.id)
    assert first.status == "queued" and first.attempts == 1 and first.run_after > utcnow()
    async with services.db.session("worker") as db:
        await db.execute(update(Job).where(Job.id == job.id).values(run_after=utcnow()))
    await worker.run_until_idle()
    assert (await _job(services, job.id)).status == "dead"


async def test_permanent_errors_are_not_retried(services):
    async with services.db.session("app") as db:
        job = await q.enqueue(db, queue="ai", kind="test.permanent")
    await Worker(services, ["ai"]).run_until_idle()
    dead = await _job(services, job.id)
    assert dead.status == "dead" and dead.attempts == 1 and "invalid input" in (dead.last_error or "")


async def test_expired_leases_are_reaped(services):
    async with services.db.session("app") as db:
        job = await q.enqueue(db, queue="analysis", kind="test.echo", payload={"value": "lease"})
    claimed = await q.claim(services.db.worker, ["analysis"], "crashed-worker", lease_s=1)
    assert [c.id for c in claimed] == [job.id]
    async with services.db.session("worker") as db:
        await db.execute(update(Job).where(Job.id == job.id).values(lease_expires_at=utcnow() - timedelta(seconds=5)))
    assert await q.reap_expired_leases(services.db.worker) >= 1
    assert (await _job(services, job.id)).status == "queued"
    assert not await q.heartbeat(services.db.worker, job.id, "crashed-worker")


async def test_periodic_schedule_enqueues_once_per_slot(services):
    async with services.db.session("maintenance") as db:
        await db.execute(update(PeriodicSchedule).values(enabled=False))
        db.add(
            PeriodicSchedule(
                name="test_tick",
                queue="maintenance",
                kind="test.echo",
                every_seconds=3600,
                next_run_at=utcnow() - timedelta(seconds=1),
                enabled=True,
            )
        )
    results = await asyncio.gather(q.schedule_periodic(services.db.worker), q.schedule_periodic(services.db.worker))
    assert sum(results) == 1
    async with services.db.session("worker") as db:
        count = (
            await db.execute(text("SELECT count(*) FROM jobs WHERE idempotency_key LIKE 'periodic:test_tick:%'"))
        ).scalar_one()
        assert count == 1
        await db.execute(text("DELETE FROM periodic_schedules WHERE name = 'test_tick'"))
        await db.execute(text("DELETE FROM jobs WHERE idempotency_key LIKE 'periodic:test_tick:%'"))
    async with services.db.session("maintenance") as db:
        await db.execute(update(PeriodicSchedule).values(enabled=True))
