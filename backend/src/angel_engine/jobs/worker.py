"""Worker process: LISTEN/NOTIFY wake-ups, per-queue consumers, lease heartbeats, reaper and scheduler."""

from __future__ import annotations

import asyncio
import contextlib
import os
import secrets
import signal
from typing import Any

import asyncpg
import structlog

from angel_engine.app_state import Services
from angel_engine.jobs import queue as q
from angel_engine.jobs.registry import JobContext, get_handler, load_handlers

log = structlog.get_logger(__name__)


def _dsn(sqlalchemy_url: str) -> str:
    return sqlalchemy_url.replace("postgresql+asyncpg://", "postgresql://", 1)


class Worker:
    def __init__(
        self, services: Services, queues: list[str], *, concurrency: int = 2, lease_s: int = 180, poll_s: float = 5.0
    ) -> None:
        self.svc = services
        self.queues = queues
        self.concurrency = concurrency
        self.lease_s = lease_s
        self.poll_s = poll_s
        self.worker_id = f"{os.uname().nodename}:{os.getpid()}:{secrets.token_hex(3)}"
        self._wake = asyncio.Event()
        self._stop = asyncio.Event()
        self._engine = services.db.worker

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    async def run(self) -> None:
        load_handlers()
        log.info("worker_started", queues=self.queues, worker=self.worker_id)
        async with asyncio.TaskGroup() as tg:
            tg.create_task(self._listen())
            tg.create_task(self._housekeeping())
            for _ in range(self.concurrency):
                tg.create_task(self._consume())
        log.info("worker_stopped", worker=self.worker_id)

    async def run_until_idle(self, *, max_jobs: int = 1000) -> int:
        """Process queued jobs until none are runnable (tests and one-shot tooling)."""
        load_handlers()
        processed = 0
        while processed < max_jobs:
            jobs = await q.claim(self._engine, self.queues, self.worker_id, n=1, lease_s=self.lease_s)
            if not jobs:
                return processed
            await self._execute(jobs[0])
            processed += 1
        return processed

    async def _listen(self) -> None:
        while not self._stop.is_set():
            conn: Any = None
            try:
                conn = await asyncpg.connect(_dsn(self.svc.settings.database_url_worker))
                await conn.add_listener(q.NOTIFY_CHANNEL, lambda *_: self._wake.set())
                await self._stop.wait()
            except (OSError, asyncpg.PostgresError) as exc:
                log.warning("worker_listen_failed", error_type=type(exc).__name__)
                await asyncio.sleep(2)
            finally:
                if conn is not None:
                    with contextlib.suppress(Exception):
                        await conn.close()

    async def _housekeeping(self) -> None:
        while not self._stop.is_set():
            try:
                await q.reap_expired_leases(self._engine)
                if await q.schedule_periodic(self._engine):
                    self._wake.set()
            except Exception as exc:  # keep the worker alive
                log.warning("worker_housekeeping_failed", error_type=type(exc).__name__)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=15)

    async def _consume(self) -> None:
        while not self._stop.is_set():
            jobs = await q.claim(self._engine, self.queues, self.worker_id, n=1, lease_s=self.lease_s)
            if not jobs:
                self._wake.clear()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._wake.wait(), timeout=self.poll_s)
                continue
            await self._execute(jobs[0])

    async def _execute(self, job: q.ClaimedJob) -> None:
        handler = get_handler(job.kind)
        if handler is None:
            await q.fail(self._engine, job, self.worker_id, f"no handler for {job.kind}", permanent=True)
            return

        async def progress(data: dict[str, Any]) -> None:
            await q.set_progress(self._engine, job.id, data)

        ctx = JobContext(self.svc, job, self.worker_id, progress)
        beat = asyncio.create_task(self._heartbeat(job))
        try:
            result = await handler(ctx, job.payload)
        except q.PermanentJobError as exc:
            status = await q.fail(self._engine, job, self.worker_id, f"{type(exc).__name__}: {exc}", permanent=True)
            log.warning("job_failed", kind=job.kind, job_id=str(job.id), status=status)
        except Exception as exc:
            status = await q.fail(self._engine, job, self.worker_id, type(exc).__name__, permanent=False)
            log.warning("job_error", kind=job.kind, job_id=str(job.id), status=status, error_type=type(exc).__name__)
        else:
            await q.complete(self._engine, job.id, self.worker_id, result)
        finally:
            beat.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await beat

    async def _heartbeat(self, job: q.ClaimedJob) -> None:
        while True:
            await asyncio.sleep(self.lease_s / 3)
            if not await q.heartbeat(self._engine, job.id, self.worker_id, lease_s=self.lease_s):
                log.warning("job_lease_lost", job_id=str(job.id))
                return


def install_signal_handlers(worker: Worker) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, worker.stop)
