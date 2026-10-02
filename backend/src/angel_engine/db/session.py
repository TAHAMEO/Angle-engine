"""Async engines and session factories for the application, worker and maintenance roles."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from angel_engine.config import Settings

DbRole = Literal["app", "worker", "maintenance"]


def _engine(url: str, settings: Settings, pool_size: int) -> AsyncEngine:
    return create_async_engine(
        url,
        pool_size=pool_size,
        max_overflow=pool_size,
        pool_pre_ping=True,
        echo=settings.db_echo,
        connect_args={"server_settings": {"application_name": "angel-engine"}},
    )


@dataclass
class Database:
    """Holds one engine per database role (least privilege)."""

    app: AsyncEngine
    worker: AsyncEngine
    maintenance: AsyncEngine

    @classmethod
    def from_settings(cls, settings: Settings) -> Database:
        return cls(
            app=_engine(settings.database_url, settings, settings.db_pool_size),
            worker=_engine(settings.database_url_worker, settings, max(2, settings.db_pool_size // 2)),
            maintenance=_engine(settings.database_url_maintenance, settings, 2),
        )

    def sessionmaker(self, role: DbRole = "app") -> async_sessionmaker[AsyncSession]:
        engine = {"app": self.app, "worker": self.worker, "maintenance": self.maintenance}[role]
        return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)

    async def dispose(self) -> None:
        for engine in (self.app, self.worker, self.maintenance):
            await engine.dispose()

    @asynccontextmanager
    async def session(self, role: DbRole = "app") -> AsyncIterator[AsyncSession]:
        """Session in a transaction: commits on success, rolls back on error."""
        async with self.sessionmaker(role)() as session, session.begin():
            yield session


async def set_investigation_scope(session: AsyncSession, investigation_ids: list[UUID] | tuple[UUID, ...]) -> None:
    """Restrict row-level-security visibility to the given investigations for this transaction."""
    joined = ",".join(str(i) for i in investigation_ids)
    await session.execute(text("SELECT set_config('ae.inv_ids', :ids, true)"), {"ids": joined})


async def allow_status_transition(session: AsyncSession) -> None:
    """Mark this transaction as performing an audited verification-status transition."""
    await session.execute(text("SELECT set_config('ae.transition', 'on', true)"))
