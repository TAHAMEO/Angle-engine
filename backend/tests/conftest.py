"""Shared fixtures. Database tests run against the local PostgreSQL test database (scripts/dev-postgres.sh)."""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio

from angel_engine.app_state import Services, build_services
from angel_engine.config import Settings
from angel_engine.crypto.keys import MemoryKeyring
from angel_engine.infra.ratelimit.gcra import MemoryRateLimiter

BACKEND = pathlib.Path(__file__).resolve().parents[1]
TEST_DB = os.environ.get("ANGEL_TEST_DB", "angel_engine_test")
PG_PORT = os.environ.get("ANGEL_PG_PORT", "54329")
ORIGIN = "https://testserver"


def db_url(role: str) -> str:
    return f"postgresql+asyncpg://{role}:{role}_dev@127.0.0.1:{PG_PORT}/{TEST_DB}"


def _alembic(*args: str) -> None:
    env = dict(os.environ, ANGEL_MIGRATION_URL=db_url("ae_owner"))
    subprocess.run(
        [sys.executable, "-m", "alembic", *args], cwd=BACKEND, env=env, check=True, capture_output=True, timeout=180
    )


@pytest.fixture(scope="session")
def migrated_db() -> None:
    """Recreate the test schema from scratch (exercises downgrade + upgrade)."""
    try:
        _alembic("downgrade", "base")
        _alembic("upgrade", "head")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        detail = getattr(exc, "stderr", b"") or b""
        pytest.skip(f"PostgreSQL test database unavailable: {detail.decode(errors='ignore')[-400:]}")


@pytest.fixture(scope="session")
def settings(migrated_db: None) -> Settings:
    return Settings(
        env="test",
        public_origin=ORIGIN,
        database_url=db_url("ae_app"),
        database_url_worker=db_url("ae_worker"),
        database_url_maintenance=db_url("ae_maintenance"),
        database_url_owner=db_url("ae_owner"),
        redis_url=None,
        cookie_secure=True,
        mfa_required=False,
        scanner="builtin",
        face_detector="fixture",
        connector_mode="fixtures",
        ai_provider="fake",
        image_sandbox=False,
        storage_path=BACKEND / "var" / "test-storage",
    )


@pytest_asyncio.fixture(scope="session")
async def services(settings: Settings) -> AsyncIterator[Services]:
    from angel_engine.bootstrap import install_extras

    svc = build_services(settings, keys=MemoryKeyring())
    install_extras(svc)
    yield svc
    await svc.close()


@pytest_asyncio.fixture(scope="session")
async def app(services: Services):  # type: ignore[no-untyped-def]
    from angel_engine.main import create_app, sync_legal_documents

    application = create_app(services=services)
    await sync_legal_documents(services)
    return application


@pytest_asyncio.fixture
async def client(app, services: Services) -> AsyncIterator[httpx.AsyncClient]:  # type: ignore[no-untyped-def]
    if isinstance(services.limiter, MemoryRateLimiter):
        services.limiter._tat.clear()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=ORIGIN, headers={"Origin": ORIGIN}
    ) as c:
        yield c


@pytest_asyncio.fixture
async def anon_client(app, services: Services) -> AsyncIterator[httpx.AsyncClient]:  # type: ignore[no-untyped-def]
    """A second, independent browser."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=ORIGIN, headers={"Origin": ORIGIN}
    ) as c:
        yield c
