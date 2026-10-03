"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import select

from angel_engine import __version__
from angel_engine.api.middleware import SecurityMiddleware
from angel_engine.app_state import Services, build_services
from angel_engine.config import Settings, get_settings
from angel_engine.core.logging import configure_logging
from angel_engine.core.problems import install_problem_handlers
from angel_engine.db.models import LegalDocument
from angel_engine.legal.documents import load_documents


async def sync_legal_documents(svc: Services) -> None:
    """Record each legal document version (acceptances reference these rows)."""
    from datetime import UTC, datetime

    async with svc.db.session("app") as db:
        existing = {(k, v) for k, v in (await db.execute(select(LegalDocument.kind, LegalDocument.version))).all()}
        for doc in load_documents().values():
            if (doc.kind, doc.version) not in existing:
                db.add(
                    LegalDocument(
                        kind=doc.kind,
                        version=doc.version,
                        sha256=doc.sha256,
                        effective_at=datetime.fromisoformat(doc.effective).replace(tzinfo=UTC),
                    )
                )


def create_app(settings: Settings | None = None, services: Services | None = None) -> FastAPI:
    settings = settings or (services.settings if services else get_settings())
    configure_logging(settings.log_level, settings.log_json)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        svc = services or build_services(settings)
        app.state.services = svc
        from angel_engine.bootstrap import install_extras

        install_extras(svc)
        await sync_legal_documents(svc)
        if svc.settings.is_production:
            from angel_engine.demo.safety import refuse_demo_accounts

            await refuse_demo_accounts(svc)
        try:
            yield
        finally:
            if services is None:
                await svc.close()

    docs_enabled = not settings.is_production
    app = FastAPI(
        title="Angel Engine API",
        version=__version__,
        description="Lawful, privacy-first OSINT evidence management. All endpoints are under /api/v1.",
        lifespan=lifespan,
        docs_url="/api/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/api/v1/openapi.json" if docs_enabled else None,
        redirect_slashes=False,
    )
    if services is not None:
        app.state.services = services  # available before lifespan runs (tests, embedded use)
    install_problem_handlers(app)
    app.add_middleware(SecurityMiddleware, public_origin=settings.public_origin, hsts=settings.is_production)
    from angel_engine.api.v1 import build_router

    app.include_router(build_router())
    return app
