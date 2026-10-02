"""Liveness and readiness probes (no sensitive details)."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from angel_engine.api.deps import ServicesDep
from angel_engine.infra.ratelimit.gcra import Limit

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live", openapi_extra={"x-public": True})
async def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready", openapi_extra={"x-public": True})
async def ready(svc: ServicesDep) -> JSONResponse:
    checks: dict[str, str] = {}
    try:
        async with svc.db.app.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "unavailable"
    try:
        await svc.limiter.hit("health:probe", Limit(1000, 1))
        checks["rate_limiter"] = "ok"
    except Exception:
        checks["rate_limiter"] = "unavailable"
    try:
        svc.keys.active_kek()
        checks["keyring"] = "ok"
    except Exception:
        checks["keyring"] = "unavailable"
    healthy = all(v == "ok" for v in checks.values())
    return JSONResponse(
        {"status": "ok" if healthy else "degraded", "checks": checks}, status_code=200 if healthy else 503
    )
