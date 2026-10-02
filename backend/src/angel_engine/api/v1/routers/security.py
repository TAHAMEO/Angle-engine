"""Content-Security-Policy violation reports from browsers (counted, never stored with content)."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

import structlog
from fastapi import APIRouter, Request, Response

from angel_engine.api.deps import ServicesDep, enforce_rate_limit, ip_pseudonym
from angel_engine.infra.ratelimit.gcra import CSP_REPORT_IP

router = APIRouter(prefix="/security", tags=["security"])
log = structlog.get_logger(__name__)
MAX_REPORT_BYTES = 16 * 1024


@router.post("/csp-reports", status_code=204, openapi_extra={"x-public": True})
async def csp_report(request: Request, svc: ServicesDep) -> Response:
    await enforce_rate_limit(svc, f"csp:{ip_pseudonym(request)}", CSP_REPORT_IP)
    raw = await request.body()
    if len(raw) <= MAX_REPORT_BYTES:
        try:
            payload = json.loads(raw or b"{}")
        except ValueError:
            payload = {}
        reports = payload if isinstance(payload, list) else [payload]
        for item in reports[:10]:
            body = item.get("csp-report") or item.get("body") or {}
            if isinstance(body, dict):
                blocked = str(body.get("blocked-uri") or body.get("blockedURL") or "")
                log.warning(
                    "csp_violation",
                    directive=str(body.get("violated-directive") or body.get("effectiveDirective") or "")[:80],
                    blocked_host=urlsplit(blocked).hostname or blocked[:20],
                )
    return Response(status_code=204)
