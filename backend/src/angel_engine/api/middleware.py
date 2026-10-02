"""ASGI middleware: request ids, security headers and Origin enforcement for state-changing requests."""

from __future__ import annotations

import secrets

from starlette.types import ASGIApp, Message, Receive, Scope, Send

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
#: Public endpoints that browsers call without an Origin header (CSP violation reports).
ORIGIN_EXEMPT_PATHS = frozenset({"/api/v1/security/csp-reports"})

API_SECURITY_HEADERS: list[tuple[bytes, bytes]] = [
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"x-frame-options", b"DENY"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"),
]


class SecurityMiddleware:
    """Adds a request id and security headers; rejects cross-origin state-changing requests early."""

    def __init__(self, app: ASGIApp, *, public_origin: str, hsts: bool) -> None:
        self.app = app
        self.public_origin = public_origin.rstrip("/")
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = secrets.token_hex(8)
        scope.setdefault("state", {})["request_id"] = request_id
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        method = scope.get("method", "GET")
        path = scope.get("path", "")

        if method not in SAFE_METHODS and path not in ORIGIN_EXEMPT_PATHS and not self._same_origin(headers):
            await self._reject(send, request_id)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                raw = list(message.get("headers", []))
                present = {k.lower() for k, _ in raw}
                for name, value in API_SECURITY_HEADERS:
                    if name not in present:
                        raw.append((name, value))
                if b"cache-control" not in present:
                    raw.append((b"cache-control", b"no-store"))
                if self.hsts:
                    raw.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                raw.append((b"x-request-id", request_id.encode()))
                message["headers"] = raw
            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _same_origin(self, headers: dict[str, str]) -> bool:
        origin = headers.get("origin")
        if origin:
            return origin.rstrip("/") == self.public_origin
        return headers.get("sec-fetch-site") == "same-origin"

    async def _reject(self, send: Send, request_id: str) -> None:
        body = (
            b'{"type":"/problems/csrf-failed","title":"The request could not be verified","status":403,'
            b'"code":"origin_mismatch","request_id":"' + request_id.encode() + b'"}'
        )
        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    (b"content-type", b"application/problem+json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"cache-control", b"no-store"),
                    (b"x-request-id", request_id.encode()),
                    *API_SECURITY_HEADERS,
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
