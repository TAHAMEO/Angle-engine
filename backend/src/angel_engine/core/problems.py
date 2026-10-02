"""RFC 9457 problem details for every error the API returns.

Error bodies never echo submitted values (validation errors list field locations and messages only)
and never include stack traces or internal identifiers beyond the request id.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = structlog.get_logger(__name__)

PROBLEM_JSON = "application/problem+json"


def problem_type(slug: str) -> str:
    return f"/problems/{slug}"


class ProblemError(Exception):
    """Base class for errors rendered as ``application/problem+json``."""

    status: int = 400
    slug: str = "bad-request"
    title: str = "Bad request"

    def __init__(self, detail: str | None = None, *, code: str | None = None, **extra: Any) -> None:
        super().__init__(detail or self.title)
        self.detail = detail
        self.code = code or self.slug.replace("-", "_")
        self.extra = extra
        self.headers: dict[str, str] = {}

    def body(self, request_id: str | None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "type": problem_type(self.slug),
            "title": self.title,
            "status": self.status,
            "code": self.code,
        }
        if self.detail:
            payload["detail"] = self.detail
        if request_id:
            payload["request_id"] = request_id
            payload["instance"] = f"urn:angel-engine:request:{request_id}"
        payload.update(self.extra)
        return payload


class BadRequest(ProblemError):
    pass


class ValidationProblem(ProblemError):
    status, slug, title = 422, "validation-error", "The request is not valid"


class Unauthenticated(ProblemError):
    status, slug, title = 401, "unauthenticated", "Authentication required"


class MfaRequired(ProblemError):
    status, slug, title = 401, "mfa-required", "Multi-factor authentication required"


class ReauthRequired(ProblemError):
    status, slug, title = 401, "reauth-required", "Please confirm your password to continue"


class Forbidden(ProblemError):
    status, slug, title = 403, "forbidden", "You do not have permission to perform this action"


class CsrfFailed(ProblemError):
    status, slug, title = 403, "csrf-failed", "The request could not be verified"


class NotFound(ProblemError):
    status, slug, title = 404, "not-found", "Not found or no access"


class Conflict(ProblemError):
    status, slug, title = 409, "conflict", "The request conflicts with the current state"


class ConflictState(ProblemError):
    status, slug, title = 409, "conflict-state", "This action is not allowed in the current state"


class PayloadTooLarge(ProblemError):
    status, slug, title = 413, "payload-too-large", "The upload is too large"


class UnsupportedMedia(ProblemError):
    status, slug, title = 415, "unsupported-media", "This file type is not supported"


class PreconditionFailed(ProblemError):
    status, slug, title = 412, "precondition-failed", "The resource was modified by someone else"


class PreconditionRequired(ProblemError):
    status, slug, title = 428, "precondition-required", "An If-Match header is required"


class RateLimited(ProblemError):
    status, slug, title = 429, "rate-limited", "Too many requests"

    def __init__(self, retry_after: int, detail: str | None = None) -> None:
        super().__init__(detail or "Please wait before trying again.", retry_after=retry_after)
        self.headers = {"Retry-After": str(max(1, retry_after))}


class PolicyRefused(ProblemError):
    """Acceptable-use refusal carrying the decision and lawful alternatives."""

    status, slug, title = 422, "policy-refused", "Angel Engine can't help with this request"

    def __init__(self, detail: str, *, policy: dict[str, Any]) -> None:
        super().__init__(detail, policy=policy)


class ServiceUnavailable(ProblemError):
    status, slug, title = 503, "service-unavailable", "A required service is unavailable"


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def _problem_response(status: int, body: dict[str, Any], headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(body, status_code=status, media_type=PROBLEM_JSON, headers=headers)


def install_problem_handlers(app: FastAPI) -> None:
    @app.exception_handler(ProblemError)
    async def _problem(request: Request, exc: ProblemError) -> JSONResponse:
        return _problem_response(exc.status, exc.body(_request_id(request)), exc.headers or None)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {"loc": [str(p) for p in err.get("loc", ())], "msg": err.get("msg", ""), "type": err.get("type", "")}
            for err in exc.errors()
        ]
        problem = ValidationProblem(errors=errors)
        return _problem_response(problem.status, problem.body(_request_id(request)))

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        mapping: dict[int, type[ProblemError]] = {
            401: Unauthenticated,
            403: Forbidden,
            404: NotFound,
            409: Conflict,
            413: PayloadTooLarge,
            415: UnsupportedMedia,
            422: ValidationProblem,
        }
        cls = mapping.get(exc.status_code)
        if cls is not None:
            problem: ProblemError = cls()
        else:
            problem = ProblemError()
            problem.status = exc.status_code
            problem.title = "Request failed"
        return _problem_response(problem.status, problem.body(_request_id(request)))

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.error("unhandled_error", error_type=type(exc).__name__, path=request.url.path)
        problem = ProblemError("An unexpected error occurred.")
        problem.status, problem.slug, problem.title = 500, "internal-error", "Internal error"
        problem.code = "internal_error"
        return _problem_response(500, problem.body(_request_id(request)))
