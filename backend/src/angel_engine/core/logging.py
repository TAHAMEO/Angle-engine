"""Structured logging. Logs carry identifiers only — never evidence content, queries or secrets."""

from __future__ import annotations

import logging
import sys
from collections.abc import MutableMapping
from typing import Any

import structlog

_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "new_password",
        "current_password",
        "token",
        "secret",
        "code",
        "totp",
        "authorization",
        "cookie",
        "set-cookie",
        "csrf",
        "api_key",
        "query",
        "text",
        "excerpt",
        "statement",
        "body",
        "email",
        "ip",
        "content",
        "prompt",
        "response",
    }
)


def _scrub(_: Any, __: str, event_dict: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    for key in list(event_dict):
        if key.lower() in _SENSITIVE_KEYS:
            event_dict[key] = "[scrubbed]"
    return event_dict


def configure_logging(level: str = "INFO", json_output: bool = False) -> None:
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level.upper())
    # Uvicorn's access log prints client addresses and full query strings (search terms). Caddy keeps a redacted
    # access log instead, so the application never writes one, whatever flags uvicorn was started with.
    logging.getLogger("uvicorn.access").disabled = True
    renderer: Any = structlog.processors.JSONRenderer() if json_output else structlog.dev.ConsoleRenderer()
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _scrub,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level.upper())),
        cache_logger_on_first_use=True,
    )
