"""Logs carry identifiers only: sensitive keys are scrubbed and no HTTP access log is written by the app."""

from __future__ import annotations

import logging

from angel_engine.core.logging import _scrub, configure_logging


def test_sensitive_keys_are_scrubbed() -> None:
    event = _scrub(None, "info", {"event": "x", "query": "jane doe", "Email": "a@b.example", "investigation_id": "1"})
    assert event == {"event": "x", "query": "[scrubbed]", "Email": "[scrubbed]", "investigation_id": "1"}


def test_uvicorn_access_log_is_disabled() -> None:
    access = logging.getLogger("uvicorn.access")
    try:
        configure_logging("INFO", json_output=True)
        assert access.disabled
    finally:
        access.disabled = False
