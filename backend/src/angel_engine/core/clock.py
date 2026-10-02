"""Single source of "now" so tests can freeze time without monkeypatching datetime."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

_frozen: datetime | None = None


def utcnow() -> datetime:
    return _frozen if _frozen is not None else datetime.now(UTC)


@contextmanager
def frozen_time(at: datetime) -> Iterator[None]:
    """Freeze :func:`utcnow` (tests only)."""
    global _frozen  # noqa: PLW0603
    previous = _frozen
    _frozen = at
    try:
        yield
    finally:
        _frozen = previous


def advance(delta: timedelta) -> None:
    """Move a frozen clock forward (tests only)."""
    global _frozen  # noqa: PLW0603
    if _frozen is None:
        raise RuntimeError("clock is not frozen")
    _frozen = _frozen + delta
