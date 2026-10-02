"""Deterministic JSON encoding (sorted keys, no whitespace) for hashing and MACs."""

from __future__ import annotations

import json
import uuid
from datetime import date, datetime
from enum import Enum
from typing import Any


def _default(value: Any) -> Any:
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, set | frozenset | tuple):
        return sorted(value) if isinstance(value, set | frozenset) else list(value)
    raise TypeError(f"not JSON serializable: {type(value).__name__}")


def canonical_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_default)


def canonical_bytes(value: Any) -> bytes:
    return canonical_dumps(value).encode("utf-8")


def json_dumps(value: Any) -> str:
    """Compact JSON for storage (stable key order is not required)."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=_default)
