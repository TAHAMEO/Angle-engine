"""Keyset pagination with HMAC-signed, opaque cursors (clients cannot forge or tamper with them)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from angel_engine.core.problems import BadRequest

MAX_LIMIT = 100


@dataclass(frozen=True, slots=True)
class CursorCodec:
    key: bytes

    def encode(self, payload: dict[str, Any]) -> str:
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str).encode()
        sig = hmac.new(self.key, raw, hashlib.sha256).digest()[:16]
        return base64.urlsafe_b64encode(sig + raw).decode().rstrip("=")

    def decode(self, cursor: str, *, filter_hash: str) -> dict[str, Any]:
        try:
            blob = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
            sig, raw = blob[:16], blob[16:]
            expected = hmac.new(self.key, raw, hashlib.sha256).digest()[:16]
            if not hmac.compare_digest(sig, expected):
                raise ValueError("bad signature")
            payload: dict[str, Any] = json.loads(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            raise BadRequest("Invalid pagination cursor.", code="invalid_cursor") from exc
        if payload.get("f") != filter_hash:
            raise BadRequest("The cursor does not match the current filters.", code="invalid_cursor")
        return payload


def filter_fingerprint(filters: dict[str, Any]) -> str:
    raw = json.dumps(filters, sort_keys=True, default=str, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def clamp_limit(limit: int | None, default: int = 50) -> int:
    if limit is None:
        return default
    return max(1, min(MAX_LIMIT, limit))
