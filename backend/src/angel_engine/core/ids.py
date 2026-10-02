"""Identifier helpers: RFC 9562 UUIDv7 (time-ordered) and investigation display references."""

from __future__ import annotations

import os
import time
import uuid

_RAND_B_MASK = (1 << 62) - 1


def new_id() -> uuid.UUID:
    """Return a UUIDv7: 48-bit Unix milliseconds, version 7, RFC 4122 variant, 74 random bits."""
    ts_ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    rand_a = (rand >> 62) & 0xFFF
    rand_b = rand & _RAND_B_MASK
    value = ((ts_ms & 0xFFFFFFFFFFFF) << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b
    return uuid.UUID(int=value)


def investigation_ref(year: int, seq: int) -> str:
    """Human-readable investigation reference, e.g. ``AE-2026-000123`` (a label, never an access token)."""
    return f"AE-{year:04d}-{seq:06d}"
