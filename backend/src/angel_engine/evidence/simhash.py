"""Keyed 64-bit SimHash for near-duplicate / syndicated-copy detection.

Shingles are hashed with a MAC derived from the investigation key, so the stored fingerprints reveal
nothing about the text and stop being comparable once the key is destroyed.
"""

from __future__ import annotations

import re
import unicodedata

from angel_engine.crypto.envelope import FieldCipher
from angel_engine.crypto.keyed_hash import SIMHASH_PURPOSE

_WORD = re.compile(r"[^\W_]+", re.UNICODE)
MIN_WORDS = 200  # shorter texts produce unreliable fingerprints
NEAR_DUPLICATE_BITS = 3  # Hamming distance at or below which two texts count as the same copy


def words(text: str) -> list[str]:
    return _WORD.findall(unicodedata.normalize("NFKC", text).casefold())


def keyed_simhash(cipher: FieldCipher, text: str, *, shingle: int = 3) -> int | None:
    tokens = words(text)
    if len(tokens) < MIN_WORDS:
        return None
    weights = [0] * 64
    for i in range(len(tokens) - shingle + 1):
        digest = int.from_bytes(cipher.mac(SIMHASH_PURPOSE, " ".join(tokens[i : i + shingle]))[:8], "big")
        for bit in range(64):
            weights[bit] += 1 if digest >> bit & 1 else -1
    value = sum(1 << bit for bit in range(64) if weights[bit] > 0)
    return value - (1 << 64) if value >= 1 << 63 else value  # store as signed BIGINT


def distance(a: int, b: int) -> int:
    return ((a ^ b) & ((1 << 64) - 1)).bit_count()
