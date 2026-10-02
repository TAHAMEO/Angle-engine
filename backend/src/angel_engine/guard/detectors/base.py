"""Shared primitives for the sensitive-data detectors.

Detectors are pure functions ``detect(scan) -> Iterable[Detection]``. A :class:`Detection` only
carries offsets into the original text plus the replacement string; matched values are never
copied, stored or logged.
"""

from __future__ import annotations

import bisect
import math
import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from angel_engine.guard.types import (
    RedactionContext,
    RedactionKind,
    RedactionMode,
    SensitivityFlag,
)

# Overlap resolution: the higher priority wins; on equal priority the longer span wins.
P_MEDICAL = 100  # whole sentence (restricted mode); contains everything inside it
P_PRIVATE_KEY = 98
P_MRZ = 96
P_WIFI = 94
P_URL_SECRET = 92
P_TOKEN = 90  # structured secrets (AKIA…, ghp_…, JWT, …)
P_CREDENTIAL = 85  # keyword-anchored values (password: …)
P_IBAN = 80
P_CARD = 78
P_NATIONAL_ID = 75
P_EMAIL = 70
P_COORDINATES = 65
P_DOB = 60
P_PLATE = 55
P_PHONE = 50
P_ADDRESS = 45


def placeholder(kind: RedactionKind) -> str:
    """Return the standard placeholder for ``kind``, e.g. ``[REDACTED:payment_card]``."""
    return f"[REDACTED:{kind.value}]"


@dataclass(frozen=True, slots=True)
class Detection:
    """A candidate redaction: offsets into the original text, never the value itself."""

    start: int
    end: int
    kind: RedactionKind
    priority: int
    replacement: str


def detection(start: int, end: int, kind: RedactionKind, priority: int, replacement: str | None = None) -> Detection:
    """Build a :class:`Detection` with the default placeholder unless ``replacement`` is given."""
    return Detection(start, end, kind, priority, placeholder(kind) if replacement is None else replacement)


@dataclass(slots=True)
class Scan:
    """Per-call scanning state shared by all detectors."""

    text: str
    mode: RedactionMode
    context: RedactionContext
    url_spans: list[tuple[int, int]] = field(default_factory=list)
    flags: set[SensitivityFlag] = field(default_factory=set)
    _url_starts: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.url_spans.sort()
        self._url_starts = [s for s, _ in self.url_spans]

    @property
    def restricted(self) -> bool:
        return self.mode is RedactionMode.RESTRICTED

    def inside_url(self, start: int, end: int) -> bool:
        """True when ``[start, end)`` overlaps a URL found in the text."""
        i = bisect.bisect_right(self._url_starts, start) - 1
        if i >= 0 and self.url_spans[i][1] > start:
            return True
        return i + 1 < len(self.url_spans) and self.url_spans[i + 1][0] < end


Detector = Callable[[Scan], Iterable[Detection]]


def words(text: str) -> frozenset[str]:
    """A whitespace-separated word list as a frozenset (keeps long vocabularies compact)."""
    return frozenset(text.split())


def luhn_valid(digits: str) -> bool:
    """Luhn (mod 10) checksum over an ASCII digit string."""
    if not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in Counter(value).values())


def char_classes(value: str) -> int:
    """Number of character classes present (lowercase, uppercase, digit, other)."""
    return (
        any(c.islower() for c in value)
        + any(c.isupper() for c in value)
        + any(c.isdigit() for c in value)
        + any(not c.isalnum() for c in value)
    )


def window_before(text: str, pos: int, size: int, *, same_line: bool = False) -> str:
    """Return up to ``size`` characters before ``pos`` (optionally cut at the last newline)."""
    chunk = text[max(0, pos - size) : pos]
    if same_line:
        nl = chunk.rfind("\n")
        if nl != -1:
            chunk = chunk[nl + 1 :]
    return chunk


def keyword_before(text: str, pos: int, pattern: re.Pattern[str], size: int) -> bool:
    """True when ``pattern`` occurs within ``size`` characters before ``pos``."""
    return pattern.search(window_before(text, pos, size)) is not None


def trie_pattern(words: Iterable[str]) -> str:
    """Compile literal ``words`` into a character-trie alternation (much faster than a flat one).

    A space in a word matches ``\\s+``. The result is a non-capturing group without anchors.
    """
    trie: dict[str, Any] = {}
    for word in words:
        node = trie
        for ch in word:
            node = node.setdefault(ch, {})
        node[""] = {}

    def build(node: dict[str, Any]) -> str:
        terminal = "" in node
        branches = [(r"\s+" if ch == " " else re.escape(ch)) + build(node[ch]) for ch in sorted(k for k in node if k)]
        if not branches:
            return ""
        if len(branches) == 1 and not terminal:
            return branches[0]
        body = "(?:" + "|".join(branches) + ")"
        return body + "?" if terminal else body

    return "(?:" + build(trie) + ")"
