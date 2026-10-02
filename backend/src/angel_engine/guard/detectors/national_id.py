"""National identifiers (US SSN, UK NINO, Canadian SIN), passport numbers in context and ICAO MRZ.

Keyword-gated identifiers are searched keyword-first: the number must start within ~25 characters
after the keyword.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from angel_engine.guard.detectors.base import (
    P_MRZ,
    P_NATIONAL_ID,
    Detection,
    Scan,
    detection,
    luhn_valid,
    trie_pattern,
)
from angel_engine.guard.types import RedactionKind

_WINDOW = 25

_SSN_DASHED = re.compile(r"\d{3}-\d{2}-\d{4}")
_SSN_LOOSE = re.compile(r"(?<![\d-])\d{3}[ .-]?\d{2}[ .-]?\d{4}(?![\d-])")
_SSN_KEYWORD = re.compile(
    r"\b" + trie_pattern(("ssn", "social security", "ss#", "ss #", "ss no")) + r"(?![^\W\d_])",
    re.IGNORECASE,
)

_NINO = re.compile(
    r"(?<![A-Za-z0-9])(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]"
    r"\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D](?![A-Za-z0-9])",
    re.IGNORECASE,
)
_NINO_KEYWORD = re.compile(
    r"\b" + trie_pattern(("national insurance", "ni number", "ni no", "ni #", "nino")) + r"(?![^\W\d_])",
    re.IGNORECASE,
)

_SIN = re.compile(r"(?<![\d-])[1-79]\d{2}[ -]?\d{3}[ -]?\d{3}(?![\d-])")
_SIN_KEYWORD = re.compile(
    r"\b"
    + trie_pattern(("sin", "s.i.n.", "s.i.n", "social insurance", "numéro d'assurance sociale", "nas"))
    + r"(?![^\W\d_])",
    re.IGNORECASE,
)

_PASSPORT_KEYWORD = re.compile(
    r"\b"
    + trie_pattern(
        ("passport", "pasaporte", "passeport", "passaporto", "passaporte", "reisepass", "reisepassnummer", "paspoort")
    )
    + r"(?![^\W\d_])",
    re.IGNORECASE,
)
_PASSPORT_VALUE = re.compile(
    r"(?:\s*(?:no\b\.?|nr\b\.?|num\b\.?|number|n[º°o]\b\.?|#|n[uú]mero|numéro|nummer))?"
    r"\s*[:#.]?\s*(?:is\s+)?(?P<v>[A-Z0-9]{6,9})(?![A-Za-z0-9])",
    re.IGNORECASE,
)

_MRZ_LINE = re.compile(r"^[ \t]*([A-Z0-9<]{28,46})[ \t]*\r?$", re.MULTILINE)
_MRZ_STRONG_START = re.compile(r"^[PIACV][A-Z<][A-Z<]{3}")


def _ssn_valid(digits: str) -> bool:
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    return area not in ("000", "666") and area[0] != "9" and group != "00" and serial != "0000"


def _after_keywords(text: str, keyword: re.Pattern[str], value: re.Pattern[str]) -> Iterator[re.Match[str]]:
    """Yield ``value`` matches that start within the window after each ``keyword`` match."""
    for kw in keyword.finditer(text):
        m = value.search(text, kw.end(), min(len(text), kw.end() + _WINDOW + 16))
        if m is not None and m.start() - kw.end() <= _WINDOW:
            yield m


def _ssn(text: str) -> Iterator[Detection]:
    for m in _SSN_DASHED.finditer(text):
        before = text[m.start() - 1] if m.start() else ""
        after = text[m.end()] if m.end() < len(text) else ""
        if (before.isdigit() or before == "-") or (after.isdigit() or after == "-"):
            continue
        if _ssn_valid(m.group().replace("-", "")):
            yield detection(m.start(), m.end(), RedactionKind.NATIONAL_ID, P_NATIONAL_ID)
    for m in _after_keywords(text, _SSN_KEYWORD, _SSN_LOOSE):
        if _ssn_valid(re.sub(r"\D", "", m.group())):
            yield detection(m.start(), m.end(), RedactionKind.NATIONAL_ID, P_NATIONAL_ID)


def _nino(text: str) -> Iterator[Detection]:
    for m in _after_keywords(text, _NINO_KEYWORD, _NINO):
        yield detection(m.start(), m.end(), RedactionKind.NATIONAL_ID, P_NATIONAL_ID)


def _sin(text: str) -> Iterator[Detection]:
    for m in _after_keywords(text, _SIN_KEYWORD, _SIN):
        if luhn_valid(re.sub(r"\D", "", m.group())):
            yield detection(m.start(), m.end(), RedactionKind.NATIONAL_ID, P_NATIONAL_ID)


def _passport(text: str) -> Iterator[Detection]:
    for kw in _PASSPORT_KEYWORD.finditer(text):
        m = _PASSPORT_VALUE.match(text, kw.end())
        if m is not None and any(c.isdigit() for c in m.group("v")):
            yield detection(m.start("v"), m.end("v"), RedactionKind.PASSPORT, P_NATIONAL_ID)


def _mrz(text: str) -> Iterator[Detection]:
    """Group consecutive MRZ-shaped lines (TD1 30, TD2 36, TD3 44 characters) into one span."""
    if "<<" not in text:
        return
    groups: list[list[re.Match[str]]] = []
    for m in _MRZ_LINE.finditer(text):
        if "<" not in m.group(1):
            continue
        if groups and text[groups[-1][-1].end() : m.start()] == "\n":
            groups[-1].append(m)
        else:
            groups.append([m])
    for group in groups:
        lines = [g.group(1) for g in group]
        strong = any(_MRZ_STRONG_START.match(line) and line.count("<") >= 2 for line in lines)
        if len(lines) >= 2:
            digits = sum(c.isdigit() for line in lines for c in line)
            ok = strong or (digits >= 6 and all(line.count("<") >= 2 for line in lines))
        else:
            ok = strong and len(lines[0]) in (29, 30, 31, 35, 36, 37, 43, 44, 45)
        if ok:
            yield detection(group[0].start(1), group[-1].end(1), RedactionKind.PASSPORT, P_MRZ)


def detect(scan: Scan) -> Iterator[Detection]:
    """Yield national-ID, passport and MRZ detections."""
    text = scan.text
    yield from _ssn(text)
    yield from _nino(text)
    yield from _sin(text)
    yield from _passport(text)
    yield from _mrz(text)
