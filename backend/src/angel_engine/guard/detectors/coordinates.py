"""Precise coordinates: decimal latitude/longitude pairs with ≥ 4 decimals, and DMS pairs with seconds."""

from __future__ import annotations

import re
from collections.abc import Iterator

from angel_engine.guard.detectors.base import P_COORDINATES, Detection, Scan, detection, window_before
from angel_engine.guard.types import RedactionKind

_DECIMAL_PAIR = re.compile(
    r"""(?<![\w.\-+−])
    (?P<lat>[-+−]?\d{1,2}\.\d{4,})(?:\s*(?P<latdeg>°))?(?:\s*(?P<lath>[NSns](?![A-Za-z])))?
    (?P<sep>\s*[,;/]\s*|\s+)
    (?P<lon>[-+−]?\d{1,3}\.\d{4,})(?:\s*(?P<londeg>°))?(?:\s*(?P<lonh>[EWOewo](?![A-Za-z])))?
    (?!\d|\.\d)""",
    re.VERBOSE,
)
_DMS_PART = (
    r"(?:[NSEWO]\s*)?\d{1,3}\s*°\s*\d{1,2}\s*['′’]\s*\d{1,2}(?:[.,]\d+)?\s*(?:\"|″|''|”)\s*(?:[NSEWO](?![A-Za-z]))?"
)
_DMS_PAIR = re.compile(rf"{_DMS_PART}\s*[,;/]?\s*{_DMS_PART}")
_GEO_CONTEXT = re.compile(
    r"\b(?:lat|latitude|lon|lng|long|longitude|gps|coord|coordinates|geo|location|position)\b",
    re.IGNORECASE,
)
_FINANCIAL_CONTEXT = re.compile(
    r"\b(?:rate|rates|price|prices|usd|eur|gbp|jpy|chf|fx|exchange|yield|ratio|coefficient|p-value|version)\b|%",
    re.IGNORECASE,
)


def _number(raw: str) -> float:
    return float(raw.replace("−", "-"))


def detect(scan: Scan) -> Iterator[Detection]:
    """Yield coordinate-pair detections."""
    text = scan.text
    for m in _DECIMAL_PAIR.finditer(text):
        lat, lon = _number(m.group("lat")), _number(m.group("lon"))
        if abs(lat) > 90 or abs(lon) > 180:
            continue
        before = window_before(text, m.start(), 30, same_line=True)
        strong = bool(
            m.group("lath") or m.group("lonh") or m.group("latdeg") or m.group("londeg") or _GEO_CONTEXT.search(before)
        )
        if not strong and (not m.group("sep").strip() or _FINANCIAL_CONTEXT.search(before)):
            continue
        yield detection(m.start(), m.end(), RedactionKind.PRECISE_COORDINATES, P_COORDINATES)
    if "°" not in text:
        return
    for m in _DMS_PAIR.finditer(text):
        yield detection(m.start(), m.end(), RedactionKind.PRECISE_COORDINATES, P_COORDINATES)
