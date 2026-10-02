"""Orchestrator: run every detector, resolve overlaps, splice placeholders into the text.

Overlaps are resolved greedily: higher priority (more specific detector) first, then the longer
span, then the earlier start. Spans always refer to the *original* input so OCR boxes can be
masked; raw matched values are never stored, returned or logged.
"""

from __future__ import annotations

import bisect
from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from angel_engine.guard.detectors import DETECTORS, Detection, Scan
from angel_engine.guard.detectors.urls import find_url_spans
from angel_engine.guard.types import (
    RedactionContext,
    RedactionMode,
    RedactionResult,
    RedactionSpan,
)

_DEFAULT_CONTEXT = RedactionContext()
_MAX_DEPTH = 32


def _resolve(candidates: Iterable[Detection]) -> list[Detection]:
    ordered = sorted(
        (d for d in candidates if d.end > d.start),
        key=lambda d: (-d.priority, -(d.end - d.start), d.start, d.kind.value),
    )
    starts: list[int] = []
    chosen: list[Detection] = []
    for d in ordered:
        i = bisect.bisect_right(starts, d.start)
        if i > 0 and chosen[i - 1].end > d.start:
            continue
        if i < len(chosen) and chosen[i].start < d.end:
            continue
        starts.insert(i, d.start)
        chosen.insert(i, d)
    return chosen


def redact_text(
    text: str,
    *,
    mode: RedactionMode = RedactionMode.STANDARD,
    context: RedactionContext | None = None,
) -> RedactionResult:
    """Redact sensitive data from ``text``.

    Returns the redacted text, per-kind counts, spans into the original text and sensitivity
    flags (content that is kept but must be hidden by default, e.g. a person's health).
    """
    if not isinstance(text, str):
        raise TypeError("redact_text expects a str")
    if not text:
        return RedactionResult(text=text)
    scan = Scan(text=text, mode=mode, context=context or _DEFAULT_CONTEXT, url_spans=find_url_spans(text))
    candidates: list[Detection] = []
    for detector in DETECTORS:
        candidates.extend(detector(scan))
    chosen = _resolve(candidates)
    parts: list[str] = []
    pos = 0
    for d in chosen:
        parts.append(text[pos : d.start])
        parts.append(d.replacement)
        pos = d.end
    parts.append(text[pos:])
    counts = Counter(d.kind.value for d in chosen)
    return RedactionResult(
        text="".join(parts),
        counts=dict(sorted(counts.items())),
        spans=tuple(RedactionSpan(d.start, d.end, d.kind, d.replacement) for d in chosen),
        flags=frozenset(scan.flags),
    )


def redact_mapping(
    data: Mapping[str, Any],
    *,
    mode: RedactionMode = RedactionMode.STANDARD,
    context: RedactionContext | None = None,
) -> tuple[dict[str, Any], dict[str, int]]:
    """Redact every string value of ``data`` recursively (dicts, lists, tuples, sets).

    Keys and non-string scalars are kept. Returns the redacted copy and the merged counts.
    """
    totals: Counter[str] = Counter()

    def walk(value: Any, depth: int) -> Any:
        if depth > _MAX_DEPTH:
            raise ValueError("mapping is nested too deeply to redact safely")
        if isinstance(value, str):
            result = redact_text(value, mode=mode, context=context)
            totals.update(result.counts)
            return result.text
        if isinstance(value, Mapping):
            return {k: walk(v, depth + 1) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v, depth + 1) for v in value]
        if isinstance(value, tuple):
            return tuple(walk(v, depth + 1) for v in value)
        if isinstance(value, (set, frozenset)):
            return type(value)(walk(v, depth + 1) for v in value)
        return value

    redacted = {k: walk(v, 1) for k, v in data.items()}
    return redacted, dict(sorted(totals.items()))
