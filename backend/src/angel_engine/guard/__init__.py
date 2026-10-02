"""Sensitive-data guard: redact personal and secret data before anything is stored or displayed.

>>> redact_text("Card 4111 1111 1111 1111").text
'Card [REDACTED:payment_card]'
"""

from __future__ import annotations

from angel_engine.guard.detectors.urls import sanitize_url
from angel_engine.guard.redactor import redact_mapping, redact_text
from angel_engine.guard.types import (
    RedactionContext,
    RedactionKind,
    RedactionMode,
    RedactionResult,
    RedactionSpan,
    SensitivityFlag,
    SourceKind,
)

__all__ = [
    "RedactionContext",
    "RedactionKind",
    "RedactionMode",
    "RedactionResult",
    "RedactionSpan",
    "SensitivityFlag",
    "SourceKind",
    "redact_mapping",
    "redact_text",
    "sanitize_url",
]
