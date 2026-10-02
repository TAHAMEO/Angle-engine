"""Regression guard against regex blow-ups: every input is evaluated in (roughly) linear time.

Evidence excerpts can be up to 100,000 characters and policy inputs up to 10,000, so a quadratic regex
turns a crafted page into a denial of service. Budgets are generous for slow CI machines but far below
what a quadratic pattern needs (minutes for these sizes).
"""

from __future__ import annotations

import time

import pytest

from angel_engine.guard import RedactionMode, redact_text
from angel_engine.policy import PolicyContext, Surface, get_default_engine

N = 50_000
ADVERSARIAL = {
    "letters": "A" * N,
    "pem_without_end": "-----BEGIN PRIVATE KEY-----\n" + "A" * N,
    "digits_dashed": "4-" * (N // 2),
    "digits_spaced": "1 " * (N // 2),
    "email_like": "x." * (N // 4) + "@" + "y." * (N // 4),
    "url_like": "http://" + "a." * (N // 2),
    "street_words": "Rua " + "A-" * (N // 2),
    "german_words": "Haupt " * (N // 6),
    "medical_no_breaks": "she was diagnosed with " * (N // 23),
    "residential_phrases": "the home address of " * (N // 20),
    "tracking_phrases": "track her location every day " * (N // 30),
    "parentheses": "(" * N + ")" * N,
    "combining_marks": "a" + "́" * N,
}
BUDGET_S = 5.0


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_redaction_is_linear(name: str) -> None:
    text = ADVERSARIAL[name]
    for mode in (RedactionMode.STANDARD, RedactionMode.RESTRICTED):
        start = time.perf_counter()
        redact_text(text, mode=mode)
        assert time.perf_counter() - start < BUDGET_S, f"{name} ({mode}) is too slow"


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_policy_evaluation_is_linear(name: str) -> None:
    engine = get_default_engine()
    start = time.perf_counter()
    engine.evaluate(ADVERSARIAL[name] + name, PolicyContext(Surface.ASSISTANT_PROMPT))
    assert time.perf_counter() - start < BUDGET_S, f"{name} is too slow"


def test_detection_still_works_after_bounding() -> None:
    red = redact_text("She lives at 12 Elm St, Springfield. Office: Hauptstraße 5, Berlin; Rua Augusta, 100.")
    assert red.counts.get("street_address") == 3
    assert "Springfield" in red.text and "Berlin" in red.text
