"""Optional second-opinion classifier hook (e.g. a Claude-based classifier supplied by the AI layer)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from angel_engine.policy.types import Category, Decision, PolicyContext


@dataclass(frozen=True, slots=True)
class ClassifierVerdict:
    decision: Decision
    categories: tuple[Category, ...] = ()
    rationale: str = ""


@runtime_checkable
class PolicyClassifier(Protocol):
    """A classifier may return ``None`` to abstain. It must not send personal data to third parties
    beyond the text it is asked to classify."""

    async def classify(self, text: str, ctx: PolicyContext) -> ClassifierVerdict | None: ...
