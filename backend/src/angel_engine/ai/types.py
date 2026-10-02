"""Contract of the AI layer.

The assistant only ever sees *evidence documents* (one per evidence item: redacted excerpt plus provenance
metadata) and must cite them. Provider output is raw until :mod:`angel_engine.ai.grounding` validated it: every
citation is mapped back to an evidence id and re-checked against the stored text, uncited sentences are labelled
as AI commentary, unknown links are removed and the text is redacted. AI output never becomes evidence; accepted
proposals become ``ai_hypothesis`` items that a human must verify.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol

INSUFFICIENT = "Insufficient public evidence to establish this conclusion."
UNCITED_LABEL = "Uncited AI commentary"


class Grounding(StrEnum):
    GROUNDED = "grounded"
    PARTIAL = "partial"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    POLICY_REFUSED = "policy_refused"
    PROVIDER_REFUSED = "provider_refused"


class Task(StrEnum):
    SUMMARIZE = "summarize"
    COMPARE = "compare"
    CHECK_CONCLUSION = "check_conclusion"
    CHAT = "chat"
    CONTRADICTIONS = "contradictions"
    GAPS = "gaps"
    SUGGEST_QUERIES = "suggest_queries"
    EXTRACT = "extract"
    TIMELINE = "timeline"
    VISION_CLUES = "vision_clues"
    DRAFT_REPORT = "draft_report"


#: Tasks answered in prose with citations (Citations API); the rest return JSON (structured outputs).
CITATION_TASKS = frozenset({Task.SUMMARIZE, Task.COMPARE, Task.CHECK_CONCLUSION, Task.CHAT, Task.DRAFT_REPORT})
STRUCTURED_TASKS = frozenset(
    {Task.CONTRADICTIONS, Task.GAPS, Task.SUGGEST_QUERIES, Task.EXTRACT, Task.TIMELINE, Task.VISION_CLUES}
)


@dataclass(frozen=True, slots=True)
class ContextDoc:
    """One evidence item as the model sees it."""

    evidence_id: uuid.UUID
    label: str  # "E-12"
    title: str  # "E-12 · news.example.org · 2026-05-01"
    context: str  # provenance / verification metadata (not citable)
    text: str  # redacted excerpt (citable)
    source_url: str | None = None
    captured_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class RawCitation:
    document_index: int
    cited_text: str
    start: int | None = None
    end: int | None = None


@dataclass(frozen=True, slots=True)
class RawBlock:
    text: str
    citations: tuple[RawCitation, ...] = ()


@dataclass(frozen=True, slots=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass(frozen=True, slots=True)
class RawAnswer:
    blocks: tuple[RawBlock, ...]
    model: str
    usage: Usage = field(default_factory=Usage)
    refused: bool = False
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class RawStructured:
    data: dict[str, Any] | None
    model: str
    usage: Usage = field(default_factory=Usage)
    refused: bool = False
    truncated: bool = False


class ProviderUnavailable(Exception):
    """Transient provider failure (network, overload, rate limit): the job may retry."""


class ProviderFailed(Exception):
    """Permanent provider failure for this request (bad request, authentication, unsupported input)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class LLMProvider(Protocol):
    name: str
    model: str
    #: Shown next to answers, e.g. "offline demo AI" for the deterministic fake provider.
    label: str

    async def grounded_answer(
        self, docs: list[ContextDoc], system: str, instruction: str, *, effort: str, max_tokens: int
    ) -> RawAnswer: ...

    async def structured(
        self,
        docs: list[ContextDoc],
        system: str,
        instruction: str,
        schema: dict[str, Any],
        *,
        effort: str,
        max_tokens: int,
        image_jpeg: bytes | None = None,
    ) -> RawStructured: ...


# --------------------------------------------------------------------------------------------------
# Validated output
# --------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Citation:
    evidence_id: str
    label: str
    cited_text: str


@dataclass(frozen=True, slots=True)
class Segment:
    """A piece of the answer. ``kind`` is "cited", "uncited" (AI commentary) or "notice"."""

    text: str
    kind: str
    citations: tuple[Citation, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "kind": self.kind,
            "citations": [
                {"evidence_id": c.evidence_id, "label": c.label, "cited_text": c.cited_text} for c in self.citations
            ],
        }


@dataclass(slots=True)
class Validated:
    segments: list[Segment]
    grounding: Grounding
    cited_evidence_ids: list[uuid.UUID]
    stats: dict[str, int] = field(default_factory=dict)
    verdict: str | None = None  # check_conclusion: supported | contradicted | insufficient
