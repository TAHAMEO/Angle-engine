"""Grounding validator: turns raw provider output into displayable, cited segments and reviewable proposals.

Rules applied to every answer, whatever the model said:

* every citation must point at a context document and quote text that really is in that document;
* sentences without a valid citation are labelled "Uncited AI commentary" (short connective text excepted);
* links that do not appear in the cited evidence are removed;
* statements about people shown in images (identity, appearance, attributes) are removed;
* the text is passed through the sensitive-data guard;
* an answer with no valid citation becomes exactly "Insufficient public evidence to establish this conclusion."

Structured outputs (contradictions, gaps, queries, entities/relationships, timeline events, vision clues) are
checked item by item: evidence labels must exist in the context, names must survive redaction unchanged,
relationship types must fit the entity types, dates must parse at the stated precision.
"""

from __future__ import annotations

import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from angel_engine.ai.prompts import CLUE_TYPES, ENTITY_TYPES, EVENT_KINDS, QUERY_INPUTS, REL_TYPES
from angel_engine.ai.types import (
    INSUFFICIENT,
    Citation,
    ContextDoc,
    Grounding,
    RawAnswer,
    RawBlock,
    RawStructured,
    Segment,
    Task,
    Validated,
)
from angel_engine.guard import RedactionContext, RedactionMode, SourceKind, redact_text

PROVIDER_REFUSED_TEXT = "The AI provider declined to answer this request."
PEOPLE_REMOVED = (
    "[Statement about a person in an image removed — Angel Engine does not identify or describe people in images.]"
)
LINK_REMOVED = "[link removed]"
MAX_ITEMS = 25
_URL = re.compile(r"\bhttps?://[^\s<>\"'()\[\]{}]{3,500}", re.IGNORECASE)
_VERDICT = re.compile(r"^[ \t>*_#-]*VERDICT:\s*\**\s*(supported|contradicted|insufficient)\b[^\n]*\n?", re.I | re.M)
_SENTENCE = re.compile(r"[^.!?\n]+[.!?]?")
_IMAGE_WORDS = re.compile(
    r"\b(?:image|images|photo|photos|photograph\w*|picture\w*|pictured|depicted|shown|visible|selfie|frame|footage)\b",
    re.IGNORECASE,
)
_PEOPLE = re.compile(
    r"\b(?:man|woman|men|women|boy|girl|child|children|kid|person|people|persons|individual|individuals|someone|"
    r"face|faces|he|she|him|her|his|hers|guy|lady|gentleman|crowd|pedestrian\w*)\b",
    re.IGNORECASE,
)
_NEGATION = re.compile(r"\b(?:no|not|nobody|none|neither|without)\b|\bno one\b", re.IGNORECASE)
_NAME = re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b")
_SIGN_BASIS = re.compile(r"\b(?:sign|signage|logo|text|written|printed|reads|label|banner|poster|lettering)\b", re.I)
_LABEL = re.compile(r"^\s*E\s*-?\s*(\d{1,9})\s*$", re.IGNORECASE)
_DATE = {
    "day": re.compile(r"^(\d{4})-(\d{2})-(\d{2})$"),
    "month": re.compile(r"^(\d{4})-(\d{2})$"),
    "year": re.compile(r"^(\d{4})$"),
}


def _norm(text: str) -> str:
    return " ".join(text.split()).casefold()


def person_statement(text: str) -> bool:
    """A sentence that talks about a person shown in an image (identity, appearance, attributes)."""
    for sentence in _SENTENCE.findall(text):
        if not (_IMAGE_WORDS.search(sentence) and _PEOPLE.search(sentence)):
            continue
        if _NEGATION.search(sentence) and not _NAME.search(sentence):
            continue  # "no people are visible"
        return True
    return False


def _connective(text: str) -> bool:
    letters = sum(ch.isalpha() for ch in text)
    stripped = text.strip()
    return letters < 25 or (letters < 60 and stripped.endswith((",", ":", "—", "–", ";")))


def _strip_links(text: str, allowed: set[str]) -> tuple[str, int]:
    removed = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal removed
        url = match.group(0).rstrip(".,;:")
        if url in allowed:
            return match.group(0)
        removed += 1
        return LINK_REMOVED + match.group(0)[len(url) :]

    return _URL.sub(replace, text), removed


def _allowed_links(docs: list[ContextDoc]) -> set[str]:
    allowed: set[str] = set()
    for doc in docs:
        if doc.source_url:
            allowed.add(doc.source_url)
        allowed.update(m.group(0).rstrip(".,;:") for m in _URL.finditer(doc.text))
    return allowed


def _redact(text: str, mode: RedactionMode, stats: Counter[str]) -> str:
    red = redact_text(text, mode=mode, context=RedactionContext(source_kind=SourceKind.AI_OUTPUT))
    if red.counts:
        stats["redactions"] += sum(red.counts.values())
    return red.text


def _take_verdict(blocks: list[RawBlock]) -> tuple[str | None, list[RawBlock]]:
    for i, block in enumerate(blocks):
        match = _VERDICT.search(block.text)
        if match:
            rest = block.text[: match.start()] + block.text[match.end() :]
            return match.group(1).lower(), [*blocks[:i], RawBlock(rest, block.citations), *blocks[i + 1 :]]
        if block.citations:
            break
    return None, blocks


def _insufficient(stats: Counter[str], *, verdict: bool = False) -> Validated:
    return Validated(
        [Segment(INSUFFICIENT, "notice")],
        Grounding.INSUFFICIENT_EVIDENCE,
        [],
        dict(stats),
        verdict="insufficient" if verdict else None,
    )


def validate_answer(raw: RawAnswer, docs: list[ContextDoc], *, task: Task, mode: RedactionMode) -> Validated:
    stats: Counter[str] = Counter()
    if raw.refused:
        return Validated([Segment(PROVIDER_REFUSED_TEXT, "notice")], Grounding.PROVIDER_REFUSED, [], {})
    blocks = list(raw.blocks)
    verdict = None
    if task == Task.CHECK_CONCLUSION:
        verdict, blocks = _take_verdict(blocks)
        if verdict == "insufficient":
            return _insufficient(stats, verdict=True)
    allowed = _allowed_links(docs)
    normalized = [_norm(d.text) for d in docs]
    segments: list[Segment] = []
    for block in blocks:
        if not block.text.strip():
            continue
        citations: dict[tuple[str, str], Citation] = {}
        for cite in block.citations:
            if not 0 <= cite.document_index < len(docs):
                stats["unknown_documents"] += 1
                continue
            quote = cite.cited_text.strip()
            if not quote or _norm(quote) not in normalized[cite.document_index]:
                stats["unverified_quotes"] += 1
                continue
            doc = docs[cite.document_index]
            citations.setdefault((doc.label, quote), Citation(str(doc.evidence_id), doc.label, quote[:500]))
        text, removed = _strip_links(block.text, allowed)
        stats["links_removed"] += removed
        if person_statement(text):
            stats["person_statements_removed"] += 1
            if not segments or segments[-1].text != PEOPLE_REMOVED:
                segments.append(Segment(PEOPLE_REMOVED, "notice"))
            continue
        text = _redact(text, mode, stats)
        if INSUFFICIENT.casefold() in text.casefold() and not citations:
            segments.append(Segment(INSUFFICIENT, "notice"))
            continue
        if citations:
            kind = "cited"
        elif _connective(text):
            kind = "plain"
        else:
            kind = "uncited"
            stats["uncited_segments"] += 1
        segments.append(Segment(text, kind, tuple(citations.values())))
    if raw.truncated:
        stats["truncated"] += 1
    if not any(s.kind == "cited" for s in segments):
        return _insufficient(stats, verdict=task == Task.CHECK_CONCLUSION)
    cited = list(dict.fromkeys(uuid.UUID(c.evidence_id) for s in segments for c in s.citations))
    grounding = Grounding.PARTIAL if any(s.kind == "uncited" for s in segments) else Grounding.GROUNDED
    return Validated(segments, grounding, cited, dict(stats), verdict=verdict)


# --------------------------------------------------------------------------------------------------
# Structured outputs → proposals
# --------------------------------------------------------------------------------------------------
@dataclass(slots=True)
class Draft:
    kind: str  # contradiction | gap | query | entity | relationship | timeline_event | clue
    payload: dict[str, Any]
    evidence_ids: list[uuid.UUID] = field(default_factory=list)


@dataclass(slots=True)
class StructuredOutcome:
    drafts: list[Draft]
    grounding: Grounding
    stats: dict[str, int]


class _Checker:
    def __init__(self, docs: list[ContextDoc], mode: RedactionMode) -> None:
        self.by_number = {int(d.label.split("-")[1]): d for d in docs}
        self.mode = mode
        self.allowed = _allowed_links(docs)
        self.stats: Counter[str] = Counter()

    def evidence(self, labels: Any) -> list[uuid.UUID]:
        out: list[uuid.UUID] = []
        for label in labels if isinstance(labels, list) else []:
            match = _LABEL.match(str(label))
            doc = self.by_number.get(int(match.group(1))) if match else None
            if doc is None:
                self.stats["unknown_evidence_labels"] += 1
                continue
            if doc.evidence_id not in out:
                out.append(doc.evidence_id)
        return out

    def text(self, value: Any, limit: int) -> str | None:
        """Cleaned text, or None when it is empty or talks about people in images."""
        raw = " ".join(str(value or "").split())[:limit]
        if not raw:
            return None
        if person_statement(raw):
            self.stats["person_statements_removed"] += 1
            return None
        raw, removed = _strip_links(raw, self.allowed)
        self.stats["links_removed"] += removed
        return _redact(raw, self.mode, self.stats)

    def name(self, value: Any, limit: int = 200) -> str | None:
        """Names must survive redaction unchanged (personal data never becomes an entity or a query)."""
        raw = " ".join(str(value or "").split())[:limit]
        if not raw:
            return None
        red = redact_text(raw, mode=self.mode, context=RedactionContext(source_kind=SourceKind.AI_OUTPUT))
        if red.redacted:
            self.stats["sensitive_names_dropped"] += 1
            return None
        return raw


def _items(data: dict[str, Any] | None, key: str) -> list[dict[str, Any]]:
    value = (data or {}).get(key)
    return [v for v in value if isinstance(v, dict)][:MAX_ITEMS] if isinstance(value, list) else []


def _date(value: Any, precision: str) -> datetime | None:
    pattern = _DATE.get(precision)
    match = pattern.match(str(value or "").strip()) if pattern else None
    if match is None:
        return None
    parts = [int(p) for p in match.groups()] + [1] * (3 - len(match.groups()))
    try:
        when = datetime(parts[0], parts[1], parts[2], tzinfo=UTC)
    except ValueError:
        return None
    return when if 1800 <= when.year <= 2100 else None


def validate_structured(
    task: Task, raw: RawStructured, docs: list[ContextDoc], *, mode: RedactionMode
) -> StructuredOutcome:
    check = _Checker(docs, mode)
    if raw.refused:
        return StructuredOutcome([], Grounding.PROVIDER_REFUSED, {})
    drafts: list[Draft] = []
    data = raw.data
    if task == Task.CONTRADICTIONS:
        for item in _items(data, "items"):
            evidence = check.evidence(item.get("evidence"))
            description = check.text(item.get("description"), 600)
            if len(evidence) < 2 or not description:
                check.stats["dropped"] += 1
                continue
            aspect = check.text(item.get("aspect"), 120) or ""
            drafts.append(Draft("contradiction", {"aspect": aspect, "description": description}, evidence))
    elif task == Task.GAPS:
        for item in _items(data, "items"):
            description = check.text(item.get("description"), 600)
            if not description:
                check.stats["dropped"] += 1
                continue
            why = check.text(item.get("why_it_matters"), 600) or ""
            drafts.append(
                Draft(
                    "gap",
                    {"description": description, "why_it_matters": why},
                    check.evidence(item.get("related_evidence")),
                )
            )
    elif task == Task.SUGGEST_QUERIES:
        for item in _items(data, "items"):
            query = check.name(item.get("query"), 200)
            input_type = str(item.get("input_type") or "")
            if not query or input_type not in QUERY_INPUTS:
                check.stats["dropped"] += 1
                continue
            rationale = check.text(item.get("rationale"), 400) or ""
            drafts.append(
                Draft(
                    "query",
                    {"query": query, "input_type": input_type, "rationale": rationale},
                    check.evidence(item.get("related_evidence")),
                )
            )
    elif task == Task.EXTRACT:
        drafts += _extract(check, data)
    elif task == Task.TIMELINE:
        for item in _items(data, "events"):
            precision = str(item.get("precision") or "")
            when = _date(item.get("date"), precision)
            kind = str(item.get("kind") or "")
            title = check.text(item.get("title"), 300)
            evidence = check.evidence(item.get("evidence"))
            if when is None or kind not in EVENT_KINDS or not title or not evidence:
                check.stats["dropped"] += 1
                continue
            drafts.append(
                Draft(
                    "timeline_event",
                    {"date": when.isoformat(), "precision": precision, "kind": kind, "title": title},
                    evidence,
                )
            )
    elif task == Task.VISION_CLUES:
        drafts += _vision(check, data)
    if raw.truncated:
        check.stats["truncated"] += 1
    grounding = Grounding.GROUNDED if drafts else Grounding.INSUFFICIENT_EVIDENCE
    return StructuredOutcome(drafts, grounding, dict(check.stats))


def _extract(check: _Checker, data: dict[str, Any] | None) -> list[Draft]:
    from angel_engine.graph.service import check_types

    drafts: list[Draft] = []
    names: dict[str, str] = {}
    for item in _items(data, "entities"):
        entity_type = str(item.get("type") or "")
        name = check.name(item.get("name"))
        evidence = check.evidence(item.get("evidence"))
        if entity_type not in ENTITY_TYPES or not name or not evidence or person_statement(name):
            check.stats["dropped"] += 1
            continue
        if name.casefold() in names:
            continue
        names[name.casefold()] = entity_type
        drafts.append(Draft("entity", {"type": entity_type, "name": name}, evidence))
    for item in _items(data, "relationships"):
        source, target = check.name(item.get("from_name")), check.name(item.get("to_name"))
        rel_type = str(item.get("rel_type") or "")
        evidence = check.evidence(item.get("evidence"))
        if not source or not target or rel_type not in REL_TYPES or not evidence:
            check.stats["dropped"] += 1
            continue
        from_type, to_type = names.get(source.casefold()), names.get(target.casefold())
        if from_type is None or to_type is None or source.casefold() == target.casefold():
            check.stats["dropped"] += 1
            continue
        try:
            check_types(rel_type, from_type, to_type)
        except Exception:
            check.stats["dropped"] += 1
            continue
        drafts.append(
            Draft(
                "relationship",
                {
                    "from": {"type": from_type, "name": source},
                    "rel_type": rel_type,
                    "to": {"type": to_type, "name": target},
                },
                evidence,
            )
        )
    return drafts


def _vision(check: _Checker, data: dict[str, Any] | None) -> list[Draft]:
    drafts: list[Draft] = []
    for item in _items(data, "clues"):
        clue_type = str(item.get("type") or "")
        value = check.name(item.get("value"), 200)
        basis = " ".join(str(item.get("basis") or "").split())[:300]
        confidence = str(item.get("confidence") or "low")
        if clue_type not in CLUE_TYPES or not value or confidence not in ("low", "moderate", "high"):
            check.stats["dropped"] += 1
            continue
        # Never anything about people: no person words, and no bare personal names unless read from a sign.
        if _PEOPLE.search(value) or _PEOPLE.search(basis) or person_statement(f"{value}. {basis}"):
            check.stats["person_statements_removed"] += 1
            continue
        if clue_type == "object" and _NAME.fullmatch(value) and not _SIGN_BASIS.search(basis):
            check.stats["person_names_dropped"] += 1  # an "object" that is just a personal-looking name
            continue
        drafts.append(
            Draft(
                "clue",
                {"type": clue_type, "value": value, "basis": check.text(basis, 300) or "", "confidence": confidence},
            )
        )
    return drafts


__all__ = [
    "LINK_REMOVED",
    "PEOPLE_REMOVED",
    "PROVIDER_REFUSED_TEXT",
    "Draft",
    "StructuredOutcome",
    "person_statement",
    "validate_answer",
    "validate_structured",
]
