"""AI layer without a network: the grounding validator, structured-output checks, the Claude provider's request and
response handling (mock transport), and the offline fake provider."""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx2
import pytest
from anthropic import AsyncAnthropic

from angel_engine.ai.grounding import (
    LINK_REMOVED,
    PEOPLE_REMOVED,
    PROVIDER_REFUSED_TEXT,
    person_statement,
    validate_answer,
    validate_structured,
)
from angel_engine.ai.prompts import SCHEMAS, SYSTEM
from angel_engine.ai.providers import AnthropicProvider, FakeProvider
from angel_engine.ai.types import (
    INSUFFICIENT,
    ContextDoc,
    Grounding,
    ProviderFailed,
    ProviderUnavailable,
    RawAnswer,
    RawBlock,
    RawCitation,
    RawStructured,
    Task,
)
from angel_engine.guard import RedactionMode

STD = RedactionMode.STANDARD


def doc(n: int, text: str, url: str | None = None) -> ContextDoc:
    return ContextDoc(uuid.uuid4(), f"E-{n}", f"E-{n} · news.example.org", "Evidence", text, source_url=url)


DOCS = [
    doc(1, "Northwind Coffee Roasters was founded in 2016 in Lisbon. See https://news.example.org/a for details."),
    doc(2, "The company opened a second roastery in 2025.", url="https://daily.example.net/b"),
    doc(3, "Northwind Coffee Roasters, established 2014, trades in Porto."),
]


def answer(*blocks: RawBlock, refused: bool = False) -> RawAnswer:
    return RawAnswer(tuple(blocks), "test-model", refused=refused)


# ------------------------------------------------------------------------------------- answers
def test_valid_citations_are_grounded_and_mapped_to_evidence() -> None:
    raw = answer(
        RawBlock("The evidence states:"),
        RawBlock("Northwind was founded in 2016.", (RawCitation(0, "founded in 2016 in Lisbon"),)),
        RawBlock("It opened a second roastery in 2025.", (RawCitation(1, "opened a second  roastery in 2025"),)),
    )
    result = validate_answer(raw, DOCS, task=Task.CHAT, mode=STD)
    assert result.grounding == Grounding.GROUNDED
    assert [s.kind for s in result.segments] == ["plain", "cited", "cited"]
    assert result.segments[1].citations[0].label == "E-1"
    assert result.cited_evidence_ids == [DOCS[0].evidence_id, DOCS[1].evidence_id]


def test_fabricated_citations_are_dropped_and_uncited_text_labelled() -> None:
    raw = answer(
        RawBlock("Northwind was founded in 2016.", (RawCitation(0, "founded in 2016"),)),
        RawBlock("It is owned by a large holding company based abroad.", (RawCitation(7, "owned by"),)),
        RawBlock("Revenue doubled in 2024 according to insiders.", (RawCitation(1, "revenue doubled"),)),
    )
    result = validate_answer(raw, DOCS, task=Task.CHAT, mode=STD)
    assert result.grounding == Grounding.PARTIAL
    assert [s.kind for s in result.segments] == ["cited", "uncited", "uncited"]
    assert result.stats["unknown_documents"] == 1 and result.stats["unverified_quotes"] == 1


def test_no_valid_citation_means_exactly_the_insufficient_phrase() -> None:
    for raw in (
        answer(RawBlock("I believe the company was founded by two brothers in the 1990s.")),
        answer(RawBlock(INSUFFICIENT)),
        answer(RawBlock("Founded in 1999.", (RawCitation(0, "founded in 1999"),))),
    ):
        result = validate_answer(raw, DOCS, task=Task.CHAT, mode=STD)
        assert result.grounding == Grounding.INSUFFICIENT_EVIDENCE
        assert [(s.text, s.kind) for s in result.segments] == [(INSUFFICIENT, "notice")]
        assert result.cited_evidence_ids == []
    assert INSUFFICIENT == "Insufficient public evidence to establish this conclusion."


def test_check_conclusion_verdicts() -> None:
    supported = validate_answer(
        answer(RawBlock("VERDICT: supported\nThe founding year is stated as 2016.", (RawCitation(0, "2016"),))),
        DOCS, task=Task.CHECK_CONCLUSION, mode=STD,
    )  # fmt: skip
    assert supported.verdict == "supported" and supported.grounding == Grounding.GROUNDED
    assert "VERDICT" not in supported.segments[0].text
    insufficient = validate_answer(answer(RawBlock("VERDICT: insufficient\nNothing.")), DOCS,
                                   task=Task.CHECK_CONCLUSION, mode=STD)  # fmt: skip
    assert insufficient.verdict == "insufficient" and insufficient.segments[0].text == INSUFFICIENT
    unsupported = validate_answer(answer(RawBlock("VERDICT: supported\nIt is obviously true.")), DOCS,
                                  task=Task.CHECK_CONCLUSION, mode=STD)  # fmt: skip
    assert unsupported.verdict == "insufficient" and unsupported.grounding == Grounding.INSUFFICIENT_EVIDENCE


def test_foreign_links_are_removed_and_known_links_kept() -> None:
    raw = answer(
        RawBlock(
            "Founded in 2016 (https://news.example.org/a); more at https://tracker.example.com/x?u=1.",
            (RawCitation(0, "founded in 2016"),),
        )
    )
    text = validate_answer(raw, DOCS, task=Task.CHAT, mode=STD).segments[0].text
    assert "https://news.example.org/a" in text and "tracker.example.com" not in text and LINK_REMOVED in text


def test_statements_about_people_in_images_are_removed() -> None:
    assert person_statement("The woman in the photo is Jane Doe.")
    assert person_statement("The man shown in the image appears to be about 40 years old.")
    assert not person_statement("No people are visible in the image.")
    assert not person_statement("The company was founded by two partners in 2016.")
    raw = answer(
        RawBlock("The sign reads Northwind.", (RawCitation(0, "Northwind Coffee Roasters"),)),
        RawBlock("The person pictured next to the sign is probably the owner, Jane Doe.", (RawCitation(0, "2016"),)),
    )
    result = validate_answer(raw, DOCS, task=Task.CHAT, mode=STD)
    assert [s.text for s in result.segments][1] == PEOPLE_REMOVED and "Jane" not in json.dumps(
        [s.as_dict() for s in result.segments]
    )


def test_personal_data_in_output_is_redacted() -> None:
    raw = answer(RawBlock("Contact jane87@gmail.com or +351 912 345 678 — founded in 2016.",
                          (RawCitation(0, "founded in 2016"),)))  # fmt: skip
    text = validate_answer(raw, DOCS, task=Task.CHAT, mode=STD).segments[0].text
    assert "jane87@gmail.com" not in text and "912 345 678" not in text and "2016" in text


def test_provider_refusal() -> None:
    result = validate_answer(answer(RawBlock("..."), refused=True), DOCS, task=Task.CHAT, mode=STD)
    assert result.grounding == Grounding.PROVIDER_REFUSED and result.segments[0].text == PROVIDER_REFUSED_TEXT


# ---------------------------------------------------------------------------------- structured
def structured(task: Task, data: dict[str, Any]) -> list[Any]:
    return validate_structured(task, RawStructured(data, "m"), DOCS, mode=STD).drafts


def test_structured_items_need_known_evidence_and_clean_names() -> None:
    contradictions = structured(Task.CONTRADICTIONS, {"items": [
        {"aspect": "founding year", "description": "E-1 says 2016, E-3 says 2014.", "evidence": ["E-1", "e3"]},
        {"aspect": "x", "description": "Only one source.", "evidence": ["E-1", "E-99"]},
    ]})  # fmt: skip
    assert len(contradictions) == 1 and contradictions[0].evidence_ids == [DOCS[0].evidence_id, DOCS[2].evidence_id]
    queries = structured(Task.SUGGEST_QUERIES, {"items": [
        {"query": "northwind-coffee.example", "input_type": "domain", "rationale": "registrar", "related_evidence": []},
        {"query": "jane87@gmail.com", "input_type": "keyword", "rationale": "owner", "related_evidence": []},
        {"query": "x", "input_type": "username", "rationale": "", "related_evidence": []},
    ]})  # fmt: skip
    assert [d.payload["query"] for d in queries] == ["northwind-coffee.example"]
    extracted = structured(Task.EXTRACT, {
        "entities": [{"type": "organization", "name": "Northwind Coffee Roasters", "evidence": ["E-1"]},
                     {"type": "location", "name": "Lisbon", "evidence": ["E-1"]},
                     {"type": "organization", "name": "Ghost Corp", "evidence": ["E-42"]}],
        "relationships": [{"from_name": "Northwind Coffee Roasters", "rel_type": "located_in", "to_name": "Lisbon",
                           "evidence": ["E-1"]},
                          {"from_name": "Lisbon", "rel_type": "subsidiary_of", "to_name": "Northwind Coffee Roasters",
                           "evidence": ["E-1"]}],
    })  # fmt: skip
    assert [(d.kind, d.payload.get("name") or d.payload.get("rel_type")) for d in extracted] == [
        ("entity", "Northwind Coffee Roasters"), ("entity", "Lisbon"), ("relationship", "located_in"),
    ]  # fmt: skip
    events = structured(Task.TIMELINE, {"events": [
        {"date": "2016-03-01", "precision": "day", "kind": "corporate_event", "title": "Founded", "evidence": ["E-1"]},
        {"date": "2016-13-01", "precision": "day", "kind": "event", "title": "Bad date", "evidence": ["E-1"]},
        {"date": "2025", "precision": "year", "kind": "event", "title": "Second roastery", "evidence": []},
    ]})  # fmt: skip
    assert [d.payload["title"] for d in events] == ["Founded"]


def test_vision_clues_never_describe_people() -> None:
    clues = structured(Task.VISION_CLUES, {"clues": [
        {"type": "brand", "value": "Northwind Coffee Roasters", "basis": "logo on the awning", "confidence": "high"},
        {"type": "object", "value": "a woman holding a cup", "basis": "foreground", "confidence": "high"},
        {"type": "object", "value": "John Smith", "basis": "the man near the door", "confidence": "low"},
        {"type": "landmark", "value": "Harbour Arch", "basis": "arch in the background", "confidence": "moderate"},
    ]})  # fmt: skip
    assert [d.payload["value"] for d in clues] == ["Northwind Coffee Roasters", "Harbour Arch"]


# ---------------------------------------------------------------------------- Claude provider
def mock_provider(responses: list[tuple[int, dict[str, Any]]]) -> tuple[AnthropicProvider, list[dict[str, Any]]]:
    seen: list[dict[str, Any]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(json.loads(request.content))
        status, body = responses[min(len(seen) - 1, len(responses) - 1)]
        return httpx2.Response(status, json=body)

    client = AsyncAnthropic(api_key="test-key", max_retries=0,
                            http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(handler)))  # fmt: skip
    return AnthropicProvider(api_key="test-key", model="claude-opus-5-5", client=client), seen


def message(content: list[dict[str, Any]], stop_reason: str = "end_turn") -> dict[str, Any]:
    usage = {"input_tokens": 1200, "output_tokens": 80}
    return {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-5-5", "content": content,
            "stop_reason": stop_reason, "stop_sequence": None, "usage": usage}  # fmt: skip


async def test_claude_request_uses_documents_citations_and_explicit_effort() -> None:
    provider, seen = mock_provider([(200, message([
        {"type": "thinking", "thinking": "internal", "signature": "sig"},
        {"type": "text", "text": "Founded in 2016.", "citations": [
            {"type": "char_location", "cited_text": "founded in 2016", "document_index": 0, "document_title": "E-1",
             "start_char_index": 31, "end_char_index": 46}]},
    ]))])  # fmt: skip
    raw = await provider.grounded_answer(DOCS, SYSTEM, "When was it founded?", effort="medium", max_tokens=1000)
    request = seen[0]
    assert request["model"] == "claude-opus-5-5" and request["output_config"] == {"effort": "medium"}
    assert "temperature" not in request and "tool_choice" not in request and request["system"] == SYSTEM
    documents = [b for b in request["messages"][0]["content"] if b["type"] == "document"]
    assert len(documents) == 3 and all(d["citations"] == {"enabled": True} for d in documents)
    assert documents[0]["title"] == "E-1 · news.example.org" and documents[-1]["cache_control"] == {"type": "ephemeral"}
    assert request["messages"][0]["content"][-1] == {"type": "text", "text": "When was it founded?"}
    assert len(raw.blocks) == 1 and raw.blocks[0].citations[0].document_index == 0  # thinking is never kept
    assert raw.usage.input_tokens == 1200 and not raw.refused


async def test_claude_structured_output_refusal_and_errors() -> None:
    provider, seen = mock_provider([(200, message([{"type": "text", "text": json.dumps({"items": []})}]))])
    raw = await provider.structured(DOCS, SYSTEM, "List gaps.", SCHEMAS[Task.GAPS], effort="medium", max_tokens=500)
    assert raw.data == {"items": []}
    assert seen[0]["output_config"]["format"] == {"type": "json_schema", "schema": SCHEMAS[Task.GAPS]}
    assert all(b.get("citations") == {"enabled": False} for b in seen[0]["messages"][0]["content"][:3])
    provider, _ = mock_provider([(200, message([{"type": "text", "text": ""}], stop_reason="refusal"))])
    refused = await provider.grounded_answer(DOCS, SYSTEM, "q", effort="low", max_tokens=100)
    assert refused.refused
    provider, _ = mock_provider([(429, {"type": "error", "error": {"type": "rate_limit_error", "message": "slow"}})])
    with pytest.raises(ProviderUnavailable):
        await provider.grounded_answer(DOCS, SYSTEM, "q", effort="low", max_tokens=100)
    provider, _ = mock_provider([(400, {"type": "error", "error": {"type": "invalid_request_error", "message": "x"}})])
    with pytest.raises(ProviderFailed):
        await provider.grounded_answer(DOCS, SYSTEM, "q", effort="low", max_tokens=100)


async def test_fake_provider_quotes_evidence_verbatim() -> None:
    fake = FakeProvider()
    raw = await fake.grounded_answer(DOCS, SYSTEM, "Answer: «When was Northwind founded?»", effort="low", max_tokens=1)
    result = validate_answer(raw, DOCS, task=Task.CHAT, mode=STD)
    assert result.grounding == Grounding.GROUNDED and result.cited_evidence_ids
    nothing = await fake.grounded_answer(DOCS, SYSTEM, "«Who won the 1950 football cup?»", effort="low", max_tokens=1)
    assert validate_answer(nothing, DOCS, task=Task.CHAT, mode=STD).segments[0].text == INSUFFICIENT
