"""LLM providers: Claude (Anthropic API) and a deterministic offline fake.

``AnthropicProvider`` sends one ``document`` block per evidence item with citations enabled (prose tasks) or a
JSON-schema output format (structured tasks — the two cannot share a request), sets the effort explicitly, never
uses temperature, prefill or forced tool choice, and maps ``stop_reason == "refusal"`` to a refused result
(it does not retry refused requests on other models). Thinking blocks are never stored or shown.

``FakeProvider`` (``ANGEL_AI_PROVIDER=fake``; refused in production) answers by quoting the most relevant
documents verbatim, so the whole pipeline — citations, validation, proposals — runs offline. Its answers are
labelled "offline demo AI".
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

from angel_engine.ai.context import terms
from angel_engine.ai.types import (
    INSUFFICIENT,
    ContextDoc,
    LLMProvider,
    ProviderFailed,
    ProviderUnavailable,
    RawAnswer,
    RawBlock,
    RawCitation,
    RawStructured,
    Usage,
)
from angel_engine.config import Settings


def _documents(docs: list[ContextDoc], *, citations: bool) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = [
        {
            "type": "document",
            "source": {"type": "text", "media_type": "text/plain", "data": doc.text},
            "title": doc.title,
            "context": doc.context,
            "citations": {"enabled": citations},
        }
        for doc in docs
    ]
    if blocks:
        blocks[-1]["cache_control"] = {"type": "ephemeral"}  # the evidence set is reused across questions
    return blocks


class AnthropicProvider:
    name = "anthropic"
    label = "Claude"

    def __init__(self, *, api_key: str, model: str, timeout: float = 300.0, client: Any = None) -> None:
        from anthropic import AsyncAnthropic

        self.model = model
        self._client = client or AsyncAnthropic(api_key=api_key, timeout=timeout, max_retries=2)

    async def _create(self, **kwargs: Any) -> Any:
        import anthropic

        try:
            return await self._client.messages.create(model=self.model, **kwargs)
        except (anthropic.APIConnectionError, anthropic.RateLimitError, anthropic.InternalServerError) as exc:
            raise ProviderUnavailable(type(exc).__name__) from exc
        except anthropic.APIStatusError as exc:
            if exc.status_code in (408, 409, 429) or exc.status_code >= 500:
                raise ProviderUnavailable(f"http_{exc.status_code}") from exc
            raise ProviderFailed(f"http_{exc.status_code}") from exc

    @staticmethod
    def _usage(message: Any) -> Usage:
        usage = getattr(message, "usage", None)
        return Usage(int(getattr(usage, "input_tokens", 0) or 0), int(getattr(usage, "output_tokens", 0) or 0))

    async def grounded_answer(
        self, docs: list[ContextDoc], system: str, instruction: str, *, effort: str, max_tokens: int
    ) -> RawAnswer:
        message = await self._create(
            max_tokens=max_tokens,
            system=system,
            messages=[
                {"role": "user", "content": [*_documents(docs, citations=True), {"type": "text", "text": instruction}]}
            ],
            output_config={"effort": effort},
        )
        blocks: list[RawBlock] = []
        for block in message.content:
            if getattr(block, "type", None) != "text":
                continue  # thinking and other blocks are never kept
            citations = tuple(
                RawCitation(
                    document_index=int(c.document_index),
                    cited_text=str(c.cited_text),
                    start=getattr(c, "start_char_index", None),
                    end=getattr(c, "end_char_index", None),
                )
                for c in (block.citations or [])
                if getattr(c, "type", None) == "char_location"
            )
            blocks.append(RawBlock(block.text, citations))
        return RawAnswer(
            blocks=tuple(blocks),
            model=str(getattr(message, "model", self.model)),
            usage=self._usage(message),
            refused=message.stop_reason == "refusal",
            truncated=message.stop_reason in ("max_tokens", "model_context_window_exceeded"),
        )

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
    ) -> RawStructured:
        content: list[dict[str, Any]] = _documents(docs, citations=False)
        if image_jpeg is not None:
            content.append(
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/jpeg",
                        "data": base64.b64encode(image_jpeg).decode(),
                    },
                }
            )
        content.append({"type": "text", "text": instruction})
        message = await self._create(
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": content}],
            output_config={"effort": effort, "format": {"type": "json_schema", "schema": schema}},
        )
        refused = message.stop_reason == "refusal"
        text = "".join(b.text for b in message.content if getattr(b, "type", None) == "text")
        data = None
        if not refused and text.strip():
            try:
                parsed = json.loads(text)
                data = parsed if isinstance(parsed, dict) else None
            except ValueError:
                data = None
        return RawStructured(
            data=data,
            model=str(getattr(message, "model", self.model)),
            usage=self._usage(message),
            refused=refused,
            truncated=message.stop_reason in ("max_tokens", "model_context_window_exceeded"),
        )


# --------------------------------------------------------------------------------------------------
# Offline fake
# --------------------------------------------------------------------------------------------------
_SENTENCE = re.compile(r"[^.!?\n]{12,400}[.!?]?")
_YEAR = re.compile(r"\b(1[89]\d{2}|20\d{2})\b")
_ISO = re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b")
_DOMAIN = re.compile(r"\b((?:[a-z0-9-]+\.)+(?:example|com|org|net|io|pt|uk|de|fr))\b", re.IGNORECASE)
_ORG = re.compile(r"\b([A-Z][A-Za-z&'-]+(?:\s+[A-Z][A-Za-z&'-]+){1,4})\b")


class FakeProvider:
    """Deterministic, offline stand-in that quotes the evidence (tests and the offline demo only)."""

    name = "fake"
    label = "offline demo AI"
    model = "fake-offline-demo"

    def _ranked(self, docs: list[ContextDoc], text: str) -> list[tuple[int, ContextDoc, str]]:
        wanted = terms(text)
        out = []
        for index, doc in enumerate(docs):
            best = max(_SENTENCE.findall(doc.text) or [doc.text[:300]], key=lambda s: len(wanted & terms(s)))
            score = len(wanted & terms(doc.text))
            if score:
                out.append((index, doc, best.strip()))
        out.sort(key=lambda x: -len(wanted & terms(x[2])))
        return out

    async def grounded_answer(
        self, docs: list[ContextDoc], system: str, instruction: str, *, effort: str, max_tokens: int
    ) -> RawAnswer:
        question = instruction.split("«", 1)[-1].split("»", 1)[0] if "«" in instruction else instruction
        ranked = self._ranked(docs, question)[:3]
        if not ranked:
            return RawAnswer((RawBlock(INSUFFICIENT),), self.model, Usage(len(instruction) // 4, 12))
        blocks: list[RawBlock] = []
        if "VERDICT:" in instruction:
            blocks.append(RawBlock("VERDICT: supported\n"))
        blocks.append(RawBlock("The evidence states:"))
        for index, _doc, sentence in ranked:
            blocks.append(RawBlock(sentence, (RawCitation(index, sentence),)))
        return RawAnswer(tuple(blocks), self.model, Usage(sum(len(d.text) for d in docs) // 4, 60))

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
    ) -> RawStructured:
        keys = set(schema.get("properties", {}))
        data: dict[str, Any]
        if keys == {"clues"}:
            ocr = instruction.rsplit("(may be incomplete):", 1)[-1]
            lines = [line.strip() for line in ocr.splitlines() if len(line.strip()) >= 4][:5]
            data = {
                "clues": [
                    {
                        "type": "sign",
                        "value": line,
                        "basis": "Legible text on a sign in the image",
                        "confidence": "moderate",
                    }
                    for line in lines
                ]
            }
        elif keys == {"events"}:
            events = []
            for doc in docs:
                for y, m, d in _ISO.findall(doc.text)[:2]:
                    events.append(
                        {
                            "date": f"{y}-{m}-{d}",
                            "precision": "day",
                            "kind": "publication",
                            "title": f"Dated statement in {doc.label}",
                            "evidence": [doc.label],
                        }
                    )
            data = {"events": events[:10]}
        elif keys == {"entities", "relationships"}:
            entities, seen = [], set()
            for doc in docs:
                for domain in _DOMAIN.findall(doc.text)[:3]:
                    if domain.lower() not in seen:
                        seen.add(domain.lower())
                        entities.append({"type": "domain", "name": domain.lower(), "evidence": [doc.label]})
            data = {"entities": entities[:15], "relationships": []}
        elif "items" in keys:
            item_keys = set(schema["properties"]["items"]["items"]["properties"])
            data = {"items": self._items(item_keys, docs)}
        else:
            data = {}
        return RawStructured(data, self.model, Usage(sum(len(d.text) for d in docs) // 4, 80))

    @staticmethod
    def _items(item_keys: set[str], docs: list[ContextDoc]) -> list[dict[str, Any]]:
        if "aspect" in item_keys:  # contradictions: documents giving different years for the same subject
            by_year: dict[str, ContextDoc] = {}
            for doc in docs:
                for year in _YEAR.findall(doc.text)[:3]:
                    by_year.setdefault(year, doc)
            years = sorted(by_year)
            if len(years) >= 2 and by_year[years[0]].label != by_year[years[-1]].label:
                a, b = by_year[years[0]], by_year[years[-1]]
                return [
                    {
                        "aspect": "date",
                        "description": f"{a.label} gives {years[0]} while {b.label} gives "
                        f"{years[-1]} for a related event.",
                        "evidence": [a.label, b.label],
                    }
                ]
            return []
        if "query" in item_keys:
            out = []
            for doc in docs:
                for domain in _DOMAIN.findall(doc.text)[:2]:
                    out.append(
                        {
                            "query": domain.lower(),
                            "input_type": "domain",
                            "rationale": f"Check registration records for a domain named in {doc.label}.",
                            "related_evidence": [doc.label],
                        }
                    )
            return out[:5]
        if "why_it_matters" in item_keys:
            if not docs:
                return []
            return [
                {
                    "description": "No registry or official publication in the evidence confirms these claims.",
                    "why_it_matters": "Claims reported by a single kind of source are easier to get wrong.",
                    "related_evidence": [docs[0].label],
                }
            ]
        return []


def build_provider(settings: Settings) -> LLMProvider | None:
    if settings.ai_provider == "fake":
        if settings.env == "production":
            raise RuntimeError("the fake AI provider is not allowed in production")
        return FakeProvider()
    if settings.ai_provider == "anthropic" and settings.anthropic_api_key is not None:
        return AnthropicProvider(
            api_key=settings.anthropic_api_key.get_secret_value(),
            model=settings.ai_model,
            timeout=settings.ai_request_timeout_s,
        )
    return None


__all__ = ["AnthropicProvider", "FakeProvider", "build_provider"]
