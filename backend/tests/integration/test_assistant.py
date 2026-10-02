"""Source-grounded assistant end to end with the offline provider: screening, citations mapped to evidence,
the exact insufficient-evidence answer, proposals accepted as AI hypotheses, vision clues and the gates."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from sqlalchemy import select

from angel_engine.ai.types import INSUFFICIENT
from angel_engine.db.models import AuditLog
from angel_engine.jobs.worker import Worker
from tests import imagegen
from tests.factories import make_investigation
from tests.helpers import create_user, csrf_headers, login

pytestmark = pytest.mark.db

QUOTES = [
    ("https://news.example.org/business/northwind", "Northwind Coffee Roasters was founded in 2016 in Lisbon by two "
     "former baristas, according to the company's own history page.", "2026-05-01T00:00:00Z"),
    ("https://daily.example.net/lisbon/northwind", "The roaster Northwind Coffee Roasters, established in 2014, now "
     "runs two shops in Lisbon and sells beans online via northwind-coffee.example.", "2026-05-03T00:00:00Z"),
    ("https://wire.example.com/stories/roastery", "Northwind Coffee Roasters opened its second roastery on "
     "2025-09-12 in the Marvila district.", "2025-09-12T00:00:00Z"),
]  # fmt: skip


async def setup(client: httpx.AsyncClient, services, *, subject_type: str = "organization"):  # type: ignore[no-untyped-def]
    user = await create_user(services)
    await login(client, user)
    inv_id = await make_investigation(services, user.id, subject_type=subject_type)
    base = f"/api/v1/investigations/{inv_id}"
    for url, excerpt, published in QUOTES:
        resp = await client.post(
            f"{base}/evidence",
            json={"url": url, "excerpt": excerpt, "category": "news_articles", "published_at": published},
            headers=csrf_headers(client),
        )
        assert resp.status_code == 201, resp.text
    return user, inv_id, base


async def ask(client: httpx.AsyncClient, services, base: str, **body: Any) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    resp = await client.post(f"{base}/assistant/requests", json=body, headers=csrf_headers(client))
    assert resp.status_code == 202, resp.text
    assert resp.json()["status"] == "pending" and resp.json()["poll_after_ms"] == 1000
    await Worker(services, ["egress"]).run_until_idle()
    done = (await client.get(f"{base}/assistant/requests/{resp.json()['id']}")).json()
    assert done["status"] == "completed", done
    return done


async def test_chat_answers_with_citations_mapped_to_evidence(client, services):
    _, inv_id, base = await setup(client, services)
    status = (await client.get("/api/v1/assistant/status")).json()
    assert status == {"available": True, "provider": "fake", "label": "offline demo AI", "model": "fake-offline-demo"}
    done = await ask(client, services, base, task="chat", question="When was Northwind Coffee Roasters founded?")
    assert done["grounding"] == "grounded" and done["provider_label"] == "offline demo AI"
    cited = [s for s in done["segments"] if s["kind"] == "cited"]
    assert cited and all(c["label"].startswith("E-") for s in cited for c in s["citations"])
    evidence = {e["id"]: e for e in (await client.get(f"{base}/evidence")).json()["items"]}
    for segment in cited:
        for citation in segment["citations"]:
            assert citation["cited_text"] in evidence[citation["evidence_id"]]["excerpt"]
    assert {e["id"] for e in done["cited_evidence"]} <= set(evidence)
    assert done["context_documents"] == 3 and done["request"]["question"].startswith("When was")
    async with services.db.session("app") as db:
        event = (
            await db.execute(
                select(AuditLog).where(AuditLog.action == "ai.completed", AuditLog.investigation_id == inv_id)
            )
        ).scalar_one()
    assert event.details["grounding"] == "grounded" and event.details["cited"] >= 1
    assert "question" not in event.details and "Northwind" not in str(event.details)  # content-free audit


async def test_insufficient_evidence_is_said_exactly(client, services):
    _, _, base = await setup(client, services)
    done = await ask(client, services, base, task="chat", question="Which bank finances the volcano observatory?")
    assert done["grounding"] == "insufficient_evidence"
    assert [(s["text"], s["kind"]) for s in done["segments"]] == [(INSUFFICIENT, "notice")]
    assert INSUFFICIENT == "Insufficient public evidence to establish this conclusion."
    empty_user = await create_user(services)
    await login(client, empty_user)
    empty = f"/api/v1/investigations/{await make_investigation(services, empty_user.id)}"
    done = await ask(client, services, empty, task="summarize")
    assert done["segments"][0]["text"] == INSUFFICIENT and done["context_documents"] == 0


async def test_check_conclusion_verdict(client, services):
    _, _, base = await setup(client, services)
    done = await ask(client, services, base, task="check_conclusion",
                     conclusion="Northwind Coffee Roasters opened a second roastery in Marvila.")  # fmt: skip
    assert done["verdict"] == "supported" and done["grounding"] == "grounded"
    assert not any("VERDICT" in s["text"] for s in done["segments"])


async def test_unsafe_requests_are_refused_before_anything_is_sent(client, services):
    _, _, base = await setup(client, services)
    resp = await client.post(
        f"{base}/assistant/requests",
        json={"task": "chat", "question": "What is the home address of the founder of Northwind?"},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 422 and resp.json()["type"] == "/problems/policy-refused"
    assert resp.json()["policy"]["alternatives"]
    assert (await client.get(f"{base}/assistant/requests")).json() == []


async def test_proposals_become_ai_hypotheses_only_when_accepted(client, services):
    _, _, base = await setup(client, services)
    done = await ask(client, services, base, task="contradictions", topic="founding year")
    assert done["grounding"] == "grounded" and len(done["proposals"]) == 1
    proposal = done["proposals"][0]
    assert proposal["kind"] == "contradiction" and len(proposal["evidence"]) == 2
    assert (await client.get(f"{base}/findings")).json()["items"] == []  # nothing recorded yet
    resp = await client.post(f"{base}/assistant/proposals/{proposal['id']}/accept", headers=csrf_headers(client))
    assert resp.status_code == 200, resp.text
    finding = (await client.get(f"{base}/findings/{resp.json()['result']['result_id']}")).json()
    assert finding["provenance"] == "ai_hypothesis" and finding["verification_status"] == "ai_hypothesis"
    again = await client.post(f"{base}/assistant/proposals/{proposal['id']}/accept", headers=csrf_headers(client))
    assert again.status_code == 409

    queries = await ask(client, services, base, task="suggest_queries")
    query = next(p for p in queries["proposals"] if p["kind"] == "query")
    assert query["payload"]["query"] == "northwind-coffee.example" and query["payload"]["input_type"] == "domain"
    accepted = await client.post(f"{base}/assistant/proposals/{query['id']}/accept", headers=csrf_headers(client))
    assert accepted.json()["result"]["prefill"] == {"query": "northwind-coffee.example", "input_type": "domain"}

    timeline = await ask(client, services, base, task="timeline")
    event = next(p for p in timeline["proposals"] if p["kind"] == "timeline_event")
    resp = await client.post(f"{base}/assistant/proposals/{event['id']}/accept", headers=csrf_headers(client))
    assert resp.status_code == 200
    events = (await client.get(f"{base}/timeline-events")).json()
    assert any(e["provenance"] == "ai_hypothesis" and e["occurred_start"].startswith("2025-09-12") for e in events)

    extracted = await ask(client, services, base, task="extract")
    entity = next(p for p in extracted["proposals"] if p["kind"] == "entity")
    rejected = await client.post(f"{base}/assistant/proposals/{entity['id']}/reject", headers=csrf_headers(client))
    assert rejected.json()["status"] == "rejected"
    pending = (await client.get(f"{base}/assistant/proposals")).json()
    assert entity["id"] not in {p["id"] for p in pending}


async def test_vision_clues_from_the_sanitized_preview(client, services):
    user = await create_user(services)
    await login(client, user)
    base = f"/api/v1/investigations/{await make_investigation(services, user.id)}"
    resp = await client.post(
        f"{base}/images",
        content=imagegen.storefront(with_exif=False),
        headers={**csrf_headers(client), "Content-Type": "image/jpeg", "Idempotency-Key": "vision-0001"},
    )
    image_id = resp.json()["id"]
    await Worker(services, ["analysis"]).run_until_idle()
    done = await ask(client, services, base, task="vision_clues", image_id=image_id)
    assert done["grounding"] == "grounded" and done["validation"]["proposals"] >= 1
    clues = (await client.get(f"{base}/images/{image_id}/clues")).json()
    ai = [c for c in clues if c["source"] == "ai"]
    assert ai and all(c["provenance"] == "ai_hypothesis" for c in ai)
    assert all(c["confidence_basis"].startswith("AI vision suggestion") for c in ai)

    faces = await client.post(
        f"{base}/images",
        content=imagegen.storefront(marker=True, with_exif=False),
        headers={**csrf_headers(client), "Content-Type": "image/jpeg", "Idempotency-Key": "vision-0002"},
    )
    await Worker(services, ["analysis"]).run_until_idle()
    resp = await client.post(
        f"{base}/assistant/requests",
        json={"task": "vision_clues", "image_id": faces.json()["id"]},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 409 and resp.json()["code"] == "approval_required"


async def test_assistant_gates(client, services, monkeypatch):
    _, inv_id, base = await setup(client, services)
    version = (await client.get(f"/api/v1/investigations/{inv_id}")).json()["version"]
    resp = await client.patch(
        f"/api/v1/investigations/{inv_id}",
        json={"ai_enabled": False},
        headers={**csrf_headers(client), "If-Match": f'"{version}"'},
    )
    assert resp.status_code == 200, resp.text
    resp = await client.post(f"{base}/assistant/requests", json={"task": "summarize"}, headers=csrf_headers(client))
    assert resp.status_code == 409 and resp.json()["code"] == "ai_disabled"
    monkeypatch.setitem(services.extras, "llm", None)
    resp = await client.post(f"{base}/assistant/requests", json={"task": "summarize"}, headers=csrf_headers(client))
    assert resp.status_code == 503 and resp.json()["code"] == "ai_unavailable"
    assert (await client.get("/api/v1/assistant/status")).json()["available"] is False
