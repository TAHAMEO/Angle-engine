"""End-to-end collection: API → egress worker (connectors over recorded fixtures) → analysis worker (sandboxed
parsing) → ingestion (sources, evidence, findings, entities, graph, facts, timeline) → suggestions."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from sqlalchemy import select

from angel_engine.db.models import EvidenceItem
from angel_engine.db.session import set_investigation_scope
from angel_engine.jobs.worker import Worker
from tests.factories import make_investigation
from tests.helpers import create_user, csrf_headers, login

pytestmark = pytest.mark.db
ORG = "Northwind Coffee Roasters"


async def setup(client: httpx.AsyncClient, services, *, subject_type: str = "organization"):  # type: ignore[no-untyped-def]
    user = await create_user(services)
    await login(client, user)
    inv_id = await make_investigation(services, user.id, subject_type=subject_type)
    return user, inv_id, f"/api/v1/investigations/{inv_id}"


async def run(client: httpx.AsyncClient, services, base: str, **body: Any) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    resp = await client.post(f"{base}/collection-runs", json=body, headers=csrf_headers(client))
    assert resp.status_code == 202, resp.text
    await Worker(services, ["egress", "analysis"]).run_until_idle()
    return (await client.get(f"{base}/collection-runs/{resp.json()['id']}")).json()


async def capture(client: httpx.AsyncClient, services, base: str, url: str) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    return await run(client, services, base, connector_id="web_capture", input_type="url", query=url)


async def test_connector_catalogue(client, services):
    _, _, base = await setup(client, services)
    catalogue = {c["id"]: c for c in (await client.get("/api/v1/connectors")).json()}
    assert len(catalogue) >= 20
    assert {c["category"] for c in catalogue.values()} >= {
        "websites",
        "news_articles",
        "public_social_media",
        "public_profiles",
        "public_documents",
        "public_company_information",
        "public_government_information",
        "public_directories",
        "public_forums",
        "public_image_sources",
        "search_engine_results",
    }
    assert catalogue["brave_search"]["status"] == "needs_key" and catalogue["gdelt"]["status"] == "ready"
    here = {c["id"]: c for c in (await client.get(f"{base}/connectors")).json()}
    assert here["github"]["needs_purpose_note"] is True and here["github"]["needs_approval"] is False


async def test_structured_sources_build_findings_entities_graph_and_facts(client, services):
    _, _inv_id, base = await setup(client, services)
    result = await run(client, services, base, connector_id="wikidata", input_type="organization", query=ORG)
    assert result["status"] == "succeeded" and result["records_count"] == 1
    findings = (await client.get(f"{base}/findings")).json()["items"]
    assert len(findings) == 1 and findings[0]["provenance"] == "source_reported"
    assert findings[0]["verification_status"] == "unverified" and findings[0]["source"]["host"] == "www.wikidata.org"
    graph = (await client.get(f"{base}/graph")).json()
    names = {n["name"] for n in graph["nodes"]}
    assert {ORG, "northwind-coffee.example"} <= names
    assert any(e["rel_type"] == "operated_by" and e["supporting_count"] == 1 for e in graph["edges"])

    rdap = await run(client, services, base, connector_id="rdap", input_type="domain", query="northwind-coffee.example")
    assert rdap["status"] == "succeeded"
    evidence = (await client.get(f"{base}/evidence", params={"q": "registrar"})).json()["items"]
    assert evidence and "owner.private@mail.example" not in str(evidence)  # registrant contacts never kept
    events = (await client.get(f"{base}/timeline-events")).json()
    assert any(e["kind"] == "registration" and e["occurred_start"].startswith("2016-02-14") for e in events)


async def test_page_captures_contradictions_corroboration_and_syndication(client, services):
    _, inv_id, base = await setup(client, services)
    await run(client, services, base, connector_id="wikidata", input_type="organization", query=ORG)  # inception 2016
    news = await capture(client, services, base, "https://news.example.org/business/northwind-second-roastery")
    assert news["status"] == "succeeded" and news["records_count"] == 1
    rival = await capture(client, services, base, "https://daily.example.net/lisbon/northwind-expands")
    assert rival["status"] == "succeeded"
    wire = await capture(client, services, base, "https://wire.example.com/stories/northwind-roastery")
    assert wire["status"] == "succeeded"

    suggestions = (await client.get(f"{base}/suggestions")).json()
    kinds = [s["kind"] for s in suggestions]
    assert "contradiction" in kinds and "corroboration" in kinds and "syndication" in kinds
    contradiction = next(s for s in suggestions if s["kind"] == "contradiction")
    assert "2014" in contradiction["message"] and "2016" in contradiction["message"]

    async with services.db.session("app") as db:
        await set_investigation_scope(db, [inv_id])
        clusters = (
            (
                await db.execute(
                    select(EvidenceItem.syndication_cluster_id).where(EvidenceItem.evidence_type == "page_capture")
                )
            )
            .scalars()
            .all()
        )
    assert len([c for c in clusters if c is not None]) == 2  # the wire copy and the original share a cluster

    resp = await client.post(f"{base}/suggestions/{contradiction['id']}/accept", json={}, headers=csrf_headers(client))
    assert resp.status_code == 200 and resp.json()["status"] == "accepted"
    contradicted = (await client.get(f"{base}/findings", params={"has_contradictions": "true"})).json()["items"]
    assert contradicted  # accepting linked the opposing evidence as contradicting


async def test_walls_robots_and_paywalls_become_references(client, services):
    _, _, base = await setup(client, services)
    blocked = await capture(client, services, base, "https://northwind-coffee.example/account/orders")
    login_wall = await capture(client, services, base, "https://members.example.org/northwind")
    paywall = await capture(client, services, base, "https://paywalled.example.org/premium/northwind")
    assert blocked["references_count"] == login_wall["references_count"] == paywall["references_count"] == 1
    sources = {s["url"]: s for s in (await client.get(f"{base}/sources")).json()["items"]}
    assert sources["https://northwind-coffee.example/account/orders"]["access_status"] == "robots_disallowed"
    assert sources["https://members.example.org/northwind"]["access_status"] == "login_required"
    assert sources["https://paywalled.example.org/premium/northwind"]["access_status"] == "paywalled"
    assert (await client.get(f"{base}/evidence")).json()["items"] == []  # nothing was stored from them


async def test_profile_lookups_need_purpose_and_respect_opt_outs(client, services):
    _, _, base = await setup(client, services)
    body = {"connector_id": "mastodon", "input_type": "username", "query": "@privatebarista@mastodon.example"}
    resp = await client.post(f"{base}/collection-runs", json=body, headers=csrf_headers(client))
    assert resp.status_code == 422 and resp.json()["code"] == "purpose_note_required"
    opted_out = await run(
        client, services, base, **body, purpose_note="Check whether this account is the company's official presence."
    )
    assert opted_out["status"] == "succeeded" and opted_out["records_count"] == 0
    assert opted_out["references_count"] == 1


async def test_unsafe_queries_and_unavailable_sources_are_refused(client, services):
    _, _, base = await setup(client, services)
    resp = await client.post(
        f"{base}/collection-runs",
        json={
            "connector_id": "gdelt",
            "input_type": "keyword",
            "query": "home address of Jane Doe and her daily routine",
        },
        headers=csrf_headers(client),
    )
    assert resp.status_code == 422 and resp.json()["policy"]["decision"] == "refuse"
    resp = await client.post(
        f"{base}/collection-runs",
        json={"connector_id": "brave_search", "input_type": "keyword", "query": ORG},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 409 and resp.json()["code"] == "connector_needs_key"
    resp = await client.post(
        f"{base}/collection-runs",
        json={"connector_id": "rdap", "input_type": "keyword", "query": ORG},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 422 and resp.json()["code"] == "unsupported_input"


async def test_restricted_mode_limits_sources_and_requires_approval(client, anon_client, services):
    user, _, base = await setup(client, services, subject_type="individual")
    resp = await client.post(
        f"{base}/collection-runs",
        json={"connector_id": "wikidata", "input_type": "organization", "query": ORG},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 409 and resp.json()["code"] == "restricted_mode"
    resp = await client.post(
        f"{base}/collection-runs",
        json={
            "connector_id": "github",
            "input_type": "username",
            "query": "northwind-coffee",
            "purpose_note": "The spokesperson's statements reference this public organization account.",
        },
        headers=csrf_headers(client),
    )
    assert resp.status_code == 202 and resp.json()["status"] == "pending_review"
    run_id = resp.json()["id"]
    assert (
        await client.post(f"{base}/collection-runs/{run_id}/approve", json={}, headers=csrf_headers(client))
    ).status_code == 403  # not a supervisor

    supervisor = await create_user(services, role="supervisor")
    await client.post(
        f"{base}/members", json={"email": supervisor.email, "role": "viewer"}, headers=csrf_headers(client)
    )
    await login(anon_client, supervisor)
    resp = await anon_client.post(
        f"{base}/collection-runs/{run_id}/approve", json={}, headers=csrf_headers(anon_client)
    )
    assert resp.status_code == 200 and resp.json()["status"] == "queued"
    await Worker(services, ["egress"]).run_until_idle()
    done = (await client.get(f"{base}/collection-runs/{run_id}")).json()
    assert done["status"] == "succeeded" and done["records_count"] == 1
    assert user.id
