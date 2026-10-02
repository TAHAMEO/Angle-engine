"""HTTP API for the research core: sources, evidence, findings, graph, timeline, search and dashboard."""

from __future__ import annotations

import uuid
from typing import Any

import httpx
import pytest

from tests.factories import make_investigation
from tests.helpers import create_user, csrf_headers, login

pytestmark = pytest.mark.db
JUSTIFICATION = "The registry record states the incorporation year directly."


async def setup(client: httpx.AsyncClient, services, *, subject_type: str = "organization"):  # type: ignore[no-untyped-def]
    user = await create_user(services)
    await login(client, user)
    inv_id = await make_investigation(services, user.id, subject_type=subject_type)
    return user, f"/api/v1/investigations/{inv_id}"


async def capture(client: httpx.AsyncClient, base: str, url: str, excerpt: str, **extra: Any) -> dict[str, Any]:
    resp = await client.post(
        f"{base}/evidence", json={"url": url, "excerpt": excerpt, **extra}, headers=csrf_headers(client)
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def test_manual_capture_sources_and_evidence(client, services):
    _, base = await setup(client, services)
    out = await capture(
        client,
        base,
        "https://news.example.org/northwind?utm_source=x",
        "Northwind Coffee Roasters, founded in 2016, opened a second roastery. "
        "Contact the owner at ana.example@gmail.com.",
        title="Northwind opens second roastery",
        category="news_articles",
        statement="Northwind Coffee Roasters was founded in 2016.",
        directly_states=True,
    )
    evidence = out["evidence"]
    assert out["created"] and out["finding_id"]
    assert evidence["label"] == "E-1" and evidence["source"]["label"] == "S-1"
    assert evidence["source"]["url"] == "https://news.example.org/northwind"
    assert "gmail.com" not in evidence["excerpt"] and evidence["redaction_counts"]["email"] == 1

    again = await capture(
        client,
        base,
        "https://news.example.org/northwind",
        "Northwind Coffee Roasters, founded in 2016, opened a second roastery. "
        "Contact the owner at ana.example@gmail.com.",
    )
    assert again["created"] is False and again["evidence"]["id"] == evidence["id"]

    sources = (await client.get(f"{base}/sources")).json()
    assert len(sources["items"]) == 1 and sources["items"][0]["evidence_count"] == 1
    sid = sources["items"][0]["id"]
    resp = await client.patch(
        f"{base}/sources/{sid}",
        json={"reliability": "B", "ownership_group": "Example Media"},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 200 and resp.json()["reliability"] == "B"
    detail = (await client.get(f"{base}/sources/{sid}")).json()
    assert detail["evidence"][0]["id"] == evidence["id"]

    url = f"{base}/evidence/{evidence['id']}"
    assert (
        await client.patch(url, json={"country": "PT", "region": "ES-MD"}, headers=csrf_headers(client))
    ).status_code == 422
    resp = await client.patch(
        url, json={"country": "PT", "region": "PT-11", "credibility": 2}, headers=csrf_headers(client)
    )
    assert resp.status_code == 200 and resp.json()["region"] == "PT-11"
    full = (await client.get(url)).json()
    assert full["findings"][0]["label"] == "F-1" and full["findings"][0]["directly_states"] is True

    assert (
        await client.post(
            f"{base}/evidence",
            json={"url": "ftp://files.example.org/x", "excerpt": "x" * 20},
            headers=csrf_headers(client),
        )
    ).status_code == 422


async def test_finding_rows_transitions_and_history(client, services):
    _, base = await setup(client, services)
    registry = await capture(
        client,
        base,
        "https://registry.example.gov/companies/123",
        "Northwind Coffee Roasters Lda — incorporated 2016-03-02.",
        category="public_company_information",
    )
    news = await capture(client, base, "https://news.example.org/northwind", "The roastery was founded in 2016.")
    rival = await capture(client, base, "https://daily.example.net/northwind", "Northwind began trading in 2014.")
    e_reg, e_news, e_rival = registry["evidence"]["id"], news["evidence"]["id"], rival["evidence"]["id"]

    resp = await client.post(
        f"{base}/findings",
        json={
            "statement": "Northwind Coffee Roasters was founded in 2016.",
            "category": "public_company_information",
            "links": [{"evidence_id": e_reg, "directly_states": True}, {"evidence_id": e_news}],
            "confidence": "moderate",
            "confidence_basis": "Registry record plus one news report.",
        },
        headers=csrf_headers(client),
    )
    assert resp.status_code == 201, resp.text
    finding = resp.json()
    fid, version = finding["id"], finding["version"]
    assert resp.headers["etag"] == f'"{version}"'
    # Source → Finding → Evidence → Timestamp → Confidence → Verification Status
    assert finding["source"]["host"] == "registry.example.gov"
    assert finding["evidence"]["supporting"] == 2 and finding["evidence"]["items"][0]["label"].startswith("E-")
    assert finding["timestamps"]["captured_at"] is not None
    assert finding["confidence"] == {"level": "moderate", "basis": "Registry record plus one news report."}
    assert finding["verification_status"] == "unverified" and finding["provenance"] == "source_reported"
    assert set(finding["allowed_transitions"]) >= {"confirmed_by_source", "corroborated"}

    url = f"{base}/findings/{fid}/transitions"
    body = {"to_status": "confirmed_by_source", "justification": JUSTIFICATION, "evidence_ids": [e_reg]}
    assert (await client.post(url, json=body, headers=csrf_headers(client))).status_code == 428
    stale = {**csrf_headers(client), "If-Match": f'"{version + 5}"'}
    assert (await client.post(url, json=body, headers=stale)).status_code == 412
    ok = {**csrf_headers(client), "If-Match": f'"{version}"'}
    resp = await client.post(url, json=body, headers=ok)
    assert resp.status_code == 200, resp.text
    finding = resp.json()
    assert finding["verification_status"] == "confirmed_by_source" and finding["version"] > version

    # Contradicting evidence: promotions are blocked until it is reviewed; dismissing it downgrades nothing.
    resp = await client.post(
        f"{base}/findings/{fid}/evidence-links",
        json={"links": [{"evidence_id": e_rival, "stance": "contradicts"}]},
        headers=csrf_headers(client),
    )
    finding = resp.json()
    assert finding["has_active_contradiction"] and finding["verification_status"] == "unverified"  # auto-downgrade
    resp = await client.post(
        url,
        json={**body, "to_status": "corroborated", "evidence_ids": [e_reg, e_news], "independence_attested": True},
        headers={**csrf_headers(client), "If-Match": f'"{finding["version"]}"'},
    )
    assert resp.status_code == 409
    problem = resp.json()
    assert problem["code"] == "transition_not_allowed" and problem["failed_preconditions"]
    assert "contradicted" in problem["allowed_transitions"]

    contra_link = next(link for link in finding["links"] if link["stance"] == "contradicts")
    resp = await client.post(
        f"{base}/findings/{fid}/evidence-links/{contra_link['id']}/dismiss",
        json={"reason": "The 2014 date refers to a market stall, not the company."},
        headers=csrf_headers(client),
    )
    finding = resp.json()
    assert not finding["has_active_contradiction"]
    resp = await client.post(
        url,
        json={**body, "to_status": "corroborated", "evidence_ids": [e_reg, e_news], "independence_attested": True},
        headers={**csrf_headers(client), "If-Match": f'"{finding["version"]}"'},
    )
    assert resp.status_code == 200 and resp.json()["verification_status"] == "corroborated"

    history = (await client.get(f"{base}/findings/{fid}/history")).json()
    assert [h["to_status"] for h in history] == ["unverified", "confirmed_by_source", "unverified", "corroborated"]
    assert history[2]["automatic"] is True and history[1]["justification"] == JUSTIFICATION

    # Filters
    rows = (await client.get(f"{base}/findings", params={"status": "corroborated"})).json()["items"]
    assert [r["id"] for r in rows] == [fid]
    assert (await client.get(f"{base}/findings", params={"status": "contradicted"})).json()["items"] == []
    assert len((await client.get(f"{base}/findings", params={"domain": "example.gov"})).json()["items"]) == 1
    assert (await client.get(f"{base}/findings", params={"domain": "unrelated.example"})).json()["items"] == []
    assert len((await client.get(f"{base}/findings", params={"q": "founded"})).json()["items"]) == 1
    assert (await client.get(f"{base}/findings", params={"q": "zeppelin"})).json()["items"] == []

    # Retraction keeps the record but removes it from verified status.
    detail = (await client.get(f"{base}/findings/{fid}")).json()
    resp = await client.post(
        f"{base}/findings/{fid}/retract",
        json={"justification": "Superseded by a more precise finding about the founding."},
        headers={**csrf_headers(client), "If-Match": f'"{detail["version"]}"'},
    )
    assert resp.status_code == 200 and resp.json()["retracted"] and resp.json()["verification_status"] == "unverified"


async def test_findings_need_evidence_and_respect_ai_rules(client, services):
    _, base = await setup(client, services)
    resp = await client.post(
        f"{base}/findings",
        json={"statement": "Founded in 2016 in Lisbon.", "category": "analysis"},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 422 and resp.json()["code"] == "evidence_required"
    resp = await client.post(
        f"{base}/findings",
        json={
            "statement": "An external AI tool suggested the photo was taken in Lisbon.",
            "category": "analysis",
            "from_external_ai": True,
        },
        headers=csrf_headers(client),
    )
    assert resp.status_code == 201
    ai = resp.json()
    assert ai["provenance"] == "ai_hypothesis" and ai["verification_status"] == "ai_hypothesis"
    assert ai["confidence"] is None
    resp = await client.post(
        f"{base}/findings",
        json={
            "statement": "Sensitive note about a person.",
            "category": "analysis",
            "from_external_ai": True,
            "confidence": "high",
            "confidence_basis": "x",
        },
        headers=csrf_headers(client),
    )
    assert resp.status_code == 422


async def test_evidence_pagination_with_signed_cursors(client, services):
    _, base = await setup(client, services)
    for i in range(3):
        await capture(client, base, f"https://site{i}.example.org/page", f"Distinct public statement number {i}.")
    page1 = (await client.get(f"{base}/evidence", params={"limit": 2})).json()
    assert len(page1["items"]) == 2 and page1["has_more"] and page1["next_cursor"]
    page2 = (await client.get(f"{base}/evidence", params={"limit": 2, "cursor": page1["next_cursor"]})).json()
    assert len(page2["items"]) == 1 and not page2["has_more"]
    assert {e["id"] for e in page1["items"]}.isdisjoint({e["id"] for e in page2["items"]})
    tampered = page1["next_cursor"][:-2] + ("AA" if not page1["next_cursor"].endswith("AA") else "BB")
    assert (await client.get(f"{base}/evidence", params={"limit": 2, "cursor": tampered})).status_code == 400
    other_filters = {"limit": 2, "cursor": page1["next_cursor"], "evidence_type": "manual_capture"}
    assert (await client.get(f"{base}/evidence", params=other_filters)).status_code == 400


async def test_graph_api(client, services):
    _, base = await setup(client, services)
    ev = (
        await capture(
            client,
            base,
            "https://rdap.example.net/domain/northwind-coffee.example",
            "Registrant organization: Northwind Coffee Roasters Lda.",
            category="public_directories",
        )
    )["evidence"]["id"]
    h = csrf_headers(client)
    org = (
        await client.post(
            f"{base}/entities",
            json={"type": "organization", "name": "Northwind Coffee Roasters Lda", "evidence_ids": [ev]},
            headers=h,
        )
    ).json()
    domain = (
        await client.post(f"{base}/entities", json={"type": "domain", "name": "northwind-coffee.example"}, headers=h)
    ).json()
    city = (
        await client.post(
            f"{base}/entities",
            json={"type": "location", "name": "Lisbon", "location_level": "locality", "country": "PT"},
            headers=h,
        )
    ).json()
    bad = await client.post(
        f"{base}/relationships",
        json={"from_entity_id": org["id"], "rel_type": "hosted_on", "to_entity_id": domain["id"], "evidence_ids": [ev]},
        headers=h,
    )
    assert bad.status_code == 422 and bad.json()["code"] == "relationship_type_mismatch"
    resp = await client.post(
        f"{base}/relationships",
        json={
            "from_entity_id": domain["id"],
            "rel_type": "registered_by",
            "to_entity_id": org["id"],
            "evidence_ids": [ev],
        },
        headers=h,
    )
    assert resp.status_code == 201, resp.text
    rel = resp.json()
    assert rel["verification_status"] == "unverified" and rel["supporting_count"] == 1
    await client.post(
        f"{base}/relationships",
        json={"from_entity_id": org["id"], "rel_type": "located_in", "to_entity_id": city["id"], "evidence_ids": [ev]},
        headers=h,
    )

    graph = (await client.get(f"{base}/graph", params={"root": domain["id"], "depth": 2})).json()
    assert {n["name"] for n in graph["nodes"]} == {
        "northwind-coffee.example",
        "Northwind Coffee Roasters Lda",
        "Lisbon",
    }
    edge = next(e for e in graph["edges"] if e["id"] == rel["id"])
    assert edge["evidence"][0]["host"] == "rdap.example.net"  # every edge shows its supporting source
    path = (await client.get(f"{base}/graph/path", params={"from": domain["id"], "to": city["id"]})).json()
    assert path["found"] and len(path["relationship_ids"]) == 2

    resp = await client.post(
        f"{base}/relationships/{rel['id']}/transitions",
        json={
            "to_status": "confirmed_by_source",
            "justification": "The RDAP record names the registrant organization.",
            "evidence_ids": [ev],
        },
        headers=h,
    )
    assert resp.status_code == 200 and resp.json()["verification_status"] == "confirmed_by_source"
    entities = (await client.get(f"{base}/entities", params={"q": "northwind"})).json()["items"]
    assert {e["type"] for e in entities} == {"organization", "domain"}
    detail = (await client.get(f"{base}/entities/{org['id']}")).json()
    assert detail["mention_count"] == 1 and detail["relationship_count"] == 2

    resp = await client.delete(f"{base}/relationships/{rel['id']}/evidence/{ev}", headers=h)
    assert resp.json() == {"status": "relationship_removed"}
    assert (await client.get(f"{base}/relationships/{rel['id']}")).status_code == 404


async def test_timeline_api(client, services):
    _, base = await setup(client, services)
    ev = (
        await capture(
            client,
            base,
            "https://archive.example.org/web/2016/northwind",
            "Archived homepage of Northwind Coffee Roasters.",
        )
    )["evidence"]["id"]
    h = csrf_headers(client)
    assert (
        await client.post(
            f"{base}/timeline-events",
            json={"occurred_start": "2016-03-02T00:00:00Z", "title": "Domain registered", "evidence_ids": []},
            headers=h,
        )
    ).status_code == 422
    resp = await client.post(
        f"{base}/timeline-events",
        json={
            "occurred_start": "2016-05-01T00:00:00Z",
            "precision": "month",
            "kind": "first_archived",
            "title": "First archived copy of the homepage",
            "evidence_ids": [ev],
        },
        headers=h,
    )
    assert resp.status_code == 201, resp.text
    event = resp.json()
    assert event["caveat"] and event["evidence_labels"] == ["E-1"]
    listing = (await client.get(f"{base}/timeline-events", params={"from": "2016-01-01T00:00:00Z"})).json()
    assert [e["id"] for e in listing] == [event["id"]]
    resp = await client.post(
        f"{base}/timeline-events/{event['id']}/status",
        json={"to_status": "confirmed_by_source", "justification": "The archive record shows the capture date."},
        headers=h,
    )
    assert resp.status_code == 200 and resp.json()["verification_status"] == "confirmed_by_source"


async def test_search_and_dashboard(client, anon_client, services):
    user, base = await setup(client, services, subject_type="individual")
    await capture(
        client,
        base,
        "https://press.example.com/recall",
        "The spokesperson announced the recall.",
        statement="A recall was announced at a press conference.",
    )
    hits = (await client.get(f"{base}/search", params={"q": "recall"})).json()
    assert hits["findings"] and hits["evidence"] and hits["terms"] == 1
    everywhere = (await client.get("/api/v1/search", params={"q": "recall"})).json()
    assert [h["investigation_id"] for h in everywhere] == [base.rsplit("/", 1)[1]]

    other = await create_user(services)
    await login(anon_client, other)
    assert (await anon_client.get("/api/v1/search", params={"q": "recall"})).json() == []

    board = (await client.get(f"{base}/dashboard")).json()
    assert board["stats"]["evidence"] == 1 and board["stats"]["findings"] == 1
    assert board["stats"]["by_status"] == {"unverified": 1}
    kinds = {w["kind"] for w in board["warnings"]}
    assert {"restricted_mode", "scanning_degraded"} <= kinds
    assert board["recent_findings"][0]["label"] == "F-1"
    assert user.id


async def test_viewer_members_cannot_write(client, anon_client, services):
    owner, base = await setup(client, services)
    viewer = await create_user(services)
    resp = await client.post(
        f"{base}/members", json={"email": viewer.email, "role": "viewer"}, headers=csrf_headers(client)
    )
    assert resp.status_code == 201
    await login(anon_client, viewer)
    assert (await anon_client.get(f"{base}/findings")).status_code == 200
    resp = await anon_client.post(
        f"{base}/evidence",
        json={"url": "https://x.example.org/", "excerpt": "y" * 20},
        headers=csrf_headers(anon_client),
    )
    assert resp.status_code == 403
    stranger = uuid.uuid4()
    assert (await anon_client.get(f"/api/v1/investigations/{stranger}/findings")).status_code == 404
    assert owner.id


async def test_notes_are_screened_redacted_and_author_owned(client, anon_client, services):
    owner, base = await setup(client, services)
    h = csrf_headers(client)
    resp = await client.post(f"{base}/notes", json={"body": "Check the 2016 registry filing; ask press@northwind-"
                                                             "coffee.example or ana.example@gmail.com."}, headers=h)
    assert resp.status_code == 201, resp.text
    note = resp.json()
    assert "gmail.com" not in note["body"] and note["redaction_counts"].get("email") == 1 and note["is_author"]
    refused = await client.post(f"{base}/notes", json={"body": "Find her home address and track where she goes."},
                                headers=h)
    assert refused.status_code == 422 and refused.json()["policy"]["decision"] == "refuse"
    assert (await client.post(f"{base}/notes", json={"target_type": "finding", "body": "Orphan note."},
                              headers=h)).status_code == 422
    listing = (await client.get(f"{base}/notes")).json()
    assert [n["id"] for n in listing] == [note["id"]]
    found = (await client.get(f"{base}/search", params={"q": "registry"})).json()
    assert found["notes"] and found["notes"][0]["id"] == note["id"]

    editor = await create_user(services)
    await client.post(f"{base}/members", json={"email": editor.email, "role": "editor"}, headers=h)
    await login(anon_client, editor)
    url = f"{base}/notes/{note['id']}"
    assert (await anon_client.patch(url, json={"body": "Edited by someone else."},
                                    headers=csrf_headers(anon_client))).status_code == 403
    assert (await anon_client.delete(url, headers=csrf_headers(anon_client))).status_code == 403
    assert (await client.delete(url, headers=h)).status_code == 200
    assert owner.id
