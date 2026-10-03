"""Reports: cited sections built from verified data, citation enforcement for analyst text, the sandboxed preview,
finalization (hash, integrity code, audit anchor, database lock) and expiring exports in every format."""

from __future__ import annotations

import io
import json

import httpx
import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import DBAPIError

from angel_engine.db.models import AuditLog, Report
from angel_engine.db.session import set_investigation_scope
from angel_engine.jobs.worker import Worker
from tests.factories import make_investigation
from tests.helpers import create_user, csrf_headers, login
from tests.integration.test_investigations import reauth, stale_reauth

pytestmark = pytest.mark.db
JUSTIFICATION = "The registry extract states the incorporation date directly."


async def setup(client: httpx.AsyncClient, services):  # type: ignore[no-untyped-def]
    user = await create_user(services)
    await login(client, user)
    inv_id = await make_investigation(services, user.id)
    base = f"/api/v1/investigations/{inv_id}"
    captures = {}
    for key, url, excerpt, category in (
        (
            "registry",
            "https://registry.example.gov/companies/123",
            "Northwind Coffee Roasters Lda — incorporated 2016-03-02.",
            "public_company_information",
        ),
        ("news", "https://news.example.org/northwind", "The roastery was founded in 2016.", "news_articles"),
        ("rival", "https://daily.example.net/northwind", "Northwind began trading in 2014.", "news_articles"),
    ):
        resp = await client.post(
            f"{base}/evidence",
            json={"url": url, "excerpt": excerpt, "category": category},
            headers=csrf_headers(client),
        )
        assert resp.status_code == 201, resp.text
        captures[key] = resp.json()["evidence"]
    resp = await client.post(
        f"{base}/findings",
        json={
            "statement": "Northwind Coffee Roasters was incorporated in 2016.",
            "category": "public_company_information",
            "links": [{"evidence_id": captures["registry"]["id"], "directly_states": True}],
            "confidence": "high",
            "confidence_basis": "Official registry extract.",
        },
        headers=csrf_headers(client),
    )
    confirmed = resp.json()
    resp = await client.post(
        f"{base}/findings/{confirmed['id']}/transitions",
        json={
            "to_status": "confirmed_by_source",
            "justification": JUSTIFICATION,
            "evidence_ids": [captures["registry"]["id"]],
        },
        headers={**csrf_headers(client), "If-Match": f'"{confirmed["version"]}"'},
    )
    assert resp.status_code == 200, resp.text
    resp = await client.post(
        f"{base}/findings",
        json={
            "statement": "Northwind began trading in 2014.",
            "category": "news_articles",
            "links": [{"evidence_id": captures["rival"]["id"]}],
        },
        headers=csrf_headers(client),
    )
    assert resp.status_code == 201
    return user, inv_id, base, captures


async def test_report_sections_cite_everything_and_enforce_citations(client, services):
    _, _, base, captures = await setup(client, services)
    resp = await client.post(
        f"{base}/reports",
        json={
            "title": "Northwind due-diligence summary",
            "options": {"confidentiality": "Internal"},
            "custom_sections": [
                {
                    "title": "Analyst assessment",
                    "paragraphs": [
                        {
                            "text": "The registry record is the strongest evidence for the founding date.",
                            "refs": [captures["registry"]["label"]],
                        },
                        {"text": "The company is probably expanding to Porto next year.", "refs": []},
                        {"text": "This claim cites a label that does not exist.", "refs": ["E-999"]},
                    ],
                }
            ],
        },
        headers=csrf_headers(client),
    )
    assert resp.status_code == 201, resp.text
    report = resp.json()
    assert report["status"] == "draft" and resp.headers["etag"] == f'"{report["version"]}"'
    doc = report["document"]
    sections = {s["key"]: s for s in doc["sections"]}
    assert list(sections)[:4] == ["overview", "methodology", "evidence_summary", "important_findings"]
    important = sections["important_findings"]["blocks"]
    assert important[0]["type"] == "finding" and important[0]["data"]["status"] == "confirmed_by_source"
    assert important[0]["data"]["confidence"] == {"level": "high", "basis": "Official registry extract."}
    assert {r["label"] for r in important[0]["refs"]} >= {captures["registry"]["label"]}
    unverified = sections["unverified_claims"]["blocks"]
    texts = [b["text"] for b in unverified]
    assert "Northwind began trading in 2014." in texts
    assert "The company is probably expanding to Porto next year." in texts  # uncited analyst text is moved here
    assert "This claim cites a label that does not exist." in texts
    custom = next(s for s in doc["sections"] if s["key"].startswith("custom_"))
    assert [b["text"] for b in custom["blocks"]] == [
        "The registry record is the strongest evidence for the founding date."
    ]
    assert report["lint"]["uncited_custom_paragraphs"] == 2
    sources = sections["sources"]["blocks"][0]["data"]["rows"]
    assert any(row[2] == "https://registry.example.gov/companies/123" for row in sources)
    assert doc["confidentiality"] == "Internal"

    preview = await client.get(f"{base}/reports/{report['id']}/preview")
    assert preview.status_code == 200 and preview.headers["content-type"].startswith("text/html")
    assert preview.headers["content-security-policy"].startswith("sandbox")
    assert preview.headers["x-frame-options"] == "SAMEORIGIN"
    html = preview.text
    assert "<script" not in html and "Northwind Coffee Roasters was incorporated in 2016." in html
    assert "Draft" in html and "DRAFT" in html


async def test_unsafe_custom_text_is_refused(client, services):
    _, _, base, _ = await setup(client, services)
    resp = await client.post(
        f"{base}/reports",
        json={
            "title": "Report",
            "custom_sections": [
                {
                    "title": "Notes",
                    "paragraphs": [
                        {"text": "Here is the founder's home address and the times she leaves the house.", "refs": []}
                    ],
                }
            ],
        },
        headers=csrf_headers(client),
    )
    assert resp.status_code == 422 and resp.json()["type"] == "/problems/policy-refused"


async def test_finalize_locks_hashes_and_anchors_in_the_audit_log(client, services):
    user, inv_id, base, _ = await setup(client, services)
    report = (
        await client.post(f"{base}/reports", json={"title": "Final summary"}, headers=csrf_headers(client))
    ).json()
    url = f"{base}/reports/{report['id']}"
    assert (await client.post(f"{url}/finalize", headers=csrf_headers(client))).status_code == 428
    resp = await client.post(f"{url}/finalize", headers={**csrf_headers(client), "If-Match": f'"{report["version"]}"'})
    assert resp.status_code == 200, resp.text
    final = resp.json()
    assert final["status"] == "final" and final["verified"] is True and len(final["final_sha256"]) == 64
    integrity = final["document"]["integrity"]
    assert integrity["sha256"] == final["final_sha256"] and integrity["audit_seq"] == final["audit_seq"]
    async with services.db.session("app") as db:
        entry = (await db.execute(select(AuditLog).where(AuditLog.seq == final["audit_seq"]))).scalar_one()
    assert entry.action == "report.finalized" and entry.details["sha256"] == final["final_sha256"]

    patch = await client.patch(
        url, json={"title": "Changed"}, headers={**csrf_headers(client), "If-Match": f'"{final["version"]}"'}
    )
    assert patch.status_code == 409
    assert (await client.delete(url, headers=csrf_headers(client))).status_code == 409
    assert (await client.post(f"{url}/refresh", headers=csrf_headers(client))).status_code == 409
    async with services.db.session("app") as db:  # the database refuses changes too
        await set_investigation_scope(db, [inv_id])
        with pytest.raises(DBAPIError, match="final reports are locked"):
            await db.execute(update(Report).where(Report.id == final["id"]).values(options={"sections": []}))
    _ = user


async def test_exports_in_every_format_need_a_recent_sign_in(client, services):
    user, _, base, _ = await setup(client, services)
    report = (await client.post(f"{base}/reports", json={"title": "Export test"}, headers=csrf_headers(client))).json()
    url = f"{base}/reports/{report['id']}"
    await stale_reauth(services, user.id)
    assert (
        await client.post(f"{url}/exports", json={"format": "pdf"}, headers=csrf_headers(client))
    ).status_code == 401
    await reauth(client)
    exports = {}
    for fmt in ("html", "markdown", "json", "pdf"):
        resp = await client.post(f"{url}/exports", json={"format": fmt}, headers=csrf_headers(client))
        assert resp.status_code == 202, resp.text
        assert resp.json()["status"] == "pending"
        exports[fmt] = resp.json()["id"]
    await Worker(services, ["analysis"]).run_until_idle()
    listed = {e["format"]: e for e in (await client.get(f"{url}/exports")).json()}
    assert all(listed[f]["status"] == "ready" and listed[f]["byte_size"] > 0 for f in exports)

    downloads = {}
    for fmt, export_id in exports.items():
        resp = await client.get(f"{url}/exports/{export_id}/download")
        assert resp.status_code == 200, resp.text
        assert resp.headers["content-disposition"].startswith("attachment;")
        downloads[fmt] = resp.content
    assert downloads["pdf"].startswith(b"%PDF-")
    from pypdf import PdfReader

    pdf_text = " ".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(downloads["pdf"])).pages)
    assert "Northwind Coffee Roasters was incorporated in 2016" in pdf_text
    assert b"<script" not in downloads["html"] and b"Important findings" in downloads["html"]
    markdown = downloads["markdown"].decode()
    assert markdown.startswith("# Export test") and "## Important findings" in markdown and "[E-" in markdown
    document = json.loads(downloads["json"])["document"]
    assert document["title"] == "Export test" and document["status"] == "draft"

    await stale_reauth(services, user.id)
    assert (await client.get(f"{url}/exports/{exports['json']}/download")).status_code == 401
