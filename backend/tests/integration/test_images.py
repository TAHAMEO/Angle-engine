"""Image analysis end to end: raw-body upload → malware scan → sandboxed pipeline (in-process here) → observed
evidence, findings, graph and timeline; rejections, quarantine, the face notice and reverse-search gate,
duplicates across investigations, clue actions and deletion. All images are synthetic (no real faces)."""

from __future__ import annotations

import io
import uuid
from typing import Any

import httpx
import pytest
from PIL import Image as PILImage
from sqlalchemy import select

from angel_engine.db.models import AuditLog, BlobDeletion, Job
from angel_engine.images.scanning import EICAR, BuiltinScanner, ClamdScanner
from angel_engine.images.types import FACE_NOTICE, UPLOAD_NOTICE
from angel_engine.jobs.worker import Worker
from tests import imagegen
from tests.factories import add_member, make_investigation
from tests.helpers import create_user, csrf_headers, login

pytestmark = pytest.mark.db


async def setup(client: httpx.AsyncClient, services, *, subject_type: str = "organization"):  # type: ignore[no-untyped-def]
    user = await create_user(services)
    await login(client, user)
    inv_id = await make_investigation(services, user.id, subject_type=subject_type)
    return user, inv_id, f"/api/v1/investigations/{inv_id}"


async def upload(
    client: httpx.AsyncClient, base: str, data: bytes, mime: str = "image/jpeg", key: str | None = None, **headers: str
) -> httpx.Response:
    return await client.post(
        f"{base}/images",
        content=data,
        headers={
            **csrf_headers(client),
            "Content-Type": mime,
            "Idempotency-Key": key or uuid.uuid4().hex,
            **headers,
        },
    )


async def analyzed(client: httpx.AsyncClient, services, base: str, data: bytes, **kw: Any) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    resp = await upload(client, base, data, **kw)
    assert resp.status_code == 201, resp.text
    await Worker(services, ["analysis"]).run_until_idle()
    detail = await client.get(f"{base}/images/{resp.json()['id']}")
    assert detail.status_code == 200
    return detail.json()


async def test_upload_analysis_builds_evidence_graph_and_timeline(client, services):
    _, _, base = await setup(client, services)
    resp = await upload(client, base, imagegen.storefront(), **{"X-Filename": "shop%20front.jpg"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "uploaded" and body["upload_notice"] == UPLOAD_NOTICE and body["label"] == "I-1"
    assert body["filename"] == "shop front.jpg" and body["original_retained"] is True

    await Worker(services, ["analysis"]).run_until_idle()
    image = (await client.get(f"{base}/images/{body['id']}")).json()
    assert image["status"] == "analyzed", image
    assert image["scan"]["engine"] == "builtin" and image["scan"]["degraded"] is True
    assert image["face_count"] == 0 and image["notices"] == []
    assert (image["country"], image["region"], image["metadata_availability"]) == ("PT", "PT-11", "rich")
    assert image["capture_time"].startswith("2026-06-14T08:12:33")
    assert image["has_preview"] and image["original_retained"] and image["original_purge_after"]
    assert {s["analyzer"] for s in image["stages"]} >= {"file_info", "metadata", "faces", "ocr", "preview"}
    assert all(s["status"] == "ok" for s in image["stages"])
    assert "device_fingerprints" not in image["metadata"]
    assert image["metadata"]["fields"]["camera_model"] == "DC-100"
    assert "NORTHWIND" in image["ocr"]["text"]
    assert {e["kind"] for e in image["evidence"]} >= {"ocr_text", "metadata"}
    assert image["reverse_search"]["allowed"] is True

    preview = await client.get(f"{base}/images/{body['id']}/preview")
    assert preview.status_code == 200 and preview.headers["content-type"] == "image/jpeg"
    assert "sandbox" in preview.headers["content-security-policy"]
    shown = PILImage.open(io.BytesIO(preview.content))
    assert not shown.getexif() and max(shown.size) <= 1568

    rows = (await client.get(f"{base}/findings")).json()["items"]
    statements = {f["statement"] for f in rows}
    assert "Visible text in image I-1 includes the domain northwind-coffee.example." in statements
    assert any("names the camera" in s for s in statements)
    assert any("Lisboa, Portugal" in s for s in statements)
    assert all(f["provenance"] == "observed" and f["verification_status"] == "unverified" for f in rows)
    assert all(f["category"] == "image_analysis" for f in rows)

    graph = (await client.get(f"{base}/graph")).json()
    names = {n["name"]: n for n in graph["nodes"]}
    assert {"Image I-1", "northwind-coffee.example", "Northwind Coffee Roasters", "Lisboa, Portugal"} <= set(names)
    rel_types = {e["rel_type"] for e in graph["edges"]}
    assert {"shows_text", "located_in"} <= rel_types
    assert all(e["supporting_count"] >= 1 for e in graph["edges"])

    events = (await client.get(f"{base}/timeline-events")).json()
    capture = next(e for e in events if e["kind"] == "capture_time")
    assert capture["precision"] == "exact" and "proves nothing" in (capture["caveat"] or capture["description"])

    clues = (await client.get(f"{base}/images/{body['id']}/clues")).json()
    domain = next(c for c in clues if c["type"] == "domain")
    assert domain["value"] == "northwind-coffee.example" and domain["confidence_basis"].startswith("OCR engine")
    assert "rdap" in {p["connector_id"] for p in domain["pivots"]}
    assert not next(c for c in clues if c["type"] == "date")["pivots"]  # dates are not searchable

    async with services.db.session("app") as db:
        actions = set((await db.execute(select(AuditLog.action).where(AuditLog.target_id == body["id"]))).scalars())
    assert {"image.uploaded", "image.scanned", "image.analyzed"} <= actions


async def test_rejections_quarantine_and_idempotency(client, services, monkeypatch):
    _, inv_id, base = await setup(client, services)
    polyglot = await upload(client, base, imagegen.with_zip_appended(imagegen.jpeg(imagegen.pattern())))
    assert polyglot.status_code == 422 and polyglot.json()["code"] == "polyglot_zip"
    mismatch = await upload(client, base, imagegen.png(imagegen.pattern()), mime="image/jpeg")
    assert mismatch.status_code == 415 and mismatch.json()["code"] == "mime_mismatch"
    svg = await upload(client, base, b'<svg xmlns="http://www.w3.org/2000/svg"/>', mime="image/svg+xml")
    assert svg.status_code == 415
    monkeypatch.setattr(services.settings, "max_upload_bytes", 1000)
    too_big = await upload(client, base, imagegen.jpeg(imagegen.pattern()))
    assert too_big.status_code == 413
    monkeypatch.undo()
    assert (await client.get(f"{base}/images")).json() == []  # nothing was stored

    data = imagegen.jpeg(imagegen.pattern(7))
    first = await upload(client, base, data, key="key-0000001")
    replay = await upload(client, base, data, key="key-0000001")
    duplicate = await upload(client, base, data, key="key-0000002")
    assert first.status_code == 201 and replay.status_code == 200 and duplicate.status_code == 200
    assert first.json()["id"] == replay.json()["id"] == duplicate.json()["id"]
    assert duplicate.json()["duplicate"] is True and replay.json()["duplicate"] is False

    async with services.db.session("app") as db:
        rejected = (
            await db.execute(
                select(AuditLog.details).where(
                    AuditLog.action == "image.upload_rejected", AuditLog.investigation_id == inv_id
                )
            )
        ).scalars()
        reasons = {d["reason"] for d in rejected}
    assert {"polyglot_zip", "mime_mismatch", "svg_not_allowed"} <= reasons


async def test_infected_upload_is_purged_and_never_analyzed(client, services):
    _, _, base = await setup(client, services)
    resp = await upload(client, base, imagegen.jpeg(imagegen.pattern(9)) + EICAR)
    assert resp.status_code == 201
    await Worker(services, ["analysis"]).run_until_idle()
    image = (await client.get(f"{base}/images/{resp.json()['id']}")).json()
    assert image["status"] == "infected" and image["scan"]["signature"] == "Eicar-Test-Signature"
    assert image["original_retained"] is False and image["has_preview"] is False and image["stages"] == []
    async with services.db.session("maintenance") as db:
        pending = (await db.execute(select(BlobDeletion.reason))).scalars().all()
    assert "infected_upload" in pending


async def test_scanner_outage_fails_closed(client, services):
    _, _, base = await setup(client, services)
    original = services.extras["scanner"]
    services.extras["scanner"] = ClamdScanner(host="127.0.0.1", port=9, timeout=1)  # nothing listens here
    try:
        resp = await upload(client, base, imagegen.jpeg(imagegen.pattern(11)))
        await Worker(services, ["analysis"]).run_until_idle()
        image = (await client.get(f"{base}/images/{resp.json()['id']}")).json()
        assert image["status"] == "scanning"  # never "clean" without a verdict
        async with services.db.session("maintenance") as db:
            job = (
                await db.execute(select(Job).where(Job.idempotency_key == f"image-scan:{resp.json()['id']}"))
            ).scalar_one()
        assert job.status == "queued" and job.attempts == 1 and job.last_error == "ScannerUnavailable"
    finally:
        services.extras["scanner"] = original
    assert isinstance(services.extras["scanner"], BuiltinScanner)


async def test_face_notice_and_reverse_search_approval(client, anon_client, services):
    user, inv_id, base = await setup(client, services)
    image = await analyzed(client, services, base, imagegen.storefront(marker=True, with_exif=False))
    assert image["face_count"] == 1 and image["notices"] == [FACE_NOTICE]
    assert FACE_NOTICE == "A face was detected in the image. Angel Engine does not perform facial identification."
    assert image["face_boxes"] and image["reverse_search"]["code"] == "approval_required"
    listed = (await client.get(f"{base}/images")).json()
    assert listed[0]["notices"] == [FACE_NOTICE]
    url = f"{base}/images/{image['id']}/reverse-search-approval"
    purpose = "Check whether this storefront photo was published earlier by news outlets."
    resp = await client.post(url, json={"purpose": purpose}, headers=csrf_headers(client))
    assert resp.status_code == 403 and resp.json()["code"] == "supervisor_required"

    supervisor = await create_user(services, role="supervisor")
    await add_member(services, inv_id, supervisor.id, "editor")
    await login(anon_client, supervisor)
    resp = await anon_client.post(url, json={"purpose": purpose}, headers=csrf_headers(anon_client))
    assert resp.status_code == 200, resp.text
    gate = resp.json()["reverse_search"]
    assert gate["allowed"] is True and gate["approved"] is True
    _ = user


async def test_restricted_mode_drops_location_and_blocks_reverse_search(client, services):
    _, _, base = await setup(client, services, subject_type="individual")
    image = await analyzed(client, services, base, imagegen.storefront())
    assert image["status"] == "analyzed" and image["country"] is None and image["region"] is None
    assert image["reverse_search"]["code"] == "restricted_mode"
    assert "location" not in image["metadata"] or image["metadata"]["location"] is None
    graph = (await client.get(f"{base}/graph")).json()
    assert not [n for n in graph["nodes"] if n["type"] == "location"]


async def test_duplicates_within_and_across_investigations(client, services):
    user, _, base = await setup(client, services)
    sign = PILImage.open(io.BytesIO(imagegen.storefront(with_exif=False))).convert("RGB")
    first = await analyzed(client, services, base, imagegen.jpeg(sign))
    second = await analyzed(client, services, base, imagegen.jpeg(sign.resize((800, 500)), quality=70))
    assert second["status"] == "analyzed"
    similar = (await client.get(f"{base}/images/{second['id']}/similar")).json()
    match = similar["matches"][0]
    assert match["image_id"] == first["id"] and match["relation"] == "near_duplicate" and match["same_investigation"]
    graph = (await client.get(f"{base}/graph")).json()
    assert any(e["rel_type"] == "same_image_as" for e in graph["edges"])
    statements = {f["statement"] for f in (await client.get(f"{base}/findings")).json()["items"]}
    assert "Image I-2 and image I-1 are near-duplicates." in statements

    other_id = await make_investigation(services, user.id, title="Second case")
    other_base = f"/api/v1/investigations/{other_id}"
    third = await analyzed(client, services, other_base, imagegen.jpeg(sign, quality=80))
    cross = (await client.get(f"{other_base}/images/{third['id']}/similar")).json()
    assert cross["cross_investigation"]["allowed"] is True
    elsewhere = [m for m in cross["matches"] if not m["same_investigation"]]
    assert {m["image_id"] for m in elsewhere} == {first["id"], second["id"]}
    assert all(m["investigation_ref"].startswith("AE-") for m in elsewhere)


async def test_clue_promotion_and_pivot(client, services):
    _, _, base = await setup(client, services)
    image = await analyzed(client, services, base, imagegen.storefront(with_exif=False))
    clues = (await client.get(f"{base}/images/{image['id']}/clues")).json()
    text_clue = next(c for c in clues if c["type"] == "visible_text" and "OPEN DAILY" in c["value"])
    resp = await client.post(
        f"{base}/images/{image['id']}/clues/{text_clue['id']}/promote", json={}, headers=csrf_headers(client)
    )
    assert resp.status_code == 201, resp.text
    promoted = resp.json()
    finding = (await client.get(f"{base}/findings/{promoted['finding_id']}")).json()
    assert finding["provenance"] == "observed" and "OPEN DAILY" in finding["statement"]
    clues = (await client.get(f"{base}/images/{image['id']}/clues")).json()
    assert next(c for c in clues if c["id"] == text_clue["id"])["promoted_evidence_id"] == promoted["evidence_id"]

    domain = next(c for c in clues if c["type"] == "domain")
    resp = await client.post(
        f"{base}/images/{image['id']}/clues/{domain['id']}/pivot",
        json={"connector_id": "rdap"},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 202, resp.text
    assert resp.json()["query"] == "northwind-coffee.example" and resp.json()["input_type"] == "domain"
    await Worker(services, ["egress", "analysis"]).run_until_idle()
    run = (await client.get(f"{base}/collection-runs/{resp.json()['id']}")).json()
    assert run["status"] == "succeeded"


async def test_delete_files_and_everything(client, services):
    user, _, base = await setup(client, services)
    image = await analyzed(client, services, base, imagegen.storefront())
    url = f"{base}/images/{image['id']}"
    from tests.integration.test_investigations import reauth, stale_reauth

    await stale_reauth(services, user.id)
    assert (await client.delete(url, headers=csrf_headers(client))).status_code == 401
    await reauth(client)
    resp = await client.delete(url, params={"scope": "file"}, headers=csrf_headers(client))
    assert resp.status_code == 200 and resp.json()["status"] == "files_deleted"
    kept = (await client.get(url)).json()
    assert kept["status"] == "files_deleted" and not kept["has_preview"] and not kept["original_retained"]
    assert (await client.get(f"{url}/preview")).status_code == 404
    assert kept["evidence"]  # results stay

    resp = await client.delete(url, params={"scope": "all"}, headers=csrf_headers(client))
    assert resp.status_code == 200, resp.text
    stats = resp.json()
    assert stats["status"] == "deleted" and stats["evidence_deleted"] >= 2 and stats["edges_removed"] >= 1
    assert (await client.get(url)).status_code == 404
    graph = (await client.get(f"{base}/graph")).json()
    assert not [n for n in graph["nodes"] if n["type"] == "image"] and not graph["edges"]
    remaining = (await client.get(f"{base}/findings")).json()["items"]
    assert remaining and all(f["evidence_removed"] for f in remaining)
    assert not [e for e in (await client.get(f"{base}/timeline-events")).json() if e["kind"] == "capture_time"]
