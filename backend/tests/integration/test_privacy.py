"""Export my data, the administrator investigation register and the data-subject lookup."""

from __future__ import annotations

import io
import json
import zipfile

import pytest
from sqlalchemy import select

from angel_engine.db.models import AuditLog
from angel_engine.jobs.worker import Worker
from tests.factories import make_investigation
from tests.helpers import create_user, csrf_headers, login
from tests.integration.test_investigations import reauth, stale_reauth

pytestmark = pytest.mark.db


async def _actions(services, actor_id) -> list[tuple[str, dict]]:  # type: ignore[no-untyped-def]
    async with services.db.session("app") as db:
        rows = (await db.execute(select(AuditLog.action, AuditLog.details).where(AuditLog.actor_id == actor_id))).all()
    return [(a, d) for a, d in rows]


async def test_export_my_data_is_single_use_and_needs_recent_sign_in(client, services):
    user = await create_user(services, name="Export Tester")
    await login(client, user)
    await stale_reauth(services, user.id)
    denied = await client.post("/api/v1/me/data-exports", headers=csrf_headers(client))
    assert denied.status_code == 401 and denied.json()["code"] == "reauth_required"
    await reauth(client)

    created = await client.post("/api/v1/me/data-exports", headers=csrf_headers(client))
    assert created.status_code == 202, created.text
    export_id = created.json()["id"]
    assert created.json()["status"] == "pending"
    again = await client.post("/api/v1/me/data-exports", headers=csrf_headers(client))
    assert again.json()["id"] == export_id  # one active export at a time

    await Worker(services, ["maintenance"]).run_until_idle()
    listed = (await client.get("/api/v1/me/data-exports")).json()
    assert listed[0]["status"] == "ready"

    resp = await client.get(f"/api/v1/me/data-exports/{export_id}/download")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    assert resp.headers["cache-control"] == "no-store"
    archive = zipfile.ZipFile(io.BytesIO(resp.content))
    names = {n.split("/", 1)[1] for n in archive.namelist()}
    assert names == {
        "README.txt",
        "account.json",
        "sessions.json",
        "attestations.json",
        "policy_decisions.json",
        "investigations.json",
        "audit_events.json",
    }
    account = json.loads(archive.read("angel-engine-account-export/account.json"))
    assert account["email"] == user.email and account["display_name"] == "Export Tester"
    raw = b"".join(archive.read(n) for n in archive.namelist())
    assert b"password_hash" not in raw and b"mfa_secret" not in raw and b"argon2" not in raw
    audit = json.loads(archive.read("angel-engine-account-export/audit_events.json"))
    assert any(e["action"] == "account.data_export_requested" for e in audit)

    second = await client.get(f"/api/v1/me/data-exports/{export_id}/download")
    assert second.status_code == 409 and second.json()["code"] == "export_already_downloaded"
    actions = [a for a, _ in await _actions(services, user.id)]
    assert "account.data_export_requested" in actions and "account.data_export_downloaded" in actions


async def test_other_people_cannot_download_my_export(client, anon_client, services):
    owner = await create_user(services)
    await login(client, owner)
    export_id = (await client.post("/api/v1/me/data-exports", headers=csrf_headers(client))).json()["id"]
    await Worker(services, ["maintenance"]).run_until_idle()
    other = await create_user(services)
    await login(anon_client, other)
    resp = await anon_client.get(f"/api/v1/me/data-exports/{export_id}/download")
    assert resp.status_code == 404


async def test_admin_register_shows_metadata_only(client, anon_client, services):
    owner = await create_user(services, name="Owner Person")
    inv_id = await make_investigation(services, owner.id, title="Sensitive working title")
    admin = await create_user(services, role="admin")
    await login(client, admin)
    rows = (await client.get("/api/v1/admin/investigations")).json()
    row = next(r for r in rows if r["id"] == str(inv_id))
    assert "title" not in row and "purpose" not in row
    assert row["owner_name"] == "Owner Person" and row["member_count"] == 1
    assert "Sensitive working title" not in json.dumps(rows)
    investigator = await create_user(services)
    await login(anon_client, investigator)
    assert (await anon_client.get("/api/v1/admin/investigations")).status_code == 403


async def test_data_subject_lookup_finds_references_without_content(client, anon_client, services):
    owner = await create_user(services)
    await login(anon_client, owner)
    inv_id = await make_investigation(services, owner.id)
    url = "https://news.example.org/business/cafe-profile?utm_source=feed"
    captured = await anon_client.post(
        f"/api/v1/investigations/{inv_id}/evidence",
        json={"url": url, "excerpt": "A profile of a neighbourhood café published by the local paper."},
        headers=csrf_headers(anon_client),
    )
    assert captured.status_code == 201, captured.text

    admin = await create_user(services, role="admin")
    await login(client, admin)
    body = {"kind": "url", "value": "https://news.example.org/business/cafe-profile", "reason": "data_subject_request"}
    resp = await client.post("/api/v1/admin/data-subject-lookup", json=body, headers=csrf_headers(client))
    assert resp.status_code == 200, resp.text
    match = next(m for m in resp.json()["matches"] if m["investigation_id"] == str(inv_id))
    assert match["sources"] == 1
    assert "excerpt" not in json.dumps(resp.json())

    by_domain = await client.post(
        "/api/v1/admin/data-subject-lookup",
        json={"kind": "domain", "value": "news.example.org", "reason": "abuse_report"},
        headers=csrf_headers(client),
    )
    assert any(m["investigation_id"] == str(inv_id) for m in by_domain.json()["matches"])
    miss = await client.post(
        "/api/v1/admin/data-subject-lookup",
        json={"kind": "url", "value": "https://elsewhere.example.net/page", "reason": "legal_request"},
        headers=csrf_headers(client),
    )
    assert all(m["investigation_id"] != str(inv_id) for m in miss.json()["matches"])

    lookups = [d for a, d in await _actions(services, admin.id) if a == "admin.data_subject_lookup"]
    assert lookups and all("news.example.org" not in json.dumps(d) for d in lookups)
    assert lookups[0]["kind"] == "url" and lookups[0]["reason"] == "data_subject_request"

    await stale_reauth(services, admin.id)
    stale = await client.post("/api/v1/admin/data-subject-lookup", json=body, headers=csrf_headers(client))
    assert stale.status_code == 401
    assert (
        await anon_client.post("/api/v1/admin/data-subject-lookup", json=body, headers=csrf_headers(anon_client))
    ).status_code == 403
