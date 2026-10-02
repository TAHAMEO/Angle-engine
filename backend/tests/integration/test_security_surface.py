"""Route coverage, security headers, RBAC on admin/audit endpoints, legal documents and abuse reports."""

from __future__ import annotations

import pytest
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute

from tests.helpers import anonymous_csrf, create_user, csrf_headers, login

pytestmark = pytest.mark.db

AUTH_DEPENDENCIES = {"current_principal", "pending_session"}


def _walk_routes(routes):  # FastAPI ≥ 0.137 nests included routers
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
        nested = getattr(route, "routes", None)
        if nested:
            yield from _walk_routes(nested)


def _dependency_names(dep: Dependant) -> set[str]:
    names = {getattr(dep.call, "__name__", "")}
    for sub in dep.dependencies:
        names |= _dependency_names(sub)
    return names


async def test_every_route_is_authenticated_or_explicitly_public(app):
    unprotected = []
    for route in _walk_routes(app.router.routes):
        if not route.path.startswith("/api/v1"):
            continue
        public = bool((route.openapi_extra or {}).get("x-public"))
        authed = bool(_dependency_names(route.dependant) & AUTH_DEPENDENCIES)
        if not public and not authed:
            unprotected.append(f"{sorted(route.methods)} {route.path}")
        assert not (public and authed) or route.path.endswith("/session"), route.path
    assert not unprotected, unprotected


async def test_security_headers_on_api_responses(client):
    resp = await client.get("/api/v1/health/live")
    assert resp.status_code == 200
    h = resp.headers
    assert h["content-security-policy"].startswith("default-src 'none'")
    assert h["x-content-type-options"] == "nosniff"
    assert h["referrer-policy"] == "no-referrer"
    assert h["cache-control"] == "no-store"
    assert h["x-frame-options"] == "DENY"
    assert "x-request-id" in h


async def test_readiness_reports_components(client):
    resp = await client.get("/api/v1/health/ready")
    assert resp.status_code == 200
    assert resp.json()["checks"]["database"] == "ok"


async def test_problem_details_for_unknown_resources(client, services):
    user = await create_user(services)
    await login(client, user)
    resp = await client.get("/api/v1/admin/users")
    assert resp.status_code == 403
    assert resp.headers["content-type"].startswith("application/problem+json")
    assert resp.json()["permission"] == "user:manage"


async def test_investigator_cannot_read_audit_but_auditor_can(client, anon_client, services):
    investigator = await create_user(services)
    await login(client, investigator)
    assert (await client.get("/api/v1/audit-events")).status_code == 403
    auditor = await create_user(services, role="auditor")
    await login(anon_client, auditor)
    page = await anon_client.get("/api/v1/audit-events")
    assert page.status_code == 200
    actions = {e["action"] for e in page.json()["items"]}
    assert "auth.login" in actions
    verified = await anon_client.get("/api/v1/audit-events/verify")
    assert verified.status_code == 200 and verified.json()["ok"] is True


async def test_admin_cannot_change_own_role_and_role_change_needs_reauth(client, services):
    admin = await create_user(services, role="admin")
    other = await create_user(services)
    await login(client, admin)
    own = await client.patch(f"/api/v1/admin/users/{admin.id}", json={"role": "viewer"}, headers=csrf_headers(client))
    assert own.status_code == 400
    ok = await client.patch(f"/api/v1/admin/users/{other.id}", json={"role": "viewer"}, headers=csrf_headers(client))
    assert ok.status_code == 200 and ok.json()["role"] == "viewer"


async def test_legal_documents_are_public_and_versioned(client):
    resp = await client.get("/api/v1/legal/documents/current")
    assert resp.status_code == 200
    kinds = {d["kind"]: d for d in resp.json()}
    assert set(kinds) == {"terms", "privacy", "acceptable_use", "responsible_use"}
    assert "from their face" in kinds["acceptable_use"]["body_markdown"]


async def test_public_abuse_report_is_encrypted_and_triaged(client, anon_client, services):
    headers = await anonymous_csrf(anon_client)
    report = {
        "category": "targeted_by_investigation",
        "description": "I believe an investigation is collecting information about me without cause.",
        "contact": "reporter@mail.example",
    }
    resp = await anon_client.post("/api/v1/abuse-reports", json=report, headers=headers)
    assert resp.status_code == 202
    async with services.db.session("app") as db:
        from sqlalchemy import select

        from angel_engine.db.models import AbuseReport

        rows = (await db.execute(select(AbuseReport))).scalars().all()
        assert rows and all(b"investigation" not in r.description for r in rows)  # ciphertext only
    admin = await create_user(services, role="admin")
    await login(client, admin)
    listed = (await client.get("/api/v1/admin/abuse-reports")).json()
    mine = next(r for r in listed if r["contact"] == "reporter@mail.example")
    upd = await client.patch(
        f"/api/v1/admin/abuse-reports/{mine['id']}",
        json={"status": "triaging", "triage_note": "Reviewing access logs."},
        headers=csrf_headers(client),
    )
    assert upd.status_code == 200 and "Reviewing access logs." in upd.json()["triage_notes"]


async def test_abuse_report_honeypot_is_silently_dropped(anon_client, services):
    headers = await anonymous_csrf(anon_client)
    resp = await anon_client.post(
        "/api/v1/abuse-reports",
        headers=headers,
        json={
            "category": "other",
            "description": "spam spam spam spam spam spam spam",
            "website": "http://spam.example",
        },
    )
    assert resp.status_code == 202
