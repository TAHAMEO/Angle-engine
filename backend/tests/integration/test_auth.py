"""Authentication, sessions, CSRF, MFA and lockout."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select, update

from angel_engine.core.clock import utcnow
from angel_engine.db.models import AuditLog, User, UserSession
from tests.helpers import CSRF_COOKIE, PASSWORD, anonymous_csrf, create_user, csrf_headers, login, totp_code

pytestmark = pytest.mark.db


async def audit_actions(services, user_id, actions) -> list[tuple[str, str]]:
    async with services.db.session("maintenance") as db:
        rows = await db.execute(
            select(AuditLog.action, AuditLog.outcome).where(AuditLog.actor_id == user_id, AuditLog.action.in_(actions))
        )
        return [(action, outcome) for action, outcome in rows.all()]


async def test_login_requires_csrf_token(client, services):
    user = await create_user(services)
    resp = await client.post("/api/v1/auth/login", json={"email": user.email, "password": PASSWORD})
    assert resp.status_code == 403
    assert resp.json()["type"].endswith("/problems/csrf-failed")


async def test_cross_origin_post_is_rejected(client, services):
    user = await create_user(services)
    headers = await anonymous_csrf(client)
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": PASSWORD},
        headers={**headers, "Origin": "https://evil.example"},
    )
    assert resp.status_code == 403
    assert resp.json()["code"] == "origin_mismatch"


async def test_login_success_sets_hardened_cookies(client, services):
    user = await create_user(services)
    headers = await anonymous_csrf(client)
    resp = await client.post("/api/v1/auth/login", json={"email": user.email, "password": PASSWORD}, headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "active"
    set_cookie = ";".join(resp.headers.get_list("set-cookie"))
    assert "__Host-ae_sid=" in set_cookie and "HttpOnly" in set_cookie and "SameSite=strict" in set_cookie
    assert "Secure" in set_cookie
    me = await client.get("/api/v1/me")
    assert me.status_code == 200
    assert me.json()["email"] == user.email
    assert int(me.headers["X-Session-Idle-Expires-In"]) > 0


async def test_wrong_password_is_generic_and_locks_after_threshold(client, services):
    user = await create_user(services)
    for _ in range(5):
        headers = await anonymous_csrf(client)
        resp = await client.post(
            "/api/v1/auth/login", json={"email": user.email, "password": "wrong-password-123"}, headers=headers
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid email or password."
    unknown = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@agency.example", "password": "x" * 12},
        headers=await anonymous_csrf(client),
    )
    assert unknown.status_code == 401 and unknown.json()["detail"] == "Invalid email or password."
    services.limiter._tat.clear()
    locked = await client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": PASSWORD}, headers=await anonymous_csrf(client)
    )
    assert locked.status_code == 401
    assert locked.json()["code"] == "account_locked"


async def test_pending_account_cannot_sign_in(client, services):
    user = await create_user(services, status="pending")
    resp = await client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": PASSWORD}, headers=await anonymous_csrf(client)
    )
    assert resp.status_code == 403
    assert resp.json()["code"] == "account_pending"


async def test_mfa_login_and_replay_protection(client, anon_client, services):
    user = await create_user(services, mfa=True)
    body = await login(client, user)
    assert body["state"] == "active"
    # The same code cannot be used again (replay), even from another browser.
    resp = await anon_client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": PASSWORD},
        headers=await anonymous_csrf(anon_client),
    )
    assert resp.json()["state"] == "mfa_pending"
    replay = await anon_client.post(
        "/api/v1/auth/mfa/verify", json={"code": totp_code(user.totp_secret)}, headers=csrf_headers(anon_client)
    )
    assert replay.status_code == 401
    assert replay.json()["code"] == "invalid_mfa_code"
    # Content endpoints are not reachable with a pending session.
    assert (await anon_client.get("/api/v1/me")).status_code == 401


async def test_mfa_enrollment_flow_when_required(client, services, settings):
    user = await create_user(services)
    settings.mfa_required = True
    try:
        resp = await client.post(
            "/api/v1/auth/login", json={"email": user.email, "password": PASSWORD}, headers=await anonymous_csrf(client)
        )
        assert resp.json()["state"] == "mfa_enroll"
        assert (await client.get("/api/v1/me")).status_code == 401
        enroll = await client.post("/api/v1/auth/mfa/enroll", headers=csrf_headers(client))
        assert enroll.status_code == 200
        secret = enroll.json()["secret"]
        assert enroll.json()["qr_data_uri"].startswith("data:image/png;base64,")
        bad = await client.post(
            "/api/v1/auth/mfa/enroll/confirm", json={"code": "000000"}, headers=csrf_headers(client)
        )
        assert bad.status_code == 422
        done = await client.post(
            "/api/v1/auth/mfa/enroll/confirm", json={"code": totp_code(secret)}, headers=csrf_headers(client)
        )
        assert done.status_code == 200, done.text
        assert done.json()["state"] == "active"
        codes = done.json()["recovery_codes"]
        assert len(codes) == 10
        assert (await client.get("/api/v1/me")).json()["mfa_enabled"] is True
    finally:
        settings.mfa_required = False


async def test_recovery_code_is_single_use(client, anon_client, services):
    user = await create_user(services, mfa=True)
    await login(client, user)
    await client.post("/api/v1/auth/reauth", json={"password": PASSWORD}, headers=csrf_headers(client))
    codes = (await client.post("/api/v1/auth/mfa/recovery-codes", headers=csrf_headers(client))).json()[
        "recovery_codes"
    ]
    for expected in (200, 401):
        await anon_client.post(
            "/api/v1/auth/login",
            json={"email": user.email, "password": PASSWORD},
            headers=await anonymous_csrf(anon_client),
        )
        resp = await anon_client.post(
            "/api/v1/auth/mfa/verify", json={"code": codes[0]}, headers=csrf_headers(anon_client)
        )
        assert resp.status_code == expected


async def test_unsafe_request_requires_session_csrf(client, services):
    user = await create_user(services)
    await login(client, user)
    resp = await client.patch("/api/v1/me", json={"display_name": "Renamed"})
    assert resp.status_code == 403
    ok = await client.patch("/api/v1/me", json={"display_name": "Renamed"}, headers=csrf_headers(client))
    assert ok.status_code == 200 and ok.json()["display_name"] == "Renamed"


async def test_form_csrf_token_is_kept_apart_from_the_session_token(client, services):
    """A session token the browser still holds once made "The request could not be verified" block signing in."""
    user = await create_user(services, mfa=True)
    await login(client, user)
    session_token = client.cookies.get(CSRF_COOKIE)
    issued = await client.get("/api/v1/auth/csrf")
    form_cookie = issued.headers["set-cookie"]
    assert form_cookie.startswith("__Host-ae_form_csrf=") and "HttpOnly" in form_cookie
    assert client.cookies.get(CSRF_COOKIE) == session_token  # a signed-in tab keeps working

    credentials = {"email": user.email, "password": PASSWORD}
    wrong = await client.post("/api/v1/auth/login", json=credentials, headers={"X-CSRF-Token": session_token})
    assert wrong.status_code == 403 and wrong.json()["code"] == "csrf_token_invalid"
    again = await client.post(
        "/api/v1/auth/login", json=credentials, headers={"X-CSRF-Token": issued.json()["csrf_token"]}
    )
    assert again.status_code == 200 and again.json()["state"] == "mfa_pending"
    # Starting over from the code step works the same way.
    restart = await client.post("/api/v1/auth/login", json=credentials, headers=await anonymous_csrf(client))
    assert restart.status_code == 200 and restart.json()["state"] == "mfa_pending"


async def test_session_endpoint_repairs_a_missing_csrf_cookie(client, services):
    user = await create_user(services)
    await login(client, user)
    client.cookies.delete(CSRF_COOKIE)
    assert (await client.get("/api/v1/auth/session")).status_code == 200
    ok = await client.patch("/api/v1/me", json={"display_name": "Renamed"}, headers=csrf_headers(client))
    assert ok.status_code == 200, ok.text


async def test_idle_expiry_and_background_requests(client, services):
    user = await create_user(services)
    await login(client, user)
    async with services.db.session("app") as db:
        row = (await db.execute(select(UserSession).where(UserSession.user_id == user.id))).scalar_one()
        before = row.idle_expires_at
        await db.execute(
            update(UserSession)
            .where(UserSession.user_id == user.id)
            .values(last_seen_at=utcnow() - timedelta(minutes=5))
        )
    await client.get("/api/v1/me", headers={"X-Angel-Activity": "background"})
    async with services.db.session("app") as db:
        row = (await db.execute(select(UserSession).where(UserSession.user_id == user.id))).scalar_one()
        assert row.idle_expires_at == before  # background polling does not keep a session alive
        await db.execute(
            update(UserSession)
            .where(UserSession.user_id == user.id)
            .values(idle_expires_at=utcnow() - timedelta(seconds=1))
        )
    resp = await client.get("/api/v1/me")
    assert resp.status_code == 401
    assert resp.json()["code"] == "session_expired"


async def test_logout_revokes_session(client, services):
    user = await create_user(services)
    await login(client, user)
    resp = await client.post("/api/v1/auth/logout", headers=csrf_headers(client))
    assert resp.status_code == 200
    assert (await client.get("/api/v1/me")).status_code == 401


async def test_password_change_revokes_other_sessions(client, anon_client, services):
    user = await create_user(services)
    await login(client, user)
    await login(anon_client, user)
    resp = await client.put(
        "/api/v1/auth/password",
        json={"current_password": PASSWORD, "new_password": "Quiet-Meadow-Compass-77"},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 200, resp.text
    assert (await client.get("/api/v1/me")).status_code == 200
    assert (await anon_client.get("/api/v1/me")).status_code == 401


async def test_password_guessing_with_a_session_is_rate_limited(client, services):
    """Change-password and re-authentication share one small budget, so a stolen session cannot guess passwords."""
    user = await create_user(services)
    await login(client, user)
    statuses = []
    for attempt in range(6):
        guess = f"wrong-guess-{attempt:04d}"
        if attempt % 2:
            payload = {"current_password": guess, "new_password": "x" * 16}
            resp = await client.put("/api/v1/auth/password", json=payload, headers=csrf_headers(client))
        else:
            resp = await client.post("/api/v1/auth/reauth", json={"password": guess}, headers=csrf_headers(client))
        statuses.append(resp.status_code)
    assert statuses == [401, 401, 401, 401, 401, 429]
    rows = await audit_actions(services, user.id, ("auth.reauth", "auth.password_change"))
    assert rows.count(("auth.password_change", "failure")) == 2 and rows.count(("auth.reauth", "failure")) == 3


async def test_weak_password_rejected(client, services):
    user = await create_user(services)
    await login(client, user)
    resp = await client.put(
        "/api/v1/auth/password",
        json={"current_password": PASSWORD, "new_password": "short"},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 422
    assert resp.json()["code"] == "weak_password"


async def test_registration_request_then_admin_approval(client, anon_client, services):
    headers = await anonymous_csrf(anon_client)
    payload = {
        "email": "new.analyst@agency.example",
        "display_name": "New Analyst",
        "password": "Silver-Ladder-Orchard-31",
        "justification": "Open-source verification of viral media for our newsroom's fact-checking desk.",
        "accept_terms": True,
        "attest_lawful_use": True,
        "attest_no_misuse": True,
    }
    resp = await anon_client.post("/api/v1/auth/registration-requests", json=payload, headers=headers)
    assert resp.status_code == 202
    again = await anon_client.post("/api/v1/auth/registration-requests", json=payload, headers=headers)
    assert again.status_code == 202  # no account enumeration
    admin = await create_user(services, role="admin")
    await login(client, admin)
    pending = (await client.get("/api/v1/admin/users", params={"status": "pending"})).json()
    target = next(u for u in pending if u["email"] == payload["email"])
    assert "fact-checking" in target["access_justification"]
    approved = await client.post(
        f"/api/v1/admin/users/{target['id']}/approve", json={"role": "investigator"}, headers=csrf_headers(client)
    )
    assert approved.status_code == 200 and approved.json()["status"] == "active"
    async with services.db.session("app") as db:
        user = (await db.execute(select(User).where(User.email == payload["email"]))).scalar_one()
        assert user.approved_by == admin.id
