"""Test helpers: users, logins and CSRF headers."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

import httpx
import pyotp

from angel_engine.app_state import Services
from angel_engine.auth.passwords import hash_password
from angel_engine.core.clock import utcnow
from angel_engine.db.models import User
from angel_engine.legal.documents import current_versions

PASSWORD = "Tidy-Harbour-Lantern-2026"
CSRF_COOKIE = "__Host-ae_csrf"


@dataclass
class TestUser:
    id: uuid.UUID
    email: str
    password: str
    role: str
    totp_secret: str | None = None


async def create_user(
    services: Services,
    *,
    role: str = "investigator",
    status: str = "active",
    mfa: bool = False,
    password: str = PASSWORD,
    name: str = "Test User",
) -> TestUser:
    email = f"{role}-{uuid.uuid4().hex[:10]}@agency.example"
    secret = pyotp.random_base32(32) if mfa else None
    async with services.db.session("app") as db:
        user = User(
            email=email,
            display_name=name,
            password_hash=await hash_password(password),
            role=role,
            status=status,
            terms_version_accepted=current_versions()["terms"],
            terms_accepted_at=utcnow(),
        )
        db.add(user)
        await db.flush()
        if secret:
            cipher = await services.vault.system_cipher(db, "system_secrets")
            user.mfa_secret = cipher.seal(secret, table="users", column="mfa_secret", row_id=user.id)
            user.mfa_enabled = True
        return TestUser(user.id, email, password, role, secret)


def csrf_headers(client: httpx.AsyncClient) -> dict[str, str]:
    token = client.cookies.get(CSRF_COOKIE)
    return {"X-CSRF-Token": token} if token else {}


async def anonymous_csrf(client: httpx.AsyncClient) -> dict[str, str]:
    resp = await client.get("/api/v1/auth/csrf")
    assert resp.status_code == 200
    return {"X-CSRF-Token": resp.json()["csrf_token"]}


def totp_code(secret: str, offset_steps: int = 0) -> str:
    return pyotp.TOTP(secret).at(time.time() + 30 * offset_steps)


async def login(client: httpx.AsyncClient, user: TestUser, *, offset_steps: int = 0) -> dict[str, object]:
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": user.password},
        headers=await anonymous_csrf(client),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    if body["state"] == "mfa_pending":
        assert user.totp_secret
        resp = await client.post(
            "/api/v1/auth/mfa/verify",
            json={"code": totp_code(user.totp_secret, offset_steps)},
            headers=csrf_headers(client),
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
    return body
