"""Load the offline demo dataset through the real API and job worker.

Everything is fictional: ``.example`` organizations, synthetic images (a magenta block stands in for a person and is
"detected" only by the development face detector) and recorded connector responses. The seed refuses to run in
production, and its fixed credentials are for local development and end-to-end tests only.
"""

from __future__ import annotations

import logging
import sys
import uuid
from dataclasses import dataclass
from typing import Any

import httpx
import pyotp
from sqlalchemy import select

from angel_engine.config import Settings, get_settings

DEMO_PASSWORD = "Demo-Harbour-Lantern-2026"  # noqa: S105 — fixed development / e2e credential, refused in production


@dataclass(frozen=True)
class DemoUser:
    email: str
    name: str
    role: str
    totp_secret: str  # fixed so end-to-end tests can compute codes


DEMO_USERS = (
    DemoUser("admin@angel-engine.example", "Avery Admin", "admin", "2RK6JLGRP5COXCL7EMU726X3YH6MNOCZ"),
    DemoUser("supervisor@angel-engine.example", "Sam Supervisor", "supervisor", "QADCK5KE6WZZBFHFU6FNTKT74LEVZ2OK"),
    DemoUser(
        "investigator@angel-engine.example", "Ivy Investigator", "investigator", "NZ2AORS6DOMYDQF6G7BM6SDUM634WBKS"
    ),
    DemoUser("viewer@angel-engine.example", "Vic Viewer", "viewer", "3CWEOQU3ONX6UMTXD7VCDAPSWC2ATGQA"),
    DemoUser("auditor@angel-engine.example", "Aud Auditor", "auditor", "RHVQ3LX6INXMHBX3ZNBL6UNIGUTAP7BH"),
)
ORG = "Northwind Coffee Roasters"
DOMAIN = "northwind-coffee.example"
PAGES = (
    "https://northwind-coffee.example/",
    "https://northwind-coffee.example/about",
    "https://news.example.org/business/northwind-second-roastery",
    "https://wire.example.com/stories/northwind-roastery",
    "https://daily.example.net/lisbon/northwind-expands",
    "https://paywalled.example.org/premium/northwind",
)


class SeedError(RuntimeError):
    pass


def _check(settings: Settings) -> None:
    if settings.env == "production" or settings.is_production:
        raise SeedError("The demo seed never runs in production.")
    if settings.connector_mode != "fixtures":
        raise SeedError("Set ANGEL_CONNECTOR_MODE=fixtures: the demo uses recorded connector responses only.")
    if settings.ai_provider == "anthropic":
        raise SeedError("Set ANGEL_AI_PROVIDER=fake (or disabled) so no demo data is sent to an AI provider.")


class Api:
    """A signed-in browser talking to the in-process app (cookies, CSRF and Origin like the web client)."""

    def __init__(self, app: Any, origin: str) -> None:
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=origin, headers={"Origin": origin}
        )

    def _csrf(self) -> dict[str, str]:
        token = self.client.cookies.get("__Host-ae_csrf") or self.client.cookies.get("ae_csrf")
        return {"X-CSRF-Token": token} if token else {}

    async def login(self, user: DemoUser) -> None:
        anon = (await self.client.get("/api/v1/auth/csrf")).json()["csrf_token"]
        resp = await self.client.post(
            "/api/v1/auth/login", json={"email": user.email, "password": DEMO_PASSWORD}, headers={"X-CSRF-Token": anon}
        )
        resp.raise_for_status()
        if resp.json()["state"] == "mfa_pending":
            code = pyotp.TOTP(user.totp_secret).now()
            (
                await self.client.post("/api/v1/auth/mfa/verify", json={"code": code}, headers=self._csrf())
            ).raise_for_status()

    async def get(self, path: str, **kwargs: Any) -> Any:
        resp = await self.client.get(path, **kwargs)
        resp.raise_for_status()
        return resp.json()

    async def send(self, method: str, path: str, *, expect: tuple[int, ...] = (200, 201, 202), **kwargs: Any) -> Any:
        headers = {**self._csrf(), **kwargs.pop("headers", {})}
        resp = await self.client.request(method, path, headers=headers, **kwargs)
        if resp.status_code not in expect:
            raise SeedError(f"{method} {path} → {resp.status_code}: {resp.text[:300]}")
        return resp.json() if resp.content else None

    async def close(self) -> None:
        await self.client.aclose()


async def _create_users(services: Any) -> None:
    from angel_engine.auth.passwords import hash_password
    from angel_engine.core.clock import utcnow
    from angel_engine.db.models import User
    from angel_engine.legal.documents import current_versions

    async with services.db.session("app") as db:
        for demo in DEMO_USERS:
            user = User(
                email=demo.email,
                display_name=demo.name,
                password_hash=await hash_password(DEMO_PASSWORD),
                role=demo.role,
                status="active",
                organization_unit="Demo newsroom"
                if demo.role in ("investigator", "supervisor", "viewer")
                else "Platform",
                terms_version_accepted=current_versions()["terms"],
                terms_accepted_at=utcnow(),
            )
            db.add(user)
            await db.flush()
            cipher = await services.vault.system_cipher(db, "system_secrets")
            user.mfa_secret = cipher.seal(demo.totp_secret, table="users", column="mfa_secret", row_id=user.id)
            user.mfa_enabled = True


async def _drain(services: Any) -> None:
    from angel_engine.jobs.worker import Worker

    for _ in range(4):  # analysis jobs can enqueue egress jobs and vice versa
        done = await Worker(services, ["egress", "analysis"]).run_until_idle()
        if not done:
            break


def _attestations(versions: dict[str, str]) -> dict[str, Any]:
    return {
        "lawful_purpose": True,
        "no_harassment_or_stalking": True,
        "no_discrimination": True,
        "no_impersonation": True,
        "understand_audit": True,
        "terms_version": versions["terms"],
        "acceptable_use_version": versions["acceptable_use"],
    }


async def _upload(api: Api, base: str, data: bytes, name: str) -> dict[str, Any]:
    return await api.send(  # type: ignore[no-any-return]
        "POST",
        f"{base}/images",
        content=data,
        headers={"Content-Type": "image/jpeg", "Idempotency-Key": str(uuid.uuid4()), "X-Filename": name},
    )


async def _run(api: Api, base: str, connector: str, input_type: str, query: str) -> None:
    await api.send(
        "POST",
        f"{base}/collection-runs",
        json={"connector_id": connector, "input_type": input_type, "query": query},
        headers={"Idempotency-Key": str(uuid.uuid4())},
        expect=(202, 422),
    )


async def _verify_findings(api: Api, base: str) -> None:
    """Record a few human verification decisions where the preconditions hold."""
    page = await api.get(f"{base}/findings", params={"limit": 100})
    confirmed = corroborated = 0
    for row in page["items"]:
        if row["provenance"] == "ai_hypothesis" or row["retracted"]:
            continue
        detail = await api.get(f"{base}/findings/{row['id']}")
        allowed = detail["allowed_transitions"]
        evidence = [
            link["evidence"]["id"] for link in detail["links"] if link["stance"] == "supports" and not link["dismissed"]
        ]
        target = None
        if "corroborated" in allowed and corroborated < 2:
            target, corroborated = "corroborated", corroborated + 1
        elif "confirmed_by_source" in allowed and confirmed < 4:
            target, confirmed = "confirmed_by_source", confirmed + 1
        if target is None:
            continue
        await api.send(
            "POST",
            f"{base}/findings/{row['id']}/transitions",
            json={
                "to_status": target,
                "justification": (
                    "Checked the captured copies: the cited sources state this directly and are independent."
                ),
                "evidence_ids": evidence,
                "independence_attested": target == "corroborated",
            },
            headers={"If-Match": f'"{detail["version"]}"'},
            expect=(200, 409),
        )


async def _seed(services: Any, app: Any, settings: Settings) -> dict[str, str]:
    from angel_engine.legal.documents import current_versions

    versions = current_versions()
    origin = settings.public_origin
    await _create_users(services)
    by_role = {u.role: u for u in DEMO_USERS}

    # --- Investigator: an organization investigation with images, collection, findings and a report ---------------
    ivy = Api(app, origin)
    await ivy.login(by_role["investigator"])
    created = await ivy.send(
        "POST",
        "/api/v1/investigations",
        json={
            "title": "Northwind Coffee Roasters — expansion claims",
            "description": "Verify public claims about a second roastery and the provenance of a storefront photo.",
            "subject_type": "organization",
            "purpose_category": "fact_checking",
            "purpose": (
                "Verify whether Northwind Coffee Roasters opened a second roastery as reported in March 2026, and "
                "establish where and when the storefront photo circulating on social media was first published."
            ),
            "lawful_basis": "public_interest_journalism",
            "authorization_ref": "DESK-2026-0412",
            "jurisdiction": "EU (GDPR)",
            "attestations": _attestations(versions),
        },
    )
    inv = created["investigation"]
    base = f"/api/v1/investigations/{inv['id']}"
    await ivy.get(base)  # records the last-active investigation for the dashboard

    first = await _upload(ivy, base, _storefront(), "storefront-harbour-street.jpg")
    await _upload(ivy, base, _storefront(size=(1200, 750), quality=70), "storefront-reshared.jpg")
    await _upload(ivy, base, _flyer(), "porto-opening-flyer.jpg")
    await _drain(services)

    for url in PAGES:
        await _run(ivy, base, "web_capture", "url", url)
    for connector, input_type, query in (
        ("rdap", "domain", DOMAIN),
        ("wayback", "domain", DOMAIN),
        ("crtsh", "domain", DOMAIN),
        ("dns", "domain", DOMAIN),
        ("common_crawl", "domain", DOMAIN),
        ("wikidata", "organization", ORG),
        ("gleif", "organization", ORG),
        ("wikipedia", "keyword", ORG),
        ("gdelt", "keyword", ORG),
    ):
        await _run(ivy, base, connector, input_type, query)
    await _drain(services)

    # Promote a clue from the first image into evidence.
    clues = await ivy.get(f"{base}/images/{first['id']}/clues")
    for clue in clues:
        if clue["type"] == "domain" and not clue["promoted_evidence_id"]:
            await ivy.send(
                "POST", f"{base}/images/{first['id']}/clues/{clue['id']}/promote", json={"importance": "key"}
            )
            break

    await _verify_findings(ivy, base)

    # Assistant (offline demo AI): a cited summary and extracted proposals.
    for task in ("summarize", "extract"):
        await ivy.send(
            "POST",
            f"{base}/assistant/requests",
            json={"task": task},
            headers={"Idempotency-Key": str(uuid.uuid4())},
            expect=(202, 422, 503),
        )
    await _drain(services)
    proposals = await ivy.get(f"{base}/assistant/proposals")
    for proposal in proposals[:2]:
        await ivy.send("POST", f"{base}/assistant/proposals/{proposal['id']}/accept", expect=(200, 409))

    await ivy.send(
        "POST",
        f"{base}/notes",
        json={"body": "Wire story and the daily both credit the same agency copy — treat them as one origin."},
    )
    await ivy.send("POST", f"{base}/reports", json={"title": "Northwind expansion — verification report"})

    # A refused request (no data is created; the decision is logged and explained).
    await _run(ivy, base, "gdelt", "keyword", "home address of the Northwind founder and her daily routine")

    # --- Investigator: an individual-subject investigation waiting for supervisor review ---------------------------
    await ivy.send(
        "POST",
        "/api/v1/investigations",
        json={
            "title": "Public statements attributed to a council spokesperson",
            "subject_type": "individual",
            "purpose_category": "fact_checking",
            "purpose": (
                "Check whether three quotes attributed to the council's spokesperson in published articles match the "
                "official council press releases. Public statements in an official capacity only."
            ),
            "lawful_basis": "public_interest_journalism",
            "authorization_ref": "DESK-2026-0533",
            "attestations": _attestations(versions),
        },
        expect=(201, 202),
    )
    await ivy.get(base)  # the dashboard's "continue where you left off" shows the main demo investigation
    await ivy.close()

    # --- Public visitors: an access request and an abuse report ----------------------------------------------------
    anon = Api(app, origin)
    token = (await anon.get("/api/v1/auth/csrf"))["csrf_token"]
    await anon.send(
        "POST",
        "/api/v1/auth/registration-requests",
        json={
            "email": "new.analyst@agency.example",
            "display_name": "Nia Newcomer",
            "password": "Quiet-Orchard-Signal-2026",
            "organization_unit": "Verification desk",
            "justification": "Joining the verification desk to work on image provenance checks for the elections team.",
            "accept_terms": True,
            "attest_lawful_use": True,
            "attest_no_misuse": True,
        },
        headers={"X-CSRF-Token": token},
    )
    await anon.send(
        "POST",
        "/api/v1/abuse-reports",
        json={
            "category": "data_removal_request",
            "description": (
                "I run a small café that appears in one of your public reports. "
                "Please review whether our opening hours are still needed."
            ),
            "target_ref": inv["ref"],
        },
        headers={"X-CSRF-Token": token},
    )
    await anon.close()
    return {"investigation": inv["ref"]}


def _storefront(**kwargs: Any) -> bytes:
    from angel_engine.demo.images import storefront

    return storefront(**kwargs)


def _flyer() -> bytes:
    from angel_engine.demo.images import flyer

    return flyer()


async def run_seed(*, reset: bool = False) -> None:
    from angel_engine.app_state import build_services
    from angel_engine.bootstrap import install_extras
    from angel_engine.db.models import User
    from angel_engine.main import create_app, sync_legal_documents

    logging.getLogger("httpx").setLevel(logging.WARNING)
    base_settings = get_settings()
    try:
        _check(base_settings)
    except SeedError as exc:
        print(f"seed-demo: {exc}", file=sys.stderr)  # noqa: T201
        raise SystemExit(2) from exc
    if reset:
        print("seed-demo: --reset is not supported; recreate the development database instead.", file=sys.stderr)  # noqa: T201
        raise SystemExit(2)
    # The in-process client is the only caller: skip rate limits so the seed is not throttled.
    settings = base_settings.model_copy(update={"rate_limit_enabled": False})
    services = build_services(settings)
    install_extras(services)
    try:
        async with services.db.session("app") as db:
            exists = (await db.execute(select(User.id).where(User.email == DEMO_USERS[0].email))).first()
        if exists:
            print("seed-demo: demo users already exist; nothing to do.")  # noqa: T201
            _print_accounts()
            return
        app = create_app(services=services)
        await sync_legal_documents(services)
        result = await _seed(services, app, settings)
    finally:
        await services.close()
    print(f"seed-demo: created demo investigation {result['investigation']}.")  # noqa: T201
    _print_accounts()


def _print_accounts() -> None:
    """The demo's sign-in details (fixed, published development values; the seed never runs in production)."""
    print(f"seed-demo: password for every demo account: {DEMO_PASSWORD}")  # noqa: T201
    for user in DEMO_USERS:
        print(f"  {user.role:<13} {user.email:<38} TOTP secret {user.totp_secret}")  # noqa: T201
    print(  # noqa: T201
        "seed-demo: for the six-digit sign-in code, add the account's TOTP secret to an authenticator app "
        "(time-based, 6 digits) or run: oathtool --totp -b <secret>"
    )
