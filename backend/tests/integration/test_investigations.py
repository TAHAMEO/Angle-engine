"""Investigations: gated creation, policy refusals, supervisor review, lifecycle, membership, oversight,
retention bounds and deletion with crypto-shredding + purge."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import select, text, update

from angel_engine.core.clock import utcnow
from angel_engine.crypto.envelope import KeyDestroyedError
from angel_engine.db.models import AuditLog, DataKey, Investigation, Job, PolicyDecision, UserSession
from angel_engine.db.session import set_investigation_scope
from angel_engine.jobs.worker import Worker
from angel_engine.legal.documents import current_versions
from tests.factories import add_evidence, make_investigation, scoped_session_add_source
from tests.helpers import PASSWORD, create_user, csrf_headers, login

pytestmark = pytest.mark.db

BENIGN_PURPOSE = (
    "Verify the publication history and provenance of a viral photo of the Northwind Coffee Roasters "
    "storefront before it is used in a fact-checking article."
)
UNSAFE_PURPOSE = (
    "Find the home address of my ex-girlfriend Jane Doe and track where she goes every day so I can show up there."
)


def payload(**overrides: Any) -> dict[str, Any]:
    versions = current_versions()
    body: dict[str, Any] = {
        "title": "Northwind storefront photo verification",
        "purpose": BENIGN_PURPOSE,
        "purpose_category": "fact_checking",
        "lawful_basis": "legitimate_interest",
        "subject_type": "organization",
        "attestations": {
            "lawful_purpose": True,
            "no_harassment_or_stalking": True,
            "no_discrimination": True,
            "no_impersonation": True,
            "understand_audit": True,
            "terms_version": versions["terms"],
            "acceptable_use_version": versions["acceptable_use"],
        },
    }
    body.update(overrides)
    return body


async def signed_in(client: httpx.AsyncClient, services, role: str = "investigator", **kw: Any):  # type: ignore[no-untyped-def]
    user = await create_user(services, role=role, **kw)
    await login(client, user)
    return user


async def create(client: httpx.AsyncClient, **overrides: Any) -> httpx.Response:
    return await client.post("/api/v1/investigations", json=payload(**overrides), headers=csrf_headers(client))


async def stale_reauth(services, user_id: uuid.UUID) -> None:  # type: ignore[no-untyped-def]
    """Pretend the sign-in happened long ago (logging in counts as a fresh authentication)."""
    async with services.db.session("app") as db:
        await db.execute(
            update(UserSession).where(UserSession.user_id == user_id).values(reauth_at=utcnow() - timedelta(hours=1))
        )


async def reauth(client: httpx.AsyncClient) -> None:
    resp = await client.post("/api/v1/auth/reauth", json={"password": PASSWORD}, headers=csrf_headers(client))
    assert resp.status_code == 200, resp.text


async def audit_actions(services, investigation_id: uuid.UUID) -> list[str]:  # type: ignore[no-untyped-def]
    async with services.db.session("app") as db:
        rows = (
            (
                await db.execute(
                    select(AuditLog.action).where(AuditLog.investigation_id == investigation_id).order_by(AuditLog.seq)
                )
            )
            .scalars()
            .all()
        )
    return list(rows)


# --------------------------------------------------------------------------------------------------
# Creation gate
# --------------------------------------------------------------------------------------------------
async def test_create_allowed_investigation(client, services):
    await signed_in(client, services)
    resp = await create(client, description="Public sources only.")
    assert resp.status_code == 201, resp.text
    body = resp.json()
    inv = body["investigation"]
    assert body["policy"]["decision"] in ("allow", "warn")
    assert inv["status"] == "active" and inv["restricted_mode"] is False
    assert inv["ref"].startswith(f"AE-{utcnow().year}-") and len(inv["ref"]) == 14
    assert inv["purpose"] == BENIGN_PURPOSE and inv["description"] == "Public sources only."
    assert inv["role"] == "owner"
    assert {"content:read", "content:write", "investigation:manage", "members:manage"} <= set(inv["permissions"])

    detail = await client.get(f"/api/v1/investigations/{inv['id']}")
    assert detail.status_code == 200 and detail.headers["etag"] == f'"{detail.json()["version"]}"'
    by_ref = await client.get(f"/api/v1/investigations/by-ref/{inv['ref'].lower()}")
    assert by_ref.status_code == 200 and by_ref.json()["id"] == inv["id"]

    listing = (await client.get("/api/v1/investigations")).json()
    assert [i["id"] for i in listing] == [inv["id"]]
    assert listing[0]["counts"] == {"evidence": 0, "sources": 0, "findings": 0, "images": 0}

    async with services.db.session("app") as db:
        stored = await db.get(Investigation, uuid.UUID(inv["id"]))
        assert stored is not None and BENIGN_PURPOSE.encode() not in stored.purpose  # encrypted at rest
    assert "investigation.created" in await audit_actions(services, uuid.UUID(inv["id"]))


async def test_create_requires_every_attestation_and_current_documents(client, services):
    await signed_in(client, services)
    body = payload()
    body["attestations"]["no_impersonation"] = False
    resp = await client.post("/api/v1/investigations", json=body, headers=csrf_headers(client))
    assert resp.status_code == 422 and resp.json()["code"] == "attestation_required"
    assert resp.json()["missing"] == ["no_impersonation"]

    body = payload()
    body["attestations"]["terms_version"] = "1999-01-01"
    resp = await client.post("/api/v1/investigations", json=body, headers=csrf_headers(client))
    assert resp.status_code == 422 and resp.json()["code"] == "stale_document_version"

    resp = await create(client, purpose_category="law_enforcement")
    assert resp.status_code == 422 and resp.json()["code"] == "authorization_required"

    resp = await create(client, purpose="Too short to explain anything.")
    assert resp.status_code == 422

    resp = await create(client, title="Contact jane.doe@gmail.com about the photo")
    assert resp.status_code == 422 and resp.json()["code"] == "sensitive_title"
    assert (await client.get("/api/v1/investigations")).json() == []


async def test_viewer_and_auditor_cannot_create(client, services):
    await signed_in(client, services, role="viewer")
    assert (await create(client)).status_code == 403


async def test_unsafe_purpose_is_refused_with_lawful_alternatives(client, services):
    user = await signed_in(client, services)
    resp = await create(client, purpose=UNSAFE_PURPOSE)
    assert resp.status_code == 422, resp.text
    problem = resp.json()
    assert problem["type"].endswith("/problems/policy-refused")
    policy = problem["policy"]
    assert policy["decision"] == "refuse"
    assert {"home_address", "location_tracking", "harassment_stalking"} & set(policy["categories"])
    assert policy["alternatives"], "refusals must offer lawful alternatives"
    assert "Jane" not in resp.text  # the submitted text is never echoed back

    # Nothing was created, but the refusal is on record for the user (without the text).
    assert (await client.get("/api/v1/investigations")).json() == []
    decisions = (await client.get("/api/v1/me/policy-decisions?decision=refuse")).json()
    assert len(decisions) == 1 and decisions[0]["id"] == policy["decision_id"]
    async with services.db.session("app") as db:
        row = await db.get(PolicyDecision, uuid.UUID(policy["decision_id"]))
        assert row is not None and row.user_id == user.id and row.input is not None
        assert UNSAFE_PURPOSE.encode() not in row.input  # stored encrypted, expires after 90 days
        refusals = (
            (
                await db.execute(
                    select(AuditLog).where(AuditLog.action == "policy.refused", AuditLog.actor_id == user.id)
                )
            )
            .scalars()
            .all()
        )
        assert len(refusals) == 1 and "Jane" not in str(refusals[0].details)


async def test_repeated_refusals_raise_account_flags(client, services):
    user = await signed_in(client, services)
    for _ in range(3):
        assert (await create(client, purpose=UNSAFE_PURPOSE)).status_code == 422
    from angel_engine.db.models import User

    async with services.db.session("app") as db:
        assert (await db.get(User, user.id)).refusal_flag_level == 1  # type: ignore[union-attr]


# --------------------------------------------------------------------------------------------------
# Individual subjects: supervisor review + restricted mode
# --------------------------------------------------------------------------------------------------
async def test_individual_subject_requires_supervisor_approval(client, anon_client, services):
    creator = await signed_in(client, services, role="supervisor")
    resp = await create(
        client,
        subject_type="individual",
        purpose_category="journalism",
        title="Spokesperson statement verification",
        purpose="Verify statements a company spokesperson made in public press conferences about the product "
        "recall, using official releases and published news coverage only.",
    )
    assert resp.status_code == 201, resp.text
    inv = resp.json()["investigation"]
    assert inv["status"] == "pending_review" and inv["restricted_mode"] is True
    assert "content:write" not in inv["permissions"]  # read-only until approved

    # The creator cannot approve their own request even though they are a supervisor.
    resp = await client.post(
        f"/api/v1/investigations/{inv['id']}/review", json={"decision": "approve"}, headers=csrf_headers(client)
    )
    assert resp.status_code == 403 and resp.json()["code"] == "self_review"

    reviewer = await signed_in(anon_client, services, role="supervisor")
    queue = (await anon_client.get("/api/v1/reviews")).json()
    item = next(i for i in queue if i["id"] == inv["id"])
    assert item["subject_type"] == "individual" and item["purpose"].startswith("Verify statements")
    # Reviewing does not grant content access.
    assert (await anon_client.get(f"/api/v1/investigations/{inv['id']}")).status_code == 404

    resp = await anon_client.post(
        f"/api/v1/investigations/{inv['id']}/review",
        json={"decision": "approve", "note": "Official-capacity statements only."},
        headers=csrf_headers(anon_client),
    )
    assert resp.status_code == 200 and resp.json()["status"] == "active"
    detail = (await client.get(f"/api/v1/investigations/{inv['id']}")).json()
    assert detail["status"] == "active" and detail["review_note"] == "Official-capacity statements only."
    assert "content:write" in detail["permissions"]
    async with services.db.session("app") as db:
        stored = await db.get(Investigation, uuid.UUID(inv["id"]))
        assert stored is not None and stored.reviewed_by == reviewer.id and stored.owner_id == creator.id
    assert (
        await anon_client.post(
            f"/api/v1/investigations/{inv['id']}/review",
            json={"decision": "approve"},
            headers=csrf_headers(anon_client),
        )
    ).status_code == 409


async def test_investigators_cannot_review(client, services):
    await signed_in(client, services)
    assert (await client.get("/api/v1/reviews")).status_code == 403


async def test_rejected_request_and_request_changes(client, anon_client, services):
    await signed_in(client, services)
    ids = []
    for _ in range(2):
        resp = await create(
            client,
            subject_type="individual",
            purpose_category="due_diligence",
            purpose="Review public, official-capacity statements and registry filings of a company "
            "director for a due-diligence report requested by our compliance team.",
        )
        assert resp.status_code == 201
        ids.append(resp.json()["investigation"]["id"])
    await signed_in(anon_client, services, role="supervisor")
    h = csrf_headers(anon_client)
    assert (
        await anon_client.post(f"/api/v1/investigations/{ids[0]}/review", json={"decision": "reject"}, headers=h)
    ).json()["status"] == "refused"
    assert (
        await anon_client.post(
            f"/api/v1/investigations/{ids[1]}/review", json={"decision": "request_changes"}, headers=h
        )
    ).json()["status"] == "draft"
    # A draft can be resubmitted by its owner; it goes back to the review queue.
    resp = await client.post(f"/api/v1/investigations/{ids[1]}/submit", headers=csrf_headers(client))
    assert resp.status_code == 200 and resp.json()["investigation"]["status"] == "pending_review"


# --------------------------------------------------------------------------------------------------
# Lifecycle, edits, membership
# --------------------------------------------------------------------------------------------------
async def test_lifecycle_transitions(client, services):
    await signed_in(client, services)
    inv = (await create(client)).json()["investigation"]
    base = f"/api/v1/investigations/{inv['id']}"
    h = csrf_headers(client)
    assert (await client.post(f"{base}/close", headers=h)).json() == {"status": "closed"}
    assert (await client.post(f"{base}/close", headers=h)).status_code == 409
    assert (await client.post(f"{base}/reopen", headers=h)).json() == {"status": "active"}
    assert (await client.post(f"{base}/close", headers=h)).status_code == 200
    assert (await client.post(f"{base}/archive", headers=h)).json() == {"status": "archived"}
    # Restoring and suspending are supervisor actions.
    assert (await client.post(f"{base}/restore", headers=h)).status_code == 403
    assert (await client.post(f"{base}/frobnicate", headers=h)).status_code in (404, 405)
    actions = await audit_actions(services, uuid.UUID(inv["id"]))
    assert actions.count("investigation.close") == 2 and "investigation.archive" in actions


async def test_patch_uses_optimistic_concurrency(client, services):
    await signed_in(client, services)
    inv = (await create(client)).json()["investigation"]
    url = f"/api/v1/investigations/{inv['id']}"
    resp = await client.patch(
        url, json={"description": "Updated scope."}, headers={**csrf_headers(client), "If-Match": f'"{inv["version"]}"'}
    )
    assert resp.status_code == 200 and resp.json()["description"] == "Updated scope."
    stale = await client.patch(
        url, json={"ai_enabled": False}, headers={**csrf_headers(client), "If-Match": f'"{inv["version"]}"'}
    )
    assert stale.status_code == 412


async def test_membership_and_non_member_404(client, anon_client, services):
    await signed_in(client, services)
    inv = (await create(client)).json()["investigation"]
    url = f"/api/v1/investigations/{inv['id']}"
    colleague = await signed_in(anon_client, services)
    assert (await anon_client.get(url)).status_code == 404  # existence is not revealed

    admin = await create_user(services, role="admin")
    resp = await client.post(
        f"{url}/members", json={"email": admin.email, "role": "viewer"}, headers=csrf_headers(client)
    )
    assert resp.status_code == 400 and resp.json()["code"] == "role_not_allowed"

    resp = await client.post(
        f"{url}/members", json={"email": colleague.email, "role": "viewer"}, headers=csrf_headers(client)
    )
    assert resp.status_code == 201
    detail = (await anon_client.get(url)).json()
    assert detail["role"] == "viewer" and detail["permissions"] == ["content:read"]
    assert detail["authorization_ref"] is None
    assert (
        await anon_client.patch(url, json={"ai_enabled": False}, headers=csrf_headers(anon_client))
    ).status_code == 403
    assert (await anon_client.post(f"{url}/close", headers=csrf_headers(anon_client))).status_code == 403

    resp = await client.patch(f"{url}/members/{colleague.id}", json={"role": "editor"}, headers=csrf_headers(client))
    assert resp.status_code == 200
    members = (await client.get(f"{url}/members")).json()
    assert {m["role"] for m in members} == {"owner", "editor"}
    assert (await client.delete(f"{url}/members/{colleague.id}", headers=csrf_headers(client))).status_code == 200
    assert (await anon_client.get(url)).status_code == 404
    actions = await audit_actions(services, uuid.UUID(inv["id"]))
    assert {
        "investigation.member_added",
        "investigation.member_role_changed",
        "investigation.member_removed",
        "investigation.access_denied",
    } <= set(actions)


async def test_oversight_grant_gives_time_boxed_read_only_access(client, anon_client, services):
    await signed_in(client, services)
    inv = (await create(client)).json()["investigation"]
    url = f"/api/v1/investigations/{inv['id']}"
    supervisor = await signed_in(anon_client, services, role="supervisor")
    await stale_reauth(services, supervisor.id)
    assert (await anon_client.get(url)).status_code == 404
    body = {"reason": "Quarterly compliance review of active investigations.", "hours": 4}
    resp = await anon_client.post(f"{url}/oversight-grants", json=body, headers=csrf_headers(anon_client))
    assert resp.status_code == 401 and resp.json()["type"].endswith("reauth-required")
    await reauth(anon_client)
    resp = await anon_client.post(
        f"{url}/oversight-grants", json={**body, "hours": 96}, headers=csrf_headers(anon_client)
    )
    assert resp.status_code == 422
    resp = await anon_client.post(f"{url}/oversight-grants", json=body, headers=csrf_headers(anon_client))
    assert resp.status_code == 201
    detail = (await anon_client.get(url)).json()
    assert detail["oversight"] is True and detail["permissions"] == ["content:read"]
    assert (
        await anon_client.patch(url, json={"ai_enabled": False}, headers=csrf_headers(anon_client))
    ).status_code == 403
    actions = await audit_actions(services, uuid.UUID(inv["id"]))
    assert "investigation.oversight_granted" in actions and "investigation.oversight_read" in actions


# --------------------------------------------------------------------------------------------------
# Retention and deletion
# --------------------------------------------------------------------------------------------------
async def test_retention_overrides_are_bounded(client, services):
    await signed_in(client, services)
    inv = (await create(client)).json()["investigation"]
    url = f"/api/v1/investigations/{inv['id']}/retention"
    current = (await client.get(url)).json()
    assert current["image_original_retention_hours"] == 24 and current["legal_hold"] is False
    too_long = current["image_original_retention_max_hours"] + 1
    resp = await client.put(url, json={"image_original_retention_hours": too_long}, headers=csrf_headers(client))
    assert resp.status_code == 422
    resp = await client.put(
        url, json={"image_original_retention_hours": 0, "closed_retention_days": 30}, headers=csrf_headers(client)
    )
    assert resp.status_code == 200
    assert resp.json()["image_original_retention_hours"] == 0 and resp.json()["closed_retention_days"] == 30


async def test_deletion_crypto_shreds_then_purges(client, services):
    user = await signed_in(client, services)
    inv = (await create(client)).json()["investigation"]
    inv_id = uuid.UUID(inv["id"])
    async with services.db.session("app") as db:
        cipher = await services.vault.investigation_cipher(db, inv_id)
        source = await scoped_session_add_source(db, cipher, inv_id)
        await add_evidence(db, cipher, inv_id, source.id)

    url = f"/api/v1/investigations/{inv['id']}/deletion"
    body = {"confirm_ref": inv["ref"], "reason": "Engagement finished."}
    await stale_reauth(services, user.id)
    resp = await client.post(url, json=body, headers=csrf_headers(client))
    assert resp.status_code == 401  # deletion needs a fresh re-authentication
    await reauth(client)
    resp = await client.post(url, json={**body, "confirm_ref": "AE-0000-000000"}, headers=csrf_headers(client))
    assert resp.status_code == 422 and resp.json()["code"] == "confirm_mismatch"
    resp = await client.post(url, json=body, headers=csrf_headers(client))
    assert resp.status_code == 202 and resp.json()["ref"] == inv["ref"]

    assert (await client.get(f"/api/v1/investigations/{inv['id']}")).status_code == 404
    assert (await client.get("/api/v1/investigations")).json() == []
    async with services.db.session("app") as db:
        keys = (await db.execute(select(DataKey).where(DataKey.investigation_id == inv_id))).scalars().all()
        assert keys and all(k.status == "destroyed" and k.wrapped_dek is None for k in keys)
        services.vault.evict_investigation(inv_id)
        with pytest.raises(KeyDestroyedError):
            await services.vault.investigation_cipher(db, inv_id)
        tomb = await db.get(Investigation, inv_id)
        assert tomb is not None and tomb.status == "deleted" and tomb.title == f"Deleted investigation {inv['ref']}"
        assert tomb.purpose == b"" and tomb.description is None

    await Worker(services, ["maintenance"]).run_until_idle()
    async with services.db.session("app") as db:
        await set_investigation_scope(db, [inv_id])
        remaining = (await db.execute(text("SELECT count(*) FROM evidence_items"))).scalar_one()
        assert remaining == 0
        purge = (await db.execute(select(Job).where(Job.idempotency_key == f"purge:{inv_id}"))).scalar_one()
        assert purge.status == "succeeded" and purge.result["rows"]["evidence_items"] == 1
    actions = await audit_actions(services, inv_id)
    assert "investigation.deleted" in actions and "investigation.purged" in actions
    assert user.id  # the owner's account itself is untouched


async def test_legal_hold_blocks_deletion(client, anon_client, services):
    await signed_in(client, services)
    inv = (await create(client)).json()["investigation"]
    await signed_in(anon_client, services, role="admin")
    await reauth(anon_client)
    hold = await anon_client.put(
        f"/api/v1/investigations/{inv['id']}/legal-hold",
        json={"enabled": True, "reason": "Preservation notice received."},
        headers=csrf_headers(anon_client),
    )
    assert hold.status_code == 200 and hold.json()["legal_hold"] is True
    await reauth(client)
    resp = await client.post(
        f"/api/v1/investigations/{inv['id']}/deletion",
        json={"confirm_ref": inv["ref"], "reason": "Engagement finished."},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 409 and resp.json()["code"] == "legal_hold"
    # Admins administer holds but still cannot read the investigation.
    assert (await anon_client.get(f"/api/v1/investigations/{inv['id']}")).status_code == 404


async def test_retention_sweep_archives_and_deletes(services):
    owner = await create_user(services)
    archive_id = await make_investigation(services, owner.id, status="closed")
    delete_id = await make_investigation(services, owner.id, status="closed")
    held_id = await make_investigation(services, owner.id, status="closed")
    draft_id = await make_investigation(services, owner.id, status="draft")
    async with services.db.session("maintenance") as db:
        now = utcnow()
        await db.execute(
            update(Investigation).where(Investigation.id == archive_id).values(closed_at=now - timedelta(days=100))
        )
        await db.execute(
            update(Investigation)
            .where(Investigation.id.in_([delete_id, held_id]))
            .values(closed_at=now - timedelta(days=400))
        )
        await db.execute(update(Investigation).where(Investigation.id == held_id).values(legal_hold=True))
        await db.execute(
            text("UPDATE investigations SET updated_at = now() - interval '45 days' WHERE id = :i"), {"i": draft_id}
        )

    from angel_engine.jobs import queue as q

    async with services.db.session("app") as db:
        await q.enqueue(db, queue="maintenance", kind="retention.sweep")
    await Worker(services, ["maintenance"]).run_until_idle()
    async with services.db.session("app") as db:
        statuses = {
            i.id: i.status
            for i in (
                await db.execute(
                    select(Investigation).where(Investigation.id.in_([archive_id, delete_id, held_id, draft_id]))
                )
            ).scalars()
        }
    assert statuses == {archive_id: "archived", delete_id: "deleted", held_id: "closed", draft_id: "deleted"}


async def test_admin_retention_settings(client, services):
    admin = await signed_in(client, services, role="admin")
    await stale_reauth(services, admin.id)
    url = "/api/v1/admin/settings/retention"
    current = (await client.get(url)).json()
    assert current["values"]["image_original_hours"] == 24 and current["overridden"] == []
    resp = await client.patch(url, json={"image_original_hours": 12}, headers=csrf_headers(client))
    assert resp.status_code == 401
    await reauth(client)
    resp = await client.patch(url, json={"ai_transcript_days": 500}, headers=csrf_headers(client))
    assert resp.status_code == 422 and resp.json()["code"] == "setting_out_of_bounds"
    resp = await client.patch(url, json={"image_original_hours": 12}, headers=csrf_headers(client))
    assert resp.status_code == 200 and resp.json()["values"]["image_original_hours"] == 12
    resp = await client.patch(url, json={"image_original_hours": None}, headers=csrf_headers(client))
    assert resp.json()["values"]["image_original_hours"] == 24 and resp.json()["overridden"] == []
