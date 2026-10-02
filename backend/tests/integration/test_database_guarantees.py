"""Row-level security, integrity triggers, crypto-shredding and the audit chain at the database level."""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

from angel_engine.audit.chain import AuditEvent, append_now, verify_chain
from angel_engine.core.clock import utcnow
from angel_engine.core.ids import new_id
from angel_engine.crypto.envelope import KeyDestroyedError
from angel_engine.db.models import EvidenceItem, Finding, FindingEvidence, Source
from angel_engine.db.session import allow_status_transition, set_investigation_scope
from tests.factories import add_evidence, make_investigation, scoped_session_add_source
from tests.helpers import create_user

pytestmark = pytest.mark.db


async def _setup(services):
    owner = await create_user(services)
    inv_a = await make_investigation(services, owner.id)
    inv_b = await make_investigation(services, owner.id)
    return owner, inv_a, inv_b


async def test_row_level_security_isolates_investigations(services):
    _, inv_a, inv_b = await _setup(services)
    async with services.db.session("app") as db:
        cipher_a = await services.vault.investigation_cipher(db, inv_a)
        await scoped_session_add_source(db, cipher_a, inv_a)
    async with services.db.session("app") as db:
        cipher_b = await services.vault.investigation_cipher(db, inv_b)
        await scoped_session_add_source(db, cipher_b, inv_b)
    async with services.db.session("app") as db:
        assert (await db.execute(select(Source))).scalars().all() == []  # no scope → nothing visible
        await set_investigation_scope(db, [inv_a])
        rows = (await db.execute(select(Source))).scalars().all()
        assert {r.investigation_id for r in rows} == {inv_a}
    with pytest.raises((DBAPIError, ProgrammingError)):
        async with services.db.session("app") as db:
            await set_investigation_scope(db, [inv_a])
            sid = new_id()
            db.add(
                Source(
                    id=sid,
                    investigation_id=inv_b,
                    label_seq=2,
                    url=b"x",
                    url_mac=b"y",
                    host="h.example",
                    registrable_domain="h.example",
                    source_category="websites",
                    connector_id="web_capture",
                    first_captured_at=utcnow(),
                    last_captured_at=utcnow(),
                )
            )
            await db.flush()  # WITH CHECK rejects writes outside the transaction's scope


async def test_evidence_is_immutable_and_findings_need_evidence(services):
    _, inv, _ = await _setup(services)
    async with services.db.session("app") as db:
        cipher = await services.vault.investigation_cipher(db, inv)
        src = await scoped_session_add_source(db, cipher, inv)
        ev = await add_evidence(db, cipher, inv, src.id)
        ev_id = ev.id
    with pytest.raises(DBAPIError):
        async with services.db.session("app") as db:
            await set_investigation_scope(db, [inv])
            await db.execute(update(EvidenceItem).where(EvidenceItem.id == ev_id).values(excerpt=b"tampered"))
    with pytest.raises((DBAPIError, IntegrityError)):
        async with services.db.session("app") as db:
            await set_investigation_scope(db, [inv])
            fid = new_id()
            db.add(
                Finding(
                    id=fid,
                    investigation_id=inv,
                    label_seq=1,
                    statement=b"x",
                    category="websites",
                    provenance="source_reported",
                    verification_status="unverified",
                    created_via="manual",
                )
            )
    async with services.db.session("app") as db:  # with an evidence link the deferred check passes
        await set_investigation_scope(db, [inv])
        fid = new_id()
        db.add(
            Finding(
                id=fid,
                investigation_id=inv,
                label_seq=1,
                statement=b"x",
                category="websites",
                provenance="source_reported",
                verification_status="unverified",
                created_via="manual",
            )
        )
        await db.flush()
        db.add(FindingEvidence(investigation_id=inv, finding_id=fid, evidence_id=ev_id, stance="supports"))
    with pytest.raises(DBAPIError):  # status changes need an audited transition
        async with services.db.session("app") as db:
            await set_investigation_scope(db, [inv])
            await db.execute(update(Finding).where(Finding.id == fid).values(verification_status="corroborated"))
    async with services.db.session("app") as db:
        await set_investigation_scope(db, [inv])
        await allow_status_transition(db)
        await db.execute(update(Finding).where(Finding.id == fid).values(verification_status="confirmed_by_source"))
    with pytest.raises(DBAPIError):  # provenance never changes
        async with services.db.session("app") as db:
            await set_investigation_scope(db, [inv])
            await allow_status_transition(db)
            await db.execute(update(Finding).where(Finding.id == fid).values(provenance="observed"))


async def test_ai_status_requires_ai_provenance(services):
    _, inv, _ = await _setup(services)
    with pytest.raises(IntegrityError):
        async with services.db.session("app") as db:
            await set_investigation_scope(db, [inv])
            db.add(
                Finding(
                    id=new_id(),
                    investigation_id=inv,
                    label_seq=1,
                    statement=b"x",
                    category="analysis",
                    provenance="source_reported",
                    verification_status="ai_hypothesis",
                    created_via="manual",
                )
            )


async def test_crypto_shredding_makes_content_unreadable(services):
    _, inv, _ = await _setup(services)
    async with services.db.session("app") as db:
        cipher = await services.vault.investigation_cipher(db, inv)
        src = await scoped_session_add_source(db, cipher, inv)
        ciphertext, src_id = src.url, src.id
    async with services.db.session("app") as db:
        assert await services.vault.destroy_investigation_keys(db, inv) >= 1
    async with services.db.session("app") as db:
        with pytest.raises(KeyDestroyedError):
            await services.vault.investigation_cipher(db, inv)
        with pytest.raises(KeyDestroyedError):
            await services.vault.cipher_for(db, ciphertext)
    assert src_id


async def test_audit_chain_concurrent_appends_and_tamper_detection(services):
    async def one(i: int) -> None:
        async with services.db.session("app") as db:
            await append_now(
                db, services.audit_key, [AuditEvent(action="test.concurrent", actor_type="system", details={"i": i})]
            )

    await asyncio.gather(*(one(i) for i in range(20)))
    async with services.db.session("app") as db:
        result = await verify_chain(db, services.audit_key)
        assert result.ok, result
    with pytest.raises(DBAPIError):
        async with services.db.session("app") as db:
            await db.execute(text("UPDATE audit_log SET action = 'x' WHERE seq = 1"))
    with pytest.raises(DBAPIError):
        async with services.db.session("app") as db:
            await db.execute(text("DELETE FROM audit_log WHERE seq = 1"))
    # A privileged attacker who disables the trigger is still detected by the hash chain.
    from sqlalchemy.ext.asyncio import create_async_engine

    owner = create_async_engine(services.settings.database_url_owner)
    try:
        async with owner.begin() as conn:
            target_seq = (await conn.execute(text("SELECT max(seq) - 3 FROM audit_log"))).scalar_one()
            original = (
                await conn.execute(text("SELECT details::text FROM audit_log WHERE seq = :s"), {"s": target_seq})
            ).scalar_one()
            await conn.execute(text("ALTER TABLE audit_log DISABLE TRIGGER trg_audit_guard"))
            await conn.execute(
                text("UPDATE audit_log SET details = '{\"tampered\": true}' WHERE seq = :s"), {"s": target_seq}
            )
            await conn.execute(text("ALTER TABLE audit_log ENABLE TRIGGER trg_audit_guard"))
        async with services.db.session("app") as db:
            result = await verify_chain(db, services.audit_key)
            assert not result.ok and result.reason == "row content does not match its hash"
            assert result.first_broken_seq == target_seq
    finally:
        async with owner.begin() as conn:  # restore the exact original row
            await conn.execute(text("ALTER TABLE audit_log DISABLE TRIGGER trg_audit_guard"))
            await conn.execute(
                text("UPDATE audit_log SET details = CAST(:d AS jsonb) WHERE seq = :s"),
                {"d": original, "s": target_seq},
            )
            await conn.execute(text("ALTER TABLE audit_log ENABLE TRIGGER trg_audit_guard"))
        await owner.dispose()
    async with services.db.session("app") as db:
        assert (await verify_chain(db, services.audit_key)).ok
