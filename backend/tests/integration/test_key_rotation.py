"""KEK rotation re-wraps every live data key; retired KEKs can be destroyed once nothing depends on them."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select

from angel_engine.crypto.envelope import Vault
from angel_engine.crypto.keys import KeyringError
from angel_engine.db.models import AuditLog, DataKey
from angel_engine.jobs.maintenance import destroy_retired_kek, rotate_and_rewrap

pytestmark = pytest.mark.db


async def test_rotation_rewraps_and_retired_kek_can_be_destroyed(services):
    row_id = uuid.uuid4()
    async with services.db.session("maintenance") as db:
        cipher = await services.vault.system_cipher(db, "system_policy")
        sealed = cipher.seal("rotation canary", table="policy_decisions", column="input", row_id=row_id)
    old_kek, _ = services.keys.active_kek()

    with pytest.raises(KeyringError, match="active KEK"):
        await destroy_retired_kek(services, old_kek)

    result = await rotate_and_rewrap(services, trigger="test")
    new_kek, _ = services.keys.active_kek()
    assert result["kek_id"] == new_kek != old_kek
    async with services.db.session("maintenance") as db:
        stale = await db.scalar(
            select(func.count()).select_from(DataKey).where(DataKey.status != "destroyed", DataKey.kek_id != new_kek)
        )
    assert stale == 0

    await destroy_retired_kek(services, old_kek)
    assert old_kek not in {info.kek_id for info in services.keys.list_keks()}
    with pytest.raises(KeyringError, match="unknown KEK"):
        await destroy_retired_kek(services, old_kek)

    # A fresh vault (no cached keys) can still open data sealed before the rotation.
    async with services.db.session("maintenance") as db:
        reopened = await Vault(services.keys).cipher_for(db, sealed)
        assert reopened.open(sealed, table="policy_decisions", column="input", row_id=row_id) == "rotation canary"
        actions = (
            await db.execute(
                select(AuditLog.action, AuditLog.details)
                .where(AuditLog.action.in_(("keys.kek_rotated", "keys.kek_destroyed")))
                .order_by(AuditLog.seq.desc())
                .limit(2)
            )
        ).all()
    assert [a for a, _ in actions] == ["keys.kek_destroyed", "keys.kek_rotated"]
    assert actions[0][1] == {"kek_id": old_kek} and actions[1][1]["trigger"] == "test"


async def test_kek_still_wrapping_live_keys_is_not_destroyed(services):
    active, _ = services.keys.active_kek()
    async with services.db.session("maintenance") as db:
        await services.vault.system_cipher(db, "system_abuse")  # make sure a live key exists
    # Simulate a KEK that still wraps a live key: rotate the keyring without re-wrapping.
    services.keys.rotate_kek()
    try:
        with pytest.raises(KeyringError, match="still wrapped"):
            await destroy_retired_kek(services, active)
        assert active in {info.kek_id for info in services.keys.list_keks()}
    finally:
        await rotate_and_rewrap(services, trigger="test")
