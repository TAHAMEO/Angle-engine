"""Envelope encryption, AAD binding, blind index and keyed hashes (no database)."""

from __future__ import annotations

import uuid

import pytest

from angel_engine.crypto import blind_index
from angel_engine.crypto.envelope import CryptoError, FieldCipher, ciphertext_key_id
from angel_engine.crypto.keys import KeyringError, MemoryKeyring


def _cipher(inv: uuid.UUID | None = None) -> FieldCipher:
    import os

    return FieldCipher(uuid.uuid4(), os.urandom(32), inv or uuid.uuid4())


def test_seal_open_roundtrip_and_header():
    c = _cipher()
    row = uuid.uuid4()
    ct = c.seal("Northwind Coffee Roasters", table="findings", column="statement", row_id=row)
    assert ciphertext_key_id(ct) == c.dek_id
    assert b"Northwind" not in ct
    assert c.open(ct, table="findings", column="statement", row_id=row) == "Northwind Coffee Roasters"


def test_ciphertext_is_bound_to_its_location():
    c = _cipher()
    row = uuid.uuid4()
    ct = c.seal("secret", table="findings", column="statement", row_id=row)
    with pytest.raises(CryptoError):
        c.open(ct, table="findings", column="statement", row_id=uuid.uuid4())
    with pytest.raises(CryptoError):
        c.open(ct, table="notes", column="body", row_id=row)


def test_other_key_cannot_open():
    a, b = _cipher(), _cipher()
    row = uuid.uuid4()
    ct = a.seal("x", table="t", column="c", row_id=row)
    with pytest.raises(CryptoError):
        b.open(ct, table="t", column="c", row_id=row)


def test_blob_roundtrip():
    c = _cipher()
    key = c.new_file_key()
    blob = FieldCipher.encrypt_blob(key, b"\x89PNG data", object_key="inv/1/img/original")
    assert FieldCipher.decrypt_blob(key, blob, object_key="inv/1/img/original") == b"\x89PNG data"
    with pytest.raises(CryptoError):
        FieldCipher.decrypt_blob(key, blob, object_key="inv/1/img/preview")


def test_blind_index_terms_and_tokens():
    assert blind_index.terms("The Roasters ROASTED coffee in Lisbon") == ["roaster", "roast", "coffe", "lisbon"]
    a, b = _cipher(), _cipher()
    ta = blind_index.tokens(a, "Northwind coffee roasters")
    assert set(blind_index.query_tokens(a, "roaster")) <= set(ta)
    assert set(blind_index.tokens(b, "Northwind coffee roasters")).isdisjoint(ta)  # per-investigation keys


def test_keyring_rotation_and_destruction():
    kr = MemoryKeyring()
    old_id, old_key = kr.active_kek()
    new_id = kr.rotate_kek()
    assert new_id != old_id and kr.kek(old_id) == old_key
    with pytest.raises(KeyringError):
        kr.destroy_kek(new_id)
    kr.destroy_kek(old_id)
    with pytest.raises(KeyringError):
        kr.kek(old_id)
    assert kr.ip_key("2026-01") == kr.ip_key("2026-01")
    assert kr.destroy_ip_keys_before("2026-02") == 1
