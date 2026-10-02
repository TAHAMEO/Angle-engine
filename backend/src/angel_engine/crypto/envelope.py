"""Envelope encryption.

Key hierarchy: KEK (keyring, outside the database) → DEK per investigation (and per system scope),
stored wrapped in ``data_keys`` → field ciphertexts and per-object file keys.

Field ciphertext format (version 1)::

    0x01 ‖ dek_id (16 bytes) ‖ nonce (12 bytes) ‖ AES-256-GCM(ciphertext ‖ tag)

The additional authenticated data binds every ciphertext to its location
(``ae1|table|column|row_id|investigation_id``), so ciphertexts cannot be swapped between rows or columns.
Destroying an investigation's DEK (``wrapped_dek = NULL``) makes every ciphertext and keyed hash derived
from it permanently unusable (crypto-shredding).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from collections import OrderedDict
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.core.clock import utcnow
from angel_engine.core.ids import new_id
from angel_engine.crypto.keys import KeyProvider
from angel_engine.db.models import DataKey

FORMAT_V1 = 0x01
_HEADER = 1 + 16 + 12
SYSTEM_SCOPES = ("system_secrets", "system_abuse", "system_policy")


class CryptoError(RuntimeError):
    pass


class KeyDestroyedError(CryptoError):
    """The data key was destroyed: the content is permanently unreadable (crypto-shredded)."""


def _aad(table: str, column: str, row_id: uuid.UUID | str, investigation_id: uuid.UUID | None) -> bytes:
    return f"ae1|{table}|{column}|{row_id}|{investigation_id or '-'}".encode()


def ciphertext_key_id(ciphertext: bytes) -> uuid.UUID:
    if len(ciphertext) < _HEADER + 16 or ciphertext[0] != FORMAT_V1:
        raise CryptoError("unrecognized ciphertext format")
    return uuid.UUID(bytes=ciphertext[1:17])


class FieldCipher:
    """Encrypts/decrypts fields with one DEK and derives purpose-bound keyed-hash subkeys."""

    __slots__ = ("_aes", "_key", "_subkeys", "dek_id", "investigation_id")

    def __init__(self, dek_id: uuid.UUID, key: bytes, investigation_id: uuid.UUID | None) -> None:
        self.dek_id = dek_id
        self.investigation_id = investigation_id
        self._key = key
        self._aes = AESGCM(key)
        self._subkeys: dict[str, bytes] = {}

    # -- field encryption ------------------------------------------------------------------------
    def seal(self, value: str | bytes, *, table: str, column: str, row_id: uuid.UUID | str) -> bytes:
        data = value.encode("utf-8") if isinstance(value, str) else value
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, data, _aad(table, column, row_id, self.investigation_id))
        return bytes([FORMAT_V1]) + self.dek_id.bytes + nonce + ct

    def seal_optional(self, value: str | None, *, table: str, column: str, row_id: uuid.UUID | str) -> bytes | None:
        return None if value is None else self.seal(value, table=table, column=column, row_id=row_id)

    def seal_json(self, value: Any, *, table: str, column: str, row_id: uuid.UUID | str) -> bytes:
        return self.seal(
            json.dumps(value, separators=(",", ":"), default=str), table=table, column=column, row_id=row_id
        )

    def open_bytes(self, ciphertext: bytes, *, table: str, column: str, row_id: uuid.UUID | str) -> bytes:
        if ciphertext_key_id(ciphertext) != self.dek_id:
            raise CryptoError("ciphertext was produced with a different key")
        nonce, ct = ciphertext[17:_HEADER], ciphertext[_HEADER:]
        try:
            return self._aes.decrypt(nonce, ct, _aad(table, column, row_id, self.investigation_id))
        except Exception as exc:  # cryptography raises InvalidTag
            raise CryptoError("ciphertext failed authentication") from exc

    def open(self, ciphertext: bytes, *, table: str, column: str, row_id: uuid.UUID | str) -> str:
        return self.open_bytes(ciphertext, table=table, column=column, row_id=row_id).decode("utf-8")

    def open_optional(
        self, ciphertext: bytes | None, *, table: str, column: str, row_id: uuid.UUID | str
    ) -> str | None:
        return None if ciphertext is None else self.open(ciphertext, table=table, column=column, row_id=row_id)

    def open_json(self, ciphertext: bytes, *, table: str, column: str, row_id: uuid.UUID | str) -> Any:
        return json.loads(self.open(ciphertext, table=table, column=column, row_id=row_id))

    # -- blobs (per-object keys) ------------------------------------------------------------------
    def new_file_key(self) -> bytes:
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def encrypt_blob(file_key: bytes, data: bytes, *, object_key: str) -> bytes:
        nonce = os.urandom(12)
        return bytes([FORMAT_V1]) + nonce + AESGCM(file_key).encrypt(nonce, data, f"ae1|blob|{object_key}".encode())

    @staticmethod
    def decrypt_blob(file_key: bytes, blob: bytes, *, object_key: str) -> bytes:
        if not blob or blob[0] != FORMAT_V1:
            raise CryptoError("unrecognized blob format")
        try:
            return AESGCM(file_key).decrypt(blob[1:13], blob[13:], f"ae1|blob|{object_key}".encode())
        except Exception as exc:
            raise CryptoError("blob failed authentication") from exc

    # -- keyed hashes -------------------------------------------------------------------------------
    def subkey(self, purpose: str) -> bytes:
        key = self._subkeys.get(purpose)
        if key is None:
            key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=purpose.encode()).derive(self._key)
            self._subkeys[purpose] = key
        return key

    def mac(self, purpose: str, data: str | bytes) -> bytes:
        raw = data.encode("utf-8") if isinstance(data, str) else data
        return hmac.new(self.subkey(purpose), raw, hashlib.sha256).digest()


class Vault:
    """Creates, caches, unwraps and destroys DEKs. One instance per process."""

    def __init__(self, keys: KeyProvider, *, cache_ttl_s: float = 300.0, cache_size: int = 512) -> None:
        self.keys = keys
        self._ttl = cache_ttl_s
        self._size = cache_size
        self._cache: OrderedDict[uuid.UUID, tuple[float, FieldCipher]] = OrderedDict()
        self._by_investigation: dict[uuid.UUID, uuid.UUID] = {}

    # -- cache ---------------------------------------------------------------------------------
    def _remember(self, cipher: FieldCipher) -> FieldCipher:
        self._cache[cipher.dek_id] = (time.monotonic() + self._ttl, cipher)
        self._cache.move_to_end(cipher.dek_id)
        while len(self._cache) > self._size:
            self._cache.popitem(last=False)
        return cipher

    def _cached(self, dek_id: uuid.UUID) -> FieldCipher | None:
        hit = self._cache.get(dek_id)
        if hit is None:
            return None
        expires, cipher = hit
        if expires < time.monotonic():
            del self._cache[dek_id]
            return None
        return cipher

    def evict_investigation(self, investigation_id: uuid.UUID) -> None:
        self._by_investigation.pop(investigation_id, None)
        for dek_id, (_, cipher) in list(self._cache.items()):
            if cipher.investigation_id == investigation_id:
                del self._cache[dek_id]

    # -- wrapping ------------------------------------------------------------------------------
    def _wrap(self, dek_id: uuid.UUID, dek: bytes) -> tuple[str, bytes]:
        kek_id, kek = self.keys.active_kek()
        nonce = os.urandom(12)
        return kek_id, nonce + AESGCM(kek).encrypt(nonce, dek, b"dek|" + dek_id.bytes)

    def _unwrap(self, row: DataKey) -> FieldCipher:
        if row.status == "destroyed" or row.wrapped_dek is None:
            raise KeyDestroyedError("this content has been permanently deleted")
        kek = self.keys.kek(row.kek_id)
        wrapped = row.wrapped_dek
        dek = AESGCM(kek).decrypt(wrapped[:12], wrapped[12:], b"dek|" + row.id.bytes)
        return FieldCipher(row.id, dek, row.investigation_id)

    # -- public API ----------------------------------------------------------------------------
    async def create_investigation_key(self, session: AsyncSession, investigation_id: uuid.UUID) -> FieldCipher:
        dek_id = new_id()
        dek = AESGCM.generate_key(bit_length=256)
        kek_id, wrapped = self._wrap(dek_id, dek)
        session.add(
            DataKey(
                id=dek_id,
                investigation_id=investigation_id,
                scope="investigation",
                version=1,
                kek_id=kek_id,
                wrapped_dek=wrapped,
                status="active",
            )
        )
        await session.flush()
        self._by_investigation[investigation_id] = dek_id
        return self._remember(FieldCipher(dek_id, dek, investigation_id))

    async def investigation_cipher(self, session: AsyncSession, investigation_id: uuid.UUID) -> FieldCipher:
        known = self._by_investigation.get(investigation_id)
        if known is not None:
            hit = self._cached(known)
            if hit is not None:
                return hit
        row = (
            await session.execute(
                select(DataKey).where(DataKey.investigation_id == investigation_id, DataKey.status == "active")
            )
        ).scalar_one_or_none()
        if row is None:
            destroyed = (
                await session.execute(select(DataKey.id).where(DataKey.investigation_id == investigation_id).limit(1))
            ).first()
            if destroyed is not None:
                raise KeyDestroyedError("this investigation has been deleted")
            raise CryptoError("no data key for investigation")
        cipher = self._unwrap(row)
        self._by_investigation[investigation_id] = cipher.dek_id
        return self._remember(cipher)

    async def system_cipher(self, session: AsyncSession, scope: str) -> FieldCipher:
        if scope not in SYSTEM_SCOPES:
            raise CryptoError(f"unknown system scope {scope}")
        row = (
            await session.execute(
                select(DataKey).where(
                    DataKey.scope == scope, DataKey.status == "active", DataKey.investigation_id.is_(None)
                )
            )
        ).scalar_one_or_none()
        if row is not None:
            hit = self._cached(row.id)
            return hit if hit is not None else self._remember(self._unwrap(row))
        dek_id = new_id()
        dek = AESGCM.generate_key(bit_length=256)
        kek_id, wrapped = self._wrap(dek_id, dek)
        session.add(
            DataKey(
                id=dek_id,
                investigation_id=None,
                scope=scope,
                version=1,
                kek_id=kek_id,
                wrapped_dek=wrapped,
                status="active",
            )
        )
        await session.flush()
        return self._remember(FieldCipher(dek_id, dek, None))

    async def cipher_for(self, session: AsyncSession, ciphertext: bytes) -> FieldCipher:
        dek_id = ciphertext_key_id(ciphertext)
        hit = self._cached(dek_id)
        if hit is not None:
            return hit
        row = (await session.execute(select(DataKey).where(DataKey.id == dek_id))).scalar_one_or_none()
        if row is None:
            raise KeyDestroyedError("this content has been permanently deleted")
        return self._remember(self._unwrap(row))

    async def destroy_investigation_keys(self, session: AsyncSession, investigation_id: uuid.UUID) -> int:
        result = await session.execute(
            update(DataKey)
            .where(DataKey.investigation_id == investigation_id, DataKey.status != "destroyed")
            .values(wrapped_dek=None, status="destroyed", destroyed_at=utcnow())
        )
        self.evict_investigation(investigation_id)
        return int(getattr(result, "rowcount", 0) or 0)

    async def rewrap_all(self, session: AsyncSession) -> int:
        """Re-wrap every live DEK under the active KEK (after KEK rotation)."""
        active_kek_id, _ = self.keys.active_kek()
        rows = (
            (
                await session.execute(
                    select(DataKey).where(DataKey.status != "destroyed", DataKey.kek_id != active_kek_id)
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            cipher = self._unwrap(row)
            row.kek_id, row.wrapped_dek = self._wrap(row.id, cipher._key)
        return len(rows)
