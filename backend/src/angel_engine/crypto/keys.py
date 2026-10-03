"""Key material provider.

The keyring holds:

* **KEKs** (key-encryption keys) that wrap every data-encryption key (DEK) stored in the database.
  KEKs rotate in epochs; destroying a retired epoch after the backup-retention window extends
  crypto-shredding to database backups.
* **System secrets** (audit-chain HMAC key, CSRF key, cursor key, recovery-code pepper).
* **Monthly IP-pseudonymization keys** that are destroyed after 90 days so pseudonyms stop being linkable.

``FileKeyring`` keeps everything in a single JSON file with ``0600`` permissions that must live
outside the database (and outside database backups). ``MemoryKeyring`` is used in tests.
"""

from __future__ import annotations

import base64
import fcntl
import json
import os
import secrets
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from angel_engine.core.clock import utcnow

SYSTEM_SECRET_NAMES = ("audit", "csrf", "cursor", "recovery_pepper", "anchor")
KEY_BYTES = 32


class KeyringError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class KekInfo:
    kek_id: str
    created_at: str
    active: bool


class KeyProvider(Protocol):
    def active_kek(self) -> tuple[str, bytes]: ...
    def kek(self, kek_id: str) -> bytes: ...
    def secret(self, name: str) -> bytes: ...
    def ip_key(self, period: str) -> bytes: ...
    def rotate_kek(self) -> str: ...
    def destroy_kek(self, kek_id: str) -> None: ...
    def destroy_ip_keys_before(self, period: str) -> int: ...
    def list_keks(self) -> list[KekInfo]: ...


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _unb64(text: str) -> bytes:
    raw = base64.b64decode(text)
    if len(raw) != KEY_BYTES:
        raise KeyringError("invalid key length in keyring")
    return raw


def _new_kek_id(now: datetime) -> str:
    return f"kek-{now:%Y%m%d}-{secrets.token_hex(3)}"


class _KeyringData:
    def __init__(self, data: dict[str, object]) -> None:
        self.data = data

    @classmethod
    def fresh(cls) -> _KeyringData:
        now = utcnow()
        kek_id = _new_kek_id(now)
        return cls(
            {
                "format": 1,
                "active_kek": kek_id,
                "keks": {kek_id: {"key": _b64(secrets.token_bytes(KEY_BYTES)), "created_at": now.isoformat()}},
                "secrets": {name: _b64(secrets.token_bytes(KEY_BYTES)) for name in SYSTEM_SECRET_NAMES},
                "ip_keys": {},
            }
        )

    @property
    def keks(self) -> dict[str, dict[str, str]]:
        return self.data["keks"]  # type: ignore[return-value]

    @property
    def secrets(self) -> dict[str, str]:
        return self.data["secrets"]  # type: ignore[return-value]

    @property
    def ip_keys(self) -> dict[str, str]:
        return self.data["ip_keys"]  # type: ignore[return-value]


class MemoryKeyring:
    """In-memory keyring (tests and ephemeral tooling)."""

    def __init__(self) -> None:
        self._data = _KeyringData.fresh()
        self._lock = threading.Lock()

    def _persist(self) -> None:  # overridden by FileKeyring
        return None

    def active_kek(self) -> tuple[str, bytes]:
        kek_id = str(self._data.data["active_kek"])
        return kek_id, self.kek(kek_id)

    def kek(self, kek_id: str) -> bytes:
        entry = self._data.keks.get(kek_id)
        if entry is None:
            raise KeyringError(f"KEK {kek_id} is not available (destroyed or unknown)")
        return _unb64(entry["key"])

    def secret(self, name: str) -> bytes:
        value = self._data.secrets.get(name)
        if value is None:
            with self._lock:
                value = self._data.secrets.setdefault(name, _b64(secrets.token_bytes(KEY_BYTES)))
                self._persist()
        return _unb64(value)

    def ip_key(self, period: str) -> bytes:
        value = self._data.ip_keys.get(period)
        if value is None:
            with self._lock:
                value = self._data.ip_keys.setdefault(period, _b64(secrets.token_bytes(KEY_BYTES)))
                self._persist()
        return _unb64(value)

    def rotate_kek(self) -> str:
        with self._lock:
            kek_id = _new_kek_id(utcnow())
            self._data.keks[kek_id] = {
                "key": _b64(secrets.token_bytes(KEY_BYTES)),
                "created_at": utcnow().isoformat(),
            }
            self._data.data["active_kek"] = kek_id
            self._persist()
            return kek_id

    def destroy_kek(self, kek_id: str) -> None:
        with self._lock:
            if kek_id == self._data.data["active_kek"]:
                raise KeyringError("cannot destroy the active KEK")
            self._data.keks.pop(kek_id, None)
            self._persist()

    def destroy_ip_keys_before(self, period: str) -> int:
        with self._lock:
            stale = [p for p in self._data.ip_keys if p < period]
            for p in stale:
                del self._data.ip_keys[p]
            if stale:
                self._persist()
            return len(stale)

    def list_keks(self) -> list[KekInfo]:
        active = self._data.data["active_kek"]
        return [
            KekInfo(kek_id=k, created_at=v.get("created_at", ""), active=k == active)
            for k, v in sorted(self._data.keks.items())
        ]


class FileKeyring(MemoryKeyring):
    """Keyring persisted to a JSON file (mode 0600). Created on first use when ``create`` is True.

    Several processes (API, workers) share one keyring file. Every change happens under an exclusive ``flock`` on a
    sibling lock file after re-reading the file, and lookups of an unknown KEK, secret or IP key re-read it first, so
    a KEK rotated by the maintenance worker or a monthly IP key created by another API process is picked up without
    a restart.
    """

    def __init__(self, path: Path, *, create: bool = False) -> None:
        self._path = path
        self._lock = threading.Lock()
        if path.exists():
            self._data = self._read()
        elif create:
            with self._file_lock():
                self._data = self._read() if path.exists() else _KeyringData.fresh()
                self._persist()
        else:
            raise KeyringError(f"keyring {path} not found — run `angel-engine keys init` to create it")

    def _read(self) -> _KeyringData:
        try:
            return _KeyringData(json.loads(self._path.read_text()))
        except (OSError, ValueError) as exc:
            raise KeyringError(f"cannot read keyring {self._path}") from exc

    @contextmanager
    def _file_lock(self) -> Iterator[None]:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._path.with_suffix(".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _reload(self) -> None:
        if self._path.exists():
            self._data = self._read()

    def _persist(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(self._data.data, handle, indent=2, sort_keys=True)
        os.replace(tmp, self._path)
        os.chmod(self._path, 0o600)

    # -- lookups: re-read once before giving up --------------------------------------------------
    def kek(self, kek_id: str) -> bytes:
        if kek_id not in self._data.keks:
            with self._lock:
                self._reload()
        return super().kek(kek_id)

    def active_kek(self) -> tuple[str, bytes]:
        with self._lock:
            self._reload()  # another process may have rotated; new wraps use the newest KEK
        return super().active_kek()

    def secret(self, name: str) -> bytes:
        if name not in self._data.secrets:
            with self._lock, self._file_lock():
                self._reload()
                if name not in self._data.secrets:
                    self._data.secrets[name] = _b64(secrets.token_bytes(KEY_BYTES))
                    self._persist()
        return _unb64(self._data.secrets[name])

    def ip_key(self, period: str) -> bytes:
        if period not in self._data.ip_keys:
            with self._lock, self._file_lock():
                self._reload()
                if period not in self._data.ip_keys:
                    self._data.ip_keys[period] = _b64(secrets.token_bytes(KEY_BYTES))
                    self._persist()
        return _unb64(self._data.ip_keys[period])

    # -- changes: read-modify-write under the file lock ------------------------------------------
    def rotate_kek(self) -> str:
        with self._file_lock():
            self._reload()
            return super().rotate_kek()

    def destroy_kek(self, kek_id: str) -> None:
        with self._file_lock():
            self._reload()
            super().destroy_kek(kek_id)

    def destroy_ip_keys_before(self, period: str) -> int:
        with self._file_lock():
            self._reload()
            return super().destroy_ip_keys_before(period)
