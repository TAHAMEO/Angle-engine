"""A keyring file shared by several processes (API, workers) stays consistent."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from angel_engine.crypto.keys import FileKeyring, KeyringError


def test_rotation_by_one_process_is_seen_by_another(tmp_path: Path) -> None:
    path = tmp_path / "keys" / "keyring.json"
    api = FileKeyring(path, create=True)
    worker = FileKeyring(path)
    old_id, old_key = api.active_kek()
    new_id = worker.rotate_kek()
    assert new_id != old_id
    # The API learns about the new KEK without a restart (unwrap after a re-wrap by the worker) …
    assert api.kek(new_id) == worker.kek(new_id)
    # … and wraps new DEKs with it.
    assert api.active_kek()[0] == new_id
    assert api.kek(old_id) == old_key


def test_lazily_created_keys_are_shared(tmp_path: Path) -> None:
    path = tmp_path / "keyring.json"
    first = FileKeyring(path, create=True)
    second = FileKeyring(path)
    assert first.ip_key("2026-10") == second.ip_key("2026-10")
    assert second.secret("new_purpose") == first.secret("new_purpose")
    data = json.loads(path.read_text())
    assert "2026-10" in data["ip_keys"] and "new_purpose" in data["secrets"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_destroyed_keys_stay_destroyed_for_every_process(tmp_path: Path) -> None:
    path = tmp_path / "keyring.json"
    one = FileKeyring(path, create=True)
    two = FileKeyring(path)
    old_id, _ = one.active_kek()
    two.rotate_kek()
    one.ip_key("2026-01")
    two.destroy_kek(old_id)
    assert two.destroy_ip_keys_before("2026-06") == 1
    reread = FileKeyring(path)
    with pytest.raises(KeyringError):
        reread.kek(old_id)
    assert "2026-01" not in json.loads(path.read_text())["ip_keys"]


def test_missing_keyring_is_an_error_unless_created(tmp_path: Path) -> None:
    with pytest.raises(KeyringError):
        FileKeyring(tmp_path / "absent.json")
