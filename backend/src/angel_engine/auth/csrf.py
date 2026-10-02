"""Signed double-submit CSRF tokens (``random.mac``), bound to a session key or a server key."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def issue(key: bytes) -> str:
    nonce = secrets.token_bytes(18)
    mac = hmac.new(key, nonce, hashlib.sha256).digest()[:18]
    return f"{_b64(nonce)}.{_b64(mac)}"


def valid(key: bytes, token: str | None) -> bool:
    if not token or "." not in token or len(token) > 128:
        return False
    nonce_b64, mac_b64 = token.split(".", 1)
    try:
        nonce = base64.urlsafe_b64decode(nonce_b64 + "=" * (-len(nonce_b64) % 4))
        mac = base64.urlsafe_b64decode(mac_b64 + "=" * (-len(mac_b64) % 4))
    except ValueError:
        return False
    expected = hmac.new(key, nonce, hashlib.sha256).digest()[:18]
    return hmac.compare_digest(mac, expected)
