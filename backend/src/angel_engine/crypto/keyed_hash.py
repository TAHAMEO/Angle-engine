"""Keyed hashes (MACs) with purpose separation. Investigation-scoped MACs die with the investigation's DEK."""

from __future__ import annotations

import hashlib
import hmac

from angel_engine.crypto.envelope import FieldCipher

URL_PURPOSE = "ae/url/v1"
CONTENT_PURPOSE = "ae/content/v1"
CANONICAL_PURPOSE = "ae/canonical/v1"
DEVICE_PURPOSE = "ae/device/v1"
SIMHASH_PURPOSE = "ae/simhash/v1"


def url_mac(cipher: FieldCipher, canonical_url: str) -> bytes:
    return cipher.mac(URL_PURPOSE, canonical_url)


def content_mac(cipher: FieldCipher, content: str | bytes) -> bytes:
    return cipher.mac(CONTENT_PURPOSE, content)


def canonical_mac(cipher: FieldCipher, kind: str, canonical: str) -> bytes:
    return cipher.mac(CANONICAL_PURPOSE, f"{kind}|{canonical}")


def system_mac(key: bytes, purpose: str, data: str | bytes) -> bytes:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hmac.new(key, purpose.encode() + b"|" + raw, hashlib.sha256).digest()
