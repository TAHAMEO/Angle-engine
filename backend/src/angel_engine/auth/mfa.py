"""TOTP multi-factor authentication with replay protection, and single-use recovery codes."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import secrets
import time

import pyotp
import qrcode
from qrcode.image.pil import PilImage

ISSUER = "Angel Engine"
STEP_SECONDS = 30
RECOVERY_CODE_COUNT = 10
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def new_secret() -> str:
    return pyotp.random_base32(length=32)


def provisioning_uri(secret: str, account: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=ISSUER)


def qr_png_data_uri(uri: str) -> str:
    img = qrcode.make(uri, image_factory=PilImage, box_size=6, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def current_timestep(now: float | None = None) -> int:
    return int((now if now is not None else time.time()) // STEP_SECONDS)


def verify_totp(secret: str, code: str, *, last_timestep: int | None, now: float | None = None) -> int | None:
    """Return the matched time step when ``code`` is valid (±1 step) and newer than ``last_timestep``.

    The caller must persist the returned step with a compare-and-set so a code can never be replayed.
    """
    digits = "".join(ch for ch in code if ch.isdigit())
    if len(digits) != 6:
        return None
    totp = pyotp.TOTP(secret)
    base = current_timestep(now)
    matched: int | None = None
    for offset in (-1, 0, 1):
        step = base + offset
        if hmac.compare_digest(totp.at(step * STEP_SECONDS), digits):
            matched = step
    if matched is None:
        return None
    if last_timestep is not None and matched <= last_timestep:
        return None
    return matched


def new_recovery_codes() -> list[str]:
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = "".join(secrets.choice(_ALPHABET) for _ in range(12))
        codes.append(f"{raw[:4]}-{raw[4:8]}-{raw[8:]}")
    return codes


def recovery_code_mac(pepper: bytes, code: str) -> bytes:
    normalized = "".join(ch for ch in code.upper() if ch.isalnum())
    return hmac.new(pepper, normalized.encode(), hashlib.sha256).digest()
