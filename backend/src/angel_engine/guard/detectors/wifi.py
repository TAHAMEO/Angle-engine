"""Wi-Fi credentials: ``WIFI:T:WPA;S:…;P:…;;`` QR payloads and "Wi-Fi password: …" phrases."""

from __future__ import annotations

import re
from collections.abc import Iterator

from angel_engine.guard.detectors.base import P_WIFI, Detection, Scan, detection, trie_pattern
from angel_engine.guard.types import RedactionKind

_KIND = RedactionKind.WIFI_CREDENTIAL

# Fields are "K:value;" with backslash escapes; the payload ends with an extra ';'.
_QR_PAYLOAD = re.compile(r"WIFI:(?:[A-Za-z]{1,3}:(?:\\.|[^\;\n])*;)+;?", re.IGNORECASE)
_QR_PASSWORD = re.compile(r"(?:^|;)P:(?:\\.|[^\;\n])+", re.IGNORECASE)
_WIFI_WORD = trie_pattern(("wifi", "wi-fi", "wlan", "wireless", "network"))
_SECRET_WORD = trie_pattern(("password", "passwort", "pass", "pw", "key", "passphrase", "code", "psk"))
_PHRASE = re.compile(
    rf"\b{_WIFI_WORD}[\s-]*{_SECRET_WORD}\s*(?:is\s*:?|:|=|-)\s*[\"']?(?P<v>[^\s\"',;]{{4,64}})"
    rf"|\b{trie_pattern(('password', 'contraseña', 'contrasena', 'senha', 'mot de passe', 'passwort'))}"
    r"\s+(?:(?:du|de|da|do|del)\s+)?(?:wi-?fi|wlan)\s*(?:is\s*:?|:|=|-)?\s*[\"']?(?P<w>[^\s\"',;]{4,64})",
    re.IGNORECASE,
)


def detect(scan: Scan) -> Iterator[Detection]:
    """Redact whole QR payloads that carry a password, and passwords named as Wi-Fi passwords."""
    for m in _QR_PAYLOAD.finditer(scan.text):
        body = m.group()[5:]
        if _QR_PASSWORD.search(body):
            yield detection(m.start(), m.end(), _KIND, P_WIFI)
    for m in _PHRASE.finditer(scan.text):
        group = "v" if m.group("v") is not None else "w"
        yield detection(m.start(group), m.end(group), _KIND, P_WIFI)
