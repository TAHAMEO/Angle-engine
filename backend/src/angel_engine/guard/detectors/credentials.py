"""Credentials: keyword-anchored secrets, structured API tokens, JWTs, PEM private keys, auth headers."""

from __future__ import annotations

import re
from collections.abc import Iterator

from angel_engine.guard.detectors.base import (
    P_CREDENTIAL,
    P_PRIVATE_KEY,
    P_TOKEN,
    Detection,
    Scan,
    char_classes,
    detection,
    shannon_entropy,
    trie_pattern,
    window_before,
    words,
)
from angel_engine.guard.types import RedactionKind

_KIND = RedactionKind.CREDENTIAL

# "password: hunter2", "DB_PASSWORD=…", '"api_key": "…"'. Only the value is redacted. A keyword may
# carry a prefix ("db_password", "stripe-api-key"): only an alphanumeric character before it blocks.
_KEYWORDS = trie_pattern(
    (
        "password",
        "passwd",
        "passphrase",
        "passcode",
        "pwd",
        "pass",
        "secret",
        "client_secret",
        "client-secret",
        "clientsecret",
        "api_key",
        "api-key",
        "apikey",
        "access_key",
        "access-key",
        "accesskey",
        "secret_key",
        "secret-key",
        "secretkey",
        "private_key",
        "private-key",
        "privatekey",
        "auth_token",
        "auth-token",
        "authtoken",
        "access_token",
        "access-token",
        "accesstoken",
        "refresh_token",
        "refresh-token",
        "refreshtoken",
        "bearer_token",
        "bearer-token",
        "token",
        "credential",
        "credentials",
        "contraseña",
        "contrasena",
        "senha",
        "passwort",
        "mot de passe",
    )
)
_KEYWORD_VALUE = re.compile(
    rf"""(?P<kw>{_KEYWORDS})["']?\s*(?::=|=>|[:=])\s*
    (?:"(?P<dq>[^"\n]{{1,256}})"|'(?P<sq>[^'\n]{{1,256}})'|(?P<bare>[^\s"',;&<>)\]}}]{{1,256}}))""",
    re.IGNORECASE | re.VERBOSE,
)
_STRONG_KW = re.compile(r"pass|pwd|contrase|senha|passwort|mot", re.IGNORECASE)
_PLACEHOLDER_VALUES = words(
    """
    null none nil undefined true false required optional n/a na redacted hidden masked removed empty unset tbd todo
    string yes no ... … <redacted> [redacted] your_password yourpassword your-password your_api_key your-api-key
    your_token example
    """
)
_TEMPLATE_VALUE = re.compile(r"^(?:\$\{|\{\{|<[^>]*>$|%\(|\$[A-Z_][A-Z0-9_]*$|\[REDACTED)")
_MASKED_VALUE = re.compile(r"^[*•xX#.\-_]+$")

# Structured tokens. Every branch starts with a literal so the engine can skip quickly; the
# character before a match is checked in Python (_TOKEN_BOUNDARY).
_TOKENS = re.compile(
    "|".join(
        (
            r"(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}(?![A-Za-z0-9])",
            r"AIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])",
            r"gh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9_])",
            r"github_pat_[A-Za-z0-9_]{22,255}",
            r"glpat-[A-Za-z0-9_\-]{20,}",
            r"xox[abposr]-[A-Za-z0-9-]{10,}",
            r"https://hooks\.slack\.com/services/[A-Za-z0-9_/\-]+",
            r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}",
            r"sk-ant-[A-Za-z0-9_\-]{20,}",
            r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}",
            r"eyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*",
            r"npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])",
            r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}(?![A-Za-z0-9_\-])",
        )
    )
)

_AWS_SECRET = re.compile(
    r"aws.{0,20}?secret.{0,30}?(?<![A-Za-z0-9/+=])(?P<v>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])",
    re.IGNORECASE,
)
_PEM_BEGIN = re.compile(r"-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----")
_PEM_BODY_LINE = re.compile(r"\r?\n(?:[A-Za-z0-9+/=]{8,}|[A-Za-z-]+: [^\n]*|=[A-Za-z0-9+/]{4})?(?=\r?\n|$)")
_AUTH_HEADER = re.compile(
    r"\b(?:proxy-)?authorization\s*[:=]\s*[\"']?(?:(?:bearer|basic|token|digest|negotiate|apikey|key)\s+)?"
    r"(?P<v>[A-Za-z0-9._~+/=\-:]{8,})",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?<![A-Za-z0-9])[Bb]earer\s+(?P<v>[A-Za-z0-9._~+/\-]{20,}=*)")
_COOKIE = re.compile(r"\b(?:set-)?cookie\s*:\s*(?P<v>[^\s=;]+=[^\r\n]{4,})", re.IGNORECASE)

_ENTROPY_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/_\-=.])[A-Za-z0-9+/_\-=.]{32,512}(?![A-Za-z0-9+/_\-=.])")
_ENTROPY_KEYWORD = re.compile(
    r"\b(?:key|keys|secret|token|passw(?:or)?d|pwd|credentials?|auth|bearer|api|apikey|private"
    r"|access|session|cookie|signature|sig|webhook)\b",
    re.IGNORECASE,
)


def _token_boundary(text: str, start: int) -> bool:
    """A token or keyword must not continue a longer word (``_`` and ``-`` prefixes are allowed)."""
    return start == 0 or not text[start - 1].isalnum()


def _keyword_values(scan: Scan) -> Iterator[Detection]:
    for m in _KEYWORD_VALUE.finditer(scan.text):
        if not _token_boundary(scan.text, m.start()):
            continue
        group = "dq" if m.group("dq") is not None else "sq" if m.group("sq") is not None else "bare"
        value = m.group(group)
        start, end = m.span(group)
        stripped = value.strip()
        if not stripped or stripped.lower() in _PLACEHOLDER_VALUES:
            continue
        if _TEMPLATE_VALUE.match(stripped) or _MASKED_VALUE.match(stripped):
            continue
        min_len = 3 if _STRONG_KW.search(m.group("kw")) else 4
        if len(stripped) < min_len:
            continue
        yield detection(start, end, _KIND, P_CREDENTIAL)


def _private_keys(text: str) -> Iterator[Detection]:
    for m in _PEM_BEGIN.finditer(text):
        end_marker = f"-----END {m.group(1)}-----"
        idx = text.find(end_marker, m.end())
        if idx != -1:
            yield detection(m.start(), idx + len(end_marker), _KIND, P_PRIVATE_KEY)
            continue
        end = m.end()  # truncated block: consume the base64 body lines that follow
        while (line := _PEM_BODY_LINE.match(text, end)) is not None and line.end() > end:
            end = line.end()
        yield detection(m.start(), end, _KIND, P_PRIVATE_KEY)


def _high_entropy(scan: Scan) -> Iterator[Detection]:
    text = scan.text
    for m in _ENTROPY_CANDIDATE.finditer(text):
        value = m.group()
        if scan.inside_url(m.start(), m.end()):
            continue
        if char_classes(value) < 3 or shannon_entropy(value) < 4.0:
            continue
        if _ENTROPY_KEYWORD.search(window_before(text, m.start(), 40, same_line=True)):
            yield detection(m.start(), m.end(), _KIND, P_CREDENTIAL)


def detect(scan: Scan) -> Iterator[Detection]:
    """Yield credential detections (values only where a keyword anchors them)."""
    text = scan.text
    yield from _private_keys(text)
    for m in _TOKENS.finditer(text):
        if _token_boundary(text, m.start()) and (m.start() == 0 or text[m.start() - 1] != "_"):
            yield detection(m.start(), m.end(), _KIND, P_TOKEN)
    for pattern in (_AWS_SECRET, _BEARER, _COOKIE):
        for m in pattern.finditer(text):
            yield detection(m.start("v"), m.end("v"), _KIND, P_TOKEN)
    for m in _AUTH_HEADER.finditer(text):
        value = m.group("v")
        if value.lower() in _PLACEHOLDER_VALUES:
            continue
        if len(value) >= 16 or any(c.isdigit() for c in value):
            yield detection(m.start("v"), m.end("v"), _KIND, P_TOKEN)
    yield from _keyword_values(scan)
    yield from _high_entropy(scan)
