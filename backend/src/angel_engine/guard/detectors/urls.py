"""URL secrets: userinfo (``user:pass@``) and secret-bearing query/fragment parameters.

The same span computation backs :func:`sanitize_url` and the in-text detector, so a URL inside
free text is sanitized exactly like a standalone URL. Removal spans are minimal (only the secret
segments and one adjoining separator), which keeps the remaining URL text visible to the other
detectors (e.g. an e-mail address in a kept parameter is still redacted).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from urllib.parse import unquote_plus

from angel_engine.guard.detectors.base import P_URL_SECRET, Detection, Scan, detection, words
from angel_engine.guard.types import RedactionKind

_URL_RE = re.compile(r"\b(?:https?|ftps?|sftp|wss?)://[^\s<>\"'`{}|\\^]+", re.IGNORECASE)
_TRAILING = ".,;:!?'\")]}>*"
_SCHEME_AUTHORITY = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_PATH_SESSION = re.compile(r";(?:jsessionid|phpsessid|sessionid|sid)=[^/;?#]*", re.IGNORECASE)

_SECRET_EXACT = words(
    """
    token access_token refresh_token id_token auth_token authtoken sig signature key api_key apikey api-key auth
    authorization password passwd pwd pass passphrase session sessionid session_id sid secret client_secret code
    auth_code jwt otp ticket csrf csrf_token _csrf xsrf xsrf_token authenticity_token phpsessid jsessionid
    aspsessionid private_token access_key secret_key accesskey secretkey awsaccesskeyid googleaccessid oauth_token
    oauth_signature oauth_verifier hmac credential credentials bearer login_token reset_token verification_code
    magic_link
    """
)
_SECRET_PREFIXES = ("x-amz-", "x-goog-")
_SECRET_SUBSTRINGS = (
    "token",
    "secret",
    "password",
    "passwd",
    "signature",
    "apikey",
    "api_key",
    "api-key",
    "sessionid",
    "session_id",
    "access_key",
    "private_key",
)


def find_url_spans(text: str) -> list[tuple[int, int]]:
    """Locate absolute URLs in ``text`` (trailing punctuation trimmed)."""
    spans: list[tuple[int, int]] = []
    for m in _URL_RE.finditer(text):
        start, end = m.span()
        while end > start and text[end - 1] in _TRAILING:
            if text[end - 1] == ")" and text.count("(", start, end) >= text.count(")", start, end):
                break
            end -= 1
        if end > start:
            spans.append((start, end))
    return spans


def is_secret_param(raw_key: str) -> bool:
    """True when a query/fragment parameter name is likely to carry a secret."""
    key = unquote_plus(raw_key).strip().lower()
    if not key:
        return False
    if key in _SECRET_EXACT or key.startswith(_SECRET_PREFIXES):
        return True
    return any(s in key for s in _SECRET_SUBSTRINGS)


def _param_spans(url: str, delim: int, end: int) -> list[tuple[int, int]]:
    """Removal spans for secret parameters in ``url[delim+1:end]`` (``delim`` is ``?`` or ``#``)."""
    segments: list[tuple[int, int, bool]] = []
    pos = delim + 1
    while True:
        amp = url.find("&", pos, end)
        seg_end = end if amp == -1 else amp
        raw = url[pos:seg_end]
        segments.append((pos, seg_end, bool(raw) and is_secret_param(raw.split("=", 1)[0])))
        if amp == -1:
            break
        pos = amp + 1
    if not any(secret for _, _, secret in segments):
        return []
    if all(secret or s == e for s, e, secret in segments):
        return [(delim, end)]  # nothing worth keeping: drop the delimiter too
    spans: list[tuple[int, int]] = []
    i, n = 0, len(segments)
    while i < n:
        if not segments[i][2]:
            i += 1
            continue
        j = i
        while j + 1 < n and segments[j + 1][2]:
            j += 1
        if i == 0:
            spans.append((segments[i][0], segments[j + 1][0]))  # "a=1&" incl. the following '&'
        else:
            spans.append((segments[i][0] - 1, segments[j][1]))  # "&a=1" incl. the preceding '&'
        i = j + 1
    return spans


def url_secret_spans(url: str) -> list[tuple[int, int]]:
    """Return sorted, non-overlapping ``(start, end)`` ranges of ``url`` that must be removed."""
    spans: list[tuple[int, int]] = []
    path_start = 0
    m = _SCHEME_AUTHORITY.match(url)
    if m:
        auth_start = m.end()
        auth_end = len(url)
        for ch in "/?#":
            idx = url.find(ch, auth_start)
            if idx != -1:
                auth_end = min(auth_end, idx)
        at = url.rfind("@", auth_start, auth_end)
        if at != -1:
            spans.append((auth_start, at + 1))
        path_start = auth_end
    q = url.find("?", path_start)
    h = url.find("#", path_start)
    if q != -1 and h != -1 and h < q:
        q = -1  # a '?' inside the fragment is not a query delimiter
    path_end = min(x for x in (q, h, len(url)) if x != -1)
    spans.extend(pm.span() for pm in _PATH_SESSION.finditer(url, path_start, path_end))
    if q != -1:
        spans.extend(_param_spans(url, q, h if h != -1 else len(url)))
    if h != -1 and "=" in url[h + 1 :]:
        spans.extend(_param_spans(url, h, len(url)))
    return sorted(spans)


def sanitize_url(url: str) -> str:
    """Strip userinfo and secret-bearing query/fragment parameters; keep everything else in order.

    >>> sanitize_url("https://u:p@h.example/x?token=abc&id=5")
    'https://h.example/x?id=5'
    """
    spans = url_secret_spans(url)
    if not spans:
        return url
    parts: list[str] = []
    pos = 0
    for start, end in spans:
        parts.append(url[pos:start])
        pos = end
    parts.append(url[pos:])
    return "".join(parts)


def detect(scan: Scan) -> Iterator[Detection]:
    """Yield removal spans (empty replacement) for secrets inside URLs found in the text."""
    for start, end in scan.url_spans:
        for s, e in url_secret_spans(scan.text[start:end]):
            yield detection(start + s, start + e, RedactionKind.URL_SECRET, P_URL_SECRET, "")
