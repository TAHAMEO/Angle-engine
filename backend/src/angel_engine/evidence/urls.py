"""URL normalization for sources: sanitize, canonicalize, de-track and find the registrable domain.

The canonical form is used for de-duplication (via a keyed MAC) and display. Userinfo and
secret-bearing parameters are removed first (sensitive-data guard), then tracking parameters,
fragments and default ports; hosts are lower-cased and IDNA-encoded.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import tldextract
from w3lib.url import canonicalize_url

from angel_engine.guard import sanitize_url

TRACKING_PARAMS = frozenset(
    {
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id", "utm_name",
        "utm_reader", "utm_brand", "utm_social", "utm_social-type", "fbclid", "gclid", "dclid", "gbraid",
        "wbraid", "msclkid", "mc_cid", "mc_eid", "igshid", "yclid", "_hsenc", "_hsmi", "mkt_tok", "ref_src",
        "ref_url", "s_cid", "spm", "vero_id", "oly_anon_id", "oly_enc_id", "wickedid", "twclid", "ttclid",
        "li_fat_id", "_ga", "_gl", "cmpid", "ito", "ncid", "sr_share",
    }
)  # fmt: skip
#: RFC 2606 / RFC 6761 special-use names, treated like public suffixes for grouping.
RESERVED_SUFFIXES = ("example", "test", "invalid", "localhost")


class UrlError(ValueError):
    """The value is not an acceptable public http(s) URL."""


@dataclass(frozen=True, slots=True)
class NormalizedUrl:
    url: str
    host: str
    registrable_domain: str


@lru_cache(maxsize=1)
def _extractor() -> tldextract.TLDExtract:
    # Offline: use the bundled public-suffix snapshot, never fetch it at runtime.
    return tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True, cache_dir=None)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


@lru_cache(maxsize=8192)
def registrable_domain(host: str) -> str:
    host = host.lower().rstrip(".")
    if _is_ip(host):
        return host
    labels = host.split(".")
    if labels[-1] in RESERVED_SUFFIXES:
        return ".".join(labels[-2:]) if len(labels) >= 2 else host
    result = _extractor()(host)
    if result.top_domain_under_public_suffix:
        return str(result.top_domain_under_public_suffix)
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _idna_host(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    if not host:
        raise UrlError("missing host")
    if _is_ip(host):
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UrlError("invalid host name") from exc


def normalize_url(raw: str) -> NormalizedUrl:
    """Return the canonical, de-tracked form of a public http(s) URL."""
    value = sanitize_url(raw.strip())
    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise UrlError("only http and https URLs are supported")
    if parts.hostname is None:
        raise UrlError("missing host")
    host = _idna_host(parts.hostname)
    if "." not in host and not _is_ip(host):
        raise UrlError("single-label host names are not public")
    try:
        port = parts.port
    except ValueError as exc:
        raise UrlError("invalid port") from exc
    netloc = host if port in (None, 80 if scheme == "http" else 443) else f"{host}:{port}"
    query = urlencode(
        [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k.lower() not in TRACKING_PARAMS],
        doseq=True,
    )
    rebuilt = urlunsplit((scheme, netloc, parts.path or "/", query, ""))
    canonical = canonicalize_url(rebuilt, keep_fragments=False)
    return NormalizedUrl(url=canonical, host=host, registrable_domain=registrable_domain(host))
