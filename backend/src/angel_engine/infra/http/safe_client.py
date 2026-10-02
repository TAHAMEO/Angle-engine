"""SafeHttpClient: the only way Angel Engine code may reach the internet.

Protections (see docs/SECURITY.md):

* URL policy — http/https only, no userinfo, default ports only, no dotless or internal-use host names.
* Connect-time IP policy — the host is resolved once, *every* resolved address must be public (IPv4-mapped
  addresses are unwrapped; 6to4, Teredo, NAT64 and documentation ranges are denied), and the socket connects
  to the vetted IP literal, so DNS rebinding cannot redirect the request. TLS still verifies the hostname.
* Redirects are followed manually (≤ 5) and every hop is re-validated.
* No cookies, no credentials, no Referer, no environment proxies; an honest bot User-Agent.
* Byte caps on the *decoded* body (defeats compression bombs), per-registrable-domain politeness delays,
  Retry-After-aware retries and a per-domain circuit breaker.

httpx/httpcore are pinned exactly because the guarded network backend replaces the transport's connection
pool (a private attribute); ``tests/unit/test_safe_http.py`` asserts the wiring.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import ssl
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpcore
import httpx

from angel_engine.evidence.urls import registrable_domain

MAX_REDIRECTS = 5
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
ALLOWED_PORTS = {"http": 80, "https": 443}
BLOCKED_SUFFIXES = (
    ".local", ".localhost", ".internal", ".intranet", ".lan", ".home", ".corp", ".onion", ".invalid", ".arpa",
    ".home.arpa", ".localdomain",
)  # fmt: skip
_DENIED_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
        "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
        "::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32", "2001:db8::/32",
        "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
    )
)  # fmt: skip
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_FORBIDDEN_HEADERS = frozenset({"cookie", "referer", "host", "proxy-authorization"})
_CREDENTIAL_HEADERS = frozenset({"authorization", "x-api-key", "x-subscription-token", "x-goog-api-key"})
_BLOCKED = "blocked: the host resolves to a non-public address"
RETRY_STATUSES = frozenset({429, 503})
MAX_RETRY_AFTER_S = 20.0


class HttpPolicyError(Exception):
    """The URL or the address it resolves to is not allowed."""


class ResponseTooLarge(Exception):
    pass


class CircuitOpen(Exception):
    """Too many recent failures for this domain; try again later."""


class HttpFetchError(Exception):
    """Network-level failure (connection, TLS, timeout)."""


# --------------------------------------------------------------------------------------------------
# Policies
# --------------------------------------------------------------------------------------------------
def ip_allowed(address: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    ip = ipaddress.ip_address(address) if isinstance(address, str) else address
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip_allowed(ip.ipv4_mapped)
        if ip.sixtofour is not None or ip.teredo is not None:
            return False
    if any(ip in net for net in _DENIED_NETWORKS):
        return False
    return ip.is_global and not (
        ip.is_multicast or ip.is_reserved or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified
    )


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def validate_url(url: str | httpx.URL) -> httpx.URL:
    """Return the URL if it may be requested, else raise :class:`HttpPolicyError`."""
    try:
        parsed = httpx.URL(str(url))
    except (httpx.InvalidURL, ValueError) as exc:
        raise HttpPolicyError("invalid URL") from exc
    if parsed.scheme not in ALLOWED_PORTS:
        raise HttpPolicyError("only http and https URLs can be fetched")
    if parsed.userinfo:
        raise HttpPolicyError("URLs with credentials are not allowed")
    if parsed.port is not None and parsed.port != ALLOWED_PORTS[parsed.scheme]:
        raise HttpPolicyError("non-standard ports are not allowed")
    host = parsed.host.rstrip(".").lower()
    if not host:
        raise HttpPolicyError("missing host")
    if _is_ip_literal(host):
        if not ip_allowed(host.strip("[]")):
            raise HttpPolicyError("this address is not publicly routable")
        return parsed
    if "." not in host or host.endswith(BLOCKED_SUFFIXES) or host in {"localhost"}:
        raise HttpPolicyError("internal host names cannot be fetched")
    return parsed


Resolver = Callable[[str, int], Awaitable[list[str]]]


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


class GuardedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Resolves the host, vets every address and connects to the vetted IP literal."""

    def __init__(self, resolver: Resolver = system_resolver, inner: httpcore.AsyncNetworkBackend | None = None) -> None:
        self._resolver = resolver
        self._inner = inner or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 - httpcore interface
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if port not in (80, 443):
            raise httpcore.ConnectError("port not allowed")
        if _is_ip_literal(host):
            addresses = [host.strip("[]")]
        else:
            try:
                addresses = await asyncio.wait_for(self._resolver(host, port), timeout=timeout or 5.0)
            except (OSError, TimeoutError) as exc:
                raise httpcore.ConnectError("name resolution failed") from exc
        if not addresses or not all(ip_allowed(a) for a in addresses):
            raise httpcore.ConnectError(_BLOCKED)
        return await self._inner.connect_tcp(
            addresses[0], port, timeout=timeout, local_address=None, socket_options=socket_options
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109 - httpcore interface
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def guarded_transport(resolver: Resolver = system_resolver) -> httpx.AsyncHTTPTransport:
    """An httpx transport whose connection pool uses :class:`GuardedNetworkBackend`."""
    context = ssl.create_default_context()
    transport = httpx.AsyncHTTPTransport(verify=context, retries=0, http2=False, trust_env=False)
    transport._pool = httpcore.AsyncConnectionPool(
        ssl_context=context,
        max_connections=20,
        max_keepalive_connections=10,
        keepalive_expiry=15.0,
        http1=True,
        http2=False,
        retries=0,
        network_backend=GuardedNetworkBackend(resolver),
    )
    return transport


class _NoCookies(httpx.Cookies):
    """A cookie jar that never stores anything."""

    def extract_cookies(self, response: httpx.Response) -> None:
        return None


# --------------------------------------------------------------------------------------------------
# Politeness: per-domain spacing and circuit breaker
# --------------------------------------------------------------------------------------------------
@dataclass
class _DomainState:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_request: float = 0.0
    failures: int = 0
    open_until: float = 0.0


class DomainGovernor:
    def __init__(
        self, *, failure_threshold: int = 5, open_seconds: float = 120.0, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._states: dict[str, _DomainState] = {}
        self.failure_threshold = failure_threshold
        self.open_seconds = open_seconds
        self._clock = clock

    def _state(self, domain: str) -> _DomainState:
        return self._states.setdefault(domain, _DomainState())

    async def wait_turn(self, domain: str, min_interval: float) -> None:
        state = self._state(domain)
        if state.open_until > self._clock():
            raise CircuitOpen(domain)
        async with state.lock:
            delay = state.last_request + min_interval - self._clock()
            if delay > 0:
                await asyncio.sleep(delay)
            state.last_request = self._clock()

    def record(self, domain: str, *, ok: bool) -> None:
        state = self._state(domain)
        if ok:
            state.failures = 0
            return
        state.failures += 1
        if state.failures >= self.failure_threshold:
            state.open_until = self._clock() + self.open_seconds
            state.failures = 0


# --------------------------------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class HttpResult:
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    content: bytes
    redirects: tuple[str, ...] = ()
    elapsed_ms: int = 0

    @property
    def content_type(self) -> str | None:
        value = self.headers.get("content-type")
        return value.split(";", 1)[0].strip().lower() if value else None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def text(self) -> str:
        charset = "utf-8"
        value = self.headers.get("content-type", "")
        for part in value.split(";")[1:]:
            key, _, val = part.strip().partition("=")
            if key.lower() == "charset" and val:
                charset = val.strip('"').strip()
        try:
            return self.content.decode(charset, errors="replace")
        except LookupError:
            return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.content)


class SafeHttpClient:
    def __init__(
        self,
        *,
        user_agent: str,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: Resolver = system_resolver,
        governor: DomainGovernor | None = None,
        timeout: float = 20.0,
    ) -> None:
        self.user_agent = user_agent
        self.governor = governor or DomainGovernor()
        self._client = httpx.AsyncClient(
            transport=transport or guarded_transport(resolver),
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(timeout, connect=5.0),
            headers={"User-Agent": user_agent, "Accept-Language": "en;q=0.9, *;q=0.5"},
        )
        # httpx copies a jar passed to the constructor into a plain Cookies object, so install ours directly.
        self._client._cookies = _NoCookies()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> SafeHttpClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        min_interval: float = 1.0,
        accept: str = "*/*",
    ) -> HttpResult:
        """GET ``url`` following validated redirects. Raises on policy, size, circuit or network errors."""
        target = validate_url(httpx.URL(url, params=params) if params else url)
        started = time.monotonic()
        redirects: list[str] = []
        # Connectors may send their own API key headers; cookies, Referer and Host are never forwarded.
        request_headers = {"Accept": accept}
        request_headers.update({k: v for k, v in (headers or {}).items() if k.lower() not in _FORBIDDEN_HEADERS})
        for _ in range(MAX_REDIRECTS + 1):
            status, response_headers, body = await self._fetch_once(target, request_headers, max_bytes, min_interval)
            if status in REDIRECT_STATUSES and "location" in response_headers:
                if len(redirects) >= MAX_REDIRECTS:
                    raise HttpPolicyError("too many redirects")
                next_url = validate_url(urljoin(str(target), response_headers["location"]))
                if target.scheme == "https" and next_url.scheme == "http":
                    raise HttpPolicyError("refusing to downgrade from https to http")
                if registrable_domain(next_url.host) != registrable_domain(target.host):
                    # never forward API credentials to another site
                    request_headers = {k: v for k, v in request_headers.items() if k.lower() not in _CREDENTIAL_HEADERS}
                redirects.append(str(next_url))
                target = next_url
                continue
            return HttpResult(
                url=str(url),
                final_url=str(target),
                status=status,
                headers=response_headers,
                content=body,
                redirects=tuple(redirects),
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
        raise HttpPolicyError("too many redirects")

    async def post(
        self,
        url: str,
        *,
        content: bytes,
        content_type: str,
        headers: Mapping[str, str] | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        min_interval: float = 1.0,
        accept: str = "application/json",
    ) -> HttpResult:
        """POST to an API endpoint (keyed providers). Redirects are refused, never followed."""
        target = validate_url(url)
        started = time.monotonic()
        request_headers = {"Accept": accept, "Content-Type": content_type}
        request_headers.update({k: v for k, v in (headers or {}).items() if k.lower() not in _FORBIDDEN_HEADERS})
        status, response_headers, body = await self._fetch_once(
            target, request_headers, max_bytes, min_interval, method="POST", content=content
        )
        if status in REDIRECT_STATUSES:
            raise HttpPolicyError("API endpoints may not redirect a POST request")
        return HttpResult(
            url=str(url),
            final_url=str(target),
            status=status,
            headers=response_headers,
            content=body,
            redirects=(),
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )

    async def _fetch_once(
        self,
        url: httpx.URL,
        headers: dict[str, str],
        max_bytes: int,
        min_interval: float,
        *,
        method: str = "GET",
        content: bytes | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        domain = registrable_domain(url.host)
        for attempt in range(2):
            await self.governor.wait_turn(domain, min_interval)
            try:
                async with self._client.stream(method, url, headers=headers, content=content) as response:
                    response_headers = {k.lower(): v for k, v in response.headers.items()}
                    declared = response_headers.get("content-length")
                    if declared and declared.isdigit() and int(declared) > max_bytes:
                        raise ResponseTooLarge(f"response larger than {max_bytes} bytes")
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > max_bytes:
                            raise ResponseTooLarge(f"response larger than {max_bytes} bytes")
                        chunks.append(chunk)
                    status = response.status_code
            except (httpx.TransportError, httpcore.ConnectError) as exc:
                self.governor.record(domain, ok=False)
                if attempt == 0 and isinstance(exc, httpx.ConnectTimeout | httpx.ReadTimeout):
                    continue
                if _BLOCKED in str(exc):
                    raise HttpPolicyError("the host resolves to a non-public address") from exc
                raise HttpFetchError(type(exc).__name__) from exc
            if status in RETRY_STATUSES and attempt == 0:
                retry_after = _retry_after_seconds(response_headers.get("retry-after"))
                if retry_after is not None and retry_after <= MAX_RETRY_AFTER_S:
                    await asyncio.sleep(retry_after)
                    continue
            self.governor.record(domain, ok=status < 500)
            return status, response_headers, b"".join(chunks)
        raise HttpFetchError("retries exhausted")


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    from email.utils import parsedate_to_datetime

    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    from angel_engine.core.clock import utcnow

    return max(0.0, (when - utcnow()).total_seconds())


def bot_user_agent(info_url: str) -> str:
    return f"AngelEngineBot/1.0 (+{info_url})"
