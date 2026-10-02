"""SafeHttpClient: SSRF policy, guarded connections, redirects, caps, cookies, retries, robots."""

from __future__ import annotations

from importlib.metadata import version

import httpcore
import httpx
import pytest

from angel_engine.infra.http.fixtures import FixtureTransport
from angel_engine.infra.http.robots import RobotsPolicy
from angel_engine.infra.http.safe_client import (
    CircuitOpen,
    DomainGovernor,
    GuardedNetworkBackend,
    HttpPolicyError,
    ResponseTooLarge,
    SafeHttpClient,
    guarded_transport,
    ip_allowed,
    validate_url,
)

UA = "AngelEngineBot/1.0 (+https://angel-engine.invalid/bot)"


@pytest.mark.parametrize(
    ("address", "allowed"),
    [
        ("8.8.8.8", True),
        ("2606:4700:4700::1111", True),
        ("127.0.0.1", False),
        ("10.1.2.3", False),
        ("172.16.0.1", False),
        ("192.168.1.1", False),
        ("169.254.169.254", False),  # cloud metadata
        ("100.64.0.1", False),  # carrier-grade NAT
        ("0.0.0.0", False),
        ("192.0.2.10", False),  # documentation
        ("203.0.113.7", False),
        ("224.0.0.1", False),
        ("::1", False),
        ("::ffff:127.0.0.1", False),  # IPv4-mapped loopback
        ("::ffff:8.8.8.8", True),
        ("2002:7f00:1::1", False),  # 6to4
        ("2001:0:4136:e378:8000:63bf:3fff:fdd2", False),  # Teredo
        ("64:ff9b::a00:1", False),  # NAT64
        ("fe80::1", False),
        ("fd00::1", False),
        ("2001:db8::1", False),
    ],
)
def test_ip_policy(address: str, allowed: bool) -> None:
    assert ip_allowed(address) is allowed


@pytest.mark.parametrize(
    "url",
    [
        "ftp://files.example.org/x",
        "https://user:pass@example.org/",
        "https://example.org:8443/",
        "http://localhost/",
        "http://intranet/",
        "https://printer.local/",
        "https://db.corp/",
        "https://hidden.onion/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
    ],
)
def test_url_policy_rejects(url: str) -> None:
    with pytest.raises(HttpPolicyError):
        validate_url(url)


def test_url_policy_accepts_public_urls() -> None:
    assert str(validate_url("https://news.example.org/a?b=1")) == "https://news.example.org/a?b=1"
    assert validate_url("http://8.8.8.8/").host == "8.8.8.8"


def test_dependencies_are_pinned_and_backend_is_wired() -> None:
    assert version("httpx") == "0.28.1" and version("httpcore") == "1.0.9"
    transport = guarded_transport()
    assert isinstance(transport._pool._network_backend, GuardedNetworkBackend)
    client = SafeHttpClient(user_agent=UA, transport=transport)
    assert type(client._client.cookies).__name__ == "_NoCookies"


async def _resolver_to(*addresses: str):  # type: ignore[no-untyped-def]
    async def resolve(host: str, port: int) -> list[str]:
        return list(addresses)

    return resolve


@pytest.mark.parametrize("addresses", [("127.0.0.1",), ("8.8.8.8", "10.0.0.1"), ("::ffff:192.168.0.1",), ()])
async def test_guarded_backend_refuses_private_resolutions(addresses: tuple[str, ...]) -> None:
    backend = GuardedNetworkBackend(await _resolver_to(*addresses))
    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("rebind.example.org", 443)


async def test_guarded_backend_refuses_other_ports() -> None:
    backend = GuardedNetworkBackend(await _resolver_to("8.8.8.8"))
    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("example.org", 8080)


async def test_client_surfaces_rebinding_as_policy_error() -> None:
    client = SafeHttpClient(user_agent=UA, resolver=await _resolver_to("10.0.0.5"))
    try:
        with pytest.raises(HttpPolicyError):
            await client.get("https://internal-looking.example.org/", min_interval=0)
    finally:
        await client.aclose()


def _client(handler, **kw) -> SafeHttpClient:  # type: ignore[no-untyped-def]
    return SafeHttpClient(user_agent=UA, transport=httpx.MockTransport(handler), **kw)


async def test_redirects_are_revalidated_and_limited() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/to-internal":
            return httpx.Response(302, headers={"location": "http://127.0.0.1/admin"})
        if request.url.path == "/downgrade":
            return httpx.Response(301, headers={"location": "http://example.org/plain"})
        if request.url.path.startswith("/loop"):
            n = int(request.url.path.removeprefix("/loop") or 0)
            return httpx.Response(302, headers={"location": f"/loop{n + 1}"})
        return httpx.Response(200, text="ok")

    async with _client(handler) as client:
        with pytest.raises(HttpPolicyError):
            await client.get("https://example.org/to-internal", min_interval=0)
        with pytest.raises(HttpPolicyError):
            await client.get("https://example.org/downgrade", min_interval=0)
        with pytest.raises(HttpPolicyError, match="too many redirects"):
            await client.get("https://example.org/loop", min_interval=0)


async def test_credentials_never_follow_a_cross_site_redirect() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "api.example.org":
            return httpx.Response(302, headers={"location": "https://cdn.other.example.net/file"})
        return httpx.Response(200, text="done")

    async with _client(handler) as client:
        result = await client.get(
            "https://api.example.org/data",
            headers={"X-Api-Key": "k-123", "Cookie": "a=b", "Referer": "https://x.example/"},
            min_interval=0,
        )
    assert result.ok and result.redirects == ("https://cdn.other.example.net/file",)
    first, second = seen
    assert first.headers["x-api-key"] == "k-123" and "cookie" not in first.headers and "referer" not in first.headers
    assert "x-api-key" not in second.headers
    assert first.headers["user-agent"] == UA


async def test_size_cap_counts_decoded_bytes() -> None:
    import gzip

    bomb = gzip.compress(b"0" * 2_000_000)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-encoding": "gzip"}, content=bomb)

    async with _client(handler) as client:
        with pytest.raises(ResponseTooLarge):
            await client.get("https://example.org/bomb", max_bytes=100_000, min_interval=0)


async def test_cookies_are_never_stored_or_sent() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, headers={"set-cookie": "session=abc; Path=/"}, text="hi")

    async with _client(handler) as client:
        await client.get("https://example.org/a", min_interval=0)
        await client.get("https://example.org/b", min_interval=0)
    assert all("cookie" not in r.headers for r in seen)


async def test_retry_after_is_honoured_once() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "0"})
        return httpx.Response(200, json={"ok": True})

    async with _client(handler) as client:
        result = await client.get("https://api.example.org/x", min_interval=0)
    assert result.status == 200 and result.json() == {"ok": True} and calls["n"] == 2


async def test_circuit_breaker_opens_after_repeated_failures() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502)

    async with _client(handler, governor=DomainGovernor(failure_threshold=2, open_seconds=60)) as client:
        for _ in range(2):
            assert (await client.get("https://flaky.example.org/", min_interval=0)).status == 502
        with pytest.raises(CircuitOpen):
            await client.get("https://flaky.example.org/", min_interval=0)


async def test_robots_policy_outcomes() -> None:
    transport = FixtureTransport(entries=[])
    transport.add("https://site.example.org/robots.txt", text="User-agent: *\nDisallow: /private\nCrawl-delay: 3\n")
    transport.add("https://broken.example.org/robots.txt", status=503)
    async with SafeHttpClient(user_agent=UA, transport=transport) as client:
        robots = RobotsPolicy(client)
        allowed = await robots.check("https://site.example.org/public/page")
        blocked = await robots.check("https://site.example.org/private/page")
        missing = await robots.check("https://norobots.example.org/anything")  # unmatched fixture → 404
        broken = await robots.check("https://broken.example.org/page")
    assert allowed.allowed and allowed.crawl_delay == 3.0
    assert not blocked.allowed and blocked.reason == "disallowed"
    assert missing.allowed and missing.reason == "no_robots"
    assert not broken.allowed and broken.reason == "robots_unavailable"
