"""robots.txt policy (Protego). Our own fetch through SafeHttpClient, cached for 24 hours per origin.

* 2xx — parsed and obeyed (``AngelEngineBot`` group, else ``*``), including Crawl-delay;
* 4xx — no robots.txt: everything allowed (RFC 9309 §2.3.1.3);
* 5xx, network errors, oversize files — treated as "disallow everything" until the next check.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from protego import Protego

from angel_engine.infra.http.safe_client import HttpFetchError, HttpPolicyError, ResponseTooLarge, SafeHttpClient

ROBOTS_TTL_S = 24 * 3600
ROBOTS_MAX_BYTES = 512 * 1024
ROBOTS_AGENT = "AngelEngineBot"


@dataclass(frozen=True, slots=True)
class RobotsDecision:
    allowed: bool
    crawl_delay: float | None
    reason: str  # "allowed" | "disallowed" | "no_robots" | "robots_unavailable"


@dataclass
class _Entry:
    parser: Protego | None
    status: str
    fetched_at: float


class RobotsPolicy:
    def __init__(self, client: SafeHttpClient, *, ttl: float = ROBOTS_TTL_S) -> None:
        self.client = client
        self.ttl = ttl
        self._cache: dict[str, _Entry] = {}

    async def _entry(self, origin: str) -> _Entry:
        cached = self._cache.get(origin)
        if cached is not None and time.monotonic() - cached.fetched_at < self.ttl:
            return cached
        try:
            result = await self.client.get(f"{origin}/robots.txt", max_bytes=ROBOTS_MAX_BYTES, accept="text/plain")
        except (HttpFetchError, ResponseTooLarge, HttpPolicyError):
            entry = _Entry(None, "robots_unavailable", time.monotonic())
        else:
            if 200 <= result.status < 300:
                entry = _Entry(Protego.parse(result.text()), "parsed", time.monotonic())
            elif 400 <= result.status < 500:
                entry = _Entry(None, "no_robots", time.monotonic())
            else:
                entry = _Entry(None, "robots_unavailable", time.monotonic())
        self._cache[origin] = entry
        return entry

    async def check(self, url: str) -> RobotsDecision:
        parts = urlsplit(url)
        entry = await self._entry(f"{parts.scheme}://{parts.netloc}")
        if entry.status == "no_robots":
            return RobotsDecision(True, None, "no_robots")
        if entry.parser is None:
            return RobotsDecision(False, None, "robots_unavailable")
        allowed = entry.parser.can_fetch(url, ROBOTS_AGENT)
        delay = entry.parser.crawl_delay(ROBOTS_AGENT)
        return RobotsDecision(bool(allowed), float(delay) if delay else None, "allowed" if allowed else "disallowed")
