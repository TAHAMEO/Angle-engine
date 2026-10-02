"""Generic cell rate algorithm (GCRA) rate limiting on Redis, with an in-process fallback for dev/tests."""

from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass
from typing import Protocol

import structlog

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Limit:
    count: int
    period_s: int
    fail_closed: bool = False

    @property
    def interval_ms(self) -> float:
        return self.period_s * 1000.0 / self.count


# Endpoint classes (see docs/SECURITY.md).
LOGIN_ACCOUNT = Limit(5, 60, fail_closed=True)
LOGIN_IP = Limit(20, 60, fail_closed=True)
MFA_ACCOUNT = Limit(5, 300, fail_closed=True)
REGISTRATION_IP = Limit(3, 3600, fail_closed=True)
ABUSE_REPORT_IP = Limit(5, 3600, fail_closed=True)
CSP_REPORT_IP = Limit(30, 60)
READS_USER = Limit(300, 60)
WRITES_USER = Limit(60, 60)
UPLOADS_USER = Limit(20, 3600, fail_closed=True)
COLLECTION_USER = Limit(30, 3600, fail_closed=True)
COLLECTION_INVESTIGATION = Limit(300, 86400, fail_closed=True)
AI_USER = Limit(30, 3600, fail_closed=True)
EXPORTS_USER = Limit(10, 3600, fail_closed=True)

_LUA = """
local now = tonumber(ARGV[3])
local interval = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local tat = tonumber(redis.call('GET', KEYS[1]) or now)
local new_tat = math.max(tat, now) + interval
local allow_at = new_tat - burst * interval
if allow_at > now then
  return {0, math.ceil(allow_at - now)}
end
redis.call('SET', KEYS[1], new_tat, 'PX', math.ceil(new_tat - now) + 1000)
return {1, 0}
"""


class RateLimiterUnavailable(RuntimeError):
    pass


class RateLimiter(Protocol):
    async def hit(self, key: str, limit: Limit) -> tuple[bool, int]: ...
    async def close(self) -> None: ...


class MemoryRateLimiter:
    def __init__(self) -> None:
        self._tat: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def hit(self, key: str, limit: Limit) -> tuple[bool, int]:
        now = time.monotonic() * 1000.0
        async with self._lock:
            tat = max(self._tat.get(key, now), now)
            new_tat = tat + limit.interval_ms
            allow_at = new_tat - limit.count * limit.interval_ms
            if allow_at > now:
                return False, math.ceil((allow_at - now) / 1000.0)
            self._tat[key] = new_tat
            return True, 0

    async def close(self) -> None:
        return None


class RedisRateLimiter:
    def __init__(self, url: str) -> None:
        from redis.asyncio import Redis

        self._redis = Redis.from_url(url, socket_timeout=0.5, socket_connect_timeout=0.5)
        self._script = self._redis.register_script(_LUA)

    async def hit(self, key: str, limit: Limit) -> tuple[bool, int]:
        try:
            now_ms = int(time.time() * 1000)
            allowed, wait_ms = await self._script(keys=[f"ae:rl:{key}"], args=[limit.interval_ms, limit.count, now_ms])
        except Exception as exc:
            log.warning("rate_limiter_unavailable", error_type=type(exc).__name__)
            raise RateLimiterUnavailable from exc
        return bool(allowed), math.ceil(int(wait_ms) / 1000.0)

    async def close(self) -> None:
        await self._redis.aclose()
