"""Process-wide service container (created in the FastAPI lifespan and by the worker)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from angel_engine.config import Settings
from angel_engine.core.pagination import CursorCodec
from angel_engine.crypto.envelope import Vault
from angel_engine.crypto.keys import FileKeyring, KeyProvider
from angel_engine.db.session import Database
from angel_engine.infra.ratelimit.gcra import MemoryRateLimiter, RateLimiter, RedisRateLimiter


@dataclass
class Services:
    settings: Settings
    db: Database
    keys: KeyProvider
    vault: Vault
    limiter: RateLimiter
    cursors: CursorCodec
    #: Late-bound optional components (object storage, policy engine, scanners, AI provider, …).
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def audit_key(self) -> bytes:
        return self.keys.secret("audit")

    def get(self, name: str) -> Any:
        return self.extras.get(name)

    async def close(self) -> None:
        for extra in list(self.extras.values()):
            closer = getattr(extra, "aclose", None)
            if closer is not None:
                await closer()
        await self.limiter.close()
        await self.db.dispose()


def build_services(settings: Settings, *, keys: KeyProvider | None = None, db: Database | None = None) -> Services:
    keyring = keys or FileKeyring(settings.keyring_path, create=settings.env != "production")
    limiter: RateLimiter
    if settings.redis_url:
        limiter = RedisRateLimiter(settings.redis_url)
    else:
        if settings.is_production:
            raise RuntimeError("Redis is required in production")
        limiter = MemoryRateLimiter()
    return Services(
        settings=settings,
        db=db or Database.from_settings(settings),
        keys=keyring,
        vault=Vault(keyring),
        limiter=limiter,
        cursors=CursorCodec(keyring.secret("cursor")),
    )
