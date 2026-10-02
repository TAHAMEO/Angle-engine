"""Connector base class and shared helpers.

A connector turns one lawful query into normalized records from *one* public source, using only that
source's official API or robots-permitted public pages through :class:`SafeHttpClient`. Connectors never
handle cookies, logins, CAPTCHAs or paywalls: such pages become :class:`ManualReference` items.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, ClassVar

from angel_engine.config import Settings
from angel_engine.infra.http.robots import RobotsPolicy
from angel_engine.infra.http.safe_client import HttpResult, SafeHttpClient
from angel_engine.osint.types import ConnectorInfo, ConnectorQuery, ConnectorResult

MAX_API_BYTES = 4 * 1024 * 1024


class ConnectorError(Exception):
    """A connector could not complete; ``code`` is safe to show and to log."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass
class ConnectorContext:
    http: SafeHttpClient
    robots: RobotsPolicy
    settings: Settings
    restricted_mode: bool = False
    now: datetime = field(default_factory=lambda: datetime.now(UTC))

    def secret(self, attribute: str | None) -> str | None:
        if attribute is None:
            return None
        value = getattr(self.settings, attribute, None)
        return value.get_secret_value() if value is not None else None


class Connector(ABC):
    info: ClassVar[ConnectorInfo]

    def status(self, settings: Settings) -> tuple[str, str | None]:
        """("ready" | "needs_key" | "disabled", reason)."""
        if self.info.id in settings.disabled_connectors:
            return "disabled", "Disabled by the administrator."
        key = self.info.requires_key
        if key and not self.info.key_optional and getattr(settings, key, None) is None:
            return "needs_key", f"Configure {key.upper()} (ANGEL_{key.upper()}) to enable this source."
        return "ready", None

    @abstractmethod
    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult: ...

    # -- helpers ----------------------------------------------------------------------------------
    async def get_json(
        self,
        ctx: ConnectorContext,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        allow_404: bool = True,
    ) -> Any:
        result = await ctx.http.get(
            url,
            params=params,
            headers=headers,
            max_bytes=MAX_API_BYTES,
            min_interval=self.info.min_interval_s,
            accept="application/json",
        )
        return self._json(result, allow_404=allow_404)

    @staticmethod
    def _json(result: HttpResult, *, allow_404: bool) -> Any:
        if result.status == 404 and allow_404:
            return None
        if result.status == 429:
            raise ConnectorError("rate_limited", "the source asked us to slow down")
        if result.status in (401, 403):
            raise ConnectorError("access_denied", f"HTTP {result.status}")
        if not result.ok:
            raise ConnectorError("upstream_error", f"HTTP {result.status}")
        try:
            return json.loads(result.content)
        except ValueError as exc:
            raise ConnectorError("invalid_response", "the source did not return JSON") from exc


def parse_date(value: Any) -> datetime | None:
    """Parse common API date formats into an aware UTC datetime (None when unknown)."""
    if value in (None, "", 0):
        return None
    if isinstance(value, int | float):
        return datetime.fromtimestamp(float(value), tz=UTC)
    text = str(value).strip()
    for fmt in ("%Y%m%d%H%M%S", "%Y%m%dT%H%M%SZ", "%Y-%m-%d", "%Y%m%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def clip(text: str | None, limit: int = 1200) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rsplit(" ", 1)[0] + "…"
