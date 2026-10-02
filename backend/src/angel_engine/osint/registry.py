"""Connector registry: which public sources exist, whether each is ready, and the shared HTTP client."""

from __future__ import annotations

from dataclasses import dataclass

from angel_engine.config import Settings
from angel_engine.infra.http.fixtures import FixtureTransport
from angel_engine.infra.http.safe_client import SafeHttpClient, bot_user_agent
from angel_engine.osint.connectors import ALL_CONNECTORS, Connector
from angel_engine.osint.types import CATEGORY_LABELS


@dataclass(frozen=True, slots=True)
class ConnectorStatus:
    id: str
    name: str
    category: str
    category_label: str
    description: str
    input_types: tuple[str, ...]
    status: str  # ready | needs_key | disabled
    reason: str | None
    person_oriented: bool
    allowed_in_restricted_mode: bool
    docs_url: str
    terms_note: str
    requires_key: bool


class ConnectorRegistry:
    def __init__(self, settings: Settings, connectors: list[Connector] | None = None) -> None:
        self.settings = settings
        self._connectors = {c.info.id: c for c in (connectors or [cls() for cls in ALL_CONNECTORS])}

    def all(self) -> list[Connector]:
        return list(self._connectors.values())

    def get(self, connector_id: str) -> Connector | None:
        return self._connectors.get(connector_id)

    def status(self, connector: Connector) -> ConnectorStatus:
        state, reason = connector.status(self.settings)
        info = connector.info
        return ConnectorStatus(
            id=info.id,
            name=info.name,
            category=info.category.value,
            category_label=CATEGORY_LABELS[info.category],
            description=info.description,
            input_types=tuple(t.value for t in info.input_types),
            status=state,
            reason=reason,
            person_oriented=info.person_oriented,
            allowed_in_restricted_mode=info.allowed_in_restricted_mode,
            docs_url=info.docs_url,
            terms_note=info.terms_note,
            requires_key=bool(info.requires_key) and not info.key_optional,
        )

    def statuses(self) -> list[ConnectorStatus]:
        return [self.status(c) for c in self.all()]


def build_registry(settings: Settings) -> ConnectorRegistry:
    return ConnectorRegistry(settings)


def build_http_client(settings: Settings) -> SafeHttpClient:
    """Live mode uses the guarded network backend; fixture mode replays recorded responses (offline)."""
    user_agent = bot_user_agent(settings.bot_info_url)
    if settings.connector_mode == "fixtures":
        return SafeHttpClient(user_agent=user_agent, transport=FixtureTransport())
    return SafeHttpClient(user_agent=user_agent)
