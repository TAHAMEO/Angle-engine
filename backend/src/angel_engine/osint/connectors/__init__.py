"""Registered public-source connectors (official APIs and robots-permitted public pages only)."""

from __future__ import annotations

from angel_engine.osint.connectors.base import Connector, ConnectorContext, ConnectorError
from angel_engine.osint.connectors.media import BraveSearch, DnsRecords, Nominatim, Openverse, WikimediaCommons
from angel_engine.osint.connectors.publications import (
    FederalRegister,
    Gdelt,
    GovUk,
    HackerNews,
    InternetArchive,
    StackExchange,
    Wikipedia,
)
from angel_engine.osint.connectors.registries import CrtSh, Gleif, Rdap, SecEdgar, Wikidata
from angel_engine.osint.connectors.social import Bluesky, GitHub, Mastodon
from angel_engine.osint.connectors.web import CommonCrawl, Wayback, WebCapture

ALL_CONNECTORS: tuple[type[Connector], ...] = (
    WebCapture, Wayback, CommonCrawl, DnsRecords,
    Gdelt,
    Mastodon, Bluesky,
    GitHub,
    InternetArchive,
    Gleif, SecEdgar,
    GovUk, FederalRegister,
    Rdap, CrtSh, Wikidata, Nominatim,
    HackerNews, StackExchange,
    WikimediaCommons, Openverse,
    BraveSearch,
    Wikipedia,
)  # fmt: skip

__all__ = ["ALL_CONNECTORS", "Connector", "ConnectorContext", "ConnectorError"]
