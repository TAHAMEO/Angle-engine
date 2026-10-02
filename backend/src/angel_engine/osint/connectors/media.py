"""Public image sources (Wikimedia Commons, Openverse), broad places (Nominatim), web search leads (Brave
Search) and DNS records."""

from __future__ import annotations

from typing import Any, ClassVar
from urllib.parse import quote

from angel_engine.osint.connectors.base import Connector, ConnectorContext, ConnectorError, clip, parse_date
from angel_engine.osint.connectors.publications import strip_html
from angel_engine.osint.types import (
    ConnectorInfo,
    ConnectorQuery,
    ConnectorResult,
    EntityDraft,
    EvidenceType,
    InputType,
    NormalizedRecord,
    SourceCategory,
)

IMG = SourceCategory.PUBLIC_IMAGE_SOURCES


class WikimediaCommons(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="wikimedia_commons",
        name="Wikimedia Commons",
        category=IMG,
        description="Freely licensed images on Wikimedia Commons with licence and capture metadata.",
        input_types=(InputType.KEYWORD,),
        docs_url="https://www.mediawiki.org/wiki/API:Imageinfo",
        terms_note="Licences come from each file's extended metadata.",
        allowed_in_restricted_mode=False,
        min_interval_s=1.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        api = "https://commons.wikimedia.org/w/api.php"
        found = (
            await self.get_json(
                ctx,
                api,
                params={
                    "action": "query",
                    "list": "search",
                    "srsearch": query.value.strip(),
                    "srnamespace": 6,
                    "format": "json",
                    "formatversion": 2,
                    "srlimit": min(query.limit, 20),
                },
            )
            or {}
        )
        titles = [h["title"] for h in (found.get("query") or {}).get("search", []) if h.get("title")][:20]
        if not titles:
            return ConnectorResult(warnings=("No matching files on Wikimedia Commons.",))
        info = (
            await self.get_json(
                ctx,
                api,
                params={
                    "action": "query",
                    "prop": "imageinfo",
                    "iiprop": "url|sha1|timestamp|extmetadata",
                    "titles": "|".join(titles),
                    "format": "json",
                    "formatversion": 2,
                },
            )
            or {}
        )
        records = []
        for page in (info.get("query") or {}).get("pages", []):
            ii = (page.get("imageinfo") or [{}])[0]
            meta = ii.get("extmetadata") or {}

            def field(name: str, meta: dict[str, Any] = meta) -> str:
                return strip_html((meta.get(name) or {}).get("value"))

            title = page.get("title", "")
            url = ii.get("descriptionurl") or f"https://commons.wikimedia.org/wiki/{quote(title)}"
            taken = parse_date(field("DateTimeOriginal")[:10]) if field("DateTimeOriginal") else None
            records.append(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=IMG,
                    url=url,
                    title=title,
                    excerpt=clip(
                        f"{title}: {field('ImageDescription')} Licence: {field('LicenseShortName') or 'unknown'}."
                        f" Credit: {field('Artist') or 'not stated'}.",
                        900,
                    ),
                    statement=f"Wikimedia Commons hosts the file “{title}” under "
                    f"{field('LicenseShortName') or 'a stated'}"
                    " licence.",
                    evidence_type=EvidenceType.SEARCH_RESULT,
                    published_at=parse_date(ii.get("timestamp")),
                    publisher="Wikimedia Commons",
                    metadata={
                        "sha1": ii.get("sha1"),
                        "image_url": ii.get("url"),
                        "license": field("LicenseShortName"),
                        "taken": taken.date().isoformat() if taken else None,
                    },
                )
            )
        return ConnectorResult(records=tuple(records))


class Openverse(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="openverse",
        name="Openverse",
        category=IMG,
        description="Openly licensed images indexed by Openverse.",
        input_types=(InputType.KEYWORD,),
        docs_url="https://api.openverse.org/v1/",
        terms_note="Anonymous access: ≤ 20 results per page, 1 request per second.",
        allowed_in_restricted_mode=False,
        min_interval_s=1.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        data = (
            await self.get_json(
                ctx,
                "https://api.openverse.org/v1/images/",
                params={"q": query.value.strip(), "page_size": min(query.limit, 20)},
            )
            or {}
        )
        records = []
        for item in data.get("results", [])[: query.limit]:
            landing = item.get("foreign_landing_url") or item.get("url")
            if not landing:
                continue
            title = clip(item.get("title") or "Untitled image", 200)
            licence = f"{item.get('license', '?').upper()} {item.get('license_version') or ''}".strip()
            records.append(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=IMG,
                    url=landing,
                    title=title,
                    excerpt=f"“{title}” from {item.get('provider') or item.get('source')}, licence {licence}, credit "
                    f"{clip(item.get('creator') or 'not stated', 80)}.",
                    statement=f"Openverse indexes the image “{title}” ({licence}).",
                    evidence_type=EvidenceType.SEARCH_RESULT,
                    publisher=item.get("provider"),
                    metadata={"image_url": item.get("url"), "license": licence},
                )
            )
        return ConnectorResult(records=tuple(records))


BROAD_TYPES = frozenset(
    {
        "country",
        "state",
        "region",
        "province",
        "county",
        "city",
        "town",
        "municipality",
        "village",
        "suburb",
        "city_district",
        "district",
    }
)
LEVEL = {"country": "country", "state": "admin1", "region": "admin1", "province": "admin1"}


class Nominatim(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="nominatim",
        name="OpenStreetMap Nominatim (broad places)",
        category=SourceCategory.PUBLIC_DIRECTORIES,
        description="Resolves a place name typed by the investigator to a country, region or city. Street-level "
        "and building results are discarded; coordinates are never stored.",
        input_types=(InputType.PLACE,),
        docs_url="https://operations.osmfoundation.org/policies/nominatim/",
        terms_note="≤ 1 request per second, identifying User-Agent, results cached, no bulk use. © OSM contributors.",
        allowed_in_restricted_mode=False,
        min_interval_s=1.1,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        rows = (
            await self.get_json(
                ctx,
                "https://nominatim.openstreetmap.org/search",
                params={
                    "q": query.value.strip(),
                    "format": "jsonv2",
                    "limit": 5,
                    "addressdetails": 1,
                    "accept-language": "en",
                },
            )
            or []
        )
        records, dropped = [], 0
        for row in rows:
            kind = row.get("addresstype") or row.get("type")
            if kind not in BROAD_TYPES:
                dropped += 1
                continue
            address = row.get("address") or {}
            country = str(address.get("country_code", "")).upper() or None
            name = address.get(kind) or row.get("name") or query.value
            level = LEVEL.get(kind, "locality")
            parts = [name, address.get("state") if level != "admin1" else None, address.get("country")]
            label = ", ".join(dict.fromkeys(p for p in parts if p))
            records.append(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=SourceCategory.PUBLIC_DIRECTORIES,
                    url=f"https://www.openstreetmap.org/{row.get('osm_type', 'node')}/{row.get('osm_id', '')}",
                    title=f"Place: {label}",
                    excerpt=f"OpenStreetMap identifies “{query.value.strip()}” as {label} ({kind}).",
                    statement=f"“{query.value.strip()}” refers to {label}.",
                    evidence_type=EvidenceType.REGISTRY_RECORD,
                    publisher="OpenStreetMap",
                    entities=(
                        EntityDraft(
                            "location", name, f"{level}:{country}:{name}", {"location_level": level, "country": country}
                        ),
                    ),
                    metadata={"osm_type": row.get("osm_type"), "place_rank": row.get("place_rank")},
                )
            )
        warnings = (
            (f"{dropped} street-level or building result(s) were discarded; only broad places are kept.",)
            if dropped
            else ()
        )
        return ConnectorResult(records=tuple(records), warnings=warnings)


class BraveSearch(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="brave_search",
        name="Brave Search",
        category=SourceCategory.SEARCH_ENGINE_RESULTS,
        description="Web search results as temporary leads. Only the pages you select are captured and stored.",
        input_types=(InputType.KEYWORD, InputType.ORGANIZATION, InputType.DOMAIN),
        docs_url="https://api-dashboard.search.brave.com/app/documentation/web-search/get-started",
        terms_note="Paid API. Results are transient leads; storing them requires the storage-rights plan.",
        requires_key="brave_api_key",
        allowed_in_restricted_mode=True,
        min_interval_s=1.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        key = ctx.secret(self.info.requires_key)
        if not key:
            raise ConnectorError("not_configured", "Brave Search API key missing")
        q = f"site:{query.value.strip()}" if query.input_type == InputType.DOMAIN else query.value.strip()
        data = (
            await self.get_json(
                ctx,
                "https://api.search.brave.com/res/v1/web/search",
                params={"q": q, "count": min(query.limit, 20), "safesearch": "strict"},
                headers={"X-Subscription-Token": key},
            )
            or {}
        )
        leads = []
        for item in (data.get("web") or {}).get("results", [])[: query.limit]:
            url, title = item.get("url"), clip(strip_html(item.get("title")), 300)
            if not url or not title:
                continue
            leads.append(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=SourceCategory.SEARCH_ENGINE_RESULTS,
                    url=url,
                    title=title,
                    excerpt=clip(strip_html(item.get("description")), 500),
                    statement=f"Search result: {title}",
                    evidence_type=EvidenceType.SEARCH_RESULT,
                    published_at=parse_date(item.get("page_age")),
                    publisher=(item.get("profile") or {}).get("name"),
                    is_lead=True,
                )
            )
        return ConnectorResult(records=tuple(leads))


class DnsRecords(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="dns",
        name="DNS records",
        category=SourceCategory.WEBSITES,
        description="Public A, AAAA, MX, NS and TXT records of a domain (no zone transfers or enumeration).",
        input_types=(InputType.DOMAIN,),
        docs_url="https://www.dnspython.org/",
        terms_note="Single lookups through a public recursive resolver.",
        allowed_in_restricted_mode=True,
        min_interval_s=0.5,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        domain = query.value.strip().lower().removeprefix("www.")
        answers = await self.lookup(domain, ctx)
        if not any(answers.values()):
            return ConnectorResult(warnings=(f"No public DNS records were found for {domain}.",))
        lines = [f"{rtype}: {', '.join(values[:10])}" for rtype, values in answers.items() if values]
        return ConnectorResult(
            records=(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=SourceCategory.WEBSITES,
                    url=f"https://{domain}/",
                    title=f"DNS: {domain}",
                    excerpt=f"DNS records for {domain} — " + "; ".join(lines) + ".",
                    statement=f"{domain} publishes DNS records ({', '.join(t for t, v in answers.items() if v)}).",
                    evidence_type=EvidenceType.REGISTRY_RECORD,
                    publisher="DNS",
                    organization_context=True,
                    entities=(EntityDraft("domain", domain, domain),),
                    metadata={"records": answers},
                ),
            )
        )

    async def lookup(self, domain: str, ctx: ConnectorContext) -> dict[str, list[str]]:
        if ctx.settings.connector_mode == "fixtures":
            from angel_engine.osint.fixtures import dns_fixture

            return dns_fixture(domain)
        import dns.asyncresolver
        import dns.exception
        import dns.resolver

        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        out: dict[str, list[str]] = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                answer = await resolver.resolve(domain, rtype, lifetime=3.0)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                out[rtype] = []
                continue
            out[rtype] = sorted({r.to_text().strip('"')[:300] for r in answer})
        return out
