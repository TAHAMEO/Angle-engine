"""Publications: news (GDELT), encyclopedic pages (Wikipedia), public documents (Internet Archive),
public forums (Hacker News, Stack Exchange) and government publications (GOV.UK, U.S. Federal Register)."""

from __future__ import annotations

import html
import re
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

from angel_engine.osint.connectors.base import Connector, ConnectorContext, clip, parse_date
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

_TAGS = re.compile(r"<[^>]{0,500}>")


def strip_html(value: str | None) -> str:
    return html.unescape(_TAGS.sub(" ", value or "")).strip()


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


# --------------------------------------------------------------------------------------------------
# News — GDELT DOC 2.0
# --------------------------------------------------------------------------------------------------
class Gdelt(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="gdelt",
        name="GDELT news index",
        category=SourceCategory.NEWS_ARTICLES,
        description="Worldwide online news coverage matching a keyword or organization (article metadata).",
        input_types=(InputType.KEYWORD, InputType.ORGANIZATION, InputType.DOMAIN),
        docs_url="https://blog.gdeltproject.org/gdelt-doc-2-0-api-debuts/",
        terms_note="Cite GDELT and link to articles; full text is only captured on request via page capture.",
        allowed_in_restricted_mode=True,
        min_interval_s=10.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        term = query.value.strip()
        q = f"domain:{term}" if query.input_type == InputType.DOMAIN else f'"{term}"' if " " in term else term
        params: dict[str, Any] = {
            "query": q,
            "mode": "ArtList",
            "format": "json",
            "maxrecords": min(query.limit, 75),
            "sort": "DateDesc",
        }
        if timespan := query.params.get("timespan"):
            params["timespan"] = timespan
        data = await self.get_json(ctx, "https://api.gdeltproject.org/api/v2/doc/doc", params=params) or {}
        records = []
        for art in data.get("articles", [])[: query.limit]:
            url, title = art.get("url"), clip(art.get("title"), 300)
            if not url or not title:
                continue
            seen = parse_date(art.get("seendate"))
            domain = art.get("domain") or _host(url)
            records.append(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=SourceCategory.NEWS_ARTICLES,
                    url=url,
                    title=title,
                    excerpt=f"Headline: “{title}” ({domain}"
                    + (f", {art.get('sourcecountry')}" if art.get("sourcecountry") else "")
                    + (f", first seen {seen.date().isoformat()}" if seen else "")
                    + ").",
                    statement=f"{domain} published an article titled “{title}”.",
                    evidence_type=EvidenceType.SEARCH_RESULT,
                    published_at=seen,
                    publisher=domain,
                    metadata={
                        "language": art.get("language"),
                        "source_country": art.get("sourcecountry"),
                        "events": [
                            {
                                "kind": "publication",
                                "date": seen.isoformat(),
                                "precision": "day",
                                "title": f"{domain}: {clip(title, 120)}",
                            }
                        ]
                        if seen
                        else [],
                    },
                )
            )
        return ConnectorResult(
            records=tuple(records), warnings=() if records else ("GDELT found no matching coverage.",)
        )


# --------------------------------------------------------------------------------------------------
# Wikipedia
# --------------------------------------------------------------------------------------------------
class Wikipedia(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="wikipedia",
        name="Wikipedia",
        category=SourceCategory.WEBSITES,
        description="Encyclopedia article summaries (the cited revision is recorded).",
        input_types=(InputType.KEYWORD, InputType.ORGANIZATION),
        docs_url="https://www.mediawiki.org/wiki/API:Main_page",
        terms_note="Text is CC BY-SA; summaries are quoted with attribution and revision.",
        allowed_in_restricted_mode=False,
        min_interval_s=1.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        lang = str(query.params.get("lang", "en"))[:5] or "en"
        base = f"https://{lang}.wikipedia.org"
        found = (
            await self.get_json(
                ctx,
                f"{base}/w/api.php",
                params={
                    "action": "query",
                    "list": "search",
                    "srsearch": query.value.strip(),
                    "format": "json",
                    "formatversion": 2,
                    "srlimit": min(query.limit, 5),
                    "maxlag": 5,
                },
            )
            or {}
        )
        records = []
        for hit in (found.get("query") or {}).get("search", [])[:3]:
            title = hit.get("title")
            if not title:
                continue
            summary = await self.get_json(ctx, f"{base}/api/rest_v1/page/summary/{quote(title.replace(' ', '_'))}")
            if not summary or summary.get("type") == "disambiguation":
                continue
            page = ((summary.get("content_urls") or {}).get("desktop") or {}).get(
                "page"
            ) or f"{base}/wiki/{quote(title.replace(' ', '_'))}"
            extract = clip(summary.get("extract"), 1500)
            records.append(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=SourceCategory.WEBSITES,
                    url=page,
                    title=f"Wikipedia: {title}",
                    excerpt=extract or clip(strip_html(hit.get("snippet")), 400),
                    statement=f"The Wikipedia article “{title}” summarizes: {clip(extract, 200)}",
                    evidence_type=EvidenceType.TEXT_EXCERPT,
                    published_at=parse_date(summary.get("timestamp")),
                    publisher="Wikipedia",
                    metadata={"revision": summary.get("revision"), "description": summary.get("description")},
                )
            )
        return ConnectorResult(
            records=tuple(records), warnings=() if records else ("No Wikipedia article matches this query.",)
        )


# --------------------------------------------------------------------------------------------------
# Internet Archive search
# --------------------------------------------------------------------------------------------------
class InternetArchive(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="internet_archive",
        name="Internet Archive collections",
        category=SourceCategory.PUBLIC_DOCUMENTS,
        description="Public documents, books and media items held by the Internet Archive.",
        input_types=(InputType.KEYWORD, InputType.ORGANIZATION),
        docs_url="https://archive.org/advancedsearch.php",
        terms_note="Metadata only; items are opened by the investigator.",
        allowed_in_restricted_mode=True,
        min_interval_s=1.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        data = (
            await self.get_json(
                ctx,
                "https://archive.org/advancedsearch.php",
                params={
                    "q": query.value.strip(),
                    "fl[]": ["identifier", "title", "date", "mediatype", "creator"],
                    "rows": min(query.limit, 50),
                    "output": "json",
                },
            )
            or {}
        )
        records = []
        for doc in (data.get("response") or {}).get("docs", [])[: query.limit]:
            ident, title = doc.get("identifier"), clip(str(doc.get("title") or ""), 300)
            if not ident:
                continue
            when = parse_date(doc.get("date"))
            records.append(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=SourceCategory.PUBLIC_DOCUMENTS,
                    url=f"https://archive.org/details/{quote(ident)}",
                    title=title or ident,
                    excerpt=f"Internet Archive item “{title or ident}” ({doc.get('mediatype', 'item')})"
                    + (f", dated {when.date().isoformat()}" if when else "")
                    + ".",
                    statement=f"The Internet Archive holds an item titled “{title or ident}”.",
                    evidence_type=EvidenceType.SEARCH_RESULT,
                    published_at=when,
                    publisher="Internet Archive",
                )
            )
        return ConnectorResult(records=tuple(records))


# --------------------------------------------------------------------------------------------------
# Forums
# --------------------------------------------------------------------------------------------------
class HackerNews(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="hacker_news",
        name="Hacker News (Algolia)",
        category=SourceCategory.PUBLIC_FORUMS,
        description="Public stories on Hacker News that mention a keyword, organization or domain.",
        input_types=(InputType.KEYWORD, InputType.ORGANIZATION, InputType.DOMAIN),
        docs_url="https://hn.algolia.com/api",
        terms_note="Public posts only.",
        allowed_in_restricted_mode=False,
        min_interval_s=1.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        data = (
            await self.get_json(
                ctx,
                "https://hn.algolia.com/api/v1/search",
                params={"query": query.value.strip(), "tags": "story", "hitsPerPage": min(query.limit, 30)},
            )
            or {}
        )
        records = []
        for hit in data.get("hits", [])[: query.limit]:
            title, item_id = clip(hit.get("title"), 300), hit.get("objectID")
            if not title or not item_id:
                continue
            when = parse_date(hit.get("created_at"))
            records.append(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=SourceCategory.PUBLIC_FORUMS,
                    url=f"https://news.ycombinator.com/item?id={item_id}",
                    title=title,
                    excerpt=f"Hacker News story “{title}” ({hit.get('points', 0)} points, {hit.get('num_comments', 0)} "
                    f"comments)" + (f" linking to {hit['url']}" if hit.get("url") else "") + ".",
                    statement=f"A Hacker News story titled “{title}” was posted"
                    + (f" on {when.date().isoformat()}." if when else "."),
                    evidence_type=EvidenceType.SEARCH_RESULT,
                    published_at=when,
                    publisher=hit.get("author"),
                )
            )
        return ConnectorResult(records=tuple(records))


class StackExchange(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="stack_exchange",
        name="Stack Exchange",
        category=SourceCategory.PUBLIC_FORUMS,
        description="Public questions on Stack Overflow and other Stack Exchange sites.",
        input_types=(InputType.KEYWORD, InputType.ORGANIZATION),
        docs_url="https://api.stackexchange.com/docs",
        terms_note="CC BY-SA content; the API's backoff requests are honoured.",
        requires_key="stackexchange_key",
        key_optional=True,
        allowed_in_restricted_mode=False,
        min_interval_s=1.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        params: dict[str, Any] = {
            "order": "desc",
            "sort": "relevance",
            "q": query.value.strip(),
            "site": str(query.params.get("site", "stackoverflow"))[:40],
            "pagesize": min(query.limit, 30),
        }
        if key := ctx.secret(self.info.requires_key):
            params["key"] = key
        data = await self.get_json(ctx, "https://api.stackexchange.com/2.3/search/advanced", params=params) or {}
        warnings = (f"Stack Exchange asked to back off for {data['backoff']} seconds.",) if data.get("backoff") else ()
        records = []
        for item in data.get("items", [])[: query.limit]:
            title, link = html.unescape(str(item.get("title") or "")), item.get("link")
            if not title or not link:
                continue
            when = parse_date(item.get("creation_date"))
            records.append(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=SourceCategory.PUBLIC_FORUMS,
                    url=link,
                    title=clip(title, 300),
                    excerpt=f"Question “{clip(title, 300)}” (score {item.get('score', 0)}; tags: "
                    f"{', '.join(item.get('tags', [])[:8])}).",
                    statement=f"A public Stack Exchange question titled “{clip(title, 200)}” exists.",
                    evidence_type=EvidenceType.SEARCH_RESULT,
                    published_at=when,
                )
            )
        return ConnectorResult(records=tuple(records), warnings=warnings)


# --------------------------------------------------------------------------------------------------
# Government
# --------------------------------------------------------------------------------------------------
class GovUk(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="gov_uk",
        name="GOV.UK search",
        category=SourceCategory.PUBLIC_GOVERNMENT_INFORMATION,
        description="UK government publications, guidance and announcements.",
        input_types=(InputType.KEYWORD, InputType.ORGANIZATION),
        docs_url="https://docs.publishing.service.gov.uk/repos/search-api.html",
        terms_note="Open Government Licence v3.0.",
        allowed_in_restricted_mode=True,
        min_interval_s=1.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        data = (
            await self.get_json(
                ctx,
                "https://www.gov.uk/api/search.json",
                params={"q": query.value.strip(), "count": min(query.limit, 50)},
            )
            or {}
        )
        records = []
        for item in data.get("results", [])[: query.limit]:
            title, link = clip(item.get("title"), 300), item.get("link")
            if not title or not link:
                continue
            url = link if link.startswith("http") else f"https://www.gov.uk{link}"
            orgs = ", ".join(o.get("title", "") for o in item.get("organisations", [])[:3] if isinstance(o, dict))
            when = parse_date(item.get("public_timestamp"))
            records.append(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=SourceCategory.PUBLIC_GOVERNMENT_INFORMATION,
                    url=url,
                    title=title,
                    excerpt=clip(f"{title}. {item.get('description') or ''}", 800),
                    statement=f"GOV.UK published “{title}”" + (f" ({orgs})" if orgs else "") + ".",
                    evidence_type=EvidenceType.SEARCH_RESULT,
                    published_at=when,
                    publisher=orgs or "GOV.UK",
                    organization_context=True,
                    entities=tuple(
                        EntityDraft("organization", o["title"], o["title"])
                        for o in item.get("organisations", [])[:3]
                        if isinstance(o, dict) and o.get("title")
                    ),
                )
            )
        return ConnectorResult(records=tuple(records))


class FederalRegister(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="federal_register",
        name="U.S. Federal Register",
        category=SourceCategory.PUBLIC_GOVERNMENT_INFORMATION,
        description="Rules, proposed rules and notices published by U.S. federal agencies.",
        input_types=(InputType.KEYWORD, InputType.ORGANIZATION),
        docs_url="https://www.federalregister.gov/developers/documentation/api/v1",
        terms_note="U.S. government works are in the public domain.",
        allowed_in_restricted_mode=True,
        min_interval_s=1.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        data = (
            await self.get_json(
                ctx,
                "https://www.federalregister.gov/api/v1/documents.json",
                params={"conditions[term]": query.value.strip(), "per_page": min(query.limit, 50), "order": "newest"},
            )
            or {}
        )
        records = []
        for doc in data.get("results", [])[: query.limit]:
            title, url = clip(doc.get("title"), 300), doc.get("html_url")
            if not title or not url:
                continue
            agencies = ", ".join(a.get("name", "") for a in doc.get("agencies", [])[:3] if isinstance(a, dict))
            when = parse_date(doc.get("publication_date"))
            records.append(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=SourceCategory.PUBLIC_GOVERNMENT_INFORMATION,
                    url=url,
                    title=title,
                    excerpt=clip(f"{doc.get('type', 'Document')}: {title}. {doc.get('abstract') or ''}", 1000),
                    statement=f"The Federal Register published “{clip(title, 200)}”"
                    + (f" ({agencies})" if agencies else "")
                    + ".",
                    evidence_type=EvidenceType.SEARCH_RESULT,
                    published_at=when,
                    publisher=agencies or "Federal Register",
                    organization_context=True,
                    metadata={"document_number": doc.get("document_number")},
                )
            )
        return ConnectorResult(records=tuple(records))
