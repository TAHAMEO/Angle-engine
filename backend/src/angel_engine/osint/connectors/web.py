"""Website connectors: page capture (robots-permitted only), Wayback Machine CDX and Common Crawl index."""

from __future__ import annotations

import json
from typing import Any, ClassVar
from urllib.parse import urlsplit

from angel_engine.infra.http.safe_client import HttpPolicyError, ResponseTooLarge
from angel_engine.osint.connectors.base import Connector, ConnectorContext, ConnectorError, clip, parse_date
from angel_engine.osint.types import (
    AccessStatus,
    ConnectorInfo,
    ConnectorQuery,
    ConnectorResult,
    EntityDraft,
    EvidenceType,
    InputType,
    ManualReference,
    NormalizedRecord,
    RawCapture,
    SourceCategory,
)

HTML_MAX_BYTES = 5 * 1024 * 1024
PDF_MAX_BYTES = 20 * 1024 * 1024
ACCEPT_DOCUMENTS = "text/html,application/xhtml+xml;q=0.9,application/pdf;q=0.8,text/plain;q=0.7"


class WebCapture(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="web_capture",
        name="Web page capture",
        category=SourceCategory.WEBSITES,
        description="Captures a public page or PDF the investigator selected, if robots.txt allows it. Login walls, "
        "paywalls and robots-blocked pages are recorded as references for manual review — never bypassed.",
        input_types=(InputType.URL,),
        docs_url="https://www.rfc-editor.org/rfc/rfc9309",
        terms_note="Captures are limited to publicly accessible pages; copyright remains with the publisher.",
        allowed_in_restricted_mode=True,
        min_interval_s=2.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        url = query.value.strip()
        decision = await ctx.robots.check(url)
        if not decision.allowed:
            reason = (
                "robots.txt does not allow automated access"
                if decision.reason == "disallowed"
                else "robots.txt could not be retrieved, so the page was not fetched"
            )
            return ConnectorResult(references=(ManualReference(url, AccessStatus.ROBOTS_DISALLOWED, reason),))
        try:
            result = await ctx.http.get(
                url,
                accept=ACCEPT_DOCUMENTS,
                max_bytes=PDF_MAX_BYTES,
                min_interval=max(self.info.min_interval_s, decision.crawl_delay or 0),
            )
        except ResponseTooLarge:
            return ConnectorResult(
                references=(
                    ManualReference(url, AccessStatus.REFERENCE_ONLY, "The document is larger than the capture limit."),
                )
            )
        except HttpPolicyError as exc:
            raise ConnectorError("blocked_url", str(exc)) from exc
        if result.status in (401, 407) or "www-authenticate" in result.headers:
            return ConnectorResult(
                references=(ManualReference(url, AccessStatus.LOGIN_REQUIRED, "The page requires signing in."),)
            )
        if result.status == 402:
            return ConnectorResult(
                references=(ManualReference(url, AccessStatus.PAYWALLED, "The page is behind a paywall."),)
            )
        if result.status == 403:
            return ConnectorResult(
                references=(
                    ManualReference(url, AccessStatus.REFERENCE_ONLY, "The site refused automated access (HTTP 403)."),
                )
            )
        if result.status in (404, 410):
            return ConnectorResult(warnings=(f"The page was not found (HTTP {result.status}).",))
        if not result.ok:
            raise ConnectorError("upstream_error", f"HTTP {result.status}")
        if result.content_type in ("text/html", "application/xhtml+xml") and len(result.content) > HTML_MAX_BYTES:
            return ConnectorResult(
                references=(
                    ManualReference(url, AccessStatus.REFERENCE_ONLY, "The page is larger than the capture limit."),
                )
            )
        robots_tag = result.headers.get("x-robots-tag", "").lower()
        capture = RawCapture(
            url=url,
            final_url=result.final_url,
            status=result.status,
            content_type=result.content_type,
            content=result.content,
            retrieved_at=ctx.now,
            no_archive="noarchive" in robots_tag or "none" in robots_tag,
            headers={k: v for k, v in result.headers.items() if k in ("last-modified", "content-language")},
        )
        return ConnectorResult(captures=(capture,))


def capture_record(capture: RawCapture, extracted: dict[str, Any]) -> NormalizedRecord | ManualReference:
    """Turn sandbox extraction output into a record (or a manual-review reference for paywalled pages)."""
    if extracted.get("paywalled") or extracted.get("paywall_hint"):
        return ManualReference(
            capture.final_url, AccessStatus.PAYWALLED, "The publisher marks this content as subscriber-only."
        )
    text = (extracted.get("text") or "").strip()
    if not text:
        return ManualReference(capture.final_url, AccessStatus.REFERENCE_ONLY, "No readable text could be extracted.")
    if capture.no_archive:
        text = clip(text, 500)  # the publisher asked not to keep copies: keep a short excerpt only
    host = urlsplit(capture.final_url).hostname or ""
    title = extracted.get("title") or host
    is_pdf = extracted.get("kind") == "pdf"
    canonical = extracted.get("canonical_url") or extracted.get("og_url")
    metadata = {
        k: extracted[k]
        for k in ("sitename", "language", "pages", "truncated", "is_based_on")
        if extracted.get(k) is not None
    }
    if canonical:
        metadata["canonical_url"] = canonical
    return NormalizedRecord(
        connector_id="web_capture",
        category=SourceCategory.PUBLIC_DOCUMENTS if is_pdf else SourceCategory.WEBSITES,
        url=capture.url,
        final_url=capture.final_url,
        title=title,
        excerpt=text,
        statement=f"The {'document' if is_pdf else 'page'} “{clip(title, 140)}” on {host} was captured.",
        evidence_type=EvidenceType.DOCUMENT_EXCERPT if is_pdf else EvidenceType.PAGE_CAPTURE,
        published_at=parse_date(extracted.get("published")),
        retrieved_at=capture.retrieved_at,
        publisher=extracted.get("publisher") or extracted.get("sitename"),
        entities=(EntityDraft("webpage", capture.final_url, capture.final_url), EntityDraft("website", host, host)),
        metadata=metadata,
    )


class Wayback(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="wayback",
        name="Internet Archive Wayback Machine",
        category=SourceCategory.WEBSITES,
        description="Lists archived snapshots of a URL or domain (first and latest captures).",
        input_types=(InputType.URL, InputType.DOMAIN),
        docs_url="https://archive.org/developers/wayback-cdx-server.html",
        terms_note="Read-only CDX queries; Save Page Now is never used.",
        allowed_in_restricted_mode=True,
        min_interval_s=1.5,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        target = query.value.strip()
        params: dict[str, Any] = {
            "url": target,
            "output": "json",
            "fl": "timestamp,original,statuscode,digest",
            "collapse": "digest",
            "limit": min(query.limit * 5, 500),
        }
        if query.input_type == InputType.DOMAIN:
            params["matchType"] = "domain"
        rows = await self.get_json(ctx, "https://web.archive.org/cdx/search/cdx", params=params) or []
        captures = [dict(zip(rows[0], row, strict=False)) for row in rows[1:]] if rows else []
        if not captures:
            return ConnectorResult(warnings=("The Wayback Machine has no captures for this target.",))
        captures.sort(key=lambda c: c.get("timestamp", ""))
        first, last = captures[0], captures[-1]
        first_at, last_at = parse_date(first["timestamp"]), parse_date(last["timestamp"])
        records = []
        for label, cap, when in (("first", first, first_at), ("latest", last, last_at)):
            archived = f"https://web.archive.org/web/{cap['timestamp']}/{cap['original']}"
            records.append(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=SourceCategory.WEBSITES,
                    url=archived,
                    title=f"Wayback {label} capture of {cap['original']}",
                    archived_url=archived,
                    excerpt=f"The Internet Archive holds {len(captures)} distinct capture(s) of {target}. The {label} "
                    f"capture was made on {when.date().isoformat() if when else cap['timestamp']} "
                    f"(HTTP {cap.get('statuscode', '?')}).",
                    statement=f"The Internet Archive's {label} capture of {target} dates from "
                    f"{when.date().isoformat() if when else cap['timestamp']}.",
                    evidence_type=EvidenceType.SEARCH_RESULT,
                    published_at=when,
                    publisher="Internet Archive",
                    metadata={
                        "events": [
                            {
                                "kind": "first_archived",
                                "date": when.isoformat(),
                                "precision": "day",
                                "title": f"First archived copy of {target}",
                            }
                        ]
                    }
                    if label == "first" and when
                    else {"captures": len(captures)},
                )
            )
        return ConnectorResult(records=tuple(records))


class CommonCrawl(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="common_crawl",
        name="Common Crawl index",
        category=SourceCategory.WEBSITES,
        description="Checks whether recent Common Crawl crawls captured a URL (index lookups only).",
        input_types=(InputType.URL,),
        docs_url="https://index.commoncrawl.org/",
        terms_note="Index metadata only; WARC payloads are not downloaded.",
        allowed_in_restricted_mode=True,
        min_interval_s=2.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        crawls = await self.get_json(ctx, "https://index.commoncrawl.org/collinfo.json") or []
        records: list[NormalizedRecord] = []
        for crawl in crawls[:2]:
            api = crawl.get("cdx-api")
            if not api:
                continue
            result = await ctx.http.get(
                api,
                params={"url": query.value.strip(), "output": "json", "limit": 5},
                min_interval=self.info.min_interval_s,
            )
            if result.status == 404 or not result.ok:
                continue
            for line in result.text().splitlines()[:5]:
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                when = parse_date(item.get("timestamp"))
                records.append(
                    NormalizedRecord(
                        connector_id=self.info.id,
                        category=SourceCategory.WEBSITES,
                        url=item.get("url", query.value),
                        title=f"Common Crawl {crawl.get('id')} capture",
                        excerpt=f"Common Crawl crawl {crawl.get('name', crawl.get('id'))} captured "
                        f"{item.get('url')} on "
                        f"{when.date().isoformat() if when else item.get('timestamp')} "
                        f"(HTTP {item.get('status')}, {item.get('mime')}).",
                        statement=f"Common Crawl captured {item.get('url')} in crawl {crawl.get('id')}.",
                        evidence_type=EvidenceType.SEARCH_RESULT,
                        published_at=when,
                        publisher="Common Crawl",
                        metadata={"crawl": crawl.get("id"), "digest": item.get("digest")},
                    )
                )
        return ConnectorResult(
            records=tuple(records), warnings=() if records else ("No Common Crawl captures were found.",)
        )
