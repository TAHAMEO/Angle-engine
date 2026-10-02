"""Recorded-response transport for tests and the offline demo (``ANGEL_CONNECTOR_MODE=fixtures``).

Fixture files are JSON lists of entries::

    [{"method": "GET", "url": "https://api.example.org/v1/search?q=northwind", "match": "exact",
      "status": 200, "headers": {"content-type": "application/json"}, "json": {...}}]

``match`` is ``exact`` (scheme, host, path and the *set* of query parameters), ``prefix``, or ``params``
(same scheme, host and path, and every parameter listed under ``query`` present with that value —
case-insensitive — so fixtures do not depend on incidental parameters such as page sizes). A body is given
as ``json``, ``text`` or ``body_file`` (path relative to the fixture file). Unmatched requests get a 404
with ``x-fixture-missing: 1`` so connectors behave exactly as for an empty live result.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

FIXTURES_ROOT = Path(__file__).resolve().parents[2] / "osint" / "fixtures"


def canonical(url: str) -> str:
    parts = urlsplit(url)
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", query, ""))


@dataclass(frozen=True, slots=True)
class FixtureEntry:
    method: str
    url: str
    match: str
    status: int
    headers: dict[str, str]
    body: bytes
    query: tuple[tuple[str, str], ...] = ()

    def matches(self, method: str, url: str) -> bool:
        if method.upper() != self.method:
            return False
        if self.match == "prefix":
            return canonical(url).startswith(self.url)
        if self.match == "params":
            parts = urlsplit(url)
            if urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", "", "")) != self.url:
                return False
            given: dict[str, list[str]] = {}
            for key, value in parse_qsl(parts.query, keep_blank_values=True):
                given.setdefault(key, []).append(value.casefold())
            return all(value.casefold() in given.get(key, []) for key, value in self.query)
        return canonical(url) == self.url


def _load_entry(raw: dict[str, Any], base: Path) -> FixtureEntry:
    headers = {k.lower(): v for k, v in raw.get("headers", {}).items()}
    if "json" in raw:
        body = json.dumps(raw["json"]).encode()
        headers.setdefault("content-type", "application/json")
    elif "body_file" in raw:
        path = (base / raw["body_file"]).resolve()
        if base.resolve() not in path.parents:
            raise ValueError("fixture body_file escapes the fixture directory")
        body = path.read_bytes()
    else:
        body = str(raw.get("text", "")).encode()
        headers.setdefault("content-type", "text/plain; charset=utf-8")
    match = raw.get("match", "params" if "query" in raw else "exact")
    if match == "prefix":
        url = raw["url"]
    elif match == "params":
        parts = urlsplit(raw["url"])
        url = urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", "", ""))
    else:
        url = canonical(raw["url"])
    return FixtureEntry(
        method=raw.get("method", "GET").upper(),
        url=url,
        match=match,
        status=int(raw.get("status", 200)),
        headers=headers,
        body=body,
        query=tuple((str(k), str(v)) for k, v in raw.get("query", {}).items()),
    )


def load_fixtures(*roots: Path) -> list[FixtureEntry]:
    entries: list[FixtureEntry] = []
    for root in roots or (FIXTURES_ROOT,):
        if not root.exists():
            continue
        for file in sorted(root.rglob("*.json")):
            data = json.loads(file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                entries.extend(_load_entry(item, file.parent) for item in data)
    return entries


class FixtureTransport(httpx.AsyncBaseTransport):
    def __init__(self, entries: list[FixtureEntry] | None = None, *, strict: bool = False) -> None:
        self.entries = entries if entries is not None else load_fixtures()
        self.strict = strict
        self.requests: list[httpx.Request] = []

    def add(
        self,
        url: str,
        *,
        status: int = 200,
        json_body: Any = None,
        text: str | None = None,
        headers: dict[str, str] | None = None,
        method: str = "GET",
        match: str | None = None,
        query: dict[str, str] | None = None,
    ) -> None:
        raw: dict[str, Any] = {"method": method, "url": url, "status": status, "headers": headers or {}}
        if match:
            raw["match"] = match
        if query is not None:
            raw["query"] = query
        if json_body is not None:
            raw["json"] = json_body
        else:
            raw["text"] = text or ""
        self.entries.insert(0, _load_entry(raw, FIXTURES_ROOT))

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)
        for entry in self.entries:
            if entry.matches(request.method, url):
                return httpx.Response(entry.status, headers=entry.headers, content=entry.body, request=request)
        if self.strict:
            raise AssertionError(f"no fixture for {request.method} {url}")
        return httpx.Response(
            404,
            headers={"x-fixture-missing": "1", "content-type": "text/plain"},
            content=b"not found in offline fixtures",
            request=request,
        )
