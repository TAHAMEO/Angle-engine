"""Text and metadata extraction from captured documents (HTML, PDF, plain text).

Runs inside the extraction sandbox (:mod:`angel_engine.osint.sandbox`), never in the egress worker:
parsing untrusted documents happens only in a resource-limited child process without network use.
Output is plain JSON-serializable data; redaction happens later, in ingestion.
"""

from __future__ import annotations

import io
import json
import re
from typing import Any

MAX_TEXT_CHARS = 100_000
MAX_PDF_PAGES = 200
MAX_JSON_LD_BLOCKS = 20
MAX_JSON_LD_BYTES = 200_000

_JSON_LD_OPEN = re.compile(r"<script[^>]{0,200}type\s*=\s*[\"']application/ld\+json[\"'][^>]{0,200}>", re.IGNORECASE)
_SCRIPT_CLOSE = re.compile(r"</script\s*>", re.IGNORECASE)
_CANONICAL = re.compile(r"<link[^>]{0,300}rel\s*=\s*[\"']canonical[\"'][^>]{0,300}>", re.IGNORECASE)
_OG_URL = re.compile(r"<meta[^>]{0,300}property\s*=\s*[\"']og:url[\"'][^>]{0,300}>", re.IGNORECASE)
_HREF = re.compile(r"href\s*=\s*[\"']([^\"']{1,2000})[\"']", re.IGNORECASE)
_CONTENT = re.compile(r"content\s*=\s*[\"']([^\"']{1,2000})[\"']", re.IGNORECASE)
_PAYWALL_HINTS = re.compile(
    r"\b(?:subscribe to (?:continue|read)|this article is for subscribers|paywall)\b", re.IGNORECASE
)


def _walk_json_ld(node: Any, out: dict[str, Any]) -> None:
    if isinstance(node, list):
        for item in node[:50]:
            _walk_json_ld(item, out)
        return
    if not isinstance(node, dict):
        return
    access = node.get("isAccessibleForFree")
    if access is not None and str(access).strip().lower() in {"false", "0", "no"}:
        out["paywalled"] = True
    for key in ("datePublished", "dateCreated", "dateModified"):
        if isinstance(node.get(key), str) and key not in out:
            out[key] = node[key][:40]
    based_on = node.get("isBasedOn")
    if isinstance(based_on, str):
        out.setdefault("is_based_on", based_on[:2000])
    elif isinstance(based_on, dict) and isinstance(based_on.get("url"), str):
        out.setdefault("is_based_on", based_on["url"][:2000])
    publisher = node.get("publisher")
    if isinstance(publisher, dict) and isinstance(publisher.get("name"), str):
        out.setdefault("publisher", publisher["name"][:200])
    if "@graph" in node:
        _walk_json_ld(node["@graph"], out)


def html_metadata(html: str) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    for i, match in enumerate(_JSON_LD_OPEN.finditer(html)):
        if i >= MAX_JSON_LD_BLOCKS:
            break
        close = _SCRIPT_CLOSE.search(html, match.end(), match.end() + MAX_JSON_LD_BYTES)
        if close is None:
            continue
        raw = html[match.end() : close.start()].strip()
        try:
            _walk_json_ld(json.loads(raw), meta)
        except (ValueError, RecursionError):
            continue
    if (tag := _CANONICAL.search(html)) and (href := _HREF.search(tag.group(0))):
        meta["canonical_url"] = href.group(1)
    if (tag := _OG_URL.search(html)) and (content := _CONTENT.search(tag.group(0))):
        meta["og_url"] = content.group(1)
    if _PAYWALL_HINTS.search(html[:200_000]):
        meta.setdefault("paywall_hint", True)
    return meta


def extract_html(content: bytes, url: str) -> dict[str, Any]:
    import trafilatura

    html = content.decode("utf-8", errors="replace")
    meta = html_metadata(html)
    doc = trafilatura.bare_extraction(
        html, url=url, with_metadata=True, include_comments=False, include_tables=True, favor_precision=True
    )
    data = doc.as_dict() if doc is not None and hasattr(doc, "as_dict") else (doc or {})
    text = (data.get("text") or "").strip()
    return {
        "kind": "html",
        "title": (data.get("title") or "")[:500] or None,
        "text": text[:MAX_TEXT_CHARS],
        "truncated": len(text) > MAX_TEXT_CHARS,
        "published": data.get("date") or meta.get("datePublished"),
        "sitename": data.get("sitename"),
        "author": data.get("author"),
        "language": data.get("language"),
        **{k: v for k, v in meta.items() if k not in {"datePublished"}},
    }


def extract_pdf(content: bytes) -> dict[str, Any]:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(content), strict=False)
    if reader.is_encrypted:
        return {"kind": "pdf", "title": None, "text": "", "encrypted": True, "pages": len(reader.pages)}
    parts: list[str] = []
    size = 0
    pages = len(reader.pages)
    for index, page in enumerate(reader.pages):
        if index >= MAX_PDF_PAGES or size > MAX_TEXT_CHARS:
            break
        piece = page.extract_text() or ""
        parts.append(piece)
        size += len(piece)
    info: Any = reader.metadata or {}
    text = "\n".join(parts).strip()
    return {
        "kind": "pdf",
        "title": str(info.get("/Title"))[:500] if info.get("/Title") else None,
        "text": text[:MAX_TEXT_CHARS],
        "truncated": len(text) > MAX_TEXT_CHARS or pages > MAX_PDF_PAGES,
        "pages": pages,
        "published": str(info.get("/CreationDate"))[:40] if info.get("/CreationDate") else None,
    }


def extract(content: bytes, content_type: str | None, url: str) -> dict[str, Any]:
    kind = (content_type or "").split(";")[0].strip().lower()
    if kind == "application/pdf" or content[:5] == b"%PDF-":
        return extract_pdf(content)
    if kind in {"text/html", "application/xhtml+xml"} or content.lstrip()[:15].lower().startswith(
        (b"<!doctype", b"<html")
    ):
        return extract_html(content, url)
    if kind.startswith("text/"):
        text = content.decode("utf-8", errors="replace").strip()
        return {"kind": "text", "title": None, "text": text[:MAX_TEXT_CHARS], "truncated": len(text) > MAX_TEXT_CHARS}
    return {"kind": "unsupported", "title": None, "text": "", "content_type": kind}
