"""Versioned legal documents (Markdown with a small front-matter header), served by the API."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

KINDS = ("terms", "privacy", "acceptable_use", "responsible_use")


@dataclass(frozen=True, slots=True)
class LegalDoc:
    kind: str
    title: str
    version: str
    effective: str
    sha256: str
    body: str


def _parse(kind: str, raw: str) -> LegalDoc:
    if not raw.startswith("---\n"):
        raise ValueError(f"legal document {kind} has no front matter")
    header, body = raw[4:].split("\n---\n", 1)
    meta: dict[str, str] = {}
    for line in header.splitlines():
        key, _, value = line.partition(":")
        meta[key.strip()] = value.strip()
    return LegalDoc(
        kind=kind,
        title=meta["title"],
        version=meta["version"],
        effective=meta["effective"],
        sha256=hashlib.sha256(raw.encode()).hexdigest(),
        body=body.strip() + "\n",
    )


@lru_cache(maxsize=1)
def load_documents() -> dict[str, LegalDoc]:
    pkg = resources.files("angel_engine.legal")
    return {kind: _parse(kind, pkg.joinpath(f"{kind}.md").read_text(encoding="utf-8")) for kind in KINDS}


def current_versions() -> dict[str, str]:
    return {kind: doc.version for kind, doc in load_documents().items()}
