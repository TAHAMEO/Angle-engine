"""Recorded responses for the offline demo and tests (fictional ``.example`` data only)."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=1)
def _dns() -> dict[str, dict[str, list[str]]]:
    path = FIXTURES_DIR / "dns_records.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def dns_fixture(domain: str) -> dict[str, list[str]]:
    return _dns().get(domain, {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []})
