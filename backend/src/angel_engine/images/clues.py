"""Visual clues for pivots: visible text, URLs, domains, handles, hashtags, e-mail domains, dates,
organization/brand names, broad public places, objects and descriptive metadata.

Clues are *suggestions* with a confidence level and a stated basis; nothing is searched automatically.
All text here is already redacted (OCR and metadata stages run the sensitive-data guard first).
"""

from __future__ import annotations

import gzip
import json
import re
from functools import lru_cache
from pathlib import Path

from angel_engine.evidence.urls import has_public_suffix
from angel_engine.images.types import Box, Clue, ClueType, MetadataResult, ObjectResult, OcrResult

ID, VERSION = "clues", "1"
DATA = Path(__file__).resolve().parents[1] / "data" / "world_places.json.gz"
_URL = re.compile(r"\b(?:https?://|www\.)[^\s<>\"'()]{3,200}", re.IGNORECASE)
_DOMAIN = re.compile(r"(?<![@\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,4}[a-z]{2,24})(?![\w.-])", re.I)
_HANDLE = re.compile(
    r"(?<![\w@])@([A-Za-z0-9_](?:[A-Za-z0-9_.]{0,28}[A-Za-z0-9_])?)(?:@([a-z0-9.-]+\.[a-z]{2,24}))?", re.IGNORECASE
)
_HASHTAG = re.compile(r"(?<![\w#])#([^\W\d_][\w]{1,49})")
_EMAIL_DOMAIN = re.compile(r"[\w.+-]{1,64}@((?:[a-z0-9-]{1,63}\.){1,4}[a-z]{2,24})", re.IGNORECASE)
_EST_YEAR = re.compile(r"\b(?:est(?:ablished)?\.?|since|founded|desde|depuis|seit)\s*(1[89]\d{2}|20\d{2})\b", re.I)
_DMY = re.compile(r"\b(\d{1,2})[./-](\d{1,2})[./-](\d{4})\b")
_ISO_DATE = re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b")
_LEGAL = re.compile(r"\b(?:ltd|limited|inc|llc|gmbh|lda|s\.?a\.?|plc|co\.)\b", re.IGNORECASE)


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


BUSINESS_WORDS = _words(
    "coffee roasters roastery cafe café bakery bank hotel restaurant bar shop store market company co corp group "
    "studio studios press news media pharmacy clinic hospital university college school museum gallery theatre "
    "theater cinema bookshop bookstore books brewery winery foods motors airlines airways insurance capital "
    "partners consulting labs laboratories technologies systems solutions industries holdings trading logistics "
    "foundation association institute ministry council agency"
)
SIGN_WORDS = _words(
    "open opening daily closed hours monday tuesday wednesday thursday friday saturday sunday entrance exit sale "
    "welcome push pull parking street st road rd avenue ave rua calle via rue lane square no smoking toilets wifi "
    "menu today special offer floor"
)
PLATFORM_HINTS = {
    "instagram": "instagram",
    "twitter": "x",
    "x.com": "x",
    "tiktok": "tiktok",
    "facebook": "facebook",
    "mastodon": "mastodon",
    "github": "github",
    "bsky": "bluesky",
    "threads": "threads",
}


@lru_cache(maxsize=1)
def _places() -> dict[str, tuple[str, str]]:
    try:
        data = json.loads(gzip.decompress(DATA.read_bytes()))
    except (OSError, ValueError):
        return {}
    out: dict[str, tuple[str, str]] = {}
    for name, cc in data.get("countries", []):
        out[name.casefold()] = ("country", cc)
    for name, cc in data.get("cities", []):
        out.setdefault(name.casefold(), ("locality", cc))
    return out


def _level(conf: float) -> str:
    return "high" if conf >= 0.85 else "moderate" if conf >= 0.6 else "low"


def _looks_like_organization(text: str, *, prominent: bool) -> bool:
    """Organization/brand names: a legal suffix, a business word, or the most prominent all-caps line —
    never opening hours, street names, place names or generic sign wording."""
    words = re.findall(r"[^\W\d_][\w'&.-]*", text)
    if len(words) < 2 or sum(c.isalpha() for c in text) < 6 or _URL.search(text) or "[REDACTED" in text:
        return False
    lowered = {w.casefold().strip(".") for w in words}
    if lowered & SIGN_WORDS or any(
        re.search(rf"(?<!\w){re.escape(p)}(?!\w)", text.casefold()) for p in _places() if len(p) >= 4
    ):
        return False
    if _LEGAL.search(text) or lowered & BUSINESS_WORDS:
        return True
    return prominent and text.upper() == text


def from_ocr(ocr: OcrResult) -> list[Clue]:
    clues: list[Clue] = []
    tallest = max((line.box.h for line in ocr.lines), default=0.0)
    for line in ocr.lines:
        text, box = line.text.strip(), line.box
        level, basis = _level(line.confidence), f"OCR engine score {line.confidence:.2f}"

        def add(
            kind: ClueType,
            value: str,
            normalized: str,
            *,
            platform: str | None = None,
            precision: str | None = None,
            box: Box | None = box,
            level: str = level,
            basis: str = basis,
        ) -> None:
            clues.append(
                Clue(
                    type=kind,
                    value=value,
                    normalized=normalized,
                    source="ocr",
                    confidence=level,
                    confidence_basis=basis,
                    box=box,
                    platform=platform,
                    precision=precision,
                )
            )

        if len(text) >= 3:
            add(ClueType.VISIBLE_TEXT, text, text.casefold())
        lowered = text.casefold()
        platform = next((p for hint, p in PLATFORM_HINTS.items() if hint in lowered), None)
        for match in _URL.finditer(text):
            url = match.group(0).rstrip(".,;:")
            add(ClueType.URL, url, url.casefold() if url.lower().startswith("http") else f"https://{url.casefold()}")
        for match in _EMAIL_DOMAIN.finditer(text):
            add(ClueType.EMAIL_DOMAIN, match.group(1).lower(), match.group(1).lower())
        for match in _DOMAIN.finditer(text):
            domain = match.group(1).lower().removeprefix("www.")
            if has_public_suffix(domain) and not domain.endswith((".jpg", ".png")):
                add(ClueType.DOMAIN, domain, domain)
        for match in _HANDLE.finditer(text):
            handle, instance = match.group(1), match.group(2)
            if instance:
                add(ClueType.USERNAME, f"@{handle}@{instance}", f"{handle}@{instance}".lower(), platform="mastodon")
            else:
                add(ClueType.USERNAME, f"@{handle}", handle.lower(), platform=platform)
        for match in _HASHTAG.finditer(text):
            add(ClueType.HASHTAG, f"#{match.group(1)}", match.group(1).casefold())
        for match in _EST_YEAR.finditer(text):
            add(ClueType.DATE, match.group(0), match.group(1), precision="year")
        for match in _ISO_DATE.finditer(text):
            add(ClueType.DATE, match.group(0), match.group(0), precision="day")
        for match in _DMY.finditer(text):
            day, month, year = match.groups()
            if 1 <= int(month) <= 12 and 1 <= int(day) <= 31:
                add(ClueType.DATE, match.group(0), f"{year}-{int(month):02d}-{int(day):02d}", precision="day")
        if _looks_like_organization(text, prominent=line.box.h >= tallest * 0.9):
            words = re.findall(r"[^\W\d_][\w'&.-]*", text)
            name = " ".join(w.capitalize() if text.upper() == text else w for w in words)
            add(ClueType.ORGANIZATION, name, name.casefold())
        for phrase, (level_name, cc) in _places().items():
            if len(phrase) >= 4 and re.search(rf"(?<!\w){re.escape(phrase)}(?!\w)", lowered):
                add(ClueType.PUBLIC_LOCATION, phrase.title(), f"{level_name}:{cc}:{phrase}")
    return _dedupe(clues)


def from_metadata(meta: MetadataResult) -> list[Clue]:
    clues: list[Clue] = []
    basis = "Embedded metadata (editable; its presence or absence proves nothing on its own)"
    for field in ("camera_make", "camera_model", "lens_model", "software", "xmp_creator_tool"):
        if value := meta.fields.get(field):
            clues.append(
                Clue(
                    type=ClueType.EXIF_FIELD,
                    value=f"{field.replace('_', ' ')}: {value}",
                    normalized=f"{field}:{str(value).casefold()}",
                    source="metadata",
                    confidence="moderate",
                    confidence_basis=basis,
                )
            )
    if meta.capture_time:
        clues.append(
            Clue(
                type=ClueType.DATE,
                value=f"Capture time (EXIF): {meta.capture_time}",
                normalized=meta.capture_time[:10],
                source="metadata",
                confidence="moderate",
                confidence_basis=basis,
                precision="day",
            )
        )
    loc = meta.location
    if loc is not None and loc.status != "unresolved" and loc.country_code:
        label = ", ".join(p for p in (loc.region_name, loc.country_name) if p)
        level = "admin1" if loc.region_code else "country"
        clues.append(
            Clue(
                type=ClueType.PUBLIC_LOCATION,
                value=f"{label} (GPS generalized to region)",
                normalized=f"{level}:{loc.country_code}:{(loc.region_code or loc.country_code).lower()}",
                source="metadata",
                confidence="moderate",
                confidence_basis=basis,
            )
        )
    return clues


def from_objects(objects: ObjectResult) -> list[Clue]:
    return _dedupe(
        [
            Clue(
                type=ClueType.OBJECT,
                value=obj.label,
                normalized=obj.label,
                source="objects",
                confidence=_level(obj.score),
                confidence_basis=f"Object detector score {obj.score:.2f}",
                box=obj.box,
            )
            for obj in objects.objects
        ]
    )


def _dedupe(clues: list[Clue]) -> list[Clue]:
    seen: dict[tuple[str, str], Clue] = {}
    for clue in clues:
        seen.setdefault((clue.type.value, clue.normalized), clue)
    return list(seen.values())[:200]
