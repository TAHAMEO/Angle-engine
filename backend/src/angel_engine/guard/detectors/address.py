"""Street addresses (multilingual heuristics). Only the street part is redacted; the city or postal
code that follows is kept.

Registered office addresses in registry/government records about organizations are kept in
standard mode, but phrases that point at a residence ("lives at", "home address", …) are always
redacted, whatever the context.

Word-boundary checks on the preceding character are done in Python where a leading lookbehind
would slow the scan down (Germanic suffix forms).
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from angel_engine.guard.detectors.base import P_ADDRESS, Detection, Scan, detection, trie_pattern
from angel_engine.guard.types import RedactionKind, SourceKind

_KIND = RedactionKind.STREET_ADDRESS
_UPPER = "A-ZÀ-ÖØ-ÞĄĆĘŁŃŚŹŻČŘŠŽĎŤŇŐŰ"
# Every word class is bounded (street-name words are short) so no pattern can backtrack quadratically on
# long runs of letters; Romance name parts exclude "-" so they cannot overlap with the [\s-] separators.
_WORD_MAX = 40
_CAP = rf"[{_UPPER}][\w'’.\-]{{0,{_WORD_MAX}}}"
_CAP_PART = rf"[{_UPPER}][\w'’.]{{0,{_WORD_MAX}}}"
_LOWER_OK = r"(?:of|the|de|la|del|du|van|von)"
_UNIT = r"(?i:apt|apartment|unit|suite|ste|flat|fl|floor|room|rm|\#)\.?\s*\#?\s*[A-Za-z0-9\-]{1,6}\b"
_HOUSE_NUMBER = r"\d{1,5}[A-Za-z]?(?:\s?[-–/]\s?\d{1,5}[A-Za-z]?)?"
_EN_SUFFIX = trie_pattern(
    (
        "Street",
        "St",
        "Avenue",
        "Ave",
        "Av",
        "Road",
        "Rd",
        "Boulevard",
        "Blvd",
        "Lane",
        "Ln",
        "Drive",
        "Dr",
        "Way",
        "Court",
        "Ct",
        "Place",
        "Pl",
        "Terrace",
        "Ter",
        "Terr",
        "Square",
        "Sq",
        "Highway",
        "Hwy",
        "Parkway",
        "Pkwy",
        "Crescent",
        "Cres",
        "Close",
        "Grove",
        "Gardens",
        "Gdns",
        "Row",
        "Mews",
        "Circle",
        "Cir",
        "Trail",
        "Trl",
        "Alley",
        "Plaza",
        "Loop",
        "Wharf",
        "Quay",
        "Embankment",
        "Esplanade",
        "Promenade",
        "Broadway",
    )
)
_DIRECTION = r"(?:N|S|E|W|NE|NW|SE|SW|North|South|East|West)"
_NOT_QUANTITY = r"(?!\s*(?:%|days?|hours?|minutes?|weeks?|months?|years?|times?|people|percent|km|kg|mb|gb)\b)"

# "12 Elm St", "221B Baker Street", "1600 Pennsylvania Avenue NW, Suite 300"
_ENGLISH = re.compile(
    rf"""(?<![\w/.,\-])(?P<num>{_HOUSE_NUMBER}),?\s+
    (?:{_DIRECTION}\.?\s+)?
    (?:{_CAP}|\d{{1,3}}(?:st|nd|rd|th))(?:\s+(?:{_CAP}|{_LOWER_OK})){{0,3}}
    \s+(?i:{_EN_SUFFIX})\b\.?
    (?:\s+{_DIRECTION}\b\.?)?
    (?:\s*,?\s*{_UNIT})?""",
    re.VERBOSE,
)
# "Flat 2, " / "Apt 4B " immediately before a house number
_UNIT_PREFIX = re.compile(rf"{_UNIT}\s*,?\s+$")

_CONNECT = (
    r"(?:de|da|do|das|dos|del|della|delle|dei|degli|di|la|le|les|des|du|d'|l'|d’|l’|van|von|der|den"
    r"|het|y|e|el|los|las|São|Santa|Santo|San|Sant'|Saint|Sainte|St\.?|Ste\.?)"
)
_ROMANCE_NAME = (
    rf"(?:{_CONNECT}\s{{0,3}}){{0,3}}(?:{_CAP_PART}|\d{{1,2}}\s+de\s+{_CAP_PART})"
    rf"(?:[\s\-]{{1,3}}(?:{_CAP_PART}|{_CONNECT}(?=\s*[{_UPPER}]))){{0,5}}"
)
_PREFIX_TYPES = trie_pattern(
    (
        "Rua",
        "R.",
        "Avenida",
        "Av.",
        "Avda",
        "Avda.",
        "Calle",
        "C/",
        "Carrer",
        "Camino",
        "Paseo",
        "Plaza",
        "Pza.",
        "Ronda",
        "Travesía",
        "Travessa",
        "Largo",
        "Praça",
        "Pça",
        "Pça.",
        "Alameda",
        "Estrada",
        "Rodovia",
        "Via",
        "Viale",
        "V.le",
        "Piazza",
        "P.za",
        "Piazzale",
        "Corso",
        "Vicolo",
        "Rue",
        "Boulevard",
        "Bd",
        "Bd.",
        "Bld",
        "Bld.",
        "Bvd",
        "Bvd.",
        "Allée",
        "Chemin",
        "Impasse",
        "Quai",
        "Cours",
        "Laan",
        "ul.",
        "ulica",
        "al.",
        "aleja",
        "os.",
        "pl.",
        "plac",
    )
)
_ROMANCE_UNIT = r"(?:\s*,?\s*\d{1,2}\s*[º°ª]\s*(?:(?i:esq|dto|dta|izq|izda|dcha|dr)\b\.?|[A-Za-z]\b)?)?"

# "Rua Augusta, 100", "Calle de Alcalá, 45, 3º B", "Via Roma 10", "ul. Marszałkowska 10"
_PREFIXED = re.compile(
    rf"""(?<![\w])(?i:{_PREFIX_TYPES})\s+{_ROMANCE_NAME}\s*,?\s*
    (?:(?i:n[º°o]\.?|núm\.?|num\.?|nr\.?)\s*)?
    (?P<num>{_HOUSE_NUMBER})(?![\d]){_NOT_QUANTITY}{_ROMANCE_UNIT}""",
    re.VERBOSE,
)

# "12 rue de la Paix", "10, avenue des Champs-Élysées", "15 Boulevard Haussmann"
_NUMBER_FIRST = re.compile(
    rf"""(?<![\w/.,\-])(?P<num>\d{{1,4}})(?:\s*(?i:bis|ter|quater))?\s*,?\s+
    (?i:rue|avenue|av\.|boulevard|bd|bld|place|allée|chemin|impasse|quai|cours|rua|avenida|calle|via
      |viale|piazza|corso)\s+
    (?:{_CONNECT}\s{{0,3}}){{0,3}}{_CAP_PART}(?:[\s\-]{{1,3}}(?:{_CAP_PART}|{_CONNECT}(?=\s*[{_UPPER}]))){{0,4}}""",
    re.VERBOSE,
)

_DE_SUFFIX = trie_pattern(
    (
        "straße",
        "strasse",
        "str.",
        "weg",
        "platz",
        "gasse",
        "allee",
        "damm",
        "ufer",
        "chaussee",
        "pfad",
        "steig",
        "straat",
        "laan",
        "plein",
        "gracht",
        "kade",
        "singel",
        "steeg",
        "dijk",
    )
)
# "Hauptstraße 5", "Berliner Straße 10a", "Kerkstraat 12", "Prinsengracht 263-1"
_GERMANIC = re.compile(
    rf"""[{_UPPER}](?:[\w\-]{{0,{_WORD_MAX}}}?|[\w\-]{{0,{_WORD_MAX}}}[\s\-]{{1,3}})(?i:{_DE_SUFFIX})\s+
    (?P<num>\d{{1,4}}\s?[a-zA-Z]?(?:\s?[-–/]\s?\d{{1,4}}[a-zA-Z]?)?)(?![\w]){_NOT_QUANTITY}""",
    re.VERBOSE,
)

#: (pattern, characters that must not precede the match)
_STRUCTURED: tuple[tuple[re.Pattern[str], str], ...] = (
    (_ENGLISH, "/.,-"),
    (_PREFIXED, ""),
    (_NUMBER_FIRST, "/.,-"),
    (_GERMANIC, ""),
)

_RESIDENTIAL_PHRASES = (
    *(
        f"{verb} {prep}"
        for verb in ("lives", "living", "lived", "resides", "residing", "resided", "is staying", "domiciled")
        for prep in ("at", "on", "in")
    ),
    *(
        f"{kind} address{tail}"
        for kind in ("home", "residential", "private", "personal")
        for tail in ("", " is", " is at", " at")
    ),
    *(f"{p} address{tail}" for p in ("his", "her", "their", "my") for tail in ("", " is")),
    "address of residence",
    "vive en",
    "mora na",
    "mora no",
    "mora em",
    "habite",
    "habite au",
    "habite à",
    "habite a",
    "wohnt",
    "wohnt in",
    "wohnt in der",
    "wohnt in dem",
    "wohnt am",
    "wohnt im",
    "wohnt an der",
)
_RESIDENTIAL = re.compile(r"\b" + trie_pattern(_RESIDENTIAL_PHRASES) + r"\b\s*[:\-–]?\s*", re.IGNORECASE)
_LENIENT = re.compile(
    rf"""(?:{_HOUSE_NUMBER},?\s+[^\W\d_][\w'’.\-]{{0,{_WORD_MAX}}}
         (?:\s+(?!(?:in|near|with|and|since|for|from|until|on|at)\b)[^\s,.;:()\d][^\s,.;:()]{{0,{_WORD_MAX}}}){{0,3}}
       |(?:[^\W\d_][\w'’\-]{{0,{_WORD_MAX}}}\s+){{1,3}}(?i:{_EN_SUFFIX})\b\.?)""",
    re.VERBOSE,
)
_YEAR_WORDS = re.compile(r"\b(?:in|since|by|until|from|during|of|year|circa|c\.)\s*$", re.IGNORECASE)


def _boundary_ok(text: str, start: int, forbidden: str) -> bool:
    if start == 0:
        return True
    prev = text[start - 1]
    return not (prev.isalnum() or prev == "_" or prev in forbidden)


def _year_like(text: str, m: re.Match[str]) -> bool:
    num = m.group("num")
    if not (num.isdigit() and len(num) == 4 and 1800 <= int(num) <= 2099):
        return False
    return m.re is not _ENGLISH or _YEAR_WORDS.search(text[max(0, m.start() - 12) : m.start()]) is not None


def _with_unit_prefix(text: str, m: re.Match[str]) -> int:
    """Extend an English match backwards over a "Flat 2, " style unit prefix."""
    if m.re is not _ENGLISH:
        return m.start()
    prefix = _UNIT_PREFIX.search(text, max(0, m.start() - 24), m.start())
    return prefix.start() if prefix is not None and _boundary_ok(text, prefix.start(), "") else m.start()


def _structured(text: str, pos: int | None = None) -> Iterator[tuple[int, int]]:
    """All structured matches, or (with ``pos``) the longest one anchored at ``pos``."""
    if pos is not None:
        best: tuple[int, int] | None = None
        for pattern, _ in _STRUCTURED:
            m = pattern.match(text, pos)
            if m and (best is None or m.end() > best[1]):
                best = (m.start(), m.end())
        if best is not None:
            yield best
        return
    for pattern, forbidden in _STRUCTURED:
        for m in pattern.finditer(text):
            if _boundary_ok(text, m.start(), forbidden) and not _year_like(text, m):
                yield _with_unit_prefix(text, m), m.end()


def _residential(text: str) -> Iterator[tuple[int, int]]:
    for phrase in _RESIDENTIAL.finditer(text):
        pos = phrase.end()
        found = next(_structured(text, pos), None)
        if found is None and (lenient := _LENIENT.match(text, pos)) is not None:
            found = (lenient.start(), lenient.end())
        if found is not None:
            yield found


def _exempt(scan: Scan) -> bool:
    """Registered office addresses in registry/government records about organizations."""
    ctx = scan.context
    return (
        not scan.restricted
        and ctx.organization_context
        and ctx.source_kind in (SourceKind.REGISTRY, SourceKind.GOVERNMENT)
    )


def detect(scan: Scan) -> Iterator[Detection]:
    """Yield street-address detections (street part only)."""
    text = scan.text
    for start, end in _residential(text):
        yield detection(start, end, _KIND, P_ADDRESS)
    if _exempt(scan):
        return
    for start, end in _structured(text):
        if not scan.inside_url(start, end):
            yield detection(start, end, _KIND, P_ADDRESS)
