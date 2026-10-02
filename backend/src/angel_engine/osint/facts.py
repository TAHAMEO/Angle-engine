"""Structured facts for deterministic corroboration and contradiction checks.

Facts are ``(entity, attribute, value, precision)`` tuples taken from structured records (registries,
Wikidata) or, for a few narrowly defined attributes, extracted from text with explicit patterns. Two
facts contradict each other only when they share the entity *and* the attribute and their date
intervals cannot overlap at the stated precision. Attributes with different definitions (e.g. Wikidata
"inception" vs the GLEIF legal-entity creation date) are never compared with each other — the registry
records that explicitly so reviewers understand why no contradiction is raised.
"""

from __future__ import annotations

import calendar
import re
from dataclasses import dataclass
from datetime import date

#: attribute → (label, definition)
ATTRIBUTES: dict[str, tuple[str, str]] = {
    "org.inception": ("Founded", "When the organization was founded or began operating (as reported)."),
    "org.legal_creation_date": ("Legal entity created", "Creation date of the legal entity in an official registry."),
    "org.lei_registration_date": ("LEI first issued", "Date the Legal Entity Identifier was first registered."),
    "domain.registration_date": ("Domain registered", "Registration date in the domain registry (RDAP)."),
}
#: Pairs that look alike but measure different things (never compared).
DIFFERENT_DEFINITIONS = {
    frozenset({"org.inception", "org.legal_creation_date"}),
    frozenset({"org.inception", "org.lei_registration_date"}),
    frozenset({"org.legal_creation_date", "org.lei_registration_date"}),
}
_FOUNDING = re.compile(
    r"\b(?:founded|established|set up|started|launched|incorporated|est\.?)\s+(?:in\s+|on\s+)?"
    r"(?:(?:early|mid|late)\s+)?(?P<year>1[89]\d{2}|20\d{2})\b",
    re.IGNORECASE,
)
_SENTENCE = re.compile(r"[^.!?\n]{1,600}[.!?\n]?")


@dataclass(frozen=True, slots=True)
class Interval:
    start: date
    end: date


def interval(value: str, precision: str | None) -> Interval | None:
    """The span of days a date value covers at its precision (``year`` → the whole year …)."""
    try:
        year = int(value[:4])
        month = int(value[5:7]) if len(value) >= 7 and value[5:7].isdigit() else 1
        day = int(value[8:10]) if len(value) >= 10 and value[8:10].isdigit() else 1
        if precision == "year":
            return Interval(date(year, 1, 1), date(year, 12, 31))
        if precision == "month":
            return Interval(date(year, month, 1), date(year, month, calendar.monthrange(year, month)[1]))
        exact = date(year, month, day)
        return Interval(exact, exact)
    except (ValueError, IndexError):
        return None


def overlaps(a: Interval, b: Interval) -> bool:
    return a.start <= b.end and b.start <= a.end


def comparable(attr_a: str, attr_b: str) -> bool:
    return attr_a == attr_b and attr_a in ATTRIBUTES


def founding_years(text: str, organizations: dict[str, str]) -> list[tuple[str, str]]:
    """``(organization key, year)`` for sentences that state when a known organization was founded.

    ``organizations`` maps a lower-cased organization name (or alias) to its key. The organization must be
    named in the same sentence as the founding phrase, so unrelated years are not attributed to it.
    """
    found: list[tuple[str, str]] = []
    if not organizations:
        return found
    for sentence in _SENTENCE.findall(text[:200_000]):
        match = _FOUNDING.search(sentence)
        if match is None:
            continue
        lowered = sentence.casefold()
        for name, key in organizations.items():
            if name and name in lowered:
                found.append((key, match.group("year")))
                break
    return list(dict.fromkeys(found))
