"""Dates of birth: only dates introduced by a birth keyword ("born on", "DOB:", "date of birth", …).

Ordinary dates ("Founded in 2016", "published on 12 March 2020") are never touched.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from angel_engine.guard.detectors.base import P_DOB, Detection, Scan, detection, trie_pattern
from angel_engine.guard.types import RedactionKind

_MONTHS = (
    r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?"
    r"|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?|enero|febrero|marzo|abril|mayo"
    r"|junio|julio|agosto|septiembre|setiembre|octubre|noviembre|diciembre|janeiro|fevereiro|março"
    r"|marco|maio|junho|julho|setembro|outubro|novembro|dezembro|janvier|février|fevrier|mars|avril"
    r"|mai|juin|juillet|août|aout|septembre|octobre|décembre|decembre|januar|jänner|februar|märz"
    r"|maerz|juni|juli|oktober|dezember|gennaio|febbraio|aprile|maggio|giugno|luglio|settembre"
    r"|ottobre|dicembre)\.?"
)
_DAY = r"(?:[12]\d|3[01]|0?[1-9])(?:st|nd|rd|th|º|°|er)?\.?"
_YEAR = r"(?:1[89]\d{2}|20\d{2})"
_DATE = rf"""(?:
    \d{{1,2}}[./\-]\d{{1,2}}[./\-](?:\d{{4}}|\d{{2}})
   |{_YEAR}[./\-]\d{{1,2}}[./\-]\d{{1,2}}
   |{_DAY}\s+(?:of\s+|de\s+)?{_MONTHS},?\s+(?:de\s+|del\s+)?{_YEAR}
   |{_MONTHS}\s+{_DAY},?\s+{_YEAR}
   |{_MONTHS}\s+(?:of\s+|de\s+)?{_YEAR}
   |{_DAY}\s+(?:of\s+|de\s+)?{_MONTHS}(?![a-z])
   |{_MONTHS}\s+{_DAY}(?!\d)
   |{_YEAR}
)"""
_KEYWORD = (
    r"\b"
    + trie_pattern(
        (
            "born",
            "date of birth",
            "birth date",
            "birthdate",
            "birthday",
            "d.o.b.",
            "d.o.b",
            "d. o. b.",
            "dob",
            "fecha de nacimiento",
            "f. nac.",
            "f.nac.",
            "nacido",
            "nacida",
            "data de nascimento",
            "nascido",
            "nascida",
            "date de naissance",
            "né le",
            "née le",
            "né en",
            "née en",
            "geboren",
            "geburtsdatum",
            "geb.",
            "data di nascita",
            "nato il",
            "nata il",
            "urodzony",
            "urodzona",
        )
    )
    + r"(?![^\W\d_])"
)
_PLACE = r"(?:(?:in|at)\s+[^\W\d_][\w'’\-]*(?:,?\s+[^\W\d_][\w'’\-]*){0,2}\s+(?:on|in)\s+(?:the\s+)?)"

_DOB = re.compile(
    rf"""{_KEYWORD}\s*(?:[:\-–]\s*)?(?:(?:on|in|el|em|le|am|a|il)\s+)?(?:the\s+)?{_PLACE}?
    (?P<date>{_DATE})(?![\w])""",
    re.IGNORECASE | re.VERBOSE,
)


def detect(scan: Scan) -> Iterator[Detection]:
    """Yield the date part of birth-date statements."""
    for m in _DOB.finditer(scan.text):
        yield detection(m.start("date"), m.end("date"), RedactionKind.DATE_OF_BIRTH, P_DOB)
