"""Vehicle registration plates — only when a plate keyword precedes the token (within ~20 chars).

Generic words such as "registration" or "reg." only count near a vehicle word, so company,
trademark or domain registration numbers are kept.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from angel_engine.guard.detectors.base import P_PLATE, Detection, Scan, detection, trie_pattern
from angel_engine.guard.types import RedactionKind

_SUFFIX = r"(?:\s*(?:number|no\b\.?|nr\b\.?|#))?"
_STRONG = re.compile(
    r"\b"
    + trie_pattern(
        (
            "license plate",
            "licence plate",
            "license-plate",
            "licence-plate",
            "licenseplate",
            "number plate",
            "number-plate",
            "numberplate",
            "registration plate",
            "plate",
            "matrícula",
            "matricula",
            "kennzeichen",
            "nummernschild",
            "immatriculation",
            "plaque",
            "targa",
            "placa",
            "kenteken",
            "tablica rejestracyjna",
        )
    )
    + _SUFFIX,
    re.IGNORECASE,
)
_WEAK = re.compile(
    r"\b" + trie_pattern(("registration", "reg.", "reg", "rego")) + r"\b\.?(?:\s*(?:number|no\b\.?|mark|#))?",
    re.IGNORECASE,
)
_VEHICLE = re.compile(
    r"\b(?:car|cars|vehicle|van|truck|lorry|motorbike|motorcycle|scooter|taxi|bus|suv|sedan|auto"
    r"|automobile|coche|carro|voiture|fahrzeug|wagen|ve[ií]culo|véhicule)\b",
    re.IGNORECASE,
)
_NON_VEHICLE = re.compile(
    r"\b(?:company|business|trade|vat|tax|charity|domain|trademark|land|voter|patent|event|course"
    r"|conference|student|user|account)\s*$",
    re.IGNORECASE,
)
_PLATE_TOKEN = re.compile(r"(?<![A-Za-z0-9])[A-Z0-9]{1,8}(?:[ \-·][A-Z0-9]{1,4}){0,3}(?![A-Za-z0-9])")
_WINDOW = 20


def _plate_like(token: str) -> bool:
    alnum = [c for c in token if c.isalnum()]
    if not 4 <= len(alnum) <= 10:
        return False
    has_digit = any(c.isdigit() for c in alnum)
    has_alpha = any(c.isalpha() for c in alnum)
    if has_digit and has_alpha:
        return True
    return has_digit and len(alnum) >= 5 and any(not c.isalnum() for c in token)


def _after_keyword(text: str, pos: int) -> Iterator[Detection]:
    for m in _PLATE_TOKEN.finditer(text, pos):
        if m.start() - pos > _WINDOW:
            break
        if _plate_like(m.group()):
            yield detection(m.start(), m.end(), RedactionKind.VEHICLE_PLATE, P_PLATE)
            return


def detect(scan: Scan) -> Iterator[Detection]:
    """Yield the first plate-like token after each plate keyword."""
    text = scan.text
    for m in _STRONG.finditer(text):
        yield from _after_keyword(text, m.end())
    for m in _WEAK.finditer(text):
        before = text[max(0, m.start() - 40) : m.start()]
        if _NON_VEHICLE.search(before):
            continue
        around = text[max(0, m.start() - 40) : m.end() + 40]
        if _VEHICLE.search(around):
            yield from _after_keyword(text, m.end())
