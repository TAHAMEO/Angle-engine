"""Phone numbers, found conservatively with ``phonenumbers.PhoneNumberMatcher``.

A cheap regex first finds digit-dense regions; only plausible regions are handed to the matcher
(``Leniency.VALID``), region by region, with results cached per region text. Years, prices, dates,
IP addresses, ISBNs, postal codes, card-like digit groups and keyword-labelled reference numbers
(order, invoice, ISBN, case, …) are rejected. Without a phone keyword nearby, a number must carry an
international prefix or parentheses, or use a common national layout (NANP or trunk-prefixed).
"""

from __future__ import annotations

import functools
import re
from collections.abc import Iterator

import phonenumbers
from phonenumbers import Leniency, PhoneNumberMatcher, PhoneNumberType

from angel_engine.guard.detectors.base import P_PHONE, Detection, Scan, detection, window_before
from angel_engine.guard.types import RedactionKind

#: Regions tried, in order, for numbers written without an international prefix.
DEFAULT_REGIONS: tuple[str, ...] = ("US", "GB", "DE", "FR", "ES", "IT", "PT", "BR", "NL", "IN", "AU")
_MIN_DIGITS = 8
_MAX_MATCHER_CALLS = 400

_CANDIDATE = re.compile(r"(?<![\w+#$€£¥%@.,\-])(?:\+|\b00)?[(\d][\d()\-. /\u00a0\u2009]{6,30}\d(?![\w%°]|[.,]\d)")
_POSITIVE = re.compile(
    r"\b(?:tel|tél|telf|tlf|phone|telephone|téléphone|call|calls|ring|mobile|mob|cell|cellphone|fax"
    r"|whatsapp|sms|text|contact|hotline|helpline|switchboard|teléfono|telefono|telefone|telemóvel"
    r"|telemovel|celular|móvil|movil|portable|telefon|handy|mobil|numer|nummer|número|numero)\b|☎|📞",
    re.IGNORECASE,
)
_NEGATIVE = re.compile(
    r"\b(?:order|invoice|isbn|issn|ref|reference|tracking|case|docket|acct|account\s+(?:no|number)"
    r"|sku|serial|model|part|item|product|ticket|receipt|transaction|txn|po|id|iban|swift|bic|vat"
    r"|tax|ein|lei|crn|patent|doi|pmid|arxiv|version|build|batch|lot|imei|policy|claim|customer\s+no"
    r"|registration|reg|company\s+(?:no|number)|license|licence|passport|ssn)\b|#",
    re.IGNORECASE,
)
_CURRENCY_AFTER = re.compile(r"^\s?(?:€|\$|£|¥|eur|euros?|usd|dollars?|gbp|chf|brl|reais|kr|zł|pln)\b", re.IGNORECASE)
_CURRENCY_BEFORE = re.compile(r"(?:€|\$|£|¥|eur|usd|gbp|chf|brl|r\$)\s?$", re.IGNORECASE)
_DATE_LIKE = re.compile(r"^(?:\d{1,2}[./\-]\d{1,2}[./\-]\d{2,4}|\d{4}[./\-]\d{1,2}[./\-]\d{1,2})$")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_YEARS = re.compile(r"^(?:(?:1[89]|20)\d{2}(?:\s*[-–/]\s*|\s+|$))+$")
_POSTAL = re.compile(r"^(?:\d{5}-\d{4}|\d{5}-\d{3})$")
_DECIMAL = re.compile(r"^\d+[.,]\d+$")
_NANP = re.compile(r"^(?:1[.\-])?\d{3}([.\-])\d{3}\1\d{4}$")
_TRUNK = re.compile(r"^0\d{1,4}(?:[\s.\-/]\d{2,8}){1,4}$")
_INTL_00 = re.compile(r"^00[1-9]")
_SEPARATOR = re.compile(r"[\s\-./()\u00a0\u2009]+")


@functools.lru_cache(maxsize=4096)
def _matches(region_text: str) -> tuple[tuple[int, int, bool], ...]:
    """Return ``(start, end, toll_free)`` matches of valid numbers inside ``region_text``."""
    international = region_text.startswith(("+", "00"))
    regions: tuple[str | None, ...] = (None,) if region_text.startswith("+") else DEFAULT_REGIONS
    for region in regions:
        found: list[tuple[int, int, bool]] = []
        for match in PhoneNumberMatcher(region_text, region, leniency=Leniency.VALID):
            toll_free = phonenumbers.number_type(match.number) == PhoneNumberType.TOLL_FREE
            found.append((match.start, match.end, toll_free))
        if found:
            return tuple(found)
        if international and region is None:
            break
    return ()


def _card_like(raw: str) -> bool:
    groups = [g for g in _SEPARATOR.split(raw) if g]
    digits = sum(len(g) for g in groups)
    return digits > 15 and all(len(g) == 4 for g in groups[:-1]) and len(groups) > 1


def _phone_shaped(raw: str) -> bool:
    """Without a label, only common layouts count: NANP 415-555-0132 / 415.555.0132 or 0-prefixed."""
    return bool(_NANP.match(raw) or _TRUNK.match(raw))


def _rejected(text: str, start: int, end: int, raw: str) -> bool:
    if _DATE_LIKE.match(raw) or _IPV4.match(raw) or _YEARS.match(raw) or _POSTAL.match(raw):
        return True
    if _DECIMAL.match(raw) or _card_like(raw):
        return True
    digits = re.sub(r"\D", "", raw)
    if len(digits) < _MIN_DIGITS or (len(digits) == 13 and digits.startswith(("978", "979"))):
        return True
    return bool(_CURRENCY_AFTER.match(text[end : end + 8]) or _CURRENCY_BEFORE.search(text[max(0, start - 4) : start]))


def _strong_format(raw: str) -> bool:
    """International prefix (+CC / 00CC) or a parenthesized area code."""
    return raw.startswith("+") or bool(_INTL_00.match(raw)) or "(" in raw


def detect(scan: Scan) -> Iterator[Detection]:
    """Yield phone detections; toll-free numbers survive only for organizations in standard mode."""
    text = scan.text
    keep_toll_free = scan.context.organization_context and not scan.restricted
    calls = 0
    for m in _CANDIDATE.finditer(text):
        raw = m.group()
        start, end = m.span()
        if scan.inside_url(start, end) or _rejected(text, start, end, raw):
            continue
        before = window_before(text, start, 25, same_line=True)
        labelled = _POSITIVE.search(before) is not None
        if not labelled and not _strong_format(raw) and (_NEGATIVE.search(before) or not _phone_shaped(raw)):
            continue
        if calls >= _MAX_MATCHER_CALLS:
            break
        calls += 1
        for s, e, toll_free in _matches(raw):
            sub = raw[s:e]
            if sum(c.isdigit() for c in sub) < _MIN_DIGITS or _DATE_LIKE.match(sub) or _YEARS.match(sub):
                continue
            if not labelled and not (_strong_format(sub) or _phone_shaped(sub)):
                continue  # a fragment of a longer digit run must stand on its own
            if toll_free and keep_toll_free:
                continue
            yield detection(start + s, start + e, RedactionKind.PHONE, P_PHONE)
