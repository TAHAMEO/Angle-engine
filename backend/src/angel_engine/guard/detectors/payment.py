"""Payment cards: 13–19 digits, Luhn-valid, with a plausible issuer prefix (IIN) and length."""

from __future__ import annotations

import re
from collections.abc import Iterator

from angel_engine.guard.detectors.base import P_CARD, Detection, Scan, detection, luhn_valid
from angel_engine.guard.types import RedactionKind

_CANDIDATE = re.compile(r"(?<![\d.,+\-/])(?:\d[ \-]?){12,18}\d(?![\d]|[.,]\d|-\d)")


def plausible_card(digits: str) -> bool:
    """Issuer-prefix and length plausibility (Visa, Mastercard, Amex, Discover, JCB, Diners, …)."""
    n = len(digits)
    if not 13 <= n <= 19:
        return False
    p2, p3, p4, p6 = int(digits[:2]), int(digits[:3]), int(digits[:4]), int(digits[:6])
    if digits[0] == "4":
        return n in (13, 16, 19)  # Visa
    if 51 <= p2 <= 55 or 2221 <= p4 <= 2720:
        return n == 16  # Mastercard
    if p2 in (34, 37):
        return n == 15  # American Express
    if p4 == 6011 or p2 == 65 or 644 <= p3 <= 649 or 622126 <= p6 <= 622925:
        return n >= 16  # Discover
    if 3528 <= p4 <= 3589:
        return n >= 16  # JCB
    if 300 <= p3 <= 305 or p2 in (36, 38):
        return n >= 14  # Diners Club
    if p2 == 62:
        return n >= 16  # UnionPay
    return p2 == 50 or 56 <= p2 <= 69  # Maestro


def detect(scan: Scan) -> Iterator[Detection]:
    """Yield card-number detections; non-Luhn numbers (order numbers, …) are kept."""
    for m in _CANDIDATE.finditer(scan.text):
        raw = m.group()
        seps = {c for c in raw if c in " -"}
        if len(seps) > 1:
            continue  # mixed separators are not how card numbers are written
        if seps and min(len(g) for g in re.split(r"[ \-]", raw)) < 2:
            continue  # lists of single digits
        digits = re.sub(r"\D", "", raw)
        if luhn_valid(digits) and plausible_card(digits):
            yield detection(m.start(), m.end(), RedactionKind.PAYMENT_CARD, P_CARD)
