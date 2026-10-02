"""Bank accounts: IBANs validated by per-country length and the ISO 13616 mod-97 checksum."""

from __future__ import annotations

import re
from collections.abc import Iterator

from angel_engine.guard.detectors.base import P_IBAN, Detection, Scan, detection
from angel_engine.guard.types import RedactionKind

#: ISO 13616 IBAN lengths (SEPA countries plus common non-SEPA registries), as country code + length.
_IBAN_TABLE = """
    AD24 AE23 AL28 AT20 AZ28 BA20 BE16 BG22 BH22 BR29 BY28 CH21 CR22 CY28 CZ24 DE22 DK18 DO28 EE20 EG29 ES24 FI18
    FO18 FR27 GB22 GE22 GI23 GL18 GR27 GT28 HR21 HU28 IE22 IL23 IQ23 IS26 IT27 JO30 KW30 KZ20 LB28 LC32 LI21 LT20
    LU20 LV21 LY25 MC27 MD24 ME22 MK19 MR27 MT31 MU30 NL18 NO15 PK24 PL28 PS29 PT25 QA29 RO24 RS22 SA24 SC31 SE24
    SI19 SK24 SM27 ST25 SV28 TL23 TN24 TR26 UA29 VA22 VG24 XK20
"""
IBAN_LENGTHS: dict[str, int] = {entry[:2]: int(entry[2:]) for entry in _IBAN_TABLE.split()}

_CANDIDATE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{2}[0-9]{2}(?:[ \-]?[A-Za-z0-9]){11,34}")


def iban_valid(compact: str) -> bool:
    """Validate an IBAN without separators (country length table + mod-97 == 1)."""
    compact = compact.upper()
    if IBAN_LENGTHS.get(compact[:2]) != len(compact) or not compact.isalnum():
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        number = int("".join(str(int(ch, 36)) for ch in rearranged))
    except ValueError:
        return False
    return number % 97 == 1


def detect(scan: Scan) -> Iterator[Detection]:
    """Yield IBAN detections; the candidate is truncated to the country's IBAN length."""
    text = scan.text
    for m in _CANDIDATE.finditer(text):
        expected = IBAN_LENGTHS.get(m.group()[:2].upper())
        if expected is None:
            continue
        count = 0
        end = m.start()
        for idx in range(m.start(), m.end()):
            if text[idx].isalnum():
                count += 1
                if count == expected:
                    end = idx + 1
                    break
        if count < expected or (end < len(text) and text[end].isalnum()):
            continue
        compact = re.sub(r"[ \-]", "", text[m.start() : end])
        if iban_valid(compact):
            yield detection(m.start(), end, RedactionKind.BANK_ACCOUNT, P_IBAN)
