"""E-mail addresses: role mailboxes kept (standard mode), corporate local parts masked, free-mail removed."""

from __future__ import annotations

import re
from collections.abc import Iterator

from angel_engine.guard.detectors.base import P_EMAIL, Detection, Scan, detection, words
from angel_engine.guard.types import RedactionKind

_KIND = RedactionKind.EMAIL
PARTIAL_REPLACEMENT = "[redacted]"

_EMAIL = re.compile(
    r"(?<![\w.%+'-])(?P<local>[\w%+'-]+(?:\.[\w%+'-]+)*)@"
    r"(?P<domain>(?:[^\W_](?:[\w-]{0,61}[^\W_])?\.)+[^\W\d_]{2,24})(?![\w-]|\.[^\W\d_])"
)
_OBFUSCATED = re.compile(
    r"(?<![\w.])(?P<local>[\w.+-]{1,64})\s*[\[({]\s*at\s*[\])}]\s*"
    r"(?P<domain>[\w-]+(?:\s*[\[({]\s*dot\s*[\])}]\s*[\w-]+)+)",
    re.IGNORECASE,
)
_OBFUSCATED_HINT = re.compile(r"[\[({]\s*at\s*[\])}]", re.IGNORECASE)
_OBFUSCATED_DOT = re.compile(r"\s*[\[({]\s*dot\s*[\])}]\s*", re.IGNORECASE)

ROLE_LOCAL_PARTS = words(
    """
    info contact contacts press media support sales hello admin webmaster abuse security privacy legal careers jobs
    office enquiries inquiries enquiry inquiry help team marketing pr newsroom ir investors investor noreply
    no-reply donotreply do-not-reply postmaster hostmaster billing service services customerservice customercare
    customersupport helpdesk servicedesk hr recruiting recruitment feedback compliance dpo gdpr dataprotection
    accounts accounting finance orders reservations bookings booking events editor editors news newsdesk tips
    communications comms partners partnerships general reception secretariat membership complaints ethics
    whistleblowing procurement purchasing returns community admissions registrar contacto contato geral imprensa
    prensa presse kontakt datenschutz rh ventas vendas ventes
    """
)
_ROLE_MODIFIERS = words(
    """
    office relations desk team customer care public affairs corporate group global main central general department
    dept intl international europe emea apac americas us uk eu de fr es pt it nl br local regional national hq head
    """
)
_ROLE_SPLIT = re.compile(r"[._-]+")

_FREE_MAIL_EXACT = words(
    """
    gmail.com googlemail.com outlook.com icloud.com me.com mac.com aol.com proton.me pm.me mail.ru inbox.ru list.ru
    bk.ru qq.com 163.com 126.com sina.com web.de t-online.de freenet.de zoho.com zohomail.com tuta.io tuta.com
    tutamail.com keemail.me ymail.com rocketmail.com fastmail.com fastmail.fm hushmail.com mailfence.com posteo.de
    libero.it virgilio.it orange.fr laposte.net free.fr wanadoo.fr sapo.pt terra.com.br uol.com.br bol.com.br
    rediffmail.com seznam.cz wp.pl o2.pl interia.pl onet.pl naver.com daum.net hanmail.net rambler.ru ukr.net
    mail.com email.com inbox.com msn.com comcast.net verizon.net att.net sbcglobal.net btinternet.com sky.com
    duck.com skiff.com
    """
)
_FREE_MAIL_WILDCARD = words(
    """
    hotmail live yahoo protonmail gmx yandex tutanota outlook aol
    """
)


def is_free_mail(domain: str) -> bool:
    """True for consumer mailbox providers (gmail.com, hotmail.*, yahoo.co.uk, gmx.de, …)."""
    labels = domain.lower().rstrip(".").split(".")
    for i in range(len(labels) - 1):
        tail = labels[i:]
        if ".".join(tail) in _FREE_MAIL_EXACT:
            return True
        if tail[0] in _FREE_MAIL_WILDCARD and len(tail) in (2, 3) and all(len(x) <= 3 for x in tail[1:]):
            return True
    return False


def is_role_mailbox(local: str) -> bool:
    """True for organizational role addresses (info@, press.office@, media-relations@, …)."""
    local = local.lower().split("+", 1)[0]
    if local in ROLE_LOCAL_PARTS:
        return True
    tokens = [t.rstrip("0123456789") for t in _ROLE_SPLIT.split(local) if t]
    if not tokens or any(not t for t in tokens):
        return False
    vocabulary = ROLE_LOCAL_PARTS | _ROLE_MODIFIERS
    return all(t in vocabulary for t in tokens) and any(
        t in ROLE_LOCAL_PARTS or t in {"customer", "public"} for t in tokens
    )


def _decide(scan: Scan, start: int, local_end: int, end: int, local: str, domain: str) -> Iterator[Detection]:
    if scan.restricted or is_free_mail(domain):
        yield detection(start, end, _KIND, P_EMAIL)
    elif not is_role_mailbox(local):
        yield detection(start, local_end, _KIND, P_EMAIL, PARTIAL_REPLACEMENT)


def detect(scan: Scan) -> Iterator[Detection]:
    """Yield e-mail detections (full or local-part-only) according to mode and mailbox type."""
    for m in _EMAIL.finditer(scan.text):
        yield from _decide(scan, m.start(), m.end("local"), m.end(), m.group("local"), m.group("domain"))
    if _OBFUSCATED_HINT.search(scan.text) is None:
        return
    for m in _OBFUSCATED.finditer(scan.text):
        domain = _OBFUSCATED_DOT.sub(".", m.group("domain"))
        yield from _decide(scan, m.start(), m.end("local"), m.end(), m.group("local"), domain)
