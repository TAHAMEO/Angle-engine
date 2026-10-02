"""Evasion-resistant text normalization for policy matching.

Pipeline: NFKC (folds fullwidth and mathematical alphanumerics), removal of invisible format
characters (zero-width, bidi controls, soft hyphen), removal of combining marks (accents),
homoglyph folding (Cyrillic/Greek/small-capital look-alikes → Latin), quote/dash normalization,
inner ``$``/``@`` folding ("pa$$word"), whitespace collapsing, tokenization, digit-as-letter
folding inside words ("h0me" → "home") and casefolding.

:class:`NormalizedText` keeps two aligned views: ``cased`` (case preserved, used to recognise
capitalised names and all-caps organisations) and ``text`` (casefolded, used for matching).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from angel_engine.policy.lexicons import words

# Look-alike code point (4 hex digits) followed by its Latin replacement, e.g. "0430a" maps U+0430 to "a".
# Written as code points so the look-alikes stay unambiguous in review.
_HOMOGLYPHS = """
    0430a 0410A 0435e 0415E 043Eo 041EO 0440p 0420P 0441c 0421C 0443y 0423Y 0445x 0425X 0456i 0406I 0457i 0407I
    0458j 0408J 0455s 0405S 04BBh 04BAH 0501d 0500D 051Bq 051AQ 051Dw 051CW 04CFl 04C0I 0412B 0432b 041AK 043Ak
    041CM 043Cm 041DH 043Dh 0422T 0442t 0475v 0474V 04AFy 04AEY
    03B1a 0391A 03B2b 0392B 03B5e 0395E 0396Z 03B7n 0397H 03B9i 0399I 03BAk 039AK 03BCu 039CM 03BDv 039DN 03BFo
    039FO 03C1p 03A1P 03C4t 03A4T 03C5u 03A5Y 03C7x 03A7X 03C9w 03F2c 03F3j
    0131i 0237j 0251a 0261g 0269i 026Ai 1D00a 0299b 1D04c 1D05d 1D07e A730f 0262g 029Ch 1D0Aj 1D0Bk 029Fl 1D0Dm
    0274n 1D0Fo 1D18p 0280r A731s 1D1Bt 1D1Cu 1D20v 1D21w 028Fy 1D22z 01C0l
    2018' 2019' 201B' 02BC' 00B4' 0060' 2032' 201C" 201D" 201E" 00AB" 00BB" 2033" 2010- 2011- 2012- 2013- 2014-
    2015- 2212-
"""
_TRANSLATE = {int(item[:4], 16): item[4:] for item in _HOMOGLYPHS.split()}

_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"}
#: Words whose digit-obfuscated spellings are folded even when the digit is at a word edge.
LEET_VOCABULARY = words(
    """
    home house address addresses live lives location locate track tracking trace stalk stalker stalking follow find
    phone number cell mobile email private profile account accounts password passwords credentials leak leaked leaks
    dump dumps breach dox doxx doxing doxxing unmask identify identity face faces facial recognition where
    whereabouts spy monitor watch harass threaten bypass paywall captcha login instagram facebook snapchat tiktok
    twitter her his him she neighbor neighbour girlfriend boyfriend wife husband birth gay lesbian religion
    ethnicity immigration ssn passport medical health schedule routine movements real name person behind expose hack
    crack fake impersonate posing pretend ex gps coordinates residence hometown family relatives
    """
)

_INNER_SYMBOLS = re.compile(r"(?<=[^\W_])[$@]+(?=[^\W_])")
_DOMAIN_AFTER = re.compile(r"[\w-]{1,63}\.[^\W\d_]{2,}")
_WHITESPACE = re.compile(r"\s+")
# Quantifiers are bounded by the RFC limits (64-character local parts, 63-character labels, ≤ 8 labels) so
# tokenization stays linear on long runs of letters, digits and hyphens.
_TOKEN = re.compile(
    r"""(?P<email>[\w.+\-]{1,64}@[\w\-]{1,63}(?:\.[\w\-]{1,63}){1,8})
       |(?P<url>https?://\S+)
       |(?P<handle>@[\w.]{0,64}\w)
       |(?P<domain>(?:[^\W_](?:[\w\-]{0,61}[^\W_])?\.){1,8}[a-z]{2,24}(?![\w]))
       |(?P<poss>'s(?![^\W_]))
       |(?P<word>[^\W_]+)
       |(?P<punct>[^\w\s])""",
    re.VERBOSE,
)


@dataclass(frozen=True, slots=True)
class Token:
    """A token of the normalized text; offsets refer to :attr:`NormalizedText.text`."""

    text: str  # casefolded, folded form
    cased: str  # case-preserving folded form
    start: int
    end: int
    kind: str  # word | handle | email | domain | url | poss | punct

    @property
    def is_word(self) -> bool:
        return self.kind == "word"


@dataclass(frozen=True, slots=True)
class NormalizedText:
    original_length: int
    cased: str  # canonical case-preserving string (used as the cache key)
    text: str  # casefolded string the annotator matches against
    tokens: tuple[Token, ...]


def _strip_invisible_and_marks(value: str) -> str:
    value = "".join(ch for ch in value if unicodedata.category(ch) != "Cf")
    decomposed = unicodedata.normalize("NFD", value)
    stripped = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return unicodedata.normalize("NFC", stripped)


def _fold_inner_symbols(value: str) -> str:
    def repl(m: re.Match[str]) -> str:
        sym = m.group()
        if "@" in sym and _DOMAIN_AFTER.match(value, m.end()):
            return sym  # an e-mail address, not "em@il"
        return "".join("a" if c == "@" else "s" for c in sym)

    return _INNER_SYMBOLS.sub(repl, value)


def fold_leet(word: str) -> str:
    """Fold digits used as letters: always inside words, at word edges only for known words."""
    if not any(c.isdigit() for c in word) or not any(c.isalpha() for c in word):
        return word
    for one in ("i", "l"):
        candidate = "".join(_LEET.get(c, c) if c != "1" else one for c in word)
        if candidate.casefold() in LEET_VOCABULARY:
            return candidate
    chars = list(word)
    for i, c in enumerate(word):
        if c in _LEET and 0 < i < len(word) - 1 and word[i - 1].isalpha() and word[i + 1].isalpha():
            chars[i] = _LEET[c]
    return "".join(chars)


def canonicalize(text: str) -> str:
    """Case-preserving canonical form (everything except tokenization, leet folding and casefolding)."""
    value = unicodedata.normalize("NFKC", text)
    value = _strip_invisible_and_marks(value)
    value = value.translate(_TRANSLATE)
    value = _fold_inner_symbols(value)
    return _WHITESPACE.sub(" ", value).strip()


def normalize(text: str) -> NormalizedText:
    """Normalize ``text`` and tokenize it."""
    cased = canonicalize(text)
    parts: list[str] = []
    tokens: list[Token] = []
    pos = 0
    prev_end = 0
    for m in _TOKEN.finditer(cased):
        kind = m.lastgroup or "punct"
        raw = m.group()
        if kind == "word":
            raw = fold_leet(raw)
        folded = raw.casefold()
        if m.start() > prev_end and parts:
            parts.append(" ")
            pos += 1
        tokens.append(Token(text=folded, cased=raw, start=pos, end=pos + len(folded), kind=kind))
        parts.append(folded)
        pos += len(folded)
        prev_end = m.end()
    return NormalizedText(original_length=len(text), cased=cased, text="".join(parts), tokens=tuple(tokens))
