"""Blind (keyed) search index for encrypted text.

Plaintext terms are normalized (NFKC, case-folded, stemmed) and turned into 64-bit keyed tokens with a
subkey derived from the investigation's DEK. The database stores only the tokens (GIN-indexed
``bigint[]``), so keyword search works on encrypted content and the tokens become meaningless once the
DEK is destroyed. Trade-off: exact (stemmed) term AND-search only — no prefix or fuzzy matching.
"""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache

import snowballstemmer

from angel_engine.crypto.envelope import FieldCipher

SEARCH_PURPOSE = "ae/search/v1"
_WORD = re.compile(r"[^\W_]+", re.UNICODE)
_STOP = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "has",
        "have",
        "in",
        "is",
        "it",
        "its",
        "of",
        "on",
        "or",
        "that",
        "the",
        "this",
        "to",
        "was",
        "were",
        "will",
        "with",
        "de",
        "la",
        "le",
        "les",
        "el",
        "los",
        "las",
        "da",
        "do",
        "das",
        "dos",
        "des",
        "du",
        "et",
        "y",
        "e",
        "o",
        "en",
        "und",
        "der",
        "die",
        "das",
    ]
)
_STEMMER = snowballstemmer.stemmer("english")
MAX_TERMS = 2048


@lru_cache(maxsize=65536)
def _stem(word: str) -> str:
    return str(_STEMMER.stemWord(word))


def terms(text: str) -> list[str]:
    """Normalized, de-duplicated search terms in first-seen order."""
    folded = unicodedata.normalize("NFKC", text).casefold()
    seen: dict[str, None] = {}
    for match in _WORD.finditer(folded):
        word = match.group(0)
        if len(word) < 2 or word in _STOP or len(word) > 64:
            continue
        seen.setdefault(_stem(word), None)
        if len(seen) >= MAX_TERMS:
            break
    return list(seen)


def token(cipher: FieldCipher, term: str) -> int:
    return int.from_bytes(cipher.mac(SEARCH_PURPOSE, term)[:8], "big", signed=True)


def tokens(cipher: FieldCipher, *texts: str | None) -> list[int]:
    out: dict[int, None] = {}
    for text in texts:
        if text:
            for term in terms(text):
                out.setdefault(token(cipher, term), None)
    return list(out)


def query_tokens(cipher: FieldCipher, query: str) -> list[int]:
    """Tokens that must all be present for a document to match ``query``."""
    return [token(cipher, t) for t in terms(query)]
