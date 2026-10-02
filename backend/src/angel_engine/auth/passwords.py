"""Password hashing (Argon2id) and the password policy (NIST SP 800-63B-4 style)."""

from __future__ import annotations

import asyncio
import gzip
import unicodedata
from functools import lru_cache
from importlib import resources

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_LENGTH = 12
MAX_LENGTH = 128
_hasher = PasswordHasher()  # argon2-cffi defaults: RFC 9106 low-memory profile (Argon2id)
_semaphore = asyncio.Semaphore(4)  # bounds memory use under concurrent logins
#: A valid hash used to equalize timing when the account does not exist.
_DUMMY_HASH = _hasher.hash("angel-engine-timing-equalizer-password")


def normalize(password: str) -> str:
    return unicodedata.normalize("NFKC", password)


@lru_cache(maxsize=1)
def _common_passwords() -> frozenset[str]:
    data = resources.files("angel_engine.data").joinpath("common-passwords.txt.gz").read_bytes()
    return frozenset(gzip.decompress(data).decode("utf-8").splitlines())


def policy_violations(password: str, *, context_words: tuple[str, ...] = ()) -> list[str]:
    """Return human-readable problems; an empty list means the password is acceptable."""
    pw = normalize(password)
    problems: list[str] = []
    if len(pw) < MIN_LENGTH:
        problems.append(f"Use at least {MIN_LENGTH} characters.")
    if len(pw) > MAX_LENGTH:
        problems.append(f"Use at most {MAX_LENGTH} characters.")
    folded = pw.casefold()
    if folded in _common_passwords():
        problems.append("This password is too common. Choose something less predictable.")
    for word in context_words:
        w = word.casefold().strip()
        if len(w) >= 4 and w in folded:
            problems.append("Do not include your name, email address or the product name.")
            break
    if len(set(folded)) < 4:
        problems.append("Use more varied characters.")
    return problems


async def hash_password(password: str) -> str:
    async with _semaphore:
        return await asyncio.to_thread(_hasher.hash, normalize(password))


async def verify_password(stored_hash: str | None, password: str) -> tuple[bool, str | None]:
    """Verify and return ``(ok, new_hash_if_rehash_needed)``. Runs a dummy verify when no hash exists."""
    async with _semaphore:
        target = stored_hash or _DUMMY_HASH
        try:
            await asyncio.to_thread(_hasher.verify, target, normalize(password))
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False, None
        if stored_hash is None:
            return False, None
        if _hasher.check_needs_rehash(stored_hash):
            return True, await asyncio.to_thread(_hasher.hash, normalize(password))
        return True, None
