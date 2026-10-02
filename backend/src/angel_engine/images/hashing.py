"""Perceptual hashes for duplicate and near-duplicate detection.

Identical = same file SHA-256 or same canonical-pixel SHA-256; near-duplicate = pHash ≤ 6 and dHash ≤ 8
bits apart; similar = pHash ≤ 12 or a crop-resistant match (an informative segment — not a near-uniform
one such as a plain background, whose hash is all zeros — within 10 bits of a segment of the other image).
"""

from __future__ import annotations

import hashlib

import imagehash
from PIL import Image

from angel_engine.images.decode import Canonical
from angel_engine.images.types import HashResult

ID, VERSION = "hashing", "1"
NEAR_PHASH, NEAR_DHASH, SIMILAR_PHASH = 6, 8, 12
SEGMENT_BITS, SEGMENT_MATCHES = 10, 1


def _signed(h: imagehash.ImageHash) -> int:
    value = int(str(h), 16)
    return value - (1 << 64) if value >= 1 << 63 else value


def compute(canonical: Canonical, original: bytes) -> HashResult:
    image: Image.Image = canonical.image
    return HashResult(
        phash=_signed(imagehash.phash(image)),
        dhash=_signed(imagehash.dhash(image)),
        ahash=_signed(imagehash.average_hash(image)),
        whash=_signed(imagehash.whash(image)),
        colorhash=str(imagehash.colorhash(image)),
        crop_resistant=str(imagehash.crop_resistant_hash(image, min_segment_size=500, segmentation_image_size=300)),
        file_sha256=hashlib.sha256(original).hexdigest(),
        pixel_sha256=canonical.pixel_sha256,
    )


def bits(a: int, b: int) -> int:
    return ((a ^ b) & ((1 << 64) - 1)).bit_count()


def relation(a: HashResult, b: HashResult) -> str | None:
    """ "identical" | "near_duplicate" | "similar" | None."""
    if a.file_sha256 == b.file_sha256 or a.pixel_sha256 == b.pixel_sha256:
        return "identical"
    return perceptual_relation(a.phash, a.dhash, a.crop_resistant, b.phash, b.dhash, b.crop_resistant)


def perceptual_relation(phash_a: int, dhash_a: int, crop_a: str, phash_b: int, dhash_b: int, crop_b: str) -> str | None:
    """Near-duplicate / similar from perceptual hashes alone (stored rows keep no raw content hashes)."""
    p, d = bits(phash_a, phash_b), bits(dhash_a, dhash_b)
    if p <= NEAR_PHASH and d <= NEAR_DHASH:
        return "near_duplicate"
    if p <= SIMILAR_PHASH:
        return "similar"
    try:
        return "similar" if _crop_match(crop_a, crop_b) else None
    except (ValueError, TypeError):
        return None


def _informative(segment: imagehash.ImageHash) -> list[imagehash.ImageHash]:
    return [segment] if 8 <= int(str(segment), 16).bit_count() <= 56 else []


def _crop_match(a: str, b: str) -> bool:
    left = [s for h in imagehash.hex_to_multihash(a).segment_hashes for s in _informative(h)]
    right = [s for h in imagehash.hex_to_multihash(b).segment_hashes for s in _informative(h)]
    matches = sum(1 for s in left if any(s - t <= SEGMENT_BITS for t in right))
    return matches >= SEGMENT_MATCHES
