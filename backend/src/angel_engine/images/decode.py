"""Canonical decode: the only place the original bytes are decoded.

Pillow opens the file with an explicit format allowlist and a pixel limit (decompression-bomb warnings
are errors), takes frame 0, applies the EXIF orientation and converts to RGB. Every later stage works on
these canonical pixels; nothing else reads the original bytes.
"""

from __future__ import annotations

import hashlib
import io
import warnings
from dataclasses import dataclass

import numpy as np
from PIL import Image, ImageOps

from angel_engine.images.errors import ImageRejected
from angel_engine.images.types import PipelineConfig

ALLOWED_FORMATS = ("JPEG", "PNG", "GIF", "WEBP", "TIFF", "BMP")


@dataclass(frozen=True)
class Canonical:
    image: Image.Image  # RGB, orientation applied
    array: np.ndarray  # H×W×3 uint8 (RGB)
    pixel_sha256: str
    source: Image.Image  # the opened (not converted) image, for metadata access

    @property
    def width(self) -> int:
        return self.image.width

    @property
    def height(self) -> int:
        return self.image.height


def open_image(data: bytes, config: PipelineConfig) -> Image.Image:
    Image.MAX_IMAGE_PIXELS = config.max_pixels
    formats = (*ALLOWED_FORMATS, "HEIF") if config.allow_heif else ALLOWED_FORMATS
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            image = Image.open(io.BytesIO(data), formats=formats)
            image.load()
        except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
            raise ImageRejected("dimensions_exceeded", "The image dimensions exceed the allowed maximum.") from exc
        except (OSError, SyntaxError, ValueError) as exc:
            raise ImageRejected("corrupt", "The image could not be decoded.") from exc
    if max(image.size) > config.max_side:
        raise ImageRejected("dimensions_exceeded", "The image dimensions exceed the allowed maximum.")
    return image


def canonicalize(data: bytes, config: PipelineConfig) -> Canonical:
    source = open_image(data, config)
    if getattr(source, "n_frames", 1) > 1:
        source.seek(0)
    try:
        oriented = ImageOps.exif_transpose(source)
    except (OSError, ValueError):
        oriented = source.copy()
    rgb = (oriented or source).convert("RGB")
    array = np.asarray(rgb, dtype=np.uint8)
    pixel_sha = hashlib.sha256(array.tobytes() + f"|{rgb.width}x{rgb.height}".encode()).hexdigest()
    return Canonical(image=rgb, array=array, pixel_sha256=pixel_sha, source=source)
