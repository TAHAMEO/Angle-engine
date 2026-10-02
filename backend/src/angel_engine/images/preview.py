"""Sanitized preview: the only derivative ever shown or sent to an external provider.

Built from the canonical pixels after face detection *and* OCR redaction succeeded: faces and redacted
text regions are expanded by 30 % and masked (pixelation + blur + noise, so the masked area cannot be
recovered by de-blurring), the image is resized so its long side is ≤ 1568 px, and it is re-encoded as
JPEG without any metadata — the encoder output is re-opened to assert that no EXIF/XMP/ICC survived.
"""

from __future__ import annotations

import hashlib
import io

import numpy as np
from PIL import Image, ImageFilter

from angel_engine.images.decode import Canonical
from angel_engine.images.errors import PreviewRefused
from angel_engine.images.types import Box, FaceResult, OcrResult, PipelineConfig, SanitizedPreview

ID, VERSION = "preview", "1"
EXPAND = 0.30
JPEG_QUALITY = 85


def _expanded(box: Box, w: int, h: int) -> tuple[int, int, int, int]:
    dx, dy = box.w * EXPAND / 2, box.h * EXPAND / 2
    x1 = max(0, int((box.x - dx) * w))
    y1 = max(0, int((box.y - dy) * h))
    x2 = min(w, round((box.x + box.w + dx) * w) + 1)
    y2 = min(h, round((box.y + box.h + dy) * h) + 1)
    return x1, y1, x2, y2


def _mask(image: Image.Image, box: tuple[int, int, int, int], rng: np.random.Generator) -> None:
    x1, y1, x2, y2 = box
    if x2 - x1 < 2 or y2 - y1 < 2:
        return
    region = image.crop(box)
    small = region.resize((max(1, (x2 - x1) // 16), max(1, (y2 - y1) // 16)), Image.Resampling.BILINEAR)
    pixelated = small.resize(region.size, Image.Resampling.NEAREST).filter(ImageFilter.GaussianBlur(6))
    noise = rng.integers(-24, 25, size=(region.size[1], region.size[0], 3))
    noisy = np.clip(np.asarray(pixelated, dtype=np.int16) + noise, 0, 255).astype(np.uint8)
    image.paste(Image.fromarray(noisy, "RGB"), box)


def build(
    canonical: Canonical, faces: FaceResult | None, ocr: OcrResult | None, config: PipelineConfig
) -> SanitizedPreview:
    if faces is None:
        raise PreviewRefused("face_detection_missing")
    if ocr is None:
        raise PreviewRefused("ocr_redaction_missing")
    image = canonical.image.copy()
    w, h = image.size
    rng = np.random.default_rng(int(canonical.pixel_sha256[:16], 16))
    for box in faces.boxes:
        _mask(image, _expanded(box, w, h), rng)
    for box in ocr.masked_boxes:
        _mask(image, _expanded(box, w, h), rng)
    scale = min(1.0, config.preview_max_side / max(w, h))
    if scale < 1.0:
        image = image.resize((max(1, round(w * scale)), max(1, round(h * scale))), Image.Resampling.LANCZOS)
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=JPEG_QUALITY, optimize=True, exif=b"", icc_profile=None)
    data = buffer.getvalue()
    check = Image.open(io.BytesIO(data), formats=("JPEG",))
    if check.getexif() or check.info.get("icc_profile") or check.info.get("xmp") or check.info.get("exif"):
        raise PreviewRefused("metadata_survived")
    return SanitizedPreview(
        data=data,
        media_type="image/jpeg",
        width=check.width,
        height=check.height,
        sha256=hashlib.sha256(data).hexdigest(),
        built_from_pixel_sha256=canonical.pixel_sha256,
        faces_masked=len(faces.boxes),
        regions_masked=len(ocr.masked_boxes),
    )
