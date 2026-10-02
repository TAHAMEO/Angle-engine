"""OCR of visible text with Tesseract 5, then sensitive-data redaction (fail closed).

Raw OCR text never leaves this module: lines are redacted by the guard first, and the boxes of words that
were redacted are returned so the preview can mask them. A failed OCR stage blocks the preview.
"""

from __future__ import annotations

from collections import defaultdict

import numpy as np
from PIL import Image, ImageOps

from angel_engine.guard import RedactionContext, RedactionMode, SourceKind, redact_text
from angel_engine.images.decode import Canonical
from angel_engine.images.errors import AnalyzerError, StageSkipped
from angel_engine.images.types import Box, OcrLine, OcrResult, PipelineConfig

ID, VERSION = "ocr", "1"
TESSERACT_TIMEOUT_S = 50
MIN_CONFIDENCE = 40.0
MAX_SIDE = 3000


def _prepare(image: Image.Image) -> tuple[Image.Image, float]:
    gray = ImageOps.grayscale(image)
    w, h = gray.size
    scale = 1.0
    if max(w, h) < 1000:
        scale = 1000 / max(w, h)
    elif max(w, h) > MAX_SIDE:
        scale = MAX_SIDE / max(w, h)
    if scale != 1.0:
        gray = gray.resize((max(1, round(w * scale)), max(1, round(h * scale))), Image.Resampling.LANCZOS)
    if float(np.asarray(gray).mean()) < 110:  # light text on a dark background (signs, screens)
        gray = ImageOps.invert(gray)
    return ImageOps.expand(gray, border=10, fill=255), scale


def run(canonical: Canonical, config: PipelineConfig) -> OcrResult:
    try:
        import pytesseract
    except ImportError as exc:
        raise StageSkipped("tesseract_missing") from exc
    prepared, scale = _prepare(canonical.image)
    try:
        data = pytesseract.image_to_data(
            prepared,
            lang=config.ocr_languages,
            config="--oem 1 --psm 11",
            output_type=pytesseract.Output.DICT,
            timeout=TESSERACT_TIMEOUT_S,
        )
    except RuntimeError as exc:  # pytesseract raises RuntimeError on timeout
        raise AnalyzerError("ocr_timeout") from exc
    except pytesseract.TesseractNotFoundError as exc:
        raise StageSkipped("tesseract_missing") from exc
    except pytesseract.TesseractError as exc:
        raise AnalyzerError("ocr_failed") from exc
    w, h = canonical.width, canonical.height
    words: dict[tuple[int, int, int], list[tuple[str, float, tuple[float, float, float, float]]]] = defaultdict(list)
    for i, text in enumerate(data.get("text", [])):
        word = (text or "").strip()
        conf = float(data["conf"][i]) if str(data["conf"][i]).lstrip("-").replace(".", "", 1).isdigit() else -1.0
        if not word or conf < MIN_CONFIDENCE:
            continue
        x = (float(data["left"][i]) - 10) / scale
        y = (float(data["top"][i]) - 10) / scale
        bw, bh = float(data["width"][i]) / scale, float(data["height"][i]) / scale
        key = (int(data["block_num"][i]), int(data["par_num"][i]), int(data["line_num"][i]))
        words[key].append((word, conf, (x, y, bw, bh)))
    mode = RedactionMode.RESTRICTED if config.restricted_mode else RedactionMode.STANDARD
    ctx = RedactionContext(source_kind=SourceKind.OCR)
    lines: list[OcrLine] = []
    masked: list[Box] = []
    counts: dict[str, int] = {}
    flags: set[str] = set()
    for key in sorted(words):
        items = words[key]
        raw = " ".join(word for word, _, _ in items)
        result = redact_text(raw, mode=mode, context=ctx)
        for kind, n in result.counts.items():
            counts[kind] = counts.get(kind, 0) + n
        flags.update(f.value for f in result.flags)
        xs = [b[0] for *_, b in items]
        ys = [b[1] for *_, b in items]
        x2 = [b[0] + b[2] for *_, b in items]
        y2 = [b[1] + b[3] for *_, b in items]
        line_box = Box(
            x=max(0.0, min(xs) / w),
            y=max(0.0, min(ys) / h),
            w=min(1.0, (max(x2) - min(xs)) / w),
            h=min(1.0, (max(y2) - min(ys)) / h),
        )
        if result.spans:
            # Mask every word that overlaps a redacted span (offsets into the space-joined line).
            offset = 0
            for word, _, (bx, by, bw, bh) in items:
                start, end = offset, offset + len(word)
                if any(span.start < end and start < span.end for span in result.spans):
                    masked.append(Box(x=max(0.0, bx / w), y=max(0.0, by / h), w=min(1.0, bw / w), h=min(1.0, bh / h)))
                offset = end + 1
        if result.text.strip():
            lines.append(
                OcrLine(
                    text=result.text, confidence=round(sum(c for _, c, _ in items) / len(items) / 100, 3), box=line_box
                )
            )
    mean = round(sum(line.confidence for line in lines) / len(lines), 3) if lines else 0.0
    return OcrResult(
        text="\n".join(line.text for line in lines),
        lines=tuple(lines),
        mean_confidence=mean,
        languages=config.ocr_languages,
        redaction_counts=counts,
        masked_boxes=tuple(masked),
        flags=tuple(sorted(flags)),
    )
