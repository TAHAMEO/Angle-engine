"""Face *detection* (never recognition): count and normalized boxes, used to blur faces and show the notice.

YuNet runs on the whole image (long side 640) and, for large images, on overlapping tiles so small faces
are not missed; boxes are merged with non-maximum suppression. Only boxes and scores are kept — the five
landmark points YuNet also outputs are discarded immediately and never leave this module. The ``fixture``
detector (tests and the offline demo only; refused in production) looks boxes up by canonical pixel hash, or
reports a pure-magenta (255, 0, 255) marker area as a "face", so no real faces are ever needed.
"""

from __future__ import annotations

import numpy as np

from angel_engine.images.decode import Canonical
from angel_engine.images.errors import AnalyzerError
from angel_engine.images.models import YUNET, model_path
from angel_engine.images.types import Box, FaceResult, PipelineConfig

ID, VERSION = "faces", "1"
INPUT_SIDE = 640
TILE_TRIGGER = 1280
NMS_IOU = 0.3
MARKER_MIN_PIXELS = 256


def _detect(detector: object, bgr: np.ndarray) -> list[tuple[float, float, float, float, float]]:
    import cv2

    h, w = bgr.shape[:2]
    scale = INPUT_SIDE / max(h, w)
    resized = (
        cv2.resize(bgr, (max(1, round(w * scale)), max(1, round(h * scale))), interpolation=cv2.INTER_AREA)
        if scale < 1
        else bgr
    )
    rh, rw = resized.shape[:2]
    detector.setInputSize((rw, rh))  # type: ignore[attr-defined]
    _, faces = detector.detect(resized)  # type: ignore[attr-defined]
    out = []
    if faces is not None:
        sx, sy = w / rw, h / rh
        for row in faces:
            x, y, fw, fh, score = float(row[0]), float(row[1]), float(row[2]), float(row[3]), float(row[-1])
            out.append((x * sx, y * sy, fw * sx, fh * sy, score))  # landmarks (row[4:14]) are dropped here
    return out


def _tiles(w: int, h: int) -> list[tuple[int, int, int, int]]:
    tile = max(w, h) // 2
    step = int(tile * 0.75)
    boxes = []
    for y in range(0, max(1, h - tile // 2), step):
        for x in range(0, max(1, w - tile // 2), step):
            boxes.append((x, y, min(tile, w - x), min(tile, h - y)))
    return boxes


def _marker_box(array: np.ndarray) -> Box | None:
    mask = (array[:, :, 0] == 255) & (array[:, :, 1] == 0) & (array[:, :, 2] == 255)
    if int(mask.sum()) < MARKER_MIN_PIXELS:
        return None
    ys, xs = np.nonzero(mask)
    h, w = mask.shape
    x1, x2, y1, y2 = int(xs.min()), int(xs.max()) + 1, int(ys.min()), int(ys.max()) + 1
    return Box(x=x1 / w, y=y1 / h, w=(x2 - x1) / w, h=(y2 - y1) / h, score=0.99)


def detect(canonical: Canonical, config: PipelineConfig) -> FaceResult:
    if config.face_detector == "fixture":
        fixture_boxes = tuple(config.fixture_faces.get(canonical.pixel_sha256, ()))
        if not fixture_boxes and (marker := _marker_box(canonical.array)) is not None:
            fixture_boxes = (marker,)
        return FaceResult(
            count=sum(
                1 for b in fixture_boxes if (1.0 if b.score is None else b.score) >= config.face_notice_threshold
            ),
            boxes=fixture_boxes,
            detector="fixture",
        )
    import cv2

    try:
        detector = cv2.FaceDetectorYN.create(
            model_path(YUNET, config.models_dir),
            "",
            (INPUT_SIDE, INPUT_SIDE),
            config.face_blur_threshold,
            NMS_IOU,
            5000,
        )
    except cv2.error as exc:
        raise AnalyzerError("face_model_load_failed") from exc
    bgr = cv2.cvtColor(canonical.array, cv2.COLOR_RGB2BGR)
    h, w = bgr.shape[:2]
    found = _detect(detector, bgr)
    if max(w, h) > TILE_TRIGGER:
        for tx, ty, tw, th in _tiles(w, h):
            for x, y, fw, fh, score in _detect(detector, bgr[ty : ty + th, tx : tx + tw]):
                found.append((x + tx, y + ty, fw, fh, score))
    if not found:
        return FaceResult(count=0, boxes=(), detector="yunet")
    keep = cv2.dnn.NMSBoxes(
        [[x, y, fw, fh] for x, y, fw, fh, _ in found], [s for *_, s in found], config.face_blur_threshold, NMS_IOU
    )
    boxes: list[Box] = []
    for i in np.array(keep).flatten().tolist():
        x, y, fw, fh, score = found[int(i)]
        boxes.append(
            Box(x=max(0.0, x / w), y=max(0.0, y / h), w=min(1.0, fw / w), h=min(1.0, fh / h), score=round(score, 3))
        )
    count = sum(1 for b in boxes if (b.score or 0) >= config.face_notice_threshold)
    return FaceResult(count=count, boxes=tuple(boxes), detector="yunet")
