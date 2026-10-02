"""Generic object detection (NanoDet-Plus, 80 COCO classes) for visual clues.

``person`` detections are only counted (used to gate reverse-image search); they are never described.
Decoding follows the Generalized Focal Loss head: per location, 80 class scores and a 4×8 distribution
over box-side distances (``reg_max`` = 7) at strides 8, 16 and 32 on a 416×416 letterboxed input.
"""

from __future__ import annotations

import math

import numpy as np

from angel_engine.images.decode import Canonical
from angel_engine.images.errors import AnalyzerError
from angel_engine.images.models import NANODET, model_path
from angel_engine.images.types import Box, DetectedObject, ObjectResult, PipelineConfig

ID, VERSION = "objects", "1"
INPUT = 416
STRIDES = (8, 16, 32)
REG_MAX = 7
SCORE_THRESHOLD = 0.4
NMS_IOU = 0.5
MEAN = np.array([103.53, 116.28, 123.675], dtype=np.float32)
STD = np.array([57.375, 57.12, 58.395], dtype=np.float32)
_COCO_LABELS = (
    "person bicycle car motorcycle airplane bus train truck boat traffic_light fire_hydrant stop_sign parking_meter "
    "bench bird cat dog horse sheep cow elephant bear zebra giraffe backpack umbrella handbag tie suitcase frisbee "
    "skis snowboard sports_ball kite baseball_bat baseball_glove skateboard surfboard tennis_racket bottle "
    "wine_glass cup fork knife spoon bowl banana apple sandwich orange broccoli carrot hot_dog pizza donut cake "
    "chair couch potted_plant bed dining_table toilet tv laptop mouse remote keyboard cell_phone microwave oven "
    "toaster sink refrigerator book clock vase scissors teddy_bear hair_drier toothbrush"
)
COCO = tuple(_COCO_LABELS.split())
assert len(COCO) == 80


def _anchors() -> list[np.ndarray]:
    out = []
    for stride in STRIDES:
        size = math.ceil(INPUT / stride)
        ys, xs = np.meshgrid(np.arange(size), np.arange(size), indexing="ij")
        centers = np.stack([xs.ravel() * stride + (stride - 1) / 2, ys.ravel() * stride + (stride - 1) / 2], axis=1)
        out.append(centers.astype(np.float32))
    return out


def _softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - x.max(axis=1, keepdims=True))
    out: np.ndarray = e / e.sum(axis=1, keepdims=True)
    return out


def decode(outputs: list[np.ndarray], score_threshold: float = SCORE_THRESHOLD) -> list[tuple[np.ndarray, float, int]]:
    """Turn raw head outputs (scores for each stride, then box distributions) into input-space boxes."""
    import cv2

    scores_by_level, boxes_by_level = outputs[: len(STRIDES)], outputs[len(STRIDES) :]
    project = np.arange(REG_MAX + 1, dtype=np.float32)
    all_boxes, all_scores = [], []
    for stride, level_scores, dist, anchors in zip(STRIDES, scores_by_level, boxes_by_level, _anchors(), strict=True):
        distances = (_softmax(dist.reshape(-1, REG_MAX + 1)) @ project).reshape(-1, 4) * stride
        x1y1 = anchors - distances[:, :2]
        x2y2 = anchors + distances[:, 2:]
        all_boxes.append(np.clip(np.concatenate([x1y1, x2y2], axis=1), 0, INPUT))
        all_scores.append(level_scores.reshape(-1, len(COCO)))
    boxes = np.concatenate(all_boxes)
    scores = np.concatenate(all_scores)
    classes = scores.argmax(axis=1)
    confidences = scores.max(axis=1)
    keep = confidences >= score_threshold
    if not keep.any():
        return []
    boxes, classes, confidences = boxes[keep], classes[keep], confidences[keep]
    xywh = np.concatenate([boxes[:, :2], boxes[:, 2:] - boxes[:, :2]], axis=1)
    picked = cv2.dnn.NMSBoxes(xywh.tolist(), confidences.tolist(), score_threshold, NMS_IOU)
    return [(boxes[i], float(confidences[i]), int(classes[i])) for i in np.array(picked).flatten().tolist()]


def detect(canonical: Canonical, config: PipelineConfig) -> ObjectResult:
    import cv2

    try:
        net = cv2.dnn.readNet(model_path(NANODET, config.models_dir))
    except cv2.error as exc:
        raise AnalyzerError("object_model_load_failed") from exc
    bgr = cv2.cvtColor(canonical.array, cv2.COLOR_RGB2BGR)
    h, w = bgr.shape[:2]
    scale = INPUT / max(h, w)
    nw, nh = max(1, round(w * scale)), max(1, round(h * scale))
    letterbox = np.zeros((INPUT, INPUT, 3), dtype=np.uint8)
    letterbox[:nh, :nw] = cv2.resize(bgr, (nw, nh), interpolation=cv2.INTER_AREA)
    blob = cv2.dnn.blobFromImage((letterbox.astype(np.float32) - MEAN) / STD)
    net.setInput(blob)
    names = net.getUnconnectedOutLayersNames()
    outputs = dict(zip(names, net.forward(names), strict=True))
    ordered = sorted(outputs.values(), key=lambda o: (o.shape[-1] != len(COCO), -o.shape[1]))
    detections = decode(ordered)
    objects, persons = [], 0
    for box, score, cls in detections:
        label = COCO[cls]
        if label == "person":
            persons += 1
            continue
        x1, y1, x2, y2 = (float(v) / scale for v in box)
        objects.append(
            DetectedObject(
                label=label.replace("_", " "),
                score=round(score, 3),
                box=Box(x=max(0.0, x1 / w), y=max(0.0, y1 / h), w=min(1.0, (x2 - x1) / w), h=min(1.0, (y2 - y1) / h)),
            )
        )
    return ObjectResult(objects=tuple(objects[:50]), person_count=persons)
