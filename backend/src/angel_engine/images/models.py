"""Vendored ONNX models, verified against MANIFEST.json before first use."""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

from angel_engine.images.errors import ModelIntegrityError, ModelUnavailable

MODELS_DIR = Path(__file__).resolve().parents[1] / "models"
YUNET = "face_detection_yunet_2023mar.onnx"
NANODET = "object_detection_nanodet_2022nov.onnx"


@lru_cache(maxsize=1)
def manifest(models_dir: str | None = None) -> dict[str, dict[str, object]]:
    path = Path(models_dir or MODELS_DIR) / "MANIFEST.json"
    return json.loads(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


@lru_cache(maxsize=8)
def model_path(name: str, models_dir: str | None = None) -> str:
    """Absolute path of a verified model file (raises if missing or tampered with)."""
    path = Path(models_dir or MODELS_DIR) / name
    if not path.is_file():
        raise ModelUnavailable()
    expected = str(manifest(models_dir).get(name, {}).get("sha256", ""))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if not expected or digest != expected:
        raise ModelIntegrityError()
    return str(path)
