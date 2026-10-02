"""Image pipeline orchestrator: a pure function of (bytes, declared MIME, config) → PipelineResult.

Stage order: file_info → decode → hashing → metadata → faces → ocr → objects → preview → clues. Mandatory
stages (file_info, decode, faces, ocr, preview) fail closed: without face detection *and* OCR redaction
there is no preview, and nothing is ever sent to an external provider. Stage reports carry stable error
codes only, never decoder messages or content.
"""

from __future__ import annotations

import base64
import time
from collections.abc import Callable
from dataclasses import asdict, fields
from typing import Any, TypeVar

from angel_engine.images import clues as clue_stage
from angel_engine.images import faces as face_stage
from angel_engine.images import hashing as hash_stage
from angel_engine.images import metadata as metadata_stage
from angel_engine.images import objects as object_stage
from angel_engine.images import ocr as ocr_stage
from angel_engine.images import preview as preview_stage
from angel_engine.images.decode import canonicalize
from angel_engine.images.errors import AnalyzerError, ImageRejected, StageSkipped
from angel_engine.images.types import (
    Box,
    Clue,
    ClueType,
    DetectedObject,
    EditIndicator,
    FaceResult,
    FileInfo,
    GeneralizedLocation,
    HashResult,
    MetadataAvailability,
    MetadataResult,
    ObjectResult,
    OcrLine,
    OcrResult,
    PipelineConfig,
    PipelineResult,
    SanitizedPreview,
    StageReport,
    StageStatus,
)
from angel_engine.images.validate import quarantine_reason, validate_upload

T = TypeVar("T")
VERSIONS = {
    "file_info": "1", "decode": "1", "hashing": hash_stage.VERSION, "metadata": metadata_stage.VERSION,
    "faces": face_stage.VERSION, "ocr": ocr_stage.VERSION, "objects": object_stage.VERSION,
    "preview": preview_stage.VERSION, "clues": clue_stage.VERSION,
}  # fmt: skip


class _Stages:
    def __init__(self) -> None:
        self.reports: list[StageReport] = []

    def run(self, name: str, fn: Callable[[], T]) -> T | None:
        started = time.monotonic()
        status, code, warning, value = StageStatus.OK, None, None, None
        try:
            value = fn()
        except StageSkipped as exc:
            status, code = StageStatus.SKIPPED, exc.code
        except AnalyzerError as exc:
            status, code = exc.status, exc.code
        except ImageRejected as exc:
            status, code = exc.status, exc.reason_code
        except MemoryError:
            status, code = StageStatus.FAILED, "memory_limit"
        except Exception as exc:  # never leak decoder/library messages
            status, code = StageStatus.FAILED, f"error_{type(exc).__name__.lower()}"[:60]
        self.reports.append(
            StageReport(
                analyzer=name,
                version=VERSIONS.get(name, "1"),
                status=status,
                duration_ms=int((time.monotonic() - started) * 1000),
                warning=warning,
                error_code=code,
            )
        )
        return value

    def skip(self, name: str, code: str) -> None:
        self.reports.append(
            StageReport(analyzer=name, version=VERSIONS.get(name, "1"), status=StageStatus.SKIPPED, error_code=code)
        )


def run_pipeline(data: bytes, declared_mime: str | None, config: PipelineConfig) -> PipelineResult:
    stages = _Stages()
    info = stages.run("file_info", lambda: validate_upload(data, declared_mime, config))
    if info is None:
        return PipelineResult(status=stages.reports[-1].status, stages=tuple(stages.reports))
    if (reason := quarantine_reason(info)) is not None:
        return PipelineResult(
            status=StageStatus.POLICY_BLOCKED, file_info=info, stages=tuple(stages.reports), quarantine_reason=reason
        )
    canonical = stages.run("decode", lambda: canonicalize(data, config))
    if canonical is None:
        return PipelineResult(status=StageStatus.FAILED, file_info=info, stages=tuple(stages.reports))
    hashes = stages.run("hashing", lambda: hash_stage.compute(canonical, data))
    metadata = stages.run(
        "metadata",
        lambda: metadata_stage.extract(canonical.source, config, canonical_phash=hashes.phash if hashes else None),
    )
    faces = stages.run("faces", lambda: face_stage.detect(canonical, config))
    ocr = stages.run("ocr", lambda: ocr_stage.run(canonical, config))
    objects = None
    if config.enable_objects:
        objects = stages.run("objects", lambda: object_stage.detect(canonical, config))
    else:
        stages.skip("objects", "disabled")
    preview: SanitizedPreview | None = None
    if faces is not None and ocr is not None:
        preview = stages.run("preview", lambda: preview_stage.build(canonical, faces, ocr, config))
    else:
        stages.skip("preview", "privacy_stage_failed")

    def collect_clues() -> list[Clue]:
        found: list[Clue] = []
        if ocr is not None:
            found += clue_stage.from_ocr(ocr)
        if metadata is not None:
            found += clue_stage.from_metadata(metadata)
        if objects is not None:
            found += clue_stage.from_objects(objects)
        return found

    clues = stages.run("clues", collect_clues) or []
    ok = faces is not None and ocr is not None and preview is not None
    warnings: list[str] = []
    if metadata is not None and metadata.indicators:
        warnings.append("Metadata is editable; its presence or absence proves nothing on its own.")
    return PipelineResult(
        status=StageStatus.OK if ok else StageStatus.FAILED,
        file_info=info,
        metadata=metadata,
        hashes=hashes,
        faces=faces,
        ocr=ocr,
        objects=objects,
        clues=tuple(clues),
        preview=preview,
        stages=tuple(stages.reports),
        warnings=tuple(warnings),
    )


# --------------------------------------------------------------------------------------------------
# Transport (sandbox ↔ worker)
# --------------------------------------------------------------------------------------------------
def to_dict(result: PipelineResult) -> dict[str, Any]:
    data = asdict(result)
    if result.preview is not None:
        data["preview"]["data"] = base64.b64encode(result.preview.data).decode()
    return data


def _box(d: dict[str, Any] | None) -> Box | None:
    return Box(**d) if d else None


def _build(cls: type[T], payload: dict[str, Any] | None, /, **overrides: Any) -> T | None:
    if payload is None:
        return None
    names = {f.name for f in fields(cls)}  # type: ignore[arg-type]
    values = {k: v for k, v in payload.items() if k in names}
    values.update(overrides)
    return cls(**values)


def from_dict(data: dict[str, Any]) -> PipelineResult:
    meta = data.get("metadata")
    metadata = None
    if meta:
        metadata = _build(
            MetadataResult,
            meta,
            availability=MetadataAvailability(meta["availability"]),
            redacted_fields=tuple(meta.get("redacted_fields", ())),
            location=_build(GeneralizedLocation, meta.get("location")),
            indicators=tuple(EditIndicator(**i) for i in meta.get("indicators", ())),
        )
    faces = data.get("faces")
    ocr = data.get("ocr")
    objects = data.get("objects")
    preview = data.get("preview")
    return PipelineResult(
        status=StageStatus(data["status"]),
        file_info=_build(FileInfo, data.get("file_info")),
        metadata=metadata,
        hashes=_build(HashResult, data.get("hashes")),
        faces=_build(FaceResult, faces, boxes=tuple(Box(**b) for b in faces.get("boxes", ()))) if faces else None,
        ocr=_build(
            OcrResult,
            ocr,
            lines=tuple(
                OcrLine(text=line["text"], confidence=line["confidence"], box=Box(**line["box"]))
                for line in ocr.get("lines", ())
            ),
            masked_boxes=tuple(Box(**b) for b in ocr.get("masked_boxes", ())),
            flags=tuple(ocr.get("flags", ())),
        )
        if ocr
        else None,
        objects=_build(
            ObjectResult,
            objects,
            objects=tuple(
                DetectedObject(label=o["label"], score=o["score"], box=Box(**o["box"]))
                for o in objects.get("objects", ())
            ),
        )
        if objects
        else None,
        clues=tuple(
            Clue(**{**c, "type": ClueType(c["type"]), "box": _box(c.get("box"))}) for c in data.get("clues", ())
        ),
        preview=_build(SanitizedPreview, preview, data=base64.b64decode(preview["data"])) if preview else None,
        stages=tuple(StageReport(**{**s, "status": StageStatus(s["status"])}) for s in data.get("stages", ())),
        warnings=tuple(data.get("warnings", ())),
        quarantine_reason=data.get("quarantine_reason"),
    )


def config_to_dict(config: PipelineConfig) -> dict[str, Any]:
    data = {f.name: getattr(config, f.name) for f in fields(config)}
    data["device_mac_key"] = config.device_mac_key.hex()
    data["fixture_faces"] = {k: [asdict(b) for b in v] for k, v in config.fixture_faces.items()}
    return data


def config_from_dict(data: dict[str, Any]) -> PipelineConfig:
    values = dict(data)
    values["device_mac_key"] = bytes.fromhex(values.get("device_mac_key", ""))
    values["fixture_faces"] = {k: [Box(**b) for b in v] for k, v in values.get("fixture_faces", {}).items()}
    return PipelineConfig(**values)


__all__ = ["config_from_dict", "config_to_dict", "from_dict", "run_pipeline", "to_dict"]
