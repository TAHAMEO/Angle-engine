"""Image pipeline: validation, privacy invariants (faces, GPS, identifying metadata, OCR redaction), hashing,
clues, sanitized preview and the sandbox transport. All images are synthetic; there are no real faces."""

from __future__ import annotations

import asyncio
import io
import json
import shutil
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from angel_engine.images import hashing
from angel_engine.images.errors import ImageRejected, ModelIntegrityError
from angel_engine.images.models import MODELS_DIR, NANODET, YUNET, model_path
from angel_engine.images.pipeline import config_from_dict, config_to_dict, from_dict, run_pipeline, to_dict
from angel_engine.images.sandbox.runner import analyze
from angel_engine.images.types import FACE_NOTICE, Box, ClueType, PipelineConfig, StageStatus
from angel_engine.images.validate import quarantine_reason, validate_upload
from tests import imagegen

KEY = b"k" * 32


def config(**overrides: object) -> PipelineConfig:
    values: dict[str, object] = {"sandbox": False, "device_mac_key": KEY}
    values.update(overrides)
    return PipelineConfig(**values)  # type: ignore[arg-type]


@pytest.fixture(scope="module")
def storefront_result():  # type: ignore[no-untyped-def]
    return run_pipeline(imagegen.storefront(), "image/jpeg", config())


# ------------------------------------------------------------------------------------- validation
def test_validation_rejects_mismatch_svg_and_bombs() -> None:
    png = imagegen.png(imagegen.pattern())
    with pytest.raises(ImageRejected) as exc:
        validate_upload(png, "image/jpeg", config())
    assert exc.value.reason_code == "mime_mismatch"
    with pytest.raises(ImageRejected) as exc:
        validate_upload(b'<svg xmlns="http://www.w3.org/2000/svg"></svg>', None, config())
    assert exc.value.reason_code == "svg_not_allowed"
    with pytest.raises(ImageRejected) as exc:
        validate_upload(imagegen.png_bomb(), "image/png", config())
    assert exc.value.reason_code == "dimensions_exceeded"
    with pytest.raises(ImageRejected) as exc:
        validate_upload(png[: len(png) // 2], "image/png", config())
    assert exc.value.reason_code == "truncated"
    info = validate_upload(png, "image/png", config())
    assert (info.format, info.width, info.height, info.trailing_signature) == ("PNG", 640, 480, None)


def test_polyglot_is_quarantined_and_never_decoded() -> None:
    data = imagegen.with_zip_appended(imagegen.jpeg(imagegen.pattern()))
    info = validate_upload(data, "image/jpeg", config())
    assert quarantine_reason(info) == "polyglot_zip"
    result = run_pipeline(data, "image/jpeg", config())
    assert result.status == StageStatus.POLICY_BLOCKED and result.quarantine_reason == "polyglot_zip"
    assert [s.analyzer for s in result.stages] == ["file_info"] and result.preview is None


# ------------------------------------------------------------------------------- full pipeline
def test_storefront_pipeline_stages_and_clues(storefront_result) -> None:  # type: ignore[no-untyped-def]
    result = storefront_result
    assert result.status == StageStatus.OK
    stages = ("file_info", "decode", "hashing", "metadata", "faces", "ocr", "objects", "preview", "clues")
    assert {s.analyzer: s.status for s in result.stages} == dict.fromkeys(stages, StageStatus.OK)
    assert "NORTHWIND" in result.ocr.text and result.ocr.mean_confidence > 0.5
    clues = {(c.type, c.value) for c in result.clues}
    assert (ClueType.ORGANIZATION, "Northwind Coffee Roasters") in clues
    assert (ClueType.DOMAIN, "northwind-coffee.example") in clues
    assert (ClueType.USERNAME, "@northwindroasters") in clues
    assert (ClueType.DATE, "EST. 2016") in clues
    # Opening hours and street signage are not organizations.
    organizations = [c.value for c in result.clues if c.type == ClueType.ORGANIZATION]
    assert organizations == ["Northwind Coffee Roasters"]
    assert all(c.confidence in ("low", "moderate", "high") and c.confidence_basis for c in result.clues)
    assert result.faces.count == 0 and result.notices == ()


def test_metadata_is_kept_generalized_and_fingerprinted(storefront_result) -> None:  # type: ignore[no-untyped-def]
    meta = storefront_result.metadata
    assert meta.availability.value == "rich"
    assert meta.fields["camera_make"] == "DemoCam" and meta.fields["camera_model"] == "DC-100"
    assert meta.capture_time == "2026-06-14T09:12:33+01:00"
    assert {i.code for i in meta.indicators} >= {"editor_software", "datetime_mismatch"}
    assert all("proves nothing" in i.caveat for i in meta.indicators)
    # Identifying fields become keyed fingerprints; the values never leave the pipeline.
    assert set(meta.device_fingerprints) == {"artist", "body_serial_number"}
    assert {"artist", "body_serial_number", "gps_coordinates"} <= set(meta.redacted_fields)
    # GPS is generalized to region level; coordinates are never returned.
    assert (meta.location.country_code, meta.location.region_code) == ("PT", "PT-11")
    serialized = json.dumps(to_dict(storefront_result))
    for secret in ("Jane Example", "DC100-0004471", "38.72", "-9.13", "9.139", "38.7223"):
        assert secret not in serialized
    assert "Metadata is editable" in " ".join(storefront_result.warnings)


def test_restricted_mode_drops_location() -> None:
    result = run_pipeline(imagegen.storefront(), "image/jpeg", config(restricted_mode=True, enable_objects=False))
    assert result.status == StageStatus.OK
    assert result.metadata.location is None and "gps_coordinates" in result.metadata.redacted_fields
    assert not [c for c in result.clues if c.source == "metadata" and c.type == ClueType.PUBLIC_LOCATION]


def test_preview_is_metadata_free_and_bounded(storefront_result) -> None:  # type: ignore[no-untyped-def]
    preview = storefront_result.preview
    img = Image.open(io.BytesIO(preview.data))
    assert img.format == "JPEG" and max(img.size) <= 1568
    assert not img.getexif() and "icc_profile" not in img.info and "exif" not in img.info
    assert preview.built_from_pixel_sha256 == storefront_result.hashes.pixel_sha256


def _dark_fraction(data: bytes, box: Box) -> float:
    pixels = np.asarray(Image.open(io.BytesIO(data)).convert("RGB")).astype(int)
    h, w = pixels.shape[:2]
    region = pixels[int(box.y * h) : int((box.y + box.h) * h), int(box.x * w) : int((box.x + box.w) * w)]
    return float((region.sum(axis=2) < 150).mean())


def test_fixture_faces_are_masked_and_trigger_the_notice() -> None:
    data = imagegen.storefront(marker=True, with_exif=False)
    result = run_pipeline(data, "image/jpeg", config(face_detector="fixture"))
    assert result.status == StageStatus.OK
    assert result.faces.count == 1 and result.notices == (FACE_NOTICE,)
    assert FACE_NOTICE == "A face was detected in the image. Angel Engine does not perform facial identification."
    assert result.preview.faces_masked == 1
    box = result.faces.boxes[0]
    assert _dark_fraction(data, box) > 0.03  # the original "face" region has fine detail …
    assert _dark_fraction(result.preview.data, box) < 0.002  # … which the preview no longer shows


def test_hash_keyed_fixture_faces() -> None:
    data = imagegen.jpeg(imagegen.pattern(3))
    probe = run_pipeline(data, "image/jpeg", config(face_detector="fixture", enable_objects=False))
    assert probe.faces.count == 0
    boxes = {probe.hashes.pixel_sha256: [Box(0.1, 0.1, 0.2, 0.3, 0.95)]}
    result = run_pipeline(
        data, "image/jpeg", config(face_detector="fixture", fixture_faces=boxes, enable_objects=False)
    )
    assert result.faces.count == 1 and result.preview.faces_masked == 1


def test_yunet_finds_no_faces_in_synthetic_text(storefront_result) -> None:  # type: ignore[no-untyped-def]
    assert storefront_result.faces.detector == "yunet" and storefront_result.faces.boxes == ()


def test_models_are_checksum_verified(tmp_path: Path) -> None:
    assert Path(model_path(YUNET)).is_file() and Path(model_path(NANODET)).is_file()
    shutil.copy(MODELS_DIR / "MANIFEST.json", tmp_path / "MANIFEST.json")
    tampered = bytearray((MODELS_DIR / YUNET).read_bytes())
    tampered[-1] ^= 0xFF
    (tmp_path / YUNET).write_bytes(bytes(tampered))
    with pytest.raises(ModelIntegrityError):
        model_path(YUNET, str(tmp_path))
    result = run_pipeline(imagegen.jpeg(imagegen.pattern()), "image/jpeg", config(models_dir=str(tmp_path)))
    stages = {s.analyzer: s for s in result.stages}
    assert stages["faces"].status == StageStatus.FAILED and stages["faces"].error_code == "model_checksum_mismatch"
    # Without face detection there is no preview: the pipeline fails closed.
    assert result.status == StageStatus.FAILED and result.preview is None
    assert stages["preview"].status == StageStatus.SKIPPED


# -------------------------------------------------------------------------------------- hashing
def test_duplicate_relations() -> None:
    base = imagegen.pattern(5, (800, 600))
    a = run_pipeline(imagegen.jpeg(base), "image/jpeg", config(enable_objects=False)).hashes
    same = run_pipeline(imagegen.png(base), "image/png", config(enable_objects=False)).hashes
    resized = run_pipeline(imagegen.jpeg(base.resize((400, 300)), quality=60), "image/jpeg",
                           config(enable_objects=False)).hashes  # fmt: skip
    other = run_pipeline(imagegen.jpeg(imagegen.pattern(42, (800, 600)).rotate(90)), "image/jpeg",
                         config(enable_objects=False)).hashes  # fmt: skip
    assert hashing.relation(a, a) == "identical"
    assert hashing.relation(a, same) in ("identical", "near_duplicate")  # lossy JPEG vs lossless PNG
    assert hashing.relation(a, resized) == "near_duplicate"
    assert hashing.relation(a, other) is None  # uniform background segments alone never match
    sign = Image.open(io.BytesIO(imagegen.storefront(with_exif=False))).convert("RGB")
    full = run_pipeline(imagegen.jpeg(sign), "image/jpeg", config(enable_objects=False)).hashes
    cropped = run_pipeline(imagegen.jpeg(sign.crop((100, 50, 1500, 950))), "image/jpeg",
                           config(enable_objects=False)).hashes  # fmt: skip
    assert hashing.bits(full.phash, cropped.phash) > hashing.SIMILAR_PHASH
    assert hashing.relation(full, cropped) == "similar"  # found by the crop-resistant hash
    assert -(1 << 63) <= a.phash < (1 << 63)  # fits a Postgres BIGINT


# ------------------------------------------------------------------------------------ transport
def test_result_and_config_round_trip(storefront_result) -> None:  # type: ignore[no-untyped-def]
    assert from_dict(json.loads(json.dumps(to_dict(storefront_result)))) == storefront_result
    cfg = config(fixture_faces={"abc": [Box(0.1, 0.2, 0.3, 0.4, 0.9)]}, restricted_mode=True)
    assert config_from_dict(json.loads(json.dumps(config_to_dict(cfg)))) == cfg


def test_sandbox_child_process() -> None:
    data = imagegen.storefront(marker=True)
    result = asyncio.run(analyze(data, "image/jpeg", config(sandbox=True, face_detector="fixture")))
    assert result.status == StageStatus.OK and result.faces.count == 1
    assert result.metadata.location.country_code == "PT" and result.preview is not None


# ---------------------------------------------------------------------------------------------- geo
@pytest.mark.parametrize(
    ("lat", "lon", "expected"),
    [
        (37.33182, -122.03118, ("resolved", "US", "US-CA")),  # Appendix D, G4
        (38.7223, -9.1393, ("resolved", "PT", "PT-11")),
        (51.5, -0.12, ("country_only", "GB", None)),  # small admin-1 regions fall back to the country
        (0.0, -30.0, ("unresolved", None, None)),  # open ocean
    ],
)
def test_gps_generalization(lat: float, lon: float, expected: tuple[str, str | None, str | None]) -> None:
    from angel_engine.infra.geo import generalize

    loc = generalize(lat, lon)
    assert (loc.status, loc.country_code, loc.region_code) == expected
    assert str(lat) not in repr(loc) and str(lon) not in repr(loc)
