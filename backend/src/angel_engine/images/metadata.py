"""Image metadata (EXIF, XMP, IPTC) with privacy by design.

Kept (redacted) fields describe the capture: camera and lens model, software, dates with offsets and
exposure settings. Identifying fields — serial numbers, owner/artist/creator names, host computer,
unique image IDs — are never returned: only that they are present and a per-investigation keyed
fingerprint (so two images from the same camera can be linked without revealing the serial). GPS
positions are generalized to country/region (none at all in restricted mode). MakerNote blobs are never
decoded. Edit indicators carry the caveat that metadata is editable.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import math
import re
from datetime import datetime
from typing import Any

from PIL import ExifTags, Image, ImageFile, IptcImagePlugin

from angel_engine.guard import RedactionContext, RedactionMode, SourceKind, redact_text
from angel_engine.images.types import (
    EditIndicator,
    GeneralizedLocation,
    MetadataAvailability,
    MetadataResult,
    PipelineConfig,
)

ID, VERSION = "metadata", "1"
IFD0_KEEP = {271: "camera_make", 272: "camera_model", 305: "software", 306: "datetime_modified", 274: "orientation"}
EXIF_KEEP = {
    36867: "datetime_original", 36868: "datetime_digitized", 36880: "offset_time", 36881: "offset_time_original",
    33434: "exposure_time", 33437: "f_number", 34855: "iso", 37386: "focal_length", 42035: "lens_make",
    42036: "lens_model", 41987: "white_balance", 37385: "flash",
}  # fmt: skip
IFD0_FREE_TEXT = {270: "image_description"}
EXIF_FREE_TEXT = {37510: "user_comment"}
IDENTIFYING = {
    "ifd0": {315: "artist", 316: "host_computer", 33432: "copyright_holder"},
    "exif": {42033: "body_serial_number", 42037: "lens_serial_number", 42032: "camera_owner_name",
             42016: "image_unique_id"},
}  # fmt: skip
IPTC_KEEP = {(2, 110): "iptc_credit", (2, 115): "iptc_source", (2, 120): "iptc_caption", (2, 55): "iptc_date_created"}
IPTC_LOCATION = {(2, 90): "iptc_city", (2, 95): "iptc_province", (2, 101): "iptc_country"}
IPTC_IDENTIFYING = {(2, 80): "iptc_byline", (2, 116): "iptc_copyright"}
EDITORS = re.compile(
    r"photoshop|lightroom|gimp|snapseed|affinity|pixelmator|canva|picsart|capture one|darktable|paint\.net|"
    r"photopea|luminar|facetune|meitu",
    re.IGNORECASE,
)
_DATE = re.compile(r"^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2}):(\d{2})")


def _text(value: Any, limit: int = 300) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.split(b"\x00", 1)[0] if not value.startswith(b"ASCII\x00\x00\x00") else value[8:]
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, tuple) and len(value) == 2 and all(isinstance(v, int) for v in value):
        value = value[0] / value[1] if value[1] else value[0]
    text = str(value).strip().strip("\x00")
    return text[:limit] or None


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        return float("nan")


def _gps_decimal(dms: Any, ref: Any) -> float | None:
    try:
        degrees, minutes, seconds = (_float(v) for v in dms)
    except (TypeError, ValueError):
        return None
    value = degrees + minutes / 60 + seconds / 3600
    if str(ref).upper().startswith(("S", "W")):
        value = -value
    return value if math.isfinite(value) else None


def _parse_exif_date(value: str | None, offset: str | None) -> datetime | None:
    if not value or not (m := _DATE.match(value)):
        return None
    iso = f"{m[1]}-{m[2]}-{m[3]}T{m[4]}:{m[5]}:{m[6]}"
    if offset and re.fullmatch(r"[+-]\d{2}:\d{2}", offset.strip()):
        iso += offset.strip()
    try:
        return datetime.fromisoformat(iso)
    except ValueError:
        return None


def _fingerprint(key: bytes, field: str, value: str) -> str:
    return hmac.new(
        key or b"angel-engine-device", f"{field}|{value.strip().casefold()}".encode(), hashlib.sha256
    ).hexdigest()[:24]


def _thumbnail_phash(image: Image.Image) -> int | None:
    raw = image.info.get("exif")
    if not isinstance(raw, bytes | bytearray):
        return None
    ifd1 = image.getexif().get_ifd(ExifTags.IFD.IFD1)
    offset, length = ifd1.get(513), ifd1.get(514)
    if not isinstance(offset, int) or not isinstance(length, int) or not 0 < length <= 512_000:
        return None
    base = 6 if raw[:6] == b"Exif\x00\x00" else 0
    blob = bytes(raw[base + offset : base + offset + length])
    try:
        import imagehash

        thumb = Image.open(io.BytesIO(blob), formats=("JPEG",))
        thumb.load()
        return int(str(imagehash.phash(thumb.convert("RGB"))), 16)
    except Exception:
        return None


def _xmp_values(node: Any, key: str, depth: int = 0) -> list[Any]:
    """All values stored under ``key`` anywhere in Pillow's nested XMP dictionary."""
    if depth > 12:
        return []
    found: list[Any] = []
    if isinstance(node, dict):
        for k, v in list(node.items())[:500]:
            if k == key:
                found.append(v)
            found.extend(_xmp_values(v, key, depth + 1))
    elif isinstance(node, list):
        for item in node[:500]:
            found.extend(_xmp_values(item, key, depth + 1))
    return found


def _count_items(node: Any) -> int:
    items = _xmp_values(node, "li")
    if not items:
        return 1
    first = items[0]
    return len(first) if isinstance(first, list) else 1


def extract(image: Image.Image, config: PipelineConfig, *, canonical_phash: int | None = None) -> MetadataResult:
    mode = RedactionMode.RESTRICTED if config.restricted_mode else RedactionMode.STANDARD
    ctx = RedactionContext(source_kind=SourceKind.METADATA)
    fields: dict[str, Any] = {}
    redacted: list[str] = []
    fingerprints: dict[str, str] = {}
    counts: dict[str, int] = {}

    def keep(name: str, value: Any, *, free_text: bool = False) -> None:
        text = _text(value, 500 if free_text else 120)
        if text is None:
            return
        result = redact_text(text, mode=mode, context=ctx)
        for kind, n in result.counts.items():
            counts[kind] = counts.get(kind, 0) + n
        if result.text.strip():
            fields[name] = result.text

    def identify(name: str, value: Any) -> None:
        text = _text(value)
        if text:
            redacted.append(name)
            fingerprints[name] = _fingerprint(config.device_mac_key, name, text)

    exif = image.getexif()
    exif_ifd = exif.get_ifd(ExifTags.IFD.Exif)
    for tag, name in IFD0_KEEP.items():
        keep(name, exif.get(tag))
    for tag, name in IFD0_FREE_TEXT.items():
        keep(name, exif.get(tag), free_text=True)
    for tag, name in EXIF_KEEP.items():
        keep(name, exif_ifd.get(tag))
    for tag, name in EXIF_FREE_TEXT.items():
        keep(name, exif_ifd.get(tag), free_text=True)
    for tag, name in IDENTIFYING["ifd0"].items():
        identify(name, exif.get(tag))
    for tag, name in IDENTIFYING["exif"].items():
        identify(name, exif_ifd.get(tag))
    if 37500 in exif_ifd:
        redacted.append("maker_note")  # proprietary blob: never decoded

    location: GeneralizedLocation | None = None
    gps = exif.get_ifd(ExifTags.IFD.GPSInfo)
    if gps:
        redacted.append("gps_coordinates")
        if not config.restricted_mode:
            lat, lon = _gps_decimal(gps.get(2), gps.get(1)), _gps_decimal(gps.get(4), gps.get(3))
            if lat is not None and lon is not None:
                from angel_engine.infra.geo import generalize

                location = generalize(lat, lon)

    try:
        iptc = (IptcImagePlugin.getiptcinfo(image) if isinstance(image, ImageFile.ImageFile) else None) or {}
    except Exception:
        iptc = {}
    for key, name in IPTC_KEEP.items():
        keep(name, iptc.get(key), free_text=name == "iptc_caption")
    if not config.restricted_mode:
        for key, name in IPTC_LOCATION.items():
            keep(name, iptc.get(key))
    for key, name in IPTC_IDENTIFYING.items():
        identify(name, iptc.get(key))

    xmp: dict[str, Any] = {}
    try:
        xmp = image.getxmp() or {}
    except Exception:
        xmp = {}
    tools = _xmp_values(xmp, "CreatorTool")
    if tools:
        keep("xmp_creator_tool", tools[0])
    history = sum(_count_items(h) for h in _xmp_values(xmp, "History"))
    if history:
        fields["xmp_edit_history_entries"] = str(history)
    if _xmp_values(xmp, "creator"):
        redacted.append("xmp_creator")

    original = _parse_exif_date(fields.get("datetime_original"), fields.get("offset_time_original"))
    modified = _parse_exif_date(fields.get("datetime_modified"), fields.get("offset_time"))
    indicators: list[EditIndicator] = []
    software = " ".join(str(fields.get(k, "")) for k in ("software", "xmp_creator_tool"))
    if EDITORS.search(software):
        indicators.append(EditIndicator("editor_software", "The file was saved by image-editing software."))
    if (
        original
        and modified
        and abs((modified.replace(tzinfo=None) - original.replace(tzinfo=None)).total_seconds()) > 60
    ):
        indicators.append(
            EditIndicator("datetime_mismatch", "The file's modification time differs from its original capture time.")
        )
    if history:
        indicators.append(EditIndicator("xmp_history", "The XMP metadata records an editing history."))
    if (
        canonical_phash is not None
        and (thumb := _thumbnail_phash(image)) is not None
        and ((thumb ^ canonical_phash) & ((1 << 64) - 1)).bit_count() > 12
    ):
        indicators.append(
            EditIndicator(
                "thumbnail_mismatch", "The embedded thumbnail does not match the image (it may have been edited)."
            )
        )

    descriptive = {k for k in fields if k not in ("orientation", "xmp_edit_history_entries")}
    if not descriptive and not redacted and location is None:
        availability = MetadataAvailability.NONE
    elif len(descriptive) >= 6 and ("datetime_original" in fields or "camera_model" in fields):
        availability = MetadataAvailability.RICH
    else:
        availability = MetadataAvailability.PARTIAL
    return MetadataResult(
        availability=availability,
        fields=fields,
        redacted_fields=tuple(dict.fromkeys(redacted)),
        device_fingerprints=fingerprints,
        location=location,
        capture_time=original.isoformat() if original else None,
        indicators=tuple(indicators),
        redaction_counts=counts,
    )
