"""Public contract of the image-analysis pipeline.

The pipeline is a pure function of the uploaded bytes plus configuration: it never touches the
database or the network. Untrusted decoding runs inside a resource-limited child process. The worker
job handler persists the returned :class:`PipelineResult`.

Privacy invariants (enforced by the implementation and its tests):

* Faces are only *detected* (count + normalized boxes). No embeddings, landmarks or attributes
  (age, gender, ethnicity, emotion, …) are computed or returned.
* Precise GPS coordinates never leave the sandbox; only country/admin-1 level names are returned.
* Raw OCR text never leaves the pipeline; only redacted text is returned.
* :class:`SanitizedPreview` can only be produced after face detection and OCR redaction both
  succeeded on the same canonical pixels; it is the only image type external providers accept.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

FACE_NOTICE = "A face was detected in the image. Angel Engine does not perform facial identification."
UPLOAD_NOTICE = (
    "Upload only images you are legally authorized to investigate. "
    "Angel Engine does not perform facial identification."
)


class StageStatus(StrEnum):
    OK = "ok"
    SKIPPED = "skipped"
    FAILED = "failed"
    TIMEOUT = "timeout"
    POLICY_BLOCKED = "policy_blocked"


class MetadataAvailability(StrEnum):
    NONE = "none"
    PARTIAL = "partial"
    RICH = "rich"


@dataclass(frozen=True, slots=True)
class Box:
    """Normalized box: all values in [0, 1] relative to the canonical image."""

    x: float
    y: float
    w: float
    h: float
    score: float | None = None


@dataclass(frozen=True, slots=True)
class PipelineConfig:
    max_upload_bytes: int = 25 * 1024 * 1024
    max_pixels: int = 40_000_000
    max_side: int = 16_384
    ocr_languages: str = "eng"
    models_dir: str | None = None                 # defaults to the packaged models directory
    enable_objects: bool = True
    face_blur_threshold: float = 0.5
    face_notice_threshold: float = 0.7
    preview_max_side: int = 1568
    sandbox: bool = True                          # False only in unit tests
    #: "yunet" (default) or "fixture" (e2e only: boxes looked up by canonical pixel hash)
    face_detector: str = "yunet"
    fixture_faces: dict[str, list[Box]] = field(default_factory=dict)
    allow_heif: bool = False


@dataclass(frozen=True, slots=True)
class StageReport:
    analyzer: str
    version: str
    status: StageStatus
    duration_ms: int = 0
    warning: str | None = None
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class FileInfo:
    mime: str
    format: str
    width: int
    height: int
    frames: int
    byte_size: int
    mode: str
    has_alpha: bool
    has_icc_profile: bool
    file_sha256: str
    trailing_bytes: int = 0
    trailing_signature: str | None = None


@dataclass(frozen=True, slots=True)
class GeneralizedLocation:
    status: str                      # "resolved" | "country_only" | "unresolved"
    country_code: str | None = None  # ISO 3166-1 alpha-2
    country_name: str | None = None
    region_code: str | None = None   # ISO 3166-2 when available
    region_name: str | None = None
    basis: str = "EXIF GPS generalized to region level per privacy policy (Natural Earth boundaries)"


@dataclass(frozen=True, slots=True)
class EditIndicator:
    code: str                        # e.g. "editor_software", "datetime_mismatch", "thumbnail_mismatch"
    message: str
    caveat: str = "Metadata is editable; its presence or absence proves nothing on its own."


@dataclass(frozen=True, slots=True)
class MetadataResult:
    availability: MetadataAvailability
    fields: dict[str, Any] = field(default_factory=dict)          # kept, already-redacted fields
    redacted_fields: tuple[str, ...] = ()                          # names of removed fields
    device_fingerprints: dict[str, str] = field(default_factory=dict)  # field -> per-investigation HMAC
    location: GeneralizedLocation | None = None
    capture_time: str | None = None                                # ISO 8601 from DateTimeOriginal (+offset)
    indicators: tuple[EditIndicator, ...] = ()
    redaction_counts: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class HashResult:
    phash: int          # signed 64-bit (fits Postgres BIGINT)
    dhash: int
    ahash: int
    whash: int
    colorhash: str
    crop_resistant: str
    file_sha256: str
    pixel_sha256: str


@dataclass(frozen=True, slots=True)
class FaceResult:
    count: int                       # faces at/above the notice threshold
    boxes: tuple[Box, ...] = ()      # all boxes at/above the blur threshold (normalized)
    detector: str = "yunet"

    @property
    def notice(self) -> str | None:
        return FACE_NOTICE if self.count > 0 else None


@dataclass(frozen=True, slots=True)
class OcrLine:
    text: str                        # redacted
    confidence: float                # 0..1
    box: Box


@dataclass(frozen=True, slots=True)
class OcrResult:
    text: str                        # full redacted text
    lines: tuple[OcrLine, ...] = ()
    mean_confidence: float = 0.0
    languages: str = "eng"
    redaction_counts: dict[str, int] = field(default_factory=dict)
    masked_boxes: tuple[Box, ...] = ()   # sensitive regions masked in the preview
    flags: tuple[str, ...] = ()          # e.g. ("medical",)


@dataclass(frozen=True, slots=True)
class DetectedObject:
    label: str                       # COCO label; "person" is never further described
    score: float
    box: Box


@dataclass(frozen=True, slots=True)
class ObjectResult:
    objects: tuple[DetectedObject, ...] = ()
    person_count: int = 0
    model: str = "nanodet-plus-m-1.5x-416"


class ClueType(StrEnum):
    VISIBLE_TEXT = "visible_text"
    URL = "url"
    DOMAIN = "domain"
    USERNAME = "username"
    HASHTAG = "hashtag"
    EMAIL_DOMAIN = "email_domain"
    DATE = "date"
    ORGANIZATION = "organization"
    BRAND = "brand"
    OBJECT = "object"
    LANDMARK = "landmark"
    SIGN = "sign"
    PUBLIC_LOCATION = "public_location"
    EXIF_FIELD = "exif_field"


@dataclass(frozen=True, slots=True)
class Clue:
    type: ClueType
    value: str                        # display value (redacted)
    normalized: str                   # canonical form used for dedupe/pivots (e.g. lowercase domain)
    source: str                       # "ocr" | "metadata" | "objects" | "ai" | "provider"
    confidence: str                   # "low" | "moderate" | "high"
    confidence_basis: str
    box: Box | None = None
    platform: str | None = None       # for usernames, e.g. "github", "mastodon"
    precision: str | None = None      # for dates: "day" | "month" | "year"


@dataclass(frozen=True, slots=True)
class SanitizedPreview:
    """Metadata-free, face- and sensitive-region-masked derivative. The only image providers accept."""

    data: bytes
    media_type: str                   # "image/jpeg" or "image/webp"
    width: int
    height: int
    sha256: str
    built_from_pixel_sha256: str
    faces_masked: int
    regions_masked: int


@dataclass(frozen=True, slots=True)
class PipelineResult:
    status: StageStatus                    # OK when the mandatory stages succeeded
    file_info: FileInfo | None = None
    metadata: MetadataResult | None = None
    hashes: HashResult | None = None
    faces: FaceResult | None = None
    ocr: OcrResult | None = None
    objects: ObjectResult | None = None
    clues: tuple[Clue, ...] = ()
    preview: SanitizedPreview | None = None
    stages: tuple[StageReport, ...] = ()
    warnings: tuple[str, ...] = ()
    quarantine_reason: str | None = None   # set when validation found a polyglot/unsupported file

    @property
    def notices(self) -> tuple[str, ...]:
        return (FACE_NOTICE,) if self.faces and self.faces.count > 0 else ()
