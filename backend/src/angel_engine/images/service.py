"""Image records (database side): upload intake, persistence of analysis results, duplicates, deletion and the
public-occurrence (reverse image search) gate.

Nothing here decodes an image: uploads are validated structurally (:func:`validate_upload`) and decoding
happens only in the sandboxed pipeline. Originals are encrypted with a per-object key before they reach storage
and are purged after the retention window; only the sanitized preview (faces and sensitive text masked, no
metadata) is ever served or sent anywhere.

Analysis results become *observed* evidence (OCR text, embedded metadata, detected objects, duplicate matches)
with ``unverified`` findings, an image node in the graph (``shows_text``, ``located_in``, ``same_image_as`` …)
and a caveated capture-time timeline event. Nothing about people is ever derived: faces are only counted.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.app_state import Services
from angel_engine.config import Settings
from angel_engine.core.clock import utcnow
from angel_engine.core.enums import ImageStatus, JobQueue
from angel_engine.core.ids import new_id
from angel_engine.core.problems import PayloadTooLarge, ProblemError, UnsupportedMedia, ValidationProblem
from angel_engine.crypto.blind_index import tokens
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.crypto.keyed_hash import DEVICE_PURPOSE, canonical_mac
from angel_engine.db.models import (
    BlobDeletion,
    Entity,
    EvidenceItem,
    Image,
    ImageAnalysis,
    ImageClue,
    ImageHash,
    Investigation,
    Relationship,
    User,
)
from angel_engine.entities.service import EntityError, EntityInput, canonicalize, upsert_entity
from angel_engine.evidence.labels import next_label
from angel_engine.evidence.service import EvidenceInput, SourceInput, add_evidence, redaction_mode, upsert_source
from angel_engine.evidence.urls import UrlError
from angel_engine.findings import service as findings
from angel_engine.findings.service import EvidenceDeletion, FindingInput, LinkInput
from angel_engine.graph.service import RelationshipInput, upsert_relationship
from angel_engine.guard import RedactionContext, SourceKind, redact_text
from angel_engine.images import hashing
from angel_engine.images.errors import ImageRejected
from angel_engine.images.providers import OccurrenceResult, VisualLabel
from angel_engine.images.types import (
    FACE_NOTICE,
    Clue,
    ClueType,
    FileInfo,
    MetadataResult,
    PipelineConfig,
    PipelineResult,
)
from angel_engine.images.validate import normalize_mime, quarantine_reason, validate_upload
from angel_engine.infra.storage.objects import investigation_object_key
from angel_engine.jobs.queue import enqueue
from angel_engine.retention.policy import load_policy
from angel_engine.timeline.service import CAVEATS, EventInput, create_event

IMAGE_PURPOSE = "ae/image/v1"
PIXEL_PURPOSE = "ae/image-pixels/v1"
CLUE_PURPOSE = "ae/image-clue/v1"
SCAN_ATTEMPTS = 12
MAX_AUTO_FINDINGS = 12
MAX_MATCHES = 10
METADATA_CAVEAT = "Metadata is editable; its presence or absence proves nothing on its own."
DONE_STATUSES = frozenset({ImageStatus.ANALYZED.value, ImageStatus.ORIGINAL_PURGED.value})
#: Statuses in which analysis results exist (the original may already be gone).
ANALYZED_STATUSES = frozenset({*DONE_STATUSES, ImageStatus.FILES_DELETED.value})

_TOO_LARGE = frozenset({"too_large"})
_UNSUPPORTED = frozenset(
    {
        "unsupported_format",
        "svg_not_allowed",
        "heif_disabled",
        "avif_not_supported",
        "bigtiff_not_supported",
        "mime_mismatch",
    }
)
_TEXT_FINDINGS = {
    ClueType.ORGANIZATION: "Visible text in image {label} names “{value}”.",
    ClueType.DOMAIN: "Visible text in image {label} includes the domain {value}.",
    ClueType.URL: "Visible text in image {label} includes the web address {value}.",
    ClueType.USERNAME: "Visible text in image {label} includes the handle {value}.",
    ClueType.EMAIL_DOMAIN: "Visible text in image {label} includes an e-mail address at {value}.",
    ClueType.HASHTAG: "Visible text in image {label} includes the hashtag {value}.",
    ClueType.DATE: "Visible text in image {label} includes the date text “{value}”.",
}
_CLUE_ENTITIES = {
    ClueType.ORGANIZATION: "organization",
    ClueType.DOMAIN: "domain",
    ClueType.EMAIL_DOMAIN: "domain",
    ClueType.USERNAME: "username",
    ClueType.URL: "webpage",
}
_METADATA_LABELS = {
    "camera_make": "Camera make",
    "camera_model": "Camera model",
    "lens_make": "Lens make",
    "lens_model": "Lens model",
    "software": "Software",
    "xmp_creator_tool": "Creator tool",
    "datetime_original": "Date/time original",
    "offset_time_original": "Time-zone offset (original)",
    "datetime_modified": "Date/time modified",
    "exposure_time": "Exposure time",
    "f_number": "F-number",
    "iso": "ISO",
    "focal_length": "Focal length",
    "iptc_credit": "IPTC credit",
    "iptc_source": "IPTC source",
    "iptc_city": "IPTC city",
    "iptc_country": "IPTC country",
    "xmp_edit_history_entries": "XMP edit-history entries",
}
_MATCH_WORDING = {
    "identical": ("have identical pixel content", "high", "Normalized pixel hashes are equal"),
    "near_duplicate": ("are near-duplicates", "moderate", "Perceptual hashes within 6 bits (pHash) and 8 bits (dHash)"),
    "similar": ("are visually similar", "low", "Perceptual hash within 12 bits or a matching image segment"),
}


def image_label(image: Image) -> str:
    return f"I-{image.label_seq}"


def notices(image: Image) -> list[str]:
    return [FACE_NOTICE] if image.face_count > 0 else []


def _payload(image: Image) -> dict[str, str]:
    return {"image_id": str(image.id), "investigation_id": str(image.investigation_id)}


# --------------------------------------------------------------------------------------------------
# Intake
# --------------------------------------------------------------------------------------------------
def rejection_problem(exc: ImageRejected) -> ProblemError:
    if exc.reason_code in _TOO_LARGE:
        return PayloadTooLarge(exc.message, code=exc.reason_code)
    if exc.reason_code in _UNSUPPORTED:
        return UnsupportedMedia(exc.message, code=exc.reason_code)
    return ValidationProblem(exc.message, code=exc.reason_code)


def check_upload(data: bytes, declared_mime: str | None, settings: Settings) -> FileInfo:
    """Structural validation (no decoding). Polyglot files are refused outright and never stored."""
    info = validate_upload(data, declared_mime, PipelineConfig(max_upload_bytes=settings.max_upload_bytes))
    if (reason := quarantine_reason(info)) is not None:
        raise ImageRejected(
            reason,
            "The file contains additional embedded data (for example an archive, a document or a script) "
            "and was not accepted.",
        )
    return info


@dataclass(frozen=True, slots=True)
class Upload:
    data: bytes
    declared_mime: str | None
    idempotency_key: str
    filename: str | None = None


@dataclass(frozen=True, slots=True)
class Intake:
    image: Image
    created: bool
    duplicate: bool = False


def _clean_filename(name: str | None, inv: Investigation) -> str | None:
    if not name:
        return None
    base = "".join(ch for ch in name.replace("\\", "/").rsplit("/", 1)[-1] if ch.isprintable()).strip()[:200]
    if not base:
        return None
    red = redact_text(base, mode=redaction_mode(inv), context=RedactionContext(source_kind=SourceKind.USER_NOTE))
    return red.text.strip() or None


async def _one(db: AsyncSession, *conditions: Any) -> Image | None:
    return (await db.execute(select(Image).where(*conditions))).scalar_one_or_none()


async def store_upload(
    svc: Services,
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    user: User,
    upload: Upload,
    info: FileInfo,
) -> Intake:
    existing = await _one(db, Image.investigation_id == inv.id, Image.idempotency_key == upload.idempotency_key)
    if existing is not None:
        return Intake(existing, created=False)
    mac = cipher.mac(IMAGE_PURPOSE, bytes.fromhex(info.file_sha256))
    if (dup := await _one(db, Image.investigation_id == inv.id, Image.content_mac == mac)) is not None:
        return Intake(dup, created=False, duplicate=True)
    seq = await next_label(db, inv.id, "image_seq")  # row lock: uploads into one investigation serialize here
    if (dup := await _one(db, Image.investigation_id == inv.id, Image.content_mac == mac)) is not None:
        return Intake(dup, created=False, duplicate=True)
    image_id = new_id()
    key = investigation_object_key(inv.id, "images", image_id)
    file_key = cipher.new_file_key()
    await svc.get("storage").put(key, FieldCipher.encrypt_blob(file_key, upload.data, object_key=key))
    policy = await load_policy(db, svc.settings)
    image = Image(
        id=image_id,
        investigation_id=inv.id,
        label_seq=seq,
        status=ImageStatus.UPLOADED.value,
        filename=cipher.seal_optional(
            _clean_filename(upload.filename, inv), table="images", column="filename", row_id=image_id
        ),
        declared_mime=normalize_mime(upload.declared_mime),
        mime=info.mime,
        byte_size=info.byte_size,
        width=info.width or None,
        height=info.height or None,
        sha256=cipher.seal(info.file_sha256, table="images", column="sha256", row_id=image_id),
        content_mac=mac,
        original_key=key,
        original_file_key=cipher.seal(file_key, table="images", column="original_file_key", row_id=image_id),
        uploaded_by=user.id,
        idempotency_key=upload.idempotency_key,
        # Safety net: originals of uploads that never finish analysis are purged as well.
        original_purge_after=utcnow() + timedelta(hours=policy.image_original_max_hours),
    )
    db.add(image)
    await db.flush()
    await enqueue(
        db,
        queue=JobQueue.ANALYSIS,
        kind="image.scan",
        payload=_payload(image),
        investigation_id=inv.id,
        idempotency_key=f"image-scan:{image.id}",
        max_attempts=SCAN_ATTEMPTS,
        created_by=user.id,
    )
    return Intake(image, created=True)


def pipeline_config(settings: Settings, inv: Investigation, cipher: FieldCipher) -> PipelineConfig:
    return PipelineConfig(
        max_upload_bytes=settings.max_upload_bytes,
        ocr_languages=settings.ocr_languages,
        enable_objects=settings.enable_object_detection,
        sandbox=settings.image_sandbox,
        face_detector=settings.face_detector,
        restricted_mode=inv.restricted_mode,
        device_mac_key=cipher.subkey(DEVICE_PURPOSE),
    )


def original_file_key(cipher: FieldCipher, image: Image) -> bytes:
    return cipher.open_bytes(
        image.original_file_key or b"", table="images", column="original_file_key", row_id=image.id
    )


def preview_file_key(cipher: FieldCipher, image: Image) -> bytes:
    return cipher.open_bytes(image.preview_file_key or b"", table="images", column="preview_file_key", row_id=image.id)


# --------------------------------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------------------------------
def purge_original(db: AsyncSession, image: Image, reason: str) -> None:
    if image.original_key:
        db.add(BlobDeletion(object_key=image.original_key, reason=reason))
    image.original_key, image.original_file_key = None, None
    image.original_purged_at = image.original_purged_at or utcnow()


def delete_files(db: AsyncSession, image: Image, reason: str) -> None:
    """Destroy the original and the preview (keys and blobs); analysis results stay."""
    purge_original(db, image, reason)
    if image.preview_key:
        db.add(BlobDeletion(object_key=image.preview_key, reason=reason))
    image.preview_key, image.preview_file_key = None, None
    image.files_deleted_at = utcnow()
    image.status = ImageStatus.FILES_DELETED.value


def _image_entity_mac(cipher: FieldCipher, image: Image) -> bytes:
    return canonical_mac(cipher, "image", canonicalize("image", f"Image {image_label(image)}"))


async def delete_image(db: AsyncSession, cipher: FieldCipher, inv: Investigation, image: Image) -> EvidenceDeletion:
    """Delete the image and everything derived from it; findings that relied on it are re-checked."""
    delete_files(db, image, "image_deleted")
    evidence = list(
        (
            await db.execute(
                select(EvidenceItem).where(
                    EvidenceItem.investigation_id == inv.id, EvidenceItem.origin_image_id == image.id
                )
            )
        ).scalars()
    )
    stats = await findings.delete_evidence(db, cipher, inv, evidence)
    entity = (
        await db.execute(
            select(Entity).where(
                Entity.investigation_id == inv.id,
                Entity.type == "image",
                Entity.canonical_mac == _image_entity_mac(cipher, image),
            )
        )
    ).scalar_one_or_none()
    if entity is not None:
        linked = await db.execute(
            select(Relationship.id)
            .where((Relationship.from_entity_id == entity.id) | (Relationship.to_entity_id == entity.id))
            .limit(1)
        )
        if linked.first() is None:
            await db.delete(entity)
    await db.delete(image)
    await db.flush()
    return stats


# --------------------------------------------------------------------------------------------------
# Persisting analysis results
# --------------------------------------------------------------------------------------------------
def _stage_output(result: PipelineResult, analyzer: str) -> dict[str, Any] | None:
    if analyzer == "file_info" and result.file_info:
        return asdict(result.file_info)
    if analyzer == "metadata" and result.metadata:
        return asdict(result.metadata)
    if analyzer == "faces" and result.faces:
        return {
            "count": result.faces.count,
            "boxes": [asdict(b) for b in result.faces.boxes],
            "detector": result.faces.detector,
        }
    if analyzer == "ocr" and result.ocr:
        return asdict(result.ocr)
    if analyzer == "objects" and result.objects:
        return asdict(result.objects)
    if analyzer == "preview" and result.preview:
        preview = asdict(result.preview)
        preview.pop("data")
        return preview
    if analyzer == "clues":
        return {"count": len(result.clues)}
    return None


def record_stages(db: AsyncSession, cipher: FieldCipher, image: Image, result: PipelineResult) -> None:
    for report in result.stages:
        output = _stage_output(result, report.analyzer)
        aid = new_id()
        db.add(
            ImageAnalysis(
                id=aid,
                investigation_id=image.investigation_id,
                image_id=image.id,
                analyzer=report.analyzer,
                analyzer_version=report.version,
                status=report.status.value,
                result=cipher.seal_json(output, table="image_analyses", column="result", row_id=aid)
                if output is not None
                else None,
                metrics={"duration_ms": report.duration_ms, "error_code": report.error_code, "warning": report.warning},
            )
        )


async def clear_results(db: AsyncSession, image: Image) -> None:
    for model in (ImageAnalysis, ImageClue, ImageHash):
        await db.execute(delete(model).where(model.image_id == image.id))


def _parse_capture_time(value: str | None) -> tuple[datetime | None, str]:
    if not value:
        return None, "day"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None, "day"
    if parsed.tzinfo is None:  # no offset recorded: the instant is only known to the day
        return parsed.replace(tzinfo=UTC), "day"
    return parsed.astimezone(UTC), "exact"


def metadata_summary(meta: MetadataResult, label: str) -> str | None:
    lines = [f"{title}: {meta.fields[key]}" for key, title in _METADATA_LABELS.items() if meta.fields.get(key)]
    if meta.capture_time:
        lines.append(f"Capture time (embedded metadata): {meta.capture_time}")
    location = meta.location
    if location is not None and location.status != "unresolved" and location.country_name:
        place = ", ".join(p for p in (location.region_name, location.country_name) if p)
        lines.append(f"GPS position present — generalized to {place}; coordinates are not stored")
    elif "gps_coordinates" in meta.redacted_fields:
        lines.append("GPS position present — not stored")
    hidden = [f for f in meta.redacted_fields if f != "gps_coordinates"]
    if hidden:
        lines.append("Identifying fields present but not stored: " + ", ".join(f.replace("_", " ") for f in hidden))
    lines += [f"Edit indicator: {indicator.message}" for indicator in meta.indicators]
    if not lines:
        return None
    return f"Embedded metadata of image {label} ({METADATA_CAVEAT[:-1].lower()}):\n" + "\n".join(lines)


@dataclass(slots=True)
class _Ctx:
    db: AsyncSession
    cipher: FieldCipher
    inv: Investigation
    image: Image
    label: str
    actor_id: uuid.UUID | None
    counts: dict[str, int]
    image_entity: Entity | None = None

    def bump(self, key: str, n: int = 1) -> None:
        self.counts[key] = self.counts.get(key, 0) + n


async def _evidence(
    ctx: _Ctx,
    excerpt: str,
    evidence_type: str,
    extra: dict[str, Any],
    kind: SourceKind,
    pre_redacted: dict[str, int] | None = None,
) -> EvidenceItem | None:
    try:
        added = await add_evidence(
            ctx.db,
            ctx.cipher,
            ctx.inv,
            EvidenceInput(
                excerpt=excerpt,
                evidence_type=evidence_type,
                provenance="observed",
                origin_image_id=ctx.image.id,
                extra=extra,
                source_kind=kind,
                created_by=ctx.actor_id,
                pre_redacted_counts=pre_redacted or {},
            ),
        )
    except ValidationProblem:  # empty after redaction
        return None
    if added.created:
        ctx.bump("evidence")
    return added.item


async def _finding(
    ctx: _Ctx,
    statement: str,
    evidence: EvidenceItem,
    *,
    confidence: str,
    basis: str,
    kind: SourceKind,
    event_time: datetime | None = None,
    precision: str | None = None,
) -> Any:
    if ctx.counts.get("findings", 0) >= MAX_AUTO_FINDINGS:
        return None
    try:
        finding = await findings.create_finding(
            ctx.db,
            ctx.cipher,
            ctx.inv,
            FindingInput(
                statement=statement,
                category="image_analysis",
                provenance="observed",
                links=(LinkInput(evidence.id, directly_states=True),),
                confidence=confidence,
                confidence_basis=basis,
                event_time=event_time,
                event_precision=precision,
                created_via="image_analysis",
                created_by=ctx.actor_id,
                source_kind=kind,
            ),
        )
    except ValidationProblem:
        return None
    ctx.bump("findings")
    return finding


async def _entity(ctx: _Ctx, data: EntityInput) -> Entity | None:
    try:
        entity, created = await upsert_entity(ctx.db, ctx.cipher, ctx.inv, data)
    except EntityError:  # names carrying personal data never become entities
        return None
    if created:
        ctx.bump("entities")
    return entity


async def _edge(
    ctx: _Ctx, rel_type: str, target: Entity | None, evidence: EvidenceItem, confidence: str | None = None
) -> None:
    if ctx.image_entity is None or target is None or target.id == ctx.image_entity.id:
        return
    _, created = await upsert_relationship(
        ctx.db,
        ctx.inv,
        RelationshipInput(
            from_entity_id=ctx.image_entity.id,
            rel_type=rel_type,
            to_entity_id=target.id,
            evidence_ids=(evidence.id,),
            provenance="observed",
            confidence=confidence,
            created_via="image_analysis",
            created_by=ctx.actor_id,
        ),
    )
    if created:
        ctx.bump("relationships")


async def _image_entity(ctx: _Ctx, image: Image, label: str) -> Entity | None:
    return await _entity(
        ctx,
        EntityInput(
            type="image", name=f"Image {label}", attributes={"image_id": str(image.id)}, created_via="image_analysis"
        ),
    )


async def _text_results(ctx: _Ctx, result: PipelineResult) -> None:
    ocr = result.ocr
    if ocr is None or not ocr.text.strip():
        return
    evidence = await _evidence(
        ctx,
        ocr.text,
        "ocr_text",
        {
            "image": ctx.label,
            "engine": "Tesseract 5 (LSTM)",
            "languages": ocr.languages,
            "mean_confidence": round(ocr.mean_confidence, 3),
            "lines": len(ocr.lines),
        },
        SourceKind.OCR,
        dict(ocr.redaction_counts),
    )
    if evidence is None:
        return
    for clue in result.clues:
        if clue.source != "ocr" or clue.type not in _TEXT_FINDINGS:
            continue
        statement = _TEXT_FINDINGS[clue.type].format(label=ctx.label, value=clue.value)
        await _finding(
            ctx, statement, evidence, confidence=clue.confidence, basis=clue.confidence_basis, kind=SourceKind.OCR
        )
        if (entity_type := _CLUE_ENTITIES.get(clue.type)) is not None:
            web = clue.type in (ClueType.URL, ClueType.DOMAIN, ClueType.EMAIL_DOMAIN)
            target = await _entity(
                ctx,
                EntityInput(
                    type=entity_type,
                    name=clue.normalized if web else clue.value,
                    attributes={"platform": clue.platform} if clue.platform else {},
                    created_via="image_analysis",
                ),
            )
            await _edge(ctx, "shows_text", target, evidence, clue.confidence)


async def _metadata_results(ctx: _Ctx, meta: MetadataResult | None) -> None:
    if meta is None or (summary := metadata_summary(meta, ctx.label)) is None:
        return
    evidence = await _evidence(
        ctx,
        summary,
        "metadata",
        {
            "image": ctx.label,
            "availability": meta.availability.value,
            "fields": meta.fields,
            "redacted_fields": list(meta.redacted_fields),
            "caveat": METADATA_CAVEAT,
        },
        SourceKind.METADATA,
    )
    if evidence is None:
        return
    basis = f"Embedded metadata. {METADATA_CAVEAT}"
    camera = " ".join(str(meta.fields[k]) for k in ("camera_make", "camera_model") if meta.fields.get(k))
    if camera:
        await _finding(
            ctx,
            f"Embedded metadata of image {ctx.label} names the camera “{camera}”.",
            evidence,
            confidence="moderate",
            basis=basis,
            kind=SourceKind.METADATA,
        )
    when, precision = _parse_capture_time(meta.capture_time)
    if when is not None:
        finding = await _finding(
            ctx,
            f"Embedded metadata of image {ctx.label} records a capture time of {meta.capture_time}.",
            evidence,
            confidence="low",
            basis=basis,
            kind=SourceKind.METADATA,
            event_time=when,
            precision=precision,
        )
        await create_event(
            ctx.db,
            ctx.cipher,
            ctx.inv,
            EventInput(
                occurred_start=when,
                precision=precision,
                kind="capture_time",
                title=f"Image {ctx.label} capture time (embedded metadata)",
                evidence_ids=(evidence.id,),
                description=CAVEATS["capture_time"],
                finding_id=finding.id if finding is not None else None,
                provenance="observed",
                created_via="image_analysis",
                created_by=ctx.actor_id,
            ),
        )
        ctx.bump("timeline_events")
    location = meta.location
    if location is not None and location.status != "unresolved" and location.country_code:
        place = ", ".join(p for p in (location.region_name, location.country_name) if p)
        await _finding(
            ctx,
            f"Embedded GPS metadata of image {ctx.label} places it in {place} (generalized to region level).",
            evidence,
            confidence="low",
            basis=basis,
            kind=SourceKind.METADATA,
        )
        level = "admin1" if location.region_code else "country"
        target = await _entity(
            ctx,
            EntityInput(
                type="location",
                name=place,
                location_level=level,
                country=location.country_code,
                created_via="image_analysis",
            ),
        )
        await _edge(ctx, "located_in", target, evidence, "low")
    if meta.indicators:
        messages = "; ".join(i.message.rstrip(".") for i in meta.indicators)
        await _finding(
            ctx,
            f"Embedded metadata of image {ctx.label} carries edit indicators: {messages}.",
            evidence,
            confidence="low",
            basis=basis,
            kind=SourceKind.METADATA,
        )


async def _object_results(ctx: _Ctx, result: PipelineResult) -> None:
    objects = result.objects
    if objects is None or not objects.objects:
        return
    best: dict[str, float] = {}
    for obj in objects.objects:
        best[obj.label] = max(best.get(obj.label, 0.0), obj.score)
    listed = ", ".join(f"{label} ({score:.2f})" for label, score in sorted(best.items(), key=lambda kv: -kv[1]))
    await _evidence(
        ctx,
        f"Generic objects detected in image {ctx.label} (NanoDet-Plus, COCO classes): {listed}.",
        "image_clue",
        {"image": ctx.label, "model": objects.model},
        SourceKind.OCR,
    )


async def _duplicates(ctx: _Ctx, result: PipelineResult) -> None:
    h = result.hashes
    if h is None:
        return
    pixel_mac = ctx.cipher.mac(PIXEL_PURPOSE, h.pixel_sha256)
    rows = (
        await ctx.db.execute(
            select(ImageHash, Image)
            .join(Image, Image.id == ImageHash.image_id)
            .where(ImageHash.investigation_id == ctx.inv.id, ImageHash.image_id != ctx.image.id)
            .order_by(Image.label_seq)
        )
    ).all()
    matches = 0
    for other_hash, other in rows:
        if matches >= MAX_MATCHES:
            break
        relation: str | None = "identical"
        if other_hash.pixel_mac != pixel_mac:
            relation = hashing.perceptual_relation(
                h.phash, h.dhash, h.crop_resistant, other_hash.phash, other_hash.dhash, other_hash.crop_resistant
            )
        if relation is None:
            continue
        phrase, confidence, basis = _MATCH_WORDING[relation]
        other_label = image_label(other)
        distance = f"pHash distance {hashing.bits(h.phash, other_hash.phash)} bits"
        evidence = await _evidence(
            ctx,
            f"Image {ctx.label} and image {other_label} {phrase} ({basis.lower()}; {distance}).",
            "image_match",
            {"image": ctx.label, "other_image": other_label, "other_image_id": str(other.id), "relation": relation},
            SourceKind.OCR,
        )
        if evidence is None:
            continue
        matches += 1
        await _finding(
            ctx,
            f"Image {ctx.label} and image {other_label} {phrase}.",
            evidence,
            confidence=confidence,
            basis=basis,
            kind=SourceKind.OCR,
        )
        other_entity = await _image_entity(ctx, other, other_label)
        rel_type = "similar_image_to" if relation == "similar" else "same_image_as"
        await _edge(ctx, rel_type, other_entity, evidence, confidence)
    ctx.counts["matches"] = matches


async def persist_analysis(
    svc: Services, db: AsyncSession, cipher: FieldCipher, inv: Investigation, image: Image, result: PipelineResult
) -> dict[str, int]:
    """Store a successful pipeline result and derive evidence, findings, graph edges and timeline events."""
    label = image_label(image)
    await clear_results(db, image)
    record_stages(db, cipher, image, result)
    if result.hashes is not None:
        h = result.hashes
        db.add(
            ImageHash(
                id=new_id(),
                investigation_id=inv.id,
                image_id=image.id,
                phash=h.phash,
                dhash=h.dhash,
                ahash=h.ahash,
                whash=h.whash,
                colorhash=h.colorhash,
                crop_resistant=h.crop_resistant,
                pixel_mac=cipher.mac(PIXEL_PURPOSE, h.pixel_sha256),
            )
        )
    if result.preview is not None:
        key = investigation_object_key(inv.id, "previews", image.id)
        file_key = cipher.new_file_key()
        await svc.get("storage").put(key, FieldCipher.encrypt_blob(file_key, result.preview.data, object_key=key))
        image.preview_key = key
        image.preview_file_key = cipher.seal(file_key, table="images", column="preview_file_key", row_id=image.id)
    for clue in result.clues:
        _store_clue(db, cipher, image, clue)
    meta = result.metadata
    info = result.file_info
    if info is not None and info.width:
        image.width, image.height = info.width, info.height
    image.face_count = result.faces.count if result.faces else 0
    image.person_count = result.objects.person_count if result.objects else 0
    image.metadata_availability = meta.availability.value if meta else None
    image.capture_time = _parse_capture_time(meta.capture_time)[0] if meta else None
    if meta is not None and meta.location is not None and meta.location.country_code:
        image.country, image.region = meta.location.country_code, meta.location.region_code
    await db.flush()

    ctx = _Ctx(db, cipher, inv, image, label, image.uploaded_by, {"clues": len(result.clues)})
    ctx.image_entity = await _image_entity(ctx, image, label)
    await _text_results(ctx, result)
    await _metadata_results(ctx, meta)
    await _object_results(ctx, result)
    await _duplicates(ctx, result)

    now = utcnow()
    policy = await load_policy(db, svc.settings)
    hours = policy.image_original_hours_for(inv)
    image.status = ImageStatus.ANALYZED.value
    image.analysis_completed_at = now
    image.original_purge_after = now + timedelta(hours=hours)
    if hours == 0:
        purge_original(db, image, "image_original_retention")
        image.status = ImageStatus.ORIGINAL_PURGED.value
    await db.flush()
    return ctx.counts


def _store_clue(db: AsyncSession, cipher: FieldCipher, image: Image, clue: Clue, provenance: str = "observed") -> None:
    cid = new_id()
    db.add(
        ImageClue(
            id=cid,
            investigation_id=image.investigation_id,
            image_id=image.id,
            clue_type=clue.type.value,
            value=cipher.seal(clue.value, table="image_clues", column="value", row_id=cid),
            normalized=cipher.seal(clue.normalized, table="image_clues", column="normalized", row_id=cid),
            normalized_mac=cipher.mac(CLUE_PURPOSE, f"{clue.type.value}|{clue.normalized}"),
            tokens=tokens(cipher, clue.value),
            bbox=asdict(clue.box) if clue.box else None,
            confidence=clue.confidence,
            confidence_basis=clue.confidence_basis,
            provenance=provenance,
            source=clue.source,
            platform=clue.platform,
            precision=clue.precision,
        )
    )


def clue_view(cipher: FieldCipher, clue: ImageClue) -> dict[str, Any]:
    return {
        "id": str(clue.id),
        "image_id": str(clue.image_id),
        "type": clue.clue_type,
        "value": cipher.open(clue.value, table="image_clues", column="value", row_id=clue.id),
        "normalized": cipher.open(clue.normalized, table="image_clues", column="normalized", row_id=clue.id),
        "source": clue.source,
        "confidence": clue.confidence,
        "confidence_basis": clue.confidence_basis,
        "provenance": clue.provenance,
        "box": clue.bbox,
        "platform": clue.platform,
        "precision": clue.precision,
        "promoted_evidence_id": str(clue.promoted_evidence_id) if clue.promoted_evidence_id else None,
    }


# --------------------------------------------------------------------------------------------------
# Public-occurrence search gate
# --------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class SearchGate:
    allowed: bool
    reason: str | None = None
    code: str | None = None
    needs_approval: bool = False


def search_gate(inv: Investigation, image: Image, *, external: bool = True) -> SearchGate:
    """Reverse/similar-image search: never in restricted mode, only with a supervisor's recorded approval when
    faces or people were detected, and — for external providers — only with a sanitized preview.
    ``external=False`` gates look-ups of local duplicates in the user's other investigations."""
    if inv.restricted_mode:
        return SearchGate(
            False, "Reverse image search is not available in restricted mode (individual subject).", "restricted_mode"
        )
    if image.status not in ANALYZED_STATUSES:
        return SearchGate(False, "The image has not been analyzed yet.", "not_analyzed")
    if external and image.preview_key is None:
        return SearchGate(False, "The image has no sanitized preview (its files were deleted).", "preview_missing")
    if (image.face_count > 0 or image.person_count > 0) and image.reverse_search_approved_by is None:
        return SearchGate(
            False,
            "Faces or people were detected. A supervisor must approve reverse image search with a recorded purpose; "
            "it never identifies people.",
            "approval_required",
            needs_approval=True,
        )
    return SearchGate(True)


# --------------------------------------------------------------------------------------------------
# Public-occurrence results (reported by a provider)
# --------------------------------------------------------------------------------------------------
_MATCH_PHRASES = {
    "matching_copy": "a matching copy of",
    "exact": "a full copy of",
    "partial": "a partial copy of",
    "similar": "an image visually similar to",
}


async def persist_occurrences(
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    image: Image,
    result: OccurrenceResult,
    *,
    provider_name: str,
    run_id: uuid.UUID,
    actor_id: uuid.UUID | None,
) -> dict[str, int]:
    """Matches become sources with source-reported evidence and unverified findings; logos and landmarks
    become AI-hypothesis clues. Nothing here is treated as established fact."""
    label = image_label(image)
    ctx = _Ctx(db, cipher, inv, image, label, actor_id, {})
    ctx.image_entity = await _image_entity(ctx, image, label)
    earliest: tuple[datetime, EvidenceItem, str] | None = None
    for match in result.matches:
        try:
            upsert = await upsert_source(
                db,
                cipher,
                inv,
                SourceInput(
                    url=match.page_url,
                    category="public_image_sources",
                    connector_id=result.provider,
                    title=match.page_title,
                    access_status="reference_only",
                    created_by=actor_id,
                ),
            )
        except (UrlError, ValidationProblem):
            continue
        source = upsert.source
        phrase = _MATCH_PHRASES.get(match.match_type, "a match for")
        details = [f"{provider_name} reports {phrase} image {label} on this page ({source.host})"]
        if match.image_url:
            details.append(f"image file: {match.image_url}")
        if match.crawl_date:
            details.append(f"first crawled {match.crawl_date.date().isoformat()}")
        if match.score is not None:
            details.append(f"match score {match.score:g}")
        try:
            added = await add_evidence(
                db,
                cipher,
                inv,
                EvidenceInput(
                    excerpt="; ".join(details) + ".",
                    evidence_type="image_match",
                    provenance="source_reported",
                    source_id=source.id,
                    origin_image_id=image.id,
                    collection_run_id=run_id,
                    created_by=actor_id,
                    extra={
                        "provider": result.provider,
                        "match_type": match.match_type,
                        "image_url": match.image_url,
                        "score": match.score,
                        "crawl_date": match.crawl_date.isoformat() if match.crawl_date else None,
                    },
                ),
            )
        except ValidationProblem:
            continue
        if not added.created:
            continue
        ctx.bump("evidence")
        statement = f"{provider_name} reports {phrase} image {label} on {source.host}."
        try:
            await findings.create_finding(
                db,
                cipher,
                inv,
                FindingInput(
                    statement=statement,
                    category="public_image_sources",
                    provenance="source_reported",
                    links=(LinkInput(added.item.id, directly_states=True),),
                    created_via="connector",
                    created_by=actor_id,
                    source_kind=SourceKind.WEB,
                ),
            )
            ctx.bump("findings")
        except ValidationProblem:
            pass
        if match.match_type != "similar":
            site = await _entity(
                ctx, EntityInput(type="website", name=source.registrable_domain, created_via="connector")
            )
            if site is not None and ctx.image_entity is not None:
                _, created = await upsert_relationship(
                    db,
                    inv,
                    RelationshipInput(
                        from_entity_id=ctx.image_entity.id,
                        rel_type="hosted_on",
                        to_entity_id=site.id,
                        evidence_ids=(added.item.id,),
                        provenance="source_reported",
                        created_via="connector",
                        created_by=actor_id,
                    ),
                )
                if created:
                    ctx.bump("relationships")
        if match.crawl_date and (earliest is None or match.crawl_date < earliest[0]):
            earliest = (match.crawl_date, added.item, source.host)
    if earliest is not None:
        when, evidence, host = earliest
        await create_event(
            db,
            cipher,
            inv,
            EventInput(
                occurred_start=when,
                precision="day",
                kind="first_archived",
                title=f"{provider_name} first crawled a copy of image {label} ({host})",
                evidence_ids=(evidence.id,),
                description=CAVEATS["first_archived"],
                provenance="source_reported",
                created_via="connector",
                created_by=actor_id,
            ),
        )
        ctx.bump("timeline_events")
    for visual in result.labels:
        await _visual_label(ctx, visual, provider_name)
    return ctx.counts


async def _visual_label(ctx: _Ctx, visual: VisualLabel, provider_name: str) -> None:
    kind = "logo" if visual.kind == "brand" else "landmark"
    basis = f"{provider_name} {kind} detection score {visual.score:.2f}"
    confidence = "high" if visual.score >= 0.85 else "moderate" if visual.score >= 0.6 else "low"
    clue_type = ClueType.BRAND if visual.kind == "brand" else ClueType.LANDMARK
    mac = ctx.cipher.mac(CLUE_PURPOSE, f"{clue_type.value}|{visual.name.casefold()}")
    exists = await ctx.db.execute(
        select(ImageClue.id).where(ImageClue.image_id == ctx.image.id, ImageClue.normalized_mac == mac)
    )
    if exists.first() is None:
        clue = Clue(
            type=clue_type,
            value=visual.name,
            normalized=visual.name.casefold(),
            source="provider",
            confidence=confidence,
            confidence_basis=basis,
        )
        _store_clue(ctx.db, ctx.cipher, ctx.image, clue, provenance="ai_hypothesis")
        ctx.bump("clues")
    evidence = await _evidence_reported(
        ctx,
        f"{provider_name} reports the {kind} “{visual.name}” in image {ctx.label} (score {visual.score:.2f}).",
        {"provider": provider_name, "kind": kind, "score": visual.score},
    )
    if evidence is None:
        return
    try:
        await findings.create_finding(
            ctx.db,
            ctx.cipher,
            ctx.inv,
            FindingInput(
                statement=f"{provider_name} suggests that image {ctx.label} shows the {kind} “{visual.name}”.",
                category="image_analysis",
                provenance="ai_hypothesis",
                links=(LinkInput(evidence.id),),
                created_via="image_analysis",
                created_by=ctx.actor_id,
                source_kind=SourceKind.WEB,
            ),
        )
        ctx.bump("findings")
    except ValidationProblem:
        pass
    target = await _entity(ctx, EntityInput(type=visual.kind, name=visual.name, created_via="image_analysis"))
    if target is not None and ctx.image_entity is not None:
        _, created = await upsert_relationship(
            ctx.db,
            ctx.inv,
            RelationshipInput(
                from_entity_id=ctx.image_entity.id,
                rel_type="depicts",
                to_entity_id=target.id,
                evidence_ids=(evidence.id,),
                provenance="ai_hypothesis",
                confidence=confidence,
                created_via="image_analysis",
                created_by=ctx.actor_id,
            ),
        )
        if created:
            ctx.bump("relationships")


async def _evidence_reported(ctx: _Ctx, excerpt: str, extra: dict[str, Any]) -> EvidenceItem | None:
    try:
        added = await add_evidence(
            ctx.db,
            ctx.cipher,
            ctx.inv,
            EvidenceInput(
                excerpt=excerpt,
                evidence_type="image_clue",
                provenance="source_reported",
                origin_image_id=ctx.image.id,
                extra=extra,
                source_kind=SourceKind.WEB,
                created_by=ctx.actor_id,
            ),
        )
    except ValidationProblem:
        return None
    if added.created:
        ctx.bump("evidence")
    return added.item
