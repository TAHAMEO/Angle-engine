"""Image analysis: raw-body uploads, status and results, the sanitized preview, visual clues (promote / pivot),
duplicates, the reverse-image-search approval gate and deletion.

Upload notice (shown by every client before upload): "Upload only images you are legally authorized to
investigate. Angel Engine does not perform facial identification." Responses for images in which a face was
detected carry the notice "A face was detected in the image. Angel Engine does not perform facial
identification." Originals are never served; only the server-side sanitized preview is.
"""

from __future__ import annotations

import math
import uuid
from datetime import datetime
from typing import Annotated, Any, Literal
from urllib.parse import unquote

from fastapi import APIRouter, Header, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select, text

from angel_engine.api.deps import InvCtx, audit_separately, enforce_rate_limit, require_recent_reauth
from angel_engine.api.v1.routers._common import ReadCtx, WriteCtx, get_scoped
from angel_engine.api.v1.routers.collection import RunOut, run_out
from angel_engine.authz.permissions import Perm, role_allows
from angel_engine.core.enums import ImageStatus, InvestigationStatus, JobQueue
from angel_engine.core.ids import new_id
from angel_engine.core.problems import (
    BadRequest,
    ConflictState,
    Forbidden,
    LengthRequired,
    NotFound,
    PayloadTooLarge,
    ValidationProblem,
)
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.db.models import (
    CollectionRun,
    EvidenceItem,
    Finding,
    FindingEvidence,
    Image,
    ImageAnalysis,
    ImageClue,
    ImageHash,
    Job,
)
from angel_engine.db.models import Investigation as InvestigationRow
from angel_engine.db.models import InvestigationMember as MemberRow
from angel_engine.db.session import set_investigation_scope
from angel_engine.evidence.service import EvidenceInput, add_evidence
from angel_engine.findings import service as findings
from angel_engine.findings.service import FindingInput, LinkInput
from angel_engine.guard import SourceKind
from angel_engine.images import hashing
from angel_engine.images import service as images
from angel_engine.images.errors import ImageRejected
from angel_engine.images.providers import provider_status
from angel_engine.images.types import FACE_NOTICE, UPLOAD_NOTICE
from angel_engine.infra.ratelimit.gcra import (
    COLLECTION_INVESTIGATION,
    COLLECTION_USER,
    UPLOAD_MIB_USER,
    UPLOADS_USER,
)
from angel_engine.jobs.queue import enqueue
from angel_engine.osint import collection
from angel_engine.policy.types import PolicyContext, Surface
from angel_engine.policy_gate import screen

router = APIRouter(tags=["images"])
BASE = "/investigations/{investigation_id}/images"
MIB = 1024 * 1024
MIN_APPROVAL_PURPOSE = 30
STATUS_LABELS = {
    ImageStatus.UPLOADED.value: "Uploaded — waiting for the malware scan",
    ImageStatus.SCANNING.value: "Scanning for malware",
    ImageStatus.CLEAN.value: "Waiting for analysis",
    ImageStatus.INFECTED.value: "Rejected — the malware scan flagged this file; it was deleted",
    ImageStatus.QUARANTINED.value: "Rejected — the file contains embedded data; it was deleted",
    ImageStatus.SCAN_FAILED.value: "The file could not be scanned; it was deleted",
    ImageStatus.ANALYZING.value: "Analyzing",
    ImageStatus.ANALYZED.value: "Analyzed",
    ImageStatus.ANALYSIS_FAILED.value: "Analysis failed",
    ImageStatus.ORIGINAL_PURGED.value: "Analyzed — original deleted after the retention period",
    ImageStatus.FILES_DELETED.value: "Image files deleted — analysis results kept",
}
#: Clue type → collection input type for pivots (dates, objects and metadata fields are not searchable).
PIVOT_INPUTS = {
    "domain": "domain",
    "email_domain": "domain",
    "url": "url",
    "username": "username",
    "organization": "organization",
    "brand": "organization",
    "visible_text": "keyword",
    "hashtag": "keyword",
    "sign": "keyword",
    "landmark": "keyword",
    "public_location": "place",
}
_UPLOAD_BODY = {
    "required": True,
    "content": {
        mime: {"schema": {"type": "string", "format": "binary"}}
        for mime in ("image/jpeg", "image/png", "image/gif", "image/webp", "image/tiff", "image/bmp")
    },
}


# --------------------------------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------------------------------
class ScanOut(BaseModel):
    engine: str | None
    signature: str | None
    completed_at: datetime | None
    degraded: bool


class SearchGateOut(BaseModel):
    allowed: bool
    reason: str | None
    code: str | None
    needs_approval: bool
    approved: bool


class ImageOut(BaseModel):
    id: str
    label: str
    status: str
    status_label: str
    filename: str | None
    mime: str | None
    byte_size: int
    width: int | None
    height: int | None
    created_at: datetime
    uploaded_by_me: bool
    scan: ScanOut
    analysis_started_at: datetime | None
    analysis_completed_at: datetime | None
    face_count: int
    person_count: int
    notices: list[str]
    metadata_availability: str | None
    capture_time: datetime | None
    country: str | None
    region: str | None
    has_preview: bool
    original_retained: bool
    original_purge_after: datetime | None
    original_purged_at: datetime | None
    files_deleted_at: datetime | None
    quarantine_reason: str | None
    reverse_search: SearchGateOut
    progress: dict[str, Any] = {}


class UploadOut(ImageOut):
    duplicate: bool = False
    upload_notice: str = UPLOAD_NOTICE


class StageOut(BaseModel):
    analyzer: str
    version: str
    status: str
    duration_ms: int | None
    error_code: str | None


class LinkedItem(BaseModel):
    id: str
    label: str
    kind: str
    verification_status: str | None = None


class ImageDetail(ImageOut):
    stages: list[StageOut]
    metadata: dict[str, Any] | None
    ocr: dict[str, Any] | None
    ocr_hidden: bool
    objects: list[dict[str, Any]]
    face_boxes: list[dict[str, Any]]
    evidence: list[LinkedItem]
    findings: list[LinkedItem]


class PivotOption(BaseModel):
    connector_id: str
    name: str
    input_type: str
    needs_purpose_note: bool


class ClueOut(BaseModel):
    id: str
    image_id: str
    type: str
    value: str
    normalized: str
    source: str
    confidence: str
    confidence_basis: str
    provenance: str
    box: dict[str, Any] | None
    platform: str | None
    precision: str | None
    promoted_evidence_id: str | None
    pivots: list[PivotOption]


class PromoteIn(BaseModel):
    statement: str | None = Field(default=None, min_length=10, max_length=1000)
    importance: Literal["key", "normal"] = "normal"


class PromoteOut(BaseModel):
    evidence_id: str
    evidence_label: str
    finding_id: str
    finding_label: str


class PivotIn(BaseModel):
    connector_id: str = Field(max_length=64)
    purpose_note: str | None = Field(default=None, max_length=1000)
    acknowledge_policy_notices: bool = False


class MatchOut(BaseModel):
    image_id: str
    label: str
    relation: str
    phash_distance: int
    investigation_id: str
    investigation_ref: str
    same_investigation: bool


class SimilarOut(BaseModel):
    matches: list[MatchOut]
    cross_investigation: SearchGateOut


class ApprovalIn(BaseModel):
    purpose: str = Field(min_length=MIN_APPROVAL_PURPOSE, max_length=2000)


class OccurrenceIn(BaseModel):
    provider: Literal["tineye", "google_vision"]


# --------------------------------------------------------------------------------------------------
# Views
# --------------------------------------------------------------------------------------------------
def _gate(inv: InvestigationRow, image: Image, *, external: bool = True) -> SearchGateOut:
    gate = images.search_gate(inv, image, external=external)
    return SearchGateOut(
        allowed=gate.allowed,
        reason=gate.reason,
        code=gate.code,
        needs_approval=gate.needs_approval,
        approved=image.reverse_search_approved_by is not None,
    )


async def _progress(ctx: InvCtx, image: Image) -> dict[str, Any]:
    if image.status not in (ImageStatus.SCANNING.value, ImageStatus.ANALYZING.value):
        return {}
    kind = "image-scan" if image.status == ImageStatus.SCANNING.value else "image-analyze"
    progress = (
        await ctx.db.execute(select(Job.progress).where(Job.idempotency_key == f"{kind}:{image.id}"))
    ).scalar_one_or_none()
    return dict(progress or {})


async def _out(ctx: InvCtx, image: Image, cls: type[ImageOut] = ImageOut, **extra: Any) -> Any:
    cipher = await ctx.cipher()
    return cls(
        id=str(image.id),
        label=images.image_label(image),
        status=image.status,
        status_label=STATUS_LABELS.get(image.status, image.status),
        filename=cipher.open_optional(image.filename, table="images", column="filename", row_id=image.id),
        mime=image.mime,
        byte_size=image.byte_size,
        width=image.width,
        height=image.height,
        created_at=image.created_at,
        uploaded_by_me=image.uploaded_by == ctx.principal.user_id,
        scan=ScanOut(
            engine=image.scan_engine,
            signature=image.scan_signature,
            completed_at=image.scan_completed_at,
            degraded=image.scan_engine == "builtin",
        ),
        analysis_started_at=image.analysis_started_at,
        analysis_completed_at=image.analysis_completed_at,
        face_count=image.face_count,
        person_count=image.person_count,
        notices=images.notices(image),
        metadata_availability=image.metadata_availability,
        capture_time=image.capture_time,
        country=image.country,
        region=image.region,
        has_preview=image.preview_key is not None,
        original_retained=image.original_key is not None,
        original_purge_after=image.original_purge_after if image.original_key else None,
        original_purged_at=image.original_purged_at,
        files_deleted_at=image.files_deleted_at,
        quarantine_reason=image.quarantine_reason,
        reverse_search=_gate(ctx.investigation, image),
        progress=await _progress(ctx, image),
        **extra,
    )


async def _analyses(ctx: InvCtx, cipher: FieldCipher, image: Image) -> dict[str, tuple[ImageAnalysis, Any]]:
    rows = (await ctx.db.execute(select(ImageAnalysis).where(ImageAnalysis.image_id == image.id))).scalars().all()
    out: dict[str, tuple[ImageAnalysis, Any]] = {}
    for row in rows:
        result = (
            cipher.open_json(row.result, table="image_analyses", column="result", row_id=row.id) if row.result else None
        )
        out[row.analyzer] = (row, result)
    return out


async def _detail(ctx: InvCtx, image: Image, *, reveal_sensitive: bool = False) -> ImageDetail:
    cipher = await ctx.cipher()
    analyses = await _analyses(ctx, cipher, image)
    order = ("file_info", "decode", "hashing", "metadata", "faces", "ocr", "objects", "preview", "clues", "sandbox")
    stages = [
        StageOut(
            analyzer=name,
            version=row.analyzer_version,
            status=row.status,
            duration_ms=row.metrics.get("duration_ms"),
            error_code=row.metrics.get("error_code"),
        )
        for name in order
        if name in analyses
        for row, _ in [analyses[name]]
    ]
    metadata = analyses.get("metadata", (None, None))[1]
    if metadata is not None:
        metadata.pop("device_fingerprints", None)  # keyed fingerprints are internal
    ocr = analyses.get("ocr", (None, None))[1]
    hidden = bool(ocr and ocr.get("flags")) and not reveal_sensitive
    if hidden and ocr is not None:
        ocr = {k: v for k, v in ocr.items() if k not in ("text", "lines")}
    objects = (analyses.get("objects", (None, None))[1] or {}).get("objects", [])
    faces = analyses.get("faces", (None, None))[1] or {}
    evidence_rows = (
        await ctx.db.execute(
            select(EvidenceItem)
            .where(EvidenceItem.investigation_id == ctx.id, EvidenceItem.origin_image_id == image.id)
            .order_by(EvidenceItem.label_seq)
        )
    ).scalars()
    evidence = [LinkedItem(id=str(e.id), label=f"E-{e.label_seq}", kind=e.evidence_type) for e in evidence_rows]
    finding_rows = (
        await ctx.db.execute(
            select(Finding)
            .join(FindingEvidence, FindingEvidence.finding_id == Finding.id)
            .join(EvidenceItem, EvidenceItem.id == FindingEvidence.evidence_id)
            .where(EvidenceItem.origin_image_id == image.id, Finding.investigation_id == ctx.id)
            .order_by(Finding.label_seq)
        )
    ).scalars()
    linked = [
        LinkedItem(id=str(f.id), label=f"F-{f.label_seq}", kind=f.category, verification_status=f.verification_status)
        for f in dict.fromkeys(finding_rows)
    ]
    return await _out(  # type: ignore[no-any-return]
        ctx,
        image,
        ImageDetail,
        stages=stages,
        metadata=metadata,
        ocr=ocr,
        ocr_hidden=hidden,
        objects=objects,
        face_boxes=faces.get("boxes", []),
        evidence=evidence,
        findings=linked,
    )


def _pivots(ctx: InvCtx, clue_type: str) -> list[PivotOption]:
    input_type = PIVOT_INPUTS.get(clue_type)
    reg = ctx.principal.services.get("connectors")
    if input_type is None or reg is None:
        return []
    out = []
    for connector in reg.all():
        info = connector.info
        if input_type not in {t.value for t in info.input_types} or reg.status(connector).status != "ready":
            continue
        if ctx.investigation.restricted_mode and not info.allowed_in_restricted_mode:
            continue
        out.append(
            PivotOption(
                connector_id=info.id, name=info.name, input_type=input_type, needs_purpose_note=info.person_oriented
            )
        )
    return out


# --------------------------------------------------------------------------------------------------
# Upload
# --------------------------------------------------------------------------------------------------
async def _read_body(request: Request, limit: int) -> bytes:
    raw_length = request.headers.get("content-length")
    if raw_length is None:
        raise LengthRequired("A Content-Length header is required for uploads.")
    try:
        declared = int(raw_length)
    except ValueError as exc:
        raise BadRequest("Invalid Content-Length header.", code="invalid_content_length") from exc
    if declared > limit:
        raise PayloadTooLarge(f"Images may be at most {limit // MIB} MiB.", code="too_large")
    if declared <= 0:
        raise ValidationProblem("The file is empty.", code="empty")
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > declared:
            raise BadRequest("The upload is longer than its Content-Length.", code="length_mismatch")
    if len(body) != declared:
        raise BadRequest("The upload ended early.", code="incomplete_upload")
    return bytes(body)


@router.post(BASE, status_code=201, openapi_extra={"requestBody": _UPLOAD_BODY})
async def upload_image(
    request: Request,
    response: Response,
    ctx: WriteCtx,
    idempotency_key: Annotated[str, Header(min_length=8, max_length=100)],
    content_type: Annotated[str | None, Header(max_length=100)] = None,
    x_filename: Annotated[str | None, Header(max_length=1000)] = None,
) -> UploadOut:
    """Upload one image as the raw request body (no multipart). The file is validated without decoding,
    encrypted, malware-scanned and then analyzed in a sandbox; poll the image until it is ``analyzed``."""
    svc = ctx.principal.services
    await enforce_rate_limit(svc, f"upload:user:{ctx.principal.user_id}", UPLOADS_USER)
    data = await _read_body(request, svc.settings.max_upload_bytes)
    await enforce_rate_limit(
        svc, f"upload-mib:user:{ctx.principal.user_id}", UPLOAD_MIB_USER, cost=max(1, math.ceil(len(data) / MIB))
    )
    try:
        info = images.check_upload(data, content_type, svc.settings)
    except ImageRejected as exc:
        await audit_separately(
            svc,
            ctx.principal.event(
                "image.upload_rejected",
                outcome="failure",
                investigation_id=ctx.id,
                details={"reason": exc.reason_code, "bytes": len(data)},
            ),
        )
        raise images.rejection_problem(exc) from exc
    filename = unquote(x_filename) if x_filename else None
    cipher = await ctx.cipher()
    intake = await images.store_upload(
        svc,
        ctx.db,
        cipher,
        ctx.investigation,
        ctx.principal.user,
        images.Upload(data=data, declared_mime=content_type, idempotency_key=idempotency_key, filename=filename),
        info,
    )
    if intake.created:
        ctx.audit(
            "image.uploaded",
            target_type="image",
            target_id=str(intake.image.id),
            details={"mime": info.mime, "bytes": info.byte_size},
        )
    else:
        response.status_code = 200
    return await _out(ctx, intake.image, UploadOut, duplicate=intake.duplicate)  # type: ignore[no-any-return]


# --------------------------------------------------------------------------------------------------
# Read
# --------------------------------------------------------------------------------------------------
@router.get(BASE)
async def list_images(
    ctx: ReadCtx,
    status: Annotated[list[str] | None, Query()] = None,
    has_faces: bool | None = None,
) -> list[ImageOut]:
    stmt = select(Image).where(Image.investigation_id == ctx.id)
    if status:
        stmt = stmt.where(Image.status.in_(status))
    if has_faces is not None:
        stmt = stmt.where(Image.face_count > 0 if has_faces else Image.face_count == 0)
    rows = (await ctx.db.execute(stmt.order_by(Image.created_at.desc()).limit(200))).scalars().all()
    return [await _out(ctx, image) for image in rows]


@router.get(BASE + "/{image_id}")
async def get_image(image_id: uuid.UUID, ctx: ReadCtx, reveal_sensitive: bool = False) -> ImageDetail:
    image = await get_scoped(ctx.db, Image, ctx, image_id)
    if reveal_sensitive:
        ctx.audit("image.sensitive_revealed", target_type="image", target_id=str(image.id))
    return await _detail(ctx, image, reveal_sensitive=reveal_sensitive)


@router.get(
    BASE + "/{image_id}/preview",
    response_class=Response,
    responses={200: {"content": {"image/jpeg": {"schema": {"type": "string", "format": "binary"}}}}},
)
async def get_preview(image_id: uuid.UUID, ctx: ReadCtx) -> Response:
    """The sanitized preview: faces and sensitive text masked, no metadata. Originals are never served."""
    image = await get_scoped(ctx.db, Image, ctx, image_id)
    if image.preview_key is None or image.preview_file_key is None:
        raise NotFound("No preview is available for this image.", code="preview_unavailable")
    cipher = await ctx.cipher()
    key = image.preview_key
    blob = await ctx.principal.services.get("storage").get(key)
    data = FieldCipher.decrypt_blob(images.preview_file_key(cipher, image), blob, object_key=key)
    return Response(
        content=data,
        media_type="image/jpeg",
        headers={
            "Content-Disposition": f'inline; filename="{images.image_label(image)}-preview.jpg"',
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "private, no-store",
        },
    )


@router.get(BASE + "/{image_id}/clues")
async def list_clues(image_id: uuid.UUID, ctx: ReadCtx) -> list[ClueOut]:
    image = await get_scoped(ctx.db, Image, ctx, image_id)
    cipher = await ctx.cipher()
    rows = (
        (await ctx.db.execute(select(ImageClue).where(ImageClue.image_id == image.id).order_by(ImageClue.created_at)))
        .scalars()
        .all()
    )
    return [ClueOut(**images.clue_view(cipher, c), pivots=_pivots(ctx, c.clue_type)) for c in rows]


# --------------------------------------------------------------------------------------------------
# Clue actions
# --------------------------------------------------------------------------------------------------
async def _clue(ctx: InvCtx, image_id: uuid.UUID, clue_id: uuid.UUID) -> tuple[Image, ImageClue]:
    image = await get_scoped(ctx.db, Image, ctx, image_id)
    clue = await get_scoped(ctx.db, ImageClue, ctx, clue_id)
    if clue.image_id != image.id:
        raise NotFound()
    return image, clue


@router.post(BASE + "/{image_id}/clues/{clue_id}/promote", status_code=201)
async def promote_clue(image_id: uuid.UUID, clue_id: uuid.UUID, body: PromoteIn, ctx: WriteCtx) -> PromoteOut:
    """Record a visual clue as observed evidence with an (unverified) finding."""
    image, clue = await _clue(ctx, image_id, clue_id)
    cipher = await ctx.cipher()
    view = images.clue_view(cipher, clue)
    label = images.image_label(image)
    if body.statement:
        await screen(
            ctx.principal.services,
            ctx.db,
            ctx.principal.user,
            body.statement,
            PolicyContext(
                surface=Surface.IMAGE_NOTE,
                subject_type=ctx.investigation.subject_type,
                restricted_mode=ctx.investigation.restricted_mode,
                face_count=image.face_count,
            ),
            investigation_id=ctx.id,
            target_type="finding",
            actor_event=ctx.principal.event(""),
        )
    kind = view["type"].replace("_", " ")
    reported = clue.provenance == "ai_hypothesis"  # e.g. a logo reported by a vision provider
    excerpt = f"Visual clue in image {label} ({kind}, from {view['source']}): {view['value']}"
    added = await add_evidence(
        ctx.db,
        cipher,
        ctx.investigation,
        EvidenceInput(
            excerpt=excerpt,
            evidence_type="image_clue",
            provenance="source_reported" if reported else "observed",
            origin_image_id=image.id,
            extra={
                "image": label,
                "clue_type": view["type"],
                "confidence_basis": view["confidence_basis"],
                "box": view["box"],
            },
            source_kind=SourceKind.OCR,
            created_by=ctx.principal.user_id,
        ),
    )
    statement = body.statement or f"Image {label} shows the {kind} “{view['value']}”."
    finding = await findings.create_finding(
        ctx.db,
        cipher,
        ctx.investigation,
        FindingInput(
            statement=statement,
            category="image_analysis",
            provenance="ai_hypothesis" if reported else "observed",
            links=(LinkInput(added.item.id, directly_states=True),),
            confidence=view["confidence"],
            confidence_basis=view["confidence_basis"],
            importance=body.importance,
            created_via="image_analysis",
            created_by=ctx.principal.user_id,
            source_kind=SourceKind.USER_NOTE if body.statement else SourceKind.OCR,
        ),
    )
    clue.promoted_evidence_id = added.item.id
    ctx.audit(
        "image.clue_promoted",
        target_type="image_clue",
        target_id=str(clue.id),
        details={"evidence_id": str(added.item.id), "finding_id": str(finding.id)},
    )
    return PromoteOut(
        evidence_id=str(added.item.id),
        evidence_label=f"E-{added.item.label_seq}",
        finding_id=str(finding.id),
        finding_label=f"F-{finding.label_seq}",
    )


@router.post(BASE + "/{image_id}/clues/{clue_id}/pivot", status_code=202)
async def pivot_clue(image_id: uuid.UUID, clue_id: uuid.UUID, body: PivotIn, ctx: WriteCtx) -> RunOut:
    """Search public sources for a clue. Runs through the same policy screening as any collection query."""
    image, clue = await _clue(ctx, image_id, clue_id)
    input_type = PIVOT_INPUTS.get(clue.clue_type)
    if input_type is None:
        raise ConflictState("This kind of clue cannot be searched.", code="not_searchable")
    cipher = await ctx.cipher()
    view = images.clue_view(cipher, clue)
    query = view["normalized"] if input_type in ("domain", "url") else view["value"].lstrip("@#")
    run, decision = await collection.create_run(
        ctx.principal.services,
        ctx.db,
        cipher,
        ctx.investigation,
        ctx.principal.user,
        connector_id=body.connector_id,
        input_type=input_type,
        query=query,
        purpose_note=body.purpose_note,
        acknowledge_policy_notices=body.acknowledge_policy_notices,
        origin_image_id=image.id,
        origin_clue_id=clue.id,
        actor_event=ctx.principal.event(""),
    )
    ctx.audit(
        "collection.requested",
        target_type="collection_run",
        target_id=str(run.id),
        details={
            "connector": run.connector_id,
            "input_type": input_type,
            "status": run.status,
            "policy": decision.value,
            "origin": "image_clue",
            "query_ref": collection.query_fingerprint(cipher, query),
        },
    )
    return await run_out(ctx, run)


# --------------------------------------------------------------------------------------------------
# Duplicates and the reverse-search gate
# --------------------------------------------------------------------------------------------------
async def _readable_investigations(ctx: InvCtx) -> list[InvestigationRow]:
    rows = (
        await ctx.db.execute(
            select(InvestigationRow)
            .join(MemberRow, MemberRow.investigation_id == InvestigationRow.id)
            .where(
                MemberRow.user_id == ctx.principal.user_id,
                InvestigationRow.id != ctx.id,
                InvestigationRow.status != InvestigationStatus.DELETED.value,
                InvestigationRow.restricted_mode.is_(False),
            )
            .limit(200)
        )
    ).scalars()
    return list(rows)


@router.get(BASE + "/{image_id}/similar")
async def similar_images(image_id: uuid.UUID, ctx: ReadCtx) -> SimilarOut:
    """Identical, near-duplicate and similar images in this investigation and — when allowed — in the other
    investigations you are a member of (never restricted-mode ones)."""
    image = await get_scoped(ctx.db, Image, ctx, image_id)
    own = (await ctx.db.execute(select(ImageHash).where(ImageHash.image_id == image.id))).scalar_one_or_none()
    gate = _gate(ctx.investigation, image, external=False)
    if own is None:
        return SimilarOut(matches=[], cross_investigation=gate)
    scope = [ctx.id]
    others: dict[uuid.UUID, InvestigationRow] = {}
    if gate.allowed:
        others = {inv.id: inv for inv in await _readable_investigations(ctx)}
        scope += list(others)
    await set_investigation_scope(ctx.db, scope)
    try:
        rows = (
            await ctx.db.execute(
                select(ImageHash, Image)
                .join(Image, Image.id == ImageHash.image_id)
                .where(
                    ImageHash.investigation_id.in_(scope),
                    ImageHash.image_id != image.id,
                    text(
                        "(bit_count((image_hashes.phash # :phash)::bit(64)) <= :limit"
                        " OR image_hashes.investigation_id = :inv)"
                    ).bindparams(phash=own.phash, limit=hashing.SIMILAR_PHASH, inv=ctx.id),
                )
                .limit(500)
            )
        ).all()
    finally:
        await set_investigation_scope(ctx.db, [ctx.id])
    matches: list[MatchOut] = []
    for other_hash, other in rows:
        same = other_hash.investigation_id == ctx.id
        relation: str | None = "identical" if same and other_hash.pixel_mac == own.pixel_mac else None
        if relation is None:
            relation = hashing.perceptual_relation(
                own.phash, own.dhash, own.crop_resistant, other_hash.phash, other_hash.dhash, other_hash.crop_resistant
            )
        if relation is None:
            continue
        inv = ctx.investigation if same else others.get(other_hash.investigation_id)
        if inv is None:
            continue
        matches.append(
            MatchOut(
                image_id=str(other.id),
                label=images.image_label(other),
                relation=relation,
                phash_distance=hashing.bits(own.phash, other_hash.phash),
                investigation_id=str(inv.id),
                investigation_ref=inv.public_ref,
                same_investigation=same,
            )
        )
    order = {"identical": 0, "near_duplicate": 1, "similar": 2}
    matches.sort(key=lambda m: (not m.same_investigation, order[m.relation], m.phash_distance))
    return SimilarOut(matches=matches[:50], cross_investigation=gate)


@router.post(BASE + "/{image_id}/reverse-search-approval")
async def approve_reverse_search(image_id: uuid.UUID, body: ApprovalIn, ctx: ReadCtx) -> ImageOut:
    """A supervisor (not the uploader) allows reverse/similar-image search for an image in which faces or people
    were detected, with a recorded purpose. Searches still use only the sanitized preview and never identify
    anyone."""
    image = await get_scoped(ctx.db, Image, ctx, image_id)
    if not role_allows(ctx.principal.role, Perm.POLICY_REVIEW):
        raise Forbidden("A supervisor must approve this.", code="supervisor_required")
    if image.uploaded_by == ctx.principal.user_id:
        raise Forbidden("You cannot approve a search for an image you uploaded.", code="self_review")
    if ctx.investigation.status != InvestigationStatus.ACTIVE.value:
        raise ConflictState("The investigation is not active.", code="investigation_state")
    if ctx.investigation.restricted_mode:
        raise ConflictState("Reverse image search is never available in restricted mode.", code="restricted_mode")
    if image.face_count == 0 and image.person_count == 0:
        raise ConflictState("No faces or people were detected; no approval is needed.", code="approval_not_needed")
    await screen(
        ctx.principal.services,
        ctx.db,
        ctx.principal.user,
        body.purpose,
        PolicyContext(
            surface=Surface.IMAGE_NOTE,
            subject_type=ctx.investigation.subject_type,
            restricted_mode=ctx.investigation.restricted_mode,
            face_count=image.face_count,
        ),
        investigation_id=ctx.id,
        target_type="image",
        actor_event=ctx.principal.event(""),
    )
    cipher = await ctx.cipher()
    image.reverse_search_approved_by = ctx.principal.user_id
    image.reverse_search_purpose = cipher.seal(
        body.purpose.strip(), table="images", column="reverse_search_purpose", row_id=image.id
    )
    ctx.audit(
        "image.reverse_search_approved",
        target_type="image",
        target_id=str(image.id),
        details={"faces": image.face_count, "persons": image.person_count},
    )
    return await _out(ctx, image)  # type: ignore[no-any-return]


@router.post(BASE + "/{image_id}/public-occurrence-search", status_code=202)
async def public_occurrence_search(
    image_id: uuid.UUID,
    body: OccurrenceIn,
    ctx: WriteCtx,
    idempotency_key: Annotated[str | None, Header(max_length=100)] = None,
) -> RunOut:
    """Ask a reverse-image provider where else the image appears. Only the sanitized preview is sent; the search is
    refused in restricted mode and, when faces or people were detected, until a supervisor approved it."""
    svc = ctx.principal.services
    image = await get_scoped(ctx.db, Image, ctx, image_id)
    if idempotency_key:
        existing = (
            await ctx.db.execute(
                select(CollectionRun).where(
                    CollectionRun.investigation_id == ctx.id, CollectionRun.idempotency_key == idempotency_key
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return await run_out(ctx, existing)
    gate = images.search_gate(ctx.investigation, image)
    if not gate.allowed:
        raise ConflictState(gate.reason, code=gate.code or "search_not_allowed")
    state, reason = provider_status(svc.settings, body.provider)
    if state != "ready":
        raise ConflictState(reason, code=f"provider_{state}")
    await enforce_rate_limit(svc, f"collect:user:{ctx.principal.user_id}", COLLECTION_USER)
    await enforce_rate_limit(svc, f"collect:inv:{ctx.id}", COLLECTION_INVESTIGATION)
    cipher = await ctx.cipher()
    run_id = new_id()
    label = images.image_label(image)
    run = CollectionRun(
        id=run_id,
        investigation_id=ctx.id,
        connector_id=body.provider,
        input_type="image",
        query=cipher.seal(f"Image {label} (sanitized preview)", table="collection_runs", column="query", row_id=run_id),
        status="queued",
        requested_by=ctx.principal.user_id,
        origin_image_id=image.id,
        idempotency_key=idempotency_key,
    )
    ctx.db.add(run)
    await ctx.db.flush()
    await enqueue(
        ctx.db,
        queue=JobQueue.EGRESS,
        kind="image.public_search",
        payload={"run_id": str(run.id), "image_id": str(image.id), "investigation_id": str(ctx.id)},
        investigation_id=ctx.id,
        created_by=ctx.principal.user_id,
        idempotency_key=f"run:{run.id}",
        max_attempts=1,  # paid searches are never repeated automatically
    )
    ctx.audit(
        "image.public_search_requested",
        target_type="image",
        target_id=str(image.id),
        details={
            "provider": body.provider,
            "run_id": str(run.id),
            "faces": image.face_count,
            "persons": image.person_count,
            "approved": image.reverse_search_approved_by is not None,
        },
    )
    return await run_out(ctx, run)


# --------------------------------------------------------------------------------------------------
# Deletion
# --------------------------------------------------------------------------------------------------
@router.delete(BASE + "/{image_id}")
async def delete_image(
    image_id: uuid.UUID, ctx: WriteCtx, scope: Annotated[Literal["file", "all"], Query()] = "file"
) -> dict[str, Any]:
    """``scope=file`` deletes the original and the preview (results stay); ``scope=all`` also deletes every result
    derived from the image — evidence, edges and timeline events — and re-checks affected findings."""
    require_recent_reauth(ctx.principal)
    image = await get_scoped(ctx.db, Image, ctx, image_id)
    if image.status in (ImageStatus.SCANNING.value, ImageStatus.ANALYZING.value):
        raise ConflictState("Wait until the scan or analysis has finished.", code="image_busy")
    cipher = await ctx.cipher()
    if scope == "file":
        images.delete_files(ctx.db, image, "image_files_deleted")
        ctx.audit("image.files_deleted", target_type="image", target_id=str(image.id))
        return {"status": "files_deleted", "image_id": str(image.id)}
    stats = await images.delete_image(ctx.db, cipher, ctx.investigation, image)
    ctx.audit("image.deleted", target_type="image", target_id=str(image_id), details=stats.as_dict())
    return {"status": "deleted", "image_id": str(image_id), **stats.as_dict()}


__all__ = ["FACE_NOTICE", "UPLOAD_NOTICE", "router"]
