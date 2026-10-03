"""Reports: cited drafts rebuilt from verified data, a sandboxed preview, finalization (locked, hashed and anchored
in the audit log) and expiring exports (HTML, Markdown, JSON, PDF) whose download needs a recent sign-in."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from angel_engine.api.deps import InvCtx, enforce_rate_limit, investigation_scope, require_recent_reauth
from angel_engine.api.v1.routers._common import IfMatch, ReadCtx, WriteCtx, get_scoped, require_version
from angel_engine.authz.permissions import Perm
from angel_engine.core.clock import utcnow
from angel_engine.core.problems import ConflictState, NotFound
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.db.models import Report, ReportExport
from angel_engine.infra.ratelimit.gcra import EXPORTS_USER
from angel_engine.reports import service
from angel_engine.reports.render import EXTENSIONS, MEDIA_TYPES, render_html

router = APIRouter(tags=["reports"])
BASE = "/investigations/{investigation_id}/reports"
ExportCtx = Annotated[InvCtx, Depends(investigation_scope(Perm.REPORT_EXPORT))]
PREVIEW_CSP = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'self'"


class Paragraph(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    refs: list[str] = Field(default_factory=list, max_length=20)


class CustomSection(BaseModel):
    title: str = Field(max_length=200)
    paragraphs: list[Paragraph] = Field(default_factory=list, max_length=30)


class ReportOptions(BaseModel):
    sections: list[str] | None = None
    confidentiality: Literal["Confidential", "Internal", "Restricted"] | None = None
    ai_interaction_id: uuid.UUID | None = None


class ReportIn(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    options: ReportOptions = Field(default_factory=ReportOptions)
    custom_sections: list[CustomSection] = Field(default_factory=list, max_length=10)
    acknowledge_policy_notices: bool = False


class ReportPatch(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=300)
    options: ReportOptions | None = None
    custom_sections: list[CustomSection] | None = Field(default=None, max_length=10)
    acknowledge_policy_notices: bool = False


class ReportSummary(BaseModel):
    id: str
    title: str
    status: str
    version: int
    generated_at: datetime | None
    finalized_at: datetime | None
    final_sha256: str | None
    audit_seq: int | None
    created_by_me: bool
    created_at: datetime
    updated_at: datetime


class ReportOut(ReportSummary):
    options: dict[str, Any]
    custom_sections: list[dict[str, Any]]
    document: dict[str, Any] | None
    lint: dict[str, int]
    verified: bool | None


class ExportIn(BaseModel):
    format: Literal["html", "markdown", "json", "pdf"]


class ExportOut(BaseModel):
    id: str
    report_id: str
    format: str
    status: str
    byte_size: int | None
    sha256: str | None
    expires_at: datetime
    downloaded_at: datetime | None
    created_at: datetime
    poll_after_ms: int | None


def _summary(cipher: FieldCipher, report: Report, ctx: InvCtx) -> dict[str, Any]:
    return {
        "id": str(report.id),
        "title": service.title_of(cipher, report),
        "status": report.status,
        "version": report.version,
        "generated_at": report.generated_at,
        "finalized_at": report.finalized_at,
        "final_sha256": report.final_sha256,
        "audit_seq": report.audit_seq,
        "created_by_me": report.created_by == ctx.principal.user_id,
        "created_at": report.created_at,
        "updated_at": report.updated_at,
    }


async def _out(ctx: InvCtx, report: Report, response: Response | None = None) -> ReportOut:
    await ctx.db.flush()
    cipher = await ctx.cipher()
    doc = service.read_document(cipher, report)
    stats = doc.stats if doc else {}
    lint = {
        k: int(stats.get(k, 0)) for k in ("uncited_custom_paragraphs", "moved_without_evidence", "ai_uncited_segments")
    }
    if response is not None:
        response.headers["ETag"] = f'"{report.version}"'
    return ReportOut(
        **_summary(cipher, report, ctx),
        options=dict(report.options or {}),
        custom_sections=service.inputs_of(cipher, report).custom_sections,
        document=doc.as_dict() if doc else None,
        lint=lint,
        verified=service.verify(cipher, report) if report.status == "final" else None,
    )


def _export_out(export: ReportExport) -> ExportOut:
    return ExportOut(
        id=str(export.id),
        report_id=str(export.report_id),
        format=export.format,
        status="expired" if export.status == "ready" and export.expires_at <= utcnow() else export.status,
        byte_size=export.byte_size,
        sha256=export.sha256,
        expires_at=export.expires_at,
        downloaded_at=export.downloaded_at,
        created_at=export.created_at,
        poll_after_ms=1000 if export.status == "pending" else None,
    )


def _sections(items: list[CustomSection] | None) -> list[dict[str, Any]] | None:
    return None if items is None else [s.model_dump() for s in items]


@router.post(BASE, status_code=201)
async def create_report(body: ReportIn, ctx: WriteCtx, response: Response) -> ReportOut:
    cipher = await ctx.cipher()
    report, _ = await service.create_report(
        ctx.principal.services,
        ctx.db,
        cipher,
        ctx.investigation,
        ctx.principal.user,
        title=body.title,
        options=body.options.model_dump(mode="json", exclude_none=True),
        custom_sections=_sections(body.custom_sections) or [],
        acknowledge=body.acknowledge_policy_notices,
        actor_event=ctx.principal.event(""),
    )
    ctx.audit("report.created", target_type="report", target_id=str(report.id))
    return await _out(ctx, report, response)


@router.get(BASE)
async def list_reports(ctx: ReadCtx) -> list[ReportSummary]:
    cipher = await ctx.cipher()
    rows = (
        await ctx.db.execute(
            select(Report).where(Report.investigation_id == ctx.id).order_by(Report.created_at.desc()).limit(100)
        )
    ).scalars()
    return [ReportSummary(**_summary(cipher, r, ctx)) for r in rows]


@router.get(BASE + "/{report_id}")
async def get_report(report_id: uuid.UUID, ctx: ReadCtx, response: Response) -> ReportOut:
    return await _out(ctx, await get_scoped(ctx.db, Report, ctx, report_id), response)


@router.patch(BASE + "/{report_id}")
async def update_report(
    report_id: uuid.UUID, body: ReportPatch, ctx: WriteCtx, response: Response, if_match: IfMatch = None
) -> ReportOut:
    report = await get_scoped(ctx.db, Report, ctx, report_id)
    require_version(if_match, report.version)
    if report.status != "draft":
        raise ConflictState("Final reports are locked.", code="report_final")
    svc, cipher = ctx.principal.services, await ctx.cipher()
    inputs = service.inputs_of(cipher, report)
    if body.title is not None:
        from angel_engine.evidence.service import redaction_mode
        from angel_engine.guard import RedactionContext, SourceKind, redact_text

        title = redact_text(
            " ".join(body.title.split()),
            mode=redaction_mode(ctx.investigation),
            context=RedactionContext(source_kind=SourceKind.USER_NOTE),
        ).text
        report.title = cipher.seal(title, table="reports", column="title", row_id=report.id)
    if body.options is not None:
        report.options = service.clean_options(body.options.model_dump(mode="json", exclude_none=True))
    if body.custom_sections is not None:
        inputs.custom_sections = await service.clean_custom_sections(
            svc,
            ctx.db,
            ctx.principal.user,
            ctx.investigation,
            _sections(body.custom_sections),
            acknowledge=body.acknowledge_policy_notices,
            actor_event=ctx.principal.event(""),
        )
    await service.rebuild(svc, ctx.db, cipher, ctx.investigation, report, inputs)
    ctx.audit("report.updated", target_type="report", target_id=str(report.id))
    return await _out(ctx, report, response)


@router.post(BASE + "/{report_id}/refresh")
async def refresh_report(report_id: uuid.UUID, ctx: WriteCtx, response: Response) -> ReportOut:
    """Rebuild a draft from the investigation's current evidence and verification statuses."""
    report = await get_scoped(ctx.db, Report, ctx, report_id)
    await service.rebuild(ctx.principal.services, ctx.db, await ctx.cipher(), ctx.investigation, report)
    return await _out(ctx, report, response)


@router.delete(BASE + "/{report_id}")
async def delete_report(report_id: uuid.UUID, ctx: WriteCtx) -> dict[str, str]:
    report = await get_scoped(ctx.db, Report, ctx, report_id)
    if report.status == "final":
        raise ConflictState("Final reports cannot be deleted.", code="report_final")
    await ctx.db.delete(report)
    ctx.audit("report.deleted", target_type="report", target_id=str(report_id))
    return {"status": "deleted"}


@router.post(BASE + "/{report_id}/finalize")
async def finalize_report(
    report_id: uuid.UUID, ctx: WriteCtx, response: Response, if_match: IfMatch = None
) -> ReportOut:
    """Lock the report: rebuild once more, hash it, record the hash in the audit log. This cannot be undone."""
    report = await get_scoped(ctx.db, Report, ctx, report_id)
    require_version(if_match, report.version)
    await service.finalize(
        ctx.principal.services,
        ctx.db,
        await ctx.cipher(),
        ctx.investigation,
        report,
        ctx.principal.user,
        ctx.principal.event(
            "report.finalized", investigation_id=ctx.id, target_type="report", target_id=str(report.id)
        ),
    )
    return await _out(ctx, report, response)


@router.get(
    BASE + "/{report_id}/preview",
    response_class=Response,
    responses={200: {"content": {"text/html": {"schema": {"type": "string"}}}}},
)
async def preview_report(report_id: uuid.UUID, ctx: ReadCtx) -> Response:
    """Self-contained HTML for a sandboxed frame (no scripts, no external resources)."""
    report = await get_scoped(ctx.db, Report, ctx, report_id)
    doc = service.read_document(await ctx.cipher(), report)
    if doc is None:
        raise NotFound("The report has not been built yet.", code="report_not_built")
    return Response(
        content=render_html(doc),
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Security-Policy": PREVIEW_CSP,
            "X-Frame-Options": "SAMEORIGIN",
            "Cache-Control": "private, no-store",
        },
    )


@router.post(BASE + "/{report_id}/exports", status_code=202)
async def create_export(report_id: uuid.UUID, body: ExportIn, ctx: ExportCtx) -> ExportOut:
    require_recent_reauth(ctx.principal)
    await enforce_rate_limit(ctx.principal.services, f"export:user:{ctx.principal.user_id}", EXPORTS_USER)
    report = await get_scoped(ctx.db, Report, ctx, report_id)
    export = await service.request_export(
        ctx.principal.services, ctx.db, ctx.investigation, report, ctx.principal.user, body.format
    )
    ctx.audit(
        "report.export_requested",
        target_type="report",
        target_id=str(report.id),
        details={"format": body.format, "status": report.status},
    )
    return _export_out(export)


@router.get(BASE + "/{report_id}/exports")
async def list_exports(report_id: uuid.UUID, ctx: ReadCtx) -> list[ExportOut]:
    report = await get_scoped(ctx.db, Report, ctx, report_id)
    rows = (
        await ctx.db.execute(
            select(ReportExport).where(ReportExport.report_id == report.id).order_by(ReportExport.created_at.desc())
        )
    ).scalars()
    return [_export_out(e) for e in rows]


@router.get(
    BASE + "/{report_id}/exports/{export_id}/download",
    response_class=Response,
    responses={200: {"content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}}},
)
async def download_export(report_id: uuid.UUID, export_id: uuid.UUID, ctx: ExportCtx) -> Response:
    require_recent_reauth(ctx.principal)
    export = await get_scoped(ctx.db, ReportExport, ctx, export_id)
    if export.report_id != report_id:
        raise NotFound()
    if export.status != "ready" or export.expires_at <= utcnow() or not export.object_key or not export.file_key:
        raise ConflictState("This export is not available (still rendering, failed or expired).", code="export_gone")
    cipher = await ctx.cipher()
    file_key = cipher.open_bytes(export.file_key, table="report_exports", column="file_key", row_id=export.id)
    blob = await ctx.principal.services.get("storage").get(export.object_key)
    content = FieldCipher.decrypt_blob(file_key, blob, object_key=export.object_key)
    export.downloaded_at = utcnow()
    ctx.audit(
        "report.downloaded", target_type="report_export", target_id=str(export.id), details={"format": export.format}
    )
    report = await get_scoped(ctx.db, Report, ctx, report_id)
    name = f"{ctx.investigation.public_ref}-report-{str(report.id)[:8]}.{EXTENSIONS[export.format]}"
    return Response(
        content=content,
        media_type=MEDIA_TYPES[export.format],
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "Cache-Control": "private, no-store",
            "X-Content-SHA256": export.sha256 or "",
        },
    )
