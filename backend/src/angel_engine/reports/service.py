"""Reports: drafts rebuilt from current data, finalization and expiring exports.

* A draft is rebuilt from the investigation's current state whenever it is created, edited or refreshed.
* Finalizing rebuilds one last time, hashes the canonical document (SHA-256), computes a keyed integrity code,
  anchors the hash in the audit chain and locks the row (a database trigger refuses later changes).
* Exports (HTML, Markdown, JSON, PDF) are rendered by a worker, encrypted with a per-object key and expire after
  the export retention window; downloading needs a recent re-authentication.

Custom analyst sections are screened by the acceptable-use policy, redacted, and stored only inside the encrypted
report body.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import asdict
from datetime import timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.app_state import Services
from angel_engine.audit.chain import AuditEvent, append_now
from angel_engine.core.canonical_json import canonical_bytes
from angel_engine.core.clock import utcnow
from angel_engine.core.enums import JobQueue
from angel_engine.core.ids import new_id
from angel_engine.core.problems import ConflictState, ValidationProblem
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.db.models import Investigation, Report, ReportExport, User
from angel_engine.evidence.service import redaction_mode
from angel_engine.guard import RedactionContext, SourceKind, redact_text
from angel_engine.jobs.queue import enqueue
from angel_engine.policy.types import PolicyContext, Surface
from angel_engine.policy_gate import require_acknowledgement, screen
from angel_engine.reports.document import (
    ALL_SECTIONS,
    CONFIDENTIALITY,
    Inputs,
    ReportDocument,
    build_document,
    document_from_dict,
)

FINAL_PURPOSE = "ae/report-final/v1"
FORMATS = ("html", "markdown", "json", "pdf")
MAX_CUSTOM_SECTIONS = 10
MAX_PARAGRAPHS = 30


def clean_options(options: dict[str, Any] | None) -> dict[str, Any]:
    options = dict(options or {})
    out: dict[str, Any] = {}
    sections = options.get("sections")
    if sections is not None:
        if not isinstance(sections, list) or not set(sections) <= set(ALL_SECTIONS):
            raise ValidationProblem("Unknown report section.", code="invalid_sections")
        out["sections"] = list(dict.fromkeys(sections))
    if options.get("confidentiality") is not None:
        if options["confidentiality"] not in CONFIDENTIALITY:
            raise ValidationProblem("Unknown confidentiality marking.", code="invalid_confidentiality")
        out["confidentiality"] = options["confidentiality"]
    if options.get("ai_interaction_id"):
        out["ai_interaction_id"] = str(options["ai_interaction_id"])
    return out


async def clean_custom_sections(
    svc: Services,
    db: AsyncSession,
    user: User,
    inv: Investigation,
    sections: list[dict[str, Any]] | None,
    *,
    acknowledge: bool,
    actor_event: AuditEvent | None,
) -> list[dict[str, Any]]:
    """Screen and redact analyst-written sections; references are kept as labels and resolved at build time."""
    out: list[dict[str, Any]] = []
    mode, ctx = redaction_mode(inv), RedactionContext(source_kind=SourceKind.USER_NOTE)
    for section in (sections or [])[:MAX_CUSTOM_SECTIONS]:
        title = " ".join(str(section.get("title") or "").split())[:200]
        paragraphs = []
        for paragraph in list(section.get("paragraphs") or [])[:MAX_PARAGRAPHS]:
            text = " ".join(str(paragraph.get("text") or "").split())[:5000]
            if not text:
                continue
            result, _ = await screen(
                svc,
                db,
                user,
                text,
                PolicyContext(
                    surface=Surface.REPORT_SECTION, subject_type=inv.subject_type, restricted_mode=inv.restricted_mode
                ),
                investigation_id=inv.id,
                target_type="report",
                actor_event=actor_event,
            )
            require_acknowledgement(result, acknowledge)
            refs = [str(r)[:20] for r in list(paragraph.get("refs") or [])[:20]]
            paragraphs.append({"text": redact_text(text, mode=mode, context=ctx).text, "refs": refs})
        if title or paragraphs:
            out.append(
                {"title": redact_text(title, mode=mode, context=ctx).text or "Analyst notes", "paragraphs": paragraphs}
            )
    return out


def _body(cipher: FieldCipher, report: Report) -> dict[str, Any]:
    if report.body is None:
        return {}
    return cipher.open_json(report.body, table="reports", column="body", row_id=report.id)  # type: ignore[no-any-return]


def inputs_of(cipher: FieldCipher, report: Report) -> Inputs:
    return Inputs(**_body(cipher, report).get("inputs", {}))


def read_document(cipher: FieldCipher, report: Report) -> ReportDocument | None:
    body = _body(cipher, report)
    return document_from_dict(body["document"]) if body.get("document") else None


def title_of(cipher: FieldCipher, report: Report) -> str:
    return cipher.open(report.title, table="reports", column="title", row_id=report.id)


def _store(cipher: FieldCipher, report: Report, inputs: Inputs, doc: ReportDocument) -> None:
    report.body = cipher.seal_json(
        {"inputs": asdict(inputs), "document": doc.as_dict()}, table="reports", column="body", row_id=report.id
    )
    report.generated_at = utcnow()


async def rebuild(
    svc: Services,
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    report: Report,
    inputs: Inputs | None = None,
    *,
    status: str | None = None,
) -> ReportDocument:
    if report.status == "final":
        raise ConflictState("Final reports are locked.", code="report_final")
    inputs = inputs if inputs is not None else inputs_of(cipher, report)
    doc = await build_document(
        db,
        cipher,
        svc.settings,
        inv,
        report_id=report.id,
        title=title_of(cipher, report),
        status=status or report.status,
        options=report.options,
        inputs=inputs,
    )
    _store(cipher, report, inputs, doc)
    return doc


async def create_report(
    svc: Services,
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    user: User,
    *,
    title: str,
    options: dict[str, Any] | None,
    custom_sections: list[dict[str, Any]],
    acknowledge: bool,
    actor_event: AuditEvent | None,
) -> tuple[Report, ReportDocument]:
    clean_title = redact_text(
        " ".join(title.split())[:300],
        mode=redaction_mode(inv),
        context=RedactionContext(source_kind=SourceKind.USER_NOTE),
    ).text
    if not clean_title:
        raise ValidationProblem("The title is empty after redaction.", code="empty_title")
    sections = await clean_custom_sections(
        svc, db, user, inv, custom_sections, acknowledge=acknowledge, actor_event=actor_event
    )
    report_id = new_id()
    report = Report(
        id=report_id,
        investigation_id=inv.id,
        title=cipher.seal(clean_title, table="reports", column="title", row_id=report_id),
        status="draft",
        options=clean_options(options),
        created_by=user.id,
    )
    db.add(report)
    await db.flush()
    doc = await rebuild(svc, db, cipher, inv, report, Inputs(custom_sections=sections))
    await db.flush()
    return report, doc


def canonical_document(doc: ReportDocument) -> bytes:
    data = doc.as_dict()
    data.pop("integrity", None)
    return canonical_bytes(data)


async def finalize(
    svc: Services,
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    report: Report,
    user: User,
    event: AuditEvent,
) -> ReportDocument:
    if report.status != "draft":
        raise ConflictState("This report is already final.", code="report_final")
    inputs = inputs_of(cipher, report)
    doc = await rebuild(svc, db, cipher, inv, report, inputs, status="final")
    canonical = canonical_document(doc)
    sha = hashlib.sha256(canonical).hexdigest()
    mac = cipher.mac(FINAL_PURPOSE, canonical)
    event.details = {**event.details, "sha256": sha}
    seq = await append_now(db, svc.audit_key, [event])
    now = utcnow()
    doc.integrity = {
        "sha256": sha,
        "mac_prefix": mac.hex()[:32],
        "audit_seq": seq,
        "finalized_at": now.strftime("%Y-%m-%d %H:%M:%S"),
    }
    _store(cipher, report, inputs, doc)
    report.status, report.final_mac, report.final_sha256 = "final", mac, sha
    report.audit_seq, report.finalized_by, report.finalized_at = seq, user.id, now
    await db.flush()
    return doc


def verify(cipher: FieldCipher, report: Report) -> bool:
    """True when a final report's stored content still matches its hash and integrity code."""
    doc = read_document(cipher, report)
    if report.status != "final" or doc is None or report.final_mac is None:
        return False
    canonical = canonical_document(doc)
    return hashlib.sha256(canonical).hexdigest() == report.final_sha256 and hmac.compare_digest(
        cipher.mac(FINAL_PURPOSE, canonical), report.final_mac
    )


async def request_export(
    svc: Services, db: AsyncSession, inv: Investigation, report: Report, user: User, fmt: str
) -> ReportExport:
    if fmt not in FORMATS:
        raise ValidationProblem("Unknown export format.", code="invalid_format")
    export = ReportExport(
        id=new_id(),
        investigation_id=inv.id,
        report_id=report.id,
        format=fmt,
        status="pending",
        expires_at=utcnow() + timedelta(hours=svc.settings.export_retention_hours),
        created_by=user.id,
    )
    db.add(export)
    await db.flush()
    await enqueue(
        db,
        queue=JobQueue.ANALYSIS,
        kind="report.export",
        payload={"export_id": str(export.id), "investigation_id": str(inv.id)},
        investigation_id=inv.id,
        idempotency_key=f"report-export:{export.id}",
        max_attempts=2,
        created_by=user.id,
    )
    return export


__all__ = [
    "FORMATS",
    "canonical_document",
    "clean_options",
    "create_report",
    "finalize",
    "inputs_of",
    "read_document",
    "rebuild",
    "request_export",
    "title_of",
    "verify",
]
