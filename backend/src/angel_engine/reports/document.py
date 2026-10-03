"""Report documents: a structured, citation-checked snapshot of an investigation.

``build_document`` gathers the investigation's data and lays it out in sections — overview, methodology, evidence
summary, important findings, contradictions, unverified claims, AI hypotheses, timeline, relationships, sources,
images, limitations and privacy considerations. Every factual block carries references (F-/E-/S- labels):

* findings without remaining evidence and custom paragraphs without valid references are moved to
  "Unverified claims" (never presented as established);
* AI material appears only under "AI hypotheses", labelled, with uncited sentences marked as AI commentary;
* faces are only ever mentioned as "detected, not identified"; no precise locations or personal data appear
  (all text was redacted on the way in).
"""

from __future__ import annotations

import re
import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.ai.types import INSUFFICIENT, UNCITED_LABEL
from angel_engine.config import Settings
from angel_engine.core.clock import utcnow
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.db.models import (
    AIInteraction,
    CollectionRun,
    Entity,
    EvidenceItem,
    Finding,
    FindingEvidence,
    Image,
    ImageAnalysis,
    Investigation,
    Relationship,
    RelationshipEvidence,
    Source,
    TimelineEvent,
    TimelineEventEvidence,
)
from angel_engine.entities.service import entity_name
from angel_engine.images.types import FACE_NOTICE
from angel_engine.retention.policy import load_policy

MAX_ROWS = 500
SECTION_TITLES = {
    "overview": "Overview",
    "methodology": "Methodology",
    "evidence_summary": "Evidence summary",
    "important_findings": "Important findings",
    "contradictions": "Contradictions",
    "unverified_claims": "Unverified claims",
    "ai_hypotheses": "AI hypotheses",
    "timeline": "Timeline",
    "relationships": "Relationships",
    "sources": "Sources",
    "images": "Images",
    "limitations": "Limitations",
    "privacy": "Privacy considerations",
}
ALL_SECTIONS = tuple(SECTION_TITLES)
#: Sections that may be switched off; the rest are always present.
OPTIONAL_SECTIONS = frozenset({"timeline", "relationships", "images", "ai_hypotheses", "unverified_claims"})
STATUS_LABELS = {
    "confirmed_by_source": "Confirmed by source",
    "corroborated": "Corroborated",
    "unverified": "Unverified",
    "contradicted": "Contradicted",
    "ai_hypothesis": "AI hypothesis",
}
PROVENANCE_LABELS = {
    "observed": "Observed",
    "source_reported": "Source-reported",
    "analyst_inference": "Analyst inference",
    "ai_hypothesis": "AI hypothesis",
}
CONFIDENTIALITY = ("Confidential", "Internal", "Restricted")
_REF = re.compile(r"^\s*([FES])\s*-\s*(\d{1,9})\s*$", re.IGNORECASE)


@dataclass(slots=True)
class Ref:
    kind: str  # finding | evidence | source
    id: str
    label: str


@dataclass(slots=True)
class Block:
    type: str  # paragraph | finding | table | list | notice | facts | ai_segment
    text: str | None = None
    refs: list[Ref] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Section:
    key: str
    title: str
    blocks: list[Block] = field(default_factory=list)


@dataclass(slots=True)
class ReportDocument:
    report_id: str
    title: str
    investigation_ref: str
    investigation_title: str
    status: str
    generated_at: str
    confidentiality: str
    restricted_mode: bool
    sections: list[Section]
    stats: dict[str, int]
    integrity: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Inputs:
    """User-chosen content: kept (encrypted) with the report body and reused on every rebuild."""

    custom_sections: list[dict[str, Any]] = field(default_factory=list)


def _date(value: datetime | None) -> str | None:
    return value.date().isoformat() if value else None


def _when(value: datetime | None) -> str | None:
    return value.isoformat(timespec="minutes") if value else None


class _Data:
    """Everything the report needs, decrypted once."""

    def __init__(self, cipher: FieldCipher, inv: Investigation) -> None:
        self.cipher, self.inv = cipher, inv
        self.findings: list[Finding] = []
        self.statements: dict[uuid.UUID, str] = {}
        self.bases: dict[uuid.UUID, str | None] = {}
        self.links: dict[uuid.UUID, list[FindingEvidence]] = {}
        self.evidence: dict[uuid.UUID, EvidenceItem] = {}
        self.sources: dict[uuid.UUID, Source] = {}
        self.images: dict[uuid.UUID, Image] = {}

    def open(self, value: bytes | None, table: str, column: str, row_id: uuid.UUID) -> str | None:
        return self.cipher.open_optional(value, table=table, column=column, row_id=row_id)

    def evidence_ref(self, evidence_id: uuid.UUID) -> Ref | None:
        item = self.evidence.get(evidence_id)
        return Ref("evidence", str(evidence_id), f"E-{item.label_seq}") if item else None

    def source_ref(self, source_id: uuid.UUID | None) -> Ref | None:
        source = self.sources.get(source_id) if source_id else None
        return Ref("source", str(source.id), f"S-{source.label_seq}") if source else None

    def origin(self, item: EvidenceItem) -> str:
        if item.source_id and item.source_id in self.sources:
            return self.sources[item.source_id].host
        image = self.images.get(item.origin_image_id) if item.origin_image_id else None
        return f"image I-{image.label_seq}" if image else "unknown origin"


async def _gather(db: AsyncSession, cipher: FieldCipher, inv: Investigation) -> _Data:
    data = _Data(cipher, inv)
    data.findings = list(
        (
            await db.execute(
                select(Finding).where(Finding.investigation_id == inv.id).order_by(Finding.label_seq).limit(2000)
            )
        ).scalars()
    )
    for finding in data.findings:
        data.statements[finding.id] = data.open(finding.statement, "findings", "statement", finding.id) or ""
        data.bases[finding.id] = data.open(finding.confidence_basis, "findings", "confidence_basis", finding.id)
    for link in (await db.execute(select(FindingEvidence).where(FindingEvidence.investigation_id == inv.id))).scalars():
        data.links.setdefault(link.finding_id, []).append(link)
    for item in (
        await db.execute(select(EvidenceItem).where(EvidenceItem.investigation_id == inv.id).limit(5000))
    ).scalars():
        data.evidence[item.id] = item
    for source in (await db.execute(select(Source).where(Source.investigation_id == inv.id).limit(5000))).scalars():
        data.sources[source.id] = source
    for image in (await db.execute(select(Image).where(Image.investigation_id == inv.id))).scalars():
        data.images[image.id] = image
    return data


def _finding_block(data: _Data, finding: Finding) -> Block:
    links = [li for li in data.links.get(finding.id, []) if li.dismissed_at is None]
    refs: list[Ref] = []
    evidence_rows = []
    for link in links:
        ref = data.evidence_ref(link.evidence_id)
        if ref is None:
            continue
        refs.append(ref)
        item = data.evidence[link.evidence_id]
        source_ref = data.source_ref(item.source_id)
        if source_ref and source_ref not in refs:
            refs.append(source_ref)
        evidence_rows.append(
            {
                "label": ref.label,
                "stance": link.stance,
                "directly_states": link.directly_states,
                "origin": data.origin(item),
                "source": source_ref.label if source_ref else None,
                "captured": _date(item.captured_at),
                "published": _date(item.published_at),
                "provenance": PROVENANCE_LABELS.get(item.provenance, item.provenance),
            }
        )
    confidence = None
    if finding.confidence and not finding.sensitive:
        confidence = {"level": finding.confidence, "basis": data.bases.get(finding.id)}
    return Block(
        "finding",
        data.statements.get(finding.id, ""),
        refs,
        {
            "label": f"F-{finding.label_seq}",
            "status": finding.verification_status,
            "status_label": STATUS_LABELS.get(finding.verification_status, finding.verification_status),
            "provenance": finding.provenance,
            "provenance_label": PROVENANCE_LABELS.get(finding.provenance, finding.provenance),
            "category": finding.category,
            "importance": finding.importance,
            "confidence": confidence,
            "event_time": _date(finding.event_time),
            "evidence": evidence_rows,
            "contradicted_by": [r["label"] for r in evidence_rows if r["stance"] == "contradicts"],
        },
    )


def _resolve_refs(data: _Data, labels: list[str]) -> list[Ref]:
    by_label: dict[str, Ref] = {}
    for finding in data.findings:
        by_label[f"F-{finding.label_seq}"] = Ref("finding", str(finding.id), f"F-{finding.label_seq}")
    for item in data.evidence.values():
        by_label[f"E-{item.label_seq}"] = Ref("evidence", str(item.id), f"E-{item.label_seq}")
    for source in data.sources.values():
        by_label[f"S-{source.label_seq}"] = Ref("source", str(source.id), f"S-{source.label_seq}")
    refs: list[Ref] = []
    for raw in labels:
        match = _REF.match(str(raw))
        if match and (ref := by_label.get(f"{match.group(1).upper()}-{int(match.group(2))}")) and ref not in refs:
            refs.append(ref)
    return refs


async def build_document(
    db: AsyncSession,
    cipher: FieldCipher,
    settings: Settings,
    inv: Investigation,
    *,
    report_id: uuid.UUID,
    title: str,
    status: str,
    options: dict[str, Any],
    inputs: Inputs,
) -> ReportDocument:
    data = await _gather(db, cipher, inv)
    enabled = set(options.get("sections") or ALL_SECTIONS) | (set(ALL_SECTIONS) - OPTIONAL_SECTIONS)
    stats: Counter[str] = Counter()
    sections: dict[str, Section] = {key: Section(key, SECTION_TITLES[key]) for key in ALL_SECTIONS}

    # -- findings by status --------------------------------------------------------------------------
    for finding in data.findings:
        if finding.retracted_at is not None:  # withdrawn by the analyst: not part of the report
            stats["retracted_findings"] += 1
            continue
        block = _finding_block(data, finding)
        has_evidence = any(r.kind == "evidence" for r in block.refs)
        stats[f"findings_{finding.verification_status}"] += 1
        if finding.provenance == "ai_hypothesis" or finding.verification_status == "ai_hypothesis":
            sections["ai_hypotheses"].blocks.append(block)
        elif not has_evidence:
            block.data["note"] = "The evidence for this claim was deleted; it is not established."
            sections["unverified_claims"].blocks.append(block)
            stats["moved_without_evidence"] += 1
        elif finding.verification_status in ("confirmed_by_source", "corroborated"):
            sections["important_findings"].blocks.append(block)
        elif finding.verification_status == "contradicted" or block.data["contradicted_by"]:
            sections["contradictions"].blocks.append(block)
        else:
            sections["unverified_claims"].blocks.append(block)

    # -- custom paragraphs (citations enforced) ------------------------------------------------------
    custom_sections: list[Section] = []
    for index, custom in enumerate(inputs.custom_sections):
        section = Section(f"custom_{index + 1}", str(custom.get("title") or f"Analyst notes {index + 1}"))
        for paragraph in custom.get("paragraphs", []):
            refs = _resolve_refs(data, list(paragraph.get("refs", [])))
            text = str(paragraph.get("text") or "")
            if not text.strip():
                continue
            if refs:
                section.blocks.append(Block("paragraph", text, refs, {"author": "analyst"}))
            else:
                sections["unverified_claims"].blocks.append(
                    Block("paragraph", text, [], {"author": "analyst", "note": "Uncited analyst statement"})
                )
                stats["uncited_custom_paragraphs"] += 1
        if section.blocks:
            custom_sections.append(section)

    await _ai_narrative(db, cipher, inv, options, sections["ai_hypotheses"], data, stats)
    _overview(sections["overview"], inv, data, status)
    await _methodology(db, cipher, inv, sections["methodology"], data)
    _evidence_summary(sections["evidence_summary"], data)
    await _timeline(db, cipher, inv, sections["timeline"], data)
    await _relationships(db, cipher, inv, sections["relationships"], data)
    _sources(sections["sources"], data)
    _images(sections["images"], data)
    await _limitations(db, inv, settings, sections["limitations"], data, stats)
    await _privacy(db, settings, inv, sections["privacy"], data)
    for key, empty_note in (
        ("important_findings", "No finding has been confirmed by a source or corroborated yet."),
        ("contradictions", "No contradictions are recorded."),
        ("unverified_claims", "No unverified claims."),
        ("ai_hypotheses", "No AI hypotheses are recorded."),
    ):
        if not sections[key].blocks:
            sections[key].blocks.append(Block("notice", empty_note))
    ordered = [sections[k] for k in ALL_SECTIONS if k in enabled]
    position = ordered.index(sections["ai_hypotheses"]) if sections["ai_hypotheses"] in ordered else len(ordered)
    ordered[position:position] = custom_sections
    stats["sources"] = len(data.sources)
    stats["evidence"] = len(data.evidence)
    stats["findings"] = len(data.findings)
    confidentiality = options.get("confidentiality") if options.get("confidentiality") in CONFIDENTIALITY else None
    return ReportDocument(
        report_id=str(report_id),
        title=title,
        investigation_ref=inv.public_ref,
        investigation_title=inv.title,
        status=status,
        generated_at=utcnow().isoformat(timespec="seconds"),
        confidentiality=confidentiality or "Confidential",
        restricted_mode=inv.restricted_mode,
        sections=ordered,
        stats=dict(stats),
    )


# --------------------------------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------------------------------
def _overview(section: Section, inv: Investigation, data: _Data, status: str) -> None:
    rows = [
        ["Reference", inv.public_ref],
        ["Investigation", inv.title],
        ["Subject type", inv.subject_type.replace("_", " ")],
        ["Purpose category", inv.purpose_category.replace("_", " ")],
        ["Lawful basis", (inv.lawful_basis or "").replace("_", " ")],
        ["Investigation status", inv.status.replace("_", " ")],
        ["Opened", _date(inv.created_at) or ""],
        ["Report status", "Final" if status == "final" else "Draft — subject to change"],
    ]
    section.blocks.append(Block("facts", None, [], {"rows": rows}))
    if inv.restricted_mode:
        section.blocks.append(
            Block(
                "notice",
                "Restricted mode: this investigation concerns an individual. It was approved by a "
                "supervisor, contact and location data are excluded, and stricter redaction applies.",
            )
        )
    section.blocks.append(
        Block(
            "paragraph",
            "Every factual statement in this report cites evidence (E-), the source it came from "
            "(S-) or a recorded finding (F-). Verification statuses are human decisions recorded with a "
            "justification; AI output appears only as labelled hypotheses.",
        )
    )


async def _methodology(
    db: AsyncSession, cipher: FieldCipher, inv: Investigation, section: Section, data: _Data
) -> None:
    runs = list(
        (
            await db.execute(
                select(CollectionRun)
                .where(CollectionRun.investigation_id == inv.id)
                .order_by(CollectionRun.created_at)
                .limit(MAX_ROWS)
            )
        ).scalars()
    )
    rows = []
    for run in runs:
        query = cipher.open(run.query, table="collection_runs", column="query", row_id=run.id)
        rows.append(
            [
                run.connector_id,
                run.input_type,
                query[:200],
                run.status,
                _when(run.created_at) or "",
                str(run.records_count),
            ]
        )
    if rows:
        section.blocks.append(
            Block(
                "table",
                "Public-source searches",
                [],
                {
                    "columns": ["Source", "Input", "Query", "Status", "Requested (UTC)", "Records"],
                    "rows": rows,
                    "nowrap": [4, 5],
                },
            )
        )
    analyzers = (
        await db.execute(
            select(ImageAnalysis.analyzer, ImageAnalysis.analyzer_version)
            .where(ImageAnalysis.investigation_id == inv.id)
            .distinct()
        )
    ).all()
    if analyzers:
        listed = ", ".join(f"{name} v{version}" for name, version in sorted(analyzers))
        section.blocks.append(
            Block(
                "paragraph",
                f"Image analyzers used: {listed}. Faces are only detected, counted "
                "and masked; no facial recognition is performed.",
            )
        )
    tasks = (
        await db.execute(
            select(AIInteraction.task, AIInteraction.model).where(AIInteraction.investigation_id == inv.id).distinct()
        )
    ).all()
    if tasks:
        models = sorted({m for _, m in tasks if m})
        section.blocks.append(
            Block(
                "paragraph",
                "AI assistance was used for: "
                + ", ".join(sorted({t.replace("_", " ") for t, _ in tasks}))
                + (f" (models: {', '.join(models)})" if models else "")
                + ". AI output was validated against the evidence and is labelled where it "
                "appears.",
            )
        )
    section.blocks.append(
        Block(
            "paragraph",
            "Collection used official APIs and pages that robots.txt allows; logins, paywalls and "
            "CAPTCHAs were never bypassed (such pages are listed as references only). All collected text was "
            "screened for personal and sensitive data before storage.",
        )
    )


def _evidence_summary(section: Section, data: _Data) -> None:
    statuses = Counter(f.verification_status for f in data.findings)
    provenances = Counter(e.provenance for e in data.evidence.values())
    categories = Counter(s.source_category for s in data.sources.values())
    section.blocks.append(
        Block(
            "table",
            "Findings by verification status",
            [],
            {
                "columns": ["Status", "Findings"],
                "rows": [[STATUS_LABELS.get(k, k), str(v)] for k, v in statuses.items()],
            },
        )
    )
    section.blocks.append(
        Block(
            "table",
            "Evidence by provenance",
            [],
            {
                "columns": ["Provenance", "Items"],
                "rows": [[PROVENANCE_LABELS.get(k, k), str(v)] for k, v in provenances.items()],
            },
        )
    )
    if categories:
        section.blocks.append(
            Block(
                "table",
                "Sources by category",
                [],
                {
                    "columns": ["Category", "Sources"],
                    "rows": [[k.replace("_", " ").capitalize(), str(v)] for k, v in sorted(categories.items())],
                },
            )
        )


async def _timeline(db: AsyncSession, cipher: FieldCipher, inv: Investigation, section: Section, data: _Data) -> None:
    events = list(
        (
            await db.execute(
                select(TimelineEvent)
                .where(TimelineEvent.investigation_id == inv.id)
                .order_by(TimelineEvent.occurred_start)
                .limit(MAX_ROWS)
            )
        ).scalars()
    )
    if not events:
        section.blocks.append(Block("notice", "No dated events are recorded."))
        return
    links: dict[uuid.UUID, list[uuid.UUID]] = {}
    for event_id, evidence_id in await db.execute(
        select(TimelineEventEvidence.event_id, TimelineEventEvidence.evidence_id).where(
            TimelineEventEvidence.investigation_id == inv.id
        )
    ):
        links.setdefault(event_id, []).append(evidence_id)
    rows, refs = [], []
    for event in events:
        title = cipher.open(event.title, table="timeline_events", column="title", row_id=event.id)
        labels = [r for r in (data.evidence_ref(e) for e in links.get(event.id, [])) if r]
        refs += labels
        when = event.occurred_start.date().isoformat() if event.precision != "year" else str(event.occurred_start.year)
        caveat = " (metadata is editable)" if event.kind == "capture_time" else ""
        rows.append(
            [
                when,
                event.precision,
                title + caveat,
                STATUS_LABELS.get(event.verification_status, ""),
                ", ".join(r.label for r in labels),
            ]
        )
    section.blocks.append(
        Block(
            "table",
            None,
            refs,
            {"columns": ["Date", "Precision", "Event", "Status", "Evidence"], "rows": rows, "nowrap": [0, 1]},
        )
    )


async def _relationships(
    db: AsyncSession, cipher: FieldCipher, inv: Investigation, section: Section, data: _Data
) -> None:
    rels = list(
        (
            await db.execute(select(Relationship).where(Relationship.investigation_id == inv.id).limit(MAX_ROWS))
        ).scalars()
    )
    if not rels:
        section.blocks.append(Block("notice", "No relationships are recorded."))
        return
    entity_ids = {r.from_entity_id for r in rels} | {r.to_entity_id for r in rels}
    names = {
        e.id: entity_name(cipher, e)
        for e in (await db.execute(select(Entity).where(Entity.id.in_(entity_ids)))).scalars()
    }
    support: dict[uuid.UUID, list[uuid.UUID]] = {}
    for rel_id, evidence_id, stance in await db.execute(
        select(
            RelationshipEvidence.relationship_id, RelationshipEvidence.evidence_id, RelationshipEvidence.stance
        ).where(RelationshipEvidence.investigation_id == inv.id)
    ):
        if stance == "supports":
            support.setdefault(rel_id, []).append(evidence_id)
    rows, refs = [], []
    for rel in rels:
        labels = [r for r in (data.evidence_ref(e) for e in support.get(rel.id, [])) if r]
        refs += labels
        rows.append(
            [
                names.get(rel.from_entity_id, "?"),
                rel.rel_type.replace("_", " "),
                names.get(rel.to_entity_id, "?"),
                STATUS_LABELS.get(rel.verification_status, ""),
                ", ".join(r.label for r in labels),
            ]
        )
    section.blocks.append(
        Block("table", None, refs, {"columns": ["From", "Relationship", "To", "Status", "Evidence"], "rows": rows})
    )


def _sources(section: Section, data: _Data) -> None:
    if not data.sources:
        section.blocks.append(Block("notice", "No sources are recorded."))
        return
    rows = []
    for source in sorted(data.sources.values(), key=lambda s: s.label_seq)[:MAX_ROWS]:
        url = data.open(source.url, "sources", "url", source.id) or ""
        title = data.open(source.title, "sources", "title", source.id) or ""
        archived = data.open(source.archived_url, "sources", "archived_url", source.id) or ""
        rows.append(
            [
                f"S-{source.label_seq}",
                title or source.host,
                url,
                source.source_category.replace("_", " "),
                _date(source.published_at) or "",
                _date(source.first_captured_at) or "",
                source.access_status.replace("_", " "),
                source.reliability or "—",
                archived,
            ]
        )
    columns = ["Ref", "Title", "URL", "Category", "Published", "Retrieved", "Access", "Reliability", "Archive"]
    links = [2, 8]
    if not any(row[8] for row in rows):  # the archive column only when some source has an archived copy
        columns, rows, links = columns[:8], [row[:8] for row in rows], [2]
    section.blocks.append(
        Block("table", None, [], {"columns": columns, "rows": rows, "links": links, "nowrap": [0, 4, 5, 7]})
    )


def _images(section: Section, data: _Data) -> None:
    if not data.images:
        section.blocks.append(Block("notice", "No images were analysed."))
        return
    rows = []
    faces = 0
    for image in sorted(data.images.values(), key=lambda i: i.label_seq):
        faces += image.face_count > 0
        place = ", ".join(p for p in (image.region, image.country) if p) or "—"
        rows.append(
            [
                f"I-{image.label_seq}",
                image.status.replace("_", " "),
                image.metadata_availability or "—",
                place,
                "yes — not identified" if image.face_count else "no",
            ]
        )
    section.blocks.append(
        Block(
            "table",
            None,
            [],
            {
                "columns": ["Image", "Status", "Metadata", "Location (generalized)", "Face detected"],
                "rows": rows,
            },
        )
    )
    if faces:
        section.blocks.append(Block("notice", FACE_NOTICE))


async def _ai_narrative(
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    options: dict[str, Any],
    section: Section,
    data: _Data,
    stats: Counter[str],
) -> None:
    raw_id = options.get("ai_interaction_id")
    if not raw_id:
        return
    try:
        interaction_id = uuid.UUID(str(raw_id))
    except ValueError:
        return
    interaction = (
        await db.execute(
            select(AIInteraction).where(AIInteraction.id == interaction_id, AIInteraction.investigation_id == inv.id)
        )
    ).scalar_one_or_none()
    if interaction is None or interaction.status != "completed" or interaction.response is None:
        return
    response = cipher.open_json(interaction.response, table="ai_interactions", column="response", row_id=interaction.id)
    section.blocks.append(
        Block(
            "notice",
            "The following narrative was drafted by AI from the cited evidence. It is "
            "an AI hypothesis, not an established conclusion.",
        )
    )
    for segment in response.get("segments", []):
        refs = [r for r in (data.evidence_ref(uuid.UUID(c["evidence_id"])) for c in segment.get("citations", [])) if r]
        kind = segment.get("kind")
        if kind == "notice" and segment.get("text") == INSUFFICIENT:
            section.blocks.append(Block("notice", INSUFFICIENT))
            continue
        label = UNCITED_LABEL if kind == "uncited" or (kind == "cited" and not refs) else None
        stats["ai_uncited_segments"] += label is not None
        section.blocks.append(Block("ai_segment", segment.get("text", ""), refs, {"label": label}))


async def _limitations(
    db: AsyncSession, inv: Investigation, settings: Settings, section: Section, data: _Data, stats: Counter[str]
) -> None:
    notes: list[str] = []
    if settings.tineye_api_key is None and settings.google_vision_api_key is None:
        notes.append(
            "No reverse image search provider was configured, so where else the images appear online was not checked."
        )
    if any(i.metadata_availability == "none" for i in data.images.values()):
        notes.append("Some images carry no embedded metadata; its absence proves nothing about their origin.")
    if any(i.face_count > 0 for i in data.images.values()):
        notes.append(
            "Faces were detected in some images. Angel Engine does not perform facial identification, so "
            "no person in any image was identified."
        )
    limited = Counter(s.access_status for s in data.sources.values() if s.access_status != "captured")
    if limited:
        listed = ", ".join(f"{n} {k.replace('_', ' ')}" for k, n in sorted(limited.items()))
        notes.append(f"Some sources could not be captured and are cited as references only ({listed}).")
    failed = (
        (
            await db.execute(
                select(CollectionRun.connector_id)
                .where(CollectionRun.investigation_id == inv.id, CollectionRun.status == "failed")
                .distinct()
            )
        )
        .scalars()
        .all()
    )
    if failed:
        notes.append("Searches that failed and were not repeated: " + ", ".join(sorted(failed)) + ".")
    if stats.get("moved_without_evidence"):
        notes.append("Claims whose evidence was later deleted are listed under unverified claims.")
    if settings.scanner != "clamd":
        notes.append("Malware scanning ran in a degraded development mode.")
    notes.append(
        "Public sources can be wrong, outdated or copied from one another; corroboration counts only "
        "independent origins."
    )
    section.blocks.append(Block("list", None, [], {"items": notes}))


async def _privacy(db: AsyncSession, settings: Settings, inv: Investigation, section: Section, data: _Data) -> None:
    redactions: Counter[str] = Counter()
    for item in data.evidence.values():
        redactions.update({k: int(v) for k, v in (item.redaction_counts or {}).items()})
    policy = await load_policy(db, settings)
    if redactions:
        counted = ", ".join(f"{n} {k.replace('_', ' ')}" for k, n in sorted(redactions.items()))
        redaction_note = f"Personal and sensitive data were redacted before storage: {counted}."
    else:
        redaction_note = "Collected text was screened for personal and sensitive data before storage; none was found."
    items = [
        redaction_note,
        f"Image originals are deleted {policy.image_original_hours_for(inv)} hours after analysis; previews have "
        "faces and sensitive text masked and carry no metadata.",
        "GPS positions were generalized to region level; coordinates were never stored.",
        f"AI transcripts are kept for {policy.ai_transcript_days} days.",
    ]
    if inv.restricted_mode:
        items.append(
            "Restricted mode excluded contact and location data and disabled AI vision and reverse image search."
        )
    section.blocks.append(Block("list", None, [], {"items": items}))


def document_from_dict(data: dict[str, Any]) -> ReportDocument:
    sections = [
        Section(
            s["key"],
            s["title"],
            [
                Block(b["type"], b.get("text"), [Ref(**r) for r in b.get("refs", [])], b.get("data", {}))
                for b in s.get("blocks", [])
            ],
        )
        for s in data.get("sections", [])
    ]
    return ReportDocument(
        report_id=data["report_id"],
        title=data["title"],
        investigation_ref=data["investigation_ref"],
        investigation_title=data["investigation_title"],
        status=data["status"],
        generated_at=data["generated_at"],
        confidentiality=data["confidentiality"],
        restricted_mode=data["restricted_mode"],
        sections=sections,
        stats=data.get("stats", {}),
        integrity=data.get("integrity", {}),
    )
