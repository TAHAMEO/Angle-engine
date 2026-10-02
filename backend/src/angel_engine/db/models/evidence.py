"""Sources, collection runs, evidence items, findings, facts and suggestions (row-level security)."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INT4RANGE, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from angel_engine.core.enums import (
    Confidence,
    FindingCategory,
    Provenance,
    Stance,
    VerificationStatus,
    values,
)
from angel_engine.db.base import (
    Base,
    InvestigationScoped,
    check_in,
    created_at_col,
    scoped_args,
    scoped_fk,
    updated_at_col,
    uuid_pk,
)

SOURCE_CATEGORIES = values(FindingCategory)[:11]
EVIDENCE_TYPES = (
    "text_excerpt",
    "page_capture",
    "document_excerpt",
    "registry_record",
    "search_result",
    "ocr_text",
    "image_clue",
    "metadata",
    "image_match",
    "manual_capture",
)
ACCESS_STATUSES = ("captured", "reference_only", "login_required", "robots_disallowed", "paywalled")


class Source(InvestigationScoped, Base):
    __tablename__ = "sources"
    __table_args__ = scoped_args(
        "sources",
        CheckConstraint(check_in("source_category", SOURCE_CATEGORIES), name="source_category"),
        CheckConstraint(check_in("access_status", ACCESS_STATUSES), name="access_status"),
        CheckConstraint("reliability IS NULL OR reliability IN ('A','B','C','D','E','F')", name="reliability"),
        UniqueConstraint("investigation_id", "url_mac"),
        Index("ix_sources_inv_domain", "investigation_id", "registrable_domain"),
        Index("ix_sources_inv_category", "investigation_id", "source_category"),
        Index("ix_sources_title_tokens", "title_tokens", postgresql_using="gin"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    label_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    url: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # [E]
    url_mac: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    host: Mapped[str] = mapped_column(Text, nullable=False)
    registrable_domain: Mapped[str] = mapped_column(Text, nullable=False)
    source_category: Mapped[str] = mapped_column(Text, nullable=False)
    connector_id: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    title_tokens: Mapped[list[int]] = mapped_column(ARRAY(BigInteger), nullable=False, server_default=text("'{}'"))
    publisher: Mapped[str | None] = mapped_column(Text)
    ownership_group: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[datetime | None]
    first_captured_at: Mapped[datetime]
    last_captured_at: Mapped[datetime]
    reliability: Mapped[str | None] = mapped_column(String(1))
    archived_url: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    access_status: Mapped[str] = mapped_column(Text, nullable=False, default="captured")
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = created_at_col()


class CollectionRun(InvestigationScoped, Base):
    __tablename__ = "collection_runs"
    __table_args__ = scoped_args(
        "collection_runs",
        CheckConstraint(
            check_in(
                "status",
                ("queued", "running", "succeeded", "partial", "failed", "cancelled", "pending_review", "refused"),
            ),
            name="status",
        ),
        UniqueConstraint("investigation_id", "idempotency_key"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    connector_id: Mapped[str] = mapped_column(Text, nullable=False)
    input_type: Mapped[str] = mapped_column(Text, nullable=False)
    query: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # [E]
    params: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    purpose_note: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E] person-oriented lookups
    policy_decision_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    status: Mapped[str] = mapped_column(Text, nullable=False, default="queued")
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    origin_image_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    origin_clue_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    records_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    references_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    leads: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E] transient search leads
    leads_expire_at: Mapped[datetime | None]
    warnings: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, server_default=text("'{}'"))
    error_code: Mapped[str | None] = mapped_column(Text)
    idempotency_key: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at_col()
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class EvidenceItem(InvestigationScoped, Base):
    """An immutable observation or quotation. Never AI-generated (CHECK on provenance)."""

    __tablename__ = "evidence_items"
    __table_args__ = scoped_args(
        "evidence_items",
        scoped_fk("source_id", "sources"),
        scoped_fk("collection_run_id", "collection_runs", ondelete="SET NULL"),
        scoped_fk("origin_image_id", "images"),
        CheckConstraint(check_in("evidence_type", EVIDENCE_TYPES), name="evidence_type"),
        CheckConstraint(check_in("provenance", ("observed", "source_reported")), name="provenance_not_ai"),
        CheckConstraint("source_id IS NOT NULL OR origin_image_id IS NOT NULL", name="has_origin"),
        CheckConstraint("credibility IS NULL OR credibility BETWEEN 1 AND 6", name="credibility"),
        UniqueConstraint(
            "investigation_id",
            "source_id",
            "origin_image_id",
            "content_mac",
            name="uq_evidence_items_content",
            postgresql_nulls_not_distinct=True,
        ),
        Index("ix_evidence_items_tokens", "search_tokens", postgresql_using="gin"),
        Index("ix_evidence_items_inv_captured", "investigation_id", "captured_at"),
        Index("ix_evidence_items_inv_location", "investigation_id", "country", "region"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    label_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    source_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    collection_run_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    origin_image_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    evidence_type: Mapped[str] = mapped_column(Text, nullable=False)
    provenance: Mapped[str] = mapped_column(Text, nullable=False)
    excerpt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # [E]
    extra: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E] structured metadata
    content_mac: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    simhash: Mapped[int | None] = mapped_column(BigInteger)
    search_tokens: Mapped[list[int]] = mapped_column(ARRAY(BigInteger), nullable=False, server_default=text("'{}'"))
    captured_at: Mapped[datetime]
    published_at: Mapped[datetime | None]
    country: Mapped[str | None] = mapped_column(String(2))
    region: Mapped[str | None] = mapped_column(Text)
    credibility: Mapped[int | None] = mapped_column(SmallInteger)
    sensitivity_flags: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, server_default=text("'{}'"))
    redaction_counts: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    dedupe_cluster_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    syndication_cluster_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = created_at_col()


class Finding(InvestigationScoped, Base):
    __tablename__ = "findings"
    __table_args__ = scoped_args(
        "findings",
        CheckConstraint(check_in("category", values(FindingCategory)), name="category"),
        CheckConstraint(check_in("provenance", values(Provenance)), name="provenance"),
        CheckConstraint(check_in("verification_status", values(VerificationStatus)), name="verification_status"),
        CheckConstraint(f"confidence IS NULL OR {check_in('confidence', values(Confidence))}", name="confidence"),
        CheckConstraint(check_in("importance", ("key", "normal")), name="importance"),
        CheckConstraint(
            "verification_status <> 'ai_hypothesis' OR provenance = 'ai_hypothesis'", name="ai_status_requires_ai"
        ),
        CheckConstraint("NOT sensitive OR confidence IS NULL", name="no_confidence_when_sensitive"),
        CheckConstraint(
            check_in("created_via", ("connector", "image_analysis", "manual", "ai_proposal", "import")),
            name="created_via",
        ),
        Index("ix_findings_inv_status", "investigation_id", "verification_status"),
        Index("ix_findings_inv_category", "investigation_id", "category"),
        Index("ix_findings_tokens", "statement_tokens", postgresql_using="gin"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    label_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    statement: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # [E]
    statement_tokens: Mapped[list[int]] = mapped_column(ARRAY(BigInteger), nullable=False, server_default=text("'{}'"))
    category: Mapped[str] = mapped_column(Text, nullable=False)
    provenance: Mapped[str] = mapped_column(Text, nullable=False)
    verification_status: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[str | None] = mapped_column(Text)
    confidence_basis: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    sensitive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    importance: Mapped[str] = mapped_column(Text, nullable=False, default="normal")
    event_time: Mapped[datetime | None]
    event_precision: Mapped[str | None] = mapped_column(Text)
    evidence_removed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    retracted_at: Mapped[datetime | None]
    ai_interaction_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_via: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
    status_changed_at: Mapped[datetime | None]

    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012


class FindingEvidence(InvestigationScoped, Base):
    __tablename__ = "finding_evidence"
    __table_args__ = scoped_args(
        "finding_evidence",
        scoped_fk("finding_id", "findings"),
        scoped_fk("evidence_id", "evidence_items"),
        CheckConstraint(check_in("stance", values(Stance)), name="stance"),
        UniqueConstraint("finding_id", "evidence_id", "stance"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    evidence_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    stance: Mapped[str] = mapped_column(Text, nullable=False)
    directly_states: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    quote_span: Mapped[Any | None] = mapped_column(INT4RANGE)
    dismissed_at: Mapped[datetime | None]
    dismissed_reason: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    dismissed_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = created_at_col()


class FindingStatusHistory(InvestigationScoped, Base):
    """Append-only record of every verification-status change."""

    __tablename__ = "finding_status_history"
    __table_args__ = scoped_args("finding_status_history", scoped_fk("finding_id", "findings"))

    id: Mapped[uuid.UUID] = uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    from_status: Mapped[str | None] = mapped_column(Text)
    to_status: Mapped[str] = mapped_column(Text, nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    justification: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    evidence_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=False, server_default=text("'{}'")
    )
    automatic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    precondition_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = created_at_col()


class Fact(InvestigationScoped, Base):
    """Structured attribute (entity, attribute, value) for deterministic corroboration/contradiction checks."""

    __tablename__ = "facts"
    __table_args__ = scoped_args(
        "facts",
        scoped_fk("evidence_id", "evidence_items"),
        scoped_fk("entity_id", "entities", ondelete="SET NULL"),
        Index("ix_facts_inv_entity_attr", "investigation_id", "entity_id", "attribute"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    entity_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    attribute: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # [E] JSON value
    value_type: Mapped[str] = mapped_column(Text, nullable=False)
    precision: Mapped[str | None] = mapped_column(Text)
    valid_from: Mapped[date | None] = mapped_column(Date)
    valid_to: Mapped[date | None] = mapped_column(Date)
    evidence_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    provenance: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = created_at_col()


class Suggestion(InvestigationScoped, Base):
    """System-computed suggestions (never applied automatically)."""

    __tablename__ = "suggestions"
    __table_args__ = scoped_args(
        "suggestions",
        CheckConstraint(
            check_in("kind", ("corroboration", "contradiction", "discrepancy", "syndication", "duplicate")),
            name="kind",
        ),
        CheckConstraint(check_in("status", ("open", "accepted", "dismissed")), name="status"),
        UniqueConstraint("investigation_id", "dedupe_key"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    finding_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=False, server_default=text("'{}'")
    )
    evidence_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=False, server_default=text("'{}'")
    )
    fact_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=False, server_default=text("'{}'")
    )
    rule_id: Mapped[str] = mapped_column(Text, nullable=False)
    rule_version: Mapped[str] = mapped_column(Text, nullable=False)
    message: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # [E]
    dedupe_key: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="open")
    decided_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    decided_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = created_at_col()
