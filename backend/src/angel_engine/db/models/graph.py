"""Entities, relationships (evidence graph) and timeline events (row-level security)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Index, LargeBinary, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, INT4RANGE, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import text

from angel_engine.core.enums import (
    PLAINTEXT_ENTITY_TYPES,
    Confidence,
    EntityType,
    Provenance,
    RelationshipType,
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

_PLAIN = tuple(t.value for t in PLAINTEXT_ENTITY_TYPES)


class Entity(InvestigationScoped, Base):
    """A public entity or clue. There is deliberately no generic private-person entity type."""

    __tablename__ = "entities"
    __table_args__ = scoped_args(
        "entities",
        scoped_fk("merged_into_id", "entities", ondelete="SET NULL", name="fk_entities_merged_into"),
        CheckConstraint(check_in("type", values(EntityType)), name="type"),
        CheckConstraint(
            f"({check_in('type', _PLAIN)} AND name IS NOT NULL) OR "
            f"(NOT {check_in('type', _PLAIN)} AND name IS NULL AND name_enc IS NOT NULL)",
            name="name_storage",
        ),
        CheckConstraint("type <> 'public_figure' OR public_role_basis IS NOT NULL", name="public_figure_basis"),
        CheckConstraint(
            "location_level IS NULL OR location_level IN ('country','admin1','locality','landmark')",
            name="location_level",
        ),
        CheckConstraint("type <> 'location' OR location_level IS NOT NULL", name="location_has_level"),
        UniqueConstraint("investigation_id", "type", "canonical_mac"),
        Index("ix_entities_name_trgm", "name", postgresql_using="gin", postgresql_ops={"name": "gin_trgm_ops"}),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    type: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str | None] = mapped_column(Text)
    name_enc: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    canonical_mac: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    location_level: Mapped[str | None] = mapped_column(Text)
    country: Mapped[str | None] = mapped_column(Text)
    public_role_basis: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    attributes: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E] JSON
    merged_into_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_via: Mapped[str] = mapped_column(Text, nullable=False, default="system")
    created_at: Mapped[datetime] = created_at_col()


class EntityMention(InvestigationScoped, Base):
    __tablename__ = "entity_mentions"
    __table_args__ = scoped_args(
        "entity_mentions",
        scoped_fk("entity_id", "entities"),
        scoped_fk("evidence_id", "evidence_items"),
        UniqueConstraint("entity_id", "evidence_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    evidence_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    span: Mapped[object | None] = mapped_column(INT4RANGE)
    created_at: Mapped[datetime] = created_at_col()


class Relationship(InvestigationScoped, Base):
    __tablename__ = "relationships"
    __table_args__ = scoped_args(
        "relationships",
        scoped_fk("from_entity_id", "entities", name="fk_relationships_from_entity"),
        scoped_fk("to_entity_id", "entities", name="fk_relationships_to_entity"),
        CheckConstraint(check_in("rel_type", values(RelationshipType)), name="rel_type"),
        CheckConstraint(check_in("provenance", values(Provenance)), name="provenance"),
        CheckConstraint(check_in("verification_status", values(VerificationStatus)), name="verification_status"),
        CheckConstraint(f"confidence IS NULL OR {check_in('confidence', values(Confidence))}", name="confidence"),
        CheckConstraint("from_entity_id <> to_entity_id", name="not_self"),
        CheckConstraint(
            "verification_status <> 'ai_hypothesis' OR provenance = 'ai_hypothesis'", name="ai_status_requires_ai"
        ),
        UniqueConstraint("investigation_id", "from_entity_id", "rel_type", "to_entity_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    from_entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    to_entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    rel_type: Mapped[str] = mapped_column(Text, nullable=False)
    provenance: Mapped[str] = mapped_column(Text, nullable=False)
    verification_status: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_via: Mapped[str] = mapped_column(Text, nullable=False, default="system")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class RelationshipEvidence(InvestigationScoped, Base):
    __tablename__ = "relationship_evidence"
    __table_args__ = scoped_args(
        "relationship_evidence",
        scoped_fk("relationship_id", "relationships"),
        scoped_fk("evidence_id", "evidence_items"),
        CheckConstraint(check_in("stance", values(Stance)), name="stance"),
        UniqueConstraint("relationship_id", "evidence_id", "stance"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    relationship_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    evidence_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    stance: Mapped[str] = mapped_column(Text, nullable=False, default="supports")
    created_at: Mapped[datetime] = created_at_col()


class RelationshipStatusHistory(InvestigationScoped, Base):
    __tablename__ = "relationship_status_history"
    __table_args__ = scoped_args("relationship_status_history", scoped_fk("relationship_id", "relationships"))

    id: Mapped[uuid.UUID] = uuid_pk()
    relationship_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    from_status: Mapped[str | None] = mapped_column(Text)
    to_status: Mapped[str] = mapped_column(Text, nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    justification: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    evidence_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=False, server_default=text("'{}'")
    )
    precondition_snapshot: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = created_at_col()


class TimelineEvent(InvestigationScoped, Base):
    __tablename__ = "timeline_events"
    __table_args__ = scoped_args(
        "timeline_events",
        scoped_fk("finding_id", "findings", ondelete="SET NULL"),
        CheckConstraint(
            check_in("precision", ("exact", "minute", "hour", "day", "month", "year", "approximate")),
            name="precision",
        ),
        CheckConstraint(check_in("provenance", values(Provenance)), name="provenance"),
        CheckConstraint(check_in("verification_status", values(VerificationStatus)), name="verification_status"),
        CheckConstraint(
            "verification_status <> 'ai_hypothesis' OR provenance = 'ai_hypothesis'", name="ai_status_requires_ai"
        ),
        CheckConstraint("occurred_end IS NULL OR occurred_end >= occurred_start", name="range"),
        Index("ix_timeline_events_inv_start", "investigation_id", "occurred_start"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    occurred_start: Mapped[datetime]
    occurred_end: Mapped[datetime | None]
    precision: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # [E]
    description: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    finding_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    provenance: Mapped[str] = mapped_column(Text, nullable=False)
    verification_status: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_via: Mapped[str] = mapped_column(Text, nullable=False, default="system")
    created_at: Mapped[datetime] = created_at_col()


class TimelineEventEvidence(InvestigationScoped, Base):
    __tablename__ = "timeline_event_evidence"
    __table_args__ = scoped_args(
        "timeline_event_evidence",
        scoped_fk("event_id", "timeline_events"),
        scoped_fk("evidence_id", "evidence_items"),
        UniqueConstraint("event_id", "evidence_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    evidence_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    created_at: Mapped[datetime] = created_at_col()
