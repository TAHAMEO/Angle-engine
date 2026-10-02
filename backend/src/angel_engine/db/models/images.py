"""Uploaded images and their (non-biometric) analysis results (row-level security)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Computed,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import text

from angel_engine.core.enums import ImageStatus, values
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

CLUE_TYPES = (
    "visible_text",
    "url",
    "domain",
    "username",
    "hashtag",
    "email_domain",
    "date",
    "organization",
    "brand",
    "object",
    "landmark",
    "sign",
    "public_location",
    "exif_field",
)


class Image(InvestigationScoped, Base):
    __tablename__ = "images"
    __table_args__ = scoped_args(
        "images",
        CheckConstraint(check_in("status", values(ImageStatus)), name="status"),
        CheckConstraint("byte_size > 0 AND byte_size <= 26214400", name="byte_size"),
        CheckConstraint("face_count >= 0 AND person_count >= 0", name="counts"),
        UniqueConstraint("investigation_id", "content_mac"),
        UniqueConstraint("investigation_id", "idempotency_key"),
        Index("ix_images_purge", "original_purge_after", postgresql_where=text("original_purged_at IS NULL")),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    label_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default=ImageStatus.UPLOADED.value)
    filename: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E] may contain personal data
    declared_mime: Mapped[str | None] = mapped_column(Text)
    mime: Mapped[str | None] = mapped_column(Text)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)
    width: Mapped[int | None] = mapped_column(Integer)
    height: Mapped[int | None] = mapped_column(Integer)
    sha256: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # [E] chain of custody
    content_mac: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    original_key: Mapped[str | None] = mapped_column(Text)
    original_file_key: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E] wrapped per-object key
    preview_key: Mapped[str | None] = mapped_column(Text)
    preview_file_key: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    face_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    person_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    metadata_availability: Mapped[str | None] = mapped_column(Text)
    capture_time: Mapped[datetime | None]
    country: Mapped[str | None] = mapped_column(Text)
    region: Mapped[str | None] = mapped_column(Text)
    scan_engine: Mapped[str | None] = mapped_column(Text)
    scan_signature: Mapped[str | None] = mapped_column(Text)
    scan_completed_at: Mapped[datetime | None]
    quarantine_reason: Mapped[str | None] = mapped_column(Text)
    analysis_started_at: Mapped[datetime | None]
    analysis_completed_at: Mapped[datetime | None]
    original_purge_after: Mapped[datetime | None]
    original_purged_at: Mapped[datetime | None]
    files_deleted_at: Mapped[datetime | None]
    reverse_search_approved_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    reverse_search_purpose: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    idempotency_key: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class ImageHash(InvestigationScoped, Base):
    __tablename__ = "image_hashes"
    __table_args__ = scoped_args(
        "image_hashes",
        scoped_fk("image_id", "images"),
        UniqueConstraint("image_id"),
        Index("ix_image_hashes_b0", "phash_b0"),
        Index("ix_image_hashes_b1", "phash_b1"),
        Index("ix_image_hashes_b2", "phash_b2"),
        Index("ix_image_hashes_b3", "phash_b3"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    image_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    phash: Mapped[int] = mapped_column(BigInteger, nullable=False)
    dhash: Mapped[int] = mapped_column(BigInteger, nullable=False)
    ahash: Mapped[int] = mapped_column(BigInteger, nullable=False)
    whash: Mapped[int] = mapped_column(BigInteger, nullable=False)
    phash_b0: Mapped[int] = mapped_column(Integer, Computed("((phash >> 48) & 65535)::int", persisted=True))
    phash_b1: Mapped[int] = mapped_column(Integer, Computed("((phash >> 32) & 65535)::int", persisted=True))
    phash_b2: Mapped[int] = mapped_column(Integer, Computed("((phash >> 16) & 65535)::int", persisted=True))
    phash_b3: Mapped[int] = mapped_column(Integer, Computed("(phash & 65535)::int", persisted=True))
    colorhash: Mapped[str] = mapped_column(Text, nullable=False)
    crop_resistant: Mapped[str] = mapped_column(Text, nullable=False)
    pixel_mac: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = created_at_col()


class ImageAnalysis(InvestigationScoped, Base):
    __tablename__ = "image_analyses"
    __table_args__ = scoped_args(
        "image_analyses",
        scoped_fk("image_id", "images"),
        UniqueConstraint("image_id", "analyzer"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    image_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    analyzer: Mapped[str] = mapped_column(Text, nullable=False)
    analyzer_version: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    result: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E] JSON
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = created_at_col()


class ImageClue(InvestigationScoped, Base):
    __tablename__ = "image_clues"
    __table_args__ = scoped_args(
        "image_clues",
        scoped_fk("image_id", "images"),
        scoped_fk("promoted_evidence_id", "evidence_items", ondelete="SET NULL"),
        CheckConstraint(check_in("clue_type", CLUE_TYPES), name="clue_type"),
        CheckConstraint(check_in("provenance", ("observed", "ai_hypothesis")), name="provenance"),
        UniqueConstraint("image_id", "clue_type", "normalized_mac"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    image_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    clue_type: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # [E]
    normalized: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # [E]
    normalized_mac: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    tokens: Mapped[list[int]] = mapped_column(ARRAY(BigInteger), nullable=False, server_default=text("'{}'"))
    bbox: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    confidence: Mapped[str] = mapped_column(Text, nullable=False)
    confidence_basis: Mapped[str] = mapped_column(Text, nullable=False)
    provenance: Mapped[str] = mapped_column(Text, nullable=False, default="observed")
    source: Mapped[str] = mapped_column(Text, nullable=False)
    platform: Mapped[str | None] = mapped_column(Text)
    precision: Mapped[str | None] = mapped_column(Text)
    promoted_evidence_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = created_at_col()
