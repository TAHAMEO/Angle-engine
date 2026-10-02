"""Investigations, membership, oversight grants and data-encryption keys."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Computed,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from angel_engine.core.enums import (
    InvestigationStatus,
    LawfulBasis,
    MemberRole,
    PurposeCategory,
    SubjectType,
    values,
)
from angel_engine.db.base import Base, check_in, created_at_col, updated_at_col, uuid_pk


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (
        CheckConstraint(check_in("status", values(InvestigationStatus)), name="status"),
        CheckConstraint(check_in("subject_type", values(SubjectType)), name="subject_type"),
        CheckConstraint(check_in("purpose_category", values(PurposeCategory)), name="purpose_category"),
        CheckConstraint(check_in("lawful_basis", values(LawfulBasis)), name="lawful_basis"),
        CheckConstraint("subject_type <> 'individual' OR restricted_mode", name="individual_restricted"),
        UniqueConstraint("ref_year", "ref_seq"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    ref_year: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    ref_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    public_ref: Mapped[str] = mapped_column(
        Text,
        Computed("'AE-' || ref_year::text || '-' || lpad(ref_seq::text, 6, '0')", persisted=True),
        unique=True,
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    purpose: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # [E]
    purpose_category: Mapped[str] = mapped_column(Text, nullable=False)
    lawful_basis: Mapped[str] = mapped_column(Text, nullable=False)
    authorization_ref: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    jurisdiction: Mapped[str | None] = mapped_column(Text)
    subject_type: Mapped[str] = mapped_column(Text, nullable=False)
    restricted_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default=InvestigationStatus.DRAFT.value)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    reviewed_at: Mapped[datetime | None]
    review_note: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    last_policy_decision_id: Mapped[uuid.UUID | None]
    image_original_retention_hours: Mapped[int | None] = mapped_column(Integer)
    closed_retention_days: Mapped[int | None] = mapped_column(Integer)
    ai_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    legal_hold: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    legal_hold_reason: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    evidence_seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    source_seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    image_seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
    submitted_at: Mapped[datetime | None]
    activated_at: Mapped[datetime | None]
    closed_at: Mapped[datetime | None]
    archived_at: Mapped[datetime | None]
    deleted_at: Mapped[datetime | None]
    purge_after: Mapped[datetime | None]

    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012


class InvestigationRefCounter(Base):
    __tablename__ = "investigation_ref_counters"

    year: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    last_seq: Mapped[int] = mapped_column(Integer, nullable=False)


class InvestigationMember(Base):
    __tablename__ = "investigation_members"
    __table_args__ = (
        CheckConstraint(check_in("role", values(MemberRole)), name="role"),
        Index(
            "uq_investigation_members_single_owner",
            "investigation_id",
            unique=True,
            postgresql_where=text("role = 'owner'"),
        ),
    )

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    added_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = created_at_col()


class OversightGrant(Base):
    """Time-boxed, audited read-only access for a supervisor who is not a member."""

    __tablename__ = "oversight_grants"
    __table_args__ = (CheckConstraint("expires_at <= created_at + interval '72 hours'", name="max_duration"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    grantee_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    granted_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    reason: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # [E]
    created_at: Mapped[datetime] = created_at_col()
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]


class DataKey(Base):
    """Wrapped data-encryption keys. ``wrapped_dek`` is NULL once destroyed (crypto-shredding)."""

    __tablename__ = "data_keys"
    __table_args__ = (
        CheckConstraint(
            check_in("scope", ("investigation", "system_secrets", "system_abuse", "system_policy")), name="scope"
        ),
        CheckConstraint(check_in("status", ("active", "retired", "destroyed")), name="status"),
        CheckConstraint("(scope = 'investigation') = (investigation_id IS NOT NULL)", name="scope_investigation"),
        CheckConstraint("(status = 'destroyed') = (wrapped_dek IS NULL)", name="destroyed_has_no_key"),
        Index(
            "uq_data_keys_active_investigation",
            "investigation_id",
            unique=True,
            postgresql_where=text("status = 'active' AND investigation_id IS NOT NULL"),
        ),
        Index(
            "uq_data_keys_active_system",
            "scope",
            unique=True,
            postgresql_where=text("status = 'active' AND investigation_id IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    kek_id: Mapped[str] = mapped_column(Text, nullable=False)
    wrapped_dek: Mapped[bytes | None] = mapped_column(LargeBinary)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="active")
    created_at: Mapped[datetime] = created_at_col()
    retired_at: Mapped[datetime | None]
    destroyed_at: Mapped[datetime | None]
