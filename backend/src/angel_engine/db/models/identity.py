"""Identity, sessions, legal documents, attestations."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, CITEXT, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from angel_engine.core.enums import LegalDocumentKind, Role, SessionState, UserStatus, values
from angel_engine.db.base import Base, check_in, created_at_col, updated_at_col, uuid_pk


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(check_in("role", values(Role)), name="role"),
        CheckConstraint(check_in("status", values(UserStatus)), name="status"),
        CheckConstraint("refusal_flag_level BETWEEN 0 AND 3", name="refusal_flag_level"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    email: Mapped[str] = mapped_column(CITEXT, unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False, default=Role.INVESTIGATOR.value)
    status: Mapped[str] = mapped_column(Text, nullable=False, default=UserStatus.PENDING.value)
    organization_unit: Mapped[str | None] = mapped_column(Text)
    #: TOTP secret, encrypted with the ``system_secrets`` DEK.
    mfa_secret: Mapped[bytes | None] = mapped_column(LargeBinary)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_last_timestep: Mapped[int | None] = mapped_column(BigInteger)
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lockout_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None]
    #: 0 none · 1 supervisor notified · 2 every request needs review · 3 suspended pending admin review
    refusal_flag_level: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    access_justification: Mapped[bytes | None] = mapped_column(LargeBinary)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    approved_at: Mapped[datetime | None]
    terms_version_accepted: Mapped[str | None] = mapped_column(Text)
    terms_accepted_at: Mapped[datetime | None]
    password_changed_at: Mapped[datetime | None]
    last_login_at: Mapped[datetime | None]
    last_active_investigation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    preferences: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    disabled_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class RecoveryCode(Base):
    __tablename__ = "recovery_codes"
    __table_args__ = (UniqueConstraint("user_id", "code_mac"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    code_mac: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    used_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = created_at_col()


class UserSession(Base):
    __tablename__ = "user_sessions"
    __table_args__ = (
        CheckConstraint(check_in("state", values(SessionState)), name="state"),
        Index("ix_user_sessions_user_active", "user_id", postgresql_where=text("revoked_at IS NULL")),
        Index("ix_user_sessions_absolute", "absolute_expires_at"),
    )

    token_hash: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    #: Public, non-secret handle used to list and revoke sessions.
    public_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), unique=True, nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False)
    csrf_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = created_at_col()
    last_seen_at: Mapped[datetime]
    idle_expires_at: Mapped[datetime]
    absolute_expires_at: Mapped[datetime]
    reauth_at: Mapped[datetime | None]
    mfa_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    revoked_at: Mapped[datetime | None]
    revoke_reason: Mapped[str | None] = mapped_column(Text)
    ip_pseudonym: Mapped[str | None] = mapped_column(Text)
    ua_family: Mapped[str | None] = mapped_column(Text)


class LegalDocument(Base):
    __tablename__ = "legal_documents"
    __table_args__ = (
        CheckConstraint(check_in("kind", values(LegalDocumentKind)), name="kind"),
        UniqueConstraint("kind", "version"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(Text, nullable=False)
    effective_at: Mapped[datetime]
    created_at: Mapped[datetime] = created_at_col()


class Attestation(Base):
    __tablename__ = "attestations"
    __table_args__ = (CheckConstraint(check_in("kind", ("account", "investigation_purpose")), name="kind"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="SET NULL"), index=True
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    document_versions: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    statements: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    accepted_at: Mapped[datetime] = created_at_col()
    ip_pseudonym: Mapped[str | None] = mapped_column(Text)
