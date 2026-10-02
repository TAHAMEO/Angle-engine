"""Policy decisions, abuse reports, audit log, jobs and platform tables (not investigation-scoped)."""

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
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from angel_engine.core.enums import AbuseCategory, AbuseStatus, JobQueue, JobStatus, PolicyDecisionValue, values
from angel_engine.db.base import Base, check_in, created_at_col, updated_at_col, uuid_pk


class PolicyDecision(Base):
    __tablename__ = "policy_decisions"
    __table_args__ = (
        CheckConstraint(check_in("decision", values(PolicyDecisionValue)), name="decision"),
        CheckConstraint(
            f"review_outcome IS NULL OR {check_in('review_outcome', ('approved', 'rejected'))}", name="review_outcome"
        ),
        Index("ix_policy_decisions_user_created", "user_id", "created_at"),
        Index("ix_policy_decisions_review", "decision", postgresql_where=text("review_outcome IS NULL")),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="SET NULL"), index=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    surface: Mapped[str] = mapped_column(Text, nullable=False)
    input: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E system_policy]
    input_mac: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    decision: Mapped[str] = mapped_column(Text, nullable=False)
    categories: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, server_default=text("'{}'"))
    rule_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, server_default=text("'{}'"))
    rule_pack_version: Mapped[str] = mapped_column(Text, nullable=False)
    llm_decision: Mapped[str | None] = mapped_column(Text)
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_type: Mapped[str | None] = mapped_column(Text)
    target_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    review_outcome: Mapped[str | None] = mapped_column(Text)
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    reviewed_at: Mapped[datetime | None]
    input_expires_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = created_at_col()


class AbuseReport(Base):
    __tablename__ = "abuse_reports"
    __table_args__ = (
        CheckConstraint(check_in("category", values(AbuseCategory)), name="category"),
        CheckConstraint(check_in("status", values(AbuseStatus)), name="status"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    category: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # [E system_abuse]
    contact: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E system_abuse]
    target_ref: Mapped[str | None] = mapped_column(Text)
    reporter_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(Text, nullable=False, default=AbuseStatus.NEW.value)
    triage_notes: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E system_abuse]
    handled_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    ip_pseudonym: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
    resolved_at: Mapped[datetime | None]


class AuditLog(Base):
    """Append-only, hash-chained audit trail. Details never contain plaintext content."""

    __tablename__ = "audit_log"
    __table_args__ = (
        CheckConstraint(check_in("actor_type", ("user", "system", "worker", "anonymous")), name="actor_type"),
        CheckConstraint(check_in("outcome", ("success", "denied", "failure")), name="outcome"),
        Index("ix_audit_log_investigation_seq", "investigation_id", "seq"),
        Index("ix_audit_log_actor_seq", "actor_id", "seq"),
        Index("ix_audit_log_occurred_brin", "occurred_at", postgresql_using="brin"),
    )

    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    occurred_at: Mapped[datetime]
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    actor_role: Mapped[str | None] = mapped_column(Text)
    actor_type: Mapped[str] = mapped_column(Text, nullable=False)
    session_pseudonym: Mapped[str | None] = mapped_column(Text)
    ip_pseudonym: Mapped[str | None] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    target_type: Mapped[str | None] = mapped_column(Text)
    target_id: Mapped[str | None] = mapped_column(Text)
    request_id: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    prev_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    row_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)


class AuditChainHead(Base):
    __tablename__ = "audit_chain_head"
    __table_args__ = (CheckConstraint("id = 1", name="singleton"),)

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    last_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)


class AuditAnchor(Base):
    __tablename__ = "audit_anchors"

    id: Mapped[uuid.UUID] = uuid_pk()
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    row_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    anchor_mac: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False, default="daily")
    created_at: Mapped[datetime] = created_at_col()


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint(check_in("queue", values(JobQueue)), name="queue"),
        CheckConstraint(check_in("status", values(JobStatus)), name="status"),
        CheckConstraint("pg_column_size(payload) < 8192", name="payload_size"),
        Index("ix_jobs_claim", "queue", "status", "run_after", "priority"),
        Index(
            "uq_jobs_idempotency",
            "idempotency_key",
            unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL"),
        ),
        Index("ix_jobs_lease", "lease_expires_at", postgresql_where=text("status = 'running'")),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    queue: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(Text, nullable=False, default=JobStatus.QUEUED.value)
    priority: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    run_after: Mapped[datetime] = mapped_column(server_default=text("now()"))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    lease_owner: Mapped[str | None] = mapped_column(Text)
    lease_expires_at: Mapped[datetime | None]
    heartbeat_at: Mapped[datetime | None]
    last_error: Mapped[str | None] = mapped_column(Text)
    idempotency_key: Mapped[str | None] = mapped_column(Text)
    progress: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = created_at_col()
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class PeriodicSchedule(Base):
    __tablename__ = "periodic_schedules"

    name: Mapped[str] = mapped_column(Text, primary_key=True)
    queue: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    every_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    next_run_at: Mapped[datetime]
    last_run_at: Mapped[datetime | None]
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class IdempotencyKey(Base):
    __tablename__ = "idempotency_keys"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    key: Mapped[str] = mapped_column(Text, primary_key=True)
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    request_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_body: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = created_at_col()
    expires_at: Mapped[datetime]


class BlobDeletion(Base):
    """Outbox for object-storage deletions so blob removal survives crashes."""

    __tablename__ = "blob_deletions"

    id: Mapped[uuid.UUID] = uuid_pk()
    object_key: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = created_at_col()
    done_at: Mapped[datetime | None]


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_at: Mapped[datetime] = updated_at_col()


class DataExport(Base):
    __tablename__ = "data_exports"
    __table_args__ = (
        CheckConstraint(check_in("status", ("pending", "ready", "failed", "expired", "downloaded")), name="status"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    object_key: Mapped[str | None] = mapped_column(Text)
    file_key: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E system_secrets]
    created_at: Mapped[datetime] = created_at_col()
    expires_at: Mapped[datetime]
    downloaded_at: Mapped[datetime | None]
