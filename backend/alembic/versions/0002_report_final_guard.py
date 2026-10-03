"""Lock finalized reports.

A final report's content, title, options and integrity fields can no longer change and the report cannot be
deleted, except by the investigation purge (``ae.purge``) or a future key re-encryption job (``ae.reencrypt``,
which may only rewrite ciphertext columns).

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-02 23:10:00
"""

from __future__ import annotations

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels = None
depends_on = None

FUNCTION = r"""
CREATE OR REPLACE FUNCTION ae_report_final_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status <> 'final' OR coalesce(current_setting('ae.purge', true), '') = 'on' THEN
    RETURN COALESCE(NEW, OLD);
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'final reports cannot be deleted' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status OR NEW.final_mac IS DISTINCT FROM OLD.final_mac
     OR NEW.final_sha256 IS DISTINCT FROM OLD.final_sha256 OR NEW.audit_seq IS DISTINCT FROM OLD.audit_seq
     OR NEW.options IS DISTINCT FROM OLD.options OR NEW.finalized_at IS DISTINCT FROM OLD.finalized_at
     OR NEW.investigation_id IS DISTINCT FROM OLD.investigation_id THEN
    RAISE EXCEPTION 'final reports are locked' USING ERRCODE = 'check_violation';
  END IF;
  IF (NEW.body IS DISTINCT FROM OLD.body OR NEW.title IS DISTINCT FROM OLD.title)
     AND coalesce(current_setting('ae.reencrypt', true), '') <> 'on' THEN
    RAISE EXCEPTION 'final reports are locked' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$
"""
TRIGGER = (
    "CREATE TRIGGER reports_final_guard BEFORE UPDATE OR DELETE ON reports "
    "FOR EACH ROW EXECUTE FUNCTION ae_report_final_guard()"
)


def upgrade() -> None:
    # asyncpg runs one statement per call
    op.execute(FUNCTION)
    op.execute(TRIGGER)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS reports_final_guard ON reports")
    op.execute("DROP FUNCTION IF EXISTS ae_report_final_guard()")
