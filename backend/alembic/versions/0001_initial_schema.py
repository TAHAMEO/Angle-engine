"""initial schema

Revision ID: 0001
Revises: 
Create Date: 2026-10-02 02:16:48.866890
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0001'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


RLS_TABLES = (
    "sources", "collection_runs", "evidence_items", "findings", "finding_evidence", "finding_status_history",
    "facts", "suggestions", "entities", "entity_mentions", "relationships", "relationship_evidence",
    "relationship_status_history", "timeline_events", "timeline_event_evidence", "images", "image_hashes",
    "image_analyses", "image_clues", "notes", "reports", "report_exports", "ai_interactions", "ai_proposals",
)

PRE_SQL = """
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
"""

FUNCTIONS_SQL = r"""
-- Transaction-local investigation scope for row-level security.
CREATE OR REPLACE FUNCTION ae_scope() RETURNS uuid[] LANGUAGE sql STABLE AS $$
  SELECT coalesce(string_to_array(NULLIF(current_setting('ae.inv_ids', true), ''), ',')::uuid[], '{}'::uuid[])
$$;

-- Evidence items are immutable observations.
CREATE OR REPLACE FUNCTION ae_evidence_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.excerpt IS DISTINCT FROM OLD.excerpt OR NEW.content_mac IS DISTINCT FROM OLD.content_mac
     OR NEW.captured_at IS DISTINCT FROM OLD.captured_at OR NEW.source_id IS DISTINCT FROM OLD.source_id
     OR NEW.origin_image_id IS DISTINCT FROM OLD.origin_image_id OR NEW.provenance IS DISTINCT FROM OLD.provenance
     OR NEW.investigation_id IS DISTINCT FROM OLD.investigation_id THEN
    RAISE EXCEPTION 'evidence items are immutable' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

-- Provenance never changes; verification status only changes inside an audited transition.
CREATE OR REPLACE FUNCTION ae_status_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.provenance IS DISTINCT FROM OLD.provenance THEN
    RAISE EXCEPTION 'provenance is immutable' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.verification_status IS DISTINCT FROM OLD.verification_status
     AND coalesce(current_setting('ae.transition', true), '') <> 'on' THEN
    RAISE EXCEPTION 'verification status may only change through an audited transition'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

-- Non-AI findings must cite at least one evidence item when created.
CREATE OR REPLACE FUNCTION ae_finding_requires_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.provenance <> 'ai_hypothesis'
     AND EXISTS (SELECT 1 FROM findings f WHERE f.id = NEW.id)
     AND NOT EXISTS (SELECT 1 FROM finding_evidence fe WHERE fe.finding_id = NEW.id) THEN
    RAISE EXCEPTION 'a finding must cite at least one evidence item' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END $$;

-- Every relationship must be supported by at least one evidence item.
CREATE OR REPLACE FUNCTION ae_relationship_requires_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM relationships r WHERE r.id = NEW.id)
     AND NOT EXISTS (SELECT 1 FROM relationship_evidence re WHERE re.relationship_id = NEW.id) THEN
    RAISE EXCEPTION 'a relationship must cite at least one evidence item' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END $$;

-- A relationship disappears together with its last supporting evidence link.
CREATE OR REPLACE FUNCTION ae_relationship_prune() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM relationships r
   WHERE r.id = OLD.relationship_id
     AND NOT EXISTS (SELECT 1 FROM relationship_evidence re WHERE re.relationship_id = OLD.relationship_id);
  RETURN NULL;
END $$;

-- Timeline events must cite evidence and disappear with their last evidence link.
CREATE OR REPLACE FUNCTION ae_timeline_requires_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM timeline_events t WHERE t.id = NEW.id)
     AND NOT EXISTS (SELECT 1 FROM timeline_event_evidence te WHERE te.event_id = NEW.id) THEN
    RAISE EXCEPTION 'a timeline event must cite at least one evidence item' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION ae_timeline_prune() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM timeline_events t
   WHERE t.id = OLD.event_id
     AND NOT EXISTS (SELECT 1 FROM timeline_event_evidence te WHERE te.event_id = OLD.event_id);
  RETURN NULL;
END $$;

-- Status-history tables are append-only; rows go only when their parent row is gone.
CREATE OR REPLACE FUNCTION ae_history_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  parent_exists boolean;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
  END IF;
  EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I WHERE id = $1)', TG_ARGV[0])
     INTO parent_exists USING (to_jsonb(OLD) ->> TG_ARGV[1])::uuid;
  IF parent_exists AND coalesce(current_setting('ae.purge', true), '') <> 'on' THEN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN OLD;
END $$;

-- The audit log is append-only; only the retention job (with an explicit flag) may trim it.
CREATE OR REPLACE FUNCTION ae_audit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' OR coalesce(current_setting('ae.audit_purge', true), '') <> 'on' THEN
    RAISE EXCEPTION 'the audit log is append-only' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN OLD;
END $$;

CREATE OR REPLACE FUNCTION ae_no_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% cannot be truncated', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END $$;
"""

TRIGGERS_SQL = """
CREATE TRIGGER trg_evidence_immutable BEFORE UPDATE ON evidence_items
  FOR EACH ROW EXECUTE FUNCTION ae_evidence_immutable();
CREATE TRIGGER trg_findings_status_guard BEFORE UPDATE ON findings
  FOR EACH ROW EXECUTE FUNCTION ae_status_guard();
CREATE TRIGGER trg_relationships_status_guard BEFORE UPDATE ON relationships
  FOR EACH ROW EXECUTE FUNCTION ae_status_guard();
CREATE TRIGGER trg_timeline_status_guard BEFORE UPDATE ON timeline_events
  FOR EACH ROW EXECUTE FUNCTION ae_status_guard();
CREATE CONSTRAINT TRIGGER trg_finding_requires_evidence AFTER INSERT ON findings
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ae_finding_requires_evidence();
CREATE CONSTRAINT TRIGGER trg_relationship_requires_evidence AFTER INSERT ON relationships
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ae_relationship_requires_evidence();
CREATE TRIGGER trg_relationship_prune AFTER DELETE ON relationship_evidence
  FOR EACH ROW EXECUTE FUNCTION ae_relationship_prune();
CREATE CONSTRAINT TRIGGER trg_timeline_requires_evidence AFTER INSERT ON timeline_events
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ae_timeline_requires_evidence();
CREATE TRIGGER trg_timeline_prune AFTER DELETE ON timeline_event_evidence
  FOR EACH ROW EXECUTE FUNCTION ae_timeline_prune();
CREATE TRIGGER trg_finding_history_guard BEFORE UPDATE OR DELETE ON finding_status_history
  FOR EACH ROW EXECUTE FUNCTION ae_history_guard('findings', 'finding_id');
CREATE TRIGGER trg_relationship_history_guard BEFORE UPDATE OR DELETE ON relationship_status_history
  FOR EACH ROW EXECUTE FUNCTION ae_history_guard('relationships', 'relationship_id');
CREATE TRIGGER trg_audit_guard BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION ae_audit_guard();
CREATE TRIGGER trg_audit_no_truncate BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION ae_no_truncate();
"""

GRANTS_SQL = """
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ae_app') THEN
    GRANT USAGE ON SCHEMA public TO ae_app, ae_worker, ae_maintenance;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ae_app, ae_worker, ae_maintenance;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ae_app, ae_worker, ae_maintenance;
    GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO ae_app, ae_worker, ae_maintenance;
    REVOKE UPDATE, DELETE ON audit_log FROM ae_app, ae_worker;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
      GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ae_app, ae_worker, ae_maintenance;
  END IF;
END $$;
"""

SEED_SQL = """
INSERT INTO audit_chain_head (id, last_seq, last_hash) VALUES (1, 0, decode(repeat('00', 32), 'hex'));
INSERT INTO periodic_schedules (name, queue, kind, every_seconds, next_run_at, enabled) VALUES
  ('purge_image_originals', 'maintenance', 'retention.purge_image_originals', 900, now(), true),
  ('retention_sweep', 'maintenance', 'retention.sweep', 3600, now(), true),
  ('session_cleanup', 'maintenance', 'maintenance.session_cleanup', 3600, now(), true),
  ('blob_deletions', 'maintenance', 'maintenance.blob_deletions', 600, now(), true),
  ('expire_exports', 'maintenance', 'retention.expire_exports', 3600, now(), true),
  ('audit_anchor', 'maintenance', 'audit.anchor_and_verify', 86400, now(), true),
  ('ip_key_rotation', 'maintenance', 'keys.destroy_old_ip_keys', 86400, now(), true),
  ('kek_rotation', 'maintenance', 'keys.rotate_kek', 2592000, now() + interval '30 days', true);
"""


def _statements(sql: str) -> list[str]:
    """Split SQL into statements, respecting $$-quoted function bodies (asyncpg runs one at a time)."""
    sql = "\n".join(line for line in sql.splitlines() if not line.lstrip().startswith("--"))
    out: list[str] = []
    buf: list[str] = []
    in_dollar = False
    i = 0
    while i < len(sql):
        if sql.startswith("$$", i):
            in_dollar = not in_dollar
            buf.append("$$")
            i += 2
            continue
        ch = sql[i]
        if ch == ";" and not in_dollar:
            stmt = "".join(buf).strip()
            if stmt and not all(line.strip().startswith("--") or not line.strip() for line in stmt.splitlines()):
                out.append(stmt)
            buf = []
        else:
            buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return out


def _run(sql: str) -> None:
    for statement in _statements(sql):
        op.execute(statement)


def _apply_security() -> None:
    _run(FUNCTIONS_SQL)
    _run(TRIGGERS_SQL)
    for table in RLS_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY {table}_investigation_scope ON {table} "
            "USING (investigation_id = ANY (ae_scope())) WITH CHECK (investigation_id = ANY (ae_scope()))"
        )
    _run(GRANTS_SQL)
    _run(SEED_SQL)


def upgrade() -> None:
    _run(PRE_SQL)
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('audit_anchors',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('seq', sa.BigInteger(), nullable=False),
    sa.Column('row_hash', sa.LargeBinary(), nullable=False),
    sa.Column('anchor_mac', sa.LargeBinary(), nullable=False),
    sa.Column('kind', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_anchors'))
    )
    op.create_table('audit_chain_head',
    sa.Column('id', sa.SmallInteger(), nullable=False),
    sa.Column('last_seq', sa.BigInteger(), nullable=False),
    sa.Column('last_hash', sa.LargeBinary(), nullable=False),
    sa.CheckConstraint('id = 1', name=op.f('ck_audit_chain_head_singleton')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_chain_head'))
    )
    op.create_table('audit_log',
    sa.Column('seq', sa.BigInteger(), autoincrement=False, nullable=False),
    sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('actor_id', sa.UUID(), nullable=True),
    sa.Column('actor_role', sa.Text(), nullable=True),
    sa.Column('actor_type', sa.Text(), nullable=False),
    sa.Column('session_pseudonym', sa.Text(), nullable=True),
    sa.Column('ip_pseudonym', sa.Text(), nullable=True),
    sa.Column('action', sa.Text(), nullable=False),
    sa.Column('outcome', sa.Text(), nullable=False),
    sa.Column('investigation_id', sa.UUID(), nullable=True),
    sa.Column('target_type', sa.Text(), nullable=True),
    sa.Column('target_id', sa.Text(), nullable=True),
    sa.Column('request_id', sa.Text(), nullable=True),
    sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('prev_hash', sa.LargeBinary(), nullable=False),
    sa.Column('row_hash', sa.LargeBinary(), nullable=False),
    sa.CheckConstraint("actor_type IN ('user', 'system', 'worker', 'anonymous')", name=op.f('ck_audit_log_actor_type')),
    sa.CheckConstraint("outcome IN ('success', 'denied', 'failure')", name=op.f('ck_audit_log_outcome')),
    sa.PrimaryKeyConstraint('seq', name=op.f('pk_audit_log'))
    )
    op.create_index('ix_audit_log_actor_seq', 'audit_log', ['actor_id', 'seq'], unique=False)
    op.create_index('ix_audit_log_investigation_seq', 'audit_log', ['investigation_id', 'seq'], unique=False)
    op.create_index('ix_audit_log_occurred_brin', 'audit_log', ['occurred_at'], unique=False, postgresql_using='brin')
    op.create_table('blob_deletions',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('object_key', sa.Text(), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('done_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_blob_deletions'))
    )
    op.create_table('investigation_ref_counters',
    sa.Column('year', sa.SmallInteger(), nullable=False),
    sa.Column('last_seq', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('year', name=op.f('pk_investigation_ref_counters'))
    )
    op.create_table('legal_documents',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('kind', sa.Text(), nullable=False),
    sa.Column('version', sa.Text(), nullable=False),
    sa.Column('sha256', sa.Text(), nullable=False),
    sa.Column('effective_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("kind IN ('terms', 'privacy', 'acceptable_use', 'responsible_use')", name=op.f('ck_legal_documents_kind')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_legal_documents')),
    sa.UniqueConstraint('kind', 'version', name=op.f('uq_legal_documents_kind_version'))
    )
    op.create_table('periodic_schedules',
    sa.Column('name', sa.Text(), nullable=False),
    sa.Column('queue', sa.Text(), nullable=False),
    sa.Column('kind', sa.Text(), nullable=False),
    sa.Column('every_seconds', sa.Integer(), nullable=False),
    sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('name', name=op.f('pk_periodic_schedules'))
    )
    op.create_table('users',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('email', postgresql.CITEXT(), nullable=False),
    sa.Column('display_name', sa.Text(), nullable=False),
    sa.Column('password_hash', sa.Text(), nullable=False),
    sa.Column('role', sa.Text(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('organization_unit', sa.Text(), nullable=True),
    sa.Column('mfa_secret', sa.LargeBinary(), nullable=True),
    sa.Column('mfa_enabled', sa.Boolean(), nullable=False),
    sa.Column('mfa_last_timestep', sa.BigInteger(), nullable=True),
    sa.Column('failed_logins', sa.Integer(), nullable=False),
    sa.Column('lockout_count', sa.Integer(), nullable=False),
    sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('refusal_flag_level', sa.SmallInteger(), nullable=False),
    sa.Column('access_justification', sa.LargeBinary(), nullable=True),
    sa.Column('approved_by', sa.Uuid(), nullable=True),
    sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('terms_version_accepted', sa.Text(), nullable=True),
    sa.Column('terms_accepted_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('password_changed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_active_investigation_id', sa.UUID(), nullable=True),
    sa.Column('preferences', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('disabled_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("role IN ('admin', 'supervisor', 'investigator', 'viewer', 'auditor')", name=op.f('ck_users_role')),
    sa.CheckConstraint("status IN ('pending', 'active', 'disabled')", name=op.f('ck_users_status')),
    sa.CheckConstraint('refusal_flag_level BETWEEN 0 AND 3', name=op.f('ck_users_refusal_flag_level')),
    sa.ForeignKeyConstraint(['approved_by'], ['users.id'], name=op.f('fk_users_approved_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_users')),
    sa.UniqueConstraint('email', name=op.f('uq_users_email'))
    )
    op.create_table('abuse_reports',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('category', sa.Text(), nullable=False),
    sa.Column('description', sa.LargeBinary(), nullable=False),
    sa.Column('contact', sa.LargeBinary(), nullable=True),
    sa.Column('target_ref', sa.Text(), nullable=True),
    sa.Column('reporter_user_id', sa.Uuid(), nullable=True),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('triage_notes', sa.LargeBinary(), nullable=True),
    sa.Column('handled_by', sa.Uuid(), nullable=True),
    sa.Column('ip_pseudonym', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("category IN ('targeted_by_investigation', 'platform_misuse', 'data_removal_request', 'security_vulnerability', 'inaccurate_information', 'other')", name=op.f('ck_abuse_reports_category')),
    sa.CheckConstraint("status IN ('new', 'triaging', 'actioned', 'dismissed')", name=op.f('ck_abuse_reports_status')),
    sa.ForeignKeyConstraint(['handled_by'], ['users.id'], name=op.f('fk_abuse_reports_handled_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['reporter_user_id'], ['users.id'], name=op.f('fk_abuse_reports_reporter_user_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_abuse_reports'))
    )
    op.create_table('data_exports',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('object_key', sa.Text(), nullable=True),
    sa.Column('file_key', sa.LargeBinary(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('downloaded_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("status IN ('pending', 'ready', 'failed', 'expired', 'downloaded')", name=op.f('ck_data_exports_status')),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_data_exports_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_data_exports'))
    )
    op.create_index(op.f('ix_data_exports_user_id'), 'data_exports', ['user_id'], unique=False)
    op.create_table('idempotency_keys',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('key', sa.Text(), nullable=False),
    sa.Column('scope', sa.Text(), nullable=False),
    sa.Column('request_hash', sa.LargeBinary(), nullable=False),
    sa.Column('response_status', sa.Integer(), nullable=True),
    sa.Column('response_body', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_idempotency_keys_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('user_id', 'key', name=op.f('pk_idempotency_keys'))
    )
    op.create_table('investigations',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('ref_year', sa.SmallInteger(), nullable=False),
    sa.Column('ref_seq', sa.Integer(), nullable=False),
    sa.Column('public_ref', sa.Text(), sa.Computed("'AE-' || ref_year::text || '-' || lpad(ref_seq::text, 6, '0')", persisted=True), nullable=False),
    sa.Column('title', sa.Text(), nullable=False),
    sa.Column('description', sa.LargeBinary(), nullable=True),
    sa.Column('purpose', sa.LargeBinary(), nullable=False),
    sa.Column('purpose_category', sa.Text(), nullable=False),
    sa.Column('lawful_basis', sa.Text(), nullable=False),
    sa.Column('authorization_ref', sa.LargeBinary(), nullable=True),
    sa.Column('jurisdiction', sa.Text(), nullable=True),
    sa.Column('subject_type', sa.Text(), nullable=False),
    sa.Column('restricted_mode', sa.Boolean(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('owner_id', sa.Uuid(), nullable=False),
    sa.Column('reviewed_by', sa.Uuid(), nullable=True),
    sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('review_note', sa.LargeBinary(), nullable=True),
    sa.Column('last_policy_decision_id', sa.Uuid(), nullable=True),
    sa.Column('image_original_retention_hours', sa.Integer(), nullable=True),
    sa.Column('closed_retention_days', sa.Integer(), nullable=True),
    sa.Column('ai_enabled', sa.Boolean(), nullable=False),
    sa.Column('legal_hold', sa.Boolean(), nullable=False),
    sa.Column('legal_hold_reason', sa.LargeBinary(), nullable=True),
    sa.Column('evidence_seq', sa.Integer(), nullable=False),
    sa.Column('finding_seq', sa.Integer(), nullable=False),
    sa.Column('source_seq', sa.Integer(), nullable=False),
    sa.Column('image_seq', sa.Integer(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('submitted_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('activated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('archived_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('purge_after', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("lawful_basis IN ('legitimate_interest', 'public_interest_journalism', 'legal_obligation', 'law_enforcement_authorization', 'research_exemption', 'contract', 'consent', 'other')", name=op.f('ck_investigations_lawful_basis')),
    sa.CheckConstraint("purpose_category IN ('journalism', 'fact_checking', 'due_diligence', 'brand_protection', 'cybersecurity', 'academic_research', 'legal_proceedings', 'law_enforcement', 'misinformation_research', 'image_verification', 'other')", name=op.f('ck_investigations_purpose_category')),
    sa.CheckConstraint("status IN ('draft', 'pending_review', 'active', 'suspended', 'closed', 'archived', 'refused', 'deleted')", name=op.f('ck_investigations_status')),
    sa.CheckConstraint("subject_type <> 'individual' OR restricted_mode", name=op.f('ck_investigations_individual_restricted')),
    sa.CheckConstraint("subject_type IN ('organization', 'website', 'public_event', 'public_figure_role', 'individual', 'image_provenance', 'other')", name=op.f('ck_investigations_subject_type')),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], name=op.f('fk_investigations_owner_id_users'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['reviewed_by'], ['users.id'], name=op.f('fk_investigations_reviewed_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_investigations')),
    sa.UniqueConstraint('public_ref', name=op.f('uq_investigations_public_ref')),
    sa.UniqueConstraint('ref_year', 'ref_seq', name=op.f('uq_investigations_ref_year_ref_seq'))
    )
    op.create_index(op.f('ix_investigations_owner_id'), 'investigations', ['owner_id'], unique=False)
    op.create_table('recovery_codes',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('code_mac', sa.LargeBinary(), nullable=False),
    sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_recovery_codes_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_recovery_codes')),
    sa.UniqueConstraint('user_id', 'code_mac', name=op.f('uq_recovery_codes_user_id_code_mac'))
    )
    op.create_index(op.f('ix_recovery_codes_user_id'), 'recovery_codes', ['user_id'], unique=False)
    op.create_table('settings',
    sa.Column('key', sa.Text(), nullable=False),
    sa.Column('value', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['updated_by'], ['users.id'], name=op.f('fk_settings_updated_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('key', name=op.f('pk_settings'))
    )
    op.create_table('user_sessions',
    sa.Column('token_hash', sa.LargeBinary(), nullable=False),
    sa.Column('public_id', sa.UUID(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('state', sa.Text(), nullable=False),
    sa.Column('csrf_key', sa.LargeBinary(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('idle_expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('absolute_expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('reauth_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('mfa_attempts', sa.Integer(), nullable=False),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoke_reason', sa.Text(), nullable=True),
    sa.Column('ip_pseudonym', sa.Text(), nullable=True),
    sa.Column('ua_family', sa.Text(), nullable=True),
    sa.CheckConstraint("state IN ('mfa_pending', 'mfa_enroll', 'active')", name=op.f('ck_user_sessions_state')),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_user_sessions_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('token_hash', name=op.f('pk_user_sessions')),
    sa.UniqueConstraint('public_id', name=op.f('uq_user_sessions_public_id'))
    )
    op.create_index('ix_user_sessions_absolute', 'user_sessions', ['absolute_expires_at'], unique=False)
    op.create_index('ix_user_sessions_user_active', 'user_sessions', ['user_id'], unique=False, postgresql_where=sa.text('revoked_at IS NULL'))
    op.create_table('ai_interactions',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=True),
    sa.Column('task', sa.Text(), nullable=False),
    sa.Column('prompt', sa.LargeBinary(), nullable=True),
    sa.Column('response', sa.LargeBinary(), nullable=True),
    sa.Column('context_evidence_ids', postgresql.ARRAY(sa.UUID()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('cited_evidence_ids', postgresql.ARRAY(sa.UUID()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('provider', sa.Text(), nullable=False),
    sa.Column('model', sa.Text(), nullable=True),
    sa.Column('input_tokens', sa.Integer(), nullable=False),
    sa.Column('output_tokens', sa.Integer(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('grounding', sa.Text(), nullable=True),
    sa.Column('validation', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('policy_decision_id', sa.UUID(), nullable=True),
    sa.Column('error_code', sa.Text(), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("grounding IS NULL OR grounding IN ('grounded', 'partial', 'insufficient_evidence', 'policy_refused', 'provider_refused')", name=op.f('ck_ai_interactions_grounding')),
    sa.CheckConstraint("status IN ('pending', 'running', 'completed', 'failed')", name=op.f('ck_ai_interactions_status')),
    sa.CheckConstraint("task IN ('summarize', 'compare', 'contradictions', 'gaps', 'suggest_queries', 'extract', 'timeline', 'draft_report', 'check_conclusion', 'chat', 'vision_clues')", name=op.f('ck_ai_interactions_task')),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_ai_interactions_investigation', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_ai_interactions_user_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_ai_interactions')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_ai_interactions_inv_id')
    )
    op.create_index(op.f('ix_ai_interactions_investigation_id'), 'ai_interactions', ['investigation_id'], unique=False)
    op.create_table('attestations',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=True),
    sa.Column('kind', sa.Text(), nullable=False),
    sa.Column('document_versions', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('statements', postgresql.ARRAY(sa.Text()), nullable=False),
    sa.Column('accepted_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('ip_pseudonym', sa.Text(), nullable=True),
    sa.CheckConstraint("kind IN ('account', 'investigation_purpose')", name=op.f('ck_attestations_kind')),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name=op.f('fk_attestations_investigation_id_investigations'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_attestations_user_id_users'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_attestations'))
    )
    op.create_index(op.f('ix_attestations_investigation_id'), 'attestations', ['investigation_id'], unique=False)
    op.create_index(op.f('ix_attestations_user_id'), 'attestations', ['user_id'], unique=False)
    op.create_table('collection_runs',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('connector_id', sa.Text(), nullable=False),
    sa.Column('input_type', sa.Text(), nullable=False),
    sa.Column('query', sa.LargeBinary(), nullable=False),
    sa.Column('params', sa.LargeBinary(), nullable=True),
    sa.Column('purpose_note', sa.LargeBinary(), nullable=True),
    sa.Column('policy_decision_id', sa.UUID(), nullable=True),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('requested_by', sa.Uuid(), nullable=True),
    sa.Column('origin_image_id', sa.UUID(), nullable=True),
    sa.Column('origin_clue_id', sa.UUID(), nullable=True),
    sa.Column('records_count', sa.Integer(), nullable=False),
    sa.Column('references_count', sa.Integer(), nullable=False),
    sa.Column('leads', sa.LargeBinary(), nullable=True),
    sa.Column('leads_expire_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('warnings', postgresql.ARRAY(sa.Text()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('error_code', sa.Text(), nullable=True),
    sa.Column('idempotency_key', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("status IN ('queued', 'running', 'succeeded', 'partial', 'failed', 'cancelled', 'pending_review', 'refused')", name=op.f('ck_collection_runs_status')),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_collection_runs_investigation', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['requested_by'], ['users.id'], name=op.f('fk_collection_runs_requested_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_collection_runs')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_collection_runs_inv_id'),
    sa.UniqueConstraint('investigation_id', 'idempotency_key', name=op.f('uq_collection_runs_investigation_id_idempotency_key'))
    )
    op.create_index(op.f('ix_collection_runs_investigation_id'), 'collection_runs', ['investigation_id'], unique=False)
    op.create_table('data_keys',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=True),
    sa.Column('scope', sa.Text(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('kek_id', sa.Text(), nullable=False),
    sa.Column('wrapped_dek', sa.LargeBinary(), nullable=True),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('retired_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('destroyed_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("(scope = 'investigation') = (investigation_id IS NOT NULL)", name=op.f('ck_data_keys_scope_investigation')),
    sa.CheckConstraint("(status = 'destroyed') = (wrapped_dek IS NULL)", name=op.f('ck_data_keys_destroyed_has_no_key')),
    sa.CheckConstraint("scope IN ('investigation', 'system_secrets', 'system_abuse', 'system_policy')", name=op.f('ck_data_keys_scope')),
    sa.CheckConstraint("status IN ('active', 'retired', 'destroyed')", name=op.f('ck_data_keys_status')),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name=op.f('fk_data_keys_investigation_id_investigations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_data_keys'))
    )
    op.create_index(op.f('ix_data_keys_investigation_id'), 'data_keys', ['investigation_id'], unique=False)
    op.create_index('uq_data_keys_active_investigation', 'data_keys', ['investigation_id'], unique=True, postgresql_where=sa.text("status = 'active' AND investigation_id IS NOT NULL"))
    op.create_index('uq_data_keys_active_system', 'data_keys', ['scope'], unique=True, postgresql_where=sa.text("status = 'active' AND investigation_id IS NULL"))
    op.create_table('entities',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('type', sa.Text(), nullable=False),
    sa.Column('name', sa.Text(), nullable=True),
    sa.Column('name_enc', sa.LargeBinary(), nullable=True),
    sa.Column('canonical_mac', sa.LargeBinary(), nullable=False),
    sa.Column('location_level', sa.Text(), nullable=True),
    sa.Column('country', sa.Text(), nullable=True),
    sa.Column('public_role_basis', sa.LargeBinary(), nullable=True),
    sa.Column('attributes', sa.LargeBinary(), nullable=True),
    sa.Column('merged_into_id', sa.UUID(), nullable=True),
    sa.Column('created_via', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("(type IN ('organization', 'website', 'domain', 'brand', 'product', 'landmark', 'event', 'location') AND name IS NOT NULL) OR (NOT type IN ('organization', 'website', 'domain', 'brand', 'product', 'landmark', 'event', 'location') AND name IS NULL AND name_enc IS NOT NULL)", name=op.f('ck_entities_name_storage')),
    sa.CheckConstraint("location_level IS NULL OR location_level IN ('country','admin1','locality','landmark')", name=op.f('ck_entities_location_level')),
    sa.CheckConstraint("type <> 'location' OR location_level IS NOT NULL", name=op.f('ck_entities_location_has_level')),
    sa.CheckConstraint("type <> 'public_figure' OR public_role_basis IS NOT NULL", name=op.f('ck_entities_public_figure_basis')),
    sa.CheckConstraint("type IN ('image', 'username', 'website', 'domain', 'webpage', 'organization', 'event', 'document', 'location', 'brand', 'product', 'landmark', 'public_figure')", name=op.f('ck_entities_type')),
    sa.ForeignKeyConstraint(['investigation_id', 'merged_into_id'], ['entities.investigation_id', 'entities.id'], name='fk_entities_merged_into', ondelete='SET NULL (merged_into_id)'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_entities_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_entities')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_entities_inv_id'),
    sa.UniqueConstraint('investigation_id', 'type', 'canonical_mac', name=op.f('uq_entities_investigation_id_type_canonical_mac'))
    )
    op.create_index(op.f('ix_entities_investigation_id'), 'entities', ['investigation_id'], unique=False)
    op.create_index('ix_entities_name_trgm', 'entities', ['name'], unique=False, postgresql_using='gin', postgresql_ops={'name': 'gin_trgm_ops'})
    op.create_table('findings',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('label_seq', sa.Integer(), nullable=False),
    sa.Column('statement', sa.LargeBinary(), nullable=False),
    sa.Column('statement_tokens', postgresql.ARRAY(sa.BigInteger()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('category', sa.Text(), nullable=False),
    sa.Column('provenance', sa.Text(), nullable=False),
    sa.Column('verification_status', sa.Text(), nullable=False),
    sa.Column('confidence', sa.Text(), nullable=True),
    sa.Column('confidence_basis', sa.LargeBinary(), nullable=True),
    sa.Column('sensitive', sa.Boolean(), nullable=False),
    sa.Column('importance', sa.Text(), nullable=False),
    sa.Column('event_time', sa.DateTime(timezone=True), nullable=True),
    sa.Column('event_precision', sa.Text(), nullable=True),
    sa.Column('evidence_removed', sa.Boolean(), nullable=False),
    sa.Column('retracted_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('ai_interaction_id', sa.UUID(), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_via', sa.Text(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('status_changed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("category IN ('websites', 'news_articles', 'public_social_media', 'public_profiles', 'public_documents', 'public_company_information', 'public_government_information', 'public_directories', 'public_forums', 'public_image_sources', 'search_engine_results', 'image_analysis', 'analysis')", name=op.f('ck_findings_category')),
    sa.CheckConstraint("confidence IS NULL OR confidence IN ('low', 'moderate', 'high')", name=op.f('ck_findings_confidence')),
    sa.CheckConstraint("created_via IN ('connector', 'image_analysis', 'manual', 'ai_proposal', 'import')", name=op.f('ck_findings_created_via')),
    sa.CheckConstraint("importance IN ('key', 'normal')", name=op.f('ck_findings_importance')),
    sa.CheckConstraint("provenance IN ('observed', 'source_reported', 'analyst_inference', 'ai_hypothesis')", name=op.f('ck_findings_provenance')),
    sa.CheckConstraint("verification_status <> 'ai_hypothesis' OR provenance = 'ai_hypothesis'", name=op.f('ck_findings_ai_status_requires_ai')),
    sa.CheckConstraint("verification_status IN ('confirmed_by_source', 'corroborated', 'unverified', 'contradicted', 'ai_hypothesis')", name=op.f('ck_findings_verification_status')),
    sa.CheckConstraint('NOT sensitive OR confidence IS NULL', name=op.f('ck_findings_no_confidence_when_sensitive')),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_findings_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_findings_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_findings')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_findings_inv_id')
    )
    op.create_index('ix_findings_inv_category', 'findings', ['investigation_id', 'category'], unique=False)
    op.create_index('ix_findings_inv_status', 'findings', ['investigation_id', 'verification_status'], unique=False)
    op.create_index(op.f('ix_findings_investigation_id'), 'findings', ['investigation_id'], unique=False)
    op.create_index('ix_findings_tokens', 'findings', ['statement_tokens'], unique=False, postgresql_using='gin')
    op.create_table('images',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('label_seq', sa.Integer(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('filename', sa.LargeBinary(), nullable=True),
    sa.Column('declared_mime', sa.Text(), nullable=True),
    sa.Column('mime', sa.Text(), nullable=True),
    sa.Column('byte_size', sa.Integer(), nullable=False),
    sa.Column('width', sa.Integer(), nullable=True),
    sa.Column('height', sa.Integer(), nullable=True),
    sa.Column('sha256', sa.LargeBinary(), nullable=False),
    sa.Column('content_mac', sa.LargeBinary(), nullable=False),
    sa.Column('original_key', sa.Text(), nullable=True),
    sa.Column('original_file_key', sa.LargeBinary(), nullable=True),
    sa.Column('preview_key', sa.Text(), nullable=True),
    sa.Column('preview_file_key', sa.LargeBinary(), nullable=True),
    sa.Column('face_count', sa.Integer(), nullable=False),
    sa.Column('person_count', sa.Integer(), nullable=False),
    sa.Column('metadata_availability', sa.Text(), nullable=True),
    sa.Column('capture_time', sa.DateTime(timezone=True), nullable=True),
    sa.Column('country', sa.Text(), nullable=True),
    sa.Column('region', sa.Text(), nullable=True),
    sa.Column('scan_engine', sa.Text(), nullable=True),
    sa.Column('scan_signature', sa.Text(), nullable=True),
    sa.Column('scan_completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('quarantine_reason', sa.Text(), nullable=True),
    sa.Column('analysis_started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('analysis_completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('original_purge_after', sa.DateTime(timezone=True), nullable=True),
    sa.Column('original_purged_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('files_deleted_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('reverse_search_approved_by', sa.Uuid(), nullable=True),
    sa.Column('reverse_search_purpose', sa.LargeBinary(), nullable=True),
    sa.Column('uploaded_by', sa.Uuid(), nullable=True),
    sa.Column('idempotency_key', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("status IN ('uploaded', 'scanning', 'clean', 'infected', 'quarantined', 'scan_failed', 'analyzing', 'analyzed', 'analysis_failed', 'original_purged', 'files_deleted')", name=op.f('ck_images_status')),
    sa.CheckConstraint('byte_size > 0 AND byte_size <= 26214400', name=op.f('ck_images_byte_size')),
    sa.CheckConstraint('face_count >= 0 AND person_count >= 0', name=op.f('ck_images_counts')),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_images_investigation', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['reverse_search_approved_by'], ['users.id'], name=op.f('fk_images_reverse_search_approved_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['uploaded_by'], ['users.id'], name=op.f('fk_images_uploaded_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_images')),
    sa.UniqueConstraint('investigation_id', 'content_mac', name=op.f('uq_images_investigation_id_content_mac')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_images_inv_id'),
    sa.UniqueConstraint('investigation_id', 'idempotency_key', name=op.f('uq_images_investigation_id_idempotency_key'))
    )
    op.create_index(op.f('ix_images_investigation_id'), 'images', ['investigation_id'], unique=False)
    op.create_index('ix_images_purge', 'images', ['original_purge_after'], unique=False, postgresql_where=sa.text('original_purged_at IS NULL'))
    op.create_table('investigation_members',
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('role', sa.Text(), nullable=False),
    sa.Column('added_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("role IN ('owner', 'editor', 'viewer')", name=op.f('ck_investigation_members_role')),
    sa.ForeignKeyConstraint(['added_by'], ['users.id'], name=op.f('fk_investigation_members_added_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name=op.f('fk_investigation_members_investigation_id_investigations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_investigation_members_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('investigation_id', 'user_id', name=op.f('pk_investigation_members'))
    )
    op.create_index(op.f('ix_investigation_members_user_id'), 'investigation_members', ['user_id'], unique=False)
    op.create_index('uq_investigation_members_single_owner', 'investigation_members', ['investigation_id'], unique=True, postgresql_where=sa.text("role = 'owner'"))
    op.create_table('jobs',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('queue', sa.Text(), nullable=False),
    sa.Column('kind', sa.Text(), nullable=False),
    sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=True),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('priority', sa.SmallInteger(), nullable=False),
    sa.Column('run_after', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('max_attempts', sa.Integer(), nullable=False),
    sa.Column('lease_owner', sa.Text(), nullable=True),
    sa.Column('lease_expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('heartbeat_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('idempotency_key', sa.Text(), nullable=True),
    sa.Column('progress', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('result', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("queue IN ('analysis', 'egress', 'ai', 'maintenance')", name=op.f('ck_jobs_queue')),
    sa.CheckConstraint("status IN ('queued', 'running', 'succeeded', 'dead', 'cancelled')", name=op.f('ck_jobs_status')),
    sa.CheckConstraint('pg_column_size(payload) < 8192', name=op.f('ck_jobs_payload_size')),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_jobs_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name=op.f('fk_jobs_investigation_id_investigations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_jobs'))
    )
    op.create_index('ix_jobs_claim', 'jobs', ['queue', 'status', 'run_after', 'priority'], unique=False)
    op.create_index(op.f('ix_jobs_investigation_id'), 'jobs', ['investigation_id'], unique=False)
    op.create_index('ix_jobs_lease', 'jobs', ['lease_expires_at'], unique=False, postgresql_where=sa.text("status = 'running'"))
    op.create_index('uq_jobs_idempotency', 'jobs', ['idempotency_key'], unique=True, postgresql_where=sa.text('idempotency_key IS NOT NULL'))
    op.create_table('notes',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('target_type', sa.Text(), nullable=False),
    sa.Column('target_id', sa.UUID(), nullable=True),
    sa.Column('body', sa.LargeBinary(), nullable=False),
    sa.Column('body_tokens', postgresql.ARRAY(sa.BigInteger()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('author_id', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("target_type IN ('investigation', 'image', 'finding', 'source', 'entity', 'evidence')", name=op.f('ck_notes_target_type')),
    sa.ForeignKeyConstraint(['author_id'], ['users.id'], name=op.f('fk_notes_author_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_notes_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_notes')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_notes_inv_id')
    )
    op.create_index(op.f('ix_notes_investigation_id'), 'notes', ['investigation_id'], unique=False)
    op.create_index(op.f('ix_notes_target_id'), 'notes', ['target_id'], unique=False)
    op.create_table('oversight_grants',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.Column('grantee_id', sa.Uuid(), nullable=False),
    sa.Column('granted_by', sa.Uuid(), nullable=False),
    sa.Column('reason', sa.LargeBinary(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("expires_at <= created_at + interval '72 hours'", name=op.f('ck_oversight_grants_max_duration')),
    sa.ForeignKeyConstraint(['granted_by'], ['users.id'], name=op.f('fk_oversight_grants_granted_by_users'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['grantee_id'], ['users.id'], name=op.f('fk_oversight_grants_grantee_id_users'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name=op.f('fk_oversight_grants_investigation_id_investigations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_oversight_grants'))
    )
    op.create_index(op.f('ix_oversight_grants_grantee_id'), 'oversight_grants', ['grantee_id'], unique=False)
    op.create_index(op.f('ix_oversight_grants_investigation_id'), 'oversight_grants', ['investigation_id'], unique=False)
    op.create_table('policy_decisions',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=True),
    sa.Column('user_id', sa.Uuid(), nullable=True),
    sa.Column('surface', sa.Text(), nullable=False),
    sa.Column('input', sa.LargeBinary(), nullable=True),
    sa.Column('input_mac', sa.LargeBinary(), nullable=False),
    sa.Column('decision', sa.Text(), nullable=False),
    sa.Column('categories', postgresql.ARRAY(sa.Text()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('rule_ids', postgresql.ARRAY(sa.Text()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('rule_pack_version', sa.Text(), nullable=False),
    sa.Column('llm_decision', sa.Text(), nullable=True),
    sa.Column('rationale', sa.Text(), nullable=False),
    sa.Column('target_type', sa.Text(), nullable=True),
    sa.Column('target_id', sa.UUID(), nullable=True),
    sa.Column('review_outcome', sa.Text(), nullable=True),
    sa.Column('reviewed_by', sa.Uuid(), nullable=True),
    sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('input_expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("decision IN ('allow', 'warn', 'review', 'refuse')", name=op.f('ck_policy_decisions_decision')),
    sa.CheckConstraint("review_outcome IS NULL OR review_outcome IN ('approved', 'rejected')", name=op.f('ck_policy_decisions_review_outcome')),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name=op.f('fk_policy_decisions_investigation_id_investigations'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['reviewed_by'], ['users.id'], name=op.f('fk_policy_decisions_reviewed_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_policy_decisions_user_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_policy_decisions'))
    )
    op.create_index(op.f('ix_policy_decisions_investigation_id'), 'policy_decisions', ['investigation_id'], unique=False)
    op.create_index('ix_policy_decisions_review', 'policy_decisions', ['decision'], unique=False, postgresql_where=sa.text('review_outcome IS NULL'))
    op.create_index('ix_policy_decisions_user_created', 'policy_decisions', ['user_id', 'created_at'], unique=False)
    op.create_table('reports',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('title', sa.LargeBinary(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('options', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('body', sa.LargeBinary(), nullable=True),
    sa.Column('generated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('final_mac', sa.LargeBinary(), nullable=True),
    sa.Column('final_sha256', sa.Text(), nullable=True),
    sa.Column('audit_seq', sa.BigInteger(), nullable=True),
    sa.Column('finalized_by', sa.Uuid(), nullable=True),
    sa.Column('finalized_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("status IN ('draft', 'final')", name=op.f('ck_reports_status')),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_reports_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['finalized_by'], ['users.id'], name=op.f('fk_reports_finalized_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_reports_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_reports')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_reports_inv_id')
    )
    op.create_index(op.f('ix_reports_investigation_id'), 'reports', ['investigation_id'], unique=False)
    op.create_table('sources',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('label_seq', sa.Integer(), nullable=False),
    sa.Column('url', sa.LargeBinary(), nullable=False),
    sa.Column('url_mac', sa.LargeBinary(), nullable=False),
    sa.Column('host', sa.Text(), nullable=False),
    sa.Column('registrable_domain', sa.Text(), nullable=False),
    sa.Column('source_category', sa.Text(), nullable=False),
    sa.Column('connector_id', sa.Text(), nullable=False),
    sa.Column('title', sa.LargeBinary(), nullable=True),
    sa.Column('title_tokens', postgresql.ARRAY(sa.BigInteger()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('publisher', sa.Text(), nullable=True),
    sa.Column('ownership_group', sa.Text(), nullable=True),
    sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('first_captured_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_captured_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('reliability', sa.String(length=1), nullable=True),
    sa.Column('archived_url', sa.LargeBinary(), nullable=True),
    sa.Column('access_status', sa.Text(), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("access_status IN ('captured', 'reference_only', 'login_required', 'robots_disallowed', 'paywalled')", name=op.f('ck_sources_access_status')),
    sa.CheckConstraint("reliability IS NULL OR reliability IN ('A','B','C','D','E','F')", name=op.f('ck_sources_reliability')),
    sa.CheckConstraint("source_category IN ('websites', 'news_articles', 'public_social_media', 'public_profiles', 'public_documents', 'public_company_information', 'public_government_information', 'public_directories', 'public_forums', 'public_image_sources', 'search_engine_results')", name=op.f('ck_sources_source_category')),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_sources_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_sources_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_sources')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_sources_inv_id'),
    sa.UniqueConstraint('investigation_id', 'url_mac', name=op.f('uq_sources_investigation_id_url_mac'))
    )
    op.create_index('ix_sources_inv_category', 'sources', ['investigation_id', 'source_category'], unique=False)
    op.create_index('ix_sources_inv_domain', 'sources', ['investigation_id', 'registrable_domain'], unique=False)
    op.create_index(op.f('ix_sources_investigation_id'), 'sources', ['investigation_id'], unique=False)
    op.create_index('ix_sources_title_tokens', 'sources', ['title_tokens'], unique=False, postgresql_using='gin')
    op.create_table('suggestions',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('kind', sa.Text(), nullable=False),
    sa.Column('finding_ids', postgresql.ARRAY(sa.UUID()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('evidence_ids', postgresql.ARRAY(sa.UUID()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('fact_ids', postgresql.ARRAY(sa.UUID()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('rule_id', sa.Text(), nullable=False),
    sa.Column('rule_version', sa.Text(), nullable=False),
    sa.Column('message', sa.LargeBinary(), nullable=False),
    sa.Column('dedupe_key', sa.Text(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('decided_by', sa.Uuid(), nullable=True),
    sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("kind IN ('corroboration', 'contradiction', 'discrepancy', 'syndication', 'duplicate')", name=op.f('ck_suggestions_kind')),
    sa.CheckConstraint("status IN ('open', 'accepted', 'dismissed')", name=op.f('ck_suggestions_status')),
    sa.ForeignKeyConstraint(['decided_by'], ['users.id'], name=op.f('fk_suggestions_decided_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_suggestions_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_suggestions')),
    sa.UniqueConstraint('investigation_id', 'dedupe_key', name=op.f('uq_suggestions_investigation_id_dedupe_key')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_suggestions_inv_id')
    )
    op.create_index(op.f('ix_suggestions_investigation_id'), 'suggestions', ['investigation_id'], unique=False)
    op.create_table('ai_proposals',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('interaction_id', sa.UUID(), nullable=False),
    sa.Column('kind', sa.Text(), nullable=False),
    sa.Column('payload', sa.LargeBinary(), nullable=False),
    sa.Column('evidence_ids', postgresql.ARRAY(sa.UUID()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('decided_by', sa.Uuid(), nullable=True),
    sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('result_ref', sa.UUID(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("kind IN ('entity', 'relationship', 'timeline_event', 'finding', 'query', 'contradiction', 'gap')", name=op.f('ck_ai_proposals_kind')),
    sa.CheckConstraint("status IN ('pending', 'accepted', 'rejected')", name=op.f('ck_ai_proposals_status')),
    sa.ForeignKeyConstraint(['decided_by'], ['users.id'], name=op.f('fk_ai_proposals_decided_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['investigation_id', 'interaction_id'], ['ai_interactions.investigation_id', 'ai_interactions.id'], name='fk_interaction_id_ai_interactions', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_ai_proposals_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_ai_proposals')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_ai_proposals_inv_id')
    )
    op.create_index(op.f('ix_ai_proposals_interaction_id'), 'ai_proposals', ['interaction_id'], unique=False)
    op.create_index(op.f('ix_ai_proposals_investigation_id'), 'ai_proposals', ['investigation_id'], unique=False)
    op.create_table('evidence_items',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('label_seq', sa.Integer(), nullable=False),
    sa.Column('source_id', sa.UUID(), nullable=True),
    sa.Column('collection_run_id', sa.UUID(), nullable=True),
    sa.Column('origin_image_id', sa.UUID(), nullable=True),
    sa.Column('evidence_type', sa.Text(), nullable=False),
    sa.Column('provenance', sa.Text(), nullable=False),
    sa.Column('excerpt', sa.LargeBinary(), nullable=False),
    sa.Column('extra', sa.LargeBinary(), nullable=True),
    sa.Column('content_mac', sa.LargeBinary(), nullable=False),
    sa.Column('simhash', sa.BigInteger(), nullable=True),
    sa.Column('search_tokens', postgresql.ARRAY(sa.BigInteger()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('captured_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('country', sa.String(length=2), nullable=True),
    sa.Column('region', sa.Text(), nullable=True),
    sa.Column('credibility', sa.SmallInteger(), nullable=True),
    sa.Column('sensitivity_flags', postgresql.ARRAY(sa.Text()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('redaction_counts', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('dedupe_cluster_id', sa.UUID(), nullable=True),
    sa.Column('syndication_cluster_id', sa.UUID(), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("evidence_type IN ('text_excerpt', 'page_capture', 'document_excerpt', 'registry_record', 'search_result', 'ocr_text', 'image_clue', 'metadata', 'image_match', 'manual_capture')", name=op.f('ck_evidence_items_evidence_type')),
    sa.CheckConstraint("provenance IN ('observed', 'source_reported')", name=op.f('ck_evidence_items_provenance_not_ai')),
    sa.CheckConstraint('credibility IS NULL OR credibility BETWEEN 1 AND 6', name=op.f('ck_evidence_items_credibility')),
    sa.CheckConstraint('source_id IS NOT NULL OR origin_image_id IS NOT NULL', name=op.f('ck_evidence_items_has_origin')),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_evidence_items_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['investigation_id', 'collection_run_id'], ['collection_runs.investigation_id', 'collection_runs.id'], name='fk_collection_run_id_collection_runs', ondelete='SET NULL (collection_run_id)'),
    sa.ForeignKeyConstraint(['investigation_id', 'origin_image_id'], ['images.investigation_id', 'images.id'], name='fk_origin_image_id_images', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id', 'source_id'], ['sources.investigation_id', 'sources.id'], name='fk_source_id_sources', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_evidence_items_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_evidence_items')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_evidence_items_inv_id'),
    sa.UniqueConstraint('investigation_id', 'source_id', 'origin_image_id', 'content_mac', name='uq_evidence_items_content', postgresql_nulls_not_distinct=True)
    )
    op.create_index('ix_evidence_items_inv_captured', 'evidence_items', ['investigation_id', 'captured_at'], unique=False)
    op.create_index('ix_evidence_items_inv_location', 'evidence_items', ['investigation_id', 'country', 'region'], unique=False)
    op.create_index(op.f('ix_evidence_items_investigation_id'), 'evidence_items', ['investigation_id'], unique=False)
    op.create_index('ix_evidence_items_tokens', 'evidence_items', ['search_tokens'], unique=False, postgresql_using='gin')
    op.create_table('finding_status_history',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('finding_id', sa.UUID(), nullable=False),
    sa.Column('from_status', sa.Text(), nullable=True),
    sa.Column('to_status', sa.Text(), nullable=False),
    sa.Column('actor_id', sa.Uuid(), nullable=True),
    sa.Column('justification', sa.LargeBinary(), nullable=True),
    sa.Column('evidence_ids', postgresql.ARRAY(sa.UUID()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('automatic', sa.Boolean(), nullable=False),
    sa.Column('precondition_snapshot', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['actor_id'], ['users.id'], name=op.f('fk_finding_status_history_actor_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['investigation_id', 'finding_id'], ['findings.investigation_id', 'findings.id'], name='fk_finding_id_findings', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_finding_status_history_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_finding_status_history')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_finding_status_history_inv_id')
    )
    op.create_index(op.f('ix_finding_status_history_finding_id'), 'finding_status_history', ['finding_id'], unique=False)
    op.create_index(op.f('ix_finding_status_history_investigation_id'), 'finding_status_history', ['investigation_id'], unique=False)
    op.create_table('image_analyses',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('image_id', sa.UUID(), nullable=False),
    sa.Column('analyzer', sa.Text(), nullable=False),
    sa.Column('analyzer_version', sa.Text(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('result', sa.LargeBinary(), nullable=True),
    sa.Column('metrics', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['investigation_id', 'image_id'], ['images.investigation_id', 'images.id'], name='fk_image_id_images', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_image_analyses_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_image_analyses')),
    sa.UniqueConstraint('image_id', 'analyzer', name=op.f('uq_image_analyses_image_id_analyzer')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_image_analyses_inv_id')
    )
    op.create_index(op.f('ix_image_analyses_image_id'), 'image_analyses', ['image_id'], unique=False)
    op.create_index(op.f('ix_image_analyses_investigation_id'), 'image_analyses', ['investigation_id'], unique=False)
    op.create_table('image_hashes',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('image_id', sa.UUID(), nullable=False),
    sa.Column('phash', sa.BigInteger(), nullable=False),
    sa.Column('dhash', sa.BigInteger(), nullable=False),
    sa.Column('ahash', sa.BigInteger(), nullable=False),
    sa.Column('whash', sa.BigInteger(), nullable=False),
    sa.Column('phash_b0', sa.Integer(), sa.Computed('((phash >> 48) & 65535)::int', persisted=True), nullable=False),
    sa.Column('phash_b1', sa.Integer(), sa.Computed('((phash >> 32) & 65535)::int', persisted=True), nullable=False),
    sa.Column('phash_b2', sa.Integer(), sa.Computed('((phash >> 16) & 65535)::int', persisted=True), nullable=False),
    sa.Column('phash_b3', sa.Integer(), sa.Computed('(phash & 65535)::int', persisted=True), nullable=False),
    sa.Column('colorhash', sa.Text(), nullable=False),
    sa.Column('crop_resistant', sa.Text(), nullable=False),
    sa.Column('pixel_mac', sa.LargeBinary(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['investigation_id', 'image_id'], ['images.investigation_id', 'images.id'], name='fk_image_id_images', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_image_hashes_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_image_hashes')),
    sa.UniqueConstraint('image_id', name=op.f('uq_image_hashes_image_id')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_image_hashes_inv_id')
    )
    op.create_index('ix_image_hashes_b0', 'image_hashes', ['phash_b0'], unique=False)
    op.create_index('ix_image_hashes_b1', 'image_hashes', ['phash_b1'], unique=False)
    op.create_index('ix_image_hashes_b2', 'image_hashes', ['phash_b2'], unique=False)
    op.create_index('ix_image_hashes_b3', 'image_hashes', ['phash_b3'], unique=False)
    op.create_index(op.f('ix_image_hashes_investigation_id'), 'image_hashes', ['investigation_id'], unique=False)
    op.create_table('relationships',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('from_entity_id', sa.UUID(), nullable=False),
    sa.Column('to_entity_id', sa.UUID(), nullable=False),
    sa.Column('rel_type', sa.Text(), nullable=False),
    sa.Column('provenance', sa.Text(), nullable=False),
    sa.Column('verification_status', sa.Text(), nullable=False),
    sa.Column('confidence', sa.Text(), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_via', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("confidence IS NULL OR confidence IN ('low', 'moderate', 'high')", name=op.f('ck_relationships_confidence')),
    sa.CheckConstraint("provenance IN ('observed', 'source_reported', 'analyst_inference', 'ai_hypothesis')", name=op.f('ck_relationships_provenance')),
    sa.CheckConstraint("rel_type IN ('shows_text', 'links_to', 'hosted_on', 'operated_by', 'subsidiary_of', 'mentions', 'published_by', 'participated_in', 'located_in', 'same_image_as', 'similar_image_to', 'documented_by', 'registered_by', 'depicts')", name=op.f('ck_relationships_rel_type')),
    sa.CheckConstraint("verification_status <> 'ai_hypothesis' OR provenance = 'ai_hypothesis'", name=op.f('ck_relationships_ai_status_requires_ai')),
    sa.CheckConstraint("verification_status IN ('confirmed_by_source', 'corroborated', 'unverified', 'contradicted', 'ai_hypothesis')", name=op.f('ck_relationships_verification_status')),
    sa.CheckConstraint('from_entity_id <> to_entity_id', name=op.f('ck_relationships_not_self')),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_relationships_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['investigation_id', 'from_entity_id'], ['entities.investigation_id', 'entities.id'], name='fk_relationships_from_entity', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id', 'to_entity_id'], ['entities.investigation_id', 'entities.id'], name='fk_relationships_to_entity', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_relationships_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_relationships')),
    sa.UniqueConstraint('investigation_id', 'from_entity_id', 'rel_type', 'to_entity_id', name=op.f('uq_relationships_investigation_id_from_entity_id_rel_type_to_entity_id')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_relationships_inv_id')
    )
    op.create_index(op.f('ix_relationships_from_entity_id'), 'relationships', ['from_entity_id'], unique=False)
    op.create_index(op.f('ix_relationships_investigation_id'), 'relationships', ['investigation_id'], unique=False)
    op.create_index(op.f('ix_relationships_to_entity_id'), 'relationships', ['to_entity_id'], unique=False)
    op.create_table('report_exports',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('report_id', sa.UUID(), nullable=False),
    sa.Column('format', sa.Text(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('object_key', sa.Text(), nullable=True),
    sa.Column('file_key', sa.LargeBinary(), nullable=True),
    sa.Column('byte_size', sa.Integer(), nullable=True),
    sa.Column('sha256', sa.Text(), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('downloaded_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("format IN ('html', 'markdown', 'json', 'pdf')", name=op.f('ck_report_exports_format')),
    sa.CheckConstraint("status IN ('pending', 'ready', 'failed', 'expired')", name=op.f('ck_report_exports_status')),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_report_exports_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['investigation_id', 'report_id'], ['reports.investigation_id', 'reports.id'], name='fk_report_id_reports', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_report_exports_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_report_exports')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_report_exports_inv_id')
    )
    op.create_index(op.f('ix_report_exports_investigation_id'), 'report_exports', ['investigation_id'], unique=False)
    op.create_index(op.f('ix_report_exports_report_id'), 'report_exports', ['report_id'], unique=False)
    op.create_table('timeline_events',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('occurred_start', sa.DateTime(timezone=True), nullable=False),
    sa.Column('occurred_end', sa.DateTime(timezone=True), nullable=True),
    sa.Column('precision', sa.Text(), nullable=False),
    sa.Column('kind', sa.Text(), nullable=False),
    sa.Column('title', sa.LargeBinary(), nullable=False),
    sa.Column('description', sa.LargeBinary(), nullable=True),
    sa.Column('finding_id', sa.UUID(), nullable=True),
    sa.Column('provenance', sa.Text(), nullable=False),
    sa.Column('verification_status', sa.Text(), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_via', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("precision IN ('exact', 'minute', 'hour', 'day', 'month', 'year', 'approximate')", name=op.f('ck_timeline_events_precision')),
    sa.CheckConstraint("provenance IN ('observed', 'source_reported', 'analyst_inference', 'ai_hypothesis')", name=op.f('ck_timeline_events_provenance')),
    sa.CheckConstraint("verification_status <> 'ai_hypothesis' OR provenance = 'ai_hypothesis'", name=op.f('ck_timeline_events_ai_status_requires_ai')),
    sa.CheckConstraint("verification_status IN ('confirmed_by_source', 'corroborated', 'unverified', 'contradicted', 'ai_hypothesis')", name=op.f('ck_timeline_events_verification_status')),
    sa.CheckConstraint('occurred_end IS NULL OR occurred_end >= occurred_start', name=op.f('ck_timeline_events_range')),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_timeline_events_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['investigation_id', 'finding_id'], ['findings.investigation_id', 'findings.id'], name='fk_finding_id_findings', ondelete='SET NULL (finding_id)'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_timeline_events_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_timeline_events')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_timeline_events_inv_id')
    )
    op.create_index('ix_timeline_events_inv_start', 'timeline_events', ['investigation_id', 'occurred_start'], unique=False)
    op.create_index(op.f('ix_timeline_events_investigation_id'), 'timeline_events', ['investigation_id'], unique=False)
    op.create_table('entity_mentions',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('entity_id', sa.UUID(), nullable=False),
    sa.Column('evidence_id', sa.UUID(), nullable=False),
    sa.Column('span', postgresql.INT4RANGE(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['investigation_id', 'entity_id'], ['entities.investigation_id', 'entities.id'], name='fk_entity_id_entities', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id', 'evidence_id'], ['evidence_items.investigation_id', 'evidence_items.id'], name='fk_evidence_id_evidence_items', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_entity_mentions_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_entity_mentions')),
    sa.UniqueConstraint('entity_id', 'evidence_id', name=op.f('uq_entity_mentions_entity_id_evidence_id')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_entity_mentions_inv_id')
    )
    op.create_index(op.f('ix_entity_mentions_entity_id'), 'entity_mentions', ['entity_id'], unique=False)
    op.create_index(op.f('ix_entity_mentions_evidence_id'), 'entity_mentions', ['evidence_id'], unique=False)
    op.create_index(op.f('ix_entity_mentions_investigation_id'), 'entity_mentions', ['investigation_id'], unique=False)
    op.create_table('facts',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('entity_id', sa.UUID(), nullable=True),
    sa.Column('attribute', sa.Text(), nullable=False),
    sa.Column('value', sa.LargeBinary(), nullable=False),
    sa.Column('value_type', sa.Text(), nullable=False),
    sa.Column('precision', sa.Text(), nullable=True),
    sa.Column('valid_from', sa.Date(), nullable=True),
    sa.Column('valid_to', sa.Date(), nullable=True),
    sa.Column('evidence_id', sa.UUID(), nullable=False),
    sa.Column('provenance', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['investigation_id', 'entity_id'], ['entities.investigation_id', 'entities.id'], name='fk_entity_id_entities', ondelete='SET NULL (entity_id)'),
    sa.ForeignKeyConstraint(['investigation_id', 'evidence_id'], ['evidence_items.investigation_id', 'evidence_items.id'], name='fk_evidence_id_evidence_items', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_facts_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_facts')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_facts_inv_id')
    )
    op.create_index('ix_facts_inv_entity_attr', 'facts', ['investigation_id', 'entity_id', 'attribute'], unique=False)
    op.create_index(op.f('ix_facts_investigation_id'), 'facts', ['investigation_id'], unique=False)
    op.create_table('finding_evidence',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('finding_id', sa.UUID(), nullable=False),
    sa.Column('evidence_id', sa.UUID(), nullable=False),
    sa.Column('stance', sa.Text(), nullable=False),
    sa.Column('directly_states', sa.Boolean(), nullable=False),
    sa.Column('quote_span', postgresql.INT4RANGE(), nullable=True),
    sa.Column('dismissed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('dismissed_reason', sa.LargeBinary(), nullable=True),
    sa.Column('dismissed_by', sa.Uuid(), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("stance IN ('supports', 'contradicts', 'context')", name=op.f('ck_finding_evidence_stance')),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_finding_evidence_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['dismissed_by'], ['users.id'], name=op.f('fk_finding_evidence_dismissed_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['investigation_id', 'evidence_id'], ['evidence_items.investigation_id', 'evidence_items.id'], name='fk_evidence_id_evidence_items', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id', 'finding_id'], ['findings.investigation_id', 'findings.id'], name='fk_finding_id_findings', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_finding_evidence_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_finding_evidence')),
    sa.UniqueConstraint('finding_id', 'evidence_id', 'stance', name=op.f('uq_finding_evidence_finding_id_evidence_id_stance')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_finding_evidence_inv_id')
    )
    op.create_index(op.f('ix_finding_evidence_evidence_id'), 'finding_evidence', ['evidence_id'], unique=False)
    op.create_index(op.f('ix_finding_evidence_finding_id'), 'finding_evidence', ['finding_id'], unique=False)
    op.create_index(op.f('ix_finding_evidence_investigation_id'), 'finding_evidence', ['investigation_id'], unique=False)
    op.create_table('image_clues',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('image_id', sa.UUID(), nullable=False),
    sa.Column('clue_type', sa.Text(), nullable=False),
    sa.Column('value', sa.LargeBinary(), nullable=False),
    sa.Column('normalized', sa.LargeBinary(), nullable=False),
    sa.Column('normalized_mac', sa.LargeBinary(), nullable=False),
    sa.Column('tokens', postgresql.ARRAY(sa.BigInteger()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('bbox', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('confidence', sa.Text(), nullable=False),
    sa.Column('confidence_basis', sa.Text(), nullable=False),
    sa.Column('provenance', sa.Text(), nullable=False),
    sa.Column('source', sa.Text(), nullable=False),
    sa.Column('platform', sa.Text(), nullable=True),
    sa.Column('precision', sa.Text(), nullable=True),
    sa.Column('promoted_evidence_id', sa.UUID(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("clue_type IN ('visible_text', 'url', 'domain', 'username', 'hashtag', 'email_domain', 'date', 'organization', 'brand', 'object', 'landmark', 'sign', 'public_location', 'exif_field')", name=op.f('ck_image_clues_clue_type')),
    sa.CheckConstraint("provenance IN ('observed', 'ai_hypothesis')", name=op.f('ck_image_clues_provenance')),
    sa.ForeignKeyConstraint(['investigation_id', 'image_id'], ['images.investigation_id', 'images.id'], name='fk_image_id_images', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id', 'promoted_evidence_id'], ['evidence_items.investigation_id', 'evidence_items.id'], name='fk_promoted_evidence_id_evidence_items', ondelete='SET NULL (promoted_evidence_id)'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_image_clues_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_image_clues')),
    sa.UniqueConstraint('image_id', 'clue_type', 'normalized_mac', name=op.f('uq_image_clues_image_id_clue_type_normalized_mac')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_image_clues_inv_id')
    )
    op.create_index(op.f('ix_image_clues_image_id'), 'image_clues', ['image_id'], unique=False)
    op.create_index(op.f('ix_image_clues_investigation_id'), 'image_clues', ['investigation_id'], unique=False)
    op.create_table('relationship_evidence',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('relationship_id', sa.UUID(), nullable=False),
    sa.Column('evidence_id', sa.UUID(), nullable=False),
    sa.Column('stance', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("stance IN ('supports', 'contradicts', 'context')", name=op.f('ck_relationship_evidence_stance')),
    sa.ForeignKeyConstraint(['investigation_id', 'evidence_id'], ['evidence_items.investigation_id', 'evidence_items.id'], name='fk_evidence_id_evidence_items', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id', 'relationship_id'], ['relationships.investigation_id', 'relationships.id'], name='fk_relationship_id_relationships', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_relationship_evidence_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_relationship_evidence')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_relationship_evidence_inv_id'),
    sa.UniqueConstraint('relationship_id', 'evidence_id', 'stance', name=op.f('uq_relationship_evidence_relationship_id_evidence_id_stance'))
    )
    op.create_index(op.f('ix_relationship_evidence_evidence_id'), 'relationship_evidence', ['evidence_id'], unique=False)
    op.create_index(op.f('ix_relationship_evidence_investigation_id'), 'relationship_evidence', ['investigation_id'], unique=False)
    op.create_index(op.f('ix_relationship_evidence_relationship_id'), 'relationship_evidence', ['relationship_id'], unique=False)
    op.create_table('relationship_status_history',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('relationship_id', sa.UUID(), nullable=False),
    sa.Column('from_status', sa.Text(), nullable=True),
    sa.Column('to_status', sa.Text(), nullable=False),
    sa.Column('actor_id', sa.Uuid(), nullable=True),
    sa.Column('justification', sa.LargeBinary(), nullable=True),
    sa.Column('evidence_ids', postgresql.ARRAY(sa.UUID()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('precondition_snapshot', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['actor_id'], ['users.id'], name=op.f('fk_relationship_status_history_actor_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['investigation_id', 'relationship_id'], ['relationships.investigation_id', 'relationships.id'], name='fk_relationship_id_relationships', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_relationship_status_history_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_relationship_status_history')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_relationship_status_history_inv_id')
    )
    op.create_index(op.f('ix_relationship_status_history_investigation_id'), 'relationship_status_history', ['investigation_id'], unique=False)
    op.create_index(op.f('ix_relationship_status_history_relationship_id'), 'relationship_status_history', ['relationship_id'], unique=False)
    op.create_table('timeline_event_evidence',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('event_id', sa.UUID(), nullable=False),
    sa.Column('evidence_id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['investigation_id', 'event_id'], ['timeline_events.investigation_id', 'timeline_events.id'], name='fk_event_id_timeline_events', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id', 'evidence_id'], ['evidence_items.investigation_id', 'evidence_items.id'], name='fk_evidence_id_evidence_items', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name='fk_timeline_event_evidence_investigation', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_timeline_event_evidence')),
    sa.UniqueConstraint('event_id', 'evidence_id', name=op.f('uq_timeline_event_evidence_event_id_evidence_id')),
    sa.UniqueConstraint('investigation_id', 'id', name='uq_timeline_event_evidence_inv_id')
    )
    op.create_index(op.f('ix_timeline_event_evidence_event_id'), 'timeline_event_evidence', ['event_id'], unique=False)
    op.create_index(op.f('ix_timeline_event_evidence_evidence_id'), 'timeline_event_evidence', ['evidence_id'], unique=False)
    op.create_index(op.f('ix_timeline_event_evidence_investigation_id'), 'timeline_event_evidence', ['investigation_id'], unique=False)
    # ### end Alembic commands ###
    _apply_security()


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_timeline_event_evidence_investigation_id'), table_name='timeline_event_evidence')
    op.drop_index(op.f('ix_timeline_event_evidence_evidence_id'), table_name='timeline_event_evidence')
    op.drop_index(op.f('ix_timeline_event_evidence_event_id'), table_name='timeline_event_evidence')
    op.drop_table('timeline_event_evidence')
    op.drop_index(op.f('ix_relationship_status_history_relationship_id'), table_name='relationship_status_history')
    op.drop_index(op.f('ix_relationship_status_history_investigation_id'), table_name='relationship_status_history')
    op.drop_table('relationship_status_history')
    op.drop_index(op.f('ix_relationship_evidence_relationship_id'), table_name='relationship_evidence')
    op.drop_index(op.f('ix_relationship_evidence_investigation_id'), table_name='relationship_evidence')
    op.drop_index(op.f('ix_relationship_evidence_evidence_id'), table_name='relationship_evidence')
    op.drop_table('relationship_evidence')
    op.drop_index(op.f('ix_image_clues_investigation_id'), table_name='image_clues')
    op.drop_index(op.f('ix_image_clues_image_id'), table_name='image_clues')
    op.drop_table('image_clues')
    op.drop_index(op.f('ix_finding_evidence_investigation_id'), table_name='finding_evidence')
    op.drop_index(op.f('ix_finding_evidence_finding_id'), table_name='finding_evidence')
    op.drop_index(op.f('ix_finding_evidence_evidence_id'), table_name='finding_evidence')
    op.drop_table('finding_evidence')
    op.drop_index(op.f('ix_facts_investigation_id'), table_name='facts')
    op.drop_index('ix_facts_inv_entity_attr', table_name='facts')
    op.drop_table('facts')
    op.drop_index(op.f('ix_entity_mentions_investigation_id'), table_name='entity_mentions')
    op.drop_index(op.f('ix_entity_mentions_evidence_id'), table_name='entity_mentions')
    op.drop_index(op.f('ix_entity_mentions_entity_id'), table_name='entity_mentions')
    op.drop_table('entity_mentions')
    op.drop_index(op.f('ix_timeline_events_investigation_id'), table_name='timeline_events')
    op.drop_index('ix_timeline_events_inv_start', table_name='timeline_events')
    op.drop_table('timeline_events')
    op.drop_index(op.f('ix_report_exports_report_id'), table_name='report_exports')
    op.drop_index(op.f('ix_report_exports_investigation_id'), table_name='report_exports')
    op.drop_table('report_exports')
    op.drop_index(op.f('ix_relationships_to_entity_id'), table_name='relationships')
    op.drop_index(op.f('ix_relationships_investigation_id'), table_name='relationships')
    op.drop_index(op.f('ix_relationships_from_entity_id'), table_name='relationships')
    op.drop_table('relationships')
    op.drop_index(op.f('ix_image_hashes_investigation_id'), table_name='image_hashes')
    op.drop_index('ix_image_hashes_b3', table_name='image_hashes')
    op.drop_index('ix_image_hashes_b2', table_name='image_hashes')
    op.drop_index('ix_image_hashes_b1', table_name='image_hashes')
    op.drop_index('ix_image_hashes_b0', table_name='image_hashes')
    op.drop_table('image_hashes')
    op.drop_index(op.f('ix_image_analyses_investigation_id'), table_name='image_analyses')
    op.drop_index(op.f('ix_image_analyses_image_id'), table_name='image_analyses')
    op.drop_table('image_analyses')
    op.drop_index(op.f('ix_finding_status_history_investigation_id'), table_name='finding_status_history')
    op.drop_index(op.f('ix_finding_status_history_finding_id'), table_name='finding_status_history')
    op.drop_table('finding_status_history')
    op.drop_index('ix_evidence_items_tokens', table_name='evidence_items', postgresql_using='gin')
    op.drop_index(op.f('ix_evidence_items_investigation_id'), table_name='evidence_items')
    op.drop_index('ix_evidence_items_inv_location', table_name='evidence_items')
    op.drop_index('ix_evidence_items_inv_captured', table_name='evidence_items')
    op.drop_table('evidence_items')
    op.drop_index(op.f('ix_ai_proposals_investigation_id'), table_name='ai_proposals')
    op.drop_index(op.f('ix_ai_proposals_interaction_id'), table_name='ai_proposals')
    op.drop_table('ai_proposals')
    op.drop_index(op.f('ix_suggestions_investigation_id'), table_name='suggestions')
    op.drop_table('suggestions')
    op.drop_index('ix_sources_title_tokens', table_name='sources', postgresql_using='gin')
    op.drop_index(op.f('ix_sources_investigation_id'), table_name='sources')
    op.drop_index('ix_sources_inv_domain', table_name='sources')
    op.drop_index('ix_sources_inv_category', table_name='sources')
    op.drop_table('sources')
    op.drop_index(op.f('ix_reports_investigation_id'), table_name='reports')
    op.drop_table('reports')
    op.drop_index('ix_policy_decisions_user_created', table_name='policy_decisions')
    op.drop_index('ix_policy_decisions_review', table_name='policy_decisions', postgresql_where=sa.text('review_outcome IS NULL'))
    op.drop_index(op.f('ix_policy_decisions_investigation_id'), table_name='policy_decisions')
    op.drop_table('policy_decisions')
    op.drop_index(op.f('ix_oversight_grants_investigation_id'), table_name='oversight_grants')
    op.drop_index(op.f('ix_oversight_grants_grantee_id'), table_name='oversight_grants')
    op.drop_table('oversight_grants')
    op.drop_index(op.f('ix_notes_target_id'), table_name='notes')
    op.drop_index(op.f('ix_notes_investigation_id'), table_name='notes')
    op.drop_table('notes')
    op.drop_index('uq_jobs_idempotency', table_name='jobs', postgresql_where=sa.text('idempotency_key IS NOT NULL'))
    op.drop_index('ix_jobs_lease', table_name='jobs', postgresql_where=sa.text("status = 'running'"))
    op.drop_index(op.f('ix_jobs_investigation_id'), table_name='jobs')
    op.drop_index('ix_jobs_claim', table_name='jobs')
    op.drop_table('jobs')
    op.drop_index('uq_investigation_members_single_owner', table_name='investigation_members', postgresql_where=sa.text("role = 'owner'"))
    op.drop_index(op.f('ix_investigation_members_user_id'), table_name='investigation_members')
    op.drop_table('investigation_members')
    op.drop_index('ix_images_purge', table_name='images', postgresql_where=sa.text('original_purged_at IS NULL'))
    op.drop_index(op.f('ix_images_investigation_id'), table_name='images')
    op.drop_table('images')
    op.drop_index('ix_findings_tokens', table_name='findings', postgresql_using='gin')
    op.drop_index(op.f('ix_findings_investigation_id'), table_name='findings')
    op.drop_index('ix_findings_inv_status', table_name='findings')
    op.drop_index('ix_findings_inv_category', table_name='findings')
    op.drop_table('findings')
    op.drop_index('ix_entities_name_trgm', table_name='entities', postgresql_using='gin', postgresql_ops={'name': 'gin_trgm_ops'})
    op.drop_index(op.f('ix_entities_investigation_id'), table_name='entities')
    op.drop_table('entities')
    op.drop_index('uq_data_keys_active_system', table_name='data_keys', postgresql_where=sa.text("status = 'active' AND investigation_id IS NULL"))
    op.drop_index('uq_data_keys_active_investigation', table_name='data_keys', postgresql_where=sa.text("status = 'active' AND investigation_id IS NOT NULL"))
    op.drop_index(op.f('ix_data_keys_investigation_id'), table_name='data_keys')
    op.drop_table('data_keys')
    op.drop_index(op.f('ix_collection_runs_investigation_id'), table_name='collection_runs')
    op.drop_table('collection_runs')
    op.drop_index(op.f('ix_attestations_user_id'), table_name='attestations')
    op.drop_index(op.f('ix_attestations_investigation_id'), table_name='attestations')
    op.drop_table('attestations')
    op.drop_index(op.f('ix_ai_interactions_investigation_id'), table_name='ai_interactions')
    op.drop_table('ai_interactions')
    op.drop_index('ix_user_sessions_user_active', table_name='user_sessions', postgresql_where=sa.text('revoked_at IS NULL'))
    op.drop_index('ix_user_sessions_absolute', table_name='user_sessions')
    op.drop_table('user_sessions')
    op.drop_table('settings')
    op.drop_index(op.f('ix_recovery_codes_user_id'), table_name='recovery_codes')
    op.drop_table('recovery_codes')
    op.drop_index(op.f('ix_investigations_owner_id'), table_name='investigations')
    op.drop_table('investigations')
    op.drop_table('idempotency_keys')
    op.drop_index(op.f('ix_data_exports_user_id'), table_name='data_exports')
    op.drop_table('data_exports')
    op.drop_table('abuse_reports')
    op.drop_table('users')
    op.drop_table('periodic_schedules')
    op.drop_table('legal_documents')
    op.drop_table('investigation_ref_counters')
    op.drop_table('blob_deletions')
    op.drop_index('ix_audit_log_occurred_brin', table_name='audit_log', postgresql_using='brin')
    op.drop_index('ix_audit_log_investigation_seq', table_name='audit_log')
    op.drop_index('ix_audit_log_actor_seq', table_name='audit_log')
    op.drop_table('audit_log')
    op.drop_table('audit_chain_head')
    op.drop_table('audit_anchors')
    # ### end Alembic commands ###
    for fn in ("ae_scope()", "ae_evidence_immutable()", "ae_status_guard()", "ae_finding_requires_evidence()",
               "ae_relationship_requires_evidence()", "ae_relationship_prune()", "ae_timeline_requires_evidence()",
               "ae_timeline_prune()", "ae_history_guard()", "ae_audit_guard()", "ae_no_truncate()"):
        op.execute(f"DROP FUNCTION IF EXISTS {fn}")
