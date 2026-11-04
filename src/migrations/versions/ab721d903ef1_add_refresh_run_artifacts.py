"""Persist exact refresh runs, per-target outcomes and immutable delta snapshots."""
from alembic import op
import sqlalchemy as sa

revision = "ab721d903ef1"
down_revision = "f2b4d6e8a0c1"
branch_labels = None
depends_on = None


def _run_fk():
    return sa.ForeignKey("refresh_runs.run_id", ondelete="CASCADE")


def upgrade():
    op.create_table(
        "refresh_runs",
        sa.Column("run_id", sa.String(128), primary_key=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("owner", sa.JSON(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_refresh_runs_started_at", "refresh_runs", ["started_at"])
    op.create_table(
        "refresh_run_scopes",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("run_id", sa.String(128), _run_fk(), nullable=False),
        sa.Column("project_id", sa.String(36)),
        sa.Column("variant_id", sa.String(36)),
    )
    op.create_index("ix_refresh_run_scopes_run_id", "refresh_run_scopes", ["run_id"])
    op.create_table(
        "refresh_run_sources",
        sa.Column("run_id", sa.String(128), _run_fk(), primary_key=True),
        sa.Column("source", sa.String(16), primary_key=True),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
    )
    op.create_table(
        "refresh_run_targets",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("run_id", sa.String(128), _run_fk(), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("vuln_id", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("error", sa.Text()),
        sa.UniqueConstraint("run_id", "source", "vuln_id", name="uq_refresh_run_targets_identity"),
    )
    op.create_index("ix_refresh_run_targets_run_id", "refresh_run_targets", ["run_id"])
    op.create_table(
        "refresh_run_target_links",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("target_id", sa.Integer(),
                  sa.ForeignKey("refresh_run_targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("package_id", sa.String(36), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column("package", sa.Text(), nullable=False),
        sa.Column("project_id", sa.String(36), nullable=False),
        sa.Column("variant_id", sa.String(36), nullable=False),
    )
    op.create_index("ix_refresh_run_target_links_target_id", "refresh_run_target_links", ["target_id"])
    op.create_index("ix_refresh_run_target_links_scope", "refresh_run_target_links", ["project_id", "variant_id"])
    op.create_table(
        "refresh_changes",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("run_id", sa.String(128), _run_fk(), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("refresh_run_targets.id", ondelete="CASCADE")),
        sa.Column("vuln_id", sa.String(64), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("field", sa.String(255), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("change_type", sa.String(16), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
    )
    op.create_index("ix_refresh_changes_run_id", "refresh_changes", ["run_id"])
    op.create_index("ix_refresh_changes_target_id", "refresh_changes", ["target_id"])


def downgrade():
    op.drop_table("refresh_changes")
    op.drop_table("refresh_run_target_links")
    op.drop_table("refresh_run_targets")
    op.drop_table("refresh_run_sources")
    op.drop_table("refresh_run_scopes")
    op.drop_table("refresh_runs")
