"""Persist exact refresh runs and immutable delta snapshots."""
from alembic import op
import sqlalchemy as sa

revision = "ab721d903ef1"
down_revision = ("f4e1c9a7b2d3", "a3d5e7f9b1c2")
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "refresh_runs",
        sa.Column("run_id", sa.String(128), primary_key=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("sources", sa.JSON(), nullable=False),
        sa.Column("source_status", sa.JSON(), nullable=False),
        sa.Column("coverage", sa.JSON(), nullable=False),
        sa.Column("owner", sa.JSON(), nullable=False),
    )
    op.create_index("ix_refresh_runs_started_at", "refresh_runs", ["started_at"])
    op.create_table(
        "refresh_changes",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("run_id", sa.String(128), sa.ForeignKey("refresh_runs.run_id", ondelete="CASCADE"), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
    )
    op.create_index("ix_refresh_changes_run_id", "refresh_changes", ["run_id"])


def downgrade():
    op.drop_table("refresh_changes")
    op.drop_table("refresh_runs")
