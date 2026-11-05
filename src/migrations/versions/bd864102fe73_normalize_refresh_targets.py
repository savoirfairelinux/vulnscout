"""Persist independently updateable refresh coverage."""
from alembic import op
import sqlalchemy as sa

revision = "bd864102fe73"
down_revision = "ab721d903ef1"
branch_labels = None
depends_on = None


def upgrade():
    targets = op.create_table(
        "refresh_targets",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("run_id", sa.String(128), sa.ForeignKey("refresh_runs.run_id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("vuln_id", sa.String(100), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("error", sa.String()),
        sa.Column("packages", sa.JSON(), nullable=False),
        sa.UniqueConstraint("run_id", "source", "vuln_id"),
    )
    op.create_index("ix_refresh_targets_run_id", "refresh_targets", ["run_id"])
    op.create_index("ix_refresh_targets_vuln_id", "refresh_targets", ["vuln_id"])
    runs = sa.table("refresh_runs", sa.column("run_id", sa.String()), sa.column("coverage", sa.JSON()))
    connection = op.get_bind()
    for run in connection.execute(sa.select(runs)):
        entries = [{"run_id": run.run_id, **entry} for entry in run.coverage]
        for start in range(0, len(entries), 500):
            connection.execute(targets.insert(), entries[start:start + 500])
    # Rebuilding the parent table on SQLite can cascade-delete retained changes.
    # Keep its legacy coverage column empty; all new reporting uses target rows.
    connection.execute(runs.update().values(coverage=[]))


def downgrade():
    connection = op.get_bind()
    runs = sa.table("refresh_runs", sa.column("run_id", sa.String()), sa.column("coverage", sa.JSON()))
    targets = sa.table("refresh_targets", *[
        sa.column(key, type_) for key, type_ in [
            ("id", sa.Integer()), ("run_id", sa.String()), ("source", sa.String()),
            ("vuln_id", sa.String()), ("status", sa.String()), ("error", sa.String()), ("packages", sa.JSON()),
        ]
    ])
    for run_id in connection.execute(sa.select(runs.c.run_id)).scalars():
        coverage = [dict(row._mapping) for row in connection.execute(sa.select(
            targets.c.source, targets.c.vuln_id, targets.c.status, targets.c.error, targets.c.packages,
        ).where(targets.c.run_id == run_id).order_by(targets.c.id))]
        connection.execute(runs.update().where(runs.c.run_id == run_id).values(coverage=coverage))
    op.drop_table("refresh_targets")
