"""Add sparse assessment group membership table.

Revision ID: x0a1b2c3d4e5
Revises: w9f0a1b2c3d4
Create Date: 2026-08-19 00:00:00.000000
"""
import uuid
from alembic import op
import sqlalchemy as sa


revision = 'x0a1b2c3d4e5'
down_revision = 'w9f0a1b2c3d4'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'assessment_group_members',
        sa.Column('assessment_id', sa.Uuid(), nullable=False),
        sa.Column('group_id', sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ['assessment_id'], ['assessments.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('assessment_id'),
    )
    op.create_index(
        'ix_assessment_group_members_group_id',
        'assessment_group_members',
        ['group_id'],
    )
    backfill_groups(op.get_bind())


def backfill_groups(connection):
    """Recreate today's frontend grouping as stored membership rows.

    Assessments are grouped by the same key the frontend uses to render one
    history entry, scoped to the vulnerability so that bulk imports sharing a
    timestamp and content across different CVEs are not fused.  Only tuples
    with more than one row become a group; single-row tuples are skipped, which
    is what keeps the table sparse.
    """
    rows = connection.execute(sa.text("""
        SELECT a.id AS assessment_id,
               f.vulnerability_id AS vuln_id,
               a.timestamp, a.status, a.simplified_status, a.status_notes,
               a.justification, a.impact_statement, a.workaround, a.origin
        FROM assessments a
        JOIN findings f ON f.id = a.finding_id
    """)).mappings().all()

    buckets: dict[tuple, list] = {}
    for row in rows:
        key = (
            row["vuln_id"], row["timestamp"], row["status"],
            row["simplified_status"], row["status_notes"], row["justification"],
            row["impact_statement"], row["workaround"], row["origin"],
        )
        buckets.setdefault(key, []).append(row["assessment_id"])

    payload: list[dict] = []
    for assessment_ids in buckets.values():
        if len(assessment_ids) < 2:
            continue
        group_id = uuid.uuid4()
        payload.extend(
            {"assessment_id": assessment_id, "group_id": group_id.hex}
            for assessment_id in assessment_ids
        )

    for start in range(0, len(payload), 500):
        connection.execute(
            sa.text(
                "INSERT INTO assessment_group_members (assessment_id, group_id) "
                "VALUES (:assessment_id, :group_id)"
            ),
            payload[start:start + 500],
        )


def downgrade():
    op.drop_index(
        'ix_assessment_group_members_group_id',
        table_name='assessment_group_members',
    )
    op.drop_table('assessment_group_members')
