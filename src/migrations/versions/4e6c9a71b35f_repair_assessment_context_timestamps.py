"""repair assessment and context timestamps on legacy databases

Revision ID: 4e6c9a71b35f
Revises: z2c3d4e5f6a7
Create Date: 2026-10-06 00:00:00.000000

This revision was previously applied to the shared local database from another
branch. Keep its ID in this migration graph so databases already stamped with
it can continue upgrading. The checks also make the repair safe for databases
that have not yet received all three columns.
"""
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa


revision = '4e6c9a71b35f'
down_revision = 'z2c3d4e5f6a7'
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    return column in {item['name'] for item in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade():
    for table, column in (
        ('variant_context', 'updated_at'),
        ('project_context', 'updated_at'),
    ):
        if not _has_column(table, column):
            with op.batch_alter_table(table) as batch_op:
                batch_op.add_column(sa.Column(column, sa.DateTime(timezone=True), nullable=True))

    if not _has_column('assessments', 'created_at'):
        with op.batch_alter_table('assessments') as batch_op:
            batch_op.add_column(sa.Column('created_at', sa.DateTime(timezone=True), nullable=True))
        now = datetime.now(timezone.utc)
        op.execute(sa.text('UPDATE assessments SET created_at = :now').bindparams(now=now))
        with op.batch_alter_table('assessments') as batch_op:
            batch_op.alter_column(
                'created_at',
                existing_type=sa.DateTime(timezone=True),
                nullable=False,
            )


def downgrade():
    # These columns are also part of the preceding migration's schema contract.
    # Keep them when rolling back this compatibility revision.
    pass