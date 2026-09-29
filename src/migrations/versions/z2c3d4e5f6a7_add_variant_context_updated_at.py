"""add context and assessment timestamps

Revision ID: z2c3d4e5f6a7
Revises: y1b2c3d4e5f6
Create Date: 2026-09-20 00:00:00.000000

"""
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa


revision = 'z2c3d4e5f6a7'
down_revision = 'y1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('variant_context') as batch_op:
        batch_op.add_column(sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True))
    with op.batch_alter_table('project_context') as batch_op:
        batch_op.add_column(sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True))
    with op.batch_alter_table('assessments') as batch_op:
        batch_op.add_column(sa.Column('created_at', sa.DateTime(timezone=True), nullable=True))
    # `timestamp` is the assessment's caller-controlled displayed date (payloads
    # and imports may set it to any past or future value), so it cannot be
    # trusted as a stand-in for "when this row was actually written". Backfill
    # legacy rows from the migration's own clock instead.
    now = datetime.now(timezone.utc)
    op.execute(sa.text("UPDATE assessments SET created_at = :now").bindparams(now=now))
    with op.batch_alter_table('assessments') as batch_op:
        batch_op.alter_column(
            'created_at',
            existing_type=sa.DateTime(timezone=True),
            nullable=False,
        )


def downgrade():
    with op.batch_alter_table('assessments') as batch_op:
        batch_op.drop_column('created_at')
    with op.batch_alter_table('project_context') as batch_op:
        batch_op.drop_column('updated_at')
    with op.batch_alter_table('variant_context') as batch_op:
        batch_op.drop_column('updated_at')
