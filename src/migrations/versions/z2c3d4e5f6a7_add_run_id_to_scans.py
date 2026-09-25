"""add run_id column to scans

Revision ID: z2c3d4e5f6a7
Revises: y1b2c3d4e5f6
Create Date: 2026-09-25 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'z2c3d4e5f6a7'
down_revision = 'y1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('run_id', sa.String(), nullable=True))


def downgrade():
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.drop_column('run_id')
