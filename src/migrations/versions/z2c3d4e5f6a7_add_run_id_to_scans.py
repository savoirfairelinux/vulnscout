"""add run_id column to scans

Revision ID: b4c5d6e7f809
Revises: 4e6c9a71b35f
Create Date: 2026-09-25 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'b4c5d6e7f809'
down_revision = '4e6c9a71b35f'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('run_id', sa.String(), nullable=True))


def downgrade():
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.drop_column('run_id')
