"""Add affected CPEs to vulnerabilities.

Revision ID: w9f0a1b2c3d4
Revises: v8e9f0a1b2c3
Create Date: 2026-08-06 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'w9f0a1b2c3d4'
down_revision = 'v8e9f0a1b2c3'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.add_column(sa.Column('cpes', sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.drop_column('cpes')