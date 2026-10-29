"""Preserve per-import package-pair dependency snapshots.

Revision ID: b4e6f8a0c2d4
Revises: a3d5e7f9b1c2
"""
from alembic import op
import sqlalchemy as sa


revision = 'b4e6f8a0c2d4'
down_revision = 'a3d5e7f9b1c2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('sbom_documents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('dependency_snapshot', sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table('sbom_documents', schema=None) as batch_op:
        batch_op.drop_column('dependency_snapshot')
