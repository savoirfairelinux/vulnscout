"""Preserve imported dependency relationship declarations.

Revision ID: f2b4d6e8a0c1
Revises: a3d5e7f9b1c2
"""
from alembic import op
import sqlalchemy as sa


revision = 'f2b4d6e8a0c1'
down_revision = 'a3d5e7f9b1c2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('package_dependencies') as batch_op:
        batch_op.add_column(sa.Column('declarations', sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table('package_dependencies') as batch_op:
        batch_op.drop_column('declarations')
