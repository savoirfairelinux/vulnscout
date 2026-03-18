"""add format column to sbom_documents

Revision ID: d3f8c1a2b9e5
Revises: c7f2a3d8e1b4
Create Date: 2026-03-18 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd3f8c1a2b9e5'
down_revision = 'c7f2a3d8e1b4'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('sbom_documents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('format', sa.String(), nullable=True))


def downgrade():
    with op.batch_alter_table('sbom_documents', schema=None) as batch_op:
        batch_op.drop_column('format')
