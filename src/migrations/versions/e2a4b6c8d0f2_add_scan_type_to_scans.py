"""add scan_type column to scans

Revision ID: e2a4b6c8d0f2
Revises: b4e9f2a7c3d1
Create Date: 2026-06-18 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e2a4b6c8d0f2'
down_revision = 'b4e9f2a7c3d1'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('scan_type', sa.String(), nullable=True, server_default='sbom'))


def downgrade():
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.drop_column('scan_type')
