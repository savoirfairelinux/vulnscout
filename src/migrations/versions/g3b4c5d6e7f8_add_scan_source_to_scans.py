"""add scan_source column to scans

Revision ID: g3b4c5d6e7f8
Revises: e2a4b6c8d0f2
Create Date: 2026-04-13 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'g3b4c5d6e7f8'
down_revision = 'e2a4b6c8d0f2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('scan_source', sa.String(), nullable=True))


def downgrade():
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.drop_column('scan_source')
