"""add nvd_data_updated_at to vulnerabilities

Revision ID: j6e7f8a9b0c1
Revises: i5d6e7f8a9b0
Create Date: 2026-05-12 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = 'j6e7f8a9b0c1'
down_revision = 'i5d6e7f8a9b0'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.add_column(sa.Column('nvd_data_updated_at', sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.drop_column('nvd_data_updated_at')
