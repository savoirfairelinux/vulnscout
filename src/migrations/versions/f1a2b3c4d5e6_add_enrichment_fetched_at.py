"""add epss_fetched_at and nvd_fetched_at to vulnerabilities

Revision ID: f1a2b3c4d5e6
Revises: c8748f805850
Create Date: 2026-03-31 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f1a2b3c4d5e6'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.add_column(sa.Column('epss_fetched_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('nvd_fetched_at', sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.drop_column('nvd_fetched_at')
        batch_op.drop_column('epss_fetched_at')
