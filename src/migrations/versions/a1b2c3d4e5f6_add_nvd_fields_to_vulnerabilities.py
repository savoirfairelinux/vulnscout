"""add NVD fields to vulnerabilities

Revision ID: a1b2c3d4e5f6
Revises: c8748f805850
Create Date: 2026-03-27 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = 'c8748f805850'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.add_column(sa.Column('weaknesses', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('versions_data', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('patch_url', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('nvd_last_modified', sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.drop_column('nvd_last_modified')
        batch_op.drop_column('patch_url')
        batch_op.drop_column('versions_data')
        batch_op.drop_column('weaknesses')
