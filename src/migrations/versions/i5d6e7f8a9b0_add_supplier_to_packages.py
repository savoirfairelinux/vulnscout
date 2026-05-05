"""add supplier to packages

Revision ID: i5d6e7f8a9b0
Revises: h4c5d6e7f8a9
Create Date: 2026-05-05 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = 'i5d6e7f8a9b0'
down_revision = 'h4c5d6e7f8a9'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('packages', sa.Column('supplier', sa.String(), server_default='', nullable=True))
    op.drop_index('ix_packages_name_version', table_name='packages')
    op.create_index('ix_packages_name_version_supplier', 'packages', ['name', 'version', 'supplier'])


def downgrade():
    op.drop_index('ix_packages_name_version_supplier', table_name='packages')
    op.create_index('ix_packages_name_version', 'packages', ['name', 'version'])
    op.drop_column('packages', 'supplier')
