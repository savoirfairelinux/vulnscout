"""add variant_host_mounts table

Revision ID: f3b8d2a6c514
Revises: e7a4c91b2d35
Create Date: 2026-11-20 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'f3b8d2a6c514'
down_revision = 'e7a4c91b2d35'
branch_labels = None
depends_on = None


def upgrade():
    if sa.inspect(op.get_bind()).has_table('variant_host_mounts'):
        return
    op.create_table(
        'variant_host_mounts',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('variant_id', sa.Uuid(), nullable=False),
        sa.Column('alias', sa.String(length=32), nullable=False),
        sa.Column('host_path', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['variant_id'], ['variants.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('variant_id', 'alias', name='uq_variant_host_mount_alias'),
    )
    op.create_index('ix_variant_host_mounts_variant_id', 'variant_host_mounts', ['variant_id'])


def downgrade():
    op.drop_index('ix_variant_host_mounts_variant_id', table_name='variant_host_mounts')
    op.drop_table('variant_host_mounts')
