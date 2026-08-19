"""Add sparse assessment group membership table.

Revision ID: x0a1b2c3d4e5
Revises: w9f0a1b2c3d4
Create Date: 2026-08-19 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'x0a1b2c3d4e5'
down_revision = 'w9f0a1b2c3d4'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'assessment_group_members',
        sa.Column('assessment_id', sa.Uuid(), nullable=False),
        sa.Column('group_id', sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ['assessment_id'], ['assessments.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('assessment_id'),
    )
    op.create_index(
        'ix_assessment_group_members_group_id',
        'assessment_group_members',
        ['group_id'],
    )


def downgrade():
    op.drop_index(
        'ix_assessment_group_members_group_id',
        table_name='assessment_group_members',
    )
    op.drop_table('assessment_group_members')
