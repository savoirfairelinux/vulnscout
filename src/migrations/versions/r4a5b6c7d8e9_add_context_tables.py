"""add project_context, variant_context, context_files tables

Revision ID: r4a5b6c7d8e9
Revises: q3f4a5b6c7d8
Create Date: 2026-06-29 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'r4a5b6c7d8e9'
down_revision = 'q3f4a5b6c7d8'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'project_context',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('project_id', sa.Uuid(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('project_id', name='uq_project_context_project'),
    )
    op.create_table(
        'variant_context',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('variant_id', sa.Uuid(), nullable=False),
        sa.Column('variant_description', sa.Text(), nullable=True),
        sa.Column('environment', sa.Text(), nullable=True),
        sa.Column('threat_model', sa.Text(), nullable=True),
        sa.Column('risks', sa.Text(), nullable=True),
        sa.Column('other_info', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['variant_id'], ['variants.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('variant_id', name='uq_variant_context_variant'),
    )
    op.create_table(
        'context_files',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('variant_context_id', sa.Uuid(), nullable=False),
        sa.Column('original_name', sa.String(), nullable=False),
        sa.Column('file_path', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ['variant_context_id'], ['variant_context.id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade():
    op.drop_table('context_files')
    op.drop_table('variant_context')
    op.drop_table('project_context')
