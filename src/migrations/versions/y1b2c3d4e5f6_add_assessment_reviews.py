"""add assessment_reviews table

Revision ID: y1b2c3d4e5f6
Revises: x0a1b2c3d4e5
Create Date: 2026-08-06 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'y1b2c3d4e5f6'
down_revision = 'x0a1b2c3d4e5'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'assessment_reviews',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('assessment_id', sa.Uuid(), nullable=False),
        sa.Column('variant_id', sa.Uuid(), nullable=False),
        sa.Column('finding_id', sa.Uuid(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('status_notes', sa.Text(), nullable=True),
        sa.Column('justification', sa.Text(), nullable=True),
        sa.Column('impact_statement', sa.Text(), nullable=True),
        sa.Column('workaround', sa.Text(), nullable=True),
        sa.Column('responses', sa.JSON(), nullable=True),
        sa.Column('rationale', sa.Text(), nullable=False),
        sa.Column('reviewed_fingerprint', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['assessment_id'], ['assessments.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['variant_id'], ['variants.id']),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'assessment_id', 'variant_id', 'finding_id', name='uq_assessment_review_target'
        ),
    )
    op.create_index(
        'ix_assessment_reviews_assessment_id', 'assessment_reviews', ['assessment_id']
    )
    op.create_index(
        'ix_assessment_reviews_variant_id', 'assessment_reviews', ['variant_id']
    )
    op.create_index(
        'ix_assessment_reviews_finding_id', 'assessment_reviews', ['finding_id']
    )


def downgrade():
    op.drop_index('ix_assessment_reviews_finding_id', table_name='assessment_reviews')
    op.drop_index('ix_assessment_reviews_variant_id', table_name='assessment_reviews')
    op.drop_index('ix_assessment_reviews_assessment_id', table_name='assessment_reviews')
    op.drop_table('assessment_reviews')
