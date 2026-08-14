"""add assessment_reviews table

Revision ID: x0a1b2c3d4e5
Revises: w9f0a1b2c3d4
Create Date: 2026-08-06 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'x0a1b2c3d4e5'
down_revision = 'w9f0a1b2c3d4'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'assessment_reviews',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('assessment_id', sa.Uuid(), nullable=False),
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
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('assessment_id', name='uq_assessment_review_assessment'),
    )
    op.create_index(
        'ix_assessment_reviews_assessment_id', 'assessment_reviews', ['assessment_id']
    )


def downgrade():
    op.drop_index('ix_assessment_reviews_assessment_id', table_name='assessment_reviews')
    op.drop_table('assessment_reviews')
