"""Add per-document package dependency edges.

Revision ID: d8e2a1c7b9f0
Revises: b4c5d6e7f809
"""
from alembic import op
import sqlalchemy as sa


revision = 'd8e2a1c7b9f0'
down_revision = 'b4c5d6e7f809'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'package_dependencies',
        sa.Column('sbom_document_id', sa.Uuid(), nullable=False),
        sa.Column('package_id', sa.Uuid(), nullable=False),
        sa.Column('dependency_id', sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(['sbom_document_id', 'package_id'],
                                ['sbom_packages.sbom_document_id', 'sbom_packages.package_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['dependency_id'], ['packages.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('sbom_document_id', 'package_id', 'dependency_id'),
    )
    op.create_index('ix_package_dependencies_document_dependency', 'package_dependencies',
                    ['sbom_document_id', 'dependency_id'])


def downgrade():
    op.drop_index('ix_package_dependencies_document_dependency', table_name='package_dependencies')
    op.drop_table('package_dependencies')
