"""Add per-document package dependency edges.

Revision ID: z2c3d4e5f6a7
Revises: y1b2c3d4e5f6
"""
from alembic import op
import sqlalchemy as sa


revision = 'z2c3d4e5f6a7'
down_revision = 'y1b2c3d4e5f6'
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
        sa.ForeignKeyConstraint(['sbom_document_id', 'dependency_id'],
                                ['sbom_packages.sbom_document_id', 'sbom_packages.package_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['dependency_id'], ['packages.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('sbom_document_id', 'package_id', 'dependency_id'),
    )
    op.create_index('ix_package_dependencies_document_dependency', 'package_dependencies',
                    ['sbom_document_id', 'dependency_id'])


def downgrade():
    op.drop_index('ix_package_dependencies_document_dependency', table_name='package_dependencies')
    op.drop_table('package_dependencies')