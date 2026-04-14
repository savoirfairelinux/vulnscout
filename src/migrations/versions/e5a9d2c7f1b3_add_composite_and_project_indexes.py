"""add composite and project indexes for query optimization

Revision ID: e5a9d2c7f1b3
Revises: b4e9f2a7c3d1
Create Date: 2026-04-08 10:00:00.000000

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'e5a9d2c7f1b3'
down_revision = 'b4e9f2a7c3d1'
branch_labels = None
depends_on = None


def upgrade():
    # Composite index on observations (scan_id, finding_id) – covers
    # the hot join pattern: JOIN observations ON finding_id = ? WHERE scan_id IN (...)
    op.create_index(
        'ix_observations_scan_finding', 'observations',
        ['scan_id', 'finding_id'],
    )

    # variants.project_id – used by _latest_scan_ids_for_project and
    # _populate_found_by to scope queries to a single project.
    op.create_index(
        'ix_variants_project_id', 'variants', ['project_id'],
    )


def downgrade():
    op.drop_index('ix_variants_project_id', 'variants')
    op.drop_index('ix_observations_scan_finding', 'observations')
