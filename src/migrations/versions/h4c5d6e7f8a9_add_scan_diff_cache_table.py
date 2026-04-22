"""add scan_diff_cache table

Revision ID: h4c5d6e7f8a9
Revises: g3b4c5d6e7f8
Create Date: 2026-06-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'h4c5d6e7f8a9'
down_revision = 'g3b4c5d6e7f8'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'scan_diff_cache',
        sa.Column('scan_id', sa.Uuid(), sa.ForeignKey('scans.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('finding_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('package_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('vuln_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('is_first', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('findings_added', sa.Integer(), nullable=True),
        sa.Column('findings_removed', sa.Integer(), nullable=True),
        sa.Column('findings_upgraded', sa.Integer(), nullable=True),
        sa.Column('findings_unchanged', sa.Integer(), nullable=True),
        sa.Column('packages_added', sa.Integer(), nullable=True),
        sa.Column('packages_removed', sa.Integer(), nullable=True),
        sa.Column('packages_upgraded', sa.Integer(), nullable=True),
        sa.Column('packages_unchanged', sa.Integer(), nullable=True),
        sa.Column('vulns_added', sa.Integer(), nullable=True),
        sa.Column('vulns_removed', sa.Integer(), nullable=True),
        sa.Column('vulns_unchanged', sa.Integer(), nullable=True),
        sa.Column('newly_detected_findings', sa.Integer(), nullable=True),
        sa.Column('newly_detected_vulns', sa.Integer(), nullable=True),
        sa.Column('branch_finding_count', sa.Integer(), nullable=True),
        sa.Column('branch_vuln_count', sa.Integer(), nullable=True),
        sa.Column('branch_package_count', sa.Integer(), nullable=True),
        sa.Column('global_finding_count', sa.Integer(), nullable=True),
        sa.Column('global_vuln_count', sa.Integer(), nullable=True),
        sa.Column('global_package_count', sa.Integer(), nullable=True),
        sa.Column('formats_json', sa.Text(), nullable=True),
    )


def downgrade():
    op.drop_table('scan_diff_cache')
