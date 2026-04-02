"""add missing indexes for performance

Revision ID: c7f2a3d8e1b4
Revises: ab6e71e9f9b8
Create Date: 2026-03-17 10:00:00.000000

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'c7f2a3d8e1b4'
down_revision = 'ab6e71e9f9b8'
branch_labels = None
depends_on = None


def upgrade():
    # packages: lookups by (name, version) in find_or_create / get_by_string_id
    op.create_index('ix_packages_name_version', 'packages', ['name', 'version'])

    # findings: lookups by vulnerability_id (get_by_vulnerability, lazy loading,
    # Assessment.get_by_vulnerability JOIN)
    op.create_index('ix_findings_vulnerability_id', 'findings', ['vulnerability_id'])
    # findings: lookups by package_id (get_by_package, lazy loading)
    op.create_index('ix_findings_package_id', 'findings', ['package_id'])

    # assessments: lookups by finding_id (from_vuln_assessment, get_by_finding, lazy loading)
    op.create_index('ix_assessments_finding_id', 'assessments', ['finding_id'])
    # assessments: lookups by variant_id (get_by_variant)
    op.create_index('ix_assessments_variant_id', 'assessments', ['variant_id'])

    # metrics: lookups by vulnerability_id (from_cvss, get_by_vulnerability, lazy loading)
    op.create_index('ix_metrics_vulnerability_id', 'metrics', ['vulnerability_id'])

    # observations: lookups by scan_id (get_by_scan)
    op.create_index('ix_observations_scan_id', 'observations', ['scan_id'])
    # observations: lookups by finding_id (lazy loading from Finding)
    op.create_index('ix_observations_finding_id', 'observations', ['finding_id'])

    # time_estimates: lookups by finding_id (lazy loading from Finding)
    op.create_index('ix_time_estimates_finding_id', 'time_estimates', ['finding_id'])

    # scans: lookups by variant_id (lazy loading from Variant)
    op.create_index('ix_scans_variant_id', 'scans', ['variant_id'])

    # sbom_documents: lookups by scan_id (lazy loading from Scan)
    op.create_index('ix_sbom_documents_scan_id', 'sbom_documents', ['scan_id'])

    # sbom_packages: lookups by package_id
    op.create_index('ix_sbom_packages_package_id', 'sbom_packages', ['package_id'])


def downgrade():
    op.drop_index('ix_sbom_packages_package_id', 'sbom_packages')
    op.drop_index('ix_sbom_documents_scan_id', 'sbom_documents')
    op.drop_index('ix_scans_variant_id', 'scans')
    op.drop_index('ix_time_estimates_finding_id', 'time_estimates')
    op.drop_index('ix_observations_finding_id', 'observations')
    op.drop_index('ix_observations_scan_id', 'observations')
    op.drop_index('ix_metrics_vulnerability_id', 'metrics')
    op.drop_index('ix_assessments_variant_id', 'assessments')
    op.drop_index('ix_assessments_finding_id', 'assessments')
    op.drop_index('ix_findings_package_id', 'findings')
    op.drop_index('ix_findings_vulnerability_id', 'findings')
    op.drop_index('ix_packages_name_version', 'packages')
