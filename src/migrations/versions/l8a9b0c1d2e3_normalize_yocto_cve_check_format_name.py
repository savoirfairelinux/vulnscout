"""normalize yocto cve check format name in sbom documents

Revision ID: l8a9b0c1d2e3
Revises: k7f8a9b0c1d2
Create Date: 2026-06-02 00:00:00.000000

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'l8a9b0c1d2e3'
down_revision = 'k7f8a9b0c1d2'
branch_labels = None
depends_on = None


def upgrade():
    # Canonicalize legacy Yocto format key.
    op.execute(
        """
        UPDATE sbom_documents
        SET format = 'yocto_cve_check'
        WHERE format = 'yocto'
        """
    )


def downgrade():
    op.execute(
        """
        UPDATE sbom_documents
        SET format = 'yocto'
        WHERE format = 'yocto_cve_check'
        """
    )