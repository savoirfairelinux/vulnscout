"""Flag SBOM documents whose dependency relationships were recorded.

Revision ID: cc5359c88dd2
Revises: d8e2a1c7b9f0

Documents imported before dependency support stay unflagged, and their source
files are usually removed after import, so their packages are reported as "not
recorded" instead of having zero dependencies. Importing the SBOM again (CLI scan
or web upload) creates a new active scan whose relationships are recorded.
"""
from alembic import op
import sqlalchemy as sa


revision = 'cc5359c88dd2'
down_revision = 'd8e2a1c7b9f0'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('sbom_documents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('dependencies_recorded', sa.Boolean(), nullable=False,
                                      server_default=sa.false()))

    # Databases that already ran the previous revision stored edges for the scans parsed since.
    documents = sa.table('sbom_documents', sa.column('id', sa.Uuid()), sa.column('scan_id', sa.Uuid()),
                         sa.column('dependencies_recorded', sa.Boolean()))
    parsed = documents.alias('parsed')
    edges = sa.table('package_dependencies', sa.column('sbom_document_id', sa.Uuid()))
    op.execute(documents.update().where(documents.c.scan_id.in_(
        sa.select(parsed.c.scan_id).join(edges, edges.c.sbom_document_id == parsed.c.id)
    )).values(dependencies_recorded=True))


def downgrade():
    with op.batch_alter_table('sbom_documents', schema=None) as batch_op:
        batch_op.drop_column('dependencies_recorded')
