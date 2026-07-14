"""Add ENISA EUVD enrichment fields.

Revision ID: s5b6c7d8e9f0
Revises: r4a5b6c7d8e9
Create Date: 2026-06-30 00:00:00.000000

The EUVD *content* fields (alias id, known-exploited flag, KEV sources, date
added) live on the vulnerabilities table next to the other vulnerability data
(e.g. epss_score).  The EUVD *refresh* timestamps go straight into the
vuln_refresh table created by the previous migration, so they never have to be
added to vulnerabilities and moved afterwards.

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 's5b6c7d8e9f0'
down_revision = 'r4a5b6c7d8e9'
branch_labels = None
depends_on = None


def upgrade():
    # EUVD content lives on the vulnerability itself (like epss_score).
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.add_column(sa.Column('euvd_id', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('euvd_known_exploited', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('euvd_kev_sources', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('euvd_date_added', sa.String(length=32), nullable=True))

    # EUVD refresh timestamps go straight into vuln_refresh.
    with op.batch_alter_table('vuln_refresh', schema=None) as batch_op:
        batch_op.add_column(sa.Column('euvd_fetched_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('euvd_data_updated_at', sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table('vuln_refresh', schema=None) as batch_op:
        batch_op.drop_column('euvd_data_updated_at')
        batch_op.drop_column('euvd_fetched_at')

    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.drop_column('euvd_date_added')
        batch_op.drop_column('euvd_kev_sources')
        batch_op.drop_column('euvd_known_exploited')
        batch_op.drop_column('euvd_id')
