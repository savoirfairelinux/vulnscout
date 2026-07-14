"""Move refresh metadata columns from vulnerabilities to new vuln_refresh table.

Revision ID: r4a5b6c7d8e9
Revises: q3f4a5b6c7d8
Create Date: 2026-06-26 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'r4a5b6c7d8e9'
down_revision = 'q3f4a5b6c7d8'
branch_labels = None
depends_on = None


def upgrade():
    # 1. Create the vuln_refresh table holding the per-vulnerability refresh
    #    metadata (fetch timestamps, NVD last-modified) that previously lived
    #    on the vulnerabilities table.
    op.create_table(
        'vuln_refresh',
        sa.Column(
            'vuln_id', sa.String(length=50),
            sa.ForeignKey('vulnerabilities.id', ondelete='CASCADE'),
            primary_key=True,
        ),
        sa.Column('epss_fetched_at', sa.DateTime(), nullable=True),
        sa.Column('epss_data_updated_at', sa.DateTime(), nullable=True),
        sa.Column('nvd_last_modified', sa.Text(), nullable=True),
        sa.Column('nvd_fetched_at', sa.DateTime(), nullable=True),
        sa.Column('nvd_data_updated_at', sa.DateTime(), nullable=True),
        sa.Column('ghsa_fetched_at', sa.DateTime(), nullable=True),
        sa.Column('ghsa_data_updated_at', sa.DateTime(), nullable=True),
    )

    # 2. Copy any non-null refresh data from the vulnerabilities table.
    #    Only creates rows for vulnerabilities that actually have refresh data,
    #    keeping the table sparse.
    conn = op.get_bind()
    conn.execute(sa.text("""
        INSERT INTO vuln_refresh (
            vuln_id,
            epss_fetched_at, epss_data_updated_at,
            nvd_last_modified, nvd_fetched_at, nvd_data_updated_at,
            ghsa_fetched_at, ghsa_data_updated_at
        )
        SELECT
            id,
            epss_fetched_at, epss_data_updated_at,
            nvd_last_modified, nvd_fetched_at, nvd_data_updated_at,
            ghsa_fetched_at, ghsa_data_updated_at
        FROM vulnerabilities
        WHERE epss_fetched_at      IS NOT NULL
           OR epss_data_updated_at IS NOT NULL
           OR nvd_last_modified    IS NOT NULL
           OR nvd_fetched_at       IS NOT NULL
           OR nvd_data_updated_at  IS NOT NULL
           OR ghsa_fetched_at      IS NOT NULL
           OR ghsa_data_updated_at IS NOT NULL
    """))

    # 3. Drop the seven refresh columns from vulnerabilities.
    #    SQLite requires batch_alter_table for column removal.
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.drop_column('epss_fetched_at')
        batch_op.drop_column('epss_data_updated_at')
        batch_op.drop_column('nvd_last_modified')
        batch_op.drop_column('nvd_fetched_at')
        batch_op.drop_column('nvd_data_updated_at')
        batch_op.drop_column('ghsa_fetched_at')
        batch_op.drop_column('ghsa_data_updated_at')


def downgrade():
    # 1. Re-add the seven refresh columns to vulnerabilities.
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.add_column(sa.Column('epss_fetched_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('epss_data_updated_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('nvd_last_modified', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('nvd_fetched_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('nvd_data_updated_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('ghsa_fetched_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('ghsa_data_updated_at', sa.DateTime(), nullable=True))

    # 2. Restore data from vuln_refresh back into vulnerabilities.
    #    Using a correlated subquery for compatibility with all SQLite versions.
    conn = op.get_bind()
    conn.execute(sa.text("""
        UPDATE vulnerabilities
        SET
            epss_fetched_at      = (SELECT r.epss_fetched_at      FROM vuln_refresh r WHERE r.vuln_id = vulnerabilities.id),
            epss_data_updated_at = (SELECT r.epss_data_updated_at FROM vuln_refresh r WHERE r.vuln_id = vulnerabilities.id),
            nvd_last_modified    = (SELECT r.nvd_last_modified    FROM vuln_refresh r WHERE r.vuln_id = vulnerabilities.id),
            nvd_fetched_at       = (SELECT r.nvd_fetched_at       FROM vuln_refresh r WHERE r.vuln_id = vulnerabilities.id),
            nvd_data_updated_at  = (SELECT r.nvd_data_updated_at  FROM vuln_refresh r WHERE r.vuln_id = vulnerabilities.id),
            ghsa_fetched_at      = (SELECT r.ghsa_fetched_at      FROM vuln_refresh r WHERE r.vuln_id = vulnerabilities.id),
            ghsa_data_updated_at = (SELECT r.ghsa_data_updated_at FROM vuln_refresh r WHERE r.vuln_id = vulnerabilities.id)
        WHERE EXISTS (SELECT 1 FROM vuln_refresh r WHERE r.vuln_id = vulnerabilities.id)
    """))

    # 3. Drop the vuln_refresh table.
    op.drop_table('vuln_refresh')
