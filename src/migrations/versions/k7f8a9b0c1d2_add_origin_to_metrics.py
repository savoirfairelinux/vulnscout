"""add origin column to metrics

Revision ID: k7f8a9b0c1d2
Revises: j6e7f8a9b0c1
Create Date: 2026-05-26 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'k7f8a9b0c1d2'
down_revision = 'j6e7f8a9b0c1'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('metrics', schema=None) as batch_op:
        batch_op.add_column(sa.Column('origin', sa.String(), nullable=True))

    # Existing rows predate explicit CVSS origin tracking.
    # Normalize legacy UUID placeholders to the historical custom author name.
    #
    # For origin classification we use the same blocklist that the runtime
    # _is_scanner_author() helper applies.  Only well-known scanner/NVD
    # identifiers and UUID-format placeholders become 'scanner'; every other
    # author — including any user-supplied name — becomes 'custom'.  This
    # preserves the behavioural contract of the old UI, which showed all
    # metrics whose author was NOT 'nvd' or 'unknown'.
    op.execute(
        """
        UPDATE metrics
        SET author = CASE
            WHEN coalesce(author, '') LIKE '________-____-____-____-____________' THEN 'vulnscout'
            ELSE author
        END,
            origin = CASE
            WHEN coalesce(author, '') = '' THEN 'scanner'
            WHEN coalesce(author, '') LIKE '________-____-____-____-____________' THEN 'custom'
            WHEN lower(trim(coalesce(author, ''))) IN (
                'nvd',
                'unknown',
                'nvd@nist.gov',
                'security-advisories@github.com',
                'cve@mitre.org',
                'secalert@redhat.com',
                'cna@cloudflare.com'
            ) THEN 'scanner'
            ELSE 'custom'
        END
        WHERE origin IS NULL
        """
    )


def downgrade():
    with op.batch_alter_table('metrics', schema=None) as batch_op:
        batch_op.drop_column('origin')
