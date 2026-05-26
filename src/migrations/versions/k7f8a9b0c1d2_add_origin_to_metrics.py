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
    # Normalize legacy UUID placeholders to the historical custom author and
    # treat only that author as custom during backfill.
    #
    # Older UI-created custom CVSS entries used "vulnscout" as the author.
    # Some legacy databases instead contain UUID-format placeholder authors;
    # those must be normalized during backfill or the review UI will now
    # classify them as scanner-authored and hide them.
    op.execute(
        """
        UPDATE metrics
        SET author = CASE
            WHEN coalesce(author, '') LIKE '________-____-____-____-____________' THEN 'vulnscout'
            ELSE author
        END,
            origin = CASE
            WHEN lower(trim(CASE
                WHEN coalesce(author, '') LIKE '________-____-____-____-____________' THEN 'vulnscout'
                ELSE coalesce(author, '')
            END)) = 'vulnscout' THEN 'custom'
            ELSE 'scanner'
        END
        WHERE origin IS NULL
        """
    )


def downgrade():
    with op.batch_alter_table('metrics', schema=None) as batch_op:
        batch_op.drop_column('origin')
