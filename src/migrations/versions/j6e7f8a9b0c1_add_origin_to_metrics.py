"""add origin column to metrics

Revision ID: j6e7f8a9b0c1
Revises: i5d6e7f8a9b0
Create Date: 2026-05-26 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'j6e7f8a9b0c1'
down_revision = 'i5d6e7f8a9b0'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('metrics', schema=None) as batch_op:
        batch_op.add_column(sa.Column('origin', sa.String(), nullable=True))

    # Existing rows predate explicit CVSS origin tracking.
    # Preserve legacy behavior where non-nvd/non-unknown authors were treated
    # as custom entries in review/export flows.
    op.execute(
        """
        UPDATE metrics
        SET origin = CASE
            WHEN lower(coalesce(author, '')) IN ('nvd', 'unknown', '') THEN 'scanner'
            ELSE 'custom'
        END
        WHERE origin IS NULL
        """
    )


def downgrade():
    with op.batch_alter_table('metrics', schema=None) as batch_op:
        batch_op.drop_column('origin')
