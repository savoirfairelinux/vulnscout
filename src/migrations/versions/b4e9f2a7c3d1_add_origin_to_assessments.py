"""add origin column to assessments

Revision ID: b4e9f2a7c3d1
Revises: f1a2b3c4d5e6
Create Date: 2026-04-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b4e9f2a7c3d1'
down_revision = 'f1a2b3c4d5e6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('assessments', schema=None) as batch_op:
        batch_op.add_column(sa.Column('origin', sa.String(), nullable=True))

    # Default existing rows to 'sbom' since they come from SBOM imports
    op.execute("UPDATE assessments SET origin = 'sbom' WHERE origin IS NULL")


def downgrade():
    with op.batch_alter_table('assessments', schema=None) as batch_op:
        batch_op.drop_column('origin')
