"""Remove structured modeled-risk references without editing assessment notes."""

from alembic import op
import sqlalchemy as sa

revision = "ef51e895ca7b"
down_revision = "f58c3d1a9e27"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_column("assessment_targets", "risk_links")


def downgrade():
    op.add_column("assessment_targets", sa.Column("risk_links", sa.JSON(), nullable=True))
