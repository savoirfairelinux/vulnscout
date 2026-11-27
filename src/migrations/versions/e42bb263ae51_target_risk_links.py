"""Store optional modeled-risk references on exact assessment targets."""

from alembic import op
import sqlalchemy as sa

revision = "e42bb263ae51"
down_revision = "c77b5e81aa64"
branch_labels = None
depends_on = None


def upgrade():
    if "risk_links" not in {c["name"] for c in sa.inspect(op.get_bind()).get_columns("assessment_targets")}:
        op.add_column("assessment_targets", sa.Column("risk_links", sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table("assessment_targets") as batch:
        batch.drop_column("risk_links")
