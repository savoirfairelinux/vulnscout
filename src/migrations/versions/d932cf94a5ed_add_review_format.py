"""Add the independent presentation preference for review rationale."""
from alembic import op
import sqlalchemy as sa

revision = "d932cf94a5ed"
down_revision = "b5d7e9f1a3c6"
branch_labels = None
depends_on = None


def upgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("project_context")}
    if "review_format" not in columns:
        op.add_column("project_context", sa.Column("review_format", sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table("project_context") as batch_op:
        batch_op.drop_column("review_format")
