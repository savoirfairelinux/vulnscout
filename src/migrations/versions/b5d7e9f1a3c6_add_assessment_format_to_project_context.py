"""Add a project-level presentation format for AI assessment text."""
from alembic import op
import sqlalchemy as sa

revision = "b5d7e9f1a3c6"
down_revision = "c77b5e81aa64"
branch_labels = None
depends_on = None


def upgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("project_context")}
    if "assessment_format" not in columns:
        op.add_column("project_context", sa.Column("assessment_format", sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table("project_context") as batch_op:
        batch_op.drop_column("assessment_format")
