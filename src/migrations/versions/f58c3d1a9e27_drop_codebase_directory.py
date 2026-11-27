"""Drop the per-variant auto-provisioned codebase directory column."""

from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "f58c3d1a9e27"
down_revision = "e42bb263ae51"
branch_labels = None
depends_on = None

INDEX_NAME = "uq_variant_context_codebase_directory"


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if INDEX_NAME in {index["name"] for index in inspector.get_indexes("variant_context")}:
        op.drop_index(INDEX_NAME, table_name="variant_context")
    if "codebase_directory" in {column["name"] for column in inspector.get_columns("variant_context")}:
        op.execute(sa.text(
            "UPDATE variant_context SET updated_at = :now WHERE codebase_directory IS NOT NULL"
        ).bindparams(now=datetime.now(timezone.utc)))
        # Plain DROP COLUMN: rebuilding this parent table can cascade-delete context files on SQLite.
        op.drop_column("variant_context", "codebase_directory")


def downgrade():
    op.add_column("variant_context", sa.Column("codebase_directory", sa.Text(), nullable=True))
    op.create_index(INDEX_NAME, "variant_context", ["codebase_directory"], unique=True)
