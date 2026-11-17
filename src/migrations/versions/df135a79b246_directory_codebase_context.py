"""Replace legacy codebase settings with unique directory names."""
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "df135a79b246"
down_revision = "ab721d903ef1"
branch_labels = None
depends_on = None

INDEX_NAME = "uq_variant_context_codebase_directory"


def upgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("variant_context")}
    if "codebase_directory" not in columns:
        op.add_column("variant_context", sa.Column("codebase_directory", sa.Text(), nullable=True))
    if {"codebase_source", "codebase_path"} <= columns:
        op.execute(sa.text(
            "UPDATE variant_context SET updated_at = :now "
            "WHERE codebase_directory IS NULL AND codebase_source = 'paths' "
            "AND (TRIM(COALESCE(codebase_path, '')) <> '' OR EXISTS ("
            "SELECT 1 FROM context_files WHERE context_files.variant_context_id = variant_context.id))"
        ).bindparams(now=datetime.now(timezone.utc)))
    # Rebuilding this parent table can cascade-delete context files on SQLite.
    for name in ("codebase_source", "codebase_path"):
        if name in columns:
            op.drop_column("variant_context", name)
    if INDEX_NAME not in {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("variant_context")}:
        op.create_index(INDEX_NAME, "variant_context", ["codebase_directory"], unique=True)


def downgrade():
    """Restore empty legacy settings; discarded values cannot be recovered."""
    op.drop_index(INDEX_NAME, table_name="variant_context")
    op.drop_column("variant_context", "codebase_directory")
    op.add_column("variant_context", sa.Column("codebase_path", sa.Text(), nullable=True))
    op.add_column("variant_context", sa.Column("codebase_source", sa.String(), nullable=False, server_default="paths"))
