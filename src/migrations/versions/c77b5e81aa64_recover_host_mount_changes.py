"""Make host folder approvals and deferred detach operations recoverable."""

from alembic import op
import sqlalchemy as sa

revision = "c77b5e81aa64"
down_revision = "f3b8d2a6c514"
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if "approval_proof" not in {c["name"] for c in inspector.get_columns("variant_host_mounts")}:
        op.add_column("variant_host_mounts", sa.Column("approval_proof", sa.Text(), nullable=True))
    if not inspector.has_table("host_mount_detach_outbox"):
        op.create_table(
            "host_mount_detach_outbox",
            sa.Column("attachment_id", sa.Uuid(), primary_key=True),
            sa.Column("variant_id", sa.Uuid(), nullable=False),
            sa.Column("alias", sa.String(32), nullable=False),
        )
        op.create_index("ix_host_mount_detach_outbox_variant_id", "host_mount_detach_outbox", ["variant_id"])


def downgrade():
    op.drop_table("host_mount_detach_outbox")
    with op.batch_alter_table("variant_host_mounts") as batch:
        batch.drop_column("approval_proof")
