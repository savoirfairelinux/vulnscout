"""ensure variant_context.codebase_path exists

The codebase_path column was added by amending the already-applied
t6c7d8e9f0a1 migration, so databases migrated before that amendment
are missing it. This migration adds the column only when absent.

Revision ID: u7d8e9f0a1b2
Revises: t6c7d8e9f0a1
Create Date: 2026-08-04 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'u7d8e9f0a1b2'
down_revision = 't6c7d8e9f0a1'
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table('variant_context'):
        return
    columns = [col['name'] for col in inspector.get_columns('variant_context')]
    if 'codebase_path' not in columns:
        op.add_column('variant_context', sa.Column('codebase_path', sa.Text(), nullable=True))


def downgrade():
    # Keep the column: it is part of the t6c7d8e9f0a1 schema for fresh databases.
    pass
