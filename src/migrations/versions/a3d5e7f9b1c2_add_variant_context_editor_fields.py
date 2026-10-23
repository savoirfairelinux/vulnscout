"""add variant context editor mode, codebase source and STRIDE fields

Revision ID: a3d5e7f9b1c2
Revises: e9b72c4a1d60
Create Date: 2026-10-23 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'a3d5e7f9b1c2'
down_revision = 'e9b72c4a1d60'
branch_labels = None
depends_on = None


def upgrade():
    # Columns may already exist (schema built from current models, then stamped).
    existing = {column['name'] for column in sa.inspect(op.get_bind()).get_columns('variant_context')}
    columns = [
        sa.Column('editor_mode', sa.String(), nullable=False, server_default='free'),
        sa.Column('codebase_source', sa.String(), nullable=False, server_default='paths'),
        sa.Column('system_scope', sa.Text(), nullable=True),
        sa.Column('system_actors', sa.Text(), nullable=True),
        sa.Column('system_entry_points', sa.Text(), nullable=True),
        sa.Column('system_trust_boundaries', sa.Text(), nullable=True),
        sa.Column('stride_model', sa.JSON(), nullable=True),
    ]
    missing = [column for column in columns if column.name not in existing]
    if missing:
        with op.batch_alter_table('variant_context') as batch_op:
            for column in missing:
                batch_op.add_column(column)
    if 'codebase_source' in existing:
        # Already populated; re-running the backfill could override a user's choice.
        return
    # Contexts that already have uploaded references keep using them.
    # updated_at is deliberately left untouched: this is not a content change.
    op.execute(sa.text(
        "UPDATE variant_context SET codebase_source = 'references' "
        "WHERE EXISTS (SELECT 1 FROM context_files f "
        "WHERE f.variant_context_id = variant_context.id)"
    ))


def downgrade():
    with op.batch_alter_table('variant_context') as batch_op:
        batch_op.drop_column('stride_model')
        batch_op.drop_column('system_trust_boundaries')
        batch_op.drop_column('system_entry_points')
        batch_op.drop_column('system_actors')
        batch_op.drop_column('system_scope')
        batch_op.drop_column('codebase_source')
        batch_op.drop_column('editor_mode')
