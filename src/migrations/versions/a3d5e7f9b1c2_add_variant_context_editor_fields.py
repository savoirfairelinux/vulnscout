"""add variant context codebase source and STRIDE fields, drop free-text threat model

Revision ID: a3d5e7f9b1c2
Revises: e9b72c4a1d60
Create Date: 2026-10-23 00:00:00.000000

"""
import json

from alembic import op
import sqlalchemy as sa


revision = 'a3d5e7f9b1c2'
down_revision = 'e9b72c4a1d60'
branch_labels = None
depends_on = None

# Free-text threat model and risks, replaced by the rendering of the STRIDE model.
FREE_TEXT_COLUMNS = ('threat_model', 'risks')


def upgrade():
    # Columns may already exist (schema built from current models, then stamped).
    existing = {column['name'] for column in sa.inspect(op.get_bind()).get_columns('variant_context')}
    columns = [
        sa.Column('codebase_source', sa.String(), nullable=False, server_default='paths'),
        sa.Column('system_scope', sa.Text(), nullable=True),
        sa.Column('system_actors', sa.Text(), nullable=True),
        sa.Column('system_entry_points', sa.Text(), nullable=True),
        sa.Column('system_trust_boundaries', sa.Text(), nullable=True),
        sa.Column('stride_model', sa.JSON(), nullable=True),
    ]
    missing = [column for column in columns if column.name not in existing]
    obsolete = [name for name in FREE_TEXT_COLUMNS if name in existing]
    if obsolete:
        # The agent stops seeing this text, so assessments made against it are outdated.
        filled = " OR ".join(f"({name} IS NOT NULL AND TRIM({name}) <> '')" for name in obsolete)
        op.execute(sa.text(f"UPDATE variant_context SET updated_at = CURRENT_TIMESTAMP WHERE {filled}"))
    if missing or obsolete:
        with op.batch_alter_table('variant_context') as batch_op:
            for column in missing:
                batch_op.add_column(column)
            for name in obsolete:
                batch_op.drop_column(name)
    if 'codebase_source' in existing:
        # Already populated; re-running the backfill could override a user's choice.
        return
    # Contexts that already have uploaded references keep using them.
    # updated_at is left untouched here: choosing the source is not a content change.
    op.execute(sa.text(
        "UPDATE variant_context SET codebase_source = 'references' "
        "WHERE EXISTS (SELECT 1 FROM context_files f "
        "WHERE f.variant_context_id = variant_context.id)"
    ))


def downgrade():
    from src.helpers.stride_model import render_risks, render_threat_model

    with op.batch_alter_table('variant_context') as batch_op:
        batch_op.add_column(sa.Column('threat_model', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('risks', sa.Text(), nullable=True))
    # Keep the agent-visible context: write the rendered model back as free text.
    connection = op.get_bind()
    rows = connection.execute(sa.text(
        "SELECT id, system_scope, system_actors, system_entry_points, system_trust_boundaries, stride_model "
        "FROM variant_context"
    )).mappings().all()
    for row in rows:
        stride = row['stride_model']
        if isinstance(stride, str):
            stride = json.loads(stride)
        system = {
            'scope': row['system_scope'],
            'actors': row['system_actors'],
            'entry_points': row['system_entry_points'],
            'trust_boundaries': row['system_trust_boundaries'],
        }
        threat_model, risks = render_threat_model(system, stride), render_risks(stride)
        if threat_model is not None or risks is not None:
            connection.execute(
                sa.text("UPDATE variant_context SET threat_model = :threat_model, risks = :risks WHERE id = :id"),
                {'threat_model': threat_model, 'risks': risks, 'id': row['id']},
            )
    with op.batch_alter_table('variant_context') as batch_op:
        batch_op.drop_column('stride_model')
        batch_op.drop_column('system_trust_boundaries')
        batch_op.drop_column('system_entry_points')
        batch_op.drop_column('system_actors')
        batch_op.drop_column('system_scope')
        batch_op.drop_column('codebase_source')
