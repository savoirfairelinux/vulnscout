# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Track cleanup ownership of provisional local-scan assessments."""

from alembic import op
import sqlalchemy as sa


revision = 'e9b72c4a1d60'
down_revision = 'd8f63a29b104'
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    if 'in_progress' not in {column['name'] for column in sa.inspect(connection).get_columns('scans')}:
        with op.batch_alter_table('scans') as batch_op:
            batch_op.add_column(sa.Column('in_progress', sa.Boolean(), nullable=False, server_default=sa.false()))
    if 'provisional_scan_id' not in {
        column['name'] for column in sa.inspect(connection).get_columns('assessments')
    }:
        with op.batch_alter_table('assessments') as batch_op:
            batch_op.add_column(sa.Column(
                'provisional_scan_id', sa.Uuid(),
                sa.ForeignKey('scans.id', name='fk_assessments_provisional_scan_id_scans', ondelete='SET NULL'),
                nullable=True,
            ))
    if 'ix_assessments_provisional_scan_id' not in {
        index['name'] for index in sa.inspect(connection).get_indexes('assessments')
    }:
        with op.batch_alter_table('assessments') as batch_op:
            batch_op.create_index('ix_assessments_provisional_scan_id', ['provisional_scan_id'])


def downgrade():
    with op.batch_alter_table('assessments') as batch_op:
        batch_op.drop_index('ix_assessments_provisional_scan_id')
        batch_op.drop_constraint('fk_assessments_provisional_scan_id_scans', type_='foreignkey')
        batch_op.drop_column('provisional_scan_id')
    with op.batch_alter_table('scans') as batch_op:
        batch_op.drop_column('in_progress')
