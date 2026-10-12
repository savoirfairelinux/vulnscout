# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Store shared AI-context entries and their explicit variant targets."""

from alembic import op
import sqlalchemy as sa

revision = 'f38ab91c620d'
down_revision = 'ed91a8f6c302'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('project_context') as batch_op:
        batch_op.add_column(sa.Column('shared_context', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('context_revision', sa.Integer(), nullable=False, server_default='0'))


def downgrade():
    with op.batch_alter_table('project_context') as batch_op:
        batch_op.drop_column('context_revision')
        batch_op.drop_column('shared_context')
