# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Persist explicit AI context editor preferences."""

from alembic import op
import sqlalchemy as sa

revision = 'ed91a8f6c302'
down_revision = 'c83e91ab402d'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('variant_context') as batch_op:
        batch_op.add_column(sa.Column('editor_mode', sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table('variant_context') as batch_op:
        batch_op.drop_column('editor_mode')
