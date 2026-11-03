# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Preserve document-scoped Zephyr compiler metadata by build target."""

from alembic import op
import sqlalchemy as sa

revision = 'e91a47b28c60'
down_revision = 'f2b4d6e8a0c1'
branch_labels = None
depends_on = None


def upgrade():
    existing = {column['name'] for column in sa.inspect(op.get_bind()).get_columns('sbom_documents')}
    if 'build_targets' in existing:
        return
    with op.batch_alter_table('sbom_documents') as batch_op:
        batch_op.add_column(sa.Column('build_targets', sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table('sbom_documents') as batch_op:
        batch_op.drop_column('build_targets')
