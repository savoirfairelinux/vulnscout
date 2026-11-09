# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Record upstream URLs and cache package repository health (OpenSSF Scorecard)."""

from alembic import op
import sqlalchemy as sa

revision = 'de1339f8135e'
down_revision = 'e91a47b28c60'
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if 'upstream_urls' not in {column['name'] for column in inspector.get_columns('sbom_packages')}:
        with op.batch_alter_table('sbom_packages') as batch_op:
            batch_op.add_column(sa.Column('upstream_urls', sa.JSON(), nullable=True))
    tables = set(inspector.get_table_names())
    if 'package_repositories' not in tables:
        op.create_table(
            'package_repositories',
            sa.Column('package_id', sa.Uuid(), sa.ForeignKey('packages.id', ondelete='CASCADE'),
                      primary_key=True),
            sa.Column('repository', sa.String(length=255), nullable=True),
            sa.Column('source', sa.String(length=16), nullable=False),
            sa.Column('evidence', sa.Text(), nullable=True),
            sa.Column('deprecated', sa.Boolean(), nullable=True),
            sa.Column('deprecated_reason', sa.Text(), nullable=True),
            sa.Column('resolved_at', sa.DateTime(), nullable=False),
        )
    if 'repository_scorecards' not in tables:
        op.create_table(
            'repository_scorecards',
            sa.Column('repository', sa.String(length=255), primary_key=True),
            sa.Column('status', sa.String(length=16), nullable=False),
            sa.Column('published_repository', sa.String(length=255), nullable=True),
            sa.Column('score', sa.Float(), nullable=True),
            sa.Column('checks', sa.JSON(), nullable=True),
            sa.Column('scorecard_date', sa.String(length=32), nullable=True),
            sa.Column('commit', sa.String(length=64), nullable=True),
            sa.Column('fetched_at', sa.DateTime(), nullable=False),
        )


def downgrade():
    op.drop_table('repository_scorecards')
    op.drop_table('package_repositories')
    with op.batch_alter_table('sbom_packages') as batch_op:
        batch_op.drop_column('upstream_urls')
