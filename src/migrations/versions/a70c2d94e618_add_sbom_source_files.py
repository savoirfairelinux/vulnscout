# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Retain document-scoped files and proven source/build associations."""

from alembic import op
import sqlalchemy as sa

revision = 'a70c2d94e618'
down_revision = 'a3d5e7f9b1c2'
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    if 'compiled_sources_complete' not in {
        column['name'] for column in sa.inspect(connection).get_columns('sbom_packages')
    }:
        with op.batch_alter_table('sbom_packages') as batch:
            batch.add_column(sa.Column('compiled_sources_complete', sa.Boolean(), nullable=True))
    if not sa.inspect(connection).has_table('sbom_files'):
        op.create_table(
            'sbom_files',
            sa.Column('sbom_document_id', sa.Uuid(), sa.ForeignKey('sbom_documents.id'), primary_key=True),
            sa.Column('spdx_id', sa.Text(), primary_key=True),
            sa.Column('path', sa.Text(), nullable=False),
            sa.Column('properties', sa.JSON(), nullable=False),
        )
    if not sa.inspect(connection).has_table('package_source_files'):
        op.create_table(
            'package_source_files',
            sa.Column('sbom_document_id', sa.Uuid(), primary_key=True),
            sa.Column('package_id', sa.Uuid(), primary_key=True),
            sa.Column('file_document_id', sa.Uuid(), primary_key=True),
            sa.Column('spdx_id', sa.Text(), primary_key=True),
            sa.ForeignKeyConstraint(
                ['sbom_document_id', 'package_id'], ['sbom_packages.sbom_document_id', 'sbom_packages.package_id'],
                ondelete='CASCADE',
            ),
            sa.ForeignKeyConstraint(
                ['file_document_id', 'spdx_id'], ['sbom_files.sbom_document_id', 'sbom_files.spdx_id'],
                ondelete='CASCADE',
            ),
        )
    if 'ix_package_source_files_file' not in {
        index['name'] for index in sa.inspect(connection).get_indexes('package_source_files')
    }:
        op.create_index('ix_package_source_files_file', 'package_source_files', ['file_document_id', 'spdx_id'])
    if not sa.inspect(connection).has_table('sbom_builds'):
        op.create_table(
            'sbom_builds',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('sbom_document_id', sa.Uuid(), sa.ForeignKey('sbom_documents.id'), nullable=False),
            sa.Column('spdx_id', sa.Text(), nullable=False),
            sa.Column('build_type', sa.Text(), nullable=True),
            sa.Column('parameters', sa.JSON(), nullable=False),
            sa.Column('outputs', sa.JSON(), nullable=False),
            sa.Column('compiled', sa.Boolean(), nullable=False),
            sa.UniqueConstraint('sbom_document_id', 'spdx_id'),
        )
    if not sa.inspect(connection).has_table('sbom_file_builds'):
        op.create_table(
            'sbom_file_builds',
            sa.Column('file_document_id', sa.Uuid(), primary_key=True),
            sa.Column('spdx_id', sa.Text(), primary_key=True),
            sa.Column('build_id', sa.Integer(), sa.ForeignKey('sbom_builds.id', ondelete='CASCADE'), primary_key=True),
            sa.ForeignKeyConstraint(
                ['file_document_id', 'spdx_id'], ['sbom_files.sbom_document_id', 'sbom_files.spdx_id'],
                ondelete='CASCADE',
            ),
        )
    if 'ix_sbom_file_builds_build' not in {
        index['name'] for index in sa.inspect(connection).get_indexes('sbom_file_builds')
    }:
        op.create_index('ix_sbom_file_builds_build', 'sbom_file_builds', ['build_id'])


def downgrade():
    op.drop_table('package_source_files')
    op.drop_table('sbom_file_builds')
    op.drop_table('sbom_builds')
    op.drop_table('sbom_files')
    with op.batch_alter_table('sbom_packages') as batch:
        batch.drop_column('compiled_sources_complete')
