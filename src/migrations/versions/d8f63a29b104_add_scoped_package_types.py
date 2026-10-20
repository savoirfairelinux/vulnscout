# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Store canonical West package provenance and scoped component types."""

from collections import defaultdict
import uuid

from alembic import op
import sqlalchemy as sa
from sqlalchemy.orm import Session

revision = 'd8f63a29b104'
down_revision = 'c83e91ab402d'
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    if 'jsonld_groups' not in {column['name'] for column in sa.inspect(connection).get_columns('sbom_documents')}:
        with op.batch_alter_table('sbom_documents') as batch_op:
            batch_op.add_column(sa.Column('jsonld_groups', sa.JSON(), nullable=True))
    for table in ('packages', 'sbom_packages'):
        if 'source_revisions' not in {column['name'] for column in sa.inspect(connection).get_columns(table)}:
            with op.batch_alter_table(table) as batch_op:
                batch_op.add_column(sa.Column('source_revisions', sa.JSON(), nullable=True))
    if 'type' not in {column['name'] for column in sa.inspect(connection).get_columns('sbom_packages')}:
        with op.batch_alter_table('sbom_packages') as batch_op:
            batch_op.add_column(sa.Column('type', sa.String(9), nullable=False, server_default='normal'))
            batch_op.create_check_constraint(
                'ck_sbom_packages_type', "type IN ('normal', 'workspace', 'built')",
            )
    # Consolidation uses the complete association schema, including its scoped type.
    from src.helpers.jsonld_storage import consolidate_jsonld_packages

    with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
        consolidate_jsonld_packages(session)
        session.commit()

    documents = sa.table(
        'sbom_documents', sa.column('id', sa.Uuid()), sa.column('scan_id', sa.Uuid()),
        sa.column('jsonld_groups', sa.JSON()),
    )
    links = sa.table(
        'sbom_packages', sa.column('sbom_document_id', sa.Uuid()), sa.column('package_id', sa.Uuid()),
        sa.column('type', sa.String(9)),
    )
    documents_by_scan = defaultdict(list)
    classifications = {}
    for document in connection.execute(sa.select(documents)).mappings():
        if document['jsonld_groups'] is None:
            continue
        documents_by_scan[document['scan_id']].append(document['id'])
        for group in document['jsonld_groups']:
            parent = group.get('canonical_package_id')
            if parent is None:
                continue
            key = document['scan_id'], uuid.UUID(parent)
            package_type = 'built' if group['built'] else 'workspace'
            if classifications.get(key) != 'built':
                classifications[key] = package_type
    for (scan_id, package_id), package_type in classifications.items():
        connection.execute(sa.update(links).where(
            links.c.sbom_document_id.in_(documents_by_scan[scan_id]),
            links.c.package_id == package_id,
        ).values(type=package_type))


def downgrade():
    with op.batch_alter_table('sbom_packages') as batch_op:
        batch_op.drop_constraint('ck_sbom_packages_type', type_='check')
        batch_op.drop_column('type')
        batch_op.drop_column('source_revisions')
    # Canonical package identities and their assessments intentionally remain.
    with op.batch_alter_table('packages') as batch_op:
        batch_op.drop_column('source_revisions')
    with op.batch_alter_table('sbom_documents') as batch_op:
        batch_op.drop_column('jsonld_groups')
