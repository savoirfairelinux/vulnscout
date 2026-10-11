# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Store identifier and Git source evidence on SBOM-package associations."""

import uuid

from alembic import op
import sqlalchemy as sa


revision = 'c83e91ab402d'
down_revision = 'cc5359c88dd2'
branch_labels = None
depends_on = None


def upgrade():
    # Global aggregates have no reliable document of origin; populate links by reimport.
    with op.batch_alter_table('sbom_packages', schema=None) as batch_op:
        batch_op.add_column(sa.Column('source_urls', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('cpe', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('purl', sa.JSON(), nullable=True))
    # Retain the final PR schema for databases that already applied its earlier migrations.
    with op.batch_alter_table('packages', schema=None) as batch_op:
        batch_op.add_column(sa.Column('legacy_source_urls', sa.JSON(), nullable=True))


def downgrade():
    packages = sa.table('packages', sa.column('id', sa.Uuid()),
                        sa.column('cpe', sa.JSON()), sa.column('purl', sa.JSON()),
                        sa.column('legacy_source_urls', sa.JSON()))
    links = sa.table('sbom_packages', sa.column('package_id', sa.Uuid()),
                     sa.column('cpe', sa.JSON()), sa.column('purl', sa.JSON()),
                     sa.column('source_urls', sa.JSON()))
    connection = op.get_bind()
    if (any(connection.execute(sa.select(links.c.source_urls)).scalars())
            or any(connection.execute(sa.select(packages.c.legacy_source_urls)).scalars())):
        raise RuntimeError(
            "Cannot downgrade SBOM evidence while Git source URLs exist: "
            "the previous schema cannot retain them. Back up the evidence before downgrading."
        )
    identifiers: dict[uuid.UUID, tuple[set[str], set[str]]] = {}
    for package_id, old_cpe, old_purl, cpe, purl in connection.execute(
        sa.select(packages.c.id, packages.c.cpe, packages.c.purl, links.c.cpe, links.c.purl)
        .join(links, links.c.package_id == packages.c.id)
    ):
        if cpe or purl:
            cpes, purls = identifiers.setdefault(package_id, (set(old_cpe or []), set(old_purl or [])))
            cpes.update(cpe or [])
            purls.update(purl or [])
    for package_id, (cpes, purls) in identifiers.items():
        connection.execute(packages.update().where(packages.c.id == package_id)
                           .values(cpe=sorted(cpes), purl=sorted(purls)))
    with op.batch_alter_table('sbom_packages', schema=None) as batch_op:
        batch_op.drop_column('purl')
        batch_op.drop_column('cpe')
        batch_op.drop_column('source_urls')
    with op.batch_alter_table('packages', schema=None) as batch_op:
        batch_op.drop_column('legacy_source_urls')
