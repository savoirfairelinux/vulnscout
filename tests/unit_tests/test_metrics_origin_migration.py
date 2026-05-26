# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import importlib

import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext


def test_metrics_origin_migration_backfills_using_vulnscout_only_custom_policy():
    migration = importlib.import_module(
        "src.migrations.versions.k7f8a9b0c1d2_add_origin_to_metrics"
    )

    engine = sa.create_engine("sqlite:///:memory:")

    with engine.begin() as connection:
        connection.execute(sa.text(
            """
            CREATE TABLE metrics (
                id TEXT PRIMARY KEY,
                vulnerability_id VARCHAR(50) NOT NULL,
                version VARCHAR,
                score NUMERIC,
                vector TEXT,
                author VARCHAR
            )
            """
        ))
        connection.execute(sa.text(
            """
            INSERT INTO metrics (id, vulnerability_id, version, score, vector, author)
            VALUES
                ('1', 'CVE-2020-0001', '3.1', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', '123e4567-e89b-12d3-a456-426614174000'),
                ('2', 'CVE-2020-0002', '3.1', 9.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'nvd'),
                ('3', 'CVE-2020-0003', '3.1', 6.8, 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 'secalert@redhat.com'),
                ('4', 'CVE-2020-0004', '3.1', 5.5, 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N', 'custom-tool'),
                ('5', 'CVE-2020-0005', '3.1', 5.2, 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N', 'vulnscout')
            """
        ))

        migration.op = Operations(MigrationContext.configure(connection))
        migration.upgrade()

        rows = connection.execute(sa.text(
            "SELECT vulnerability_id, author, origin FROM metrics ORDER BY vulnerability_id"
        )).all()

    assert rows == [
        ('CVE-2020-0001', 'vulnscout', 'custom'),
        ('CVE-2020-0002', 'nvd', 'scanner'),
        ('CVE-2020-0003', 'secalert@redhat.com', 'scanner'),
        ('CVE-2020-0004', 'custom-tool', 'scanner'),
        ('CVE-2020-0005', 'vulnscout', 'custom'),
    ]