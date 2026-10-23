# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import importlib
import uuid

import pytest
import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext


migration = importlib.import_module(
    "src.migrations.versions.e9b72c4a1d60_track_provisional_scan_assessments"
)


@pytest.mark.parametrize("already_upgraded", [False, True])
def test_provisional_assessment_migration_preserves_history(already_upgraded):
    metadata = sa.MetaData()
    scans = sa.Table("scans", metadata, sa.Column("id", sa.Uuid(), primary_key=True))
    assessments = sa.Table("assessments", metadata, sa.Column("id", sa.Uuid(), primary_key=True))
    if already_upgraded:
        scans.append_column(sa.Column("in_progress", sa.Boolean(), nullable=False, server_default=sa.false()))
        assessments.append_column(sa.Column(
            "provisional_scan_id", sa.Uuid(),
            sa.ForeignKey("scans.id", name="fk_assessments_provisional_scan_id_scans", ondelete="SET NULL"),
            nullable=True, index=True,
        ))
    engine = sa.create_engine("sqlite:///:memory:")
    scan_id, assessment_id = uuid.uuid4(), uuid.uuid4()
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            metadata.create_all(connection)
            connection.execute(scans.insert().values(id=scan_id))
            connection.execute(assessments.insert().values(id=assessment_id))
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade()
                migration.upgrade()
                current = sa.MetaData()
                scans = sa.Table("scans", current, autoload_with=connection)
                assessments = sa.Table("assessments", current, autoload_with=connection)
                assert connection.scalar(sa.select(scans.c.in_progress)) is False
                assert connection.scalar(sa.select(assessments.c.provisional_scan_id)) is None

                connection.execute(scans.update().values(in_progress=True))
                connection.execute(assessments.update().values(provisional_scan_id=scan_id.hex))
                migration.upgrade()
                assert connection.scalar(sa.select(scans.c.in_progress)) is True
                assert connection.scalar(sa.select(assessments.c.provisional_scan_id)) == scan_id.hex
                assert sa.inspect(connection).get_foreign_keys("assessments")[0]["options"]["ondelete"] == "SET NULL"

                migration.downgrade()
                assert {column["name"] for column in sa.inspect(connection).get_columns("scans")} == {"id"}
                assert {column["name"] for column in sa.inspect(connection).get_columns("assessments")} == {"id"}
                assert connection.scalar(sa.select(scans.c.id)) == scan_id.hex
                assert connection.scalar(sa.select(assessments.c.id)) == assessment_id.hex

                migration.upgrade()
                connection.execute(assessments.update().values(provisional_scan_id=scan_id.hex))
                connection.execute(scans.delete())
                assert connection.scalar(sa.select(assessments.c.provisional_scan_id)) is None
    finally:
        engine.dispose()
