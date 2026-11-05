# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Coverage normalization preserves retained artifacts and can be reversed."""

import importlib
import os
import uuid

from alembic.migration import MigrationContext
from alembic.operations import Operations
import sqlalchemy as sa


def test_refresh_target_migration_round_trip(tmp_path):
    engine = sa.create_engine(os.getenv(
        "VULNSCOUT_TEST_POSTGRES_URI", f"sqlite:///{tmp_path / 'migration.db'}",
    ))
    if engine.dialect.name == "sqlite":
        @sa.event.listens_for(engine, "connect")
        def enable_foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")
    schema = "migration_" + uuid.uuid4().hex
    coverage = [{"source": "epss", "vuln_id": "CVE-2024-1111", "status": "complete",
                 "error": None, "packages": [{"project_id": "project-one", "variant_id": "variant-one"}]}]
    migration = importlib.import_module("src.migrations.versions.bd864102fe73_normalize_refresh_targets")
    try:
        with engine.begin() as connection:
            if engine.dialect.name == "postgresql":
                connection.execute(sa.text(f'CREATE SCHEMA "{schema}"'))
                connection.execute(sa.text(f'SET search_path TO "{schema}"'))
            metadata = sa.MetaData()
            runs = sa.Table("refresh_runs", metadata,
                            sa.Column("run_id", sa.String(128), primary_key=True),
                            sa.Column("coverage", sa.JSON(), nullable=False))
            changes = sa.Table("refresh_changes", metadata,
                               sa.Column("id", sa.Integer(), primary_key=True),
                               sa.Column("run_id", sa.String(128),
                                         sa.ForeignKey("refresh_runs.run_id", ondelete="CASCADE")),
                               sa.Column("snapshot", sa.JSON()))
            metadata.create_all(connection)
            connection.execute(runs.insert(), [{"run_id": "retained", "coverage": coverage}])
            connection.execute(changes.insert(), [{"id": 1, "run_id": "retained", "snapshot": {"after": 0.8}}])
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade()
                targets = sa.Table("refresh_targets", sa.MetaData(), autoload_with=connection)
                row = connection.execute(sa.select(targets)).one()
                assert row.run_id == "retained" and row.packages == coverage[0]["packages"]
                assert connection.execute(sa.select(changes.c.snapshot)).scalar_one() == {"after": 0.8}
                migration.downgrade()
                assert connection.execute(sa.select(runs.c.coverage)).scalar_one() == coverage
            if engine.dialect.name == "postgresql":
                connection.execute(sa.text("SET search_path TO public"))
                connection.execute(sa.text(f'DROP SCHEMA "{schema}" CASCADE'))
    finally:
        engine.dispose()
