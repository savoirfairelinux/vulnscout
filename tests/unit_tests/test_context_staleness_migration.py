# -*- coding: utf-8 -*-
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import importlib
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations


migration = importlib.import_module(
    "src.migrations.versions.z2c3d4e5f6a7_add_variant_context_updated_at"
)
repair = importlib.import_module(
    "src.migrations.versions.4e6c9a71b35f_repair_assessment_context_timestamps"
)


def _bind_alembic_op(connection):
    migration.op = Operations(MigrationContext.configure(connection))
    repair.op = Operations(MigrationContext.configure(connection))


def _column_names(connection, table):
    return {
        column["name"] for column in sa.inspect(connection).get_columns(table)
    }


def _create_pre_upgrade_schema(connection):
    connection.exec_driver_sql(
        "CREATE TABLE assessments ("
        "id VARCHAR PRIMARY KEY, timestamp DATETIME NOT NULL)"
    )
    connection.exec_driver_sql(
        "CREATE TABLE variant_context (id VARCHAR PRIMARY KEY)"
    )
    connection.exec_driver_sql(
        "CREATE TABLE project_context (id VARCHAR PRIMARY KEY)"
    )


def test_upgrade_adds_and_backfills_context_and_assessment_timestamps():
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _create_pre_upgrade_schema(connection)
        connection.exec_driver_sql(
            "INSERT INTO assessments (id, timestamp) "
            "VALUES ('a1', '2026-09-01 12:30:00')"
        )
        _bind_alembic_op(connection)

        before = datetime.now(timezone.utc) - timedelta(seconds=1)
        migration.upgrade()
        after = datetime.now(timezone.utc) + timedelta(seconds=1)

        assessment_columns = _column_names(connection, "assessments")
        variant_context_columns = _column_names(connection, "variant_context")
        project_context_columns = _column_names(connection, "project_context")
        row = connection.exec_driver_sql(
            "SELECT timestamp, created_at FROM assessments WHERE id = 'a1'"
        ).mappings().one()

    created_at = datetime.fromisoformat(row["created_at"]).replace(tzinfo=timezone.utc)

    assert "created_at" in assessment_columns
    assert "updated_at" in variant_context_columns
    assert "updated_at" in project_context_columns
    assert before <= created_at <= after
    assert row["created_at"] != row["timestamp"]


def test_upgrade_ignores_a_future_assessment_timestamp_when_backfilling_created_at():
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _create_pre_upgrade_schema(connection)
        connection.exec_driver_sql(
            "INSERT INTO assessments (id, timestamp) "
            "VALUES ('a1', '2099-01-01 00:00:00')"
        )
        _bind_alembic_op(connection)

        before = datetime.now(timezone.utc) - timedelta(seconds=1)
        migration.upgrade()
        after = datetime.now(timezone.utc) + timedelta(seconds=1)

        row = connection.exec_driver_sql(
            "SELECT timestamp, created_at FROM assessments WHERE id = 'a1'"
        ).mappings().one()

    created_at = datetime.fromisoformat(row["created_at"]).replace(tzinfo=timezone.utc)

    assert before <= created_at <= after
    assert row["created_at"] != row["timestamp"]


def test_downgrade_removes_context_and_assessment_timestamps():
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _create_pre_upgrade_schema(connection)
        connection.exec_driver_sql(
            "INSERT INTO assessments (id, timestamp) "
            "VALUES ('a1', '2026-09-01 12:30:00')"
        )
        _bind_alembic_op(connection)

        migration.upgrade()
        migration.downgrade()

        assessment_columns = _column_names(connection, "assessments")
        variant_context_columns = _column_names(connection, "variant_context")
        project_context_columns = _column_names(connection, "project_context")

    assert "created_at" not in assessment_columns
    assert "updated_at" not in variant_context_columns
    assert "updated_at" not in project_context_columns


def test_repair_fills_missing_columns_on_a_stamped_database():
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _create_pre_upgrade_schema(connection)
        connection.exec_driver_sql(
            "INSERT INTO assessments (id, timestamp) VALUES ('a1', '2099-01-01 00:00:00')"
        )
        _bind_alembic_op(connection)

        before = datetime.now(timezone.utc) - timedelta(seconds=1)
        repair.upgrade()
        after = datetime.now(timezone.utc) + timedelta(seconds=1)
        repair.upgrade()

        row = connection.exec_driver_sql(
            "SELECT timestamp, created_at FROM assessments WHERE id = 'a1'"
        ).mappings().one()
        assert 'updated_at' in _column_names(connection, 'variant_context')
        assert 'updated_at' in _column_names(connection, 'project_context')
        assert 'created_at' in _column_names(connection, 'assessments')

    created_at = datetime.fromisoformat(row['created_at']).replace(tzinfo=timezone.utc)
    assert before <= created_at <= after
    assert row['created_at'] != row['timestamp']


def test_repair_preserves_an_already_upgraded_database():
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _create_pre_upgrade_schema(connection)
        _bind_alembic_op(connection)
        migration.upgrade()
        repair.upgrade()
        assert 'created_at' in _column_names(connection, 'assessments')


editor_fields = importlib.import_module(
    "src.migrations.versions.a3d5e7f9b1c2_add_variant_context_editor_fields"
)

EDITOR_COLUMNS = {
    "codebase_source", "system_scope", "system_actors",
    "system_entry_points", "system_trust_boundaries", "stride_model",
}


def _create_editor_pre_upgrade_schema(connection):
    connection.exec_driver_sql(
        "CREATE TABLE variant_context ("
        "id VARCHAR PRIMARY KEY, variant_id VARCHAR, codebase_path TEXT, "
        "threat_model TEXT, risks TEXT, updated_at DATETIME)"
    )
    connection.exec_driver_sql(
        "CREATE TABLE context_files (id VARCHAR PRIMARY KEY, variant_context_id VARCHAR)"
    )
    rows = [("A", "src;lib"), ("B", None), ("C", "src"), ("D", None)]
    for ctx_id, path in rows:
        connection.exec_driver_sql(
            "INSERT INTO variant_context (id, variant_id, codebase_path, updated_at) "
            "VALUES (?, ?, ?, '2026-01-01T00:00:00Z')",
            (ctx_id, f"v{ctx_id}", path),
        )
    for ctx_id in ("A", "B"):
        connection.exec_driver_sql(
            "INSERT INTO context_files (id, variant_context_id) VALUES (?, ?)",
            (f"f{ctx_id}", ctx_id),
        )


def test_editor_fields_migration_defaults():
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _create_editor_pre_upgrade_schema(connection)
        editor_fields.op = Operations(MigrationContext.configure(connection))

        editor_fields.upgrade()

        rows = connection.exec_driver_sql(
            "SELECT id, codebase_source, updated_at, stride_model, "
            "system_scope, system_actors, system_entry_points, system_trust_boundaries "
            "FROM variant_context"
        ).mappings().all()
        columns = _column_names(connection, "variant_context")

    assert not {"threat_model", "risks", "editor_mode"} & columns
    by_id = {r["id"]: r for r in rows}
    assert {k: v["codebase_source"] for k, v in by_id.items()} == {
        "A": "references", "B": "references", "C": "paths", "D": "paths",
    }
    for row in rows:
        assert row["updated_at"] == "2026-01-01T00:00:00Z"
        assert row["stride_model"] is None
        assert row["system_scope"] is None
        assert row["system_actors"] is None
        assert row["system_entry_points"] is None
        assert row["system_trust_boundaries"] is None


def test_editor_fields_downgrade_drops_columns():
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _create_editor_pre_upgrade_schema(connection)
        editor_fields.op = Operations(MigrationContext.configure(connection))

        editor_fields.upgrade()
        assert EDITOR_COLUMNS <= _column_names(connection, "variant_context")
        editor_fields.downgrade()

        columns = _column_names(connection, "variant_context")

    assert not (EDITOR_COLUMNS & columns)
    assert {"threat_model", "risks"} <= columns
