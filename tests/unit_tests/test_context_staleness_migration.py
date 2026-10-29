# -*- coding: utf-8 -*-
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import importlib
import json
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


def test_editor_fields_upgrade_outdates_only_contexts_that_lose_text():
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _create_editor_pre_upgrade_schema(connection)
        connection.exec_driver_sql("UPDATE variant_context SET threat_model = 'Old model' WHERE id = 'A'")
        connection.exec_driver_sql("UPDATE variant_context SET risks = '  ' WHERE id = 'B'")
        editor_fields.op = Operations(MigrationContext.configure(connection))

        editor_fields.upgrade()

        stamps = dict(connection.exec_driver_sql("SELECT id, updated_at FROM variant_context").all())

    assert stamps["A"] != "2026-01-01T00:00:00Z"
    assert {stamps[k] for k in "BCD"} == {"2026-01-01T00:00:00Z"}


def test_editor_fields_downgrade_restores_rendered_text():
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _create_editor_pre_upgrade_schema(connection)
        editor_fields.op = Operations(MigrationContext.configure(connection))
        editor_fields.upgrade()
        model = {
            "components": [{"id": "C1", "name": "API", "description": "", "trust_zone": ""}],
            "interactions": [],
            "threats": [{"id": "T1", "category": "spoofing", "description": "Fake caller", "target_ids": ["C1"]}],
            "risks": [{"threat_id": "T1", "likelihood": "high", "impact": "low", "mitigation": "", "residual": ""}],
        }
        connection.execute(
            sa.text("UPDATE variant_context SET system_scope = 'Scope text', stride_model = :m WHERE id = 'A'"),
            {"m": json.dumps(model)},
        )

        editor_fields.downgrade()

        rows = {r["id"]: r for r in connection.exec_driver_sql(
            "SELECT id, threat_model, risks FROM variant_context").mappings().all()}

    assert "Scope text" in rows["A"]["threat_model"] and "T1 [C1 API]: Fake caller" in rows["A"]["threat_model"]
    assert "T1 Spoofing, Fake caller" in rows["A"]["risks"]
    assert rows["B"]["threat_model"] is None and rows["B"]["risks"] is None
