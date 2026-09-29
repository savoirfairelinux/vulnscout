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


def _bind_alembic_op(connection):
    migration.op = Operations(MigrationContext.configure(connection))


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
