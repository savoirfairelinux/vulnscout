# -*- coding: utf-8 -*-
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import importlib

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


def test_upgrade_adds_and_backfills_context_and_assessment_timestamps():
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _create_pre_upgrade_schema(connection)
        connection.exec_driver_sql(
            "INSERT INTO assessments (id, timestamp) "
            "VALUES ('a1', '2026-09-01 12:30:00')"
        )
        _bind_alembic_op(connection)

        migration.upgrade()

        assessment_columns = _column_names(connection, "assessments")
        variant_context_columns = _column_names(connection, "variant_context")
        row = connection.exec_driver_sql(
            "SELECT timestamp, created_at FROM assessments WHERE id = 'a1'"
        ).mappings().one()

    assert "created_at" in assessment_columns
    assert "updated_at" in variant_context_columns
    assert row["created_at"] == row["timestamp"]


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

    assert "created_at" not in assessment_columns
    assert "updated_at" not in variant_context_columns
