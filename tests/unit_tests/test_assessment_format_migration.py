# -*- coding: utf-8 -*-
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import importlib

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

migration = importlib.import_module(
    "src.migrations.versions.b5d7e9f1a3c6_add_assessment_format_to_project_context")
review_migration = importlib.import_module("src.migrations.versions.d932cf94a5ed_add_review_format")


def _columns(connection) -> set:
    return {column["name"] for column in sa.inspect(connection).get_columns("project_context")}


def test_adds_a_nullable_format_and_round_trips():
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE project_context (id VARCHAR PRIMARY KEY, project_id VARCHAR, description TEXT)")
        connection.exec_driver_sql("INSERT INTO project_context VALUES ('1', 'p', 'kept')")
        migration.op = Operations(MigrationContext.configure(connection))
        migration.upgrade()
        migration.upgrade()
        assert "assessment_format" in _columns(connection)
        assert connection.exec_driver_sql(
            "SELECT description, assessment_format FROM project_context").all() == [("kept", None)]
        connection.exec_driver_sql("""UPDATE project_context SET assessment_format = '{"sections":[]}'""")
        review_migration.op = migration.op
        review_migration.upgrade()
        review_migration.upgrade()
        assert connection.exec_driver_sql("SELECT assessment_format, review_format FROM project_context").all() == [
            ('{"sections":[]}', None)]
        review_migration.downgrade()
        assert "review_format" not in _columns(connection)
        assert "assessment_format" in _columns(connection)
        migration.downgrade()
        assert "assessment_format" not in _columns(connection)
        assert connection.exec_driver_sql("SELECT description FROM project_context").all() == [("kept",)]
