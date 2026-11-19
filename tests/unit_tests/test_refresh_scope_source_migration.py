# -*- coding: utf-8 -*-
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import importlib
import json

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

migration = importlib.import_module("src.migrations.versions.e7a4c91b2d35_add_source_to_refresh_run_scopes")


def test_backfill_reads_only_mixed_batches_in_bounded_pages(monkeypatch):
    monkeypatch.setattr(migration, "BATCH", 2)
    engine = sa.create_engine("sqlite:///:memory:")
    mixed = {"source_scopes": {"nvd": {"project_id": "a", "variant_id": None},
                               "epss": {"project_id": "b", "variant_id": None, "variants": [
                                   {"project_id": "b", "variant_id": "v"}]}}}
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE refresh_runs (run_id VARCHAR PRIMARY KEY, scope JSON)")
        connection.exec_driver_sql(
            "CREATE TABLE refresh_run_scopes (id INTEGER PRIMARY KEY, run_id VARCHAR, "
            "project_id VARCHAR, variant_id VARCHAR)")
        for index in range(5):
            connection.exec_driver_sql("INSERT INTO refresh_runs VALUES (?, ?)", (f"m{index}", json.dumps(mixed)))
        connection.exec_driver_sql("INSERT INTO refresh_runs VALUES ('plain', ?)", (json.dumps({"project_id": "a"}),))
        connection.exec_driver_sql("INSERT INTO refresh_run_scopes (run_id, project_id) VALUES ('plain', 'a')")
        migration.op = Operations(MigrationContext.configure(connection))
        migration.upgrade()
        rows = connection.exec_driver_sql(
            "SELECT run_id, project_id, variant_id, source FROM refresh_run_scopes ORDER BY run_id, source, variant_id"
        ).all()
    assert [row for row in rows if row[0] == "plain"] == [("plain", "a", None, None)]
    assert sorted((row[1:] for row in rows if row[0] == "m4"), key=str) == sorted([
        ("a", None, "nvd"), ("b", None, "epss"), ("b", "v", "epss")], key=str)
    assert len([row for row in rows if row[0].startswith("m")]) == 15
