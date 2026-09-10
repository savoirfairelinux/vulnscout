# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Detects a database left behind by an amended migration revision."""

import sqlalchemy as sa

STALE_SCHEMA_MESSAGE = (
    "assessments still has variant_id/finding_id: this database applied an"
    " earlier form of revision x0a1b2c3d4e5, so the rewritten version was"
    " skipped.  Please delete your development database and start again."
)


def assert_schema_is_current(connection) -> None:
    """Fail loudly when a stale database skipped the rewritten revision.

    Revision ``x0a1b2c3d4e5`` was amended in place while #538 was being split.
    A database that applied its earlier form has the revision recorded as done,
    so alembic skips the rewrite and leaves ``assessments`` half-migrated with
    no error at all.  This turns a silent wrong schema into a startup failure.
    """
    columns = {
        column["name"]
        for column in sa.inspect(connection).get_columns("assessments")
    }
    if "variant_id" in columns or "finding_id" in columns:
        raise RuntimeError(STALE_SCHEMA_MESSAGE)
