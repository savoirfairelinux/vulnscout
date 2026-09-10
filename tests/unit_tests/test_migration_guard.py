# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
import sqlalchemy as sa

from src.helpers.schema_guard import assert_schema_is_current


@pytest.fixture
def stale_connection():
    """A connection whose ``assessments`` table still has the scalar columns."""
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(sa.text(
            """
            CREATE TABLE assessments (
                id TEXT PRIMARY KEY,
                variant_id TEXT,
                finding_id TEXT
            )
            """
        ))
        yield connection


def test_upgrade_guard_rejects_a_stale_schema(stale_connection):
    """A database that applied x0a1b2c3d4e5 in its PR-A form must not run on.

    Alembic records the revision as applied, so the rewritten version is
    skipped silently.  The guard turns that into a loud failure.
    """
    with pytest.raises(RuntimeError, match="delete your development database"):
        assert_schema_is_current(stale_connection)
