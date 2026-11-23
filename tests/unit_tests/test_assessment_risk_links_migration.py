import importlib

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations


def test_migrating_existing_targets_leaves_links_unset(monkeypatch):
    migration = importlib.import_module("src.migrations.versions.e42bb263ae51_target_risk_links")
    with sa.create_engine("sqlite://").begin() as conn:
        conn.exec_driver_sql("CREATE TABLE assessment_targets (id INTEGER PRIMARY KEY)")
        conn.exec_driver_sql("INSERT INTO assessment_targets VALUES (1)")
        monkeypatch.setattr(migration, "op", Operations(MigrationContext.configure(conn)))
        migration.upgrade()
        migration.upgrade()  # The application may already have created the current schema.
        assert conn.exec_driver_sql("SELECT id, risk_links FROM assessment_targets").one() == (1, None)
        migration.downgrade()
        assert conn.exec_driver_sql("SELECT * FROM assessment_targets").one() == (1,)
