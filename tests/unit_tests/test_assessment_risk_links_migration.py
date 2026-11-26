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


def test_drop_legacy_risk_links_preserves_notes_targets_and_model(monkeypatch):
    migration = importlib.import_module("src.migrations.versions.ef51e895ca7b_remove_target_risk_links")
    with sa.create_engine("sqlite://").begin() as conn:
        conn.exec_driver_sql("PRAGMA foreign_keys = ON")
        metadata = sa.MetaData()
        assessments = sa.Table(
            "assessments", metadata, sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("origin", sa.Text), sa.Column("status_notes", sa.Text), sa.Column("impact_statement", sa.Text),
        )
        variants = sa.Table("variants", metadata, sa.Column("id", sa.Integer, primary_key=True))
        findings = sa.Table("findings", metadata, sa.Column("id", sa.Integer, primary_key=True))
        context = sa.Table(
            "variant_context", metadata, sa.Column("variant_id", sa.ForeignKey("variants.id"), primary_key=True),
            sa.Column("stride_model", sa.JSON),
        )
        targets = sa.Table(
            "assessment_targets", metadata,
            sa.Column("assessment_id", sa.ForeignKey("assessments.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("variant_id", sa.ForeignKey("variants.id"), primary_key=True, index=True),
            sa.Column("finding_id", sa.ForeignKey("findings.id"), primary_key=True, index=True),
            sa.Column("risk_links", sa.JSON),
        )
        metadata.create_all(conn)
        model = {"risks": [{"id": "R1", "threat_ids": ["T1"]}], "threats": [{"id": "T1"}]}
        conn.execute(assessments.insert(), [
            {"id": 1, "origin": "ai", "status_notes": "Authored comment for v2 / pkg: R1 and T1.",
             "impact_statement": "Existing impact"},
            {"id": 2, "origin": "custom", "status_notes": "Reviewer-authored notes", "impact_statement": None},
        ])
        conn.execute(variants.insert(), [{"id": 1}, {"id": 2}])
        conn.execute(findings.insert(), [{"id": 1}, {"id": 2}])
        conn.execute(context.insert(), {"variant_id": 2, "stride_model": model})
        snapshot = [{"risk_id": "R2", "risk_description": "Legacy structured metadata"}]
        conn.execute(targets.insert(), [
            {"assessment_id": 1, "variant_id": 1, "finding_id": 1, "risk_links": None},
            {"assessment_id": 1, "variant_id": 2, "finding_id": 2, "risk_links": snapshot},
            {"assessment_id": 2, "variant_id": 2, "finding_id": 2, "risk_links": snapshot},
        ])
        before = conn.execute(assessments.select().order_by(assessments.c.id)).all()

        monkeypatch.setattr(migration, "op", Operations(MigrationContext.configure(conn)))
        migration.upgrade()

        pair_rows = [(1, 1, 1), (1, 2, 2), (2, 2, 2)]
        assert conn.exec_driver_sql("SELECT * FROM assessment_targets ORDER BY assessment_id, variant_id").all() == (
            pair_rows
        )
        assert conn.execute(assessments.select().order_by(assessments.c.id)).all() == before
        assert conn.execute(sa.select(context.c.stride_model)).scalar_one() == model
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert {i["name"] for i in sa.inspect(conn).get_indexes("assessment_targets")} == {
            "ix_assessment_targets_variant_id", "ix_assessment_targets_finding_id",
        }

        migration.downgrade()
        assert conn.exec_driver_sql("SELECT * FROM assessment_targets ORDER BY assessment_id, variant_id").all() == [
            (*pair, None) for pair in pair_rows
        ]
