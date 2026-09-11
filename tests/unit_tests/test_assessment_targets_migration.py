# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import importlib
import json
import uuid

import pytest
import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext

migration = importlib.import_module(
    "src.migrations.versions.x0a1b2c3d4e5_add_assessment_targets"
)

SHARED_TIMESTAMP = "2026-01-01 00:00:00"


def _new_id() -> str:
    return uuid.uuid4().hex


def _build_schema(connection):
    connection.execute(sa.text(
        "CREATE TABLE variants (id TEXT PRIMARY KEY, project_id TEXT)"
    ))
    connection.execute(sa.text(
        "CREATE TABLE findings (id TEXT PRIMARY KEY, vulnerability_id VARCHAR(50))"
    ))
    connection.execute(sa.text(
        """
        CREATE TABLE assessments (
            id TEXT PRIMARY KEY,
            origin VARCHAR,
            status VARCHAR,
            simplified_status VARCHAR,
            status_notes TEXT,
            justification TEXT,
            impact_statement TEXT,
            workaround TEXT,
            timestamp TEXT,
            finding_id TEXT,
            variant_id TEXT,
            responses TEXT
        )
        """
    ))
    connection.execute(sa.text(
        """
        CREATE TABLE assessment_targets (
            assessment_id TEXT NOT NULL,
            variant_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            PRIMARY KEY (assessment_id, variant_id, finding_id)
        )
        """
    ))


def _add_variant(connection, project_id: str) -> str:
    variant_id = _new_id()
    connection.execute(
        sa.text("INSERT INTO variants (id, project_id) VALUES (:id, :project_id)"),
        {"id": variant_id, "project_id": project_id},
    )
    return variant_id


def _add_finding(connection, vuln_id: str) -> str:
    finding_id = _new_id()
    connection.execute(
        sa.text(
            "INSERT INTO findings (id, vulnerability_id) VALUES (:id, :vuln_id)"
        ),
        {"id": finding_id, "vuln_id": vuln_id},
    )
    return finding_id


def _add_assessment(
    connection,
    finding_id: str,
    variant_id: str | None,
    *,
    status: str = "not_affected",
    timestamp: str = SHARED_TIMESTAMP,
    responses: "list[str] | None" = None,
) -> str:
    assessment_id = _new_id()
    connection.execute(
        sa.text(
            """
            INSERT INTO assessments (
                id, origin, status, simplified_status, status_notes,
                justification, impact_statement, workaround, timestamp,
                finding_id, variant_id, responses
            ) VALUES (
                :id, 'import', :status, 'fixed', 'notes',
                'code_not_reachable', 'no impact', 'none', :timestamp,
                :finding_id, :variant_id, :responses
            )
            """
        ),
        {
            "id": assessment_id,
            "status": status,
            "timestamp": timestamp,
            "finding_id": finding_id,
            "variant_id": variant_id,
            "responses": json.dumps(responses) if responses is not None else None,
        },
    )
    return assessment_id


def _existing_assessments(connection) -> set[str]:
    return {
        row["id"]
        for row in connection.execute(sa.text(
            "SELECT id FROM assessments"
        )).mappings()
    }


def _target_counts(connection) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in connection.execute(sa.text(
        "SELECT assessment_id FROM assessment_targets"
    )).mappings():
        counts[row["assessment_id"]] = counts.get(row["assessment_id"], 0) + 1
    return counts


def _run_backfill(connection):
    migration.backfill_targets(connection)
    migration.fuse_duplicates(connection)


def test_backfill_never_groups_assessments_across_projects():
    """Identical assessments in two projects must not fuse into one row.

    Reads are project-filtered, so a fused row spanning two projects would let
    one project delete or reconcile the other project's assessment.
    """
    engine = sa.create_engine("sqlite:///:memory:")

    with engine.begin() as connection:
        _build_schema(connection)
        finding_id = _add_finding(connection, "CVE-2026-0001")
        project_a_variant = _add_variant(connection, _new_id())
        project_b_variant = _add_variant(connection, _new_id())
        first = _add_assessment(connection, finding_id, project_a_variant)
        second = _add_assessment(connection, finding_id, project_b_variant)

        _run_backfill(connection)

        remaining = _existing_assessments(connection)
        counts = _target_counts(connection)

    assert remaining == {first, second}
    assert counts.get(first) == 1
    assert counts.get(second) == 1


def test_backfill_still_groups_assessments_within_one_project():
    engine = sa.create_engine("sqlite:///:memory:")

    with engine.begin() as connection:
        _build_schema(connection)
        finding_id = _add_finding(connection, "CVE-2026-0002")
        project_id = _new_id()
        first = _add_assessment(
            connection, finding_id, _add_variant(connection, project_id))
        second = _add_assessment(
            connection, finding_id, _add_variant(connection, project_id))

        _run_backfill(connection)

        remaining = _existing_assessments(connection)
        counts = _target_counts(connection)

    assert len(remaining) == 1
    survivor = next(iter(remaining))
    assert survivor in {first, second}
    assert counts.get(survivor) == 2


def test_upgrade_aborts_on_an_assessment_with_no_variant():
    """A target is a ``(variant, finding)`` pair; a variant-less row has none.

    The old group backfill tolerated this by bucketing variant-less rows under
    a ``NULL`` project key, since a group only recorded membership. A target
    row cannot express "no variant", so this now has to abort instead of
    silently producing a row with no valid target.
    """
    engine = sa.create_engine("sqlite:///:memory:")

    with engine.begin() as connection:
        _build_schema(connection)
        finding_id = _add_finding(connection, "CVE-2026-0003")
        _add_assessment(connection, finding_id, None)

        with pytest.raises(RuntimeError, match="no valid target"):
            migration.backfill_targets(connection)


def test_backfill_stays_sparse_for_unique_assessments():
    engine = sa.create_engine("sqlite:///:memory:")

    with engine.begin() as connection:
        _build_schema(connection)
        finding_id = _add_finding(connection, "CVE-2026-0004")
        project_id = _new_id()
        first = _add_assessment(
            connection, finding_id, _add_variant(connection, project_id),
            status="affected")
        second = _add_assessment(
            connection, finding_id, _add_variant(connection, project_id),
            status="not_affected")

        _run_backfill(connection)

        remaining = _existing_assessments(connection)
        counts = _target_counts(connection)

    assert remaining == {first, second}
    assert counts.get(first) == 1
    assert counts.get(second) == 1


def test_backfill_never_groups_assessments_with_different_responses():
    """Otherwise-identical rows carrying different VEX responses stay apart.

    Fusing rows with different response sets would discard one set entirely,
    so they must remain separate assessments.
    """
    engine = sa.create_engine("sqlite:///:memory:")

    with engine.begin() as connection:
        _build_schema(connection)
        finding_id = _add_finding(connection, "CVE-2026-0005")
        project_id = _new_id()
        first = _add_assessment(
            connection, finding_id, _add_variant(connection, project_id),
            responses=["will_not_fix"])
        second = _add_assessment(
            connection, finding_id, _add_variant(connection, project_id),
            responses=["update"])

        _run_backfill(connection)

        remaining = _existing_assessments(connection)
        counts = _target_counts(connection)

    assert remaining == {first, second}
    assert counts.get(first) == 1
    assert counts.get(second) == 1


def test_backfill_groups_rows_whose_responses_only_differ_in_order():
    """Response order is not meaningful, so it must not split a real fusion."""
    engine = sa.create_engine("sqlite:///:memory:")

    with engine.begin() as connection:
        _build_schema(connection)
        finding_id = _add_finding(connection, "CVE-2026-0006")
        project_id = _new_id()
        first = _add_assessment(
            connection, finding_id, _add_variant(connection, project_id),
            responses=["update", "will_not_fix"])
        second = _add_assessment(
            connection, finding_id, _add_variant(connection, project_id),
            responses=["will_not_fix", "update"])

        _run_backfill(connection)

        remaining = _existing_assessments(connection)
        counts = _target_counts(connection)

    assert len(remaining) == 1
    survivor = next(iter(remaining))
    assert survivor in {first, second}
    assert counts.get(survivor) == 2


def test_backfill_treats_missing_and_empty_responses_as_equal():
    """A NULL column and an empty list both mean "no responses"."""
    engine = sa.create_engine("sqlite:///:memory:")

    with engine.begin() as connection:
        _build_schema(connection)
        finding_id = _add_finding(connection, "CVE-2026-0007")
        project_id = _new_id()
        first = _add_assessment(
            connection, finding_id, _add_variant(connection, project_id),
            responses=None)
        second = _add_assessment(
            connection, finding_id, _add_variant(connection, project_id),
            responses=[])

        _run_backfill(connection)

        remaining = _existing_assessments(connection)
        counts = _target_counts(connection)

    assert len(remaining) == 1
    survivor = next(iter(remaining))
    assert survivor in {first, second}
    assert counts.get(survivor) == 2


def test_upgrade_aborts_on_an_assessment_with_no_finding():
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        _build_schema(connection)
        connection.execute(sa.text(
            "INSERT INTO assessments (id, origin, status, timestamp,"
            " finding_id, variant_id) VALUES (:id, 'custom', 'affected',"
            " :ts, NULL, NULL)"
        ), {"id": _new_id(), "ts": SHARED_TIMESTAMP})

        with pytest.raises(RuntimeError, match="no valid target"):
            migration.backfill_targets(connection)


def test_responses_key_normalizes_equivalent_encodings():
    """Decoded (PostgreSQL) and text (SQLite) JSON must produce one key."""
    assert migration.responses_key(None) == migration.responses_key("[]")
    assert migration.responses_key(["update"]) == migration.responses_key('["update"]')


def test_responses_key_falls_back_to_the_raw_text_when_unparsable():
    """An unparsable value keeps rows apart instead of fusing them."""
    assert migration.responses_key("not json") == "not json"


def test_responses_key_handles_a_non_list_json_value():
    assert migration.responses_key('{"b": 1, "a": 2}') == '{"a": 2, "b": 1}'


def _build_pre_upgrade_schema(connection):
    """Create the schema as it stands just before this revision runs.

    ``_build_schema`` above pre-creates ``assessment_targets`` so the backfill
    helpers can be called on their own; ``upgrade()`` creates that table
    itself, and drops indexes the helper never creates, so it needs the real
    pre-revision shape.
    """
    connection.execute(sa.text(
        "CREATE TABLE variants (id TEXT PRIMARY KEY, project_id TEXT)"
    ))
    connection.execute(sa.text(
        "CREATE TABLE findings (id TEXT PRIMARY KEY, vulnerability_id VARCHAR(50))"
    ))
    connection.execute(sa.text(
        """
        CREATE TABLE assessments (
            id TEXT PRIMARY KEY,
            source VARCHAR,
            origin VARCHAR,
            status VARCHAR,
            simplified_status VARCHAR,
            status_notes TEXT,
            justification TEXT,
            impact_statement TEXT,
            workaround TEXT,
            timestamp TEXT,
            finding_id TEXT REFERENCES findings (id),
            variant_id TEXT REFERENCES variants (id),
            responses TEXT
        )
        """
    ))
    connection.execute(sa.text(
        "CREATE INDEX ix_assessments_finding_id ON assessments (finding_id)"
    ))
    connection.execute(sa.text(
        "CREATE INDEX ix_assessments_variant_id ON assessments (variant_id)"
    ))


def _bind_alembic_op(connection):
    migration.op = Operations(MigrationContext.configure(connection))


def _assessment_columns(connection) -> set[str]:
    return {
        row[1]
        for row in connection.execute(sa.text("PRAGMA table_info(assessments)"))
    }


def _targets(connection) -> set[tuple]:
    return {
        (row["assessment_id"], row["variant_id"], row["finding_id"])
        for row in connection.execute(sa.text(
            "SELECT assessment_id, variant_id, finding_id FROM assessment_targets"
        )).mappings()
    }


@pytest.fixture
def migrated_connection():
    """A connection holding the post-upgrade schema and its backfilled targets.

    The two seed assessments use different findings (and thus different CVEs)
    so ``fuse_duplicates`` -- which buckets by vulnerability among other
    fields -- leaves them apart; each keeps exactly one target after upgrade,
    matching what a single scalar-column row backfills to.
    """
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _build_pre_upgrade_schema(connection)
        project_id = _new_id()
        variant_a = _add_variant(connection, project_id)
        variant_b = _add_variant(connection, project_id)
        finding_a = _add_finding(connection, "CVE-2026-0900")
        finding_b = _add_finding(connection, "CVE-2026-0901")
        _add_assessment(connection, finding_a, variant_a)
        _add_assessment(connection, finding_b, variant_b)

        _bind_alembic_op(connection)
        migration.upgrade()

        yield connection


def test_an_assessment_may_now_hold_several_targets(migrated_connection):
    """The invariant that made PR-B and PR-C safe is deliberately lifted."""
    assessment_id, variant_id = migrated_connection.execute(sa.text(
        "SELECT assessment_id, variant_id FROM assessment_targets LIMIT 1")).one()
    other_finding = migrated_connection.execute(sa.text(
        "SELECT id FROM findings WHERE id NOT IN"
        " (SELECT finding_id FROM assessment_targets WHERE assessment_id = :a)"
    ), {"a": assessment_id}).scalar()
    migrated_connection.execute(sa.text(
        "INSERT INTO assessment_targets (assessment_id, variant_id, finding_id)"
        " VALUES (:a, :v, :f)"
    ), {"a": assessment_id, "v": variant_id, "f": other_finding})
    count = migrated_connection.execute(sa.text(
        "SELECT COUNT(*) FROM assessment_targets WHERE assessment_id = :a"
    ), {"a": assessment_id}).scalar()
    assert count == 2


def test_upgrade_moves_targets_off_the_scalar_columns_and_fuses_duplicates():
    engine = sa.create_engine("sqlite:///:memory:")

    with engine.begin() as connection:
        _build_pre_upgrade_schema(connection)
        project_id = _new_id()
        finding_id = _add_finding(connection, "CVE-2026-0100")
        variant_a = _add_variant(connection, project_id)
        variant_b = _add_variant(connection, project_id)
        first = _add_assessment(connection, finding_id, variant_a)
        second = _add_assessment(connection, finding_id, variant_b)
        other_finding = _add_finding(connection, "CVE-2026-0101")
        lone = _add_assessment(connection, other_finding, variant_a)

        _bind_alembic_op(connection)
        migration.upgrade()

        columns = _assessment_columns(connection)
        remaining = _existing_assessments(connection)
        targets = _targets(connection)

    assert "variant_id" not in columns
    assert "finding_id" not in columns
    survivor = min(first, second, key=str)
    assert remaining == {survivor, lone}
    assert targets == {
        (survivor, variant_a, finding_id),
        (survivor, variant_b, finding_id),
        (lone, variant_a, other_finding),
    }


def test_downgrade_gives_every_target_its_own_assessment_row_again():
    engine = sa.create_engine("sqlite:///:memory:")

    with engine.begin() as connection:
        _build_pre_upgrade_schema(connection)
        project_id = _new_id()
        finding_id = _add_finding(connection, "CVE-2026-0200")
        variant_a = _add_variant(connection, project_id)
        variant_b = _add_variant(connection, project_id)
        _add_assessment(connection, finding_id, variant_a)
        _add_assessment(connection, finding_id, variant_b)

        _bind_alembic_op(connection)
        migration.upgrade()
        assert len(_existing_assessments(connection)) == 1

        migration.downgrade()

        columns = _assessment_columns(connection)
        rows = [
            (row["variant_id"], row["finding_id"], row["status"])
            for row in connection.execute(sa.text(
                "SELECT variant_id, finding_id, status FROM assessments"
            )).mappings()
        ]
        target_table = connection.execute(sa.text(
            "SELECT name FROM sqlite_master WHERE name = 'assessment_targets'"
        )).scalar()

    assert "variant_id" in columns and "finding_id" in columns
    assert target_table is None
    assert sorted(rows) == sorted([
        (variant_a, finding_id, "not_affected"),
        (variant_b, finding_id, "not_affected"),
    ])


def _build_pr_a_b_c_shaped_schema(connection):
    """Recreate the physical shape this revision had in PR-A/B/C.

    That form of the revision created ``assessment_targets`` WITH a
    ``uq_assessment_targets_assessment_id`` unique constraint (one target per
    assessment) and never dropped the scalar ``assessments.variant_id`` /
    ``finding_id`` columns.  A database can reach exactly this shape today via
    a manual ``flask db stamp`` to this revision followed by a re-upgrade --
    the same scenario the re-run test in
    ``tests/webapp_tests/test_migration_chain_schema.py`` exercises.
    """
    _build_pre_upgrade_schema(connection)
    connection.execute(sa.text(
        """
        CREATE TABLE assessment_targets (
            assessment_id TEXT NOT NULL,
            variant_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            PRIMARY KEY (assessment_id, variant_id, finding_id),
            CONSTRAINT uq_assessment_targets_assessment_id UNIQUE (assessment_id)
        )
        """
    ))
    connection.execute(sa.text(
        "CREATE INDEX ix_assessment_targets_variant_id"
        " ON assessment_targets (variant_id)"
    ))
    connection.execute(sa.text(
        "CREATE INDEX ix_assessment_targets_finding_id"
        " ON assessment_targets (finding_id)"
    ))


def test_upgrade_does_not_drop_a_target_when_adopting_a_pre_release_shaped_table():
    """Re-running upgrade() on a PR-A/B/C-shaped database must lose no targets.

    The table-existence guard alone would skip ``create_table`` (keeping the
    stale one-target-per-assessment unique constraint) while still running
    ``fuse_duplicates``, whose ``UPDATE OR IGNORE`` silently swallows the
    resulting unique-constraint violation while the paired ``DELETE`` still
    removes the source row -- destroying one of two fusible targets instead of
    merging them.  Two assessments here share every fusible field but target
    different variants of the same finding, so a correct upgrade must fuse
    them into one assessment row carrying BOTH targets.
    """
    engine = sa.create_engine("sqlite:///:memory:")

    with engine.begin() as connection:
        _build_pr_a_b_c_shaped_schema(connection)
        project_id = _new_id()
        finding_id = _add_finding(connection, "CVE-2026-0950")
        variant_a = _add_variant(connection, project_id)
        variant_b = _add_variant(connection, project_id)
        first = _add_assessment(connection, finding_id, variant_a)
        second = _add_assessment(connection, finding_id, variant_b)
        for assessment_id, variant_id in ((first, variant_a), (second, variant_b)):
            connection.execute(sa.text(
                "INSERT INTO assessment_targets"
                " (assessment_id, variant_id, finding_id)"
                " VALUES (:a, :v, :f)"
            ), {"a": assessment_id, "v": variant_id, "f": finding_id})

        _bind_alembic_op(connection)
        migration.upgrade()

        remaining = _existing_assessments(connection)
        targets = _targets(connection)
        uniques_after = {
            row["name"] for row in connection.execute(sa.text(
                "SELECT name FROM sqlite_master"
                " WHERE type = 'index' AND tbl_name = 'assessment_targets'"
            )).mappings()
        }

    assert len(remaining) == 1
    survivor = next(iter(remaining))
    assert targets == {
        (survivor, variant_a, finding_id),
        (survivor, variant_b, finding_id),
    }
    assert "uq_assessment_targets_assessment_id" not in uniques_after
