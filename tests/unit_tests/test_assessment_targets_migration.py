# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import importlib
import json
import uuid

import pytest
import sqlalchemy as sa

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
