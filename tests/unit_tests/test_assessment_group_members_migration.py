# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import importlib
import uuid

import sqlalchemy as sa

migration = importlib.import_module(
    "src.migrations.versions.x0a1b2c3d4e5_add_assessment_group_members"
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
            variant_id TEXT
        )
        """
    ))
    connection.execute(sa.text(
        """
        CREATE TABLE assessment_group_members (
            assessment_id TEXT PRIMARY KEY,
            group_id TEXT NOT NULL
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
) -> str:
    assessment_id = _new_id()
    connection.execute(
        sa.text(
            """
            INSERT INTO assessments (
                id, origin, status, simplified_status, status_notes,
                justification, impact_statement, workaround, timestamp,
                finding_id, variant_id
            ) VALUES (
                :id, 'import', :status, 'fixed', 'notes',
                'code_not_reachable', 'no impact', 'none', :timestamp,
                :finding_id, :variant_id
            )
            """
        ),
        {
            "id": assessment_id,
            "status": status,
            "timestamp": timestamp,
            "finding_id": finding_id,
            "variant_id": variant_id,
        },
    )
    return assessment_id


def _groups(connection) -> dict[str, str]:
    return {
        row["assessment_id"]: row["group_id"]
        for row in connection.execute(sa.text(
            "SELECT assessment_id, group_id FROM assessment_group_members"
        )).mappings()
    }


def test_backfill_never_groups_assessments_across_projects():
    """Identical assessments in two projects must not share a group.

    Reads are project-filtered but group mutations load every member by
    ``group_id``, so a cross-project group would let one project delete or
    reconcile the other project's assessments.
    """
    engine = sa.create_engine("sqlite:///:memory:")

    with engine.begin() as connection:
        _build_schema(connection)
        finding_id = _add_finding(connection, "CVE-2026-0001")
        project_a_variant = _add_variant(connection, _new_id())
        project_b_variant = _add_variant(connection, _new_id())
        first = _add_assessment(connection, finding_id, project_a_variant)
        second = _add_assessment(connection, finding_id, project_b_variant)

        migration.backfill_groups(connection)

        groups = _groups(connection)

    assert first not in groups
    assert second not in groups


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

        migration.backfill_groups(connection)

        groups = _groups(connection)

    assert set(groups) == {first, second}
    assert groups[first] == groups[second]


def test_backfill_keeps_variantless_assessments_out_of_project_groups():
    """Variant-less rows have no project, so they only group with each other."""
    engine = sa.create_engine("sqlite:///:memory:")

    with engine.begin() as connection:
        _build_schema(connection)
        finding_id = _add_finding(connection, "CVE-2026-0003")
        project_id = _new_id()
        scoped_first = _add_assessment(
            connection, finding_id, _add_variant(connection, project_id))
        scoped_second = _add_assessment(
            connection, finding_id, _add_variant(connection, project_id))
        orphan_first = _add_assessment(connection, finding_id, None)
        orphan_second = _add_assessment(connection, finding_id, None)

        migration.backfill_groups(connection)

        groups = _groups(connection)

    assert set(groups) == {
        scoped_first, scoped_second, orphan_first, orphan_second}
    assert groups[scoped_first] == groups[scoped_second]
    assert groups[orphan_first] == groups[orphan_second]
    assert groups[orphan_first] != groups[scoped_first]


def test_backfill_stays_sparse_for_unique_assessments():
    engine = sa.create_engine("sqlite:///:memory:")

    with engine.begin() as connection:
        _build_schema(connection)
        finding_id = _add_finding(connection, "CVE-2026-0004")
        project_id = _new_id()
        _add_assessment(
            connection, finding_id, _add_variant(connection, project_id),
            status="affected")
        _add_assessment(
            connection, finding_id, _add_variant(connection, project_id),
            status="not_affected")

        migration.backfill_groups(connection)

        groups = _groups(connection)

    assert groups == {}
