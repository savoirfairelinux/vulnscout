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

backfill_targets = migration.backfill_targets
fuse_duplicates = migration.fuse_duplicates

SHARED_TIMESTAMP = "2026-01-01 00:00:00"


def _new_id() -> str:
    return uuid.uuid4().hex


def _build_pre_upgrade_schema(connection):
    """Create the schema as it stands just before this revision runs."""
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
    finding_id: "str | None",
    variant_id: "str | None",
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
                id, source, origin, status, simplified_status, status_notes,
                justification, impact_statement, workaround, timestamp,
                finding_id, variant_id, responses
            ) VALUES (
                :id, 'manual', 'import', :status, 'fixed', 'notes',
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


def _bind_alembic_op(connection):
    migration.op = Operations(MigrationContext.configure(connection))


@pytest.fixture
def migrated_connection():
    """A connection holding the post-upgrade schema and its backfilled targets."""
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _build_pre_upgrade_schema(connection)
        project_id = _new_id()
        variant_a = _add_variant(connection, project_id)
        variant_b = _add_variant(connection, project_id)
        finding_a = _add_finding(connection, "CVE-2026-0100")
        _add_finding(connection, "CVE-2026-0101")
        _add_assessment(connection, finding_a, variant_a)
        _add_assessment(connection, finding_a, variant_b)

        _bind_alembic_op(connection)
        migration.upgrade()

        yield connection


@pytest.fixture
def connection_with_null_variant():
    """A pre-upgrade connection holding one assessment with no variant."""
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _build_pre_upgrade_schema(connection)
        _add_assessment(
            connection, _add_finding(connection, "CVE-2026-0200"), None)

        yield connection


@pytest.fixture
def connection_with_duplicates():
    """Two assessments produced by one user action, before they are fused.

    Built at the point mid-``upgrade`` where ``fuse_duplicates`` runs: the
    target table exists and is backfilled, but the scalar columns are still on
    ``assessments`` because ``fuse_duplicates`` itself still reads them.
    """
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _build_pre_upgrade_schema(connection)
        connection.execute(sa.text(
            """
            CREATE TABLE assessment_targets (
                assessment_id TEXT NOT NULL REFERENCES assessments (id)
                    ON DELETE CASCADE,
                variant_id TEXT NOT NULL REFERENCES variants (id),
                finding_id TEXT NOT NULL REFERENCES findings (id),
                PRIMARY KEY (assessment_id, variant_id, finding_id)
            )
            """
        ))
        connection.execute(sa.text(
            "CREATE INDEX ix_assessment_targets_variant_id"
            " ON assessment_targets (variant_id)"))
        connection.execute(sa.text(
            "CREATE INDEX ix_assessment_targets_finding_id"
            " ON assessment_targets (finding_id)"))

        project_id = _new_id()
        variant_a = _add_variant(connection, project_id)
        variant_b = _add_variant(connection, project_id)
        finding_a = _add_finding(connection, "CVE-2026-0400")

        first = _add_assessment(connection, finding_a, variant_a)
        second = _add_assessment(connection, finding_a, variant_b)

        for assessment_id, variant_id in ((first, variant_a), (second, variant_b)):
            connection.execute(sa.text(
                "INSERT INTO assessment_targets (assessment_id, variant_id, finding_id)"
                " VALUES (:a, :v, :f)"
            ), {"a": assessment_id, "v": variant_id, "f": finding_a})

        _bind_alembic_op(connection)

        yield connection


def test_backfill_gives_every_assessment_exactly_one_target(migrated_connection):
    """Every pre-existing assessment gets one target from its scalar columns."""
    rows = migrated_connection.execute(sa.text(
        "SELECT assessment_id, COUNT(*) FROM assessment_targets GROUP BY assessment_id"
    )).all()
    assert rows, "backfill produced no targets"
    assert all(count == 1 for _, count in rows)


def test_scalar_columns_are_gone(migrated_connection):
    columns = {row[1] for row in migrated_connection.execute(
        sa.text("PRAGMA table_info(assessments)")).all()}
    assert "variant_id" not in columns
    assert "finding_id" not in columns


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


def test_duplicate_rows_from_one_user_action_are_fused(connection_with_duplicates):
    """Rows sharing project, CVE, content and timestamp become one row."""
    fuse_duplicates(connection_with_duplicates)
    survivors = connection_with_duplicates.execute(sa.text(
        "SELECT COUNT(*) FROM assessments")).scalar()
    targets = connection_with_duplicates.execute(sa.text(
        "SELECT COUNT(*) FROM assessment_targets")).scalar()
    assert survivors == 1
    assert targets == 2


def test_backfill_is_idempotent(migrated_connection):
    """Re-running the backfill against populated targets adds nothing."""
    before = migrated_connection.execute(
        sa.text("SELECT COUNT(*) FROM assessment_targets")).scalar()
    backfill_targets(migrated_connection)
    after = migrated_connection.execute(
        sa.text("SELECT COUNT(*) FROM assessment_targets")).scalar()
    assert after == before


def test_orphan_assessment_stops_the_upgrade(connection_with_null_variant):
    """An assessment with a NULL column would migrate to zero targets."""
    with pytest.raises(RuntimeError, match="no valid target"):
        backfill_targets(connection_with_null_variant)


def test_upgrade_mirrors_the_scalar_columns_onto_every_target(migrated_connection):
    """Each target names exactly the pair its assessment still carries."""
    mismatched = migrated_connection.execute(sa.text(
        "SELECT COUNT(*) FROM assessments a JOIN assessment_targets t"
        " ON t.assessment_id = a.id"
        " WHERE t.variant_id != a.variant_id OR t.finding_id != a.finding_id"
    )).scalar()
    assert mismatched == 0


def test_downgrade_drops_both_tables_and_keeps_the_scalar_columns(
    migrated_connection,
):
    """``downgrade`` reverses ``upgrade``, which never touched the scalar columns.

    Both halves of the revision have to come off: leaving
    ``assessment_group_members`` behind would make a re-upgrade adopt a table
    holding memberships computed from a schema that has since moved.
    """
    migration.downgrade()

    columns = {row[1] for row in migrated_connection.execute(
        sa.text("PRAGMA table_info(assessments)")).all()}
    remaining = set(migrated_connection.execute(sa.text(
        "SELECT name FROM sqlite_master WHERE name IN"
        " ('assessment_targets', 'assessment_group_members')"
    )).scalars().all())

    assert remaining == set()
    assert "variant_id" in columns
    assert "finding_id" in columns


@pytest.fixture
def pre_upgrade_connection():
    """A seeded connection holding the schema as it stands before this revision."""
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _build_pre_upgrade_schema(connection)
        project_id = _new_id()
        variant_a = _add_variant(connection, project_id)
        variant_b = _add_variant(connection, project_id)
        finding_a = _add_finding(connection, "CVE-2026-0300")
        _add_finding(connection, "CVE-2026-0301")
        _add_assessment(connection, finding_a, variant_a)
        _add_assessment(connection, finding_a, variant_b)

        _bind_alembic_op(connection)

        yield connection


def _target_rows(connection):
    return set(connection.execute(sa.text(
        "SELECT assessment_id, variant_id, finding_id FROM assessment_targets"
    )).all())


def test_upgrade_is_idempotent(pre_upgrade_connection):
    """A retried upgrade completes instead of dying on 'table already exists'."""
    migration.upgrade()
    after_first = _target_rows(pre_upgrade_connection)

    migration.upgrade()

    assert _target_rows(pre_upgrade_connection) == after_first


def test_upgrade_completes_when_the_table_exists_but_is_empty(pre_upgrade_connection):
    """A table created by a crashed run is adopted and then backfilled."""
    migration._create_target_table()
    assert _target_rows(pre_upgrade_connection) == set()

    migration.upgrade()

    expected = set(pre_upgrade_connection.execute(sa.text(
        "SELECT id, variant_id, finding_id FROM assessments")).all())
    assert _target_rows(pre_upgrade_connection) == expected


def test_upgrade_refuses_a_table_with_unexpected_columns(pre_upgrade_connection):
    """A same-named table of a different shape is a divergent schema, not ours."""
    pre_upgrade_connection.execute(sa.text(
        "CREATE TABLE assessment_targets ("
        " assessment_id TEXT NOT NULL, group_id TEXT NOT NULL,"
        " PRIMARY KEY (assessment_id, group_id))"
    ))

    with pytest.raises(RuntimeError, match="already exists with columns"):
        migration.upgrade()


def test_upgrade_refuses_a_table_missing_an_index(pre_upgrade_connection):
    """A partially created table stops the upgrade rather than half-applying it."""
    migration._create_target_table()
    pre_upgrade_connection.execute(
        sa.text("DROP INDEX ix_assessment_targets_finding_id"))

    with pytest.raises(RuntimeError, match="missing index"):
        migration.upgrade()


def test_upgrade_refuses_a_table_without_the_unique_constraint(pre_upgrade_connection):
    """Without the 1:1 constraint the PR-B/PR-C reader swaps are not neutral."""
    pre_upgrade_connection.execute(sa.text(
        "CREATE TABLE assessment_targets ("
        " assessment_id TEXT NOT NULL, variant_id TEXT NOT NULL,"
        " finding_id TEXT NOT NULL,"
        " PRIMARY KEY (assessment_id, variant_id, finding_id))"
    ))
    pre_upgrade_connection.execute(sa.text(
        "CREATE INDEX ix_assessment_targets_variant_id"
        " ON assessment_targets (variant_id)"))
    pre_upgrade_connection.execute(sa.text(
        "CREATE INDEX ix_assessment_targets_finding_id"
        " ON assessment_targets (finding_id)"))

    with pytest.raises(RuntimeError, match="no unique constraint named"):
        migration.upgrade()


def test_upgrade_refuses_a_unique_constraint_over_the_wrong_columns(
        pre_upgrade_connection):
    """The right name over the wrong columns permits several targets per assessment."""
    pre_upgrade_connection.execute(sa.text(
        "CREATE TABLE assessment_targets ("
        " assessment_id TEXT NOT NULL, variant_id TEXT NOT NULL,"
        " finding_id TEXT NOT NULL,"
        " PRIMARY KEY (assessment_id, variant_id, finding_id),"
        " CONSTRAINT uq_assessment_targets_assessment_id"
        " UNIQUE (assessment_id, variant_id))"
    ))
    pre_upgrade_connection.execute(sa.text(
        "CREATE INDEX ix_assessment_targets_variant_id"
        " ON assessment_targets (variant_id)"))
    pre_upgrade_connection.execute(sa.text(
        "CREATE INDEX ix_assessment_targets_finding_id"
        " ON assessment_targets (finding_id)"))

    with pytest.raises(RuntimeError, match="requires it to cover"):
        migration.upgrade()


def _create_lookup_indexes(connection):
    """Add the two lookup indexes this revision defines, by name and column."""
    connection.execute(sa.text(
        "CREATE INDEX ix_assessment_targets_variant_id"
        " ON assessment_targets (variant_id)"))
    connection.execute(sa.text(
        "CREATE INDEX ix_assessment_targets_finding_id"
        " ON assessment_targets (finding_id)"))


def test_upgrade_refuses_a_table_with_the_wrong_primary_key(pre_upgrade_connection):
    """A single-column key lets one assessment hold contradictory triples."""
    pre_upgrade_connection.execute(sa.text(
        "CREATE TABLE assessment_targets ("
        " assessment_id TEXT NOT NULL REFERENCES assessments (id)"
        " ON DELETE CASCADE,"
        " variant_id TEXT NOT NULL REFERENCES variants (id),"
        " finding_id TEXT NOT NULL REFERENCES findings (id),"
        " PRIMARY KEY (assessment_id),"
        " CONSTRAINT uq_assessment_targets_assessment_id UNIQUE (assessment_id))"
    ))
    _create_lookup_indexes(pre_upgrade_connection)

    with pytest.raises(RuntimeError, match="requires the composite key"):
        migration.upgrade()


def test_upgrade_refuses_a_table_with_no_primary_key(pre_upgrade_connection):
    """A missing key is a divergence too, not an absence the guard can ignore."""
    pre_upgrade_connection.execute(sa.text(
        "CREATE TABLE assessment_targets ("
        " assessment_id TEXT NOT NULL REFERENCES assessments (id)"
        " ON DELETE CASCADE,"
        " variant_id TEXT NOT NULL REFERENCES variants (id),"
        " finding_id TEXT NOT NULL REFERENCES findings (id),"
        " CONSTRAINT uq_assessment_targets_assessment_id UNIQUE (assessment_id))"
    ))
    _create_lookup_indexes(pre_upgrade_connection)

    with pytest.raises(RuntimeError, match="requires the composite key"):
        migration.upgrade()


def test_upgrade_refuses_an_index_over_the_wrong_column(pre_upgrade_connection):
    """The expected name over the wrong column leaves the lookup unindexed."""
    migration._create_target_table()
    pre_upgrade_connection.execute(
        sa.text("DROP INDEX ix_assessment_targets_finding_id"))
    pre_upgrade_connection.execute(sa.text(
        "CREATE INDEX ix_assessment_targets_finding_id"
        " ON assessment_targets (assessment_id)"))

    with pytest.raises(RuntimeError, match="covers.*requires it to cover"):
        migration.upgrade()


def test_upgrade_refuses_a_table_without_its_foreign_keys(pre_upgrade_connection):
    """Unreferenced targets can name rows that do not exist."""
    pre_upgrade_connection.execute(sa.text(
        "CREATE TABLE assessment_targets ("
        " assessment_id TEXT NOT NULL, variant_id TEXT NOT NULL,"
        " finding_id TEXT NOT NULL,"
        " PRIMARY KEY (assessment_id, variant_id, finding_id),"
        " CONSTRAINT uq_assessment_targets_assessment_id UNIQUE (assessment_id))"
    ))
    _create_lookup_indexes(pre_upgrade_connection)

    with pytest.raises(RuntimeError, match="carries no foreign key on"):
        migration.upgrade()


def test_upgrade_refuses_a_foreign_key_to_the_wrong_table(pre_upgrade_connection):
    """A key pointing elsewhere constrains the wrong rows."""
    pre_upgrade_connection.execute(sa.text(
        "CREATE TABLE assessment_targets ("
        " assessment_id TEXT NOT NULL REFERENCES variants (id),"
        " variant_id TEXT NOT NULL REFERENCES variants (id),"
        " finding_id TEXT NOT NULL REFERENCES findings (id),"
        " PRIMARY KEY (assessment_id, variant_id, finding_id),"
        " CONSTRAINT uq_assessment_targets_assessment_id UNIQUE (assessment_id))"
    ))
    _create_lookup_indexes(pre_upgrade_connection)

    with pytest.raises(RuntimeError, match="references table 'variants'"):
        migration.upgrade()


def test_upgrade_refuses_a_foreign_key_to_the_wrong_column(pre_upgrade_connection):
    """A key onto a non-key column of the right table is still divergent."""
    pre_upgrade_connection.execute(sa.text(
        "CREATE TABLE assessment_targets ("
        " assessment_id TEXT NOT NULL REFERENCES assessments (id)"
        " ON DELETE CASCADE,"
        " variant_id TEXT NOT NULL REFERENCES variants (project_id),"
        " finding_id TEXT NOT NULL REFERENCES findings (id),"
        " PRIMARY KEY (assessment_id, variant_id, finding_id),"
        " CONSTRAINT uq_assessment_targets_assessment_id UNIQUE (assessment_id))"
    ))
    _create_lookup_indexes(pre_upgrade_connection)

    with pytest.raises(RuntimeError, match="references \\['project_id'\\]"):
        migration.upgrade()


def test_upgrade_refuses_a_duplicate_divergent_foreign_key(pre_upgrade_connection):
    """The expected key beside a divergent one over the same column is divergent.

    Keying reflected foreign keys by their constrained columns alone lets the
    second key replace the first in the lookup, so a table constraining
    ``assessment_id`` against both ``assessments`` and ``variants`` would pass
    verification and be adopted.  Every reflected key has to be accounted for.
    """
    pre_upgrade_connection.execute(sa.text(
        "CREATE TABLE assessment_targets ("
        " assessment_id TEXT NOT NULL,"
        " variant_id TEXT NOT NULL REFERENCES variants (id),"
        " finding_id TEXT NOT NULL REFERENCES findings (id),"
        " PRIMARY KEY (assessment_id, variant_id, finding_id),"
        " CONSTRAINT uq_assessment_targets_assessment_id UNIQUE (assessment_id),"
        " FOREIGN KEY (assessment_id) REFERENCES variants (id),"
        " FOREIGN KEY (assessment_id) REFERENCES assessments (id)"
        " ON DELETE CASCADE)"
    ))
    _create_lookup_indexes(pre_upgrade_connection)

    with pytest.raises(RuntimeError, match="foreign keys on \\['assessment_id'\\]"):
        migration.upgrade()


def test_upgrade_refuses_a_foreign_key_this_revision_does_not_define(
        pre_upgrade_connection):
    """A key over columns this revision never constrains is still a divergence."""
    pre_upgrade_connection.execute(sa.text(
        "CREATE TABLE assessment_targets ("
        " assessment_id TEXT NOT NULL REFERENCES assessments (id)"
        " ON DELETE CASCADE,"
        " variant_id TEXT NOT NULL REFERENCES variants (id),"
        " finding_id TEXT NOT NULL REFERENCES findings (id),"
        " PRIMARY KEY (assessment_id, variant_id, finding_id),"
        " CONSTRAINT uq_assessment_targets_assessment_id UNIQUE (assessment_id),"
        " FOREIGN KEY (variant_id, finding_id)"
        " REFERENCES variants (id, project_id))"
    ))
    _create_lookup_indexes(pre_upgrade_connection)

    with pytest.raises(RuntimeError, match="that this revision does not define"):
        migration.upgrade()


class _NoReferredColumnsInspector:
    """An inspector reporting the expected keys without their referred columns.

    No SQLite reference omits them -- the dialect resolves an implicit
    reference to the referred primary key -- so the dialect gap the guard
    refuses on is reproduced here rather than in the database.
    """

    def get_foreign_keys(self, table_name):
        """Report every expected key, each missing ``referred_columns``."""
        return [
            {
                'constrained_columns': sorted(constrained),
                'referred_table': referred_table,
            }
            for constrained, (referred_table, _columns)
            in migration.EXPECTED_FOREIGN_KEYS.items()
        ]


def test_verification_refuses_a_dialect_that_omits_referred_columns():
    """An unperformed check cannot be reported as a passed one."""
    with pytest.raises(RuntimeError, match="reports no referred columns"):
        migration._verify_foreign_keys(
            _NoReferredColumnsInspector(),
            migration.TARGET_TABLE,
            migration.EXPECTED_FOREIGN_KEYS,
        )


def test_conflicting_pre_existing_target_stops_the_backfill(pre_upgrade_connection):
    """A target disagreeing with the scalar columns cannot be silently kept.

    ``uq_assessment_targets_assessment_id`` allows one target per assessment, so
    the correct row cannot be inserted beside the wrong one.  Ignoring the
    collision would leave the target table and the scalar columns contradicting
    each other while the migration reported success.
    """
    migration._create_target_table()
    assessment_id, variant_id, finding_id = pre_upgrade_connection.execute(sa.text(
        "SELECT id, variant_id, finding_id FROM assessments LIMIT 1")).one()
    other_variant = pre_upgrade_connection.execute(sa.text(
        "SELECT id FROM variants WHERE id != :v"), {"v": variant_id}).scalar()
    pre_upgrade_connection.execute(sa.text(
        "INSERT INTO assessment_targets (assessment_id, variant_id, finding_id)"
        " VALUES (:a, :v, :f)"
    ), {"a": assessment_id, "v": other_variant, "f": finding_id})

    with pytest.raises(RuntimeError, match="contradicts their"):
        migration.upgrade()

    still_wrong = pre_upgrade_connection.execute(sa.text(
        "SELECT variant_id FROM assessment_targets WHERE assessment_id = :a"
    ), {"a": assessment_id}).scalar()
    assert still_wrong == other_variant, "the migration must not half-repair"


def test_conflicting_finding_id_stops_the_backfill(pre_upgrade_connection):
    """The same guard covers a target whose finding_id drifted from the scalar."""
    migration._create_target_table()
    assessment_id, variant_id, finding_id = pre_upgrade_connection.execute(sa.text(
        "SELECT id, variant_id, finding_id FROM assessments LIMIT 1")).one()
    other_finding = pre_upgrade_connection.execute(sa.text(
        "SELECT id FROM findings WHERE id != :f"), {"f": finding_id}).scalar()
    pre_upgrade_connection.execute(sa.text(
        "INSERT INTO assessment_targets (assessment_id, variant_id, finding_id)"
        " VALUES (:a, :v, :f)"
    ), {"a": assessment_id, "v": variant_id, "f": other_finding})

    with pytest.raises(RuntimeError, match="contradicts their"):
        backfill_targets(pre_upgrade_connection)


def test_backfill_completes_assessments_missing_a_target(pre_upgrade_connection):
    """A half-finished backfill is finished, not abandoned."""
    migration._create_target_table()
    assessment_id, variant_id, finding_id = pre_upgrade_connection.execute(sa.text(
        "SELECT id, variant_id, finding_id FROM assessments LIMIT 1")).one()
    pre_upgrade_connection.execute(sa.text(
        "INSERT INTO assessment_targets (assessment_id, variant_id, finding_id)"
        " VALUES (:a, :v, :f)"
    ), {"a": assessment_id, "v": variant_id, "f": finding_id})

    backfill_targets(pre_upgrade_connection)

    expected = set(pre_upgrade_connection.execute(sa.text(
        "SELECT id, variant_id, finding_id FROM assessments")).all())
    assert _target_rows(pre_upgrade_connection) == expected


# --- the group-members half of this revision (PR-D removes it) -------------


def test_upgrade_creates_both_tables_this_revision_defines(pre_upgrade_connection):
    """One revision, two tables.

    ``assessment_group_members`` shipped on staging under this same revision
    id.  The model, the controller and the routes still read it throughout
    PR-A, so an amendment that creates only ``assessment_targets`` leaves a
    freshly migrated database unable to serve a single assessment POST.
    """
    migration.upgrade()

    tables = set(pre_upgrade_connection.execute(sa.text(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    )).scalars().all())

    assert "assessment_group_members" in tables
    assert "assessment_targets" in tables


def test_upgrade_adopts_a_group_table_left_by_the_staging_revision(
    pre_upgrade_connection,
):
    """A database stamped at staging's form of this revision already has it.

    Re-running the amended revision there must adopt the existing table rather
    than die on 'table already exists', which is the only way such a database
    can ever pick the targets half up.
    """
    migration._create_group_table()
    pre_upgrade_connection.execute(sa.text(
        "INSERT INTO assessment_group_members (assessment_id, group_id)"
        " SELECT id, :group_id FROM assessments"
    ), {"group_id": _new_id()})
    before = set(pre_upgrade_connection.execute(sa.text(
        "SELECT assessment_id, group_id FROM assessment_group_members")).all())

    migration.upgrade()

    assert set(pre_upgrade_connection.execute(sa.text(
        "SELECT assessment_id, group_id FROM assessment_group_members"
    )).all()) == before
    assert _target_rows(pre_upgrade_connection) == set(
        pre_upgrade_connection.execute(sa.text(
            "SELECT id, variant_id, finding_id FROM assessments")).all())


def test_group_backfill_is_idempotent(pre_upgrade_connection):
    """A retried upgrade must not collide with the memberships it already wrote."""
    migration.upgrade()
    after_first = set(pre_upgrade_connection.execute(sa.text(
        "SELECT assessment_id, group_id FROM assessment_group_members")).all())
    assert after_first, "the two seeded assessments share a key and must group"

    migration.upgrade()

    assert set(pre_upgrade_connection.execute(sa.text(
        "SELECT assessment_id, group_id FROM assessment_group_members"
    )).all()) == after_first


def test_upgrade_refuses_a_divergent_group_table(pre_upgrade_connection):
    """A same-named table of another shape is not the one this revision defines."""
    pre_upgrade_connection.execute(sa.text(
        "CREATE TABLE assessment_group_members ("
        " assessment_id TEXT PRIMARY KEY, cluster_id TEXT NOT NULL)"
    ))

    with pytest.raises(RuntimeError, match="already exists with columns"):
        migration.upgrade()
