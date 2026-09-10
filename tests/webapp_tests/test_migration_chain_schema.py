# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""The alembic chain must build the same schema the models declare.

Every other test builds its database with ``db.create_all()``, which reads the
model metadata and therefore cannot notice a table the migrations forgot.  A
real deployment only ever runs ``flask db upgrade``, so a table that exists in
the models but in no migration is invisible to the whole suite and fails on the
first request that touches it.

The upgrade runs in a subprocess, exactly as a deployment runs it: importing the
whole revision chain into the test process would otherwise be the only thing
that ever imports the older revisions.
"""

import os
import shutil
import subprocess
import sys

import pytest
import sqlalchemy as sa

from src.bin.webapp import create_app
from src.extensions import db as _db

from . import setup_demo_db


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _flask(db_path, *args):
    env = dict(os.environ)
    env["FLASK_APP"] = "src.bin.webapp:create_app"
    env["FLASK_SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    completed = subprocess.run(
        [sys.executable, "-m", "flask", "db", *args],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
    )
    assert completed.returncode == 0, (
        f"`flask db {' '.join(args)}` failed:\n{completed.stdout}\n{completed.stderr}"
    )
    return completed


@pytest.fixture(scope="module")
def migrated_db_path(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("chain") / "chain.db"
    _flask(db_path, "upgrade")
    return db_path


@pytest.fixture()
def migrated_tables(migrated_db_path):
    engine = sa.create_engine(f"sqlite:///{migrated_db_path}")
    try:
        yield sa.inspect(engine)
    finally:
        engine.dispose()


def test_migration_chain_creates_every_model_table(migrated_tables):
    application = create_app()
    with application.app_context():
        declared = set(_db.metadata.tables)
    missing = declared - set(migrated_tables.get_table_names())
    assert missing == set(), (
        "these tables are declared by the models but no migration creates them, "
        f"so a freshly upgraded database cannot serve them: {sorted(missing)}"
    )


def test_migration_chain_creates_the_assessment_tables(migrated_tables):
    """The fused assessment-target schema must survive the chain.

    ``assessment_targets`` is created by revision x0a1b2c3d4e5; naming it
    explicitly keeps a future amendment from quietly dropping it.

    ``assessment_group_members`` no longer exists: PR-D's write-path fusion
    (Task 15) makes "a group is an assessment" literally true, so the
    membership table this plan used mid-series is fully retired -- no
    migration creates it and the model is deleted -- and this test must not
    assert for it any more.
    """
    tables = set(migrated_tables.get_table_names())
    assert "assessments" in tables
    assert "assessment_group_members" not in tables
    assert "assessment_targets" in tables

    target_columns = {c["name"] for c in migrated_tables.get_columns("assessment_targets")}
    assert target_columns == {"assessment_id", "variant_id", "finding_id"}

    # Task 15 lifts the one-target-per-assessment invariant (Task 14 already
    # dropped it from the migration itself); several targets per assessment
    # are legal from here on, so no unique constraint on assessment_id alone
    # is expected any more.
    assert not any(
        u["name"] == "uq_assessment_targets_assessment_id"
        for u in migrated_tables.get_unique_constraints("assessment_targets")
    ), "the one-target-per-assessment constraint must not survive PR-D"


def test_migration_chain_creates_every_model_column(migrated_tables):
    """A column the models declare and no migration adds fails only in production.

    The table-level check above catches a whole forgotten table; this catches
    the narrower version of the same defect, a table the migrations create in
    an older shape than the models now expect.  Only the model-declared
    direction is asserted: a migrated database may legitimately hold columns
    the models no longer declare, since nothing drops them.
    """
    application = create_app()
    with application.app_context():
        declared = {
            name: {column.name for column in table.columns}
            for name, table in _db.metadata.tables.items()
        }
    migrated_names = set(migrated_tables.get_table_names())

    missing = {
        name: sorted(columns - {c["name"] for c in migrated_tables.get_columns(name)})
        for name, columns in declared.items()
        if name in migrated_names
        and columns - {c["name"] for c in migrated_tables.get_columns(name)}
    }
    assert missing == {}, (
        "these columns are declared by the models but no migration creates "
        f"them, so a freshly upgraded database cannot serve them: {missing}"
    )


def test_migration_chain_is_linear_with_a_single_head(migrated_db_path):
    """Two revisions claiming the same id silently replace one another.

    A branch is the other way this chain can go wrong: a revision inserted
    beside, rather than after, an id that some database is already stamped at
    leaves that database believing it is up to date while the new node never
    runs.  ``flask db history`` prints one ``down -> up`` edge per revision, so
    a chain in which no two edges share a source and no two share a target is
    linear.
    """
    output = _flask(migrated_db_path, "heads").stdout.strip()
    heads = [line for line in output.splitlines() if line.strip()]
    assert len(heads) == 1, f"expected one alembic head, got {heads}"
    assert "x0a1b2c3d4e5" in heads[0]

    edges = []
    for line in _flask(migrated_db_path, "history").stdout.splitlines():
        if "->" not in line:
            continue
        down, _, rest = line.partition("->")
        up = rest.split(",")[0].replace("(head)", "").replace("(base)", "").strip()
        edges.append((down.strip(), up))

    sources = [down for down, _ in edges]
    targets = [up for _, up in edges]
    assert len(set(sources)) == len(sources), (
        f"the revision chain branches; two revisions share a parent: {edges}"
    )
    assert len(set(targets)) == len(targets), (
        f"the revision chain merges; two revisions share an id: {edges}"
    )
    assert ("w9f0a1b2c3d4", "x0a1b2c3d4e5") in edges, (
        "the assessment revision must stay pinned to its recorded parent; "
        f"found {edges[:3]}"
    )


@pytest.fixture()
def migrated_app(migrated_db_path, tmp_path):
    """An application served by a database the migrations built.

    Not ``create_all``: the point is to exercise the schema a deployment
    actually gets.  The module-scoped migrated database is copied first so a
    seeded test cannot leak rows into the reflection tests.
    """
    db_copy = tmp_path / "served.db"
    shutil.copyfile(migrated_db_path, db_copy)

    status_file = tmp_path / "status.txt"
    status_file.write_text("__END_OF_SCAN_SCRIPT__")

    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_copy}"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": status_file,
            "OPENVEX_FILE": tmp_path / "openvex.json",
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db",
        })
        setup_demo_db(application, create_schema=False)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


def test_posting_an_assessment_works_on_a_migrated_database(migrated_app):
    """The request that a missing migration breaks first.

    Writing an assessment reads ``assessment_group_members`` while serializing
    the result, so a chain that never creates that table returns 500 here even
    though every ``create_all`` test passes.  This is the end-to-end form of
    the schema check above, against the schema a deployment really runs.
    """
    client = migrated_app.test_client()

    response = client.post(
        "/api/vulnerabilities/CVE-2020-35492/assessments",
        json={
            "packages": ["cairo@1.16.0"],
            "status": "exploitable",
            "workaround": "Disable option X in configuration",
            "variant_id": "22222222-2222-2222-2222-222222222222",
        },
    )

    assert response.status_code == 200, response.get_data(as_text=True)
    assert "Disable option X in configuration" in client.get(
        "/api/assessments?format=list").get_data(as_text=True)


def test_the_assessment_revision_can_be_re_run_on_a_migrated_database(
    migrated_db_path, tmp_path,
):
    """Re-running the revision must adopt what it already built, not die.

    Both halves of the revision guard their create step by reflection.  Sending
    an already-migrated database back one revision and forward again is the
    closest reproduction of a database stamped at the ``staging`` form of this
    revision meeting the amended form of it.
    """
    db_copy = tmp_path / "rerun.db"
    shutil.copyfile(migrated_db_path, db_copy)

    _flask(db_copy, "stamp", "w9f0a1b2c3d4")
    _flask(db_copy, "upgrade")

    engine = sa.create_engine(f"sqlite:///{db_copy}")
    try:
        tables = set(sa.inspect(engine).get_table_names())
    finally:
        engine.dispose()

    assert "assessment_group_members" not in tables
    assert "assessment_targets" in tables
