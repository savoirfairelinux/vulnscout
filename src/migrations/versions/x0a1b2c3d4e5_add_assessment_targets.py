"""Add assessment group members and assessment targets.

Revision ID: x0a1b2c3d4e5
Revises: w9f0a1b2c3d4
Create Date: 2026-08-19 00:00:00.000000

This revision carries two halves.

``assessment_group_members`` is the half that already shipped on ``staging``
under this same revision id.  It stays here, unchanged in effect, because the
model, the controller and the routes still read that table throughout PR-A,
PR-B and PR-C.  **PR-D removes this half**, along with the group-member model
it serves.

``assessment_targets`` is the new half: the storage the reader migrations in
PR-B and PR-C move onto.

Both halves live in one revision on purpose.  This revision is amended in place
across the PR series -- its id and its ``down_revision`` never change, and no
new revision is ever added beside it -- so that the chain stays linear and a
database that has already run it is never left half-migrated by a chain that
grew a new node behind its recorded position.  A consequence, and an accepted
one, is that a database already stamped at this revision will not re-run it and
so will not pick up later amendments: every PR description in the series tells
you to delete your development database before testing, and PR-D adds a loud
post-upgrade schema guard.
"""
import json
import uuid
from alembic import op
import sqlalchemy as sa


revision = 'x0a1b2c3d4e5'
down_revision = 'w9f0a1b2c3d4'
branch_labels = None
depends_on = None

# --- group-members half (PR-D removes this) -------------------------------
GROUP_TABLE = 'assessment_group_members'
GROUP_INDEX_NAME = 'ix_assessment_group_members_group_id'
GROUP_EXPECTED_COLUMNS = {'assessment_id', 'group_id'}
GROUP_EXPECTED_PRIMARY_KEY = {'assessment_id'}
GROUP_EXPECTED_INDEXES = {GROUP_INDEX_NAME: {'group_id'}}
GROUP_EXPECTED_FOREIGN_KEYS = {
    frozenset({'assessment_id'}): ('assessments', {'id'}),
}
# --- end group-members half -----------------------------------------------

TARGET_TABLE = 'assessment_targets'
UNIQUE_CONSTRAINT_NAME = 'uq_assessment_targets_assessment_id'
VARIANT_INDEX_NAME = 'ix_assessment_targets_variant_id'
FINDING_INDEX_NAME = 'ix_assessment_targets_finding_id'
EXPECTED_COLUMNS = {'assessment_id', 'variant_id', 'finding_id'}
EXPECTED_PRIMARY_KEY = {'assessment_id', 'variant_id', 'finding_id'}
EXPECTED_INDEXES = {
    VARIANT_INDEX_NAME: {'variant_id'},
    FINDING_INDEX_NAME: {'finding_id'},
}
EXPECTED_FOREIGN_KEYS = {
    frozenset({'assessment_id'}): ('assessments', {'id'}),
    frozenset({'variant_id'}): ('variants', {'id'}),
    frozenset({'finding_id'}): ('findings', {'id'}),
}


def upgrade():
    """Add ``assessment_group_members`` and ``assessment_targets``.

    This revision is amended in place across the PR series, so a database may
    meet it more than once, and may meet it already holding a half-built or an
    older shape of either table.  Every create step is therefore guarded by
    reflection rather than run blind: a missing table is created, a matching
    table is adopted, and a table that differs from what this revision defines
    aborts the upgrade.  Continuing silently on a divergent schema is the exact
    outcome the one-target-per-assessment invariant exists to prevent.

    A database stamped at the ``staging`` form of this revision already holds
    ``assessment_group_members``; adopting it rather than failing is what lets
    the revision be re-run there.
    """
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    existing_tables = set(inspector.get_table_names())

    # --- group-members half (PR-D removes this) ---------------------------
    if GROUP_TABLE in existing_tables:
        _verify_existing_group_table(inspector)
    else:
        _create_group_table()
    backfill_groups(connection)
    # --- end group-members half -------------------------------------------

    if TARGET_TABLE in existing_tables:
        _verify_existing_target_table(inspector)
    else:
        _create_target_table()

    backfill_targets(connection)


# --- group-members half (PR-D removes this) -------------------------------


def _create_group_table():
    """Create the sparse group-membership table and its lookup index."""
    op.create_table(
        GROUP_TABLE,
        sa.Column('assessment_id', sa.Uuid(), nullable=False),
        sa.Column('group_id', sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ['assessment_id'], ['assessments.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('assessment_id'),
    )
    op.create_index(GROUP_INDEX_NAME, GROUP_TABLE, ['group_id'])


def _verify_existing_group_table(inspector):
    """Refuse to continue unless the existing table is the one defined here.

    A database stamped at the ``staging`` form of this revision already carries
    this table, so meeting it is the normal case and must be adopted rather
    than treated as an error.  A table of a *different* shape is another
    matter: the group reads and mutations that run against it assume this exact
    one, so the upgrade stops and names the divergence.
    """
    _verify_columns(inspector, GROUP_TABLE, GROUP_EXPECTED_COLUMNS)
    _verify_primary_key(inspector, GROUP_TABLE, GROUP_EXPECTED_PRIMARY_KEY)
    _verify_indexes(inspector, GROUP_TABLE, GROUP_EXPECTED_INDEXES)
    _verify_foreign_keys(inspector, GROUP_TABLE, GROUP_EXPECTED_FOREIGN_KEYS)


def responses_key(raw):
    """Return a stable bucket-key fragment for an assessment's VEX responses.

    The column is JSON, and the driver hands it back either already decoded
    (PostgreSQL) or as text (SQLite), so both shapes are normalized here.
    Order is irrelevant to the group serializer, so the list is sorted; an
    unparsable value falls back to its literal text, which at worst keeps two
    rows apart instead of fusing them.
    """
    if raw is None:
        return "[]"
    value = raw
    if isinstance(value, (str, bytes)):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return str(raw)
    if isinstance(value, list):
        return json.dumps(sorted(str(item) for item in value))
    return json.dumps(value, sort_keys=True)


def backfill_groups(connection):
    """Recreate today's frontend grouping as stored membership rows.

    Assessments are grouped by the same key the frontend uses to render one
    history entry, scoped to the vulnerability so that bulk imports sharing a
    timestamp and content across different CVEs are not fused.  Only tuples
    with more than one row become a group; single-row tuples are skipped, which
    is what keeps the table sparse.

    The key also carries the owning project, resolved through the assessment's
    variant.  Reads are project-filtered while group mutations (delete,
    reconcile, approve/reject) load every member by ``group_id``, so a group
    spanning two projects would let one project silently mutate the other's
    assessments.  Assessments without a variant have no project; they fall into
    their own ``NULL`` bucket and never join a project's group.

    ``responses`` is part of the key too: the group serializer exposes only the
    head's responses and reconcile applies one response set to every member, so
    fusing rows that differ there would hide one set and later mutate both as a
    single action.

    The backfill is re-runnable: assessments that already hold a membership row
    are left out of the bucketing entirely, so a second run inserts nothing and
    cannot collide with the primary key.  Leaving them out can strand a partner
    as a singleton, which is then skipped -- an assessment kept out of a group
    is rendered on its own, which is the pre-group behaviour and safe, whereas
    rewriting memberships already stored would silently redraw groups an
    operator may since have reconciled.
    """
    rows = connection.execute(sa.text("""
        SELECT a.id AS assessment_id,
               f.vulnerability_id AS vuln_id,
               v.project_id AS project_id,
               a.timestamp, a.status, a.simplified_status, a.status_notes,
               a.justification, a.impact_statement, a.workaround, a.origin,
               a.responses
        FROM assessments a
        JOIN findings f ON f.id = a.finding_id
        LEFT JOIN variants v ON v.id = a.variant_id
        WHERE NOT EXISTS (
            SELECT 1 FROM assessment_group_members m
            WHERE m.assessment_id = a.id)
    """)).mappings().all()

    buckets: dict[tuple, list] = {}
    for row in rows:
        key = (
            row["project_id"],
            row["vuln_id"], row["timestamp"], row["status"],
            row["simplified_status"], row["status_notes"], row["justification"],
            row["impact_statement"], row["workaround"], row["origin"],
            responses_key(row["responses"]),
        )
        buckets.setdefault(key, []).append(row["assessment_id"])

    payload: list[dict] = []
    for assessment_ids in buckets.values():
        if len(assessment_ids) < 2:
            continue
        group_id = uuid.uuid4()
        payload.extend(
            {"assessment_id": assessment_id, "group_id": group_id.hex}
            for assessment_id in assessment_ids
        )

    for start in range(0, len(payload), 500):
        connection.execute(
            sa.text(
                "INSERT INTO assessment_group_members (assessment_id, group_id) "
                "VALUES (:assessment_id, :group_id)"
            ),
            payload[start:start + 500],
        )


# --- end group-members half -----------------------------------------------


def _create_target_table():
    """Create the target table and its two lookup indexes."""
    op.create_table(
        TARGET_TABLE,
        sa.Column('assessment_id', sa.Uuid(), nullable=False),
        sa.Column('variant_id', sa.Uuid(), nullable=False),
        sa.Column('finding_id', sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ['assessment_id'], ['assessments.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['variant_id'], ['variants.id']),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id']),
        sa.PrimaryKeyConstraint('assessment_id', 'variant_id', 'finding_id'),
        # PR-A only.  Holds the one-target-per-assessment invariant that makes
        # the reader migrations in PR-B and PR-C behaviour-neutral: a target
        # join can only return what a filter on the scalar column returned
        # while this is true.  PR-D removes it and turns on fusion.
        sa.UniqueConstraint('assessment_id', name=UNIQUE_CONSTRAINT_NAME),
    )
    op.create_index(VARIANT_INDEX_NAME, TARGET_TABLE, ['variant_id'])
    op.create_index(FINDING_INDEX_NAME, TARGET_TABLE, ['finding_id'])


def _verify_existing_target_table(inspector):
    """Refuse to continue unless the existing table is the one defined here.

    Reflection through ``sa.inspect`` rather than SQLite ``PRAGMA`` statements,
    so the guard holds on PostgreSQL too.  Every divergence names what was
    expected and what was found, because an operator has to repair the database
    by hand before the upgrade can be retried.
    """
    _verify_columns(inspector, TARGET_TABLE, EXPECTED_COLUMNS)
    _verify_primary_key(inspector, TARGET_TABLE, EXPECTED_PRIMARY_KEY)
    _verify_indexes(inspector, TARGET_TABLE, EXPECTED_INDEXES)

    unique_constraints = {
        constraint['name']: set(constraint.get('column_names') or [])
        for constraint in inspector.get_unique_constraints(TARGET_TABLE)
    }
    if UNIQUE_CONSTRAINT_NAME not in unique_constraints:
        raise RuntimeError(
            f"Table '{TARGET_TABLE}' already exists but carries no unique"
            f" constraint named '{UNIQUE_CONSTRAINT_NAME}'; found"
            f" {sorted(unique_constraints)}.  Without it an assessment could"
            " hold several targets and the reader migrations in PR-B and PR-C"
            " would no longer be behaviour-neutral."
        )
    constrained = unique_constraints[UNIQUE_CONSTRAINT_NAME]
    if constrained != {'assessment_id'}:
        raise RuntimeError(
            f"Constraint '{UNIQUE_CONSTRAINT_NAME}' on '{TARGET_TABLE}' covers"
            f" {sorted(constrained)}, but this revision requires it to cover"
            " ['assessment_id'] alone."
        )

    _verify_foreign_keys(inspector, TARGET_TABLE, EXPECTED_FOREIGN_KEYS)


def _verify_columns(inspector, table, expected_columns):
    """Refuse a table whose columns are not the ones this revision defines."""
    columns = {column['name'] for column in inspector.get_columns(table)}
    if columns != expected_columns:
        raise RuntimeError(
            f"Table '{table}' already exists with columns"
            f" {sorted(columns)}, but this revision defines"
            f" {sorted(expected_columns)}.  Refusing to upgrade a divergent"
            " schema; drop or repair the table and retry."
        )


def _verify_primary_key(inspector, table, expected_primary_key):
    """Refuse a table whose primary key is not the expected one.

    A wrong or missing primary key lets a row the rest of the series assumes is
    unique be stored twice.  ``get_pk_constraint`` reports an empty
    ``constrained_columns`` list rather than raising when a table has no
    primary key, and dialects disagree on column order, so the comparison is
    over a set.
    """
    pk_columns = set(
        inspector.get_pk_constraint(table).get('constrained_columns') or [])
    if pk_columns != expected_primary_key:
        raise RuntimeError(
            f"Table '{table}' already exists with primary key"
            f" {sorted(pk_columns)}, but this revision requires the composite"
            f" key {sorted(expected_primary_key)}.  Refusing to upgrade a"
            " divergent schema; drop or repair the table and retry."
        )


def _verify_indexes(inspector, table, expected_indexes):
    """Refuse a table whose lookup indexes are missing or misaimed.

    An index carrying an expected name over the wrong column is worse than a
    missing one: it makes the table look complete while the lookups the readers
    rely on stay unindexed.  ``column_names`` may hold ``None`` entries for
    expression indexes on some dialects, which simply fail the comparison.
    """
    found_indexes = {
        index['name']: set(index.get('column_names') or [])
        for index in inspector.get_indexes(table)
    }
    missing_indexes = set(expected_indexes) - set(found_indexes)
    if missing_indexes:
        raise RuntimeError(
            f"Table '{table}' already exists but is missing index(es)"
            f" {sorted(missing_indexes)} defined by this revision.  Refusing to"
            " upgrade a partially created table; drop or repair it and retry."
        )

    for name, expected_columns in sorted(expected_indexes.items()):
        covered = found_indexes[name]
        if covered != expected_columns:
            raise RuntimeError(
                f"Index '{name}' on '{table}' covers"
                f" {sorted(covered)}, but this revision requires it to cover"
                f" {sorted(expected_columns)}."
            )


def _verify_foreign_keys(inspector, table, expected_foreign_keys):
    """Refuse a table whose foreign keys do not point where this revision says.

    Without them a row can name an assessment, variant or finding that does not
    exist, and the cascade that removes it with its assessment is gone.  Every
    reflected key has to be accounted for, not just the expected ones: a table
    carrying the expected key *and* a second, divergent key over the same
    column still constrains rows this revision does not allow, so keys are
    grouped by their constrained columns and a group holding more than one key
    is a divergence rather than a match.

    ``referred_columns`` is optional in the reflection contract.  When a
    dialect omits it the referred columns simply have not been verified, and
    reporting an unperformed check as passed is the silent divergence this
    guard exists to prevent -- so a missing value raises.
    """
    found_keys: dict = {}
    for foreign_key in inspector.get_foreign_keys(table):
        constrained = frozenset(
            foreign_key.get('constrained_columns') or [])
        found_keys.setdefault(constrained, []).append(foreign_key)

    unexpected = set(found_keys) - set(expected_foreign_keys)
    if unexpected:
        raise RuntimeError(
            f"Table '{table}' already exists but carries foreign"
            f" key(s) on"
            f" {[sorted(columns) for columns in sorted(unexpected, key=sorted)]}"
            " that this revision does not define.  Refusing to upgrade a"
            " divergent schema; drop or repair the table and retry."
        )

    for constrained, expected in sorted(
            expected_foreign_keys.items(), key=lambda item: sorted(item[0])):
        expected_table, expected_columns = expected
        matches = found_keys.get(constrained, [])
        if not matches:
            raise RuntimeError(
                f"Table '{table}' already exists but carries no foreign"
                f" key on {sorted(constrained)} referencing"
                f" '{expected_table}'.  Refusing to upgrade a divergent schema;"
                " drop or repair the table and retry."
            )
        if len(matches) > 1:
            raise RuntimeError(
                f"Table '{table}' carries {len(matches)} foreign keys on"
                f" {sorted(constrained)}, referencing"
                f" {sorted(str(match.get('referred_table')) for match in matches)},"
                f" but this revision defines exactly one, referencing"
                f" '{expected_table}'.  Refusing to upgrade a divergent schema;"
                " drop or repair the table and retry."
            )
        foreign_key = matches[0]
        referred_table = foreign_key.get('referred_table')
        if referred_table != expected_table:
            raise RuntimeError(
                f"Foreign key on {sorted(constrained)} in '{table}'"
                f" references table '{referred_table}', but this revision"
                f" requires it to reference '{expected_table}'."
            )
        referred_columns = foreign_key.get('referred_columns')
        if not referred_columns:
            raise RuntimeError(
                f"Foreign key on {sorted(constrained)} in '{table}'"
                " reports no referred columns, so it cannot be verified"
                f" against the {sorted(expected_columns)} of"
                f" '{expected_table}' this revision requires.  Refusing to"
                " adopt a table whose shape has not been established."
            )
        if set(referred_columns) != expected_columns:
            raise RuntimeError(
                f"Foreign key on {sorted(constrained)} in '{table}'"
                f" references {sorted(referred_columns)} of"
                f" '{expected_table}', but this revision requires"
                f" {sorted(expected_columns)}."
            )


def backfill_targets(connection):
    """Give every assessment one target row from its scalar columns.

    Both scalar columns are nullable in the schema even though production has
    no NULLs in either.  A row missing one has no valid target and would
    migrate to zero targets, becoming invisible to every variant-filtered read,
    so the migration stops rather than creating it.

    The backfill is re-runnable: it inserts only for assessments that hold no
    target yet.  Before inserting anything it proves that every target already
    present agrees with the scalar columns of its assessment.  A disagreement
    cannot be reconciled here -- ``uq_assessment_targets_assessment_id`` allows
    only one target per assessment, so the correct row cannot be added
    alongside the wrong one -- and swallowing it would leave the target table
    and the scalar columns permanently contradicting each other while the
    migration reported success.  It raises instead.
    """
    orphans = connection.execute(sa.text(
        "SELECT COUNT(*) FROM assessments"
        " WHERE finding_id IS NULL OR variant_id IS NULL"
    )).scalar()
    if orphans:
        raise RuntimeError(
            f"{orphans} assessment(s) have no valid target: finding_id or"
            " variant_id is NULL.  Resolve or delete them before upgrading."
        )

    conflicts = connection.execute(sa.text(
        "SELECT t.assessment_id FROM assessment_targets t"
        " JOIN assessments a ON a.id = t.assessment_id"
        " WHERE t.variant_id != a.variant_id OR t.finding_id != a.finding_id"
        " ORDER BY t.assessment_id"
    )).scalars().all()
    if conflicts:
        shown = ', '.join(str(assessment_id) for assessment_id in conflicts[:10])
        suffix = ', ...' if len(conflicts) > 10 else ''
        raise RuntimeError(
            f"{len(conflicts)} assessment(s) already hold a target that"
            " contradicts their variant_id/finding_id columns:"
            f" {shown}{suffix}.  Only one target per assessment is allowed in"
            " this phase, so the correct target cannot be added beside the"
            " existing one.  Reconcile them before upgrading."
        )

    connection.execute(sa.text(
        "INSERT INTO assessment_targets (assessment_id, variant_id, finding_id)"
        " SELECT a.id, a.variant_id, a.finding_id FROM assessments a"
        " WHERE NOT EXISTS ("
        "   SELECT 1 FROM assessment_targets t WHERE t.assessment_id = a.id)"
    ))


def downgrade():
    """Drop both tables this revision added, newest half first.

    ``upgrade()`` only adds tables; the scalar columns on ``assessments`` are
    left untouched and still carry every target, so there is nothing to restore
    there.  The targets half comes off before the group-members half, the
    reverse of the order they went on.
    """
    op.drop_index(FINDING_INDEX_NAME, table_name=TARGET_TABLE)
    op.drop_index(VARIANT_INDEX_NAME, table_name=TARGET_TABLE)
    op.drop_table(TARGET_TABLE)

    # --- group-members half (PR-D removes this) ---------------------------
    op.drop_index(GROUP_INDEX_NAME, table_name=GROUP_TABLE)
    op.drop_table(GROUP_TABLE)
    # --- end group-members half -------------------------------------------
