"""Add assessment targets and collapse duplicate assessments.

Revision ID: x0a1b2c3d4e5
Revises: w9f0a1b2c3d4
Create Date: 2026-08-19 00:00:00.000000
"""
import json
from alembic import op
import sqlalchemy as sa


revision = 'x0a1b2c3d4e5'
down_revision = 'w9f0a1b2c3d4'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'assessment_targets',
        sa.Column('assessment_id', sa.Uuid(), nullable=False),
        sa.Column('variant_id', sa.Uuid(), nullable=False),
        sa.Column('finding_id', sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ['assessment_id'], ['assessments.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['variant_id'], ['variants.id']),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id']),
        sa.PrimaryKeyConstraint('assessment_id', 'variant_id', 'finding_id'),
    )
    op.create_index(
        'ix_assessment_targets_variant_id', 'assessment_targets', ['variant_id'])
    op.create_index(
        'ix_assessment_targets_finding_id', 'assessment_targets', ['finding_id'])

    connection = op.get_bind()
    backfill_targets(connection)
    fuse_duplicates(connection)

    # SQLite refuses native DROP COLUMN here: both columns carry a foreign key
    # and an index, and it fails with "unknown column ... in foreign key
    # definition".  Batch mode does the create-copy-drop-rename rebuild.
    with op.batch_alter_table('assessments') as batch:
        batch.drop_index('ix_assessments_variant_id')
        batch.drop_index('ix_assessments_finding_id')
        batch.drop_column('variant_id')
        batch.drop_column('finding_id')


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


def backfill_targets(connection):
    """Give every assessment one target row from its scalar columns.

    Both columns are nullable in the schema even though production has no NULLs
    in either.  A row missing one has no valid target and would migrate to zero
    targets, becoming invisible to every variant-filtered read, so the migration
    stops rather than creating it.

    ``OR IGNORE`` keeps the backfill idempotent so it can be re-run against a
    table that already holds some of these triples -- a retried or partially
    applied upgrade, or a caller that seeded rows through the ORM before
    invoking the backfill directly.  On a clean upgrade the target table is
    created by this same revision, so every inserted triple is distinct and the
    clause is a no-op.
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
    connection.execute(sa.text(
        "INSERT OR IGNORE INTO assessment_targets (assessment_id, variant_id, finding_id)"
        " SELECT id, variant_id, finding_id FROM assessments"
    ))


def fuse_duplicates(connection):
    """Collapse assessments that one user action produced into single rows.

    This is the same bucketing the group backfill used to perform, writing a
    different result.  Assessments are grouped by the key the frontend uses to
    render one history entry, scoped to the vulnerability so that bulk imports
    sharing a timestamp and content across different CVEs are not fused.

    The key carries the owning project, resolved through the assessment's
    variant.  Reads are project-filtered, so a bucket spanning two projects
    would let one project silently mutate the other's assessments.

    ``responses`` is part of the key too: one response set now belongs to one
    assessment, so fusing rows that differ there would discard one set.

    Within a bucket the lowest ``id`` survives; timestamps are identical by
    construction, so ``id`` is the only deterministic tie-break.  The others'
    target rows move onto the survivor and the rows themselves are deleted.
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

    moves: list[dict] = []
    doomed: list[dict] = []
    for assessment_ids in buckets.values():
        if len(assessment_ids) < 2:
            continue
        survivor, *others = sorted(assessment_ids, key=str)
        for other in others:
            moves.append({"survivor": survivor, "other": other})
            doomed.append({"other": other})

    for start in range(0, len(moves), 500):
        connection.execute(
            sa.text(
                "UPDATE OR IGNORE assessment_targets SET assessment_id = :survivor"
                " WHERE assessment_id = :other"
            ),
            moves[start:start + 500],
        )
    # OR IGNORE above leaves behind any row whose (variant, finding) the
    # survivor already covers -- two rows in one bucket may name the same
    # target -- so the leftovers are dropped rather than colliding on the
    # composite primary key.
    for start in range(0, len(doomed), 500):
        connection.execute(
            sa.text("DELETE FROM assessment_targets WHERE assessment_id = :other"),
            doomed[start:start + 500],
        )
    for start in range(0, len(doomed), 500):
        connection.execute(
            sa.text("DELETE FROM assessments WHERE id = :other"),
            doomed[start:start + 500],
        )


def downgrade():
    """Return to the pre-x0a1b2c3d4e5 world: scalar columns, no grouping.

    Every target becomes its own assessment row again.  The survivor keeps its
    id and its first target; each additional target becomes a fresh row copying
    the content.  No group ids are invented, because before this revision no
    grouping existed.
    """
    with op.batch_alter_table('assessments') as batch:
        batch.add_column(sa.Column('finding_id', sa.Uuid(), nullable=True))
        batch.add_column(sa.Column('variant_id', sa.Uuid(), nullable=True))
        batch.create_index('ix_assessments_finding_id', ['finding_id'])
        batch.create_index('ix_assessments_variant_id', ['variant_id'])

    connection = op.get_bind()
    fan_out(connection)

    op.drop_index('ix_assessment_targets_finding_id',
                  table_name='assessment_targets')
    op.drop_index('ix_assessment_targets_variant_id',
                  table_name='assessment_targets')
    op.drop_table('assessment_targets')


def fan_out(connection):
    """Give every target its own assessment row, restoring the scalar columns."""
    import uuid as _uuid

    columns = [
        "source", "origin", "status", "simplified_status", "status_notes",
        "justification", "impact_statement", "workaround", "timestamp",
        "responses",
    ]
    targets = connection.execute(sa.text(
        "SELECT assessment_id, variant_id, finding_id FROM assessment_targets"
        " ORDER BY assessment_id, variant_id, finding_id"
    )).mappings().all()

    seen: set = set()
    for target in targets:
        assessment_id = target["assessment_id"]
        if assessment_id not in seen:
            seen.add(assessment_id)
            connection.execute(
                sa.text(
                    "UPDATE assessments SET variant_id = :variant_id,"
                    " finding_id = :finding_id WHERE id = :id"
                ),
                {"variant_id": target["variant_id"],
                 "finding_id": target["finding_id"],
                 "id": assessment_id},
            )
            continue
        source = connection.execute(
            sa.text(f"SELECT {', '.join(columns)} FROM assessments WHERE id = :id"),
            {"id": assessment_id},
        ).mappings().one()
        payload = dict(source)
        payload["id"] = _uuid.uuid4().hex
        payload["variant_id"] = target["variant_id"]
        payload["finding_id"] = target["finding_id"]
        names = ", ".join(payload.keys())
        binds = ", ".join(f":{name}" for name in payload)
        connection.execute(
            sa.text(f"INSERT INTO assessments ({names}) VALUES ({binds})"),
            payload,
        )
