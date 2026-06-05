"""add variant_id to metrics and backfill legacy CVSS rows

Revision ID: l8a9b0c1d2e3
Revises: k7f8a9b0c1d2
Create Date: 2026-05-26 00:00:00.000000
"""

import uuid

from alembic import op
import sqlalchemy as sa

revision = 'l8a9b0c1d2e3'
down_revision = 'k7f8a9b0c1d2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('metrics', schema=None) as batch_op:
        batch_op.add_column(sa.Column('variant_id', sa.Uuid(), nullable=True))
        batch_op.create_index('ix_metrics_variant_id', ['variant_id'], unique=False)
        batch_op.create_foreign_key('fk_metrics_variant_id_variants', 'variants', ['variant_id'], ['id'])

    conn = op.get_bind()

    legacy_rows = conn.execute(
        sa.text(
            """
            SELECT id, vulnerability_id, version, score, vector, author
            FROM metrics
            WHERE variant_id IS NULL
            """
        )
    ).fetchall()

    for row in legacy_rows:
        related_variants = conn.execute(
            sa.text(
                """
                SELECT DISTINCT s.variant_id
                FROM findings f
                JOIN observations o ON o.finding_id = f.id
                JOIN scans s ON s.id = o.scan_id
                WHERE f.vulnerability_id = :vulnerability_id
                """
            ),
            {"vulnerability_id": row.vulnerability_id},
        ).fetchall()

        if not related_variants:
            continue

        inserted_any = False
        for variant_row in related_variants:
            variant_id = variant_row.variant_id
            exists = conn.execute(
                sa.text(
                    """
                    SELECT 1
                    FROM metrics
                    WHERE vulnerability_id = :vulnerability_id
                      AND variant_id = :variant_id
                      AND (version = :version OR (version IS NULL AND :version IS NULL))
                      AND (score = :score OR (score IS NULL AND :score IS NULL))
                      AND (vector = :vector OR (vector IS NULL AND :vector IS NULL))
                      AND (author = :author OR (author IS NULL AND :author IS NULL))
                    LIMIT 1
                    """
                ),
                {
                    "vulnerability_id": row.vulnerability_id,
                    "variant_id": variant_id,
                    "version": row.version,
                    "score": row.score,
                    "vector": row.vector,
                    "author": row.author,
                },
            ).fetchone()
            if exists:
                inserted_any = True
                continue

            conn.execute(
                sa.text(
                    """
                    INSERT INTO metrics (id, vulnerability_id, variant_id, version, score, vector, author)
                    VALUES (:id, :vulnerability_id, :variant_id, :version, :score, :vector, :author)
                    """
                ),
                {
                    "id": str(uuid.uuid4()),
                    "vulnerability_id": row.vulnerability_id,
                    "variant_id": variant_id,
                    "version": row.version,
                    "score": row.score,
                    "vector": row.vector,
                    "author": row.author,
                },
            )
            inserted_any = True

        if inserted_any:
            conn.execute(
                sa.text("DELETE FROM metrics WHERE id = :id"),
                {"id": row.id},
            )


def downgrade():
    with op.batch_alter_table('metrics', schema=None) as batch_op:
        batch_op.drop_constraint('fk_metrics_variant_id_variants', type_='foreignkey')
        batch_op.drop_index('ix_metrics_variant_id')
        batch_op.drop_column('variant_id')
