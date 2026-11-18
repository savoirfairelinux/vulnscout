"""Record which refresh source each initiating run scope applies to."""
import json

from alembic import op
import sqlalchemy as sa

revision = "e7a4c91b2d35"
down_revision = "df135a79b246"
branch_labels = None
depends_on = None

BATCH = 200


def upgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("refresh_run_scopes")}
    if "source" not in columns:
        op.add_column("refresh_run_scopes", sa.Column("source", sa.String(16), nullable=True))
    # Retained batches with per-provider scopes previously stored only the merged variants.
    # Only those rows are read, in bounded keyset pages, because history may be large.
    bind = op.get_bind()
    scopes = sa.table("refresh_run_scopes", sa.column("run_id"), sa.column("project_id"),
                      sa.column("variant_id"), sa.column("source"))
    runs = sa.table("refresh_runs", sa.column("run_id"), sa.column("scope", sa.JSON))
    last = ""
    while True:
        page = bind.execute(
            sa.select(runs.c.run_id, runs.c.scope)
            .where(runs.c.run_id > last, sa.cast(runs.c.scope, sa.Text).like('%"source_scopes"%'))
            .order_by(runs.c.run_id).limit(BATCH)
        ).all()
        if not page:
            break
        for run_id, scope in page:
            last = run_id
            if isinstance(scope, str):
                scope = json.loads(scope)
            source_scopes = (scope or {}).get("source_scopes")
            if not source_scopes:
                continue
            bind.execute(sa.delete(scopes).where(scopes.c.run_id == run_id))
            for source, item in source_scopes.items():
                pairs = {(entry.get("project_id"), entry.get("variant_id"))
                         for entry in [item, *item.get("variants", [])]}
                for project_id, variant_id in sorted(pairs, key=str):
                    if project_id or variant_id:
                        bind.execute(sa.insert(scopes).values(
                            run_id=run_id, project_id=project_id, variant_id=variant_id, source=source))


def downgrade():
    with op.batch_alter_table("refresh_run_scopes") as batch:
        batch.drop_column("source")
