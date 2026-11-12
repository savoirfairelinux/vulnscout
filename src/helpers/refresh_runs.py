# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Refresh identity and immutable, transaction-local delta snapshots.

Outcomes live in per-source and per-target rows. Every mutation is a single
UPDATE/INSERT scoped to the rows it owns, so a concurrent writer (for example
a queue cancellation while another source commits) can never overwrite
outcomes committed by someone else, and each target result costs one indexed
row update rather than rewriting the whole run.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from typing import Iterator
from functools import wraps
import re
import os
import socket
import time
from pathlib import Path

from sqlalchemy import and_, case, event, exists, insert, select, update
from sqlalchemy.orm import Session

from ..extensions import db, hold_write_lock
from ..models.refresh_run import (
    RefreshChange, RefreshRun, RefreshRunScope, RefreshRunSource, RefreshTarget, RefreshTargetLink,
)
from .history_source import refresh_history

_capture: ContextVar[tuple[str, str] | None] = ContextVar("refresh_run_capture", default=None)

# Identifiers that collide with fixed /api/refresh-runs/<name> routes.
RESERVED_RUN_IDS = frozenset({"latest"})
HEARTBEAT_INTERVAL_SECONDS = 60.0
_CHUNK = 500
_last_heartbeat: dict[str, float] = {}


def _process_start(pid: int) -> str | None:
    try:
        # /proc stat's command may contain spaces and parentheses.
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _write(statement, rows: list[dict] | None = None):
    """Execute a Core write under the session's serialised write transaction."""
    if db.session.get_bind().dialect.name == "sqlite":
        hold_write_lock()
    # Pending provider writes keep their own flush/commit cadence.
    with db.session.no_autoflush:
        if rows is not None:
            return db.session.execute(statement, rows)
        return db.session.execute(statement.execution_options(synchronize_session=False))


def _heartbeat(run_id: str, *, force: bool = False) -> None:
    """Record owner liveness at most once per interval, as a single-column update."""
    now = time.monotonic()
    if not force and now - _last_heartbeat.get(run_id, float("-inf")) < HEARTBEAT_INTERVAL_SECONDS:
        return
    _last_heartbeat[run_id] = now
    _write(
        update(RefreshRun).where(RefreshRun.run_id == run_id)
        .values(last_seen_at=datetime.now(timezone.utc))
    )


def _require_run(run_id: str, message: str) -> None:
    if db.session.scalar(select(RefreshRun.run_id).where(RefreshRun.run_id == run_id)) is None:
        raise ValueError(message)


def reconcile_interrupted_runs() -> None:
    """Reconcile dead local owners, preserving concurrent live CLI/server runs.

    Remote/container owners cannot be probed by PID. Their last committed
    heartbeat expires after a day rather than claiming activity indefinitely.
    """
    now = datetime.now(timezone.utc)
    interrupted_ids = []
    for run_id, owner, last_seen_at in db.session.execute(
        select(RefreshRun.run_id, RefreshRun.owner, RefreshRun.last_seen_at)
        .where(RefreshRun.finished_at.is_(None))
    ):
        interrupted = False
        if owner["host"] == socket.gethostname():
            try:
                os.kill(owner["pid"], 0)
            except ProcessLookupError:
                interrupted = True
            except PermissionError:
                continue
            else:
                current_start = _process_start(owner["pid"])
                interrupted = bool(owner.get("process_start") and current_start
                                   and owner["process_start"] != current_start)
        else:
            interrupted = now - _aware(last_seen_at) > timedelta(days=1)
        if interrupted:
            interrupted_ids.append(run_id)
    for run_id in interrupted_ids:
        _write(
            update(RefreshTarget)
            .where(RefreshTarget.run_id == run_id, RefreshTarget.status == "pending")
            .values(status="failed", error="Refresh owner stopped or its heartbeat expired")
        )
        _write(
            update(RefreshRunSource)
            .where(RefreshRunSource.run_id == run_id, RefreshRunSource.status == "pending")
            .values(status="incomplete")
        )
        _write(
            update(RefreshRun)
            .where(RefreshRun.run_id == run_id, RefreshRun.finished_at.is_(None))
            .values(finished_at=now)
        )
    if interrupted_ids:
        db.session.commit()


def visibility_for(vuln_ids: list[str]) -> dict[str, list[dict]]:
    """Capture only active observed package/variant links, not global package membership."""
    from ..models import Finding, Observation, Package, Scan, Variant
    from .active_scans import active_package_ids_for_scans, active_scan_ids_for_variant

    result: dict[str, list[dict]] = {identifier: [] for identifier in vuln_ids}
    for variant in db.session.scalars(db.select(Variant)).all():
        scans = active_scan_ids_for_variant(variant.id)
        if not scans:
            continue
        package_ids = active_package_ids_for_scans(scans)
        for start in range(0, len(vuln_ids), 500):
            rows = db.session.execute(
                db.select(Finding.vulnerability_id, Package.id, Package.name, Package.version, Package.supplier)
                .select_from(Finding).join(Package).join(Observation).join(Scan)
                .where(Finding.vulnerability_id.in_(vuln_ids[start:start + 500]), Observation.scan_id.in_(scans))
                .where(db.or_(Scan.scan_type.is_(None), Scan.scan_type == "sbom", Finding.package_id.in_(package_ids)))
                .distinct()
            ).all()
            for vuln_id, package_id, name, version, supplier in rows:
                result[vuln_id].append({
                    "package_id": str(package_id), "name": name, "version": version,
                    "package": f"{name}@{version}" + (f"::{supplier}" if supplier else ""),
                    "variant_id": str(variant.id), "project_id": str(variant.project_id),
                })
    return result


def _ensure_source(run_id: str, source: str) -> bool:
    if db.session.get(RefreshRunSource, (run_id, source)) is not None:
        return False
    position = db.session.scalar(
        select(db.func.max(RefreshRunSource.position)).where(RefreshRunSource.run_id == run_id)
    ) or 0
    db.session.add(RefreshRunSource(run_id=run_id, source=source, position=position + 1, status="pending"))
    db.session.flush()
    return True


def _insert_targets(run_id: str, source: str, ids: list[str]) -> int:
    """Insert targets with their captured package links, skipping existing ones."""
    inserted = 0
    for start in range(0, len(ids), _CHUNK):
        chunk = ids[start:start + _CHUNK]
        existing = set(db.session.scalars(select(RefreshTarget.vuln_id).where(
            RefreshTarget.run_id == run_id, RefreshTarget.source == source,
            RefreshTarget.vuln_id.in_(chunk),
        )))
        new_ids = [identifier for identifier in chunk if identifier not in existing]
        if not new_ids:
            continue
        rows = _write(
            insert(RefreshTarget).returning(RefreshTarget.id, RefreshTarget.vuln_id, sort_by_parameter_order=True),
            [{"run_id": run_id, "source": source, "vuln_id": identifier, "status": "pending", "error": None}
             for identifier in new_ids],
        ).all()
        links = visibility_for(new_ids)
        link_rows = [{"target_id": target_id, **package}
                     for target_id, vuln_id in rows for package in links[vuln_id]]
        if link_rows:
            _write(insert(RefreshTargetLink), link_rows)
        inserted += len(rows)
    return inserted


def create_run(targets: dict[str, list[str]], *, run_id: str | None = None,
               scope: dict | None = None) -> str:
    from ..controllers.operation_registry import new_queue_id
    run_id = run_id or new_queue_id()
    # Run identities also populate VulnerabilityHistory.queue_id (VARCHAR(38)).
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,37}", run_id):
        raise ValueError("Invalid run ID: use up to 38 letters, digits, dots, underscores or hyphens")
    if run_id.lower() in RESERVED_RUN_IDS:
        raise ValueError(f"Invalid run ID: '{run_id}' is reserved")
    if db.session.get(RefreshRun, run_id) is not None:
        raise ValueError("Refresh run identity already exists")
    targets = {source: list(dict.fromkeys(ids)) for source, ids in targets.items()}
    now = datetime.now(timezone.utc)
    scope = scope or {"project_id": None, "variant_id": None}
    db.session.add(RefreshRun(
        run_id=run_id, started_at=now, finished_at=None if targets else now, scope=scope,
        owner={"host": socket.gethostname(), "pid": os.getpid(), "process_start": _process_start(os.getpid())},
        last_seen_at=now,
    ))
    db.session.flush()
    pairs = {(entry.get("project_id"), entry.get("variant_id")) for entry in [scope, *scope.get("variants", [])]}
    db.session.add_all(RefreshRunScope(run_id=run_id, project_id=project_id, variant_id=variant_id)
                       for project_id, variant_id in sorted(pairs, key=str) if project_id or variant_id)
    db.session.add_all(RefreshRunSource(run_id=run_id, source=source, position=position, status="pending")
                       for position, source in enumerate(targets, 1))
    db.session.flush()
    for source, identifiers in targets.items():
        _insert_targets(run_id, source, identifiers)
    db.session.commit()
    _last_heartbeat[run_id] = time.monotonic()
    return run_id


def add_targets(run_id: str, source: str, ids: list[str]) -> None:
    _require_run(run_id, "Refresh run unavailable")
    added_source = _ensure_source(run_id, source)
    if _insert_targets(run_id, source, list(dict.fromkeys(ids))) or added_source:
        db.session.commit()


def target_result(source: str, vuln_id: str, status: str = "complete", error: str | None = None) -> None:
    capture = _capture.get()
    if capture is None:
        return
    result = _write(
        update(RefreshTarget)
        .where(RefreshTarget.run_id == capture[0], RefreshTarget.source == source,
               RefreshTarget.vuln_id == vuln_id)
        .values(status=status, error=error)
    )
    if not result.rowcount:  # type: ignore[attr-defined]
        _require_run(capture[0], "Refresh artifact disappeared during execution")
    _heartbeat(capture[0])


def finish_source(run_id: str, source: str, status: str = "failed", error: str | None = None) -> None:
    """Settle one source atomically; other sources' committed outcomes are never rewritten."""
    _require_run(run_id, "Refresh artifact unavailable")
    _write(
        update(RefreshTarget)
        .where(RefreshTarget.run_id == run_id, RefreshTarget.source == source,
               RefreshTarget.status == "pending")
        .values(status=status, error=error or "Target was not checked")
    )
    # Lock the parent before changing sources or deciding whether all have settled.
    _heartbeat(run_id, force=True)
    _ensure_source(run_id, source)
    unchecked = exists().where(RefreshTarget.run_id == run_id, RefreshTarget.source == source,
                               RefreshTarget.status != "complete")
    _write(
        update(RefreshRunSource)
        .where(RefreshRunSource.run_id == run_id, RefreshRunSource.source == source)
        .values(status=case(
            (and_(RefreshRunSource.status != "incomplete", ~unchecked), "complete"), else_="incomplete",
        ) if status == "failed" and error is None else "incomplete")
    )
    now = datetime.now(timezone.utc)
    pending = exists().where(RefreshRunSource.run_id == run_id, RefreshRunSource.status == "pending")
    finished = _write(
        update(RefreshRun)
        .where(RefreshRun.run_id == run_id, RefreshRun.finished_at.is_(None), ~pending)
        .values(finished_at=now)
    ).rowcount
    db.session.commit()
    if finished:
        _last_heartbeat.pop(run_id, None)


def source_statuses(run_id: str) -> dict[str, str]:
    """Source outcomes in the order the run declared its sources."""
    return {source: status for source, status in db.session.execute(
        select(RefreshRunSource.source, RefreshRunSource.status)
        .where(RefreshRunSource.run_id == run_id).order_by(RefreshRunSource.position)
    )}


@contextmanager
def capture_source(run_id: str, source: str) -> Iterator[None]:
    token = _capture.set((run_id, source))
    try:
        with refresh_history(source, run_id):
            yield
    finally:
        _capture.reset(token)


def tracked_refresh(source: str):
    """Capture a source execution, including failures otherwise swallowed by providers."""
    def decorate(function):
        @wraps(function)
        def execute(ctx):
            from ..controllers.job_context import CancelledError
            run_id = ctx.queue_id
            if run_id is None:
                run_id = create_run({source: list(ctx.options.get("ids", []))})
                ctx.queue_id = run_id
            elif db.session.get(RefreshRun, run_id) is None:
                create_run({source: list(ctx.options.get("ids", []))}, run_id=run_id)
            try:
                add_targets(run_id, source, list(ctx.options.get("ids", [])))
                db.session.commit()
                with capture_source(run_id, source):
                    result = function(ctx)
                    db.session.commit()
            except BaseException as exc:
                db.session.rollback()
                finish_source(run_id, source, "cancelled" if isinstance(exc, CancelledError) else "failed",
                              "Cancelled" if isinstance(exc, CancelledError) else "Source refresh failed")
                raise
            else:
                finish_source(run_id, source)
                return result
        return execute
    return decorate


def tracked_single_refresh(source: str):
    """Keep existing single-refresh responses while exposing exact artifact identity."""
    def decorate(function):
        @wraps(function)
        def execute(*args, **kwargs):
            from flask import make_response, request
            from ..models.vulnerability import Vulnerability
            identifier = (args[0] if args else next(iter(kwargs.values()))).upper()
            if db.session.get(Vulnerability, identifier) is None:
                return function(*args, **kwargs)
            scope = {key: request.args.get(key) for key in ("project_id", "variant_id")}
            if any(scope.values()):
                from flask import abort
                links = visibility_for([identifier])[identifier]
                if not any(all(not scope[key] or entry[key] == scope[key]
                               for key in ("project_id", "variant_id")) for entry in links):
                    abort(404, description="Vulnerability outside selected scope")
            run_id = create_run({source: [identifier]}, scope=scope)
            try:
                with capture_source(run_id, source):
                    response = make_response(function(*args, **kwargs))
                    target_result(source, identifier, "complete" if response.status_code < 400 else "failed",
                                  None if response.status_code < 400 else f"HTTP {response.status_code}")
                    db.session.commit()
            except BaseException:
                db.session.rollback()
                finish_source(run_id, source, error="Single refresh failed")
                raise
            finish_source(run_id, source)
            response.headers["X-Refresh-Run-ID"] = run_id
            return response
        return execute
    return decorate


def capture_changes(session, rows: list[dict]) -> None:
    """Called after flush: snapshots share the originating write's transaction."""
    capture = _capture.get()
    if capture is None or not rows:
        return
    from ..models.metrics import Metrics
    from ..models.vulnerability import Vulnerability
    from ..models.vulnerability_history import CVSS_FIELD_PREFIX, cvss_field, normalize_value
    import uuid

    connection = session.connection()
    vuln_ids = list({row["vuln_id"] for row in rows})
    target_ids = dict(connection.execute(
        select(RefreshTarget.vuln_id, RefreshTarget.id).where(
            RefreshTarget.run_id == capture[0], RefreshTarget.source == capture[1],
            RefreshTarget.vuln_id.in_(vuln_ids),
        )
    ).all())
    snapshots = []
    for row in rows:
        field = row["field"]
        if field.startswith(CVSS_FIELD_PREFIX):
            metric_id = field.rsplit(":", 1)[1]
            metric = connection.execute(
                select(Metrics.version, Metrics.author, Metrics.score, Metrics.vector)
                .where(Metrics.id == uuid.UUID(metric_id))
            ).first()
            after = (
                {"score": float(metric.score), "vector": metric.vector or None}
                if metric and cvss_field(metric.version, metric.author, metric_id) == field else None
            )
        else:
            after = normalize_value(connection.execute(
                select(getattr(Vulnerability, field)).where(Vulnerability.id == row["vuln_id"])
            ).scalar_one_or_none())
        before = session.info.get("refresh_before", {}).get((row["vuln_id"], field), row["old_value"])
        if before == after:
            continue
        kind = "first_enrichment" if before is None else "changed"
        snapshots.append({
            "run_id": capture[0], "target_id": target_ids.get(row["vuln_id"]),
            "vuln_id": row["vuln_id"], "source": capture[1], "field": field, "kind": kind,
            "change_type": "addition" if before is None else "removal" if after is None else "modification",
            "snapshot": {
                "vuln_id": row["vuln_id"], "source": capture[1], "field": field,
                "before": before, "after": after, "kind": kind,
                "changed_at": row["changed_at"].isoformat(),
            },
        })
    if snapshots:
        connection.execute(insert(RefreshChange), snapshots)


@event.listens_for(Session, "before_flush")
def _capture_persisted_before(session, _flush_context, _instances):
    """Lock rows in model/primary-key order and read their actual predecessors.

    An ORM instance may have been loaded before another refresh committed.
    Its attribute history is then insufficient evidence of the value replaced.
    """
    session.info.pop("refresh_before", None)
    if _capture.get() is None:
        return
    from ..models.metrics import Metrics
    from ..models.vulnerability import Vulnerability
    from ..models.vulnerability_history import TRACKED_FIELDS, cvss_field, cvss_value, normalize_value
    before = {}
    connection = session.connection()
    vuln_ids = [obj.id for obj in session.dirty if isinstance(obj, Vulnerability)]
    if vuln_ids:
        columns = [getattr(Vulnerability, field) for field in TRACKED_FIELDS]
        # NO KEY UPDATE excludes competing writes without blocking history FK checks.
        rows = connection.execute(
            select(Vulnerability.id, *columns).where(Vulnerability.id.in_(vuln_ids))
            .order_by(Vulnerability.id).with_for_update(key_share=True)
        )
        for row in rows:
            before.update({(row.id, field): normalize_value(value) for field, value in zip(TRACKED_FIELDS, row[1:])})
    metric_ids = [obj.id for obj in list(session.dirty) + list(session.deleted) if isinstance(obj, Metrics)]
    if metric_ids:
        rows = connection.execute(select(
            Metrics.id, Metrics.vulnerability_id, Metrics.variant_id,
            Metrics.version, Metrics.author, Metrics.score, Metrics.vector,
        ).where(Metrics.id.in_(metric_ids)).order_by(Metrics.id).with_for_update(key_share=True))
        for row in rows:
            if row.variant_id is None:
                before[(row.vulnerability_id, cvss_field(row.version, row.author, row.id))] = (
                    cvss_value(row.score, row.vector)
                )
    session.info["refresh_before"] = before
