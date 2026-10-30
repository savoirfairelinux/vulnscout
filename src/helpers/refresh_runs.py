# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Refresh identity and immutable, transaction-local delta snapshots."""

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Iterator
from uuid import uuid4
from functools import wraps
import re
import os
import socket
from pathlib import Path

from sqlalchemy import event, insert
from sqlalchemy.orm import Session

from ..extensions import db
from ..models.refresh_run import RefreshChange, RefreshRun
from .history_source import history_operation, history_source

_capture: ContextVar[tuple[str, str] | None] = ContextVar("refresh_run_capture", default=None)


def _process_start(pid: int) -> str | None:
    try:
        # /proc stat's command may contain spaces and parentheses.
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def reconcile_interrupted_runs() -> None:
    """Reconcile dead local owners, preserving concurrent live CLI/server runs.

    Remote/container owners cannot be probed by PID. Their last committed
    heartbeat expires after a day rather than claiming activity indefinitely.
    """
    from datetime import timedelta
    changed = False
    now = datetime.now(timezone.utc)
    for run in db.session.scalars(db.select(RefreshRun).where(RefreshRun.finished_at.is_(None))):
        owner = run.owner
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
            interrupted = now - datetime.fromisoformat(owner["last_seen_at"]) > timedelta(days=1)
        if not interrupted:
            continue
        run.coverage = [
            {**entry, "status": "failed", "error": "Refresh owner stopped or its heartbeat expired"}
            if entry["status"] == "pending" else entry for entry in run.coverage
        ]
        run.source_status = {source: "incomplete" if status == "pending" else status
                             for source, status in run.source_status.items()}
        run.finished_at = now
        changed = True
    if changed:
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
                db.select(Finding.vulnerability_id, Package)
                .select_from(Finding).join(Package).join(Observation).join(Scan)
                .where(Finding.vulnerability_id.in_(vuln_ids[start:start + 500]), Observation.scan_id.in_(scans))
                .where(db.or_(Scan.scan_type.is_(None), Scan.scan_type == "sbom", Finding.package_id.in_(package_ids)))
                .distinct()
            ).all()
            for vuln_id, package in rows:
                result[vuln_id].append({
                    "package_id": str(package.id), "name": package.name, "version": package.version,
                    "package": package.string_id,
                    "variant_id": str(variant.id), "project_id": str(variant.project_id),
                })
    return result


def create_run(targets: dict[str, list[str]], *, run_id: str | None = None,
               scope: dict | None = None) -> str:
    run_id = run_id or str(uuid4())
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", run_id):
        raise ValueError("Invalid run ID: use up to 128 letters, digits, dots, underscores or hyphens")
    if db.session.get(RefreshRun, run_id) is not None:
        raise ValueError("Refresh run identity already exists")
    targets = {source: list(dict.fromkeys(ids)) for source, ids in targets.items()}
    links = visibility_for(list(dict.fromkeys(identifier for ids in targets.values() for identifier in ids)))
    run = RefreshRun(
        run_id=run_id, started_at=datetime.now(timezone.utc),
        finished_at=None if targets else datetime.now(timezone.utc),
        scope=scope or {"project_id": None, "variant_id": None},
        sources=list(targets),
        source_status={source: "pending" for source in targets},
        owner={"host": socket.gethostname(), "pid": os.getpid(),
               "process_start": _process_start(os.getpid()),
               "last_seen_at": datetime.now(timezone.utc).isoformat()},
        coverage=[
            {"source": source, "vuln_id": identifier, "status": "pending", "error": None,
             "packages": links[identifier]}
            for source, identifiers in targets.items() for identifier in identifiers
        ],
    )
    db.session.add(run)
    db.session.commit()
    return run_id


def add_targets(run_id: str, source: str, ids: list[str]) -> None:
    run = db.session.get(RefreshRun, run_id)
    if run is None:
        raise ValueError("Refresh run unavailable")
    existing = {(entry["source"], entry["vuln_id"]) for entry in run.coverage}
    new_ids = [identifier for identifier in dict.fromkeys(ids) if (source, identifier) not in existing]
    if not new_ids:
        return
    links = visibility_for(new_ids) if new_ids else {}
    run.coverage = run.coverage + [
        {"source": source, "vuln_id": identifier, "status": "pending", "error": None,
         "packages": links[identifier]}
        for identifier in new_ids
    ]
    db.session.commit()


def target_result(source: str, vuln_id: str, status: str = "complete", error: str | None = None) -> None:
    capture = _capture.get()
    if capture is None:
        return
    run = db.session.get(RefreshRun, capture[0])
    if run is None:
        raise ValueError("Refresh artifact disappeared during execution")
    run.coverage = [
        {**entry, "status": status, "error": error}
        if entry["source"] == source and entry["vuln_id"] == vuln_id else entry
        for entry in run.coverage
    ]
    run.owner = {**run.owner, "last_seen_at": datetime.now(timezone.utc).isoformat()}


def finish_source(run_id: str, source: str, status: str = "failed", error: str | None = None) -> None:
    run = db.session.get(RefreshRun, run_id)
    if run is None:
        raise ValueError("Refresh artifact unavailable")
    run.coverage = [
        {**entry, "status": status, "error": error or "Target was not checked"}
        if entry["source"] == source and entry["status"] == "pending" else entry
        for entry in run.coverage
    ]
    source_entries = [entry for entry in run.coverage if entry["source"] == source]
    run.source_status = {**run.source_status, source: (
        "complete" if status == "failed" and error is None
        and all(entry["status"] == "complete" for entry in source_entries)
        and run.source_status.get(source) != "incomplete"
        else "incomplete"
    )}
    run.owner = {**run.owner, "last_seen_at": datetime.now(timezone.utc).isoformat()}
    if all(value != "pending" for value in run.source_status.values()):
        run.finished_at = datetime.now(timezone.utc)
    db.session.commit()


@contextmanager
def capture_source(run_id: str, source: str, operation_id: str | None = None) -> Iterator[None]:
    token = _capture.set((run_id, source))
    try:
        with history_operation(run_id, operation_id or source), history_source(source):
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
            add_targets(run_id, source, list(ctx.options.get("ids", [])))
            try:
                with capture_source(run_id, source, ctx.op_id):
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
    from ..models.vulnerability_history import CVSS_FIELD_PREFIX, normalize_value

    connection = session.connection()
    coverage = connection.execute(
        db.select(RefreshRun.coverage).where(RefreshRun.run_id == capture[0])
    ).scalar_one()
    snapshots = []
    for row in rows:
        field = row["field"]
        if field.startswith(CVSS_FIELD_PREFIX):
            metric_id = field.rsplit(":", 1)[1]
            import uuid
            metric = connection.execute(
                db.select(Metrics.version, Metrics.author, Metrics.score, Metrics.vector)
                .where(Metrics.id == uuid.UUID(metric_id))
            ).first()
            from ..models.vulnerability_history import cvss_field
            after = (
                {"score": float(metric.score), "vector": metric.vector or None}
                if metric and cvss_field(metric.version, metric.author, metric_id) == field else None
            )
        else:
            after = normalize_value(connection.execute(
                db.select(getattr(Vulnerability, field)).where(Vulnerability.id == row["vuln_id"])
            ).scalar_one_or_none())
        packages: list[dict] = next((entry["packages"] for entry in coverage
                                    if entry["source"] == capture[1] and entry["vuln_id"] == row["vuln_id"]), [])
        before = session.info.get("refresh_before", {}).get((row["vuln_id"], field), row["old_value"])
        if before == after:
            continue
        snapshots.append({"run_id": capture[0], "snapshot": {
            "vuln_id": row["vuln_id"], "source": capture[1], "field": field,
            "before": before, "after": after,
            "kind": "first_enrichment" if before is None else "changed",
            "changed_at": row["changed_at"].isoformat(), "packages": packages,
        }})
    if snapshots:
        connection.execute(insert(RefreshChange), snapshots)


@event.listens_for(Session, "before_flush")
def _capture_persisted_before(session, _flush_context, _instances):
    """Read the actual predecessor while holding the existing session write lock.

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
    for obj in session.dirty:
        if isinstance(obj, Vulnerability):
            columns = [getattr(Vulnerability, field) for field in TRACKED_FIELDS]
            row = connection.execute(db.select(*columns).where(Vulnerability.id == obj.id)).first()
            if row:
                before.update({(obj.id, field): normalize_value(value) for field, value in zip(TRACKED_FIELDS, row)})
    for obj in list(session.dirty) + list(session.deleted):
        if isinstance(obj, Metrics):
            row = connection.execute(db.select(
                Metrics.vulnerability_id, Metrics.variant_id,
                Metrics.version, Metrics.author, Metrics.score, Metrics.vector,
            ).where(Metrics.id == obj.id)).first()
            if row and row.variant_id is None:
                before[(row.vulnerability_id, cvss_field(row.version, row.author, obj.id))] = (
                    cvss_value(row.score, row.vector)
                )
    session.info["refresh_before"] = before
