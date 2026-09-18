# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Unified operation queue API.

One endpoint enqueues any mix of scans and vulnerability refreshes; progress is
delivered exclusively through ``/api/events/stream``.
"""

from __future__ import annotations

import threading
import uuid as uuid_module
from typing import Dict, List, Tuple

from flask import Flask, jsonify, request
from flask.typing import ResponseReturnValue

from ..controllers.job_context import JobContext
from ..controllers.operation_queue import queue
from ..controllers.operation_registry import (
    KIND_REFRESH,
    KIND_SCAN,
    LANE_PIPELINE,
    new_queue_id,
    registry,
)
from ..controllers.refresh_jobs import (
    MAX_CVE_IDS,
    MAX_GHSA_IDS,
    REFRESH_JOBS,
    known_cve_ids,
    normalise_cve_ids,
    normalise_ghsa_ids,
    run_deferred_refresh,
)
from ..controllers.scan_jobs import SCAN_JOBS
from ..controllers.variants import VariantController

SCAN_LABELS = {
    "grype": "Grype",
    "nvd": "NVD CPE",
    "osv": "OSV PURL",
    "scc": "sbom-cve-check",
}

REFRESH_LABELS = {
    "nvd": "NVD",
    "epss": "EPSS",
    "ghsa": "GHSA",
    "euvd": "ENISA EUVD",
}

# The order the frontend used to enforce by awaiting each manager in turn.
SCAN_ORDER = ["grype", "nvd", "osv", "scc"]
REFRESH_ORDER = ["nvd", "epss", "ghsa", "euvd"]

VALID_MODES = ("local", "api")

# Serialises the conflict check and the registry writes so two simultaneous
# requests cannot both pass the check and double-submit the same operation.
_enqueue_lock = threading.Lock()


def scan_op_id(source: str, variant_id: str) -> str:
    return f"scan:{source}:{variant_id}"


def refresh_op_id(source: str) -> str:
    return f"refresh:{source}"


class _PlanError(Exception):
    """Rejects a batch before anything is queued."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


def _job_options(job: dict) -> dict:
    options = job.get("options")
    if options is None:
        return {}
    if not isinstance(options, dict):
        raise _PlanError("options must be an object")
    return options


def _mode_option(options: dict) -> str:
    mode = options.get("mode", "local")
    if mode not in VALID_MODES:
        raise _PlanError(f"Unsupported mode: {mode}")
    return mode


def _bool_option(options: dict, key: str, default: bool) -> bool:
    value = options.get(key, default)
    if not isinstance(value, bool):
        raise _PlanError(f"{key} must be a boolean")
    return value


def _plan_scan_job(job: dict) -> List[dict]:
    source = job.get("source")
    if source not in SCAN_JOBS:
        raise _PlanError(f"Unknown scan source: {source}")

    variant_ids = job.get("variant_ids") or []
    if not isinstance(variant_ids, list) or not variant_ids:
        raise _PlanError(f"{source} scan requires a non-empty variant_ids list")

    options = _job_options(job)
    mode = _mode_option(options)
    exclude_kernel = _bool_option(options, "exclude_kernel", True)
    planned: List[dict] = []
    for raw_id in variant_ids:
        try:
            variant_uuid = uuid_module.UUID(str(raw_id))
        except (ValueError, AttributeError):
            raise _PlanError(f"Invalid variant id: {raw_id}")
        variant = VariantController.get(variant_uuid)
        if variant is None:
            raise _PlanError(f"Variant not found: {raw_id}", status=404)

        planned.append({
            "op_id": scan_op_id(source, str(variant_uuid)),
            "kind": KIND_SCAN,
            "source": source,
            "label": SCAN_LABELS[source],
            "lane": LANE_PIPELINE,
            "scope": {
                "variant_id": str(variant_uuid),
                "variant_name": variant.name,
                "project_id": str(variant.project_id),
            },
            "options": {
                "variant_id": str(variant_uuid),
                "exclude_kernel": exclude_kernel,
                "mode": mode,
            },
            "runner": SCAN_JOBS[source],
        })
    return planned


def _deferred_refresh_options(source: str, job: dict, mode: str) -> dict:
    if job.get("ids") is not None:
        raise _PlanError("refresh jobs cannot specify both ids and variant_ids")
    raw_variant_ids = job.get("variant_ids")
    if not isinstance(raw_variant_ids, list) or not raw_variant_ids:
        raise _PlanError(f"{source} deferred refresh requires variant_ids")

    variant_ids: List[str] = []
    for raw_id in raw_variant_ids:
        try:
            variant_uuid = uuid_module.UUID(str(raw_id))
        except (ValueError, AttributeError):
            raise _PlanError(f"Invalid variant id: {raw_id}")
        if VariantController.get(variant_uuid) is None:
            raise _PlanError(f"Variant not found: {raw_id}", status=404)
        variant_ids.append(str(variant_uuid))

    exclude_ids = (
        normalise_ghsa_ids(job.get("exclude_ids", []))
        if source == "ghsa"
        else normalise_cve_ids(job.get("exclude_ids", []))
    )
    return {
        "ids": [],
        "mode": mode,
        "source": source,
        "variant_ids": variant_ids,
        "exclude_ids": exclude_ids,
    }


def _explicit_refresh_options(source: str, job: dict, mode: str) -> dict:
    if source == "ghsa":
        ids = normalise_ghsa_ids(job.get("ids"))
        if not ids:
            raise _PlanError("ghsa refresh requires valid GHSA identifiers")
        if len(ids) > MAX_GHSA_IDS:
            raise _PlanError(f"ghsa refresh accepts at most {MAX_GHSA_IDS} identifiers")
        return {"ids": ids, "mode": mode}

    ids = normalise_cve_ids(job.get("ids"))
    if not ids:
        raise _PlanError(f"{source} refresh requires valid CVE identifiers")
    if source == "nvd" and mode == "api" and len(ids) > MAX_CVE_IDS:
        raise _PlanError(
            f"nvd refresh accepts at most {MAX_CVE_IDS} identifiers in api mode"
        )
    if source == "epss":
        ids = known_cve_ids(ids)
        if not ids:
            raise _PlanError("epss refresh requires at least one known CVE identifier")
    return {"ids": ids, "mode": mode}


def _plan_refresh_job(job: dict) -> List[dict]:
    source = job.get("source")
    if source not in REFRESH_JOBS:
        raise _PlanError(f"Unknown refresh source: {source}")

    options = _job_options(job)
    mode = _mode_option(options)
    deferred = job.get("variant_ids") is not None
    job_options = (
        _deferred_refresh_options(source, job, mode)
        if deferred
        else _explicit_refresh_options(source, job, mode)
    )

    return [{
        "op_id": refresh_op_id(source),
        "kind": KIND_REFRESH,
        "source": source,
        "label": REFRESH_LABELS[source],
        "lane": LANE_PIPELINE,
        "scope": None,
        "options": job_options,
        "runner": run_deferred_refresh if deferred else REFRESH_JOBS[source],
    }]


def _plan(jobs: List[dict]) -> List[dict]:
    """Expand the requested jobs into individual operations, in execution order."""
    scans: Dict[str, List[dict]] = {}
    refreshes: Dict[str, List[dict]] = {}

    for job in jobs:
        if not isinstance(job, dict):
            raise _PlanError("Each job must be an object")
        kind = job.get("kind")
        if kind == KIND_SCAN:
            scans.setdefault(str(job.get("source")), []).extend(_plan_scan_job(job))
        elif kind == KIND_REFRESH:
            refreshes.setdefault(str(job.get("source")), []).extend(_plan_refresh_job(job))
        else:
            raise _PlanError(f"Unsupported job kind: {kind}")

    planned: List[dict] = []
    for source in SCAN_ORDER:
        planned.extend(scans.get(source, []))
    for source in REFRESH_ORDER:
        planned.extend(refreshes.get(source, []))
    return planned


def _conflicts(planned: List[dict]) -> List[str]:
    return [item["op_id"] for item in planned if registry.has_active(item["op_id"])]


def _duplicates(planned: List[dict]) -> List[str]:
    seen: set = set()
    duplicated: List[str] = []
    for item in planned:
        if item["op_id"] in seen:
            duplicated.append(item["op_id"])
        seen.add(item["op_id"])
    return duplicated


class _ConflictError(Exception):
    """Raised when a requested operation is already queued or running."""

    def __init__(self, operations: List[str]) -> None:
        super().__init__("conflicting operations")
        self.operations = operations


def _enqueue(planned: List[dict]) -> Tuple[str, List[dict]]:
    queue_id = new_queue_id()
    created: List[dict] = []
    for position, item in enumerate(planned, 1):
        operation = registry.create(
            op_id=item["op_id"],
            kind=item["kind"],
            source=item["source"],
            label=item["label"],
            lane=item["lane"],
            scope=item["scope"],
            queue_id=queue_id,
            position=position,
            options=item["options"],
            cancellable=True,
        )
        created.append(operation)
        queue.submit(
            op_id=item["op_id"],
            lane=item["lane"],
            runner=item["runner"],
            ctx=JobContext(item["op_id"], item["options"]),
        )
    return queue_id, created


def _enqueue_exclusively(planned: List[dict]) -> Tuple[str, List[dict]]:
    """Conflict check and registry writes under one lock, so concurrent
    requests cannot both pass the check and double-submit an operation."""
    with _enqueue_lock:
        conflicting = _conflicts(planned)
        if conflicting:
            raise _ConflictError(conflicting)
        return _enqueue(planned)


def _cancel_operation_response(op_id: str) -> ResponseReturnValue:
    operation = registry.get(op_id)
    if operation is not None and not operation.get("cancellable", False):
        return jsonify({"error": "This operation does not support cancellation"}), 409
    if queue.cancel(op_id):
        return jsonify({"status": "cancelling", "op_id": op_id}), 200
    return jsonify({"error": "No active operation with that id"}), 404


def init_app(app: Flask) -> None:

    @app.route('/api/operations', methods=['POST'])
    def enqueue_operations() -> ResponseReturnValue:
        """Queue a batch of scans and vulnerability refreshes.

        Body: ``{"jobs": [{"kind": "scan", "source": "grype",
        "variant_ids": [...], "options": {...}}, ...]}``

        Scans run before refreshes and each family keeps its canonical order, so
        one request reproduces the whole pipeline. Progress is published on
        ``/api/events/stream``; there is no status endpoint to poll.

        OpenAPI:
        body JsonObject optional Batch of jobs to queue.
        response 202 JsonObject Queue accepted with the created operations.
        response 400 Error Invalid job specification.
        response 404 Error Referenced variant not found.
        response 409 Error One of the requested operations is already active.
        """
        body = request.get_json(force=True, silent=True) or {}
        jobs = body.get("jobs")
        if not isinstance(jobs, list) or not jobs:
            return jsonify({"error": "jobs must be a non-empty list"}), 400

        try:
            planned = _plan(jobs)
        except _PlanError as error:
            return jsonify({"error": error.message}), error.status

        if not planned:
            return jsonify({"error": "jobs produced no operations"}), 400

        duplicated = _duplicates(planned)
        if duplicated:
            return jsonify({
                "error": "jobs contain duplicate operations",
                "operations": duplicated,
            }), 400

        try:
            queue_id, created = _enqueue_exclusively(planned)
        except _ConflictError as conflict:
            return jsonify({
                "error": "Some requested operations are already queued or running",
                "operations": conflict.operations,
            }), 409
        return jsonify({"queue_id": queue_id, "operations": created}), 202

    @app.route('/api/operations', methods=['GET'])
    def list_operations() -> ResponseReturnValue:
        """Return every tracked operation.

        The SSE stream sends the same payload as its first frame; this endpoint
        exists for clients that cannot hold a stream open and for diagnostics.

        OpenAPI:
        response 200 JsonObject Current operation snapshot.
        """
        return jsonify({"operations": registry.snapshot()})

    @app.route('/api/operations/<path:op_id>/cancel', methods=['POST'])
    def cancel_operation(op_id: str) -> ResponseReturnValue:
        """Cancel a queued or running operation.

        Queued work is dropped without starting; running work receives a
        cooperative stop signal that its job body honours at the next checkpoint.

        OpenAPI:
        response 200 JsonObject Cancellation accepted.
        response 404 Error No such active operation.
        """
        return _cancel_operation_response(op_id)

    @app.route('/api/operations/queue/<queue_id>/cancel', methods=['POST'])
    def cancel_operation_queue(queue_id: str) -> ResponseReturnValue:
        """Cancel every still-active operation in a batch.

        OpenAPI:
        response 200 JsonObject Number of operations cancelled.
        """
        return jsonify({"cancelled": queue.cancel_queue(queue_id)}), 200

    @app.route('/api/operations/<path:op_id>', methods=['DELETE'])
    def dismiss_operation(op_id: str) -> ResponseReturnValue:
        """Forget a finished operation so it disappears from every client.

        OpenAPI:
        response 200 JsonObject Operation dismissed.
        response 409 Error Operation is still active.
        """
        if registry.remove(op_id):
            return jsonify({"status": "dismissed", "op_id": op_id}), 200
        return jsonify({"error": "Operation is unknown or still active"}), 409
