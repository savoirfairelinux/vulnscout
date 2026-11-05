# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Refresh artifacts are exact, immutable, scoped, and honest about coverage."""

import csv
import io
import json
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from src.bin.webapp import create_app
from src.controllers.job_context import CancelledError, JobContext
from src.controllers.refresh_jobs import run_epss_refresh
from src.extensions import db
from src.helpers.refresh_runs import capture_source, create_run, finish_source, target_result
from src.models import Finding, Observation, Project, Scan, Variant, Vulnerability
from src.models.metrics import Metrics
from src.models.refresh_run import RefreshRun
from sqlalchemy import event
from sqlalchemy.orm import Session
from . import setup_demo_db

CVE = "CVE-2020-35492"
PROJECT = "11111111-1111-1111-1111-111111111111"
VARIANT = "22222222-2222-2222-2222-222222222222"


@pytest.fixture()
def app(monkeypatch, tmp_path):
    (tmp_path / "status").write_text("__END_OF_SCAN_SCRIPT__")
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", os.getenv(
        "VULNSCOUT_TEST_POSTGRES_URI", f"sqlite:///{tmp_path / 'database.db'}",
    ))
    monkeypatch.setenv("FLASK_TESTING", "true")
    monkeypatch.setenv("FLASK_SCAN_FILE", str(tmp_path / "status"))
    application = create_app()
    setup_demo_db(application)
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


def _change(run_id, score, *, source="epss"):
    with capture_source(run_id, source):
        record = db.session.get(Vulnerability, CVE)
        record.epss_score = score
        target_result(source, CVE)
        db.session.commit()


def test_exact_run_is_immutable_and_latest_uses_coverage_even_unchanged(app, client):
    with app.app_context():
        first = create_run({"epss": [CVE]}, run_id="first")
        _change(first, 0.4)
        finish_source(first, "epss")
    frozen = client.get("/api/refresh-runs/first").get_json()
    with app.app_context():
        second = create_run({"epss": [CVE]}, run_id="second")
        _change(second, 0.4)
        finish_source(second, "epss")
        record = db.session.get(Vulnerability, CVE)
        record.epss_score = 0.99
        db.session.commit()
    assert client.get("/api/refresh-runs/first").get_json() == frozen
    latest = client.get("/api/refresh-runs/latest", query_string={"vuln_id": CVE, "project_id": PROJECT}).get_json()
    assert latest["run_id"] == second
    assert latest["status"] == "complete"
    assert latest["changes"] == []
    assert latest["coverage"][0]["status"] == "complete"
    assert frozen["changes"][0]["before"] == pytest.approx(0.31132)
    assert frozen["changes"][0]["after"] == 0.4
    assert client.get("/api/refresh-runs/missing").status_code == 404


def test_interleaved_runs_attribute_each_transaction_not_global_baseline(app, client):
    with app.app_context():
        a = create_run({"epss": [CVE]}, run_id="a")
        b = create_run({"nvd": [CVE]}, run_id="b")
        with capture_source(a, "epss"):
            record = db.session.get(Vulnerability, CVE)
            record.epss_score = 0.5
            db.session.commit()
            with capture_source(b, "nvd"):
                record.description = "interleaved"
                target_result("nvd", CVE)
                db.session.commit()
            record.epss_score = 0.6
            target_result("epss", CVE)
            db.session.commit()
        finish_source(a, "epss")
        finish_source(b, "nvd")
    a_rows = client.get("/api/refresh-runs/a").get_json()["changes"]
    b_rows = client.get("/api/refresh-runs/b").get_json()["changes"]
    assert [row["field"] for row in a_rows] == ["epss_score", "epss_score"]
    assert [row["source"] for row in a_rows] == ["epss", "epss"]
    assert [(row["field"], row["source"], row["after"]) for row in b_rows] == [
        ("description", "nvd", "interleaved"),
    ]


@pytest.mark.parametrize("queued", [False, True])
def test_captured_refresh_remains_available_in_last_refresh_history_export(app, client, queued):
    with app.app_context():
        run = create_run({"epss": [CVE]})
        if queued:
            with patch("src.controllers.refresh_jobs.EPSS_DB") as api:
                api.return_value.api_get_epss_batch.return_value = {CVE: {"score": 0.8}}
                run_epss_refresh(JobContext("cli-refresh:epss", {"ids": [CVE]}, run))
        else:
            _change(run, 0.8)
            finish_source(run, "epss")
    response = client.get("/api/vulnerabilities/history/export",
                          query_string={"last_refresh": "true", "vuln_id": CVE})
    assert response.status_code == 200
    rows = response.get_json()["history"]
    assert [(row["field"], row["value"]) for row in rows] == [("epss_score", 0.8)]


def test_shared_cve_visibility_is_captured_and_package_links_are_scope_filtered(app, client):
    with app.app_context():
        project = Project(id=uuid.uuid4(), name="other")
        variant = Variant(id=uuid.uuid4(), name="other", project_id=project.id)
        scan = Scan(id=uuid.uuid4(), variant_id=variant.id, scan_type="sbom")
        finding = db.session.scalar(db.select(Finding).where(Finding.vulnerability_id == CVE))
        db.session.add_all([project, variant, scan])
        db.session.flush()
        db.session.add(Observation(finding_id=finding.id, scan_id=scan.id))
        db.session.commit()
        other_id = str(project.id)
        run = create_run({"epss": [CVE]}, scope={"project_id": PROJECT, "variant_id": None})
        _change(run, 0.7)
        finish_source(run, "epss")
        # Removing the live association must not change the retained artifact.
        db.session.delete(scan)
        db.session.commit()
    data = client.get(f"/api/refresh-runs/{run}", query_string={"project_id": other_id}).get_json()
    assert data["changes"][0]["packages"][0]["project_id"] == other_id
    assert all(package["project_id"] == other_id for package in data["coverage"][0]["packages"])
    assert client.get(f"/api/refresh-runs/{run}", query_string={"project_id": str(uuid.uuid4())}).status_code == 404
    assert client.get("/api/refresh-runs/latest", query_string={"project_id": other_id}).get_json()["run_id"] == run


def test_first_enrichment_cvss_identity_and_pagination_filters(app, client):
    with app.app_context():
        record = db.session.get(Vulnerability, CVE)
        record.epss_score = None
        db.session.commit()
        run = create_run({"epss": [CVE], "nvd": [CVE]})
        _change(run, 0)
        finish_source(run, "epss")
        with capture_source(run, "nvd"):
            db.session.add(Metrics(vulnerability_id=CVE, version="3.1", author="provider",
                                   score=9.8, vector="CVSS:3.1/AV:N"))
            target_result("nvd", CVE)
            db.session.commit()
        finish_source(run, "nvd")
    data = client.get(f"/api/refresh-runs/{run}", query_string={"limit": 1}).get_json()
    assert data["total"] == 2 and len(data["changes"]) == 1
    assert data["summary"]["changed_vulnerabilities"] == 1
    assert data["summary"]["first_enrichments"] == 2
    metric = client.get(f"/api/refresh-runs/{run}", query_string={"offset": 1}).get_json()["changes"][0]
    assert metric["field"].startswith("cvss:3.1:provider:")
    assert metric["after"] == {"score": 9.8, "vector": "CVSS:3.1/AV:N"}
    params = {"source": "nvd", "kind": "first_enrichment", "change_type": "addition"}
    assert client.get(f"/api/refresh-runs/{run}", query_string=params).get_json()["total"] == 1
    assert len(data["coverage"]) == 2


def test_partial_provider_response_is_incomplete_not_removal(app, client):
    missing = "CVE-2099-1111"
    with app.app_context():
        Vulnerability.create_record(id=missing, epss_score=0.1)
        run = create_run({"epss": [CVE, missing]})
        with patch("src.controllers.refresh_jobs.EPSS_DB") as api:
            api.return_value.api_get_epss_batch.return_value = {CVE: {"score": 0.8}}
            run_epss_refresh(JobContext("test", {"ids": [CVE, missing]}, run))
    data = client.get(f"/api/refresh-runs/{run}").get_json()
    assert data["status"] == "incomplete"
    assert [entry["status"] for entry in data["coverage"]] == ["complete", "skipped"]
    assert [row["vuln_id"] for row in data["changes"]] == [CVE]


def test_cancelled_and_failed_targets_have_explicit_coverage(app, client):
    with app.app_context():
        run = create_run({"epss": [CVE]})
        ctx = JobContext("test", {"ids": [CVE]}, run)
        ctx.request_cancel()
        with pytest.raises(CancelledError):
            run_epss_refresh(ctx)
    data = client.get(f"/api/refresh-runs/{run}").get_json()
    assert data["status"] == "incomplete"
    assert data["coverage"][0]["status"] == "cancelled"
    with app.app_context():
        run = create_run({"epss": [CVE]})
        with patch("src.controllers.refresh_jobs.EPSS_DB") as api:
            api.return_value.api_get_epss_batch.side_effect = RuntimeError("offline")
            run_epss_refresh(JobContext("test", {"ids": [CVE]}, run))
    data = client.get(f"/api/refresh-runs/{run}").get_json()
    assert data["coverage"][0]["status"] == "failed"
    assert data["status"] == "incomplete"


def test_expired_exact_run_never_substitutes_latest_and_can_be_pruned(app, client):
    with app.app_context():
        expired = create_run({"epss": [CVE]}, run_id="expired")
        db.session.get(RefreshRun, expired).started_at = datetime.now(timezone.utc) - timedelta(days=91)
        db.session.commit()
        create_run({"epss": [CVE]}, run_id="newest")
    assert client.get("/api/refresh-runs/expired").status_code == 404
    assert client.get("/api/refresh-runs/expired/export").status_code == 404
    result = app.test_cli_runner().invoke(args=["export-refresh-changes", "--run-id", expired])
    assert result.exit_code != 0 and "expired" in result.output
    result = app.test_cli_runner().invoke(args=["prune-refresh-runs"])
    assert result.exit_code == 0
    assert result.output == "Removed 1 expired refresh runs.\n"
    with app.app_context():
        assert db.session.get(RefreshRun, expired) is None
        assert db.session.get(RefreshRun, "newest") is not None
    result = app.test_cli_runner().invoke(args=["prune-refresh-runs"])
    assert result.exit_code == 0
    assert result.output == "Removed 0 expired refresh runs.\n"


def test_json_csv_consistency_nested_multiline_formula_strings_and_zero_changes(app, client):
    with app.app_context():
        run = create_run({"nvd": [CVE]})
        with capture_source(run, "nvd"):
            record = db.session.get(Vulnerability, CVE)
            record.description = '=HYPERLINK("https://example.invalid")\nsecond line, "quoted"'
            record.links = ["https://example.invalid/a,b", "https://example.invalid/\nnext"]
            target_result("nvd", CVE)
            db.session.commit()
        finish_source(run, "nvd")
    exported = client.get(f"/api/refresh-runs/{run}/export?format=json").get_json()
    response = client.get(f"/api/refresh-runs/{run}/export?format=csv")
    rows = list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))
    assert json.loads(rows[0]["metadata"])["coverage"] == exported["coverage"]
    csv_changes = rows[1:]
    assert len(csv_changes) == len(exported["changes"])
    for row, original in zip(csv_changes, exported["changes"]):
        assert json.loads(row["before"]) == original["before"]
        assert json.loads(row["after"]) == original["after"]
        assert not row["after"].startswith(("=", "+", "-", "@"))
    with app.app_context():
        empty = create_run({"epss": []})
        finish_source(empty, "epss")
    assert client.get(f"/api/refresh-runs/{empty}").get_json()["status"] == "complete"
    assert len(list(csv.DictReader(io.StringIO(
        client.get(f"/api/refresh-runs/{empty}/export?format=csv").get_data(as_text=True))
    ))) == 1


def test_single_refresh_exposes_exact_identity_and_scope_rejects_outside(app, client):
    with patch("src.routes.vulnerabilities.EPSS_DB") as api:
        api.return_value.api_get_epss.return_value = {"score": 0.5}
        response = client.post(f"/api/vulnerabilities/{CVE}/epss-refresh?project_id={PROJECT}")
    assert response.status_code == 200
    run = response.headers["X-Refresh-Run-ID"]
    assert client.get(f"/api/refresh-runs/{run}").get_json()["changes"][0]["after"] == 0.5
    assert client.post(f"/api/vulnerabilities/{CVE}/epss-refresh?project_id={uuid.uuid4()}").status_code == 404


def test_duplicate_identity_and_invalid_pagination_fail_explicitly(app, client):
    with app.app_context():
        create_run({"epss": []}, run_id="duplicate")
        with pytest.raises(ValueError, match="already exists"):
            create_run({"epss": []}, run_id="duplicate")
    assert client.get("/api/refresh-runs/duplicate?limit=no").status_code == 400
    assert client.get("/api/refresh-runs/duplicate/export?format=pdf").status_code == 400


def test_stale_loaded_instance_records_actual_committed_predecessor(app, client):
    with app.app_context():
        run = create_run({"epss": [CVE]})
        with Session(db.engine) as stale:
            record = stale.get(Vulnerability, CVE)
            fresh = db.session.get(Vulnerability, CVE)
            fresh.epss_score = 0.6
            db.session.commit()
            with capture_source(run, "epss"):
                record.epss_score = 0.7
                stale.commit()
        with capture_source(run, "epss"):
            target_result("epss", CVE)
            db.session.commit()
        finish_source(run, "epss")
    row = client.get(f"/api/refresh-runs/{run}").get_json()["changes"][0]
    assert (row["before"], row["after"]) == (0.6, 0.7)


def test_artifact_rolls_back_with_failed_write_and_records_incomplete(app, client, monkeypatch):
    with app.app_context():
        run = create_run({"epss": [CVE]})
        commit = db.session.commit
        calls = []

        def fail_once():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("write rejected")
            return commit()

        with patch("src.controllers.refresh_jobs.EPSS_DB") as api:
            api.return_value.api_get_epss_batch.return_value = {CVE: {"score": 0.9}}
            monkeypatch.setattr(db.session, "commit", fail_once)
            with pytest.raises(RuntimeError, match="write rejected"):
                run_epss_refresh(JobContext("test", {"ids": [CVE]}, run))
            assert float(db.session.get(Vulnerability, CVE).epss_score) == pytest.approx(0.31132)
    data = client.get(f"/api/refresh-runs/{run}").get_json()
    assert data["status"] == "incomplete"
    assert data["changes"] == []
    assert data["coverage"][0]["status"] == "failed"


def test_cancel_after_committed_chunk_preserves_partial_artifact(app, client, monkeypatch):
    from src.controllers import refresh_jobs as jobs
    with app.app_context():
        other = "CVE-2099-1112"
        Vulnerability.create_record(id=other, epss_score=0.1)
        run = create_run({"epss": [CVE, other]})
        ctx = JobContext("test", {"ids": [CVE, other]}, run)
        original_apply = jobs._apply_epss_score

        def apply_then_cancel(*args):
            original_apply(*args)
            ctx.request_cancel()

        monkeypatch.setattr(jobs, "EPSS_BATCH_SIZE", 1)
        monkeypatch.setattr(jobs, "_apply_epss_score", apply_then_cancel)
        with patch("src.controllers.refresh_jobs.EPSS_DB") as api:
            api.return_value.api_get_epss_batch.return_value = {CVE: {"score": 0.8}}
            with pytest.raises(CancelledError):
                run_epss_refresh(ctx)
    data = client.get(f"/api/refresh-runs/{run}").get_json()
    assert data["status"] == "incomplete"
    assert [entry["status"] for entry in data["coverage"]] == ["complete", "cancelled"]
    assert [entry["vuln_id"] for entry in data["changes"]] == [CVE]


def test_zero_target_initiating_scope_and_skipped_deferred_source_are_visible(app, client):
    from src.controllers import refresh_jobs as jobs
    from src.helpers.refresh_runs import tracked_refresh
    with app.app_context():
        run = create_run({"epss": []}, scope={"project_id": PROJECT, "variant_id": VARIANT})
        ctx = JobContext("refresh:epss", {"ids": [], "source": "epss", "variant_ids": [VARIANT]}, run)
        with patch.object(jobs.registry, "get", return_value={"queue_id": run, "position": 2}), \
                patch.object(jobs.registry, "snapshot", return_value=[
                    {"queue_id": run, "kind": "scan", "position": 1, "status": "error"},
                ]):
            tracked_refresh("epss")(jobs.run_deferred_refresh)(ctx)
    data = client.get("/api/refresh-runs/latest", query_string={"project_id": PROJECT}).get_json()
    assert data["run_id"] == run and data["status"] == "incomplete"
    assert data["source_status"] == {"epss": "incomplete"}
    assert data["coverage"] == []
    assert client.get(f"/api/refresh-runs/{run}?project_id={uuid.uuid4()}").status_code == 404


def test_grouped_queue_keeps_exact_run_and_initiating_scope(app, client, monkeypatch):
    from src.controllers import refresh_jobs as jobs
    from src.controllers.operation_queue import queue
    from src.controllers.operation_registry import registry
    registry.clear()
    submitted = []
    monkeypatch.setattr(type(queue), "submit", lambda self, **kwargs: submitted.append(kwargs))
    payload = {"jobs": [
        {"kind": "refresh", "source": source, "ids": [CVE],
         "options": {"project_id": PROJECT, "variant_id": VARIANT}}
        for source in ("nvd", "epss")
    ]}
    response = client.post("/api/operations", json=payload)
    assert response.status_code == 202
    run = response.get_json()["queue_id"]
    data = client.get(f"/api/refresh-runs/{run}").get_json()
    assert data["status"] == "running"
    assert data["scope"] == {"project_id": PROJECT, "variant_id": VARIANT}
    with app.app_context(), patch.object(jobs, "_get_scc_engine"), \
            patch.object(jobs, "_refresh_nvd_record", return_value=True), \
            patch.object(jobs, "EPSS_DB") as api:
        api.return_value.api_get_epss_batch.return_value = {CVE: {"score": 0.8}}
        for job in submitted:
            job["runner"](job["ctx"])
    data = client.get(f"/api/refresh-runs/{run}").get_json()
    assert data["status"] == "complete"
    assert data["sources"] == ["nvd", "epss"]
    assert len(data["coverage"]) == 2 and data["total"] == 1
    registry.clear()


def test_queued_refresh_rejects_targets_outside_initiating_scope(client):
    response = client.post("/api/operations", json={"jobs": [
        {"kind": "refresh", "source": "nvd", "ids": ["CVE-2099-9999"],
         "options": {"project_id": PROJECT}},
    ]})
    assert response.status_code == 400
    assert "outside" in response.get_json()["error"]


def test_dead_owner_is_incomplete_but_concurrent_live_owner_is_not(app, client):
    with app.app_context():
        interrupted = create_run({"epss": [CVE]}, run_id="interrupted")
        live = create_run({"epss": [CVE]}, run_id="live")
        run = db.session.get(RefreshRun, interrupted)
        run.owner = {**run.owner, "process_start": "previous-process-incarnation"}
        db.session.commit()
    data = client.get(f"/api/refresh-runs/{interrupted}").get_json()
    assert data["status"] == "incomplete"
    assert data["coverage"][0]["status"] == "failed"
    assert client.get(f"/api/refresh-runs/{live}").get_json()["status"] == "running"


def test_cli_refresh_partial_run_is_nonzero_but_exports_remain_available(app):
    from src.controllers import refresh_jobs as jobs
    with patch.object(jobs, "_get_scc_engine", side_effect=RuntimeError("unavailable")), \
            patch.object(jobs, "EPSS_DB") as epss, patch.object(jobs, "EUVD_DB") as euvd:
        epss.return_value.api_get_epss_batch.return_value = {CVE: {"score": 0.8}}
        euvd.return_value.get_full_mapping.return_value = {}
        result = app.test_cli_runner().invoke(args=[
            "refresh-vulnerability-data", "--project", "demo", "--run-id", "cli-partial",
        ])
    assert result.exit_code == 1
    assert "Refresh run: cli-partial" in result.output
    export = app.test_cli_runner().invoke(args=["export-refresh-changes", "--run-id", "cli-partial"])
    assert export.exit_code == 0
    data = json.loads(export.output)
    assert data["status"] == "incomplete" and data["changes"]
    duplicate = app.test_cli_runner().invoke(args=["refresh-vulnerability-data", "--run-id", "cli-partial"])
    assert duplicate.exit_code == 1 and "already exists" in duplicate.output


@pytest.mark.parametrize("length", [38, 39, 128])
def test_caller_run_identity_matches_history_column_capacity(app, length):
    with app.app_context():
        if length > 38:
            with pytest.raises(ValueError, match="38"):
                create_run({"epss": [CVE]}, run_id="x" * length)
        else:
            run = create_run({"epss": [CVE]}, run_id="x" * length)
            _change(run, 0.6)
            finish_source(run, "epss")


def test_list_pages_before_loading_changes_and_aggregates_filtered_summaries(app, client):
    with app.app_context():
        for index in range(5):
            run = create_run({"epss": [CVE]}, run_id=f"page-{index}")
            _change(run, 0.4 + index / 10)
            finish_source(run, "epss")
        queries = []

        def record(_connection, _cursor, statement, _params, _context, _many):
            queries.append(statement)

        event.listen(db.engine, "before_cursor_execute", record)
        try:
            response = client.get("/api/refresh-runs", query_string={
                "limit": 1, "offset": 1, "project_id": PROJECT, "vuln_id": CVE,
                "source": "epss", "change_type": "modification",
            })
            assert response.status_code == 200
            data = response.get_json()
            assert data["total"] == 5
            assert [run["run_id"] for run in data["runs"]] == ["page-3"]
            assert data["runs"][0]["summary"] == {
                "total_changes": 1, "changed_vulnerabilities": 1, "first_enrichments": 0,
            }
            change_queries = [statement for statement in queries if "FROM refresh_changes" in statement]
            assert len(change_queries) == 1
            assert "count(" in change_queries[0].lower()
            assert "refresh_changes.snapshot \n" not in change_queries[0]
            empty = client.get("/api/refresh-runs", query_string={"project_id": str(uuid.uuid4())}).get_json()
            assert empty["total"] == 0 and empty["runs"] == []
        finally:
            event.remove(db.engine, "before_cursor_execute", record)


def test_queued_provider_cancellation_cannot_overwrite_executing_provider(app, client):
    with app.app_context():
        run_id = create_run({"epss": [CVE], "nvd": [CVE]})
    worker_loaded = threading.Event()
    cancelled = threading.Event()
    errors = []

    def worker():
        try:
            with app.app_context():
                run = db.session.get(RefreshRun, run_id)
                assert len(run.coverage) == 2
                worker_loaded.set()
                assert cancelled.wait(5)
                _change(run_id, 0.8)
                finish_source(run_id, "epss")
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    try:
        assert worker_loaded.wait(5)
        with app.app_context():
            finish_source(run_id, "nvd", "cancelled", "Cancelled while queued")
    finally:
        cancelled.set()
        thread.join(10)
    assert not thread.is_alive()
    assert not errors
    data = client.get(f"/api/refresh-runs/{run_id}").get_json()
    assert data["status"] == "incomplete" and data["finished_at"] is not None
    assert data["source_status"] == {"epss": "complete", "nvd": "incomplete"}
    assert [(entry["source"], entry["status"]) for entry in data["coverage"]] == [
        ("epss", "complete"), ("nvd", "cancelled"),
    ]
    assert data["changes"][0]["after"] == 0.8


def test_target_reporting_updates_only_indexed_target_rows(app):
    from src.models.refresh_run import RefreshTarget
    with app.app_context():
        ids = [f"CVE-2099-{index:04d}" for index in range(1000)]
        run = create_run({"epss": ids})
        queries = []

        def record(_connection, _cursor, statement, _params, _context, _many):
            queries.append(statement)

        event.listen(db.engine, "before_cursor_execute", record)
        try:
            with capture_source(run, "epss"):
                for identifier in ids[:5]:
                    target_result("epss", identifier)
                db.session.commit()
        finally:
            event.remove(db.engine, "before_cursor_execute", record)
        assert not any("refresh_targets.packages" in sql and "refresh_targets.vuln_id =" not in sql
                       for sql in queries)
        assert len([sql for sql in queries if sql.startswith("UPDATE refresh_targets")]) == 5
        assert db.session.scalar(db.select(db.func.count()).select_from(RefreshTarget).where(
            RefreshTarget.run_id == run, RefreshTarget.status == "complete",
        )) == 5


@pytest.mark.skipif(not os.getenv("VULNSCOUT_TEST_POSTGRES_URI"), reason="Requires isolated PostgreSQL test database")
@pytest.mark.parametrize("field", ["epss_score", "cvss_score"])
def test_independent_concurrent_sessions_capture_locked_predecessor(app, client, field):
    with app.app_context():
        if field == "epss_score":
            model, identifier, attribute = Vulnerability, CVE, "epss_score"
            record = db.session.get(model, identifier)
            record.epss_score = 0.1
        else:
            record = Metrics(vulnerability_id=CVE, version="3.1", author="concurrent",
                             score=0.1, vector="CVSS:3.1/AV:N")
            db.session.add(record)
            db.session.flush()
            model, identifier, attribute = Metrics, record.id, "score"
        db.session.commit()
        first = create_run({"epss": [CVE]}, run_id="writer-first")
        second = create_run({"epss": [CVE]}, run_id="writer-second")
        engine = db.engine
    loaded = threading.Barrier(2)
    predecessor_read = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()
    second_finished = threading.Event()
    errors = []

    def hold_first(_connection, _cursor, statement, _params, _context, _many):
        if (threading.current_thread().name == "writer-first" and statement.startswith("SELECT ")
                and ("vulnerabilities.epss_score" in statement or "metrics.score" in statement)
                and "FOR UPDATE" in statement):
            predecessor_read.set()
            assert release_first.wait(10)

    def write(run_id, score):
        try:
            with app.app_context(), Session(engine) as session:
                record = session.get(model, identifier)
                loaded.wait(10)
                if run_id == second:
                    assert predecessor_read.wait(10)
                    second_started.set()
                with capture_source(run_id, "epss"):
                    setattr(record, attribute, score)
                    session.commit()
        except BaseException as exc:
            errors.append(exc)
        finally:
            if run_id == second:
                second_finished.set()

    event.listen(engine, "after_cursor_execute", hold_first)
    threads = [threading.Thread(target=write, name=run, args=(run, score))
               for run, score in [(first, 0.2), (second, 0.3)]]
    try:
        for thread in threads:
            thread.start()
        assert predecessor_read.wait(10)
        assert second_started.wait(10)
        assert not second_finished.wait(0.3), "Second writer bypassed the predecessor row lock"
    finally:
        release_first.set()
        for thread in threads:
            thread.join(15)
        event.remove(engine, "after_cursor_execute", hold_first)
    assert all(not thread.is_alive() for thread in threads)
    assert not errors
    first_row = client.get(f"/api/refresh-runs/{first}").get_json()["changes"][0]
    second_row = client.get(f"/api/refresh-runs/{second}").get_json()["changes"][0]

    def value(row, key):
        return row[key] if field == "epss_score" else row[key]["score"]

    assert (value(first_row, "before"), value(first_row, "after")) == (0.1, 0.2)
    assert (value(second_row, "before"), value(second_row, "after")) == (0.2, 0.3)


@pytest.mark.parametrize("mode", ["api", "local"])
def test_shared_nvd_refresh_preserves_patch_and_fix_enrichment(app, mode):
    from src.controllers import refresh_jobs as jobs
    cve = {
        "id": CVE, "references": [{"url": "https://example.invalid/new-patch", "tags": ["Patch"]}],
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True, "criteria": "cpe:2.3:a:vendor:package:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "2.0",
        }]}]}],
    }
    with app.app_context():
        record = db.session.get(Vulnerability, CVE)
        record.patch_url = ["https://example.invalid/old-patch"]
        record.versions_data = {"old": {"fix": ["1.0"], "affected": []}}
        db.session.commit()
        with patch.object(jobs, "get_cve_json", return_value=cve), patch.object(jobs, "NVD_DB") as api:
            api.return_value.api_get_cve.return_value = (200, {"vulnerabilities": [{"cve": cve}]})
            # The API wrapper normally delegates to the same production extractor.
            api.extract_cve_details.side_effect = jobs.extract_cve_details
            assert jobs._refresh_nvd_record(CVE, mode, api.return_value if mode == "api" else None)
            db.session.commit()
        record = db.session.get(Vulnerability, CVE)
        assert record.patch_url == ["https://example.invalid/new-patch"]
        assert record.versions_data["package (nvd-cpe-match)"]["fix"] == [">=? 2.0"]


def test_processing_refresh_preserves_caller_identity(app):
    from src.bin import cmd_process
    from src.controllers import ControllersCache
    with app.app_context(), patch.object(cmd_process, "_refresh_source", return_value=True):
        cmd_process.refresh_vulnerability_sources(ControllersCache(), [CVE], run_id="process-exact")
        assert db.session.get(RefreshRun, "process-exact") is not None
    with patch.object(cmd_process, "_run_main") as process:
        result = app.test_cli_runner().invoke(args=[
            "process", "--refresh-vulnerability-data", "--refresh-run-id", "process-forwarded",
        ])
        assert result.exit_code == 0, result.output
        assert process.call_args.kwargs["refresh_run_id"] == "process-forwarded"
