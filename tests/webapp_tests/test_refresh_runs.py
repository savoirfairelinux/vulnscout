# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Refresh artifacts are exact, immutable, scoped, and honest about coverage."""

import csv
import io
import json
import urllib.error
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from flask import Flask
from sqlalchemy import create_engine, text

from src.bin.webapp import create_app
from src.controllers.job_context import CancelledError, JobContext
from src.controllers.refresh_jobs import run_epss_refresh
from src.extensions import db
from src.helpers.refresh_runs import capture_source, create_run, finish_source, target_result
from src.models import Finding, Observation, Project, Scan, Variant, Vulnerability
from src.models.metrics import Metrics
from src.models.refresh_run import RefreshChange, RefreshRun
from src.models.vulnerability_history import VulnerabilityHistory
from sqlalchemy.orm import Session
from . import setup_demo_db

CVE = "CVE-2020-35492"
PROJECT = "11111111-1111-1111-1111-111111111111"
VARIANT = "22222222-2222-2222-2222-222222222222"


@pytest.fixture()
def app(monkeypatch, tmp_path):
    (tmp_path / "status").write_text("__END_OF_SCAN_SCRIPT__")
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
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


@pytest.mark.parametrize("length", [39, 128])
def test_caller_run_id_fits_history_and_preserves_changes_on_postgresql(postgres_uri, length):
    engine = create_engine(postgres_uri)
    schema = f"vulnscout_refresh_{uuid.uuid4().hex}"
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    application = Flask(__name__)
    application.config.update(
        SQLALCHEMY_DATABASE_URI=postgres_uri,
        SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"options": f"-csearch_path={schema}"}},
    )
    db.init_app(application)
    try:
        with application.app_context():
            db.create_all()
            Vulnerability.create_record(id=CVE, epss_score=0.1)
            invalid_id = "x" * length
            with pytest.raises(ValueError, match="up to 38"):
                create_run({"epss": [CVE]}, run_id=invalid_id)
            assert db.session.get(RefreshRun, invalid_id) is None

            run = create_run({"epss": [CVE]}, run_id="caller-" + "x" * 31)
            _change(run, 0.8)
            finish_source(run, "epss")
            db.session.expire_all()
            assert float(db.session.get(Vulnerability, CVE).epss_score) == pytest.approx(0.8)
            history = db.session.scalar(db.select(VulnerabilityHistory).where(
                VulnerabilityHistory.queue_id == run, VulnerabilityHistory.field == "epss_score",
            ))
            assert history.old_value == pytest.approx(0.1)
            change = db.session.scalar(db.select(RefreshChange).where(RefreshChange.run_id == run))
            assert change.snapshot["before"] == pytest.approx(0.1)
            assert change.snapshot["after"] == pytest.approx(0.8)
    finally:
        with application.app_context():
            db.session.remove()
            db.engine.dispose()
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()


@pytest.mark.parametrize("scope", [{}, {"project_id": PROJECT}, {"variant_id": VARIANT}])
def test_latest_without_refresh_history_is_a_successful_empty_result(client, scope):
    latest = client.get("/api/refresh-runs/latest", query_string=scope)
    assert latest.status_code == 200
    assert latest.get_json() is None
    listing = client.get("/api/refresh-runs", query_string=scope)
    assert listing.status_code == 200
    assert listing.get_json()["runs"] == []
    assert listing.get_json()["total"] == 0
    assert client.get("/api/refresh-runs/missing", query_string=scope).status_code == 404
    assert client.get("/api/refresh-runs/missing/export", query_string=scope).status_code == 404


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
        with patch("src.controllers.epss_db.urllib.request.urlopen") as request:
            response = request.return_value.__enter__.return_value
            response.status = 200
            response.read.return_value = json.dumps({
                "data": [{"cve": CVE, "epss": "0.8", "percentile": "0.9"}],
            }).encode()
            run_epss_refresh(JobContext("test", {"ids": [CVE, missing]}, run))
    data = client.get(f"/api/refresh-runs/{run}").get_json()
    assert data["status"] == "incomplete"
    assert [entry["status"] for entry in data["coverage"]] == ["complete", "skipped"]
    assert [row["vuln_id"] for row in data["changes"]] == [CVE]


def test_provider_completion_preserves_one_pending_batch_and_its_coverage_gaps(app, client):
    missing = "CVE-2099-1111"
    with app.app_context():
        Vulnerability.create_record(id=missing, epss_score=0.1)
        run = create_run({"epss": [CVE, missing], "euvd": [CVE, missing]})
        with patch("src.controllers.refresh_jobs.EPSS_DB") as api:
            api.return_value.api_get_epss_batch.return_value = {CVE: {"score": 0.8}}
            run_epss_refresh(JobContext("test", {"ids": [CVE, missing]}, run))
    partial = client.get(f"/api/refresh-runs/{run}").get_json()
    assert partial["status"] == "running"
    assert partial["finished_at"] is None
    assert partial["source_status"] == {"epss": "incomplete", "euvd": "pending"}
    assert client.get("/api/refresh-runs").get_json()["total"] == 1

    with app.app_context():
        with capture_source(run, "euvd"):
            target_result("euvd", CVE)
            target_result("euvd", missing)
        finish_source(run, "euvd")
    finished = client.get(f"/api/refresh-runs/{run}").get_json()
    assert finished["status"] == "incomplete"
    assert finished["finished_at"] is not None
    assert finished["source_status"] == {"epss": "incomplete", "euvd": "complete"}
    assert any(row["source"] == "epss" and row["status"] == "skipped" for row in finished["coverage"])
    listing = client.get("/api/refresh-runs").get_json()
    assert listing["total"] == 1
    assert listing["runs"][0]["run_id"] == run


def test_cancelled_targets_have_explicit_coverage(app, client):
    with app.app_context():
        run = create_run({"epss": [CVE]})
        ctx = JobContext("test", {"ids": [CVE]}, run)
        ctx.request_cancel()
        with pytest.raises(CancelledError):
            run_epss_refresh(ctx)
    data = client.get(f"/api/refresh-runs/{run}").get_json()
    assert data["status"] == "incomplete"
    assert data["coverage"][0]["status"] == "cancelled"


@pytest.mark.parametrize("error", [
    urllib.error.HTTPError("https://api.first.org/data/v1/epss", 503, "Unavailable", None, None),
    urllib.error.URLError("connection refused"),
    TimeoutError("timed out"),
])
def test_failed_provider_is_incomplete_not_success(app, client, error):
    with app.app_context():
        run = create_run({"epss": [CVE]})
        with patch("src.controllers.epss_db.urllib.request.urlopen", side_effect=error):
            run_epss_refresh(JobContext("test", {"ids": [CVE]}, run))
    data = client.get(f"/api/refresh-runs/{run}").get_json()
    assert data["coverage"][0]["status"] == "failed"
    assert str(error) in data["coverage"][0]["error"]
    assert data["status"] == "incomplete"
    assert data["changes"] == []


def test_invalid_epss_response_is_failed_not_missing(app, client):
    with app.app_context():
        run = create_run({"epss": [CVE]})
        with patch("src.controllers.epss_db.urllib.request.urlopen") as request:
            response = request.return_value.__enter__.return_value
            response.status = 200
            response.read.return_value = b"not json"
            run_epss_refresh(JobContext("test", {"ids": [CVE]}, run))
    data = client.get(f"/api/refresh-runs/{run}").get_json()
    assert data["coverage"][0]["status"] == "failed"
    assert data["status"] == "incomplete"
    assert data["changes"] == []


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


def test_queued_cancellation_waits_and_never_overwrites_concurrently_committed_outcomes(monkeypatch, tmp_path):
    """Cancelling EPSS while NVD holds an uncommitted write must keep NVD's outcome."""
    import threading
    import time
    from src import extensions
    (tmp_path / "status").write_text("__END_OF_SCAN_SCRIPT__")
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", f"sqlite:///{tmp_path / 'refresh.db'}")
    monkeypatch.setenv("FLASK_TESTING", "true")
    monkeypatch.setenv("FLASK_SCAN_FILE", str(tmp_path / "status"))
    application = create_app()
    setup_demo_db(application)
    with application.app_context():
        run = create_run({"nvd": [CVE], "epss": [CVE]}, run_id="concurrent")
        errors = []

        def cancel_epss():
            try:
                with application.app_context():
                    finish_source(run, "epss", "cancelled", "Cancelled before start")
            except Exception as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        with capture_source(run, "nvd"):
            target_result("nvd", CVE)
            canceller = threading.Thread(target=cancel_epss)
            canceller.start()
            deadline = time.monotonic() + 5
            while not extensions._db_write_lock._waiters and time.monotonic() < deadline:
                time.sleep(0.01)
            db.session.commit()
        canceller.join(10)
        assert not canceller.is_alive() and not errors
        finish_source(run, "nvd")
    data = application.test_client().get(f"/api/refresh-runs/{run}").get_json()
    assert [(entry["source"], entry["status"]) for entry in data["coverage"]] == [
        ("nvd", "complete"), ("epss", "cancelled"),
    ]
    assert data["source_status"] == {"nvd": "complete", "epss": "incomplete"}
    assert data["status"] == "incomplete" and data["finished_at"]


def test_target_result_updates_one_row_without_rewriting_the_run(app):
    from sqlalchemy import event as sa_event
    with app.app_context():
        others = [f"CVE-2099-2{index:03d}" for index in range(5)]
        for identifier in others:
            Vulnerability.create_record(id=identifier, epss_score=0.1)
        run = create_run({"epss": [CVE, *others]})
        statements = []

        def record(_conn, _cursor, statement, parameters, _context, _executemany):
            statements.append((statement, parameters))

        sa_event.listen(db.engine, "before_cursor_execute", record)
        try:
            with capture_source(run, "epss"):
                for identifier in [CVE, *others]:
                    target_result("epss", identifier)
                db.session.commit()
        finally:
            sa_event.remove(db.engine, "before_cursor_execute", record)
    writes = [statement for statement, _ in statements if statement.lstrip().upper().startswith(("UPDATE", "INSERT"))]
    assert len([statement for statement in writes if "refresh_run_targets" in statement]) == 6
    assert not [statement for statement in writes if "UPDATE refresh_runs" in statement]


def test_run_list_is_paginated_in_the_database_without_loading_change_bodies(app, client):
    from sqlalchemy import event as sa_event
    with app.app_context():
        for index in range(4):
            run = create_run({"epss": [CVE]}, run_id=f"listed-{index}")
            _change(run, 0.5 + index / 10)
            finish_source(run, "epss")
        other = str(uuid.uuid4())
        create_run({"epss": []}, run_id="elsewhere", scope={"project_id": other, "variant_id": None})
        statements = []

        def record(_conn, _cursor, statement, *_args):
            statements.append(statement)

        sa_event.listen(db.engine, "before_cursor_execute", record)
    try:
        page = client.get("/api/refresh-runs", query_string={"project_id": PROJECT, "limit": 2, "offset": 1})
    finally:
        with app.app_context():
            sa_event.remove(db.engine, "before_cursor_execute", record)
    data = page.get_json()
    assert data["total"] == 4
    assert [item["run_id"] for item in data["runs"]] == ["listed-2", "listed-1"]
    assert all("coverage" not in item and "changes" not in item for item in data["runs"])
    assert data["runs"][0]["summary"] == {"total_changes": 1, "changed_vulnerabilities": 1, "first_enrichments": 0}
    assert data["runs"][0]["status"] == "complete"
    assert not [statement for statement in statements if "snapshot" in statement]
    assert not [statement for statement in statements if "refresh_run_target_links.name" in statement]
    assert client.get("/api/refresh-runs", query_string={"project_id": other}).get_json()["total"] == 1


@pytest.mark.parametrize("args, message", [
    (["--project", ""], "--project must not be empty"),
    (["--project", "  "], "--project must not be empty"),
    (["--project", "demo", "--variant", ""], "--variant must not be empty"),
])
def test_export_rejects_supplied_empty_scope_instead_of_broadening(app, args, message):
    with app.app_context():
        create_run({"epss": [CVE]}, run_id="scoped-export")
    result = app.test_cli_runner().invoke(args=["export-refresh-changes", "--run-id", "scoped-export", *args])
    assert result.exit_code == 2
    assert message in result.output


def test_reserved_latest_identity_is_rejected_so_exact_urls_never_resolve_another_run(app, client):
    with app.app_context():
        with pytest.raises(ValueError, match="reserved"):
            create_run({"epss": [CVE]}, run_id="latest")
    result = app.test_cli_runner().invoke(args=["refresh-vulnerability-data", "--run-id", "latest"])
    assert result.exit_code == 1 and "reserved" in result.output
    with app.app_context():
        assert db.session.get(RefreshRun, "latest") is None
