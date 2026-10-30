# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Refresh artifacts are exact, immutable, scoped, and honest about coverage."""

import csv
import io
import json
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
    with app.app_context():
        assert db.session.get(RefreshRun, expired) is None


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
