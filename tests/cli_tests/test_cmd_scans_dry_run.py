# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Dry-run previews for the destructive cleanup CLI commands."""

import uuid

import pytest

from src.bin.webapp import create_app
from src.extensions import db as _db


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    application = create_app()
    application.config.update({"TESTING": True, "SCAN_FILE": str(tmp_path / "scan_status.txt")})
    (tmp_path / "scan_status.txt").write_text("__END_OF_SCAN_SCRIPT__")
    with application.app_context():
        _db.create_all()
        yield application
        _db.drop_all()


def _refuse(*_args, **_kwargs):
    raise AssertionError("a dry run must not delete anything")


def test_delete_scan_dry_run_keeps_scan(app):
    from src.models.project import Project
    from src.models.scan import Scan
    from src.models.variant import Variant

    with app.app_context():
        project = Project.create("DryRunProj")
        variant = Variant.create("v1", project.id)
        scan_id = Scan.create("nightly", variant.id).id

    result = app.test_cli_runner().invoke(args=["delete-scan", str(scan_id), "--dry-run"])

    assert result.exit_code == 0, result.output
    assert f"Would delete scan {scan_id} (DryRunProj/v1," in result.output
    assert "nightly" in result.output
    with app.app_context():
        assert _db.session.get(Scan, scan_id) is not None


def test_delete_scan_dry_run_unknown_scan_fails(app):
    missing = uuid.uuid4()

    result = app.test_cli_runner().invoke(args=["delete-scan", str(missing), "--dry-run"])

    assert result.exit_code == 1
    assert f"Scan not found: {missing}" in result.output


def test_delete_outdated_dry_run_lists_candidates(app, monkeypatch):
    preview = {
        "candidate_ids": {},
        "packages": [{
            "package": "firefox@1.0", "project": "P", "variant": "v1",
            "vulnerabilities": ["CVE-2099-0001", "CVE-2099-0002"], "linked_data": {},
        }],
        "assessments": [{
            "vulnerability": "CVE-2099-0001", "package": "firefox@1.0", "project": "P", "variant": "v1",
        }],
    }
    monkeypatch.setattr("src.helpers.outdated_cleanup.outdated_data_preview", lambda: preview)
    monkeypatch.setattr("src.helpers.outdated_cleanup.delete_outdated_data", _refuse)

    result = app.test_cli_runner().invoke(args=["delete-outdated", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "Would delete 1 outdated package links and 1 assessments" in result.output
    assert "package firefox@1.0 in P/v1 (2 vulnerabilities)" in result.output
    assert "assessment CVE-2099-0001 on firefox@1.0 in P/v1" in result.output


def test_delete_empty_scans_dry_run_lists_candidates(app, monkeypatch):
    preview = [{
        "id": "1b4e28ba-2fa1-11d2-883f-0016d3cca427", "description": "rescan",
        "timestamp": "2026-10-01T00:00:00", "project": "P", "variant": "v1",
    }]
    monkeypatch.setattr("src.helpers.outdated_cleanup.empty_scans_preview", lambda: preview)
    monkeypatch.setattr("src.helpers.outdated_cleanup.delete_empty_scans", _refuse)

    result = app.test_cli_runner().invoke(args=["delete-empty-scans", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "Would delete 1 empty scans" in result.output
    assert "1b4e28ba-2fa1-11d2-883f-0016d3cca427 P/v1 2026-10-01T00:00:00 rescan" in result.output


def test_delete_orphaned_vulns_dry_run_lists_candidates(app, monkeypatch):
    preview = [{"id": "CVE-2099-0003", "assessments": 2}]
    monkeypatch.setattr("src.helpers.outdated_cleanup.orphaned_vulnerabilities_preview", lambda: preview)
    monkeypatch.setattr("src.helpers.outdated_cleanup.delete_orphaned_vulnerabilities", _refuse)

    result = app.test_cli_runner().invoke(args=["delete-orphaned-vulns", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "Would delete 1 orphaned vulnerabilities" in result.output
    assert "CVE-2099-0003 (2 assessments)" in result.output
