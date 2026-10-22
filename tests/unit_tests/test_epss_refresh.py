# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
import pytest
import tempfile
from datetime import datetime, timezone
from decimal import Decimal
from unittest.mock import patch

from src.bin.webapp import create_app
from src.extensions import db
from src.models.vulnerability import Vulnerability
from tests.webapp_tests import write_demo_files, setup_demo_db


@pytest.fixture()
def app_with_scan(tmp_path):
    """App fixture with a valid scan-complete marker file."""
    files = {
        "status": tmp_path / "status.txt",
        "packages": tmp_path / "packages-merged.json",
        "vulnerabilities": tmp_path / "vulnerabilities-merged.json",
        "assessments": tmp_path / "assessments-merged.json",
        "openvex": tmp_path / "openvex.json",
        "time_estimates": tmp_path / "time_estimates.json",
    }
    write_demo_files(files)

    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": files["status"],
            "OPENVEX_FILE": files["openvex"],
        })
        setup_demo_db(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app_with_scan):
    return app_with_scan.test_client()


def test_epss_refresh_persists_score_to_db(app_with_scan):
    """After a successful refresh the new EPSS score is persisted in the DB."""
    cve_id = "CVE-2020-35492"
    with patch("src.routes.vulnerabilities.EPSS_DB") as MockEPSS:
        MockEPSS.return_value.api_get_epss.return_value = {"score": 0.999, "percentile": 0.998}
        with app_with_scan.test_client() as c:
            c.post(f"/api/vulnerabilities/{cve_id}/epss-refresh")

    with app_with_scan.app_context():
        rec = db.session.get(Vulnerability, cve_id)
        assert rec is not None
        assert rec.epss_score is not None
        assert abs(float(rec.epss_score) - 0.999) < 1e-4


def test_epss_refresh_response_contains_percentile(client):
    """Response body includes epss.percentile even though it is not a DB column."""
    cve_id = "CVE-2020-35492"
    with patch("src.routes.vulnerabilities.EPSS_DB") as MockEPSS:
        MockEPSS.return_value.api_get_epss.return_value = {"score": 0.5, "percentile": 0.88}
        resp = client.post(f"/api/vulnerabilities/{cve_id}/epss-refresh")
    assert resp.status_code == 200
    data = resp.get_json()
    vuln = data["vulnerabilities"][0]
    assert vuln["epss"]["percentile"] == pytest.approx(0.88, abs=1e-4)


def test_epss_refresh_does_not_overwrite_score_on_api_failure(app_with_scan):
    """When the EPSS API returns None the original score is unchanged."""
    cve_id = "CVE-2020-35492"
    original_score: Decimal | None = None
    with app_with_scan.app_context():
        rec = db.session.get(Vulnerability, cve_id)
        assert rec is not None
        original_score = rec.epss_score

    with patch("src.routes.vulnerabilities.EPSS_DB") as MockEPSS:
        MockEPSS.return_value.api_get_epss.return_value = None
        with app_with_scan.test_client() as c:
            resp = c.post(f"/api/vulnerabilities/{cve_id}/epss-refresh")
    assert resp.status_code == 503

    with app_with_scan.app_context():
        rec = db.session.get(Vulnerability, cve_id)
        assert rec is not None
        assert rec.epss_score == original_score


def test_initial_epss_enrichment_sets_data_updated_at(app_with_scan):
    """fetch_epss_scores() stamps epss_data_updated_at on first-time population."""
    from decimal import Decimal
    from unittest.mock import MagicMock
    from src.controllers.vulnerabilities import VulnerabilitiesController

    cve_id = "CVE-2020-35492"

    # Reset so the controller considers it un-enriched
    with app_with_scan.app_context():
        rec = db.session.get(Vulnerability, cve_id)
        rec.epss_fetched_at = None
        rec.epss_data_updated_at = None
        db.session.commit()

    # Build a minimal controller with just the one CVE
    with app_with_scan.app_context():
        rec = db.session.get(Vulnerability, cve_id)
        ctrl = VulnerabilitiesController.__new__(VulnerabilitiesController)
        ctrl.vulnerabilities = {cve_id: rec}
        ctrl._db_record_cache = {}
        mock_epss = MagicMock()
        mock_epss.api_get_epss_batch.return_value = {cve_id: {"score": 0.42, "percentile": 0.7}}
        ctrl.epss_api = mock_epss

        before = datetime.now(timezone.utc).replace(tzinfo=None)
        ctrl.fetch_epss_scores()
        after = datetime.now(timezone.utc).replace(tzinfo=None)
        assert rec.epss_fetched_at.tzinfo is None
        assert before <= rec.epss_fetched_at <= after
        assert rec.epss_data_updated_at == rec.epss_fetched_at
        db.session.commit()

    with app_with_scan.app_context():
        rec = db.session.get(Vulnerability, cve_id)
        assert rec.epss_data_updated_at is not None
        assert abs(float(rec.epss_score) - 0.42) < 1e-4
