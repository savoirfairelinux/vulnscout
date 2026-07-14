# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for data_updated_at stamping during initial NVD and GHSA enrichment."""

import pytest
from unittest.mock import MagicMock, patch
from src.bin.webapp import create_app
from src.extensions import db
from src.models.vulnerability import Vulnerability
from tests.webapp_tests import write_demo_files, setup_demo_db


@pytest.fixture()
def app(tmp_path):
    import os
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


def _make_controller(app, cve_id):
    """Build a minimal VulnerabilitiesController around one CVE record."""
    from src.controllers.vulnerabilities import VulnerabilitiesController
    with app.app_context():
        rec = db.session.get(Vulnerability, cve_id)
        ctrl = VulnerabilitiesController.__new__(VulnerabilitiesController)
        ctrl.vulnerabilities = {cve_id: rec}
        ctrl._db_record_cache = {}
        return ctrl


# ---------------------------------------------------------------------------
# NVD initial enrichment
# ---------------------------------------------------------------------------

def test_nvd_initial_populate_sets_nvd_data_updated_at(app):
    """fetch_nvd_data() stamps nvd_data_updated_at when NVD returns real data."""
    cve_id = "CVE-2020-35492"

    with app.app_context():
        rec = db.session.get(Vulnerability, cve_id)
        rec.nvd_fetched_at = None
        rec.nvd_data_updated_at = None
        db.session.commit()

    ctrl = _make_controller(app, cve_id)

    fake_cve_json = {
        "id": cve_id,
        "published": "2020-05-01T00:00:00.000",
        "lastModified": "2020-06-01T00:00:00.000",
        "vulnStatus": "Analyzed",
        "weaknesses": [
            {"source": "nvd", "type": "Primary",
             "description": [{"lang": "en", "value": "CWE-787"}]}
        ],
        "references": [],
        "descriptions": [{"lang": "en", "value": "test description"}],
    }

    with app.app_context():
        with patch("src.controllers.vulnerabilities.get_cve_json",
                   return_value=fake_cve_json):
            ctrl.fetch_nvd_data()
            db.session.commit()

    with app.app_context():
        rec = db.session.get(Vulnerability, cve_id)
        assert rec.nvd_data_updated_at is not None


def test_nvd_not_found_does_not_set_nvd_data_updated_at(app):
    """fetch_nvd_data() does NOT stamp nvd_data_updated_at for a CVE not found in local DB."""
    cve_id = "CVE-2020-35492"

    with app.app_context():
        rec = db.session.get(Vulnerability, cve_id)
        rec.nvd_fetched_at = None
        rec.nvd_data_updated_at = None
        db.session.commit()

    ctrl = _make_controller(app, cve_id)

    with app.app_context():
        with patch("src.controllers.vulnerabilities.get_cve_json", return_value=None):
            ctrl.fetch_nvd_data()
            db.session.commit()

    with app.app_context():
        rec = db.session.get(Vulnerability, cve_id)
        assert rec.nvd_data_updated_at is None
        assert rec.nvd_fetched_at is not None  # fetched_at IS set for not_found


# ---------------------------------------------------------------------------
# GHSA initial enrichment
# ---------------------------------------------------------------------------

def test_ghsa_initial_populate_sets_ghsa_data_updated_at(app):
    """fetch_nvd_data() (which also handles GHSA) stamps ghsa_data_updated_at on first publish_date."""
    import datetime as dt
    ghsa_id = "GHSA-R7JW-VC2X-4GBH"

    with app.app_context():
        # Seed a GHSA vulnerability with no publish_date
        Vulnerability.create_record(id=ghsa_id, description="test GHSA")
        rec = db.session.get(Vulnerability, ghsa_id)
        rec.publish_date = None
        rec.ghsa_fetched_at = None
        rec.ghsa_data_updated_at = None
        db.session.commit()

    from src.controllers.vulnerabilities import VulnerabilitiesController
    with app.app_context():
        rec = db.session.get(Vulnerability, ghsa_id)
        ctrl = VulnerabilitiesController.__new__(VulnerabilitiesController)
        ctrl.vulnerabilities = {ghsa_id: rec}
        ctrl._db_record_cache = {}

        with patch.object(VulnerabilitiesController, "_fetch_ghsa_published",
                          return_value="2023-06-15T00:00:00Z"):
            # No CVE-prefixed IDs → NVD (get_cve_json) path skipped entirely
            ctrl.fetch_nvd_data()
            db.session.commit()

    with app.app_context():
        rec = db.session.get(Vulnerability, ghsa_id)
        assert rec.ghsa_data_updated_at is not None
        assert rec.publish_date == dt.date(2023, 6, 15)
