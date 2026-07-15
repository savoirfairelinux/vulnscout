# -*- coding: utf-8 -*-
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Coverage tests targeting the remaining uncovered lines in:
  - src/controllers/vulnerabilities.py
  - src/routes/assessments.py
  - src/routes/vulnerabilities.py
"""

import json
import uuid as _uuid
import pytest

from src.bin.webapp import create_app
from . import write_demo_files, setup_demo_db


# ---------------------------------------------------------------------------
# Shared fixtures (same pattern as other webapp_tests)
# ---------------------------------------------------------------------------

@pytest.fixture()
def init_files(tmp_path):
    files = {
        "status": tmp_path / "status.txt",
        "packages": tmp_path / "packages-merged.json",
        "vulnerabilities": tmp_path / "vulnerabilities-merged.json",
        "assessments": tmp_path / "assessments-merged.json",
        "openvex": tmp_path / "openvex.json",
        "time_estimates": tmp_path / "time_estimates.json",
    }
    write_demo_files(files)
    return files


@pytest.fixture()
def app(init_files):
    import os
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": init_files["status"],
            "OPENVEX_FILE": init_files["openvex"],
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db",
        })
        setup_demo_db(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


# ===========================================================================
# routes/assessments.py — project_id query-param paths
# ===========================================================================

class TestAssessmentsProjectIdPaths:
    """Lines 53, 123, 131, 139, 163, 171: project_id branches on GET endpoints."""

    def test_index_assess_project_id(self, client, app):
        """Lines 123-131: GET /api/assessments?project_id=<uuid> returns list."""
        proj_id = "11111111-1111-1111-1111-111111111111"
        resp = client.get(f"/api/assessments?project_id={proj_id}")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert isinstance(data, list)

    def test_index_assess_project_id_unknown(self, client):
        """project_id with no variants → empty list."""
        unknown = str(_uuid.uuid4())
        resp = client.get(f"/api/assessments?project_id={unknown}")
        assert resp.status_code == 200
        assert json.loads(resp.data) == []

    def test_index_assess_format_dict(self, client, app):
        """Line 48: ?format=dict returns dict keyed by assessment id."""
        resp = client.get("/api/assessments?format=dict")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert isinstance(data, dict)

    def test_review_assessments_project_id(self, client, app):
        """Lines 163-171: GET /api/assessments/review?project_id=<uuid>."""
        proj_id = "11111111-1111-1111-1111-111111111111"
        resp = client.get(f"/api/assessments/review?project_id={proj_id}")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert isinstance(data, list)

    def test_review_assessments_no_filter(self, client):
        """Line 336: no variant/project → get_by_origin() with no args."""
        resp = client.get("/api/assessments/review")
        assert resp.status_code == 200
        assert isinstance(json.loads(resp.data), list)

    def test_index_assess_invalid_project_id(self, client):
        """Line 131: invalid UUID → 400 from parse_uuid_or_400."""
        resp = client.get("/api/assessments?project_id=not-a-uuid")
        assert resp.status_code == 400

    def test_index_assess_invalid_variant_id(self, client):
        """Line 123: invalid variant UUID → 400."""
        resp = client.get("/api/assessments?variant_id=not-a-uuid")
        assert resp.status_code == 400


class TestVariantActivePackages:
    """GET /api/vulnerabilities/<vuln_id>/variant-active-packages."""

    def test_returns_list_per_variant(self, client):
        """Real vuln → list of {variant_id, active_packages} entries."""
        resp = client.get("/api/vulnerabilities/CVE-2020-35492/variant-active-packages")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert isinstance(data, list)
        for entry in data:
            assert isinstance(entry["variant_id"], str)
            assert isinstance(entry["active_packages"], list)
            assert all(isinstance(p, str) for p in entry["active_packages"])

    def test_project_id_filter(self, client):
        """project_id filters variants without error."""
        proj_id = "11111111-1111-1111-1111-111111111111"
        resp = client.get(
            f"/api/vulnerabilities/CVE-2020-35492/variant-active-packages?project_id={proj_id}"
        )
        assert resp.status_code == 200
        assert isinstance(json.loads(resp.data), list)

    def test_invalid_project_id(self, client):
        """Invalid project UUID → 400."""
        resp = client.get(
            "/api/vulnerabilities/CVE-2020-35492/variant-active-packages?project_id=not-a-uuid"
        )
        assert resp.status_code == 400

    def test_unknown_vuln_returns_empty(self, client):
        """Unknown vuln → empty list."""
        resp = client.get("/api/vulnerabilities/CVE-0000-00000/variant-active-packages")
        assert resp.status_code == 200
        assert json.loads(resp.data) == []



class TestAssessmentsExportCustomData:
    """Lines 597, 624, 627: export-custom-data endpoint."""

    def test_export_custom_data_empty_returns_404(self, client):
        """Line 597: no custom data → 404."""
        resp = client.get("/api/assessments/review/export-custom-data")
        assert resp.status_code == 404

    def test_export_custom_data_with_variant_id(self, client, app):
        """Lines 624-627: variant_id scoping builds filename."""
        from src.extensions import db as _db
        from src.models.package import Package
        from src.models.vulnerability import Vulnerability
        from src.models.finding import Finding
        from src.models.assessment import Assessment

        with app.app_context():
            pkg = Package.find_or_create("xpkg", "2.0")
            vuln = Vulnerability.create_record("CVE-2099-XP01")
            finding = Finding.get_or_create(pkg.id, "CVE-2099-XP01")
            Assessment.create(
                status="not_affected",
                finding_id=finding.id,
                variant_id=_uuid.UUID("22222222-2222-2222-2222-222222222222"),
                origin="custom",
            )
            _db.session.commit()

        var_id = "22222222-2222-2222-2222-222222222222"
        resp = client.get(f"/api/assessments/review/export-custom-data?variant_id={var_id}")
        assert resp.status_code == 200
        assert resp.content_type == "application/json"

    def test_export_custom_data_with_project_id(self, client, app):
        """Line 658-659: project_id scoping."""
        from src.extensions import db as _db
        from src.models.package import Package
        from src.models.vulnerability import Vulnerability
        from src.models.finding import Finding
        from src.models.assessment import Assessment

        with app.app_context():
            pkg = Package.find_or_create("ypkg", "3.0")
            Vulnerability.create_record("CVE-2099-YP01")
            finding = Finding.get_or_create(pkg.id, "CVE-2099-YP01")
            Assessment.create(
                status="not_affected",
                finding_id=finding.id,
                variant_id=_uuid.UUID("22222222-2222-2222-2222-222222222222"),
                origin="custom",
            )
            _db.session.commit()

        proj_id = "11111111-1111-1111-1111-111111111111"
        resp = client.get(f"/api/assessments/review/export-custom-data?project_id={proj_id}")
        assert resp.status_code == 200


class TestReviewTimeEstimates:
    """Lines 338, 343-345, 361-362, 421, 429: review/time-estimates endpoint."""

    def test_review_time_estimates_no_filter(self, client):
        """No variant/project → all time estimates."""
        resp = client.get("/api/assessments/review/time-estimates")
        assert resp.status_code == 200
        assert isinstance(json.loads(resp.data), list)

    def test_review_time_estimates_project_id(self, client, app):
        """Lines 343-345: project_id scoping."""
        proj_id = "11111111-1111-1111-1111-111111111111"
        resp = client.get(f"/api/assessments/review/time-estimates?project_id={proj_id}")
        assert resp.status_code == 200

    def test_review_custom_cvss_project_id(self, client, app):
        """Lines 481, 491: review/custom-cvss with project_id."""
        proj_id = "11111111-1111-1111-1111-111111111111"
        resp = client.get(f"/api/assessments/review/custom-cvss?project_id={proj_id}")
        assert resp.status_code == 200
        assert isinstance(json.loads(resp.data), list)

    def test_review_custom_cvss_no_filter(self, client):
        """Line 708-709: no variant/project → returns all."""
        resp = client.get("/api/assessments/review/custom-cvss")
        assert resp.status_code == 200

    def test_review_custom_cvss_unknown_project(self, client):
        """Line 689-695: project with no variants → empty list."""
        unknown = str(_uuid.uuid4())
        resp = client.get(f"/api/assessments/review/custom-cvss?project_id={unknown}")
        assert resp.status_code == 200
        assert json.loads(resp.data) == []


class TestAssessmentUpdate:
    """Line 750: update_assessment not found → 404."""

    def test_put_assessment_not_found(self, client):
        """PUT /api/assessments/<unknown-id> → 404."""
        fake_id = str(_uuid.uuid4())
        resp = client.put(f"/api/assessments/{fake_id}", json={"status": "affected"})
        assert resp.status_code == 404


# ===========================================================================
# routes/vulnerabilities.py — uncovered paths
# ===========================================================================

class TestVulnsRouteGetSingle:
    """Lines 710, 751, 755: GET /api/vulnerabilities/<id> paths."""

    def test_get_vuln_with_variant_id(self, client):
        """Line 710: variant_id param triggers variant-scoped overrides."""
        var_id = "22222222-2222-2222-2222-222222222222"
        resp = client.get(f"/api/vulnerabilities/CVE-2020-35492?variant_id={var_id}")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["id"] == "CVE-2020-35492"

    def test_get_vuln_not_found(self, client):
        """Line 701: record not found → 404."""
        resp = client.get("/api/vulnerabilities/CVE-9999-ZZZZ")
        assert resp.status_code == 404

    def test_get_vuln_invalid_variant_id(self, client):
        """Line 710: invalid variant UUID → 400."""
        resp = client.get("/api/vulnerabilities/CVE-2020-35492?variant_id=not-a-uuid")
        assert resp.status_code == 400


class TestVulnsRouteFormatDict:
    """Line 696: GET /api/vulnerabilities?format=dict."""

    def test_index_vulns_format_dict(self, client):
        resp = client.get("/api/vulnerabilities?format=dict")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert isinstance(data, dict)
        assert "CVE-2020-35492" in data


class TestVulnsVariantSnapshots:
    """Lines 751, 755, 786, 794: GET /api/vulnerabilities/<id>/variant-snapshots."""

    def test_variant_snapshots_no_findings(self, client):
        """Vuln with no variant observations → empty list."""
        resp = client.get("/api/vulnerabilities/CVE-2020-35492/variant-snapshots")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert isinstance(data, list)

    def test_variant_snapshots_not_found(self, client):
        """Non-existent vuln → 404."""
        resp = client.get("/api/vulnerabilities/CVE-9999-SNAP/variant-snapshots")
        assert resp.status_code == 404

    def test_variant_snapshots_with_project_filter(self, client):
        """Lines 786, 794: project_id restricts returned variant UUIDs."""
        proj_id = "11111111-1111-1111-1111-111111111111"
        resp = client.get(f"/api/vulnerabilities/CVE-2020-35492/variant-snapshots?project_id={proj_id}")
        assert resp.status_code == 200


class TestVulnsBatchPatch:
    """Lines 815-820: PATCH /api/vulnerabilities/batch error paths."""

    def test_batch_patch_not_found(self, client):
        """Lines 815-820: item with unknown vuln id → error in response."""
        resp = client.patch("/api/vulnerabilities/batch", json={
            "vulnerabilities": [{"id": "CVE-9999-NOTEXIST", "effort": {
                "optimistic": "PT1H", "likely": "PT2H", "pessimistic": "PT4H"
            }}]
        })
        assert resp.status_code in (200, 400)
        data = json.loads(resp.data)
        assert data.get("errors") or data.get("status") == "error"

    def test_batch_patch_invalid_item(self, client):
        """Lines 815: non-dict item → error appended."""
        resp = client.patch("/api/vulnerabilities/batch", json={
            "vulnerabilities": ["not-a-dict"]
        })
        assert resp.status_code in (200, 400)
        data = json.loads(resp.data)
        assert data.get("errors")

    def test_batch_patch_invalid_format(self, client):
        """Line 848: missing vulnerabilities key → 400."""
        resp = client.patch("/api/vulnerabilities/batch", json={"vulns": []})
        assert resp.status_code == 400

    def test_batch_patch_with_variant_id(self, client):
        """Lines 879-880: effort + explicit variant_id → applied."""
        var_id = "22222222-2222-2222-2222-222222222222"
        resp = client.patch("/api/vulnerabilities/batch", json={
            "vulnerabilities": [{
                "id": "CVE-2020-35492",
                "variant_id": var_id,
                "effort": {"optimistic": "PT1H", "likely": "PT2H", "pessimistic": "PT3H"},
            }]
        })
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "success"

    def test_batch_patch_cvss_with_variant_id(self, client):
        """Lines 888-889: cvss + explicit variant_id in batch."""
        var_id = "22222222-2222-2222-2222-222222222222"
        resp = client.patch("/api/vulnerabilities/batch", json={
            "vulnerabilities": [{
                "id": "CVE-2020-35492",
                "variant_id": var_id,
                "cvss": {
                    "base_score": 7.5,
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "version": "3.1",
                    "author": "test@example.com",
                    "origin": "custom",
                },
            }]
        })
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "success"


class TestVulnsEpssRefresh:
    """Lines 1081-1086: POST /api/vulnerabilities/<id>/epss-refresh."""

    def test_epss_refresh_not_found(self, client):
        """CVE not in DB → 404."""
        resp = client.post("/api/vulnerabilities/CVE-9999-EPSS/epss-refresh")
        assert resp.status_code == 404

    def test_epss_refresh_api_none(self, client):
        """Lines 1081-1086: EPSS API returns None → 503."""
        from unittest.mock import patch
        with patch("src.routes.vulnerabilities.EPSS_DB") as MockEPSS:
            MockEPSS.return_value.api_get_epss.return_value = None
            resp = client.post("/api/vulnerabilities/CVE-2020-35492/epss-refresh")
        assert resp.status_code == 503

    def test_epss_refresh_success(self, client):
        """Happy path: EPSS API returns valid data → 200."""
        from unittest.mock import patch
        fake_epss = {"score": 0.5, "percentile": 0.9}
        with patch("src.routes.vulnerabilities.EPSS_DB") as MockEPSS:
            MockEPSS.return_value.api_get_epss.return_value = fake_epss
            resp = client.post("/api/vulnerabilities/CVE-2020-35492/epss-refresh")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "vulnerabilities" in data


class TestVulnsGhsaRefresh:
    """Lines 1129-1134: POST /api/vulnerabilities/<id>/ghsa-refresh."""

    def test_ghsa_refresh_invalid_id(self, client):
        """Non-GHSA id → 400."""
        resp = client.post("/api/vulnerabilities/CVE-2020-35492/ghsa-refresh")
        assert resp.status_code == 400

    def test_ghsa_refresh_not_found_in_db(self, client):
        """Valid GHSA format but not in DB → 404."""
        resp = client.post("/api/vulnerabilities/GHSA-AAAA-BBBB-CCCC/ghsa-refresh")
        assert resp.status_code == 404

    def test_ghsa_refresh_http_error_404(self, client, app):
        """Lines 1129: GitHub API 404 → our 404."""
        import urllib.error
        from unittest.mock import patch
        from src.models.vulnerability import Vulnerability
        from src.extensions import db as _db

        with app.app_context():
            Vulnerability.create_record("GHSA-XXXX-YYYY-ZZZZ")
            _db.session.commit()

        err_404 = urllib.error.HTTPError(None, 404, "Not Found", {}, None)
        with patch("src.controllers.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published",
                   side_effect=err_404):
            resp = client.post("/api/vulnerabilities/GHSA-XXXX-YYYY-ZZZZ/ghsa-refresh")
        assert resp.status_code == 404

    def test_ghsa_refresh_url_error(self, client, app):
        """Lines 1129-1134: network error → 503."""
        import urllib.error
        from unittest.mock import patch
        from src.models.vulnerability import Vulnerability
        from src.extensions import db as _db

        with app.app_context():
            Vulnerability.create_record("GHSA-AAAB-BBBC-CCCD")
            _db.session.commit()

        with patch("src.controllers.vulnerabilities.VulnerabilitiesController._fetch_ghsa_published",
                   side_effect=urllib.error.URLError("timeout")):
            resp = client.post("/api/vulnerabilities/GHSA-AAAB-BBBC-CCCD/ghsa-refresh")
        assert resp.status_code == 503


# ===========================================================================
# controllers/vulnerabilities.py — unit-testable paths
# ===========================================================================

class TestVulnerabilitiesControllerGet:
    """Lines 158-159, 181-182, 220-221: get() alias and scoped-return-None paths."""

    def _make_ctrl(self, scope=None):
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.packages import PackagesController
        return VulnerabilitiesController(PackagesController(), scope=scope)

    def test_get_by_alias(self, app):
        """Lines 181-182: get() resolves alias → returns original vulnerability."""
        from src.models.vulnerability import Vulnerability as VulnModel

        ctrl = self._make_ctrl()
        with app.app_context():
            vuln = VulnModel("CVE-2099-ALIAS", [], "", "nvd")
            ctrl.vulnerabilities["CVE-2099-ALIAS"] = vuln
            ctrl.alias_registered["ALIAS-2099"] = "CVE-2099-ALIAS"
            result = ctrl.get("ALIAS-2099")
        assert result is vuln

    def test_get_returns_none_when_scoped_and_not_loaded(self, app):
        """Lines 220-221: scoped controller returns None for unloaded vuln."""
        from src.helpers.export_scope import ExportScope

        scope = ExportScope(variant_ids={_uuid.uuid4()}, package_ids=set())
        ctrl = self._make_ctrl(scope=scope)
        with app.app_context():
            result = ctrl.get("CVE-9999-NOTLOADED")
        assert result is None

    def test_get_fallback_to_db(self, app):
        """Lines 158-159: vuln not in cache → DB lookup."""
        from src.models.vulnerability import Vulnerability as VulnModel

        ctrl = self._make_ctrl()
        with app.app_context():
            VulnModel.create_record("CVE-2099-DBLOOKUP")
            result = ctrl.get("CVE-2099-DBLOOKUP")
        assert result is not None
        assert result.id == "CVE-2099-DBLOOKUP"


class TestVulnerabilitiesControllerIter:
    """Lines 701-702: __iter__ scoped vs unscoped."""

    def _make_ctrl(self, scope=None):
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.packages import PackagesController
        return VulnerabilitiesController(PackagesController(), scope=scope)

    def test_iter_scoped_returns_nothing(self, app):
        """Lines 701: scoped controller __iter__ returns early without yielding."""
        from src.helpers.export_scope import ExportScope

        scope = ExportScope(variant_ids={_uuid.uuid4()}, package_ids=set())
        ctrl = self._make_ctrl(scope=scope)
        with app.app_context():
            result = list(ctrl)
        assert result == []

    def test_iter_unscoped_yields_db_records(self, app):
        """Lines 701-702: unscoped __iter__ yields from Vulnerability.get_all()."""
        from src.models.vulnerability import Vulnerability as VulnModel

        ctrl = self._make_ctrl()
        with app.app_context():
            VulnModel.create_record("CVE-2099-ITER")
            vulns = list(ctrl)
        assert any(v.id == "CVE-2099-ITER" for v in vulns)
