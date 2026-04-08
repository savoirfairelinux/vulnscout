# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for src/routes/metrics.py.

Covers:
- Pure helper functions (_score_to_severity_index, _severity_text_to_index,
  _zeroise_dt, _prev_dt, _generate_checkpoints, _format_checkpoint_label,
  _compute_evolution)
- GET /api/metrics endpoint: global, variant-scoped, project-scoped, error cases
"""

import uuid
import pytest
import json
from datetime import datetime, timezone, timedelta

from src.bin.webapp import create_app
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Unit tests – helper functions (no Flask context needed)
# ---------------------------------------------------------------------------

from src.routes.metrics import (
    _score_to_severity_index,
    _severity_text_to_index,
    _zeroise_dt,
    _prev_dt,
    _generate_checkpoints,
    _format_checkpoint_label,
    _compute_evolution,
)


class TestScoreToSeverityIndex:
    def test_none_returns_0(self):
        assert _score_to_severity_index(None) == 0

    def test_zero_returns_0(self):
        assert _score_to_severity_index(0.0) == 0
        assert _score_to_severity_index(0) == 0

    def test_low(self):
        assert _score_to_severity_index(0.1) == 1
        assert _score_to_severity_index(3.9) == 1

    def test_medium(self):
        assert _score_to_severity_index(4.0) == 2
        assert _score_to_severity_index(6.9) == 2

    def test_high(self):
        assert _score_to_severity_index(7.0) == 3
        assert _score_to_severity_index(8.9) == 3

    def test_critical(self):
        assert _score_to_severity_index(9.0) == 4
        assert _score_to_severity_index(10.0) == 4

    def test_string_score(self):
        # Accepted because SQLAlchemy may return Decimal / str
        assert _score_to_severity_index("8.5") == 3


class TestSeverityTextToIndex:
    def test_none_returns_0(self):
        assert _severity_text_to_index(None) == 0

    def test_empty_string_returns_0(self):
        assert _severity_text_to_index("") == 0

    def test_unknown_returns_0(self):
        assert _severity_text_to_index("unknown") == 0

    def test_none_text_returns_0(self):
        assert _severity_text_to_index("none") == 0

    def test_low_returns_1(self):
        assert _severity_text_to_index("low") == 1

    def test_medium_returns_2(self):
        assert _severity_text_to_index("medium") == 2

    def test_high_returns_3(self):
        assert _severity_text_to_index("high") == 3

    def test_critical_returns_4(self):
        assert _severity_text_to_index("critical") == 4

    def test_case_insensitive(self):
        assert _severity_text_to_index("HIGH") == 3
        assert _severity_text_to_index("Critical") == 4


class TestZeroiseAndPrevDt:
    BASE = datetime(2024, 6, 15, 14, 35, 22, 123456, tzinfo=timezone.utc)

    def test_zeroise_month(self):
        result = _zeroise_dt(self.BASE, "months")
        assert result.day == 1
        assert result.hour == 0 and result.minute == 0

    def test_zeroise_day(self):
        result = _zeroise_dt(self.BASE, "days")
        assert result.hour == 0 and result.minute == 0 and result.second == 0

    def test_zeroise_week(self):
        result = _zeroise_dt(self.BASE, "weeks")
        assert result.hour == 0 and result.second == 0

    def test_zeroise_hour(self):
        result = _zeroise_dt(self.BASE, "hours")
        assert result.minute == 0 and result.second == 0 and result.microsecond == 0

    def test_prev_week(self):
        dt = datetime(2024, 6, 15, tzinfo=timezone.utc)
        result = _prev_dt(dt, "weeks")
        assert result == dt - timedelta(weeks=1)

    def test_prev_hour(self):
        dt = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        result = _prev_dt(dt, "hours")
        assert result == dt - timedelta(hours=1)

    def test_prev_day(self):
        dt = datetime(2024, 6, 15, tzinfo=timezone.utc)
        result = _prev_dt(dt, "days")
        assert result == dt - timedelta(days=1)

    def test_prev_month_steps_back_one_day(self):
        dt = datetime(2024, 6, 15, tzinfo=timezone.utc)
        result = _prev_dt(dt, "months")
        assert result == dt - timedelta(days=1)


class TestGenerateCheckpoints:
    def test_returns_correct_count(self):
        checkpoints = _generate_checkpoints(6, "months")
        assert len(checkpoints) == 6

    def test_oldest_first(self):
        checkpoints = _generate_checkpoints(5, "days")
        for i in range(len(checkpoints) - 1):
            assert checkpoints[i] <= checkpoints[i + 1]

    def test_all_timezone_aware(self):
        for cp in _generate_checkpoints(3, "hours"):
            assert cp.tzinfo is not None

    def test_weeks_unit(self):
        checkpoints = _generate_checkpoints(4, "weeks")
        assert len(checkpoints) == 4


class TestFormatCheckpointLabel:
    def test_hour_label(self):
        dt = datetime(2024, 6, 15, 9, 0, 0, tzinfo=timezone.utc)
        assert _format_checkpoint_label(dt, "hours") == "09:00"

    def test_month_label(self):
        dt = datetime(2024, 6, 1, tzinfo=timezone.utc)
        label = _format_checkpoint_label(dt, "months")
        assert "Jun" in label or "Jun" in label

    def test_day_label(self):
        dt = datetime(2024, 6, 15, tzinfo=timezone.utc)
        label = _format_checkpoint_label(dt, "days")
        assert "15" in label and "Jun" in label


class TestComputeEvolution:
    def _cp(self, days_ago: int) -> datetime:
        return datetime.now(timezone.utc) - timedelta(days=days_ago)

    def test_empty_assessments(self):
        cps = [self._cp(4), self._cp(3), self._cp(2), self._cp(1)]
        result = _compute_evolution({}, cps)
        assert result == [0, 0, 0, 0]

    def test_single_vuln_always_active(self):
        """A vuln with one 'Pending Assessment' covers all checkpoints."""
        cps = [self._cp(4), self._cp(3), self._cp(2), self._cp(1)]
        # Assessment created before all checkpoints
        ts = self._cp(10)
        data = {"CVE-001": [(ts, "Pending Assessment")]}
        result = _compute_evolution(data, cps)
        assert all(v == 1 for v in result)

    def test_fixed_vuln_does_not_count(self):
        """A vuln fixed before all checkpoints should not be active at any checkpoint."""
        cps = [self._cp(3), self._cp(2), self._cp(1)]
        ts_fixed = self._cp(10)
        data = {"CVE-001": [(ts_fixed, "Fixed")]}
        result = _compute_evolution(data, cps)
        assert result == [0, 0, 0]

    def test_vuln_fixed_after_first_checkpoint(self):
        """Vuln opened after cp[0] and fixed before cp[1]: counted at cp[0] only.

        The algorithm counts a checkpoint as active only when the 'open'
        assessment timestamp is >= that checkpoint.  A vuln opened inside
        the [cp[0], cp[1]) window is counted at cp[0] only.
        """
        cps = [self._cp(5), self._cp(3), self._cp(1)]
        ts_open = self._cp(4)    # after cp[0], before cp[1]
        ts_fix = self._cp(2)     # between cp[1] and cp[2]
        data = {"CVE-001": [(ts_open, "Pending Assessment"), (ts_fix, "Fixed")]}
        result = _compute_evolution(data, cps)
        # Opened after cp[0] → counted at cp[0]; fixed before cp[2] → not counted later
        assert result[0] == 1
        assert result[1] == 0
        assert result[2] == 0

    def test_naive_datetime_handled(self):
        """Naive datetimes are treated as UTC."""
        cps = [self._cp(3), self._cp(2), self._cp(1)]
        ts = datetime.now() - timedelta(days=10)  # naive
        data = {"CVE-NV": [(ts, "Exploitable")]}
        result = _compute_evolution(data, cps)
        assert sum(result) > 0


# ---------------------------------------------------------------------------
# Integration tests – GET /api/metrics endpoint
# ---------------------------------------------------------------------------

def _build_metrics_db(app):
    """Populate a full DB chain suitable for exercising /api/metrics."""
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.assessment import Assessment
    from src.models.metrics import Metrics

    with app.app_context():
        _db.drop_all()
        _db.create_all()

        project = Project.create("MetricsProject")
        variant = Variant.create("default", project.id)
        scan = Scan.create("scan1", variant.id)

        pkg = Package.find_or_create("cairo", "1.16.0")
        vuln = Vulnerability.create_record(
            id="CVE-2020-35492",
            description="cairo vuln",
            status="high",
            epss_score=0.3,
            links=[],
        )
        finding = Finding.get_or_create(pkg.id, vuln.id)
        _db.session.commit()

        sbom = SBOMDocument.create("/grype.json", "grype", scan.id, format="grype")
        SBOMPackage.create(sbom.id, pkg.id)
        Observation.create(finding_id=finding.id, scan_id=scan.id)

        # Assessment: fixed
        assess = Assessment(
            id=uuid.uuid4(),
            status="fixed",
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            finding_id=finding.id,
            responses=[],
        )
        _db.session.add(assess)

        # CVSS score
        Metrics.create(vulnerability_id="CVE-2020-35492", version="3.1", score=8.5)

        _db.session.commit()

        return {
            "project_id": str(project.id),
            "variant_id": str(variant.id),
            "scan_id": str(scan.id),
        }


@pytest.fixture()
def app(tmp_path):
    import os
    scan_file = tmp_path / "status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": str(scan_file),
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db",
        })
        ids = _build_metrics_db(application)
        application._test_ids = ids
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def ids(app):
    return app._test_ids


# ---------------------------------------------------------------------------
# Response shape
# ---------------------------------------------------------------------------

class TestMetricsResponseShape:
    def test_global_returns_200(self, client):
        response = client.get("/api/metrics")
        assert response.status_code == 200

    def test_global_has_all_keys(self, client):
        data = json.loads(client.get("/api/metrics").data)
        for key in ("vuln_by_severity", "vuln_by_status", "vuln_evolution",
                    "vuln_by_source", "top_packages", "top_vulns"):
            assert key in data, f"Missing key: {key}"

    def test_vuln_by_severity_has_5_elements(self, client):
        data = json.loads(client.get("/api/metrics").data)
        assert len(data["vuln_by_severity"]) == 5

    def test_vuln_by_status_has_4_elements(self, client):
        data = json.loads(client.get("/api/metrics").data)
        assert len(data["vuln_by_status"]) == 4

    def test_vuln_evolution_has_labels_and_data(self, client):
        data = json.loads(client.get("/api/metrics").data)
        evo = data["vuln_evolution"]
        assert "labels" in evo and "data" in evo
        assert len(evo["labels"]) == len(evo["data"])

    def test_top_packages_is_list(self, client):
        data = json.loads(client.get("/api/metrics").data)
        assert isinstance(data["top_packages"], list)

    def test_top_vulns_is_list(self, client):
        data = json.loads(client.get("/api/metrics").data)
        assert isinstance(data["top_vulns"], list)


# ---------------------------------------------------------------------------
# time_scale parameter
# ---------------------------------------------------------------------------

class TestMetricsTimeScale:
    def test_default_6_months(self, client):
        data = json.loads(client.get("/api/metrics").data)
        assert len(data["vuln_evolution"]["labels"]) == 6

    def test_custom_scale_3_weeks(self, client):
        data = json.loads(client.get("/api/metrics?time_scale=3_weeks").data)
        assert len(data["vuln_evolution"]["labels"]) == 3

    def test_custom_scale_12_days(self, client):
        data = json.loads(client.get("/api/metrics?time_scale=12_days").data)
        assert len(data["vuln_evolution"]["labels"]) == 12

    def test_custom_scale_hours(self, client):
        data = json.loads(client.get("/api/metrics?time_scale=24_hours").data)
        assert len(data["vuln_evolution"]["labels"]) == 24

    def test_invalid_time_scale_missing_underscore(self, client):
        response = client.get("/api/metrics?time_scale=6months")
        assert response.status_code == 400
        assert "time_scale" in json.loads(response.data)["error"]

    def test_invalid_time_scale_non_integer(self, client):
        response = client.get("/api/metrics?time_scale=abc_months")
        assert response.status_code == 400

    def test_invalid_time_scale_bad_unit(self, client):
        response = client.get("/api/metrics?time_scale=6_years")
        assert response.status_code == 400

    def test_invalid_time_scale_too_small(self, client):
        response = client.get("/api/metrics?time_scale=1_months")
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# Scope filtering – variant_id / project_id
# ---------------------------------------------------------------------------

class TestMetricsScoping:
    def test_valid_variant_id_returns_data(self, client, ids):
        response = client.get(f"/api/metrics?variant_id={ids['variant_id']}")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "vuln_by_severity" in data

    def test_invalid_variant_id_returns_400(self, client):
        response = client.get("/api/metrics?variant_id=not-a-uuid")
        assert response.status_code == 400
        assert "variant_id" in json.loads(response.data)["error"]

    def test_valid_project_id_returns_data(self, client, ids):
        response = client.get(f"/api/metrics?project_id={ids['project_id']}")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "vuln_by_severity" in data

    def test_invalid_project_id_returns_400(self, client):
        response = client.get("/api/metrics?project_id=not-a-uuid")
        assert response.status_code == 400
        assert "project_id" in json.loads(response.data)["error"]

    def test_unknown_variant_returns_empty_response(self, client):
        """A valid UUID that has no scan returns zeroed-out metrics."""
        unknown = str(uuid.uuid4())
        response = client.get(f"/api/metrics?variant_id={unknown}")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["vuln_by_severity"] == [0, 0, 0, 0, 0]
        assert data["top_packages"] == []
        assert data["top_vulns"] == []

    def test_unknown_project_returns_empty_response(self, client):
        """A valid project UUID with no scans returns zeroed-out metrics."""
        unknown = str(uuid.uuid4())
        response = client.get(f"/api/metrics?project_id={unknown}")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["vuln_by_severity"] == [0, 0, 0, 0, 0]


# ---------------------------------------------------------------------------
# Content – counts / values
# ---------------------------------------------------------------------------

class TestMetricsContent:
    def test_global_severity_total_equals_vuln_count(self, client):
        """Sum of vuln_by_severity should equal number of vulnerabilities."""
        data = json.loads(client.get("/api/metrics").data)
        total = sum(data["vuln_by_severity"])
        assert total == 1  # one CVE in the demo DB

    def test_global_status_total_equals_vuln_count(self, client):
        data = json.loads(client.get("/api/metrics").data)
        total = sum(data["vuln_by_status"])
        assert total == 1

    def test_fixed_vuln_counted_in_status(self, client):
        """Demo vuln has a 'fixed' assessment → status_counts[1] should be 1."""
        data = json.loads(client.get("/api/metrics").data)
        assert data["vuln_by_status"][1] == 1  # index 1 = Fixed

    def test_source_label_present_when_grype(self, client):
        """grype doc in demo DB → 'Grype' appears in vuln_by_source labels."""
        data = json.loads(client.get("/api/metrics").data)
        labels = data["vuln_by_source"]["labels"]
        assert "Grype" in labels

    def test_top_packages_populated(self, client):
        data = json.loads(client.get("/api/metrics").data)
        pkgs = data["top_packages"]
        assert len(pkgs) >= 1
        assert pkgs[0]["name"] == "cairo"

    def test_top_packages_entry_has_required_fields(self, client):
        data = json.loads(client.get("/api/metrics").data)
        pkg = data["top_packages"][0]
        assert "id" in pkg and "name" in pkg and "version" in pkg and "count" in pkg

    def test_scoped_by_variant_matches_global_for_single_variant(self, client, ids):
        """Scoping to the only variant in the DB yields same counts as global query."""
        global_data = json.loads(client.get("/api/metrics").data)
        scoped_data = json.loads(
            client.get(f"/api/metrics?variant_id={ids['variant_id']}").data
        )
        assert sum(scoped_data["vuln_by_severity"]) == sum(global_data["vuln_by_severity"])

    def test_scoped_by_project_matches_global(self, client, ids):
        global_data = json.loads(client.get("/api/metrics").data)
        scoped_data = json.loads(
            client.get(f"/api/metrics?project_id={ids['project_id']}").data
        )
        assert sum(scoped_data["vuln_by_severity"]) == sum(global_data["vuln_by_severity"])


# ---------------------------------------------------------------------------
# top_vulns – 'Fixed' vuln should NOT appear (active only)
# ---------------------------------------------------------------------------

class TestMetricsTopVulns:
    def test_fixed_vuln_not_in_top_vulns(self, client):
        """Fixed vulnerability must not appear in top_vulns."""
        data = json.loads(client.get("/api/metrics").data)
        cve_ids = [entry["cve"] for entry in data["top_vulns"]]
        assert "CVE-2020-35492" not in cve_ids

    def test_top_vulns_empty_when_all_fixed(self, client):
        """Since the only vuln is Fixed, top_vulns must be []."""
        data = json.loads(client.get("/api/metrics").data)
        assert data["top_vulns"] == []

    def test_top_vulns_populated_for_open_vuln(self, app, client, ids):
        """Add a second 'Pending Assessment' vuln – it should appear in top_vulns."""
        with app.app_context():
            from src.models.vulnerability import Vulnerability
            from src.models.finding import Finding
            from src.models.observation import Observation
            from src.models.package import Package

            pkg = _db.session.execute(_db.select(Package)).scalars().first()
            from src.models.scan import Scan
            scan = _db.session.execute(_db.select(Scan)).scalars().first()

            vuln2 = Vulnerability.create_record(
                id="CVE-2099-00001",
                description="open vuln",
                status="high",
                epss_score=0.5,
                links=[],
            )
            finding2 = Finding.get_or_create(pkg.id, vuln2.id)
            _db.session.commit()
            Observation.create(finding_id=finding2.id, scan_id=scan.id)

        data = json.loads(client.get("/api/metrics").data)
        cve_ids = [entry["cve"] for entry in data["top_vulns"]]
        assert "CVE-2099-00001" in cve_ids

    def test_top_vuln_entry_has_required_fields(self, app, client):
        """When populated, each top_vulns entry has the expected keys."""
        with app.app_context():
            from src.models.vulnerability import Vulnerability
            from src.models.finding import Finding
            from src.models.observation import Observation
            from src.models.package import Package
            from src.models.scan import Scan

            pkg = _db.session.execute(_db.select(Package)).scalars().first()
            scan = _db.session.execute(_db.select(Scan)).scalars().first()

            vuln3 = Vulnerability.create_record(
                id="CVE-2099-00002",
                description="open vuln 2",
                status="high",
                epss_score=0.6,
                links=[],
            )
            finding3 = Finding.get_or_create(pkg.id, vuln3.id)
            _db.session.commit()
            Observation.create(finding_id=finding3.id, scan_id=scan.id)

        data = json.loads(client.get("/api/metrics").data)
        if data["top_vulns"]:
            entry = data["top_vulns"][0]
            for field in ("rank", "cve", "package", "severity", "max_cvss", "texts", "vuln"):
                assert field in entry, f"Missing field: {field}"
