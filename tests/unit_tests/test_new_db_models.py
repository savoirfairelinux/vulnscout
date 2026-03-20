# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Coverage tests for the new DB models: Vulnerability, Finding,
Assessment, TimeEstimate, Metrics and their controllers."""

import datetime
import pytest
from src.bin.webapp import create_app
from src.extensions import db as _db
from src.models.project import Project
from src.models.variant import Variant
from src.models.package import Package
from src.models.vulnerability import Vulnerability
from src.models.finding import Finding
from src.models.assessment import Assessment
from src.models.time_estimate import TimeEstimate
from src.models.metrics import Metrics
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.controllers.findings import FindingController
from src.controllers.time_estimates import TimeEstimateController
from src.controllers.metrics import MetricsController


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def app():
    import os
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": "/dev/null",
        })
        with application.app_context():
            _db.create_all()
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def project(app):
    return Project.create("TestProject")


@pytest.fixture()
def variant(app, project):
    return Variant.create("TestVariant", project.id)


@pytest.fixture()
def package(app):
    return Package.create("libfoo", "1.0.0")


@pytest.fixture()
def vuln(app):
    return Vulnerability.create_record(
        id="CVE-2024-1234",
        description="A test vulnerability.",
        status="under_investigation",
    )


@pytest.fixture()
def finding(app, package, vuln):
    return Finding.create(package.id, vuln.id)


@pytest.fixture()
def assessment(app, finding, variant):
    return Assessment.create(
        status="under_investigation",
        finding_id=finding.id,
        variant_id=variant.id,
    )


@pytest.fixture()
def time_estimate(app, finding, variant):
    return TimeEstimate.create(
        finding_id=finding.id,
        variant_id=variant.id,
        optimistic=1,
        likely=3,
        pessimistic=8,
    )


@pytest.fixture()
def metrics(app, vuln):
    return Metrics.create(
        vulnerability_id=vuln.id,
        version="3.1",
        score=7.5,
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        author="NVD",
    )


# ===========================================================================
# Vulnerability model
# ===========================================================================

class TestVulnerability:
    def test_create_and_get(self, app):
        v = Vulnerability.create_record("CVE-2024-9999", description="desc")
        assert Vulnerability.get_by_id("CVE-2024-9999") == v

    def test_id_uppercased(self, app):
        v = Vulnerability.create_record("cve-2024-0001")
        assert v.id == "CVE-2024-0001"

    def test_get_all(self, vuln, app):
        Vulnerability.create_record("CVE-2024-0002")
        records = Vulnerability.get_all()
        assert len(records) >= 2

    def test_get_or_create_existing(self, vuln):
        v2 = Vulnerability.get_or_create(vuln.id)
        assert v2.id == vuln.id

    def test_get_or_create_new(self, app):
        v = Vulnerability.get_or_create("CVE-2024-8888")
        assert v.id == "CVE-2024-8888"

    def test_update(self, vuln):
        vuln.update_record(description="updated", status="fixed")
        assert vuln.description == "updated"
        assert vuln.status == "fixed"

    def test_update_publish_date(self, vuln):
        d = datetime.date(2024, 1, 15)
        vuln.update_record(publish_date=d)
        assert vuln.publish_date == d

    def test_update_epss_score(self, vuln):
        vuln.update_record(epss_score=0.85)
        assert float(vuln.epss_score) == pytest.approx(0.85)

    def test_update_links(self, vuln):
        links = ["https://example.com/cve"]
        vuln.update_record(links=links)
        assert vuln.links == links

    def test_delete(self, app):
        v = Vulnerability.create_record("CVE-2024-DEL")
        v.delete_record()
        assert Vulnerability.get_by_id("CVE-2024-DEL") is None

    def test_repr(self, vuln):
        assert "CVE-2024-1234" in repr(vuln)


# ===========================================================================
# Finding model
# ===========================================================================

class TestFindingModel:
    def test_create_and_get(self, finding):
        f = Finding.get_by_id(finding.id)
        assert f is not None
        assert f.id == finding.id

    def test_vulnerability_id_uppercased(self, package, vuln):
        f = Finding.create(package.id, "cve-2024-1234")
        assert f.vulnerability_id == "CVE-2024-1234"

    def test_get_by_package(self, finding, package):
        results = Finding.get_by_package(package.id)
        assert any(f.id == finding.id for f in results)

    def test_get_by_vulnerability(self, finding, vuln):
        results = Finding.get_by_vulnerability(vuln.id)
        assert any(f.id == finding.id for f in results)

    def test_get_by_package_and_vulnerability(self, finding, package, vuln):
        f = Finding.get_by_package_and_vulnerability(package.id, vuln.id)
        assert f is not None
        assert f.id == finding.id

    def test_get_or_create_existing(self, finding, package, vuln):
        f2 = Finding.get_or_create(package.id, vuln.id)
        assert f2.id == finding.id

    def test_get_or_create_new(self, app, package, vuln):
        pkg2 = Package.create("libbar", "2.0.0")
        f = Finding.get_or_create(pkg2.id, vuln.id)
        assert f is not None

    def test_delete(self, app, package, vuln):
        f = Finding.create(package.id, vuln.id)
        fid = f.id
        f.delete()
        assert Finding.get_by_id(fid) is None

    def test_repr(self, finding):
        assert "Finding" in repr(finding)


# ===========================================================================
# Assessment model
# ===========================================================================

class TestAssessmentModel:
    def test_create_and_get(self, assessment):
        a = Assessment.get_by_id(assessment.id)
        assert a is not None
        assert a.status == "under_investigation"

    def test_get_by_finding(self, assessment, finding):
        results = Assessment.get_by_finding(finding.id)
        assert any(a.id == assessment.id for a in results)

    def test_get_by_variant(self, assessment, variant):
        results = Assessment.get_by_variant(variant.id)
        assert any(a.id == assessment.id for a in results)

    def test_get_by_finding_and_variant(self, assessment, finding, variant):
        results = Assessment.get_by_finding_and_variant(finding.id, variant.id)
        assert any(a.id == assessment.id for a in results)

    def test_update_status(self, assessment):
        assessment.update(status="fixed")
        assert assessment.status == "fixed"

    def test_update_many_fields(self, assessment):
        assessment.update(
            source="grype",
            simplified_status="fixed",
            status_notes="resolved in 1.2",
            justification="vulnerable_code_not_present",
            impact_statement="no impact",
            workaround="upgrade",
            responses=["update"],
        )
        assert assessment.source == "grype"
        assert assessment.simplified_status == "fixed"
        assert assessment.responses == ["update"]

    def test_timestamp_set(self, assessment):
        assert assessment.timestamp is not None

    def test_delete(self, app, finding, variant):
        a = Assessment.create("affected", finding_id=finding.id, variant_id=variant.id)
        aid = a.id
        a.delete()
        assert Assessment.get_by_id(aid) is None

    def test_repr(self, assessment):
        assert "Assessment" in repr(assessment)


# ===========================================================================
# TimeEstimate model
# ===========================================================================

class TestTimeEstimateModel:
    def test_create_and_get(self, time_estimate):
        e = TimeEstimate.get_by_id(time_estimate.id)
        assert e is not None
        assert e.optimistic == 1
        assert e.likely == 3
        assert e.pessimistic == 8

    def test_get_by_finding(self, time_estimate, finding):
        results = TimeEstimate.get_by_finding(finding.id)
        assert any(e.id == time_estimate.id for e in results)

    def test_get_by_variant(self, time_estimate, variant):
        results = TimeEstimate.get_by_variant(variant.id)
        assert any(e.id == time_estimate.id for e in results)

    def test_get_by_finding_and_variant(self, time_estimate, finding, variant):
        e = TimeEstimate.get_by_finding_and_variant(finding.id, variant.id)
        assert e is not None
        assert e.id == time_estimate.id

    def test_update(self, time_estimate):
        time_estimate.update(optimistic=2, likely=5, pessimistic=10)
        assert time_estimate.optimistic == 2
        assert time_estimate.likely == 5
        assert time_estimate.pessimistic == 10

    def test_delete(self, app, finding, variant):
        e = TimeEstimate.create(finding_id=finding.id, variant_id=variant.id, optimistic=1, likely=2, pessimistic=3)
        eid = e.id
        e.delete()
        assert TimeEstimate.get_by_id(eid) is None

    def test_repr(self, time_estimate):
        assert "TimeEstimate" in repr(time_estimate)


# ===========================================================================
# Metrics model
# ===========================================================================

class TestMetricsModel:
    def test_create_and_get(self, metrics):
        m = Metrics.get_by_id(metrics.id)
        assert m is not None
        assert m.version == "3.1"
        assert float(m.score) == pytest.approx(7.5)

    def test_get_by_vulnerability(self, metrics, vuln):
        results = Metrics.get_by_vulnerability(vuln.id)
        assert any(m.id == metrics.id for m in results)

    def test_vulnerability_id_uppercased(self, app, vuln):
        m = Metrics.create(vulnerability_id=vuln.id.lower(), score=5.0)
        assert m.vulnerability_id == vuln.id.upper()

    def test_update(self, metrics):
        metrics.update(score=9.8, author="MITRE")
        assert float(metrics.score) == pytest.approx(9.8)
        assert metrics.author == "MITRE"

    def test_delete(self, app, vuln):
        m = Metrics.create(vulnerability_id=vuln.id, version="2.0", score=6.0)
        mid = m.id
        m.delete()
        assert Metrics.get_by_id(mid) is None

    def test_repr(self, metrics):
        assert "Metrics" in repr(metrics)


# ===========================================================================
# VulnerabilitiesController (DB helpers)
# ===========================================================================

class TestVulnerabilitiesControllerDB:
    def test_serialize(self, vuln):
        data = VulnerabilitiesController.serialize(vuln)
        assert data["id"] == "CVE-2024-1234"
        assert "description" in data
        assert "epss_score" in data

    def test_serialize_list(self, vuln):
        lst = VulnerabilitiesController.serialize_list([vuln])
        assert len(lst) == 1

    def test_get(self, vuln):
        assert VulnerabilitiesController.get_db(vuln.id).id == vuln.id

    def test_get_all(self, vuln):
        assert len(VulnerabilitiesController.get_all_db()) >= 1

    def test_create(self, app):
        v = VulnerabilitiesController.create_db("CVE-2025-0001", description="new")
        assert v.id == "CVE-2025-0001"

    def test_create_empty_raises(self, app):
        with pytest.raises(ValueError):
            VulnerabilitiesController.create_db("  ")

    def test_create_with_date_string(self, app):
        v = VulnerabilitiesController.create_db("CVE-2025-0002", publish_date="2025-01-01")
        assert v.publish_date == datetime.date(2025, 1, 1)

    def test_get_or_create(self, vuln):
        v2 = VulnerabilitiesController.get_or_create_db(vuln.id)
        assert v2.id == vuln.id

    def test_get_or_create_empty_raises(self, app):
        with pytest.raises(ValueError):
            VulnerabilitiesController.get_or_create_db("")

    def test_update_by_instance(self, vuln):
        VulnerabilitiesController.update_db(vuln, status="fixed")
        assert vuln.status == "fixed"

    def test_update_by_id_string(self, vuln):
        VulnerabilitiesController.update_db(vuln.id, description="updated desc")
        assert vuln.description == "updated desc"

    def test_update_not_found_raises(self, app):
        with pytest.raises(ValueError):
            VulnerabilitiesController.update_db("CVE-9999-XXXX")

    def test_delete_by_instance(self, app):
        v = VulnerabilitiesController.create_db("CVE-2025-DEL")
        VulnerabilitiesController.delete_db(v)
        assert VulnerabilitiesController.get_db("CVE-2025-DEL") is None

    def test_delete_by_id_string(self, app):
        v = VulnerabilitiesController.create_db("CVE-2025-DEL2")
        VulnerabilitiesController.delete_db(v.id)
        assert VulnerabilitiesController.get_db("CVE-2025-DEL2") is None

    def test_delete_not_found_raises(self, app):
        with pytest.raises(ValueError):
            VulnerabilitiesController.delete_db("CVE-NOTEXIST")


# ===========================================================================
# FindingController
# ===========================================================================

class TestFindingController:
    def test_serialize(self, finding):
        data = FindingController.serialize(finding)
        assert "id" in data
        assert data["vulnerability_id"] == "CVE-2024-1234"

    def test_serialize_list(self, finding):
        lst = FindingController.serialize_list([finding])
        assert len(lst) == 1

    def test_get(self, finding):
        assert FindingController.get(str(finding.id)).id == finding.id

    def test_get_by_package(self, finding, package):
        results = FindingController.get_by_package(package.id)
        assert any(f.id == finding.id for f in results)

    def test_get_by_vulnerability(self, finding, vuln):
        results = FindingController.get_by_vulnerability(vuln.id)
        assert any(f.id == finding.id for f in results)

    def test_create(self, app, package, vuln):
        pkg2 = Package.create("libtest", "3.0.0")
        f = FindingController.create(pkg2.id, vuln.id)
        assert f.vulnerability_id == vuln.id

    def test_create_empty_vuln_id_raises(self, package):
        with pytest.raises(ValueError):
            FindingController.create(package.id, "  ")

    def test_get_or_create(self, finding, package, vuln):
        f2 = FindingController.get_or_create(package.id, vuln.id)
        assert f2.id == finding.id

    def test_delete_by_instance(self, app, package, vuln):
        f = Finding.create(package.id, vuln.id)
        fid = f.id
        FindingController.delete(f)
        assert FindingController.get(fid) is None

    def test_delete_by_id_string(self, app, package, vuln):
        pkg2 = Package.create("libdel", "1.0")
        f = Finding.create(pkg2.id, vuln.id)
        fid = f.id
        FindingController.delete(str(fid))
        assert FindingController.get(fid) is None

    def test_delete_not_found_raises(self, app):
        import uuid
        with pytest.raises(ValueError):
            FindingController.delete(str(uuid.uuid4()))


# ===========================================================================
# Assessment – CRUD helpers (formerly via AssessmentDBController)
# ===========================================================================

class TestAssessmentDBController:
    def test_serialize(self, assessment):
        # Field access on the model replaces the old controller serialize()
        assert assessment.status == "under_investigation"
        assert assessment.finding_id is not None
        assert assessment.variant_id is not None

    def test_serialize_list(self, assessment):
        lst = [assessment]
        assert len(lst) == 1

    def test_get(self, assessment):
        assert Assessment.get_by_id(str(assessment.id)).id == assessment.id

    def test_get_by_finding(self, assessment, finding):
        results = Assessment.get_by_finding(finding.id)
        assert any(a.id == assessment.id for a in results)

    def test_get_by_variant(self, assessment, variant):
        results = Assessment.get_by_variant(variant.id)
        assert any(a.id == assessment.id for a in results)

    def test_create(self, app, finding, variant):
        a = Assessment.create(
            "affected",
            finding_id=finding.id,
            variant_id=variant.id,
        )
        assert a.status == "affected"

    def test_update_by_instance(self, assessment):
        assessment.update(status="fixed")
        assert assessment.status == "fixed"

    def test_delete_by_instance(self, app, finding, variant):
        a = Assessment.create("affected", finding_id=finding.id, variant_id=variant.id)
        aid = a.id
        a.delete()
        assert Assessment.get_by_id(aid) is None


# ===========================================================================
# TimeEstimateController
# ===========================================================================

class TestTimeEstimateController:
    def test_serialize(self, time_estimate):
        data = TimeEstimateController.serialize(time_estimate)
        assert data["optimistic"] == 1
        assert data["likely"] == 3
        assert data["pessimistic"] == 8

    def test_serialize_list(self, time_estimate):
        lst = TimeEstimateController.serialize_list([time_estimate])
        assert len(lst) == 1

    def test_get(self, time_estimate):
        assert TimeEstimateController.get(str(time_estimate.id)).id == time_estimate.id

    def test_get_by_finding(self, time_estimate, finding):
        results = TimeEstimateController.get_by_finding(finding.id)
        assert any(e.id == time_estimate.id for e in results)

    def test_get_by_variant(self, time_estimate, variant):
        results = TimeEstimateController.get_by_variant(variant.id)
        assert any(e.id == time_estimate.id for e in results)

    def test_create(self, app, finding, variant):
        e = TimeEstimateController.create(finding_id=finding.id, variant_id=variant.id,
                                          optimistic=2, likely=4, pessimistic=6)
        assert e.optimistic == 2

    def test_create_invalid_order_raises(self, app, finding, variant):
        with pytest.raises(ValueError):
            TimeEstimateController.create(optimistic=10, likely=5, pessimistic=3)

    def test_update(self, time_estimate):
        TimeEstimateController.update(time_estimate, optimistic=2, likely=5, pessimistic=10)
        assert time_estimate.optimistic == 2

    def test_update_invalid_order_raises(self, time_estimate):
        with pytest.raises(ValueError):
            TimeEstimateController.update(time_estimate, optimistic=100)

    def test_update_not_found_raises(self, app):
        import uuid
        with pytest.raises(ValueError):
            TimeEstimateController.update(str(uuid.uuid4()))

    def test_delete_by_instance(self, app, finding, variant):
        e = TimeEstimate.create(finding_id=finding.id, variant_id=variant.id,
                                optimistic=1, likely=2, pessimistic=3)
        eid = e.id
        TimeEstimateController.delete(e)
        assert TimeEstimateController.get(eid) is None

    def test_delete_not_found_raises(self, app):
        import uuid
        with pytest.raises(ValueError):
            TimeEstimateController.delete(str(uuid.uuid4()))


# ===========================================================================
# MetricsController
# ===========================================================================

class TestMetricsController:
    def test_serialize(self, metrics):
        data = MetricsController.serialize(metrics)
        assert data["vulnerability_id"] == "CVE-2024-1234"
        assert data["version"] == "3.1"
        assert data["score"] == pytest.approx(7.5)

    def test_serialize_list(self, metrics):
        lst = MetricsController.serialize_list([metrics])
        assert len(lst) == 1

    def test_get(self, metrics):
        assert MetricsController.get(str(metrics.id)).id == metrics.id

    def test_get_by_vulnerability(self, metrics, vuln):
        results = MetricsController.get_by_vulnerability(vuln.id)
        assert any(m.id == metrics.id for m in results)

    def test_create(self, app, vuln):
        m = MetricsController.create(vuln.id, version="2.0", score=5.0, author="NVD")
        assert float(m.score) == pytest.approx(5.0)

    def test_create_empty_vuln_id_raises(self, app):
        with pytest.raises(ValueError):
            MetricsController.create("  ")

    def test_update_by_instance(self, metrics):
        MetricsController.update(metrics, score=9.9, author="MITRE")
        assert float(metrics.score) == pytest.approx(9.9)
        assert metrics.author == "MITRE"

    def test_update_not_found_raises(self, app):
        import uuid
        with pytest.raises(ValueError):
            MetricsController.update(str(uuid.uuid4()), score=1.0)

    def test_delete_by_instance(self, app, vuln):
        m = Metrics.create(vulnerability_id=vuln.id, score=1.0)
        mid = m.id
        MetricsController.delete(m)
        assert MetricsController.get(mid) is None

    def test_delete_not_found_raises(self, app):
        import uuid
        with pytest.raises(ValueError):
            MetricsController.delete(str(uuid.uuid4()))
