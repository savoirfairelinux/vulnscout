# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for ``src/routes/scans.py``'s tool-scan diff endpoint.

The import-deduplication coverage this file used to carry for
``_existing_assessment_identities`` (a scalar-mirror vs. target-join
equivalence check from the PR-B migration window) now lives in
``test_scan_target_join.py``, which exercises it against a genuine
multi-target assessment. What remains here is the one thing that file does
not cover: the tool scan diff's ``newly_detected_assessments`` listing, at
the HTTP level.
"""

import os

import pytest


@pytest.fixture()
def app(tmp_path):
    from src.bin.webapp import create_app
    from src.extensions import db as _db

    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
        with application.app_context():
            _db.create_all()
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


def _finding(vuln_id: str, pkg_name: str, version: str = "1.0.0"):
    from src.extensions import db
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability

    vuln = db.session.get(Vulnerability, vuln_id.upper()) or Vulnerability.create_record(id=vuln_id)
    package = Package.find_or_create(pkg_name, version)
    db.session.commit()
    return Finding.get_or_create(package.id, vuln.id)


class TestNewlyDetectedAssessments:
    """A tool scan's diff lists its new assessments through their target rows."""

    def _seed(self, app):
        import time
        from src.extensions import db
        from src.models.assessment import Assessment
        from src.models.observation import Observation
        from src.models.package import Package
        from src.models.project import Project
        from src.models.sbom_document import SBOMDocument
        from src.models.sbom_package import SBOMPackage
        from src.models.scan import Scan
        from src.models.variant import Variant

        project = Project.create(name="diff")
        variant = Variant.create(name="v", project_id=project.id)

        sbom_scan = Scan.create("sbom", variant.id, scan_type="sbom")
        package = Package.find_or_create("openssl", "1.0.0")
        db.session.commit()
        document = SBOMDocument.create("/sbom.json", "spdx", sbom_scan.id)
        SBOMPackage.create(document.id, package.id)
        db.session.commit()

        time.sleep(0.05)
        # A pre-existing assessment from an earlier tool scan of the same
        # variant.  It belongs to the "before" set, so a join that widened the
        # result set would surface it beside the new one.
        old_scan = Scan.create("nvd", variant.id, scan_type="tool")
        old_scan.scan_source = "nvd"
        old_finding = _finding("CVE-2026-9011", "openssl")
        Observation.create(finding_id=old_finding.id, scan_id=old_scan.id)
        db.session.commit()
        old_assessment = Assessment.create(
            status="affected", origin="nvd", status_notes="old",
            targets=[(variant.id, old_finding.id)],
        )
        old_assessment.timestamp = old_scan.timestamp
        db.session.commit()

        time.sleep(0.05)
        tool_scan = Scan.create("nvd", variant.id, scan_type="tool")
        tool_scan.scan_source = "nvd"
        finding = _finding("CVE-2026-9010", "openssl")
        Observation.create(finding_id=finding.id, scan_id=tool_scan.id)
        db.session.commit()

        assessment = Assessment.create(
            status="not_affected", origin="nvd", status_notes="note",
            targets=[(variant.id, finding.id)],
        )
        assessment.timestamp = tool_scan.timestamp
        db.session.commit()
        return {"tool_scan": str(tool_scan.id), "assessment": assessment.id}

    def test_lists_the_new_assessment(self, app):
        with app.app_context():
            ids = self._seed(app)

        response = app.test_client().get(f"/api/scans/{ids['tool_scan']}/export-diff")

        assert response.status_code == 200
        assert response.get_json()["newly_detected_assessments"] == [{
            "vulnerability_id": "CVE-2026-9010", "status": "not_affected",
            "simplified_status": "Pending Assessment", "justification": "",
            "impact_statement": "", "status_notes": "note",
        }]
