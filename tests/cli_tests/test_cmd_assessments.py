# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Coverage tests for src/bin/cmd_assessments.py.

Targets uncovered branches:
  cmd_assessments.py – line 107 (assert variant_obj in single-variant export)
"""

import pytest
from unittest.mock import patch

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


class TestExportCustomOpenVexAssessments:
    """Cover the single-variant OpenVEX export path."""

    def test_export_with_variant_covers_assert(self, app, tmp_path):
        """Providing --variant exports custom assessments as one OpenVEX document."""
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.package import Package
        from src.models.vulnerability import Vulnerability
        from src.models.finding import Finding
        from src.models.assessment import Assessment

        with app.app_context():
            proj = Project.create("AssessProj")
            var = Variant.create("v1", proj.id)
            pkg = Package.create("testpkg", "1.0.0")
            vuln = Vulnerability.create_record("CVE-2099-1234")
            finding = Finding.create(pkg.id, vuln.id)
            Assessment.create(
                status="not_affected",
                finding_id=finding.id,
                variant_id=var.id,
                origin="custom",
            )
            _db.session.commit()

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "export-custom-openvex-assessments",
            "--project", "AssessProj",
            "--variant", "v1",
            "--output-dir", str(tmp_path),
        ])

        assert result.exit_code == 0, result.output
        assert "Custom OpenVEX assessments exported" in result.output
