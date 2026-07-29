# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Coverage tests for src/bin/cmd_assessments.py."""

import json
import pytest
from datetime import datetime, timezone
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


class TestExportCustomVulnScoutData:
    """Cover the custom JSON export path."""

    def test_export_includes_pending_ai_assessments(self, app, tmp_path):
        """AI rows are preserved for the Review page AI Assessments tab."""
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.package import Package
        from src.models.vulnerability import Vulnerability
        from src.models.finding import Finding
        from src.models.assessment import Assessment

        with app.app_context():
            project = Project.create("AiAssessProj")
            variant = Variant.create("v1", project.id)
            package = Package.create("testpkg", "1.0.0")
            vulnerability = Vulnerability.create_record("CVE-2099-5678")
            finding = Finding.create(package.id, vulnerability.id)
            Assessment.create(
                status="under_investigation",
                finding_id=finding.id,
                variant_id=variant.id,
                origin="ai",
            )

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "export-custom-vulnscout-data",
            "--project", "AiAssessProj",
            "--output-dir", str(tmp_path),
        ])

        assert result.exit_code == 0, result.output
        exported_path = tmp_path / "custom_vulnscout_data_all.json"
        exported = json.loads(exported_path.read_text())
        assert exported["assessments"] == []
        assert len(exported["ai_assessments"]) == 1
        assert exported["ai_assessments"][0]["vuln_id"] == "CVE-2099-5678"


class TestImportTimestampOptions:
    def test_vulnscout_import_can_preserve_original_timestamps(self, app, tmp_path):
        from src.helpers.datetime_utils import ensure_utc_iso
        from src.models.assessment import Assessment
        from src.models.project import Project
        from src.models.variant import Variant

        original_timestamp = "2001-02-03T04:05:06+00:00"
        with app.app_context():
            project = Project.create("TimestampProject")
            variant = Variant.create("vulnscout", project.id)
            project_name = project.name
            variant_id = variant.id

        import_file = tmp_path / "custom-vulnscout.json"
        import_file.write_text(json.dumps({
            "version": 1,
            "assessments": [{
                "vuln_id": "CVE-2099-10001",
                "status": "affected",
                "packages": ["vulnscout-timestamp@1.0"],
                "variant_id": str(variant_id),
                "timestamp": original_timestamp,
            }],
        }))

        result = app.test_cli_runner().invoke(args=[
            "import-custom-vulnscout-data",
            "--project", project_name,
            "--use-original-timestamps",
            str(import_file),
        ])

        assert result.exit_code == 0, result.output
        with app.app_context():
            imported = Assessment.get_by_origin([variant_id], origin="custom")
            assert len(imported) == 1
            assert ensure_utc_iso(imported[0].timestamp) == original_timestamp

    def test_vulnscout_import_can_use_current_timestamps(self, app, tmp_path):
        from src.models.assessment import Assessment
        from src.models.project import Project
        from src.models.variant import Variant

        with app.app_context():
            project = Project.create("TimestampProject")
            variant = Variant.create("vulnscout-current", project.id)
            project_name = project.name
            variant_id = variant.id

        import_file = tmp_path / "custom-vulnscout-current.json"
        import_file.write_text(json.dumps({
            "version": 1,
            "assessments": [{
                "vuln_id": "CVE-2099-10003",
                "status": "affected",
                "packages": ["vulnscout-current@1.0"],
                "variant_id": str(variant_id),
                "timestamp": "2001-02-03T04:05:06+00:00",
            }],
        }))
        before_import = datetime.now(timezone.utc)

        result = app.test_cli_runner().invoke(args=[
            "import-custom-vulnscout-data",
            "--project", project_name,
            "--use-current-timestamps",
            str(import_file),
        ])
        after_import = datetime.now(timezone.utc)

        assert result.exit_code == 0, result.output
        with app.app_context():
            imported = Assessment.get_by_origin([variant_id], origin="custom")
            assert len(imported) == 1
            stored_timestamp = imported[0].timestamp
            if stored_timestamp.tzinfo is None:
                stored_timestamp = stored_timestamp.replace(tzinfo=timezone.utc)
            assert before_import <= stored_timestamp <= after_import

    def test_openvex_import_can_use_current_timestamps(self, app, tmp_path):
        from src.models.assessment import Assessment
        from src.models.project import Project
        from src.models.variant import Variant

        with app.app_context():
            project = Project.create("TimestampProject")
            variant = Variant.create("openvex", project.id)
            project_name = project.name
            variant_name = variant.name
            variant_id = variant.id

        import_file = tmp_path / "custom-openvex.json"
        import_file.write_text(json.dumps({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [{
                "vulnerability": {"name": "CVE-2099-10002"},
                "status": "affected",
                "products": [{"@id": "openvex-timestamp@1.0"}],
                "timestamp": "2001-02-03T04:05:06+00:00",
            }],
        }))
        before_import = datetime.now(timezone.utc)

        result = app.test_cli_runner().invoke(args=[
            "import-custom-openvex-assessments",
            "--project", project_name,
            "--variant", variant_name,
            "--use-current-timestamps",
            str(import_file),
        ])
        after_import = datetime.now(timezone.utc)

        assert result.exit_code == 0, result.output
        with app.app_context():
            imported = Assessment.get_by_origin([variant_id], origin="custom")
            assert len(imported) == 1
            stored_timestamp = imported[0].timestamp
            if stored_timestamp.tzinfo is None:
                stored_timestamp = stored_timestamp.replace(tzinfo=timezone.utc)
            assert before_import <= stored_timestamp <= after_import

    def test_openvex_import_can_preserve_original_timestamps(self, app, tmp_path):
        from src.helpers.datetime_utils import ensure_utc_iso
        from src.models.assessment import Assessment
        from src.models.project import Project
        from src.models.variant import Variant

        original_timestamp = "2001-02-03T04:05:06+00:00"
        with app.app_context():
            project = Project.create("TimestampProject")
            variant = Variant.create("openvex-original", project.id)
            project_name = project.name
            variant_name = variant.name
            variant_id = variant.id

        import_file = tmp_path / "custom-openvex-original.json"
        import_file.write_text(json.dumps({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [{
                "vulnerability": {"name": "CVE-2099-10004"},
                "status": "affected",
                "products": [{"@id": "openvex-original@1.0"}],
                "timestamp": original_timestamp,
            }],
        }))

        result = app.test_cli_runner().invoke(args=[
            "import-custom-openvex-assessments",
            "--project", project_name,
            "--variant", variant_name,
            "--use-original-timestamps",
            str(import_file),
        ])

        assert result.exit_code == 0, result.output
        with app.app_context():
            imported = Assessment.get_by_origin([variant_id], origin="custom")
            assert len(imported) == 1
            assert ensure_utc_iso(imported[0].timestamp) == original_timestamp
