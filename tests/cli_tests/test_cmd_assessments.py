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
                targets=[(var.id, finding.id)],
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
                targets=[(variant.id, finding.id)],
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


class TestImportCrossInstanceVariantId:
    """The VulnScout JSON's ``variant_id`` is only meaningful within the
    instance that exported it: another database mints its own variant UUIDs,
    so re-importing the file elsewhere must not trust that UUID as-is.
    """

    def test_foreign_variant_id_falls_back_to_variant_name(self, app, tmp_path):
        from src.models.assessment import Assessment
        from src.models.project import Project
        from src.models.variant import Variant

        with app.app_context():
            project = Project.create("CrossInstanceProject")
            variant = Variant.create("x86", project.id)
            project_name = project.name
            variant_id = variant.id

        foreign_variant_id = "99999999-9999-9999-9999-999999999999"
        import_file = tmp_path / "custom-vulnscout-foreign.json"
        import_file.write_text(json.dumps({
            "version": 1,
            "assessments": [{
                "vuln_id": "CVE-2099-20001",
                "status": "affected",
                "packages": ["cross-instance@1.0"],
                "variant_id": foreign_variant_id,
                "variant": "x86",
            }],
        }))

        result = app.test_cli_runner().invoke(args=[
            "import-custom-vulnscout-data",
            "--project", project_name,
            str(import_file),
        ])

        assert result.exit_code == 0, result.output
        assert "Imported 1 assessments" in result.output
        with app.app_context():
            imported = Assessment.get_by_origin([variant_id], origin="custom")
            assert len(imported) == 1
            assert imported[0].vuln_id == "CVE-2099-20001"

    def test_foreign_variant_id_without_name_is_reported_as_error(self, app, tmp_path):
        from src.models.project import Project

        with app.app_context():
            project = Project.create("CrossInstanceProjectNoName")
            project_name = project.name

        foreign_variant_id = "99999999-9999-9999-9999-999999999999"
        import_file = tmp_path / "custom-vulnscout-foreign-no-name.json"
        import_file.write_text(json.dumps({
            "version": 1,
            "assessments": [{
                "vuln_id": "CVE-2099-20002",
                "status": "affected",
                "packages": ["cross-instance-noname@1.0"],
                "variant_id": foreign_variant_id,
            }],
        }))

        result = app.test_cli_runner().invoke(args=[
            "import-custom-vulnscout-data",
            "--project", project_name,
            str(import_file),
        ])

        assert result.exit_code != 0
        assert foreign_variant_id in result.output

    def test_future_custom_data_version_is_rejected(self, app, tmp_path):
        from src.models.project import Project

        with app.app_context():
            project_name = Project.create("FutureVersionProject").name
        import_file = tmp_path / "future-custom-data.json"
        import_file.write_text(json.dumps({"version": 3, "assessments": []}))

        result = app.test_cli_runner().invoke(args=[
            "import-custom-vulnscout-data",
            "--project", project_name,
            str(import_file),
        ])

        assert result.exit_code != 0
        assert "Unsupported VulnScout JSON version: 3" in result.output

    @pytest.mark.parametrize("legacy_version", ["1", "1.0"])
    def test_legacy_string_versions_are_accepted(self, app, tmp_path, legacy_version):
        from src.models.project import Project
        from src.models.variant import Variant

        with app.app_context():
            project = Project.create("LegacyStringVersionProject")
            variant = Variant.create("legacy-string-version", project.id)
            project_name = project.name
            variant_id = variant.id

        import_file = tmp_path / "legacy-string-version.json"
        import_file.write_text(json.dumps({
            "version": legacy_version,
            "assessments": [{
                "vuln_id": "CVE-2099-LEGACY-STRING-CLI",
                "status": "affected",
                "packages": ["legacy-string-cli@1.0"],
                "variant_id": str(variant_id),
            }],
        }))

        result = app.test_cli_runner().invoke(args=[
            "import-custom-vulnscout-data",
            "--project", project_name,
            str(import_file),
        ])

        assert result.exit_code == 0, result.output
        assert "Imported 1 assessments" in result.output

    def test_legacy_decimal_version_is_accepted(self, app, tmp_path):
        from src.models.project import Project
        from src.models.variant import Variant

        with app.app_context():
            project = Project.create("LegacyDecimalVersionProject")
            variant = Variant.create("legacy-decimal-version", project.id)
            project_name = project.name
            variant_id = variant.id

        import_file = tmp_path / "legacy-decimal-version.json"
        import_file.write_text(
            '{"version": 1.0, "assessments": [{'
            '"vuln_id": "CVE-2099-LEGACY-DECIMAL-CLI", '
            '"status": "affected", '
            '"packages": ["legacy-decimal-cli@1.0"], '
            f'"variant_id": "{variant_id}"'
            '}]}'
        )

        result = app.test_cli_runner().invoke(args=[
            "import-custom-vulnscout-data",
            "--project", project_name,
            str(import_file),
        ])

        assert result.exit_code == 0, result.output
        assert "Imported 1 assessments" in result.output


def _seed_custom_assessment(project_name, variant_name, cve_id):
    from src.models.assessment import Assessment
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.vulnerability import Vulnerability

    project = Project.get_by_name(project_name) or Project.create(project_name)
    variant = Variant.create(variant_name, project.id)
    package = Package.create(f"pkg-{variant_name}", "1.0.0")
    vulnerability = Vulnerability.create_record(cve_id)
    finding = Finding.create(package.id, vulnerability.id)
    Assessment.create(
        status="not_affected", targets=[(variant.id, finding.id)], origin="custom",
        impact_statement="Not reachable.",
    )
    _db.session.commit()
    return variant


class TestExportCustomOpenVexAllVariants:
    """Without --variant every variant of the project is exported to its own file."""

    def test_export_without_variant_writes_one_file_per_variant(self, app, tmp_path):
        with app.app_context():
            _seed_custom_assessment("MultiProj", "v1", "CVE-2099-0001")
            _seed_custom_assessment("MultiProj", "v2", "CVE-2099-0002")

        result = app.test_cli_runner().invoke(args=[
            "export-custom-openvex-assessments", "--project", "MultiProj", "--output-dir", str(tmp_path),
        ])

        assert result.exit_code == 0, result.output
        assert not (tmp_path / "custom_openvex_all.json").exists()
        for label, cve in (("v1", "CVE-2099-0001"), ("v2", "CVE-2099-0002")):
            document = json.loads((tmp_path / f"custom_openvex_{label}.json").read_text())
            assert {s["vulnerability"]["name"] for s in document["statements"]} == {cve}

    def test_export_removes_stale_file_of_variant_without_assessments(self, app, tmp_path):
        from src.models.assessment import Assessment

        with app.app_context():
            _seed_custom_assessment("StaleProj", "v1", "CVE-2099-0004")
            v2 = _seed_custom_assessment("StaleProj", "v2", "CVE-2099-0005")
            v2_id = v2.id
        invoke = lambda: app.test_cli_runner().invoke(args=[  # noqa: E731
            "export-custom-openvex-assessments", "--project", "StaleProj", "--output-dir", str(tmp_path),
        ])
        assert invoke().exit_code == 0
        assert (tmp_path / "custom_openvex_v2.json").exists()

        with app.app_context():
            for assessment in Assessment.get_by_origin([v2_id]):
                _db.session.delete(assessment)
            _db.session.commit()

        result = invoke()

        assert result.exit_code == 0, result.output
        assert (tmp_path / "custom_openvex_v1.json").exists()
        assert not (tmp_path / "custom_openvex_v2.json").exists()

    def test_export_keeps_stale_looking_file_of_another_project(self, app, tmp_path):
        with app.app_context():
            _seed_custom_assessment("ProjA", "v2", "CVE-2099-0008")
            _seed_custom_assessment("ProjB", "v1", "CVE-2099-0009")
            from src.models.project import Project
            from src.models.variant import Variant
            Variant.create("v2", Project.get_by_name("ProjB").id)
            _db.session.commit()
        invoke = lambda name: app.test_cli_runner().invoke(args=[  # noqa: E731
            "export-custom-openvex-assessments", "--project", name, "--output-dir", str(tmp_path),
        ])
        assert invoke("ProjA").exit_code == 0

        result = invoke("ProjB")

        assert result.exit_code == 0, result.output
        document = json.loads((tmp_path / "custom_openvex_v2.json").read_text())
        assert {s["vulnerability"]["name"] for s in document["statements"]} == {"CVE-2099-0008"}

    def test_export_rejects_variant_names_sharing_a_file_name(self, app, tmp_path):
        with app.app_context():
            _seed_custom_assessment("CollideProj", "a/b", "CVE-2099-0006")
            _seed_custom_assessment("CollideProj", "a_b", "CVE-2099-0007")

        result = app.test_cli_runner().invoke(args=[
            "export-custom-openvex-assessments", "--project", "CollideProj", "--output-dir", str(tmp_path),
        ])

        assert result.exit_code != 0
        assert "same output file name" in result.output
        assert not list(tmp_path.glob("custom_openvex_*"))

    def test_export_without_variant_ignores_other_projects(self, app, tmp_path):
        from src.models.project import Project

        with app.app_context():
            Project.create("EmptyProj")
            _seed_custom_assessment("OtherProj", "v1", "CVE-2099-0003")
            _db.session.commit()

        result = app.test_cli_runner().invoke(args=[
            "export-custom-openvex-assessments", "--project", "EmptyProj", "--output-dir", str(tmp_path),
        ])

        assert result.exit_code != 0
        assert "No custom assessments to export." in result.output
        assert not (tmp_path / "custom_openvex_all.json").exists()


_OPENVEX_IMPORT_DOC = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "statements": [{
        "vulnerability": {"name": "CVE-2099-10009"},
        "status": "affected",
        "products": [{"@id": "fallback-pkg@1.0"}],
        "timestamp": "2001-02-03T04:05:06+00:00",
    }],
}


class TestImportCustomOpenVexVariantFallback:
    """Without --variant the import targets the project's only variant."""

    def _write(self, tmp_path):
        path = tmp_path / "custom-openvex.json"
        path.write_text(json.dumps(_OPENVEX_IMPORT_DOC))
        return str(path)

    def test_import_without_variant_uses_only_variant(self, app, tmp_path):
        from src.models.assessment import Assessment
        from src.models.project import Project
        from src.models.variant import Variant

        with app.app_context():
            project = Project.create("SoloProj")
            variant_id = Variant.create("only", project.id).id
            _db.session.commit()

        result = app.test_cli_runner().invoke(args=[
            "import-custom-openvex-assessments", "--project", "SoloProj", self._write(tmp_path),
        ])

        assert result.exit_code == 0, result.output
        with app.app_context():
            assert len(Assessment.get_by_origin([variant_id], origin="custom")) == 1

    @pytest.mark.parametrize(
        ("variant_names", "listed"),
        [([], "0 variants (none)"), (["a", "b"], "2 variants (a, b)")],
    )
    def test_import_without_variant_requires_single_variant(self, app, tmp_path, variant_names, listed):
        from src.models.project import Project
        from src.models.variant import Variant

        with app.app_context():
            project = Project.create("AmbiguousProj")
            for name in variant_names:
                Variant.create(name, project.id)
            _db.session.commit()

        result = app.test_cli_runner().invoke(args=[
            "import-custom-openvex-assessments", "--project", "AmbiguousProj", self._write(tmp_path),
        ])

        assert result.exit_code != 0
        assert f"project 'AmbiguousProj' has {listed}; choose one with --variant." in result.output
