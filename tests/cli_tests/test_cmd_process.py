# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Coverage tests for src/bin/cmd_process.py.

Targets uncovered branches reported by the CI coverage run:
  cmd_process.py – lines 131, 152, 236, 255-256, 302-303, 348, 360-361
"""

import json
import pytest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

from src.bin.webapp import create_app
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _build_db(app):
    """Minimal DB: project → variant → scan."""
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan

    with app.app_context():
        _db.drop_all()
        _db.create_all()

        default_project = Project.create("default")
        Variant.create("default", default_project.id)
        Variant.create("release", default_project.id)

        project = Project.create("ProcessProject")
        variant = Variant.create("ProcessVariant", project.id)
        Variant.create("SecondVariant", project.id)
        Scan.create("scan", variant.id, scan_type="sbom")
        _db.session.commit()


@pytest.fixture()
def app(tmp_path, monkeypatch):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    application = create_app()
    application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
    _build_db(application)
    yield application


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCmdProcessCoverage:
    """flask process and helper-function coverage."""

    def test_process_command_invokes_run_main(self, app):
        """flask process calls _run_main (line 236)."""
        with patch("src.bin.cmd_process._run_main") as mock_main:
            mock_main.return_value = {}
            runner = app.test_cli_runner()
            result = runner.invoke(args=["process"])
        assert result.exit_code == 0
        mock_main.assert_called_once_with(
            refresh_vulnerability_data=False,
            project_name=None,
            variant_name=None,
        )

    def test_process_command_propagates_refresh_flag(self, app):
        with patch("src.bin.cmd_process._run_main") as run_main:
            runner = app.test_cli_runner()
            result = runner.invoke(args=["process", "--refresh-vulnerability-data"])

        assert result.exit_code == 0
        run_main.assert_called_once_with(
            refresh_vulnerability_data=True,
            project_name=None,
            variant_name=None,
        )

    def test_process_command_propagates_condition_scope(self, app):
        with patch("src.bin.cmd_process._run_main") as run_main:
            result = app.test_cli_runner().invoke(
                args=[
                    "process", "--project", "ProcessProject",
                    "--variant", "ProcessVariant",
                ]
            )

        assert result.exit_code == 0
        run_main.assert_called_once_with(
            refresh_vulnerability_data=False,
            project_name="ProcessProject",
            variant_name="ProcessVariant",
        )

    def test_condition_scope_defaults_to_default_variant(self, app):
        from src.bin.cmd_process import _condition_scope

        with app.app_context():
            scope = _condition_scope(None, None)

        assert len(scope.variant_ids) == 1

    def test_condition_scope_includes_all_project_variants(self, app):
        from src.bin.cmd_process import _condition_scope

        with app.app_context():
            scope = _condition_scope("ProcessProject", None)

        assert len(scope.variant_ids) == 2

    def test_condition_scope_selects_one_variant(self, app):
        from src.bin.cmd_process import _condition_scope

        with app.app_context():
            scope = _condition_scope("ProcessProject", "ProcessVariant")

        assert len(scope.variant_ids) == 1

    def test_condition_scope_uses_default_project_for_variant(self, app):
        from src.bin.cmd_process import _condition_scope

        with app.app_context():
            scope = _condition_scope(None, "release")

        assert len(scope.variant_ids) == 1

    def test_condition_matches_euvd_known_exploitable(self, app):
        from src.bin.cmd_process import evaluate_condition
        from src.controllers import ControllersCache
        from src.models.vulnerability import Vulnerability

        with app.app_context():
            vulnerability = Vulnerability.get_or_create("CVE-2026-0001")
            vulnerability.euvd_known_exploited = True
            controllers = ControllersCache()

            matched = evaluate_condition(
                controllers.vulnerabilities,
                controllers.assessments,
                "((cvss >= 9.0 or (cvss >= 7.0 and epss >= 30%)) or "
                "known_exploitable and (pending or affected))",
            )

        assert matched == [vulnerability.id]

    def test_project_condition_matches_each_variant_independently(self, app):
        from src.bin.cmd_process import _condition_scope, _evaluate_condition_in_scope
        from src.models.assessment import Assessment
        from src.models.finding import Finding
        from src.models.package import Package
        from src.models.project import Project
        from src.models.sbom_document import SBOMDocument
        from src.models.sbom_package import SBOMPackage
        from src.models.scan import Scan
        from src.models.variant import Variant
        from src.models.vulnerability import Vulnerability

        with app.app_context():
            project = Project.get_by_name("ProcessProject")
            variants = {variant.name: variant for variant in Variant.get_by_project(project.id)}
            first_variant = variants["ProcessVariant"]
            second_variant = variants["SecondVariant"]
            first_scan = Scan.get_by_variant_id(first_variant.id)[0]
            second_scan = Scan.create("second-scan", second_variant.id, scan_type="sbom")
            package = Package.create("shared-package", "1.0")
            for scan in (first_scan, second_scan):
                document = SBOMDocument.create(f"/{scan.id}.spdx", "spdx", scan.id)
                SBOMPackage.create(document.id, package.id)

            vulnerability = Vulnerability.get_or_create("CVE-2026-0001")
            finding = Finding.get_or_create(package.id, vulnerability.id)
            now = datetime.now(timezone.utc)
            Assessment.create(
                "affected",
                targets=[(first_variant.id, finding.id)],
                timestamp=now - timedelta(days=1),
            )
            Assessment.create(
                "not_affected",
                targets=[(second_variant.id, finding.id)],
                timestamp=now,
            )

            matched = _evaluate_condition_in_scope(
                _condition_scope("ProcessProject", None),
                "affected",
            )

        assert matched == [vulnerability.id]

    @pytest.mark.parametrize(
        ("project_name", "variant_name", "message"),
        [
            ("MissingProject", None, "project not found: MissingProject"),
            ("ProcessProject", "MissingVariant", "variant not found: MissingVariant"),
        ],
    )
    def test_condition_scope_rejects_unknown_names(
        self, app, capsys, project_name, variant_name, message
    ):
        from src.bin.cmd_process import _condition_scope

        with app.app_context(), pytest.raises(SystemExit) as exc_info:
            _condition_scope(project_name, variant_name)

        assert exc_info.value.code == 1
        assert message in capsys.readouterr().out

    def test_standalone_refresh_uses_all_vulnerabilities(self, app):
        with patch("src.bin.cmd_process.refresh_vulnerability_sources", return_value=[]) as refresh:
            result = app.test_cli_runner().invoke(args=["refresh-vulnerability-data"])

        assert result.exit_code == 0
        assert set(refresh.call_args.args[1]) == set(refresh.call_args.args[0].vulnerabilities.vulnerabilities)
        assert "Vulnerability data refresh complete." in result.output

    def test_standalone_refresh_scopes_to_project(self, app):
        with patch("src.bin.cmd_process.refresh_vulnerability_sources", return_value=[]) as refresh:
            result = app.test_cli_runner().invoke(
                args=["refresh-vulnerability-data", "--project", "ProcessProject"]
            )

        assert result.exit_code == 0
        assert refresh.call_args.args[0]._scope is not None

    def test_standalone_refresh_scopes_to_variant(self, app):
        with patch("src.bin.cmd_process.refresh_vulnerability_sources", return_value=[]) as refresh:
            result = app.test_cli_runner().invoke(
                args=[
                    "refresh-vulnerability-data", "--project", "ProcessProject",
                    "--variant", "ProcessVariant",
                ]
            )

        assert result.exit_code == 0
        assert len(refresh.call_args.args[0]._scope.variant_ids) == 1

    def test_standalone_refresh_rejects_variant_without_project(self, app):
        result = app.test_cli_runner().invoke(
            args=["refresh-vulnerability-data", "--variant", "ProcessVariant"]
        )

        assert result.exit_code == 2
        assert "--variant requires --project" in result.output

    def test_process_refresh_failure_exits_one(self, app):
        with patch("src.bin.cmd_process.read_inputs"), \
                patch("src.bin.cmd_process.populate_observations"):
            with patch(
                    "src.bin.cmd_process.refresh_vulnerability_sources",
                    return_value=["NVD", "GHSA"],
            ):
                runner = app.test_cli_runner()
                result = runner.invoke(args=["process", "--refresh-vulnerability-data"])

        assert result.exit_code == 1
        assert "NVD, GHSA vulnerability-data refresh failed" in result.output

    def test_process_refresh_reports_source_steps(self, app):
        def report_all_sources(*args, on_source_start, **kwargs):
            labels = ("EPSS", "NVD", "EUVD", "GHSA")
            for step, label in enumerate(labels, start=1):
                on_source_start(label, step, len(labels))
            return []

        with patch("src.bin.cmd_process.read_inputs"), \
                patch("src.bin.cmd_process.populate_observations"), \
                patch(
                    "src.bin.cmd_process.refresh_vulnerability_sources",
                    side_effect=report_all_sources,
                ):
            runner = app.test_cli_runner()
            result = runner.invoke(args=["process", "--refresh-vulnerability-data"])

        assert result.exit_code == 0
        assert "Refreshing EPSS data (step 1 of 4)..." in result.output
        assert "Refreshing NVD data (step 2 of 4)..." in result.output
        assert "Refreshing EUVD data (step 3 of 4)..." in result.output
        assert "Refreshing GHSA data (step 4 of 4)..." in result.output
        assert "Vulnerability data refresh complete." in result.output

    def test_refresh_vulnerability_sources_uses_settings_order_and_scope(self):
        from src.bin.cmd_process import refresh_vulnerability_sources
        from src.controllers.vulnerabilities import EnrichmentResult

        events = []

        class Vulnerabilities:
            def __init__(self):
                self.vulnerabilities = {
                    "CVE-2026-0001": object(),
                    "CVE-OLD-0001": object(),
                    "GHSA-aaaa-bbbb-cccc": object(),
                }

            def fetch_nvd_data(self):
                events.append(("fetch-nvd", tuple(self.vulnerabilities)))
                return EnrichmentResult(successful=1)

            def fetch_euvd_data(self):
                events.append(("fetch-euvd", tuple(self.vulnerabilities)))
                return EnrichmentResult(successful=1)

        vulnerabilities = Vulnerabilities()
        original_vulnerabilities = vulnerabilities.vulnerabilities
        controllers = SimpleNamespace(vulnerabilities=vulnerabilities)

        with patch(
            "src.bin.cmd_process.post_treatment",
            side_effect=lambda _: events.append(
                ("fetch-epss", tuple(vulnerabilities.vulnerabilities))
            ) or EnrichmentResult(successful=1),
        ):
            failed = refresh_vulnerability_sources(
                controllers,
                {"CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"},
                on_source_start=lambda label, step, total: events.append(
                    ("start", label, step, total)
                ),
            )

        assert failed == []
        assert events == [
            ("start", "EPSS", 1, 4),
            ("fetch-epss", ("CVE-2026-0001",)),
            ("start", "NVD", 2, 4),
            ("fetch-nvd", ("CVE-2026-0001",)),
            ("start", "EUVD", 3, 4),
            ("fetch-euvd", ("CVE-2026-0001",)),
            ("start", "GHSA", 4, 4),
            ("fetch-nvd", ("GHSA-aaaa-bbbb-cccc",)),
        ]
        assert vulnerabilities.vulnerabilities is original_vulnerabilities

    def test_refresh_progress_excludes_inapplicable_ghsa_source(self):
        from src.bin.cmd_process import refresh_vulnerability_sources
        from src.controllers.vulnerabilities import EnrichmentResult

        class Vulnerabilities:
            vulnerabilities = {"CVE-2026-0001": object()}

            def fetch_nvd_data(self):
                return EnrichmentResult(successful=1)

            def fetch_euvd_data(self):
                return EnrichmentResult(successful=1)

        events = []
        controllers = SimpleNamespace(vulnerabilities=Vulnerabilities())
        with patch(
            "src.bin.cmd_process.post_treatment",
            return_value=EnrichmentResult(successful=1),
        ):
            failed = refresh_vulnerability_sources(
                controllers,
                ["CVE-2026-0001"],
                on_source_start=lambda label, step, total: events.append(
                    (label, step, total)
                ),
            )

        assert failed == []
        assert events == [
            ("EPSS", 1, 3),
            ("NVD", 2, 3),
            ("EUVD", 3, 3),
        ]

    def test_refresh_vulnerability_sources_continues_after_failure(self):
        from src.bin.cmd_process import refresh_vulnerability_sources
        from src.controllers.vulnerabilities import EnrichmentResult

        calls = []

        class Vulnerabilities:
            vulnerabilities = {"CVE-2026-0001": object()}

            def fetch_nvd_data(self):
                calls.append("nvd")
                return EnrichmentResult(successful=1)

            def fetch_euvd_data(self):
                calls.append("euvd")
                return EnrichmentResult(successful=1)

        controllers = SimpleNamespace(vulnerabilities=Vulnerabilities())
        with patch(
            "src.bin.cmd_process.post_treatment",
            side_effect=RuntimeError("EPSS unavailable"),
        ):
            failed = refresh_vulnerability_sources(
                controllers,
                ["CVE-2026-0001"],
                {"epss", "nvd", "euvd"},
            )

        assert failed == ["EPSS"]
        assert calls == ["nvd", "euvd"]

    def test_populate_observations_no_scan_prints_warning(self, app, capsys):
        """populate_observations(None, …) prints warning and returns early (lines 255-256)."""
        from src.bin.cmd_process import populate_observations
        mock_ctrl = MagicMock()
        mock_ctrl._encountered_this_run = set()

        with app.app_context():
            populate_observations(None, mock_ctrl)
        assert "Warning: no scan provided" in capsys.readouterr().out

    def test_populate_observations_db_exception_is_warned(self, app, capsys):
        """DB error inside populate_observations is caught and printed (lines 302-303)."""
        from src.bin.cmd_process import populate_observations
        mock_ctrl = MagicMock()
        mock_ctrl._encountered_this_run = {"CVE-FAKE"}

        mock_scan = MagicMock()
        mock_scan.id = "fake-scan-id"

        with app.app_context():
            with patch("src.bin.cmd_process._db") as mock_db:
                mock_db.session.execute.side_effect = RuntimeError("db failure")
                mock_db.select = _db.select
                populate_observations(mock_scan, mock_ctrl)

        assert "Warning: could not populate observations table" in capsys.readouterr().out

    def test_run_main_interactive_mode_skips_post_treatment(self, app, monkeypatch):
        """_run_main skips post_treatment when INTERACTIVE_MODE=true (line 348)."""
        monkeypatch.setenv("INTERACTIVE_MODE", "true")
        with patch("src.bin.cmd_process.post_treatment") as mock_pt, \
             patch("src.bin.cmd_process.read_inputs") as mock_ri, \
             patch("src.bin.cmd_process.populate_observations"):
            mock_ri.return_value = {}
            with app.app_context():
                from src.bin.cmd_process import _run_main
                _run_main()
        mock_pt.assert_not_called()

    def test_run_main_json_cache_write_exception_swallowed(self, app, monkeypatch):
        """IO error writing JSON cache is silently swallowed (lines 360-361)."""
        import json as _json_mod

        monkeypatch.setenv("MATCH_CONDITION", "cvss > 5")
        with patch("src.bin.cmd_process.read_inputs") as mock_ri, \
             patch("src.bin.cmd_process.post_treatment"), \
             patch("src.bin.cmd_process.populate_observations"), \
             patch("src.bin.cmd_process.evaluate_condition", return_value=[]), \
             patch.object(_json_mod, "dump", side_effect=OSError("disk full")):
            mock_ri.return_value = {}
            with app.app_context():
                from src.bin.cmd_process import _run_main
                _run_main()  # Must not raise despite json.dump() failing

    def test_read_inputs_unknown_format_prints_warning(self, app, tmp_path, capsys):
        """read_inputs prints a warning for docs with unrecognisable format (line 152)."""
        from src.bin.cmd_process import read_inputs
        from src.controllers import ControllersCache
        from src.models.sbom_document import SBOMDocument
        from src.models.scan import Scan

        unknown_file = tmp_path / "unknown.json"
        # Content that doesn't match SPDX, CycloneDX, OpenVEX, Yocto or Grype
        unknown_file.write_text(json.dumps({"totally_unknown": "value", "xyz": 42}))

        with app.app_context():
            scan = _db.session.execute(_db.select(Scan)).scalar_one()
            SBOMDocument.create(str(unknown_file), "unknown.json", scan.id, format=None)
            _db.session.commit()

            read_inputs(ControllersCache(), scan_id=scan.id)

        assert "Warning: unknown format" in capsys.readouterr().out

    def test_read_inputs_spdx3_uses_fast_parser(self, app, tmp_path):
        """read_inputs dispatches to FastSPDX3.parse_from_dict for SPDX 3 docs (line 131)."""
        from src.bin.cmd_process import read_inputs
        from src.controllers import ControllersCache
        from src.models.sbom_document import SBOMDocument
        from src.models.scan import Scan

        # Minimal SPDX 3 JSON structure that passes could_parse_spdx()
        spdx3_data = {
            "@graph": [
                {"@type": "CreationInfo", "specVersion": "3.0.0"},
            ]
        }
        spdx3_file = tmp_path / "sbom_spdx3.spdx.json"
        spdx3_file.write_text(json.dumps(spdx3_data))

        with app.app_context():
            scan = _db.session.execute(_db.select(Scan)).scalar_one()
            SBOMDocument.create(str(spdx3_file), "sbom_spdx3.spdx.json", scan.id, format="spdx")
            _db.session.commit()

            with patch("src.views.fast_spdx3.FastSPDX3.parse_from_dict") as mock_parse:
                read_inputs(ControllersCache(), scan_id=scan.id)

        mock_parse.assert_called_once_with(spdx3_data)
