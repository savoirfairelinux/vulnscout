# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Coverage tests for src/bin/cmd_export.py.

Targets uncovered branches reported by the CI coverage run:
  cmd_export.py – lines 72-74, 122-125, 145, 157, 160-163, 165-168
"""

import json
import os
import pytest
from unittest.mock import patch

from src.bin.webapp import create_app
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _build_db(app):
    """Minimal DB with tables created."""
    with app.app_context():
        _db.drop_all()
        _db.create_all()
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

class TestCmdExportCoverage:
    """flask export and flask report coverage."""

    # ---- export_command ----

    def test_export_exception_handler(self, app, tmp_path):
        """Exception inside export_command is caught and exits with code 1 (lines 72-74)."""
        with patch("src.bin.cmd_export.SPDX3") as MockSPDX3:
            MockSPDX3.return_value.output_as_json.side_effect = RuntimeError("boom")
            runner = app.test_cli_runner()
            result = runner.invoke(args=[
                "export", "--format", "spdx3", "--output-dir", str(tmp_path)
            ])

        assert result.exit_code != 0
        assert "Error: could not export" in result.output

    # ---- report_command ----

    def test_report_adoc_written_as_plain_text(self, app, tmp_path):
        """report_command auto-detects .adoc and writes plain text (line 157)."""
        with patch("src.views.templates.Templates.render") as mock_render:
            mock_render.return_value = "= Title\nsome content"
            runner = app.test_cli_runner()
            result = runner.invoke(args=[
                "report", "report.adoc", "--output-dir", str(tmp_path)
            ])

        out_file = tmp_path / "report.adoc"
        assert out_file.exists()
        assert out_file.read_text() == "= Title\nsome content"
        assert "Report written" in result.output

    def test_report_pdf_output(self, app, tmp_path):
        """report_command writes PDF bytes when --format pdf is given (lines 160-163)."""
        with patch("src.views.templates.Templates.render") as mock_render, \
             patch("src.views.templates.Templates.adoc_to_pdf") as mock_pdf:
            mock_render.return_value = "= Title\ncontent"
            mock_pdf.return_value = b"%PDF-1.4 fake"
            runner = app.test_cli_runner()
            result = runner.invoke(args=[
                "report", "report.adoc",
                "--output-dir", str(tmp_path),
                "--format", "pdf",
            ])

        out_file = tmp_path / "report.adoc.pdf"
        assert out_file.exists()
        assert out_file.read_bytes() == b"%PDF-1.4 fake"
        assert "Report written" in result.output

    def test_report_html_output(self, app, tmp_path):
        """report_command writes HTML bytes when --format html is given (lines 165-168)."""
        with patch("src.views.templates.Templates.render") as mock_render, \
             patch("src.views.templates.Templates.adoc_to_html") as mock_html:
            mock_render.return_value = "= Title\ncontent"
            mock_html.return_value = b"<html>test</html>"
            runner = app.test_cli_runner()
            result = runner.invoke(args=[
                "report", "report.adoc",
                "--output-dir", str(tmp_path),
                "--format", "html",
            ])

        out_file = tmp_path / "report.adoc.html"
        assert out_file.exists()
        assert out_file.read_bytes() == b"<html>test</html>"
        assert "Report written" in result.output

    def test_report_generate_documents_env_adds_extra_templates(self, app, tmp_path, monkeypatch):
        """GENERATE_DOCUMENTS env var causes extra templates to be rendered (line 145)."""
        monkeypatch.setenv("GENERATE_DOCUMENTS", "extra.adoc, also_extra.adoc")
        with patch("src.views.templates.Templates.render") as mock_render:
            mock_render.return_value = "rendered content"
            runner = app.test_cli_runner()
            result = runner.invoke(args=[
                "report", "main.adoc", "--output-dir", str(tmp_path)
            ])

        # main.adoc + 2 extras = 3 renders
        assert mock_render.call_count == 3
        assert result.output.count("Report written") == 3

    def test_report_match_condition_invalid_cache_falls_back(self, app, tmp_path, monkeypatch):
        """Invalid cache JSON causes fallback to evaluate_condition (lines 122-125)."""
        cache_path = "/tmp/vulnscout_matched_vulns.json"
        with open(cache_path, "w") as f:
            f.write("{{not-valid-json")
        try:
            monkeypatch.setenv("MATCH_CONDITION", "cvss > 5")
            with patch("src.views.templates.Templates.render") as mock_render, \
                 patch("src.bin.cmd_export.evaluate_condition") as mock_eval:
                mock_render.return_value = "rendered"
                mock_eval.return_value = []
                runner = app.test_cli_runner()
                result = runner.invoke(args=[
                    "report", "report.adoc", "--output-dir", str(tmp_path)
                ])
            mock_eval.assert_called_once()
        finally:
            if os.path.exists(cache_path):
                os.remove(cache_path)

    def test_report_match_condition_no_cache_calls_evaluate(self, app, tmp_path, monkeypatch):
        """Absent cache file causes evaluate_condition to be called (line 125)."""
        cache_path = "/tmp/vulnscout_matched_vulns.json"
        if os.path.exists(cache_path):
            os.remove(cache_path)
        monkeypatch.setenv("MATCH_CONDITION", "cvss > 7")
        with patch("src.views.templates.Templates.render") as mock_render, \
             patch("src.bin.cmd_export.evaluate_condition") as mock_eval:
            mock_render.return_value = "rendered"
            mock_eval.return_value = ["CVE-1234-5678"]
            runner = app.test_cli_runner()
            result = runner.invoke(args=[
                "report", "report.adoc", "--output-dir", str(tmp_path)
            ])
        mock_eval.assert_called_once()

    def test_report_does_not_rebuild_vulnerabilities_controller(self, app, tmp_path):
        """report_command must not re-persist all vulns via from_dict (perf)."""
        with patch("src.views.templates.Templates.render") as mock_render, \
             patch("src.controllers.vulnerabilities.VulnerabilitiesController.from_dict") as mock_from_dict:
            mock_render.return_value = "= Title\ncontent"
            runner = app.test_cli_runner()
            result = runner.invoke(args=[
                "report", "report.adoc", "--output-dir", str(tmp_path)
            ])

        assert result.exit_code == 0, result.output
        mock_from_dict.assert_not_called()


class TestCmdExportSpdx2:
    def test_author_present(self, app, tmp_path, monkeypatch):
        """Exception inside export_command is caught and exits with code 1 (lines 72-74)."""
        monkeypatch.setenv("AUTHOR_NAME", "TestAuthor")

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "export", "--format", "spdx2", "--output-dir", str(tmp_path)
        ])

        assert result.exit_code == 0, result.output
        exported_file = tmp_path / "sbom_spdx_v2_3.spdx.json"
        assert exported_file.exists()

        with open(exported_file, "r") as f:
            data = json.load(f)

        assert "Organization: TestAuthor" in data["creationInfo"]["creators"]


class TestCmdExportVariantScoping:
    """Cover the variant_id and project scoping branches (lines 59-67)."""

    def test_invalid_variant_id_warns_and_exports_all(self, app, tmp_path):
        """Lines 62-63: non-UUID variant_id → warning, fall back to global export."""
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "export", "--format", "spdx2",
            "--output-dir", str(tmp_path),
            "--variant-id", "not-a-uuid",
        ])
        assert result.exit_code == 0
        assert "invalid variant id" in result.output.lower()

    def test_unknown_variant_id_warns_and_exports_all(self, app, tmp_path):
        """Lines 64-65: valid UUID but not found in DB → warning, fall back."""
        import uuid as _uuid
        fake_id = str(_uuid.uuid4())
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "export", "--format", "spdx2",
            "--output-dir", str(tmp_path),
            "--variant-id", fake_id,
        ])
        assert result.exit_code == 0
        assert "not found" in result.output.lower()

    def test_unknown_project_warns_and_exports_all(self, app, tmp_path):
        """Lines 69-70: project name not in DB → warning, fall back to global."""
        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "export", "--format", "spdx2",
            "--output-dir", str(tmp_path),
            "--project", "nonexistent-project",
        ])
        assert result.exit_code == 0
        assert "not found" in result.output.lower()

    def test_known_variant_id_scopes_export(self, app, tmp_path):
        """Line 67: valid UUID found in DB → scope = compute_export_scope(variant_id=vid)."""
        from src.models.project import Project
        from src.models.variant import Variant

        with app.app_context():
            proj = Project.create("ExportScopeProj2")
            var = Variant.create("v1", proj.id)
            _db.session.commit()
            var_id = str(var.id)

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "export", "--format", "spdx2",
            "--output-dir", str(tmp_path),
            "--variant-id", var_id,
        ])
        assert result.exit_code == 0, result.output
        assert "not found" not in result.output.lower()
