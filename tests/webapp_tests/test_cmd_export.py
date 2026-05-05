# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Coverage tests for src/bin/cmd_export.py.

Targets uncovered branches reported by the CI coverage run:
  cmd_export.py – lines 72-74, 122-125, 145, 157, 160-163, 165-168
"""

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
def app(tmp_path):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
        _build_db(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


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

    def test_report_generate_documents_env_adds_extra_templates(self, app, tmp_path):
        """GENERATE_DOCUMENTS env var causes extra templates to be rendered (line 145)."""
        with patch("src.views.templates.Templates.render") as mock_render:
            mock_render.return_value = "rendered content"
            os.environ["GENERATE_DOCUMENTS"] = "extra.adoc, also_extra.adoc"
            try:
                runner = app.test_cli_runner()
                result = runner.invoke(args=[
                    "report", "main.adoc", "--output-dir", str(tmp_path)
                ])
            finally:
                os.environ.pop("GENERATE_DOCUMENTS", None)

        # main.adoc + 2 extras = 3 renders
        assert mock_render.call_count == 3
        assert result.output.count("Report written") == 3

    def test_report_match_condition_invalid_cache_falls_back(self, app, tmp_path):
        """Invalid cache JSON causes fallback to evaluate_condition (lines 122-125)."""
        cache_path = "/tmp/vulnscout_matched_vulns.json"
        with open(cache_path, "w") as f:
            f.write("{{not-valid-json")
        try:
            with patch("src.views.templates.Templates.render") as mock_render, \
                 patch("src.bin.cmd_export.evaluate_condition") as mock_eval:
                mock_render.return_value = "rendered"
                mock_eval.return_value = []
                os.environ["MATCH_CONDITION"] = "cvss > 5"
                try:
                    runner = app.test_cli_runner()
                    result = runner.invoke(args=[
                        "report", "report.adoc", "--output-dir", str(tmp_path)
                    ])
                finally:
                    os.environ.pop("MATCH_CONDITION", None)
            mock_eval.assert_called_once()
        finally:
            if os.path.exists(cache_path):
                os.remove(cache_path)

    def test_report_match_condition_no_cache_calls_evaluate(self, app, tmp_path):
        """Absent cache file causes evaluate_condition to be called (line 125)."""
        cache_path = "/tmp/vulnscout_matched_vulns.json"
        if os.path.exists(cache_path):
            os.remove(cache_path)
        with patch("src.views.templates.Templates.render") as mock_render, \
             patch("src.bin.cmd_export.evaluate_condition") as mock_eval:
            mock_render.return_value = "rendered"
            mock_eval.return_value = ["CVE-1234-5678"]
            os.environ["MATCH_CONDITION"] = "cvss > 7"
            try:
                runner = app.test_cli_runner()
                result = runner.invoke(args=[
                    "report", "report.adoc", "--output-dir", str(tmp_path)
                ])
            finally:
                os.environ.pop("MATCH_CONDITION", None)
        mock_eval.assert_called_once()
