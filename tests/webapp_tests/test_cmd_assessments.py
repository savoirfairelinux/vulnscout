# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Coverage tests for src/bin/cmd_assessments.py.

Targets uncovered branches reported by the CI coverage run:
  cmd_assessments.py – line 115 (warning echo when errors list is non-empty)
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
    """Minimal DB: project → variant."""
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan

    with app.app_context():
        _db.drop_all()
        _db.create_all()

        project = Project.create("AssessProject")
        variant = Variant.create("AssessVariant", project.id)
        Scan.create("scan", variant.id, scan_type="sbom")
        _db.session.commit()

        return {
            "project_name": "AssessProject",
            "variant_name": "AssessVariant",
        }


@pytest.fixture()
def app(tmp_path):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
        ids = _build_db(application)
        application._test_ids = ids
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def ids(app):
    return app._test_ids


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCmdAssessmentsCoverage:
    """flask import-custom-assessments coverage."""

    def test_import_json_with_import_errors_prints_warnings(self, app, ids, tmp_path):
        """import-custom-assessments echoes Warning lines when errors are returned (line 115)."""
        variant_name = ids["variant_name"]

        vex_doc = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://example.com/vex/test",
            "author": "Test",
            "timestamp": "2026-01-01T00:00:00Z",
            "statements": [
                {
                    "@id": "s1",
                    "vulnerability": {"@id": "https://nvd.nist.gov/vuln/detail/CVE-TEST-001"},
                    "products": [{"@id": "pkg:generic/testpkg@1.0"}],
                    "status": "not_affected",
                }
            ],
        }
        json_file = tmp_path / f"{variant_name}.json"
        json_file.write_text(json.dumps(vex_doc))

        # Simulate import returning one error entry
        with patch("src.helpers.assessment_io.import_statements") as mock_import:
            mock_import.return_value = ([], [{"stmt": "s1", "error": "parse error"}], 0)
            runner = app.test_cli_runner()
            result = runner.invoke(args=["import-custom-assessments", str(json_file)])

        assert result.exit_code == 0
        assert "Warning:" in result.output

    def test_import_unsupported_extension_exits(self, app, tmp_path):
        """Unsupported file extension (not .json or .tar.gz) exits with code 1."""
        bad_file = tmp_path / "assessments.csv"
        bad_file.write_text("data")

        runner = app.test_cli_runner()
        result = runner.invoke(args=["import-custom-assessments", str(bad_file)])

        assert result.exit_code != 0
        assert "unsupported file type" in result.output
