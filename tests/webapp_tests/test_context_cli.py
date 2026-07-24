# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the ``flask export-context`` and ``flask import-context`` CLI commands."""

import json
import os

import pytest

from src.bin.webapp import create_app


def _build_db(app):
    from src.extensions import db
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.project_context import ProjectContext
    from src.models.variant_context import VariantContext

    with app.app_context():
        db.drop_all()
        db.create_all()

        project_a = Project.create("ProjectA")
        variant_a1 = Variant.create("VariantA1", project_a.id)
        variant_a2 = Variant.create("VariantA2", project_a.id)

        project_b = Project.create("ProjectB")
        Variant.create("VariantB1", project_b.id)

        ProjectContext.upsert(project_a.id, description="ProjectA description")
        VariantContext.upsert(
            variant_a1.id,
            variant_description="A1 variant desc",
            threat_model="A1 threat model",
        )
        VariantContext.upsert(variant_a2.id, threat_model="A2 threat model")

        return {
            "project_a_id": str(project_a.id),
            "variant_a1_id": str(variant_a1.id),
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


class TestExportContextCLI:

    @staticmethod
    def _flat(doc):
        """Flatten the nested export document to (project_name, variant_name)
        records for assertions."""
        return [
            {"project_name": p["project_name"], **v}
            for p in doc["projects"] for v in p["variants"]
        ]

    def test_export_all_writes_envelope(self, app, tmp_path):
        out = tmp_path / "ctx.json"
        result = app.test_cli_runner().invoke(args=[
            "export-context", "--output", str(out),
        ])
        assert result.exit_code == 0, result.output
        assert out.exists()
        doc = json.loads(out.read_text())
        assert doc["version"] == "2.0"
        assert isinstance(doc["exported_at"], str) and doc["exported_at"]
        keys = {(e["project_name"], e["variant_name"]) for e in self._flat(doc)}
        assert keys == {
            ("ProjectA", "VariantA1"),
            ("ProjectA", "VariantA2"),
            ("ProjectB", "VariantB1"),
        }

    def test_export_filter_by_project(self, app, tmp_path):
        out = tmp_path / "ctx.json"
        result = app.test_cli_runner().invoke(args=[
            "export-context", "--output", str(out), "--project", "ProjectA",
        ])
        assert result.exit_code == 0, result.output
        doc = json.loads(out.read_text())
        assert {p["project_name"] for p in doc["projects"]} == {"ProjectA"}
        assert len(self._flat(doc)) == 2

    def test_export_single_variant(self, app, tmp_path):
        out = tmp_path / "ctx.json"
        result = app.test_cli_runner().invoke(args=[
            "export-context", "--output", str(out),
            "--project", "ProjectA", "--variant", "VariantA1",
        ])
        assert result.exit_code == 0, result.output
        doc = json.loads(out.read_text())
        flat = self._flat(doc)
        assert len(flat) == 1
        assert flat[0]["variant_name"] == "VariantA1"

    def test_export_variant_without_project_errors(self, app, tmp_path):
        out = tmp_path / "ctx.json"
        result = app.test_cli_runner().invoke(args=[
            "export-context", "--output", str(out), "--variant", "VariantA1",
        ])
        assert result.exit_code != 0
        assert "--variant requires --project" in result.output

    def test_export_unknown_project_errors(self, app, tmp_path):
        out = tmp_path / "ctx.json"
        result = app.test_cli_runner().invoke(args=[
            "export-context", "--output", str(out), "--project", "Nope",
        ])
        assert result.exit_code != 0
        assert "project not found" in result.output.lower()


class TestImportContextCLI:

    def _write(self, tmp_path, payload):
        path = tmp_path / "import.json"
        path.write_text(json.dumps(payload))
        return str(path)

    def test_import_envelope_overwrites(self, app, tmp_path):
        payload = {
            "version": "2.0",
            "exported_at": "2026-07-22T00:00:00+00:00",
            "projects": [{
                "project_name": "ProjectA",
                "project_description": "New description",
                "variants": [{
                    "variant_name": "VariantA1",
                    "threat_model": "new threat model",
                }],
            }],
        }
        path = self._write(tmp_path, payload)
        result = app.test_cli_runner().invoke(args=["import-context", path])
        assert result.exit_code == 0, result.output
        assert "Imported 1 context entry" in result.output

        with app.app_context():
            from src.models.project_context import ProjectContext
            import uuid
            pc = ProjectContext.get_by_project(uuid.UUID(app._test_ids["project_a_id"]))
            assert pc.description == "New description"

    def test_import_bare_array(self, app, tmp_path):
        payload = [{
            "project_name": "ProjectA",
            "project_description": "d",
            "variants": [{
                "variant_name": "VariantA1",
                "threat_model": "t",
            }],
        }]
        path = self._write(tmp_path, payload)
        result = app.test_cli_runner().invoke(args=["import-context", path])
        assert result.exit_code == 0, result.output
        assert "Imported 1 context entr" in result.output

    def test_import_reports_ignored_and_failed(self, app, tmp_path):
        payload = [
            {"project_name": "ProjectA", "project_description": "d", "variants": [
                {"variant_name": "VariantA1", "threat_model": "t"},
                {"variant_name": "NoSuchVariant", "threat_model": "t"},
            ]},
            {"project_name": "ProjectB", "project_description": "d", "variants": [
                {"variant_name": "VariantB1"},  # missing threat_model
            ]},
        ]
        path = self._write(tmp_path, payload)
        result = app.test_cli_runner().invoke(args=["import-context", path])
        assert result.exit_code == 0, result.output
        assert "1 ignored" in result.output
        assert "1 failed" in result.output
        assert "Variant not found" in result.output

    def test_import_missing_file_errors(self, app, tmp_path):
        result = app.test_cli_runner().invoke(args=[
            "import-context", str(tmp_path / "nope.json"),
        ])
        assert result.exit_code != 0
        assert "file not found" in result.output.lower()

    def test_import_malformed_body_errors(self, app, tmp_path):
        path = self._write(tmp_path, {"version": "2.0"})  # no projects
        result = app.test_cli_runner().invoke(args=["import-context", path])
        assert result.exit_code != 0
        assert "projects" in result.output.lower()
