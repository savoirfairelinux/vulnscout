# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the ``flask export-context`` and ``flask import-context`` CLI commands."""

import json
import os
from pathlib import Path

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

    def test_structured_import_matches_http_and_roundtrips_through_cli(self, app, tmp_path):
        fixture = json.loads((Path(__file__).parents[1] / "fixtures/stride_context_v2.json").read_text())
        payload = {"version": "2.0", "projects": [{
            "project_name": "ProjectA", "project_description": "Structured project", "variants": [fixture["variant"]],
        }]}
        path = self._write(tmp_path, payload)
        result = app.test_cli_runner().invoke(args=["import-context", path])
        assert result.exit_code == 0, result.output
        output = tmp_path / "export.json"
        result = app.test_cli_runner().invoke(args=[
            "export-context", "--output", str(output), "--project", "ProjectA", "--variant", "VariantA1",
        ])
        assert result.exit_code == 0, result.output
        exported = json.loads(output.read_text())
        assert exported["projects"] == payload["projects"]
        http_export = app.test_client().get(
            f"/api/context/export?variant_ids={app._test_ids['variant_a1_id']}"
        ).json
        assert http_export["projects"] == exported["projects"]
        result = app.test_cli_runner().invoke(args=["import-context", str(output)])
        assert result.exit_code == 0, result.output

    def test_legacy_cli_import_persists_free_mode_with_verbatim_text(self, app, tmp_path):
        from src.models.variant_context import VariantContext
        from src.helpers.stride_context import export_fields, import_fields
        import uuid
        fields = export_fields(None, None, "stride")
        fields["system"]["scope"] = "System scope"
        values = import_fields({"variant_name": "VariantA1", **fields})
        original = "  " + values["threat_model"] + "\n "
        path = self._write(tmp_path, [{
            "project_name": "ProjectA", "project_description": "Description",
            "variants": [{"variant_name": "VariantA1", "threat_model": original}],
        }])
        result = app.test_cli_runner().invoke(args=["import-context", path])
        assert result.exit_code == 0, result.output
        with app.app_context():
            context = VariantContext.get_by_variant(uuid.UUID(app._test_ids["variant_a1_id"]))
            assert context.editor_mode == "free"
            assert context.threat_model == original

    def _write(self, tmp_path, payload):
        path = tmp_path / "import.json"
        path.write_text(json.dumps(payload))
        return str(path)

    def test_import_envelope_overwrites(self, app, tmp_path):
        payload = {
            "version": "1.0",
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
        # A failed entry makes the command exit non-zero.
        assert result.exit_code != 0, result.output
        assert "1 ignored" in result.output
        assert "1 failed" in result.output
        assert "Variant not found" in result.output

    def test_import_ignored_only_exits_zero(self, app, tmp_path):
        payload = [
            {"project_name": "ProjectA", "project_description": "d", "variants": [
                {"variant_name": "VariantA1", "threat_model": "t"},
                {"variant_name": "NoSuchVariant", "threat_model": "t"},
            ]},
        ]
        path = self._write(tmp_path, payload)
        result = app.test_cli_runner().invoke(args=["import-context", path])
        # Ignored entries are not failures, so the command still succeeds.
        assert result.exit_code == 0, result.output
        assert "1 ignored" in result.output
        assert "0 failed" in result.output

    def test_import_missing_file_errors(self, app, tmp_path):
        result = app.test_cli_runner().invoke(args=[
            "import-context", str(tmp_path / "nope.json"),
        ])
        assert result.exit_code != 0
        assert "file not found" in result.output.lower()

    def test_import_malformed_body_errors(self, app, tmp_path):
        path = self._write(tmp_path, {"version": "1.0"})  # no projects
        result = app.test_cli_runner().invoke(args=["import-context", path])
        assert result.exit_code != 0
        assert "projects" in result.output.lower()
