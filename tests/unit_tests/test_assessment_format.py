# -*- coding: utf-8 -*-
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Project-level presentation format for AI assessment text."""

import os
import uuid

import pytest

from src.bin.webapp import create_app
from src.extensions import db as _db
from src.helpers.assessment_format import (
    MAX_LABEL,
    MAX_STYLE_NOTES,
    SECTION_IDS,
    normalize_assessment_format,
)
from src.helpers.stride_model import StrideValidationError
from src.models.project import Project
from src.models.project_context import KEEP, ProjectContext
from src.models.variant import Variant

FORMAT = {
    "sections": [
        {"id": "confidence", "enabled": True, "label": "Confidence"},
        {"id": "verdict", "enabled": True},
        {"id": "evidence", "enabled": True, "label": "Evidence"},
        {"id": "reachability", "enabled": False},
        {"id": "remediation", "enabled": True, "label": "Fix"},
    ],
    "layout": "lines",
    "style_notes": "Neutral tone.",
}


def _errors(raw) -> dict:
    with pytest.raises(StrideValidationError) as exc:
        normalize_assessment_format(raw)
    return exc.value.fields


class TestNormalizeAssessmentFormat:

    def test_none_is_the_default_presentation(self):
        assert normalize_assessment_format(None) is None

    def test_valid_format_is_kept(self):
        assert normalize_assessment_format(FORMAT) == FORMAT

    def test_defaults_and_blank_values_are_dropped(self):
        result = normalize_assessment_format({
            "sections": [{"id": "verdict"}, {"id": "evidence", "label": "  "}],
            "style_notes": " \n ",
        })
        assert result == {
            "sections": [{"id": "verdict", "enabled": True}, {"id": "evidence", "enabled": True}],
            "layout": "inline",
        }

    def test_strips_control_characters(self):
        result = normalize_assessment_format({
            "sections": [{"id": "verdict", "label": "Ver\x00dict\n\x1b"}],
            "layout": "inline",
            "style_notes": "Line one\nline\x07 two\ttab\x9b",
        })
        assert result["sections"][0]["label"] == "Verdict"
        assert result["style_notes"] == "Line one\nline two\ttab"

    def test_does_not_mutate_input(self):
        raw = {"sections": [{"id": "verdict", "label": " V "}], "layout": "lines"}
        normalize_assessment_format(raw)
        assert raw == {"sections": [{"id": "verdict", "label": " V "}], "layout": "lines"}

    def test_rejects_unencodable_text_at_each_field(self):
        assert _errors({
            "sections": [{"id": "evidence", "label": "\ud800"}],
            "style_notes": "broken \udfff",
        }) == {
            "assessment_format.sections[0].label": "must be valid UTF-8 text",
            "assessment_format.style_notes": "must be valid UTF-8 text",
        }

    @pytest.mark.parametrize("raw", ["text", 3, ["sections"], True])
    def test_rejects_non_objects(self, raw):
        assert _errors(raw) == {"assessment_format": "must be an object or null"}

    def test_reports_every_problem_with_field_paths(self):
        fields = _errors({
            "sections": [
                {"id": "verdict", "enabled": "yes"},
                {"id": "verdict"},
                {"id": "severity"},
                "evidence",
                {"id": "evidence", "label": 7, "color": "red"},
                {"id": "remediation", "label": "x" * (MAX_LABEL + 1)},
            ],
            "layout": "table",
            "style_notes": "x" * (MAX_STYLE_NOTES + 1),
            "extra": 1,
        })
        assert fields == {
            "assessment_format.sections[0].enabled": "must be a boolean",
            "assessment_format.sections[1].id": "is duplicated",
            "assessment_format.sections[2].id": f"must be one of: {', '.join(SECTION_IDS)}",
            "assessment_format.sections[3]": "must be an object",
            "assessment_format.sections[4].color": "is not a supported field",
            "assessment_format.sections[4].label": "must be a string",
            "assessment_format.sections[5].label": f"must be at most {MAX_LABEL} characters",
            "assessment_format.layout": "must be one of: inline, lines",
            "assessment_format.style_notes": f"must be at most {MAX_STYLE_NOTES} characters",
            "assessment_format.extra": "is not a supported field",
        }

    def test_sections_must_be_a_list(self):
        assert _errors({"layout": "inline"}) == {"assessment_format.sections": "must be a list"}
        assert _errors({"sections": {"id": "verdict"}}) == {"assessment_format.sections": "must be a list"}

    def test_limits_apply_after_cleaning(self):
        result = normalize_assessment_format({
            "sections": [{"id": "verdict", "label": " " + "x" * MAX_LABEL + "\x00 "}],
            "style_notes": "y" * MAX_STYLE_NOTES + "\x01",
        })
        assert result["sections"][0]["label"] == "x" * MAX_LABEL
        assert result["style_notes"] == "y" * MAX_STYLE_NOTES


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path / "cache"))
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": "/dev/null"})
        application._INT_SCAN_FINISHED = True
        with application.app_context():
            _db.create_all()
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def project(app):
    return Project.create("FormatProject")


@pytest.fixture()
def variant(app, project):
    return Variant.create("FormatVariant", project.id)


@pytest.fixture()
def client(app):
    return app.test_client()


class TestProjectContextModel:

    def test_keep_leaves_the_stored_values(self, project):
        ProjectContext.upsert(project.id, description="desc", assessment_format=FORMAT)
        pc = ProjectContext.upsert(project.id, description=KEEP)
        assert pc.description == "desc"
        assert pc.assessment_format == FORMAT
        assert pc.to_dict()["assessment_format"] == FORMAT

    def test_format_change_does_not_bump_updated_at(self, project):
        pc = ProjectContext.upsert(project.id, description="desc")
        before = pc.updated_at
        pc = ProjectContext.upsert(project.id, description=KEEP, assessment_format=FORMAT)
        assert pc.updated_at == before
        assert pc.assessment_format == FORMAT

    def test_new_row_with_only_a_format_has_no_description(self, project):
        pc = ProjectContext.upsert(project.id, description=KEEP, assessment_format=FORMAT)
        assert pc.description is None
        assert pc.updated_at is None


class TestProjectContextRoutes:

    def _put(self, client, project, body):
        return client.put(f"/api/projects/{project.id}/context", json=body)

    def test_get_returns_null_format_by_default(self, client, project):
        data = client.get(f"/api/projects/{project.id}/context").get_json()
        assert data["assessment_format"] is None

    def test_put_saves_the_normalized_format_and_keeps_the_description(self, client, project):
        self._put(client, project, {"description": "desc"})
        raw = {**FORMAT, "style_notes": "  Neutral tone.\x00  "}
        resp = self._put(client, project, {"assessment_format": raw})
        assert resp.status_code == 200
        assert resp.get_json() == {
            "project_id": str(project.id), "description": "desc", "assessment_format": FORMAT,
        }
        assert client.get(f"/api/projects/{project.id}/context").get_json()["assessment_format"] == FORMAT

    def test_description_only_put_keeps_the_format(self, client, project):
        self._put(client, project, {"description": "desc", "assessment_format": FORMAT})
        resp = self._put(client, project, {"description": "new"})
        assert resp.get_json()["assessment_format"] == FORMAT
        assert resp.get_json()["description"] == "new"

    def test_null_resets_to_default(self, client, project):
        self._put(client, project, {"description": "desc", "assessment_format": FORMAT})
        resp = self._put(client, project, {"assessment_format": None})
        assert resp.status_code == 200
        assert resp.get_json()["assessment_format"] is None
        assert resp.get_json()["description"] == "desc"

    def test_format_save_does_not_outdate_assessments(self, client, project):
        self._put(client, project, {"description": "desc"})
        before = ProjectContext.get_by_project(project.id).updated_at
        self._put(client, project, {"assessment_format": FORMAT})
        assert ProjectContext.get_by_project(project.id).updated_at == before

    def test_invalid_format_returns_field_errors_and_changes_nothing(self, client, project):
        self._put(client, project, {"description": "desc", "assessment_format": FORMAT})
        resp = self._put(client, project, {
            "description": "changed",
            "assessment_format": {"sections": [{"id": "verdict"}, {"id": "verdict"}], "layout": "grid"},
        })
        assert resp.status_code == 400
        body = resp.get_json()
        assert body["fields"] == {
            "assessment_format.sections[1].id": "is duplicated",
            "assessment_format.layout": "must be one of: inline, lines",
        }
        assert "error" in body
        saved = ProjectContext.get_by_project(project.id)
        assert saved.description == "desc"
        assert saved.assessment_format == FORMAT

    def test_non_object_body_is_rejected(self, client, project):
        resp = self._put(client, project, ["description"])
        assert resp.status_code == 400
        assert resp.get_json()["fields"] == {"body": "must be an object"}

    def test_unknown_project_is_404_even_with_an_invalid_format(self, client):
        resp = client.put(f"/api/projects/{uuid.uuid4()}/context", json={"assessment_format": "bad"})
        assert resp.status_code == 404

    def test_merged_context_exposes_the_format(self, client, project, variant):
        url = f"/api/context?project_id={project.id}&variant_id={variant.id}"
        assert client.get(url).get_json()["assessment_format"] is None
        self._put(client, project, {"description": "desc", "assessment_format": FORMAT})
        assert client.get(url).get_json()["assessment_format"] == FORMAT
