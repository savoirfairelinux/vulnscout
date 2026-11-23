# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from io import BytesIO
from threading import Event

import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session

from src.bin.webapp import create_app
from src.extensions import db
from src.models.assessment import Assessment as DBAssessment
from src.models.variant import Variant
from . import write_demo_files, setup_demo_db

VARIANT_UUID = uuid.UUID("22222222-2222-2222-2222-222222222222")
PROJECT_UUID = uuid.UUID("11111111-1111-1111-1111-111111111111")
SCAN_UUID = uuid.UUID("33333333-3333-3333-3333-333333333333")
VULN_ID = "CVE-2020-35492"
PKG = "cairo@1.16.0"
PKG2 = "abc@1.2.3"


@pytest.fixture()
def init_files(tmp_path):
    files = {
        "status": tmp_path / "status.txt",
        "packages": tmp_path / "packages-merged.json",
        "vulnerabilities": tmp_path / "vulnerabilities-merged.json",
        "assessments": tmp_path / "assessments-merged.json",
        "openvex": tmp_path / "openvex.json",
        "time_estimates": tmp_path / "time_estimates.json",
    }
    write_demo_files(files)
    return files


@pytest.fixture()
def app(init_files):
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": init_files["status"],
            "OPENVEX_FILE": init_files["openvex"],
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db",
        })
        setup_demo_db(application, extra_packages=["abc@1.2.3"])
        with application.app_context():
            from src.models.finding import Finding
            from src.models.observation import Observation
            from src.models.package import Package

            package = Package.get_by_string_id(PKG2)
            assert package is not None
            finding = Finding.get_or_create(package.id, VULN_ID)
            Observation.create(finding.id, SCAN_UUID, commit=False)
            db.session.commit()
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


def _post_ai(client, vuln_id=VULN_ID, packages=None, status="affected",
             variant_id=str(VARIANT_UUID), **extra):
    payload = {
        "packages": packages or [PKG],
        "status": status,
        "variant_id": variant_id,
        "ai_generated": True,
    }
    payload.update(extra)
    return client.post(f"/api/vulnerabilities/{vuln_id}/assessments", json=payload)


def test_ai_post_creates_ai_origin(client):
    resp = _post_ai(client)
    assert resp.status_code == 200
    body = json.loads(resp.data)
    assert body["assessments"]
    assert all(a["origin"] == "ai" for a in body["assessments"])


def _ai_rows(app, vuln_id=VULN_ID):
    with app.app_context():
        return [
            (str(a.id), sorted(str(t.variant_id) for t in a.target_rows))
            for a in DBAssessment.get_by_vulnerability(vuln_id)
            if a.origin == "ai"
        ]


def _review_ai(client):
    resp = client.get(f"/api/assessments/review/ai?variant_id={VARIANT_UUID}")
    assert resp.status_code == 200
    return json.loads(resp.data)


def _set_context(app, **fields):
    from src.models.variant_context import VariantContext
    with app.app_context():
        VariantContext.upsert(VARIANT_UUID, **fields)


def _set_project_context(app, description):
    from src.models.project_context import ProjectContext
    with app.app_context():
        ProjectContext.upsert(PROJECT_UUID, description=description)


def test_ai_context_outdated_false_without_context(client):
    _post_ai(client)
    assert [a["context_outdated"] for a in _review_ai(client)] == [False]


def test_ai_context_outdated_true_when_first_context_is_added(client, app):
    _post_ai(client)
    assert [a["context_outdated"] for a in _review_ai(client)] == [False]
    _set_context(app, environment="new")
    assert [a["context_outdated"] for a in _review_ai(client)] == [True]


def test_ai_context_outdated_false_when_context_older(client, app):
    _set_context(app, environment="old")
    _post_ai(client)
    assert [a["context_outdated"] for a in _review_ai(client)] == [False]


def test_ai_context_outdated_true_after_context_edit(client, app):
    _set_context(app, environment="old")
    _post_ai(client)
    _set_context(app, environment="new")
    assert [a["context_outdated"] for a in _review_ai(client)] == [True]


def test_ai_context_outdated_stays_true_when_context_is_restored(client, app):
    _set_context(app, environment="old")
    _post_ai(client)
    _set_context(app, environment="new")
    assert [a["context_outdated"] for a in _review_ai(client)] == [True]
    _set_context(app, environment="old")
    assert [a["context_outdated"] for a in _review_ai(client)] == [True]


def test_ai_context_outdated_uses_creation_time_after_assessment_edit(client, app):
    _set_context(app, environment="old")
    _post_ai(client)
    _set_context(app, environment="new")

    with app.app_context():
        assessment = DBAssessment.get_by_origin(
            [VARIANT_UUID], origin="ai"
        )[0]
        created_at = assessment.created_at
        assessment.update(status_notes="revised after context edit")
        assert assessment.timestamp > created_at
        assert assessment.created_at == created_at

    assert [a["context_outdated"] for a in _review_ai(client)] == [True]


def test_ai_context_outdated_ignores_noop_save(client, app):
    _set_context(app, environment="same")
    _post_ai(client)
    _set_context(app, environment="same")
    assert [a["context_outdated"] for a in _review_ai(client)] == [False]


def test_ai_context_outdated_only_for_edited_variant(client, app):
    other_variant = "22222222-2222-2222-2222-222222222223"
    _add_variant(app, other_variant)
    _post_ai(client)
    _post_ai(client, variant_id=other_variant)
    _set_context(app, environment="new")
    resp = client.get("/api/assessments/review/ai")
    by_variant = {a["targets"][0]["variant_id"]: a["context_outdated"] for a in json.loads(resp.data)}
    assert by_variant == {str(VARIANT_UUID): True, other_variant: False}


def test_ai_context_outdated_when_any_target_context_is_newer(client, app):
    other_variant = "22222222-2222-2222-2222-222222222223"
    _add_variant(app, other_variant)
    response = _post_ai(
        client,
        targets=[
            {"package": PKG, "variant_id": str(VARIANT_UUID)},
            {"package": PKG2, "variant_id": other_variant},
        ],
    )
    assert response.status_code == 200

    _set_context(app, environment="changed")

    rows = json.loads(client.get("/api/assessments/review/ai").data)
    assert len(rows) == 1
    assert rows[0]["context_outdated"] is True


def test_reviews_endpoint_flags_ai_context_outdated(client, app):
    _set_context(app, environment="old")
    _post_ai(client)
    url = f"/api/reviews/assessments?variant_id={VARIANT_UUID}&origin=ai"
    assert [a["context_outdated"] for a in json.loads(client.get(url).data)] == [False]
    _set_context(app, environment="new")
    assert [a["context_outdated"] for a in json.loads(client.get(url).data)] == [True]


def test_ai_context_outdated_true_after_project_description_edit(client, app):
    """The project description is part of the context AI agents consume."""
    _set_project_context(app, "old")
    _post_ai(client)
    assert [a["context_outdated"] for a in _review_ai(client)] == [False]
    _set_project_context(app, "new")
    assert [a["context_outdated"] for a in _review_ai(client)] == [True]


def test_ai_context_outdated_true_when_first_project_description_is_added(client, app):
    _post_ai(client)
    _set_project_context(app, "added later")
    assert [a["context_outdated"] for a in _review_ai(client)] == [True]


def test_ai_context_outdated_ignores_noop_project_save(client, app):
    _set_project_context(app, "same")
    _post_ai(client)
    _set_project_context(app, "same")
    assert [a["context_outdated"] for a in _review_ai(client)] == [False]


def test_ai_context_outdated_ignores_project_context_read(client, app):
    """Reading the context creates an empty row; that is not an edit."""
    _post_ai(client)
    assert client.get(f"/api/projects/{PROJECT_UUID}/context").status_code == 200
    assert [a["context_outdated"] for a in _review_ai(client)] == [False]


def test_project_description_edit_outdates_every_variant_of_the_project(client, app):
    other_variant = "22222222-2222-2222-2222-222222222223"
    _add_variant(app, other_variant)
    _post_ai(client)
    _post_ai(client, variant_id=other_variant)
    _set_project_context(app, "changed")
    resp = client.get("/api/assessments/review/ai")
    by_variant = {a["targets"][0]["variant_id"]: a["context_outdated"] for a in json.loads(resp.data)}
    assert by_variant == {str(VARIANT_UUID): True, other_variant: True}


def test_project_description_edit_flagged_on_vuln_scoped_endpoint(client, app):
    _set_project_context(app, "old")
    _post_ai(client)
    url = f"/api/vulnerabilities/{VULN_ID}/assessments"
    ai_flags = lambda: [  # noqa: E731
        a["context_outdated"] for a in json.loads(client.get(url).data) if a["origin"] == "ai"
    ]
    assert ai_flags() == [False]
    _set_project_context(app, "new")
    assert ai_flags() == [True]


def test_future_payload_timestamp_does_not_suppress_outdating(client, app):
    """created_at must come from the server clock, not the payload."""
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    assert _post_ai(client, timestamp=future).status_code == 200
    _set_context(app, environment="changed after the assessment was written")
    assert [a["context_outdated"] for a in _review_ai(client)] == [True]


def test_past_payload_timestamp_does_not_outdate_a_fresh_assessment(client, app):
    _set_context(app, environment="current")
    past = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    assert _post_ai(client, timestamp=past).status_code == 200
    assert [a["context_outdated"] for a in _review_ai(client)] == [False]


def test_ai_post_replaces_pending_on_same_target(client, app):
    first = _post_ai(client, packages=[PKG], status="affected")
    assert first.status_code == 200
    first_id = json.loads(first.data)["assessment"]["id"]

    second = _post_ai(client, packages=[PKG], status="not_affected",
                      justification="component_not_present")
    assert second.status_code == 200
    body = json.loads(second.data)
    assert body["assessment"]["id"] != first_id
    assert body["replaced"] == [
        {"id": first_id, "action": "deleted", "variant_ids": [str(VARIANT_UUID)]}]

    rows = _ai_rows(app)
    assert [r[0] for r in rows] == [body["assessment"]["id"]]


def test_ai_post_keeps_pending_on_other_package_of_same_variant(client, app):
    """Assessing another package of the variant must not discard the first
    package's pending suggestion (separate Assess with AI requests)."""
    first_id = json.loads(_post_ai(client, packages=[PKG]).data)["assessment"]["id"]

    second = _post_ai(client, packages=[PKG2], status="not_affected",
                      justification="component_not_present")
    assert second.status_code == 200
    body = json.loads(second.data)
    assert "replaced" not in body

    assert sorted(r[0] for r in _ai_rows(app)) == sorted([first_id, body["assessment"]["id"]])


def test_ai_post_trims_only_the_overlapping_package(client, app):
    first_id = json.loads(_post_ai(client, packages=[PKG, PKG2]).data)["assessment"]["id"]

    second = _post_ai(client, packages=[PKG2], status="not_affected",
                      justification="component_not_present")
    assert second.status_code == 200
    body = json.loads(second.data)
    assert body["replaced"] == [
        {"id": first_id, "action": "trimmed", "variant_ids": [str(VARIANT_UUID)]}]

    with app.app_context():
        kept = DBAssessment.get_by_id(first_id)
        assert kept is not None
        assert [t.finding.package.string_id for t in kept.target_rows] == [PKG]


def test_edited_approval_conflicts_after_partial_replacement(client, app):
    other_variant = "22222222-2222-2222-2222-222222222223"
    _add_variant(app, other_variant)
    first = client.post(f"/api/vulnerabilities/{VULN_ID}/assessments", json={
        "packages": [PKG], "status": "affected", "ai_generated": True,
        "variant_ids": [str(VARIANT_UUID), other_variant],
    }).json["assessment"]
    url = "/api/assessments/" + first["id"]
    assert _post_ai(client).json["replaced"][0]["action"] == "trimmed"

    assert client.post(url + "/approve", json={
        "expected_fingerprint": first["approval_fingerprint"], "status_notes": "Reviewed on A",
    }).status_code == 409
    current = client.get(url).json
    assert current["origin"] == "ai"
    assert current["variant_ids"] == [other_variant]
    assert current["status_notes"] == first["status_notes"]
    assert client.post(url + "/approve", json={
        "expected_fingerprint": current["approval_fingerprint"],
    }).status_code == 200


def _risk_model(app, variant, description, extra_risks=(), target_ids=("C1",)):
    from src.models.variant_context import VariantContext

    with app.app_context():
        context = VariantContext.get_or_create(uuid.UUID(variant))
        context.stride_model = {
            "risks": [{"id": "R1", "description": description, "threat_ids": ["T1"]}, *extra_risks],
            "threats": [{"id": "T1", "description": f"{description} threat", "target_ids": list(target_ids)},
                        {"id": "T2", "description": "Unrelated threat"}],
        }
        db.session.commit()


def test_risk_links_are_scoped_to_exact_targets_and_reviewed_atomically(client, app):
    first, second = str(VARIANT_UUID), str(uuid.uuid4())
    _add_variant(app, second)
    _risk_model(app, first, "First model", [{"id": "R2", "description": "First variant only", "threat_ids": []}])
    _risk_model(app, second, "Second model")
    ref = {"risk_id": "R1", "threat_id": "T1"}
    a, b = {"variant_id": first, "package": PKG}, {"variant_id": second, "package": PKG2}
    response = _post_ai(client, targets=[{**a, "risk_links": [ref]}, {**b, "risk_links": [ref]}])
    assert response.status_code == 200
    row = response.json["assessment"]
    url = f"/api/assessments/{row['id']}"
    reviewed = client.get("/api/reviews/assessments?origin=ai").json[0]
    links = {t["variant_id"]: t["risk_links"][0] for t in reviewed["targets"]}
    assert links[first] == {**ref, "risk_description": "First model", "threat_description": "First model threat",
                            "threat_target_ids": ["C1"], "stale": False}
    assert links[second]["risk_description"] == "Second model"
    for path in (f"/api/reviews/assessments?origin=ai&variant_id={first}",
                 f"/api/reviews/assessments?origin=ai&variant_id={first}&project_id={PROJECT_UUID}",
                 f"/api/assessments/review/ai?variant_id={first}"):
        scoped = client.get(path).json[0]
        pairs = {t["variant_id"]: t for t in scoped["targets"]}
        assert pairs[first]["risk_links"] == [links[first]]
        assert pairs[second]["risk_links_out_of_scope"] and "risk_links" not in pairs[second]
        assert "Second model" not in json.dumps(scoped)
    for invalid in ({**a, "package": PKG2, "risk_links": []},
                    {**b, "risk_links": [{"risk_id": "R1", "threat_id": "T2"}]},
                    {**b, "risk_links": [{"risk_id": "R2"}]}):
        response = client.post(url + "/approve", json={
            "target_risk_links": [{**a, "risk_links": []}, invalid], "status_notes": "Should not persist",
        })
        assert response.status_code == 400
        assert client.get(url).json["approval_fingerprint"] == row["approval_fingerprint"]

    _risk_model(app, first, "Repurposed ID")
    assert client.post(url + "/approve").status_code == 400
    assert client.post(url + "/approve", json={
        "target_risk_links": [{**a, "risk_links": [ref, {"risk_id": "R1"}]}],
    }).status_code == 400
    stale = next(t for t in client.get(url).json["targets"] if t["variant_id"] == first)
    assert stale["risk_links"] == [{**links[first], "stale": True}]
    response = client.post(url + "/approve", json={
        "target_risk_links": [{**a, "risk_links": []}, {**b, "risk_links": [{"risk_id": "R1"}]}],
        "expected_fingerprint": row["approval_fingerprint"],
    })
    assert response.status_code == 200
    approved = client.get(url).json
    assert (approved["origin"], approved["status"]) == ("custom", row["status"])
    assert {t["variant_id"]: t.get("risk_links", []) for t in approved["targets"]} == {
        first: [], second: [{"risk_id": "R1", "risk_description": "Second model", "stale": False}]}
    listing = client.get("/api/assessments?format=list").json
    listed = next(a for a in listing if a["id"] == row["id"])
    assert next(t for t in listed["targets"] if t["variant_id"] == second)["risk_links"][0]["risk_id"] == "R1"


def test_reconfirm_requires_the_description_current_at_approval(client, app):
    variant = str(VARIANT_UUID)
    _risk_model(app, variant, "Saved")
    ref = {"risk_id": "R1", "threat_id": "T1"}
    target = {"variant_id": variant, "package": PKG}
    row = _post_ai(client, targets=[{**target, "risk_links": [ref]}]).json["assessment"]
    url = f"/api/assessments/{row['id']}"

    def confirmation(description):
        current = client.get(url + "/risk-link-preview", query_string={**target, **ref}).json
        assert current["risk_description"] == description and current["threat_description"] == f"{description} threat"
        return {"target_risk_links": [{**target, "risk_links": [{**ref, "confirmed_revision": current["revision"]}]}]}

    _risk_model(app, variant, "First revision")
    assert client.get(url + "/risk-link-preview", query_string={
        **target, **ref, "package": PKG2,
    }).status_code == 404
    reviewed = confirmation("First revision")
    _risk_model(app, variant, "Another revision")
    assert client.post(url + "/approve", json=reviewed).status_code == 400
    assert client.get(url).json["approval_fingerprint"] == row["approval_fingerprint"]
    result = client.post(url + "/approve", json=confirmation("Another revision")).json["assessments"][0]
    assert (result["origin"], result["status"]) == ("custom", row["status"])
    assert result["targets"][0]["risk_links"] == [{
        **ref, "risk_description": "Another revision", "threat_description": "Another revision threat",
        "threat_target_ids": ["C1"], "stale": False,
    }]


def test_retargeted_threat_requires_confirmation_even_when_descriptions_match(client, app):
    variant = str(VARIANT_UUID)
    _risk_model(app, variant, "Unchanged", target_ids=["I1", "C1"])
    ref = {"risk_id": "R1", "threat_id": "T1"}
    target = {"variant_id": variant, "package": PKG}
    row = _post_ai(client, targets=[{**target, "risk_links": [ref]}]).json["assessment"]
    url = f"/api/assessments/{row['id']}"

    def preview():
        return client.get(url + "/risk-link-preview", query_string={**target, **ref}).json

    def approve(revision):
        return client.post(url + "/approve", json={"target_risk_links": [
            {**target, "risk_links": [{**ref, "confirmed_revision": revision}]},
        ]})

    first = preview()
    _risk_model(app, variant, "Unchanged", target_ids=["C1", "I1"])
    assert preview() == first
    _risk_model(app, variant, "Unchanged", target_ids=["C2"])
    stored = client.get(url).json["targets"][0]["risk_links"][0]
    assert stored["stale"] and stored["threat_target_ids"] == ["C1", "I1"]
    assert client.post(url + "/approve").status_code == 400
    assert approve(first["revision"]).status_code == 400
    current = preview()
    assert current["threat_target_ids"] == ["C2"]
    approved = approve(current["revision"]).json["assessments"][0]
    assert approved["status"] == row["status"]
    assert approved["targets"][0]["risk_links"] == [{**stored, "stale": False, "threat_target_ids": ["C2"]}]


def test_link_limits_reject_expanded_edits_and_replacements_atomically(app, client):
    variant = str(VARIANT_UUID)
    # Each target fits individually; together their repeated descriptions exceed the byte budget.
    desc = "x" * 20000
    refs = [{"risk_id": f"R{i}"} for i in range(1, 9)]
    _risk_model(app, variant, desc, [{"id": r["risk_id"], "description": desc} for r in refs[1:]])
    targets = [{"variant_id": variant, "package": pkg} for pkg in (PKG, PKG2)]
    row = _post_ai(client, targets=[{**targets[0], "risk_links": refs}, targets[1]]).json["assessment"]
    url = f"/api/assessments/{row['id']}"
    edit = {**targets[1], "risk_links": refs}
    for edits in ([edit], [{**targets[0], "risk_links": [refs[0]] * 17}]):
        assert client.post(url + "/approve", json={"target_risk_links": edits}).status_code == 400
    assert _post_ai(client, targets=[{**t, "risk_links": refs} for t in targets]).status_code == 400
    assert client.get(url).json["approval_fingerprint"] == row["approval_fingerprint"]


def test_bad_replacement_preserves_links_and_valid_replacement_trims_only_its_target(client, app):
    v = str(VARIANT_UUID)
    _risk_model(app, v, "Existing risk")
    a = {"variant_id": v, "package": PKG, "risk_links": [{"risk_id": "R1"}]}
    b = {**a, "package": PKG2}
    row = _post_ai(client, targets=[a, b]).json["assessment"]
    url = f"/api/assessments/{row['id']}"
    for invalid in (None, {"risk_id": "R1"}, [{"risk_id": []}], [{"threat_id": "T1"}],
                    [{"risk_id": "R1", "threat_id": "T9"}]):
        assert _post_ai(client, targets=[{**a, "risk_links": invalid}]).status_code == 400
        assert client.get(url).json["approval_fingerprint"] == row["approval_fingerprint"]
    assert _post_ai(client, targets=[{**a, "risk_links": []}]).status_code == 200
    preserved = client.get(url).json["targets"]
    assert len(preserved) == 1 and preserved[0]["package"] == PKG2
    assert preserved[0]["risk_links"][0]["risk_id"] == "R1"
    assert client.post(url + "/approve").status_code == 200
    assert client.get(url).json["targets"] == preserved


def test_ai_post_without_pending_reports_nothing_replaced(client):
    body = json.loads(_post_ai(client).data)
    assert "replaced" not in body


def test_ai_post_replace_leaves_approved_and_sbom_untouched(client, app):
    approved_id = json.loads(_post_ai(client).data)["assessment"]["id"]
    assert _approve_id(client, approved_id).status_code == 200

    with app.app_context():
        before = sorted(str(a.id) for a in DBAssessment.get_by_vulnerability(VULN_ID)
                        if a.origin != "ai")

    resp = _post_ai(client, status="under_investigation")
    assert resp.status_code == 200
    assert "replaced" not in json.loads(resp.data)

    with app.app_context():
        after = sorted(str(a.id) for a in DBAssessment.get_by_vulnerability(VULN_ID)
                       if a.origin != "ai")
    assert after == before
    assert approved_id in after


def test_ai_post_failed_create_keeps_pending(client, app):
    first_id = json.loads(_post_ai(client).data)["assessment"]["id"]

    resp = _post_ai(client, packages=["nonexistent@9.9.9"])
    assert resp.status_code == 400
    assert [r[0] for r in _ai_rows(app)] == [first_id]


def test_ai_post_create_failure_rolls_back_the_replacement(client, app, monkeypatch):
    """The create fails AFTER the old row was removed; the removal must roll back."""
    from src.routes import assessments as routes

    first_id = json.loads(_post_ai(client).data)["assessment"]["id"]

    def boom(*args, **kwargs):
        raise RuntimeError("simulated create failure")

    monkeypatch.setattr(routes, "create_assessment_record", boom)
    resp = _post_ai(client, status="not_affected", justification="component_not_present")
    assert resp.status_code == 500
    assert [r[0] for r in _ai_rows(app)] == [first_id]


def test_ai_post_multi_variant_replaces_separate_pending_rows(client, app):
    other_variant = "22222222-2222-2222-2222-222222222223"
    _add_variant(app, other_variant)
    first_id = json.loads(_post_ai(client).data)["assessment"]["id"]
    second_id = json.loads(_post_ai(client, variant_id=other_variant).data)["assessment"]["id"]

    resp = client.post(
        f"/api/vulnerabilities/{VULN_ID}/assessments",
        json={"packages": [PKG], "status": "affected", "ai_generated": True,
              "variant_ids": [str(VARIANT_UUID), other_variant]},
    )
    assert resp.status_code == 200
    body = json.loads(resp.data)
    assert {r["id"] for r in body["replaced"]} == {first_id, second_id}
    assert all(r["action"] == "deleted" for r in body["replaced"])
    assert [r[0] for r in _ai_rows(app)] == [body["assessment"]["id"]]


def test_ai_post_second_variant_allowed(client, app):
    first = _post_ai(client)
    assert first.status_code == 200

    other_variant = "22222222-2222-2222-2222-222222222223"
    _add_variant(app, other_variant)

    second = _post_ai(client, variant_id=other_variant)
    assert second.status_code == 200


def test_non_ai_post_not_blocked_by_pending_ai(client):
    first = _post_ai(client)
    assert first.status_code == 200

    resp = client.post(
        f"/api/vulnerabilities/{VULN_ID}/assessments",
        json={
            "packages": [PKG],
            "status": "affected",
            "variant_id": str(VARIANT_UUID),
        },
    )
    assert resp.status_code == 200


def _get_first_ai_id(client):
    body = json.loads(_post_ai(client).data)
    return body["assessment"]["id"]


def _approve(client, assessment_id):
    return client.post(f"/api/assessments/{assessment_id}/approve")


_approve_id = _approve


def _reject(client, assessment_id):
    return client.post(f"/api/assessments/{assessment_id}/reject")


def test_postgresql_rejection_locks_parent_before_deleting_targets(postgres_app, monkeypatch):
    from src.routes import assessments as routes

    routes.init_app(postgres_app)
    setup_demo_db(postgres_app)
    client = postgres_app.test_client()
    pending = _post_ai(client).get_json()["assessment"]
    aid = pending["id"]
    validated, rejected = Event(), Event()
    validate = routes._validate_content_edit

    def pause_after_validation(*args, **kwargs):
        result = validate(*args, **kwargs)
        validated.set()
        assert rejected.wait(10)
        return result

    def check_parent_lock(session, flush_context, instances):
        if not any(isinstance(row, DBAssessment) for row in session.deleted):
            return
        with db.engine.connect() as observer:
            query = db.select(DBAssessment.id).where(DBAssessment.id == uuid.UUID(aid))
            assert observer.scalar(query) == uuid.UUID(aid)
            assert observer.scalar(query.with_for_update(skip_locked=True)) is None

    monkeypatch.setattr(routes, "_validate_content_edit", pause_after_validation)
    with ThreadPoolExecutor(max_workers=1) as pool:
        approval = pool.submit(postgres_app.test_client().post, f"/api/assessments/{aid}/approve", json={
            "expected_fingerprint": pending["approval_fingerprint"], "status_notes": "Reviewed",
        })
        event.listen(Session, "before_flush", check_parent_lock)
        try:
            assert validated.wait(10)
            assert _reject(client, aid).status_code == 200
        finally:
            event.remove(Session, "before_flush", check_parent_lock)
            rejected.set()
        assert approval.result(timeout=10).status_code == 409


def test_patch_reloads_parent_after_concurrent_approval(postgres_app, monkeypatch):
    from src.routes import assessments as routes

    routes.init_app(postgres_app)
    setup_demo_db(postgres_app)
    client = postgres_app.test_client()
    reason = "vulnerable_code_not_in_execute_path"
    pending = _post_ai(client, status="not_affected", justification=reason,
                       impact_statement="The code is isolated").json["assessment"]
    url = f"/api/assessments/{pending['id']}"

    with postgres_app.app_context(), ThreadPoolExecutor(max_workers=1) as pool:
        # Retain the ordinary edit's original ORM snapshot while a second
        # request commits approval using only the impact statement as reason.
        snapshot = DBAssessment.get_by_id(pending["id"])
        assert snapshot.justification == reason
        approval = pool.submit(postgres_app.test_client().post, url + "/approve", json={
            "expected_fingerprint": pending["approval_fingerprint"], "justification": "",
        }).result(timeout=10)
        assert approval.status_code == 200
        assert snapshot.origin == "ai"
        validate = routes._validate_content_edit

        def validate_locked(row, payload):
            # Reloading without a lock would just move the race to validation.
            with db.engine.connect() as observer:
                query = db.select(DBAssessment.id).where(DBAssessment.id == row.id)
                assert observer.scalar(query.with_for_update(skip_locked=True)) is None
            return validate(row, payload)

        monkeypatch.setattr(routes, "_validate_content_edit", validate_locked)
        response = client.patch(url, json={"justification": reason, "impact_statement": ""})
        assert response.status_code == 200

    with postgres_app.app_context():
        row = DBAssessment.get_by_id(pending["id"])
        assert row.origin == "custom"
        assert row.impact_statement == ""
        assert row.to_openvex_dict()["justification"] == reason


def test_approve_promotes_group_to_custom(client):
    aid = _get_first_ai_id(client)
    resp = _approve(client, aid)
    assert resp.status_code == 200
    body = json.loads(resp.data)
    assert all(a["origin"] == "custom" for a in body["assessments"])
    # now visible in the list feed
    listed = json.loads(client.get("/api/assessments?format=list").data)
    assert any(a["id"] == aid and a["origin"] == "custom" for a in listed)


def test_approve_promotes_only_the_addressed_row(client, app):
    """Two separate AI writes (different variants) are two separate user
    actions and stay two separate rows; approving one must not promote the
    other."""
    other_variant = "22222222-2222-2222-2222-222222222224"
    _add_variant(app, other_variant)

    first = json.loads(_post_ai(client, packages=[PKG]).data)["assessment"]
    second = json.loads(
        _post_ai(client, packages=[PKG2], variant_id=other_variant).data
    )["assessment"]
    assert first["id"] != second["id"]

    resp = _approve(client, first["id"])

    assert resp.status_code == 200
    approved = json.loads(resp.data)["assessments"]
    assert {a["id"] for a in approved} == {first["id"]}
    assert approved[0]["origin"] == "custom"

    listed = json.loads(client.get("/api/assessments?format=list").data)
    listed_ids = {a["id"] for a in listed}
    assert first["id"] in listed_ids
    assert second["id"] not in listed_ids
    still_pending = json.loads(client.get("/api/assessments/review/ai").data)
    assert any(a["id"] == second["id"] for a in still_pending)


def test_approve_missing_returns_404(client):
    resp = _approve(client, str(uuid.uuid4()))
    assert resp.status_code == 404


def test_approve_non_ai_returns_400(client):
    # create a normal custom assessment
    r = client.post(f"/api/vulnerabilities/{VULN_ID}/assessments", json={
        "packages": [PKG], "status": "affected", "variant_id": str(VARIANT_UUID),
    })
    custom_id = json.loads(r.data)["assessment"]["id"]
    resp = _approve(client, custom_id)
    assert resp.status_code == 400


def _add_variant(app, variant_id):
    with app.app_context():
        from src.models.finding import Finding
        from src.models.observation import Observation
        from src.models.scan import Scan

        variant_uuid = uuid.UUID(variant_id)
        db.session.add(
            Variant(id=variant_uuid, project_id=PROJECT_UUID, name="variant-b")
        )
        scan = Scan(id=uuid.uuid4(), variant_id=variant_uuid)
        db.session.add(scan)
        db.session.flush()
        for finding in Finding.get_by_vulnerability(VULN_ID):
            Observation.create(finding.id, scan.id, commit=False)
        db.session.commit()


def test_reject_deletes_only_the_addressed_row(client, app):
    """Two separate AI writes (different variants) stay two separate rows;
    rejecting one must not delete the other."""
    other_variant = "22222222-2222-2222-2222-222222222225"
    _add_variant(app, other_variant)

    first = json.loads(_post_ai(client, packages=[PKG]).data)["assessment"]
    second = json.loads(
        _post_ai(client, packages=[PKG2], variant_id=other_variant).data
    )["assessment"]

    resp = _reject(client, first["id"])

    assert resp.status_code == 200
    assert set(json.loads(resp.data)["deleted"]) == {first["id"]}
    listed = json.loads(client.get("/api/assessments?format=list").data)
    assert first["id"] not in {a["id"] for a in listed}
    still_pending = json.loads(client.get("/api/assessments/review/ai").data)
    assert any(a["id"] == second["id"] for a in still_pending)


def test_reject_missing_returns_404(client):
    assert _reject(client, str(uuid.uuid4())).status_code == 404


def test_reject_non_ai_returns_400(client):
    r = client.post(f"/api/vulnerabilities/{VULN_ID}/assessments", json={
        "packages": [PKG], "status": "affected", "variant_id": str(VARIANT_UUID),
    })
    custom_id = json.loads(r.data)["assessment"]["id"]
    assert _reject(client, custom_id).status_code == 400


def test_ai_excluded_from_list_all_formats(client):
    _post_ai(client)
    listed = json.loads(client.get("/api/assessments?format=list").data)
    assert all(a["origin"] != "ai" for a in listed)
    as_dict = json.loads(client.get("/api/assessments?format=dict").data)
    assert all(a["origin"] != "ai" for a in as_dict.values())


def test_ai_excluded_from_list_by_variant(client):
    _post_ai(client)
    listed = json.loads(client.get(
        f"/api/assessments?format=list&variant_id={VARIANT_UUID}").data)
    assert all(a["origin"] != "ai" for a in listed)


def test_ai_visible_on_per_vuln_endpoint(client):
    _post_ai(client)
    data = json.loads(client.get(f"/api/vulnerabilities/{VULN_ID}/assessments").data)
    assert any(a["origin"] == "ai" for a in data)


def test_patch_ai_row_updates_and_keeps_ai_origin(client):
    aid = _get_first_ai_id(client)
    resp = client.patch(
        f"/api/assessments/{aid}",
        json={
            "status": "not_affected",
            "justification": "component_not_present",
        },
    )
    assert resp.status_code == 200
    body = json.loads(resp.data)["assessment"]
    assert body["status"] == "not_affected"
    assert body["justification"] == "component_not_present"
    # Editing a pending AI assessment directly must not auto-approve it.
    assert body["origin"] == "ai"

    # Still excluded from normal listings / scan-history counts until approved.
    listed = json.loads(client.get("/api/assessments?format=list").data)
    assert all(a["id"] != aid for a in listed)


@pytest.mark.parametrize("method", ["PUT", "PATCH"])
def test_edit_not_affected_requires_justification_key_not_value(client, method):
    row = _post_ai(client, status="not_affected", justification="component_not_present",
                   impact_statement="Component is absent").json["assessment"]
    url = f"/api/assessments/{row['id']}"
    assert client.open(url, method=method, json={"status_notes": "Reviewed"}).status_code == 400
    response = client.open(url, method=method, json={"justification": ""})
    assert response.status_code == 200
    assert response.json["assessment"]["justification"] == ""
    assert response.json["assessment"]["impact_statement"] == "Component is absent"


def test_patch_ai_row_then_approve_promotes_to_custom(client):
    aid = _get_first_ai_id(client)
    patch_resp = client.patch(
        f"/api/assessments/{aid}",
        json={
            "status": "not_affected",
            "justification": "component_not_present",
        },
    )
    assert patch_resp.status_code == 200

    approve_resp = _approve(client, aid)
    assert approve_resp.status_code == 200
    approved = json.loads(approve_resp.data)["assessments"]
    assert any(a["id"] == aid and a["origin"] == "custom" for a in approved)

    listed = json.loads(client.get("/api/assessments?format=list").data)
    listed_row = next(a for a in listed if a["id"] == aid)
    assert listed_row["origin"] == "custom"
    assert listed_row["status"] == "not_affected"
    assert listed_row["justification"] == "component_not_present"


def _stored(app, assessment_id):
    with app.app_context():
        row = DBAssessment.get_by_id(assessment_id)
        assert row is not None
        return {
            "origin": row.origin,
            "status": row.status,
            "simplified_status": row.simplified_status,
            "status_notes": row.status_notes,
            "justification": row.justification,
            "impact_statement": row.impact_statement,
            "workaround": row.workaround,
        }


def test_approve_with_edits_applies_content_and_promotes_atomically(client, app):
    aid = _post_ai(client, status="not_affected", justification="vulnerable_code_not_present",
                   status_notes="AI rationale").json["assessment"]["id"]

    resp = client.post(f"/api/assessments/{aid}/approve", json={
        "justification": "code_not_reachable",
        "impact_statement": "Edited impact",
        "status_notes": "Edited message",
        "workaround": "Edited workaround",
    })

    assert resp.status_code == 200
    approved = json.loads(resp.data)["assessments"]
    assert [a["id"] for a in approved] == [aid]
    assert approved[0]["origin"] == "custom"
    assert approved[0]["status"] == "not_affected"
    assert approved[0]["status_notes"] == "Edited message"
    assert _stored(app, aid) == {
        "origin": "custom",
        "status": "not_affected",
        "simplified_status": "Not affected",
        "status_notes": "Edited message",
        "justification": "code_not_reachable",
        "impact_statement": "Edited impact",
        "workaround": "Edited workaround",
    }
    listed = json.loads(client.get("/api/assessments?format=list").data)
    assert any(a["id"] == aid and a["status_notes"] == "Edited message" for a in listed)


@pytest.mark.parametrize("original,edited,exported", [
    ("code_not_reachable", "component_not_present", "not_affected"),
    ("component_not_present", "code_not_reachable", "false_positive"),
])
def test_approve_preserves_exported_verdict(client, app, original, edited, exported):
    pending = _post_ai(client, status="not_affected", justification=original).json["assessment"]
    aid = pending["id"]
    before = _stored(app, aid)
    response = client.post(f"/api/assessments/{aid}/approve", json={
        "justification": edited, "status_notes": "Revised", "expected_fingerprint": pending["approval_fingerprint"],
    })
    assert response.status_code == 400
    assert "CycloneDX verdict" in response.json["error"]
    assert _stored(app, aid) == before
    assert client.post(f"/api/assessments/{aid}/approve", json={"status_notes": "Revised"}).status_code == 200
    with app.app_context():
        approved = DBAssessment.get_by_id(aid)
        assert approved.to_cdx_vex_dict()["analysis"]["state"] == exported


def test_approve_with_partial_edit_keeps_other_fields(client, app):
    aid = json.loads(_post_ai(
        client, status_notes="AI rationale", workaround="AI workaround",
        impact_statement="Original impact",
    ).data)["assessment"]["id"]

    resp = client.post(f"/api/assessments/{aid}/approve", json={"status_notes": "Edited message"})

    assert resp.status_code == 200
    stored = _stored(app, aid)
    assert stored["origin"] == "custom"
    assert stored["status"] == "affected"
    assert stored["impact_statement"] == "Original impact"
    assert stored["status_notes"] == "Edited message"
    assert stored["workaround"] == "AI workaround"


def test_approve_replaced_imported_message_exports_only_corrected_detail(client, app):
    pending = _post_ai(client, impact_statement="Original impact", status_notes="").json["assessment"]
    resp = client.post(f"/api/assessments/{pending['id']}/approve", json={
        "expected_fingerprint": pending["approval_fingerprint"],
        "status_notes": "Corrected message", "impact_statement": "",
    })
    assert resp.status_code == 200
    with app.app_context():
        approved = DBAssessment.get_by_id(pending["id"])
        assert approved.to_openvex_dict()["status_notes"] == "Corrected message"
        assert approved.to_cdx_vex_dict()["analysis"]["detail"] == "Corrected message"


def test_approve_partial_edit_keeps_existing_required_justification(client, app):
    aid = json.loads(_post_ai(
        client,
        status="not_affected",
        justification="component_not_present",
        impact_statement="The component is absent.",
    ).data)["assessment"]["id"]

    resp = client.post(
        f"/api/assessments/{aid}/approve", json={"status_notes": "Reviewed"},
    )

    assert resp.status_code == 200
    stored = _stored(app, aid)
    assert stored["origin"] == "custom"
    assert stored["justification"] == "component_not_present"
    assert stored["status_notes"] == "Reviewed"


def test_approve_notes_edit_after_clearing_justification_keeps_impact(client, app):
    row = _post_ai(client, status="not_affected", justification="component_not_present",
                   impact_statement="Component is absent").json["assessment"]
    url = f"/api/assessments/{row['id']}"
    assert client.patch(url, json={"justification": ""}).status_code == 200

    assert client.post(url + "/approve", json={"status_notes": "Reviewed"}).status_code == 200
    stored = _stored(app, row["id"])
    assert (stored["origin"], stored["status_notes"]) == ("custom", "Reviewed")
    assert (stored["justification"], stored["impact_statement"]) == ("", "Component is absent")


@pytest.mark.parametrize("status", ["affected", "not_affected", None])
def test_approve_rejects_supplied_status_without_applying_edits(client, app, status):
    row = _post_ai(client, impact_statement="The vulnerable path is reachable").json["assessment"]
    before = _stored(app, row["id"])
    response = client.post(f"/api/assessments/{row['id']}/approve", json={
        "status": status, "justification": "component_not_present", "status_notes": "Edited",
        "expected_fingerprint": row["approval_fingerprint"],
    })
    assert response.status_code == 400
    assert _stored(app, row["id"]) == before


@pytest.mark.parametrize("impact", ["", " \t "])
def test_approve_rejects_empty_merged_required_justification(client, app, impact):
    aid = json.loads(_post_ai(
        client,
        status="not_affected",
        justification="component_not_present",
        impact_statement="The component is absent.",
    ).data)["assessment"]["id"]
    before = _stored(app, aid)

    resp = client.post(f"/api/assessments/{aid}/approve", json={
        "justification": "",
        "impact_statement": impact,
    })

    assert resp.status_code == 400
    assert json.loads(resp.data)["error"] == "Justification required"
    assert _stored(app, aid) == before


@pytest.mark.parametrize("payload, error", [
    ({"simplified_status": "Fixed"},
     "Approval accepts only rationale fields, target_risk_links and expected_fingerprint"),
    ({"justification": "bogus"}, "Invalid justification"),
    *[({field: "reviewed\x00text"}, f"{field} must not contain NUL characters")
      for field in ("status_notes", "impact_statement", "workaround", "justification")],
])
def test_approve_with_invalid_edits_leaves_suggestion_pending(client, app, payload, error):
    aid = json.loads(_post_ai(client, status_notes="AI rationale").data)["assessment"]["id"]
    before = _stored(app, aid)

    resp = client.post(f"/api/assessments/{aid}/approve", json=payload)

    assert resp.status_code == 400
    assert json.loads(resp.data)["error"] == error
    assert _stored(app, aid) == before
    assert before["origin"] == "ai"


@pytest.mark.parametrize("field", [
    "expected_fingerprint", "status_notes", "justification", "impact_statement", "workaround",
])
def test_approve_rejects_non_string_override_fields(client, app, field):
    aid = _get_first_ai_id(client)
    before = _stored(app, aid)

    resp = client.post(
        f"/api/assessments/{aid}/approve", json={field: None},
    )

    assert resp.status_code == 400
    assert _stored(app, aid) == before
    assert before["origin"] == "ai"


def test_approve_returns_conflict_if_row_was_already_approved(client, app, monkeypatch):
    aid = _get_first_ai_id(client)
    from src.routes import assessments as assessment_routes

    resolve_pending = assessment_routes._resolve_pending_ai_row

    def resolve_then_approve(assessment_id):
        row, error = resolve_pending(assessment_id)
        assert row is not None and error is None
        row.update(origin="custom", status_notes="First reviewer")
        return row, error

    monkeypatch.setattr(
        assessment_routes, "_resolve_pending_ai_row", resolve_then_approve,
    )
    resp = client.post(
        f"/api/assessments/{aid}/approve", json={"status_notes": "Stale edit"},
    )

    assert resp.status_code == 409
    assert _stored(app, aid)["origin"] == "custom"
    assert _stored(app, aid)["status_notes"] == "First reviewer"


@pytest.mark.parametrize("edits", [{}, {"status_notes": "Reviewed as affected"}])
def test_confirm_requires_the_content_seen_by_the_editor(client, app, edits):
    aid = _get_first_ai_id(client)
    url = f"/api/assessments/{aid}"
    original = next(a for a in client.get("/api/reviews/assessments?origin=ai").json if a["id"] == aid)
    assert client.patch(url, json={"status": "fixed"}).status_code == 200
    before = _stored(app, aid)

    assert client.post(url + "/approve", json={
        "expected_fingerprint": original["approval_fingerprint"], **edits,
    }).status_code == 409
    assert _stored(app, aid) == before
    latest = client.get(url).json
    assert client.post(url + "/approve", json={
        "expected_fingerprint": latest["approval_fingerprint"], **edits,
    }).status_code == 200


def test_approval_conflicts_after_response_only_reconcile(client):
    pending = _post_ai(client, responses=["update"]).json["assessment"]
    url = f"/api/assessments/{pending['id']}"
    reconciled = client.post(url + "/reconcile", json={
        "vuln_id": VULN_ID, "packages": [PKG], "variant_ids": [str(VARIANT_UUID)],
        "status": pending["status"], "responses": ["will_not_fix"],
    })
    assert reconciled.status_code == 200
    stale = client.post(url + "/approve", json={"expected_fingerprint": pending["approval_fingerprint"]})
    assert stale.status_code == 409
    current = client.get(url).json
    assert (current["origin"], current["responses"]) == ("ai", ["will_not_fix"])
    refreshed = client.post(url + "/approve", json={"expected_fingerprint": current["approval_fingerprint"]})
    assert refreshed.status_code == 200


def test_approval_rechecks_responses_at_promotion(client, monkeypatch):
    from src.routes import assessments as routes

    pending = _post_ai(client, responses=["update"]).json["assessment"]
    validate = routes._validate_content_edit

    def validate_then_change(row, *args, **kwargs):
        result = validate(row, *args, **kwargs)
        with db.engine.begin() as connection:
            connection.execute(db.update(DBAssessment).where(DBAssessment.id == row.id)
                               .values(responses=["will_not_fix"]))
        assert row.responses == ["update"]
        return result

    monkeypatch.setattr(routes, "_validate_content_edit", validate_then_change)
    url = f"/api/assessments/{pending['id']}"
    response = client.post(url + "/approve", json={
        "expected_fingerprint": pending["approval_fingerprint"], "status_notes": "Edited",
    })
    assert response.status_code == 409
    current = client.get(url).json
    assert (current["origin"], current["responses"], current["status_notes"]) == (
        "ai", ["will_not_fix"], pending["status_notes"],
    )


def test_edited_approval_rechecks_targets_at_promotion(client, app, monkeypatch):
    from src.routes import assessments as routes

    original = _post_ai(client, packages=[PKG, PKG2]).json["assessment"]
    validate = routes._validate_content_edit

    def validate_then_trim(row, *args, **kwargs):
        result = validate(row, *args, **kwargs)
        row.target_rows.pop()
        db.session.commit()
        return result

    monkeypatch.setattr(routes, "_validate_content_edit", validate_then_trim)
    response = client.post(f"/api/assessments/{original['id']}/approve", json={
        "expected_fingerprint": original["approval_fingerprint"], "status_notes": "Reviewed both",
    })
    assert response.status_code == 409
    assert _stored(app, original["id"])["origin"] == "ai"


def test_edited_approval_conflicts_with_concurrent_content_change(client, app, monkeypatch):
    from src.routes import assessments as routes

    aid = json.loads(_post_ai(
        client, status="not_affected", justification="component_not_present",
    ).data)["assessment"]["id"]
    validate = routes._validate_content_edit

    def validate_then_change(row, *args, **kwargs):
        result = validate(row, *args, **kwargs)
        # Interleave the state written by a PATCH before the approval's UPDATE.
        row.update(status="affected")
        return result

    monkeypatch.setattr(routes, "_validate_content_edit", validate_then_change)
    resp = client.post(f"/api/assessments/{aid}/approve", json={"status_notes": "Stale edit"})

    assert resp.status_code == 409
    stored = _stored(app, aid)
    assert (stored["origin"], stored["status"]) == ("ai", "affected")


def test_approve_rejects_non_object_or_malformed_body(client, app):
    aid = _get_first_ai_id(client)

    assert client.post(f"/api/assessments/{aid}/approve", json=["status"]).status_code == 400
    malformed = client.post(
        f"/api/assessments/{aid}/approve", data="{", content_type="application/json",
    )
    assert malformed.status_code == 400
    assert _stored(app, aid)["origin"] == "ai"


@pytest.mark.parametrize("without_length", [False, True])
@pytest.mark.parametrize("extra_byte", [False, True])
def test_approve_request_body_limit(client, app, without_length, extra_byte):
    aid = _get_first_ai_id(client)
    payload = b"{}".ljust(64 * 1024 + int(extra_byte))
    url = f"/api/assessments/{aid}/approve"
    if without_length:
        req = app.test_request_context(url, method="POST", content_type="application/json").request
        req.environ.pop("CONTENT_LENGTH", None)
        req.environ.update({"wsgi.input": BytesIO(payload), "wsgi.input_terminated": True})
        resp = client.open(req)
        assert resp.request.content_length is None
    else:
        resp = client.post(url, data=payload, content_type="application/json")

    assert resp.status_code == (413 if extra_byte else 200)
    assert _stored(app, aid)["origin"] == ("ai" if extra_byte else "custom")


def test_approve_ignores_non_json_body(client, app):
    aid = json.loads(_post_ai(client, status_notes="AI rationale").data)["assessment"]["id"]

    resp = client.post(f"/api/assessments/{aid}/approve", data="status_notes=x", content_type="text/plain")

    assert resp.status_code == 200
    stored = _stored(app, aid)
    assert stored["origin"] == "custom"
    assert stored["status_notes"] == "AI rationale"


def test_approve_with_empty_object_approves_unchanged(client, app):
    aid = json.loads(_post_ai(client, status_notes="AI rationale").data)["assessment"]["id"]

    resp = client.post(f"/api/assessments/{aid}/approve", json={})

    assert resp.status_code == 200
    stored = _stored(app, aid)
    assert stored["origin"] == "custom"
    assert stored["status_notes"] == "AI rationale"


def test_approve_with_edits_on_non_ai_returns_400_without_changes(client, app):
    r = client.post(f"/api/vulnerabilities/{VULN_ID}/assessments", json={
        "packages": [PKG], "status": "affected", "variant_id": str(VARIANT_UUID),
        "status_notes": "Human notes",
    })
    custom_id = json.loads(r.data)["assessment"]["id"]

    resp = client.post(f"/api/assessments/{custom_id}/approve", json={"status_notes": "Changed"})

    assert resp.status_code == 400
    assert _stored(app, custom_id)["status_notes"] == "Human notes"


def test_delete_ai_row_returns_400(client):
    aid = _get_first_ai_id(client)
    resp = client.delete(f"/api/assessments/{aid}")
    assert resp.status_code == 400
    assert json.loads(resp.data)["error"] == (
        "Use the AI approve/reject endpoints for pending AI assessments"
    )


def _openvex_statements(client):
    from src.views.openvex import OpenVex
    from src.controllers.cache import ControllersCache
    with client.application.app_context():
        ctrls = ControllersCache()
        ctrls.packages._preload_cache()
        return OpenVex(ctrls).to_dict().get("statements", [])


def test_pending_ai_excluded_from_openvex_export(client):
    before = json.dumps(_openvex_statements(client), sort_keys=True)

    aid = _get_first_ai_id(client)

    pending = json.dumps(_openvex_statements(client), sort_keys=True)
    assert pending == before

    resp = _approve(client, aid)
    assert resp.status_code == 200

    approved = json.dumps(_openvex_statements(client), sort_keys=True)
    assert approved != before


def test_pending_ai_excluded_from_scan_history(client):
    baseline = json.loads(client.get("/api/scans").data)
    baseline_scan = next(row for row in baseline if row["id"] == str(SCAN_UUID))
    assert baseline_scan["assessment_count"] == 0
    assert baseline_scan["assessments_added"] == 0

    _post_ai(client)

    data = json.loads(client.get("/api/scans").data)
    scan = next(row for row in data if row["id"] == str(SCAN_UUID))
    assert scan["assessment_count"] == 0
    assert scan["assessments_added"] == 0


def test_pending_ai_excluded_from_scan_diff(client):
    baseline = json.loads(client.get(f"/api/scans/{SCAN_UUID}/diff").data)
    assert baseline["assessment_count"] == 0
    assert baseline["assessments_added"] == []
    assert baseline["assessments_unchanged"] == []
    assert baseline["assessments_removed"] == []

    _post_ai(client)

    data = json.loads(client.get(f"/api/scans/{SCAN_UUID}/diff").data)
    assert data["assessment_count"] == 0
    assert data["assessments_added"] == []
    assert data["assessments_unchanged"] == []
    assert data["assessments_removed"] == []


def test_pending_ai_excluded_from_scan_global_result(client):
    baseline = json.loads(client.get(f"/api/scans/{SCAN_UUID}/global-result").data)
    assert baseline["vulnerabilities"]
    assert any(v["vulnerability_id"] == VULN_ID for v in baseline["vulnerabilities"])
    assert baseline["assessment_count"] == 0
    assert baseline["assessments"] == []

    _post_ai(client)

    data = json.loads(client.get(f"/api/scans/{SCAN_UUID}/global-result").data)
    assert data["assessment_count"] == 0
    assert data["assessments"] == []


def _cyclonedx_vuln_analysis(client):
    """The CycloneDX VEX analysis emitted for VULN_ID (or None if absent)."""
    from src.views.cyclonedx import CycloneDx
    from src.controllers.cache import ControllersCache
    with client.application.app_context():
        ctrls = ControllersCache()
        ctrls.packages._preload_cache()
        output = json.loads(CycloneDx(ctrls).output_as_json())
    for v in output.get("vulnerabilities", []):
        if v.get("id") == VULN_ID:
            return v.get("analysis")
    return None


def test_pending_ai_excluded_from_cyclonedx_export(client):
    before = _cyclonedx_vuln_analysis(client)

    aid = _get_first_ai_id(client)

    # Pending AI must not surface as the exported VEX analysis.
    assert _cyclonedx_vuln_analysis(client) == before

    resp = _approve(client, aid)
    assert resp.status_code == 200

    # Once approved (origin -> custom) it becomes the exported analysis.
    assert _cyclonedx_vuln_analysis(client) != before


def _report_assessment_ids(client):
    """Assessment ids exposed to report templates via unfiltered_assessments."""
    from jinja2 import DictLoader
    from src.views.templates import Templates
    from src.controllers.cache import ControllersCache
    with client.application.app_context():
        ctrls = ControllersCache()
        ctrls.packages._preload_cache()
        templ = Templates(ctrls)
        templ.env.loader = DictLoader(
            {"__ai_probe__": "{{ unfiltered_assessments.keys() | list | join(',') }}"}
        )
        rendered = templ.render("__ai_probe__")
    return set(filter(None, rendered.split(",")))


def test_pending_ai_excluded_from_report_templates(client):
    aid = _get_first_ai_id(client)

    # Pending AI is not passed to report templates.
    assert aid not in _report_assessment_ids(client)

    resp = _approve(client, aid)
    assert resp.status_code == 200

    # After approval it appears in the report feed.
    assert aid in _report_assessment_ids(client)


# ── legacy per-assessment approve/reject (compatibility wrappers) ─────────

def test_legacy_approve_promotes_only_the_addressed_row(client, app):
    """Pre-group clients address one id. Two separate AI writes (different
    variants) stay two separate rows, so the legacy wrapper only ever
    promotes the addressed row."""
    other_variant = "22222222-2222-2222-2222-222222222226"
    _add_variant(app, other_variant)

    first = json.loads(_post_ai(client, packages=[PKG]).data)["assessment"]
    second = json.loads(
        _post_ai(client, packages=[PKG2], variant_id=other_variant).data
    )["assessment"]

    resp = client.post(f"/api/assessments/{first['id']}/approve")

    assert resp.status_code == 200
    approved = json.loads(resp.data)["assessments"]
    assert {a["id"] for a in approved} == {first["id"]}
    assert approved[0]["origin"] == "custom"
    still_pending = {a["id"] for a in json.loads(
        client.get("/api/assessments/review/ai").data)}
    assert still_pending == {second["id"]}


def test_legacy_approve_works_on_an_ungrouped_assessment(client):
    aid = _get_first_ai_id(client)

    resp = client.post(f"/api/assessments/{aid}/approve")

    assert resp.status_code == 200
    listed = json.loads(client.get("/api/assessments?format=list").data)
    assert any(a["id"] == aid and a["origin"] == "custom" for a in listed)


def test_legacy_reject_deletes_only_the_addressed_row(client, app):
    other_variant = "22222222-2222-2222-2222-222222222227"
    _add_variant(app, other_variant)

    first = json.loads(_post_ai(client, packages=[PKG]).data)["assessment"]
    second = json.loads(
        _post_ai(client, packages=[PKG2], variant_id=other_variant).data
    )["assessment"]

    resp = client.post(f"/api/assessments/{first['id']}/reject")

    assert resp.status_code == 200
    assert set(json.loads(resp.data)["deleted"]) == {first["id"]}
    listed = json.loads(client.get("/api/assessments?format=list").data)
    assert first["id"] not in {a["id"] for a in listed}
    still_pending = {a["id"] for a in json.loads(
        client.get("/api/assessments/review/ai").data)}
    assert still_pending == {second["id"]}


def test_legacy_approve_rejects_a_non_ai_assessment(client):
    resp = client.post(
        f"/api/vulnerabilities/{VULN_ID}/assessments",
        json={"packages": [PKG], "status": "affected",
              "variant_id": str(VARIANT_UUID)},
    )
    custom_id = json.loads(resp.data)["assessment"]["id"]

    assert client.post(f"/api/assessments/{custom_id}/approve").status_code == 400
    assert client.post(f"/api/assessments/{custom_id}/reject").status_code == 400


def test_legacy_approve_returns_404_for_unknown_assessment(client):
    unknown = str(uuid.uuid4())

    assert client.post(f"/api/assessments/{unknown}/approve").status_code == 404
    assert client.post(f"/api/assessments/{unknown}/reject").status_code == 404


# NOTE: there is deliberately no test for "approve refuses a group with a
# non-AI member". A group is an assessment, and an assessment carries a
# single `origin`, so a group spanning two origins is unrepresentable
# rather than merely rejected.
