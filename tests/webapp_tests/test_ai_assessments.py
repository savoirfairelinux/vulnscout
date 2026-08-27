# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import os
import uuid

import pytest

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


def test_ai_post_duplicate_rejected(client):
    first = _post_ai(client)
    assert first.status_code == 200

    second = _post_ai(client)
    assert second.status_code == 409
    body = json.loads(second.data)
    assert body["error"] == "A pending AI assessment already exists for this variant"


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


def _group_id_for(client, assessment_id):
    """Resolve (creating if needed) the group an assessment belongs to."""
    resp = client.post(f"/api/assessments/{assessment_id}/group")
    return json.loads(resp.data)["group_id"]


def _approve(client, assessment_id):
    """Promote a single assessment to a group (or reuse its existing one),
    then approve that group. Mirrors the lazy-promotion flow the front-end
    uses for a single-target AI review row."""
    group_id = _group_id_for(client, assessment_id)
    return client.post(f"/api/assessment-groups/{group_id}/approve")


def _reject(client, assessment_id):
    group_id = _group_id_for(client, assessment_id)
    return client.post(f"/api/assessment-groups/{group_id}/reject")


def test_approve_promotes_group_to_custom(client):
    aid = _get_first_ai_id(client)
    resp = _approve(client, aid)
    assert resp.status_code == 200
    body = json.loads(resp.data)
    assert all(a["origin"] == "custom" for a in body["assessments"])
    # now visible in the list feed
    listed = json.loads(client.get("/api/assessments?format=list").data)
    assert any(a["id"] == aid and a["origin"] == "custom" for a in listed)


def test_approve_promotes_only_the_addressed_row(client):
    """A multi-package AI write still creates one row per package (write-path
    migration to a shared multi-target assessment is out of scope for this
    read-path task); each row is now its own group, so approving one no
    longer promotes its siblings."""
    body = json.loads(_post_ai(client, packages=[PKG, PKG2]).data)
    rows = body["assessments"]
    assert len(rows) == 2
    first, second = rows
    assert first["group_id"] == first["id"]

    resp = client.post(f"/api/assessment-groups/{first['group_id']}/approve")

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
    resp = client.post(f"/api/assessment-groups/{uuid.uuid4()}/approve")
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


def test_group_id_payload_no_longer_merges_writes_across_variants(client, app):
    """Joining an existing group at write time is out of scope for this
    phase (a group only grows through reconcile, once it already holds real
    targets — see test_post_endpoints.py). Posting a second AI write with an
    existing assessment's id as ``group_id`` simply creates its own,
    independent row instead of merging into it."""
    other_variant = "22222222-2222-2222-2222-222222222223"
    _add_variant(app, other_variant)

    a1 = json.loads(_post_ai(client).data)["assessment"]["id"]
    group_id = _group_id_for(client, a1)
    a2_resp = _post_ai(client, variant_id=other_variant, group_id=group_id)
    assert a2_resp.status_code == 200
    a2_row = json.loads(a2_resp.data)["assessment"]
    assert a2_row["group_id"] == a2_row["id"]
    assert a2_row["group_id"] != group_id

    resp = client.post(f"/api/assessment-groups/{group_id}/approve")
    assert resp.status_code == 200
    approved = {a["id"] for a in json.loads(resp.data)["assessments"]}
    assert approved == {a1}

    # the sibling row remains pending, untouched by the first row's approval
    still_pending = json.loads(client.get("/api/assessments/review/ai").data)
    assert any(a["id"] == a2_row["id"] for a in still_pending)


def test_joining_a_pending_ai_group_with_a_custom_row_no_longer_conflicts(client):
    """Origin homogeneity is enforced per-row now (a group is one row, one
    origin); the legacy ``group_id`` payload no longer fuses across writes,
    so a mismatched-origin write is simply its own independent row rather
    than being refused."""
    aid = _get_first_ai_id(client)
    group_id = _group_id_for(client, aid)
    r = client.post(f"/api/vulnerabilities/{VULN_ID}/assessments", json={
        "packages": [PKG2], "status": "affected", "variant_id": str(VARIANT_UUID),
        "group_id": group_id,
    })
    assert r.status_code == 200
    new_row = json.loads(r.data)["assessment"]
    assert new_row["origin"] == "custom"
    assert new_row["group_id"] == new_row["id"]

    # the pending AI row must remain untouched and still approvable
    listed = json.loads(client.get("/api/assessments/review/ai").data)
    assert any(a["id"] == aid for a in listed)
    assert client.post(f"/api/assessment-groups/{group_id}/approve").status_code == 200


def test_reject_deletes_only_the_addressed_row(client):
    """A multi-package AI write still creates one row per package; rejecting
    one row's group no longer deletes its siblings."""
    body = json.loads(_post_ai(client, packages=[PKG, PKG2]).data)
    rows = body["assessments"]
    assert len(rows) == 2
    first, second = rows

    resp = client.post(f"/api/assessment-groups/{first['group_id']}/reject")

    assert resp.status_code == 200
    assert set(json.loads(resp.data)["deleted"]) == {first["id"]}
    listed = json.loads(client.get("/api/assessments?format=list").data)
    assert first["id"] not in {a["id"] for a in listed}
    still_pending = json.loads(client.get("/api/assessments/review/ai").data)
    assert any(a["id"] == second["id"] for a in still_pending)


def test_reject_missing_returns_404(client):
    assert client.post(
        f"/api/assessment-groups/{uuid.uuid4()}/reject"
    ).status_code == 404


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

def test_legacy_approve_promotes_only_the_addressed_row(client):
    """Pre-group clients address one id. A multi-package write still creates
    one row per package (write-path migration is out of scope for this
    read-path task); each row is now its own group, so the legacy wrapper
    only ever promotes the addressed row."""
    body = json.loads(_post_ai(client, packages=[PKG, PKG2]).data)
    rows = body["assessments"]
    assert len(rows) == 2
    first, second = rows

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


def test_legacy_reject_deletes_only_the_addressed_row(client):
    body = json.loads(_post_ai(client, packages=[PKG, PKG2]).data)
    rows = body["assessments"]
    assert len(rows) == 2
    first, second = rows

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


# NOTE: the old `test_legacy_approve_refuses_a_group_with_a_non_ai_member`
# manufactured a "heterogeneous group" by inserting an AssessmentGroupMember
# row directly, bypassing write-time validation, to simulate pre-migration
# data. A group is now an assessment: _resolve_pending_ai_rows resolves only
# the addressed row (never AssessmentGroupMember), so a group can no longer
# span more than one origin. That scenario is categorically impossible under
# the new model and the test was deleted rather than rewritten.
