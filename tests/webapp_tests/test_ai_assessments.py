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
        setup_demo_db(application)
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
    with app.app_context():
        db.session.add(
            Variant(
                id=uuid.UUID(other_variant),
                project_id=PROJECT_UUID,
                name="variant-b",
            )
        )
        db.session.commit()

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


def test_approve_promotes_group_to_custom(client):
    aid = _get_first_ai_id(client)
    resp = client.post(f"/api/assessments/{aid}/approve")
    assert resp.status_code == 200
    body = json.loads(resp.data)
    assert all(a["origin"] == "custom" for a in body["assessments"])
    # now visible in the list feed
    listed = json.loads(client.get("/api/assessments?format=list").data)
    assert any(a["id"] == aid and a["origin"] == "custom" for a in listed)


def test_approve_promotes_multi_package_group(client):
    body = json.loads(_post_ai(client, packages=[PKG, PKG2]).data)
    aid = body["assessments"][0]["id"]

    resp = client.post(f"/api/assessments/{aid}/approve")

    assert resp.status_code == 200
    approved = json.loads(resp.data)["assessments"]
    assert len(approved) >= 2
    assert all(a["origin"] == "custom" for a in approved)

    listed = json.loads(client.get("/api/assessments?format=list").data)
    promoted = [a for a in listed if a["id"] in {row["id"] for row in approved}]
    assert len(promoted) >= 2
    assert all(a["origin"] == "custom" for a in promoted)


def test_approve_group_update_is_atomic(client, app, monkeypatch):
    body = json.loads(_post_ai(client, packages=[PKG, PKG2]).data)
    ids = [row["id"] for row in body["assessments"]]

    original_update = DBAssessment.update
    call_count = 0

    def flaky_update(self, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            raise RuntimeError("boom")
        return original_update(self, *args, **kwargs)

    monkeypatch.setattr(DBAssessment, "update", flaky_update)

    with pytest.raises(RuntimeError, match="boom"):
        client.post(f"/api/assessments/{ids[0]}/approve")

    with app.app_context():
        reloaded = [DBAssessment.get_by_id(assessment_id) for assessment_id in ids]
        assert all(row is not None and row.origin == "ai" for row in reloaded)


def test_approve_missing_returns_404(client):
    resp = client.post(f"/api/assessments/{uuid.uuid4()}/approve")
    assert resp.status_code == 404


def test_approve_non_ai_returns_400(client):
    # create a normal custom assessment
    r = client.post(f"/api/vulnerabilities/{VULN_ID}/assessments", json={
        "packages": [PKG], "status": "affected", "variant_id": str(VARIANT_UUID),
    })
    custom_id = json.loads(r.data)["assessment"]["id"]
    resp = client.post(f"/api/assessments/{custom_id}/approve")
    assert resp.status_code == 400


def _add_variant(app, variant_id):
    with app.app_context():
        db.session.add(
            Variant(id=uuid.UUID(variant_id), project_id=PROJECT_UUID, name="variant-b")
        )
        db.session.commit()


def test_approve_with_ids_spans_multiple_variants(client, app):
    """A grouped review row can cover several variants; passing every id in the
    row must promote all of them, not just the addressed variant's assessment."""
    other_variant = "22222222-2222-2222-2222-222222222223"
    _add_variant(app, other_variant)

    a1 = json.loads(_post_ai(client).data)["assessment"]["id"]
    a2 = json.loads(_post_ai(client, variant_id=other_variant).data)["assessment"]["id"]

    resp = client.post(f"/api/assessments/{a1}/approve", json={"ids": [a1, a2]})
    assert resp.status_code == 200
    approved = {a["id"]: a for a in json.loads(resp.data)["assessments"]}
    assert set(approved) == {a1, a2}
    assert all(a["origin"] == "custom" for a in approved.values())


def test_reject_with_ids_spans_multiple_variants(client, app):
    other_variant = "22222222-2222-2222-2222-222222222223"
    _add_variant(app, other_variant)

    a1 = json.loads(_post_ai(client).data)["assessment"]["id"]
    a2 = json.loads(_post_ai(client, variant_id=other_variant).data)["assessment"]["id"]

    resp = client.post(f"/api/assessments/{a1}/reject", json={"ids": [a1, a2]})
    assert resp.status_code == 200
    assert set(json.loads(resp.data)["deleted"]) == {a1, a2}
    listed = json.loads(client.get("/api/assessments?format=list").data)
    assert not ({a1, a2} & {a["id"] for a in listed})


def test_approve_with_ids_rejects_non_ai_member(client):
    aid = _get_first_ai_id(client)
    r = client.post(f"/api/vulnerabilities/{VULN_ID}/assessments", json={
        "packages": [PKG2], "status": "affected", "variant_id": str(VARIANT_UUID),
    })
    custom_id = json.loads(r.data)["assessment"]["id"]

    resp = client.post(f"/api/assessments/{aid}/approve", json={"ids": [aid, custom_id]})
    assert resp.status_code == 400
    # the pending AI row must remain untouched
    listed = json.loads(client.get("/api/assessments/review/ai").data)
    assert any(a["id"] == aid for a in listed)


def test_approve_with_ids_rejects_missing_member(client):
    aid = _get_first_ai_id(client)
    resp = client.post(
        f"/api/assessments/{aid}/approve", json={"ids": [aid, str(uuid.uuid4())]}
    )
    assert resp.status_code == 404


def test_reject_deletes_group(client):
    body = json.loads(_post_ai(client, packages=[PKG, PKG2]).data)
    aid = body["assessment"]["id"]
    ids = {a["id"] for a in body["assessments"]}

    resp = client.post(f"/api/assessments/{aid}/reject")

    assert resp.status_code == 200
    assert len(body["assessments"]) >= 2
    assert set(json.loads(resp.data)["deleted"]) == ids
    listed = json.loads(client.get("/api/assessments?format=list").data)
    assert not (ids & {a["id"] for a in listed})


def test_reject_group_delete_is_atomic(client, app, monkeypatch):
    body = json.loads(_post_ai(client, packages=[PKG, PKG2]).data)
    ids = [row["id"] for row in body["assessments"]]

    original_delete = DBAssessment.delete
    call_count = 0

    def flaky_delete(self, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            raise RuntimeError("boom")
        return original_delete(self, *args, **kwargs)

    monkeypatch.setattr(DBAssessment, "delete", flaky_delete)

    with pytest.raises(RuntimeError, match="boom"):
        client.post(f"/api/assessments/{ids[0]}/reject")

    with app.app_context():
        reloaded = [DBAssessment.get_by_id(assessment_id) for assessment_id in ids]
        assert all(row is not None and row.origin == "ai" for row in reloaded)


def test_reject_missing_returns_404(client):
    assert client.post(f"/api/assessments/{uuid.uuid4()}/reject").status_code == 404


def test_reject_non_ai_returns_400(client):
    r = client.post(f"/api/vulnerabilities/{VULN_ID}/assessments", json={
        "packages": [PKG], "status": "affected", "variant_id": str(VARIANT_UUID),
    })
    custom_id = json.loads(r.data)["assessment"]["id"]
    assert client.post(f"/api/assessments/{custom_id}/reject").status_code == 400


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

    approve_resp = client.post(f"/api/assessments/{aid}/approve")
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

    resp = client.post(f"/api/assessments/{aid}/approve")
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

    resp = client.post(f"/api/assessments/{aid}/approve")
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

    resp = client.post(f"/api/assessments/{aid}/approve")
    assert resp.status_code == 200

    # After approval it appears in the report feed.
    assert aid in _report_assessment_ids(client)
