# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for POST /api/assessments/group-reconcile."""

import os
import uuid

import pytest

from src.bin.webapp import create_app
from . import write_demo_files, setup_demo_db

VULN = "CVE-2020-35492"
PKG = "cairo@1.16.0"
VARIANT_1 = "22222222-2222-2222-2222-222222222222"
VARIANT_2 = "55555555-5555-5555-5555-555555555555"


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
            "OPENVEX_FILE": str(init_files["openvex"]),
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db",
        })
        setup_demo_db(application)
        _add_second_variant(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


def _add_second_variant(application):
    """Give the demo finding a second variant so multi-variant groups exist."""
    from src.extensions import db
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.scan import Scan
    from src.models.variant import Variant

    with application.app_context():
        variant = Variant(
            id=uuid.UUID(VARIANT_2),
            name="second",
            project_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
        )
        db.session.add(variant)
        scan = Scan(id=uuid.UUID("66666666-6666-6666-6666-666666666666"), variant_id=variant.id)
        db.session.add(scan)
        db.session.commit()
        finding = db.session.execute(
            db.select(Finding).where(Finding.vulnerability_id == VULN)
        ).scalars().first()
        db.session.add(Observation(finding_id=finding.id, scan_id=scan.id))
        db.session.commit()


@pytest.fixture()
def client(app):
    return app.test_client()


def _create(client, variant_id=VARIANT_1, status="affected"):
    resp = client.post(
        f"/api/vulnerabilities/{VULN}/assessments",
        json={"packages": [PKG], "status": status, "variant_id": variant_id},
    )
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["assessment"]["id"]


def _reconcile(client, **payload):
    return client.post("/api/assessments/group-reconcile", json=payload)


def test_updates_existing_row_in_place(client):
    assessment_id = _create(client)
    resp = _reconcile(
        client,
        vuln_id=VULN, existing_ids=[assessment_id], packages=[PKG],
        variant_ids=[VARIANT_1], status="fixed",
    )
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert body["status"] == "success"
    assert len(body["updated"]) == 1
    assert body["created"] == []
    assert body["deleted"] == []
    assert body["updated"][0]["id"] == assessment_id
    assert body["updated"][0]["status"] == "fixed"


def test_creates_row_for_newly_selected_variant(client):
    assessment_id = _create(client)
    resp = _reconcile(
        client,
        vuln_id=VULN, existing_ids=[assessment_id], packages=[PKG],
        variant_ids=[VARIANT_1, VARIANT_2], status="fixed",
    )
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert len(body["updated"]) == 1
    assert len(body["created"]) == 1
    assert body["created"][0]["variant_id"] == VARIANT_2
    assert body["deleted"] == []


def test_deletes_row_for_deselected_variant(client):
    first = _create(client, variant_id=VARIANT_1)
    second = _create(client, variant_id=VARIANT_2)
    resp = _reconcile(
        client,
        vuln_id=VULN, existing_ids=[first, second], packages=[PKG],
        variant_ids=[VARIANT_1], status="fixed",
    )
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert body["deleted"] == [second]
    assert len(body["updated"]) == 1
    assert client.get(f"/api/assessments/{second}").status_code == 404


def test_all_rows_share_one_timestamp(client):
    assessment_id = _create(client)
    resp = _reconcile(
        client,
        vuln_id=VULN, existing_ids=[assessment_id], packages=[PKG],
        variant_ids=[VARIANT_1, VARIANT_2], status="fixed",
    )
    body = resp.get_json()
    stamps = {row["timestamp"] for row in body["updated"] + body["created"]}
    assert len(stamps) == 1


def test_rejects_id_belonging_to_another_vulnerability(client):
    assessment_id = _create(client)
    resp = _reconcile(
        client,
        vuln_id="CVE-2019-0001", existing_ids=[assessment_id], packages=[PKG],
        variant_ids=[VARIANT_1], status="fixed",
    )
    assert resp.status_code == 400
    assert "does not belong to" in resp.get_json()["error"]


def test_rejects_unknown_package(client):
    resp = _reconcile(
        client,
        vuln_id=VULN, existing_ids=[], packages=["ghost@9.9.9"],
        variant_ids=[VARIANT_1], status="fixed",
    )
    assert resp.status_code == 400
    assert "Package not found" in resp.get_json()["error"]


def test_rejects_empty_variant_ids(client):
    resp = _reconcile(
        client, vuln_id=VULN, existing_ids=[], packages=[PKG],
        variant_ids=[], status="fixed",
    )
    assert resp.status_code == 400
    assert "variant_ids" in resp.get_json()["error"]


def test_invalid_combo_writes_nothing(client):
    """One bad package must cancel the whole action, including the good rows."""
    first = _create(client, variant_id=VARIANT_1, status="affected")
    second = _create(client, variant_id=VARIANT_2, status="affected")

    resp = _reconcile(
        client,
        vuln_id=VULN, existing_ids=[first, second],
        packages=[PKG, "ghost@9.9.9"],
        variant_ids=[VARIANT_1], status="fixed",
    )
    assert resp.status_code == 400

    # Neither the update to `first` nor the deletion of `second` happened.
    for assessment_id in (first, second):
        row = client.get(f"/api/assessments/{assessment_id}")
        assert row.status_code == 200
        assert row.get_json()["status"] == "affected"


def test_editing_pending_ai_row_keeps_it_pending(client):
    resp = client.post(
        f"/api/vulnerabilities/{VULN}/assessments",
        json={"packages": [PKG], "status": "affected",
              "variant_id": VARIANT_1, "ai_generated": True},
    )
    assert resp.status_code == 200, resp.get_json()
    assessment_id = resp.get_json()["assessment"]["id"]

    body = _reconcile(
        client,
        vuln_id=VULN, existing_ids=[assessment_id], packages=[PKG],
        variant_ids=[VARIANT_1], status="fixed",
    ).get_json()
    assert body["updated"][0]["origin"] == "ai"

    persisted = client.get(f"/api/assessments/{assessment_id}")
    assert persisted.status_code == 200
    assert persisted.get_json()["origin"] == "ai"


def test_update_timestamp_false_preserves_timestamps(client):
    assessment_id = _create(client)
    before = client.get(f"/api/assessments/{assessment_id}").get_json()["timestamp"]
    body = _reconcile(
        client,
        vuln_id=VULN, existing_ids=[assessment_id], packages=[PKG],
        variant_ids=[VARIANT_1], status="fixed", update_timestamp=False,
    ).get_json()
    assert body["updated"][0]["timestamp"] == before

    persisted = client.get(f"/api/assessments/{assessment_id}")
    assert persisted.status_code == 200
    assert persisted.get_json()["timestamp"] == before


def _mutate_row(application, assessment_id, **fields):
    """Set fields directly on a stored row (to build states the API forbids)."""
    from src.extensions import db
    from src.models.assessment import Assessment

    with application.app_context():
        row = db.session.get(Assessment, uuid.UUID(assessment_id))
        for name, value in fields.items():
            setattr(row, name, value)
        db.session.commit()


def _read_row(application, assessment_id, field):
    from src.extensions import db
    from src.models.assessment import Assessment

    with application.app_context():
        row = db.session.get(Assessment, uuid.UUID(assessment_id))
        return getattr(row, field)


def test_edit_without_responses_keeps_stored_responses(app, client):
    """An edit that omits ``responses`` must not wipe imported VEX responses."""
    assessment_id = _create(client)
    _mutate_row(app, assessment_id, responses=["will_not_fix", "workaround_available"])

    resp = _reconcile(
        client,
        vuln_id=VULN, existing_ids=[assessment_id], packages=[PKG],
        variant_ids=[VARIANT_1], status="fixed",
    )
    assert resp.status_code == 200, resp.get_json()
    assert resp.get_json()["updated"][0]["responses"] == ["will_not_fix", "workaround_available"]
    assert _read_row(app, assessment_id, "responses") == ["will_not_fix", "workaround_available"]


def test_explicit_responses_replace_stored_responses(app, client):
    assessment_id = _create(client)
    _mutate_row(app, assessment_id, responses=["will_not_fix"])

    resp = _reconcile(
        client,
        vuln_id=VULN, existing_ids=[assessment_id], packages=[PKG],
        variant_ids=[VARIANT_1], status="fixed", responses=["rollback"],
    )
    assert resp.status_code == 200, resp.get_json()
    assert resp.get_json()["updated"][0]["responses"] == ["rollback"]
    assert _read_row(app, assessment_id, "responses") == ["rollback"]


def test_rejects_row_without_variant(app, client):
    """A legacy row with no variant cannot be keyed, so the request is refused."""
    assessment_id = _create(client)
    _mutate_row(app, assessment_id, variant_id=None)

    resp = _reconcile(
        client,
        vuln_id=VULN, existing_ids=[assessment_id], packages=[PKG],
        variant_ids=[VARIANT_1], status="fixed",
    )
    assert resp.status_code == 400
    assert "cannot be reconciled" in resp.get_json()["error"]
    # Nothing was written: the row kept its original status.
    assert _read_row(app, assessment_id, "status") == "affected"


def test_new_sibling_shares_group_timestamp_when_not_updating(app, client):
    """With update_timestamp false the created row uses the group timestamp."""
    assessment_id = _create(client)
    before = client.get(f"/api/assessments/{assessment_id}").get_json()["timestamp"]

    body = _reconcile(
        client,
        vuln_id=VULN, existing_ids=[assessment_id], packages=[PKG],
        variant_ids=[VARIANT_1, VARIANT_2], status="fixed",
        update_timestamp=False, timestamp=before,
    ).get_json()
    assert len(body["created"]) == 1
    assert body["updated"][0]["timestamp"] == before
    assert body["created"][0]["timestamp"] == before


def test_refuses_to_delete_pending_ai_row(app, client):
    """AI rows are approved/rejected through their own endpoints, never here."""
    kept = _create(client, variant_id=VARIANT_1)
    resp = client.post(
        f"/api/vulnerabilities/{VULN}/assessments",
        json={"packages": [PKG], "status": "affected",
              "variant_id": VARIANT_2, "ai_generated": True},
    )
    assert resp.status_code == 200, resp.get_json()
    ai_id = resp.get_json()["assessment"]["id"]

    result = _reconcile(
        client,
        vuln_id=VULN, existing_ids=[kept, ai_id], packages=[PKG],
        variant_ids=[VARIANT_1], status="fixed",
    )
    assert result.status_code == 400
    assert "AI approve/reject" in result.get_json()["error"]
    # Neither the deletion nor the update to the kept row happened.
    assert client.get(f"/api/assessments/{ai_id}").status_code == 200
    assert _read_row(app, kept, "status") == "affected"


def test_deleting_non_custom_row_invalidates_scan_cache(app, client, monkeypatch):
    kept = _create(client, variant_id=VARIANT_1)
    dropped = _create(client, variant_id=VARIANT_2)
    _mutate_row(app, dropped, origin="sbom")

    calls = []
    monkeypatch.setattr(
        "src.routes.assessments.invalidate_scan_list_cache",
        lambda *a, **kw: calls.append(True),
    )
    resp = _reconcile(
        client,
        vuln_id=VULN, existing_ids=[kept, dropped], packages=[PKG],
        variant_ids=[VARIANT_1], status="fixed",
    )
    assert resp.status_code == 200, resp.get_json()
    assert resp.get_json()["deleted"] == [dropped]
    assert calls, "deleting a non-custom row must invalidate the scan list cache"


def test_deleting_custom_row_does_not_invalidate_scan_cache(app, client, monkeypatch):
    kept = _create(client, variant_id=VARIANT_1)
    dropped = _create(client, variant_id=VARIANT_2)

    calls = []
    monkeypatch.setattr(
        "src.routes.assessments.invalidate_scan_list_cache",
        lambda *a, **kw: calls.append(True),
    )
    resp = _reconcile(
        client,
        vuln_id=VULN, existing_ids=[kept, dropped], packages=[PKG],
        variant_ids=[VARIANT_1], status="fixed",
    )
    assert resp.status_code == 200, resp.get_json()
    assert calls == []
