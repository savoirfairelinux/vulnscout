# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Regression tests for the multi-target assessment refactor.

Each test here pins behaviour that existed before assessments gained
``assessment_targets`` and that the refactor changed by accident:

- a variant-scoped export must not disclose another variant's targets;
- a version-2 export must stay re-importable even when it spans variants;
- ``GET /api/assessments`` must not hide a multi-target assessment's coverage;
- the pending-AI duplicate guard must fire for every covered variant.
"""

import json
import os
import uuid
from contextlib import nullcontext
from datetime import datetime, timezone

import pytest

from src.bin.webapp import create_app
from src.extensions import db
from . import write_demo_files, setup_demo_db

PROJECT_UUID = uuid.UUID("11111111-1111-1111-1111-111111111111")
VARIANT_A = uuid.UUID("22222222-2222-2222-2222-222222222222")
SCAN_A = uuid.UUID("33333333-3333-3333-3333-333333333333")
VARIANT_B = uuid.UUID("55555555-5555-5555-5555-555555555555")
SCAN_B = uuid.UUID("66666666-6666-6666-6666-666666666666")

VULN_ID = "CVE-2020-35492"
PKG_A = "cairo@1.16.0"
PKG_B = "abc@1.2.3"


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
    """App with two variants of one project, each observing its own package.

    Variant A observes ``cairo``, variant B observes ``abc``; both for the same
    CVE, which is what lets one assessment legitimately target both.
    """
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": init_files["status"],
            "OPENVEX_FILE": str(init_files["openvex"]),
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db",
        })
        setup_demo_db(application, extra_packages=[PKG_B])
        with application.app_context():
            from src.models.finding import Finding
            from src.models.observation import Observation
            from src.models.package import Package
            from src.models.scan import Scan
            from src.models.variant import Variant

            db.session.add(Variant(id=VARIANT_B, name="second", project_id=PROJECT_UUID))
            db.session.add(Scan(id=SCAN_B, variant_id=VARIANT_B))
            db.session.commit()

            package_b = Package.get_by_string_id(PKG_B)
            assert package_b is not None
            finding_b = Finding.get_or_create(package_b.id, VULN_ID)
            Observation.create(finding_b.id, SCAN_B, commit=False)
            db.session.commit()
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


def _finding_id(package_string_id):
    from src.models.finding import Finding
    from src.models.package import Package

    package = Package.get_by_string_id(package_string_id)
    assert package is not None
    finding = Finding.get_by_package_and_vulnerability(package_string_id, VULN_ID)
    if finding is None:
        finding = Finding.get_or_create(package.id, VULN_ID)
    return finding.id


def _make_cross_variant_assessment(origin="custom", status="fixed"):
    """One assessment covering (variant A, cairo) and (variant B, abc)."""
    from src.models.assessment import Assessment as DBAssessment

    return DBAssessment.create(
        status=status,
        origin=origin,
        simplified_status="Fixed",
        timestamp=datetime(2024, 6, 8, 12, 0, 0, tzinfo=timezone.utc),
        targets=[
            (VARIANT_A, _finding_id(PKG_A)),
            (VARIANT_B, _finding_id(PKG_B)),
        ],
    )


# ── R3: a variant-scoped export must not leak other variants ──────────────

def test_scoped_export_excludes_out_of_scope_targets(app):
    from src.helpers.assessment_io import build_custom_data_export

    with app.app_context():
        _make_cross_variant_assessment()
        exported = build_custom_data_export([VARIANT_A])

    assert len(exported["assessments"]) == 1
    record = exported["assessments"][0]
    assert record["targets"] == [{"variant": "default", "package": PKG_A}]
    assert [t["package"] for t in record["targets"]] == [PKG_A]
    assert record["packages"] == [PKG_A]
    assert "variant_id" not in record
    assert "variant" not in record


def test_scoped_export_of_the_other_variant_is_symmetric(app):
    from src.helpers.assessment_io import build_custom_data_export

    with app.app_context():
        _make_cross_variant_assessment()
        exported = build_custom_data_export([VARIANT_B])

    record = exported["assessments"][0]
    assert record["targets"] == [{"variant": "second", "package": PKG_B}]
    assert record["packages"] == [PKG_B]
    assert "variant_id" not in record
    assert "variant" not in record


def test_unscoped_export_keeps_every_target(app):
    """A full backup stays lossless: only the *scoped* export is truncated."""
    from src.helpers.assessment_io import build_custom_data_export

    with app.app_context():
        _make_cross_variant_assessment()
        exported = build_custom_data_export(None)

    record = exported["assessments"][0]
    assert {t["variant"] for t in record["targets"]} == {"default", "second"}
    assert sorted(record["packages"]) == sorted([PKG_A, PKG_B])
    assert "variant_id" not in record
    assert "variant" not in record


# ── R4: VulnScout must accept its own version-2 export ────────────────────

def test_detect_format_accepts_v2_export_spanning_variants(app):
    from src.helpers.assessment_io import (
        build_custom_data_export,
        detect_review_export_format,
    )

    with app.app_context():
        _make_cross_variant_assessment()
        exported = build_custom_data_export(None)

    assert "variant_id" not in exported["assessments"][0]
    # Round-trip through JSON: this is what export-update/import receive.
    assert detect_review_export_format(json.loads(json.dumps(exported))) == "custom"


def test_detect_format_still_rejects_v1_record_without_variant(app):
    from src.helpers.assessment_io import detect_review_export_format

    doc = {
        "version": 1,
        "assessments": [{"variant_id": None, "vuln_id": VULN_ID, "packages": []}],
        "ai_assessments": [], "cvss": [], "time_estimates": [],
    }
    with pytest.raises(ValueError):
        detect_review_export_format(doc)


def test_detect_format_rejects_future_custom_data_version(app):
    from src.helpers.assessment_io import detect_review_export_format

    with pytest.raises(ValueError, match=r"version: 3.*1, 2"):
        detect_review_export_format({"version": 3, "assessments": []})


def test_detect_format_rejects_v2_record_with_unusable_targets(app):
    from src.helpers.assessment_io import detect_review_export_format

    doc = {
        "version": 2,
        # A target that names no variant at all cannot be resolved on import.
        "assessments": [{
            "variant_id": None, "vuln_id": VULN_ID, "packages": [],
            "targets": [{"package": PKG_A}],
        }],
        "ai_assessments": [], "cvss": [], "time_estimates": [],
    }
    with pytest.raises(ValueError):
        detect_review_export_format(doc)


def test_scoped_export_round_trips_through_import(app):
    """The scoped export must remain importable, restoring only its targets."""
    from src.helpers.assessment_io import (
        build_custom_data_export,
        build_variant_by_name_map,
        detect_review_export_format,
        import_custom_data,
    )
    from src.models.assessment import Assessment as DBAssessment

    with app.app_context():
        _make_cross_variant_assessment()
        exported = json.loads(json.dumps(build_custom_data_export([VARIANT_A])))
        assert detect_review_export_format(exported) == "custom"

        for assessment in DBAssessment.get_by_vulnerability(VULN_ID):
            if assessment.origin == "custom":
                assessment.delete()

        result = import_custom_data(
            exported,
            build_variant_by_name_map(PROJECT_UUID),
            use_original_timestamps=True,
        )
        assert not result["errors"], result["errors"]

        restored = [
            a for a in DBAssessment.get_by_vulnerability(VULN_ID)
            if a.origin == "custom"
        ]
        assert len(restored) == 1
        assert {t.variant_id for t in restored[0].target_rows} == {VARIANT_A}


# ── R5: the list endpoint must report the whole target set ────────────────

def test_list_endpoint_reports_every_target(client, app):
    with app.app_context():
        assessment_id = str(_make_cross_variant_assessment().id)

    listed = json.loads(client.get("/api/assessments?format=list").data)
    record = next(a for a in listed if a["id"] == assessment_id)

    assert sorted(record["packages"]) == sorted([PKG_A, PKG_B])
    assert record["variant_ids"] == sorted([str(VARIANT_A), str(VARIANT_B)])
    # No single variant covers it, matching Assessment.to_dict's semantics.
    assert record["variant_id"] is None


def test_list_endpoint_scoped_to_variant_reports_only_that_variant(client, app):
    with app.app_context():
        assessment_id = str(_make_cross_variant_assessment().id)

    listed = json.loads(client.get(f"/api/assessments?format=list&variant_id={VARIANT_A}").data)
    record = next(a for a in listed if a["id"] == assessment_id)

    assert record["packages"] == [PKG_A]
    assert record["variant_ids"] == [str(VARIANT_A)]
    assert record["variant_id"] == str(VARIANT_A)


def test_list_endpoint_emits_one_record_per_assessment(client, app):
    """Folding targets back together must not duplicate the assessment."""
    with app.app_context():
        assessment_id = str(_make_cross_variant_assessment().id)

    listed = json.loads(client.get("/api/assessments?format=list").data)
    assert [a["id"] for a in listed].count(assessment_id) == 1

    keyed = json.loads(client.get("/api/assessments?format=dict").data)
    assert sorted(keyed[assessment_id]["packages"]) == sorted([PKG_A, PKG_B])


# ── R2: the pending-AI guard must cover every targeted variant ────────────

def test_covers_variant_matches_each_target(app):
    with app.app_context():
        assessment = _make_cross_variant_assessment()
        assert assessment.covers_variant(VARIANT_A)
        assert assessment.covers_variant(VARIANT_B)
        assert not assessment.covers_variant(uuid.uuid4())
        assert not assessment.covers_variant(None)
        # single_variant_id collapses to None here -- the bug this replaces.
        assert assessment.single_variant_id is None


def test_covers_variant_treats_empty_target_set_as_unscoped(app):
    """The legacy record seeded with no targets keeps its old NULL semantics."""
    from src.models.assessment import Assessment as DBAssessment

    with app.app_context():
        legacy = DBAssessment.get_by_id("da4d18f0-d89e-4d54-819d-86fc884cc737")
        assert legacy is not None
        assert legacy.target_rows == []
        assert legacy.covers_variant(None)
        assert not legacy.covers_variant(VARIANT_A)


def _ai_rows(app):
    from src.models.assessment import Assessment as DBAssessment

    with app.app_context():
        return {
            str(a.id): sorted(str(t.variant_id) for t in a.target_rows)
            for a in DBAssessment.get_by_vulnerability(VULN_ID)
            if a.origin == "ai"
        }


def test_new_ai_write_trims_only_the_overlapping_variant(client, app):
    """A pending AI row spans A and B; a new AI write for A takes A away from
    it but leaves B's pending suggestion alone."""
    with app.app_context():
        old_id = str(_make_cross_variant_assessment(
            origin="ai", status="under_investigation").id)

    response = client.post(
        f"/api/vulnerabilities/{VULN_ID}/assessments",
        json={
            "packages": [PKG_A],
            "status": "affected",
            "variant_id": str(VARIANT_A),
            "ai_generated": True,
        },
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["replaced"] == [
        {"id": old_id, "action": "trimmed", "variant_ids": [str(VARIANT_A)]}]

    rows = _ai_rows(app)
    assert rows[old_id] == [str(VARIANT_B)]
    assert rows[body["assessment"]["id"]] == [str(VARIANT_A)]


def test_new_ai_write_covering_every_target_deletes_the_old_row(client, app):
    with app.app_context():
        old_id = str(_make_cross_variant_assessment(
            origin="ai", status="under_investigation").id)

    response = client.post(
        f"/api/vulnerabilities/{VULN_ID}/assessments",
        json={
            "packages": [PKG_A, PKG_B],
            "status": "affected",
            "variant_ids": [str(VARIANT_A), str(VARIANT_B)],
            "ai_generated": True,
        },
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["replaced"] == [{
        "id": old_id, "action": "deleted",
        "variant_ids": sorted([str(VARIANT_A), str(VARIANT_B)]),
    }]
    assert list(_ai_rows(app)) == [body["assessment"]["id"]]


def test_to_dict_carries_the_exact_target_pairs(app):
    """packages x variant_ids is a cross-product, and a sparse assessment is
    not: without the pairs a consumer cannot tell (A, cairo)+(B, abc) apart
    from an assessment that also covers (A, abc) and (B, cairo)."""
    with app.app_context():
        assessment = _make_cross_variant_assessment()

        serialized = assessment.to_dict()

    assert serialized["targets"] == [
        {"variant_id": str(VARIANT_A), "package": PKG_A},
        {"variant_id": str(VARIANT_B), "package": PKG_B},
    ]


def test_batch_keeps_exact_target_pairs_when_another_pair_was_observed(app, client):
    from src.models.observation import Observation

    with app.app_context():
        Observation.create(_finding_id(PKG_A), SCAN_B)

    targets = [
        {"variant_id": str(VARIANT_A), "package": PKG_A},
        {"variant_id": str(VARIANT_B), "package": PKG_B},
    ]
    item = {"vuln_id": VULN_ID, "status": "fixed", "targets": targets}
    invalid_item = {**item, "targets": [*targets, {"variant_id": str(VARIANT_A), "package": PKG_B}]}
    response = client.post("/api/assessments/batch", json={"assessments": [item, invalid_item]})
    assert response.status_code == 400

    response = client.post("/api/assessments/batch", json={"assessments": [item]})
    assert response.status_code == 200
    [assessment] = response.get_json()["assessments"]
    assert assessment["targets"] == targets


@pytest.mark.parametrize("include_outdated", ["false", "true"])
def test_advertised_current_targets_are_exact_and_writable(app, client, include_outdated):
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.models.scan import Scan
    from src.models.vulnerability import Vulnerability

    vuln_id = "CVE-2099-12345"
    with app.app_context():
        Vulnerability.create_record(id=vuln_id, description="Synthetic supplier attribution")
        exact = Package.find_or_create("synthetic-lib", "1")
        alias = Package.find_or_create("synthetic-lib", "1", supplier="Supplier")
        sbom = SBOMDocument(path="/synthetic/sbom.json", source_name="sbom.json", format="spdx", scan_id=SCAN_A)
        old_tool = Scan(variant_id=VARIANT_A, scan_type="tool", scan_source="grype",
                        timestamp=datetime(2020, 1, 1, tzinfo=timezone.utc))
        tool = Scan(variant_id=VARIANT_A, scan_type="tool", scan_source="grype")
        db.session.add_all([sbom, old_tool, tool])
        db.session.flush()
        tool_doc = SBOMDocument(path="/synthetic/tool.json", source_name="tool.json", format="grype", scan_id=tool.id)
        db.session.add(tool_doc)
        db.session.flush()
        db.session.add_all([
            SBOMPackage(sbom_document_id=sbom.id, package_id=exact.id),
            SBOMPackage(sbom_document_id=sbom.id, package_id=alias.id),
            SBOMPackage(sbom_document_id=tool_doc.id, package_id=alias.id),
        ])
        finding = Finding.get_or_create(exact.id, vuln_id)
        Observation.create(finding.id, tool.id, commit=False)
        db.session.commit()
        alias_id, old_tool_id = alias.id, old_tool.id

    rows = client.get(f"/api/vulnerabilities?variant_id={VARIANT_A}&include_outdated={include_outdated}").get_json()
    row = next(item for item in rows if item["id"] == vuln_id)
    assert row["packages_current"] == ["synthetic-lib@1", "synthetic-lib@1::Supplier"]
    advertised = row["assessment_targets_by_variant"]
    assert advertised == {str(VARIANT_A): ["synthetic-lib@1"]}
    targets = [
        {"variant_id": variant_id, "package": package}
        for variant_id, packages in advertised.items() for package in packages
    ]
    payload = {"current_only": True, "assessments": [{"vuln_id": vuln_id, "status": "fixed", "targets": targets}]}
    result = client.post("/api/assessments/batch", json=payload)
    assert result.status_code == 200
    assert result.get_json()["assessments"][0]["targets"] == targets

    with app.app_context():
        old_finding = Finding.get_or_create(alias_id, vuln_id)
        Observation.create(old_finding.id, old_tool_id)
    payload["assessments"][0]["targets"] = [{"variant_id": str(VARIANT_A), "package": "synthetic-lib@1::Supplier"}]
    rejected = client.post("/api/assessments/batch", json=payload)
    assert rejected.status_code == 400
    assert "no longer current" in rejected.get_json()["errors"][0]["error"]


def test_current_only_batch_rejects_stale_targets_atomically_but_preserves_legacy_writes(app, client):
    from src.models.assessment import Assessment
    from src.models.scan import Scan

    def assessment_ids():
        with app.app_context():
            return {assessment.id for assessment in Assessment.get_by_vulnerability(VULN_ID)}

    with app.app_context():
        tool_scan = Scan.get_by_id(SCAN_B)
        assert tool_scan is not None
        tool_scan.scan_type = "tool"
        tool_scan.scan_source = "osv"
        db.session.commit()

    items = [
        {"vuln_id": VULN_ID, "status": "fixed", "targets": [{"variant_id": str(variant_id), "package": package}]}
        for variant_id, package in ((VARIANT_B, PKG_B), (VARIANT_A, PKG_A))
    ]
    endpoint = "/api/assessments/batch"
    assert client.post(endpoint, json={"current_only": True, "assessments": items}).status_code == 200

    with app.app_context():
        Scan.create("New SBOM without the old package", VARIANT_A)

    before = assessment_ids()
    response = client.post(endpoint, json={"current_only": True, "assessments": items})
    assert response.status_code == 400
    assert response.get_json()["count"] == 0
    assert [error["error"] for error in response.get_json()["errors"]] == [
        f"Package targets are no longer current: {PKG_A} in {VARIANT_A}",
    ]
    assert assessment_ids() == before

    assert client.post(endpoint, json={"assessments": items}).status_code == 200
    legacy_item = {"vuln_id": VULN_ID, "status": "fixed", "packages": [PKG_A], "variant_id": str(VARIANT_A)}
    assert client.post(endpoint, json={"current_only": True, "assessments": [legacy_item]}).status_code == 400
    assert client.post(endpoint, json={"assessments": [legacy_item]}).status_code == 200


@pytest.mark.parametrize("fails", [False, True])
def test_provisional_tool_findings_do_not_replace_current_evidence(app, client, fails):
    from src.helpers.scan_runs import tool_scan
    from src.models import Finding, Observation, Package, Scan, Vulnerability

    next_vuln = "CVE-2099-12346"
    with app.app_context():
        previous = db.session.get(Scan, SCAN_B)
        previous.scan_type = "tool"
        previous.scan_source = "fixture"
        previous.timestamp = datetime(2020, 1, 1, tzinfo=timezone.utc)
        Vulnerability.create_record(id=next_vuln, description="Synthetic pending result")
        package = Package.get_by_string_id(PKG_B)
        finding_id = Finding.get_or_create(package.id, next_vuln).id
        db.session.commit()

    scopes = [f"variant_id={VARIANT_B}", f"project_id={PROJECT_UUID}"]

    def targets(scope, historical=False):
        response = client.get(f"/api/vulnerabilities?{scope}&include_outdated={str(historical).lower()}")
        assert response.status_code == 200
        return {row["id"]: row["assessment_targets_by_variant"].get(str(VARIANT_B), [])
                for row in response.get_json()}

    def submit(vuln_id):
        return client.post("/api/assessments/batch", json={"current_only": True, "assessments": [{
            "vuln_id": vuln_id, "status": "fixed",
            "targets": [{"variant_id": str(VARIANT_B), "package": PKG_B}],
        }]})

    with app.app_context(), (pytest.raises(RuntimeError, match="synthetic failure") if fails else nullcontext()):
        with tool_scan(VARIANT_B, "fixture") as pending:
            Observation.create(finding_id, pending.id)
            for scope in scopes:
                assert targets(scope)[VULN_ID] == [PKG_B]
                assert next_vuln not in targets(scope, historical=True)
            assert submit(VULN_ID).status_code == 200
            rejected = submit(next_vuln)
            assert rejected.status_code == 400
            errors = rejected.get_json()["errors"]
            assert "Invalid package version for vulnerability and variant" in errors[0]["error"]
            if fails:
                raise RuntimeError("synthetic failure")

    for scope in scopes:
        rows = targets(scope)
        assert rows[VULN_ID if fails else next_vuln] == [PKG_B]
        assert not rows.get(next_vuln if fails else VULN_ID)
    assert submit(next_vuln).status_code == (400 if fails else 200)


@pytest.mark.parametrize("fails", [False, True])
def test_editor_and_manual_writes_require_published_variant_targets(app, client, fails):
    from src.helpers.scan_runs import tool_scan
    from src.models import Observation

    def editor_targets():
        response = client.get(f"/api/vulnerabilities/{VULN_ID}/variant-active-packages")
        assert response.status_code == 200
        variant = next(row for row in response.get_json() if row["variant_id"] == str(VARIANT_A))
        return {finding["package"]: finding["outdated"] for finding in variant["findings"]}

    def submit(package):
        return client.post(f"/api/vulnerabilities/{VULN_ID}/assessments", json={
            "status": "fixed", "targets": [{"variant_id": str(VARIANT_A), "package": package}],
        })

    with app.app_context(), (pytest.raises(RuntimeError, match="synthetic failure") if fails else nullcontext()):
        with tool_scan(VARIANT_A, "fixture") as pending:
            Observation.create(_finding_id(PKG_B), pending.id)
            assert editor_targets() == {PKG_A: False}
            assert submit(PKG_B).status_code == 400
            assert submit(PKG_A).status_code == 200
            if fails:
                raise RuntimeError("synthetic failure")

    assert editor_targets() == ({PKG_A: False} if fails else {PKG_A: False, PKG_B: True})
    assert submit(PKG_B).status_code == (400 if fails else 200)


@pytest.mark.parametrize("publication", ["native", "export", "tool"])
def test_postgresql_scan_publication_waits_for_current_only_batch(postgres_app, monkeypatch, publication):
    from concurrent.futures import ThreadPoolExecutor
    from queue import Queue
    from threading import Event
    from time import monotonic, sleep

    from flask import request
    from sqlalchemy import event, text

    from src.helpers.scan_runs import tool_scan
    from src.models.scan import Scan
    from src.routes import assessments, scans

    assessments.init_app(postgres_app)
    scans.init_app(postgres_app)
    setup_demo_db(postgres_app)
    with postgres_app.app_context():
        engine = db.engine
        old_scan = db.session.get(Scan, SCAN_A)
        old_scan.timestamp = datetime(2020, 1, 1, tzinfo=timezone.utc)
        if publication == "tool":
            old_scan.scan_type = "tool"
            old_scan.scan_source = "fixture"
        db.session.commit()

    validated = Event()
    release = Event()
    tool_ready = Event()
    publish_tool = Event()
    tool_finished = Event()
    publisher_pid = Queue()
    find_packages = assessments.finding_packages_for_scans

    def wait_for_tool_publication(_session):
        assert tool_finished.wait(8), "Tool publisher did not finish after the batch committed"

    def pause_after_read(*args, **kwargs):
        targets = find_packages(*args, **kwargs)
        if publication == "tool" and not validated.is_set():
            # The database lock is released, but batch_session has not restored commit yet.
            event.listen(db.session(), "after_commit", wait_for_tool_publication, once=True)
        validated.set()
        assert release.wait(8)
        return targets

    @postgres_app.before_request
    def capture_import_connection():
        if request.path == "/api/scans/import":
            publisher_pid.put(db.session.scalar(text("SELECT pg_backend_pid()")))

    def publish():
        if publication == "export":
            response = postgres_app.test_client().post("/api/scans/import", json={
                "scan_id": str(uuid.uuid4()), "scan_type": "import_sbom",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "project_name": "demo", "variant_name": "default", "packages": [], "findings": [],
            })
            assert response.status_code == 201, response.get_json()
        elif publication == "native":
            with postgres_app.app_context():
                publisher_pid.put(db.session.scalar(text("SELECT pg_backend_pid()")))
                Scan.create("New SBOM without the package", VARIANT_A)
        else:
            try:
                with postgres_app.app_context(), tool_scan(VARIANT_A, "fixture"):
                    publisher_pid.put(db.session.scalar(text("SELECT pg_backend_pid()")))
                    tool_ready.set()
                    assert publish_tool.wait(8)
            finally:
                tool_finished.set()

    payload = {"current_only": True, "assessments": [{
        "vuln_id": VULN_ID, "status": "fixed",
        "targets": [{"variant_id": str(VARIANT_A), "package": PKG_A}],
    }]}
    client = postgres_app.test_client()
    monkeypatch.setattr(assessments, "finding_packages_for_scans", pause_after_read)
    with ThreadPoolExecutor(max_workers=2) as executor:
        publisher = executor.submit(publish) if publication == "tool" else None
        try:
            if publication == "tool":
                assert tool_ready.wait(5)
            batch = executor.submit(client.post, "/api/assessments/batch", json=payload)
            assert validated.wait(5)
            if publisher is None:
                publisher = executor.submit(publish)
            publish_tool.set()
            pid = publisher_pid.get(timeout=5)
            deadline = monotonic() + 5
            with engine.connect() as observer:
                while not observer.scalar(text("SELECT cardinality(pg_blocking_pids(:pid))"), {"pid": pid}):
                    assert not publisher.done(), "Scan published before the validated batch committed"
                    assert monotonic() < deadline, "Publisher did not wait on the variant lock"
                    sleep(0.01)
        finally:
            release.set()
            publish_tool.set()
        assert batch.result().status_code == 200
        publisher.result()

    stale = client.post("/api/assessments/batch", json=payload)
    assert stale.status_code == 400
    assert stale.get_json()["count"] == 0


def test_vulnerability_assessments_endpoint_carries_target_pairs(app, client):
    """This endpoint feeds the vuln modal's per-variant status matrix."""
    with app.app_context():
        assessment_id = str(_make_cross_variant_assessment().id)

    response = client.get(f"/api/vulnerabilities/{VULN_ID}/assessments")

    assert response.status_code == 200
    records = [a for a in response.json if a["id"] == assessment_id]
    assert len(records) == 1
    record = records[0]
    assert {(t["variant_id"], t["package"]) for t in record["targets"]} == {
        (str(VARIANT_A), PKG_A),
        (str(VARIANT_B), PKG_B),
    }


def test_single_assessment_endpoint_carries_target_pairs_with_outdated(app, client):
    """One multi-target assessment stays one record, with per-target staleness."""
    with app.app_context():
        assessment_id = str(_make_cross_variant_assessment().id)

    response = client.get(f"/api/assessments/{assessment_id}")

    assert response.status_code == 200
    data = response.json
    assert data["id"] == assessment_id
    assert {(target["variant_id"], target["package"]) for target in data["targets"]} == {
        (str(VARIANT_A), PKG_A),
        (str(VARIANT_B), PKG_B),
    }
    assert all("outdated" in target for target in data["targets"])


def test_assessments_index_carries_target_pairs(app, client):
    """/api/assessments builds its dicts by hand rather than via to_dict."""
    with app.app_context():
        _make_cross_variant_assessment()

    response = client.get("/api/assessments")

    assert response.status_code == 200
    record = next(a for a in response.json if a["origin"] == "custom")
    assert {(t["variant_id"], t["package"]) for t in record["targets"]} == {
        (str(VARIANT_A), PKG_A),
        (str(VARIANT_B), PKG_B),
    }
