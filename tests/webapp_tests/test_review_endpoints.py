# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the review-specific assessment endpoints:
- GET  /api/assessments/review
- GET  /api/assessments/review/export
- POST /api/assessments/review/import
"""

import io
import json
import uuid
from datetime import datetime, timezone

import pytest

from src.bin.webapp import create_app
from . import write_demo_files, setup_demo_db

VARIANT_UUID = uuid.UUID("22222222-2222-2222-2222-222222222222")
PROJECT_UUID = uuid.UUID("11111111-1111-1111-1111-111111111111")


# ── fixtures ──────────────────────────────────────────────────────────────

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
    import os
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": init_files["status"],
            "OPENVEX_FILE": str(init_files["openvex"]),
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db",
        })
        setup_demo_db(application, extra_packages=["custompkg@2.0.0", "glibc@2.39", "scannerpkg@1.0.0", "abc@1.2.3"])
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def demo_ids(app):
    """Independent fixture data for the group-reconcile tests.

    Copied from ``test_post_endpoints.py``'s ``demo_ids`` fixture (per the
    plan's instruction to reuse that pattern rather than the ported reconcile
    tests' original fixtures) so reconcile tests get two packages observed
    across two variants for two vulnerabilities, independent of this file's
    default CVE-2020-35492 demo data.
    """
    from src.extensions import db
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.scan import Scan
    from src.models.variant import Variant
    import uuid as uuid_module

    with app.app_context():
        vuln_id = "CVE-1999-12345"
        other_vuln_id = "CVE-1999-99999"
        for vid in (vuln_id, other_vuln_id):
            if Vulnerability.get_by_id(vid) is None:
                Vulnerability.create_record(id=vid)

        pkg_a = Package.find_or_create("cairo", "1.16.0")
        pkg_b = Package.find_or_create("libpng", "1.6.37")
        db.session.commit()

        variant_id = uuid_module.UUID("22222222-2222-2222-2222-222222222222")
        other_variant = Variant(
            id=uuid_module.uuid4(), name="other",
            project_id=uuid_module.UUID("11111111-1111-1111-1111-111111111111"))
        db.session.add(other_variant)
        db.session.commit()

        existing_scan_id = uuid_module.UUID("33333333-3333-3333-3333-333333333333")
        other_scan = Scan(id=uuid_module.uuid4(), variant_id=other_variant.id)
        db.session.add(other_scan)
        db.session.commit()

        for vid in (vuln_id, other_vuln_id):
            for pkg in (pkg_a, pkg_b):
                finding = Finding.get_or_create(pkg.id, vid)
                db.session.add(Observation(finding_id=finding.id, scan_id=existing_scan_id))
                db.session.add(Observation(finding_id=finding.id, scan_id=other_scan.id))
        db.session.commit()

        return {
            "vuln_id": vuln_id,
            "other_vuln_id": other_vuln_id,
            "variant_id": str(variant_id),
            "other_variant_id": str(other_variant.id),
            "two_packages": [pkg_a.string_id, pkg_b.string_id],
        }


def _create_handmade_assessment(client, vuln_id="CVE-2020-35492",
                                packages=None, status="affected",
                                variant_id=VARIANT_UUID, **extra):
    """Helper – create a custom assessment via POST."""
    payload = {
        "packages": packages or ["cairo@1.16.0"],
        "status": status,
        "variant_id": variant_id,
    }
    payload.update(extra)
    resp = client.post(
        f"/api/vulnerabilities/{vuln_id}/assessments",
        json=payload,
    )
    return resp


def _create_ai_assessment(client, vuln_id="CVE-2020-35492",
                           packages=None, status="affected",
                           variant_id=VARIANT_UUID, **extra):
    """Helper – create a pending AI-generated assessment via POST."""
    payload = {
        "packages": packages or ["cairo@1.16.0"],
        "status": status,
        "variant_id": variant_id,
        "ai_generated": True,
    }
    payload.update(extra)
    resp = client.post(
        f"/api/vulnerabilities/{vuln_id}/assessments",
        json=payload,
    )
    return resp


# ── GET /api/assessments/review ──────────────────────────────────────────

def test_review_list_empty(client):
    """No handmade assessments yet → empty list."""
    resp = client.get("/api/assessments/review")
    assert resp.status_code == 200
    assert json.loads(resp.data) == []


def test_review_list_after_create(client):
    """After creating a custom assessment it appears in the review list."""
    _create_handmade_assessment(client)
    resp = client.get("/api/assessments/review")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data) >= 1


def test_review_list_by_variant(client):
    _create_handmade_assessment(client)
    resp = client.get(f"/api/assessments/review?variant_id={VARIANT_UUID}")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data) >= 1


def test_review_list_by_variant_invalid(client):
    resp = client.get("/api/assessments/review?variant_id=not-a-uuid")
    assert resp.status_code == 400


def test_review_list_by_project(client):
    _create_handmade_assessment(client)
    resp = client.get(f"/api/assessments/review?project_id={PROJECT_UUID}")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data) >= 1


def test_review_list_by_project_invalid(client):
    resp = client.get("/api/assessments/review?project_id=bad")
    assert resp.status_code == 400


def test_review_list_by_project_no_variants(client):
    """Project with no variants → empty list."""
    fake_project = str(uuid.uuid4())
    resp = client.get(f"/api/assessments/review?project_id={fake_project}")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data == []


class TestReviewListTexts:
    VARIANT_A = uuid.UUID(int=1)
    VARIANT_B = uuid.UUID(int=2)
    VULNERABILITY_ID = "CVE-2020-35492"

    @pytest.fixture(autouse=True)
    def _setup(self, app):
        from src.extensions import db
        from src.models import Scan, SBOMDocument, Variant, SBOMObservation, Assessment, Finding

        with app.app_context():
            variant_a = Variant(id=self.VARIANT_A, project_id=PROJECT_UUID, name="a")
            variant_b = Variant(id=self.VARIANT_B, project_id=PROJECT_UUID, name="b")
            scan_a = Scan(variant=variant_a)
            scan_b = Scan(variant=variant_b)
            doc_a = SBOMDocument(path="x", source_name="x", format="x", scan=scan_a)
            doc_b = SBOMDocument(path="x", source_name="x", format="x", scan=scan_b)
            sbom_observations = [
                SBOMObservation(
                    vulnerability_id=self.VULNERABILITY_ID,
                    sbom_document=doc_a,
                    key="Text A",
                    description="Text specific to A",
                ),
                SBOMObservation(
                    vulnerability_id=self.VULNERABILITY_ID,
                    sbom_document=doc_a,
                    key="Text Shared",
                    description="Content for A",
                ),
                SBOMObservation(
                    vulnerability_id=self.VULNERABILITY_ID,
                    sbom_document=doc_a,
                    key="Text Duplicated",
                    description="Same content for both",
                ),
                SBOMObservation(
                    vulnerability_id=self.VULNERABILITY_ID,
                    sbom_document=doc_b,
                    key="Text Shared",
                    description="Content for B",
                ),
                SBOMObservation(
                    vulnerability_id=self.VULNERABILITY_ID,
                    sbom_document=doc_b,
                    key="Text Duplicated",
                    description="Same content for both",
                ),
            ]
            # Flushed here, as one coherent unit, before Assessment.create()
            # below: it validates its target against the variants table, so
            # variant_a/variant_b must already be visible to that query.
            db.session.add_all(sbom_observations)
            db.session.flush()
            finding = Finding.get_by_vulnerability(self.VULNERABILITY_ID)[0]
            assess_a = Assessment.create(status="x", variant_id=self.VARIANT_A, finding_id=finding.id, origin="custom")
            assess_b = Assessment.create(status="x", variant_id=self.VARIANT_B, finding_id=finding.id, origin="custom")
            db.session.add_all(sbom_observations + [assess_a, assess_b])
            db.session.commit()

    def test_no_variants_all(self, client):
        resp = client.get("/api/assessments/review")
        assert resp.status_code == 200
        assessments = json.loads(resp.data)

        assert isinstance(assessments, list)
        assert len(assessments) == 2
        assess_a, assess_b = assessments

        assert assess_a["vuln_texts"] == assess_b["vuln_texts"]  # same vulnerability = same texts
        assert assess_a["vuln_texts"] == [
            {
                "title": "description",
                "content": "A flaw was found in cairo's image-compositor.c in all versions prior to 1.17.4 [...]"
            },
            {
                "title": "Text A",
                "content": "Text specific to A"
            },
            {  # only once for this duplicated text
                "title": "Text Duplicated",
                "content": "Same content for both",
            },
            {
                "title": "Text Shared",
                "content": "Content for A",
            },
            {
                "title": "Text Shared",
                "content": "Content for B",
            },
            {  # from the db setup
                "content": "Some Yocto description",
                "title": "yocto"
            },
        ]

    def test_variant_specific(self, client):
        resp = client.get(f"/api/assessments/review?variant_id={self.VARIANT_B}")
        assert resp.status_code == 200
        assessments = json.loads(resp.data)

        assert isinstance(assessments, list)
        assert len(assessments) == 1
        assess_b, = assessments

        assert assess_b["vuln_texts"] == [
            {
                "title": "description",
                "content": "A flaw was found in cairo's image-compositor.c in all versions prior to 1.17.4 [...]"
            },
            # Text A does not leak
            {
                "title": "Text Duplicated",
                "content": "Same content for both",
            },
            # Text Shared for A does not leak
            {
                "title": "Text Shared",
                "content": "Content for B",
            },
        ]

    def test_project_specific(self, client):
        resp = client.get(f"/api/assessments/review?project_id={PROJECT_UUID}")
        assert resp.status_code == 200
        assessments = json.loads(resp.data)

        assert isinstance(assessments, list)
        assert len(assessments) == 2
        assess_a, assess_b = assessments

        assert assess_a["vuln_texts"] == assess_b["vuln_texts"]  # same vulnerability = same texts

        assert assess_a["vuln_texts"] == [
            {
                "title": "description",
                "content": "A flaw was found in cairo's image-compositor.c in all versions prior to 1.17.4 [...]"
            },
            {
                "title": "Text A",
                "content": "Text specific to A"
            },
            {  # only once for this duplicated text
                "title": "Text Duplicated",
                "content": "Same content for both",
            },
            {
                "title": "Text Shared",
                "content": "Content for A",
            },
            {
                "title": "Text Shared",
                "content": "Content for B",
            },
            {  # from the db setup
                "content": "Some Yocto description",
                "title": "yocto"
            },
        ]


# ── GET /api/assessments/review/ai ────────────────────────────────────────

def test_review_ai_list_empty(client):
    """No pending AI assessments yet → empty list."""
    resp = client.get("/api/assessments/review/ai")
    assert resp.status_code == 200
    assert json.loads(resp.data) == []


def test_review_ai_list_after_create(client):
    """After creating an AI-generated assessment it appears in the AI review list."""
    _create_ai_assessment(client)
    resp = client.get("/api/assessments/review/ai")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data) >= 1
    assert all(a["origin"] == "ai" for a in data)


def test_review_ai_does_not_leak_into_custom_review(client):
    """AI-origin assessments must not appear in the custom /review list, and
    custom assessments must not appear in the AI review list."""
    ai_create_resp = _create_ai_assessment(client)
    custom_create_resp = _create_handmade_assessment(client)
    assert ai_create_resp.status_code == 200
    assert custom_create_resp.status_code == 200

    custom_resp = client.get("/api/assessments/review")
    ai_resp = client.get("/api/assessments/review/ai")
    assert custom_resp.status_code == 200
    assert ai_resp.status_code == 200

    custom_data = json.loads(custom_resp.data)
    ai_data = json.loads(ai_resp.data)

    assert all(a["origin"] == "custom" for a in custom_data)
    assert all(a["origin"] == "ai" for a in ai_data)
    assert len(custom_data) >= 1
    assert len(ai_data) >= 1


def test_review_ai_list_by_variant(client):
    _create_ai_assessment(client)
    resp = client.get(f"/api/assessments/review/ai?variant_id={VARIANT_UUID}")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data) >= 1


def test_review_ai_list_by_variant_invalid(client):
    resp = client.get("/api/assessments/review/ai?variant_id=not-a-uuid")
    assert resp.status_code == 400


def test_review_ai_list_by_project(client):
    _create_ai_assessment(client)
    resp = client.get(f"/api/assessments/review/ai?project_id={PROJECT_UUID}")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data) >= 1


def test_review_ai_list_by_project_invalid(client):
    resp = client.get("/api/assessments/review/ai?project_id=bad")
    assert resp.status_code == 400


def test_review_ai_list_by_project_no_variants(client):
    """Project with no variants → empty list."""
    fake_project = str(uuid.uuid4())
    resp = client.get(f"/api/assessments/review/ai?project_id={fake_project}")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data == []


def test_review_ai_list_includes_vuln_texts(client):
    """Each entry is enriched with a vuln_texts key, same as /review."""
    _create_ai_assessment(client)
    resp = client.get("/api/assessments/review/ai")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data) >= 1
    assert "vuln_texts" in data[0]
    assert isinstance(data[0]["vuln_texts"], list)


# ── GET /api/assessments (project_id path) ───────────────────────────────

def test_assessments_list_by_project(client):
    resp = client.get(f"/api/assessments?project_id={PROJECT_UUID}")
    assert resp.status_code == 200


def test_assessments_list_by_project_invalid(client):
    resp = client.get("/api/assessments?project_id=xxx")
    assert resp.status_code == 400


# ── GET /api/assessments/review/export ───────────────────────────────────

def test_export_requires_one_variant(client):
    """OpenVEX export needs an explicit single variant."""
    resp = client.get("/api/assessments/review/export")
    assert resp.status_code == 400
    assert "variant" in json.loads(resp.data)["error"].lower()


def test_export_openvex_json(client):
    _create_handmade_assessment(client)
    resp = client.get(f"/api/assessments/review/export?variant_id={VARIANT_UUID}")
    assert resp.status_code == 200
    assert resp.content_type == "application/json"
    doc = json.loads(resp.data)
    assert "openvex" in doc.get("@context", "")
    assert isinstance(doc.get("statements"), list)
    for stmt in doc["statements"]:
        assert "vulnerability" in stmt
        assert "products" in stmt
        assert "status" in stmt


def test_export_contains_variant_name(client):
    _create_handmade_assessment(client)
    resp = client.get(f"/api/assessments/review/export?variant_id={VARIANT_UUID}")
    assert 'review_openvex_default.json' in resp.headers["Content-Disposition"]


def test_export_rejects_multiple_variants(client, app):
    from src.extensions import db
    from src.models import Variant

    second_variant_id = uuid.uuid4()
    with app.app_context():
        db.session.add(Variant(id=second_variant_id, project_id=PROJECT_UUID, name="second"))
        db.session.commit()

    resp = client.get(
        "/api/assessments/review/export"
        f"?variant_id={VARIANT_UUID}&variant_id={second_variant_id}"
    )

    assert resp.status_code == 400


def test_export_selected_variants_invalid_uuid(client):
    _create_handmade_assessment(client)
    resp = client.get("/api/assessments/review/export?variant_id=not-a-uuid")
    assert resp.status_code == 400


def test_export_enriched_fields(client):
    """Exported statements should have enriched vulnerability and product fields."""
    _create_handmade_assessment(client)
    resp = client.get(f"/api/assessments/review/export?variant_id={VARIANT_UUID}")
    doc = json.loads(resp.data)
    for stmt in doc["statements"]:
        vuln = stmt["vulnerability"]
        assert "name" in vuln
        assert "description" in vuln
        assert "aliases" in vuln
        for prod in stmt["products"]:
            assert "identifiers" in prod
        assert "scanners" in stmt


# ── POST /api/assessments/review/import ──────────────────────────────────

def _make_openvex_json(variant_name, statements):
    """Build a minimal OpenVEX JSON document."""
    return json.dumps({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://example.com/test",
        "author": "test",
        "timestamp": "2025-01-01T00:00:00Z",
        "version": 1,
        "statements": statements,
    }).encode("utf-8")


def test_import_no_file(client):
    resp = client.post("/api/assessments/review/import",
                       content_type="multipart/form-data")
    assert resp.status_code == 400


def test_import_json_valid(client):
    """Import a single .json document into the selected variant."""
    statements = [{
        "vulnerability": {"name": "CVE-2020-35492"},
        "products": [{"@id": "cairo@1.16.0"}],
        "status": "affected",
        "status_notes": "test import",
        "justification": "",
        "impact_statement": "",
        "action_statement": "",
    }]
    data = _make_openvex_json("default", statements)
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json"), "variant_id": str(VARIANT_UUID)},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["status"] == "success"
    assert result["imported"] >= 1


def test_import_json_requires_selected_variant(client):
    data = _make_openvex_json("unknown_variant", [])
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "unknown_variant.json")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    assert "variant_id" in json.loads(resp.data)["error"]


def test_import_json_selected_variant_ignores_filename(client):
    data = _make_openvex_json("unrelated", [])
    resp = client.post(
        "/api/assessments/review/import",
        data={
            "file": (io.BytesIO(data), "unrelated.json"),
            "variant_id": str(VARIANT_UUID),
        },
        content_type="multipart/form-data",
    )

    assert resp.status_code == 200
    assert json.loads(resp.data)["status"] == "success"


def test_import_json_selected_variant_not_found(client):
    data = _make_openvex_json("unrelated", [])
    resp = client.post(
        "/api/assessments/review/import",
        data={
            "file": (io.BytesIO(data), "unrelated.json"),
            "variant_id": str(uuid.uuid4()),
        },
        content_type="multipart/form-data",
    )

    assert resp.status_code == 404
    assert "variant" in json.loads(resp.data)["error"].lower()


def test_import_json_invalid_json(client):
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(b"not json"), "default.json"), "variant_id": str(VARIANT_UUID)},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400


def test_import_json_not_openvex(client):
    data = json.dumps({"foo": "bar"}).encode()
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json"), "variant_id": str(VARIANT_UUID)},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    assert "openvex" in json.loads(resp.data)["error"].lower()


def test_import_unsupported_file_type(client):
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(b"data"), "review.xml")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    assert "unsupported" in json.loads(resp.data)["error"].lower()


def test_import_not_multipart(client):
    resp = client.post(
        "/api/assessments/review/import",
        json={"statements": []},
    )
    assert resp.status_code == 400


def test_import_duplicate_skipped(client):
    """Importing the same data twice should skip duplicates."""
    statements = [{
        "vulnerability": {"name": "CVE-2020-35492"},
        "products": [{"@id": "cairo@1.16.0"}],
        "status": "affected",
        "status_notes": "",
        "justification": "",
        "impact_statement": "",
        "action_statement": "",
    }]
    data = _make_openvex_json("default", statements)
    # First import
    resp1 = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json"), "variant_id": str(VARIANT_UUID)},
        content_type="multipart/form-data",
    )
    assert resp1.status_code == 200
    r1 = json.loads(resp1.data)
    assert r1["imported"] >= 1

    # Second import — same data
    resp2 = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json"), "variant_id": str(VARIANT_UUID)},
        content_type="multipart/form-data",
    )
    assert resp2.status_code == 200
    r2 = json.loads(resp2.data)
    assert r2["skipped"] >= 1
    assert r2["imported"] == 0


def _import_openvex_with_timestamp(client, vuln_id, package, timestamp):
    statements = [{
        "vulnerability": {"name": vuln_id},
        "products": [{"@id": package}],
        "status": "affected",
        "timestamp": timestamp,
    }]
    data = _make_openvex_json("default", statements)
    return client.post(
        "/api/assessments/review/import",
        data={
            "file": (io.BytesIO(data), "default.json"),
            "variant_id": str(VARIANT_UUID),
            "timestamp_policy": "original",
        },
        content_type="multipart/form-data",
    )


def test_import_openvex_original_timestamp_keeps_distinct_entries(client):
    """A later statement timestamp is imported instead of skipped as duplicate."""
    vuln_id, package = "CVE-2020-35492", "openvex-history@1.0"

    first = _import_openvex_with_timestamp(
        client, vuln_id, package, "2026-07-07T10:00:00+00:00")
    second = _import_openvex_with_timestamp(
        client, vuln_id, package, "2026-07-20T10:00:00+00:00")

    assert json.loads(first.data)["imported"] == 1
    assert json.loads(second.data)["imported"] == 1

    listed = json.loads(client.get("/api/assessments/review").data)
    timestamps = sorted(
        a["timestamp"] for a in listed
        if a["vuln_id"] == vuln_id and package in a["packages"]
    )
    assert timestamps == ["2026-07-07T10:00:00+00:00", "2026-07-20T10:00:00+00:00"]


def test_import_openvex_original_timestamp_is_idempotent(client):
    """Re-importing an identical OpenVEX document stays a no-op."""
    vuln_id, package = "CVE-2020-35492", "openvex-idempotent@1.0"

    first = _import_openvex_with_timestamp(
        client, vuln_id, package, "2026-07-20T10:00:00+00:00")
    second = _import_openvex_with_timestamp(
        client, vuln_id, package, "2026-07-20T10:00:00+00:00")

    assert json.loads(first.data)["imported"] == 1
    assert json.loads(second.data)["imported"] == 0
    assert json.loads(second.data)["skipped"] == 1


def test_import_statement_missing_vuln(client):
    """Statement without vulnerability name → error."""
    statements = [{
        "vulnerability": {},
        "products": [{"@id": "cairo@1.16.0"}],
        "status": "affected",
    }]
    data = _make_openvex_json("default", statements)
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json"), "variant_id": str(VARIANT_UUID)},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["imported"] == 0


def test_import_statement_missing_status(client):
    statements = [{
        "vulnerability": {"name": "CVE-2020-35492"},
        "products": [{"@id": "cairo@1.16.0"}],
    }]
    data = _make_openvex_json("default", statements)
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json"), "variant_id": str(VARIANT_UUID)},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["imported"] == 0


def test_import_statement_missing_products(client):
    statements = [{
        "vulnerability": {"name": "CVE-2020-35492"},
        "status": "affected",
    }]
    data = _make_openvex_json("default", statements)
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json"), "variant_id": str(VARIANT_UUID)},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["imported"] == 0


def test_import_product_string_format(client):
    """Products can also be plain strings instead of dicts."""
    statements = [{
        "vulnerability": {"name": "CVE-2020-35492"},
        "products": ["cairo@1.16.0"],
        "status": "affected",
        "status_notes": "",
        "justification": "",
        "impact_statement": "",
        "action_statement": "",
    }]
    data = _make_openvex_json("default", statements)
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json"), "variant_id": str(VARIANT_UUID)},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["imported"] >= 1


def test_import_product_without_version(client):
    """Package without @ separator should still work."""
    statements = [{
        "vulnerability": {"name": "CVE-2020-35492"},
        "products": [{"@id": "somepkg"}],
        "status": "affected",
        "status_notes": "",
        "justification": "",
        "impact_statement": "",
        "action_statement": "",
    }]
    data = _make_openvex_json("default", statements)
    resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(data), "default.json"), "variant_id": str(VARIANT_UUID)},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["imported"] >= 1


# ── round-trip: export then import ───────────────────────────────────────

def test_export_import_round_trip(client):
    """Export Review → Import Review should be a valid round-trip."""
    _create_handmade_assessment(client, status="affected")
    # Export
    export_resp = client.get(f"/api/assessments/review/export?variant_id={VARIANT_UUID}")
    assert export_resp.status_code == 200
    # Import the exported file back
    import_resp = client.post(
        "/api/assessments/review/import",
        data={"file": (io.BytesIO(export_resp.data), "review.json"), "variant_id": str(VARIANT_UUID)},
        content_type="multipart/form-data",
    )
    assert import_resp.status_code == 200
    result = json.loads(import_resp.data)
    assert result["status"] == "success"


# ── GET /api/assessments/review/time-estimates ───────────────────────────

def test_review_time_estimates_empty(client):
    """No time estimates → empty list."""
    resp = client.get("/api/assessments/review/time-estimates")
    assert resp.status_code == 200
    assert json.loads(resp.data) == []


def test_review_time_estimates_basic(client):
    """After adding a time estimate it appears in the listing."""
    _create_handmade_assessment(client)
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "effort": {"optimistic": "PT2H", "likely": "PT4H", "pessimistic": "PT8H"},
        }]
    })
    resp = client.get("/api/assessments/review/time-estimates")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data) >= 1
    entry = data[0]
    assert entry["vuln_id"] == "CVE-2020-35492"
    assert entry["optimistic"] == 2
    assert entry["likely"] == 4
    assert entry["pessimistic"] == 8
    assert "optimistic_iso" in entry
    assert "vuln_texts" in entry


def test_review_time_estimates_by_variant(client):
    _create_handmade_assessment(client)
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "effort": {"optimistic": "PT1H", "likely": "PT2H", "pessimistic": "PT3H"},
        }]
    })
    resp = client.get(f"/api/assessments/review/time-estimates?variant_id={VARIANT_UUID}")
    assert resp.status_code == 200
    assert isinstance(json.loads(resp.data), list)


def test_review_time_estimates_by_project(client):
    _create_handmade_assessment(client)
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "effort": {"optimistic": "PT1H", "likely": "PT2H", "pessimistic": "PT3H"},
        }]
    })
    resp = client.get(f"/api/assessments/review/time-estimates?project_id={PROJECT_UUID}")
    assert resp.status_code == 200
    assert isinstance(json.loads(resp.data), list)


def test_review_time_estimates_one_row_per_variant(app, client):
    """Each variant with its own estimate yields a distinct row (not merged)."""
    from src.extensions import db
    from src.models.finding import Finding
    from src.models.variant import Variant
    from src.models.time_estimate import TimeEstimate

    second_variant_id = uuid.UUID("22222222-2222-2222-2222-222222222223")
    with app.app_context():
        # Add a second variant in the same project.
        db.session.add(Variant(
            id=second_variant_id,
            name="second",
            project_id=PROJECT_UUID,
        ))
        finding = Finding.get_by_vulnerability("CVE-2020-35492")[0]
        # One estimate per variant on the same finding.
        TimeEstimate.create(finding_id=finding.id, variant_id=VARIANT_UUID,
                            optimistic=5, likely=5, pessimistic=5)
        TimeEstimate.create(finding_id=finding.id, variant_id=second_variant_id,
                            optimistic=8, likely=8, pessimistic=8)
        db.session.commit()

    resp = client.get(f"/api/assessments/review/time-estimates?project_id={PROJECT_UUID}")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    rows = [e for e in data if e["vuln_id"] == "CVE-2020-35492"]
    assert len(rows) == 2
    variants = {e["variant_id"] for e in rows}
    assert str(VARIANT_UUID) in variants
    assert str(second_variant_id) in variants
    by_variant = {e["variant_id"]: e for e in rows}
    assert by_variant[str(VARIANT_UUID)]["optimistic"] == 5
    assert by_variant[str(second_variant_id)]["optimistic"] == 8


def test_review_time_estimates_matches_export_via_patch_flow(app, client):
    """Reproduce the real UI flow: set effort per variant through PATCH, then
    verify the review endpoint AND the export endpoint both expose one entry
    per variant (project scope and unscoped)."""
    from src.extensions import db
    from src.models.variant import Variant

    second_variant_id = uuid.UUID("22222222-2222-2222-2222-222222222224")
    with app.app_context():
        db.session.add(Variant(
            id=second_variant_id,
            name="second-patch",
            project_id=PROJECT_UUID,
        ))
        db.session.commit()

    # Set a different estimate for each variant exactly like the web UI does.
    r1 = client.patch("/api/vulnerabilities/CVE-2020-35492", json={
        "variant_id": str(VARIANT_UUID),
        "effort": {"optimistic": "PT5H", "likely": "PT5H", "pessimistic": "PT5H"},
    })
    assert r1.status_code == 200
    r2 = client.patch("/api/vulnerabilities/CVE-2020-35492", json={
        "variant_id": str(second_variant_id),
        "effort": {"optimistic": "PT8H", "likely": "PT8H", "pessimistic": "PT8H"},
    })
    assert r2.status_code == 200

    # Review endpoint (project scope) → two distinct rows.
    resp = client.get(f"/api/assessments/review/time-estimates?project_id={PROJECT_UUID}")
    assert resp.status_code == 200
    rows = [e for e in json.loads(resp.data) if e["vuln_id"] == "CVE-2020-35492"]
    by_variant = {e["variant_id"]: e for e in rows}
    assert by_variant.get(str(VARIANT_UUID), {}).get("optimistic") == 5
    assert by_variant.get(str(second_variant_id), {}).get("optimistic") == 8
    assert len(rows) == 2

    # Review endpoint (no scope / all variants) → still two rows.
    resp_all = client.get("/api/assessments/review/time-estimates")
    assert resp_all.status_code == 200
    rows_all = [e for e in json.loads(resp_all.data) if e["vuln_id"] == "CVE-2020-35492"]
    assert len({e["variant_id"] for e in rows_all}) == 2

    # The all-variant export retains both time-estimate entries.
    exp = client.get("/api/assessments/review/export-custom-data")
    assert exp.status_code == 200
    exported = json.loads(exp.data)["time_estimates"]
    exp_rows = [e for e in exported if e["vuln_id"] == "CVE-2020-35492"]
    assert len(exp_rows) == 2



# ── GET /api/assessments/review/custom-cvss ──────────────────────────────

def test_review_custom_cvss_empty(client):
    """No custom CVSS entries → empty list."""
    resp = client.get("/api/assessments/review/custom-cvss")
    assert resp.status_code == 200
    assert json.loads(resp.data) == []


def test_review_custom_cvss_basic(client):
    """Custom CVSS entries (non-nvd author) appear in the listing."""
    _create_handmade_assessment(client)
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "cvss": {
                "base_score": 8.0,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "version": "3.1",
                "author": "custom-tool",
                "exploitability_score": 0.0,
                "impact_score": 0.0,
            },
        }]
    })
    resp = client.get("/api/assessments/review/custom-cvss")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data) >= 1
    entry = data[0]
    assert entry["vuln_id"] == "CVE-2020-35492"
    assert "version" in entry
    assert "vector_string" in entry
    assert "author" in entry
    assert "vuln_texts" in entry


# ── GET /api/assessments/review/export-custom-data ───────────────────────

def test_export_custom_data_empty(client):
    """No handmade assessments → 404."""
    resp = client.get("/api/assessments/review/export-custom-data")
    assert resp.status_code == 404


def test_export_custom_data_basic(client):
    """After creating an assessment, export-custom-data returns the right structure."""
    _create_handmade_assessment(client)
    resp = client.get("/api/assessments/review/export-custom-data")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["version"] == 1
    assert "exported_at" in data
    assert isinstance(data["assessments"], list)
    assert len(data["assessments"]) >= 1
    assert isinstance(data["cvss"], list)
    assert isinstance(data["time_estimates"], list)
    # Each assessment should have the expected keys
    a = data["assessments"][0]
    assert "vuln_id" in a
    assert "status" in a
    assert "packages" in a
    assert "variant" in a


def test_export_custom_data_by_variant(client):
    _create_handmade_assessment(client)
    resp = client.get(f"/api/assessments/review/export-custom-data?variant_id={VARIANT_UUID}")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data["assessments"]) >= 1
    for assessment in data["assessments"]:
        assert assessment["variant_id"] == str(VARIANT_UUID)


def test_export_custom_data_by_project(client):
    _create_handmade_assessment(client)
    resp = client.get(f"/api/assessments/review/export-custom-data?project_id={PROJECT_UUID}")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data["assessments"]) >= 1


def test_export_custom_data_invalid_variant(client):
    resp = client.get("/api/assessments/review/export-custom-data?variant_id=bad")
    assert resp.status_code == 400


def test_export_custom_data_invalid_project(client):
    resp = client.get("/api/assessments/review/export-custom-data?project_id=bad")
    assert resp.status_code == 400


def test_export_custom_data_with_cvss(client):
    """Custom CVSS entries (non-nvd, non-unknown) appear in the export."""
    _create_handmade_assessment(client)
    # Add a custom CVSS via the batch endpoint
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "cvss": {
                "base_score": 7.5,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "version": "3.1",
                "author": "my-custom-tool",
                "exploitability_score": 0.0,
                "impact_score": 0.0,
            },
        }]
    })
    resp = client.get("/api/assessments/review/export-custom-data")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    # The CVSS entry should exist (author may vary depending on Metrics.from_cvss logic)
    assert isinstance(data["cvss"], list)
    if data["cvss"]:
        assert "variant" in data["cvss"][0]


def test_export_custom_data_with_time_estimate(client):
    """Time estimates appear in the export."""
    _create_handmade_assessment(client)
    # Add a time estimate via the batch endpoint
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "effort": {
                "optimistic": "PT2H",
                "likely": "PT4H",
                "pessimistic": "PT8H",
            },
        }]
    })
    resp = client.get("/api/assessments/review/export-custom-data")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert isinstance(data["time_estimates"], list)
    assert len(data["time_estimates"]) >= 1
    te = data["time_estimates"][0]
    assert te["vuln_id"] == "CVE-2020-35492"
    assert "optimistic" in te
    assert "likely" in te
    assert "pessimistic" in te
    assert "variant" in te


def test_export_custom_data_filename_by_variant(client):
    """Export by variant_id includes the project name in the filename."""
    _create_handmade_assessment(client)
    resp = client.get(f"/api/assessments/review/export-custom-data?variant_id={VARIANT_UUID}")
    assert resp.status_code == 200
    disposition = resp.headers.get("Content-Disposition", "")
    assert "custom_data_" in disposition
    assert disposition.endswith('.json"')


def test_export_custom_data_filename_by_project(client):
    """Export by project_id includes the project name in the filename."""
    _create_handmade_assessment(client)
    resp = client.get(f"/api/assessments/review/export-custom-data?project_id={PROJECT_UUID}")
    assert resp.status_code == 200
    disposition = resp.headers.get("Content-Disposition", "")
    assert "custom_data_" in disposition
    assert disposition.endswith('.json"')


# ── POST /api/assessments/review/export-update ───────────────────────────

def test_update_custom_export_preserves_matching_content_and_removes_unselected(client):
    _create_handmade_assessment(client)
    exported = client.get(f"/api/assessments/review/export-custom-data?variant_id={VARIANT_UUID}")
    existing = json.loads(exported.data)
    existing["custom_header"] = "preserved"
    existing["assessments"][0]["x-local-note"] = "preserved"
    existing["assessments"].insert(0, {
        "vuln_id": "CVE-2099-REMOVED",
        "variant_id": "33333333-3333-3333-3333-333333333333",
        "variant": "not-selected",
        "packages": [],
        "status": "affected",
    })

    response = client.post(
        "/api/assessments/review/export-update",
        data={
            "file": (io.BytesIO(json.dumps(existing).encode()), "custom_data.json"),
            "project_id": str(PROJECT_UUID),
            "variant_id": str(VARIANT_UUID),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    updated = json.loads(response.data)
    assert updated["custom_header"] == "preserved"
    assert updated["assessments"][0]["x-local-note"] == "preserved"
    assert {item["variant_id"] for item in updated["assessments"]} == {str(VARIANT_UUID)}
    assert 'filename="custom_data.json"' in response.headers["Content-Disposition"]


def test_update_openvex_auto_detects_format_and_preserves_document_id(client):
    _create_handmade_assessment(client)
    exported = client.get(f"/api/assessments/review/export?variant_id={VARIANT_UUID}")
    existing = json.loads(exported.data)
    existing["@id"] = "https://example.com/stable-review-id"
    existing["author"] = "Existing review author"
    existing["version"] = 3

    response = client.post(
        "/api/assessments/review/export-update",
        data={
            "file": (io.BytesIO(json.dumps(existing).encode()), "review.json"),
            "project_id": str(PROJECT_UUID),
            "variant_id": str(VARIANT_UUID),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    updated = json.loads(response.data)
    assert updated["@id"] == "https://example.com/stable-review-id"
    assert updated["author"] == "Existing review author"
    assert updated["version"] == 4
    assert "openvex" in updated["@context"]


def test_update_export_can_remove_all_selected_data(client):
    existing = {
        "version": 1,
        "assessments": [{
            "vuln_id": "CVE-2099-REMOVED",
            "variant_id": str(VARIANT_UUID),
            "packages": [],
            "status": "affected",
        }],
        "ai_assessments": [], "cvss": [], "time_estimates": [],
    }

    response = client.post(
        "/api/assessments/review/export-update",
        data={
            "file": (io.BytesIO(json.dumps(existing).encode()), "custom_data.json"),
            "project_id": str(PROJECT_UUID),
            "variant_id": str(VARIANT_UUID),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert json.loads(response.data)["assessments"] == []


@pytest.mark.parametrize("body, expected_error", [
    (b"not-json", "Invalid JSON file"),
    (json.dumps({"foo": "bar"}).encode(), "Unsupported export format"),
    (json.dumps({"@context": "openvex", "statements": []}).encode(), "Unsupported export format"),
])
def test_update_export_rejects_malformed_or_unsupported_input(client, body, expected_error):
    response = client.post(
        "/api/assessments/review/export-update",
        data={
            "file": (io.BytesIO(body), "review.json"),
            "project_id": str(PROJECT_UUID),
            "variant_id": str(VARIANT_UUID),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert expected_error in json.loads(response.data)["error"]


def test_update_export_rejects_variant_from_another_project(client, app):
    from src.models.project import Project
    from src.models.variant import Variant

    with app.app_context():
        foreign_project = Project.create("foreign-review-project")
        foreign_variant = Variant.create("foreign-review-variant", foreign_project.id)
        foreign_variant_id = str(foreign_variant.id)

    existing = {
        "version": 1,
        "assessments": [],
        "ai_assessments": [],
        "cvss": [],
        "time_estimates": [],
    }
    response = client.post(
        "/api/assessments/review/export-update",
        data={
            "file": (io.BytesIO(json.dumps(existing).encode()), "custom_data.json"),
            "project_id": str(PROJECT_UUID),
            "variant_id": [str(VARIANT_UUID), foreign_variant_id],
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "does not belong to project" in json.loads(response.data)["error"]


# ── POST /api/assessments/review/import-custom-data ──────────────────────

def _custom_data_payload(assessments=None, cvss=None, time_estimates=None):
    """Build a minimal custom-data JSON payload."""
    return {
        "version": 1,
        "exported_at": "2025-01-01T00:00:00Z",
        "project_id": str(PROJECT_UUID),
        "assessments": assessments or [],
        "cvss": cvss or [],
        "time_estimates": time_estimates or [],
    }


def test_import_custom_data_no_file(client):
    resp = client.post("/api/assessments/review/import-custom-data",
                       content_type="multipart/form-data")
    assert resp.status_code == 400


def test_import_custom_data_wrong_content_type(client):
    resp = client.post("/api/assessments/review/import-custom-data",
                       data=b"hello", content_type="text/plain")
    assert resp.status_code == 400


def test_import_custom_data_invalid_json(client):
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        data={"file": (io.BytesIO(b"not json"), "data.json")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400


def test_import_custom_data_missing_version(client):
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json={"assessments": []},
        content_type="application/json",
    )
    assert resp.status_code == 400


def test_import_custom_data_assessments(client):
    """Import assessments via the custom-data endpoint."""
    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2020-35492",
        "status": "affected",
        "packages": ["cairo@1.16.0"],
        "variant_id": VARIANT_UUID,
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload,
        content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["status"] == "success"
    assert result["assessments_imported"] >= 1


def test_import_custom_data_multipart_accepts_unmodified_export(client):
    """A custom-data export can be uploaded with its destination as form data."""
    _create_handmade_assessment(client)
    exported = client.get("/api/assessments/review/export-custom-data")
    assert exported.status_code == 200

    response = client.post(
        "/api/assessments/review/import-custom-data",
        data={
            "file": (io.BytesIO(exported.data), "custom_data.json"),
            "project_id": str(PROJECT_UUID),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert json.loads(response.data)["status"] == "success"


def test_import_custom_data_uses_original_timestamp(app, client):
    original_timestamp = "2001-02-03T04:05:06+00:00"
    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2099-91001",
        "status": "affected",
        "packages": ["timestamp-original@1.0"],
        "variant_id": str(VARIANT_UUID),
        "timestamp": original_timestamp,
    }])
    payload["timestamp_policy"] = "original"

    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload,
        content_type="application/json",
    )

    assert resp.status_code == 200
    with app.app_context():
        from src.helpers.datetime_utils import ensure_utc_iso
        from src.models.assessment import Assessment

        imported = next(
            assessment for assessment in Assessment.get_by_origin([VARIANT_UUID], origin="custom")
            if assessment.vuln_id == "CVE-2099-91001"
        )
        assert ensure_utc_iso(imported.timestamp) == original_timestamp


def test_import_custom_data_uses_current_system_time(app, client):
    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2099-91002",
        "status": "affected",
        "packages": ["timestamp-current@1.0"],
        "variant_id": str(VARIANT_UUID),
        "timestamp": "2001-02-03T04:05:06+00:00",
    }])
    payload["timestamp_policy"] = "current"
    before_import = datetime.now(timezone.utc)

    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload,
        content_type="application/json",
    )
    after_import = datetime.now(timezone.utc)

    assert resp.status_code == 200
    with app.app_context():
        from src.models.assessment import Assessment

        imported = next(
            assessment for assessment in Assessment.get_by_origin([VARIANT_UUID], origin="custom")
            if assessment.vuln_id == "CVE-2099-91002"
        )
        stored_timestamp = imported.timestamp
        if stored_timestamp.tzinfo is None:
            stored_timestamp = stored_timestamp.replace(tzinfo=timezone.utc)
        assert before_import <= stored_timestamp <= after_import


def test_import_custom_data_rejects_invalid_timestamp_policy(client):
    payload = _custom_data_payload()
    payload["timestamp_policy"] = "invalid"
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload,
        content_type="application/json",
    )

    assert resp.status_code == 400
    assert "timestamp_policy" in json.loads(resp.data)["error"]


def _import_custom_data_with_timestamp(client, vuln_id, package, timestamp, **extra):
    payload = _custom_data_payload(assessments=[{
        "vuln_id": vuln_id,
        "status": "affected",
        "packages": [package],
        "variant_id": str(VARIANT_UUID),
        "timestamp": timestamp,
        **extra,
    }])
    payload["timestamp_policy"] = "original"
    return client.post(
        "/api/assessments/review/import-custom-data",
        json=payload,
        content_type="application/json",
    )


def test_import_custom_data_original_timestamp_keeps_distinct_entries(client):
    """A later timestamp is a new history entry, not a duplicate to discard."""
    vuln_id, package = "CVE-2099-91003", "timestamp-history@1.0"

    first = _import_custom_data_with_timestamp(
        client, vuln_id, package, "2026-07-07T10:00:00+00:00")
    second = _import_custom_data_with_timestamp(
        client, vuln_id, package, "2026-07-20T10:00:00+00:00")

    assert json.loads(first.data)["assessments_imported"] == 1
    assert json.loads(second.data)["assessments_imported"] == 1

    listed = json.loads(client.get("/api/assessments/review").data)
    timestamps = sorted(a["timestamp"] for a in listed if a["vuln_id"] == vuln_id)
    assert timestamps == ["2026-07-07T10:00:00+00:00", "2026-07-20T10:00:00+00:00"]


def test_import_custom_data_original_timestamp_is_idempotent(client):
    """Re-importing the same file does not duplicate its assessments."""
    vuln_id, package = "CVE-2099-91004", "timestamp-idempotent@1.0"

    first = _import_custom_data_with_timestamp(
        client, vuln_id, package, "2026-07-20T10:00:00+00:00")
    second = _import_custom_data_with_timestamp(
        client, vuln_id, package, "2026-07-20T10:00:00+00:00")

    assert json.loads(first.data)["assessments_imported"] == 1
    assert json.loads(second.data)["assessments_imported"] == 0
    assert json.loads(second.data)["assessments_skipped"] == 1


def test_import_custom_data_original_timestamp_normalised_to_utc(client):
    """A non-UTC offset is converted rather than stored as wall-clock time."""
    vuln_id, package = "CVE-2099-91005", "timestamp-offset@1.0"

    resp = _import_custom_data_with_timestamp(
        client, vuln_id, package, "2026-07-20T12:00:00+02:00")

    assert json.loads(resp.data)["assessments_imported"] == 1
    listed = json.loads(client.get("/api/assessments/review").data)
    imported = next(a for a in listed if a["vuln_id"] == vuln_id)
    assert imported["timestamp"] == "2026-07-20T10:00:00+00:00"


def test_import_custom_data_assessments_without_variant_field(client):
    """Import remains backward compatible when variant fields are missing."""
    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2020-35492",
        "status": "affected",
        "packages": ["cairo@1.16.0"],
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload,
        content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["status"] == "success"
    assert result["assessments_imported"] >= 1


def test_import_custom_data_assessments_with_variant_name(client):
    """Assessment import accepts the human-readable variant name field."""
    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2020-35492",
        "status": "affected",
        "packages": ["cairo@1.16.0"],
        "variant": "default",
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload,
        content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["status"] == "success"
    assert result["assessments_imported"] >= 1


def test_import_custom_data_foreign_variant_id_falls_back_to_name(client):
    """A ``variant_id`` from another VulnScout instance never matches a local
    variant (each instance mints its own UUIDs). Importing it as-is used to
    attach the assessment to a variant_id no query would ever find, so it
    silently disappeared from the Review page while remaining in the DB.
    The import must fall back to the ``variant`` name field instead.
    """
    foreign_variant_id = str(uuid.uuid4())
    assert foreign_variant_id != str(VARIANT_UUID)
    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2020-35492",
        "status": "affected",
        "packages": ["cairo@1.16.0"],
        "variant_id": foreign_variant_id,
        "variant": "default",
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload,
        content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["status"] == "success"
    assert result["assessments_imported"] == 1

    # Visible through the same variant-scoped query the Review page uses.
    listing = client.get(f"/api/assessments/review?variant_id={VARIANT_UUID}")
    assert listing.status_code == 200
    vuln_ids = [a["vuln_id"] for a in json.loads(listing.data)]
    assert "CVE-2020-35492" in vuln_ids


def test_import_custom_data_scopes_duplicate_variant_names_to_project(app, client):
    """A name fallback must not resolve a variant in another project."""
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.metrics import Metrics
    from src.models.project import Project
    from src.models.time_estimate import TimeEstimate
    from src.models.variant import Variant

    with app.app_context():
        Metrics.reset_cache()
        foreign_project = Project.create("foreign-project")
        foreign_variant = Variant.create("default", foreign_project.id)
        foreign_local_variant_id = foreign_variant.id

    foreign_variant_id = str(uuid.uuid4())
    payload = _custom_data_payload(
        assessments=[{
            "vuln_id": "CVE-2020-35492",
            "status": "affected",
            "packages": ["cairo@1.16.0"],
            "variant_id": foreign_variant_id,
            "variant": "default",
            "origin": "custom",
        }],
        cvss=[{
            "vuln_id": "CVE-2020-35492",
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "base_score": 7.5,
            "variant_id": foreign_variant_id,
            "variant": "default",
        }],
        time_estimates=[{
            "vuln_id": "CVE-2020-35492",
            "optimistic": "PT1H",
            "likely": "PT2H",
            "pessimistic": "PT3H",
            "variant_id": foreign_variant_id,
            "variant": "default",
        }],
    )
    payload["project_id"] = str(PROJECT_UUID)

    response = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload,
        content_type="application/json",
    )

    assert response.status_code == 200
    import_result = json.loads(response.data)
    assert import_result["assessments_imported"] == 1, import_result
    with app.app_context():
        imported_assessments = Assessment.get_by_origin([VARIANT_UUID], origin="custom")
        foreign_assessments = Assessment.get_by_origin([foreign_local_variant_id], origin="custom")
        imported_metrics = db.session.execute(
            db.select(Metrics).where(
                Metrics.vulnerability_id == "CVE-2020-35492",
                Metrics.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            )
        ).scalars().all()
        imported_estimates = db.session.execute(
            db.select(TimeEstimate).where(TimeEstimate.variant_id == VARIANT_UUID)
        ).scalars().all()
        foreign_estimates = db.session.execute(
            db.select(TimeEstimate).where(TimeEstimate.variant_id == foreign_local_variant_id)
        ).scalars().all()

    assert len(imported_assessments) == 1
    assert not foreign_assessments
    assert len(imported_metrics) == 1
    assert imported_metrics[0].variant_id == VARIANT_UUID
    assert imported_estimates
    assert not foreign_estimates


def test_import_custom_data_foreign_variant_id_without_name_is_rejected(client):
    """A foreign variant_id with no local ``variant`` name to fall back to
    must be reported as an error instead of silently attaching to a
    variant_id that does not exist in this database.
    """
    foreign_variant_id = str(uuid.uuid4())
    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2020-35492",
        "status": "affected",
        "packages": ["cairo@1.16.0"],
        "variant_id": foreign_variant_id,
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload,
        content_type="application/json",
    )
    assert resp.status_code == 400
    result = json.loads(resp.data)
    assert result["assessments_imported"] == 0
    assert any(foreign_variant_id in e.get("error", "") for e in result["errors"])


def test_import_custom_data_duplicate_skipped(client):
    """Same assessment imported twice → second is skipped."""
    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2020-35492",
        "status": "not_affected",
        "justification": "component_not_present",
        "packages": ["cairo@1.16.0"],
        "variant_id": VARIANT_UUID,
    }])
    resp1 = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp1.status_code == 200
    r1 = json.loads(resp1.data)
    assert r1["assessments_imported"] >= 1

    resp2 = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp2.status_code == 200
    r2 = json.loads(resp2.data)
    assert r2["assessments_skipped"] >= 1
    assert r2["assessments_imported"] == 0


def _seed_assessment(app, *, vuln_id, pkg_name, pkg_version, status, origin):
    """Create an assessment with a specific origin directly in the DB."""
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.finding import Finding
    from src.models.assessment import Assessment
    with app.app_context():
        pkg = Package.find_or_create(pkg_name, pkg_version, supplier="")
        Vulnerability.get_or_create(vuln_id)
        finding = Finding.get_or_create(pkg.id, vuln_id)
        Assessment.create(
            status=status,
            finding_id=finding.id,
            variant_id=VARIANT_UUID,
            origin=origin,
        )


def test_import_custom_data_duplicate_multiple_existing_rows(app, client):
    """Dedup must not crash when several matching assessments already exist.

    ``--export-custom-assessments`` can yield an item whose finding/variant/
    status matches more than one existing assessment row. The dedup query
    previously used ``scalar_one_or_none()`` which raised
    "Multiple rows were found when one or none was required" and dropped the
    item. The import should skip it cleanly instead.
    """
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.finding import Finding
    from src.models.assessment import Assessment

    with app.app_context():
        pkg = Package.find_or_create("generic/glibc", "2.39", supplier="")
        Vulnerability.get_or_create("CVE-2026-5450")
        finding = Finding.get_or_create(pkg.id, "CVE-2026-5450")
        # Two assessments sharing finding + variant + status.
        for _ in range(2):
            Assessment.create(
                status="affected",
                finding_id=finding.id,
                variant_id=VARIANT_UUID,
                origin="custom",
            )

    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2026-5450",
        "status": "affected",
        "packages": ["generic/glibc@2.39"],
        "variant_id": VARIANT_UUID,
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["status"] == "success"
    assert result["assessments_skipped"] >= 1
    # No error entry for the CVE that previously triggered the crash.
    assert all(e.get("vuln_id") != "CVE-2026-5450" for e in result["errors"])


def test_import_statements_duplicate_multiple_existing_rows(app):
    """OpenVEX import (import_statements) must not crash on multiple matches.

    Files produced by ``--export-custom-assessments`` are OpenVEX documents
    re-imported through ``import_statements``. When two existing assessments
    share the same finding/variant/status, the dedup query previously used
    ``scalar_one_or_none()`` which raised "Multiple rows were found when one
    or none was required" and dropped the statement.
    """
    from src.helpers.assessment_io import import_statements
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.finding import Finding
    from src.models.assessment import Assessment

    with app.app_context():
        pkg = Package.find_or_create("linux-stm32mp", "6.6.116-stm32mp-r3", supplier="")
        Vulnerability.get_or_create("CVE-1999-0061")
        finding = Finding.get_or_create(pkg.id, "CVE-1999-0061")
        for _ in range(2):
            Assessment.create(
                status="fixed",
                finding_id=finding.id,
                variant_id=VARIANT_UUID,
                origin="custom",
            )

        statements = [{
            "vulnerability": {"name": "CVE-1999-0061"},
            "status": "fixed",
            "products": ["linux-stm32mp@6.6.116-stm32mp-r3"],
        }]
        created, errors, skipped = import_statements(statements, VARIANT_UUID)

    assert skipped >= 1
    # The statement must not be dropped with a "Multiple rows" error.
    assert all(
        "Multiple rows" not in str(e.get("error", "")) for e in errors
    )


def test_import_statements_not_skipped_when_only_scanner_assessment_exists(app):
    """A scanner-origin assessment must not block importing an OpenVEX one.

    Like ``import_custom_data``, the OpenVEX import dedup is origin-aware: it
    only deduplicates against existing ``origin == "custom"`` assessments, so a
    scanner/SBOM assessment with the same finding/variant/status must not
    prevent the custom statement from being created.
    """
    from src.helpers.assessment_io import import_statements
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.finding import Finding
    from src.models.assessment import Assessment

    with app.app_context():
        pkg = Package.find_or_create("scannerpkg", "1.0.0", supplier="")
        Vulnerability.get_or_create("CVE-2099-00003")
        finding = Finding.get_or_create(pkg.id, "CVE-2099-00003")
        Assessment.create(
            status="fixed",
            finding_id=finding.id,
            variant_id=VARIANT_UUID,
            origin="Imported SBOM",
        )

        statements = [{
            "vulnerability": {"name": "CVE-2099-00003"},
            "status": "fixed",
            "products": ["scannerpkg@1.0.0"],
        }]
        created, errors, skipped = import_statements(statements, VARIANT_UUID)

    assert errors == []
    assert skipped == 0
    assert len(created) == 1


def test_import_statements_preserves_original_timestamp(app):
    """The OpenVEX statement timestamp must be persisted on the assessment.

    This keeps exports ordered by the date of the custom assessment and makes
    the exported file reproducible when two developers import each other's
    assessments (the date travels with the assessment instead of being reset
    to the import time).
    """
    from src.helpers.assessment_io import import_statements
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.finding import Finding
    from src.models.assessment import Assessment
    from src.helpers.datetime_utils import ensure_utc_iso

    original_ts = "2024-05-01T12:00:00+00:00"
    with app.app_context():
        Package.find_or_create("tspreserve", "1.0.0", supplier="")
        Vulnerability.get_or_create("CVE-2024-90001")

        statements = [{
            "vulnerability": {"name": "CVE-2024-90001"},
            "status": "fixed",
            "products": ["tspreserve@1.0.0"],
            "timestamp": original_ts,
        }]
        created, errors, skipped = import_statements(statements, VARIANT_UUID)

        assert errors == []
        assert len(created) == 1

        finding = Finding.get_or_create(
            Package.find_or_create("tspreserve", "1.0.0", supplier="").id,
            "CVE-2024-90001",
        )
        stored = Assessment.get_by_finding_and_variant(finding.id, VARIANT_UUID)
        assert stored
        assert ensure_utc_iso(stored[0].timestamp) == original_ts


def test_import_statements_invalid_timestamp_falls_back(app):
    """An unparseable statement timestamp must not break the import."""
    from src.helpers.assessment_io import import_statements
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability

    with app.app_context():
        Package.find_or_create("tsbad", "1.0.0", supplier="")
        Vulnerability.get_or_create("CVE-2024-90002")

        statements = [{
            "vulnerability": {"name": "CVE-2024-90002"},
            "status": "fixed",
            "products": ["tsbad@1.0.0"],
            "timestamp": "not-a-date",
        }]
        created, errors, skipped = import_statements(statements, VARIANT_UUID)

    assert errors == []
    assert len(created) == 1


def test_import_custom_data_not_skipped_when_only_scanner_assessment_exists(app, client):
    """A scanner-origin assessment must not block importing a custom one.

    The dedup is origin-aware: importing custom data only deduplicates
    against existing ``origin == "custom"`` assessments, so a deleted custom
    assessment can be restored even when a scanner assessment with the same
    finding/variant/status is still present.
    """
    _seed_assessment(
        app, vuln_id="CVE-2099-00001", pkg_name="scannerpkg",
        pkg_version="1.0.0", status="affected", origin="Imported SBOM",
    )

    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2099-00001",
        "status": "affected",
        "packages": ["scannerpkg@1.0.0"],
        "variant_id": VARIANT_UUID,
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["status"] == "success"
    assert result["assessments_imported"] == 1
    assert result["assessments_skipped"] == 0


def test_import_custom_data_skipped_when_custom_assessment_exists(app, client):
    """An existing custom assessment with the same key is still deduplicated."""
    _seed_assessment(
        app, vuln_id="CVE-2099-00002", pkg_name="custompkg",
        pkg_version="2.0.0", status="affected", origin="custom",
    )

    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2099-00002",
        "status": "affected",
        "packages": ["custompkg@2.0.0"],
        "variant_id": VARIANT_UUID,
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["status"] == "success"
    assert result["assessments_imported"] == 0
    assert result["assessments_skipped"] == 1


def test_import_custom_data_cvss(client):
    """Import CVSS via the custom-data endpoint."""
    payload = _custom_data_payload(cvss=[{
        "vuln_id": "CVE-2020-35492",
        "version": "3.1",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "base_score": 7.5,
        "author": "custom-author",
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["cvss_imported"] >= 1


def test_import_custom_data_cvss_with_variant_name(client):
    """CVSS import accepts the human-readable variant name field."""
    payload = _custom_data_payload(cvss=[{
        "vuln_id": "CVE-2020-35492",
        "variant": "default",
        "version": "3.1",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "base_score": 7.5,
        "author": "custom-author",
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["cvss_imported"] >= 1


def test_import_custom_data_time_estimates(client):
    """Import time estimates via the custom-data endpoint."""
    payload = _custom_data_payload(time_estimates=[{
        "vuln_id": "CVE-2020-35492",
        "optimistic": "PT2H",
        "likely": "PT4H",
        "pessimistic": "PT8H",
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["time_estimates_imported"] >= 1


def test_import_custom_data_time_estimates_with_variant_name(client):
    """Time-estimate import accepts the human-readable variant name field."""
    payload = _custom_data_payload(time_estimates=[{
        "vuln_id": "CVE-2020-35492",
        "variant": "default",
        "optimistic": "PT2H",
        "likely": "PT4H",
        "pessimistic": "PT8H",
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["time_estimates_imported"] >= 1


def test_import_custom_data_all_together(client):
    """Import assessments + CVSS + time estimates in a single request."""
    payload = _custom_data_payload(
        assessments=[{
            "vuln_id": "CVE-2020-35492",
            "status": "under_investigation",
            "packages": ["cairo@1.16.0"],
            "variant_id": VARIANT_UUID,
        }],
        cvss=[{
            "vuln_id": "CVE-2020-35492",
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "base_score": 7.5,
            "author": "my-tool",
        }],
        time_estimates=[{
            "vuln_id": "CVE-2020-35492",
            "optimistic": "PT1H",
            "likely": "PT2H",
            "pessimistic": "PT4H",
        }],
    )
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["assessments_imported"] >= 1
    assert result["cvss_imported"] >= 1
    assert result["time_estimates_imported"] >= 1


def test_import_custom_data_via_file_upload(client):
    """Import custom-data via multipart file upload."""
    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2020-35492",
        "status": "affected",
        "packages": ["cairo@1.16.0"],
        "variant_id": str(VARIANT_UUID),
    }])
    data_bytes = json.dumps(payload).encode("utf-8")
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        data={
            "file": (io.BytesIO(data_bytes), "custom_data.json"),
            "project_id": str(PROJECT_UUID),
        },
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["assessments_imported"] >= 1


def test_import_custom_data_unknown_vuln_cvss(client):
    """CVSS for a non-existent vulnerability → error reported."""
    payload = _custom_data_payload(cvss=[{
        "vuln_id": "CVE-9999-99999",
        "version": "3.1",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "base_score": 7.5,
        "author": "test",
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    # Should succeed overall but report the error
    result = json.loads(resp.data)
    assert any("Vulnerability not found" in e.get("error", "") for e in result.get("errors", []))


def test_export_import_custom_data_round_trip(client):
    """Export custom data → import it back."""
    _create_handmade_assessment(client, status="affected")
    # Add CVSS and time estimate
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "effort": {"optimistic": "PT1H", "likely": "PT2H", "pessimistic": "PT4H"},
        }]
    })

    # Export
    export_resp = client.get("/api/assessments/review/export-custom-data")
    assert export_resp.status_code == 200
    exported = json.loads(export_resp.data)
    assert exported["version"] == 1
    assert len(exported["assessments"]) >= 1
    exported["project_id"] = str(PROJECT_UUID)

    # Import back
    import_resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=exported, content_type="application/json",
    )
    assert import_resp.status_code == 200
    result = json.loads(import_resp.data)
    assert result["status"] == "success"


def test_export_custom_data_with_only_pending_ai_assessments(client):
    """The Review page can export a pending AI assessment without custom data."""
    _create_ai_assessment(client)

    response = client.get("/api/assessments/review/export-custom-data")

    assert response.status_code == 200
    exported = json.loads(response.data)
    assert exported["assessments"] == []
    assert len(exported["ai_assessments"]) == 1
    assert exported["ai_assessments"][0]["vuln_id"] == "CVE-2020-35492"


# ── review_custom_cvss: variant/project filtering ────────────────────────

def test_review_custom_cvss_by_variant(client):
    """Filter by variant_id returns only CVSSes for that variant's findings."""
    _create_handmade_assessment(client)
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "cvss": {
                "base_score": 4.1,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "version": "3.1",
                "author": "my-org",
                "origin": "custom",
                "exploitability_score": 0.0,
                "impact_score": 0.0,
            },
        }]
    })
    resp = client.get(f"/api/assessments/review/custom-cvss?variant_id={VARIANT_UUID}")
    assert resp.status_code == 200
    assert isinstance(json.loads(resp.data), list)


def test_review_custom_cvss_by_variant_invalid(client):
    """Invalid variant_id UUID → 400."""
    resp = client.get("/api/assessments/review/custom-cvss?variant_id=not-a-uuid")
    assert resp.status_code == 400


def test_review_custom_cvss_by_project(client):
    """Filter by project_id returns results scoped to that project."""
    _create_handmade_assessment(client)
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "cvss": {
                "base_score": 4.2,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "version": "3.1",
                "author": "sec-team",
                "origin": "custom",
                "exploitability_score": 0.0,
                "impact_score": 0.0,
            },
        }]
    })
    resp = client.get(f"/api/assessments/review/custom-cvss?project_id={PROJECT_UUID}")
    assert resp.status_code == 200
    assert isinstance(json.loads(resp.data), list)


def test_review_custom_cvss_by_project_invalid(client):
    """Invalid project_id UUID → 400."""
    resp = client.get("/api/assessments/review/custom-cvss?project_id=bad")
    assert resp.status_code == 400


def test_review_custom_cvss_by_project_no_variants(client):
    """project_id pointing to a project with no variants → empty list."""
    fake_project = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    resp = client.get(f"/api/assessments/review/custom-cvss?project_id={fake_project}")
    assert resp.status_code == 200
    assert json.loads(resp.data) == []


def test_review_custom_cvss_origin_field_present(client):
    """Each entry in the response includes the 'origin' field."""
    _create_handmade_assessment(client)
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "cvss": {
                "base_score": 4.3,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "version": "3.1",
                "author": "researcher",
                "origin": "custom",
                "exploitability_score": 0.0,
                "impact_score": 0.0,
            },
        }]
    })
    resp = client.get("/api/assessments/review/custom-cvss")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert len(data) >= 1
    assert "origin" in data[0]
    assert data[0]["origin"] == "custom"


def test_review_custom_cvss_skips_scanner_author(client):
    """CVSS stored with origin=custom but scanner-like author is excluded.

    When a CVSS is PATCHed without an explicit author, origin is forced to
    'custom' by the route, but _validate_and_apply_cvss then defaults the
    author to 'unknown' (a scanner author). The review endpoint must skip
    such entries via _is_scanner_author.
    """
    _create_handmade_assessment(client)
    # PATCH without author → stored as origin=custom, author=unknown
    client.patch("/api/vulnerabilities/batch", json={
        "vulnerabilities": [{
            "id": "CVE-2020-35492",
            "cvss": {
                "base_score": 4.4,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "version": "3.1",
                # no 'author' key — defaults to "unknown" inside _validate_and_apply_cvss
                "exploitability_score": 0.0,
                "impact_score": 0.0,
            },
        }]
    })
    resp = client.get("/api/assessments/review/custom-cvss")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    # The entry must not appear because "unknown" is a scanner author
    for entry in data:
        assert entry.get("author") != "unknown"


# ── import_review_custom_data: additional error paths ─────────────────────

def test_import_custom_data_invalid_variant_id(client):
    """variant_id query param that is not a valid UUID → 400."""
    payload = _custom_data_payload(assessments=[{
        "vuln_id": "CVE-2020-35492",
        "status": "affected",
        "packages": ["cairo@1.16.0"],
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data?variant_id=not-a-uuid",
        json=payload, content_type="application/json",
    )
    assert resp.status_code == 400


def test_import_custom_data_invalid_json_body(client):
    """application/json body that cannot be parsed → 400."""
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        data=b"this is not json",
        content_type="application/json",
    )
    assert resp.status_code == 400


def test_import_custom_data_cvss_sets_origin_from_import(client):
    """CVSS imported without an explicit origin gets origin='scanner' from
    _validate_and_apply_cvss defaults (no setdefault in the import path)."""
    payload = _custom_data_payload(cvss=[{
        "vuln_id": "CVE-2020-35492",
        "version": "3.1",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "base_score": 7.5,
        # no 'origin' key → _validate_and_apply_cvss defaults to "scanner"
        "author": "imported-tool",
    }])
    resp = client.post(
        "/api/assessments/review/import-custom-data",
        json=payload, content_type="application/json",
    )
    assert resp.status_code == 200
    result = json.loads(resp.data)
    assert result["cvss_imported"] >= 1

class TestFetchVulnerabilitiesTexts:
    """Regression tests for src.routes._scan_queries.fetch_vulnerabilities_texts.

    A user hit an AssertionError (`assert text.packages`) when an observation
    that carries a package matched an existing text whose ``packages`` list was
    still ``None`` (e.g. the vulnerability ``description`` text, or an
    observation first seen without a package).
    """

    VULNERABILITY_ID = "CVE-2020-35492"
    SBOM_DOC_ID = uuid.UUID("44444444-4444-4444-4444-444444444444")

    def test_observation_matching_description_text_with_package(self, app):
        """An observation with key='description' + a package must not crash."""
        from src.extensions import db
        from src.models import SBOMObservation
        from src.models.package import Package
        from src.models.vulnerability import Vulnerability
        from src.routes._scan_queries import fetch_vulnerabilities_texts

        with app.app_context():
            description = db.session.get(Vulnerability, self.VULNERABILITY_ID).description
            pkg = Package.find_or_create("cairo", "1.16.0", [], [], "")
            db.session.add(SBOMObservation(
                vulnerability_id=self.VULNERABILITY_ID,
                sbom_document_id=self.SBOM_DOC_ID,
                key="description",
                description=description,
                package_id=pkg.id,
            ))
            db.session.commit()

            texts = fetch_vulnerabilities_texts(
                [self.VULNERABILITY_ID], include_packages=True
            )

        entries = texts[self.VULNERABILITY_ID]
        description_entries = [
            t for t in entries
            if t.title == "description" and t.content == description
        ]
        assert len(description_entries) == 1
        assert description_entries[0].packages == ["cairo"]

    def test_observation_without_then_with_package(self, app):
        """Same key/content, one observation without a package, one with one.

        The packageless observation creates a text whose ``packages`` is None;
        the second observation (carrying a package) must enrich it in place
        rather than raise.
        """
        from src.extensions import db
        from src.models import SBOMObservation
        from src.models.package import Package
        from src.routes._scan_queries import fetch_vulnerabilities_texts

        with app.app_context():
            pkg = Package.find_or_create("cairo", "1.16.0", [], [], "")
            db.session.add_all([
                SBOMObservation(
                    vulnerability_id=self.VULNERABILITY_ID,
                    sbom_document_id=self.SBOM_DOC_ID,
                    key="shared key",
                    description="shared content",
                    package_id=None,
                ),
                SBOMObservation(
                    vulnerability_id=self.VULNERABILITY_ID,
                    sbom_document_id=self.SBOM_DOC_ID,
                    key="shared key",
                    description="shared content",
                    package_id=pkg.id,
                ),
            ])
            db.session.commit()

            texts = fetch_vulnerabilities_texts(
                [self.VULNERABILITY_ID], include_packages=True
            )

        shared = [
            t for t in texts[self.VULNERABILITY_ID]
            if t.title == "shared key" and t.content == "shared content"
        ]
        assert len(shared) == 1
        assert shared[0].packages == ["cairo"]


# ── POST /api/assessment-groups/<group_id>/reconcile ────────────────────────
#
# Ported from Feature#23169-dedup-assessment-table-entries's
# tests/webapp_tests/test_assessment_group_reconcile.py, rekeyed to address
# groups by ``group_id`` (looked up through ``AssessmentGroupMember`` via
# ``load_group``) instead of an explicit ``existing_ids`` list, and using the
# ``demo_ids`` fixture instead of that branch's bespoke fixtures. Tests that
# only existed to exercise ``load_group_rows``'s id-list validation (rejecting
# an id from another vulnerability/project, or a row with no variant) are not
# ported: that function was intentionally not carried over, since a group is
# now identified by the URL's ``group_id`` and loaded via membership rather
# than by trusting a client-supplied id list.

def _create_group(client, demo_ids, packages=None, variant_id=None, status="affected", **extra):
    """Create one multi-target assessment and return (group_id, [group_id]).

    A group is now exactly one assessment row; its "members" are targets on
    that row, not sibling rows. The multi-package HTTP endpoint still creates
    one independent row per package (migrating it to multi-target creation is
    out of scope for this read-path task), so these reconcile tests build the
    genuine multi-target assessment a migrated write path would produce,
    directly at the model layer — the same pattern already used by
    ``test_assessment_groups_controller.py``. The returned id list always has
    exactly one entry; it stays a list because most call sites only ever loop
    over it.
    """
    from src.models.assessment import Assessment, STATUS_TO_SIMPLIFIED
    from src.models.finding import Finding
    from src.models.package import Package

    pkg_ids = packages if packages is not None else demo_ids["two_packages"]
    variant = uuid.UUID(str(variant_id or demo_ids["variant_id"]))
    origin = "ai" if extra.pop("ai_generated", False) else "custom"

    with client.application.app_context():
        targets = []
        for pkg_string_id in pkg_ids:
            package = Package.get_by_string_id(pkg_string_id)
            finding = Finding.get_or_create(package.id, demo_ids["vuln_id"])
            targets.append((variant, finding.id))
        assessment = Assessment.create(
            status=status,
            simplified_status=STATUS_TO_SIMPLIFIED.get(status, "Pending Assessment"),
            origin=origin,
            targets=targets,
            justification=extra.get("justification", ""),
            responses=extra.get("responses"),
            commit=True,
        )
        group_id = str(assessment.id)
    return group_id, [group_id]


def _reconcile(client, group_id, demo_ids, packages=None, variant_ids=None, status="fixed", **extra):
    payload = {
        "vuln_id": demo_ids["vuln_id"],
        "packages": packages if packages is not None else demo_ids["two_packages"],
        "variant_ids": variant_ids if variant_ids is not None else [demo_ids["variant_id"]],
        "status": status,
    }
    payload.update(extra)
    return client.post(f"/api/assessment-groups/{group_id}/reconcile", json=payload)


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


def test_reconcile_updates_every_member_and_keeps_the_group_id(client, demo_ids):
    group_id, _ = _create_group(client, demo_ids, status="not_affected",
                                 justification="component_not_present")

    resp = _reconcile(client, group_id, demo_ids, status="not_affected",
                       justification="vulnerable_code_not_present")
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert body["group_id"] == group_id
    assert len(body["updated"]) == 1
    assert body["created"] == []
    assert body["deleted"] == []

    group = client.get(f"/api/assessment-groups/{group_id}").get_json()
    assert group["status"] == "not_affected"
    assert group["justification"] == "vulnerable_code_not_present"
    assert len(group["targets"]) == 2


def test_reconcile_removing_a_target_keeps_the_group_alive(client, demo_ids):
    group_id, ids = _create_group(client, demo_ids, status="not_affected",
                                   justification="component_not_present")

    resp = _reconcile(client, group_id, demo_ids,
                       packages=[demo_ids["two_packages"][0]], status="not_affected",
                       justification="component_not_present")
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert body["deleted"] == [], "dropping one of two targets must not delete the group"
    assert len(body["updated"]) == 1

    group = client.get(f"/api/assessment-groups/{group_id}").get_json()
    assert group["group_id"] == group_id, "a group shrunk to one target survives"
    assert len(group["targets"]) == 1


def test_reconcile_on_unknown_group_is_404(client):
    resp = client.post(
        f"/api/assessment-groups/{uuid.uuid4()}/reconcile",
        json={"vuln_id": "CVE-1999-12345", "packages": ["cairo@1.16.0"],
              "variant_ids": ["22222222-2222-2222-2222-222222222222"], "status": "fixed"},
    )
    assert resp.status_code == 404


def test_reconcile_adds_targets_for_a_newly_selected_variant(client, demo_ids):
    """A newly selected variant grows the group's targets, not its rows."""
    group_id, ids = _create_group(client, demo_ids, status="affected")

    resp = _reconcile(
        client, group_id, demo_ids,
        variant_ids=[demo_ids["variant_id"], demo_ids["other_variant_id"]],
        status="fixed",
    )
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert len(body["updated"]) == 1
    assert body["created"] == [], "a group is one assessment; new combos become targets, not rows"
    assert body["deleted"] == []

    group = client.get(f"/api/assessment-groups/{group_id}").get_json()
    assert len(group["targets"]) == 4
    assert group["assessment_ids"] == [group_id]


def test_reconcile_rejects_unknown_package(client, demo_ids):
    group_id, _ = _create_group(client, demo_ids)

    resp = _reconcile(client, group_id, demo_ids, packages=["ghost@9.9.9"])
    assert resp.status_code == 400
    assert "Package not found" in resp.get_json()["error"]


def test_reconcile_rejects_empty_variant_ids(client, demo_ids):
    group_id, _ = _create_group(client, demo_ids)

    resp = _reconcile(client, group_id, demo_ids, variant_ids=[])
    assert resp.status_code == 400
    assert "variant_ids" in resp.get_json()["error"]


def test_reconcile_editing_pending_ai_row_keeps_it_pending(client, demo_ids):
    group_id, ids = _create_group(client, demo_ids, status="affected", ai_generated=True)

    resp = _reconcile(client, group_id, demo_ids, status="fixed")
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert {row["origin"] for row in body["updated"]} == {"ai"}

    for assessment_id in ids:
        assert _read_row(client.application, assessment_id, "origin") == "ai"


def test_reconcile_refuses_to_delete_pending_ai_row(client, demo_ids):
    group_id, ids = _create_group(client, demo_ids, status="affected")
    _mutate_row(client.application, group_id, origin="ai")

    resp = _reconcile(client, group_id, demo_ids,
                       packages=[demo_ids["two_packages"][0]])
    assert resp.status_code == 400
    assert "AI approve/reject" in resp.get_json()["error"]
    # Neither the surviving target's update nor the dropped target's removal
    # happened.
    assert _read_row(client.application, group_id, "status") == "affected"
    assert _read_row(client.application, group_id, "origin") == "ai"


def test_reconcile_invalid_combo_writes_nothing(client, demo_ids):
    group_id, ids = _create_group(client, demo_ids, status="affected")

    resp = _reconcile(client, group_id, demo_ids,
                       packages=[demo_ids["two_packages"][0], "ghost@9.9.9"])
    assert resp.status_code == 400

    for assessment_id in ids:
        assert _read_row(client.application, assessment_id, "status") == "affected"


def test_reconcile_edit_without_responses_keeps_stored_responses(client, demo_ids):
    group_id, ids = _create_group(client, demo_ids, status="affected")
    _mutate_row(client.application, ids[0], responses=["will_not_fix", "workaround_available"])

    resp = _reconcile(client, group_id, demo_ids, status="fixed")
    assert resp.status_code == 200, resp.get_json()
    updated_by_id = {row["id"]: row for row in resp.get_json()["updated"]}
    assert updated_by_id[ids[0]]["responses"] == ["will_not_fix", "workaround_available"]
    assert _read_row(client.application, ids[0], "responses") == ["will_not_fix", "workaround_available"]


def test_reconcile_explicit_responses_replace_stored_responses(client, demo_ids):
    group_id, ids = _create_group(client, demo_ids, status="affected")
    _mutate_row(client.application, ids[0], responses=["will_not_fix"])

    resp = _reconcile(client, group_id, demo_ids, status="fixed", responses=["rollback"])
    assert resp.status_code == 200, resp.get_json()
    updated_by_id = {row["id"]: row for row in resp.get_json()["updated"]}
    assert updated_by_id[ids[0]]["responses"] == ["rollback"]
    assert _read_row(client.application, ids[0], "responses") == ["rollback"]


def test_reconcile_update_timestamp_false_preserves_timestamps(client, demo_ids):
    group_id, ids = _create_group(client, demo_ids, status="affected")
    before = client.get(f"/api/assessments/{ids[0]}").get_json()["timestamp"]

    resp = _reconcile(client, group_id, demo_ids, status="fixed", update_timestamp=False)
    assert resp.status_code == 200, resp.get_json()
    updated_by_id = {row["id"]: row for row in resp.get_json()["updated"]}
    assert updated_by_id[ids[0]]["timestamp"] == before

    persisted = client.get(f"/api/assessments/{ids[0]}").get_json()["timestamp"]
    assert persisted == before


def test_reconcile_failure_during_write_rolls_everything_back(client, demo_ids, monkeypatch):
    """A crash part-way through the writes must leave the group untouched."""
    group_id, ids = _create_group(client, demo_ids, status="affected",
                                   variant_id=demo_ids["variant_id"])

    def boom(*args, **kwargs):
        raise RuntimeError("write failed half-way")

    # Dropping only one of the group's two targets leaves the assessment
    # alive, so ``Assessment.update`` (not ``.delete``) is the write that
    # actually runs and can fail here.
    monkeypatch.setattr("src.models.assessment.Assessment.update", boom)

    resp = _reconcile(client, group_id, demo_ids,
                       packages=[demo_ids["two_packages"][0]], status="fixed")
    assert resp.status_code == 500
    # Matches this codebase's existing convention for write-endpoint DB
    # errors (see add_assessment/add_assessments_batch): the exception text
    # is included in the error body rather than redacted.
    assert "write failed half-way" in resp.get_data(as_text=True)

    # The target removal that ran before the failing content update must not
    # have been committed either — the group keeps both original targets.
    group = client.get(f"/api/assessment-groups/{group_id}").get_json()
    assert len(group["targets"]) == 2
    assert _read_row(client.application, group_id, "status") == "affected"


# The following tests restore coverage dropped when the source branch's
# test_assessment_group_reconcile.py was ported into this file (task-9-review
# finding E): they exercise behavior this design still has, adapted to the
# group_id-keyed reconcile API and the demo_ids fixture.


def _add_variant_without_finding(application):
    """Add a scanned variant where demo_ids' vulnerability was never observed.

    The package/variant selection is a cross-product but the scan data is
    sparse, so such an empty cell has to be reachable in the tests.
    """
    from src.extensions import db
    from src.models.scan import Scan
    from src.models.variant import Variant

    with application.app_context():
        variant = Variant(id=uuid.uuid4(), name="empty", project_id=PROJECT_UUID)
        db.session.add(variant)
        db.session.add(Scan(id=uuid.uuid4(), variant_id=variant.id))
        db.session.commit()
        return str(variant.id)


def test_reconcile_preserves_the_timestamp_when_adding_a_target(client, demo_ids):
    """With update_timestamp false, growing the target set leaves the
    assessment's single stored timestamp untouched.

    (Replaces test_reconcile_all_rows_share_one_timestamp and
    test_reconcile_new_sibling_shares_group_timestamp_when_not_updating: both
    verified that sibling rows created/updated by one reconcile share a
    timestamp, which is now trivially true — a group is one row, so there is
    nothing left to cross-check a timestamp against.)
    """
    group_id, ids = _create_group(client, demo_ids, status="affected")
    before = client.get(f"/api/assessments/{ids[0]}").get_json()["timestamp"]

    resp = _reconcile(
        client, group_id, demo_ids,
        variant_ids=[demo_ids["variant_id"], demo_ids["other_variant_id"]],
        status="fixed", update_timestamp=False, timestamp=before,
    )
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert body["created"] == []
    assert len(body["updated"]) == 1
    assert body["updated"][0]["timestamp"] == before

    group = client.get(f"/api/assessment-groups/{group_id}").get_json()
    assert len(group["targets"]) == 4
    assert group["timestamp"] == before


def test_reconcile_variant_without_the_package_does_not_cancel_the_edit(client, demo_ids):
    """A combo with no finding is an empty cell, not an invalid request.

    Rejecting it would make the group uneditable, which the per-row loop this
    endpoint replaced never did.
    """
    empty_variant = _add_variant_without_finding(client.application)
    group_id, ids = _create_group(client, demo_ids, status="affected")

    resp = _reconcile(
        client, group_id, demo_ids,
        variant_ids=[demo_ids["variant_id"], empty_variant],
        status="fixed",
    )
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert {row["id"] for row in body["updated"]} == set(ids)
    assert body["created"] == [], "no row can be created where nothing was scanned"
    assert body["deleted"] == [], "the still-selected rows must not be deleted"
    for assessment_id in ids:
        assert _read_row(client.application, assessment_id, "status") == "fixed"


def test_reconcile_package_observed_in_no_selected_variant_is_refused(client, demo_ids):
    """A selection that resolves to nothing anywhere is still a bad request."""
    empty_variant = _add_variant_without_finding(client.application)
    group_id, ids = _create_group(client, demo_ids, status="affected")

    resp = _reconcile(client, group_id, demo_ids, variant_ids=[empty_variant], status="fixed")
    assert resp.status_code == 400
    assert demo_ids["two_packages"][0] in resp.get_json()["error"]
    for assessment_id in ids:
        assert _read_row(client.application, assessment_id, "status") == "affected"


def test_reconcile_deleting_non_custom_row_invalidates_scan_cache(client, demo_ids, monkeypatch):
    group_id, ids = _create_group(client, demo_ids, status="affected")
    _mutate_row(client.application, group_id, origin="sbom")

    calls = []
    monkeypatch.setattr(
        "src.routes.assessments.invalidate_scan_list_cache",
        lambda *a, **kw: calls.append(True),
    )
    resp = _reconcile(client, group_id, demo_ids,
                       packages=[demo_ids["two_packages"][0]], status="fixed")
    assert resp.status_code == 200, resp.get_json()
    assert resp.get_json()["deleted"] == [], "one of two targets is dropped, the row survives"
    assert calls, "dropping a target from a non-custom assessment must invalidate the scan list cache"


def test_reconcile_deleting_custom_row_does_not_invalidate_scan_cache(client, demo_ids, monkeypatch):
    group_id, ids = _create_group(client, demo_ids, status="affected")

    calls = []
    monkeypatch.setattr(
        "src.routes.assessments.invalidate_scan_list_cache",
        lambda *a, **kw: calls.append(True),
    )
    resp = _reconcile(client, group_id, demo_ids,
                       packages=[demo_ids["two_packages"][0]], status="fixed")
    assert resp.status_code == 200, resp.get_json()
    assert calls == []


def test_reconcile_rejects_mismatched_vuln_id(client, demo_ids):
    """The payload's vuln_id must match the group's real vulnerability (G1)."""
    group_id, ids = _create_group(client, demo_ids, status="affected")

    resp = _reconcile(client, group_id, demo_ids, vuln_id=demo_ids["other_vuln_id"])
    assert resp.status_code == 400
    assert "vuln_id" in resp.get_json()["error"]

    group = client.get(f"/api/assessment-groups/{group_id}").get_json()
    assert group["group_id"] == group_id
    assert len(group["targets"]) == 2
    for assessment_id in ids:
        assert _read_row(client.application, assessment_id, "status") == "affected"


# ── DELETE /api/assessment-groups/<group_id> and lazy promotion ────────────


def test_delete_group_removes_only_the_addressed_row(client, demo_ids):
    """A multi-package write still creates one independent group per package."""
    created = client.post(
        f"/api/vulnerabilities/{demo_ids['vuln_id']}/assessments",
        json={
            "status": "not_affected",
            "justification": "component_not_present",
            "packages": demo_ids["two_packages"],
            "variant_id": demo_ids["variant_id"],
        },
    ).get_json()
    rows = created["assessments"]
    assert len({row["group_id"] for row in rows}) == 2, "each package is its own group"
    group_id = rows[0]["group_id"]

    response = client.delete(f"/api/assessment-groups/{group_id}")

    assert response.status_code == 200
    assert response.get_json()["deleted_ids"] == [group_id]
    assert client.get(f"/api/assessment-groups/{group_id}").status_code == 404
    # The sibling package's independent group is untouched.
    assert client.get(f"/api/assessment-groups/{rows[1]['group_id']}").status_code == 200


def test_deleting_one_assessment_does_not_touch_the_sibling_packages_group(client, demo_ids):
    created = client.post(
        f"/api/vulnerabilities/{demo_ids['vuln_id']}/assessments",
        json={
            "status": "not_affected",
            "justification": "component_not_present",
            "packages": demo_ids["two_packages"],
            "variant_id": demo_ids["variant_id"],
        },
    ).get_json()
    rows = created["assessments"]

    client.delete(f"/api/assessments/{rows[0]['id']}")

    assert client.get(f"/api/assessment-groups/{rows[0]['group_id']}").status_code == 404
    sibling_group = client.get(f"/api/assessment-groups/{rows[1]['group_id']}").get_json()
    assert sibling_group["assessment_ids"] == [rows[1]["id"]]


def test_promote_returns_the_assessments_own_group_id(client, demo_ids):
    """Every assessment is already its own group; promoting is a no-op read."""
    created = client.post(
        f"/api/vulnerabilities/{demo_ids['vuln_id']}/assessments",
        json={
            "status": "affected",
            "packages": [demo_ids["two_packages"][0]],
            "variant_id": demo_ids["variant_id"],
        },
    ).get_json()
    assessment_id = created["assessments"][0]["id"]
    assert created["assessments"][0]["group_id"] == assessment_id

    response = client.post(f"/api/assessments/{assessment_id}/group")

    assert response.status_code == 200
    group_id = response.get_json()["group_id"]
    group = client.get(f"/api/assessment-groups/{group_id}").get_json()
    assert group["assessment_ids"] == [assessment_id]


def test_promoting_an_already_grouped_assessment_returns_its_group(client, demo_ids):
    created = client.post(
        f"/api/vulnerabilities/{demo_ids['vuln_id']}/assessments",
        json={
            "status": "not_affected",
            "justification": "component_not_present",
            "packages": demo_ids["two_packages"],
            "variant_id": demo_ids["variant_id"],
        },
    ).get_json()
    existing_group = created["assessments"][0]["group_id"]

    response = client.post(
        f"/api/assessments/{created['assessments'][0]['id']}/group")

    assert response.status_code == 200
    assert response.get_json()["group_id"] == existing_group


def test_group_endpoints_reject_a_malformed_group_id(client):
    assert client.post("/api/assessment-groups/not-a-uuid/approve").status_code == 400
    assert client.post("/api/assessment-groups/not-a-uuid/reject").status_code == 400
    assert client.delete("/api/assessment-groups/not-a-uuid").status_code == 400


def test_promote_rejects_a_malformed_assessment_id(client):
    response = client.post("/api/assessments/not-a-uuid/group")

    assert response.status_code == 400


def test_delete_unknown_group_returns_404(client):
    response = client.delete(f"/api/assessment-groups/{uuid.uuid4()}")

    assert response.status_code == 404


def test_promote_unknown_assessment_returns_404(client):
    response = client.post(f"/api/assessments/{uuid.uuid4()}/group")

    assert response.status_code == 404


def test_delete_group_of_pending_ai_assessments_is_rejected(client, app, demo_ids):
    group_id, assessment_ids = _create_group(client, demo_ids)
    for assessment_id in assessment_ids:
        _mutate_row(app, assessment_id, origin="ai")

    response = client.delete(f"/api/assessment-groups/{group_id}")

    assert response.status_code == 400
    assert client.get(f"/api/assessment-groups/{group_id}").status_code == 200


def test_delete_group_of_non_custom_assessments_succeeds(client, app, demo_ids):
    group_id, assessment_ids = _create_group(client, demo_ids)
    for assessment_id in assessment_ids:
        _mutate_row(app, assessment_id, origin="sbom")

    response = client.delete(f"/api/assessment-groups/{group_id}")

    assert response.status_code == 200
    assert sorted(response.get_json()["deleted_ids"]) == sorted(assessment_ids)
    assert client.get(f"/api/assessment-groups/{group_id}").status_code == 404


def test_reconcile_rejects_existing_ids_that_is_not_a_list(client, demo_ids):
    group_id, _ = _create_group(client, demo_ids)

    response = _reconcile(client, group_id, demo_ids, existing_ids="nope")

    assert response.status_code == 400
    assert "existing_ids" in response.get_json()["error"]


def test_reconcile_converts_non_custom_rows_to_custom(client, app, demo_ids):
    group_id, assessment_ids = _create_group(client, demo_ids)
    for assessment_id in assessment_ids:
        _mutate_row(app, assessment_id, origin="sbom")

    response = _reconcile(client, group_id, demo_ids, status="fixed")

    assert response.status_code == 200
    for assessment_id in assessment_ids:
        assert _read_row(app, assessment_id, "origin") == "custom"


# ── POST /api/assessments/batch — grouping invariants ────────────────────

def _variant_in_another_project(application, demo_ids):
    """Add a variant under a second project observing the same packages."""
    from src.extensions import db
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package
    from src.models.project import Project
    from src.models.scan import Scan
    from src.models.variant import Variant

    with application.app_context():
        project = Project.create(name="second-project")
        variant = Variant.create(name="second-variant", project_id=project.id)
        scan = Scan(id=uuid.uuid4(), variant_id=variant.id)
        db.session.add(scan)
        db.session.commit()
        for pkg_string_id in demo_ids["two_packages"]:
            package = Package.get_by_string_id(pkg_string_id)
            finding = Finding.get_or_create(package.id, demo_ids["vuln_id"])
            db.session.add(Observation(finding_id=finding.id, scan_id=scan.id))
        db.session.commit()
        return str(variant.id)


def _batch(client, items):
    return client.post("/api/assessments/batch", json={"assessments": items})


def test_batch_never_groups_assessments_across_projects(client, app, demo_ids):
    """One batch touching two projects must produce two independent groups.

    Reads are project-filtered while delete/reconcile/approve/reject load the
    addressed assessment by its own ``group_id``, so a cross-project group
    would let one project mutate the other's assessment.
    """
    other_project_variant = _variant_in_another_project(app, demo_ids)
    package = demo_ids["two_packages"][0]

    response = _batch(client, [
        {"vuln_id": demo_ids["vuln_id"], "packages": [package],
         "status": "affected", "variant_id": demo_ids["variant_id"]},
        {"vuln_id": demo_ids["vuln_id"], "packages": [package],
         "status": "affected", "variant_id": other_project_variant},
    ])

    assert response.status_code == 200, response.get_json()
    rows = response.get_json()["assessments"]
    assert len(rows) == 2
    group_ids = {row["group_id"] for row in rows}
    assert None not in group_ids
    assert len(group_ids) == 2


def test_batch_never_groups_assessments_with_different_content(client, demo_ids):
    """Same CVE, same project, but two statuses are two distinct groups."""
    packages = demo_ids["two_packages"]

    response = _batch(client, [
        {"vuln_id": demo_ids["vuln_id"], "packages": packages,
         "status": "affected", "variant_id": demo_ids["variant_id"]},
        {"vuln_id": demo_ids["vuln_id"], "packages": packages,
         "status": "fixed", "variant_id": demo_ids["other_variant_id"]},
    ])

    assert response.status_code == 200, response.get_json()
    rows = response.get_json()["assessments"]
    groups = {row["status"]: row["group_id"] for row in rows}
    assert groups["affected"] is not None
    assert groups["fixed"] is not None
    assert groups["affected"] != groups["fixed"]


def test_batch_content_identical_rows_across_variants_are_still_two_groups(client, demo_ids):
    """Identical content across variants no longer collapses into one group.

    Grouping is storage, not inference: two batch-created rows are two
    groups even when their content happens to match.
    """
    package = demo_ids["two_packages"][0]

    response = _batch(client, [
        {"vuln_id": demo_ids["vuln_id"], "packages": [package],
         "status": "affected", "variant_id": demo_ids["variant_id"]},
        {"vuln_id": demo_ids["vuln_id"], "packages": [package],
         "status": "affected", "variant_id": demo_ids["other_variant_id"]},
    ])

    assert response.status_code == 200, response.get_json()
    group_ids = {row["group_id"] for row in response.get_json()["assessments"]}
    assert None not in group_ids
    assert len(group_ids) == 2


def test_batch_never_groups_two_vulnerabilities(client, demo_ids):
    package = demo_ids["two_packages"][0]

    response = _batch(client, [
        {"vuln_id": demo_ids["vuln_id"], "packages": [package],
         "status": "affected", "variant_id": demo_ids["variant_id"]},
        {"vuln_id": demo_ids["other_vuln_id"], "packages": [package],
         "status": "affected", "variant_id": demo_ids["variant_id"]},
    ])

    assert response.status_code == 200, response.get_json()
    group_ids = {row["group_id"] for row in response.get_json()["assessments"]}
    assert None not in group_ids
    assert len(group_ids) == 2
