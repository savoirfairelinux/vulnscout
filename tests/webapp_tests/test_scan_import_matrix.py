# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Round-trip matrix for scan export -> import.

Every scenario below exports real data through the export endpoints, imports
the result back through ``POST /api/scans/import``, and asserts that what
landed in the destination matches what the source held.  The source fixture
deliberately mixes the awkward cases — SBOM and tool scans, several scan
sources, suppliers in three shapes, an empty scan, unicode and assessments —
so a regression in any one of them fails a named scenario rather than
silently degrading fidelity.
"""

import json
import os
import uuid

import pytest

from src.bin.webapp import create_app
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Source fixture
# ---------------------------------------------------------------------------

def _build_source_db(app):
    """Populate one project with variants covering the interesting shapes.

    Layout
    ------
    MatrixSource
      v-sbom   S1 sbom  : cairo@1.16.0 (no supplier)         -> CVE-A
               S2 sbom  : cairo@1.16.0, libpng@1.6.37 (SPDX  -> CVE-A, CVE-B
                          supplier), zlib@1.2.13 (plain)        + assessments
      v-tool   T1 sbom  : openssl@3.0.0                      -> (no findings)
               T2 tool  : grype                              -> CVE-C
               T3 tool  : nvd                                -> CVE-C, CVE-D
      v-empty  E1 sbom  : no packages, no findings
      v-uni    U1 sbom  : 'café-lib@1.0' unicode name        -> CVE-É
    """
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.assessment import Assessment

    with app.app_context():
        _db.drop_all()
        _db.create_all()

        project = Project.create("MatrixSource")
        v_sbom = Variant.create("v-sbom", project.id)
        v_tool = Variant.create("v-tool", project.id)
        v_empty = Variant.create("v-empty", project.id)
        v_uni = Variant.create("v-uni", project.id)

        cairo = Package.find_or_create("cairo", "1.16.0")
        libpng = Package.find_or_create(
            "libpng", "1.6.37", supplier="Organization: PNG Group (png@example.com)"
        )
        zlib = Package.find_or_create("zlib", "1.2.13", supplier="Zlib Project")
        openssl = Package.find_or_create("openssl", "3.0.0")
        cafe = Package.find_or_create("café-lib", "1.0")

        vulns = {
            key: Vulnerability.create_record(id=vid, description=f"{key} vuln")
            for key, vid in {
                "A": "CVE-2020-35492", "B": "CVE-2019-7317",
                "C": "CVE-2022-0778", "D": "CVE-2023-0464",
                "E": "GHSA-jfh8-c2jp-5v3q",
            }.items()
        }
        f_cairo_a = Finding.get_or_create(cairo.id, vulns["A"].id)
        f_libpng_b = Finding.get_or_create(libpng.id, vulns["B"].id)
        f_zlib_a = Finding.get_or_create(zlib.id, vulns["A"].id)
        f_ssl_c = Finding.get_or_create(openssl.id, vulns["C"].id)
        f_ssl_d = Finding.get_or_create(openssl.id, vulns["D"].id)
        f_cafe_e = Finding.get_or_create(cafe.id, vulns["E"].id)
        _db.session.commit()

        ids = {}

        # -- v-sbom: two SBOM scans, the second adding packages -------------
        s1 = Scan.create("S1", v_sbom.id)
        doc = SBOMDocument.create("/s1/sbom.json", "spdx", s1.id)
        SBOMPackage.create(doc.id, cairo.id)
        Observation.create(finding_id=f_cairo_a.id, scan_id=s1.id)

        s2 = Scan.create("S2", v_sbom.id)
        doc = SBOMDocument.create("/s2/sbom.json", "spdx", s2.id)
        for pkg in (cairo, libpng, zlib):
            SBOMPackage.create(doc.id, pkg.id)
        for finding in (f_cairo_a, f_libpng_b, f_zlib_a):
            Observation.create(finding_id=finding.id, scan_id=s2.id)

        # origin mirrors what a native SBOM scan records; assessments without
        # one are filtered out of every export.
        Assessment.create(
            status="fixed", targets=[(v_sbom.id, f_cairo_a.id)],
            origin="sbom", simplified_status="fixed",
            justification="patched upstream", status_notes="verified",
            impact_statement="", commit=False,
        )
        Assessment.create(
            status="not_affected", targets=[(v_sbom.id, f_libpng_b.id)],
            origin="sbom", simplified_status="not affected",
            justification="component not built", status_notes="",
            impact_statement="not reachable", commit=False,
        )
        ids["sbom_first"] = str(s1.id)
        ids["sbom_second"] = str(s2.id)
        ids["v_sbom"] = str(v_sbom.id)

        # -- v-tool: an SBOM base plus two tool scans from two sources ------
        t1 = Scan.create("T1", v_tool.id)
        doc = SBOMDocument.create("/t1/sbom.json", "spdx", t1.id)
        SBOMPackage.create(doc.id, openssl.id)

        t2 = Scan.create("T2", v_tool.id, scan_type="tool", scan_source="grype")
        Observation.create(finding_id=f_ssl_c.id, scan_id=t2.id)

        t3 = Scan.create("T3", v_tool.id, scan_type="tool", scan_source="nvd")
        Observation.create(finding_id=f_ssl_c.id, scan_id=t3.id)
        Observation.create(finding_id=f_ssl_d.id, scan_id=t3.id)
        ids["tool_sbom_base"] = str(t1.id)
        ids["tool_grype"] = str(t2.id)
        ids["tool_nvd"] = str(t3.id)
        ids["v_tool"] = str(v_tool.id)

        # -- v-empty: a scan that observed nothing --------------------------
        e1 = Scan.create("E1", v_empty.id)
        SBOMDocument.create("/e1/sbom.json", "spdx", e1.id)
        ids["empty"] = str(e1.id)
        ids["v_empty"] = str(v_empty.id)

        # -- v-uni: unicode package name, GHSA-style vulnerability id -------
        u1 = Scan.create("U1", v_uni.id)
        doc = SBOMDocument.create("/u1/sbom.json", "spdx", u1.id)
        SBOMPackage.create(doc.id, cafe.id)
        Observation.create(finding_id=f_cafe_e.id, scan_id=u1.id)
        ids["unicode"] = str(u1.id)
        ids["v_uni"] = str(v_uni.id)

        _db.session.commit()
        ids["project_id"] = str(project.id)
        return ids


@pytest.fixture()
def app(tmp_path):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
        application._test_ids = _build_source_db(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def ids(app):
    return app._test_ids


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_destination(app, name_hint="dest"):
    """Create an empty project/variant and return its (project, variant) names."""
    from src.models.project import Project
    from src.models.variant import Variant

    project_name = f"MatrixDest-{name_hint}-{uuid.uuid4().hex[:8]}"
    with app.app_context():
        project = Project.create(project_name)
        Variant.create("dest-variant", project.id)
    return project_name, "dest-variant"


def _retarget(payload, project_name, variant_name):
    """Point one export, or a list of them, at a destination."""
    entries = payload if isinstance(payload, list) else [payload]
    for entry in entries:
        entry["project_name"] = project_name
        entry["variant_name"] = variant_name
    return payload


def _scan_state(app, scan_id):
    """Return the (package, vulnerability) pairs a scan observed."""
    from src.models.scan import Scan

    with app.app_context():
        scan = _db.session.get(Scan, uuid.UUID(str(scan_id)))
        return {
            (
                obs.finding.package.name,
                obs.finding.package.version,
                obs.finding.vulnerability_id,
            )
            for obs in scan.observations
        }


def _scan_packages(app, scan_id):
    """Return the packages an SBOM scan declares through its documents."""
    from src.models.scan import Scan

    with app.app_context():
        scan = _db.session.get(Scan, uuid.UUID(str(scan_id)))
        return {
            (link.package.name, link.package.version)
            for document in scan.sbom_documents
            for link in document.sbom_packages
        }


def _variant_assessments(app, project_name, variant_name):
    """Return the assessment content attached to a variant."""
    from src.models.assessment import Assessment
    from src.models.assessment_target import AssessmentTarget
    from src.models.project import Project
    from src.models.variant import Variant

    with app.app_context():
        project = Project.get_by_name(project_name)
        variant = Variant.get_by_name_and_project(variant_name, project.id)
        rows = _db.session.execute(
            _db.select(Assessment)
            .join(AssessmentTarget, AssessmentTarget.assessment_id == Assessment.id)
            .where(AssessmentTarget.variant_id == variant.id)
        ).scalars().unique().all()
        return {
            (
                target.finding.vulnerability_id,
                a.status,
                a.simplified_status,
                a.justification or "",
                a.impact_statement or "",
            )
            for a in rows
            for target in a.target_rows
            if target.variant_id == variant.id
        }


def _export(client, path):
    response = client.get(path)
    assert response.status_code == 200, f"{path} -> {response.status_code}"
    return json.loads(response.data)


def _import(client, payload):
    return client.post("/api/scans/import", json=payload)


# ---------------------------------------------------------------------------
# Matrix — single-scan exports round-tripped into an empty destination
# ---------------------------------------------------------------------------

#: (scenario id, source scan key, export endpoint suffix)
SINGLE_SCAN_MATRIX = [
    ("sbom-first/diff", "sbom_first", "export-diff"),
    ("sbom-first/full", "sbom_first", "export-result"),
    ("sbom-later/diff", "sbom_second", "export-diff"),
    ("sbom-later/full", "sbom_second", "export-result"),
    ("tool-sbom-base/diff", "tool_sbom_base", "export-diff"),
    ("tool-sbom-base/full", "tool_sbom_base", "export-result"),
    ("tool-grype/diff", "tool_grype", "export-diff"),
    ("tool-grype/full", "tool_grype", "export-result"),
    ("tool-nvd/diff", "tool_nvd", "export-diff"),
    ("tool-nvd/full", "tool_nvd", "export-result"),
    ("empty-scan/diff", "empty", "export-diff"),
    ("empty-scan/full", "empty", "export-result"),
    ("unicode-ghsa/diff", "unicode", "export-diff"),
    ("unicode-ghsa/full", "unicode", "export-result"),
]


class TestSingleScanRoundTrip:
    """Each export format, for each kind of scan, imports into a clean variant."""

    @pytest.mark.parametrize(
        "scenario, scan_key, endpoint",
        SINGLE_SCAN_MATRIX,
        ids=[row[0] for row in SINGLE_SCAN_MATRIX],
    )
    def test_round_trip(self, app, client, ids, scenario, scan_key, endpoint):
        payload = _export(client, f"/api/scans/{ids[scan_key]}/{endpoint}")
        project_name, variant_name = _fresh_destination(app, scan_key)
        _retarget(payload, project_name, variant_name)

        response = _import(client, payload)

        assert response.status_code == 201, response.get_json()
        body = response.get_json()
        assert body["imported_count"] == 1
        assert body["format"] == ("diff" if endpoint == "export-diff" else "full")

        source_state = _scan_state(app, ids[scan_key])
        imported_state = _scan_state(app, body["scan_id"])

        if endpoint == "export-diff":
            # A diff export carries the scan's own state, so it must survive
            # the round trip exactly.
            assert imported_state == source_state, scenario
        else:
            # A full-result export carries the cumulative state at that scan,
            # which is a superset of what the scan itself observed.
            assert imported_state >= source_state, scenario

        # Counts reported back must match what actually landed.
        assert body["finding_count"] == len(imported_state)
        assert body["vulnerability_count"] == len({v for _n, _ver, v in imported_state})


# ---------------------------------------------------------------------------
# Matrix — supplier shapes survive the round trip
# ---------------------------------------------------------------------------

class TestSupplierFidelity:
    def test_supplier_shapes_round_trip(self, app, client, ids):
        """SPDX-prefixed, plain and absent suppliers all land correctly."""
        from src.models.package import Package
        from src.models.scan import Scan

        payload = _export(client, f"/api/scans/{ids['sbom_second']}/export-diff")
        project_name, variant_name = _fresh_destination(app, "supplier")
        _retarget(payload, project_name, variant_name)

        response = _import(client, payload)
        assert response.status_code == 201

        with app.app_context():
            scan = _db.session.get(Scan, uuid.UUID(response.get_json()["scan_id"]))
            by_name = {
                obs.finding.package.name: obs.finding.package
                for obs in scan.observations
            }
            # Export strips the SPDX prefix and contact address, so the import
            # sees a bare "PNG Group". It must still resolve to the package the
            # destination already has, keeping the richer stored supplier
            # rather than creating a second row.
            assert by_name["libpng"].supplier == "Organization: PNG Group (png@example.com)"
            assert by_name["zlib"].supplier == "Zlib Project"
            assert by_name["cairo"].supplier == ""
            assert len(Package.get_all()) == 5, "import created duplicate packages"

    def test_supplier_shapes_land_intact_in_an_empty_database(self, app, client, ids):
        """Into a destination with no packages, exported suppliers are kept."""
        from src.models.package import Package
        from src.models.scan import Scan

        payload = _export(client, f"/api/scans/{ids['sbom_second']}/export-diff")
        project_name, variant_name = _fresh_destination(app, "supplier-new")
        _retarget(payload, project_name, variant_name)
        # Rename the packages so none of them already exists.
        for group in ("packages", "findings"):
            for row in payload[group]:
                row["package_name"] = f"new-{row['package_name']}"

        response = _import(client, payload)
        assert response.status_code == 201

        with app.app_context():
            scan = _db.session.get(Scan, uuid.UUID(response.get_json()["scan_id"]))
            suppliers = {
                obs.finding.package.name: obs.finding.package.supplier
                for obs in scan.observations
            }
            assert suppliers == {
                "new-cairo": "", "new-libpng": "PNG Group", "new-zlib": "Zlib Project",
            }
            assert len(Package.get_all()) == 8


# ---------------------------------------------------------------------------
# Matrix — batch exports (Export All) at each scope
# ---------------------------------------------------------------------------

BATCH_MATRIX = [
    ("all-scans/diff", "", "diff"),
    ("all-scans/total", "", "total"),
    ("by-project/diff", "project", "diff"),
    ("by-project/total", "project", "total"),
    ("by-variant-sbom/diff", "v_sbom", "diff"),
    ("by-variant-sbom/total", "v_sbom", "total"),
    ("by-variant-tool/diff", "v_tool", "diff"),
    ("by-variant-tool/total", "v_tool", "total"),
    ("by-variant-empty/diff", "v_empty", "diff"),
    ("by-variant-empty/total", "v_empty", "total"),
]


class TestBatchRoundTrip:
    """The Export All download imports as one atomic batch at every scope."""

    @pytest.mark.parametrize(
        "scenario, scope, export_type",
        BATCH_MATRIX,
        ids=[row[0] for row in BATCH_MATRIX],
    )
    def test_batch_round_trip(self, app, client, ids, scenario, scope, export_type):
        if scope == "":
            query = f"type={export_type}"
        elif scope == "project":
            query = f"type={export_type}&project_id={ids['project_id']}"
        else:
            query = f"type={export_type}&variant_id={ids[scope]}"

        payload = _export(client, f"/api/scans/export?{query}")
        assert isinstance(payload, list) and payload, scenario

        project_name, variant_name = _fresh_destination(app, scenario[:12])
        _retarget(payload, project_name, variant_name)

        response = _import(client, payload)

        assert response.status_code == 201, response.get_json()
        body = response.get_json()
        assert body["imported_count"] == len(payload)
        assert len(body["scans"]) == len(payload)
        # Each entry keeps the source scan it came from, so the destination can
        # tell the copies apart.
        assert len({s["source_scan_id"] for s in body["scans"]}) == len(payload)


# ---------------------------------------------------------------------------
# Matrix — assessments
# ---------------------------------------------------------------------------

class TestAssessmentRoundTrip:
    def test_full_result_carries_assessments(self, app, client, ids):
        payload = _export(client, f"/api/scans/{ids['sbom_second']}/export-result")
        assert payload["assessments"], "fixture should export assessments"
        project_name, variant_name = _fresh_destination(app, "assess")
        _retarget(payload, project_name, variant_name)

        response = _import(client, payload)

        assert response.status_code == 201
        assert response.get_json()["assessment_count"] == len(payload["assessments"])
        imported = _variant_assessments(app, project_name, variant_name)
        expected = {
            (
                a["vulnerability_id"], a["status"], a["simplified_status"],
                a["justification"], a["impact_statement"],
            )
            for a in payload["assessments"]
        }
        assert imported == expected

    def test_imported_data_can_be_exported_again(self, app, client, ids):
        """Import -> export -> import keeps packages, findings and assessments.

        An imported row that the export layer filters out (an assessment with
        no origin, say) would leave this second export thinner than the first.
        """
        first = _export(client, f"/api/scans/{ids['sbom_second']}/export-result")
        hop1 = _fresh_destination(app, "hop1")
        _retarget(first, *hop1)
        response = _import(client, first)
        assert response.status_code == 201
        imported_scan_id = response.get_json()["scan_id"]

        # Export the copy straight back out again.
        second = _export(client, f"/api/scans/{imported_scan_id}/export-result")

        assert {(p["package_name"], p["package_version"]) for p in second["packages"]} \
            == {(p["package_name"], p["package_version"]) for p in first["packages"]}
        assert {(f["vulnerability_id"], f["package_name"]) for f in second["findings"]} \
            == {(f["vulnerability_id"], f["package_name"]) for f in first["findings"]}
        assert {a["vulnerability_id"] for a in second["assessments"]} \
            == {a["vulnerability_id"] for a in first["assessments"]}

        # And that re-export imports once more, unchanged.
        hop2 = _fresh_destination(app, "hop2")
        _retarget(second, *hop2)
        third = _import(client, second)
        assert third.status_code == 201
        assert third.get_json()["assessment_count"] == len(first["assessments"])
        assert _variant_assessments(app, *hop2) == _variant_assessments(app, *hop1)

    def test_tool_scan_assessments_keep_their_source_as_origin(self, app, client, ids):
        """An imported tool-scan assessment is labelled with that tool."""
        from src.models.assessment import Assessment
        from src.models.assessment_target import AssessmentTarget
        from src.models.project import Project
        from src.models.variant import Variant

        payload = _export(client, f"/api/scans/{ids['tool_nvd']}/export-result")
        payload["assessments"] = [{
            "vulnerability_id": "CVE-2022-0778", "status": "fixed",
            "simplified_status": "fixed", "justification": "",
            "impact_statement": "", "status_notes": "",
        }]
        project_name, variant_name = _fresh_destination(app, "origin")
        _retarget(payload, project_name, variant_name)

        assert _import(client, payload).status_code == 201

        with app.app_context():
            project = Project.get_by_name(project_name)
            variant = Variant.get_by_name_and_project(variant_name, project.id)
            origins = {
                a.origin for a in _db.session.execute(
                    _db.select(Assessment)
                    .join(AssessmentTarget, AssessmentTarget.assessment_id == Assessment.id)
                    .where(AssessmentTarget.variant_id == variant.id)
                ).scalars().unique().all()
            }
        assert origins == {"nvd"}

    def test_reimport_does_not_duplicate_assessments(self, app, client, ids):
        payload = _export(client, f"/api/scans/{ids['sbom_second']}/export-result")
        project_name, variant_name = _fresh_destination(app, "assess-dup")
        _retarget(payload, project_name, variant_name)

        assert _import(client, payload).status_code == 201
        before = _variant_assessments(app, project_name, variant_name)

        # A genuinely different scan restating the same assessments: the scan
        # is new, the assessments are not.
        again = dict(
            payload, scan_id=str(uuid.uuid4()),
            timestamp="2027-03-04T05:06:07+00:00",
        )
        second = _import(client, again)

        assert second.status_code == 201
        assert second.get_json()["assessment_count"] == 0
        assert _variant_assessments(app, project_name, variant_name) == before


# ---------------------------------------------------------------------------
# Matrix — destination states
# ---------------------------------------------------------------------------

class TestDestinationStates:
    def test_import_into_populated_variant_appends(self, app, client, ids):
        """Importing beside existing scans adds to the timeline, not over it."""
        from src.models.scan import Scan
        from src.models.project import Project
        from src.models.variant import Variant

        first = _export(client, f"/api/scans/{ids['sbom_first']}/export-diff")
        second = _export(client, f"/api/scans/{ids['sbom_second']}/export-diff")
        project_name, variant_name = _fresh_destination(app, "populated")
        _retarget(first, project_name, variant_name)
        _retarget(second, project_name, variant_name)

        assert _import(client, first).status_code == 201
        response = _import(client, second)
        assert response.status_code == 201
        assert response.get_json()["is_first"] is False

        with app.app_context():
            project = Project.get_by_name(project_name)
            variant = Variant.get_by_name_and_project(variant_name, project.id)
            assert len(Scan.get_by_variant_id(variant.id)) == 2

    def test_reimport_into_same_variant_is_skipped(self, app, client, ids):
        payload = _export(client, f"/api/scans/{ids['sbom_first']}/export-diff")
        project_name, variant_name = _fresh_destination(app, "dup")
        _retarget(payload, project_name, variant_name)

        assert _import(client, payload).status_code == 201
        duplicate = _import(client, payload)

        assert duplicate.status_code == 201
        assert duplicate.get_json()["imported_count"] == 0
        assert duplicate.get_json()["skipped_count"] == 1

    def test_import_skips_existing_scans_and_adds_new_ones(self, app, client, ids):
        from src.models.project import Project
        from src.models.scan import Scan
        from src.models.variant import Variant

        payload = _export(client, f"/api/scans/export?type=diff&variant_id={ids['v_tool']}")
        project_name, variant_name = _fresh_destination(app, "overlap")
        _retarget(payload, project_name, variant_name)

        assert _import(client, payload[:2]).status_code == 201
        response = _import(client, payload)

        assert response.status_code == 201
        assert response.get_json()["imported_count"] == 1
        assert response.get_json()["skipped_count"] == 2
        with app.app_context():
            project = Project.get_by_name(project_name)
            variant = Variant.get_by_name_and_project(variant_name, project.id)
            assert len(Scan.get_by_variant_id(variant.id)) == 3

    def test_same_export_into_two_variants_is_allowed(self, app, client, ids):
        """The duplicate guard is per destination variant, not global."""
        payload = _export(client, f"/api/scans/{ids['sbom_first']}/export-diff")
        first_project, first_variant = _fresh_destination(app, "vA")
        second_project, second_variant = _fresh_destination(app, "vB")

        assert _import(
            client, _retarget(dict(payload), first_project, first_variant)
        ).status_code == 201
        assert _import(
            client, _retarget(dict(payload), second_project, second_variant)
        ).status_code == 201

    def test_import_back_into_the_source_variant_is_skipped(self, app, client, ids):
        """Re-importing an export where it came from does not add a scan."""
        payload = _export(client, f"/api/scans/{ids['sbom_first']}/export-diff")

        response = _import(client, payload)

        assert response.status_code == 201
        assert response.get_json()["imported_count"] == 0
        assert response.get_json()["skipped_count"] == 1


# ---------------------------------------------------------------------------
# Matrix — rejection cases, none of which may write anything
# ---------------------------------------------------------------------------

class TestRejectionsLeaveNothingBehind:
    @pytest.mark.parametrize("scenario, mutate, status", [
        ("missing-project", lambda p: p.update({"project_name": "Nope"}), 404),
        ("missing-variant", lambda p: p.update({"variant_name": "Nope"}), 404),
        ("bad-scan-id", lambda p: p.update({"scan_id": "not-a-uuid"}), 400),
        ("bad-timestamp", lambda p: p.update({"timestamp": "yesterday"}), 400),
        ("bad-version", lambda p: p.update({"export_version": 99}), 400),
        ("bad-format", lambda p: p.update({"export_format": "something"}), 400),
        ("findings-not-array", lambda p: p.update({"findings": {}}), 400),
        ("packages-not-array", lambda p: p.update({"packages": "no"}), 400),
        ("finding-not-object", lambda p: p.update({"findings": ["x"]}), 400),
        ("finding-missing-name",
         lambda p: p.update({"findings": [{"vulnerability_id": "CVE-1"}]}), 400),
        ("assessment-unmatched",
         lambda p: p.update({"assessments": [
             {"vulnerability_id": "CVE-9999-1", "status": "fixed"}]}), 400),
        ("assessment-missing-status",
         lambda p: p.update({"assessments": [{"vulnerability_id": "CVE-1"}]}), 400),
    ], ids=lambda v: v if isinstance(v, str) else "")
    def test_rejection(self, app, client, ids, scenario, mutate, status):
        from src.models.scan import Scan

        payload = _export(client, f"/api/scans/{ids['sbom_second']}/export-diff")
        project_name, variant_name = _fresh_destination(app, "reject")
        _retarget(payload, project_name, variant_name)
        mutate(payload)

        with app.app_context():
            before = len(Scan.get_all())

        response = _import(client, payload)

        assert response.status_code == status, (scenario, response.get_json())
        assert response.get_json()["error"]
        with app.app_context():
            assert len(Scan.get_all()) == before, f"{scenario} wrote to the database"

    def test_bad_entry_in_batch_rolls_the_whole_batch_back(self, app, client, ids):
        from src.models.scan import Scan

        payload = _export(client, f"/api/scans/export?type=diff&variant_id={ids['v_sbom']}")
        project_name, variant_name = _fresh_destination(app, "batchfail")
        _retarget(payload, project_name, variant_name)
        payload[-1]["timestamp"] = "not-a-timestamp"

        with app.app_context():
            before = len(Scan.get_all())

        response = _import(client, payload)

        assert response.status_code == 400
        assert f"Export #{len(payload)} of {len(payload)}" in response.get_json()["error"]
        with app.app_context():
            assert len(Scan.get_all()) == before


# ---------------------------------------------------------------------------
# Matrix — format compatibility
# ---------------------------------------------------------------------------

class TestFormatCompatibility:
    def test_legacy_full_result_without_version_markers(self, app, client, ids):
        payload = _export(client, f"/api/scans/{ids['sbom_second']}/export-result")
        payload.pop("export_version")
        payload.pop("export_format")
        project_name, variant_name = _fresh_destination(app, "legacy")
        _retarget(payload, project_name, variant_name)

        response = _import(client, payload)

        assert response.status_code == 201
        assert response.get_json()["format"] == "full"

    def test_single_object_and_single_element_array_agree(self, app, client, ids):
        payload = _export(client, f"/api/scans/{ids['sbom_first']}/export-diff")
        as_object_dest = _fresh_destination(app, "obj")
        as_array_dest = _fresh_destination(app, "arr")

        object_response = _import(
            client, _retarget(dict(payload), *as_object_dest)
        )
        array_response = _import(
            client, [_retarget(dict(payload), *as_array_dest)]
        )

        assert object_response.status_code == array_response.status_code == 201
        for key in ("format", "imported_count", "package_count", "finding_count"):
            assert object_response.get_json()[key] == array_response.get_json()[key]

    def test_scan_type_and_source_survive_the_round_trip(self, app, client, ids):
        """A tool scan stays a tool scan of the same source after import."""
        from src.models.scan import Scan

        payload = _export(client, f"/api/scans/{ids['tool_nvd']}/export-diff")
        project_name, variant_name = _fresh_destination(app, "kind")
        _retarget(payload, project_name, variant_name)

        response = _import(client, payload)

        assert response.status_code == 201
        with app.app_context():
            scan = _db.session.get(Scan, uuid.UUID(response.get_json()["scan_id"]))
            assert scan.scan_type == "tool"
            assert scan.scan_source == "nvd"
            assert scan.timestamp.isoformat().startswith(payload["timestamp"][:19])

    def test_sbom_import_registers_its_packages_as_a_document(self, app, client, ids):
        """SBOM scans expose packages through a document; tool scans do not."""
        from src.models.scan import Scan

        sbom = _export(client, f"/api/scans/{ids['sbom_second']}/export-diff")
        tool = _export(client, f"/api/scans/{ids['tool_grype']}/export-diff")
        sbom_dest = _fresh_destination(app, "doc-sbom")
        tool_dest = _fresh_destination(app, "doc-tool")

        sbom_response = _import(client, _retarget(sbom, *sbom_dest))
        tool_response = _import(client, _retarget(tool, *tool_dest))

        assert sbom_response.status_code == tool_response.status_code == 201
        assert _scan_packages(app, sbom_response.get_json()["scan_id"]) == {
            ("cairo", "1.16.0"), ("libpng", "1.6.37"), ("zlib", "1.2.13"),
        }
        with app.app_context():
            scan = _db.session.get(Scan, uuid.UUID(tool_response.get_json()["scan_id"]))
            assert scan.sbom_documents == []


# ---------------------------------------------------------------------------
# Matrix — full instance migration, the flow the feature exists for
# ---------------------------------------------------------------------------

class TestWholeInstanceMigration:
    @pytest.mark.parametrize("export_type", ["diff", "total"])
    def test_export_everything_then_import_into_a_new_instance(
        self, app, client, ids, export_type
    ):
        """Export every scan, import each variant's slice into a fresh copy."""
        from src.models.project import Project
        from src.models.variant import Variant
        from src.models.scan import Scan

        payload = _export(client, f"/api/scans/export?type={export_type}")
        source_variants = {
            (entry["project_name"], entry["variant_name"]) for entry in payload
        }
        assert len(source_variants) == 4  # v-sbom, v-tool, v-empty, v-uni

        # Recreate the source layout under a new project name.
        destination = f"MatrixMigrated-{export_type}-{uuid.uuid4().hex[:6]}"
        with app.app_context():
            project = Project.create(destination)
            for _project_name, variant_name in sorted(source_variants):
                Variant.create(variant_name, project.id)
        for entry in payload:
            entry["project_name"] = destination

        response = _import(client, payload)

        assert response.status_code == 201, response.get_json()
        assert response.get_json()["imported_count"] == len(payload)

        with app.app_context():
            project = Project.get_by_name(destination)
            migrated = [
                scan
                for variant in Variant.get_by_project(project.id)
                for scan in Scan.get_by_variant_id(variant.id)
            ]
            assert len(migrated) == len(payload)
            # Every scan kept its type and source.
            assert (
                sorted((s.scan_type, s.scan_source) for s in migrated)
                == sorted(
                    (
                        "tool" if e["scan_type"] == "vulnerability_scan" else "sbom",
                        e.get("scan_source"),
                    )
                    for e in payload
                )
            )
