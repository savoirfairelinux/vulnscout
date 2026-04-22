# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for variant enrichment in GET /api/vulnerabilities.

The variant enrichment logic (in src/routes/vulnerabilities.py) populates the
``variants`` field on each returned vulnerability dict.  The fix in commit
4d67a68 ensures that the enrichment reuses the same ``current_scan_ids`` that
were used to select the vulnerabilities, instead of recomputing scan IDs per
variant with ``max(timestamp)`` (which only returned a single scan and could
miss SBOM findings when a tool scan was newer).

These tests verify:
  1. A variant-scoped request with both SBOM and tool scans returns the
     correct ``variants`` list.
  2. A project-scoped request also returns the correct ``variants`` list.
  3. An unscoped request (no variant_id/project_id) returns the correct
     ``variants`` list.
  4. When a tool scan is the newest, SBOM-only findings still appear in the
     variant enrichment (the original bug scenario).
  5. Multiple variants in the same project each appear correctly.
"""

import json
import os
import uuid
from datetime import datetime, timezone, timedelta

import pytest

from src.bin.webapp import create_app
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Database builder
# ---------------------------------------------------------------------------

def _build_variant_enrichment_db(app):
    """Populate a Project with multiple Variants, Scans, and Observations.

    Layout
    ------
    Project "EnrichProject"
      ├─ Variant "alpha"
      │    ├─ Scan S1  (sbom, grype,  t=T)        → Observation for Finding-A
      │    └─ Scan S2  (tool, nvd,    t=T+1h)     → Observation for Finding-B
      └─ Variant "beta"
           └─ Scan S3  (sbom, grype,  t=T)        → Observation for Finding-A

    Packages / Vulnerabilities:
      - Package: cairo@1.16.0
      - Package: libpng@1.6.37
      - Vuln: CVE-2020-35492 → Finding-A (cairo,  CVE-2020-35492)
      - Vuln: CVE-2021-99999 → Finding-B (libpng, CVE-2021-99999)

    Key points:
      - Finding-A is observed in SBOM scans S1 and S3.
      - Finding-B is observed only in tool scan S2.
      - S2 is newer than S1, so under the old buggy logic ``max(timestamp)``
        for variant "alpha" would return only S2, missing Finding-A → the
        ``variants`` list for CVE-2020-35492 would be empty (or missing
        "alpha").
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

    with app.app_context():
        _db.drop_all()
        _db.create_all()

        project = Project.create("EnrichProject")
        variant_alpha = Variant.create("alpha", project.id)
        variant_beta = Variant.create("beta", project.id)

        t0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        # Scans ---------------------------------------------------------
        scan_s1 = Scan(
            description="sbom scan alpha",
            variant_id=variant_alpha.id,
            scan_type="sbom",
            scan_source="grype",
            timestamp=t0,
        )
        _db.session.add(scan_s1)

        scan_s2 = Scan(
            description="tool scan alpha (nvd)",
            variant_id=variant_alpha.id,
            scan_type="tool",
            scan_source="nvd",
            timestamp=t0 + timedelta(hours=1),
        )
        _db.session.add(scan_s2)

        scan_s3 = Scan(
            description="sbom scan beta",
            variant_id=variant_beta.id,
            scan_type="sbom",
            scan_source="grype",
            timestamp=t0,
        )
        _db.session.add(scan_s3)
        _db.session.commit()

        # Packages & Vulns ----------------------------------------------
        pkg_cairo = Package.find_or_create("cairo", "1.16.0")
        pkg_libpng = Package.find_or_create("libpng", "1.6.37")

        vuln_a = Vulnerability.create_record(
            id="CVE-2020-35492", description="cairo vulnerability"
        )
        vuln_b = Vulnerability.create_record(
            id="CVE-2021-99999", description="libpng vulnerability"
        )

        finding_a = Finding.get_or_create(pkg_cairo.id, vuln_a.id)
        finding_b = Finding.get_or_create(pkg_libpng.id, vuln_b.id)
        _db.session.commit()

        # SBOM documents (required for SBOM scans to be meaningful)
        sbom_s1 = SBOMDocument.create("/alpha/sbom.json", "grype", scan_s1.id)
        SBOMPackage.create(sbom_s1.id, pkg_cairo.id)
        sbom_s3 = SBOMDocument.create("/beta/sbom.json", "grype", scan_s3.id)
        SBOMPackage.create(sbom_s3.id, pkg_cairo.id)
        _db.session.commit()

        # Observations (link findings → scans) -------------------------
        # Finding-A in SBOM scans S1 (alpha) and S3 (beta)
        Observation.create(finding_id=finding_a.id, scan_id=scan_s1.id)
        Observation.create(finding_id=finding_a.id, scan_id=scan_s3.id)
        # Finding-B only in tool scan S2 (alpha)
        Observation.create(finding_id=finding_b.id, scan_id=scan_s2.id)
        _db.session.commit()

        return {
            "project_id": str(project.id),
            "variant_alpha_id": str(variant_alpha.id),
            "variant_beta_id": str(variant_beta.id),
            "scan_s1_id": str(scan_s1.id),
            "scan_s2_id": str(scan_s2.id),
            "scan_s3_id": str(scan_s3.id),
            "vuln_a_id": "CVE-2020-35492",
            "vuln_b_id": "CVE-2021-99999",
        }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def app(tmp_path):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
        ids = _build_variant_enrichment_db(application)
        application._test_ids = ids
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def ids(app):
    return app._test_ids


def _vuln_by_id(vulns, vuln_id):
    """Return the vulnerability dict with the given id, or None."""
    for v in vulns:
        if v["id"] == vuln_id:
            return v
    return None


# ---------------------------------------------------------------------------
# Tests — variant-scoped request
# ---------------------------------------------------------------------------

class TestVariantScopedEnrichment:
    """GET /api/vulnerabilities?variant_id=<alpha> must return both vulns
    (from SBOM scan S1 and tool scan S2), each with ``variants`` including
    "alpha".
    """

    def test_both_vulns_returned_for_alpha(self, client, ids):
        """Both CVEs are visible for variant alpha (SBOM + tool scans)."""
        resp = client.get(f"/api/vulnerabilities?variant_id={ids['variant_alpha_id']}")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        returned_ids = {v["id"] for v in data}
        assert ids["vuln_a_id"] in returned_ids, "SBOM finding (CVE-2020-35492) missing"
        assert ids["vuln_b_id"] in returned_ids, "Tool finding (CVE-2021-99999) missing"

    def test_variant_enrichment_for_sbom_vuln(self, client, ids):
        """CVE-2020-35492 (SBOM-only in alpha) has 'alpha' in its variants."""
        resp = client.get(f"/api/vulnerabilities?variant_id={ids['variant_alpha_id']}")
        data = json.loads(resp.data)
        vuln_a = _vuln_by_id(data, ids["vuln_a_id"])
        assert vuln_a is not None
        assert "alpha" in vuln_a["variants"], (
            f"Expected 'alpha' in variants but got {vuln_a['variants']}"
        )

    def test_variant_enrichment_for_tool_vuln(self, client, ids):
        """CVE-2021-99999 (tool scan in alpha) has 'alpha' in its variants."""
        resp = client.get(f"/api/vulnerabilities?variant_id={ids['variant_alpha_id']}")
        data = json.loads(resp.data)
        vuln_b = _vuln_by_id(data, ids["vuln_b_id"])
        assert vuln_b is not None
        assert "alpha" in vuln_b["variants"], (
            f"Expected 'alpha' in variants but got {vuln_b['variants']}"
        )

    def test_beta_only_has_sbom_vuln(self, client, ids):
        """Variant beta only has SBOM scan S3 → only CVE-2020-35492."""
        resp = client.get(f"/api/vulnerabilities?variant_id={ids['variant_beta_id']}")
        data = json.loads(resp.data)
        returned_ids = {v["id"] for v in data}
        assert ids["vuln_a_id"] in returned_ids
        assert ids["vuln_b_id"] not in returned_ids

    def test_beta_variant_name_in_enrichment(self, client, ids):
        """CVE-2020-35492 seen via beta has 'beta' in its variants."""
        resp = client.get(f"/api/vulnerabilities?variant_id={ids['variant_beta_id']}")
        data = json.loads(resp.data)
        vuln_a = _vuln_by_id(data, ids["vuln_a_id"])
        assert vuln_a is not None
        assert "beta" in vuln_a["variants"]


# ---------------------------------------------------------------------------
# Tests — project-scoped request
# ---------------------------------------------------------------------------

class TestProjectScopedEnrichment:
    """GET /api/vulnerabilities?project_id=<id> returns vulns from all
    variants.  The ``variants`` list should reflect which variants have
    each vulnerability.
    """

    def test_all_vulns_from_project(self, client, ids):
        """Both CVEs appear when querying by project."""
        resp = client.get(f"/api/vulnerabilities?project_id={ids['project_id']}")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        returned_ids = {v["id"] for v in data}
        assert ids["vuln_a_id"] in returned_ids
        assert ids["vuln_b_id"] in returned_ids

    def test_vuln_a_has_both_variants(self, client, ids):
        """CVE-2020-35492 is observed in alpha (S1) and beta (S3) →
        variants should contain both names.
        """
        resp = client.get(f"/api/vulnerabilities?project_id={ids['project_id']}")
        data = json.loads(resp.data)
        vuln_a = _vuln_by_id(data, ids["vuln_a_id"])
        assert vuln_a is not None
        assert sorted(vuln_a["variants"]) == ["alpha", "beta"], (
            f"Expected ['alpha', 'beta'] but got {vuln_a['variants']}"
        )

    def test_vuln_b_only_in_alpha(self, client, ids):
        """CVE-2021-99999 is only in tool scan S2 (alpha)."""
        resp = client.get(f"/api/vulnerabilities?project_id={ids['project_id']}")
        data = json.loads(resp.data)
        vuln_b = _vuln_by_id(data, ids["vuln_b_id"])
        assert vuln_b is not None
        assert vuln_b["variants"] == ["alpha"], (
            f"Expected ['alpha'] but got {vuln_b['variants']}"
        )


# ---------------------------------------------------------------------------
# Tests — unscoped request (no variant_id / project_id)
# ---------------------------------------------------------------------------

class TestUnscopedEnrichment:
    """GET /api/vulnerabilities (no filters) should still enrich variants
    correctly by computing active scans for every variant.
    """

    def test_all_vulns_returned(self, client, ids):
        resp = client.get("/api/vulnerabilities")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        returned_ids = {v["id"] for v in data}
        assert ids["vuln_a_id"] in returned_ids
        assert ids["vuln_b_id"] in returned_ids

    def test_vuln_a_has_both_variants_unscoped(self, client, ids):
        resp = client.get("/api/vulnerabilities")
        data = json.loads(resp.data)
        vuln_a = _vuln_by_id(data, ids["vuln_a_id"])
        assert vuln_a is not None
        assert sorted(vuln_a["variants"]) == ["alpha", "beta"]

    def test_vuln_b_only_in_alpha_unscoped(self, client, ids):
        resp = client.get("/api/vulnerabilities")
        data = json.loads(resp.data)
        vuln_b = _vuln_by_id(data, ids["vuln_b_id"])
        assert vuln_b is not None
        assert vuln_b["variants"] == ["alpha"]


# ---------------------------------------------------------------------------
# Tests — the original bug scenario
# ---------------------------------------------------------------------------

class TestToolScanNewerThanSbom:
    """Regression test for the original bug: when the tool scan (S2) is
    newer than the SBOM scan (S1) for a variant, the old code would only
    return S2 via ``max(timestamp)``.  Finding-A, which was observed in
    S1, would have no matching observations and its ``variants`` field
    would be empty.

    With the fix, ``current_scan_ids`` is ``[S1, S2]`` (both the latest
    SBOM and the latest tool scan per source), so Finding-A is included
    and its ``variants`` correctly contains "alpha".
    """

    def test_sbom_finding_not_hidden_by_newer_tool_scan(self, client, ids):
        """CVE-2020-35492 (SBOM finding in S1) is returned and enriched
        with 'alpha' even though tool scan S2 is newer.
        """
        resp = client.get(f"/api/vulnerabilities?variant_id={ids['variant_alpha_id']}")
        data = json.loads(resp.data)
        vuln_a = _vuln_by_id(data, ids["vuln_a_id"])
        assert vuln_a is not None, "SBOM finding CVE-2020-35492 not returned at all"
        assert "alpha" in vuln_a["variants"], (
            f"Variant 'alpha' missing from variants: {vuln_a['variants']}"
        )

    def test_tool_finding_still_present(self, client, ids):
        """CVE-2021-99999 (tool finding in S2) is also returned."""
        resp = client.get(f"/api/vulnerabilities?variant_id={ids['variant_alpha_id']}")
        data = json.loads(resp.data)
        vuln_b = _vuln_by_id(data, ids["vuln_b_id"])
        assert vuln_b is not None, "Tool finding CVE-2021-99999 not returned"
        assert "alpha" in vuln_b["variants"]

    def test_packages_current_includes_sbom_packages(self, client, ids):
        """packages_current for CVE-2020-35492 should include cairo@1.16.0."""
        resp = client.get(f"/api/vulnerabilities?variant_id={ids['variant_alpha_id']}")
        data = json.loads(resp.data)
        vuln_a = _vuln_by_id(data, ids["vuln_a_id"])
        assert vuln_a is not None
        assert "cairo@1.16.0" in vuln_a.get("packages_current", [])


# ---------------------------------------------------------------------------
# Tests — first_scan_date enrichment
# ---------------------------------------------------------------------------

class TestFirstScanDateEnrichment:
    """The first_scan_date field should reflect the earliest scan where the
    vulnerability was observed.
    """

    def test_first_scan_date_for_vuln_a(self, client, ids):
        """CVE-2020-35492 is observed in S1 (t=T) and S3 (t=T), both at
        the same timestamp → first_scan_date = T.
        """
        resp = client.get(f"/api/vulnerabilities?variant_id={ids['variant_alpha_id']}")
        data = json.loads(resp.data)
        vuln_a = _vuln_by_id(data, ids["vuln_a_id"])
        assert vuln_a is not None
        assert vuln_a["first_scan_date"] is not None
        assert "2025-01-01" in vuln_a["first_scan_date"]

    def test_first_scan_date_for_vuln_b(self, client, ids):
        """CVE-2021-99999 is observed in S2 (t=T+1h) → first_scan_date = T+1h."""
        resp = client.get(f"/api/vulnerabilities?variant_id={ids['variant_alpha_id']}")
        data = json.loads(resp.data)
        vuln_b = _vuln_by_id(data, ids["vuln_b_id"])
        assert vuln_b is not None
        assert vuln_b["first_scan_date"] is not None
        assert "2025-01-01" in vuln_b["first_scan_date"]


# ---------------------------------------------------------------------------
# Tests — multiple tool sources on same variant
# ---------------------------------------------------------------------------

class TestMultipleToolSources:
    """When a variant has tool scans from multiple sources (nvd + osv),
    both latest-per-source tool scans plus the latest SBOM scan should
    be included in the active set.
    """

    @pytest.fixture(autouse=True)
    def _add_osv_scan(self, app, ids):
        """Add a second tool scan (osv) to variant alpha, newer than the
        nvd tool scan, with a new observation for a third vulnerability.
        """
        from src.models.scan import Scan
        from src.models.package import Package
        from src.models.vulnerability import Vulnerability
        from src.models.finding import Finding
        from src.models.observation import Observation

        with app.app_context():
            t0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
            scan_osv = Scan(
                description="tool scan alpha (osv)",
                variant_id=uuid.UUID(ids["variant_alpha_id"]),
                scan_type="tool",
                scan_source="osv",
                timestamp=t0 + timedelta(hours=2),
            )
            _db.session.add(scan_osv)
            _db.session.commit()

            pkg_zlib = Package.find_or_create("zlib", "1.2.11")
            vuln_c = Vulnerability.create_record(
                id="CVE-2022-37434", description="zlib vuln"
            )
            finding_c = Finding.get_or_create(pkg_zlib.id, vuln_c.id)
            _db.session.commit()

            Observation.create(finding_id=finding_c.id, scan_id=scan_osv.id)
            _db.session.commit()

            self.scan_osv_id = str(scan_osv.id)
            self.vuln_c_id = "CVE-2022-37434"

    def test_all_three_vulns_for_alpha(self, client, ids):
        """Alpha should now have 3 vulns: SBOM (S1) + NVD (S2) + OSV."""
        resp = client.get(f"/api/vulnerabilities?variant_id={ids['variant_alpha_id']}")
        data = json.loads(resp.data)
        returned_ids = {v["id"] for v in data}
        assert ids["vuln_a_id"] in returned_ids, "SBOM vuln missing"
        assert ids["vuln_b_id"] in returned_ids, "NVD tool vuln missing"
        assert self.vuln_c_id in returned_ids, "OSV tool vuln missing"

    def test_variant_enrichment_all_three(self, client, ids):
        """Each of the three vulns should list 'alpha' in its variants."""
        resp = client.get(f"/api/vulnerabilities?variant_id={ids['variant_alpha_id']}")
        data = json.loads(resp.data)
        for vid in [ids["vuln_a_id"], ids["vuln_b_id"], self.vuln_c_id]:
            vuln = _vuln_by_id(data, vid)
            assert vuln is not None, f"{vid} not found"
            assert "alpha" in vuln["variants"], (
                f"{vid}: 'alpha' missing from {vuln['variants']}"
            )


# ---------------------------------------------------------------------------
# Tests — edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge-case scenarios for variant enrichment."""

    def test_empty_variant_no_crash(self, app):
        """A variant with no scans should return an empty list, not crash."""
        from src.models.variant import Variant

        with app.app_context():
            variant_empty = Variant.create("empty", uuid.UUID(app._test_ids["project_id"]))
            _db.session.commit()
            empty_id = str(variant_empty.id)

        client = app.test_client()
        resp = client.get(f"/api/vulnerabilities?variant_id={empty_id}")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data == []

    def test_invalid_variant_id(self, client):
        """An invalid variant_id returns 400."""
        resp = client.get("/api/vulnerabilities?variant_id=not-a-uuid")
        assert resp.status_code == 400

    def test_invalid_project_id(self, client):
        """An invalid project_id returns 400."""
        resp = client.get("/api/vulnerabilities?project_id=not-a-uuid")
        assert resp.status_code == 400

    def test_nonexistent_variant_id(self, client):
        """A valid UUID that doesn't exist returns empty list."""
        fake_uuid = str(uuid.uuid4())
        resp = client.get(f"/api/vulnerabilities?variant_id={fake_uuid}")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data == []

    def test_dict_format(self, client, ids):
        """format=dict returns a mapping keyed by vuln ID."""
        resp = client.get(
            f"/api/vulnerabilities?variant_id={ids['variant_alpha_id']}&format=dict"
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert isinstance(data, dict)
        assert ids["vuln_a_id"] in data
        assert "alpha" in data[ids["vuln_a_id"]]["variants"]
