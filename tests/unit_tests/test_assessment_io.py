# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Unit tests for assessment_io.py helper functions."""

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from src.helpers.assessment_io import (
    is_openvex_doc,
    sanitize_variant_name,
    _get_vuln_info,
    build_variant_by_name_map,
    build_openvex_doc,
    build_custom_data_export,
    import_statements,
    import_custom_data,
)


# ---------------------------------------------------------------------------
# is_openvex_doc() tests
# ---------------------------------------------------------------------------

class TestIsOpenvexDoc:
    """Test is_openvex_doc validator."""

    def test_valid_openvex_doc(self):
        """GIVEN a valid OpenVEX document WHEN validated THEN return True."""
        doc = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [],
        }
        assert is_openvex_doc(doc) is True

    def test_openvex_doc_with_url_list(self):
        """GIVEN a valid OpenVEX document with list context WHEN validated THEN return True."""
        doc = {
            "@context": ["https://openvex.dev/ns/v0.2.0"],
            "statements": [],
        }
        assert is_openvex_doc(doc) is True

    def test_non_dict_input(self):
        """GIVEN a non-dict input WHEN validated THEN return False."""
        assert is_openvex_doc("not a dict") is False
        assert is_openvex_doc([]) is False
        assert is_openvex_doc(None) is False
        assert is_openvex_doc(42) is False

    def test_missing_context(self):
        """GIVEN a dict without @context WHEN validated THEN return False."""
        doc = {"statements": []}
        assert is_openvex_doc(doc) is False

    def test_missing_statements(self):
        """GIVEN a dict without statements key WHEN validated THEN return False."""
        doc = {"@context": "https://openvex.dev/ns/v0.2.0"}
        assert is_openvex_doc(doc) is False

    def test_statements_not_list(self):
        """GIVEN a doc with non-list statements WHEN validated THEN return False."""
        doc = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": "not a list",
        }
        assert is_openvex_doc(doc) is False

    def test_context_without_openvex(self):
        """GIVEN a doc with @context missing 'openvex' WHEN validated THEN return False."""
        doc = {
            "@context": "https://example.com/ns/v1.0",
            "statements": [],
        }
        assert is_openvex_doc(doc) is False

    def test_empty_context_string(self):
        """GIVEN a doc with empty @context WHEN validated THEN return False."""
        doc = {
            "@context": "",
            "statements": [],
        }
        assert is_openvex_doc(doc) is False


# ---------------------------------------------------------------------------
# sanitize_variant_name() tests
# ---------------------------------------------------------------------------

class TestSanitizeVariantName:
    """Test sanitize_variant_name function."""

    def test_forward_slash_replaced(self):
        """GIVEN a name with forward slashes WHEN sanitized THEN slashes become underscores."""
        assert sanitize_variant_name("my/variant") == "my_variant"
        assert sanitize_variant_name("/root/path") == "_root_path"

    def test_backslash_replaced(self):
        """GIVEN a name with backslashes WHEN sanitized THEN backslashes become underscores."""
        assert sanitize_variant_name("my\\variant") == "my_variant"
        assert sanitize_variant_name("\\root\\path") == "_root_path"

    def test_both_slashes_replaced(self):
        """GIVEN a name with both forward and backslashes WHEN sanitized THEN both become underscores."""
        assert sanitize_variant_name("my/variant\\name") == "my_variant_name"

    def test_normal_name_unchanged(self):
        """GIVEN a normal variant name WHEN sanitized THEN it remains unchanged."""
        assert sanitize_variant_name("my-variant-1.0") == "my-variant-1.0"
        assert sanitize_variant_name("variant_name") == "variant_name"
        assert sanitize_variant_name("VariantName") == "VariantName"

    def test_empty_string(self):
        """GIVEN an empty string WHEN sanitized THEN it remains empty."""
        assert sanitize_variant_name("") == ""

    def test_only_slashes(self):
        """GIVEN a string with only slashes WHEN sanitized THEN all become underscores."""
        assert sanitize_variant_name("/") == "_"
        assert sanitize_variant_name("\\") == "_"
        assert sanitize_variant_name("///") == "___"


# ---------------------------------------------------------------------------
# _get_vuln_info() tests
# ---------------------------------------------------------------------------

class TestGetVulnInfo:
    """Test _get_vuln_info helper."""

    def test_vuln_not_in_cache(self):
        """GIVEN a vuln_id not in cache WHEN fetched THEN db is queried and cache updated."""
        cache = {}
        
        # Mock the Vulnerability model
        mock_vuln = mock.MagicMock()
        mock_vuln.description = "Test CVE description"
        mock_vuln.aliases = ["ALIAS-1", "ALIAS-2"]
        mock_vuln.urls = ["https://example.com/cve"]
        mock_vuln.links = None
        
        with mock.patch(
            "src.models.vulnerability.Vulnerability.get_by_id",
            return_value=mock_vuln
        ):
            result = _get_vuln_info("CVE-2021-1234", cache)
        
        assert result["description"] == "Test CVE description"
        assert result["aliases"] == ["ALIAS-1", "ALIAS-2"]
        assert result["url"] == "https://example.com/cve"
        assert "CVE-2021-1234" in cache

    def test_vuln_not_found_cve(self):
        """GIVEN a CVE that doesn't exist WHEN fetched THEN return empty strings."""
        cache = {}
        with mock.patch(
            "src.models.vulnerability.Vulnerability.get_by_id",
            return_value=None
        ):
            result = _get_vuln_info("CVE-2021-9999", cache)
        
        assert result["description"] == ""
        assert result["aliases"] == []
        assert result["url"] == ""

    def test_vuln_not_found_ghsa(self):
        """GIVEN a GHSA that doesn't exist WHEN fetched THEN return empty strings."""
        cache = {}
        with mock.patch(
            "src.models.vulnerability.Vulnerability.get_by_id",
            return_value=None
        ):
            result = _get_vuln_info("GHSA-xxxx-yyyy-zzzz", cache)
        
        assert result["description"] == ""
        assert result["aliases"] == []
        assert result["url"] == ""

    def test_vuln_not_found_unknown_type(self):
        """GIVEN an unknown vuln ID that doesn't exist WHEN fetched THEN no URL."""
        cache = {}
        with mock.patch(
            "src.models.vulnerability.Vulnerability.get_by_id",
            return_value=None
        ):
            result = _get_vuln_info("UNKNOWN-2021-1234", cache)
        
        assert result["description"] == ""
        assert result["aliases"] == []
        assert result["url"] == ""

    def test_vuln_with_links_fallback(self):
        """GIVEN a vuln with links instead of urls WHEN fetched THEN use links."""
        cache = {}
        
        mock_vuln = mock.MagicMock()
        mock_vuln.description = "Test vulnerability"
        mock_vuln.aliases = None
        mock_vuln.urls = None
        mock_vuln.links = ["https://example.com/link"]
        
        with mock.patch(
            "src.models.vulnerability.Vulnerability.get_by_id",
            return_value=mock_vuln
        ):
            result = _get_vuln_info("CVE-2021-1234", cache)
        
        assert result["url"] == "https://example.com/link"
        assert result["aliases"] == []

    def test_vuln_cached_on_second_call(self):
        """GIVEN a cached vuln WHEN fetched again THEN db is not queried."""
        with mock.patch(
            "src.models.vulnerability.Vulnerability.get_by_id",
            return_value=None
        ) as mock_get:
            cache = {"CVE-2021-1234": None}
            result = _get_vuln_info("CVE-2021-1234", cache)
        
            # Should not call get_by_id since it's in cache
            mock_get.assert_not_called()
            assert result["url"] == ""


# ---------------------------------------------------------------------------
# build_variant_by_name_map() tests
# ---------------------------------------------------------------------------

class TestBuildVariantByNameMap:
    """Test build_variant_by_name_map function."""

    def test_returns_dict(self):
        """GIVEN a project_id WHEN building map THEN return dict."""
        mock_variant = mock.MagicMock()
        mock_variant.name = "test-variant"
        mock_variant.id = "test-id"
        
        with mock.patch(
            "src.models.variant.Variant.get_by_project",
            return_value=[mock_variant]
        ):
            import uuid
            project_id = uuid.uuid4()
            result = build_variant_by_name_map(project_id)
        
        assert isinstance(result, dict)
        assert "test-variant" in result

    def test_includes_sanitized_name(self):
        """GIVEN a variant with special characters WHEN building map THEN include both names."""
        mock_variant = mock.MagicMock()
        mock_variant.name = "my/variant"
        mock_variant.id = "test-id"
        
        with mock.patch(
            "src.models.variant.Variant.get_by_project",
            return_value=[mock_variant]
        ):
            import uuid
            project_id = uuid.uuid4()
            result = build_variant_by_name_map(project_id)
        
        # Should have both the original and sanitized names
        assert "my/variant" in result
        assert "my_variant" in result

    def test_all_variants_when_no_project_id(self):
        """GIVEN no project_id WHEN building map THEN fetch all variants."""
        mock_variant = mock.MagicMock()
        mock_variant.name = "global-variant"
        mock_variant.id = "test-id"
        
        with mock.patch(
            "src.models.variant.Variant.get_all",
            return_value=[mock_variant]
        ):
            result = build_variant_by_name_map(None)
        
        assert "global-variant" in result


# ---------------------------------------------------------------------------
# _get_vuln_info() — fallback URL branches
# ---------------------------------------------------------------------------

class TestGetVulnInfoFallbackUrls:
    """Test the CVE/GHSA fallback URL logic inside _get_vuln_info."""

    def _mock_vuln(self, **kwargs):
        v = mock.MagicMock()
        v.description = kwargs.get("description", "")
        v.aliases = kwargs.get("aliases", [])
        v.urls = kwargs.get("urls", None)
        v.links = kwargs.get("links", None)
        return v

    def test_cve_with_no_url_gets_nvd_fallback(self):
        """GIVEN a CVE that exists but has empty urls and links WHEN fetched THEN NVD URL."""
        cache = {}
        vuln = self._mock_vuln(urls=[], links=[])
        with mock.patch("src.models.vulnerability.Vulnerability.get_by_id", return_value=vuln):
            result = _get_vuln_info("CVE-2021-1234", cache)
        assert result["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2021-1234"

    def test_cve_with_none_urls_and_none_links_gets_nvd_fallback(self):
        """GIVEN a CVE with urls=None and links=None WHEN fetched THEN NVD URL."""
        cache = {}
        vuln = self._mock_vuln(urls=None, links=None)
        with mock.patch("src.models.vulnerability.Vulnerability.get_by_id", return_value=vuln):
            result = _get_vuln_info("CVE-2099-0001", cache)
        assert result["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2099-0001"

    def test_ghsa_with_no_url_gets_github_fallback(self):
        """GIVEN a GHSA that exists but has no URLs WHEN fetched THEN GitHub URL."""
        cache = {}
        vuln = self._mock_vuln(urls=[], links=[])
        with mock.patch("src.models.vulnerability.Vulnerability.get_by_id", return_value=vuln):
            result = _get_vuln_info("GHSA-ABCD-1234-XY78", cache)
        assert result["url"] == "https://github.com/advisories/GHSA-ABCD-1234-XY78"

    def test_vuln_with_url_in_urls_list(self):
        """GIVEN a vuln with a non-empty urls list WHEN fetched THEN first URL is returned."""
        cache = {}
        vuln = self._mock_vuln(urls=["https://example.com/first", "https://example.com/second"])
        with mock.patch("src.models.vulnerability.Vulnerability.get_by_id", return_value=vuln):
            result = _get_vuln_info("CVE-2021-9999", cache)
        assert result["url"] == "https://example.com/first"


# ---------------------------------------------------------------------------
# build_openvex_doc() tests
# ---------------------------------------------------------------------------

_EMPTY_VULN_INFO = {"description": "", "aliases": [], "url": ""}


class TestBuildOpenvexDoc:
    """Unit tests for build_openvex_doc."""

    def test_empty_assessments_produces_empty_statements(self):
        """GIVEN no assessments WHEN building doc THEN statements list is empty."""
        doc = build_openvex_doc([], "test-author")
        assert doc["statements"] == []
        assert doc["author"] == "test-author"
        assert "openvex" in doc["@context"]

    def test_custom_now_iso_used(self):
        """GIVEN a custom now_iso WHEN building doc THEN timestamp equals it."""
        doc = build_openvex_doc([], "author", now_iso="2025-06-01T00:00:00Z")
        assert doc["timestamp"] == "2025-06-01T00:00:00Z"

    def test_assessment_with_none_to_openvex_dict_is_skipped(self):
        """GIVEN assessment whose to_openvex_dict returns None WHEN building doc THEN skipped."""
        assess = mock.MagicMock()
        assess.to_openvex_dict.return_value = None
        with mock.patch("src.helpers.assessment_io._get_vuln_info", return_value=_EMPTY_VULN_INFO):
            doc = build_openvex_doc([assess], "author")
        assert doc["statements"] == []

    def test_product_without_at_sign(self):
        """GIVEN a package string with no '@' WHEN building doc THEN version is empty string."""
        assess = mock.MagicMock()
        assess.to_openvex_dict.return_value = {"status": "affected"}
        assess.vuln_id = "CVE-2021-1234"
        assess.packages = ["libfoo"]
        assess.source = "scanner"
        assess.origin = "scanner"
        with mock.patch("src.helpers.assessment_io._get_vuln_info", return_value=_EMPTY_VULN_INFO):
            doc = build_openvex_doc([assess], "author")
        stmt = doc["statements"][0]
        assert len(stmt["products"]) == 1
        prod = stmt["products"][0]
        assert prod["@id"] == "libfoo"
        assert "libfoo" in prod["identifiers"]["purl"]
        assert prod["identifiers"]["purl"].endswith("@")

    def test_product_with_at_sign(self):
        """GIVEN a package string with '@' WHEN building doc THEN name and version split correctly."""
        assess = mock.MagicMock()
        assess.to_openvex_dict.return_value = {"status": "fixed"}
        assess.vuln_id = "CVE-2021-5678"
        assess.packages = ["mylib@2.0.1"]
        assess.source = "scanner"
        assess.origin = "scanner"
        with mock.patch("src.helpers.assessment_io._get_vuln_info", return_value=_EMPTY_VULN_INFO):
            doc = build_openvex_doc([assess], "author")
        prod = doc["statements"][0]["products"][0]
        assert prod["@id"] == "mylib@2.0.1"
        assert "mylib" in prod["identifiers"]["cpe23"]
        assert "2.0.1" in prod["identifiers"]["cpe23"]

    def test_none_source_and_origin_default_to_local_user_data(self):
        """GIVEN assessment with None source and origin WHEN building doc THEN scanners contains default."""
        assess = mock.MagicMock()
        assess.to_openvex_dict.return_value = {"status": "under_investigation"}
        assess.vuln_id = "CVE-2021-0001"
        assess.packages = ["pkg@1.0"]
        assess.source = None
        assess.origin = None
        with mock.patch("src.helpers.assessment_io._get_vuln_info", return_value=_EMPTY_VULN_INFO):
            doc = build_openvex_doc([assess], "author")
        scanners = doc["statements"][0]["scanners"]
        assert "local_user_data" in scanners

    def test_vuln_cache_reused_across_assessments(self):
        """GIVEN shared vuln_cache WHEN building doc THEN DB queried only once per vuln_id."""
        cache = {}
        assess1 = mock.MagicMock()
        assess1.to_openvex_dict.return_value = {"status": "affected"}
        assess1.vuln_id = "CVE-2021-1111"
        assess1.packages = ["pkg@1.0"]
        assess1.source = "s"
        assess1.origin = "o"
        assess2 = mock.MagicMock()
        assess2.to_openvex_dict.return_value = {"status": "fixed"}
        assess2.vuln_id = "CVE-2021-1111"
        assess2.packages = ["pkg@2.0"]
        assess2.source = "s"
        assess2.origin = "o"
        with mock.patch("src.models.vulnerability.Vulnerability.get_by_id", return_value=None) as mock_get:
            build_openvex_doc([assess1, assess2], "author", vuln_cache=cache)
        # Queried only once because cache is reused
        mock_get.assert_called_once_with("CVE-2021-1111")

    def test_action_statement_timestamp_default_added(self):
        """GIVEN assessment whose dict lacks action_statement_timestamp WHEN building doc THEN default added."""
        assess = mock.MagicMock()
        assess.to_openvex_dict.return_value = {"status": "not_affected"}
        assess.vuln_id = "CVE-2021-0002"
        assess.packages = ["pkg@1.0"]
        assess.source = "s"
        assess.origin = "o"
        with mock.patch("src.helpers.assessment_io._get_vuln_info", return_value=_EMPTY_VULN_INFO):
            doc = build_openvex_doc([assess], "author")
        assert "action_statement_timestamp" in doc["statements"][0]

    def _make_assessment(self, vuln_id, pkg, ts):
        assess = mock.MagicMock()
        assess.to_openvex_dict.return_value = {"status": "affected", "timestamp": ts}
        assess.vuln_id = vuln_id
        assess.packages = [pkg]
        assess.source = "s"
        assess.origin = "o"
        return assess

    def test_statements_ordered_by_assessment_date(self):
        """GIVEN assessments in arbitrary order WHEN building doc THEN statements sorted by date."""
        a_new = self._make_assessment("CVE-2021-0003", "pkg@1.0", "2025-03-01T00:00:00+00:00")
        a_old = self._make_assessment("CVE-2021-0001", "pkg@1.0", "2025-01-01T00:00:00+00:00")
        a_mid = self._make_assessment("CVE-2021-0002", "pkg@1.0", "2025-02-01T00:00:00+00:00")
        with mock.patch("src.helpers.assessment_io._get_vuln_info", return_value=_EMPTY_VULN_INFO):
            doc = build_openvex_doc([a_new, a_old, a_mid], "author")
        names = [s["vulnerability"]["name"] for s in doc["statements"]]
        assert names == ["CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003"]

    def test_equal_dates_ordered_by_vuln_then_package(self):
        """GIVEN assessments with equal dates WHEN building doc THEN tie-broken deterministically."""
        ts = "2025-01-01T00:00:00+00:00"
        a_b = self._make_assessment("CVE-2021-0002", "zlib@1.0", ts)
        a_a2 = self._make_assessment("CVE-2021-0001", "zlib@2.0", ts)
        a_a1 = self._make_assessment("CVE-2021-0001", "zlib@1.0", ts)
        with mock.patch("src.helpers.assessment_io._get_vuln_info", return_value=_EMPTY_VULN_INFO):
            doc = build_openvex_doc([a_b, a_a2, a_a1], "author")
        keys = [
            (s["vulnerability"]["name"], s["products"][0]["@id"])
            for s in doc["statements"]
        ]
        assert keys == [
            ("CVE-2021-0001", "zlib@1.0"),
            ("CVE-2021-0001", "zlib@2.0"),
            ("CVE-2021-0002", "zlib@1.0"),
        ]

    def test_ordering_independent_of_input_order(self):
        """GIVEN the same assessments in two different orders THEN identical output ordering."""
        specs = [
            ("CVE-2021-0003", "pkg@1.0", "2025-03-01T00:00:00+00:00"),
            ("CVE-2021-0001", "pkg@1.0", "2025-01-01T00:00:00+00:00"),
            ("CVE-2021-0002", "pkg@1.0", "2025-02-01T00:00:00+00:00"),
        ]
        with mock.patch("src.helpers.assessment_io._get_vuln_info", return_value=_EMPTY_VULN_INFO):
            doc1 = build_openvex_doc(
                [self._make_assessment(*s) for s in specs], "author"
            )
            doc2 = build_openvex_doc(
                [self._make_assessment(*s) for s in reversed(specs)], "author"
            )
        names1 = [s["vulnerability"]["name"] for s in doc1["statements"]]
        names2 = [s["vulnerability"]["name"] for s in doc2["statements"]]
        assert names1 == names2


# ---------------------------------------------------------------------------
# import_statements() — unit tests for early-exit paths (no DB needed)
# ---------------------------------------------------------------------------

class TestImportStatementsUnit:
    """Unit tests for import_statements early-exit branches (no DB calls)."""

    def _variant_id(self):
        import uuid as _uuid
        return _uuid.uuid4()

    def test_non_dict_statement_is_skipped(self):
        """GIVEN a list with non-dict items WHEN importing THEN they are silently skipped."""
        variant_id = self._variant_id()
        # All non-dict, so nothing to process → empty results
        created, errors, skipped = import_statements(["not-a-dict", 42, None], variant_id)
        assert created == []
        assert errors == []
        assert skipped == 0

    def test_missing_vulnerability_name_appends_error(self):
        """GIVEN a statement with an empty vulnerability object WHEN importing THEN error appended."""
        variant_id = self._variant_id()
        stmt = {"vulnerability": {}, "status": "affected", "products": [{"@id": "pkg@1.0"}]}
        created, errors, skipped = import_statements([stmt], variant_id)
        assert len(errors) == 1
        assert "Missing vulnerability name" in errors[0]["error"]

    def test_vulnerability_not_dict_is_missing_name(self):
        """GIVEN a statement where vulnerability is not a dict WHEN importing THEN error appended."""
        variant_id = self._variant_id()
        stmt = {"vulnerability": "not-a-dict", "status": "affected", "products": [{"@id": "pkg@1.0"}]}
        created, errors, skipped = import_statements([stmt], variant_id)
        assert len(errors) == 1
        assert "Missing vulnerability name" in errors[0]["error"]

    def test_missing_status_appends_error(self):
        """GIVEN a statement with no status key WHEN importing THEN error appended."""
        variant_id = self._variant_id()
        stmt = {"vulnerability": {"name": "CVE-2021-1234"}, "products": [{"@id": "pkg@1.0"}]}
        created, errors, skipped = import_statements([stmt], variant_id)
        assert len(errors) == 1
        assert errors[0]["vuln_id"] == "CVE-2021-1234"
        assert "Missing status" in errors[0]["error"]

    def test_empty_status_appends_error(self):
        """GIVEN a statement with falsy status WHEN importing THEN error appended."""
        variant_id = self._variant_id()
        stmt = {"vulnerability": {"name": "CVE-2021-1234"}, "status": "", "products": [{"@id": "pkg@1.0"}]}
        created, errors, skipped = import_statements([stmt], variant_id)
        assert len(errors) == 1

    def test_no_products_appends_error(self):
        """GIVEN a statement with empty products list WHEN importing THEN error appended."""
        variant_id = self._variant_id()
        stmt = {"vulnerability": {"name": "CVE-2021-1234"}, "status": "affected", "products": []}
        created, errors, skipped = import_statements([stmt], variant_id)
        assert len(errors) == 1
        assert "No products" in errors[0]["error"]

    def test_products_with_only_unsupported_types_appends_error(self):
        """GIVEN products list with only ints (no dicts or strings) WHEN importing THEN error appended."""
        variant_id = self._variant_id()
        stmt = {"vulnerability": {"name": "CVE-2021-1234"}, "status": "affected", "products": [42, True]}
        created, errors, skipped = import_statements([stmt], variant_id)
        assert len(errors) == 1
        assert "No products" in errors[0]["error"]

    def test_mixed_statements_accumulates_errors(self):
        """GIVEN multiple bad statements WHEN importing THEN all errors collected."""
        variant_id = self._variant_id()
        statements = [
            "not-a-dict",
            {"vulnerability": {}, "status": "affected", "products": [{"@id": "p@1.0"}]},
            {"vulnerability": {"name": "CVE-X"}, "products": [{"@id": "p@1.0"}]},  # no status
        ]
        created, errors, skipped = import_statements(statements, variant_id)
        assert created == []
        assert len(errors) == 2  # vuln name missing + status missing


# ---------------------------------------------------------------------------
# Import → multi-target assessments — one statement/entry, many targets
# ---------------------------------------------------------------------------

@pytest.fixture()
def app():
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        from src.bin.webapp import create_app
        from src.extensions import db as _db
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": "/dev/null"})
        with application.app_context():
            _db.create_all()
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def variant_and_project(app):
    from src.models.project import Project
    from src.models.variant import Variant
    proj = Project.create("io-group-proj")
    var = Variant.create("io-group-var", proj.id)
    return proj, var


def _make_variant(project_id, name):
    """Create a Variant under an existing project's *project_id*."""
    from src.models.variant import Variant
    return Variant.create(f"io-multitarget-var-{name}", project_id)


def _make_finding(vuln_id, pkg_name, pkg_version=""):
    """Create (or reuse) a Package/Vulnerability/Finding triple for *vuln_id*."""
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.finding import Finding
    pkg = Package.find_or_create(pkg_name, pkg_version)
    Vulnerability.get_or_create(vuln_id)
    return Finding.get_or_create(pkg.id, vuln_id)


class TestImportStatementsMultiTarget:
    """One OpenVEX statement (one vuln_id, multiple products) now produces one
    multi-target assessment instead of one assessment per product."""

    def test_openvex_import_creates_one_assessment_for_three_products(self, app, variant_and_project):
        """GIVEN one statement covering 3 products WHEN imported THEN one
        assessment is created with 3 targets."""
        from src.models.assessment import Assessment

        _, var = variant_and_project
        stmt = {
            "vulnerability": {"name": "CVE-2099-GRP01"},
            "status": "affected",
            "products": [
                {"@id": "pkg:generic/openssl@1.0"},
                {"@id": "pkg:generic/zlib@1.0"},
                {"@id": "pkg:generic/curl@1.0"},
            ],
        }
        with app.app_context():
            created, errors, skipped = import_statements([stmt], var.id)
            assert errors == []
            assert len(created) == 1
            assert len(Assessment.get_by_id(created[0]["id"]).targets) == 3

    def test_single_package_statement_creates_single_target_assessment(self, app, variant_and_project):
        """GIVEN one statement covering only 1 package WHEN imported THEN one
        assessment is created with exactly 1 target, trivially its own group."""
        from src.models.assessment import Assessment

        _, var = variant_and_project
        stmt = {
            "vulnerability": {"name": "CVE-2099-GRP02"},
            "status": "affected",
            "products": [{"@id": "pkg-solo@1.0"}],
        }
        with app.app_context():
            created, errors, skipped = import_statements([stmt], var.id)
            assert errors == []
            assert len(created) == 1
            row = Assessment.get_by_id(created[0]["id"])
            assert len(row.targets) == 1
            assert row.group_id == row.id

    def test_duplicate_product_in_one_statement_is_deduplicated(self, app, variant_and_project):
        """GIVEN a statement listing the same product twice WHEN imported THEN
        only one target is stored (the primary key would otherwise collide)."""
        from src.models.assessment import Assessment

        _, var = variant_and_project
        stmt = {
            "vulnerability": {"name": "CVE-2099-GRP06"},
            "status": "affected",
            "products": [{"@id": "dup-pkg@1.0"}, {"@id": "dup-pkg@1.0"}],
        }
        with app.app_context():
            created, errors, skipped = import_statements([stmt], var.id)
            assert errors == []
            assert len(created) == 1
            assert len(Assessment.get_by_id(created[0]["id"]).targets) == 1

    def test_reimporting_the_same_multi_product_statement_is_idempotent(self, app, variant_and_project):
        """GIVEN a multi-target assessment already exists for this exact set
        of products WHEN the same statement is imported again THEN no second
        assessment is created and the duplicate is reported skipped, not
        imported.  The multi-target row's scalar finding_id/variant_id are
        None, so this only works if duplicate detection also matches on the
        assessment_targets set, not just the scalar columns."""
        from src.models.assessment import Assessment

        _, var = variant_and_project
        stmt = {
            "vulnerability": {"name": "CVE-2099-REIMPORT"},
            "status": "affected",
            "products": [
                {"@id": "reimport-pkg-a@1.0"},
                {"@id": "reimport-pkg-b@1.0"},
                {"@id": "reimport-pkg-c@1.0"},
            ],
        }
        with app.app_context():
            created1, errors1, skipped1 = import_statements([stmt], var.id)
            assert errors1 == []
            assert len(created1) == 1

            created2, errors2, skipped2 = import_statements([stmt], var.id)
            assert errors2 == []
            assert created2 == []
            assert skipped2 == 1

            rows = [a for a in Assessment.get_all() if a.vuln_id == "CVE-2099-REIMPORT"]
            assert len(rows) == 1
            assert len(rows[0].targets) == 3

    def test_overlapping_but_distinct_multi_product_statement_is_not_a_duplicate(self, app, variant_and_project):
        """GIVEN a multi-target assessment already exists WHEN a statement
        naming a target *superset* of it is imported THEN the second
        statement is imported as a distinct assessment -- an overlapping
        target set is not the same assessment, only an equal one is."""
        from src.models.assessment import Assessment

        _, var = variant_and_project
        first_stmt = {
            "vulnerability": {"name": "CVE-2099-OVERLAP"},
            "status": "affected",
            "products": [
                {"@id": "overlap-pkg-a@1.0"},
                {"@id": "overlap-pkg-b@1.0"},
            ],
        }
        superset_stmt = {
            "vulnerability": {"name": "CVE-2099-OVERLAP"},
            "status": "affected",
            "products": [
                {"@id": "overlap-pkg-a@1.0"},
                {"@id": "overlap-pkg-b@1.0"},
                {"@id": "overlap-pkg-c@1.0"},
            ],
        }
        with app.app_context():
            created1, errors1, skipped1 = import_statements([first_stmt], var.id)
            assert errors1 == []
            assert len(created1) == 1

            created2, errors2, skipped2 = import_statements([superset_stmt], var.id)
            assert errors2 == []
            assert skipped2 == 0
            assert len(created2) == 1

            rows = [a for a in Assessment.get_all() if a.vuln_id == "CVE-2099-OVERLAP"]
            assert len(rows) == 2
            assert {len(row.targets) for row in rows} == {2, 3}


class TestImportCustomDataMultiTarget:
    """Version-1 'assessments'/'ai_assessments' entries keep fanning out to one
    assessment per package (legacy shape); version-2 entries create one
    assessment with many targets instead."""

    def test_v1_multi_package_entry_still_creates_two_assessments(self, app, variant_and_project):
        """GIVEN a version-1 entry covering 2 packages WHEN imported THEN two
        independent single-target assessments are created (no fusing, no
        shared group -- the old AssessmentGroupMember linkage is gone)."""
        from src.models.assessment import Assessment

        _, var = variant_and_project
        data = {
            "version": 1,
            "assessments": [{
                "vuln_id": "CVE-2099-GRP03",
                "status": "not_affected",
                "packages": ["grp-pkg-a@1.0", "grp-pkg-b@1.0"],
                "variant_id": str(var.id),
            }]
        }
        with app.app_context():
            result = import_custom_data(data, {var.name: var})
            assert result["assessments_imported"] == 2
            rows = Assessment.get_by_origin([var.id], origin="custom")
            assert len(rows) == 2
            assert {len(row.targets) for row in rows} == {1}
            # Each row is trivially its own group; none are fused together.
            assert len({row.id for row in rows}) == 2

    def test_v1_single_package_entry_creates_one_assessment(self, app, variant_and_project):
        """GIVEN a version-1 entry covering only 1 package WHEN imported THEN
        one single-target assessment is created."""
        from src.models.assessment import Assessment

        _, var = variant_and_project
        data = {
            "version": 1,
            "assessments": [{
                "vuln_id": "CVE-2099-GRP04",
                "status": "not_affected",
                "packages": ["grp-pkg-solo@1.0"],
                "variant_id": str(var.id),
            }]
        }
        with app.app_context():
            result = import_custom_data(data, {var.name: var})
            assert result["assessments_imported"] == 1
            rows = Assessment.get_by_origin([var.id], origin="custom")
            assert len(rows) == 1
            assert len(rows[0].targets) == 1

    def test_v1_custom_and_ai_entries_create_independent_assessments(self, app, variant_and_project):
        """GIVEN the same vuln_id/packages appear in both 'assessments' and
        'ai_assessments' WHEN imported THEN the custom-origin and ai-origin
        rows are entirely independent (no group ever links them)."""
        from src.models.assessment import Assessment

        _, var = variant_and_project
        packages = ["dual-pkg-a@1.0", "dual-pkg-b@1.0"]
        data = {
            "version": 1,
            "assessments": [{
                "vuln_id": "CVE-2099-GRP05",
                "status": "not_affected",
                "packages": packages,
                "variant_id": str(var.id),
            }],
            "ai_assessments": [{
                "vuln_id": "CVE-2099-GRP05",
                "status": "affected",
                "packages": packages,
                "variant_id": str(var.id),
            }],
        }
        with app.app_context():
            result = import_custom_data(data, {var.name: var})
            assert result["assessments_imported"] == 2
            assert result["ai_assessments_imported"] == 2

            custom_rows = Assessment.get_by_origin([var.id], origin="custom")
            ai_rows = Assessment.get_by_origin([var.id], origin="ai")
            assert len(custom_rows) == 2
            assert len(ai_rows) == 2
            assert {row.id for row in custom_rows}.isdisjoint({row.id for row in ai_rows})

    def test_version_1_import_still_works(self, app, variant_and_project):
        """Existing backup archives (no 'targets' key) must stay importable,
        fanning out one assessment per package exactly as they did before."""
        from src.models.assessment import Assessment

        _, var = variant_and_project
        data = {
            "version": 1,
            "assessments": [{
                "vuln_id": "CVE-2099-V1IMP",
                "status": "affected",
                "packages": ["v1-pkg-a@1.0", "v1-pkg-b@1.0"],
                "variant_id": str(var.id),
            }],
        }
        with app.app_context():
            result = import_custom_data(data, {var.name: var})
            assert result["errors"] == []
            assert len(Assessment.get_by_vulnerability("CVE-2099-V1IMP")) == 2


class TestCustomDataVersion2:
    """Version-2 export/import: one assessment, many ``{variant_id, package}``
    targets, replacing the fan-out that ``AssessmentGroupMember`` used to
    paper over."""

    def test_export_emits_version_2_with_targets(self, app, variant_and_project):
        """A single-target custom assessment exports its target explicitly."""
        from src.models.assessment import Assessment

        _, var = variant_and_project
        finding = _make_finding("CVE-2099-EXP01", "exp-pkg", "1.0")
        with app.app_context():
            Assessment.create(
                status="not_affected", origin="custom",
                finding_id=finding.id, variant_id=var.id,
                justification="component_not_present",
                commit=True,
            )
            payload = build_custom_data_export([var.id])

        assert payload["version"] == 2
        assert len(payload["assessments"]) == 1
        assert payload["assessments"][0]["targets"] == [
            {"variant_id": str(var.id), "package": "exp-pkg@1.0"},
        ]

    def test_version_2_export_round_trips_a_cross_variant_assessment(self, app):
        """A genuine multi-target (cross-variant) assessment created via
        Assessment.create(targets=...) round-trips through export/import."""
        from src.models.project import Project
        from src.models.assessment import Assessment

        with app.app_context():
            project = Project.create("io-v2-roundtrip-proj")
            variant_a = _make_variant(project.id, "a")
            variant_b = _make_variant(project.id, "b")
            openssl = _make_finding("CVE-2099-XV01", "openssl", "1.0")
            zlib = _make_finding("CVE-2099-XV01", "zlib", "1.0")

            original = Assessment.create(
                status="not_affected", origin="custom",
                justification="component_not_present",
                targets=[(variant_a.id, openssl.id), (variant_b.id, zlib.id)],
                commit=True,
            )

            payload = build_custom_data_export()
            assert payload["version"] == 2

            original.delete()

            # Scalar-column queries can't see a genuine multi-target row (its
            # scalar finding_id/variant_id are None), so match via the
            # transient vuln_id property, which does fall back to target_rows.
            def _by_vuln(vuln_id):
                return [a for a in Assessment.get_all() if a.vuln_id == vuln_id]

            assert _by_vuln("CVE-2099-XV01") == []

            variant_by_name = {variant_a.name: variant_a, variant_b.name: variant_b}
            result = import_custom_data(payload, variant_by_name)
            assert result["errors"] == []

            restored = _by_vuln("CVE-2099-XV01")
            assert len(restored) == 1
            assert set(restored[0].targets) == {
                (variant_a.id, openssl.id), (variant_b.id, zlib.id),
            }

    def test_a_package_that_fails_to_resolve_is_reported_not_silently_dropped(self, app, variant_and_project):
        """A version-2 target naming an unknown package is reported as an
        error while the resolvable targets on the same entry still import."""
        from src.models.assessment import Assessment

        _, var = variant_and_project
        _make_finding("CVE-2099-BADPKG", "openssl", "")
        data = {
            "version": 2,
            "assessments": [{
                "vuln_id": "CVE-2099-BADPKG",
                "status": "affected",
                "targets": [
                    {"variant_id": str(var.id), "package": "openssl"},
                    {"variant_id": str(var.id), "package": "does-not-exist"},
                ],
            }],
        }
        with app.app_context():
            result = import_custom_data(data, {var.name: var})

        assert result["assessments_imported"] == 1
        assert len(result["errors"]) == 1
        assert "does-not-exist" in result["errors"][0].get("package", "")
        rows = Assessment.get_by_vulnerability("CVE-2099-BADPKG")
        assert len(rows) == 1
        assert len(rows[0].targets) == 1

    def test_v2_entry_spanning_two_projects_is_reported_not_silently_created(self, app):
        """A version-2 entry whose targets span two different projects
        violates the one-assessment-one-project invariant: it is reported as
        an error and no assessment is created for it, while a separate,
        well-formed entry in the same payload still imports."""
        from src.models.project import Project
        from src.models.assessment import Assessment

        with app.app_context():
            project_a = Project.create("io-v2-cross-proj-a")
            project_b = Project.create("io-v2-cross-proj-b")
            variant_a = _make_variant(project_a.id, "cp-a")
            variant_b = _make_variant(project_b.id, "cp-b")
            _make_finding("CVE-2099-XPROJ", "cross-pkg-a", "1.0")
            _make_finding("CVE-2099-XPROJ", "cross-pkg-b", "1.0")
            single_finding = _make_finding("CVE-2099-OK", "ok-pkg", "1.0")

            data = {
                "version": 2,
                "assessments": [
                    {
                        "vuln_id": "CVE-2099-XPROJ",
                        "status": "affected",
                        "targets": [
                            {"variant_id": str(variant_a.id), "package": "cross-pkg-a@1.0"},
                            {"variant_id": str(variant_b.id), "package": "cross-pkg-b@1.0"},
                        ],
                    },
                    {
                        "vuln_id": "CVE-2099-OK",
                        "status": "affected",
                        "targets": [
                            {"variant_id": str(variant_a.id), "package": "ok-pkg@1.0"},
                        ],
                    },
                ],
            }
            variant_by_name = {variant_a.name: variant_a, variant_b.name: variant_b}
            result = import_custom_data(data, variant_by_name)

            assert result["assessments_imported"] == 1
            assert len(result["errors"]) == 1
            assert Assessment.get_by_vulnerability("CVE-2099-XPROJ") == []
            ok_rows = Assessment.get_by_vulnerability("CVE-2099-OK")
            assert len(ok_rows) == 1
            assert ok_rows[0].targets == [(variant_a.id, single_finding.id)]

    def test_reimporting_the_same_v2_multi_target_payload_is_idempotent(self, app, variant_and_project):
        """GIVEN a genuine multi-target assessment (2+ targets, scalar
        finding_id/variant_id both None) already exists WHEN its version-2
        export is imported a second time WITHOUT deleting the original THEN
        no second assessment is created: the import is reported skipped, not
        imported.  Reproduces the reviewer's critical finding directly (no
        `.delete()` between export and re-import, unlike the round-trip test
        above, which would otherwise mask this exact bug)."""
        from src.models.assessment import Assessment

        _, var = variant_and_project
        finding_a = _make_finding("CVE-2099-DUPFIX", "dupfix-pkg-a", "1.0")
        finding_b = _make_finding("CVE-2099-DUPFIX", "dupfix-pkg-b", "1.0")
        with app.app_context():
            Assessment.create(
                status="not_affected", origin="custom",
                justification="component_not_present",
                targets=[(var.id, finding_a.id), (var.id, finding_b.id)],
                commit=True,
            )
            payload = build_custom_data_export()
            assert payload["version"] == 2

            def rows_for(vuln_id):
                return [a for a in Assessment.get_all() if a.vuln_id == vuln_id]

            assert len(rows_for("CVE-2099-DUPFIX")) == 1

            variant_by_name = {var.name: var}
            result_1 = import_custom_data(payload, variant_by_name)
            assert result_1["errors"] == []
            assert result_1["assessments_imported"] == 0
            assert result_1["assessments_skipped"] == 1
            assert len(rows_for("CVE-2099-DUPFIX")) == 1

            result_2 = import_custom_data(payload, variant_by_name)
            assert result_2["errors"] == []
            assert result_2["assessments_imported"] == 0
            assert result_2["assessments_skipped"] == 1
            assert len(rows_for("CVE-2099-DUPFIX")) == 1

    def test_v2_payload_with_overlapping_but_distinct_targets_is_not_a_duplicate(self, app, variant_and_project):
        """GIVEN a multi-target assessment exists for {a, b} WHEN a version-2
        payload naming a *different* target set {a, c} (overlapping on `a`
        only) is imported THEN it is treated as a distinct assessment and
        imported, not skipped as a duplicate -- set overlap is not set
        equality."""
        from src.models.assessment import Assessment

        _, var = variant_and_project
        finding_a = _make_finding("CVE-2099-OVERLAP2", "overlap2-pkg-a", "1.0")
        finding_b = _make_finding("CVE-2099-OVERLAP2", "overlap2-pkg-b", "1.0")
        finding_c = _make_finding("CVE-2099-OVERLAP2", "overlap2-pkg-c", "1.0")
        with app.app_context():
            Assessment.create(
                status="not_affected", origin="custom",
                justification="component_not_present",
                targets=[(var.id, finding_a.id), (var.id, finding_b.id)],
                commit=True,
            )
            data = {
                "version": 2,
                "assessments": [{
                    "vuln_id": "CVE-2099-OVERLAP2",
                    "status": "not_affected",
                    "justification": "component_not_present",
                    "targets": [
                        {"variant_id": str(var.id), "package": "overlap2-pkg-a@1.0"},
                        {"variant_id": str(var.id), "package": "overlap2-pkg-c@1.0"},
                    ],
                }],
            }
            result = import_custom_data(data, {var.name: var})
            assert result["errors"] == []
            assert result["assessments_imported"] == 1
            assert result["assessments_skipped"] == 0

            rows = [a for a in Assessment.get_all() if a.vuln_id == "CVE-2099-OVERLAP2"]
            assert len(rows) == 2
            assert {frozenset(row.targets) for row in rows} == {
                frozenset({(var.id, finding_a.id), (var.id, finding_b.id)}),
                frozenset({(var.id, finding_a.id), (var.id, finding_c.id)}),
            }
