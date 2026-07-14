# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Unit tests for assessment_io.py helper functions."""

import io
import json
import os
import tarfile
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from src.helpers.assessment_io import (
    is_openvex_doc,
    sanitize_variant_name,
    _get_vuln_info,
    import_archive_bytes,
    import_directory,
    build_variant_by_name_map,
    build_openvex_doc,
    build_openvex_archive,
    import_statements,
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
# import_archive_bytes() tests
# ---------------------------------------------------------------------------

class TestImportArchiveBytes:
    """Test import_archive_bytes function."""

    def test_invalid_tar_gz_bytes(self):
        """GIVEN invalid tar.gz bytes WHEN imported THEN raise ValueError."""
        invalid_bytes = b"this is not a tar file"
        variant_by_name = {}
        
        with pytest.raises(ValueError, match="Unable to open tar.gz archive"):
            import_archive_bytes(invalid_bytes, variant_by_name)

    def test_tar_with_no_json_files(self):
        """GIVEN a tar.gz with no JSON files WHEN imported THEN skip them."""
        # Create a tar archive with non-JSON files
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
            # Add non-JSON files
            info = tarfile.TarInfo(name="readme.txt")
            info.size = 5
            tar.addfile(info, io.BytesIO(b"hello"))
        
        variant_by_name = {}
        created, errors, skipped, variant_files_found = import_archive_bytes(
            tar_buffer.getvalue(),
            variant_by_name
        )
        
        assert variant_files_found == 0
        assert created == []
        assert errors == []

    def test_tar_with_missing_variant(self):
        """GIVEN a tar with JSON for unknown variant WHEN imported THEN add error."""
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
            doc = {"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}
            json_bytes = json.dumps(doc).encode()
            info = tarfile.TarInfo(name="unknown_variant.json")
            info.size = len(json_bytes)
            tar.addfile(info, io.BytesIO(json_bytes))
        
        variant_by_name = {}
        created, errors, skipped, variant_files_found = import_archive_bytes(
            tar_buffer.getvalue(),
            variant_by_name
        )
        
        assert variant_files_found == 0
        assert len(errors) == 1
        assert "No variant found" in errors[0]["error"]

    def test_tar_with_directory_member(self):
        """GIVEN a tar with directory entries WHEN imported THEN skip them."""
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
            # Add a directory
            info = tarfile.TarInfo(name="subdir/")
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
        
        variant_by_name = {}
        created, errors, skipped, variant_files_found = import_archive_bytes(
            tar_buffer.getvalue(),
            variant_by_name
        )
        
        assert variant_files_found == 0


# ---------------------------------------------------------------------------
# import_directory() tests
# ---------------------------------------------------------------------------

class TestImportDirectory:
    """Test import_directory function."""

    def test_empty_directory(self):
        """GIVEN a directory with no JSON files WHEN imported THEN raise ValueError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            variant_by_name = {}
            
            with pytest.raises(ValueError, match="No .json files found"):
                import_directory(tmpdir, variant_by_name)

    def test_directory_with_non_json_files(self):
        """GIVEN a directory with only non-JSON files WHEN imported THEN raise ValueError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a non-JSON file
            with open(os.path.join(tmpdir, "readme.txt"), "w") as f:
                f.write("hello")
            
            variant_by_name = {}
            
            with pytest.raises(ValueError, match="No .json files found"):
                import_directory(tmpdir, variant_by_name)

    def test_directory_with_unknown_variant(self):
        """GIVEN a directory with JSON for unknown variant WHEN imported THEN add error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a valid JSON file
            doc = {"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}
            json_path = os.path.join(tmpdir, "unknown_variant.json")
            with open(json_path, "w") as f:
                json.dump(doc, f)
            
            variant_by_name = {}
            created, errors, skipped, variant_files_found = import_directory(
                tmpdir,
                variant_by_name
            )
            
            assert variant_files_found == 0
            assert len(errors) == 1
            assert "No variant found" in errors[0]["error"]

    def test_directory_sorted_by_filename(self):
        """GIVEN a directory with multiple JSON files WHEN imported THEN files are processed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple JSON files with different names
            for name in ["zebra.json", "apple.json", "monkey.json"]:
                doc = {"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}
                json_path = os.path.join(tmpdir, name)
                with open(json_path, "w") as f:
                    json.dump(doc, f)
            
            variant_by_name = {}
            
            # All 3 files should produce errors for missing variants
            created, errors, skipped, variant_files_found = import_directory(
                tmpdir,
                variant_by_name
            )
            
            # All 3 files should produce errors for missing variants
            assert len(errors) == 3


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
# build_openvex_archive() tests
# ---------------------------------------------------------------------------

class TestBuildOpenvexArchive:
    """Unit tests for build_openvex_archive."""

    def test_empty_assessments_returns_empty_tar(self):
        """GIVEN no assessments WHEN building archive THEN tar.gz with no members."""
        result = build_openvex_archive([], {}, "author")
        buf = io.BytesIO(result)
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            assert len(tar.getmembers()) == 0

    def test_assessment_without_variant_goes_to_unassigned(self):
        """GIVEN assessment with variant_id=None WHEN building archive THEN unassigned.json."""
        assess = mock.MagicMock()
        assess.variant_id = None
        assess.to_openvex_dict.return_value = {"status": "affected"}
        assess.vuln_id = "CVE-2021-1234"
        assess.packages = ["pkg@1.0"]
        assess.source = "s"
        assess.origin = "o"
        with mock.patch("src.helpers.assessment_io._get_vuln_info", return_value=_EMPTY_VULN_INFO):
            result = build_openvex_archive([assess], {}, "author")
        buf = io.BytesIO(result)
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            names = [m.name for m in tar.getmembers()]
        assert "unassigned.json" in names

    def test_assessment_with_variant_uses_variant_name(self):
        """GIVEN assessment with known variant WHEN building archive THEN file named after variant."""
        import uuid as _uuid
        vid = str(_uuid.uuid4())
        assess = mock.MagicMock()
        assess.variant_id = vid
        assess.to_openvex_dict.return_value = {"status": "fixed"}
        assess.vuln_id = "CVE-2021-5678"
        assess.packages = ["lib@0.1"]
        assess.source = "s"
        assess.origin = "o"
        variant_names = {vid: "my-variant"}
        with mock.patch("src.helpers.assessment_io._get_vuln_info", return_value=_EMPTY_VULN_INFO):
            result = build_openvex_archive([assess], variant_names, "author")
        buf = io.BytesIO(result)
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            names = [m.name for m in tar.getmembers()]
        assert "my-variant.json" in names

    def test_variant_name_with_slash_is_sanitized(self):
        """GIVEN a variant name with '/' WHEN building archive THEN slashes become underscores."""
        import uuid as _uuid
        vid = str(_uuid.uuid4())
        assess = mock.MagicMock()
        assess.variant_id = vid
        assess.to_openvex_dict.return_value = None  # skipped
        assess.packages = []
        variant_names = {vid: "board/arch"}
        with mock.patch("src.helpers.assessment_io._get_vuln_info", return_value=_EMPTY_VULN_INFO):
            result = build_openvex_archive([assess], variant_names, "author")
        buf = io.BytesIO(result)
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            names = [m.name for m in tar.getmembers()]
        assert "board_arch.json" in names

    def test_json_content_is_valid_openvex(self):
        """GIVEN an archive built from one assessment WHEN extracting THEN JSON is valid OpenVEX."""
        assess = mock.MagicMock()
        assess.variant_id = None
        assess.to_openvex_dict.return_value = {"status": "not_affected"}
        assess.vuln_id = "CVE-2021-9999"
        assess.packages = ["pkg@2.0"]
        assess.source = "scanner"
        assess.origin = "custom"
        with mock.patch("src.helpers.assessment_io._get_vuln_info", return_value={"description": "d", "aliases": [], "url": "https://example.com"}):
            result = build_openvex_archive([assess], {}, "author", now_iso="2025-01-01T00:00:00Z")
        buf = io.BytesIO(result)
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            member = tar.getmembers()[0]
            doc = json.load(tar.extractfile(member))
        assert is_openvex_doc(doc)
        assert doc["author"] == "author"
        assert doc["timestamp"] == "2025-01-01T00:00:00Z"


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
