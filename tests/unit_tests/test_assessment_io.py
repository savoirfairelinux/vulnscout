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
