# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import base64
import os
import pytest
from unittest.mock import MagicMock, patch, mock_open
from src.views.templates import Templates, TemplatesExtensions, find_asset, embed_image, ALLOWED_ASSET_EXTENSIONS
from src.models.package import Package
from src.models.vulnerability import Vulnerability
from src.models.assessment import Assessment
from src.controllers import ControllersCache


@pytest.fixture
def templates_instance(tmp_path):
    with patch('src.controllers.vulnerabilities.EPSS_DB') as mock_epss:
        mock_epss.return_value = MagicMock()
        controllers = ControllersCache()
        _ = controllers.vulnerabilities  # pre-load cache with mocked epss DB
        controllers.project = None
        controllers.variant = None
        controllers.scan = None
        controllers.sbom_document = None
        yield Templates(controllers)


@pytest.fixture
def pkg_ABC():
    return Package("abc", "1.2.3", ["cpe:2.3:a:abc:abc:1.2.3:*:*:*:*:*:*:*"], ["pkg:generic/abc@1.2.3"])


@pytest.fixture
def vuln_123():
    vuln = Vulnerability("CVE-1234-000", ["scanner"], "https://nvd.nist.gov/vuln/detail/CVE-1234-000", "unknown")
    vuln.add_package("abc@1.2.3")
    vuln.description = "A flaw was found in abc's image-compositor.c (...)"
    vuln.add_alias("CVE-1234-999")
    vuln.set_epss(0.5, 0.97)
    vuln.severity_without_cvss("medium", 5.4, True)
    return vuln


@pytest.fixture
def assesment_123(pkg_ABC, vuln_123):
    assess = Assessment.new_dto(vuln_123.id, [pkg_ABC])
    assess.set_status("in_triage")
    return assess


class TestTemplatesRenderExceptions:
    """Test exception handling in render method"""

    def test_render_with_invalid_epss_score(self, templates_instance, pkg_ABC, vuln_123, assesment_123):
        """Test that render handles invalid EPSS scores gracefully (lines 85-86)"""
        templates_instance.packagesCtrl.add(pkg_ABC)
        templates_instance.vulnerabilitiesCtrl.add(vuln_123)
        templates_instance.assessmentsCtrl.add(assesment_123)

        # Create a vulnerability with invalid EPSS data that will cause an exception
        vuln_bad = Vulnerability("CVE-9999-999", ["scanner"], "https://nvd.nist.gov/vuln/detail/CVE-9999-999", "unknown")
        vuln_bad.add_package("abc@1.2.3")
        vuln_bad.severity_without_cvss("high", 7.0, True)
        # Directly set the EPSS score to an invalid string to trigger exception in float()
        vuln_bad.epss["score"] = "invalid_score"

        # Add an assessment for the bad vulnerability so it passes the len > 0 check
        assess_bad = Assessment.new_dto(vuln_bad.id, [pkg_ABC])
        assess_bad.set_status("affected")

        templates_instance.vulnerabilitiesCtrl.add(vuln_bad)
        templates_instance.assessmentsCtrl.add(assess_bad)

        # Create a simple test template
        with patch.object(templates_instance.env, 'get_template') as mock_template:
            mock_template.return_value.render.return_value = "test"

            # This should not raise an exception despite invalid EPSS
            result = templates_instance.render("test.jinja2", only_epss_greater=50)
            assert result == "test"

    def test_render_with_filter_date_for_assessments(self, templates_instance, pkg_ABC, vuln_123, assesment_123):
        """Test render with filter_date to cover assessment filtering (lines 87-92)"""
        templates_instance.packagesCtrl.add(pkg_ABC)
        templates_instance.vulnerabilitiesCtrl.add(vuln_123)
        templates_instance.assessmentsCtrl.add(assesment_123)

        with patch.object(templates_instance.env, 'get_template') as mock_template:
            mock_template.return_value.render.return_value = "test"

            # Test with a filter date that includes the assessment
            result = templates_instance.render("test.jinja2", ignore_before="2020-01-01T00:00")
            assert result == "test"


class TestRenderGroupsAssessments:
    """render() groups assessments from to_dict() instead of a per-vuln DB query."""

    def test_render_does_not_call_gets_by_vuln(self, templates_instance, pkg_ABC, vuln_123, assesment_123):
        """The N+1 gets_by_vuln() per vulnerability must no longer be used."""
        templates_instance.packagesCtrl.add(pkg_ABC)
        templates_instance.vulnerabilitiesCtrl.add(vuln_123)
        templates_instance.assessmentsCtrl.add(assesment_123)
        templates_instance.assessmentsCtrl.gets_by_vuln = MagicMock(
            side_effect=AssertionError("gets_by_vuln must not be called by render()")
        )

        captured = {}

        def _capture(**kwargs):
            captured.update(kwargs)
            return "ok"

        with patch.object(templates_instance.env, 'get_template') as mock_template:
            mock_template.return_value.render.side_effect = _capture
            result = templates_instance.render("test.jinja2")

        assert result == "ok"
        templates_instance.assessmentsCtrl.gets_by_vuln.assert_not_called()
        # The assessment is still correctly associated with its vulnerability.
        rendered_vuln = captured["vulnerabilities"][vuln_123.id]
        assert len(rendered_vuln["assessments"]) == 1
        assert rendered_vuln["assessments"][0]["vuln_id"] == vuln_123.id


class TestAdocToPdfErrors:
    """Test error handling in adoc_to_pdf method"""

    @patch('subprocess.run')
    @patch('shutil.rmtree')
    @patch('builtins.open', new_callable=mock_open)
    def test_adoc_to_pdf_subprocess_failure(self, mock_file, mock_rmtree, mock_subprocess, templates_instance):
        """Test adoc_to_pdf when subprocess returns non-zero exit code."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = b"stdout output"
        mock_result.stderr = b"stderr output"
        mock_subprocess.return_value = mock_result

        with pytest.raises(Exception, match="Error converting adoc to pdf"):
            templates_instance.adoc_to_pdf("= Test Document")

        # Temp directory must be cleaned up even on failure
        assert mock_rmtree.called

    @patch('subprocess.run')
    @patch('builtins.open', new_callable=mock_open)
    def test_adoc_to_pdf_success(self, mock_file, mock_subprocess, templates_instance):
        """Test successful adoc_to_pdf conversion."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result

        mock_file.return_value.read.return_value = b"PDF content"

        result = templates_instance.adoc_to_pdf("= Test Document")
        assert result == b"PDF content"


class TestAdocToHtmlErrors:
    """Test error handling in adoc_to_html method"""

    @patch('subprocess.run')
    @patch('shutil.rmtree')
    @patch('builtins.open', new_callable=mock_open)
    def test_adoc_to_html_subprocess_failure(self, mock_file, mock_rmtree, mock_subprocess, templates_instance):
        """Test adoc_to_html when subprocess returns non-zero exit code."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = b"stdout output"
        mock_result.stderr = b"stderr output"
        mock_subprocess.return_value = mock_result

        with pytest.raises(Exception, match="Error converting adoc to html"):
            templates_instance.adoc_to_html("= Test Document")

        # Temp directory must be cleaned up even on failure
        assert mock_rmtree.called

    @patch('subprocess.run')
    @patch('builtins.open', new_callable=mock_open)
    def test_adoc_to_html_success(self, mock_file, mock_subprocess, templates_instance):
        """Test successful adoc_to_html conversion."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result

        mock_file.return_value.read.return_value = b"HTML content"

        result = templates_instance.adoc_to_html("= Test Document")
        assert result == b"HTML content"


class TestListDocumentsError:
    """Test error handling in list_documents method"""

    def test_list_documents_with_exception(self, templates_instance):
        """Test list_documents when an exception occurs (lines 151-152)"""
        # Mock the internal_loader to raise an exception
        with patch.object(templates_instance.internal_loader, 'list_templates', side_effect=Exception("Test error")):
            # Should return empty list and not raise exception
            result = templates_instance.list_documents()
            assert result == []

    def test_list_documents_success(self, templates_instance):
        """Test successful list_documents"""
        # Mock the loaders to return template lists
        with patch.object(templates_instance.internal_loader, 'list_templates', return_value=["template1.jinja2"]):
            with patch.object(templates_instance.external_loader, 'list_templates', return_value=["custom.jinja2"]):
                result = templates_instance.list_documents()
                assert len(result) == 2
                assert {"id": "template1.jinja2", "is_template": True, "category": ["built-in"]} in result
                assert {"id": "custom.jinja2", "is_template": True, "category": ["custom"]} in result


class TestFilterEpssScoreException:
    """Test exception handling in filter_epss_score"""

    def test_filter_epss_score_with_invalid_data(self):
        """Test filter_epss_score when EPSS data causes exception (lines 244-245)"""
        # Create test data with invalid EPSS that will trigger exception
        vulns = [
            {"id": "CVE-1", "epss": {"score": "invalid"}},  # This will cause exception
            {"id": "CVE-2", "epss": {"score": 0.8}},
            {"id": "CVE-3", "epss": None},  # No EPSS data
        ]

        result = TemplatesExtensions.filter_epss_score(vulns, 50)

        # Should only include CVE-2 which has valid EPSS >= 50%
        assert len(result) == 1
        assert result[0]["id"] == "CVE-2"

    def test_filter_epss_score_with_dict_input_and_exceptions(self):
        """Test filter_epss_score with dict input and exception handling"""
        vulns_dict = {
            "a": {"id": "CVE-1", "epss": {"score": None}},  # Will cause exception
            "b": {"id": "CVE-2", "epss": {"score": 0.7}},
            "c": {"id": "CVE-3"},  # No EPSS key at all
        }

        result = TemplatesExtensions.filter_epss_score(vulns_dict, 50)

        # Should only include CVE-2
        assert len(result) == 1
        assert result[0]["id"] == "CVE-2"


class TestFilterAsListMethod:
    """Test filter_as_list method"""

    def test_filter_as_list(self):
        """Test that filter_as_list converts dict to list"""
        test_dict = {
            "key1": {"id": "value1"},
            "key2": {"id": "value2"},
            "key3": {"id": "value3"}
        }

        result = TemplatesExtensions.filter_as_list(test_dict)

        assert isinstance(result, list)
        assert len(result) == 3
        assert {"id": "value1"} in result
        assert {"id": "value2"} in result
        assert {"id": "value3"} in result


class TestGetEnvVarMethod:
    """Test get_env_var method for accessing host environment variables in templates"""

    def test_get_env_var_with_prefixed_variable(self):
        """Test that prefixed VULNSCOUT_TPL_ variables are found"""
        with patch.dict('os.environ', {'VULNSCOUT_TPL_DISTRO': 'poky'}):
            result = TemplatesExtensions.get_env_var("DISTRO")
            assert result == "poky"

    def test_get_env_var_with_direct_variable(self):
        """Test that direct environment variables without prefix are ignored"""
        with patch.dict('os.environ', {'MACHINE': 'qemuarm64'}, clear=False):
            # Ensure no prefixed version exists
            import os
            if 'VULNSCOUT_TPL_MACHINE' in os.environ:
                del os.environ['VULNSCOUT_TPL_MACHINE']
            result = TemplatesExtensions.get_env_var("MACHINE")
            assert result == ""

    def test_get_env_var_prefixed_takes_priority(self):
        """Test that VULNSCOUT_TPL_ prefix takes priority over direct variable"""
        with patch.dict('os.environ', {
            'VULNSCOUT_TPL_MY_VAR': 'prefixed_value',
            'MY_VAR': 'direct_value'
        }):
            result = TemplatesExtensions.get_env_var("MY_VAR")
            assert result == "prefixed_value"

    def test_get_env_var_with_default(self):
        """Test that default value is returned when variable is not set"""
        with patch.dict('os.environ', {}, clear=True):
            result = TemplatesExtensions.get_env_var("NONEXISTENT_VAR", "my_default")
            assert result == "my_default"

    def test_get_env_var_returns_empty_string_by_default(self):
        """Test that empty string is returned when variable is not set and no default"""
        with patch.dict('os.environ', {}, clear=True):
            result = TemplatesExtensions.get_env_var("NONEXISTENT_VAR")
            assert result == ""

    def test_env_available_as_jinja_global(self, templates_instance):
        """Test that env() is available as a Jinja global function"""
        assert "env" in templates_instance.env.globals
        assert templates_instance.env.globals["env"] == TemplatesExtensions.get_env_var


# ---------------------------------------------------------------------------
# TemplatesExtensions — filter_by_variant, filter_by_project, sort_by_scan_date
# (lines 567-568, 572-573, 577)
# ---------------------------------------------------------------------------

class TestTemplatesExtensionsFilterSort:
    def test_filter_by_variant_matching(self):
        """Lines 567-568: filter_by_variant returns items where variant_id matches."""
        items = [
            {"id": "v1", "variant_id": "var-A", "variant_ids": []},
            {"id": "v2", "variant_id": "var-B", "variant_ids": []},
            {"id": "v3", "variant_id": None,    "variant_ids": ["var-A"]},
        ]
        result = TemplatesExtensions.filter_by_variant(items, "var-A")
        ids = [r["id"] for r in result]
        assert "v1" in ids
        assert "v3" in ids
        assert "v2" not in ids

    def test_filter_by_project_matching(self):
        """Lines 572-573: filter_by_project returns items where project_id matches."""
        items = [
            {"id": "v1", "project_id": "proj-1"},
            {"id": "v2", "project_id": "proj-2"},
        ]
        result = TemplatesExtensions.filter_by_project(items, "proj-1")
        assert len(result) == 1
        assert result[0]["id"] == "v1"

    def test_sort_by_scan_date_descending(self):
        """Line 577: sort_by_scan_date sorts by timestamp descending."""
        items = [
            {"id": "a", "timestamp": "2023-01-01T00:00:00"},
            {"id": "b", "timestamp": "2024-01-01T00:00:00"},
            {"id": "c", "timestamp": "2022-01-01T00:00:00"},
        ]
        result = TemplatesExtensions.sort_by_scan_date(items)
        assert result[0]["id"] == "b"  # newest first


# ---------------------------------------------------------------------------
# Templates.render — assessments with variant_id (line 162)
# ---------------------------------------------------------------------------

class TestTemplatesRenderAssessmentsWithVariantId:
    def test_render_with_assessment_variant_id_populates_by_variant(self, templates_instance, pkg_ABC, vuln_123):
        """Line 162: by_variant.setdefault is called when assessment has variant_id."""
        assess_with_variant = Assessment.new_dto(vuln_123.id, [pkg_ABC])
        assess_with_variant.set_status("affected")
        assess_with_variant.variant_id = "test-variant-uuid"

        templates_instance.packagesCtrl.add(pkg_ABC)
        templates_instance.vulnerabilitiesCtrl.add(vuln_123)
        templates_instance.assessmentsCtrl.add(assess_with_variant)

        with patch.object(templates_instance.env, 'get_template') as mock_tpl:
            mock_tpl.return_value.render.return_value = "rendered"
            result = templates_instance.render("test.jinja2")
        assert result == "rendered"


# ---------------------------------------------------------------------------
# TemplatesExtensions.escape_adoc — HTML sanitization
# ---------------------------------------------------------------------------

class TestEscapeAdoc:
    """Tests for the escape_adoc Jinja filter.

    Validates that:
    - HTML tags are stripped to plain text.
    - HTML entities are decoded to their character equivalents.
    - Block-level HTML tags introduce newlines to preserve structure.
    - AsciiDoc structural markup (block fences, headings) is still neutralised.
    - Empty / None input returns an empty string without error.
    - Plain text that contains no HTML is returned unchanged (modulo structural
      neutralization when needed).
    """

    def test_none_returns_empty_string(self):
        assert TemplatesExtensions.escape_adoc(None) == ""

    def test_empty_string_returns_empty_string(self):
        assert TemplatesExtensions.escape_adoc("") == ""

    def test_plain_text_unchanged(self):
        text = "A flaw was found in the foo library version 1.2.3."
        assert TemplatesExtensions.escape_adoc(text) == text

    def test_html_tags_stripped(self):
        result = TemplatesExtensions.escape_adoc(
            "A <b>critical</b> flaw in <code>foo</code>."
        )
        assert "<b>" not in result
        assert "<code>" not in result
        assert "critical" in result
        assert "foo" in result

    def test_anchor_tag_stripped(self):
        result = TemplatesExtensions.escape_adoc(
            'See <a href="https://example.com">this advisory</a> for details.'
        )
        assert "<a" not in result
        assert "href" not in result
        assert "this advisory" in result

    def test_html_entity_decoded(self):
        result = TemplatesExtensions.escape_adoc(
            "Versions &lt;= 1.0 are affected. Use &amp; to concatenate."
        )
        assert "&lt;" not in result
        assert "&amp;" not in result
        assert "<= 1.0" in result
        assert "& to concatenate" in result

    def test_block_tag_preserves_newline(self):
        result = TemplatesExtensions.escape_adoc(
            "<p>First paragraph.</p><p>Second paragraph.</p>"
        )
        assert "First paragraph." in result
        assert "Second paragraph." in result
        # Paragraphs should be separated by at least one newline.
        assert "\n" in result

    def test_br_tag_introduces_newline(self):
        result = TemplatesExtensions.escape_adoc("Line one.<br>Line two.")
        assert "Line one." in result
        assert "Line two." in result
        assert "\n" in result

    def test_structural_markup_still_neutralised_after_html_strip(self):
        """Block fences that survive HTML stripping must still be defused."""
        description = "Normal text.\n----\nCode block.\n----"
        result = TemplatesExtensions.escape_adoc(description)
        for line in result.splitlines():
            stripped = line.lstrip("\u200b")
            if stripped.strip() == "----":
                assert line.startswith("\u200b"), (
                    f"AsciiDoc fence not neutralised: {line!r}"
                )

    def test_heading_neutralised_after_html_strip(self):
        """AsciiDoc / Markdown headings must be defused even after tag stripping."""
        description = "Normal text.\n== Section Heading\nMore text."
        result = TemplatesExtensions.escape_adoc(description)
        for line in result.splitlines():
            if line.lstrip("\u200b").startswith("== "):
                assert line.startswith("\u200b"), (
                    f"AsciiDoc heading not neutralised: {line!r}"
                )

    def test_entity_encoded_tag_does_not_reintroduce_html(self):
        """Decoding &lt;b&gt; must not resurrect a raw <b> tag in the output.

        A single HTMLParser pass decodes charrefs inside handle_data without
        re-tokenizing the decoded text, so "&lt;b&gt;bold&lt;/b&gt;" would
        otherwise decode straight to the literal string "<b>bold</b>" and
        reach Asciidoctor as unstripped HTML.
        """
        result = TemplatesExtensions.escape_adoc("&lt;b&gt;bold&lt;/b&gt; text")
        assert "<b>" not in result
        assert "</b>" not in result
        assert "bold" in result
        assert "text" in result

    def test_doubly_encoded_entity_fully_decoded(self):
        """Double-encoded entities (&amp;lt; -> &lt; -> <) must be fully resolved."""
        result = TemplatesExtensions.escape_adoc("&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;")
        assert "<script>" not in result
        assert "&lt;" not in result
        assert "&amp;" not in result

    def test_deeply_nested_encoded_tag_does_not_reintroduce_html(self):
        """Six layers of "&amp;"-nesting must not leave a live <b> tag.

        A bounded loop that re-runs the tag stripper (rather than fully
        decoding entities before tokenizing) can exhaust its pass budget one
        step before the tag stripper gets to see the fully-decoded "<b>" and
        would then return that unsafe intermediate value. Decoding entities
        to a fixed point before tokenizing avoids that regardless of nesting
        depth.
        """
        opening, closing = "<b>", "</b>"
        for _ in range(6):
            opening = opening.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            closing = closing.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        payload = f"{opening}bold{closing}"
        result = TemplatesExtensions.escape_adoc(payload)
        assert "<b>" not in result
        assert "</b>" not in result
        assert "&lt;" not in result
        assert "&amp;" not in result
        assert "bold" in result

    def test_encoding_beyond_pass_budget_never_yields_raw_tag(self):
        """Nesting deeper than the internal pass budget must still be safe.

        When the decode loop stops before reaching a fixed point, the
        remaining entities must stay encoded and inert (the tag-stripping
        pass performs no decoding), never surfacing as a raw tag.
        """
        payload = "<b>bold</b>"
        for _ in range(TemplatesExtensions._MAX_ENTITY_DECODE_PASSES + 5):
            payload = payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        result = TemplatesExtensions.escape_adoc(payload)
        assert "<b>" not in result
        assert "</b>" not in result
        assert "bold" in result

    def test_mixed_html_and_structural_markup(self):
        """HTML tags stripped AND AsciiDoc fences neutralised in the same input."""
        description = (
            "<p>Overview: affected versions &lt; 2.0.</p>\n"
            "====\n"
            "delimiter block\n"
            "====\n"
        )
        result = TemplatesExtensions.escape_adoc(description)
        assert "<p>" not in result
        assert "&lt;" not in result
        assert "< 2.0" in result
        for line in result.splitlines():
            stripped = line.lstrip("\u200b")
            if stripped.strip() == "====":
                assert line.startswith("\u200b"), (
                    f"AsciiDoc fence not neutralised: {line!r}"
                )
# find_asset — path safety and extension filtering
# ---------------------------------------------------------------------------

class TestFindAsset:
    def test_returns_none_for_missing_file(self, tmp_path):
        with patch("src.views.templates._ASSET_SEARCH_DIRS", [str(tmp_path)]):
            assert find_asset("logo.png") is None

    def test_returns_path_when_file_exists(self, tmp_path):
        img = tmp_path / "logo.png"
        img.write_bytes(b"\x89PNG")
        with patch("src.views.templates._ASSET_SEARCH_DIRS", [str(tmp_path)]):
            result = find_asset("logo.png")
            assert result is not None
            assert result.endswith("logo.png")

    def test_rejects_path_traversal(self, tmp_path):
        assert find_asset("../etc/passwd") is None
        assert find_asset("../../secret.png") is None

    def test_rejects_directory_separator(self, tmp_path):
        assert find_asset("subdir/logo.png") is None

    def test_rejects_disallowed_extension(self, tmp_path):
        assert find_asset("script.js") is None
        assert find_asset("shell.sh") is None

    def test_rejects_empty_and_none(self):
        assert find_asset("") is None  # type: ignore[arg-type]

    def test_all_allowed_extensions_accepted(self, tmp_path):
        for ext in ALLOWED_ASSET_EXTENSIONS:
            fname = f"asset.{ext}"
            (tmp_path / fname).write_bytes(b"data")
            with patch("src.views.templates._ASSET_SEARCH_DIRS", [str(tmp_path)]):
                assert find_asset(fname) is not None, f"Expected {ext} to be allowed"

    def test_searches_dirs_in_order(self, tmp_path):
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()
        (dir_b / "logo.png").write_bytes(b"from_b")
        with patch("src.views.templates._ASSET_SEARCH_DIRS", [str(dir_a), str(dir_b)]):
            result = find_asset("logo.png")
            assert result is not None
            assert os.path.realpath(str(dir_b / "logo.png")) == result


# ---------------------------------------------------------------------------
# embed_image — data-URI generation
# ---------------------------------------------------------------------------

class TestEmbedImage:
    def test_returns_empty_string_when_asset_missing(self, tmp_path):
        with patch("src.views.templates._ASSET_SEARCH_DIRS", [str(tmp_path)]):
            assert embed_image("logo.png") == ""

    def test_returns_data_uri_macro_for_png(self, tmp_path):
        img_bytes = b"\x89PNG\r\n\x1a\n"
        (tmp_path / "logo.png").write_bytes(img_bytes)
        with patch("src.views.templates._ASSET_SEARCH_DIRS", [str(tmp_path)]):
            result = embed_image("logo.png")
        expected_b64 = base64.b64encode(img_bytes).decode("ascii")
        assert result.startswith("image::data:image/png;base64,")
        assert expected_b64 in result

    def test_includes_alt_text(self, tmp_path):
        (tmp_path / "logo.svg").write_bytes(b"<svg/>")
        with patch("src.views.templates._ASSET_SEARCH_DIRS", [str(tmp_path)]):
            result = embed_image("logo.svg", alt="My Logo")
        assert "[My Logo]" in result

    def test_includes_width(self, tmp_path):
        (tmp_path / "logo.jpg").write_bytes(b"\xff\xd8\xff")
        with patch("src.views.templates._ASSET_SEARCH_DIRS", [str(tmp_path)]):
            result = embed_image("logo.jpg", width=150)
        assert ",150]" in result

    def test_correct_mime_for_each_extension(self, tmp_path):
        cases = {
            "img.png": "image/png",
            "img.jpg": "image/jpeg",
            "img.jpeg": "image/jpeg",
            "img.gif": "image/gif",
            "img.svg": "image/svg+xml",
            "img.webp": "image/webp",
        }
        for fname, expected_mime in cases.items():
            (tmp_path / fname).write_bytes(b"data")
            with patch("src.views.templates._ASSET_SEARCH_DIRS", [str(tmp_path)]):
                result = embed_image(fname)
            assert expected_mime in result, f"Expected {expected_mime} in output for {fname}"

    def test_embed_image_registered_as_jinja_global(self, templates_instance):
        assert "embed_image" in templates_instance.env.globals
        assert templates_instance.env.globals["embed_image"] is embed_image

    def test_find_asset_registered_as_jinja_global(self, templates_instance):
        assert "find_asset" in templates_instance.env.globals
        assert templates_instance.env.globals["find_asset"] is find_asset


# ---------------------------------------------------------------------------
# _run_asciidoctor — stable tempdir, attributes, cleanup
# ---------------------------------------------------------------------------

class TestRunAsciidoctor:
    def _make_subprocess_mock(self, returncode: int = 0, output: bytes = b"result") -> MagicMock:
        mock_proc = MagicMock()
        mock_proc.returncode = returncode
        mock_proc.stdout = b""
        mock_proc.stderr = b""
        return mock_proc

    @patch("subprocess.run")
    @patch("shutil.rmtree")
    @patch("tempfile.mkdtemp", return_value="/tmp/vulnscout_adoc_test")
    def test_uses_tempdir_not_cwd(self, mock_mkdtemp, mock_rmtree, mock_run, templates_instance, tmp_path):
        mock_run.return_value = self._make_subprocess_mock()
        adoc_path = "/tmp/vulnscout_adoc_test/report.adoc"
        output_path = "/tmp/vulnscout_adoc_test/report.pdf"

        with patch("builtins.open", mock_open(read_data=b"PDF")):
            with patch("os.path.isdir", return_value=True):
                try:
                    templates_instance.adoc_to_pdf("= Test")
                except Exception:
                    pass  # file reading may fail in mock context

        # The .adoc file must be inside the temp dir, not CWD
        call_args = mock_run.call_args[0][0]
        assert any("/tmp/vulnscout_adoc_test" in str(a) for a in call_args)

    @patch("subprocess.run")
    def test_passes_safe_mode_and_imagesdir(self, mock_run, templates_instance, tmp_path):
        """``-S safe`` (never ``unsafe``) and ``-a imagesdir`` must be in the asciidoctor call."""
        mock_run.return_value = self._make_subprocess_mock()
        assets = tmp_path / "assets"
        assets.mkdir()

        with patch("src.views.templates._ASSET_SEARCH_DIRS", [str(assets)]):
            with patch("builtins.open", mock_open(read_data=b"PDF")):
                try:
                    templates_instance.adoc_to_pdf("= Test")
                except Exception:
                    pass

        call_args = mock_run.call_args[0][0]
        joined = " ".join(str(a) for a in call_args)
        assert "-S" in joined and "safe" in joined
        assert "unsafe" not in joined
        assert "imagesdir" in joined

    @patch("subprocess.run")
    @patch("shutil.rmtree")
    def test_referenced_assets_copied_into_tempdir(self, mock_rmtree, mock_run, templates_instance, tmp_path):
        """Only assets referenced by an image macro are copied into the sandboxed tempdir."""
        mock_run.return_value = self._make_subprocess_mock()
        assets = tmp_path / "assets"
        assets.mkdir()
        (assets / "logo.png").write_bytes(b"PNGDATA")
        (assets / "unused.png").write_bytes(b"PNGDATA")

        with patch("src.views.templates._ASSET_SEARCH_DIRS", [str(assets)]):
            try:
                templates_instance.adoc_to_pdf("image::logo.png[Logo]")
            except Exception:
                pass  # the real asciidoctor binary is not actually invoked

        call_args = [str(a) for a in mock_run.call_args[0][0]]
        imagesdir_value = next(a for a in call_args if a.startswith("imagesdir=")).split("=", 1)[1]
        assert os.path.isfile(os.path.join(imagesdir_value, "logo.png"))
        assert not os.path.isfile(os.path.join(imagesdir_value, "unused.png"))

    @patch("subprocess.run")
    def test_base_dir_restricted_to_tempdir(self, mock_run, templates_instance):
        """``-B`` must point at the temporary directory, not the real filesystem root."""
        mock_run.return_value = self._make_subprocess_mock()

        with patch("builtins.open", mock_open(read_data=b"PDF")):
            try:
                templates_instance.adoc_to_pdf("= Test")
            except Exception:
                pass

        call_args = [str(a) for a in mock_run.call_args[0][0]]
        assert "-B" in call_args
        base_dir = call_args[call_args.index("-B") + 1]
        assert "vulnscout_adoc_" in base_dir

    @patch("subprocess.run")
    def test_html_gets_data_uri_attribute(self, mock_run, templates_instance, tmp_path):
        """HTML conversions must include -a data-uri; PDF must not."""
        mock_run.return_value = self._make_subprocess_mock()

        with patch("builtins.open", mock_open(read_data=b"HTML")):
            try:
                templates_instance.adoc_to_html("= Test")
            except Exception:
                pass

        call_args_html = " ".join(str(a) for a in mock_run.call_args[0][0])
        assert "data-uri" in call_args_html

    @patch("subprocess.run")
    def test_pdf_does_not_get_data_uri(self, mock_run, templates_instance, tmp_path):
        mock_run.return_value = self._make_subprocess_mock()

        with patch("builtins.open", mock_open(read_data=b"PDF")):
            try:
                templates_instance.adoc_to_pdf("= Test")
            except Exception:
                pass

        call_args_pdf = " ".join(str(a) for a in mock_run.call_args[0][0])
        assert "data-uri" not in call_args_pdf

    @patch("subprocess.run")
    @patch("shutil.rmtree")
    def test_tempdir_cleaned_up_on_error(self, mock_rmtree, mock_run, templates_instance):
        """shutil.rmtree must be called even when asciidoctor fails."""
        mock_run.return_value = self._make_subprocess_mock(returncode=1)

        with patch("builtins.open", mock_open()):
            with pytest.raises(RuntimeError):
                templates_instance.adoc_to_pdf("= Bad")

        assert mock_rmtree.called
