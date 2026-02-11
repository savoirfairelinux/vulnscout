# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from unittest.mock import MagicMock, patch, mock_open
from src.views.templates import Templates, TemplatesExtensions
from src.models.package import Package
from src.models.vulnerability import Vulnerability
from src.models.assessment import VulnAssessment
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.controllers.assessments import AssessmentsController
import subprocess


@pytest.fixture
def templates_instance():
    controllers = {}
    controllers["packages"] = PackagesController()
    controllers["vulnerabilities"] = VulnerabilitiesController(controllers["packages"])
    controllers["assessments"] = AssessmentsController(controllers["packages"], controllers["vulnerabilities"])
    return Templates(controllers)


@pytest.fixture
def pkg_ABC():
    return Package("abc", "1.2.3", ["cpe:2.3:a:abc:abc:1.2.3:*:*:*:*:*:*:*"], ["pkg:generic/abc@1.2.3"])


@pytest.fixture
def vuln_123():
    vuln = Vulnerability("CVE-1234-000", ["scanner"], "https://nvd.nist.gov/vuln/detail/CVE-1234-000", "unknown")
    vuln.add_package("abc@1.2.3")
    vuln.add_text("A flaw was found in abc's image-compositor.c (...)", "description")
    vuln.add_alias("CVE-1234-999")
    vuln.set_epss(0.5, 0.97)
    vuln.severity_without_cvss("medium", 5.4, True)
    return vuln


@pytest.fixture
def assesment_123(pkg_ABC, vuln_123):
    assess = VulnAssessment(vuln_123.id, [pkg_ABC])
    assess.set_status("in_triage")
    return assess


class TestTemplatesRenderExceptions:
    """Test exception handling in render method"""

    def test_render_with_invalid_epss_score(self, templates_instance, pkg_ABC, vuln_123, assesment_123):
        """Test that render handles invalid EPSS scores gracefully (lines 84-85)"""
        templates_instance.packagesCtrl.add(pkg_ABC)
        templates_instance.vulnerabilitiesCtrl.add(vuln_123)
        templates_instance.assessmentsCtrl.add(assesment_123)

        # Create a vulnerability with invalid EPSS data that will cause an exception
        vuln_bad = Vulnerability("CVE-9999-999", ["scanner"], "https://nvd.nist.gov/vuln/detail/CVE-9999-999", "unknown")
        vuln_bad.add_package("abc@1.2.3")
        vuln_bad.severity_without_cvss("high", 7.0, True)
        
        # Add an assessment for the bad vulnerability
        assess_bad = VulnAssessment(vuln_bad.id, [pkg_ABC])
        assess_bad.set_status("affected")
        
        templates_instance.vulnerabilitiesCtrl.add(vuln_bad)
        templates_instance.assessmentsCtrl.add(assess_bad)
        
        # Mock the vulnerability to have invalid EPSS data
        vuln_dict = templates_instance.vulnerabilitiesCtrl.to_dict()
        if vuln_bad.id in vuln_dict:
            vuln_dict[vuln_bad.id]['epss'] = {'score': 'invalid'}  # This will cause float() to fail
        
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


class TestAdocToPdfErrors:
    """Test error handling in adoc_to_pdf method"""

    @patch('subprocess.run')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.remove')
    def test_adoc_to_pdf_subprocess_failure(self, mock_remove, mock_file, mock_subprocess, templates_instance):
        """Test adoc_to_pdf when subprocess returns non-zero exit code (lines 104-110)"""
        # Mock subprocess to return non-zero exit code
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = b"stdout output"
        mock_result.stderr = b"stderr output"
        mock_subprocess.return_value = mock_result

        with pytest.raises(Exception, match="Error converting adoc to pdf"):
            templates_instance.adoc_to_pdf("= Test Document")

        # Verify cleanup was attempted
        assert mock_remove.called

    @patch('subprocess.run')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.remove')
    def test_adoc_to_pdf_success(self, mock_remove, mock_file, mock_subprocess, templates_instance):
        """Test successful adoc_to_pdf conversion"""
        # Mock subprocess to return success
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result

        # Mock reading the PDF file
        mock_file.return_value.read.return_value = b"PDF content"

        result = templates_instance.adoc_to_pdf("= Test Document")
        assert result == b"PDF content"
        assert mock_remove.call_count == 2  # Should remove both .adoc and .pdf files


class TestAdocToHtmlErrors:
    """Test error handling in adoc_to_html method"""

    @patch('subprocess.run')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.remove')
    @patch('os.path.exists')
    def test_adoc_to_html_subprocess_failure(self, mock_exists, mock_remove, mock_file, mock_subprocess, templates_instance):
        """Test adoc_to_html when subprocess returns non-zero exit code (lines 128-136)"""
        # Mock subprocess to return non-zero exit code
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = b"stdout output"
        mock_result.stderr = b"stderr output"
        mock_subprocess.return_value = mock_result
        
        # Mock that both files exist for cleanup
        mock_exists.return_value = True

        with pytest.raises(Exception, match="Error converting adoc to html"):
            templates_instance.adoc_to_html("= Test Document")

        # Verify cleanup was attempted
        assert mock_remove.called

    @patch('subprocess.run')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.remove')
    def test_adoc_to_html_success(self, mock_remove, mock_file, mock_subprocess, templates_instance):
        """Test successful adoc_to_html conversion"""
        # Mock subprocess to return success
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result

        # Mock reading the HTML file
        mock_file.return_value.read.return_value = b"HTML content"

        result = templates_instance.adoc_to_html("= Test Document")
        assert result == b"HTML content"
        assert mock_remove.call_count == 2  # Should remove both .adoc and .html files


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
