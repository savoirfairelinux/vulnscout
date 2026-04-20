# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Unit tests for src/controllers/osv_client.py — OSVClient."""

import json
import pytest
from unittest.mock import patch, MagicMock
import urllib.error

from src.controllers.osv_client import OSVClient


class TestOSVClientQueryByPurl:
    """Tests for OSVClient.query_by_purl()."""

    def _mock_urlopen_response(self, data_dict, status=200):
        """Create a mock context-manager for urlopen that returns JSON."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(data_dict).encode("utf-8")
        mock_resp.status = status
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    @patch("src.controllers.osv_client.urllib.request.urlopen")
    def test_returns_vulns_on_success(self, mock_urlopen):
        vulns = [{"id": "GHSA-1234", "summary": "test"}]
        mock_urlopen.return_value = self._mock_urlopen_response({"vulns": vulns})
        client = OSVClient(timeout=5)
        result = client.query_by_purl("pkg:pypi/requests@2.28.0")
        assert result == vulns
        mock_urlopen.assert_called_once()

    @patch("src.controllers.osv_client.urllib.request.urlopen")
    def test_returns_empty_when_no_vulns(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen_response({})
        client = OSVClient(timeout=5)
        result = client.query_by_purl("pkg:pypi/safe-lib@1.0.0")
        assert result == []

    @patch("src.controllers.osv_client.urllib.request.urlopen")
    def test_returns_empty_on_http_400(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.osv.dev/v1/query",
            code=400, msg="Bad Request", hdrs={}, fp=None,
        )
        client = OSVClient(timeout=5)
        result = client.query_by_purl("invalid-purl")
        assert result == []

    @patch("src.controllers.osv_client.urllib.request.urlopen")
    def test_returns_empty_on_http_404(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.osv.dev/v1/query",
            code=404, msg="Not Found", hdrs={}, fp=None,
        )
        client = OSVClient(timeout=5)
        result = client.query_by_purl("pkg:pypi/nonexistent@0.0.0")
        assert result == []

    @patch("src.controllers.osv_client.time.sleep")
    @patch("src.controllers.osv_client.urllib.request.urlopen")
    def test_retries_on_http_500(self, mock_urlopen, mock_sleep):
        vulns = [{"id": "CVE-2023-1234"}]
        mock_urlopen.side_effect = [
            urllib.error.HTTPError(
                url="https://api.osv.dev/v1/query",
                code=500, msg="Server Error", hdrs={}, fp=None,
            ),
            self._mock_urlopen_response({"vulns": vulns}),
        ]
        client = OSVClient(timeout=5)
        result = client.query_by_purl("pkg:pypi/lib@1.0")
        assert result == vulns
        assert mock_urlopen.call_count == 2
        mock_sleep.assert_called_once()

    @patch("src.controllers.osv_client.time.sleep")
    @patch("src.controllers.osv_client.urllib.request.urlopen")
    def test_raises_after_all_retries_exhausted(self, mock_urlopen, mock_sleep):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.osv.dev/v1/query",
            code=500, msg="Server Error", hdrs={}, fp=None,
        )
        client = OSVClient(timeout=5)
        with pytest.raises(urllib.error.HTTPError):
            client.query_by_purl("pkg:pypi/lib@1.0", retries=3)
        assert mock_urlopen.call_count == 3

    @patch("src.controllers.osv_client.time.sleep")
    @patch("src.controllers.osv_client.urllib.request.urlopen")
    def test_retries_on_url_error(self, mock_urlopen, mock_sleep):
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        client = OSVClient(timeout=5)
        with pytest.raises(urllib.error.URLError):
            client.query_by_purl("pkg:pypi/lib@1.0", retries=2)
        assert mock_urlopen.call_count == 2

    @patch("src.controllers.osv_client.time.sleep")
    @patch("src.controllers.osv_client.urllib.request.urlopen")
    def test_retries_on_timeout(self, mock_urlopen, mock_sleep):
        mock_urlopen.side_effect = TimeoutError("timed out")
        client = OSVClient(timeout=1)
        with pytest.raises(TimeoutError):
            client.query_by_purl("pkg:pypi/lib@1.0", retries=2)
        assert mock_urlopen.call_count == 2
