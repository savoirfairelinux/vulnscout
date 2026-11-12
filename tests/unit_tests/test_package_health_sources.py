# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""JSON clients for OpenSSF Scorecard, deps.dev and OSV, over real HTTP."""

import json
import socket
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from src.controllers.package_health import depsdev_repository, osv_repository
from src.controllers.package_health_sources import DEPSDEV_API, OSV_API, SCORECARD_API, JsonApi


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append((self.path, self.headers.get("User-Agent")))
        responses = (self.server.routes.get(self.path) or self.server.routes.get(self.path.split("?", 1)[0])
                     or [(404, {"error": "not found"})])
        status, body = responses.pop(0) if len(responses) > 1 else responses[0]
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture()
def service():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.routes = {}
    server.requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def _api(server, retries=3):
    return JsonApi(f"http://127.0.0.1:{server.server_port}/", timeout=5, retries=retries, backoff=0)


def test_documents_are_decoded_and_segments_percent_encoded(service):
    service.routes["/packages/%40colors%2Fcolors/versions/1.5.0"] = [(200, {"ok": True})]
    assert _api(service).get("packages", "@colors/colors", "versions", "1.5.0") == {"ok": True}
    assert service.requests[0][1].startswith("VulnScout")


@pytest.mark.parametrize("status", [400, 404])
def test_missing_documents_are_none_without_retry(service, status):
    service.routes["/projects/github.com/a/b"] = [(status, {"error": "missing"})]
    assert _api(service).get("projects", "github.com", "a", "b") is None
    assert len(service.requests) == 1


def test_non_object_documents_are_none(service):
    service.routes["/list"] = [(200, [1, 2])]
    assert _api(service).get("list") is None


def test_server_errors_are_retried_until_success(service):
    service.routes["/flaky"] = [(503, {"error": "busy"}), (500, b"oops"), (200, {"done": 1})]
    assert _api(service).get("flaky") == {"done": 1}
    assert len(service.requests) == 3


def test_exhausted_retries_raise_the_last_failure(service):
    service.routes["/down"] = [(503, {"error": "busy"})]
    with pytest.raises(urllib.error.HTTPError):
        _api(service, retries=2).get("down")
    assert len(service.requests) == 2
    service.routes["/garbled"] = [(200, b"not json")]
    with pytest.raises(ValueError):
        _api(service, retries=1).get("garbled")


def test_unreachable_hosts_raise():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(urllib.error.URLError):
        JsonApi(f"http://127.0.0.1:{port}", timeout=2, retries=1).get("x")


def test_osv_repository_prefers_exact_package_name_among_matching_git_ranges():
    cpe = "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*"
    payload = {"affected": [{"ranges": [
        {"type": "GIT", "repo": "https://github.com/alsyundawy/openssl-1.0.2",
         "database_specific": {"extracted_events": [{"cpe": cpe}]}},
        {"type": "GIT", "repo": "https://github.com/openssl/openssl",
         "database_specific": {"extracted_events": [{"cpe": cpe}]}},
    ]}]}

    assert osv_repository(payload, "openssl", [cpe]) == "github.com/openssl/openssl"


@pytest.fixture()
def live_network():
    try:
        socket.create_connection(("api.osv.dev", 443), timeout=5).close()
    except OSError:
        pytest.skip("public APIs are unreachable from this environment")


def test_live_scorecard_publishes_checks(live_network):
    result = JsonApi(SCORECARD_API).get("projects", "github.com", "curl", "curl")
    assert result is not None
    assert 0 <= result["score"] <= 10
    assert "Maintained" in {check["name"] for check in result["checks"]}
    assert JsonApi(SCORECARD_API).get("projects", "github.com", "OpenSSL", "OpenSSL") is None


def test_live_depsdev_links_repository_and_deprecation(live_network):
    react = JsonApi(DEPSDEV_API).get("systems", "NPM", "packages", "react", "versions", "18.2.0")
    assert depsdev_repository(react) == "github.com/facebook/react"
    request = JsonApi(DEPSDEV_API).get("systems", "NPM", "packages", "request", "versions", "2.88.2")
    assert request["isDeprecated"] is True


def test_live_osv_git_ranges_name_the_upstream_repository(live_network):
    record = JsonApi(OSV_API).get("vulns", "CVE-2023-0464")
    cpe = "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*"
    assert osv_repository(record, "openssl", [cpe]) == "github.com/openssl/openssl"
    assert osv_repository(record, "unrelated", ["cpe:2.3:a:other:unrelated:1:*:*:*:*:*:*:*"]) is None
