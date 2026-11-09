# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Upstream repository resolution, OpenSSF Scorecard caching and the package health API."""

import datetime
import json
import socket
import sqlite3
import uuid

import pytest

from src.bin.cmd_process import read_inputs
from src.bin.webapp import create_app
from src.controllers import ControllersCache
from src.controllers import package_health as health
from src.controllers.job_context import CancelledError, JobContext, OperationError
from src.controllers.operation_queue import OperationQueue
from src.controllers.operation_registry import registry
from src.controllers.package_health_sources import JsonApi
from src.extensions import db
from src.models import (
    Finding, Observation, Package, PackageRepository, Project, RepositoryScorecard, SBOMDocument, SBOMPackage, Scan, Variant,
    Vulnerability,
)
from tests.unit_tests.test_package_health_sources import _api, service  # noqa: F401

SCORECARD = {
    "date": "2026-11-09", "repo": {"name": "github.com/curl/curl", "commit": "c" * 40},
    "score": 9.1,
    "checks": [
        {"name": "Maintained", "score": 10, "reason": "30 commit(s) in the last 90 days",
         "documentation": {"short": "Is it maintained?", "url": "https://github.com/ossf/scorecard/docs#maintained"}},
        {"name": "Packaging", "score": -1, "reason": "no workflow",
         "documentation": {"url": "javascript:alert(1)"}},
        {"score": 3},
        "invalid",
    ],
}
OPENSSL_CVE = {"affected": [{"ranges": [{
    "type": "GIT", "repo": "https://github.com/openssl/openssl",
    "database_specific": {"extracted_events": [{"cpe": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"}]},
}]}]}
GLIBC_CVE = {"affected": [{"ranges": [
    {"type": "GIT", "repo": "https://github.com/bminor/glibc"},
    {"type": "ECOSYSTEM"},
    {"type": "GIT", "repo": "https://sourceware.org/git/glibc.git",
     "database_specific": {"extracted_events": [{"cpe": "cpe:2.3:a:gnu:glibc:*:*:*:*:*:*:*:*"}]}},
]}]}


class RecordingContext(JobContext):
    def __init__(self, options):
        super().__init__("refresh:scorecard", options)
        self.messages = []

    def report(self, current, total, message):
        self.messages.append(message)
        super().report(current, total, message)


@pytest.fixture()
def app(tmp_path, monkeypatch, request):
    uri = f"sqlite:///{tmp_path / 'health.db'}" if getattr(request, "param", None) == "file" else "sqlite:///:memory:"
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", uri)
    monkeypatch.delenv(health.ENABLED_ENV, raising=False)
    status = tmp_path / "scan-status"
    status.write_text("__END_OF_SCAN_SCRIPT__\n")
    application = create_app()
    application.config.update(TESTING=True, SCAN_FILE=str(status))
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


def _link(document, package, **evidence):
    link = SBOMPackage.get_or_create(document.id, package.id)
    for field, value in evidence.items():
        setattr(link, field, value)
    return link


@pytest.fixture()
def scope(app):
    project = Project.create("health")
    variant = Variant.create("board", project.id)
    other = Variant.create("other", project.id)
    scan = Scan.create("SBOM", variant.id)
    document = SBOMDocument.create("/sbom.json", "sbom.json", scan.id, format="spdx")
    curl = Package.find_or_create("curl", "8.0.0", cpe=["cpe:2.3:a:haxx:curl:8.0.0:*:*:*:*:*:*:*"])
    _link(document, curl, upstream_urls=["https://github.com/curl/curl/releases/download/curl-8_0_0/curl.tar.xz"])
    react = Package.find_or_create("react", "18.2.0", purl=["pkg:npm/react@18.2.0"])
    _link(document, react, purl=["pkg:npm/react@18.2.0"])
    request = Package.find_or_create("request", "2.88.2", purl=["pkg:npm/request@2.88.2"])
    _link(document, request, purl=["pkg:npm/request@2.88.2"])
    openssl = Package.find_or_create("openssl", "3.0.1", cpe=["cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*"])
    _link(document, openssl, cpe=["cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*"])
    glibc = Package.find_or_create("glibc", "2.41")
    glibc.generate_generic_cpe()
    _link(document, glibc, cpe=["cpe:2.3:a:gnu:glibc:2.41:*:*:*:*:*:*:*"])
    busybox = Package.find_or_create("busybox", "1.36.1")
    _link(document, busybox, upstream_urls=["git://git.busybox.net/busybox;branch=1_36_stable"])
    lonely = Package.find_or_create("lonely", "1.0")
    _link(document, lonely)
    for cve_id, package in (("CVE-2023-0464", openssl), ("CVE-2023-4911", glibc), ("CVE-2020-0001", glibc)):
        Vulnerability.create_record(id=cve_id, description="test")
        finding = Finding.create(package.id, cve_id)
        Observation.create(finding.id, scan.id)
    db.session.commit()
    return {"project": str(project.id), "variant": str(variant.id), "other": str(other.id)}


@pytest.fixture()
def apis(service):  # noqa: F811
    service.routes.update({
        "/scorecard/projects/github.com/curl/curl": [(200, SCORECARD)],
        "/scorecard/projects/github.com/openssl/openssl": [(503, {"error": "busy"})],
        "/depsdev/systems/NPM/packages/react/versions/18.2.0": [(200, {"relatedProjects": [
            {"projectKey": {"id": "github.com/facebook/react"}, "relationType": "SOURCE_REPO",
             "relationProvenance": "UNVERIFIED_METADATA"},
        ]})],
        "/depsdev/systems/NPM/packages/request/versions/2.88.2": [(200, {
            "isDeprecated": True, "deprecatedReason": "request has been deprecated",
            "relatedProjects": [{"projectKey": {"id": "github.com/request/request"}, "relationType": "SOURCE_REPO"}],
        })],
        "/osv/vulns/CVE-2023-0464": [(200, OPENSSL_CVE)],
        "/osv/vulns/CVE-2023-4911": [(200, GLIBC_CVE)],
        "/github/repos/facebook/react": [(200, {"full_name": "facebook/react"})],
        "/github/repos/request/request": [(200, {"full_name": "Request/Request"})],
        "/scorecard/projects/github.com/Request/Request": [(200, {
            "repo": {"name": "github.com/Request/Request"}, "score": 4, "checks": [],
        })],
    })
    base = f"http://127.0.0.1:{service.server_port}"
    return service, health.PackageHealthRefresher(
        scorecard=JsonApi(f"{base}/scorecard", timeout=5, retries=1, backoff=0),
        github=JsonApi(f"{base}/github", timeout=5, retries=1, backoff=0),
        depsdev=JsonApi(f"{base}/depsdev", timeout=5, retries=1, backoff=0),
        osv=JsonApi(f"{base}/osv", timeout=5, retries=1, backoff=0),
    )


def _run(variant_ids, refresher, force=False):
    ctx = RecordingContext({"variant_ids": variant_ids, "force": force})
    health.run_scorecard_refresh(ctx, refresher)
    return ctx


def _health(app, query):
    response = app.test_client().get(f"/api/packages/health?{query}")
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def _repository_key(package, scope):
    scan_ids = health.active_sbom_scan_ids_for_variant(uuid.UUID(scope["variant"]))
    evidence = health._evidence_by_package([package.id], scan_ids)[package.id]
    cves = health._cve_ids_by_package([package.id], scan_ids).get(package.id, [])
    return package.id, evidence.key(cves)


def test_refresh_resolves_every_source_and_caches_scores(app, scope, apis, monkeypatch):
    monkeypatch.setattr(health, "COMMIT_EVERY", 2)
    service, refresher = apis
    ctx = _run([scope["variant"]], refresher)
    assert ctx.messages[-1] == ("OpenSSF Scorecard refresh complete (6/7 packages with a repository, "
                                "4 repositories fetched)")

    data = _health(app, f"variant_id={scope['variant']}")
    assert data["enabled"] is True
    packages = data["packages"]
    assert set(packages) == {"curl@8.0.0", "react@18.2.0", "request@2.88.2", "openssl@3.0.1", "glibc@2.41",
                             "busybox@1.36.1", "lonely@1.0"}
    curl = packages["curl@8.0.0"]
    assert (curl["repository"], curl["repository_source"]) == ("github.com/curl/curl", "sbom")
    assert curl["scorecard"]["status"] == "scored"
    assert curl["scorecard"]["score"] == 9.1
    assert curl["scorecard"]["maintained"] == {"score": 10, "reason": "30 commit(s) in the last 90 days"}
    assert "checks" not in curl["scorecard"]
    assert packages["react@18.2.0"]["repository_source"] == "deps_dev"
    assert packages["react@18.2.0"]["repository_evidence"] == "npm:react@18.2.0"
    assert packages["react@18.2.0"]["deprecated"] is False
    assert packages["react@18.2.0"]["scorecard"]["status"] == "not_found"
    assert packages["request@2.88.2"]["deprecated"] is True
    assert packages["request@2.88.2"]["deprecated_reason"] == "request has been deprecated"
    assert packages["request@2.88.2"]["scorecard"]["repository"] == "github.com/Request/Request"
    assert packages["request@2.88.2"]["scorecard"]["score"] == 4
    assert packages["openssl@3.0.1"]["repository_evidence"] == "CVE-2023-0464"
    assert packages["openssl@3.0.1"]["scorecard"]["status"] == "error"
    assert packages["glibc@2.41"]["repository"] == "sourceware.org/git/glibc"
    assert packages["glibc@2.41"]["scorecard"] == {"status": "unsupported"}
    assert packages["busybox@1.36.1"]["scorecard"] == {"status": "unsupported"}
    assert packages["lonely@1.0"] == {
        **packages["lonely@1.0"], "repository": None, "repository_source": "none", "scorecard": None,
    }

    detail = _health(app, f"variant_id={scope['variant']}&package_id=curl@8.0.0")["packages"]
    assert list(detail) == ["curl@8.0.0"]
    checks = detail["curl@8.0.0"]["scorecard"]["checks"]
    assert [check["name"] for check in checks] == ["Maintained", "Packaging"]
    assert checks[0]["url"].startswith("https://")
    assert checks[1] == {"name": "Packaging", "score": -1, "reason": "no workflow", "description": None, "url": None}

    # Cached repositories and scores are reused; only the failed lookup is retried.
    requests = len(service.requests)
    _run([scope["variant"]], refresher)
    assert [path for path, _ in service.requests[requests:]] == ["/scorecard/projects/github.com/openssl/openssl"]


def test_failed_scorecard_lookup_keeps_previous_score(app, scope, apis):
    service, refresher = apis
    _run([scope["variant"]], refresher)
    row = db.session.get(RepositoryScorecard, "github.com/curl/curl")
    row.fetched_at -= health.SCORECARD_TTL
    db.session.commit()
    service.routes["/scorecard/projects/github.com/curl/curl"] = [(503, {"error": "busy"})]
    _run([scope["variant"]], refresher)
    assert db.session.get(RepositoryScorecard, "github.com/curl/curl").score == 9.1


def test_shared_package_repository_is_scoped_to_variant(app, scope, apis):
    _, refresher = apis
    package = Package.find_or_create("shared", "1", purl=["pkg:github/global/wrong@1"])
    first = db.session.scalars(db.select(SBOMDocument)).first()
    _link(first, package, source_urls=["https://gitlab.com/z-first/shared"])
    old_scan = Scan.create("superseded", uuid.UUID(scope["variant"]))
    old_scan.timestamp -= datetime.timedelta(days=1)
    old_document = SBOMDocument.create("/old.json", "old.json", old_scan.id, format="spdx")
    _link(old_document, package, source_urls=["https://gitlab.com/a-obsolete/shared"])
    other_scan = Scan.create("SBOM", uuid.UUID(scope["other"]))
    other_document = SBOMDocument.create("/other.json", "other.json", other_scan.id, format="spdx")
    _link(other_document, package, source_urls=["https://gitlab.com/a-other/shared"])
    db.session.commit()
    _run([scope["variant"]], refresher)
    result = _health(app, f"variant_id={scope['variant']}")["packages"]["shared@1"]
    assert result["repository"] == "gitlab.com/z-first/shared"
    _run([scope["other"]], refresher)
    result = _health(app, f"variant_id={scope['other']}")["packages"]["shared@1"]
    assert result["repository"] == "gitlab.com/a-other/shared"
    result = _health(app, f"variant_id={scope['variant']}")["packages"]["shared@1"]
    assert result["repository"] == "gitlab.com/z-first/shared"


def test_cve_evidence_uses_only_selected_active_scans(app, scope):
    package = Package.get_by_string_id("lonely@1.0")
    variant_id = uuid.UUID(scope["variant"])
    old_sbom = Scan.create("old SBOM", variant_id)
    old_sbom.timestamp -= datetime.timedelta(days=1)
    other = Scan.create("other", uuid.UUID(scope["other"]))
    old_tool = Scan.create("old OSV", variant_id, "tool", "osv")
    old_tool.timestamp -= datetime.timedelta(days=1)
    active_tool = Scan.create("OSV", variant_id, "tool", "osv")
    for cve_id, scan in (("CVE-2026-0001", old_sbom), ("CVE-2026-0002", other),
                         ("CVE-2026-0003", old_tool), ("CVE-2026-0004", active_tool)):
        Vulnerability.create_record(id=cve_id, description="test")
        finding = Finding.create(package.id, cve_id)
        Observation.create(finding.id, scan.id)
    db.session.commit()
    scan_ids = health.active_sbom_scan_ids_for_variant(variant_id)
    assert health._cve_ids_by_package([package.id], scan_ids) == {package.id: ["CVE-2026-0004"]}


@pytest.mark.parametrize("app", ["file"], indirect=True)
def test_external_lookups_release_sqlite_writer(app, scope, apis):
    service, _ = apis
    database = db.engine.url.database
    checked = []

    class WriterCheckingApi(JsonApi):
        def get(self, *segments):
            with sqlite3.connect(database, timeout=0.1) as writer:
                writer.execute("BEGIN IMMEDIATE")
                writer.execute("UPDATE projects SET name = name")
            checked.append(self.base_url)
            return super().get(*segments)

    base = f"http://127.0.0.1:{service.server_port}"
    refresher = health.PackageHealthRefresher(**{
        name: WriterCheckingApi(f"{base}/{name}", timeout=5, retries=1, backoff=0)
        for name in ("scorecard", "depsdev", "osv", "github")
    })
    _run([scope["variant"]], refresher)
    assert {url.rsplit("/", 1)[-1] for url in checked} == {"scorecard", "depsdev", "osv", "github"}
    assert _health(app, f"variant_id={scope['variant']}")["packages"]["react@18.2.0"]["repository"] == (
        "github.com/facebook/react")


def test_force_and_stale_rows_are_resolved_again(app, scope, apis):
    service, refresher = apis
    _run([scope["variant"]], refresher)
    curl = Package.get_by_string_id("curl@8.0.0")
    lonely = Package.get_by_string_id("lonely@1.0")
    link = SBOMPackage.get_by_package(lonely.id)[0]
    link.upstream_urls = ["https://gitlab.com/lonely/lonely"]
    db.session.commit()
    refresher.now = health._utcnow()
    _run([scope["variant"]], refresher)
    assert db.session.get(PackageRepository, _repository_key(lonely, scope)).repository == "gitlab.com/lonely/lonely"
    for link in SBOMPackage.get_by_package(curl.id):
        link.upstream_urls = None
    db.session.commit()
    _run([scope["variant"]], refresher)
    assert db.session.get(PackageRepository, _repository_key(curl, scope)).source == "none"
    requests = len(service.requests)
    _run([scope["variant"]], refresher, force=True)
    forced = [path for path, _ in service.requests[requests:]]
    assert "/depsdev/systems/NPM/packages/react/versions/18.2.0" in forced
    assert "/scorecard/projects/github.com/facebook/react" in forced


def test_network_failures_never_cache_an_unknown_repository(app, scope, apis):
    service, refresher = apis
    del service.routes["/osv/vulns/CVE-2023-4911"]
    service.routes["/osv/vulns/CVE-2023-0464"] = [(500, {"error": "down"})]
    _run([scope["variant"]], refresher)
    openssl = Package.get_by_string_id("openssl@3.0.1")
    assert db.session.get(PackageRepository, _repository_key(openssl, scope)) is None
    glibc = Package.get_by_string_id("glibc@2.41")
    assert db.session.get(PackageRepository, _repository_key(glibc, scope)).source == "none"


def test_consecutive_failures_abort_with_an_actionable_error(app):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed = JsonApi(f"http://127.0.0.1:{probe.getsockname()[1]}", timeout=2, retries=1)
    refresher = health.PackageHealthRefresher(scorecard=closed, depsdev=closed, osv=closed)
    for _ in range(health.MAX_CONSECUTIVE_FAILURES - 1):
        assert refresher._get(closed, "x") == (False, None)
    with pytest.raises(OperationError, match=health.ENABLED_ENV):
        refresher._get(closed, "x")


def test_github_name_lookups_degrade_quietly(app, service, monkeypatch):  # noqa: F811
    base = f"http://127.0.0.1:{service.server_port}"
    service.routes["/repos/limited/lib"] = [(403, {"message": "rate limited"})]
    service.routes["/repos/odd/lib"] = [(200, {"name": "lib"})]
    refresher = health.PackageHealthRefresher(github=JsonApi(base, timeout=5, retries=1))
    assert refresher._github_name("gitlab.com/acme/lib") is None
    assert refresher._github_name("github.com/missing/lib") is None
    assert refresher._github_name("github.com/odd/lib") is None
    assert refresher._github_available is True
    assert refresher._github_name("github.com/limited/lib") is None
    assert refresher._github_available is False
    assert refresher._github_name("github.com/odd/lib") is None
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed = JsonApi(f"http://127.0.0.1:{probe.getsockname()[1]}", timeout=2, retries=1)
    unreachable = health.PackageHealthRefresher(github=closed)
    assert unreachable._github_name("github.com/acme/lib") is None
    assert unreachable._github_available is False
    monkeypatch.setenv("GITHUB_TOKEN", " secret ")
    assert health._github_headers()["Authorization"] == "Bearer secret"
    monkeypatch.delenv("GITHUB_TOKEN")
    assert "Authorization" not in health._github_headers()


def test_cancellation_commits_and_stops(app, scope, apis):
    _, refresher = apis
    ctx = RecordingContext({"variant_ids": [scope["variant"]]})
    ctx.request_cancel()
    with pytest.raises(CancelledError):
        health.run_scorecard_refresh(ctx, refresher)
    assert db.session.query(PackageRepository).count() == 0


def test_disabled_lookups_do_nothing(app, scope, monkeypatch):
    monkeypatch.setenv(health.ENABLED_ENV, "off")
    ctx = RecordingContext({"variant_ids": [scope["variant"]]})
    health.run_scorecard_refresh(ctx)
    assert ctx.messages == [f"OpenSSF Scorecard lookups are disabled ({health.ENABLED_ENV}=0)"]
    assert _health(app, f"variant_id={scope['variant']}") == {"enabled": False, "packages": {}}


def test_repository_awaiting_its_first_lookup_has_no_scorecard(app, scope):
    lonely = Package.get_by_string_id("lonely@1.0")
    db.session.add(PackageRepository(package_id=lonely.id, evidence_key=_repository_key(lonely, scope)[1],
                                     repository="github.com/acme/lonely", source="sbom",
                                     resolved_at=health._utcnow()))
    db.session.commit()
    result = _health(app, f"variant_id={scope['variant']}")["packages"]["lonely@1.0"]
    assert result["repository"] == "github.com/acme/lonely"
    assert result["scorecard"] is None
    assert result["deprecated"] is None


def test_orphan_rows_are_removed(app, scope, apis):
    _, refresher = apis
    orphan = Package.find_or_create("orphan", "1")
    orphan_id = orphan.id
    db.session.add(PackageRepository(package_id=orphan_id, repository=None, source="none",
                                     resolved_at=health._utcnow()))
    db.session.commit()
    db.session.execute(db.delete(Package).where(Package.id == orphan_id))
    db.session.commit()
    db.session.expunge_all()
    _run([scope["variant"]], refresher)
    assert db.session.query(PackageRepository).filter_by(package_id=orphan_id).count() == 0


def test_health_api_scopes(app, scope, apis):
    _, refresher = apis
    _run([scope["variant"]], refresher)
    client = app.test_client()
    assert client.get("/api/packages/health").status_code == 400
    assert client.get("/api/packages/health?variant_id=nope").status_code == 400
    assert client.get("/api/packages/health?project_id=nope").status_code == 400
    assert len(_health(app, f"project_id={scope['project']}")["packages"]) == 7
    assert len(_health(app, f"variant_ids={scope['other']},{scope['variant']}")["packages"]) == 7
    assert len(_health(app, f"variant_id={scope['other']}&compare_variant_id={scope['variant']}")["packages"]) == 7
    assert _health(app, f"variant_id={scope['other']}")["packages"] == {}
    assert _health(app, f"variant_id={scope['variant']}&package_id=missing@1")["packages"] == {}


def test_scorecard_refresh_is_planned_per_variant_selection(app, scope, monkeypatch):
    # Planning only: queued jobs must not run against the public APIs.
    monkeypatch.setattr(OperationQueue, "submit", lambda *args, **kwargs: None)
    client = app.test_client()
    registry.clear()
    response = client.post("/api/operations", json={"jobs": [
        {"kind": "refresh", "source": "scorecard", "variant_ids": [scope["variant"]], "options": {"force": True}},
    ]})
    assert response.status_code == 202, response.get_json()
    operation = response.get_json()["operations"][0]
    assert operation["label"] == "OpenSSF Scorecard"
    assert operation["options"] == {"variant_ids": [scope["variant"]], "force": True}
    registry.clear()
    for job, status in (
        ({"ids": ["CVE-2024-0001"], "variant_ids": [scope["variant"]]}, 400),
        ({}, 400),
        ({"variant_ids": ["nope"]}, 400),
        ({"variant_ids": [scope["variant"]], "options": {"force": "yes"}}, 400),
        ({"variant_ids": ["00000000-0000-0000-0000-000000000000"]}, 404),
    ):
        response = client.post("/api/operations", json={"jobs": [{"kind": "refresh", "source": "scorecard", **job}]})
        assert response.status_code == status, (job, response.get_json())
    registry.clear()


@pytest.mark.parametrize("value,enabled", [(None, True), ("1", True), ("0", False), ("False", False), ("no", False)])
def test_enabled_switch(monkeypatch, value, enabled):
    if value is None:
        monkeypatch.delenv(health.ENABLED_ENV, raising=False)
    else:
        monkeypatch.setenv(health.ENABLED_ENV, value)
    assert health.scorecard_enabled() is enabled


@pytest.mark.parametrize("cpe,expected", [
    ("cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*", ("openssl", "openssl")),
    ("cpe:2.3:a:*:Busybox:1:*:*:*:*:*:*:*", ("*", "busybox")),
    ("cpe:2.3:a:vendor:*:1", None),
    ("cpe:2.3:a", None),
    ("not:a:cpe:at:all", None),
    (None, None),
])
def test_cpe_product(cpe, expected):
    assert health.cpe_product(cpe) == expected


def test_sbom_repository_prefers_tiers_then_scorecard_hosts():
    assert health.sbom_repository(["pkg:generic/x@1"], [], []) is None
    assert health.sbom_repository(["pkg:github/acme/lib@1"], [], ["https://github.com/other/lib"]) == (
        "github.com/acme/lib", "pkg:github/acme/lib@1")
    assert health.sbom_repository([], [], [
        "git://git.example.org/lib.git", "https://github.com/acme/lib/archive/v1.tar.gz",
    ]) == ("github.com/acme/lib", "https://github.com/acme/lib/archive/v1.tar.gz")
    assert health.sbom_repository([], [], ["git://git.example.org/lib.git"]) == (
        "git.example.org/lib", "git://git.example.org/lib.git")
    assert health.sbom_repository([], ["git+https://github.com/mirror/busybox@" + "a" * 40], []) is None


@pytest.mark.parametrize("purl,expected", [
    ("pkg:npm/%40colors/colors@1.5.0", ("NPM", "@colors/colors", "1.5.0")),
    ("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
     ("MAVEN", "org.apache.logging.log4j:log4j-core", "2.17.0")),
    ("pkg:maven/log4j-core@2.17.0", None),
    ("pkg:pypi/Zope.Interface@5.0", ("PYPI", "zope-interface", "5.0")),
    ("pkg:golang/github.com/gorilla/mux@v1.8.0", ("GO", "github.com/gorilla/mux", "v1.8.0")),
    ("pkg:cargo/serde@1.0.0", ("CARGO", "serde", "1.0.0")),
    ("pkg:npm/react", None),
    ("pkg:generic/openssl@3", None),
    ("not-a-purl", None),
])
def test_depsdev_key(purl, expected):
    assert health.depsdev_key(purl) == expected


def test_depsdev_repository_prefers_attested_links():
    payload = {"relatedProjects": [
        {"projectKey": {"id": "github.com/unverified/lib"}, "relationType": "SOURCE_REPO",
         "relationProvenance": "UNVERIFIED_METADATA"},
        {"projectKey": {"id": "github.com/lib/issues"}, "relationType": "ISSUE_TRACKER"},
        {"projectKey": {"id": "github.com/mirror/lib"}, "relationType": "SOURCE_REPO",
         "relationProvenance": "SLSA_ATTESTATION"},
        {"projectKey": {"id": "github.com/attested/lib"}, "relationType": "SOURCE_REPO",
         "relationProvenance": "SLSA_ATTESTATION"},
        "invalid",
    ]}
    assert health.depsdev_repository(payload) == "github.com/attested/lib"
    assert health.depsdev_repository({"relatedProjects": [{"relationType": "SOURCE_REPO"}]}) is None


def test_osv_repository_requires_matching_product_or_name():
    cpes = ["cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*"]
    assert health.osv_repository(OPENSSL_CVE, "openssl", cpes) == "github.com/openssl/openssl"
    assert health.osv_repository(OPENSSL_CVE, "libssl", ["cpe:2.3:a:other:openssl:1:*:*:*:*:*:*:*"]) is None
    assert health.osv_repository(GLIBC_CVE, "glibc", ["cpe:2.3:a:*:glibc:2.41:*:*:*:*:*:*:*"]) == (
        "sourceware.org/git/glibc")
    unnamed = {"affected": [None, {"ranges": ["bad", {"type": "GIT", "repo": "https://github.com/zlib/zlib"}]}]}
    assert health.osv_repository(unnamed, "zlib", []) == "github.com/zlib/zlib"
    assert health.osv_repository(unnamed, "libz", []) is None
    assert health.osv_repository({"affected": [{"ranges": [{"type": "GIT", "repo": "not a url"}]}]}, "x", []) is None


def test_package_merge_keeps_upstream_urls():
    package = Package("lib", "1.0")
    other = Package("lib", "1.0")
    other.add_upstream_url("https://github.com/acme/lib")
    other.add_upstream_url("https://github.com/acme/lib")
    other.add_upstream_url("https://example.org/lib-1.0.tar.gz")
    assert other.upstream_urls == ["https://github.com/acme/lib"]
    assert package.merge(other)
    assert package.upstream_urls == ["https://github.com/acme/lib"]


def _spdx2(packages):
    return {
        "spdxVersion": "SPDX-2.2", "SPDXID": "SPDXRef-DOCUMENT", "name": "upstream", "dataLicense": "CC0-1.0",
        "documentNamespace": "http://spdx.org/spdxdocs/upstream",
        "creationInfo": {"creators": ["Tool: test"], "created": "2024-01-01T00:00:00Z"},
        "packages": [{"SPDXID": f"SPDXRef-{index}", "name": name, "versionInfo": "1.0", **fields}
                     for index, (name, fields) in enumerate(packages)],
    }


@pytest.mark.parametrize("ignore_parsing_errors", ["false", "true"])
def test_sbom_imports_record_upstream_urls(app, tmp_path, monkeypatch, ignore_parsing_errors):
    monkeypatch.setenv("IGNORE_PARSING_ERRORS", ignore_parsing_errors)
    documents = {
        "spdx2.spdx.json": ("spdx", _spdx2([
            ("bash-completion", {"downloadLocation":
                                 "https://github.com/scop/bash-completion/releases/download/2.16.0/b.tar.xz"}),
            ("acl", {"downloadLocation": "NOASSERTION", "homepage": "https://gitlab.com/acl/acl"}),
            ("tarball", {"downloadLocation": "https://ftp.gnu.org/gnu/tarball-1.0.tar.gz"}),
        ])),
        "spdx3.spdx.json": ("spdx", {"@graph": [
            {"type": "CreationInfo", "specVersion": "3.0.1"},
            {"type": "software_Package", "spdxId": "pkg:hal", "name": "hal", "software_packageVersion": "1.0",
             "software_downloadLocation": "git+https://github.com/zephyrproject-rtos/hal_adi@" + "a" * 40},
            {"type": "software_Package", "spdxId": "pkg:web", "name": "web", "software_packageVersion": "1.0",
             "software_homePage": "https://example.org",
             "externalRef": [{"type": "ExternalRef", "externalRefType": "vcs",
                              "locator": ["https://github.com/acme/web.git"]},
                             {"type": "ExternalRef", "externalRefType": "documentation",
                              "locator": "https://github.com/acme/docs"}, "invalid"]},
        ]}),
        "bom.cdx.json": ("cdx", {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [
            {"type": "library", "bom-ref": "lib", "name": "lib", "version": "1.0", "externalReferences": [
                {"type": "vcs", "url": "https://github.com/acme/lib"},
                {"type": "documentation", "url": "https://github.com/acme/handbook"},
            ]},
        ]}),
    }
    project = Project.create("upstream")
    variant = Variant.create("default", project.id)
    scan = Scan.create("SBOM", variant.id)
    for name, (fmt, document) in documents.items():
        path = tmp_path / name
        path.write_text(json.dumps(document))
        SBOMDocument.create(str(path), name, scan.id, format=fmt)
    read_inputs(ControllersCache(), scan.id)
    db.session.commit()
    upstream = {
        link.package.name: link.upstream_urls
        for document in SBOMDocument.get_by_scan(scan.id) for link in SBOMPackage.get_by_document(document.id)
    }
    assert upstream["bash-completion"] == [
        "https://github.com/scop/bash-completion/releases/download/2.16.0/b.tar.xz"]
    assert upstream["acl"] == ["https://gitlab.com/acl/acl"]
    assert upstream["tarball"] is None
    assert upstream["hal"] == ["git+https://github.com/zephyrproject-rtos/hal_adi@" + "a" * 40]
    assert upstream["web"] == ["https://github.com/acme/web.git"]
    assert upstream["lib"] == ["https://github.com/acme/lib"]


@pytest.fixture()
def live_network():
    try:
        socket.create_connection(("api.scorecard.dev", 443), timeout=5).close()
    except OSError:
        pytest.skip("public APIs are unreachable from this environment")


def test_live_refresh_scores_a_github_package(app, live_network):
    project = Project.create("live")
    variant = Variant.create("board", project.id)
    scan = Scan.create("SBOM", variant.id)
    document = SBOMDocument.create("/live.json", "live.json", scan.id, format="spdx")
    package = Package.find_or_create("curl", "8.0.0", purl=["pkg:github/curl/curl@curl-8_0_0"])
    _link(document, package, purl=["pkg:github/curl/curl@curl-8_0_0"])
    db.session.commit()
    _run([str(variant.id)], health.PackageHealthRefresher())
    result = _health(app, f"variant_id={variant.id}&package_id=curl@8.0.0")["packages"]["curl@8.0.0"]
    assert result["repository"] == "github.com/curl/curl"
    assert result["scorecard"]["status"] == "scored"
    assert 0 <= result["scorecard"]["score"] <= 10
    assert datetime.date.fromisoformat(result["scorecard"]["date"][:10]) > datetime.date(2024, 1, 1)
    assert any(check["name"] == "Maintained" for check in result["scorecard"]["checks"])


def test_live_scorecard_lookup_falls_back_to_lowercase(app, live_network):
    refresher = health.PackageHealthRefresher()
    refresher.refresh_scorecard("github.com/OpenSSL/OpenSSL", None)
    db.session.commit()
    row = db.session.get(RepositoryScorecard, "github.com/OpenSSL/OpenSSL")
    assert row.status == "scored"
    assert row.score is not None
