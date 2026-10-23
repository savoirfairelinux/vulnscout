# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""A scan archive must preserve scoped scanner inputs, not just display names."""

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
import uuid

import pytest

from src.bin.cmd_process import read_inputs
from src.bin.webapp import create_app
from src.controllers import ControllersCache
from src.extensions import db
from src.helpers.active_scans import package_snapshots_for_sbom_scans
from src.models import Finding, Package, Project, SBOMDocument, SBOMPackage, Scan, Variant
from src.models.sbom_package import SBOMReimportRequiredError
from src.routes import scans as scan_routes


@pytest.fixture
def app(monkeypatch, tmp_path):
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("SBOM_CVE_CHECK_DATABASES_DIR", str(tmp_path / "advisories"))
    status = tmp_path / "status"
    status.write_text("__END_OF_SCAN_SCRIPT__\n")
    application = create_app()
    application.config.update(TESTING=True, SCAN_FILE=str(status))
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


def _variant(project_name, variant_name):
    project = Project.create(project_name)
    return Variant.create(variant_name, project.id)


def _zephyr_scan():
    variant = _variant("zephyr-source", "original")
    scan = Scan.create("Example Zephyr", variant.id)
    for path in sorted((Path(__file__).parents[2] / "example" / "zephyr").glob("*.jsonld")):
        SBOMDocument.create(str(path), path.name, scan.id, format="spdx")
    read_inputs(ControllersCache(), scan.id)
    db.session.commit()
    return scan


def _snapshots(scan_id):
    snapshots = {}
    for package in package_snapshots_for_sbom_scans([scan_id]):
        version_info = package.version_info
        version_info["version_evidence"].sort(key=lambda item: (item["source"], item["identifier"], item["version"]))
        snapshots[package.string_id] = (
            sorted(package.cpe), sorted(package.purl), sorted(package.source_urls),
            version_info, package.component_types,
        )
    return snapshots


def _advisory_scan(app, project, variant, backend):
    if backend == "nvd":
        args = ["nvd-scan", "--mode", "api"]
        target = "src.bin.cmd_vuln_scan.NVD_DB.api_get_cves_by_cpe"
        advisory = {"cve": {"id": "CVE-2099-12345", "descriptions": []}}
    else:
        args = ["osv-scan"]
        target = "src.bin.cmd_vuln_scan.OSVClient.query_by_purl"
        advisory = {"id": "CVE-2099-12345", "summary": "Mock advisory"}
    with patch(target, return_value=[advisory]) as query:
        result = app.test_cli_runner().invoke(
            args=[*args, "--project", project, "--variant", variant],
        )
    assert result.exit_code == 0, result.output
    assert query.call_count > 0
    findings = {
        (finding.package.string_id, finding.vulnerability_id)
        for finding in db.session.execute(db.select(Finding)).scalars()
    }
    assert findings
    return {call.args[0] for call in query.call_args_list}, findings


@pytest.mark.parametrize("endpoint", ["export-result", "export-diff", "bulk-total", "bulk-diff"])
@pytest.mark.parametrize("backend", ["nvd", "osv"])
def test_example_zephyr_roundtrip_still_queries_advisories(app, endpoint, backend):
    scan = _zephyr_scan()
    snapshots = _snapshots(scan.id)
    assert len(snapshots) == 96
    expected_queries, expected_findings = _advisory_scan(app, "zephyr-source", "original", backend)
    client = app.test_client()
    if endpoint.startswith("bulk-"):
        response = client.get(f"/api/scans/export?type={endpoint.removeprefix('bulk-')}")
        payload = next(entry for entry in response.json if entry["scan_id"] == str(scan.id))
    else:
        response = client.get(f"/api/scans/{scan.id}/{endpoint}")
        payload = response.json
    assert response.status_code == 200
    assert len(payload["packages"]) == 96

    # An empty destination prevents shared global Package identifiers from
    # accidentally hiding a broken archive, as reimporting in place can do.
    db.session.remove()
    db.drop_all()
    db.create_all()
    _variant("zephyr-destination", "restored")
    payload.update(project_name="zephyr-destination", variant_name="restored")
    response = client.post("/api/scans/import", json=payload)
    assert response.status_code == 201, response.json
    restored_id = uuid.UUID(response.json["scan_id"])
    assert _snapshots(restored_id) == snapshots
    queries, findings = _advisory_scan(app, "zephyr-destination", "restored", backend)
    assert queries == expected_queries
    assert findings == expected_findings


def _archive(app):
    scan = _zephyr_scan()
    return app.test_client().get(f"/api/scans/{scan.id}/export-result").json


def test_legacy_archive_does_not_inherit_other_variants_identifiers(app):
    payload = _archive(app)
    for package in payload["packages"]:
        package.pop("sbom_evidence")
    _variant("legacy-destination", "restored")
    payload.update(project_name="legacy-destination", variant_name="restored")
    response = app.test_client().post("/api/scans/import", json=payload)
    assert response.status_code == 201
    with pytest.raises(SBOMReimportRequiredError):
        _snapshots(uuid.UUID(response.json["scan_id"]))


@pytest.mark.parametrize("same_variant", [False, True])
@pytest.mark.parametrize("endpoint", ["export-result", "export-diff"])
def test_export_evidence_is_scoped_to_historical_sbom(app, same_variant, endpoint):
    scan = _zephyr_scan()
    package = db.session.execute(db.select(Package).order_by(Package.name)).scalars().first()
    variant = scan.variant if same_variant else _variant("unrelated-project", "unrelated")
    later_scan = Scan.create("unrelated identifiers", variant.id)
    document = SBOMDocument.create("unrelated.json", "unrelated.json", later_scan.id)
    marker = "pkg:generic/unrelated@999.0"
    package.add_purl(marker)
    db.session.add(SBOMPackage(
        sbom_document_id=document.id, package_id=package.id, cpe=[], purl=[marker],
        source_urls=["git+https://example.org/unrelated.git@" + "a" * 40],
    ))
    db.session.commit()
    response = app.test_client().get(f"/api/scans/{scan.id}/{endpoint}")
    assert response.status_code == 200
    assert marker not in response.get_data(as_text=True)
    assert "unrelated.git" not in response.get_data(as_text=True)


@pytest.mark.parametrize("bad_evidence", [
    None, {}, [], [None], [{"cpe": "cpe:2.3:a:bad"}], [{"purl": [None]}],
    [{"source_urls": [42]}], [{"source_revisions": [""]}], [{"type": "unexpected"}],
])
def test_invalid_evidence_rejects_whole_batch_without_writing(app, bad_evidence):
    payload = _archive(app)
    _variant("invalid-destination", "restored")
    payload.update(project_name="invalid-destination", variant_name="restored")
    invalid = deepcopy(payload)
    invalid["packages"][0]["sbom_evidence"] = bad_evidence
    count = db.session.query(Scan).count()
    response = app.test_client().post("/api/scans/import", json=[payload, invalid])
    assert response.status_code == 400, response.json
    assert "sbom_evidence" in response.json["error"]
    assert db.session.query(Scan).count() == count


def test_evidence_preserves_empty_unknown_and_multiple_association_types(app):
    payload = _archive(app)
    payload["findings"] = []
    payload["assessments"] = []
    package = payload["packages"][0]
    package["sbom_evidence"] = [
        {"cpe": [], "purl": [], "source_urls": [], "source_revisions": [], "type": "workspace"},
        {"cpe": [], "purl": [], "source_urls": [], "source_revisions": [], "type": "built"},
    ]
    payload["packages"] = [package]
    _variant("typed-destination", "restored")
    payload.update(project_name="typed-destination", variant_name="restored")
    client = app.test_client()
    response = client.post("/api/scans/import", json=payload)
    assert response.status_code == 201
    scan_id = uuid.UUID(response.json["scan_id"])
    snapshots = package_snapshots_for_sbom_scans([scan_id])
    assert len(snapshots) == 1
    assert snapshots[0].cpe == snapshots[0].purl == []
    assert snapshots[0].component_types == ["built", "workspace"]
    exported = client.get(f"/api/scans/{scan_id}/export-result").json
    assert len(exported["packages"][0]["sbom_evidence"]) == 2
    # Null is not equivalent to an explicitly empty list, even on a package
    # that also has another, fully populated association.
    association = db.session.execute(
        db.select(SBOMPackage).join(SBOMDocument)
        .where(SBOMDocument.scan_id == scan_id)
    ).scalars().first()
    association.cpe = None
    db.session.commit()
    with pytest.raises(SBOMReimportRequiredError):
        _snapshots(scan_id)


@pytest.mark.parametrize("endpoint", ["export-diff", "bulk-diff"])
def test_upgraded_package_diff_roundtrip_preserves_scanner_evidence(app, endpoint):
    variant = _variant("upgrade-source", "original")
    scans = []
    for version in ("1", "2"):
        scan = Scan.create(f"foo {version}", variant.id)
        scan.timestamp = datetime(2026, 1, int(version), tzinfo=timezone.utc)
        package = Package(name="foo", version=version, supplier="")
        document = SBOMDocument(
            path=f"foo-{version}.json", source_name="foo", scan_id=scan.id,
        )
        db.session.add_all([package, document])
        db.session.flush()
        db.session.add(SBOMPackage(
            sbom_document_id=document.id, package_id=package.id,
            cpe=[f"cpe:2.3:a:example:foo:{version}:*:*:*:*:*:*:*"],
            purl=[f"pkg:generic/foo@{version}"], source_urls=[], source_revisions=[],
        ))
        db.session.commit()
        scans.append(scan)
    expected = _snapshots(scans[-1].id)
    client = app.test_client()
    if endpoint == "bulk-diff":
        response = client.get("/api/scans/export?type=diff")
        payload = next(entry for entry in response.json if entry["scan_id"] == str(scans[-1].id))
    else:
        response = client.get(f"/api/scans/{scans[-1].id}/export-diff")
        payload = response.json
    assert response.status_code == 200
    assert payload["diff"]["packages_upgraded"][0]["new_version"] == "2"
    assert [(entry["package_name"], entry["package_version"]) for entry in payload["packages"]] == [("foo", "2")]
    assert payload["packages"][0]["sbom_evidence"][0]["purl"] == ["pkg:generic/foo@2"]

    db.session.remove()
    db.drop_all()
    db.create_all()
    _variant("upgrade-destination", "restored")
    payload.update(project_name="upgrade-destination", variant_name="restored")
    response = client.post("/api/scans/import", json=payload)
    assert response.status_code == 201, response.json
    assert _snapshots(uuid.UUID(response.json["scan_id"])) == expected
    _advisory_scan(app, "upgrade-destination", "restored", "osv")


def _evidence_archive():
    return {
        "export_version": 1, "export_format": "full-result",
        "scan_id": str(uuid.uuid4()), "scan_type": "import_sbom",
        "timestamp": "2026-01-01T00:00:00Z",
        "project_name": "evidence-destination", "variant_name": "restored",
        "packages": [{
            "package_name": "foo", "package_version": "1",
            "sbom_evidence": [
                {"cpe": [], "purl": [], "source_urls": [], "source_revisions": [], "type": "normal"},
            ],
        }],
        "findings": [],
    }


@pytest.mark.parametrize("split_packages", [False, True])
def test_evidence_per_package_limit_counts_duplicates_before_deduplication(app, monkeypatch, split_packages):
    monkeypatch.setattr(scan_routes, "_MAX_IMPORT_EVIDENCE_PER_PACKAGE", 3, raising=False)
    _variant("evidence-destination", "restored")
    payload = _evidence_archive()
    package = payload["packages"][0]
    package["sbom_evidence"] *= 2 if split_packages else 4
    if split_packages:
        payload["packages"].append(deepcopy(package))
    response = app.test_client().post("/api/scans/import", json=payload)
    assert response.status_code == 400
    assert "sbom_evidence" in response.json["error"]
    assert db.session.query(Scan).count() == 0
    assert db.session.query(Package).count() == 0


@pytest.mark.parametrize("split_exports", [False, True])
def test_evidence_request_limit_rejects_batch_atomically(app, monkeypatch, split_exports):
    monkeypatch.setattr(scan_routes, "_MAX_IMPORT_EVIDENCE", 3, raising=False)
    _variant("evidence-destination", "restored")
    payload = _evidence_archive()
    payload["packages"][0]["sbom_evidence"] *= 2
    second = deepcopy(payload)
    if split_exports:
        second["scan_id"] = str(uuid.uuid4())
        second["timestamp"] = "2026-01-02T00:00:00Z"
        payload = [payload, second]
    else:
        second["packages"][0]["package_name"] = "bar"
        payload["packages"].extend(second["packages"])
    response = app.test_client().post("/api/scans/import", json=payload)
    assert response.status_code == 400
    assert "sbom_evidence" in response.json["error"]
    assert db.session.query(Scan).count() == 0


def test_evidence_limits_accept_exact_boundary(app, monkeypatch):
    monkeypatch.setattr(scan_routes, "_MAX_IMPORT_EVIDENCE_PER_PACKAGE", 3)
    monkeypatch.setattr(scan_routes, "_MAX_IMPORT_EVIDENCE", 3)
    _variant("evidence-destination", "restored")
    payload = _evidence_archive()
    payload["packages"][0]["sbom_evidence"] *= 3
    response = app.test_client().post("/api/scans/import", json=payload)
    assert response.status_code == 201, response.json
    assert db.session.query(SBOMPackage).count() == 1


def test_many_evidence_records_use_batched_flushes_and_hash_deduplication(app):
    _variant("evidence-destination", "restored")
    payload = _evidence_archive()
    evidence = payload["packages"][0]["sbom_evidence"]
    evidence[:] = [
        {**evidence[0], "purl": [f"pkg:generic/foo@{index}"]}
        for index in range(100)
    ]
    payload["packages"].append(deepcopy(payload["packages"][0]))
    with (
        patch.object(db.session(), "flush", wraps=db.session().flush) as flush,
        patch.object(scan_routes, "_import_evidence_key", wraps=scan_routes._import_evidence_key) as key,
    ):
        response = app.test_client().post("/api/scans/import", json=payload)
    assert response.status_code == 201, response.json
    assert flush.call_count < 20
    assert key.call_count == 300
    scan_id = uuid.UUID(response.json["scan_id"])
    assert db.session.query(SBOMDocument).filter_by(scan_id=scan_id).count() == 100
    restored = app.test_client().get(f"/api/scans/{scan_id}/export-result").json
    assert len(restored["packages"][0]["sbom_evidence"]) == 100
    assert {tuple(entry["purl"]) for entry in restored["packages"][0]["sbom_evidence"]} == {
        (f"pkg:generic/foo@{index}",) for index in range(100)
    }
