# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""The unified enqueue API that replaced the eight trigger endpoints."""

import os
from unittest.mock import patch

import pytest

from src.bin.webapp import create_app
from src.extensions import db as _db
from src.controllers.operation_registry import STATUS_DONE, registry


def _build_db(app):
    from src.models.package import Package
    from src.models.project import Project
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.models.scan import Scan
    from src.models.variant import Variant
    from src.models.vulnerability import Vulnerability

    with app.app_context():
        _db.drop_all()
        _db.create_all()

        project = Project.create("OpsProject")
        first = Variant.create("alpha", project.id)
        second = Variant.create("beta", project.id)

        scan = Scan.create("initial scan", first.id, scan_type="sbom")
        package = Package.find_or_create(
            "openssl", "1.1.1",
            cpe=["cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"],
            purl=["pkg:generic/openssl/openssl@1.1.1"],
        )
        Vulnerability.create_record(id="CVE-2024-1111", description="known")
        _db.session.commit()

        sbom = SBOMDocument.create("/test/sbom.json", "spdx", scan.id)
        SBOMPackage.create(sbom.id, package.id)
        _db.session.commit()

        return {
            "project_id": str(project.id),
            "variant_a": str(first.id),
            "variant_b": str(second.id),
        }


@pytest.fixture()
def app(tmp_path):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
        application._test_ids = _build_db(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def ids(app):
    return app._test_ids


@pytest.fixture(autouse=True)
def clean_registry():
    registry.clear()
    yield
    registry.clear()


@pytest.fixture(autouse=True)
def never_execute():
    """Keep enqueue tests about planning, not about running real scanners."""
    with patch("src.controllers.operation_queue.OperationQueue.submit"):
        yield


# ---------------------------------------------------------------------------
# Planning and ordering
# ---------------------------------------------------------------------------

def test_one_request_queues_scans_then_refreshes_in_canonical_order(client, ids):
    response = client.post("/api/operations", json={"jobs": [
        {"kind": "refresh", "source": "epss", "ids": ["CVE-2024-1111"]},
        {"kind": "scan", "source": "scc", "variant_ids": [ids["variant_a"]]},
        {"kind": "scan", "source": "grype", "variant_ids": [ids["variant_a"]]},
        {"kind": "refresh", "source": "nvd", "ids": ["CVE-2024-1111"]},
    ]})

    assert response.status_code == 202
    assert [op["op_id"] for op in response.get_json()["operations"]] == [
        f"scan:grype:{ids['variant_a']}",
        f"scan:scc:{ids['variant_a']}",
        "refresh:nvd",
        "refresh:epss",
    ]


def test_a_scan_expands_to_one_operation_per_variant(client, ids):
    response = client.post("/api/operations", json={"jobs": [
        {"kind": "scan", "source": "grype",
         "variant_ids": [ids["variant_a"], ids["variant_b"]]},
    ]})

    operations = response.get_json()["operations"]
    assert [op["position"] for op in operations] == [1, 2]
    assert [op["scope"]["variant_name"] for op in operations] == ["alpha", "beta"]


def test_every_operation_in_a_batch_shares_one_queue_id(client, ids):
    payload = client.post("/api/operations", json={"jobs": [
        {"kind": "scan", "source": "grype", "variant_ids": [ids["variant_a"]]},
        {"kind": "refresh", "source": "epss", "ids": ["CVE-2024-1111"]},
    ]}).get_json()

    queue_ids = {op["queue_id"] for op in payload["operations"]}
    assert queue_ids == {payload["queue_id"]}


def test_deferred_refresh_is_reserved_with_its_scan_batch(client, ids):
    payload = client.post("/api/operations", json={"jobs": [
        {"kind": "scan", "source": "grype", "variant_ids": [ids["variant_a"]]},
        {"kind": "refresh", "source": "epss", "variant_ids": [ids["variant_a"]],
         "exclude_ids": ["CVE-2024-1111"]},
    ]}).get_json()

    assert [operation["op_id"] for operation in payload["operations"]] == [
        f"scan:grype:{ids['variant_a']}",
        "refresh:epss",
    ]
    refresh = payload["operations"][1]
    assert refresh["queue_id"] == payload["queue_id"]
    assert refresh["options"]["variant_ids"] == [ids["variant_a"]]
    assert refresh["options"]["exclude_ids"] == ["CVE-2024-1111"]
    assert refresh["cancellable"] is True


def test_scan_options_are_carried_onto_the_operation(client, ids):
    response = client.post("/api/operations", json={"jobs": [
        {"kind": "scan", "source": "nvd", "variant_ids": [ids["variant_a"]],
         "options": {"exclude_kernel": False, "mode": "api"}},
    ]})

    options = response.get_json()["operations"][0]["options"]
    assert options["exclude_kernel"] is False
    assert options["mode"] == "api"


def test_operations_start_queued_so_the_ui_can_show_the_whole_batch(client, ids):
    response = client.post("/api/operations", json={"jobs": [
        {"kind": "scan", "source": "grype",
         "variant_ids": [ids["variant_a"], ids["variant_b"]]},
    ]})

    assert {op["status"] for op in response.get_json()["operations"]} == {"queued"}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_empty_job_list_is_rejected(client):
    assert client.post("/api/operations", json={"jobs": []}).status_code == 400


def test_unknown_scan_source_is_rejected(client, ids):
    response = client.post("/api/operations", json={"jobs": [
        {"kind": "scan", "source": "nessus", "variant_ids": [ids["variant_a"]]},
    ]})
    assert response.status_code == 400
    assert "nessus" in response.get_json()["error"]


def test_malformed_variant_id_is_rejected(client):
    response = client.post("/api/operations", json={"jobs": [
        {"kind": "scan", "source": "grype", "variant_ids": ["not-a-uuid"]},
    ]})
    assert response.status_code == 400


def test_unknown_variant_returns_404(client):
    response = client.post("/api/operations", json={"jobs": [
        {"kind": "scan", "source": "grype",
         "variant_ids": ["11111111-1111-1111-1111-111111111111"]},
    ]})
    assert response.status_code == 404


def test_refresh_without_valid_identifiers_is_rejected(client):
    response = client.post("/api/operations", json={"jobs": [
        {"kind": "refresh", "source": "nvd", "ids": ["not-a-cve"]},
    ]})
    assert response.status_code == 400


def test_epss_refresh_requires_at_least_one_known_cve(client):
    response = client.post("/api/operations", json={"jobs": [
        {"kind": "refresh", "source": "epss", "ids": ["CVE-2000-9999"]},
    ]})
    assert response.status_code == 400


def test_ghsa_refresh_rejects_cve_identifiers(client):
    response = client.post("/api/operations", json={"jobs": [
        {"kind": "refresh", "source": "ghsa", "ids": ["CVE-2024-1111"]},
    ]})
    assert response.status_code == 400


def test_nothing_is_queued_when_planning_fails(client, ids):
    client.post("/api/operations", json={"jobs": [
        {"kind": "scan", "source": "grype", "variant_ids": [ids["variant_a"]]},
        {"kind": "scan", "source": "grype", "variant_ids": ["not-a-uuid"]},
    ]})
    assert registry.snapshot() == []


def test_the_same_operation_twice_in_one_batch_is_rejected(client, ids):
    response = client.post("/api/operations", json={"jobs": [
        {"kind": "scan", "source": "grype", "variant_ids": [ids["variant_a"]]},
        {"kind": "scan", "source": "grype", "variant_ids": [ids["variant_a"]]},
    ]})
    assert response.status_code == 400
    assert response.get_json()["operations"] == [f"scan:grype:{ids['variant_a']}"]


def test_relaunching_an_active_operation_conflicts(client, ids):
    job = {"kind": "scan", "source": "grype", "variant_ids": [ids["variant_a"]]}
    assert client.post("/api/operations", json={"jobs": [job]}).status_code == 202

    response = client.post("/api/operations", json={"jobs": [job]})
    assert response.status_code == 409
    assert response.get_json()["operations"] == [f"scan:grype:{ids['variant_a']}"]


def test_a_finished_operation_can_be_relaunched(client, ids):
    job = {"kind": "scan", "source": "grype", "variant_ids": [ids["variant_a"]]}
    client.post("/api/operations", json={"jobs": [job]})
    registry.update(f"scan:grype:{ids['variant_a']}", status=STATUS_DONE)

    assert client.post("/api/operations", json={"jobs": [job]}).status_code == 202


def test_non_object_options_are_rejected(client, ids):
    response = client.post("/api/operations", json={"jobs": [
        {"kind": "scan", "source": "grype", "variant_ids": [ids["variant_a"]],
         "options": "exclude_kernel"},
    ]})
    assert response.status_code == 400
    assert "options must be an object" in response.get_json()["error"]


def test_unknown_mode_is_rejected(client, ids):
    response = client.post("/api/operations", json={"jobs": [
        {"kind": "scan", "source": "nvd", "variant_ids": [ids["variant_a"]],
         "options": {"mode": "turbo"}},
    ]})
    assert response.status_code == 400
    assert "Unsupported mode" in response.get_json()["error"]


def test_string_exclude_kernel_is_rejected_instead_of_truthy_coerced(client, ids):
    response = client.post("/api/operations", json={"jobs": [
        {"kind": "scan", "source": "grype", "variant_ids": [ids["variant_a"]],
         "options": {"exclude_kernel": "false"}},
    ]})
    assert response.status_code == 400
    assert "exclude_kernel must be a boolean" in response.get_json()["error"]


def test_refresh_with_unknown_mode_is_rejected(client):
    response = client.post("/api/operations", json={"jobs": [
        {"kind": "refresh", "source": "nvd", "ids": ["CVE-2024-1111"],
         "options": {"mode": "remote"}},
    ]})
    assert response.status_code == 400
    assert "Unsupported mode" in response.get_json()["error"]


def test_concurrent_requests_for_the_same_operation_yield_one_winner(app):
    """The conflict check and the registry writes happen under one lock."""
    import threading

    # An nvd refresh plans without touching the database, so every thread
    # reaches the enqueue step and the race is purely about the lock.
    job = {"kind": "refresh", "source": "nvd", "ids": ["CVE-2024-1111"]}
    attempts = 8
    barrier = threading.Barrier(attempts)
    statuses = []
    statuses_lock = threading.Lock()

    def submit():
        thread_client = app.test_client()
        barrier.wait()
        response = thread_client.post("/api/operations", json={"jobs": [job]})
        with statuses_lock:
            statuses.append(response.status_code)

    threads = [threading.Thread(target=submit) for _ in range(attempts)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(statuses) == [202] + [409] * (attempts - 1)
    assert len(registry.snapshot()) == 1


# ---------------------------------------------------------------------------
# Snapshot, cancel, dismiss
# ---------------------------------------------------------------------------

def test_snapshot_endpoint_mirrors_the_stream(client, ids):
    client.post("/api/operations", json={"jobs": [
        {"kind": "scan", "source": "grype", "variant_ids": [ids["variant_a"]]},
    ]})

    payload = client.get("/api/operations").get_json()
    assert [op["op_id"] for op in payload["operations"]] == [
        f"scan:grype:{ids['variant_a']}"
    ]


def test_cancelling_an_unknown_operation_returns_404(client):
    assert client.post("/api/operations/scan:grype:nope/cancel").status_code == 404


def test_cancelling_an_unsupported_operation_returns_409(client):
    registry.create(
        op_id="upload:active", kind="upload", source="sbom", label="SBOM import",
        lane="upload",
    )

    response = client.post("/api/operations/upload:active/cancel")

    assert response.status_code == 409
    assert "does not support cancellation" in response.get_json()["error"]


def test_cancelling_a_batch_reports_how_many_stopped(client, ids):
    payload = client.post("/api/operations", json={"jobs": [
        {"kind": "scan", "source": "grype",
         "variant_ids": [ids["variant_a"], ids["variant_b"]]},
    ]}).get_json()

    response = client.post(f"/api/operations/queue/{payload['queue_id']}/cancel")
    assert response.status_code == 200


def test_dismiss_removes_a_finished_operation(client, ids):
    client.post("/api/operations", json={"jobs": [
        {"kind": "scan", "source": "grype", "variant_ids": [ids["variant_a"]]},
    ]})
    op_id = f"scan:grype:{ids['variant_a']}"
    registry.update(op_id, status=STATUS_DONE)

    assert client.delete(f"/api/operations/{op_id}").status_code == 200
    assert registry.get(op_id) is None


def test_dismiss_refuses_while_the_operation_is_active(client, ids):
    client.post("/api/operations", json={"jobs": [
        {"kind": "scan", "source": "grype", "variant_ids": [ids["variant_a"]]},
    ]})

    response = client.delete(f"/api/operations/scan:grype:{ids['variant_a']}")
    assert response.status_code == 409
