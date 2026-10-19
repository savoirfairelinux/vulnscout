"""Project scan configuration API with real database and cache storage."""

import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import UUID

import pytest
from sqlalchemy import event

from src.bin.webapp import create_app
from src.extensions import db
from src.helpers.scan_configuration import (
    DEFAULT_NATIVE_EXCEPTIONS, read_scan_configuration, write_scan_configuration,
)
from src.models.project import Project
from src.models.variant import Variant
from src.models.scan import Scan
from src.models.package import Package
from src.models.sbom_document import SBOMDocument
from src.models.sbom_package import SBOMPackage


@pytest.fixture()
def configuration_api(tmp_path, monkeypatch):
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path))
    app = create_app()
    status = tmp_path / "status.txt"
    status.write_text("__END_OF_SCAN_SCRIPT__")
    app.config.update(TESTING=True, SCAN_FILE=str(status))
    with app.app_context():
        db.create_all()
        project = Project.create("First")
        other = Project.create("Second")
        variant = Variant.create("default", project.id)
        scan = Scan.create("SBOM", variant.id, scan_type="sbom")
        document = SBOMDocument.create("/test/native.json", "spdx", scan.id)
        for name in ("gcc-native", "make-native", "openssl"):
            package = Package.find_or_create(name, "1")
            SBOMPackage.create(document.id, package.id)
        db.session.commit()
        yield app.test_client(), str(project.id), str(other.id), tmp_path
        db.session.remove()
        db.drop_all()


def test_defaults_and_available_native_packages(configuration_api):
    client, project_id, _, _ = configuration_api
    response = client.get(f"/api/projects/{project_id}/scan-configuration")
    assert response.status_code == 200
    assert response.json == {
        "exclude_native": True,
        "native_package_exceptions": DEFAULT_NATIVE_EXCEPTIONS,
        "native_packages": ["gcc-native", "make-native"],
    }


def test_large_native_selection_is_supported(configuration_api):
    client, project_id, _, _ = configuration_api
    names = [f"tool-{index}-native" for index in range(1002)]
    response = client.put(f"/api/projects/{project_id}/scan-configuration", json={
        "exclude_native": True, "native_package_exceptions": names,
    })
    assert response.status_code == 200
    assert set(response.json["native_package_exceptions"]) == set(names)


@pytest.mark.parametrize("variant_count", [1, 8])
def test_native_names_use_one_project_scoped_query_for_latest_sboms(configuration_api, variant_count):
    client, project_id, other_id, _ = configuration_api
    with client.application.app_context():
        project = db.session.get(Project, UUID(project_id))
        other = db.session.get(Project, UUID(other_id))

        def add_scan(variant, name, scan_type="sbom"):
            scan = Scan.create(name, variant.id, scan_type=scan_type)
            document = SBOMDocument.create(f"/test/{name}.json", "spdx", scan.id)
            for package_name in (name, "openssl"):
                package = Package.find_or_create(package_name, "1")
                SBOMPackage.create(document.id, package.id)

        for index in range(variant_count):
            variant = Variant.create(f"variant-{index}", project.id)
            add_scan(variant, f"stale-{index}-native")
            add_scan(variant, " GCC-Native ")
            add_scan(variant, f"tool-{index}-native", "tool")
        add_scan(Variant.create("other", other.id), "other-native")
        db.session.remove()
        statements = []

        def record_statement(connection, cursor, statement, parameters, context, executemany):
            statements.append(statement)

        event.listen(db.engine, "before_cursor_execute", record_statement)
        try:
            response = client.get(f"/api/projects/{project_id}/scan-configuration")
        finally:
            event.remove(db.engine, "before_cursor_execute", record_statement)
        assert response.status_code == 200
        assert response.json["native_packages"] == [" GCC-Native ", "gcc-native", "make-native"]
        assert len(statements) == 2  # Project lookup and one scalar native-name query.
        assert not any(isinstance(value, Package) for value in db.session.identity_map.values())


def test_batch_save_validates_every_project_before_writing(configuration_api):
    client, project_id, other_id, cache = configuration_api
    configuration = {"exclude_native": True, "native_package_exceptions": ["make-native"]}
    response = client.put("/api/projects/scan-configurations", json={
        project_id: configuration, other_id: {"exclude_native": "invalid"},
    })
    assert response.status_code == 400
    assert not (cache / "project-scan.json").exists()


@pytest.mark.parametrize("value,status", [
    (None, 400), ([], 400), ({}, 400), ({"invalid": {}}, 400),
    ({"00000000-0000-0000-0000-000000000001": {}}, 404),
])
def test_invalid_batch_does_not_write(configuration_api, value, status):
    client, _, _, cache = configuration_api
    response = client.put("/api/projects/scan-configurations", json=value)
    assert response.status_code == status
    assert not (cache / "project-scan.json").exists()


def test_batch_save_is_atomic_on_replace_failure(configuration_api, monkeypatch):
    client, project_id, other_id, cache = configuration_api
    initial = {"exclude_native": False, "native_package_exceptions": []}
    write_scan_configuration("First", initial)
    before = (cache / "project-scan.json").read_bytes()

    def fail_replace(*args):
        raise OSError("Disk unavailable")

    monkeypatch.setattr("src.helpers.scan_configuration.os.replace", fail_replace)
    response = client.put("/api/projects/scan-configurations", json={
        project_id: {"exclude_native": True, "native_package_exceptions": ["make-native"]},
        other_id: initial,
    })
    assert response.status_code == 500
    assert (cache / "project-scan.json").read_bytes() == before
    assert not list(cache.glob(".project-scan-*"))


def test_batch_save_preserves_global_and_unselected_project_preferences(configuration_api):
    client, project_id, other_id, cache = configuration_api
    initial = {"exclude_native": False, "native_package_exceptions": []}
    write_scan_configuration(None, initial)
    write_scan_configuration("Unselected", initial)
    first = {"exclude_native": True, "native_package_exceptions": ["make-native"]}
    response = client.put("/api/projects/scan-configurations", json={project_id: first, other_id: initial})
    assert response.status_code == 200
    assert response.json == {project_id: first, other_id: initial}
    stored = json.loads((cache / "project-scan.json").read_text())
    assert stored == {"global": initial, "projects": {
        "First": first, "Second": initial, "Unselected": initial,
    }}


def test_configuration_survives_new_client_and_is_project_scoped(configuration_api):
    client, project_id, other_id, cache = configuration_api
    url = f"/api/projects/{project_id}/scan-configuration"
    response = client.put(url, json={
        "exclude_native": False, "native_package_exceptions": [" MAKE-native ", "make-native"],
    })
    assert response.status_code == 200
    stored = json.loads((cache / "project-scan.json").read_text())
    assert stored["projects"] == {"First": {"exclude_native": False, "native_package_exceptions": ["make-native"]}}
    assert stored["global"]["exclude_native"] is True
    assert client.application.test_client().get(url).json["native_package_exceptions"] == ["make-native"]
    assert client.get(f"/api/projects/{other_id}/scan-configuration").json["native_package_exceptions"] == sorted(DEFAULT_NATIVE_EXCEPTIONS)
    assert not list(cache.glob(".project-scan-*"))


def test_saving_another_project_preserves_existing_preferences(configuration_api):
    client, project_id, other_id, cache = configuration_api
    first = {"exclude_native": False, "native_package_exceptions": ["make-native"]}
    second = {"exclude_native": True, "native_package_exceptions": []}
    first_url = f"/api/projects/{project_id}/scan-configuration"
    second_url = f"/api/projects/{other_id}/scan-configuration"
    assert client.put(first_url, json=first).status_code == 200
    assert client.put(second_url, json=second).status_code == 200
    first["exclude_native"] = True
    assert client.put(first_url, json=first).status_code == 200
    assert json.loads((cache / "project-scan.json").read_text())["projects"] == {"First": first, "Second": second}
    assert client.get(first_url).json == {**first, "native_packages": ["gcc-native", "make-native"]}
    assert client.get(second_url).json == {**second, "native_packages": []}
    assert list(cache.glob("*.json")) == [cache / "project-scan.json"]


def test_preferences_are_looked_up_by_project_name(configuration_api):
    client, project_id, _, cache = configuration_api
    configuration = {"exclude_native": False, "native_package_exceptions": []}
    (cache / "project-scan.json").write_text(json.dumps({"First": configuration}))
    response = client.get(f"/api/projects/{project_id}/scan-configuration")
    assert response.status_code == 200
    assert response.json == {**configuration, "native_packages": ["gcc-native", "make-native"]}


def test_concurrent_saves_preserve_all_project_names(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path))
    names = ["First", "Second", "../project/name", "Project with spaces"]
    barrier = Barrier(len(names))
    configuration = {"exclude_native": False, "native_package_exceptions": ["make-native"]}

    def save(name):
        barrier.wait(timeout=10)
        return write_scan_configuration(name, configuration)

    with ThreadPoolExecutor(max_workers=len(names)) as executor:
        assert list(executor.map(save, names)) == [configuration] * len(names)
    assert json.loads((tmp_path / "project-scan.json").read_text())["projects"] == dict.fromkeys(names, configuration)
    assert all(read_scan_configuration(name) == configuration for name in names)
    assert not list(tmp_path.glob(".project-scan-*"))


@pytest.mark.parametrize("value", [None, {}, {"exclude_native": "true"}, {
    "exclude_native": True, "native_package_exceptions": ["openssl"],
}])
def test_invalid_settings_do_not_write_configuration(configuration_api, value):
    client, project_id, _, cache = configuration_api
    assert client.put(f"/api/projects/{project_id}/scan-configuration", json=value).status_code == 400
    assert not (cache / "project-scan.json").exists()


@pytest.mark.parametrize("project_id,status", [("invalid", 400), ("00000000-0000-0000-0000-000000000001", 404)])
def test_unknown_project_is_rejected(configuration_api, project_id, status):
    client, _, _, _ = configuration_api
    assert client.get(f"/api/projects/{project_id}/scan-configuration").status_code == status


@pytest.mark.parametrize("content", [
    "not json", "[]", '{"First": {}}', '{"Second": null}',
    '{"global": {}, "projects": {}}',
    '{"global": {"exclude_native": true, "native_package_exceptions": []}, "projects": []}',
])
def test_corrupt_configuration_is_reported_without_overwriting(configuration_api, content):
    client, project_id, _, cache = configuration_api
    path = cache / "project-scan.json"
    path.write_text(content)
    url = f"/api/projects/{project_id}/scan-configuration"
    assert client.get(url).status_code == 500
    assert client.put(url, json={
        "exclude_native": True, "native_package_exceptions": [],
    }).status_code == 500
    assert path.read_text() == content


def test_global_defaults_and_project_override(configuration_api):
    client, project_id, other_id, cache = configuration_api
    global_url = "/api/config/native-packages"
    response = client.get(global_url)
    assert response.status_code == 200
    assert response.json == {"exclude_native": True, "native_package_exceptions": DEFAULT_NATIVE_EXCEPTIONS}
    project_url = f"/api/projects/{project_id}/scan-configuration"
    project_preferences = {"exclude_native": False, "native_package_exceptions": ["make-native"]}
    assert client.put(project_url, json=project_preferences).status_code == 200
    global_preferences = {"exclude_native": True, "native_package_exceptions": [" TOOL-Native ", "tool-native"]}
    response = client.put(global_url, json=global_preferences)
    assert response.status_code == 200
    normalized = {"exclude_native": True, "native_package_exceptions": ["tool-native"]}
    assert response.json == normalized
    assert client.application.test_client().get(global_url).json == normalized
    assert client.get(project_url).json == {**project_preferences, "native_packages": ["gcc-native", "make-native"]}
    assert client.get(f"/api/projects/{other_id}/scan-configuration").json == {**normalized, "native_packages": []}
    stored = json.loads((cache / "project-scan.json").read_text())
    assert stored == {"global": normalized, "projects": {"First": project_preferences}}
    assert client.put(f"/api/projects/{other_id}/scan-configuration", json=normalized).status_code == 200
    assert client.get(global_url).json == normalized


def test_legacy_projects_are_preserved_on_global_save(configuration_api):
    client, project_id, _, cache = configuration_api
    preferences = {"exclude_native": False, "native_package_exceptions": ["make-native"]}
    path = cache / "project-scan.json"
    path.write_text(json.dumps({"First": preferences, "global": preferences, "projects": preferences}))
    global_preferences = {"exclude_native": True, "native_package_exceptions": []}
    assert client.put("/api/config/native-packages", json=global_preferences).status_code == 200
    assert json.loads(path.read_text()) == {
        "global": global_preferences,
        "projects": {"First": preferences, "global": preferences, "projects": preferences},
    }
    assert client.get(f"/api/projects/{project_id}/scan-configuration").json["exclude_native"] is False


@pytest.mark.parametrize("value", [None, {}, {"exclude_native": "true"}, {
    "exclude_native": True, "native_package_exceptions": ["openssl"],
}])
def test_invalid_global_settings_do_not_write(configuration_api, value):
    client, _, _, cache = configuration_api
    assert client.put("/api/config/native-packages", json=value).status_code == 400
    assert not (cache / "project-scan.json").exists()


def test_corrupt_global_settings_are_reported_without_overwriting(configuration_api):
    client, _, _, cache = configuration_api
    path = cache / "project-scan.json"
    path.write_text("not json")
    url = "/api/config/native-packages"
    assert client.get(url).status_code == 500
    assert client.put(url, json={"exclude_native": True, "native_package_exceptions": []}).status_code == 500
    assert path.read_text() == "not json"


def test_global_and_project_concurrent_saves_preserve_both(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path))
    barrier = Barrier(2)
    global_preferences = {"exclude_native": True, "native_package_exceptions": ["tool-native"]}
    project_preferences = {"exclude_native": False, "native_package_exceptions": []}

    def save(project_name, preferences):
        barrier.wait(timeout=10)
        return write_scan_configuration(project_name, preferences)

    with ThreadPoolExecutor(max_workers=2) as executor:
        global_save = executor.submit(save, None, global_preferences)
        project_save = executor.submit(save, "First", project_preferences)
        assert global_save.result() == global_preferences
        assert project_save.result() == project_preferences
    assert json.loads((tmp_path / "project-scan.json").read_text()) == {
        "global": global_preferences, "projects": {"First": project_preferences},
    }