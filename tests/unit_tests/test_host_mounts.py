# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Attached host folders: API, source browsing through the helper, CLI and persistence."""

import os
import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import scoped_session, sessionmaker

from src.bin.webapp import create_app
from src.controllers import host_mounts
from src.extensions import db as _db
from src.helpers import host_mount_helper as hh
from src.models.host_mount import HostMount, HostMountDetach
from src.models.project import Project
from src.models.variant import Variant
from src.models.variant_context import VariantContext
from tests.unit_tests.host_mount_permits import host_permit


@pytest.fixture()
def host(tmp_path):
    root = tmp_path / "host"
    app_dir = root / "work" / "app"
    build_dir = root / "work" / "build"
    (app_dir / "src").mkdir(parents=True)
    build_dir.mkdir()
    (app_dir / "src" / "main.c").write_text("int main(void) { return 0; } /* needle */\n")
    (build_dir / "log.txt").write_text("needle in build\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    return {"root": root, "app": app_dir, "build": build_dir, "outside": outside, "tmp": tmp_path}


@pytest.fixture()
def app(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(cache))
    monkeypatch.delenv("VULNSCOUT_HOST_HELPER_SOCKET", raising=False)
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{tmp_path / 'test.db'}"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": "/dev/null"})
        application._INT_SCAN_FINISHED = True
        with application.app_context():
            _db.create_all()
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def helper_server(app, host, tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    helper = hh.Helper(str(state))
    path = tmp_path / "cache" / "host-helper" / hh.SOCKET_NAME
    server = hh.HelperServer(str(path), helper)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    yield helper
    server.shutdown()
    server.server_close()
    thread.join(5)


@pytest.fixture()
def variant(app):
    project = Project.create("Demo")
    return Variant.create("x86", project.id)


@pytest.fixture()
def client(app):
    return app.test_client()


def _attach(helper, variant, alias, path):
    permit = host_permit(helper, variant.id, **{alias: path})
    return host_mounts.attach(variant.id, alias, str(path), host_permit=permit)


def _source(client, variant, file_id, **params):
    return client.get(f"/api/variants/{variant.id}/context/files/{file_id}/source", query_string=params)


def test_shell_rejects_remote_and_invalid_sources(client, variant):
    url = f"/api/variants/{variant.id}/context/shell"
    body = {"file_id": "directory", "command": "ls"}
    assert client.post(url, json=body, environ_overrides={"REMOTE_ADDR": "192.0.2.10"}).status_code == 403
    assert client.post(url, json={"file_id": "upload", "command": "ls"}).status_code == 400
    assert client.post(url, json={"file_id": "directory", "command": ""}).status_code == 400


def test_shell_action_guard_is_variant_scoped(app, variant):
    from types import SimpleNamespace

    from src.controllers.ai_actions import AssessGuard, ReviewTurn

    target = SimpleNamespace(variant_id=str(variant.id), package="pkg")
    assess = AssessGuard("CVE-1", [target])
    review = ReviewTurn()
    review.armed = (None, [target])
    for candidate, allowed in ((str(variant.id), True), (str(uuid.uuid4()), False)):
        with app.test_request_context(f"/api/variants/{candidate}/context/shell", method="POST"):
            assert (assess.allow() is None) is allowed
            assert (review.guard() is None) is allowed


@pytest.mark.skipif(not os.getenv("VULNSCOUT_TEST_SHELL_IMAGE"), reason="requires a local Docker image")
def test_attached_folder_shell_end_to_end(client, variant, host, helper_server):
    import shutil

    helper_server.engine = shutil.which("podman") or shutil.which("docker")
    helper_server.image = os.environ["VULNSCOUT_TEST_SHELL_IMAGE"]
    _attach(helper_server, variant, "src", host["app"])
    url = f"/api/variants/{variant.id}/context/shell"
    response = client.post(url, json={
        "file_id": "mount:src", "folder": "src",
        "command": "grep -n needle main.c; touch main.c",
    })
    assert response.status_code == 200
    body = response.get_json()
    assert body["exit_code"] != 0
    assert "1:int main" in body["output"]
    assert "Permission denied" in body["output"] or "Read-only file system" in body["output"]
    assert "needle" in (host["app"] / "src" / "main.c").read_text()


class TestAccessControl:

    @pytest.mark.parametrize("peer", ["192.0.2.1", "192.0.2.2"])
    @pytest.mark.parametrize("loopback_published", [False, True])
    def test_forwarded_host_folder_access(self, client, variant, host, helper_server, tmp_path, monkeypatch,
                                          peer, loopback_published):
        from src.routes import agent
        monkeypatch.setattr(agent, "_container_gateway", lambda: "192.0.2.1")
        monkeypatch.setattr(agent, "_container_host_forward_ip", lambda _: "192.0.2.2")
        monkeypatch.setattr(agent, "_LOOPBACK_PUBLICATION", Path("/") if loopback_published else tmp_path / "absent")
        _attach(helper_server, variant, "src", host["app"])
        url = "http://127.0.0.2:7275"
        forwarded = {"environ_overrides": {"REMOTE_ADDR": peer}, "base_url": url, "headers": {"Origin": url}}
        base = f"/api/variants/{variant.id}/context"
        responses = [client.get(f"{base}/mounts", **forwarded),
                     client.get(f"{base}/files/mount:src/source", **forwarded),
                     client.delete(f"{base}/mounts/src", **forwarded)]
        assert [response.status_code for response in responses] == [200 if loopback_published else 403] * 3

    def test_host_folder_routes_reject_remote_clients(self, client, variant, host):
        remote = {"environ_overrides": {"REMOTE_ADDR": "192.0.2.10"}}
        responses = [
            client.get(f"/api/variants/{variant.id}/context/mounts", **remote),
            client.delete(f"/api/variants/{variant.id}/context/mounts/src", **remote),
            client.get(
                f"/api/variants/{variant.id}/context/files/mount:src/source",
                environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
            ),
        ]
        assert [response.status_code for response in responses] == [403] * len(responses)

    def test_host_folder_routes_reject_cross_origin_browsers(self, client, variant):
        response = client.get(
            f"/api/variants/{variant.id}/context/files/mount:src/source",
            headers={"Origin": "https://attacker.example"},
        )
        assert response.status_code == 403

    def test_local_same_origin_access_remains_available(self, client, variant, helper_server):
        response = client.get(f"/api/variants/{variant.id}/context/mounts", headers={"Origin": "http://localhost"})
        assert response.status_code == 200


class TestHelperUnavailable:

    def test_denied_helper_socket_reports_permissions(self, helper_server, monkeypatch):
        from src.helpers import host_mounts as transport

        def denied(*args, **kwargs):
            raise PermissionError("connect")

        monkeypatch.setattr(hh, "request", denied)
        with pytest.raises(transport.HostHelperUnavailable, match="Permission denied connecting"):
            transport.call("status")

    def test_incompatible_helper_is_unavailable(self, client, variant, helper_server, monkeypatch):
        legacy_reply = {"ok": True, "result": {"protocol": 1, "roots": ["/old"]}}
        monkeypatch.setattr(hh, "request", lambda *args, **kwargs: legacy_reply)
        body = client.get(f"/api/variants/{variant.id}/context/mounts").json
        assert not body["helper"]["available"] and "restart" in body["helper"]["message"]

    def test_list_reports_unavailable_helper(self, client, variant):
        body = client.get(f"/api/variants/{variant.id}/context/mounts").json
        assert not body["helper"]["available"]
        assert "ai-context helper start" in body["helper"]["message"]

    def test_reads_never_create_the_socket_directory(self, client, variant, tmp_path):
        client.get(f"/api/variants/{variant.id}/context/mounts")
        assert not (tmp_path / "cache" / "host-helper").exists()

    def test_list_reports_each_mount_unavailable(self, client, variant, host, helper_server):
        assert _attach(helper_server, variant, "src", host["app"])[1:] == (True, None)
        os.unlink(os.path.join(os.environ["VULNSCOUT_CACHE_DIR"], "host-helper", hh.SOCKET_NAME))
        body = client.get(f"/api/variants/{variant.id}/context/mounts").get_json()
        assert body["helper"]["available"] is False
        assert body["mounts"][0]["status"] == "unavailable"
        response = _source(client, variant, "mount:src")
        assert response.status_code == 503


class TestAttachDetach:

    def test_no_rest_grant_or_host_picker(self, client, variant, host):
        for url in ("/api/context/host-roots", "/api/context/host-roots/browse"):
            assert client.get(url).status_code == 404
        response = client.post(f"/api/variants/{variant.id}/context/mounts",
                               json={"alias": "src", "host_path": str(host["app"])})
        assert response.status_code == 405
        assert not HostMount.get_by_variant(variant.id)
        paths = client.get("/api/openapi").json["paths"]
        assert not any(path.startswith("/api/context/host-roots") for path in paths)
        assert "post" not in paths["/api/variants/{variant_id}/context/mounts"]

    def test_attach_response_survives_detach_before_activation(self, client, variant, host, helper_server, monkeypatch):
        monkeypatch.setattr(hh, "_NAME_TO_HANDLE_AT", None)
        owner = variant.id
        original = host_mounts.helper.call

        def detach_before_activate(op, **kwargs):
            if op == "activate":
                with client.application.app_context():
                    assert host_mounts.detach(owner, "src") == (True, None)
            return original(op, **kwargs)

        monkeypatch.setattr(host_mounts.helper, "call", detach_before_activate)
        row, created, warning = _attach(helper_server, variant, "src", host["app"])
        assert created and "detached" in warning
        assert row["file_id"] == "mount:src"
        assert HostMount.get(owner, "src") is None

    def test_list_response_survives_detach_during_global_cleanup(
            self, client, variant, host, helper_server, monkeypatch):
        owner = variant.id
        assert _attach(helper_server, variant, "src", host["app"])[1:] == (True, None)
        _db.session.add(HostMountDetach(attachment_id=uuid.uuid4(), variant_id=uuid.uuid4(), alias="old"))
        _db.session.commit()
        original = host_mounts.helper.call

        def detach_during_cleanup(op, **kwargs):
            if op == "detach" and kwargs["alias"] == "old":
                with client.application.app_context():
                    assert host_mounts.detach(owner, "src") == (True, None)
            return original(op, **kwargs)

        monkeypatch.setattr(host_mounts.helper, "call", detach_during_cleanup)
        url = f"/api/variants/{owner}/context/mounts"
        response = client.get(url)
        assert response.status_code == 200
        assert [(row["alias"], row["status"]) for row in response.json["mounts"]] == [("src", "available")]
        assert client.get(url).json["mounts"] == []

    def test_listing_retries_bounded_cleanup_for_deleted_variants(
            self, client, variant, helper_server, monkeypatch):
        monkeypatch.setattr(host_mounts, "_DRAIN_LIMIT", 1)
        for _ in range(3):
            _db.session.add(HostMountDetach(attachment_id=uuid.uuid4(), variant_id=uuid.uuid4(), alias="old"))
        _db.session.commit()
        assert _db.session.query(HostMountDetach).count() == 3
        assert client.get(f"/api/variants/{variant.id}/context/mounts").status_code == 200
        assert _db.session.query(HostMountDetach).count() == 2

    def test_detach_while_offline_releases_quota_after_restart(self, client, variant, host, helper_server, monkeypatch):
        monkeypatch.setattr(hh, "MAX_ATTACHMENTS_PER_VARIANT", 1)
        assert _attach(helper_server, variant, "old", host["app"])[1:] == (True, None)
        with monkeypatch.context() as offline:
            offline.setenv("VULNSCOUT_HOST_HELPER_SOCKET", str(host["tmp"] / "offline"))
            result = client.delete(f"/api/variants/{variant.id}/context/mounts/old")
            assert result.status_code == 200 and result.get_json()["warning"]
            assert _source(client, variant, "mount:old").status_code == 404
        # No operator intervention or manual status refresh before the next attach.
        assert _attach(helper_server, variant, "new", host["build"])[1:] == (True, None)
        assert _source(client, variant, "mount:new").status_code == 200
        assert helper_server.registry.get(str(variant.id), "old") is None

    def test_helper_io_leaves_sqlite_writable(self, client, variant, host, helper_server, monkeypatch):
        db_file = _db.engine.url.database
        original = host_mounts.helper.call
        calls = []

        def verify_unrelated_write(op, **kwargs):
            with sqlite3.connect(db_file, timeout=0.1) as independent:
                independent.execute("BEGIN IMMEDIATE")
            calls.append(op)
            return original(op, **kwargs)

        monkeypatch.setattr(host_mounts.helper, "call", verify_unrelated_write)
        assert _attach(helper_server, variant, "src", host["app"])[1:] == (True, None)
        assert calls

    def test_delayed_repeat_cannot_replace_new_cli_approval(
            self, app, client, variant, host, helper_server, monkeypatch):
        variant_id = variant.id
        assert _attach(helper_server, variant, "src", host["app"])[1:] == (True, None)
        original = host_mounts.helper.call
        raced = False

        def replace_before_revalidation(op, **kwargs):
            nonlocal raced
            if not raced and kwargs.get("alias") == "src":
                raced = True
                with app.app_context():
                    assert host_mounts.detach(variant_id, "src")[0]
                    replacement = str(host["outside"])
                    host_mounts.attach(variant_id, "src", replacement,
                                       host_permit=host_permit(helper_server, variant_id, src=replacement))
            return original(op, **kwargs)

        monkeypatch.setattr(host_mounts.helper, "call", replace_before_revalidation)
        path = str(host["app"])
        permit = host_permit(helper_server, variant_id, src=path)
        try:
            host_mounts.attach(variant_id, "src", path, host_permit=permit)
        except (host_mounts.HostMountConflict, host_mounts.HostHelperError):
            pass  # A stale request may fail; the replacement must remain usable.
        assert raced
        _db.session.expire_all()
        assert HostMount.get(variant_id, "src").host_path == str(host["outside"])
        assert _source(client, variant, "mount:src").status_code == 200

    def test_attach_list_and_detach(self, client, variant, host, helper_server):
        row, created, warning = _attach(helper_server, variant, "src", host["app"])
        assert created and not warning
        assert row["alias"] == "src" and row["file_id"] == "mount:src" and row["host_path"] == str(host["app"])
        assert _attach(helper_server, variant, "build", host["build"])[1:] == (True, None)

        listed = client.get(f"/api/variants/{variant.id}/context/mounts").get_json()
        assert listed["helper"] == {"available": True, "message": None}
        assert [(m["alias"], m["status"]) for m in listed["mounts"]] == [("build", "available"), ("src", "available")]

        deleted = client.delete(f"/api/variants/{variant.id}/context/mounts/build")
        assert deleted.status_code == 200
        assert deleted.get_json() == {"alias": "build", "detached": True, "warning": None}
        assert helper_server.registry.get(str(variant.id), "build") is None
        assert client.delete(f"/api/variants/{variant.id}/context/mounts/build").status_code == 404
        assert _source(client, variant, "mount:build").status_code == 404

    def test_conditional_detach_rejects_reused_alias(self, client, variant, host, helper_server):
        url = f"/api/variants/{variant.id}/context/mounts"
        _attach(helper_server, variant, "src", host["app"])
        target = {"attachment_id": client.get(url).json["mounts"][0]["attachment_id"]}
        assert client.delete(f"{url}/src", query_string=target).status_code == 200
        assert client.delete(f"{url}/src", query_string=target).status_code == 409

        _attach(helper_server, variant, "src", host["build"])
        revision = VariantContext.get_by_variant(variant.id).updated_at
        assert client.delete(f"{url}/src", query_string=target).status_code == 409
        replacement = client.get(url).json["mounts"][0]
        assert replacement["attachment_id"] != target["attachment_id"]
        assert replacement["status"] == "available" and replacement["host_path"] == str(host["build"])
        assert VariantContext.get_by_variant(variant.id).updated_at == revision

    def test_invalid_detach_precondition_is_not_unconditional(self, client, variant, host, helper_server):
        _attach(helper_server, variant, "src", host["app"])
        url = f"/api/variants/{variant.id}/context/mounts/src"
        for value in ("", "invalid"):
            assert client.delete(url, query_string={"attachment_id": value}).status_code == 400
            assert client.delete(url, query_string={"approval_revision": value}).status_code == 400
        assert HostMount.get(variant.id, "src") is not None

    def test_conditional_detach_rejects_same_path_reapproval(self, client, variant, host, helper_server):
        url = f"/api/variants/{variant.id}/context/mounts"
        _attach(helper_server, variant, "src", host["app"])
        original = client.get(url).json["mounts"][0]
        host["app"].rename(host["root"] / "previous")
        host["app"].mkdir()
        _attach(helper_server, variant, "src", host["app"])
        current = client.get(url).json["mounts"][0]
        assert current["attachment_id"] == original["attachment_id"]
        assert current["approval_revision"] != original["approval_revision"]
        for row, status in ((original, 409), (current, 200)):
            response = client.delete(f"{url}/src", query_string={"approval_revision": row["approval_revision"]})
            assert response.status_code == status

    def test_reattach_is_idempotent_but_aliases_are_unique(self, client, variant, host, helper_server):
        assert _attach(helper_server, variant, "src", host["app"])[1:] == (True, None)
        context = VariantContext.get_by_variant(variant.id)
        revision = context.updated_at
        assert _attach(helper_server, variant, "src", host["app"])[1:] == (False, None)
        _db.session.refresh(context)
        assert context.updated_at == revision
        with pytest.raises(host_mounts.HostMountConflict, match="detach it first"):
            _attach(helper_server, variant, "src", host["build"])
        assert HostMount.get(variant.id, "src").host_path == str(host["app"])
        assert helper_server.registry.get(str(variant.id), "src") == str(host["app"])

    def test_exact_reattach_without_helper(self, client, variant, host, helper_server, monkeypatch):
        assert _attach(helper_server, variant, "src", host["app"])[1:] == (True, None)
        context = VariantContext.get_by_variant(variant.id)
        revision = context.updated_at
        monkeypatch.setenv("VULNSCOUT_HOST_HELPER_SOCKET", str(host["tmp"] / "missing.sock"))
        with pytest.raises(host_mounts.HostHelperUnavailable):
            _attach(helper_server, variant, "src", host["app"])
        _db.session.refresh(context)
        assert context.updated_at == revision
        assert HostMount.get(variant.id, "src").host_path == str(host["app"])

    def test_status_full_unicode_attachment_set(self, client, variant, helper_server, monkeypatch):
        # Exercise the socket framing independently of OS-specific filesystem path limits.
        monkeypatch.setattr(helper_server, "_open_folder", lambda path: os.open(helper_server.state_dir, os.O_RDONLY))
        path = "/" + "\U0001f600" * (hh.MAX_PATH_CHARS - 1)
        aliases = [f"s{i:031d}" for i in range(hh.MAX_ATTACHMENTS_PER_VARIANT)]
        for alias in aliases:
            assert _attach(helper_server, variant, alias, path)[1:] == (True, None)
        listed = client.get(f"/api/variants/{variant.id}/context/mounts").get_json()
        assert listed["helper"]["available"]
        assert [(m["alias"], m["status"]) for m in listed["mounts"]] == [(a, "available") for a in aliases]

    def test_mount_mutations_create_and_advance_context_revision(self, client, variant, host, helper_server):
        assert VariantContext.get_by_variant(variant.id) is None

        assert _attach(helper_server, variant, "src", host["app"])[1:] == (True, None)
        context = VariantContext.get_by_variant(variant.id)
        assert context is not None
        attached_revision = context.updated_at

        assert client.delete(f"/api/variants/{variant.id}/context/mounts/src").status_code == 200
        _db.session.refresh(context)
        assert context.updated_at != attached_revision

    def test_legacy_row_requires_explicit_reapproval(self, client, variant, host, helper_server):
        _db.session.add(HostMount(variant_id=variant.id, alias="src", host_path=str(host["app"])))
        _db.session.commit()
        url = f"/api/variants/{variant.id}/context/mounts"
        assert client.get(url).json["mounts"][0]["status"] == "unavailable"
        assert _source(client, variant, "mount:src").status_code == 403
        before = VariantContext.touch(variant.id).updated_at
        assert _attach(helper_server, variant, "src", host["app"])[1:] == (False, None)
        restored = VariantContext.get_by_variant(variant.id).updated_at
        assert restored > before
        assert _attach(helper_server, variant, "src", host["app"])[1:] == (False, None)
        assert VariantContext.get_by_variant(variant.id).updated_at == restored
        assert client.get(url).json["mounts"][0]["status"] == "available"
        assert _source(client, variant, "mount:src").status_code == 200

    def test_unknown_variant(self, client, helper_server):
        missing = "00000000-0000-4000-8000-000000000000"
        assert client.get(f"/api/variants/{missing}/context/mounts").status_code == 404

    def test_missing_folder_is_reported_unavailable(self, client, variant, host, helper_server):
        assert _attach(helper_server, variant, "build", host["build"])[1:] == (True, None)
        (host["build"] / "log.txt").unlink()
        host["build"].rmdir()
        mount = client.get(f"/api/variants/{variant.id}/context/mounts").get_json()["mounts"][0]
        assert mount["status"] == "unavailable" and "not found" in mount["message"]

    def test_variant_deletion_removes_its_mounts(self, client, variant, host, helper_server):
        assert _attach(helper_server, variant, "src", host["app"])[1:] == (True, None)
        variant.delete()
        assert _db.session.execute(_db.select(HostMount)).scalars().all() == []


def test_first_concurrent_attaches_preserve_both_aliases(postgres_uri, helper_server, host, monkeypatch):
    schema = f"mount_test_{uuid.uuid4().hex}"
    engine = sa.create_engine(postgres_uri, connect_args={"options": f"-csearch_path={schema}"})
    sessions = scoped_session(sessionmaker(bind=engine))
    monkeypatch.setattr(_db, "session", sessions)
    with engine.begin() as conn:
        conn.execute(sa.schema.CreateSchema(schema))
    try:
        models = (Project, Variant, HostMount, HostMountDetach, VariantContext)
        _db.metadata.create_all(engine, tables=[model.__table__ for model in models])
        variant_id = Variant.create("x86", Project.create("Demo").id).id
        sessions.remove()
        barrier = threading.Barrier(2, timeout=10)

        @sa.event.listens_for(engine, "before_cursor_execute")
        def synchronize_revision_inserts(conn, cursor, stmt, params, context, executemany):
            # Both transactions reach the first revision insert before either can commit.
            if context.isinsert and context.compiled.statement.table.name == VariantContext.__tablename__:
                barrier.wait()

        def attach(alias):
            try:
                path = str(host["app" if alias == "src" else "build"])
                permit = host_permit(helper_server, variant_id, **{alias: path})
                return host_mounts.attach(variant_id, alias, path, host_permit=permit)[1]
            finally:
                sessions.remove()

        with ThreadPoolExecutor(max_workers=2) as pool:
            assert list(pool.map(attach, ["src", "build"])) == [True, True]
        assert [mount.alias for mount in HostMount.get_by_variant(variant_id)] == ["build", "src"]
        assert VariantContext.get_by_variant(variant_id).updated_at is not None
        sa.event.remove(engine, "before_cursor_execute", synchronize_revision_inserts)

        @sa.event.listens_for(engine, "before_cursor_execute")
        def synchronize_deletes(conn, cursor, stmt, params, context, executemany):
            if context.isdelete and context.compiled.statement.table.name == HostMount.__tablename__:
                barrier.wait()

        def offline(op, **params):
            raise host_mounts.HostHelperUnavailable()

        monkeypatch.setattr(host_mounts.helper, "call", offline)

        def detach(alias):
            try:
                return host_mounts.detach(variant_id, alias)[0]
            finally:
                sessions.remove()

        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(detach, ["src", "src"])) == [False, True]
        assert sessions.query(HostMountDetach).count() == 1
    finally:
        sessions.remove()
        with engine.begin() as conn:
            conn.execute(sa.schema.DropSchema(schema, cascade=True))
        engine.dispose()


class TestSourceBrowsing:

    def test_multibyte_paths_fit_helper_packets(self, client, variant, host, helper_server):
        folder = "/".join(["\u754c" * 80] * 11)
        directory = host["app"] / folder
        directory.mkdir(parents=True)
        names = [f"{n:03}.txt" for n in range(200)]
        for name in names:
            (directory / name).write_text("needle")
        _attach(helper_server, variant, "src", host["app"])

        packet = host_mounts.browse(variant.id, "src", "list", {"folder": folder, "offset": 3})
        assert packet["truncated"] and packet["next_offset"] == 3 + len(packet["files"]) < len(names)
        paths = []
        while len(paths) < len(names):
            response = _source(client, variant, "mount:src", folder=folder, offset=len(paths))
            assert response.status_code == 200 and len(response.data) <= 65536
            page = response.json
            if not paths:
                assert "512 KiB" in page["message"]
            assert page["files"]
            paths.extend(row["path"] for row in page["files"])
            assert page["next_offset"] == (len(paths) if len(paths) < len(names) else None)
        assert paths == [f"{folder}/{name}" for name in names]

    def test_listing_fits_complete_entries_to_wire_budget(self, client, variant, host, helper_server):
        folder = "s" * 195
        directory = host["app"] / folder
        directory.mkdir()
        names = [f"{index:03}-" + "p" * 180 for index in range(200)]
        for name in names:
            (directory / name).write_text("needle" * 82)
        _attach(helper_server, variant, "src", host["app"])

        def page(operation, **params):
            response = _source(client, variant, "mount:src", operation=operation, folder=folder, **params)
            assert response.status_code == 200 and len(response.data) <= 65536
            return response.json

        first = page("list")
        assert first["truncated"] and "64 KiB" in first["message"]
        assert first["next_offset"] == len(first["files"]) < first["total"] == 200
        last = page("list", offset=first["next_offset"])
        assert last["next_offset"] is None
        assert [row["path"] for row in first["files"] + last["files"]] == [f"{folder}/{name}" for name in names]

        first = page("children", limit=200)
        assert not first["complete"] and 0 < len(first["children"]) < len(names)
        last = page("children", limit=200, cursor=first["next_cursor"])
        assert last["complete"] and last["next_cursor"] is None
        assert sorted(row["path"] for row in first["children"] + last["children"]) == [
            f"{folder}/{name}" for name in names]

    def test_wire_budget_preserves_lines_and_marks_partial_preview(self, client, variant, host, helper_server):
        long = "\t" * 40000
        (host["app"] / "escaped").write_text(f"first\n{long}\nlast\n")
        _attach(helper_server, variant, "src", host["app"])

        def read(line):
            response = _source(client, variant, "mount:src", operation="read", path="escaped", start_line=line)
            assert response.status_code == 200 and len(response.data) <= 65536
            return response.json

        first = read(1)
        assert first["content"] == "first\n" and first["next_line"] == 2
        preview = read(2)
        assert preview["partial_line"] and 0 < len(preview["content"]) < len(long)
        assert long.startswith(preview["content"]) and preview["next_line"] == 3
        assert read(3)["content"] == "last\n"

    def test_agents_target_one_alias(self, client, variant, host, helper_server):
        _attach(helper_server, variant, "src", host["app"])
        _attach(helper_server, variant, "build", host["build"])
        listing = _source(client, variant, "mount:src").get_json()
        assert listing["file_id"] == "mount:src" and [f["path"] for f in listing["files"]] == ["src/main.c"]
        assert _source(client, variant, "mount:src", operation="search", query="needle").status_code == 400
        read = _source(client, variant, "mount:build", operation="read", path="log.txt").get_json()
        assert read["content"] == "needle in build\n" and read["original_name"] == "Host folder build"

    def test_folder_scopes_host_folder_browsing(self, client, variant, host, helper_server):
        _attach(helper_server, variant, "src", host["app"])
        listing = _source(client, variant, "mount:src", folder="src", pattern="*.c").get_json()
        assert [f["path"] for f in listing["files"]] == ["src/main.c"]
        for folder in ("../outside", "/etc", ".git"):
            assert _source(client, variant, "mount:src", folder=folder).status_code in (400, 404)
        assert _source(client, variant, "mount:src", folder="x" * 1025).status_code == 400

    def test_folder_is_rejected_for_non_host_sources(self, app):
        from src.routes.context import _browse_reference
        with app.test_request_context("/?folder=src"):
            body, status = _browse_reference("/nonexistent", "ref.zip", "codebase reference")
        assert status == 400 and "host folders" in body["error"]

    def test_merged_context_lists_mounts(self, client, variant, host, helper_server):
        _attach(helper_server, variant, "src", host["app"])
        body = client.get("/api/context", query_string={
            "project_id": str(variant.project_id), "variant_id": str(variant.id),
        }, environ_overrides={"REMOTE_ADDR": "192.0.2.1"}).get_json()
        assert body["mounts"] == [{"alias": "src", "file_id": "mount:src"}]

    @pytest.mark.parametrize("file_id, params, status", [
        ("mount:nope", {}, 404),
        ("mount:BAD", {}, 400),
        ("mount:src", {"operation": "write"}, 400),
        ("mount:src", {"operation": "read", "path": "../outside"}, 400),
        ("mount:src", {"operation": "search", "query": ""}, 400),
        ("mount:src", {"limit": 500}, 400),
        ("mount:src", {"pattern": "*?" * 20 + "Z"}, 400),
        ("mount:src", {"operation": "search", "query": "needle", "pattern": "*" * 17}, 400),
    ])
    def test_invalid_source_requests(self, client, variant, host, helper_server, file_id, params, status):
        _attach(helper_server, variant, "src", host["app"])
        assert _source(client, variant, file_id, **params).status_code == status

    def test_excessive_wildcards_are_rejected_before_reaching_the_helper(
            self, client, variant, host, helper_server, monkeypatch):
        _attach(helper_server, variant, "src", host["app"])
        from src.controllers import host_mounts as controller
        calls = []
        monkeypatch.setattr(controller, "browse", lambda *args: calls.append(args) or {"files": []})
        response = _source(client, variant, "mount:src", pattern="*?" * 20 + "Z")
        assert response.status_code == 400 and "16" in response.get_json()["error"]
        assert calls == []
        assert _source(client, variant, "mount:src", pattern="src/*.c").status_code == 200
        assert len(calls) == 1

    def test_source_works_without_a_helper_registry_entry(self, client, variant, host, helper_server):
        _attach(helper_server, variant, "src", host["app"])
        helper_server.registry.remove(str(variant.id), "src", attachment_id=str(HostMount.get(variant.id, "src").id))
        assert _source(client, variant, "mount:src").status_code == 200
        assert helper_server.registry.get(str(variant.id), "src") == str(host["app"])

    def test_detached_alias_is_refused_even_if_the_helper_still_knows_it(self, client, variant, host,
                                                                         helper_server):
        _attach(helper_server, variant, "src", host["app"])
        _db.session.delete(HostMount.get(variant.id, "src"))
        _db.session.commit()
        assert helper_server.registry.get(str(variant.id), "src") is not None
        assert _source(client, variant, "mount:src").status_code == 404

    def test_moved_folder_is_not_followed(self, client, variant, host, helper_server):
        _attach(helper_server, variant, "src", host["app"])
        moved = host["root"] / "moved"
        host["app"].rename(moved)
        host["app"].symlink_to(moved)
        with pytest.raises(host_mounts.HostHelperError, match="does not authorize"):
            _attach(helper_server, variant, "src", host["app"])
        assert helper_server.registry.get(str(variant.id), "src") == str(host["app"])
        response = _source(client, variant, "mount:src")
        assert response.status_code == 409 and "moved" in response.get_json()["error"]

    def test_source_uses_database_path_not_mutable_helper_alias(self, client, variant, host, helper_server):
        _attach(helper_server, variant, "src", host["app"])
        mount = HostMount.get(variant.id, "src")
        helper_server.registry.remove(str(variant.id), "src", attachment_id=str(mount.id))
        replacement = dict(variant_id=str(variant.id), alias="src", attachment_id=str(uuid.uuid4()),
                           path=str(host["build"]),
                           host_permit=host_permit(helper_server, variant.id, src=host["build"]))
        staged = helper_server.dispatch({"op": "stage", **replacement})["result"]
        assert helper_server.dispatch({"op": "activate", **replacement, **staged})["ok"]

        response = _source(client, variant, "mount:src")
        assert response.status_code == 409 and "replaced" in response.json["error"]


class TestCli:

    def _run(self, app, *args):
        return app.test_cli_runner().invoke(args=list(args))

    def test_host_command_grants_only_one_scoped_folder(self, app, client, variant, host, helper_server, monkeypatch):
        scope = self._run(app, "ai-context-list", "-p", "Demo", "-v", "x86", "--variant-id-only")
        assert scope.exit_code == 0 and scope.output.strip() == str(variant.id)
        path = str(host["app"])
        permit = Path(helper_server.state_dir) / host_permit(helper_server, variant.id, src=path)
        params = {"variant_id": str(variant.id), "alias": "src", "path": path, "host_permit": permit.name}
        for invalid in ({"variant_id": str(uuid.uuid4())}, {"alias": "other"}, {"path": str(host["outside"])}):
            stage = {"op": "stage", "attachment_id": str(uuid.uuid4()), **params, **invalid}
            assert not helper_server.dispatch(stage)["ok"]
        # Another HTTP request sees the earlier snapshot while the host has staged its approval.
        endpoint = f"/api/variants/{variant.id}/context/mounts"
        original_call = host_mounts.helper.call
        refreshed = False

        def refresh_before_commit(op, **kwargs):
            nonlocal refreshed
            reply = original_call(op, **kwargs)
            if op == "stage" and kwargs.get("host_permit"):
                with app.app_context():
                    assert app.test_client().get(endpoint).get_json()["mounts"] == []
                refreshed = True
            return reply

        monkeypatch.setattr(host_mounts.helper, "call", refresh_before_commit)
        result = self._run(app, "ai-context-attach", "-p", "Demo", "-v", "x86",
                           "--host-permit", permit.name, f"src={path}")
        assert result.exit_code == 0, result.output
        assert refreshed
        assert not (permit / "src").exists()
        restarted = hh.Helper(helper_server.state_dir)
        restored = restarted.dispatch({"op": "list", "variant_id": str(variant.id), "alias": "src"})
        if HostMount.get(variant.id, "src").approval_proof.startswith("s"):
            assert not restored["ok"] and "reattach" in restored["error"]
        else:
            assert restored["ok"]
        assert _source(client, variant, "mount:src").status_code == 200
        assert helper_server.dispatch({"op": "detach", "variant_id": str(variant.id), "alias": "src",
                                       "attachment_id": str(uuid.uuid4())})["result"]["removed"] is False
        assert self._run(app, "ai-context-detach", "-p", "Demo", "-v", "x86", "src").exit_code == 0
        assert helper_server.registry.get(str(variant.id), "src") is None
        assert not helper_server.dispatch({"op": "stage", "attachment_id": str(uuid.uuid4()), **params})["ok"]

    def test_committed_cli_approval_recovers_after_interrupted_activation(
            self, client, variant, host, helper_server, monkeypatch):
        path = str(host["outside"])
        permit = Path(helper_server.state_dir) / host_permit(helper_server, variant.id, src=path)
        original_call = host_mounts.helper.call

        def interrupt(op, **kwargs):
            if op == "activate":
                raise host_mounts.HostHelperUnavailable()
            return original_call(op, **kwargs)

        with monkeypatch.context() as offline:
            offline.setattr(host_mounts.helper, "call", interrupt)
            result = self._run(client.application, "ai-context-attach", "-p", "Demo", "-v", "x86",
                               "--host-permit", permit.name, f"src={path}")
            assert result.exit_code == 0 and "activation pending" in result.output
            _, created, warning = _attach(helper_server, variant, "build", host["build"])
            assert created and "activation pending" in warning
        assert not (permit / "src").exists()
        owner_id = variant.id
        _db.session.remove()
        variant = _db.session.get(Variant, owner_id)
        assert _source(client, variant, "mount:src").status_code == 200
        stored = HostMount.get(variant.id, "src")
        activation = {"op": "activate", "variant_id": str(variant.id), "path": path,
                      "alias": "src", "attachment_id": str(stored.id), "approval_proof": stored.approval_proof}
        for field, value in (("alias", "bad"), ("attachment_id", str(uuid.uuid4())), ("path", str(host["app"]))):
            assert helper_server.dispatch({**activation, field: value})["ok"] is False
        assert client.delete(f"/api/variants/{variant.id}/context/mounts/src").status_code == 200
        assert hh.Helper(helper_server.state_dir).dispatch(activation)["ok"] is False

    def test_attach_list_detach(self, app, variant, host, helper_server):
        permit = host_permit(helper_server, variant.id, src=host["app"], build=host["build"])
        result = self._run(app, "ai-context-attach", "-p", "Demo", "-v", "x86",
                           "--host-permit", permit, f"src={host['app']}", f"build={host['build']}")
        assert result.exit_code == 0, result.output
        assert "Attached src" in result.output and "mount:build" in result.output
        listed = self._run(app, "ai-context-list", "-p", "Demo", "-v", "x86")
        assert "src" in listed.output and "available" in listed.output
        as_json = self._run(app, "ai-context-list", "-p", "Demo", "-v", "x86", "--json")
        import json
        assert [m["alias"] for m in json.loads(as_json.output)["mounts"]] == ["build", "src"]
        detached = self._run(app, "ai-context-detach", "-p", "Demo", "-v", "x86", "build")
        assert detached.exit_code == 0 and "Detached build" in detached.output
        assert [m.alias for m in HostMount.get_by_variant(variant.id)] == ["src"]

    def test_attach_errors_exit_non_zero(self, app, variant, host, helper_server):
        result = self._run(app, "ai-context-attach", "-p", "Demo", "-v", "x86", f"out={host['outside']}")
        assert result.exit_code == 1 and "./vulnscout ai-context attach" in result.output
        result = self._run(app, "ai-context-attach", "-p", "Demo", "-v", "x86", "no-equals")
        assert result.exit_code == 1 and "ALIAS=HOST_PATH" in result.output
        result = self._run(app, "ai-context-detach", "-p", "Demo", "-v", "x86", "ghost")
        assert result.exit_code == 1

    def test_attach_without_helper(self, app, variant, host):
        result = self._run(app, "ai-context-attach", "-p", "Demo", "-v", "x86",
                           "--host-permit", "permit.Abc123Def456", f"src={host['app']}")
        assert result.exit_code == 1 and "helper is not running" in result.output
