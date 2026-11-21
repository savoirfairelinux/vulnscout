# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Attached host folders: API, source browsing through the helper, CLI and persistence."""

import os
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
from src.models.host_mount import HostMount
from src.models.project import Project
from src.models.variant import Variant
from src.models.variant_context import VariantContext


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
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
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
    helper = hh.Helper([str(host["root"])], str(state))
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


def _attach(client, variant, alias, path):
    return client.post(f"/api/variants/{variant.id}/context/mounts", json={"alias": alias, "host_path": str(path)})


def _source(client, variant, file_id, **params):
    return client.get(f"/api/variants/{variant.id}/context/files/{file_id}/source", query_string=params)


class TestAccessControl:

    def test_host_folder_routes_reject_remote_clients(self, client, variant, host):
        remote = {"environ_overrides": {"REMOTE_ADDR": "192.0.2.10"}}
        responses = [
            client.get("/api/context/host-roots", **remote),
            client.get("/api/context/host-roots/browse", **remote),
            client.get(f"/api/variants/{variant.id}/context/mounts", **remote),
            client.post(f"/api/variants/{variant.id}/context/mounts",
                        json={"alias": "src", "host_path": str(host["app"])}, **remote),
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

    def test_local_same_origin_access_remains_available(self, client, helper_server):
        response = client.get("/api/context/host-roots", headers={"Origin": "http://localhost"})
        assert response.status_code == 200


class TestHelperUnavailable:

    def test_roots_report_unavailable_helper(self, client):
        body = client.get("/api/context/host-roots").get_json()
        assert body["available"] is False and body["roots"] == []
        assert "ai-context helper start" in body["message"]

    def test_reads_never_create_the_socket_directory(self, client, variant, tmp_path):
        client.get("/api/context/host-roots")
        client.get(f"/api/variants/{variant.id}/context/mounts")
        assert not (tmp_path / "cache" / "host-helper").exists()

    def test_attach_and_browse_fail_with_503(self, client, variant, host):
        response = _attach(client, variant, "src", host["app"])
        assert response.status_code == 503 and response.get_json()["helper_available"] is False
        assert client.get("/api/context/host-roots/browse").status_code == 503

    def test_list_reports_each_mount_unavailable(self, client, variant, host, helper_server):
        assert _attach(client, variant, "src", host["app"]).status_code == 201
        os.unlink(os.path.join(os.environ["VULNSCOUT_CACHE_DIR"], "host-helper", hh.SOCKET_NAME))
        body = client.get(f"/api/variants/{variant.id}/context/mounts").get_json()
        assert body["helper"]["available"] is False
        assert body["mounts"][0]["status"] == "unavailable"
        response = _source(client, variant, "mount:src")
        assert response.status_code == 503


class TestAttachDetach:

    def test_roots_and_browse(self, client, host, helper_server):
        body = client.get("/api/context/host-roots").get_json()
        assert body == {"available": True, "message": None, "roots": [str(host["root"])]}
        listing = client.get("/api/context/host-roots/browse", query_string={"path": str(host["root"] / "work")})
        assert [entry["name"] for entry in listing.get_json()["directories"]] == ["app", "build"]
        outside = client.get("/api/context/host-roots/browse", query_string={"path": str(host["outside"])})
        assert outside.status_code == 403

    def test_attach_list_and_detach(self, client, variant, host, helper_server):
        response = _attach(client, variant, "src", host["app"] / "src" / "..")
        assert response.status_code == 201
        body = response.get_json()
        assert body["alias"] == "src" and body["file_id"] == "mount:src"
        assert body["host_path"] == str(host["app"]) and body["status"] == "available"
        assert _attach(client, variant, "build", host["build"]).status_code == 201

        listed = client.get(f"/api/variants/{variant.id}/context/mounts").get_json()
        assert listed["helper"] == {"available": True, "message": None}
        assert [(m["alias"], m["status"]) for m in listed["mounts"]] == [("build", "available"), ("src", "available")]

        deleted = client.delete(f"/api/variants/{variant.id}/context/mounts/build")
        assert deleted.status_code == 200 and deleted.get_json() == {"alias": "build", "detached": True,
                                                                      "warning": None}
        assert helper_server.registry.get(str(variant.id), "build") is None
        assert client.delete(f"/api/variants/{variant.id}/context/mounts/build").status_code == 404
        assert _source(client, variant, "mount:build").status_code == 404

    def test_reattach_is_idempotent_but_aliases_are_unique(self, client, variant, host, helper_server):
        assert _attach(client, variant, "src", host["app"]).status_code == 201
        context = VariantContext.get_by_variant(variant.id)
        revision = context.updated_at
        assert _attach(client, variant, "src", host["app"]).status_code == 200
        _db.session.refresh(context)
        assert context.updated_at == revision
        conflict = _attach(client, variant, "src", host["build"])
        assert conflict.status_code == 409 and "detach it first" in conflict.get_json()["error"]
        assert HostMount.get(variant.id, "src").host_path == str(host["app"])
        assert helper_server.registry.get(str(variant.id), "src") == str(host["app"])

    def test_exact_reattach_without_helper(self, client, variant, host, helper_server, monkeypatch):
        assert _attach(client, variant, "src", host["app"]).status_code == 201
        context = VariantContext.get_by_variant(variant.id)
        revision = context.updated_at
        monkeypatch.setenv("VULNSCOUT_HOST_HELPER_SOCKET", str(host["tmp"] / "missing.sock"))
        assert _attach(client, variant, "src", host["app"]).status_code == 503
        _db.session.refresh(context)
        assert context.updated_at == revision
        assert HostMount.get(variant.id, "src").host_path == str(host["app"])

    def test_status_full_unicode_attachment_set(self, client, variant, helper_server, monkeypatch):
        # Exercise the socket framing independently of OS-specific filesystem path limits.
        monkeypatch.setattr(helper_server, "_checked", lambda variant_id, alias, path: (path, path))
        monkeypatch.setattr(helper_server, "_open_folder", lambda path, root: os.open(os.devnull, os.O_RDONLY))
        path = "/" + "\U0001f600" * (hh.MAX_PATH_CHARS - 1)
        aliases = [f"s{i:031d}" for i in range(hh.MAX_ATTACHMENTS_PER_VARIANT)]
        _db.session.add_all([HostMount(variant_id=variant.id, alias=alias, host_path=path) for alias in aliases])
        _db.session.commit()
        listed = client.get(f"/api/variants/{variant.id}/context/mounts").get_json()
        assert listed["helper"]["available"]
        assert [(m["alias"], m["status"]) for m in listed["mounts"]] == [(a, "available") for a in aliases]

    def test_mount_mutations_create_and_advance_context_revision(self, client, variant, host, helper_server):
        assert VariantContext.get_by_variant(variant.id) is None

        assert _attach(client, variant, "src", host["app"]).status_code == 201
        context = VariantContext.get_by_variant(variant.id)
        assert context is not None
        attached_revision = context.updated_at

        assert client.delete(f"/api/variants/{variant.id}/context/mounts/src").status_code == 200
        _db.session.refresh(context)
        assert context.updated_at != attached_revision

    @pytest.mark.parametrize("payload, status", [
        ({"alias": "Bad Alias", "host_path": "/x"}, 400),
        ({"alias": "src"}, 400),
        ({"alias": 3, "host_path": "/x"}, 400),
        ({"alias": "src", "host_path": "relative"}, 400),
    ])
    def test_invalid_requests(self, client, variant, helper_server, payload, status):
        response = client.post(f"/api/variants/{variant.id}/context/mounts", json=payload)
        assert response.status_code == status

    def test_paths_outside_approved_roots_are_forbidden(self, client, variant, host, helper_server):
        response = _attach(client, variant, "out", host["outside"])
        assert response.status_code == 403
        link = host["root"] / "escape"
        link.symlink_to(host["outside"])
        assert _attach(client, variant, "esc", link).status_code == 403
        assert HostMount.get_by_variant(variant.id) == []

    def test_unknown_variant(self, client, helper_server, host):
        missing = "00000000-0000-4000-8000-000000000000"
        assert client.get(f"/api/variants/{missing}/context/mounts").status_code == 404
        assert client.post(f"/api/variants/{missing}/context/mounts",
                           json={"alias": "src", "host_path": str(host["app"])}).status_code == 404

    def test_missing_folder_is_reported_unavailable(self, client, variant, host, helper_server):
        assert _attach(client, variant, "build", host["build"]).status_code == 201
        (host["build"] / "log.txt").unlink()
        host["build"].rmdir()
        mount = client.get(f"/api/variants/{variant.id}/context/mounts").get_json()["mounts"][0]
        assert mount["status"] == "unavailable" and "not found" in mount["message"]

    def test_variant_deletion_removes_its_mounts(self, client, variant, host, helper_server):
        assert _attach(client, variant, "src", host["app"]).status_code == 201
        variant.delete()
        assert _db.session.execute(_db.select(HostMount)).scalars().all() == []


def test_first_concurrent_attaches_preserve_both_aliases(postgres_uri, monkeypatch):
    schema = f"mount_test_{uuid.uuid4().hex}"
    engine = sa.create_engine(postgres_uri, connect_args={"options": f"-csearch_path={schema}"})
    sessions = scoped_session(sessionmaker(bind=engine))
    monkeypatch.setattr(_db, "session", sessions)
    monkeypatch.setattr(host_mounts.helper, "call", lambda op, **params: params)
    with engine.begin() as conn:
        conn.execute(sa.schema.CreateSchema(schema))
    try:
        models = (Project, Variant, HostMount, VariantContext)
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
                return host_mounts.attach(variant_id, alias, f"/{alias}")[1]
            finally:
                sessions.remove()

        with ThreadPoolExecutor(max_workers=2) as pool:
            assert list(pool.map(attach, ["src", "build"])) == [True, True]
        assert [mount.alias for mount in HostMount.get_by_variant(variant_id)] == ["build", "src"]
        assert VariantContext.get_by_variant(variant_id).updated_at is not None
    finally:
        sessions.remove()
        with engine.begin() as conn:
            conn.execute(sa.schema.DropSchema(schema, cascade=True))
        engine.dispose()


class TestSourceBrowsing:

    def test_agents_target_one_alias(self, client, variant, host, helper_server):
        _attach(client, variant, "src", host["app"])
        _attach(client, variant, "build", host["build"])
        listing = _source(client, variant, "mount:src").get_json()
        assert listing["file_id"] == "mount:src" and [f["path"] for f in listing["files"]] == ["src/main.c"]
        search = _source(client, variant, "mount:src", operation="search", query="needle").get_json()
        assert [match["path"] for match in search["matches"]] == ["src/main.c"]
        read = _source(client, variant, "mount:build", operation="read", path="log.txt").get_json()
        assert read["content"] == "needle in build\n" and read["original_name"] == "Host folder build"

    def test_folder_scopes_host_folder_browsing(self, client, variant, host, helper_server):
        _attach(client, variant, "src", host["app"])
        listing = _source(client, variant, "mount:src", folder="src", pattern="*.c").get_json()
        assert [f["path"] for f in listing["files"]] == ["src/main.c"]
        search = _source(client, variant, "mount:src", operation="search", query="needle", folder="src").get_json()
        assert [match["path"] for match in search["matches"]] == ["src/main.c"]
        for folder in ("../outside", "/etc", ".git"):
            assert _source(client, variant, "mount:src", folder=folder).status_code in (400, 404)
        assert _source(client, variant, "mount:src", folder="x" * 1025).status_code == 400

    def test_folder_is_rejected_for_non_host_sources(self, app):
        from src.routes.context import _browse_reference
        with app.test_request_context("/?folder=src"):
            body, status = _browse_reference("/nonexistent", "ref.zip", "codebase reference")
        assert status == 400 and "host folders" in body["error"]

    def test_merged_context_lists_mounts(self, client, variant, host, helper_server):
        _attach(client, variant, "src", host["app"])
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
        _attach(client, variant, "src", host["app"])
        assert _source(client, variant, file_id, **params).status_code == status

    def test_excessive_wildcards_are_rejected_before_reaching_the_helper(self, client, variant, host,
                                                                          helper_server, monkeypatch):
        _attach(client, variant, "src", host["app"])
        from src.controllers import host_mounts as controller
        calls = []
        monkeypatch.setattr(controller, "browse", lambda *args: calls.append(args) or {"files": []})
        response = _source(client, variant, "mount:src", pattern="*?" * 20 + "Z")
        assert response.status_code == 400 and "16" in response.get_json()["error"]
        assert calls == []
        assert _source(client, variant, "mount:src", pattern="src/*.c").status_code == 200
        assert len(calls) == 1

    def test_source_works_without_a_helper_registry_entry(self, client, variant, host, helper_server):
        _attach(client, variant, "src", host["app"])
        helper_server.registry.remove(str(variant.id), "src")
        assert _source(client, variant, "mount:src").status_code == 200
        assert helper_server.registry.get(str(variant.id), "src") is None

    def test_detached_alias_is_refused_even_if_the_helper_still_knows_it(self, client, variant, host,
                                                                         helper_server):
        _attach(client, variant, "src", host["app"])
        _db.session.delete(HostMount.get(variant.id, "src"))
        _db.session.commit()
        assert helper_server.registry.get(str(variant.id), "src") is not None
        assert _source(client, variant, "mount:src").status_code == 404

    def test_moved_folder_is_not_followed(self, client, variant, host, helper_server):
        _attach(client, variant, "src", host["app"])
        moved = host["root"] / "moved"
        host["app"].rename(moved)
        host["app"].symlink_to(moved)
        assert _attach(client, variant, "src", host["app"]).status_code == 409
        assert helper_server.registry.get(str(variant.id), "src") == str(host["app"])
        response = _source(client, variant, "mount:src")
        assert response.status_code == 409 and "moved" in response.get_json()["error"]

    def test_source_uses_database_path_not_mutable_helper_alias(self, client, variant, host, helper_server):
        _attach(client, variant, "src", host["app"])
        helper_server.registry.set(str(variant.id), "src", str(host["build"]))

        response = _source(client, variant, "mount:src")

        assert response.status_code == 200
        assert [entry["path"] for entry in response.get_json()["files"]] == ["src/main.c"]


class TestCli:

    def _run(self, app, *args):
        return app.test_cli_runner().invoke(args=list(args))

    def test_host_command_grants_only_one_scoped_folder(self, app, client, variant, host, helper_server):
        scope = self._run(app, "ai-context-list", "-p", "Demo", "-v", "x86", "--variant-id-only")
        assert scope.exit_code == 0 and scope.output.strip() == str(variant.id)
        helper_server.roots.clear()
        path = str(host["app"])
        permit = Path(helper_server.state_dir) / "permit.Abc123Def456"
        permit.mkdir()
        (permit / "src").write_bytes(str(variant.id).encode() + b"\0" + os.fsencode(path))
        params = {"variant_id": str(variant.id), "alias": "src", "path": path, "host_permit": permit.name}
        for invalid in ({"variant_id": str(uuid.uuid4())}, {"alias": "other"}, {"path": str(host["outside"])}):
            assert not helper_server.dispatch({"op": "attach", **params, **invalid})["ok"]
        result = self._run(app, "ai-context-attach", "-p", "Demo", "-v", "x86",
                           "--host-permit", permit.name, f"src={path}")
        assert result.exit_code == 0, result.output
        assert not (permit / "src").exists()
        assert client.get("/api/context/host-roots").get_json()["roots"] == []
        assert _attach(client, variant, "other", path).status_code == 403
        restarted = hh.Helper([], helper_server.state_dir)
        assert restarted.dispatch({"op": "sync", "variant_id": str(variant.id),
                                   "attachments": {"src": path}})["result"]["attachments"]["src"]["status"] == "available"
        assert _source(client, variant, "mount:src").status_code == 200
        assert self._run(app, "ai-context-detach", "-p", "Demo", "-v", "x86", "src").exit_code == 0
        assert not helper_server.registry.host_approved(str(variant.id), "src", path)
        assert _attach(client, variant, "src", path).status_code == 403

    def test_attach_list_detach(self, app, variant, host, helper_server):
        result = self._run(app, "ai-context-attach", "-p", "Demo", "-v", "x86",
                           f"src={host['app']}", f"build={host['build']}")
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
        assert result.exit_code == 1 and "outside the operator-approved roots" in result.output
        result = self._run(app, "ai-context-attach", "-p", "Demo", "-v", "x86", "no-equals")
        assert result.exit_code == 1 and "ALIAS=HOST_PATH" in result.output
        result = self._run(app, "ai-context-detach", "-p", "Demo", "-v", "x86", "ghost")
        assert result.exit_code == 1

    def test_attach_without_helper(self, app, variant, host):
        result = self._run(app, "ai-context-attach", "-p", "Demo", "-v", "x86", f"src={host['app']}")
        assert result.exit_code == 1 and "helper is not running" in result.output
