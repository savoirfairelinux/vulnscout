# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Host folder helper: allowlist, traversal/symlink containment, bounds and socket permissions."""

import json
import os
import socket
import stat
import threading
import uuid

import pytest

from src.helpers import host_mount_helper as hh

VARIANT = str(uuid.uuid4())


@pytest.fixture()
def tree(tmp_path):
    root = tmp_path / "approved"
    app = root / "work" / "app"
    (app / "src").mkdir(parents=True)
    (app / "src" / "main.c").write_text("int main(void) {\n    return 0; /* needle */\n}\n")
    (app / "README").write_text("line 1\nline 2\nline 3\n")
    (app / ".git").mkdir()
    (app / ".git" / "config").write_text("needle\n")
    (app / "api_token.txt").write_text("needle\n")
    (app / "blob.bin").write_bytes(b"needle\x00\x01")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.c").write_text("needle outside\n")
    (outside / "plain.c").write_text("needle outside\n")
    (app / "escape.c").symlink_to(outside / "plain.c")
    (app / "escape_dir").symlink_to(outside)
    return {"root": root, "app": app, "outside": outside, "tmp": tmp_path}


@pytest.fixture()
def helper(tree):
    state = tree["tmp"] / "state"
    state.mkdir()
    return hh.Helper(hh.canonical_roots([str(tree["root"])]), str(state))


def call(helper, op, **params):
    return helper.dispatch({"op": op, **params})


def ok(helper, op, **params):
    reply = call(helper, op, **params)
    assert reply["ok"], reply
    return reply["result"]


def err(helper, op, **params):
    reply = call(helper, op, **params)
    assert not reply["ok"], reply
    return reply["code"], reply["error"]


def attached(helper, tree, alias="src", path=None):
    return ok(helper, "attach", variant_id=VARIANT, alias=alias, path=str(path or tree["app"]))


# -- approved roots -----------------------------------------------------------------------------

def test_roots_must_be_absolute_existing_and_not_the_host_root(tmp_path):
    warnings = []
    with pytest.raises(ValueError, match="absolute"):
        hh.canonical_roots(["relative/dir"])
    with pytest.raises(ValueError, match="'/'"):
        hh.canonical_roots(["/"])
    with pytest.raises(ValueError, match="'/'"):
        hh.canonical_roots([str(tmp_path / "..") + "/" + "/".join([".."] * 40)])
    assert hh.canonical_roots([str(tmp_path / "missing"), str(tmp_path)], warn=warnings.append) == [str(tmp_path)]
    assert "missing" in warnings[0]


def test_attach_canonicalizes_inside_roots(helper, tree):
    result = ok(helper, "attach", variant_id=VARIANT, alias="src", path=str(tree["app"] / "src" / ".."))
    assert result["path"] == str(tree["app"])
    assert helper.registry.get(VARIANT, "src") == str(tree["app"])


@pytest.mark.parametrize("make_path, code", [
    (lambda t: t["outside"], "forbidden"),
    (lambda t: t["root"] / ".." / "outside", "forbidden"),
    (lambda t: t["app"] / "escape_dir", "forbidden"),
    (lambda t: t["app"] / ".git", "forbidden"),
    (lambda t: t["app"] / "README", "invalid"),
    (lambda t: t["app"] / "missing", "not_found"),
])
def test_attach_rejects_paths_outside_or_unusable(helper, tree, make_path, code):
    assert err(helper, "attach", variant_id=VARIANT, alias="src", path=str(make_path(tree)))[0] == code
    assert helper.registry.get(VARIANT, "src") is None


def test_symlink_inside_roots_resolves_to_its_target(helper, tree):
    link = tree["root"] / "link"
    link.symlink_to(tree["app"])
    assert attached(helper, tree, path=link)["path"] == str(tree["app"])


@pytest.mark.parametrize("alias", ["", "Src", "-src", "a" * 33, "../x", "src/x", None, 3])
def test_alias_must_be_a_short_safe_identifier(helper, tree, alias):
    assert err(helper, "attach", variant_id=VARIANT, alias=alias, path=str(tree["app"]))[0] == "invalid"


def test_variant_id_must_be_a_uuid(helper, tree):
    assert err(helper, "attach", variant_id="../x", alias="src", path=str(tree["app"]))[0] == "invalid"


def test_requests_are_scoped_by_variant_and_alias(helper, tree):
    attached(helper, tree)
    other = str(uuid.uuid4())
    assert err(helper, "list", variant_id=other, alias="src")[0] == "not_found"
    assert err(helper, "list", variant_id=VARIANT, alias="build")[0] == "not_found"


def test_attachments_outside_new_roots_are_refused(tree):
    state = tree["tmp"] / "state"
    state.mkdir()
    first = hh.Helper([str(tree["root"])], str(state))
    attached(first, tree)
    narrowed = hh.Helper([str(tree["outside"])], str(state))
    assert narrowed.registry.get(VARIANT, "src") == str(tree["app"])
    assert err(narrowed, "list", variant_id=VARIANT, alias="src")[0] == "forbidden"


def test_attachment_replaced_by_a_link_becomes_unavailable(helper, tree):
    attached(helper, tree)
    moved = tree["root"] / "moved"
    tree["app"].rename(moved)
    tree["app"].symlink_to(moved)
    code, message = err(helper, "list", variant_id=VARIANT, alias="src")
    assert code == "unavailable" and "moved" in message
    exact = err(helper, "attach", variant_id=VARIANT, alias="src", path=str(tree["app"]), exact=True)
    assert exact[0] == "unavailable"


def test_unknown_and_write_operations_do_not_exist(helper):
    for op in ("write", "delete", "mkdir", None):
        assert err(helper, op)[0] == "invalid"
    assert call(helper, "status")["result"]["read_only"] is True


# -- read ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("path, code", [
    ("../outside/plain.c", "invalid"),
    ("src/../../outside/plain.c", "invalid"),
    ("/etc/passwd", "invalid"),
    ("src//main.c", "invalid"),
    ("escape.c", "invalid"),
    ("escape_dir/plain.c", "invalid"),
    (".git/config", "not_found"),
    ("api_token.txt", "not_found"),
    ("blob.bin", "invalid"),
    ("missing.c", "not_found"),
    ("src", "invalid"),
])
def test_read_rejects_traversal_links_and_excluded_files(helper, tree, path, code):
    attached(helper, tree)
    assert err(helper, "read", variant_id=VARIANT, alias="src", path=path)[0] == code


def test_read_pages_lines(helper, tree):
    attached(helper, tree)
    result = ok(helper, "read", variant_id=VARIANT, alias="src", path="README", start_line=2, max_lines=1)
    assert result == {"path": "README", "start_line": 2, "end_line": 2, "content": "line 2\n",
                      "total_lines": 3, "next_line": 3}


def test_read_bounds_file_size_and_line_count(helper, tree, monkeypatch):
    attached(helper, tree)
    monkeypatch.setattr(hh, "MAX_FILE_BYTES", 8)
    assert err(helper, "read", variant_id=VARIANT, alias="src", path="README")[0] == "limit"
    monkeypatch.undo()
    assert err(helper, "read", variant_id=VARIANT, alias="src", path="README", max_lines=201)[0] == "invalid"
    (tree["app"] / "long.txt").write_text("x" * (hh.MAX_CONTENT_BYTES + 1))
    assert err(helper, "read", variant_id=VARIANT, alias="src", path="long.txt")[0] == "limit"


def test_symlink_swapped_in_for_a_directory_component_is_not_followed(helper, tree):
    attached(helper, tree)
    (tree["app"] / "src" / "main.c").unlink()
    (tree["app"] / "src").rmdir()
    (tree["app"] / "src").symlink_to(tree["outside"])
    assert err(helper, "read", variant_id=VARIANT, alias="src", path="src/plain.c")[0] == "invalid"


# -- list / search ------------------------------------------------------------------------------

def test_list_excludes_hidden_sensitive_and_linked_entries(helper, tree):
    attached(helper, tree)
    result = ok(helper, "list", variant_id=VARIANT, alias="src")
    assert [entry["path"] for entry in result["files"]] == ["README", "blob.bin", "src/main.c"]
    assert result["truncated"] is False and result["next_offset"] is None


def test_list_paginates_and_filters(helper, tree):
    attached(helper, tree)
    page = ok(helper, "list", variant_id=VARIANT, alias="src", offset=1, limit=1)
    assert [entry["path"] for entry in page["files"]] == ["blob.bin"] and page["next_offset"] == 2
    assert ok(helper, "list", variant_id=VARIANT, alias="src", pattern="src/*")["total"] == 1
    assert err(helper, "list", variant_id=VARIANT, alias="src", limit=201)[0] == "invalid"


def test_list_reports_truncation_at_the_entry_budget(helper, tree, monkeypatch):
    attached(helper, tree)
    monkeypatch.setattr(hh, "MAX_WALK_ENTRIES", 3)
    result = ok(helper, "list", variant_id=VARIANT, alias="src")
    assert result["truncated"] is True and "3 entries" in result["message"]


def test_list_reports_truncation_at_the_time_limit(helper, tree, monkeypatch):
    attached(helper, tree)
    monkeypatch.setattr(hh, "LIST_TIME_LIMIT", -1.0)
    result = ok(helper, "list", variant_id=VARIANT, alias="src")
    assert result["truncated"] is True and "time limit" in result["message"]


def test_search_skips_excluded_binary_and_linked_files(helper, tree):
    attached(helper, tree)
    result = ok(helper, "search", variant_id=VARIANT, alias="src", query="needle")
    assert result["matches"] == [{"path": "src/main.c", "line": 2, "text": "    return 0; /* needle */"}]
    assert result["skipped_binary_files"] == 1 and result["truncated"] is False


def test_search_bounds_results_bytes_and_query(helper, tree, monkeypatch):
    attached(helper, tree)
    for index in range(3):
        (tree["app"] / f"many{index}.c").write_text("needle\n")
    result = ok(helper, "search", variant_id=VARIANT, alias="src", query="needle", max_results=2)
    assert len(result["matches"]) == 2 and result["truncated"] is True
    monkeypatch.setattr(hh, "SEARCH_BYTE_BUDGET", 10)
    result = ok(helper, "search", variant_id=VARIANT, alias="src", query="needle")
    assert result["truncated"] is True and "MiB" in result["message"]
    monkeypatch.setattr(hh, "MAX_FILE_BYTES", 4)
    monkeypatch.setattr(hh, "SEARCH_BYTE_BUDGET", 1024)
    assert ok(helper, "search", variant_id=VARIANT, alias="src", query="needle")["skipped_large_files"] >= 4
    assert err(helper, "search", variant_id=VARIANT, alias="src", query="x" * 201)[0] == "invalid"
    assert err(helper, "search", variant_id=VARIANT, alias="src", query="")[0] == "invalid"


# -- browse / sync / registry -------------------------------------------------------------------

def test_browse_lists_roots_then_subfolders_without_links_or_hidden(helper, tree):
    roots = ok(helper, "browse")
    assert roots["directories"] == [{"name": str(tree["root"]), "path": str(tree["root"])}]
    listing = ok(helper, "browse", path=str(tree["app"]))
    assert [entry["name"] for entry in listing["directories"]] == ["src"]
    assert listing["parent"] == str(tree["app"].parent) and listing["root"] == str(tree["root"])
    assert ok(helper, "browse", path=str(tree["root"]))["parent"] is None
    assert err(helper, "browse", path=str(tree["outside"]))[0] == "forbidden"
    assert err(helper, "browse", path="relative")[0] == "invalid"


def test_browse_bounds_entries(helper, tree, monkeypatch):
    for index in range(5):
        (tree["root"] / f"d{index}").mkdir()
    monkeypatch.setattr(hh, "MAX_BROWSE_ENTRIES", 2)
    listing = ok(helper, "browse", path=str(tree["root"]))
    assert len(listing["directories"]) == 2 and listing["truncated"] is True


def test_sync_restores_prunes_and_reports_availability(helper, tree):
    attached(helper, tree, alias="stale")
    result = ok(helper, "sync", variant_id=VARIANT, attachments={
        "src": str(tree["app"]), "gone": str(tree["root"] / "missing"), "out": str(tree["outside"]),
    })
    assert result["attachments"]["src"]["status"] == "available"
    assert result["attachments"]["gone"]["status"] == "unavailable"
    assert result["attachments"]["out"]["status"] == "unavailable"
    assert helper.registry.aliases(VARIANT) == {"src": str(tree["app"])}


def test_registry_is_private_and_persistent(helper, tree):
    attached(helper, tree)
    path = tree["tmp"] / "state" / hh.REGISTRY_NAME
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text())["attachments"][VARIANT]["src"]["path"] == str(tree["app"])
    assert hh.Registry(str(tree["tmp"] / "state")).get(VARIANT, "src") == str(tree["app"])
    assert ok(helper, "detach", variant_id=VARIANT, alias="src") == {"removed": True}
    assert ok(helper, "detach", variant_id=VARIANT, alias="src") == {"removed": False}


def test_attachments_per_variant_are_bounded(helper, tree, monkeypatch):
    monkeypatch.setattr(hh, "MAX_ATTACHMENTS_PER_VARIANT", 1)
    attached(helper, tree)
    assert err(helper, "attach", variant_id=VARIANT, alias="other", path=str(tree["app"]))[0] == "limit"


# -- socket server ------------------------------------------------------------------------------

@pytest.fixture()
def server(helper, tree):
    path = tree["tmp"] / "cache" / "host-helper" / hh.SOCKET_NAME
    instance = hh.HelperServer(str(path), helper)
    thread = threading.Thread(target=instance.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    yield instance
    instance.shutdown()
    instance.server_close()
    thread.join(5)


def test_socket_and_directory_are_owner_only(server):
    assert stat.S_IMODE(os.stat(server.socket_path).st_mode) == 0o600
    assert stat.S_ISSOCK(os.lstat(server.socket_path).st_mode)
    assert stat.S_IMODE(os.stat(os.path.dirname(server.socket_path)).st_mode) == 0o700


def test_socket_round_trip_and_cleanup(server, tree):
    reply = hh.request(server.socket_path, {"op": "status"})
    assert reply["ok"] and reply["result"]["roots"] == [str(tree["root"])]
    reply = hh.request(server.socket_path, {"op": "attach", "variant_id": VARIANT, "alias": "src",
                                            "path": str(tree["app"])})
    assert reply["ok"]
    reply = hh.request(server.socket_path, {"op": "read", "variant_id": VARIANT, "alias": "src", "path": "README"})
    assert reply["result"]["total_lines"] == 3


def _raw_exchange(path, payload):
    address, fd = hh._short_path(path)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(address)
            connection.sendall(payload)
            return json.loads(connection.makefile("rb").readline())
    finally:
        if fd is not None:
            os.close(fd)


def test_oversized_and_invalid_requests_are_rejected(server):
    reply = _raw_exchange(server.socket_path, b"x" * (hh.MAX_REQUEST_BYTES + 10) + b"\n")
    assert reply == {"ok": False, "code": "invalid", "error": "Request is too large or incomplete."}
    assert _raw_exchange(server.socket_path, b"not json\n")["code"] == "invalid"


def test_a_second_helper_cannot_take_over_a_live_socket(server, helper):
    with pytest.raises(ValueError, match="already listening"):
        hh.HelperServer(server.socket_path, helper)
    assert hh.request(server.socket_path, {"op": "status"})["ok"]


def test_stale_socket_is_replaced_but_regular_files_are_not(helper, tree):
    directory = tree["tmp"] / "sock"
    directory.mkdir(mode=0o700)
    stale = directory / hh.SOCKET_NAME
    address, fd = hh._short_path(str(stale))
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as leftover:
            leftover.bind(address)
    finally:
        if fd is not None:
            os.close(fd)
    instance = hh.HelperServer(str(stale), helper)
    instance.server_close()
    assert not stale.exists()
    stale.write_text("not a socket")
    with pytest.raises(ValueError, match="non-socket"):
        hh.HelperServer(str(stale), helper)
    assert stale.read_text() == "not a socket"


def test_socket_directory_must_not_be_a_link(helper, tree):
    real = tree["tmp"] / "real"
    real.mkdir()
    link = tree["tmp"] / "link"
    link.symlink_to(real)
    with pytest.raises(ValueError, match="not a directory"):
        hh.HelperServer(str(link / hh.SOCKET_NAME), helper)


def test_long_socket_paths_are_supported(helper, tree):
    directory = tree["tmp"] / ("d" * 60) / ("e" * 60)
    path = directory / hh.SOCKET_NAME
    instance = hh.HelperServer(str(path), helper)
    thread = threading.Thread(target=instance.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        assert len(str(path)) > 108
        assert hh.request(str(path), {"op": "status"})["ok"]
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(5)


def test_peer_credentials_allow_only_the_owner_or_root(monkeypatch):
    uid = os.getuid()
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with left, right:
        assert hh.peer_allowed(left)
        monkeypatch.setattr(hh.os, "getuid", lambda: uid + 12345)
        assert hh.peer_allowed(left) is (uid == 0)


def test_helper_refuses_to_run_as_root(monkeypatch, tree, capsys):
    monkeypatch.setattr(hh.os, "geteuid", lambda: 0)
    assert hh.main(["serve", "--socket", str(tree["tmp"] / "s.sock"), "--state-dir", str(tree["tmp"] / "st"),
                    "--root", str(tree["root"])]) == 1
    assert "must not run as root" in capsys.readouterr().err


@pytest.mark.skipif(os.geteuid() == 0, reason="the helper refuses to run as root")
def test_daemon_writes_pid_answers_ping_and_cleans_up_on_sigterm(tree):
    import signal
    import subprocess
    import sys
    import time

    script = hh.__file__
    socket_path = tree["tmp"] / "cache" / "host-helper" / hh.SOCKET_NAME
    state = tree["tmp"] / "state"
    pid_file = state / "helper.pid"
    started = subprocess.run([
        sys.executable, script, "serve", "--daemon", "--socket", str(socket_path), "--state-dir", str(state),
        "--pid-file", str(pid_file), "--log-file", str(state / "helper.log"), "--root", str(tree["root"]),
    ], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
    assert started.returncode == 0, started.stderr
    for _ in range(100):
        if pid_file.exists():
            break
        time.sleep(0.05)
    pid = int(pid_file.read_text())
    try:
        ping = subprocess.run([sys.executable, script, "ping", "--socket", str(socket_path)],
                              capture_output=True, text=True, timeout=30)
        assert ping.returncode == 0 and ping.stdout.split() == [str(tree["root"])]
        assert stat.S_IMODE(state.stat().st_mode) == 0o700
    finally:
        os.kill(pid, signal.SIGTERM)
    for _ in range(100):
        if not socket_path.exists() and not pid_file.exists():
            break
        time.sleep(0.05)
    assert not socket_path.exists() and not pid_file.exists()
    assert "stopped" in (state / "helper.log").read_text()


def test_serve_reports_missing_roots(tree, capsys):
    assert hh.main(["serve", "--socket", str(tree["tmp"] / "s.sock"), "--state-dir", str(tree["tmp"] / "st"),
                    "--root", str(tree["tmp"] / "missing")]) == 1
    assert "No approved host root exists" in capsys.readouterr().err
