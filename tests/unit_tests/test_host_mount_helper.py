# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Host folder helper: exact grants, traversal/symlink containment, bounds and socket permissions."""

import json
import os
import socket
import stat
import threading
import uuid

import pytest

from src.helpers import host_mount_helper as hh
from tests.unit_tests.host_mount_permits import host_permit

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
    return hh.Helper(str(state))


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


def grant(helper, path, alias="src"):
    return dict(variant_id=VARIANT, alias=alias, path=str(path), attachment_id=str(uuid.uuid4()),
                host_permit=host_permit(helper, VARIANT, **{alias: path}))


def attached(helper, tree, alias="src", path=None):
    params = grant(helper, path or tree["app"], alias)
    result = ok(helper, "stage", **params)
    binding = {**result, "attachment_id": params["attachment_id"]}
    ok(helper, "activate", **binding)
    return binding


@pytest.mark.parametrize("make_path, code", [
    (lambda t: "/", "forbidden"),
    (lambda t: "relative", "forbidden"),
    (lambda t: t["root"] / ".." / "outside", "forbidden"),
    (lambda t: t["app"] / "escape_dir", "forbidden"),
    (lambda t: t["app"] / ".git", "forbidden"),
    (lambda t: t["app"] / "README", "unavailable"),
    (lambda t: t["app"] / "missing", "not_found"),
])
def test_permit_rejects_noncanonical_sensitive_or_unusable_folders(helper, tree, make_path, code):
    assert err(helper, "stage", **grant(helper, make_path(tree)))[0] == code
    assert helper.registry.get(VARIANT, "src") is None


@pytest.mark.parametrize("alias", ["", "Src", "-src", "a" * 33, "../x", "src/x", None, 3])
def test_alias_must_be_a_short_safe_identifier(helper, tree, alias):
    assert err(helper, "stage", attachment_id=str(uuid.uuid4()), variant_id=VARIANT,
               alias=alias, path=str(tree["app"]))[0] == "invalid"


def test_variant_id_must_be_a_uuid(helper, tree):
    assert err(helper, "stage", attachment_id=str(uuid.uuid4()), variant_id="../x",
               alias="src", path=str(tree["app"]))[0] == "invalid"


def test_requests_are_scoped_by_variant_and_alias(helper, tree):
    attached(helper, tree)
    other = str(uuid.uuid4())
    assert err(helper, "list", variant_id=other, alias="src")[0] == "not_found"
    assert err(helper, "list", variant_id=VARIANT, alias="build")[0] == "not_found"


def test_unapproved_legacy_registry_never_grants_access(helper, tree):
    path = tree["tmp"] / "state" / hh.REGISTRY_NAME
    path.write_text(json.dumps({"version": 1, "attachments": {VARIANT: {
        "src": {"path": str(tree["app"]), "attachment_id": str(uuid.uuid4())}}}}))
    restarted = hh.Helper(helper.state_dir)
    assert err(restarted, "list", variant_id=VARIANT, alias="src")[0] == "not_found"
    binding = dict(variant_id=VARIANT, alias="src", path=str(tree["app"]), attachment_id=str(uuid.uuid4()))
    assert err(restarted, "activate", **binding)[0] == "forbidden"


def test_attachment_replaced_by_a_link_becomes_unavailable(helper, tree):
    attached(helper, tree)
    moved = tree["root"] / "moved"
    tree["app"].rename(moved)
    tree["app"].symlink_to(moved)
    code, message = err(helper, "list", variant_id=VARIANT, alias="src")
    assert code == "unavailable" and "moved" in message


def test_ancestor_replaced_by_symlink_after_validation_is_not_followed(tree, monkeypatch):
    ancestor = tree["tmp"] / "ancestor"
    root = ancestor / "approved"
    app = root / "app"
    app.mkdir(parents=True)
    (app / "main.c").write_text("approved")
    (tree["outside"] / "main.c").write_text("outside")
    state = tree["tmp"] / "race-state"
    state.mkdir()
    helper = hh.Helper(str(state))
    attached(helper, {"app": app}, path=app)

    original = hh._open_absolute

    def swap_then_open(path):
        ancestor.rename(tree["tmp"] / "ancestor-moved")
        ancestor.symlink_to(tree["outside"], target_is_directory=True)
        return original(path)

    monkeypatch.setattr(hh, "_open_absolute", swap_then_open)
    assert err(helper, "list", variant_id=VARIANT, alias="src")[0] == "unavailable"


def test_unknown_and_write_operations_do_not_exist(helper):
    for op in ("write", "delete", "mkdir", "attach", "browse", "sync", None):
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
    result = ok(helper, "read", variant_id=VARIANT, alias="src", path="long.txt")
    assert result["partial_line"] and result["content"] == "x" * hh.MAX_CONTENT_BYTES


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


def test_discovered_paths_round_trip_from_scoped_folder(helper, tree):
    attached(helper, tree)
    folder = "/".join(["a" * 198] * 5)
    directory = tree["app"] / folder
    directory.mkdir(parents=True)
    for name in ("ok", "a" * 40, "back\\slash", "control\nchar"):
        (directory / name).write_text("needle")
    scope = {"variant_id": VARIANT, "alias": "src"}
    listing = ok(helper, "list", folder=folder, **scope)
    search = ok(helper, "search", folder=folder, query="needle", **scope)
    for result, key in ((listing, "files"), (search, "matches")):
        assert result["truncated"] and "skipped 3" in result["message"]
        assert result["skipped_paths"] == 3 and result["io_errors"] == 0
        rows = result[key]
        assert [row["path"] for row in rows] == [folder + "/ok"]
        assert ok(helper, "read", path=rows[0]["path"], **scope)["content"] == "needle"


def test_staging_requires_a_single_use_scoped_permit_and_never_grants_access(helper, tree):
    params = grant(helper, tree["app"])
    for changed in ({"host_permit": None}, {"exact": True, "host_permit": None},
                    {"path": str(tree["app"] / "src")}, {"alias": "other"}, {"variant_id": str(uuid.uuid4())}):
        assert err(helper, "stage", **{**params, **changed})[0] == "forbidden"
    staged = ok(helper, "stage", **params)
    assert err(helper, "stage", **params)[0] == "forbidden"
    assert err(helper, "list", variant_id=VARIANT, alias="src")[0] == "not_found"
    binding = {**staged, "attachment_id": params["attachment_id"]}
    for changed in ({"approval_proof": None}, {"path": str(tree["outside"])}, {"alias": "other"},
                    {"variant_id": str(uuid.uuid4())}, {"attachment_id": str(uuid.uuid4())}):
        assert err(helper, "activate", **{**binding, **changed})[0] == "forbidden"
    ok(helper, "activate", **binding)
    assert err(helper, "source", variant_id=VARIANT, alias="src", mount_path=str(tree["outside"]),
               source_operation="list")[0] == "forbidden"


def test_registry_is_private_and_persistent(helper, tree):
    binding = attached(helper, tree)
    path = tree["tmp"] / "state" / hh.REGISTRY_NAME
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text())["attachments"][VARIANT]["src"]["path"] == str(tree["app"])
    assert hh.Registry(str(tree["tmp"] / "state")).get(VARIANT, "src") == str(tree["app"])
    assert ok(helper, "detach", **binding) == {"removed": True}
    assert ok(helper, "detach", **binding) == {"removed": False}


def test_retirements_survive_migration_and_restart(helper, tree):
    directory = tree["tmp"] / "state"
    path = directory / hh.REGISTRY_NAME
    old_id, new_id = "old-generation", "new-generation"
    path.write_text(json.dumps({"attachments": {}, "retired": [old_id]}))
    registry = hh.Registry(str(directory))
    registry.remove(VARIANT, "src", attachment_id=new_id, retire=True)
    assert "retired" not in json.loads(path.read_text())
    # Simulate a stop after the fence committed but before the JSON rename.
    path.write_text(json.dumps({"attachments": {VARIANT: {"src": {
        "path": str(tree["app"]), "attachment_id": new_id, "host_approved": "yes"}}}}))
    restored = hh.Registry(str(directory))
    assert restored.get(VARIANT, "src") is None
    for generation in (old_id, new_id):
        with pytest.raises(hh.HelperError, match="detached or replaced"):
            restored.set(VARIANT, "src", str(tree["app"]), attachment_id=generation)


def test_attachments_per_variant_are_bounded(helper, tree, monkeypatch):
    monkeypatch.setattr(hh, "MAX_ATTACHMENTS_PER_VARIANT", 1)
    attached(helper, tree)
    params = grant(helper, tree["app"], "other")
    staged = ok(helper, "stage", **params)
    assert err(helper, "activate", attachment_id=params["attachment_id"], **staged)[0] == "limit"


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


def test_socket_round_trip_and_cleanup(server, helper, tree):
    reply = hh.request(server.socket_path, {"op": "status"})
    assert reply["ok"] and reply["result"] == {"protocol": hh.PROTOCOL_VERSION, "read_only": True}
    params = grant(helper, tree["app"])
    staged = hh.request(server.socket_path, {"op": "stage", **params})["result"]
    assert hh.request(server.socket_path, {"op": "activate", **staged, "attachment_id": params["attachment_id"]})["ok"]
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
    assert reply == {"protocol": hh.PROTOCOL_VERSION, "ok": False, "code": "invalid",
                     "error": "Request is too large or incomplete."}
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


def test_uncertain_probe_does_not_remove_socket(helper, tree, monkeypatch):
    path = tree["tmp"] / "sockets" / hh.SOCKET_NAME
    instance = hh.HelperServer(str(path), helper)

    def timeout(connection, address):
        raise TimeoutError()

    monkeypatch.setattr(socket.socket, "connect", timeout)
    try:
        with pytest.raises(TimeoutError):
            hh.HelperServer(str(path), helper)
        assert path.is_socket()
    finally:
        instance.server_close()


@pytest.mark.parametrize("subdir", ["", "child"])
def test_socket_directory_must_not_contain_a_link(helper, tree, subdir):
    real = tree["tmp"] / "real"
    real.mkdir()
    link = tree["tmp"] / "link"
    link.symlink_to(real)
    with pytest.raises(ValueError, match="not a directory"):
        hh.HelperServer(str(link / subdir / hh.SOCKET_NAME), helper)
    assert not list(real.iterdir())


def test_server_retains_verified_directory_until_close(helper, tree):
    directory = tree["tmp"] / "socket-dir"
    directory.mkdir()
    previous = os.umask(0o027)
    try:
        instance = hh.HelperServer(str(directory / hh.SOCKET_NAME), helper)
    finally:
        restored = os.umask(previous)
    fd = instance.directory_fd
    assert fd is not None
    try:
        assert restored == 0o027
        assert os.path.samestat(os.fstat(fd), directory.stat())
        assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o700
        assert instance.socket.getsockname() == f"/proc/self/fd/{fd}/{hh.SOCKET_NAME}"
    finally:
        instance.server_close()
    with pytest.raises(OSError):
        os.fstat(fd)
    instance.server_close()
    assert not list(directory.iterdir())


def test_refused_setup_releases_directory_descriptor(helper, tree, monkeypatch):
    directory = tree["tmp"] / "socket-dir"
    directory.mkdir()
    path = directory / hh.SOCKET_NAME
    path.touch()
    descriptors = []
    prepare = hh.prepare_socket_dir

    def record_fd(directory):
        fd = prepare(directory)
        descriptors.append(fd)
        return fd

    monkeypatch.setattr(hh, "prepare_socket_dir", record_fd)
    with pytest.raises(ValueError, match="non-socket"):
        hh.HelperServer(str(path), helper)
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


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
    assert hh.main(["serve", "--socket", str(tree["tmp"] / "s.sock"), "--state-dir", str(tree["tmp"] / "st")]) == 1
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
        "--pid-file", str(pid_file), "--log-file", str(state / "helper.log"),
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
        assert ping.returncode == 0 and ping.stdout == ""
        assert stat.S_IMODE(state.stat().st_mode) == 0o700
    finally:
        os.kill(pid, signal.SIGTERM)
    for _ in range(100):
        if not socket_path.exists() and not pid_file.exists():
            break
        time.sleep(0.05)
    assert not socket_path.exists() and not pid_file.exists()
    assert "stopped" in (state / "helper.log").read_text()


def test_serve_rejects_legacy_root_argument(tree, capsys):
    with pytest.raises(SystemExit):
        hh.main(["serve", "--socket", str(tree["tmp"] / "s.sock"), "--state-dir", str(tree["tmp"] / "st"),
                 "--root", str(tree["root"])])
    assert "unrecognized arguments" in capsys.readouterr().err


# -- file patterns ------------------------------------------------------------------------------

@pytest.mark.parametrize("op, params", [("list", {}), ("search", {"query": "needle"})])
def test_patterns_with_too_many_wildcards_are_rejected(helper, tree, op, params):
    attached(helper, tree)
    code, message = err(helper, op, variant_id=VARIANT, alias="src", pattern="*?" * 20 + "Z", **params)
    assert code == "invalid" and "16" in message
    limit = "*" * hh.MAX_PATTERN_WILDCARDS
    assert call(helper, op, variant_id=VARIANT, alias="src", pattern=limit, **params)["ok"]
    assert err(helper, op, variant_id=VARIANT, alias="src", pattern=limit + "?", **params)[0] == "invalid"


@pytest.mark.parametrize("pattern, expected", [
    ("*", ["README", "blob.bin", "src/main.c"]),
    ("src/*.c", ["src/main.c"]),
    ("*.[cb]*", ["blob.bin", "src/main.c"]),
    ("READM?", ["README"]),
    ("*.h", []),
])
def test_normal_globs_still_match(helper, tree, pattern, expected):
    attached(helper, tree)
    result = ok(helper, "list", variant_id=VARIANT, alias="src", pattern=pattern)
    assert [entry["path"] for entry in result["files"]] == expected


def test_pattern_is_compiled_once_per_request(helper, tree, monkeypatch):
    attached(helper, tree)
    compiled = []
    original = hh.translate
    monkeypatch.setattr(hh, "translate", lambda pattern: compiled.append(pattern) or original(pattern))
    ok(helper, "list", variant_id=VARIANT, alias="src", pattern="*.c")
    ok(helper, "search", variant_id=VARIANT, alias="src", query="needle", pattern="*")
    assert compiled == ["*.c", "*"]


def test_helper_requires_python_3_9(monkeypatch, capsys):
    monkeypatch.setattr(hh.sys, "version_info", (3, 8, 18))
    assert hh.main(["ping", "--socket", "unused"]) == 1
    assert "Python 3.9 or newer" in capsys.readouterr().err


def test_literal_prefix_prunes_unrelated_folders(helper, tree, monkeypatch):
    (tree["app"] / "docs").mkdir()
    (tree["app"] / "docs" / "guide.txt").write_text("guide\n")
    attached(helper, tree)
    opened = []
    real_open = hh.os.open

    def tracking_open(path, *args, **kwargs):
        opened.append(path)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(hh.os, "open", tracking_open)
    result = ok(helper, "list", variant_id=VARIANT, alias="src", pattern="src/*")
    assert result["total"] == 1 and "visited_entries" in result and "elapsed_seconds" in result
    assert "src" in opened and "docs" not in opened


def test_wide_root_direct_lookup_and_partial_listing(helper, tree, monkeypatch):
    wide = tree["app"] / "wide"
    wide.mkdir()
    for n in range(10):
        (wide / str(n)).write_text("match")
    attached(helper, tree)
    monkeypatch.setattr(hh, "MAX_WALK_ENTRIES", 3)
    for pattern in ("wide/9", "escape_dir/plain.c", "../plain.c", "/etc/passwd"):
        result = ok(helper, "list", variant_id=VARIANT, alias="src", pattern=pattern)
        assert [row["path"] for row in result["files"]] == (["wide/9"] if pattern == "wide/9" else [])
    result = ok(helper, "search", variant_id=VARIANT, alias="src", folder="wide", query="match")
    assert result["truncated"] and len(result["matches"]) == 3


def test_folder_scopes_list_and_search_inside_the_attachment(helper, tree):
    (tree["app"] / "docs").mkdir()
    (tree["app"] / "docs" / "guide.c").write_text("needle docs\n")
    attached(helper, tree)
    listing = ok(helper, "list", variant_id=VARIANT, alias="src", folder="src", pattern="*.c")
    assert [item["path"] for item in listing["files"]] == ["src/main.c"]
    found = ok(helper, "search", variant_id=VARIANT, alias="src", folder="docs/", query="needle")
    assert [(item["path"], item["line"]) for item in found["matches"]] == [("docs/guide.c", 1)]
    # Returned paths stay relative to the attachment, so they can be read directly.
    assert ok(helper, "read", variant_id=VARIANT, alias="src", path="src/main.c")["total_lines"] == 3


def test_folder_rejects_traversal_links_hidden_and_missing_folders(helper, tree):
    attached(helper, tree)
    for folder in ("/", "///", "../outside", "/etc", "src/../..", ".git", "escape_dir", "api_token.txt", "src//x"):
        assert err(helper, "list", variant_id=VARIANT, alias="src", folder=folder)[0] in ("invalid", "not_found")
        assert err(helper, "search", variant_id=VARIANT, alias="src", folder=folder, query="needle")[0] in (
            "invalid", "not_found")
    assert err(helper, "list", variant_id=VARIANT, alias="src", folder="missing")[0] == "not_found"
    assert err(helper, "list", variant_id=VARIANT, alias="src", folder="README")[0] == "invalid"


def test_nonmatching_content_spends_the_byte_budget(helper, tree, monkeypatch):
    attached(helper, tree)
    folder = tree["app"] / "docs"
    folder.mkdir()
    (folder / "a").write_bytes(b"xxxx")
    (folder / "b").write_bytes(b"yyyy")
    monkeypatch.setattr(hh, "SEARCH_BYTE_BUDGET", 4)
    result = ok(helper, "search", variant_id=VARIANT, alias="src", folder="docs", query="absent")
    assert result["engine"] == "python" and result["matches"] == []
    assert result["truncated"] and "byte budget" in result["message"]
    assert result["searched_files"] == 1 and result["bytes_read"] == 4
    (folder / "b").unlink()
    assert not ok(helper, "search", variant_id=VARIANT, alias="src", folder="docs", query="absent")["truncated"]


def test_growing_file_cannot_overread_remaining_budget(helper, tree, monkeypatch):
    attached(helper, tree)
    path = tree["app"] / "README"
    path.write_bytes(b"x")
    monkeypatch.setattr(hh, "SEARCH_BYTE_BUDGET", 3)
    read_sizes = []

    read = hh.os.read

    def read_after_growth(fd, size):
        path.write_bytes(b"later match")
        data = read(fd, size)
        read_sizes.append(len(data))
        return data

    monkeypatch.setattr(hh.os, "read", read_after_growth)
    result = ok(helper, "search", variant_id=VARIANT, alias="src", pattern="README", query="match")
    assert result["truncated"] and "byte budget" in result["message"]
    assert result["searched_files"] == 0 and result["bytes_read"] == 3 and read_sizes == [3]


@pytest.mark.parametrize("limit,value,reason", [
    ("MAX_WALK_ENTRIES", 2, "entries"),
    ("SEARCH_TIME_LIMIT", -1.0, "time limit"),
])
def test_no_match_still_reports_walk_limits(helper, tree, monkeypatch, limit, value, reason):
    attached(helper, tree)
    monkeypatch.setattr(hh, limit, value)
    result = ok(helper, "search", variant_id=VARIANT, alias="src", query="absent")
    assert not result["matches"] and result["truncated"] and reason in result["message"]
    assert result["visited_entries"] <= hh.MAX_WALK_ENTRIES


def test_search_reports_file_and_subtree_io_errors_alongside_matches(helper, tree, monkeypatch):
    attached(helper, tree)
    (tree["app"] / "unreadable").mkdir()
    (tree["app"] / "back\\slash").touch()
    (tree["app"] / "invalid.txt").write_bytes(b"\xff")
    real_open = hh.os.open

    def deny(path, *args, **kwargs):
        if path in ("README", "unreadable"):
            raise PermissionError()
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(hh.os, "open", deny)
    result = ok(helper, "search", variant_id=VARIANT, alias="src", query="needle")
    assert [item["path"] for item in result["matches"]] == ["src/main.c"]
    assert result["truncated"] and "I/O" in result["message"] and result["io_errors"] == 2
    assert result["skipped_paths"] == 1 and "skipped 1" in result["message"]
    assert result["skipped_binary_files"] == 2 and result["searched_files"] == 1
