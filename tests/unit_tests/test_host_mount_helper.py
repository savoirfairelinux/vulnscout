# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Host folder helper: exact grants, traversal/symlink containment, bounds and socket permissions."""

import ctypes
import hashlib
import importlib.util
import io
import json
import os
import shutil
import socket
import stat
import struct
import subprocess
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

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


def test_config_is_a_file_only_exception_inside_an_approved_mount(helper, tree):
    root = tree["app"]
    attached(helper, tree)
    params = dict(variant_id=VARIANT, alias="src", mount_path=str(root))

    def source(operation, **kwargs):
        return ok(helper, "source", source_operation=operation, **params, **kwargs)

    build = root / "build"
    build.mkdir()
    path = "build/.config"
    text = "CONFIG_FIRST=y\n# CONFIG_LAST is not set\n"
    (root / path).write_text(text)
    (build / ".CONFIG").touch()
    (build / ".config.old").touch()
    for name in ("dir", "hard", "sym"):
        (build / name).mkdir()
    hidden = build / "dir" / ".config"
    hidden.mkdir()
    (hidden / "inner").touch()
    os.link(tree["outside"] / "plain.c", build / "hard" / ".config")
    (build / "sym" / ".config").symlink_to(tree["outside"] / "plain.c")

    assert {"path": path, "type": "file"} in source("children", folder="build")["children"]
    for pattern in ("*", "*/.config", ".config"):
        assert [f["path"] for f in source("list", folder="build", pattern=pattern)["files"]] == (
            [] if pattern == "*/.config" else [path])
    assert source("read", path=path)["content"] == text
    hit, = source("search_file", path=path, query="CONFIG_LAST")["matches"]
    assert source("read", path=path, position=hit["position"])["match_line"] == 2
    for name in ("dir", "hard", "sym"):
        folder = f"build/{name}"
        page = source("children", folder=folder)
        assert not page["children"] and page["entries_filtered"]
        assert not source("list", folder=folder, pattern=".config")["files"]
        for op, kwargs in (("read", {}), ("search_file", {"query": "CONFIG_LAST"}),
                           ("read", {"position": hit["position"]})):
            err(helper, "source", source_operation=op, path=folder + "/.config", **params, **kwargs)
    err(helper, "source", source_operation="read", path="build/dir/.config/inner", **params)
    err(helper, "source", source_operation="children", folder="build/dir/.config", **params)
    assert not source("list", folder="build", pattern="dir/.config/inner")["files"]
    snapshot = tree["tmp"] / "snapshot"
    snapshot.mkdir()
    fd = helper._shell_root(dict(source="mount", folder="build", **params))
    try:
        assert helper._shell_snapshot(fd, str(snapshot))["files"] == 1
    finally:
        os.close(fd)
    assert (snapshot / ".config").read_text() == text


def test_search_large_known_file_resumes_without_inventory(helper, tree, monkeypatch):
    root = tree["app"]
    query = "CVE-2026-1234"
    path = root / "task.log"
    path.write_bytes(b"x" * (hh.SEARCH_CHUNK - 2) + "\u20ac".encode() + b"x" * hh.MAX_FILE_BYTES
                     + f"\n{query}0\nnot{query}\n{query}_tag\n{query} patched\nstatus: fixed\n".encode())
    attached(helper, tree)
    params = dict(variant_id=VARIANT, alias="src", mount_path=str(root), source_operation="search_file",
                  path=path.name, query=query)
    assert "maximum readable" in err(helper, "read", variant_id=VARIANT, alias="src", path=path.name)[1]
    monkeypatch.setattr(os, "scandir", lambda *a: pytest.fail("Unexpected inventory"))
    monkeypatch.setattr(helper, "_shell_snapshot", lambda *a: pytest.fail("Unexpected snapshot"))
    offsets = []
    pread = os.pread

    def track(fd, size, offset):
        assert os.path.samefile(f"/proc/self/fd/{fd}", path)
        offsets.append(offset)
        return pread(fd, size, offset)

    monkeypatch.setattr(os, "pread", track)
    cursor = ""
    rows = []
    while True:
        page = ok(helper, "source", **params, cursor=cursor)
        assert page["bytes_scanned"] <= hh.SEARCH_BYTES
        rows.extend(page["matches"])
        if page["complete"]:
            assert cursor and page["next_cursor"] is None
            break
        assert cursor != page["next_cursor"]
        cursor = page["next_cursor"]
    assert offsets == sorted(set(offsets))
    position = rows[0].pop("position")
    assert rows == [{"path": "task.log", "line": 5, "text": f"{query} patched"}]
    offsets.clear()
    page = ok(helper, "source", variant_id=VARIANT, alias="src", mount_path=str(root), source_operation="read",
              path=path.name, position=position, max_lines=3)
    assert offsets and min(offsets) > hh.MAX_FILE_BYTES - hh.POSITION_RADIUS
    assert page["content"] == f"{query}_tag\n{query} patched\nstatus: fixed\n"
    assert (page["start_line"], page["match_line"], page["end_line"]) == (4, 5, 6)
    assert page["truncated_before"] and not page["truncated_after"]
    assert not page["partial_first_line"] and not page["partial_last_line"]


def test_position_is_bound_to_the_authorization_path_version_and_purpose(helper, tree, monkeypatch):
    root = tree["app"]
    path = root / "build.log"
    path.write_text("needle\n" * 4)
    attached(helper, tree)
    attached(helper, tree, alias="other")
    params = dict(variant_id=VARIANT, alias="src", mount_path=str(root), path=path.name)
    monkeypatch.setattr(hh, "SEARCH_MATCHES", 1)
    page = ok(helper, "source", **params, source_operation="search_file", query="needle")
    token = page["matches"][0]["position"]
    assert "position" in err(helper, "source", **params, source_operation="read_position")[1]
    read = dict(**params, source_operation="read_position", position=token)
    forged = token[:-1] + ("a" if token[-1] != "a" else "b")
    for change in ({"alias": "other"}, {"path": "README"}, {"position": forged},
                   {"position": page["next_cursor"]}, {"position": ""}, {"start_line": 2}):
        assert err(helper, "source", **{**read, **change})[0] == "invalid"
    assert "cursor" in err(helper, "source", **params, source_operation="search_file", query="needle", cursor=token)[1]
    os.link(path, root / "hard")
    assert "links" in err(helper, "source", **read)[1]
    (root / "hard").unlink()
    path.write_text("NEEDLE\n" * 4)
    assert "stale" in err(helper, "source", **read)[1]


def test_position_clips_long_utf8_line_around_each_match(helper, tree):
    root = tree["app"]
    path = root / "long"
    left = "\u20ac" * 3000
    path.write_text(f"\n{left}hit-A{left}hit-B{left}\n")
    attached(helper, tree)
    params = dict(variant_id=VARIANT, alias="src", mount_path=str(root), path=path.name)
    rows = ok(helper, "source", **params, source_operation="search_file", query="hit")["matches"]
    assert len(rows) == 2 and rows[0]["position"] != rows[1]["position"]
    for row, tag in zip(rows, ["hit-A", "hit-B"]):
        page = ok(helper, "source", **params, source_operation="read", position=row["position"])
        assert tag in page["content"] and len(page["content"].encode()) <= 2 * hh.POSITION_RADIUS
        assert len(json.dumps(page)) < hh.MAX_CONTENT_BYTES
        assert page["partial_first_line"] and page["partial_last_line"]
        assert page["truncated_before"] and page["truncated_after"]
        assert page["start_line"] == page["end_line"] == page["match_line"] == 2


def test_search_chunk_boundary_time_and_cursor_binding(helper, tree, monkeypatch):
    root = tree["app"]
    path = root / "log"
    query = "CVE-2026-1234"
    path.write_text(" " * (hh.SEARCH_CHUNK - 3) + query + "\n" + query + "0")
    (root / "other").write_bytes(path.read_bytes())
    attached(helper, tree)
    params = dict(variant_id=VARIANT, alias="src", mount_path=str(root), source_operation="search_file",
                  query=query, path=path.name)
    monkeypatch.setattr(hh, "SEARCH_SECONDS", 0)
    first = ok(helper, "source", **params)
    assert first["bytes_scanned"] == hh.SEARCH_CHUNK and not first["matches"] and not first["complete"]
    params["cursor"] = first["next_cursor"]
    second = ok(helper, "source", **params)
    assert [m["line"] for m in second["matches"]] == [1]
    assert ok(helper, "source", **params) == second
    for change in ({"path": "other"}, {"query": query + "0"}, {"cursor": "1:99:0.bad"}):
        assert "cursor" in err(helper, "source", **{**params, **change})[1]
    path.write_text("different content")
    assert "changed" in err(helper, "source", **params)[1]


def test_search_match_and_serialized_budgets_resume_unreturned_hit(helper, tree, monkeypatch):
    root = tree["app"]
    (root / "log").write_text(("\U0001f600" * 50 + "??\n") * 140)
    attached(helper, tree)
    params = dict(variant_id=VARIANT, alias="src", mount_path=str(root), source_operation="search_file",
                  path="log", query="??")
    monkeypatch.setattr(hh, "SEARCH_MATCHES", 3)
    page = ok(helper, "source", **params)
    assert not page["complete"] and len(page["matches"]) == 3
    rows = page["matches"]
    monkeypatch.setattr(hh, "SEARCH_MATCHES", 100)
    monkeypatch.setattr(hh, "MAX_CONTENT_BYTES", 8192)
    while not page["complete"]:
        page = ok(helper, "source", **params, cursor=page["next_cursor"])
        assert len(json.dumps(page)) < hh.MAX_CONTENT_BYTES
        assert 0 < len(page["matches"]) < 100
        rows.extend(page["matches"])
    assert [row["line"] for row in rows] == list(range(1, 141))


def test_search_rejects_forbidden_members(helper, tree):
    root = tree["app"]
    os.mkfifo(root / "fifo")
    os.link(tree["outside"] / "plain.c", root / "hard")
    (root / "invalid").write_bytes(b"needle\xff")
    attached(helper, tree)
    for path in ("../outside/plain.c", ".git/config", "api_token.txt", "escape_dir/plain.c", "escape.c",
                 "fifo", "hard", "src", "blob.bin", "invalid"):
        code, _ = err(helper, "source", variant_id=VARIANT, alias="src", mount_path=str(root),
                      source_operation="search_file", query="needle", path=path)
        assert code in ("invalid", "not_found"), path


def test_shallow_pages_bound_actual_work_and_do_not_open_children(helper, tree, monkeypatch):
    root = tree["app"]
    wide = root / "wide"
    wide.mkdir()
    for n in range(600):
        (wide / f"item-{n}").touch()
    (wide / "deep" / "unrelated" / "more").mkdir(parents=True)
    (wide / ".hidden").touch()
    (wide / "key.pem").touch()
    (wide / "linked").symlink_to(tree["outside"])
    os.link(wide / "item-1", wide / "hardlink")
    os.mkfifo(wide / "pipe")
    attached(helper, tree)
    params = dict(variant_id=VARIANT, alias="src", mount_path=str(root), source_operation="children", folder="wide")
    records = []
    read = hh._directory_records

    def observed(fd, cookie):
        assert os.path.samefile(f"/proc/self/fd/{fd}", wide)
        for record in read(fd, cookie):
            records.append(record[1])
            yield record

    original_open = os.open

    def monitored_open(path, *args, dir_fd=None, **kwargs):
        if dir_fd is not None:
            assert not Path(os.readlink(f"/proc/self/fd/{dir_fd}")).is_relative_to(wide)
        return original_open(path, *args, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(hh, "_directory_records", observed)
    monkeypatch.setattr(os, "open", monitored_open)
    monkeypatch.setattr(os, "scandir", lambda *a: pytest.fail("Unexpected recursive inventory"))
    monkeypatch.setattr(helper, "_shell_snapshot", lambda *a: pytest.fail("Unexpected snapshot"))
    page = ok(helper, "source", **params, limit=1)
    assert len(page["children"]) == 1 and 0 < len(records) < 10
    excluded = {".hidden", "key.pem", "linked", "item-1", "hardlink", "pipe"}
    assert page["entries_filtered"] == bool(excluded.intersection(records))
    seen = list(page["children"])
    while not page["complete"]:
        start = len(records)
        page = ok(helper, "source", **params, cursor=page["next_cursor"], limit=97)
        assert page["entries_filtered"] == bool(excluded.intersection(records[start:]))
        seen.extend(page["children"])
    assert page["next_cursor"] is None
    assert len(records) == len(set(records))  # Continuations do not replay earlier names.
    assert len(seen) == 600
    assert {row["path"] for row in seen if row["type"] == "file"} == {
        f"wide/item-{n}" for n in range(600) if n != 1
    }
    assert {"path": "wide/deep", "type": "directory"} in seen


def test_excluded_children_progress_and_scope(helper, tree):
    root = tree["app"]
    excluded = root / "ignored"
    excluded.mkdir()
    for n in range(600):
        (excluded / f".hidden-{n}").touch()
    attached(helper, tree)
    params = dict(variant_id=VARIANT, alias="src", mount_path=str(root), source_operation="children", folder="ignored")
    page = ok(helper, "source", **params)
    assert page["entries_filtered"] and not page["children"] and not page["complete"]
    assert 254 <= page["visited_entries"] <= 256  # Directory cookies may include . and .. in any order.
    cursor = page["next_cursor"]
    cookie, signature = cursor.split(".")
    forged = f"{int(cookie, 16) ^ 1:x}.{signature}"
    assert "restart" in err(helper, "source", **params, cursor=forged)[1]
    attached(helper, tree, alias="other")
    assert "restart" in err(helper, "source", **{**params, "alias": "other"}, cursor=cursor)[1]
    assert err(helper, "source", **{**params, "folder": ""}, cursor=cursor)[0] == "invalid"
    for change, code in (({"folder": "../outside"}, "invalid"), ({"folder": ".git"}, "not_found"),
                         ({"folder": "escape_dir"}, "invalid"), ({"variant_id": str(uuid.uuid4())}, "not_found"),
                         ({"mount_path": str(tree["outside"])}, "forbidden")):
        assert err(helper, "source", **{**params, **change})[0] == code
    while not page["complete"]:
        page = ok(helper, "source", **params, cursor=page["next_cursor"])
        assert not page["children"] and page["visited_entries"] <= 256
    assert page["next_cursor"] is None
    old = excluded.stat()
    os.utime(excluded, ns=(old.st_atime_ns, old.st_mtime_ns + 2_000_000_000))
    assert err(helper, "source", **params, cursor=cursor)[0] == "invalid"


@pytest.mark.parametrize("limit", [1, 50])
@pytest.mark.parametrize("vanishes", [False, True])
def test_shallow_page_rejects_changes_during_read(helper, tree, monkeypatch, limit, vanishes):
    root = tree["app"]
    folder = root / "one"
    folder.mkdir()
    member = folder / "file"
    member.touch()
    attached(helper, tree)
    records = hh._directory_records

    def change(fd, cookie):
        for after, name in records(fd, cookie):
            if name == member.name:
                if vanishes:
                    member.unlink()
                else:
                    (folder / "new").touch()
            yield after, name

    monkeypatch.setattr(hh, "_directory_records", change)
    code, msg = err(helper, "source", variant_id=VARIANT, alias="src", mount_path=str(root),
                    source_operation="children", folder="one", limit=limit)
    assert code == "invalid" and "restart" in msg


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


@pytest.mark.parametrize("version,identity,old_proof", [
    (2, None, "a" * 64),
    (3, "1:2", "1:2:" + "a" * 64),
])
def test_upgrade_requires_reapproval_for_older_grants(helper, tree, version, identity, old_proof):
    binding = grant(helper, tree["app"])
    path = tree["tmp"] / "state" / hh.REGISTRY_NAME
    path.write_text(json.dumps({"version": version, "attachments": {VARIANT: {"src": {
        "path": binding["path"], "attachment_id": binding["attachment_id"], "host_approved": "yes",
        "identity": identity}}}}))
    restarted = hh.Helper(helper.state_dir)
    assert err(restarted, "list", variant_id=VARIANT, alias="src")[0] == "not_found"
    assert err(restarted, "activate", **binding, approval_proof=old_proof)[0] == "forbidden"
    assert err(restarted, "stage", **binding)[0] == "forbidden"
    staged = ok(restarted, "stage", **{**binding, "host_permit": host_permit(restarted, VARIANT, src=tree["app"])})
    ok(restarted, "activate", attachment_id=binding["attachment_id"], **staged)


def test_attachment_replaced_by_a_link_becomes_unavailable(helper, tree):
    attached(helper, tree)
    moved = tree["root"] / "moved"
    tree["app"].rename(moved)
    tree["app"].symlink_to(moved)
    code, message = err(helper, "list", variant_id=VARIANT, alias="src")
    assert code == "unavailable" and "moved" in message


def test_real_directory_replacement_requires_new_permit(helper, tree):
    binding = attached(helper, tree)
    scope = dict(variant_id=VARIANT, alias="src")
    shutil.rmtree(tree["app"])
    tree["app"].mkdir()
    (tree["app"] / "README").write_text("replacement")
    assert err(helper, "read", **scope, path="README")[0] == "unavailable"
    restarted = hh.Helper(helper.state_dir)
    assert err(restarted, "activate", **binding)[0] == "unavailable"
    assert err(restarted, "read", **scope, path="README")[0] == "unavailable"
    permit = host_permit(restarted, VARIANT, src=tree["app"])
    approved = ok(restarted, "stage", **binding, host_permit=permit)
    ok(restarted, "activate", **{**binding, **approved})
    assert ok(restarted, "read", **scope, path="README")["content"] == "replacement"


@pytest.mark.parametrize("change", ["generation", "mount"])
def test_handle_survives_restart_but_rejects_reused_inode(helper, tree, monkeypatch, change):
    root = tree["app"]
    previous = root.stat()
    current = {"generation": 1, "mount": 7}
    real_fstat = os.fstat

    def reused_inode(fd):
        if os.readlink(f"/proc/self/fd/{fd}") == str(root):
            return previous
        return real_fstat(fd)

    def get_handle(fd, name, handle_ptr, mount_ptr, flags):
        assert name == b"" and flags == 0x1001 and os.path.samestat(os.fstat(fd), previous)
        handle = ctypes.cast(handle_ptr, ctypes.POINTER(hh._FileHandle)).contents
        handle.size, handle.kind = 9, 1
        handle.data[:9] = previous.st_ino.to_bytes(8, "big") + bytes([current["generation"]])
        ctypes.cast(mount_ptr, ctypes.POINTER(ctypes.c_uint64))[0] = current["mount"]
        return 0

    monkeypatch.setattr(os, "fstat", reused_inode)
    monkeypatch.setattr(hh, "_root_anchor", lambda _: None)
    monkeypatch.setattr(hh, "_NAME_TO_HANDLE_AT", get_handle)
    binding = grant(helper, root)
    staged = ok(helper, "stage", **binding)
    restarted = hh.Helper(helper.state_dir)
    binding.update(staged)
    ok(restarted, "activate", **binding)
    (root / "new").write_text("edited")
    assert ok(restarted, "read", variant_id=VARIANT, alias="src", path="new")["content"] == "edited"
    shutil.rmtree(root)
    root.mkdir()
    current[change] += 1
    (root / "new").write_text("replacement")
    for server in (restarted, hh.Helper(helper.state_dir)):
        assert err(server, "activate", **binding)[0] == "unavailable"
        assert err(server, "read", variant_id=VARIANT, alias="src", path="new")[0] == "unavailable"


@pytest.fixture
def kernel(tree, monkeypatch):
    """Model the kernel answers for the actual descriptors opened by the helper."""
    state = {"boot": b"a" * 16, "root": 42, "key": 42, "folder": 42, "gen": 9, "key_gen": 1,
             "uuid": bytes(range(16)), "fs": b"ext4", "kind": 1}
    original_open = open

    def open_file(path, *args, **kwargs):
        if path == "/proc/self/mountinfo":
            return io.BytesIO(b"8 1 1:2 / / rw - " + state["fs"] + b" /dev/test rw\n")
        if str(path).startswith("/proc/self/fdinfo/"):
            return io.BytesIO(b"mnt_id:\t8\n")
        return original_open(path, *args, **kwargs)

    def handle(fd, name, handle_ptr, mount_ptr, flags):
        path = os.readlink(f"/proc/self/fd/{fd}")
        target = "root" if path == "/" else "key" if path.endswith("/.approval.key") else "folder"
        result = ctypes.cast(handle_ptr, ctypes.POINTER(hh._FileHandle)).contents
        result.kind = state["kind"] if target == "folder" else 1
        result.size = 8
        generation = {"folder": state["gen"], "key": state["key_gen"], "root": 0}[target]
        result.data[:8] = struct.pack("=II", os.fstat(fd).st_ino & 0xffffffff, generation)
        ctypes.cast(mount_ptr, ctypes.POINTER(ctypes.c_uint64))[0] = state[target]
        return 0

    def fsuuid(fd, op, arg):
        assert op == 0x80111500 and arg == bytes(17) and os.readlink(f"/proc/self/fd/{fd}") == "/"
        return bytes([16]) + state["uuid"]

    monkeypatch.setattr(hh, "open", open_file, raising=False)
    monkeypatch.setattr(hh, "_boot_id", lambda: state["boot"])
    monkeypatch.setattr(hh, "_NAME_TO_HANDLE_AT", handle)
    monkeypatch.setattr(hh.fcntl, "ioctl", fsuuid)
    return state


def reboot(kernel):
    kernel.update(boot=b"b" * 16, root=67, key=67, folder=67)


@pytest.fixture
def previous_helper(tmp_path):
    # Test the previous reader, not a copy of its proof grammar in this test.
    blob = "78c22f11458e59a94dd464328c9f6946146c8670"
    if not shutil.which("git"):
        pytest.skip("downgrade test requires Git and the previous helper blob")
    result = subprocess.run(["git", "cat-file", "blob", blob], cwd=Path(__file__).resolve().parent,
                            capture_output=True)
    if result.returncode:
        pytest.skip("downgrade test requires repository history containing the previous helper blob")
    path = tmp_path / "previous_helper.py"
    path.write_bytes(result.stdout)
    spec = importlib.util.spec_from_file_location("previous_helper", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("prefix", ["b", "d"])
def test_downgrade_requires_fresh_host_permit(tree, kernel, previous_helper, prefix):
    if prefix == "b":
        kernel["key"] += 1
    state = tree["tmp"] / "state"
    state.mkdir()
    binding = attached(hh.Helper(str(state)), tree)
    assert binding["approval_proof"].startswith(prefix)
    old = previous_helper.Helper(str(state))
    scope = dict(variant_id=VARIANT, alias="src", path="README")
    assert err(old, "activate", **binding)[0] == "forbidden"
    assert err(old, "read", **scope)[0] == "unavailable"
    assert err(old, "stage", **binding)[0] == "forbidden"
    permit = state / "permit.Abc123Def456"
    permit.mkdir(mode=0o700)
    (permit / "src").write_bytes(VARIANT.encode() + b"\0" + os.fsencode(tree["app"]))
    approved = ok(old, "stage", **binding, host_permit=permit.name)
    ok(old, "activate", **{**binding, **approved})
    assert ok(old, "read", **scope)["content"].startswith("line 1")


@pytest.fixture
def ext4_root_tree(tree):
    if sys.platform != "linux" or os.geteuid() == 0:
        pytest.skip("requires Linux running as the non-root launcher user")
    mounts = Path("/proc/self/mountinfo")
    if not mounts.is_file() or not Path("/proc/self/fdinfo").is_dir():
        pytest.skip("requires procfs mountinfo and fdinfo")
    roots = [fields for fields in map(bytes.split, mounts.read_bytes().splitlines()) if fields[4] == b"/"]
    if len(roots) != 1 or roots[0][3] != b"/" or roots[0][roots[0].index(b"-") + 1] != b"ext4":
        pytest.skip("requires a native ext4 root mount")
    for path in (tree["tmp"], tree["app"]):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            info = Path(f"/proc/self/fdinfo/{fd}").read_bytes().splitlines()
            if not any(line.split() == [b"mnt_id:", roots[0][0]] for line in info):
                pytest.skip("requires the pytest fixture directory on the same ext4 root mount")
        finally:
            os.close(fd)
    if tuple(map(int, os.uname().release.split("-", 1)[0].split(".")[:2])) < (6, 12):
        pytest.skip("requires Linux 6.12+ for unique mount IDs")
    return tree


def test_reboot_on_real_ext4_root(ext4_root_tree, monkeypatch):
    tree = ext4_root_tree
    state = tree["tmp"] / "state"
    state.mkdir()
    server = hh.Helper(str(state))
    params = grant(server, tree["app"])
    staged = ok(server, "stage", **params)
    assert staged["approval_proof"].startswith("d"), "supported ext4 launcher must issue a durable proof"
    binding = {**staged, "attachment_id": params["attachment_id"]}
    ok(server, "activate", **binding)
    monkeypatch.setattr(hh, "_boot_id", lambda: uuid.UUID(int=0).bytes)
    restarted = hh.Helper(str(state))
    ok(restarted, "activate", **binding)
    assert ok(restarted, "read", variant_id=VARIANT, alias="src", path="README")["content"].startswith("line 1")


def test_reboot_verifies_signed_binding_and_each_read(tree, kernel):
    state = tree["tmp"] / "state"
    state.mkdir()
    binding = attached(hh.Helper(str(state)), tree)
    reboot(kernel)
    restarted = hh.Helper(str(state))
    proof = binding["approval_proof"]
    forged = proof[:-1] + ("1" if proof[-1] == "0" else "0")
    assert err(restarted, "activate", **{**binding, "approval_proof": forged})[0] == "forbidden"
    ok(restarted, "activate", **binding)
    scope = dict(variant_id=VARIANT, alias="src", path="README")
    assert ok(restarted, "read", **scope)["content"].startswith("line 1")
    kernel["folder"] += 1  # Same filesystem and directory, different bind mount.
    assert err(restarted, "read", **scope)[0] == "unavailable"
    assert err(hh.Helper(str(state)), "activate", **binding)[0] == "unavailable"


@pytest.mark.parametrize("changed", [
    {"gen": 10}, {"uuid": b"x" * 16}, {"uuid": bytes(16)}, {"key": 99},
    {"kind": 2}, {"fs": b"overlay"}, {"boot": None}, {"key_gen": 11},
])
def test_reboot_cannot_reauthorize_an_unverified_object(tree, kernel, changed):
    state = tree["tmp"] / "state"
    state.mkdir()
    binding = attached(hh.Helper(str(state)), tree)
    reboot(kernel)
    kernel.update(changed)
    restarted = hh.Helper(str(state))
    for op in ("activate", "list"):
        code, message = err(restarted, op, **binding)
        assert code == "unavailable" and "reattach" in message and "moved" not in message
        if changed in ({"gen": 10}, {"uuid": b"x" * 16}, {"key_gen": 11}):
            assert "identity changed" in message


def test_boot_only_and_legacy_proofs_never_gain_durable_authority(tree, kernel):
    state = tree["tmp"] / "state"
    state.mkdir()
    kernel["key"] += 1
    server = hh.Helper(str(state))
    binding = attached(server, tree)
    assert binding["identity"].startswith("b")
    # Construct the old v4 MAC using its original handle digest.
    scope = {k: binding[k] for k in ("attachment_id", "variant_id", "alias", "path")}
    fid = struct.pack("=II", tree["app"].stat().st_ino & 0xffffffff, kernel["gen"])
    digest = hashlib.sha256(kernel["boot"] + struct.pack("!Qi", kernel["folder"], 1) + fid).hexdigest()
    legacy = {**scope, "approval_proof": server._proof(**scope, identity="h" + digest)}
    ok(server, "activate", **legacy)
    reboot(kernel)  # Even if the new configuration supports a durable anchor.
    restarted = hh.Helper(str(state))
    assert "after host reboot" in err(restarted, "activate", **binding)[1]
    assert "cannot distinguish reboot" in err(restarted, "activate", **legacy)[1]
    assert "reattach" in err(restarted, "list", **scope)[1]
    new = ok(restarted, "stage", **scope, host_permit=host_permit(restarted, VARIANT, src=tree["app"]))
    ok(restarted, "activate", **{**scope, **new})


def test_session_pin_survives_edits_not_replacement_or_restart(helper, tree, monkeypatch):
    monkeypatch.setattr(hh, "_NAME_TO_HANDLE_AT", None)
    binding = attached(helper, tree)
    root = tree["app"]
    scope = dict(variant_id=VARIANT, alias="src")
    (root / "new").write_text("edited")
    assert ok(helper, "read", **scope, path="new")["content"] == "edited"
    permit = host_permit(helper, VARIANT, src=root)
    assert ok(helper, "stage", **binding, host_permit=permit)["approval_proof"] == binding["approval_proof"]
    restarted = hh.Helper(helper.state_dir)
    assert "reattach" in err(restarted, "read", **scope, path="new")[1]
    assert "reattach" in err(restarted, "activate", **binding)[1]
    shutil.rmtree(root)
    root.mkdir()
    (root / "new").write_text("replacement")
    assert err(helper, "read", **scope, path="new")[0] == "unavailable"
    assert err(restarted, "activate", **binding)[0] == "unavailable"
    ok(restarted, "activate", **{**binding, **ok(restarted, "stage", **binding,
                                                 host_permit=host_permit(restarted, VARIANT, src=root))})
    assert ok(restarted, "read", **scope, path="new")["content"] == "replacement"


def test_session_pin_quota_released_on_expiry_and_detach(helper, tree, monkeypatch):
    monkeypatch.setattr(hh, "_NAME_TO_HANDLE_AT", None)
    monkeypatch.setattr(hh, "MAX_SESSION_PINS", 1)
    pending = grant(helper, tree["app"])
    staged = ok(helper, "stage", **pending)
    fd = helper._pins[staged["identity"]].fd
    assert err(helper, "stage", **grant(helper, tree["app"], "other"))[0] == "limit"
    now = hh.time.monotonic() + hh.STAGED_PIN_SECONDS + 1
    monkeypatch.setattr(hh.time, "monotonic", lambda: now)
    helper.expire_pending_pins()
    with pytest.raises(OSError):
        os.fstat(fd)
    assert "reattach" in err(helper, "activate", **{**pending, **staged})[1]
    active = attached(helper, tree)
    fd = helper._pins[active["identity"]].fd
    now += hh.STAGED_PIN_SECONDS + 1
    helper.expire_pending_pins()
    ok(helper, "list", variant_id=VARIANT, alias="src")
    ok(helper, "detach", **active)
    with pytest.raises(OSError):
        os.fstat(fd)


def test_special_file_is_never_opened_for_io(helper, tree, monkeypatch):
    attached(helper, tree)
    os.mkfifo(tree["app"] / "pipe")
    original = os.open
    flags_used = []

    def track(path, flags, *args, **kwargs):
        if path == "pipe":
            flags_used.append(flags)
            assert flags & os.O_PATH
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", track)
    assert err(helper, "read", variant_id=VARIANT, alias="src", path="pipe")[0] == "invalid"
    assert len(flags_used) == 1


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


# -- listing ------------------------------------------------------------------------------------

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


def test_discovered_paths_round_trip_from_scoped_folder(helper, tree):
    attached(helper, tree)
    folder = "/".join(["a" * 198] * 5)
    directory = tree["app"] / folder
    directory.mkdir(parents=True)
    for name in ("ok", "a" * 40, "back\\slash", "control\nchar"):
        (directory / name).write_text("needle")
    scope = {"variant_id": VARIANT, "alias": "src"}
    listing = ok(helper, "list", folder=folder, **scope)
    assert listing["truncated"] and "skipped 3" in listing["message"]
    assert listing["skipped_paths"] == 3 and listing["io_errors"] == 0
    rows = listing["files"]
    assert [row["path"] for row in rows] == [folder + "/ok"]
    assert ok(helper, "read", path=rows[0]["path"], **scope)["content"] == "needle"


def test_staging_requires_a_single_use_scoped_permit_and_never_grants_access(helper, tree):
    params = grant(helper, tree["app"])
    legacy = host_permit(helper, VARIANT, src=tree["app"])
    (tree["tmp"] / "state" / legacy / "src").write_bytes(VARIANT.encode() + b"\0" + os.fsencode(tree["app"]))
    assert err(helper, "stage", **{**params, "host_permit": legacy})[0] == "forbidden"
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
            restored.set(VARIANT, "src", str(tree["app"]), attachment_id=generation, identity="1:1")


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


def test_stalled_activation_does_not_block_other_socket_requests(server, helper, tree, monkeypatch):
    monkeypatch.setattr(hh, "_NAME_TO_HANDLE_AT", None)
    attached(helper, tree)
    params = grant(helper, tree["outside"], alias="slow")
    staged = ok(helper, "stage", **params)
    entered, release = threading.Event(), threading.Event()
    open_folder = helper._open_folder

    def stall(path):
        if path == params["path"]:
            entered.set()
            assert release.wait(10)
        return open_folder(path)

    monkeypatch.setattr(helper, "_open_folder", stall)
    with ThreadPoolExecutor(max_workers=1) as pool:
        activation = pool.submit(hh.request, server.socket_path,
                                 {"op": "activate", **staged, "attachment_id": params["attachment_id"]})
        try:
            assert entered.wait(3)
            assert hh.request(server.socket_path, {"op": "status"}, timeout=2)["ok"]
            read = {"op": "read", "variant_id": VARIANT, "alias": "src", "path": "README"}
            assert hh.request(server.socket_path, read, timeout=2)["result"]["total_lines"] == 3
        finally:
            release.set()
        assert activation.result()["ok"]


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


def test_selinux_label_applies_to_socket_creation_only(helper, tree, monkeypatch):
    from unittest.mock import Mock

    lib = Mock()
    lib.getsockcreatecon_raw.return_value = lib.setsockcreatecon_raw.return_value = 0
    monkeypatch.setattr(hh.ctypes, "CDLL", lambda *args, **kwargs: lib)
    label = "system_u:system_r:container_t:s0:c12,c34"
    create = hh.socket.socket
    bind = hh.HelperServer.server_bind

    def labelled_socket(*args, **kwargs):
        lib.setsockcreatecon_raw.assert_called_once_with(label.encode())
        return create(*args, **kwargs)

    def ordinary_bind(server):
        assert lib.setsockcreatecon_raw.call_count == 2
        assert lib.setsockcreatecon_raw.call_args.args[0].value is None
        bind(server)

    monkeypatch.setattr(hh.socket, "socket", labelled_socket)
    monkeypatch.setattr(hh.HelperServer, "server_bind", ordinary_bind)
    hh.HelperServer(str(tree["tmp"] / "private" / "helper.sock"), helper, label).server_close()


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
    cache = socket_path.parent.parent
    folder = cache / "context-build"
    folder.mkdir(parents=True)
    with (folder / "log").open("wb") as member:
        member.truncate(1024 * 1024 + 1)
    started = subprocess.run([
        sys.executable, script, "serve", "--daemon", "--socket", str(socket_path), "--state-dir", str(state),
        "--pid-file", str(pid_file), "--log-file", str(state / "helper.log"),
        "--cache-dir", str(cache), "--snapshot-mib", "1", "--engine", "/bin/false", "--image", "fixture",
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
        reply = hh.request(str(socket_path), {
            "op": "shell", "source": "directory", "directory": folder.name, "command": "true",
        })
        assert reply["code"] == "limit" and "1048576 bytes" in reply["error"]
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

@pytest.mark.parametrize("op, params", [("list", {})])
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
    assert compiled == ["*.c"]


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
    result = ok(helper, "list", variant_id=VARIANT, alias="src", folder="wide")
    assert result["truncated"] and len(result["files"]) == 3


def test_folder_scopes_listing_inside_the_attachment(helper, tree):
    (tree["app"] / "docs").mkdir()
    (tree["app"] / "docs" / "guide.c").write_text("needle docs\n")
    attached(helper, tree)
    listing = ok(helper, "list", variant_id=VARIANT, alias="src", folder="src", pattern="*.c")
    assert [item["path"] for item in listing["files"]] == ["src/main.c"]
    found = ok(helper, "list", variant_id=VARIANT, alias="src", folder="docs/")
    assert [item["path"] for item in found["files"]] == ["docs/guide.c"]
    # Returned paths stay relative to the attachment, so they can be read directly.
    assert ok(helper, "read", variant_id=VARIANT, alias="src", path="src/main.c")["total_lines"] == 3


@pytest.mark.parametrize("mount_work_root", [True, False], ids=["work-root", "enclosing-root"])
def test_discover_recipe_task_log_relative_to_attachment(helper, tree, mount_work_root):
    workspace = tree["root"] / "workspace"
    work = workspace / "build/tmp/work"
    arch = work / "arm-poky-linux"
    recipe = "sample-provider"
    cve = "CVE-2099-12345"
    for name in ("another-provider", recipe):
        temp = arch / name / "2.4+git" / "temp"
        temp.mkdir(parents=True)
        log = temp / "log.do_cve_check.17"
        log.write_text(f"recipe: {name}\n{cve}: not vulnerable\n")
        (temp / "log.do_cve_check").symlink_to(log.name)
    attached(helper, tree, alias="artifacts", path=work if mount_work_root else workspace)
    scope = dict(variant_id=VARIANT, alias="artifacts")
    if mount_work_root:
        assert err(helper, "list", **scope, folder="build/tmp/work")[0] == "not_found"

    # Orient using a file from a different recipe, then scope to the requested provider.
    sample = ok(helper, "list", **scope, limit=1)["files"][0]["path"]
    tuple_path = PurePosixPath(sample).parents[3]
    listing = ok(helper, "list", **scope, folder=str(tuple_path), pattern=f"{recipe}/*/temp/log.do_cve_check*")
    path, = (PurePosixPath(item["path"]) for item in listing["files"])
    assert path.relative_to(tuple_path) == PurePosixPath(recipe, "2.4+git/temp/log.do_cve_check.17")
    read = ok(helper, "read", **scope, path=str(path), start_line=1, max_lines=2)
    assert read["content"].splitlines() == [f"recipe: {recipe}", f"{cve}: not vulnerable"]


def test_root_sample_can_miss_a_mounted_recipe_workdir(helper, tree, monkeypatch):
    workspace = tree["root"] / "workspace"
    unrelated = workspace / "archives"
    unrelated.mkdir(parents=True)
    for n in range(8):
        (unrelated / str(n)).touch()
    workdir = "build/tmp/work/arm-poky-linux/sample/2.4/temp"
    temp = workspace / workdir
    temp.mkdir(parents=True)
    (temp / "log.do_cve_check.17").touch()
    attached(helper, tree, path=workspace)
    scope = dict(variant_id=VARIANT, alias="src")
    monkeypatch.setattr(hh, "MAX_WALK_ENTRIES", 5)

    sample = ok(helper, "list", **scope, limit=1)
    assert sample["truncated"] and sample["visited_entries"] == 5
    assert len(sample["files"]) == 1 and sample["files"][0]["path"].startswith("archives/")
    scoped = ok(helper, "list", **scope, folder=workdir)
    assert not scoped["truncated"]
    assert [f["path"] for f in scoped["files"]] == [f"{workdir}/log.do_cve_check.17"]


def test_task_log_candidates_need_run_and_exact_cve_evidence(helper, tree):
    workdir = "arm-poky-linux/sample/2.4/temp"
    temp = tree["app"] / workdir
    temp.mkdir(parents=True)
    cve = "CVE-2099-1234"
    target_log = f"{workdir}/log.do_cve_check.17"
    other_log = f"{workdir}/log.do_cve_check.23"
    (tree["app"] / target_log).write_text(f"{cve}5: vulnerable\n{cve}: not vulnerable\n")
    (tree["app"] / other_log).write_text(f"{cve}: vulnerable\n")
    (tree["app"] / "target-task-record").write_text(target_log + "\n")
    attached(helper, tree)
    scope = dict(variant_id=VARIANT, alias="src")

    found = ok(helper, "list", **scope, folder=workdir, pattern="log.do_cve_check*")
    candidates = {}
    for hit in found["files"]:
        content = ok(helper, "read", **scope, path=hit["path"])["content"]
        for line_number, line in enumerate(content.splitlines(), 1):
            if cve in line:
                candidates[hit["path"], line_number] = line.strip()
    assert not found["truncated"]
    assert candidates == {
        (target_log, 1): f"{cve}5: vulnerable",
        (target_log, 2): f"{cve}: not vulnerable",
        (other_log, 1): f"{cve}: vulnerable",
    }
    record = ok(helper, "read", **scope, path="target-task-record")["content"].strip()
    verified = [(number, line) for (path, number), line in candidates.items()
                if path == record and line.partition(":")[0] == cve]
    assert verified == [(2, f"{cve}: not vulnerable")]


def test_folder_rejects_traversal_links_hidden_and_missing_folders(helper, tree):
    attached(helper, tree)
    for folder in ("/", "///", "../outside", "/etc", "src/../..", ".git", "escape_dir", "api_token.txt", "src//x"):
        assert err(helper, "list", variant_id=VARIANT, alias="src", folder=folder)[0] in ("invalid", "not_found")
    assert err(helper, "list", variant_id=VARIANT, alias="src", folder="missing")[0] == "not_found"
    assert err(helper, "list", variant_id=VARIANT, alias="src", folder="README")[0] == "invalid"
