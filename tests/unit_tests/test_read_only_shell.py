import os
import shutil
import subprocess
from pathlib import Path

import pytest

from src.helpers.host_mount_helper import Helper, HelperError, request


@pytest.fixture
def worker(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    source = cache / "context-p-v"
    source.mkdir()
    (source / "source.c").write_text("int vulnerable(void) { return 1; }\n")
    engine = shutil.which("podman") or shutil.which("docker")
    return Helper(str(state), str(cache), engine, os.getenv("VULNSCOUT_TEST_SHELL_IMAGE")), source


def test_snapshot_excludes_sensitive_and_linked_files(worker, tmp_path):
    helper, source = worker
    (source / ".hidden").write_text("hidden")
    (source / "password.txt").write_text("secret")
    (source / "link").symlink_to(source / "source.c")
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    root = helper._shell_root({"source": "directory", "directory": "context-p-v"})
    try:
        result = helper._shell_snapshot(root, str(snapshot))
    finally:
        os.close(root)
    assert result["files"] == 1
    assert result["bytes"] == len((source / "source.c").read_bytes())
    assert "Hidden" in result["excluded"]
    assert sorted(p.name for p in snapshot.iterdir()) == ["source.c"]


def test_snapshot_rejects_hardlinks(worker, tmp_path):
    helper, source = worker
    os.link(source / "source.c", source / "linked.c")
    root = helper._shell_root({"source": "directory", "directory": "context-p-v"})
    try:
        with pytest.raises(HelperError, match="links and special"):
            helper._shell_snapshot(root, str(tmp_path / "snapshot"))
    finally:
        os.close(root)


def test_snapshot_rejects_concurrent_changes(worker, tmp_path, monkeypatch):
    from src.helpers import host_mount_helper

    helper, source = worker
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    root = helper._shell_root({"source": "directory", "directory": "context-p-v"})
    read = os.read

    def mutate_then_read(fd, size):
        (source / "source.c").write_text("different content\n")
        return read(fd, size)

    monkeypatch.setattr(host_mount_helper.os, "read", mutate_then_read)
    try:
        with pytest.raises(HelperError, match="changed"):
            helper._shell_snapshot(root, str(snapshot))
    finally:
        os.close(root)


def test_snapshot_rejects_budget_overflow(worker, tmp_path, monkeypatch):
    helper, _ = worker
    monkeypatch.setattr(helper, "snapshot_bytes", 4)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    root = helper._shell_root({"source": "directory", "directory": "context-p-v"})
    try:
        with pytest.raises(HelperError, match=r"snapshot limit \(4 bytes\)"):
            helper._shell_snapshot(root, str(snapshot))
    finally:
        os.close(root)


@pytest.mark.parametrize("reason", ["bytes", "time", "entries"])
def test_snapshot_enforces_runtime_copy_and_walk_limits(worker, tmp_path, monkeypatch, reason):
    from src.helpers import host_mount_helper as hh

    helper, source = worker
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    path = source / "source.c"
    path.write_bytes(b"A" * 64)
    helper.snapshot_bytes = 64
    monkeypatch.setattr(hh, "SNAPSHOT_CHUNK", 16)
    clock = [0.0]
    monkeypatch.setattr(hh.time, "monotonic", lambda: clock[0])
    if reason == "entries":
        monkeypatch.setattr(hh, "MAX_WALK_ENTRIES", 1)
        (source / "other").touch()
    read = os.read
    reads = []

    def bounded(fd, size):
        assert size <= 16
        reads.append(size)
        if reason == "bytes" and len(reads) == 1:
            with path.open("ab") as growing:
                growing.write(b"+")
        if reason == "time" and len(reads) == 2:
            clock[0] += hh.LIST_TIME_LIMIT + 1
        return read(fd, size)

    monkeypatch.setattr(os, "read", bounded)
    root = helper._shell_root({"source": "directory", "directory": "context-p-v"})
    try:
        limit = {"time": "10s copy/traversal time", "entries": "1 entries", "bytes": "64 bytes"}[reason]
        with pytest.raises(HelperError, match=rf"Shell snapshot limit \({limit}\)"):
            helper._shell_snapshot(root, str(snapshot))
        if reason == "time":
            assert (snapshot / path.name).stat().st_size == 16 and len(reads) == 2
        elif reason == "bytes":
            assert (snapshot / path.name).stat().st_size == 64 and reads[-1] == 1
    finally:
        os.close(root)


def test_shell_rejects_unconfigured_worker(worker):
    helper, _ = worker
    helper.engine = None
    with pytest.raises(HelperError, match="not configured"):
        helper.shell({"source": "directory", "directory": "context-p-v", "command": "ls"})


def test_shell_rejects_remote_docker(worker, monkeypatch, tmp_path):
    helper, _ = worker
    helper.engine = "/usr/bin/docker"
    helper.image = "image"
    monkeypatch.setenv("DOCKER_HOST", "tcp://example.test:2375")
    with pytest.raises(HelperError, match="local Docker Unix socket"):
        helper._run_shell(str(tmp_path), "ls")


def test_snapshot_accepts_binaries_larger_than_text_read_limit(worker, tmp_path):
    helper, source = worker
    with open(source / "binary", "wb") as target:
        target.truncate(11 * 1024 * 1024)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    root = helper._shell_root({"source": "directory", "directory": "context-p-v"})
    try:
        result = helper._shell_snapshot(root, str(snapshot))
    finally:
        os.close(root)
    assert result["files"] == 2
    assert (snapshot / "binary").stat().st_size == 11 * 1024 * 1024


@pytest.mark.skipif(not os.getenv("VULNSCOUT_TEST_SHELL_IMAGE"), reason="requires a local Docker image")
def test_real_worker_is_read_only_and_isolated(worker):
    helper, source = worker
    result = helper.shell({
        "source": "directory", "directory": "context-p-v",
        "command": (
            "grep -n vulnerable source.c; touch source.c; "
            "test ! -e /scan/src && test ! -S /var/run/docker.sock && echo isolated; "
            "ls /sys/class/net"
        ),
    })
    assert result["exit_code"] == 0
    assert "1:int vulnerable" in result["output"]
    assert "Permission denied" in result["output"] or "Read-only file system" in result["output"]
    assert "isolated" in result["output"]
    assert "lo" in result["output"] and "eth0" not in result["output"]
    assert source.joinpath("source.c").read_text() == "int vulnerable(void) { return 1; }\n"


@pytest.mark.skipif(not os.getenv("VULNSCOUT_TEST_SHELL_IMAGE"), reason="requires a local Docker image")
def test_real_worker_supports_binary_tools_and_caps_output(worker):
    helper, source = worker
    shutil.copyfile("/bin/true", source / "program")
    result = helper.shell({
        "source": "directory", "directory": "context-p-v",
        "command": "find . -name '*.c' | grep source | sed 's/source/matched/'; readelf -h program",
    })
    assert result["exit_code"] == 0
    assert "./matched.c" in result["output"] and "ELF Header:" in result["output"]
    result = helper.shell({"source": "directory", "directory": "context-p-v", "command": "yes X"})
    assert result["truncated"] is True
    assert len(result["output"].encode()) == 64 * 1024


@pytest.mark.skipif(not os.getenv("VULNSCOUT_TEST_SHELL_IMAGE"), reason="requires a local Docker image")
def test_real_worker_timeout(worker, monkeypatch):
    from src.helpers import host_mount_helper

    helper, _ = worker
    monkeypatch.setattr(host_mount_helper, "SHELL_TIMEOUT", 2.0)
    result = helper.shell({"source": "directory", "directory": "context-p-v", "command": "sleep 30"})
    assert result["timed_out"] is True


@pytest.mark.skipif(not os.getenv("VULNSCOUT_TEST_SHELL_IMAGE"), reason="requires a local Docker image")
def test_launcher_worker_end_to_end(tmp_path):
    launcher = Path(__file__).resolve().parents[2] / "vulnscout"
    env = {**os.environ, "VULNSCOUT_BUILD_DIR": str(tmp_path / "build"),
           "VULNSCOUT_IMAGE": os.environ["VULNSCOUT_TEST_SHELL_IMAGE"]}
    cache = tmp_path / "build" / "cache"
    source = cache / "context-p-v"
    source.mkdir(parents=True)
    (source / "source.c").write_text("int vulnerable;\n")
    try:
        subprocess.run([str(launcher), "ai-context", "helper", "start"], env=env, check=True, timeout=30)
        reply = request(str(cache / "host-helper" / "helper.sock"), {
            "op": "shell", "source": "directory", "directory": "context-p-v",
            "command": "grep -n vulnerable source.c",
        }, timeout=60)
        assert reply["ok"] is True
        assert reply["result"]["exit_code"] == 0
        assert "1:int vulnerable" in reply["result"]["output"]
    finally:
        subprocess.run([str(launcher), "ai-context", "helper", "stop"], env=env, check=True, timeout=30)
