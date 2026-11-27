import io
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

from src.helpers.host_mount_helper import Helper, HelperError, request
from tests.unit_tests.host_mount_permits import approve_mount, approve_on_socket

REPO_ROOT = Path(__file__).resolve().parents[2]

VARIANT = "fe447aa1-308e-4ffc-b510-7f8a4cc97138"


def binding(source):
    return {"source": "mount", "variant_id": VARIANT, "alias": "src", "mount_path": str(source)}


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
    helper = Helper(str(state), engine=engine, image=os.getenv("VULNSCOUT_TEST_SHELL_IMAGE"))
    approve_mount(helper, source, helper.dispatch, VARIANT)
    return helper, source


def test_snapshot_excludes_sensitive_and_linked_files(worker, tmp_path):
    helper, source = worker
    (source / ".hidden").write_text("hidden")
    (source / "password.txt").write_text("secret")
    (source / "link").symlink_to(source / "source.c")
    (source / ".config").write_text("CONFIG_NET=m\n")
    (source / "build" / ".config").mkdir(parents=True)
    (source / "build" / ".config" / "private").touch()
    with pytest.raises(HelperError, match="excluded"):
        helper._shell_root({**binding(source), "folder": "build/.config"})
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    root = helper._shell_root(binding(source))
    try:
        result = helper._shell_snapshot(root, str(snapshot))
    finally:
        os.close(root)
    assert result["files"] == 2
    assert (snapshot / ".config").read_text() == "CONFIG_NET=m\n"
    assert result["bytes"] == len((source / "source.c").read_bytes()) + len("CONFIG_NET=m\n")
    assert "Hidden" in result["excluded"]
    assert sorted(p.name for p in snapshot.iterdir()) == [".config", "source.c"]


def test_snapshot_rejects_hardlinks(worker, tmp_path):
    helper, source = worker
    os.link(source / "source.c", source / "linked.c")
    root = helper._shell_root(binding(source))
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
    root = helper._shell_root(binding(source))
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
    helper, source = worker
    monkeypatch.setattr(helper, "snapshot_bytes", 4)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    root = helper._shell_root(binding(source))
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
    root = helper._shell_root(binding(source))
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
    helper, source = worker
    helper.engine = None
    with pytest.raises(HelperError, match="not configured"):
        helper.shell({**binding(source), "command": "ls"})


def test_worker_rejects_unapproved_shell_sources_before_copy(worker, monkeypatch):
    helper, source = worker
    helper.engine = "podman"
    helper.image = "fixture"
    monkeypatch.setattr(helper, "_snapshot_workspace", lambda: pytest.fail("Unexpected snapshot"))
    for fields, code in (({"source": "directory", "directory": source.name}, "forbidden"),
                         ({**binding(source), "mount_path": str(source.parent)}, "forbidden"),
                         ({**binding(source), "alias": "unknown"}, "not_found")):
        result = helper.dispatch({"op": "shell", "command": "true", **fields})
        assert not result["ok"] and result["code"] == code


def test_reaper_only_removes_abandoned_owned_snapshots(worker):
    helper, source = worker
    state = Path(helper.state_dir)
    unrelated = state / "shell-manual-backup"
    unrelated.mkdir()
    # Simulate a worker process exiting without running its finally blocks.
    process = subprocess.run([
        sys.executable, "-c",
        "import os, sys\n"
        "from src.helpers.host_mount_helper import Helper\n"
        "with Helper(sys.argv[1])._snapshot_workspace() as path:\n"
        "    print(path, flush=True)\n"
        "    os._exit(0)\n", str(state),
    ], check=True, text=True, capture_output=True, cwd=REPO_ROOT)
    abandoned = Path(process.stdout.strip())
    (abandoned / "source").symlink_to(source, target_is_directory=True)
    with helper._snapshot_workspace() as active:
        Helper(str(state)).reap_shell_snapshots()
        assert Path(active).is_dir()
        assert not abandoned.exists() and unrelated.is_dir() and (source / "source.c").is_file()


def _wait_for_path(path, process):
    for _ in range(250):
        if path.exists():
            return
        assert process.poll() is None
        time.sleep(.02)
    pytest.fail(f"Timed out waiting for {path.name}")


@pytest.mark.skipif(os.geteuid() == 0, reason="the host helper refuses to run as root")
def test_restart_drains_a_running_shell_job(worker, tmp_path):
    _, source = worker
    state = tmp_path / "daemon-state"
    engine = tmp_path / "podman"
    running = tmp_path / "running"
    release = tmp_path / "release"
    engine.write_text(
        f"#!{sys.executable}\nimport time\nfrom pathlib import Path\n"
        f"Path({str(running)!r}).touch()\nwhile not Path({str(release)!r}).exists(): time.sleep(.02)\n"
    )
    engine.chmod(0o700)
    socket_path = tmp_path / "socket" / "helper.sock"
    pid_path = tmp_path / "helper.pid"
    argv = [sys.executable, "-m", "src.helpers.host_mount_helper", "serve", "--socket", str(socket_path),
            "--pid-file", str(pid_path), "--state-dir", str(state),
            "--engine", str(engine), "--image", "fixture"]

    for first_start in (True, False):
        process = subprocess.Popen(argv, cwd=REPO_ROOT)
        try:
            _wait_for_path(pid_path, process)
            assert request(str(socket_path), {"op": "status"})["ok"]
            if first_start:
                approve_on_socket(state, socket_path, source, VARIANT)
                with ThreadPoolExecutor(max_workers=1) as pool:
                    result = pool.submit(request, str(socket_path), {
                        "op": "shell", **binding(source), "command": "true",
                    })
                    try:
                        _wait_for_path(running, process)
                        process.terminate()
                        with pytest.raises(subprocess.TimeoutExpired):
                            process.wait(timeout=.2)
                    finally:
                        release.touch()
                    assert result.result(timeout=5)["ok"]
            else:
                process.terminate()
            assert process.wait(timeout=5) == 0
            assert not list(state.glob("shell-*"))
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


@pytest.mark.skipif(os.geteuid() == 0, reason="the host helper refuses to run as root")
def test_shutdown_signal_does_not_interrupt_request_handoff(tmp_path):
    script = """
import os
import signal
import socketserver
from src.helpers.host_mount_helper import main

def finish_before_handoff_returns(server, connection, address):
    server.process_request_thread(connection, address)
    os.kill(os.getpid(), signal.SIGTERM)

socketserver.ThreadingMixIn.process_request = finish_before_handoff_returns
raise SystemExit(main())
"""
    socket_path = tmp_path / "socket" / "helper.sock"
    pid_path = tmp_path / "helper.pid"
    argv = [sys.executable, "-c", script, "serve", "--socket", str(socket_path),
            "--pid-file", str(pid_path), "--state-dir", str(tmp_path / "daemon-state")]
    with subprocess.Popen(argv, cwd=REPO_ROOT) as process:
        try:
            _wait_for_path(pid_path, process)
            assert request(str(socket_path), {"op": "status"}, timeout=5)["ok"]
            assert process.wait(timeout=5) == 0
        finally:
            if process.poll() is None:
                process.kill()
    assert not pid_path.exists()
    assert not socket_path.exists()


def test_shutdown_drains_pending_shell_reply(worker, monkeypatch):
    from src.helpers import host_mount_helper as hh

    helper, _ = worker
    monkeypatch.setattr(helper, "_shell_job", lambda request: {"output": "fixture"})
    writing, release = Event(), Event()
    idle_at_drain: Future[bool] = Future()
    wait_for = helper._shell_condition.wait_for

    def observe_drain(predicate, timeout):
        idle_at_drain.set_result(predicate())
        return wait_for(predicate, timeout)

    class BlockingReply(io.BytesIO):
        def write(self, data):
            writing.set()
            assert release.wait(5)
            return super().write(data)

    monkeypatch.setattr(helper._shell_condition, "wait_for", observe_drain)
    handler = object.__new__(hh._Handler)
    handler.server = SimpleNamespace(helper=helper)
    handler.rfile = io.BytesIO(b'{"op":"shell"}\n')
    handler.wfile = BlockingReply()

    with ThreadPoolExecutor(max_workers=2) as pool:
        handling = pool.submit(handler.handle)
        try:
            assert writing.wait(5)
            draining = pool.submit(helper.drain_shells)
            assert idle_at_drain.result(timeout=5) is False
        finally:
            release.set()
        handling.result(timeout=5)
        draining.result(timeout=5)
    assert json.loads(handler.wfile.getvalue())["result"] == {"output": "fixture"}


def test_shell_rejects_remote_docker(worker, monkeypatch, tmp_path):
    helper, _ = worker
    helper.engine = "/usr/bin/docker"
    helper.image = "image"
    monkeypatch.setenv("DOCKER_HOST", "tcp://example.test:2375")
    with pytest.raises(HelperError, match="local Docker Unix socket"):
        helper._run_shell(str(tmp_path), "ls")


class _StoppedProcess:
    stdout = None
    returncode = 0

    def __init__(self):
        read, write = os.pipe()
        os.close(write)
        self.stdout = os.fdopen(read, "rb")

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0


def _launched_args(helper, monkeypatch, tmp_path):
    from src.helpers import host_mount_helper as hh

    launched = []
    monkeypatch.setattr(hh.subprocess, "Popen", lambda args, **kwargs: launched.append(args) or _StoppedProcess())
    helper._run_shell(str(tmp_path), "true")
    return launched[0]


def test_podman_worker_drops_proxies_and_default_mounts(worker, monkeypatch, tmp_path):
    helper, _ = worker
    helper.engine, helper.image = "/usr/bin/podman", "image"
    args = _launched_args(helper, monkeypatch, tmp_path)
    empty = Path(helper.state_dir) / ".empty-mounts.conf"
    assert "--http-proxy=false" in args and f"--default-mounts-file={empty}" in args
    assert empty.read_bytes() == b""


def test_podman_worker_resets_mounts_file_content(worker, monkeypatch, tmp_path):
    helper, _ = worker
    helper.engine, helper.image = "/usr/bin/podman", "image"
    empty = Path(helper.state_dir) / ".empty-mounts.conf"
    empty.write_text("/etc/pki:/etc/pki\n")
    _launched_args(helper, monkeypatch, tmp_path)
    assert empty.read_bytes() == b""


def test_docker_worker_overrides_injected_proxies(worker, monkeypatch, tmp_path):
    helper, _ = worker
    helper.engine, helper.image = "/usr/bin/docker", "image"
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    args = _launched_args(helper, monkeypatch, tmp_path)
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "no_proxy"):
        assert f"--env={name}=" in args


def test_state_locks_use_writable_files(worker, monkeypatch):
    from src.helpers import host_mount_helper as hh
    import fcntl

    helper, _ = worker
    modes = []
    flock = fcntl.flock

    def checked(fd, operation):
        modes.append(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE)
        return flock(fd, operation)

    monkeypatch.setattr(hh.fcntl, "flock", checked)
    with helper._snapshot_workspace():
        helper.reap_shell_snapshots()
    assert len(modes) == 4 and set(modes) == {os.O_RDWR}


def test_drain_gives_up_on_jobs_blocked_in_io(worker, monkeypatch):
    from src.helpers import host_mount_helper as hh

    helper, _ = worker
    monkeypatch.setattr(hh, "SHELL_DRAIN_TIMEOUT", 0.05)
    helper._active_shells = 1
    started = time.monotonic()
    helper.drain_shells()
    assert time.monotonic() - started < 2
    with pytest.raises(HelperError, match="stopping"):
        helper.shell({**binding(Path("/")), "command": "true"})


def test_snapshot_accepts_binaries_larger_than_text_read_limit(worker, tmp_path):
    helper, source = worker
    with open(source / "binary", "wb") as target:
        target.truncate(11 * 1024 * 1024)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    root = helper._shell_root(binding(source))
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
        **binding(source),
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
def test_real_worker_does_not_inherit_proxy_credentials(worker, monkeypatch):
    helper, source = worker
    for name in ("HTTP_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://user:dummy-secret@proxy.invalid:3128")
    result = helper.shell({**binding(source), "command": "env"})
    assert result["exit_code"] == 0
    assert "dummy-secret" not in result["output"]


@pytest.mark.skipif(not os.getenv("VULNSCOUT_TEST_SHELL_IMAGE"), reason="requires a local Docker image")
def test_real_worker_supports_binary_tools_and_caps_output(worker):
    helper, source = worker
    shutil.copyfile("/bin/true", source / "program")
    result = helper.shell({
        **binding(source),
        "command": "find . -name '*.c' | grep source | sed 's/source/matched/'; readelf -h program",
    })
    assert result["exit_code"] == 0
    assert "./matched.c" in result["output"] and "ELF Header:" in result["output"]
    result = helper.shell({**binding(source), "command": "yes X"})
    assert result["truncated"] is True
    assert len(result["output"].encode()) == 64 * 1024


@pytest.mark.skipif(not os.getenv("VULNSCOUT_TEST_SHELL_IMAGE"), reason="requires a local Docker image")
def test_real_worker_timeout(worker, monkeypatch):
    from src.helpers import host_mount_helper

    helper, source = worker
    monkeypatch.setattr(host_mount_helper, "SHELL_TIMEOUT", 2.0)
    result = helper.shell({**binding(source), "command": "sleep 30"})
    assert result["timed_out"] is True


@pytest.mark.skipif(not os.getenv("VULNSCOUT_TEST_SHELL_IMAGE"), reason="requires a local Docker image")
def test_launcher_worker_end_to_end(tmp_path):
    launcher = Path(__file__).resolve().parents[2] / "vulnscout"
    state = tmp_path / "state"
    env = {**os.environ, "VULNSCOUT_BUILD_DIR": str(tmp_path / "build"), "VULNSCOUT_HOST_HELPER_STATE_DIR": str(state),
           "VULNSCOUT_IMAGE": os.environ["VULNSCOUT_TEST_SHELL_IMAGE"]}
    cache = tmp_path / "build" / "cache"
    source = tmp_path / "approved"
    source.mkdir(parents=True)
    (source / "source.c").write_text("int vulnerable;\n")
    try:
        subprocess.run([str(launcher), "ai-context", "helper", "start"], env=env, check=True, timeout=30)
        socket = cache / "host-helper" / "helper.sock"
        approve_on_socket(state, socket, source, VARIANT)
        reply = request(str(socket), {
            "op": "shell", **binding(source),
            "command": "grep -n vulnerable source.c",
        }, timeout=60)
        assert reply["ok"] is True
        assert reply["result"]["exit_code"] == 0
        assert "1:int vulnerable" in reply["result"]["output"]
    finally:
        subprocess.run([str(launcher), "ai-context", "helper", "stop"], env=env, check=True, timeout=30)
