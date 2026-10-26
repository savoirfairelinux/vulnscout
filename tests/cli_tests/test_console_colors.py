# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Color policy, real terminal behavior, and the host/container boundary."""

import errno
import json
import os
from pathlib import Path
import pty
import re
import subprocess
import sys
from threading import Thread
from types import SimpleNamespace
import uuid

import click
from click.testing import CliRunner
import pytest

from src.bin._console import Command, color_enabled, echo, print_message, verbose, warn
from src.bin.cmd_scans import _echo_object_list
from src.bin.cmd_vuln_scan import _echo_query_results, new_scan_run_id_command

ROOT = Path(__file__).resolve().parents[2]
ANSI = re.compile(r"\x1b\[[0-9;]*m")


@pytest.fixture
def env(tmp_path, monkeypatch):
    for key in ("NO_COLOR", "_VULNSCOUT_COLOR_STDOUT", "_VULNSCOUT_COLOR_STDERR"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("TERM", "xterm")
    result = dict(os.environ)
    result.update({
        "VULNSCOUT_BUILD_DIR": str(tmp_path / "build"),
        "VULNSCOUT_BASE_DIR": str(tmp_path),
        "VULNSCOUT_INPUTS_DIR": str(tmp_path / "inputs"),
        "VULNSCOUT_CONFIG": str(tmp_path / "config.env"),
        "SBOM_CVE_CHECK_DATABASES_DIR": str(tmp_path / "databases"),
        "OUTPUTS_DIR": str(tmp_path / "outputs"),
        "TEST_ENTRYPOINT": str(ROOT / "src/entrypoint.sh"),
        "TEST_ENGINE_LOG": str(tmp_path / "engine.log"),
        "TEST_PYTHON": sys.executable,
        "PYTHONPATH": str(ROOT),
    })
    return result


def run(command, env, *, terminal=None):
    """Attach one selected destination to a real PTY, retaining separate streams."""
    if terminal is None:
        return subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
    master, slave = pty.openpty()
    chunks = []

    def read_terminal():
        try:
            while True:
                chunk = os.read(master, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except OSError as exc:
            if exc.errno != errno.EIO:
                raise

    reader = Thread(target=read_terminal)
    reader.start()
    try:
        process = subprocess.Popen(
            command, env=env,
            stdout=slave if terminal == "stdout" else subprocess.PIPE,
            stderr=slave if terminal == "stderr" else subprocess.PIPE,
        )
        os.close(slave)
        stdout, stderr = process.communicate(timeout=30)
        reader.join(timeout=5)
        assert not reader.is_alive()
        output = b"".join(chunks).decode().replace("\r\n", "\n")
        return SimpleNamespace(
            returncode=process.returncode,
            stdout=output if terminal == "stdout" else stdout.decode(),
            stderr=output if terminal == "stderr" else stderr.decode(),
        )
    finally:
        os.close(master)


def stub_engine(tmp_path, env, engine="podman"):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    stub = bindir / engine
    stub.write_text("""#!/bin/bash
set -euo pipefail
case "$1" in
    ps) echo vulnscout ;;
    exec)
        printf '%s\\n' "$@" > "$TEST_ENGINE_LOG"
        shift
        while [[ "${1:-}" == --env ]]; do export "$2"; shift 2; done
        shift 2
        bash "$TEST_ENTRYPOINT" "$@" ;;
    *) exit 0 ;;
esac
""")
    stub.chmod(0o755)
    # A controlled PATH also permits testing Docker on hosts with Podman installed.
    env["PATH"] = f"{bindir}:/usr/bin:/bin"
    return bindir


def stub_flask(bindir):
    flask = bindir / "flask"
    flask.write_text("""#!/bin/bash
set -euo pipefail
shift 2 # --app src.bin.webapp
case "$1" in
    db) exit 0 ;;
    new-scan-run-id) printf 'run-id\\n'; exit 0 ;;
    process) printf '::STATUS::1::Processing\\n' ;;
esac
"$TEST_PYTHON" -c '
import click
from src.bin._console import Command, echo
with click.Context(Command("test")):
    echo("Finished", role="success")
    echo("Warning: test", role="warning", err=True)
'
[[ "$1" != process ]] || exit 2
""")
    flask.chmod(0o755)


@pytest.mark.parametrize(("role", "code"), [
    ("info", 36), ("success", 32), ("warning", 33), ("error", 31),
])
def test_exact_palette_and_plain_text(env, monkeypatch, role, code):
    monkeypatch.setenv("_VULNSCOUT_COLOR_STDOUT", "1")

    @click.command(cls=Command)
    def command():
        echo("Message", role=role)

    colored = CliRunner().invoke(command, color=True)
    assert colored.output == f"\x1b[{code}mMessage\x1b[0m\n"
    monkeypatch.setenv("NO_COLOR", "1")
    plain = CliRunner().invoke(command, color=True)
    assert plain.output == "Message\n"
    assert ANSI.sub("", colored.output) == plain.output


@pytest.mark.parametrize("setting", [{"NO_COLOR": "1"}, {"TERM": "dumb"}])
def test_opt_out_overrides_transport_hints(env, monkeypatch, setting):
    monkeypatch.setenv("_VULNSCOUT_COLOR_STDOUT", "1")
    monkeypatch.setenv("_VULNSCOUT_COLOR_STDERR", "1")
    for key, value in setting.items():
        monkeypatch.setenv(key, value)
    assert not color_enabled()
    assert not color_enabled(err=True)


def test_empty_no_color_does_not_disable_colors(env, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "")
    monkeypatch.setenv("_VULNSCOUT_COLOR_STDOUT", "1")
    assert color_enabled()


def test_python_messages_detect_each_terminal_stream(env):
    code = """import click
from src.bin._console import Command, echo
with click.Context(Command('test')):
    echo('Info')
    echo('Error', role='error', err=True)
"""
    command = [sys.executable, "-c", code]
    plain = run(command, env)
    assert plain.stdout == "Info\n"
    assert plain.stderr == "Error\n"
    out = run(command, env, terminal="stdout")
    err = run(command, env, terminal="stderr")
    assert out.stdout == "\x1b[36mInfo\x1b[0m\n"
    assert out.stderr == plain.stderr
    assert err.stdout == plain.stdout
    assert err.stderr == "\x1b[31mError\x1b[0m\n"


def test_click_help_and_generated_errors(env, monkeypatch):
    monkeypatch.setenv("_VULNSCOUT_COLOR_STDOUT", "1")
    monkeypatch.setenv("_VULNSCOUT_COLOR_STDERR", "1")

    @click.command(cls=Command)
    @click.option("--fail", is_flag=True)
    def command(fail):
        """Example command."""
        if fail:
            raise click.ClickException("Failed")

    runner = CliRunner()
    help_result = runner.invoke(command, ["--help"], color=True)
    assert help_result.exit_code == 0
    assert "\x1b[36m\x1b[1mUsage:" in help_result.stdout
    assert "\x1b[36m\x1b[1m--fail\x1b[0m" in help_result.stdout
    for args, exit_code in [(["--unknown"], 2), (["--fail"], 1)]:
        result = runner.invoke(command, args, color=True)
        assert result.exit_code == exit_code
        assert "\x1b[31m" in result.stderr
        monkeypatch.setenv("NO_COLOR", "1")
        plain = runner.invoke(command, args, color=True)
        assert ANSI.sub("", result.stderr) == plain.stderr
        monkeypatch.delenv("NO_COLOR")


def test_machine_output_pager_and_scan_progress(env, monkeypatch):
    monkeypatch.setenv("_VULNSCOUT_COLOR_STDOUT", "1")
    monkeypatch.setenv("_VULNSCOUT_COLOR_STDERR", "1")
    runner = CliRunner()
    run_id = runner.invoke(new_scan_run_id_command, color=True)
    assert run_id.exit_code == 0
    assert run_id.stdout.startswith("q-")
    uuid.UUID(run_id.stdout.strip()[2:])
    assert "\x1b" not in run_id.stdout

    @click.command(cls=Command)
    @click.option("--json", "as_json", is_flag=True)
    def listing(as_json):
        _echo_object_list(as_json, ["item"], lambda obj: obj + "\n", lambda obj: {"name": obj})

    assert json.loads(runner.invoke(listing, ["--json"], color=True).stdout) == [{"name": "item"}]
    pretty = runner.invoke(listing, color=True).stdout
    assert "\x1b[36mitem" in pretty
    monkeypatch.setenv("NO_COLOR", "1")
    assert "\x1b" not in runner.invoke(listing, color=True).stdout
    monkeypatch.delenv("NO_COLOR")

    @click.command(cls=Command)
    def progress():
        _echo_query_results(1, 2, "package", ["CVE-2026-1234"])
        print_message("Parsed")
        verbose("Details")
        warn("Problem")

    monkeypatch.setenv("VERBOSE_MODE", "true")
    result = runner.invoke(progress, color=True)
    assert "\x1b[36m[1/2] package" in result.stdout
    assert "\x1b[36mParsed" in result.stdout
    assert "\x1b[36mDetails" in result.stdout
    assert "\x1b[33mProblem" in result.stderr


def test_shared_helpers_stay_plain_outside_cli(env, monkeypatch, capsys):
    monkeypatch.setenv("_VULNSCOUT_COLOR_STDOUT", "1")
    print_message("Shared processing")
    assert capsys.readouterr().out == "Shared processing\n"


@pytest.mark.parametrize("script", ["vulnscout", "src/entrypoint.sh"])
def test_shell_help_in_terminal_pipe_and_file(tmp_path, env, script):
    stub_engine(tmp_path, env)
    command = ["bash", str(ROOT / script), "--help"]
    plain = run(command, env)
    colored = run(command, env, terminal="stdout")
    assert colored.returncode == plain.returncode == 0
    assert "\x1b[1;36m" in colored.stdout
    assert "\x1b" not in plain.stdout
    assert ANSI.sub("", colored.stdout) == plain.stdout
    for setting in ({"NO_COLOR": "1"}, {"TERM": "dumb"}):
        disabled = run(command, {**env, **setting}, terminal="stdout")
        assert disabled.stdout == plain.stdout
    output = tmp_path / "help.txt"
    with output.open("w") as file:
        subprocess.run(command, env=env, stdout=file, check=True, timeout=30)
    assert output.read_text() == plain.stdout


def test_every_launcher_command_help_preserves_plain_text(tmp_path, env):
    stub_engine(tmp_path, env)
    commands = (
        "add", "scan", "match-condition", "report", "export", "import", "refresh",
        "delete", "list", "config", "asset", "start", "stop", "restart", "update",
        "version", "serve",
    )
    for verb in commands:
        command = ["bash", str(ROOT / "vulnscout"), verb, "--help"]
        plain = run(command, env)
        colored = run(command, env, terminal="stdout")
        assert colored.returncode == plain.returncode == 0, verb
        assert "\x1b[1;36m" in colored.stdout, verb
        assert ANSI.sub("", colored.stdout) == plain.stdout, verb


def test_completion_and_config_values_are_plain_in_terminal(tmp_path, env):
    stub_engine(tmp_path, env)
    completion = run(["bash", str(ROOT / "vulnscout"), "completion", "bash"], env, terminal="stdout")
    assert completion.returncode == 0
    assert "\x1b" not in completion.stdout
    assert "complete -F _vulnscout_complete" in completion.stdout
    config = tmp_path / "build/cache/config.env"
    config.parent.mkdir(parents=True)
    config.write_text("TEST_VALUE=hello\n")
    value = run(["bash", str(ROOT / "vulnscout"), "config", "get", "TEST_VALUE"], env, terminal="stdout")
    assert value.returncode == 0
    assert value.stdout == "hello\n"
    assert config.read_text() == "TEST_VALUE=hello\n"


def test_shell_error_stream_detection(tmp_path, env):
    stub_engine(tmp_path, env)
    command = ["bash", str(ROOT / "vulnscout"), "unknown"]
    plain = run(command, env)
    colored = run(command, env, terminal="stderr")
    assert colored.returncode == plain.returncode == 1
    assert "\x1b[31m" in colored.stderr
    assert ANSI.sub("", colored.stderr) == plain.stderr
    assert colored.stdout == plain.stdout


@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("terminal", [None, "stdout", "stderr"])
def test_host_container_stream_policy(tmp_path, env, engine, terminal):
    stub_flask(stub_engine(tmp_path, env, engine))
    command = ["bash", str(ROOT / "vulnscout"), "list", "projects"]
    result = run(command, env, terminal=terminal)
    assert result.returncode == 0, result.stderr
    assert ("\x1b[32mFinished" in result.stdout) == (terminal == "stdout")
    assert ("\x1b[33mWarning: test" in result.stderr) == (terminal == "stderr")
    log = Path(env["TEST_ENGINE_LOG"]).read_text()
    assert f"_VULNSCOUT_COLOR_STDOUT={int(terminal == 'stdout')}\n" in log
    assert f"_VULNSCOUT_COLOR_STDERR={int(terminal == 'stderr')}\n" in log
    assert "-t\n" not in log and "--tty\n" not in log
    disabled = run(command, {**env, "NO_COLOR": "1"}, terminal=terminal)
    assert "\x1b" not in disabled.stdout + disabled.stderr
    assert "NO_COLOR=1\n" in Path(env["TEST_ENGINE_LOG"]).read_text()


def test_processing_pipeline_status_file_and_failure_exit(tmp_path, env):
    bindir = stub_engine(tmp_path, env)
    stub_flask(bindir)
    result = run(
        ["bash", str(ROOT / "vulnscout"), "match-condition", "affected"],
        env, terminal="stdout",
    )
    assert result.returncode == 2, result.stderr
    assert "::STATUS::" not in result.stdout
    assert "\x1b[36mStep (1/2): Processing" in result.stdout
    assert "\x1b[32mFinished" in result.stdout
    status = (tmp_path / "status.txt").read_text()
    assert "1 Processing\n" in status
    assert "\x1b" not in status
