# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Host and container forwarding for exact refresh artifacts, without a daemon."""

import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def wrapper(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    podman = bin_dir / "podman"
    podman.write_text("""#!/bin/bash
set -eu
case "$1" in
    info) echo false ;;
    ps) echo vulnscout ;;
    exec)
        printf '%s\\n' "$*" >> "$CALL_LOG"
        case "$*" in *--export-refresh-changes*) printf '{"run_id":"exact"}\\n' ;; esac
        exit "${EXEC_EXIT:-0}" ;;
    inspect) echo v0.24 ;;
    *) exit 99 ;;
esac
""")
    podman.chmod(0o755)
    log = tmp_path / "calls"
    env = {**os.environ, "PATH": f"{bin_dir}:/usr/bin:/bin", "CALL_LOG": str(log),
           "VULNSCOUT_BUILD_DIR": str(tmp_path / "build")}

    def run(*args, exit_code=0):
        return subprocess.run(
            [str(ROOT / "vulnscout"), *args], cwd=ROOT, env={**env, "EXEC_EXIT": str(exit_code)},
            text=True, capture_output=True,
        )

    return run, log, tmp_path, env


def test_refresh_scope_options_after_command_and_caller_identity(wrapper):
    run, log, _, _ = wrapper
    result = run("refresh", "--run-id", "caller-exact", "-p", "demo", "-v", "x86")
    assert result.returncode == 0, result.stderr
    assert "--project demo --variant x86 --refresh-vulnerability-data --refresh-run-id caller-exact" in log.read_text()
    assert run("refresh", "--run-id", "caller-exact", exit_code=1).returncode == 1
    assert run("refresh", "-v", "x86").returncode != 0


@pytest.mark.parametrize("format_", ["json", "csv"])
def test_exact_export_forwarding_stdout_and_failure(wrapper, format_):
    run, log, _, _ = wrapper
    result = run("export", "refresh-changes", "--run-id", "caller-exact", "--format", format_, "-p", "demo")
    assert result.returncode == 0
    assert result.stdout == '{"run_id":"exact"}\n'
    assert f"--project demo --export-refresh-changes caller-exact --refresh-changes-format {format_}" in log.read_text()
    assert run("export", "refresh-changes", "--run-id", "caller-exact", exit_code=1).returncode == 1
    assert run("export", "refresh-changes").returncode != 0
    assert run("export", "refresh-changes", "--run-id", "caller-exact", "--format", "pdf").returncode != 0


def test_container_entrypoint_forwards_exact_id_format_and_scope(wrapper):
    _, log, directory, env = wrapper
    flask = directory / "bin" / "flask"
    flask.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$CALL_LOG"\nprintf \'{"exact":true}\\n\'\n')
    flask.chmod(0o755)
    env = {**env, "VULNSCOUT_BASE_DIR": str(ROOT), "VULNSCOUT_CONFIG": str(directory / "absent.env")}
    result = subprocess.run(
        ["bash", str(ROOT / "src/entrypoint.sh"), "--project", "demo", "--variant", "x86",
         "--export-refresh-changes", "exact", "--refresh-changes-format", "csv"],
        cwd=ROOT, env=env, text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == '{"exact":true}\n'
    assert "--app src.bin.webapp export-refresh-changes --run-id exact --format csv --project demo --variant x86" in (
        log.read_text()
    )
