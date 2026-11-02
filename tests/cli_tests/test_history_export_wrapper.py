# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""History export forwarding without a container daemon."""

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
    ps) echo vulnscout ;;
    exec)
        printf '%s\\n' "$*" >> "$CALL_LOG"
        printf '{"history":[]}\\n'
        exit "${EXEC_EXIT:-0}" ;;
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

    return run, log, bin_dir, env


@pytest.mark.parametrize("format_", ["json", "csv"])
def test_history_export_forwards_timestamps_filters_scope_and_exit_status(wrapper, format_):
    run, log, _, _ = wrapper
    args = ["export", "vulnerability-history", "--since", "2026-10-01", "--until", "2026-10-02",
            "--source", "nvd", "--source", "epss", "--field", "description", "--vuln-id", "CVE-2099-0001",
            "--format", format_, "-p", "demo", "-v", "x86"]
    result = run(*args)
    assert result.returncode == 0, result.stderr
    assert result.stdout == '{"history":[]}\n'
    assert ("--project demo --variant x86 --export-vulnerability-history "
            "--since 2026-10-01 --until 2026-10-02 --source nvd --source epss "
            "--field description --vuln-id CVE-2099-0001 --format " + format_) in log.read_text()
    assert run(*args, exit_code=1).returncode == 1


@pytest.mark.parametrize("args", [
    [], ["--since"], ["--since", "2026-10-01", "--format", "pdf"],
    ["--since", "2026-10-01", "-v", "x86"], ["--since", "2026-10-01", "--run-id", "old"],
    ["--since", "2026-10-01", "--until"],
])
def test_history_export_rejects_missing_values_and_unsupported_options(wrapper, args):
    run, log, _, _ = wrapper
    result = run("export", "vulnerability-history", *args)
    assert result.returncode != 0
    assert not log.exists()


def test_entrypoint_forwards_history_options_and_scope_to_flask(wrapper):
    _, log, bin_dir, env = wrapper
    flask = bin_dir / "flask"
    flask.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$CALL_LOG"\nprintf \'{"history":[]}\\n\'\n')
    flask.chmod(0o755)
    result = subprocess.run(
        ["bash", str(ROOT / "src/entrypoint.sh"), "--project", "demo", "--variant", "x86",
         "--export-vulnerability-history", "--since", "2026-10-01", "--until", "2026-10-02", "--format", "csv"],
        cwd=ROOT, env={**env, "VULNSCOUT_BASE_DIR": str(ROOT),
                       "VULNSCOUT_CONFIG": str(bin_dir / "absent.env")},
        text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == '{"history":[]}\n'
    assert ("--app src.bin.webapp export-vulnerability-history --project demo --variant x86 "
            "--since 2026-10-01 --until 2026-10-02 --format csv") in log.read_text()
