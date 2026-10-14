# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Additive entrypoint flags used by the host wrapper's subcommands."""

import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = ROOT / "src" / "entrypoint.sh"
APP = "--app src.bin.webapp"


def _run(tmp_path, *args):
    """Run the entrypoint with a fake flask; return the result and the non-migration flask calls."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(exist_ok=True)
    flask = fake_bin / "flask"
    flask.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$TEST_FLASK_LOG"\n')
    flask.chmod(0o755)
    log = tmp_path / "flask.log"
    log.write_text("")
    env = {key: value for key, value in os.environ.items()
           if key not in {"USER_UID", "USER_GID", "PROJECT_NAME", "VARIANT_NAME"}}
    env.update({
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "VULNSCOUT_CONFIG": str(tmp_path / "absent.env"),
        "VULNSCOUT_BASE_DIR": str(tmp_path),
        "VULNSCOUT_INPUTS_DIR": str(tmp_path / "inputs"),
        "OUTPUTS_DIR": str(tmp_path / "outputs"),
        "TEST_FLASK_LOG": str(log),
    })
    result = subprocess.run(
        ["bash", str(ENTRYPOINT), *args], env=env, capture_output=True, text=True, timeout=30,
    )
    calls = [line for line in log.read_text().splitlines() if line != f"{APP} db upgrade"]
    return result, calls


@pytest.mark.parametrize(("args", "command"), [
    (["--delete-scan", "1b4e28ba-2fa1-11d2-883f-0016d3cca427"], "delete-scan 1b4e28ba-2fa1-11d2-883f-0016d3cca427"),
    (["--delete-outdated"], "delete-outdated"),
    (["--delete-empty-scans"], "delete-empty-scans"),
    (["--delete-orphaned-vulns"], "delete-orphaned-vulns"),
])
def test_dry_run_is_forwarded_to_delete_commands(tmp_path, args, command):
    result, calls = _run(tmp_path, "--dry-run", *args)

    assert result.returncode == 0, result.stderr
    assert calls == [f"{APP} {command} --dry-run"]


def test_delete_without_dry_run_is_unchanged(tmp_path):
    result, calls = _run(tmp_path, "--delete-outdated")

    assert result.returncode == 0, result.stderr
    assert calls == [f"{APP} delete-outdated"]


@pytest.mark.parametrize(("args", "scope"), [
    ([], "--project default --variant default"),
    (["--variant", "x86"], "--project default --variant x86"),
    (["--all-variants"], "--project default"),
    (["--project", "P", "--all-variants", "--variant", "x86"], "--project P --variant x86"),
])
def test_custom_openvex_export_scope(tmp_path, args, scope):
    result, calls = _run(tmp_path, *args, "--export-custom-openvex-assessments")

    assert result.returncode == 0, result.stderr
    assert calls == [f"{APP} export-custom-openvex-assessments {scope} --output-dir {tmp_path / 'outputs'}"]


@pytest.mark.parametrize(("args", "scope"), [
    ([], "--project default --variant default"),
    (["--variant", "x86"], "--project default --variant x86"),
    (["--all-variants"], "--project default"),
])
def test_custom_openvex_import_scope(tmp_path, args, scope):
    result, calls = _run(tmp_path, *args, "--import-custom-openvex-assessments", "/tmp/vex.json")

    assert result.returncode == 0, result.stderr
    assert calls == [f"{APP} import-custom-openvex-assessments {scope} /tmp/vex.json"]


@pytest.mark.parametrize(("args", "expected"), [
    (["--project", "P"], "import-context /tmp/ctx.json"),
    (["--project", "P", "--retarget-context"], "import-context --project P /tmp/ctx.json"),
    (["--project", "P", "--variant", "V", "--retarget-context"], "import-context --project P --variant V /tmp/ctx.json"),
])
def test_import_context_retargeting(tmp_path, args, expected):
    result, calls = _run(tmp_path, *args, "--import-context", "/tmp/ctx.json")

    assert result.returncode == 0, result.stderr
    assert calls == [f"{APP} {expected}"]


@pytest.mark.parametrize(("args", "suffix"), [
    ([], ""),
    (["--report-format", "pdf"], " --format pdf"),
    (["--report-format", "html"], " --format html"),
])
def test_report_format_is_forwarded(tmp_path, args, suffix):
    result, calls = _run(tmp_path, *args, "--report", "summary.adoc")

    assert result.returncode == 0, result.stderr
    assert calls == [f"{APP} report summary.adoc --output-dir {tmp_path / 'outputs'} --project default{suffix}"]


@pytest.mark.parametrize("args", [["--report-format", "docx"], ["--report-format"]])
def test_report_format_rejects_unknown_values(tmp_path, args):
    result, calls = _run(tmp_path, *args, "--report", "summary.adoc")

    assert result.returncode == 1
    assert "--report-format must be pdf or html" in result.stderr
    assert calls == []
