"""CLI coverage for typed scanner selection at the host and container boundaries."""

import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = ROOT / "src" / "entrypoint.sh"
WRAPPER = ROOT / "vulnscout"


@pytest.mark.parametrize("script", [ENTRYPOINT, WRAPPER], ids=["entrypoint", "wrapper"])
@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--perform-scans"], "requires a scan type"),
        (["--perform-scans", "--refresh-vulnerability-data"], "requires a scan type"),
        (["--perform-scans", "unknown"], "unknown scan type 'unknown'"),
        (["--perform-scans", "nvd,unknown"], "unknown scan type 'unknown'"),
        (["--perform-scans", "nvd,"], "requires scan types"),
        (["--perform-scans", ",nvd"], "requires scan types"),
        (["--perform-scans", "nvd,,osv"], "requires scan types"),
    ],
)
def test_rejects_invalid_scan_selection(script, args, message):
    if script == WRAPPER and not (shutil.which("podman") or shutil.which("docker")):
        pytest.skip("host wrapper requires a container engine executable")

    result = subprocess.run(["bash", str(script), *args], cwd=ROOT, capture_output=True, text=True)

    assert result.returncode == 1
    assert message in result.stderr


@pytest.mark.parametrize(
    "args",
    [
        ["--perform-scans", "all"],
        ["--perform-scans", "grype,nvd,osv,sbom-cve-check"],
        ["--perform-scans", "osv", "--perform-scans", "nvd"],
    ],
)
def test_entrypoint_accepts_valid_scan_selections(args):
    result = subprocess.run(
        ["bash", str(ENTRYPOINT), *args, "--help"],
        cwd=ROOT, capture_output=True, text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "--perform-scans <types|all>" in result.stdout


def test_wrapper_lists_scan_selection():
    if not (shutil.which("podman") or shutil.which("docker")):
        pytest.skip("host wrapper requires a container engine executable")

    result = subprocess.run(
        ["bash", str(WRAPPER), "--help"],
        cwd=ROOT, capture_output=True, text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "--perform-scans <types|all>" in result.stdout


@pytest.mark.parametrize(
    ("args", "scanner"),
    [
        (["--perform-scans", "nvd"], "NVD"),
        (["--perform-scans", "osv"], "OSV"),
        (["--perform-scans", "osv,nvd"], "NVD"),
        (["--perform-scans", "osv", "--perform-scans", "nvd"], "NVD"),
        (["--perform-scans", "sbom-cve-check"], "sbom-cve-check"),
        (["--perform-nvd-scan"], "NVD"),
        (["--perform-osv-scan"], "OSV"),
        (["--perform-sbom-cve-check-scan"], "sbom-cve-check"),
    ],
)
def test_entrypoint_dispatches_scan_with_real_flask_cli(tmp_path, args, scanner):
    env = os.environ.copy()
    env["VULNSCOUT_CONFIG"] = str(tmp_path / "absent-config.env")
    env["VULNSCOUT_BASE_DIR"] = str(ROOT)
    env["VULNSCOUT_INPUTS_DIR"] = str(tmp_path / "inputs")
    env["SBOM_CVE_CHECK_DATABASES_DIR"] = str(tmp_path / "local_databases")
    env["FLASK_SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{tmp_path / 'scan.db'}"
    result = subprocess.run(
        ["bash", str(ENTRYPOINT), "--project", "scan-selection-empty", *args],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
    )

    assert result.returncode != 0
    assert f"Running {scanner} scan for project 'scan-selection-empty'" in result.stdout
    assert "No scans found for variant" in result.stderr


@pytest.mark.parametrize("args", [["--perform-scans", "grype"], ["--perform-scans", "all"], ["--perform-grype-scan"]])
def test_entrypoint_dispatches_grype_with_real_flask_cli(tmp_path, args):
    env = os.environ.copy()
    env["VULNSCOUT_CONFIG"] = str(tmp_path / "absent-config.env")
    env["VULNSCOUT_BASE_DIR"] = str(ROOT)
    env["VULNSCOUT_INPUTS_DIR"] = str(tmp_path / "inputs")
    env["FLASK_SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{tmp_path / 'scan.db'}"
    result = subprocess.run(
        ["bash", str(ENTRYPOINT), "--project", "scan-selection-empty", *args],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
    )

    assert "Exporting current project as CycloneDX for Grype scan" in result.stdout