"""CLI coverage for typed scanner selection at the host and container boundaries."""

from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import threading

import pytest


ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = ROOT / "src" / "entrypoint.sh"
WRAPPER = ROOT / "vulnscout"


@pytest.fixture
def scanner_environment(tmp_path):
    """Run the real scanner CLI against isolated, deterministic advisory inputs."""
    databases = tmp_path / "local_databases"
    for name in ("nvd-fkie", "cvelist"):
        repository = databases / f"{name}-source"
        repository.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(repository)], check=True)
        if name == "nvd-fkie":
            advisory = repository / "CVE-2026" / "CVE-2026-00xx" / "CVE-2026-0001.json"
            advisory.parent.mkdir(parents=True)
            advisory.write_text(json.dumps({
                "id": "CVE-2026-0001",
                "sourceIdentifier": "test@example.org",
                "published": "2026-01-01T00:00:00.000",
                "lastModified": "2026-01-01T00:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Local scanner test advisory"}],
                "configurations": [{"nodes": [{
                    "operator": "OR",
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "7.0.0",
                        "versionEndExcluding": "8.0.0",
                    }],
                }]}],
            }))
        subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(repository), "-c", "user.name=Test", "-c",
             "user.email=test@example.org", "commit", "-qm", "Test advisories", "--allow-empty"],
            check=True,
        )
        subprocess.run(
            ["git", "clone", "-q", str(repository), str(databases / name)],
            check=True,
        )

    queries = []

    class OSVHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/v1/query":
                self.send_error(404)
                return
            queries.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            body = json.dumps({"vulns": [{
                "id": "CVE-2026-0002", "summary": "Local OSV test advisory",
            }]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    binaries = tmp_path / "bin"
    binaries.mkdir()
    flask = binaries / "flask"
    flask.write_text(
        f"#!{sys.executable}\n"
        "import os\n"
        "from src.controllers import osv_client\n"
        "from flask.cli import main\n"
        "osv_client.OSV_API_BASE = os.environ['TEST_OSV_API_BASE']\n"
        "main()\n"
    )
    flask.chmod(0o755)
    grype = binaries / "grype"
    grype.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "sbom = next(Path(arg[5:]) for arg in sys.argv[1:] if arg.startswith('sbom:'))\n"
        "assert json.loads(sbom.read_text())['components']\n"
        "Path(os.environ['TEST_GRYPE_LOG']).write_text(json.dumps(sys.argv[1:]))\n"
        "print(json.dumps({'matches': []}))\n"
    )
    grype.chmod(0o755)

    server = ThreadingHTTPServer(("127.0.0.1", 0), OSVHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield {
            **os.environ,
            "PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}",
            "PYTHONPATH": f"{ROOT}{os.pathsep}{os.environ.get('PYTHONPATH', '')}",
            "SBOM_CVE_CHECK_DATABASES_DIR": str(databases),
            "SBOM_CVE_CHECK_AUTO_UPDATE": "false",
            "TEST_OSV_API_BASE": f"http://127.0.0.1:{server.server_port}/v1",
            "TEST_GRYPE_LOG": str(tmp_path / "grype.json"),
        }, queries
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


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
    assert "Run vulnerability scans" in result.stdout


@pytest.mark.parametrize(
    ("failed_step", "status", "expected_steps"),
    [
        ("db", 7, ["db"]),
        ("merge", 8, ["db", "merge"]),
        ("process", 9, ["db", "merge", "process"]),
        ("process", 2, ["db", "merge", "process", "db", "report", "db", "export"]),
    ],
)
def test_entrypoint_stops_after_scan_failure_and_retains_inputs(tmp_path, failed_step, status, expected_steps):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    flask = fake_bin / "flask"
    flask.write_text(
        '#!/bin/bash\n'
        'printf "%s\\n" "$3" >> "$TEST_FLASK_LOG"\n'
        'if [[ "$3" == "$TEST_FAILED_STEP" ]]; then exit "$TEST_FAILED_STATUS"; fi\n'
    )
    flask.chmod(0o755)
    inputs = tmp_path / "inputs" / "spdx"
    inputs.mkdir(parents=True)
    sbom = inputs / "test.spdx.json"
    sbom.write_text("{}")
    log = tmp_path / "flask.log"
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "VULNSCOUT_CONFIG": str(tmp_path / "absent.env"),
        "VULNSCOUT_BASE_DIR": str(tmp_path),
        "VULNSCOUT_INPUTS_DIR": str(inputs.parent),
        "TEST_FLASK_LOG": str(log),
        "TEST_FAILED_STEP": failed_step,
        "TEST_FAILED_STATUS": str(status),
    }
    result = subprocess.run(
        ["bash", str(ENTRYPOINT), "--match-condition", "affected",
         "--report", "summary.adoc", "--export-spdx"],
        env=env, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == status, result.stderr
    assert log.read_text().splitlines() == expected_steps
    assert sbom.exists() is (status != 2)
    assert "Initialization Done" not in result.stdout


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


@pytest.mark.parametrize(
    "args",
    [
        ["--perform-scans", "osv"],
        ["--perform-scans", "osv,nvd"],
        ["--perform-scans", "osv", "--perform-scans", "nvd"],
        ["--perform-scans", "all"],
    ],
)
def test_entrypoint_runs_selected_scanners_on_active_sbom(tmp_path, args, scanner_environment):
    env, osv_queries = scanner_environment
    env["VULNSCOUT_CONFIG"] = str(tmp_path / "absent-config.env")
    env["VULNSCOUT_BASE_DIR"] = str(ROOT)
    env["VULNSCOUT_INPUTS_DIR"] = str(tmp_path / "inputs")
    env["FLASK_SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{tmp_path / 'scan.db'}"
    seed = subprocess.run(
        ["bash", str(ENTRYPOINT), "--project", "scan-selection", "--add-cdx",
         str(ROOT / "tests" / "end_to_end_tests" / "input_cdx.json")],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
    )
    assert seed.returncode == 0, seed.stderr

    result = subprocess.run(
        ["bash", str(ENTRYPOINT), "--project", "scan-selection", *args],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
    )

    assert result.returncode == 0, result.stderr
    assert {"package": {"purl": "pkg:generic/haxx/curl@7.82.0"}} in osv_queries
    with closing(sqlite3.connect(tmp_path / "scan.db")) as connection:
        vulnerabilities = {row[0] for row in connection.execute("SELECT id FROM vulnerabilities")}
    assert "CVE-2026-0002" in vulnerabilities
    if any("nvd" in arg or arg == "all" for arg in args):
        assert "CVE-2026-0001" in vulnerabilities
        assert result.stdout.index("Running NVD scan") < result.stdout.index("Running OSV scan")
        assert result.stdout.count("Scan complete") >= 2
    else:
        assert "Running OSV scan" in result.stdout
        assert "Scan complete" in result.stdout
    if "all" in args:
        grype_args = json.loads(Path(env["TEST_GRYPE_LOG"]).read_text())
        assert "--add-cpes-if-none" in grype_args
        assert result.stdout.index("Merging Grype results") < result.stdout.index("Running NVD scan")
        assert result.stdout.index("Running OSV scan") < result.stdout.index("Running sbom-cve-check scan")


def test_failed_nvd_scan_still_runs_osv_and_processes_inputs(tmp_path):
    env = os.environ.copy()
    env["VULNSCOUT_CONFIG"] = str(tmp_path / "absent-config.env")
    env["VULNSCOUT_BASE_DIR"] = str(ROOT)
    env["VULNSCOUT_INPUTS_DIR"] = str(tmp_path / "inputs")
    env["SBOM_CVE_CHECK_DATABASES_DIR"] = str(tmp_path / "local_databases")
    env["SBOM_CVE_CHECK_AUTO_UPDATE"] = "false"
    env["FLASK_SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{tmp_path / 'scan.db'}"

    result = subprocess.run(
        ["bash", str(ENTRYPOINT), "--project", "scan-selection", "--add-cdx",
         str(ROOT / "tests" / "end_to_end_tests" / "input_cdx.json"),
         "--perform-scans", "nvd,osv,sbom-cve-check"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
    )

    assert result.returncode != 0
    assert result.stdout.index("Running NVD scan") < result.stdout.index("Running OSV scan")
    assert result.stdout.index("Running OSV scan") < result.stdout.index("Running sbom-cve-check scan")
    assert not list((tmp_path / "inputs" / "cdx").glob("*.json"))
    scans = subprocess.run(
        ["bash", str(ENTRYPOINT), "--list-scans"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
    )
    assert scans.returncode == 0, scans.stderr
    assert "project scan-selection" in scans.stdout
    assert "1 SBOMs" in scans.stdout


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


def test_grype_failure_does_not_stage_partial_results(tmp_path):
    env = os.environ.copy()
    env["VULNSCOUT_CONFIG"] = str(tmp_path / "absent-config.env")
    env["VULNSCOUT_BASE_DIR"] = str(ROOT)
    env["VULNSCOUT_INPUTS_DIR"] = str(tmp_path / "inputs")
    env["FLASK_SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{tmp_path / 'scan.db'}"
    seed = subprocess.run(
        ["bash", str(ENTRYPOINT), "--project", "scan-selection", "--add-cdx",
         str(ROOT / "tests" / "end_to_end_tests" / "input_cdx.json")],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
    )
    assert seed.returncode == 0, seed.stderr

    result = subprocess.run(
        ["bash", str(ENTRYPOINT), "--project", "scan-selection", "--perform-scans", "grype"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
    )

    assert "Grype scan:" in result.stdout, result.stderr
    if not shutil.which("grype"):
        assert result.returncode != 0
    assert not (tmp_path / "inputs" / "grype" / "grype_from_db.grype.json").exists()


@pytest.mark.parametrize("scan_types", ["all", "grype", "nvd,osv,sbom-cve-check"])
def test_new_inputs_are_processed_before_scanners(tmp_path, scan_types):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    flask = fake_bin / "flask"
    flask.write_text(
        '#!/bin/bash\n'
        'step="$3"\n'
        'printf "%s\\n" "$step" >> "$TEST_FLASK_LOG"\n'
        'case "$step" in\n'
        '  merge) touch "$TEST_PENDING";;\n'
        '  process)\n'
        '    if [[ -f "$TEST_PENDING" && -n "$MATCH_CONDITION" ]]; then exit 20; fi\n'
        '    rm -f "$TEST_PENDING";;\n'
        '  export)\n'
        '    [[ ! -f "$TEST_PENDING" ]] || exit 17\n'
        '    [[ " $* " == *" --project demo --variant native "* ]] || exit 18\n'
        '    while [[ $# -gt 0 ]]; do\n'
        '      if [[ "$1" == "--output-dir" ]]; then\n'
        '        printf "{}" > "$2/sbom_cyclonedx_v1_6.cdx.json"; break\n'
        '      fi\n'
        '      shift\n'
        '    done;;\n'
        '  *-scan) [[ ! -f "$TEST_PENDING" ]] || exit 19;;\n'
        'esac\n'
    )
    flask.chmod(0o755)
    grype = fake_bin / "grype"
    grype.write_text('#!/bin/bash\nprintf \'{"matches": []}\\n\'\n')
    grype.chmod(0o755)
    inputs = tmp_path / "inputs" / "spdx"
    inputs.mkdir(parents=True)
    sbom = inputs / "test.spdx.json"
    sbom.write_text("{}")
    log = tmp_path / "flask.log"
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "VULNSCOUT_CONFIG": str(tmp_path / "absent.env"),
        "VULNSCOUT_BASE_DIR": str(tmp_path),
        "VULNSCOUT_INPUTS_DIR": str(inputs.parent),
        "SBOM_CVE_CHECK_DATABASES_DIR": str(tmp_path / "local_databases"),
        "TEST_FLASK_LOG": str(log),
        "TEST_PENDING": str(tmp_path / "pending"),
    }
    result = subprocess.run(
        ["bash", str(ENTRYPOINT), "--project", "demo", "--variant", "native",
         "--perform-scans", scan_types, "--match-condition", "affected"],
        env=env, capture_output=True, text=True, timeout=10,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    expected = ["db", "merge", "process"]
    if scan_types in ("all", "grype"):
        expected.extend(["export", "merge", "process"])
    if scan_types != "grype":
        expected.extend(["nvd-scan", "osv-scan", "sbom-cve-check-scan"])
    expected.append("process")
    assert log.read_text().splitlines() == expected
    assert not sbom.exists()


def test_initial_processing_failure_prevents_scanning(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    flask = fake_bin / "flask"
    flask.write_text(
        '#!/bin/bash\n'
        'printf "%s\\n" "$3" >> "$TEST_FLASK_LOG"\n'
        'if [[ "$3" == "process" ]]; then exit 9; fi\n'
    )
    flask.chmod(0o755)
    inputs = tmp_path / "inputs" / "spdx"
    inputs.mkdir(parents=True)
    sbom = inputs / "test.spdx.json"
    sbom.write_text("{}")
    log = tmp_path / "flask.log"
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "VULNSCOUT_CONFIG": str(tmp_path / "absent.env"),
        "VULNSCOUT_BASE_DIR": str(tmp_path),
        "VULNSCOUT_INPUTS_DIR": str(inputs.parent),
        "SBOM_CVE_CHECK_DATABASES_DIR": str(tmp_path / "local_databases"),
        "TEST_FLASK_LOG": str(log),
    }
    result = subprocess.run(
        ["bash", str(ENTRYPOINT), "--perform-scans", "all"],
        env=env, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 9, result.stdout + result.stderr
    assert log.read_text().splitlines() == ["db", "merge", "process"]
    assert sbom.exists()
