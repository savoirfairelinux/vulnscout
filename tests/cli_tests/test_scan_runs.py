# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Run real CLI/database/API paths with only external scanner data replaced."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from src.bin.webapp import create_app
from src.routes._scan_diff import invalidate_scan_list_cache


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("legacy,fail_nvd", [(False, False), (True, True)])
def test_entrypoint_batches_form_distinct_api_transaction_blocks(tmp_path, monkeypatch, legacy, fail_nvd):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    flask = fake_bin / "flask"
    flask.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        f"sys.path.insert(0, {str(ROOT)!r})\n"
        "from types import SimpleNamespace\n"
        "from unittest.mock import patch\n"
        "from flask.cli import main\n"
        "engine = SimpleNamespace(applicable_vulns=lambda package: iter(()))\n"
        "def get_engine(*args, **kwargs):\n"
        "    if os.environ.get('TEST_FAIL_NVD') == 'true' and 'nvd-scan' in sys.argv:\n"
        "        raise RuntimeError('test NVD failure')\n"
        "    return engine\n"
        "with patch('src.controllers.scc_engine.get_engine', side_effect=get_engine), \\\n"
        "     patch('src.bin.cmd_vuln_scan.get_engine', side_effect=get_engine), \\\n"
        "     patch('src.bin.cmd_vuln_scan.OSVClient.query_by_purl',\n"
        "           return_value=[{'id': 'CVE-2026-1234'}]):\n"
        "    main()\n"
    )
    flask.chmod(0o755)
    grype = fake_bin / "grype"
    grype.write_text('#!/bin/sh\nprintf \'{"matches": []}\\n\'\n')
    grype.chmod(0o755)
    settings = {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "VULNSCOUT_CONFIG": str(tmp_path / "absent.env"),
        "VULNSCOUT_BASE_DIR": str(ROOT),
        "VULNSCOUT_INPUTS_DIR": str(tmp_path / "inputs"),
        "SBOM_CVE_CHECK_DATABASES_DIR": str(tmp_path / "local_databases"),
        "SBOM_CVE_CHECK_AUTO_UPDATE": "false",
        "FLASK_SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'scans.db'}",
        "FLASK_SCAN_FILE": str(tmp_path / "status.txt"),
        "TEST_FAIL_NVD": str(fail_nvd).lower(),
        "TMPDIR": str(tmp_path),
        "MATCH_CONDITION": "",
    }
    for name, value in settings.items():
        monkeypatch.setenv(name, value)
    (tmp_path / "status.txt").write_text("__END_OF_SCAN_SCRIPT__")

    def invoke(*args):
        return subprocess.run(
            ["bash", str(ROOT / "src" / "entrypoint.sh"), "--project", "cli-runs", *args],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
        )

    seed = invoke("--add-cdx", str(ROOT / "tests" / "end_to_end_tests" / "input_cdx.json"))
    assert seed.returncode == 0, seed.stdout + seed.stderr
    args = (["--perform-grype-scan", "--perform-nvd-scan", "--perform-osv-scan",
             "--perform-sbom-cve-check-scan"] if legacy else ["--perform-scans", "all"])
    for _ in range(2):
        result = invoke(*args)
        assert (result.returncode != 0) is fail_nvd, result.stdout + result.stderr
        assert "Running OSV scan" in result.stdout
        assert "Running sbom-cve-check scan" in result.stdout

    app = create_app()
    app.config["TESTING"] = True
    invalidate_scan_list_cache()
    try:
        response = app.test_client().get("/api/scans")
        assert response.status_code == 200
        scans = response.json
        sbom_scans = [scan for scan in scans if scan["scan_type"] == "sbom"]
        assert len(sbom_scans) == 1
        assert sbom_scans[0]["run_id"] is None
        steps = [scan for scan in scans if scan["scan_type"] == "tool"]
        run_ids = {scan["run_id"] for scan in steps}
        assert None not in run_ids
        assert len(run_ids) == 2
        expected_sources = ["grype", "osv", "scc"] if fail_nvd else ["grype", "nvd", "osv", "scc"]
        for run_id in run_ids:
            members = [scan for scan in steps if scan["run_id"] == run_id]
            assert len(members) == len(expected_sources)
            summary = members[0]["run"]
            assert all(scan["run"] == summary for scan in members)
            assert summary["id"] == run_id
            assert summary["sources"] == expected_sources
            assert set(summary["scan_ids"]) == {scan["id"] for scan in members}
            assert summary["vuln_count"] == 1
    finally:
        invalidate_scan_list_cache()
