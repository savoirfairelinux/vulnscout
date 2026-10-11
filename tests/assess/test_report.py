import json
from datetime import datetime, timezone

from vulnscout_assess.report import (
    CveResult, build_summary, exit_code_for, format_duration, format_progress, format_table, write_summary,
)

OK = CveResult("CVE-2024-1234", "ok", 252.0, ("x86",), "logs/CVE-2024-1234.jsonl", 0)
SKIP = CveResult("CVE-2024-5678", "skipped", detail="ai assessment exists")
TIMEOUT = CveResult("CVE-2023-0001", "timeout", 900.0, ("x86",), "logs/CVE-2023-0001.jsonl")


def test_format_duration():
    assert format_duration(None) == "-"
    assert format_duration(5) == "0m05s"
    assert format_duration(252.4) == "4m12s"
    assert format_duration(900) == "15m00s"


def test_format_progress_includes_index_outcome_and_detail():
    assert format_progress(3, 12, OK) == "[3/12] CVE-2024-1234 ... ok (4m12s)"
    assert format_progress(1, 2, SKIP) == "[1/2] CVE-2024-5678 ... skipped (-)\n    ai assessment exists"


def test_format_table_aligns_columns():
    table = format_table([OK, SKIP]).splitlines()

    assert table[0].split() == ["CVE", "OUTCOME", "DURATION", "LOG"]
    assert table[1].split() == ["CVE-2024-1234", "ok", "4m12s", "logs/CVE-2024-1234.jsonl"]
    assert table[2].split() == ["CVE-2024-5678", "skipped", "-", "-"]
    assert table[0].index("OUTCOME") == table[1].index("ok")


def test_build_and_write_summary(tmp_path):
    started = datetime(2026, 10, 2, 15, 30, tzinfo=timezone.utc)
    summary = build_summary("Proj", ["x86"], started, [OK, SKIP, TIMEOUT])

    assert summary["project"] == "Proj"
    assert summary["variants"] == ["x86"]
    assert summary["started_at"] == "2026-10-02T15:30:00Z"
    assert summary["counts"] == {"ok": 1, "skipped": 1, "failed": 0, "timeout": 1, "planned": 0}
    assert summary["results"][0] == {
        "cve": "CVE-2024-1234", "outcome": "ok", "duration_s": 252.0, "assessed_variants": ["x86"],
        "log": "logs/CVE-2024-1234.jsonl", "exit_code": 0, "detail": "",
    }
    write_summary(tmp_path / "summary.json", summary)
    assert json.loads((tmp_path / "summary.json").read_text()) == summary


def test_exit_code_for():
    assert exit_code_for([OK, SKIP, CveResult("CVE-1", "planned")]) == 0
    assert exit_code_for([OK, TIMEOUT]) == 1
    assert exit_code_for([CveResult("CVE-1", "failed")]) == 1
    assert exit_code_for([]) == 0
