import json
import os
import signal
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vulnscout_assess.cli import main
from vulnscout_assess.copilot import RunResult
from vulnscout_assess.preflight import PreflightError
from vulnscout_mcp.client import VulnScoutError

NOW = datetime(2026, 10, 2, 15, 30, tzinfo=timezone.utc)


def preflight_ok(work_dir, *, require_copilot=True, **_):
    return "/usr/bin/copilot" if require_copilot else "copilot"


class Runner:
    def __init__(self, results=None, interrupt_on=None):
        self.calls = []
        self.results = results or {}
        self.interrupt_on = interrupt_on

    def __call__(self, argv, **kwargs):
        cve = Path(kwargs["stdout_path"]).stem
        self.calls.append((cve, argv, kwargs))
        if cve == self.interrupt_on:
            raise KeyboardInterrupt
        return self.results.get(cve, RunResult("ok", 0, 1.0, ""))


@pytest.fixture()
def run_main(client, tmp_path, capsys):
    def _run(*args, runner=None, preflight=preflight_ok):
        runner = runner or Runner()
        argv = ["--dir", str(tmp_path), "--log-dir", str(tmp_path / "logs"), *args]
        code = main(argv, client=client, preflight=preflight, runner=runner, now=NOW)
        return code, runner, capsys.readouterr()
    return _run


def prompt_of(call):
    argv = call[1]
    return argv[argv.index("-p") + 1]


def test_runs_one_session_per_cve_and_exits_zero(run_main, tmp_path):
    code, runner, out = run_main("--cve", "CVE-2026-0001", "--cve", "CVE-2026-0002")

    assert code == 0
    assert [c[0] for c in runner.calls] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert runner.calls[0][1][0] == "/usr/bin/copilot"
    assert runner.calls[0][2]["cwd"] == tmp_path.resolve()
    assert runner.calls[0][2]["timeout_s"] == 900
    assert prompt_of(runner.calls[0]) == "/cve-assessment CVE: CVE-2026-0001, project: default, variants: default"
    assert "[2/2] CVE-2026-0002 ... ok" in out.out


def test_repeated_cve_runs_once(run_main):
    _, runner, _ = run_main("--cve", "CVE-2026-0001", "--cve", "CVE-2026-0001")

    assert [c[0] for c in runner.calls] == ["CVE-2026-0001"]


def test_skips_cve_when_every_variant_has_ai_assessment(run_main, client):
    client.assessments["CVE-2026-0001"] = [{"origin": "ai", "variant_ids": ["v-def"]}]

    code, runner, out = run_main("--cve", "CVE-2026-0001")

    assert code == 0
    assert runner.calls == []
    assert "skipped" in out.out


def test_prompt_lists_only_missing_variants(run_main, client):
    client.assessments["CVE-2026-0001"] = [{"origin": "ai", "variant_ids": ["v-x86"]}]

    _, runner, _ = run_main("--project", "Proj", "--cve", "CVE-2026-0001")

    assert prompt_of(runner.calls[0]).endswith("project: Proj, variants: arm")


def test_force_skips_precheck_and_assesses_all_variants(run_main, client):
    client.assessments["CVE-2026-0001"] = [{"origin": "ai", "variant_ids": ["v-x86", "v-arm"]}]

    _, runner, _ = run_main("--project", "Proj", "--force", "--cve", "CVE-2026-0001")

    assert client.assessment_calls == []
    assert prompt_of(runner.calls[0]).endswith("variants: x86, arm")


def test_failure_does_not_stop_batch_and_exits_one(run_main):
    runner = Runner({"CVE-2026-0001": RunResult("failed", 2, 3.0, "boom")})

    code, runner, out = run_main("--cve", "CVE-2026-0001", "--cve", "CVE-2026-0002", runner=runner)

    assert code == 1
    assert [c[0] for c in runner.calls] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert "failed" in out.out
    assert "    boom" in out.out


def test_api_error_in_precheck_fails_that_cve_and_continues(run_main, client):
    client.errors["CVE-0000-0000"] = VulnScoutError("Vulnerability not found")

    code, runner, out = run_main("--cve", "CVE-0000-0000", "--cve", "CVE-2026-0002")

    assert code == 1
    assert [c[0] for c in runner.calls] == ["CVE-2026-0002"]
    assert "pre-check failed: Vulnerability not found" in out.out


def test_scope_error_exits_one_before_any_session(run_main):
    code, runner, out = run_main("--project", "Nope", "--cve", "CVE-2026-0001")

    assert code == 1
    assert runner.calls == []
    assert "project not found: Nope" in out.err


def test_preflight_error_exits_one(run_main):
    def preflight(work_dir, *, require_copilot=True):
        raise PreflightError("copilot CLI not found on PATH")

    code, runner, out = run_main("--cve", "CVE-2026-0001", preflight=preflight)

    assert code == 1
    assert runner.calls == []
    assert "copilot CLI not found on PATH" in out.err


def test_dry_run_prints_argv_and_spawns_nothing(run_main, tmp_path):
    code, runner, out = run_main("--dry-run", "--cve", "CVE-2026-0001")

    assert code == 0
    assert runner.calls == []
    assert "copilot -p '/cve-assessment CVE: CVE-2026-0001" in out.out
    assert "planned" in out.out
    assert not (tmp_path / "logs").exists()


def test_json_writes_summary(run_main, tmp_path):
    run_main("--json", "--cve", "CVE-2026-0001")

    summary = json.loads((tmp_path / "logs" / "summary.json").read_text())
    assert summary["counts"]["ok"] == 1
    assert summary["results"][0]["log"] == str(tmp_path / "logs" / "CVE-2026-0001.jsonl")


def test_extra_tools_and_model_are_forwarded(run_main):
    _, runner, _ = run_main("--allow-tool", "url(example.org)", "--model", "gpt-5", "--cve", "CVE-2026-0001")

    argv = runner.calls[0][1]
    assert "--allow-tool=url(example.org)" in argv
    assert argv[argv.index("--model") + 1] == "gpt-5"


def test_keyboard_interrupt_writes_partial_summary_and_returns_130(run_main, tmp_path):
    runner = Runner(interrupt_on="CVE-2026-0002")

    code, _, _ = run_main("--json", "--cve", "CVE-2026-0001", "--cve", "CVE-2026-0002", runner=runner)

    assert code == 130
    summary = json.loads((tmp_path / "logs" / "summary.json").read_text())
    assert [(r["cve"], r["outcome"]) for r in summary["results"]] == [
        ("CVE-2026-0001", "ok"), ("CVE-2026-0002", "failed")]
    assert summary["results"][1]["detail"] == "interrupted"


@pytest.mark.parametrize("bad_id", ["../../etc/x", "CVE-1/2", "", "-rf", "CVE 1"])
def test_path_like_or_malformed_cve_id_is_usage_error(client, tmp_path, bad_id):
    with pytest.raises(SystemExit) as exc_info:
        main(["--dir", str(tmp_path), "--cve", bad_id], client=client, preflight=preflight_ok, runner=Runner())

    assert exc_info.value.code == 1


def test_missing_dir_is_usage_error(client):
    with pytest.raises(SystemExit) as exc_info:
        main(["--cve", "CVE-2026-0001"], client=client, preflight=preflight_ok, runner=Runner())

    assert exc_info.value.code == 1


def test_oserror_starting_session_fails_that_cve_and_continues(run_main):
    class FailingRunner(Runner):
        def __call__(self, argv, **kwargs):
            if Path(kwargs["stdout_path"]).stem == "CVE-2026-0001":
                self.calls.append(("CVE-2026-0001", argv, kwargs))
                raise OSError("No such file or directory")
            return super().__call__(argv, **kwargs)

    runner = FailingRunner()

    code, runner, out = run_main("--cve", "CVE-2026-0001", "--cve", "CVE-2026-0002", runner=runner)

    assert code == 1
    assert [c[0] for c in runner.calls] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert "could not run copilot" in out.out


def test_valueerror_in_precheck_fails_that_cve_and_continues(run_main, client):
    client.errors["CVE-0000-0000"] = ValueError("Expecting value")

    code, runner, out = run_main("--cve", "CVE-0000-0000", "--cve", "CVE-2026-0002")

    assert code == 1
    assert [c[0] for c in runner.calls] == ["CVE-2026-0002"]
    assert "pre-check failed: Expecting value" in out.out


def test_variant_absent_for_cve_is_excluded_from_prompt(run_main, client):
    client.vuln_variants["CVE-2026-0001"] = [{"id": "v-x86", "name": "x86"}]

    _, runner, _ = run_main("--project", "Proj", "--cve", "CVE-2026-0001")

    assert prompt_of(runner.calls[0]).endswith("project: Proj, variants: x86")


def test_cve_absent_from_every_in_scope_variant_fails_without_session(run_main, client):
    client.vuln_variants["CVE-2026-0001"] = [{"id": "v-other", "name": "other"}]

    code, runner, out = run_main("--cve", "CVE-2026-0001")

    assert code == 1
    assert runner.calls == []
    assert client.assessment_calls == []
    assert "CVE not found in scope" in out.out


def test_unknown_cve_with_empty_variant_list_fails_even_with_force(run_main, client):
    client.vuln_variants["CVE-0000-0000"] = []

    code, runner, out = run_main("--force", "--cve", "CVE-0000-0000")

    assert code == 1
    assert runner.calls == []
    assert "CVE not found in scope" in out.out


def test_force_still_intersects_variants(run_main, client):
    client.vuln_variants["CVE-2026-0001"] = [{"id": "v-arm", "name": "arm"}]

    _, runner, _ = run_main("--project", "Proj", "--force", "--cve", "CVE-2026-0001")

    assert prompt_of(runner.calls[0]).endswith("variants: arm")


def test_cve_with_ai_assessments_on_every_present_variant_is_skipped(run_main, client):
    client.vuln_variants["CVE-2026-0001"] = [{"id": "v-x86", "name": "x86"}]
    client.assessments["CVE-2026-0001"] = [{"origin": "ai", "variant_ids": ["v-x86"]}]

    code, runner, out = run_main("--project", "Proj", "--cve", "CVE-2026-0001")

    assert code == 0
    assert runner.calls == []
    assert "skipped" in out.out


def test_api_error_listing_variants_fails_that_cve(run_main, client):
    def boom(vuln_id):
        raise VulnScoutError("variants unavailable")

    client.list_variants_by_vuln = boom

    code, runner, out = run_main("--cve", "CVE-2026-0001")

    assert code == 1
    assert runner.calls == []
    assert "pre-check failed: variants unavailable" in out.out


def test_sigterm_is_handled_like_interrupt_and_handler_restored(run_main, tmp_path):
    previous = signal.getsignal(signal.SIGTERM)

    class TermRunner(Runner):
        def __call__(self, argv, **kwargs):
            if Path(kwargs["stdout_path"]).stem == "CVE-2026-0002":
                os.kill(os.getpid(), signal.SIGTERM)
            return super().__call__(argv, **kwargs)

    code, _, out = run_main("--json", "--cve", "CVE-2026-0001", "--cve", "CVE-2026-0002", runner=TermRunner())

    assert code == 130
    assert "Interrupted; writing partial summary." in out.err
    summary = json.loads((tmp_path / "logs" / "summary.json").read_text())
    assert [r["cve"] for r in summary["results"]] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert signal.getsignal(signal.SIGTERM) is previous


def test_sigterm_install_failure_off_main_thread_is_ignored(run_main, monkeypatch):
    def refuse(signum, handler):
        raise ValueError("signal only works in main thread")

    monkeypatch.setattr("vulnscout_assess.cli.signal.signal", refuse)

    code, runner, _ = run_main("--cve", "CVE-2026-0001")

    assert code == 0
    assert len(runner.calls) == 1


def test_oserror_in_preflight_exits_one_with_message(run_main):
    def preflight(work_dir, *, require_copilot=True):
        raise OSError("permission denied")

    code, runner, out = run_main("--cve", "CVE-2026-0001", preflight=preflight)

    assert code == 1
    assert runner.calls == []
    assert "Error: permission denied" in out.err


def test_valueerror_during_scope_exits_one_with_message(run_main, client):
    def bad_projects():
        raise ValueError("Expecting value")

    client.list_projects = bad_projects

    code, _, out = run_main("--cve", "CVE-2026-0001")

    assert code == 1
    assert "Error: Expecting value" in out.err


def test_unusable_log_dir_exits_one_with_message(client, tmp_path, capsys):
    blocker = tmp_path / "file"
    blocker.write_text("x")

    code = main(["--dir", str(tmp_path), "--log-dir", str(blocker / "logs"), "--cve", "CVE-2026-0001"],
                client=client, preflight=preflight_ok, runner=Runner(), now=NOW)

    assert code == 1
    assert capsys.readouterr().err.startswith("Error: ")


def test_keyboard_interrupt_during_setup_exits_130(run_main):
    def preflight(work_dir, *, require_copilot=True):
        raise KeyboardInterrupt

    code, runner, out = run_main("--cve", "CVE-2026-0001", preflight=preflight)

    assert code == 130
    assert runner.calls == []
    assert "Interrupted." in out.err
