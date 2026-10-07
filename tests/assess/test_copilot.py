import signal
import subprocess
from pathlib import Path

import pytest

from vulnscout_assess.copilot import (
    DEFAULT_ALLOWED_TOOLS, DENIED_TOOLS, KILL_GRACE_S, RunResult, build_argv, build_prompt, run_copilot,
)


def allowed_tools(argv):
    return [arg.split("=", 1)[1] for arg in argv if arg.startswith("--allow-tool=")]


def denied_tools(argv):
    return [arg.split("=", 1)[1] for arg in argv if arg.startswith("--deny-tool=")]


def test_build_prompt_injects_skill_and_context():
    prompt = build_prompt("CVE-2026-0001", "Proj", ["x86", "arm"])

    assert prompt == "/cve-assessment CVE: CVE-2026-0001, project: Proj, variants: x86, arm"


def test_build_argv_has_headless_flags_allowlist_and_write_denial():
    argv = build_argv("P", work_dir=Path("/src"), log_dir=Path("/logs/CVE-1/copilot"))

    assert argv[:8] == ["copilot", "-p", "P", "-s", "--output-format", "json", "--add-dir", "/src"]
    assert allowed_tools(argv) == list(DEFAULT_ALLOWED_TOOLS)
    assert denied_tools(argv) == list(DENIED_TOOLS)
    assert "write" in denied_tools(argv)
    assert "--allow-tool" not in argv and "--deny-tool" not in argv
    assert "--no-ask-user" in argv
    assert argv[-2:] == ["--log-dir", "/logs/CVE-1/copilot"]
    assert "--allow-all-tools" not in argv
    assert "--model" not in argv


def test_build_argv_appends_user_tools_model_and_binary():
    argv = build_argv(
        "P", work_dir=Path("/src"), log_dir=Path("/l"),
        extra_allowed=["url(example.org)"], model="gpt-5", copilot_bin="/opt/copilot",
    )

    assert allowed_tools(argv)[-1] == "url(example.org)"
    assert argv[0] == "/opt/copilot"
    assert argv[argv.index("--model") + 1] == "gpt-5"


@pytest.mark.parametrize("subcommand", [
    "push", "commit", "checkout", "switch", "restore", "reset", "clean", "stash",
    "rm", "add", "merge", "rebase", "apply", "config", "remote",
])
def test_destructive_git_subcommands_are_denied(subcommand):
    argv = build_argv("P", work_dir=Path("/src"), log_dir=Path("/l"))

    assert f"shell(git {subcommand})" in denied_tools(argv)


class FakeProc:
    pid = 4242

    def __init__(self, waits):
        self.waits = list(waits)
        self.wait_timeouts = []

    def wait(self, timeout=None):
        self.wait_timeouts.append(timeout)
        result = self.waits.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


def make_popen(proc, stderr_text=b""):
    calls = []

    def popen(argv, **kwargs):
        calls.append((argv, kwargs))
        kwargs["stderr"].write(stderr_text)
        return proc

    return popen, calls


def ticking_clock(step=5.0):
    state = {"t": 0.0}

    def clock():
        state["t"] += step
        return state["t"]

    return clock


def run(tmp_path, **kwargs):
    return run_copilot(
        ["copilot"], cwd=tmp_path, stdout_path=tmp_path / "o.jsonl",
        stderr_path=tmp_path / "e.log", timeout_s=900, clock=ticking_clock(), **kwargs,
    )


def test_exit_zero_is_ok_and_runs_in_new_session(tmp_path):
    popen, calls = make_popen(FakeProc([0]))

    result = run(tmp_path, popen=popen)

    assert result == RunResult("ok", 0, 5.0, "")
    kwargs = calls[0][1]
    assert kwargs["cwd"] == tmp_path
    assert kwargs["start_new_session"] is True
    assert kwargs["stdin"] is subprocess.DEVNULL


def test_nonzero_exit_is_failed_with_stderr_tail(tmp_path):
    lines = b"".join(f"line {i}\n".encode() for i in range(30))
    popen, _ = make_popen(FakeProc([3]), stderr_text=lines)

    result = run(tmp_path, popen=popen)

    assert result.outcome == "failed"
    assert result.exit_code == 3
    assert result.stderr_tail.splitlines() == [f"line {i}" for i in range(10, 30)]


def test_timeout_sends_sigterm_to_process_group(tmp_path):
    proc = FakeProc([subprocess.TimeoutExpired("copilot", 900), -15])
    popen, _ = make_popen(proc)
    kills = []

    result = run(tmp_path, popen=popen, killpg=lambda pid, sig: kills.append((pid, sig)))

    assert result.outcome == "timeout"
    assert result.exit_code is None
    assert kills == [(4242, signal.SIGTERM)]
    assert proc.wait_timeouts == [900, KILL_GRACE_S]


def test_timeout_escalates_to_sigkill_when_sigterm_ignored(tmp_path):
    proc = FakeProc([
        subprocess.TimeoutExpired("copilot", 900),
        subprocess.TimeoutExpired("copilot", KILL_GRACE_S),
        -9,
    ])
    popen, _ = make_popen(proc)
    kills = []

    result = run(tmp_path, popen=popen, killpg=lambda pid, sig: kills.append((pid, sig)))

    assert result.outcome == "timeout"
    assert kills == [(4242, signal.SIGTERM), (4242, signal.SIGKILL)]


def test_timeout_tolerates_already_exited_group(tmp_path):
    popen, _ = make_popen(FakeProc([subprocess.TimeoutExpired("copilot", 900)]))

    def killpg(pid, sig):
        raise ProcessLookupError

    assert run(tmp_path, popen=popen, killpg=killpg).outcome == "timeout"


def test_keyboard_interrupt_kills_group_and_reraises(tmp_path):
    popen, _ = make_popen(FakeProc([KeyboardInterrupt(), 0]))
    kills = []

    with pytest.raises(KeyboardInterrupt):
        run(tmp_path, popen=popen, killpg=lambda pid, sig: kills.append(sig))

    assert kills == [signal.SIGTERM]
