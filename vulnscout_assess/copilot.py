"""Build and run one headless GitHub Copilot CLI session per CVE."""

import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

SKILL_NAME = "cve-assessment"
DEFAULT_ALLOWED_TOOLS = (
    "vulnscout",
    "shell(git:*)", "shell(grep)", "shell(find)", "shell(ls)", "shell(cat)", "shell(head)",
    "url(nvd.nist.gov)", "url(github.com)", "url(api.github.com)",
)
# Denies beat allows, so these hold even though shell(git:*) is allowed above.
DENIED_TOOLS = (
    "write",
    *(f"shell(git {sub})" for sub in (
        "push", "commit", "checkout", "switch", "restore", "reset", "clean", "stash",
        "rm", "add", "merge", "rebase", "apply", "config", "remote",
    )),
)
KILL_GRACE_S = 10
STDERR_TAIL_LINES = 20


@dataclass(frozen=True)
class RunResult:
    outcome: str  # "ok" | "failed" | "timeout"
    exit_code: int | None
    duration_s: float
    stderr_tail: str


def build_prompt(cve_id: str, project: str, variant_names: Sequence[str]) -> str:
    return f"/{SKILL_NAME} CVE: {cve_id}, project: {project}, variants: {', '.join(variant_names)}"


def build_argv(
    prompt: str,
    *,
    work_dir: Path,
    log_dir: Path,
    extra_allowed: Sequence[str] = (),
    model: str | None = None,
    copilot_bin: str = "copilot",
) -> list[str]:
    argv = [copilot_bin, "-p", prompt, "-s", "--output-format", "json", "--add-dir", str(work_dir),
            "--no-ask-user"]
    # Single "--flag=value" elements: both flags are variadic and would swallow later arguments.
    argv += [f"--allow-tool={tool}" for tool in (*DEFAULT_ALLOWED_TOOLS, *extra_allowed)]
    argv += [f"--deny-tool={tool}" for tool in DENIED_TOOLS]
    if model:
        argv += ["--model", model]
    return argv + ["--log-dir", str(log_dir)]


def run_copilot(
    argv: list[str],
    *,
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout_s: float,
    popen=subprocess.Popen,
    killpg=os.killpg,
    clock=time.monotonic,
) -> RunResult:
    """Run Copilot in its own process group; kill the whole group on timeout or Ctrl-C."""
    start = clock()
    with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
        proc = popen(argv, cwd=cwd, stdout=out, stderr=err,
                     stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            exit_code = proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            _terminate(proc, killpg)
            return RunResult("timeout", None, clock() - start, _tail(stderr_path))
        except KeyboardInterrupt:
            _terminate(proc, killpg)
            raise
    if exit_code == 0:
        return RunResult("ok", 0, clock() - start, "")
    return RunResult("failed", exit_code, clock() - start, _tail(stderr_path))


def _terminate(proc, killpg) -> None:
    for sig, grace in ((signal.SIGTERM, KILL_GRACE_S), (signal.SIGKILL, None)):
        try:
            killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=grace)
            return
        except subprocess.TimeoutExpired:
            continue


def _tail(path: Path) -> str:
    lines = path.read_text(errors="replace").splitlines()
    return "\n".join(lines[-STDERR_TAIL_LINES:])
