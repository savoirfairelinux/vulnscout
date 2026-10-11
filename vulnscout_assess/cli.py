"""Entry point for `vulnscout cve-assessment`: one headless Copilot session per CVE."""

import argparse
import os
import re
import shlex
import signal
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from vulnscout_mcp.client import VulnScoutClient, VulnScoutError

from .copilot import build_argv, build_prompt, run_copilot
from .precheck import missing_variants, variants_with_vuln
from .preflight import PreflightError, check_preflight
from .report import CveResult, build_summary, exit_code_for, format_progress, format_table, write_summary
from .scope import Scope, ScopeError, resolve_scope

DEFAULT_BASE_URL = "http://localhost:7275"
DEFAULT_TIMEOUT_S = 900
DEFAULT_LOG_ROOT = Path("cve-assessment-logs")
EXIT_INTERRUPTED = 130
# IDs become log file names: no path separators, no leading dash, no whitespace.
_VULN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # usage errors exit 1, not argparse's default 2
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def _vuln_id(value: str) -> str:
    if not _VULN_ID_RE.match(value):
        raise argparse.ArgumentTypeError(f"invalid vulnerability ID: {value!r}")
    return value


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    p = _Parser(prog="vulnscout cve-assessment",
                description="Run the cve-assessment skill in one headless Copilot CLI session per CVE.")
    p.add_argument("--cve", dest="cves", action="append", required=True, type=_vuln_id)
    p.add_argument("--project")
    p.add_argument("--variant")
    p.add_argument("--dir", dest="work_dir", required=True, type=Path)
    p.add_argument("--timeout", type=_positive_int, default=DEFAULT_TIMEOUT_S)
    p.add_argument("--log-dir", type=Path)
    p.add_argument("--model")
    p.add_argument("--allow-tool", dest="allow_tools", action="append", default=[])
    p.add_argument("--force", action="store_true")
    p.add_argument("--json", dest="write_json", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)
    args.cves = list(dict.fromkeys(args.cves))
    return args


@dataclass(frozen=True)
class Session:
    args: argparse.Namespace
    scope: Scope
    client: Any
    copilot_bin: str
    work_dir: Path
    log_dir: Path
    runner: Any
    out: Any

    def assess(self, cve: str) -> CveResult:
        try:
            present = variants_with_vuln(self.client, cve, self.scope.variants)
            if not present:
                return CveResult(cve, "failed", detail="CVE not found in scope")
            targets = present if self.args.force else missing_variants(self.client, cve, present)
        except (VulnScoutError, ValueError) as exc:
            return CveResult(cve, "failed", detail=f"pre-check failed: {exc}")
        if not targets:
            return CveResult(cve, "skipped", detail="ai assessment exists")
        names = tuple(v.name for v in targets)
        argv = build_argv(
            build_prompt(cve, self.scope.project, names),
            work_dir=self.work_dir, log_dir=self.log_dir / cve / "copilot",
            extra_allowed=self.args.allow_tools, model=self.args.model, copilot_bin=self.copilot_bin,
        )
        if self.args.dry_run:
            print(shlex.join(argv), file=self.out)
            return CveResult(cve, "planned", assessed_variants=names)
        stdout_path = self.log_dir / f"{cve}.jsonl"
        try:
            run = self.runner(argv, cwd=self.work_dir, stdout_path=stdout_path,
                              stderr_path=self.log_dir / f"{cve}.stderr.log", timeout_s=self.args.timeout)
        except OSError as exc:
            return CveResult(cve, "failed", assessed_variants=names, detail=f"could not run copilot: {exc}")
        return CveResult(cve, run.outcome, run.duration_s, names, str(stdout_path),
                         run.exit_code, run.stderr_tail)


def _setup(args, client, preflight, work_dir):
    copilot_bin = preflight(work_dir, require_copilot=not args.dry_run)
    client = client or VulnScoutClient(os.environ.get("VULNSCOUT_BASE_URL", DEFAULT_BASE_URL))
    return copilot_bin, client, resolve_scope(client, args.project, args.variant)


def _raise_interrupt(signum, frame):
    raise KeyboardInterrupt


def _install_sigterm():
    """Route SIGTERM through the Ctrl-C path; return a restore callable (no-op if unavailable)."""
    try:
        previous = signal.signal(signal.SIGTERM, _raise_interrupt)
    except ValueError:  # not the main thread
        return lambda: None
    return lambda: signal.signal(signal.SIGTERM, previous)


def main(argv=None, *, client=None, preflight=check_preflight, runner=run_copilot,
         now: datetime | None = None, out=None) -> int:
    out = out or sys.stdout
    args = parse_args(argv)
    started_at = now or datetime.now(timezone.utc)
    work_dir = args.work_dir.resolve()
    log_dir = (args.log_dir or DEFAULT_LOG_ROOT / started_at.strftime("%Y%m%dT%H%M%SZ")).resolve()
    try:
        copilot_bin, client, scope = _setup(args, client, preflight, work_dir)
        if not args.dry_run:
            log_dir.mkdir(parents=True, exist_ok=True)
    except (PreflightError, ScopeError, VulnScoutError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return EXIT_INTERRUPTED
    session = Session(args, scope, client, copilot_bin, work_dir, log_dir, runner, out)
    results: list[CveResult] = []
    restore_sigterm = _install_sigterm()
    try:
        for index, cve in enumerate(args.cves, start=1):
            results.append(session.assess(cve))
            print(format_progress(index, len(args.cves), results[-1]), file=out, flush=True)
    except KeyboardInterrupt:
        print("Interrupted; writing partial summary.", file=sys.stderr)
        if len(results) < len(args.cves):
            results.append(CveResult(args.cves[len(results)], "failed", detail="interrupted"))
        _finish(session, started_at, results)
        return EXIT_INTERRUPTED
    finally:
        restore_sigterm()
    return _finish(session, started_at, results)


def _finish(session: Session, started_at: datetime, results: list[CveResult]) -> int:
    print(format_table(results), file=session.out)
    if session.args.write_json and not session.args.dry_run:
        summary = build_summary(session.scope.project, [v.name for v in session.scope.variants],
                                started_at, results)
        write_summary(session.log_dir / "summary.json", summary)
    return exit_code_for(results)
