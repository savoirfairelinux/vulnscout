"""Per-CVE results, progress lines, the final table and summary.json."""

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Sequence

OUTCOMES = ("ok", "skipped", "failed", "timeout", "planned")
SUCCESS_OUTCOMES = ("ok", "skipped", "planned")


@dataclass(frozen=True)
class CveResult:
    cve: str
    outcome: str
    duration_s: float | None = None
    assessed_variants: tuple[str, ...] = ()
    log: str | None = None
    exit_code: int | None = None
    detail: str = ""


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes}m{secs:02d}s"


def format_progress(index: int, total: int, result: CveResult) -> str:
    line = f"[{index}/{total}] {result.cve} ... {result.outcome} ({format_duration(result.duration_s)})"
    if not result.detail:
        return line
    indented = "\n".join(f"    {d}" for d in result.detail.splitlines())
    return f"{line}\n{indented}"


def format_table(results: Sequence[CveResult]) -> str:
    rows = [("CVE", "OUTCOME", "DURATION", "LOG")] + [
        (r.cve, r.outcome, format_duration(r.duration_s), r.log or "-") for r in results
    ]
    widths = [max(len(row[i]) for row in rows) for i in range(3)]
    return "\n".join(
        f"{row[0]:<{widths[0]}}  {row[1]:<{widths[1]}}  {row[2]:<{widths[2]}}  {row[3]}".rstrip()
        for row in rows
    )


def build_summary(project: str, variants: Sequence[str], started_at: datetime,
                  results: Sequence[CveResult]) -> dict:
    return {
        "project": project,
        "variants": list(variants),
        "started_at": started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "results": [{**asdict(r), "assessed_variants": list(r.assessed_variants)} for r in results],
        "counts": {o: sum(1 for r in results if r.outcome == o) for o in OUTCOMES},
    }


def write_summary(path: Path, summary: dict) -> None:
    path.write_text(json.dumps(summary, indent=2) + "\n")


def exit_code_for(results: Sequence[CveResult]) -> int:
    return 0 if all(r.outcome in SUCCESS_OUTCOMES for r in results) else 1
