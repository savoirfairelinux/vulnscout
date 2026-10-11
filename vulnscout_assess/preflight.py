"""Checks that must pass before any Copilot session is started."""

import json
import shutil
import subprocess
from pathlib import Path

MCP_SERVER_NAME = "vulnscout"
MCP_LIST_TIMEOUT_S = 60
MISSING_MCP_HINT = (
    f"no enabled '{MCP_SERVER_NAME}' MCP server in Copilot config; add it to "
    "~/.copilot/mcp-config.json (see doc/source/ai-assessments.md, Step 1)"
)
MISSING_SKILL_HINT = (
    "cve-assessment skill not found; copy or symlink .github/skills/cve-assessment from the "
    "VulnScout repo into ~/.copilot/skills/ or into <--dir>/.github/skills/"
)
SKILL_FILE = Path("cve-assessment") / "SKILL.md"


class PreflightError(Exception):
    """Raised when the environment cannot run headless assessments."""


def check_preflight(work_dir: Path, *, require_copilot: bool = True,
                    which=shutil.which, run=subprocess.run, home: Path | None = None) -> str:
    """Validate --dir and the Copilot setup; return the copilot binary to execute."""
    if not work_dir.is_dir():
        raise PreflightError(f"--dir is not a directory: {work_dir}")
    if not require_copilot:
        return "copilot"
    copilot = which("copilot")
    if copilot is None:
        raise PreflightError("copilot CLI not found on PATH")
    if not _skill_installed(work_dir, home or Path.home()):
        raise PreflightError(MISSING_SKILL_HINT)
    if not _vulnscout_server_enabled(copilot, run):
        raise PreflightError(MISSING_MCP_HINT)
    return copilot


def _skill_installed(work_dir: Path, home: Path) -> bool:
    return any((root / SKILL_FILE).is_file()
               for root in (work_dir / ".github" / "skills", home / ".copilot" / "skills"))


def _vulnscout_server_enabled(copilot: str, run) -> bool:
    argv = [copilot, "mcp", "list", "--json"]
    try:
        result = run(argv, capture_output=True, text=True, timeout=MCP_LIST_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        raise PreflightError("`copilot mcp list` timed out")
    except OSError as exc:
        raise PreflightError(f"could not run `copilot mcp list`: {exc}")
    if result.returncode != 0:
        raise PreflightError(f"`copilot mcp list` failed: {result.stderr.strip()}")
    try:
        server = json.loads(result.stdout).get("mcpServers", {}).get(MCP_SERVER_NAME)
    except (json.JSONDecodeError, AttributeError) as exc:
        raise PreflightError(f"could not parse `copilot mcp list --json` output: {exc}")
    return isinstance(server, dict) and bool(server) and server.get("enabled", True) is not False
