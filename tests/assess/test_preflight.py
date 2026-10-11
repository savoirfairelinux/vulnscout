import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from vulnscout_assess.preflight import PreflightError, check_preflight


def mcp_list(servers, returncode=0, stderr=""):
    def run(argv, **kwargs):
        assert argv[1:] == ["mcp", "list", "--json"]
        return SimpleNamespace(returncode=returncode, stdout=json.dumps({"mcpServers": servers}), stderr=stderr)
    return run


def which(name):
    return "/usr/bin/copilot"


SKILL_REL = Path(".github/skills/cve-assessment/SKILL.md")
COPILOT_SKILL_REL = Path(".copilot/skills/cve-assessment/SKILL.md")


def make_skill(root, rel):
    path = root / rel
    path.parent.mkdir(parents=True)
    path.write_text("---\nname: cve-assessment\n---\n")


@pytest.fixture()
def home(tmp_path_factory):
    """A fake home that contains the skill, so success-path tests pass the skill check."""
    path = tmp_path_factory.mktemp("home")
    make_skill(path, COPILOT_SKILL_REL)
    return path


@pytest.fixture()
def bare_home(tmp_path_factory):
    return tmp_path_factory.mktemp("bare_home")


def test_returns_copilot_path_when_all_checks_pass(tmp_path, home):
    run = mcp_list({"vulnscout": {"type": "local", "enabled": True}})

    assert check_preflight(tmp_path, which=which, run=run, home=home) == "/usr/bin/copilot"


def test_missing_work_dir_fails(tmp_path):
    with pytest.raises(PreflightError, match="--dir is not a directory"):
        check_preflight(tmp_path / "missing", which=which, run=mcp_list({}))


def test_missing_copilot_binary_fails(tmp_path):
    with pytest.raises(PreflightError, match="copilot CLI not found on PATH"):
        check_preflight(tmp_path, which=lambda name: None, run=mcp_list({}))


def test_missing_vulnscout_server_fails_with_hint(tmp_path, home):
    with pytest.raises(PreflightError, match="mcp-config.json"):
        check_preflight(tmp_path, which=which, run=mcp_list({"redmine": {"enabled": True}}), home=home)


def test_disabled_vulnscout_server_fails(tmp_path, home):
    run = mcp_list({"vulnscout": {"type": "local", "enabled": False}})

    with pytest.raises(PreflightError, match="vulnscout"):
        check_preflight(tmp_path, which=which, run=run, home=home)


def test_mcp_list_failure_reports_stderr(tmp_path, home):
    with pytest.raises(PreflightError, match="not logged in"):
        check_preflight(tmp_path, which=which, run=mcp_list({}, returncode=1, stderr="not logged in"), home=home)


def test_unparseable_mcp_list_output_fails(tmp_path, home):
    def run(argv, **kwargs):
        return SimpleNamespace(returncode=0, stdout="User servers:\n  vulnscout", stderr="")

    with pytest.raises(PreflightError, match="could not parse"):
        check_preflight(tmp_path, which=which, run=run, home=home)


def test_mcp_list_timeout_fails(tmp_path, home):
    def run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    with pytest.raises(PreflightError, match="timed out"):
        check_preflight(tmp_path, which=which, run=run, home=home)


def test_dry_run_only_checks_work_dir(tmp_path):
    def fail(*args, **kwargs):
        raise AssertionError("copilot must not be called")

    assert check_preflight(tmp_path, require_copilot=False, which=fail, run=fail) == "copilot"


def test_skill_in_work_dir_passes(tmp_path, bare_home):
    make_skill(tmp_path, SKILL_REL)
    run = mcp_list({"vulnscout": {"enabled": True}})

    assert check_preflight(tmp_path, which=which, run=run, home=bare_home) == "/usr/bin/copilot"


def test_skill_in_home_passes(tmp_path, home):
    run = mcp_list({"vulnscout": {"enabled": True}})

    assert check_preflight(tmp_path, which=which, run=run, home=home) == "/usr/bin/copilot"


def test_missing_skill_fails_with_hint(tmp_path, bare_home):
    with pytest.raises(PreflightError, match="cve-assessment skill not found; copy or symlink"):
        check_preflight(tmp_path, which=which, run=mcp_list({"vulnscout": {}}), home=bare_home)


def test_skill_is_checked_before_mcp_server(tmp_path, bare_home):
    def fail(*args, **kwargs):
        raise AssertionError("mcp list must not run")

    with pytest.raises(PreflightError, match="skill not found"):
        check_preflight(tmp_path, which=which, run=fail, home=bare_home)


def test_dry_run_skips_skill_check(tmp_path, bare_home):
    assert check_preflight(tmp_path, require_copilot=False, home=bare_home) == "copilot"


def test_mcp_list_oserror_becomes_preflight_error(tmp_path, home):
    def run(argv, **kwargs):
        raise OSError("exec format error")

    with pytest.raises(PreflightError, match="could not run `copilot mcp list`: exec format error"):
        check_preflight(tmp_path, which=which, run=run, home=home)


def test_non_dict_server_entry_counts_as_not_enabled(tmp_path, home):
    with pytest.raises(PreflightError, match="mcp-config.json"):
        check_preflight(tmp_path, which=which, run=mcp_list({"vulnscout": "yes"}), home=home)
