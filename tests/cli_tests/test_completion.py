import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "vulnscout"


def _stub_env(tmp_path, with_engine=True):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    if with_engine:
        stub = bindir / "podman"
        stub.write_text("#!/bin/sh\nexit 0\n")
        stub.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = f"{bindir}:/usr/bin:/bin"
    env["VULNSCOUT_BUILD_DIR"] = str(tmp_path / "build")
    return env


def _run(args, tmp_path, with_engine=True):
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        capture_output=True, text=True, env=_stub_env(tmp_path, with_engine),
    )


@pytest.fixture
def completion_script(tmp_path):
    res = _run(["completion", "bash"], tmp_path)
    assert res.returncode == 0, res.stderr
    path = tmp_path / "vulnscout.bash"
    path.write_text(res.stdout)
    return path


def complete(script, words, tmp_path=None):
    """Return the COMPREPLY candidates for `words` (last word = current word)."""
    quoted = " ".join(f"'{w}'" for w in words)
    code = (
        f"source '{script}'\n"
        f"COMP_WORDS=({quoted})\n"
        f"COMP_CWORD=$(( ${{#COMP_WORDS[@]}} - 1 ))\n"
        "_vulnscout_complete\n"
        'printf "%s\\n" "${COMPREPLY[@]}"\n'
    )
    res = subprocess.run(["bash", "-c", code], capture_output=True, text=True,
                         cwd=str(script.parent))
    assert res.returncode == 0, res.stderr
    return res.stdout.split()


def test_completion_requires_bash_shell(tmp_path):
    for args in (["completion"], ["completion", "zsh"]):
        res = _run(args, tmp_path)
        assert res.returncode == 1
        assert "bash" in res.stderr


def test_completion_works_without_container_engine(tmp_path):
    res = _run(["completion", "bash"], tmp_path, with_engine=False)
    assert res.returncode == 0
    assert "complete -F _vulnscout_complete vulnscout ./vulnscout" in res.stdout


def test_registered_for_bare_and_relative_invocation(completion_script):
    code = f"source '{completion_script}'; complete -p"
    out = subprocess.run(["bash", "-c", code], capture_output=True, text=True).stdout
    registered = {line.split()[-1] for line in out.splitlines()}
    assert {"vulnscout", "./vulnscout"} <= registered


def test_completion_verb_is_hidden(tmp_path, completion_script):
    assert "completion" not in _run(["--help"], tmp_path).stdout
    assert "completion" not in complete(completion_script, ["vulnscout", ""])


def test_top_level_offers_all_verbs(completion_script):
    out = complete(completion_script, ["vulnscout", ""])
    for verb in ("add", "scan", "match-condition", "report", "export", "import",
                 "refresh", "delete", "list", "config", "asset", "start", "stop",
                 "restart", "update", "version", "serve"):
        assert verb in out
    assert "--dev" in out


def test_scope_value_is_not_taken_as_subcommand(completion_script):
    out = complete(completion_script, ["vulnscout", "-p", "export", "export", ""])
    assert "spdx" in out and "custom-openvex" in out


def test_scope_flags_only_on_data_commands(completion_script):
    assert "-p" in complete(completion_script, ["vulnscout", "export", "-"])
    for verb in ("config", "list", "delete", "asset", "start"):
        out = complete(completion_script, ["vulnscout", verb, "-"])
        assert "-p" not in out and "--variant" not in out, verb


def test_scan_types_and_comma_lists(completion_script):
    assert set(complete(completion_script, ["vulnscout", "scan", "n"])) == {"nvd"}
    assert complete(completion_script, ["vulnscout", "scan", "nvd,o"]) == ["nvd,osv"]


def test_fixed_values(completion_script):
    assert set(complete(completion_script, ["vulnscout", "report", "--format", ""])) == {"pdf", "html"}
    assert set(complete(completion_script, ["vulnscout", "import", "context", "--timestamps", ""])) == {"original", "current"}
    assert set(complete(completion_script, ["vulnscout", "delete", ""])) >= {"scan", "outdated", "empty-scans", "orphaned-vulns", "--dry-run", "--yes"}
    assert set(complete(completion_script, ["vulnscout", "config", ""])) >= {"get", "set", "unset", "list"}
    assert set(complete(completion_script, ["vulnscout", "list", ""])) >= {"projects", "scans", "--json"}


def test_completion_matches_help(tmp_path, completion_script):
    """Drift check: every command and option documented in --help is completed."""
    overview = _run(["--help"], tmp_path).stdout
    verbs = re.findall(r"^    ([a-z][a-z-]*)\s{2,}\S", overview, re.M)
    assert verbs
    offered = complete(completion_script, ["vulnscout", ""])
    for verb in verbs:
        assert verb in offered, verb
        help_text = _run([verb, "--help"], tmp_path).stdout
        flags = set(re.findall(r"^    (--[a-z-]+)", help_text, re.M)) - {"--project", "--variant"}
        reply = complete(completion_script, ["vulnscout", verb, "-"])
        for flag in flags:
            assert flag in reply, f"{verb} {flag}"
