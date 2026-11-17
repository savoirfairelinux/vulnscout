"""Documented new-syntax examples must put -p/-v after the command."""

import re

import pytest

from tests.cli_tests.test_completion import ROOT, _run

VERBS = ("start", "stop", "restart", "update", "version", "serve", "add", "scan",
         "match-condition", "refresh", "asset", "report", "export", "import",
         "delete", "list", "config", "assess", "review")
LEADING_SCOPE = re.compile(r"\bvulnscout\s+(?:\[\s*)?(?:-p|-v|--project|--variant)\s")
# Legacy flag-syntax examples are kept in the migration guide on purpose.
LEGACY_CALL = re.compile(r"\bvulnscout\s+--project\s+\S+\s+--variant\s+\S+\s*\\?$")

DOC_FILES = [ROOT / "README.adoc", *sorted((ROOT / "doc" / "source").glob("*.md"))]


def _offending(text):
    return [line.strip() for line in text.splitlines()
            if LEADING_SCOPE.search(line) and not LEGACY_CALL.search(line)]


@pytest.mark.parametrize("path", DOC_FILES, ids=lambda p: p.name)
def test_docs_put_scope_flags_after_command(path):
    assert _offending(path.read_text()) == []


@pytest.mark.parametrize("line", [
    "vulnscout -p demo add --spdx sbom.json",
    "vulnscout --variant x86 scan",
    "Usage: vulnscout [-p <project>] [-v <variant>] add <input options>",
    "Usage: vulnscout [--variant <variant>] scan",
])
def test_leading_scope_detection_includes_optional_usage_flags(line):
    assert _offending(line) == [line]


@pytest.mark.parametrize("help_flag", ["--help", "-h"])
@pytest.mark.parametrize("verb", [None, *VERBS], ids=lambda v: v or "overview")
def test_help_puts_scope_flags_after_command(verb, help_flag, tmp_path):
    res = _run([verb, help_flag] if verb else [help_flag], tmp_path)
    assert res.returncode == 0, res.stderr
    assert _offending(res.stdout) == []
    invocations = re.findall(r"^(?:Usage:\s+|\s+)(vulnscout \S+)", res.stdout, re.MULTILINE)
    assert invocations
    assert all(invocation == f"vulnscout {verb or '<command>'}" for invocation in invocations)
