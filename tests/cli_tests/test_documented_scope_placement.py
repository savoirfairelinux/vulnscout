"""Documented new-syntax examples must put -p/-v after the command."""

import re

import pytest

from tests.cli_tests.test_completion import ROOT, _run

VERBS = ("start", "stop", "restart", "update", "version", "serve", "add", "scan",
         "match-condition", "refresh", "asset", "report", "export", "import",
         "delete", "list", "config", "assess")
LEADING_SCOPE = re.compile(r"\bvulnscout\s+(?:-p|-v|--project|--variant)\s")
# Legacy flag-syntax examples are kept in the migration guide on purpose.
LEGACY_CALL = re.compile(r"\bvulnscout\s+--project\s+\S+\s+--variant\s+\S+\s*\\?$")

DOC_FILES = [ROOT / "README.adoc", *sorted((ROOT / "doc" / "source").glob("*.md"))]


def _offending(text):
    return [line.strip() for line in text.splitlines()
            if LEADING_SCOPE.search(line) and not LEGACY_CALL.search(line)]


@pytest.mark.parametrize("path", DOC_FILES, ids=lambda p: p.name)
def test_docs_put_scope_flags_after_command(path):
    assert _offending(path.read_text()) == []


@pytest.mark.parametrize("verb", [None, *VERBS], ids=lambda v: v or "overview")
def test_help_puts_scope_flags_after_command(verb, tmp_path):
    res = _run([verb, "--help"] if verb else ["--help"], tmp_path)
    assert res.returncode == 0, res.stderr
    assert _offending(res.stdout) == []
