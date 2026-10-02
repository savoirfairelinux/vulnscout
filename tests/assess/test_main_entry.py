import os
import subprocess
import sys
from pathlib import Path

from vulnscout_assess.__main__ import entry


def test_import_error_prints_hint_and_returns_one(capsys):
    def broken_loader():
        raise ImportError("No module named 'httpx'")

    code = entry(loader=broken_loader)

    assert code == 1
    err = capsys.readouterr().err
    assert "needs Python 3.10+ with httpx installed" in err
    assert "VULNSCOUT_PYTHON" in err
    assert err.count("\n") == 1


def test_entry_delegates_to_loaded_main():
    assert entry(loader=lambda: (lambda: 7)) == 7


def test_module_without_httpx_prints_hint_via_subprocess():
    preamble = (
        "import sys; sys.modules['httpx'] = None; sys.argv = ['x', '--help']; "
        "import runpy; runpy.run_module('vulnscout_assess', run_name='__main__')"
    )
    repo_root = Path(__file__).resolve().parents[2]
    env = {**os.environ, "PYTHONPATH": str(repo_root)}
    result = subprocess.run([sys.executable, "-c", preamble], capture_output=True, text=True,
                            timeout=60, cwd=repo_root, env=env)

    assert result.returncode == 1
    assert "needs Python 3.10+ with httpx installed" in result.stderr
