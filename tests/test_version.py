"""Version single-source-of-truth checks.

The v1.8.0 release prep caught __version__ reading "1.6.1" while
pyproject.toml said 1.8.0 (fixed in ba66ef7). These tests keep the two
declarations and the CLI flag from drifting again.
"""

import re
import subprocess
import sys
from pathlib import Path

import pytest

import sigil

_ROOT = Path(__file__).resolve().parent.parent


def _pyproject_version() -> str:
    # regex instead of tomllib so the test runs on Python 3.10
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, flags=re.M)
    assert match is not None, "no version field in pyproject.toml"
    return match.group(1)


def _requires_python() -> str:
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^requires-python\s*=\s*"([^"]+)"', text, flags=re.M)
    assert match is not None, "no requires-python field in pyproject.toml"
    return match.group(1)


def test_dunder_version_matches_pyproject():
    """sigil.__version__ and pyproject.toml must declare the same version."""
    assert sigil.__version__ == _pyproject_version()


def test_python_floor_matches_runtime_annotations():
    assert _requires_python() == ">=3.9"


def test_cli_version_flag():
    """`python sigil.py --version` exits 0 and prints the version SECURITY.md asks reporters for."""
    result = subprocess.run(
        [sys.executable, str(_ROOT / "sigil.py"), "--version"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == f"SIGIL {sigil.__version__}"


def test_cli_version_flag_in_process(monkeypatch, capsys):
    """Same flag through sigil.cli() directly, no subprocess."""
    monkeypatch.setattr(sys, "argv", ["sigil.py", "--version"])
    with pytest.raises(SystemExit) as excinfo:
        sigil.cli()
    assert excinfo.value.code == 0
    assert capsys.readouterr().out.strip() == f"SIGIL {sigil.__version__}"
