from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_import_graph.py"


def _run_in_clean_interpreter(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_app_import_graph_never_pulls_in_pillow_or_map_parser() -> None:
    # The Docker image uninstalls Pillow/vacuum-map-parser; importing them anywhere breaks it.
    result = _run_in_clean_interpreter(
        "import runpy, sys; "
        f"sys.argv = [{str(SCRIPT)!r}]; "
        f"runpy.run_path({str(SCRIPT)!r}, run_name='__main__')"
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(importlib.util.find_spec("PIL") is None, reason="Pillow not installed")
def test_import_graph_check_detects_pillow() -> None:
    result = _run_in_clean_interpreter(
        "import PIL, runpy, sys; "
        f"check = runpy.run_path({str(SCRIPT)!r})['check']; "
        "sys.exit(0 if any('map-rendering modules' in f for f in check()) else 1)"
    )
    assert result.returncode == 0, result.stdout + result.stderr
