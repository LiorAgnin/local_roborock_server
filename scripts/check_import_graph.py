"""Import the whole app and fail if the map-rendering stack gets pulled in.

The Docker image uninstalls Pillow and vacuum-map-parser (only used by
python-roborock's map modules, which the app never imports). Run this after
that removal, and from the test suite, so a code change or python-roborock bump
that starts needing them fails loudly instead of at runtime.

Imports every module under ``roborock_local_server`` (the bundled backend as
the top-level packages ``backend.py`` exposes it as) plus every ``roborock``
module the app source imports, then checks ``sys.modules``.
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
from pathlib import Path
import pkgutil
import sys
import traceback

FORBIDDEN_MODULES = ("PIL", "vacuum_map_parser_base", "vacuum_map_parser_roborock")


def _import(name: str, failures: list[str]) -> None:
    try:
        importlib.import_module(name)
    except Exception:
        failures.append(f"{name}:\n{traceback.format_exc()}")


def _roborock_modules_used_by(package_dir: Path) -> set[str]:
    """Collect ``roborock`` modules the app imports, including function-local imports."""
    names: set[str] = set()
    for path in package_dir.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names if alias.name.split(".")[0] == "roborock")
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                if node.module.split(".")[0] != "roborock":
                    continue
                names.add(node.module)
                for alias in node.names:
                    candidate = f"{node.module}.{alias.name}"
                    if _is_submodule(candidate):
                        names.add(candidate)
    return names


def _is_submodule(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def check() -> list[str]:
    failures: list[str] = []

    import roborock_local_server
    import roborock_local_server.backend  # puts bundled_backend on sys.path

    package_dir = Path(roborock_local_server.__file__).resolve().parent
    backend_dir = package_dir / "bundled_backend"

    walk_errors = lambda name: failures.append(f"{name}:\n{traceback.format_exc()}")  # noqa: E731
    app_modules = [
        info.name
        for info in pkgutil.walk_packages(roborock_local_server.__path__, "roborock_local_server.", onerror=walk_errors)
        if not info.name.startswith("roborock_local_server.bundled_backend")
    ]
    backend_modules = [info.name for info in pkgutil.walk_packages([str(backend_dir)], onerror=walk_errors)]
    roborock_modules = sorted(_roborock_modules_used_by(package_dir))

    if len(app_modules) < 5 or not backend_modules or not roborock_modules:
        failures.append(
            f"import walk found too little: app={len(app_modules)} "
            f"backend={len(backend_modules)} roborock={len(roborock_modules)}"
        )
    for name in [*app_modules, *backend_modules, *roborock_modules]:
        _import(name, failures)

    loaded = sorted(
        name for name in sys.modules if name.split(".")[0] in FORBIDDEN_MODULES
    )
    if loaded:
        failures.append(f"map-rendering modules were imported: {', '.join(loaded)}")
    print(
        f"import graph: {len(app_modules)} app, {len(backend_modules)} backend, "
        f"{len(roborock_modules)} roborock modules; failures={len(failures)}"
    )
    return failures


def main() -> int:
    failures = check()
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
