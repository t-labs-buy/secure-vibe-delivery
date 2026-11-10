"""Project detection: languages, test runner, environments, API specs."""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", ".svd", "dist", "build",
             ".tox", ".mypy_cache", ".pytest_cache", "site-packages", ".next", "coverage"}


def iter_files(root: Path, suffixes: tuple[str, ...], limit: int = 5000):
    count = 0
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = list(d.iterdir())
        except OSError:
            continue
        for p in entries:
            if p.is_dir():
                if p.name not in SKIP_DIRS and not p.name.startswith("."):
                    stack.append(p)
            elif p.suffix in suffixes:
                yield p
                count += 1
                if count >= limit:
                    return


@dataclass
class ProjectInfo:
    root: Path
    is_python: bool = False
    is_js: bool = False
    python_cmd: list[str] = field(default_factory=list)
    test_runner: Optional[str] = None  # pytest | jest | None
    has_tests: bool = False
    locustfile: Optional[Path] = None
    openapi_file: Optional[Path] = None
    is_git: bool = False
    svd_rules_dir: Optional[Path] = None


VENV_DIRS = (".venv", "venv", "env")


def venv_exe(root: Path, name: str) -> Optional[Path]:
    """A program inside the project's virtual environment: bin/<name> on macOS and Linux,
    Scripts\\<name>.exe on Windows."""
    for venv in VENV_DIRS:
        for candidate in (root / venv / "bin" / name, root / venv / "Scripts" / f"{name}.exe"):
            if candidate.exists():
                return candidate
    return None


def find_python(root: Path) -> list[str]:
    py = venv_exe(root, "python")
    if py:
        return [str(py)]
    if (root / "uv.lock").exists() and shutil.which("uv"):
        return [shutil.which("uv"), "run", "--project", str(root), "python"]
    # Windows usually has "python" (or the "py" launcher) rather than "python3"
    return [shutil.which("python3") or shutil.which("python") or shutil.which("py") or "python3"]


def detect(root: str | Path) -> ProjectInfo:
    root = Path(root).resolve()
    info = ProjectInfo(root=root)
    py_markers = ["pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile"]
    info.is_python = any((root / m).exists() for m in py_markers) or any(
        True for _ in iter_files(root, (".py",), limit=1))
    pkg = root / "package.json"
    info.is_js = pkg.exists()
    info.is_git = (root / ".git").exists()
    if (root / "svd-rules").is_dir():
        info.svd_rules_dir = root / "svd-rules"

    for name in ("locustfile.py", "tests/locustfile.py", "load/locustfile.py", "perf/locustfile.py"):
        if (root / name).exists():
            info.locustfile = root / name
            break

    for name in ("openapi.json", "openapi.yaml", "openapi.yml", "swagger.json", "swagger.yaml",
                 "docs/openapi.json", "docs/openapi.yaml", "api/openapi.yaml"):
        if (root / name).exists():
            info.openapi_file = root / name
            break

    # Test runner
    js_jest = False
    if info.is_js:
        try:
            pj = json.loads(pkg.read_text())
            deps = {**pj.get("dependencies", {}), **pj.get("devDependencies", {})}
            js_jest = "jest" in deps or "jest" in json.dumps(pj.get("scripts", {})) or "jest" in pj
        except (OSError, json.JSONDecodeError):
            pass
        js_jest = js_jest or any((root / f).exists() for f in
                                 ("jest.config.js", "jest.config.ts", "jest.config.cjs", "jest.config.mjs"))
    py_tests = False
    if info.is_python:
        py_tests = any((root / f).exists() for f in ("pytest.ini", "conftest.py", "tests", "test")) or any(
            p.name.startswith("test_") or p.name.endswith("_test.py") for p in iter_files(root, (".py",), 2000))
        if not py_tests and (root / "pyproject.toml").exists():
            py_tests = "[tool.pytest" in (root / "pyproject.toml").read_text(errors="ignore")
    if py_tests:
        info.test_runner = "pytest"
        info.python_cmd = find_python(root)
    elif js_jest:
        info.test_runner = "jest"
    info.has_tests = info.test_runner is not None
    if info.is_python and not info.python_cmd:
        info.python_cmd = find_python(root)
    return info
