"""Project detection: languages, test suites, environments, API specs."""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", ".svd", "dist", "build",
             ".tox", ".mypy_cache", ".pytest_cache", "site-packages", ".next", "coverage"}

JS_TEST_SUFFIXES = (".test.js", ".test.ts", ".test.jsx", ".test.tsx", ".test.mjs", ".test.cjs",
                    ".spec.js", ".spec.ts", ".spec.jsx", ".spec.tsx", ".spec.mjs", ".spec.cjs")
JEST_CONFIGS = ("jest.config.js", "jest.config.ts", "jest.config.cjs", "jest.config.mjs", "jest.config.json")


def is_venv(d: Path) -> bool:
    """A Python virtual environment, whatever it's called (.venv, hindsight-venv, .venv-loadtest...):
    every venv has a pyvenv.cfg at its top."""
    return (d / "pyvenv.cfg").is_file()


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
                if p.name not in SKIP_DIRS and not p.name.startswith(".") and not is_venv(p):
                    stack.append(p)
            elif p.suffix in suffixes:
                yield p
                count += 1
                if count >= limit:
                    return


def find_venvs(root: Path, depth: int = 3) -> list[str]:
    """Virtual environments inside the project, as paths relative to it. They hold third-party code,
    which the scanners must skip: a venv's packages are full of example keys and old code patterns."""
    found: list[str] = []

    def walk(d: Path, level: int) -> None:
        try:
            entries = [p for p in d.iterdir() if p.is_dir() and not p.is_symlink()]
        except OSError:
            return
        for p in entries:
            if is_venv(p):
                found.append(p.relative_to(root).as_posix())
            elif level < depth and p.name not in {".git", "node_modules", "__pycache__", ".svd"}:
                walk(p, level + 1)

    walk(root, 1)
    return sorted(found)


@dataclass
class ProjectInfo:
    root: Path
    is_python: bool = False
    is_js: bool = False
    python_cmd: list[str] = field(default_factory=list)
    test_runner: Optional[str] = None  # the first suite's runner (pytest | jest), kept for display
    test_runners: list[str] = field(default_factory=list)  # every runner found, e.g. ["pytest", "jest"]
    jest_dirs: list[Path] = field(default_factory=list)  # folders to run Jest in (root, frontend/, ...)
    has_tests: bool = False
    locustfile: Optional[Path] = None
    openapi_file: Optional[Path] = None
    is_git: bool = False
    svd_rules_dir: Optional[Path] = None
    venvs: list[str] = field(default_factory=list)


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


LOCUST_DIRS = ("", "tests", "load", "perf", "loadtest", "loadtests", "load-test", "load-tests", "locust",
               "performance", "tests/load", "tests/perf", "tests/performance")


def find_locustfile(root: Path) -> Optional[Path]:
    """The project's locustfile: the usual places first, then any locustfile.py two levels down."""
    for d in LOCUST_DIRS:
        p = root / d / "locustfile.py"
        if p.is_file():
            return p
    hits = sorted((p for p in iter_files(root, (".py",), 3000)
                   if p.name == "locustfile.py" and len(p.relative_to(root).parts) <= 3),
                  key=lambda p: (len(p.parts), str(p)))
    return hits[0] if hits else None


def _uses_jest(d: Path) -> bool:
    if any((d / f).exists() for f in JEST_CONFIGS):
        return True
    pkg = d / "package.json"
    if not pkg.is_file():
        return False
    try:
        pj = json.loads(pkg.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    deps = {**pj.get("dependencies", {}), **pj.get("devDependencies", {})}
    return "jest" in deps or "jest" in json.dumps(pj.get("scripts", {})) or "jest" in pj


def _has_js_tests(d: Path) -> bool:
    for p in iter_files(d, (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"), 4000):
        if p.name.endswith(JS_TEST_SUFFIXES) or "__tests__" in p.parts:
            return True
    return False


def find_jest_dirs(root: Path) -> list[Path]:
    """Folders that set up Jest and actually contain tests: the root and its direct subfolders
    (frontend/, web/, client/...). A package.json that lists Jest but has no tests isn't a suite."""
    try:
        subs = sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith(".")
                      and p.name not in SKIP_DIRS and (p / "package.json").is_file())
    except OSError:
        subs = []
    return [d for d in [root, *subs] if _uses_jest(d) and _has_js_tests(d)]


def detect(root: str | Path) -> ProjectInfo:
    root = Path(root).resolve()
    info = ProjectInfo(root=root)
    py_markers = ["pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile"]
    info.is_python = any((root / m).exists() for m in py_markers) or any(
        True for _ in iter_files(root, (".py",), limit=1))
    info.is_js = (root / "package.json").exists() or any(
        (p / "package.json").is_file() for p in root.iterdir() if p.is_dir() and p.name not in SKIP_DIRS)
    info.is_git = (root / ".git").exists()
    if (root / "svd-rules").is_dir():
        info.svd_rules_dir = root / "svd-rules"
    info.venvs = find_venvs(root)
    info.locustfile = find_locustfile(root)

    for name in ("openapi.json", "openapi.yaml", "openapi.yml", "swagger.json", "swagger.yaml",
                 "docs/openapi.json", "docs/openapi.yaml", "api/openapi.yaml"):
        if (root / name).exists():
            info.openapi_file = root / name
            break

    # Test suites: pytest and Jest are independent. A Python backend with a JavaScript frontend
    # gets both run, each with its own results and coverage.
    py_tests = False
    if info.is_python:
        py_tests = any((root / f).exists() for f in ("pytest.ini", "conftest.py", "tests", "test")) or any(
            p.name.startswith("test_") or p.name.endswith("_test.py") for p in iter_files(root, (".py",), 2000))
        if not py_tests and (root / "pyproject.toml").exists():
            py_tests = "[tool.pytest" in (root / "pyproject.toml").read_text(errors="ignore")
    if py_tests:
        info.test_runners.append("pytest")
        info.python_cmd = find_python(root)
    if info.is_js:
        info.jest_dirs = find_jest_dirs(root)
        if info.jest_dirs:
            info.test_runners.append("jest")
    info.test_runner = info.test_runners[0] if info.test_runners else None
    info.has_tests = bool(info.test_runners)
    if info.is_python and not info.python_cmd:
        info.python_cmd = find_python(root)
    return info
