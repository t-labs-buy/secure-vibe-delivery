"""Per-project settings from .svd.toml (or svd.toml) at the project root.

Everything is optional; a project without the file is checked exactly as before.

    [functional]
    # Run these instead of the auto-detected pytest / Jest suites. Use it when the project's tests
    # must not, or cannot, run under pytest (their own runner, a sandbox database, a wrapper script).
    [[functional.suite]]
    name = "backend"
    command = "scripts/test_coverage_safe.sh 70"   # run from the project root, through the shell
    junit = ".svd/functional/junit.xml"            # optional: JUnit XML the command writes
    coverage = ".svd/functional/coverage.json"     # optional: coverage.py JSON or Istanbul summary
    timeout = 3600                                 # seconds (default 1800)

    # pytest is refused when test files use nose-style setup()/teardown() (pytest 8 doesn't call
    # them, so the tests run without the isolation they were written to have). Set this only after
    # checking those files are safe without it.
    allow_unsafe_pytest = false

    [performance]
    locustfile = "loadtest/locustfile.py"
    env_file = ".env"                    # variables Locust's process gets (e.g. test-account passwords)
    env = { LOADTEST_LLM = "0" }         # set after env_file, so these win

    [security]
    exclude = ["generated", "vendor"]    # extra folders the scanners skip
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

CONFIG_NAMES = (".svd.toml", "svd.toml")


class ConfigError(ValueError):
    pass


@dataclass
class Suite:
    name: str
    command: str
    junit: Optional[str] = None
    coverage: Optional[str] = None
    timeout: int = 1800


@dataclass
class ProjectConfig:
    path: Optional[Path] = None
    suites: list[Suite] = field(default_factory=list)
    allow_unsafe_pytest: bool = False
    locustfile: Optional[str] = None
    locust_env_file: Optional[str] = None
    locust_env: dict[str, str] = field(default_factory=dict)
    exclude: list[str] = field(default_factory=list)


def _str_list(v, where: str) -> list[str]:
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ConfigError(f"{where} must be a list of strings")
    return v


def load(root: Path) -> ProjectConfig:
    """Read the project's config. A missing file gives the defaults; a malformed one raises
    ConfigError with a message that says what to fix."""
    path = next((root / n for n in CONFIG_NAMES if (root / n).is_file()), None)
    if path is None:
        return ProjectConfig()
    try:
        data = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"{path.name} can't be read: {e}") from e
    cfg = ProjectConfig(path=path)

    fun = data.get("functional", {}) or {}
    for i, s in enumerate(fun.get("suite", []) or []):
        if not isinstance(s, dict) or not isinstance(s.get("command"), str) or not s["command"].strip():
            raise ConfigError(f"{path.name}: functional.suite #{i + 1} needs a command")
        cfg.suites.append(Suite(name=str(s.get("name") or f"suite {i + 1}"), command=s["command"],
                                junit=s.get("junit"), coverage=s.get("coverage"),
                                timeout=int(s.get("timeout") or 1800)))
    cfg.allow_unsafe_pytest = bool(fun.get("allow_unsafe_pytest", False))

    perf = data.get("performance", {}) or {}
    cfg.locustfile = perf.get("locustfile")
    cfg.locust_env_file = perf.get("env_file")
    env = perf.get("env", {}) or {}
    if not isinstance(env, dict):
        raise ConfigError(f"{path.name}: performance.env must be a table of NAME = \"value\"")
    cfg.locust_env = {str(k): str(v) for k, v in env.items()}

    cfg.exclude = _str_list((data.get("security", {}) or {}).get("exclude"), f"{path.name}: security.exclude")
    return cfg


def read_env_file(path: Path) -> dict[str, str]:
    """KEY=value lines (an optional `export ` prefix, # comments, quoted values), the subset of the
    dotenv format that every .env reader agrees on. Values are never logged."""
    out: dict[str, str] = {}
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not key.replace("_", "").isalnum():
            continue
        value = value.strip()
        if value[:1] in ("'", '"') and value[-1:] == value[:1] and len(value) >= 2:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        out[key] = value
    return out


def locust_env(root: Path, cfg: ProjectConfig) -> tuple[dict[str, str], list[str]]:
    """The extra environment for Locust and the variable names it sets (names only, for the log)."""
    env: dict[str, str] = {}
    if cfg.locust_env_file:
        p = (root / cfg.locust_env_file).resolve()
        if not p.is_file():
            raise ConfigError(f"performance.env_file {cfg.locust_env_file} not found")
        env.update(read_env_file(p))
    env.update(cfg.locust_env)
    return env, sorted(env)


def suite_argv(command: str) -> list[str]:
    """Run a suite's command through the shell, so pipes, `&&` and environment prefixes work."""
    if os.name == "nt":
        return ["cmd", "/c", command]
    return ["/bin/sh", "-c", command]
