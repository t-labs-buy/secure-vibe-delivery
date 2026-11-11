"""Subprocess helpers and external-tool resolution."""
from __future__ import annotations

import asyncio
import atexit
import contextvars
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .models import CommandRecord

# The run log: when a pipeline run sets this list, every command any check runs is appended to it,
# so the report can show exactly what was executed, in order.
JOURNAL: contextvars.ContextVar[Optional[list]] = contextvars.ContextVar("svd_journal", default=None)


def journal_step(kind: str, text: str, **extra) -> None:
    j = JOURNAL.get()
    if j is not None:
        j.append({"t": time.time(), "kind": kind, "text": text, **extra})


# Tools that can be run through `uvx` when they aren't on PATH.
UVX_FALLBACK = {"semgrep": "semgrep", "locust": "locust"}


def find_uv_runner() -> Optional[list[str]]:
    """The argv prefix that runs a tool through uv, or None if uv can't be found.

    PATH comes first. When it misses (common on Windows after `pip install --user uv`, which puts
    uvx.exe in a Scripts folder that isn't on PATH), fall back to the `UV` variable: uv sets it to
    its own binary for every process it starts, and this server is normally started by uvx.
    """
    found = shutil.which("uvx")
    if found:
        return [found]
    uv = os.environ.get("UV", "")
    if uv and Path(uv).is_file():
        uv_path = Path(uv)
        sibling = uv_path.with_name("uvx" + uv_path.suffix)  # uvx.exe beside uv.exe on Windows
        if sibling.is_file():
            return [str(sibling)]
        return [str(uv_path), "tool", "run"]
    found = shutil.which("uv")
    if found:
        return [found, "tool", "run"]
    return None


def resolve_tool(name: str) -> Optional[list[str]]:
    """Return the argv prefix that runs `name`, or None if it can't be found."""
    path = shutil.which(name)
    if path:
        return [path]
    if name == "snyk":
        # downloaded by svd_setup into this server's own cache folder
        from .installer import cached_snyk
        cached = cached_snyk()
        if cached:
            return [str(cached)]
    runner = find_uv_runner() if name in UVX_FALLBACK else None
    if runner:
        return [*runner, "--python", "3.12", UVX_FALLBACK[name]]
    return None


@dataclass
class ProcResult:
    exit_code: Optional[int]
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False
    error: str = ""

    def record(self, name: str, argv: list[str], raw_dir: Optional[Path]) -> CommandRecord:
        out_p = err_p = ""
        if raw_dir is not None:
            raw_dir.mkdir(parents=True, exist_ok=True)
            safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", name)
            (raw_dir / f"{safe}.stdout.txt").write_text(self.stdout, errors="replace")
            (raw_dir / f"{safe}.stderr.txt").write_text(self.stderr, errors="replace")
            out_p, err_p = str(raw_dir / f"{safe}.stdout.txt"), str(raw_dir / f"{safe}.stderr.txt")
        return CommandRecord(
            name=name,
            argv=[redact_arg(a) for a in argv],
            started_at=time.time() - self.duration_s,
            exit_code=self.exit_code,
            duration_s=round(self.duration_s, 2),
            stdout_path=out_p,
            stderr_path=err_p,
            timed_out=self.timed_out,
            error=self.error,
        )


def redact_arg(a: str) -> str:
    return re.sub(r"(token|password|secret)=\S+", r"\1=***", a, flags=re.I)


def command_line(argv: list[str]) -> str:
    """The command as a user would type it (quoted for this OS), so it can be copied and re-run."""
    args = [redact_arg(str(a)) for a in argv]
    if sys.platform == "win32":
        return subprocess.list2cmdline(args)

    def q(a: str) -> str:
        if "'" in a and not re.search(r'["$`\\!]', a):
            return f'"{a}"'  # easier to read than shlex's '"'"' escaping, and equivalent in a POSIX shell
        return shlex.quote(a)
    return " ".join(q(a) for a in args)


async def run_cmd(
    argv: list[str],
    cwd: str | Path,
    timeout: float = 900,
    env: Optional[dict[str, str]] = None,
) -> ProcResult:
    started_wall = time.time()
    res = await _run_cmd(argv, cwd, timeout, env)
    j = JOURNAL.get()
    if j is not None:
        j.append({"t": started_wall, "kind": "command", "text": command_line(argv),
                  "cwd": str(cwd), "exit_code": res.exit_code, "duration_s": round(res.duration_s, 2),
                  "timed_out": res.timed_out, "error": res.error})
    return res


async def _run_cmd(
    argv: list[str],
    cwd: str | Path,
    timeout: float = 900,
    env: Optional[dict[str, str]] = None,
) -> ProcResult:
    start = time.monotonic()
    full_env = {**os.environ, **(env or {})}
    full_env.setdefault("NO_COLOR", "1")
    # Client configs pass tokens through as "" when the user hasn't set them; an empty value
    # would override the login saved by `snyk auth` / `semgrep login`, so drop empty ones.
    for k in ("SNYK_TOKEN", "SVD_SNYK_ORG", "SNYK_CFG_ORG", "SEMGREP_APP_TOKEN"):
        if k in full_env and not full_env[k].strip():
            del full_env[k]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(cwd),
            env=full_env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            **_group_kwargs(),
        )
    except (FileNotFoundError, PermissionError) as e:
        return ProcResult(None, "", "", time.monotonic() - start, error=str(e))
    LIVE.add(proc.pid)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return ProcResult(proc.returncode, out.decode(errors="replace"), err.decode(errors="replace"),
                          time.monotonic() - start)
    except asyncio.TimeoutError:
        kill_group(proc.pid)
        out, err = await proc.communicate()
        return ProcResult(None, out.decode(errors="replace"), err.decode(errors="replace"),
                          time.monotonic() - start, timed_out=True, error=f"timed out after {timeout}s")
    except asyncio.CancelledError:
        kill_group(proc.pid)
        raise
    finally:
        # Tools that fork workers (Semgrep starts semgrep-core; test suites start servers) can leave
        # them running after the parent exits. They share the command's own process group, so ending
        # the group cleans them up too.
        kill_group(proc.pid, after_exit=True)
        LIVE.discard(proc.pid)


# Commands still running, so their process groups can be ended if the server itself exits.
LIVE: set[int] = set()


def _group_kwargs() -> dict:
    """Start each command as the leader of its own process group (a new session on macOS and Linux,
    a new process group on Windows), so everything it starts can be ended together."""
    if sys.platform == "win32":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def kill_group(pid: int, after_exit: bool = False) -> None:
    """End a command and every process it started. A group that has already finished is ignored."""
    if sys.platform == "win32":
        if not after_exit:  # taskkill /T finds the children through the parent, so only while it runs
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True)
        return
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _kill_live() -> None:
    for pid in list(LIVE):
        kill_group(pid)


atexit.register(_kill_live)
