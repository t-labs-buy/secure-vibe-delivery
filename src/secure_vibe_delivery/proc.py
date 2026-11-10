"""Subprocess helpers and external-tool resolution."""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .models import CommandRecord

# Tools that can be run through `uvx` when they aren't on PATH.
UVX_FALLBACK = {"semgrep": "semgrep", "locust": "locust"}


def resolve_tool(name: str) -> Optional[list[str]]:
    """Return the argv prefix that runs `name`, or None if it can't be found."""
    path = shutil.which(name)
    if path:
        return [path]
    if name in UVX_FALLBACK and shutil.which("uvx"):
        return [shutil.which("uvx"), "--python", "3.12", UVX_FALLBACK[name]]
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
            exit_code=self.exit_code,
            duration_s=round(self.duration_s, 2),
            stdout_path=out_p,
            stderr_path=err_p,
            timed_out=self.timed_out,
            error=self.error,
        )


def redact_arg(a: str) -> str:
    return re.sub(r"(token|password|secret)=\S+", r"\1=***", a, flags=re.I)


async def run_cmd(
    argv: list[str],
    cwd: str | Path,
    timeout: float = 900,
    env: Optional[dict[str, str]] = None,
) -> ProcResult:
    start = time.monotonic()
    full_env = {**os.environ, **(env or {})}
    full_env.setdefault("NO_COLOR", "1")
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(cwd),
            env=full_env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (FileNotFoundError, PermissionError) as e:
        return ProcResult(None, "", "", time.monotonic() - start, error=str(e))
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return ProcResult(proc.returncode, out.decode(errors="replace"), err.decode(errors="replace"),
                          time.monotonic() - start)
    except asyncio.TimeoutError:
        proc.kill()
        out, err = await proc.communicate()
        return ProcResult(None, out.decode(errors="replace"), err.decode(errors="replace"),
                          time.monotonic() - start, timed_out=True, error=f"timed out after {timeout}s")
