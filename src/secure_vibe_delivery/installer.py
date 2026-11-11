"""One-time setup: fetch the Snyk CLI if it's missing, and start the Snyk / Semgrep sign-ins.

Nothing is installed system-wide. Snyk is downloaded from Snyk's official site into this
server's own cache folder and checked against the SHA-256 checksum Snyk publishes beside it.
Sign-ins run in the background, because they wait for the person to finish in a browser and
MCP clients give up on a single tool call after about a minute.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import platform
import re
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx
import logging

logging.getLogger("httpx").setLevel(logging.WARNING)

SNYK_BASE = "https://static.snyk.io/cli/latest"
URL_RE = re.compile(r"https://\S+")


# --- Where things live ------------------------------------------------------------------

def cache_dir() -> Path:
    override = os.environ.get("SVD_CACHE_DIR", "").strip()
    if override:
        d = Path(override).expanduser()
        d.mkdir(parents=True, exist_ok=True)
        return d
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    elif os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    d = base / "secure-vibe-delivery"
    d.mkdir(parents=True, exist_ok=True)
    return d


def snyk_asset() -> Optional[str]:
    """Name of Snyk's standalone build for this machine (None if Snyk doesn't publish one)."""
    machine = platform.machine().lower()
    arm = machine in ("arm64", "aarch64")
    if sys.platform == "darwin":
        return "snyk-macos-arm64" if arm else "snyk-macos"
    if os.name == "nt":
        return "snyk-win.exe"  # no ARM build; Windows on ARM runs the x64 one
    if sys.platform.startswith("linux"):
        if Path("/etc/alpine-release").exists():
            return "snyk-alpine"
        return "snyk-linux-arm64" if arm else "snyk-linux"
    return None


def cached_snyk() -> Optional[Path]:
    p = cache_dir() / "bin" / ("snyk.exe" if os.name == "nt" else "snyk")
    return p if p.exists() else None


# --- Snyk download ----------------------------------------------------------------------

async def install_snyk(progress: Optional[callable] = None) -> Path:
    asset = snyk_asset()
    if not asset:
        raise RuntimeError(f"Snyk doesn't publish a standalone build for {sys.platform}/{platform.machine()}")
    bin_dir = cache_dir() / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    dest = bin_dir / ("snyk.exe" if os.name == "nt" else "snyk")
    tmp = dest.with_suffix(".download")
    async with httpx.AsyncClient(timeout=httpx.Timeout(30, read=120), follow_redirects=True,
                                 headers={"User-Agent": "secure-vibe-delivery"}) as client:
        r = await client.get(f"{SNYK_BASE}/{asset}.sha256")
        r.raise_for_status()
        expected = r.text.split()[0].strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise RuntimeError("Snyk's checksum file had an unexpected format")
        h = hashlib.sha256()
        done = 0
        async with client.stream("GET", f"{SNYK_BASE}/{asset}") as resp:
            resp.raise_for_status()
            with tmp.open("wb") as fh:
                async for chunk in resp.aiter_bytes(1 << 20):
                    fh.write(chunk)
                    h.update(chunk)
                    done += len(chunk)
                    if progress:
                        progress(done)
    if h.hexdigest() != expected:
        tmp.unlink(missing_ok=True)
        raise RuntimeError("The downloaded Snyk didn't match Snyk's published checksum, so it was deleted")
    tmp.chmod(tmp.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    tmp.replace(dest)
    proc = await asyncio.create_subprocess_exec(str(dest), "--version", stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.PIPE)
    out, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
    if proc.returncode != 0:
        raise RuntimeError("Snyk was downloaded but won't start on this machine")
    return dest


# --- Background sign-ins ----------------------------------------------------------------

@dataclass
class SignIn:
    tool: str
    state: str = "idle"  # idle | starting | waiting_for_browser | signed_in | failed | manual
    url: str = ""
    detail: str = ""
    started_at: float = 0.0
    proc: object = None
    output: list = field(default_factory=list)


def _snyk_cmd() -> Optional[list[str]]:
    from .proc import resolve_tool
    return resolve_tool("snyk")


def _semgrep_cmd() -> Optional[list[str]]:
    from .proc import resolve_tool
    return resolve_tool("semgrep")


def semgrep_login_command() -> str:
    """The PowerShell line a person types to sign in to Semgrep, using the same program the server
    found. A bare name only when PowerShell will find that name on PATH; otherwise the full path,
    so it still works when uvx.exe isn't on PATH (e.g. after `pip install --user uv`)."""
    import shutil
    cmd = _semgrep_cmd()
    if not cmd:
        return "uvx semgrep login"
    exe, rest = cmd[0], cmd[1:]
    name = Path(exe).stem
    on_path = shutil.which(name)
    head = name if on_path and Path(on_path).resolve() == Path(exe).resolve() else f'& "{exe}"'
    return " ".join([head, *rest, "login"])


def start_snyk_auth(si: SignIn) -> None:
    """`snyk auth` works without a terminal: it prints a link, opens the browser and waits."""
    cmd = _snyk_cmd()
    if not cmd:
        si.state, si.detail = "failed", "Snyk isn't installed yet"
        return
    si.state, si.started_at, si.url, si.output = "starting", time.time(), "", []
    p = subprocess.Popen([*cmd, "auth"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, errors="replace")
    si.proc = p

    def pump():
        for line in p.stdout:
            si.output.append(line.rstrip())
            m = URL_RE.search(line)
            if m and not si.url:
                si.url, si.state = m.group(0), "waiting_for_browser"
        p.wait()
        si.state = "signed_in" if p.returncode == 0 else "failed"
        if p.returncode != 0:
            si.detail = " ".join(si.output[-3:])[:300]
    threading.Thread(target=pump, daemon=True).start()


def start_semgrep_login(si: SignIn) -> None:
    """`semgrep login` insists on a terminal, so give it a pseudo-terminal (macOS/Linux).
    Windows has no pseudo-terminal: there the person runs one command themselves."""
    cmd = _semgrep_cmd()
    if not cmd:
        si.state, si.detail = "failed", "Semgrep isn't available (install uv, or brew install semgrep)"
        return
    if os.name == "nt":
        si.state = "manual"
        si.detail = ("On Windows, Semgrep's sign-in needs a terminal window. Open PowerShell and run: "
                     + semgrep_login_command())
        return
    import pty
    import select
    si.state, si.started_at, si.url, si.output = "starting", time.time(), "", []
    master, slave = pty.openpty()
    p = subprocess.Popen([*cmd, "login"], stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    si.proc = p

    def pump():
        buf = ""
        while True:
            r, _, _ = select.select([master], [], [], 1.0)
            if r:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk.decode(errors="replace")
                m = URL_RE.search(buf)
                if m and not si.url:
                    si.url, si.state = m.group(0).rstrip(".,)"), "waiting_for_browser"
            elif p.poll() is not None:
                break
        p.wait()
        os.close(master)
        si.output = buf.splitlines()[-5:]
        si.state = "signed_in" if p.returncode == 0 else "failed"
        if p.returncode != 0:
            si.detail = " ".join(si.output)[:300]
    threading.Thread(target=pump, daemon=True).start()


# --- Status checks ----------------------------------------------------------------------

async def snyk_signed_in() -> Optional[bool]:
    """True/False, or None when Snyk isn't installed."""
    from .proc import run_cmd
    cmd = _snyk_cmd()
    if not cmd:
        return None
    if os.environ.get("SNYK_TOKEN", "").strip():
        return True
    p = await run_cmd([*cmd, "whoami", "--experimental"], Path.home(), timeout=60)
    return p.exit_code == 0 and bool(p.stdout.strip())


SNYK_CODE_OFF = re.compile(r"not (?:been )?enabled|enable (?:it|snyk code)|not supported for (?:your|this) "
                           r"(?:current )?org|snyk code is disabled", re.I)
SNYK_CODE_HOWTO = ("In your browser, go to app.snyk.io, open Settings, choose Snyk Code, switch on the "
                   "\"Enable Snyk Code\" toggle, and click Save changes.")


async def snyk_code_enabled() -> Optional[bool]:
    """Run Snyk Code on a two-line throwaway file. True if it scans, False if Snyk says Snyk Code is
    switched off for the organisation, None if it can't tell (for example, no network)."""
    import tempfile
    from .proc import run_cmd
    cmd = _snyk_cmd()
    if not cmd:
        return None
    with tempfile.TemporaryDirectory(prefix="svd-snyk-code-") as d:
        Path(d, "probe.py").write_text("def add(a, b):\n    return a + b\n")
        p = await run_cmd([*cmd, "code", "test", "--json"], d, timeout=180)
    if p.exit_code in (0, 1) and "runs" in p.stdout:
        return True
    if SNYK_CODE_OFF.search(p.stdout + p.stderr):
        return False
    return None


async def semgrep_signed_in() -> Optional[bool]:
    from .proc import run_cmd
    cmd = _semgrep_cmd()
    if not cmd:
        return None
    if os.environ.get("SEMGREP_APP_TOKEN", "").strip():
        return True
    p = await run_cmd([*cmd, "show", "deployment"], Path.home(), timeout=120)
    return p.exit_code == 0 and "{" in p.stdout + p.stderr

