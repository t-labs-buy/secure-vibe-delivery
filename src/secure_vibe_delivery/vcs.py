"""Which version of the code a run checked: git commit, branch, uncommitted changes.

A go-live sign-off has to name exactly what it covers. We read this when the run starts and again
when it ends, so the report can also say if the code changed while the checks were running.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from .proc import resolve_tool, run_cmd

MAX_LISTED = 25
_OWN_OUTPUT = (".svd/", ".svd")


def _redact_remote(url: str) -> str:
    """Drop any user:token@ part of a remote URL."""
    return re.sub(r"(https?://)[^/@\s]+@", r"\1", url.strip())


async def _git(git: list[str], root: Path, *args: str) -> tuple[int, str]:
    p = await run_cmd([*git, *args], root, timeout=30)
    return (p.exit_code if p.exit_code is not None else -1), p.stdout


async def snapshot(root: Path) -> dict:
    """{"is_git": bool, "commit", "short", "branch", "subject", "committed_at", "remote",
        "dirty": bool, "changed": [paths], "changed_count", "untracked_count", "reason"}"""
    git = resolve_tool("git")
    if not git:
        return {"is_git": False, "reason": "git is not installed, so the code version couldn't be recorded"}
    code, out = await _git(git, root, "rev-parse", "--show-toplevel")
    if code != 0:
        return {"is_git": False, "reason": "This folder isn't a git repository, so the report can't name the "
                                           "exact code version it checked"}
    info: dict = {"is_git": True, "repo_root": out.strip()}
    try:
        sub = Path(root).resolve().relative_to(Path(out.strip()).resolve()).as_posix()
    except ValueError:
        sub = ""
    info["subfolder"] = "" if sub == "." else sub
    code, out = await _git(git, root, "rev-parse", "HEAD")
    if code != 0:
        info.update(commit="", short="", reason="The repository has no commits yet")
    else:
        info["commit"] = out.strip()
        info["short"] = info["commit"][:12]
        code, out = await _git(git, root, "log", "-1", "--format=%cI%n%s")
        if code == 0:
            parts = out.split("\n", 1)
            info["committed_at"] = parts[0].strip()
            info["subject"] = (parts[1].strip() if len(parts) > 1 else "")[:200]
    code, out = await _git(git, root, "rev-parse", "--abbrev-ref", "HEAD")
    branch = out.strip() if code == 0 else ""
    info["branch"] = "" if branch == "HEAD" else branch
    info["detached"] = branch == "HEAD"
    code, out = await _git(git, root, "remote", "get-url", "origin")
    info["remote"] = _redact_remote(out) if code == 0 and out.strip() else ""
    # -z keeps unusual file names intact; -uall lists files inside new folders
    # Only the project folder counts: in a larger repository, changes elsewhere don't affect what was checked.
    # (Paths in the output stay relative to the repository root.)
    code, out = await _git(git, root, "status", "--porcelain=v1", "-z", "-uall", "--", ".")
    changed, untracked = [], 0
    if code == 0:
        entries = out.split("\0")
        i = 0
        while i < len(entries):
            e = entries[i]
            i += 1
            if len(e) < 4:
                continue
            status, path = e[:2], e[3:]
            if status[0] in "RC":  # renames carry the old path in the next entry
                i += 1
            if path.startswith(_OWN_OUTPUT) or "/.svd/" in path:
                continue  # this server's own output folder
            if status == "??":
                untracked += 1
            changed.append(f"{status.strip() or '?'} {path}")
    info["changed_count"] = len(changed)
    info["untracked_count"] = untracked
    info["changed"] = changed[:MAX_LISTED]
    info["dirty"] = bool(changed)
    return info


def fingerprint(s: dict) -> Optional[tuple]:
    if not s.get("is_git"):
        return None
    return (s.get("commit"), s.get("changed_count"), tuple(s.get("changed", [])))


def changed_during_run(start: dict, end: dict) -> bool:
    a, b = fingerprint(start), fingerprint(end)
    return a is not None and b is not None and a != b


def describe(s: dict) -> str:
    """One line for the run log."""
    if not s.get("is_git"):
        return s.get("reason", "Not a git repository")
    where = s.get("branch") or ("detached HEAD" if s.get("detached") else "")
    line = f"Code version: commit {s.get('short') or '(none)'}" + (f" on {where}" if where else "")
    if s.get("dirty"):
        line += f", with {s['changed_count']} uncommitted change(s) ({s.get('untracked_count', 0)} new file(s))"
    else:
        line += ", no uncommitted changes"
    return line
