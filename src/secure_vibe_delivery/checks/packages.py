"""Package provenance: every direct dependency must exist and not be brand-new.

Guards against "slopsquatting": AI tools suggest packages that don't exist, and attackers
register those names. Only package names are sent to the public registries.
"""
from __future__ import annotations

import asyncio
import json
import re
import tomllib
from datetime import datetime, timezone
from pathlib import Path

import httpx

from ..models import Finding

NEW_PACKAGE_DAYS = 30
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def python_deps(root: Path) -> set[str]:
    names: set[str] = set()
    for req in list(root.glob("requirements*.txt")) + list(root.glob("requirements/*.txt")):
        for line in req.read_text(errors="ignore").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "git+", "http")):
                continue
            m = _REQ_LINE.match(line)
            if m:
                names.add(_norm_py(m.group(1)))
    pp = root / "pyproject.toml"
    if pp.exists():
        try:
            data = tomllib.loads(pp.read_text())
            deps = list(data.get("project", {}).get("dependencies", []))
            for group in data.get("project", {}).get("optional-dependencies", {}).values():
                deps += group
            for group in data.get("dependency-groups", {}).values():
                deps += [d for d in group if isinstance(d, str)]
            poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            deps += [k for k in poetry if k.lower() != "python"]
            for d in deps:
                m = _REQ_LINE.match(d)
                if m:
                    names.add(_norm_py(m.group(1)))
        except (tomllib.TOMLDecodeError, OSError):
            pass
    return names


def js_deps(root: Path) -> set[str]:
    pj = root / "package.json"
    if not pj.exists():
        return set()
    try:
        data = json.loads(pj.read_text())
    except (json.JSONDecodeError, OSError):
        return set()
    out = set()
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (data.get(key) or {}).items():
            if isinstance(spec, str) and spec.startswith(("file:", "link:", "workspace:", "git", "http")):
                continue
            out.add(name)
    return out


async def _pypi(client: httpx.AsyncClient, name: str) -> tuple[str, str, int | None]:
    r = await client.get(f"https://pypi.org/pypi/{name}/json")
    if r.status_code == 404:
        return "pypi", name, None
    r.raise_for_status()
    times = [f["upload_time_iso_8601"] for files in r.json().get("releases", {}).values() for f in files
             if f.get("upload_time_iso_8601")]
    if not times:
        return "pypi", name, -1
    first = min(datetime.fromisoformat(t.replace("Z", "+00:00")) for t in times)
    return "pypi", name, (datetime.now(timezone.utc) - first).days


async def _npm(client: httpx.AsyncClient, name: str) -> tuple[str, str, int | None]:
    r = await client.get(f"https://registry.npmjs.org/{name.replace('/', '%2F')}",
                         headers={"Accept": "application/vnd.npm.install-v1+json; q=1.0, application/json"})
    if r.status_code == 404:
        return "npm", name, None
    r.raise_for_status()
    created = (r.json().get("time") or {}).get("created")
    if not created:
        r2 = await client.get(f"https://registry.npmjs.org/{name.replace('/', '%2F')}")
        created = (r2.json().get("time") or {}).get("created") if r2.status_code == 200 else None
    if not created:
        return "npm", name, -1
    first = datetime.fromisoformat(created.replace("Z", "+00:00"))
    return "npm", name, (datetime.now(timezone.utc) - first).days


async def check(root: Path) -> tuple[list[Finding], dict]:
    py, js = sorted(python_deps(root)), sorted(js_deps(root))
    meta = {"python_packages": len(py), "npm_packages": len(js), "lookup_errors": []}
    if not py and not js:
        return [], meta
    sem = asyncio.Semaphore(8)
    async with httpx.AsyncClient(timeout=15, headers={"User-Agent": "secure-vibe-delivery"}) as client:
        async def guarded(fn, n):
            async with sem:
                try:
                    return await fn(client, n)
                except (httpx.HTTPError, ValueError) as e:
                    meta["lookup_errors"].append(f"{n}: {type(e).__name__}")
                    return None
        results = await asyncio.gather(*[guarded(_pypi, n) for n in py], *[guarded(_npm, n) for n in js])
    findings = []
    for res in results:
        if res is None:
            continue
        registry, name, age = res
        if age is None:
            findings.append(Finding(
                tool="svd-provenance", category="package", rule_id="unknown-package", severity="critical",
                title=f"Package does not exist on {registry}", package=name, sources=["svd-provenance"],
                message=f"'{name}' was not found on the public {registry} registry. It may be an AI-invented "
                        f"name that an attacker could register.",
                fix_hint="Remove it, or confirm it comes from a private registry you control."))
        elif 0 <= age < NEW_PACKAGE_DAYS:
            findings.append(Finding(
                tool="svd-provenance", category="package", rule_id="brand-new-package", severity="high",
                title=f"Package first published {age} day(s) ago", package=name, sources=["svd-provenance"],
                message=f"'{name}' first appeared on {registry} {age} day(s) ago (under {NEW_PACKAGE_DAYS}).",
                fix_hint="Check the maintainer and source repository before trusting it."))
    meta["checked"] = len([r for r in results if r])
    return findings, meta
