"""Environment checks: which tools are installed, authenticated and usable."""
from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

from .detect import detect
from .proc import resolve_tool, run_cmd


def _first_version(text: str) -> str:
    m = re.search(r"\d+\.\d+(?:\.\d+)?", text)
    return m.group(0) if m else text.strip()[:40]


async def tool_versions(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in ("snyk", "semgrep", "locust"):
        cmd = resolve_tool(name)
        if not cmd:
            out[name] = "missing"
            continue
        p = await run_cmd([*cmd, "--version"], root, timeout=180)
        out[name] = _first_version(p.stdout or p.stderr) if p.exit_code == 0 else "error"
        if cmd[0].endswith("uvx"):
            out[name] += " (via uvx)"
    return out


async def doctor(project_path: str) -> dict:
    root = Path(project_path).expanduser().resolve()
    if not root.is_dir():
        return {"ok": False, "error": f"{root} is not a directory"}
    info = detect(root)
    versions = await tool_versions(root)
    report: dict = {"project": str(root), "tools": {}, "project_detection": {}, "actions": []}
    tools = report["tools"]

    # Snyk
    tools["snyk"] = {"version": versions["snyk"]}
    if versions["snyk"] == "missing":
        report["actions"].append("Install Snyk CLI: brew tap snyk/tap && brew install snyk (or npm i -g snyk)")
    else:
        snyk = resolve_tool("snyk")
        who = await run_cmd([*snyk, "whoami", "--experimental"], root, timeout=60)
        authed = who.exit_code == 0 and bool(who.stdout.strip())
        tools["snyk"]["authenticated"] = authed or bool(os.environ.get("SNYK_TOKEN"))
        if not tools["snyk"]["authenticated"]:
            report["actions"].append("Authenticate Snyk: run `snyk auth`, or set SNYK_TOKEN in the MCP server's env")
        sec = await run_cmd([*snyk, "secrets", "test", "--json"], root, timeout=180)
        from .checks.snyk import secrets_unavailable
        reason = secrets_unavailable(sec.stdout, sec.stderr, sec.exit_code)
        tools["snyk"]["secrets"] = "available" if reason is None else f"unavailable: {reason[:200]}"
        if reason:
            tools["snyk"]["secrets_fallback"] = "Semgrep p/secrets + bundled svd-secrets rules"

    tools["semgrep"] = {"version": versions["semgrep"]}
    if versions["semgrep"] == "missing":
        report["actions"].append("Install Semgrep: brew install semgrep (or install uv so it runs via uvx)")
    tools["locust"] = {"version": versions["locust"]}
    if versions["locust"] == "missing":
        report["actions"].append("Install Locust: pip install locust (or install uv so it runs via uvx)")
    tools["uv"] = {"available": bool(shutil.which("uvx"))}

    det = report["project_detection"]
    det.update(python=info.is_python, javascript=info.is_js, test_runner=info.test_runner,
               locustfile=str(info.locustfile) if info.locustfile else None,
               openapi=str(info.openapi_file) if info.openapi_file else None,
               project_svd_rules=str(info.svd_rules_dir) if info.svd_rules_dir else None)
    if info.test_runner == "pytest":
        det["python"] = " ".join(info.python_cmd)
        probe = await run_cmd([*info.python_cmd, "-c",
                               "import importlib.util as u;print(*[m for m in ('pytest','pytest_cov','pip') "
                               "if u.find_spec(m)])"], root, timeout=60)
        have = probe.stdout.split()
        det["pytest"], det["pytest_cov"], det["pip_in_env"] = "pytest" in have, "pytest_cov" in have, "pip" in have
        if not det["pytest"] or not det["pytest_cov"]:
            report["actions"].append(f"Install test tools in the project env: {info.python_cmd[0]} -m pip install pytest pytest-cov")
        if not det["pip_in_env"]:
            report["actions"].append("Snyk Open Source needs pip inside the project venv: "
                                     f"{info.python_cmd[0]} -m ensurepip (or uv pip install pip)")
    elif info.test_runner == "jest":
        det["jest_installed"] = (root / "node_modules" / ".bin" / "jest").exists()
        if not det["jest_installed"]:
            report["actions"].append("Install Jest: npm install --save-dev jest")
    else:
        report["actions"].append("No test suite detected; the functional check will be NOT_RUN (a failure).")
    if not info.locustfile:
        report["actions"].append("No locustfile.py: one will be generated (svd_generate_locustfile to review it first).")
    report["ok"] = not any(a.startswith(("Install Snyk", "Authenticate", "Install Semgrep")) for a in report["actions"])
    return report
