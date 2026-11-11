"""Environment checks: which tools are installed, authenticated and usable."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .checks.functional import unsafe_pytest_files
from .config import ConfigError, load as load_config
from .detect import detect
from .proc import UVX_FALLBACK, find_uv_runner, resolve_tool, run_cmd


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
        if name in UVX_FALLBACK and cmd[-1] == UVX_FALLBACK[name] and len(cmd) > 1:
            out[name] += " (via uvx)"
    return out


async def semgrep_account(root: Path) -> dict:
    """Which Semgrep account and organisation the CLI is using (SEMGREP_APP_TOKEN or `semgrep login`)."""
    sg = resolve_tool("semgrep")
    p = await run_cmd([*sg, "show", "deployment"], root, timeout=60)
    m = re.search(r"\{.*\}", p.stdout + p.stderr, re.S)
    if p.exit_code != 0 or not m:
        if os.environ.get("SEMGREP_APP_TOKEN") and re.search(r"\b40[13]\b", p.stdout + p.stderr):
            return {"logged_in": False, "token_rejected": True}
        return {"logged_in": False,
                "note": "Not logged in: free rules still run; source lines are hidden in Semgrep output"}
    try:
        info = json.loads(m.group(0))
    except json.JSONDecodeError:
        return {"logged_in": True}
    return {"logged_in": True, "organisation": info.get("display_name") or info.get("name"),
            "org_slug": info.get("slug"),
            "token_source": "SEMGREP_APP_TOKEN" if os.environ.get("SEMGREP_APP_TOKEN") else "semgrep login"}


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
        report["actions"].append("Install Snyk: offer the guided one-time setup (svd_setup walks the person "
                                 "through it step by step), or install it yourself with brew tap snyk/tap && "
                                 "brew install snyk")
    else:
        snyk = resolve_tool("snyk")
        who = await run_cmd([*snyk, "whoami", "--experimental"], root, timeout=60)
        authed = who.exit_code == 0 and bool(who.stdout.strip())
        tools["snyk"]["authenticated"] = authed or bool(os.environ.get("SNYK_TOKEN"))
        if not tools["snyk"]["authenticated"]:
            report["actions"].append("Authenticate Snyk: offer the guided one-time setup (svd_setup, step by "
                                     "step), or run `snyk auth` yourself")
        from .checks import snyk as snyk_mod
        tools["snyk"]["org"] = snyk_mod.org() or "account default (set SVD_SNYK_ORG to pin one)"
        sec = await run_cmd([*snyk, "secrets", "test", "--json", *snyk_mod.org_args()], root, timeout=180)
        reason = snyk_mod.secrets_unavailable(sec.stdout, sec.stderr, sec.exit_code)
        if reason and snyk_mod.org_hint(reason):
            tools["snyk"]["org_access"] = False
            report["actions"].append(snyk_mod.org_hint(reason).replace(" Hint: the", "The").strip())
        elif snyk_mod.org():
            tools["snyk"]["org_access"] = True
        tools["snyk"]["secrets"] = "available" if reason is None else f"unavailable: {reason[:200]}"
        if reason:
            tools["snyk"]["secrets_fallback"] = "Semgrep p/secrets + bundled svd-secrets rules"

    tools["semgrep"] = {"version": versions["semgrep"]}
    if versions["semgrep"] == "missing":
        report["actions"].append("Install Semgrep: brew install semgrep (or install uv so it runs via uvx)")
    else:
        tools["semgrep"].update(await semgrep_account(root))
        if not tools["semgrep"].get("logged_in") and not tools["semgrep"].get("token_rejected"):
            report["actions"].append("Recommended: a free Semgrep sign-in gives more detailed results. Use "
                                     "the optional step in svd_setup, or run `semgrep login` yourself.")
        if tools["semgrep"].get("token_rejected"):
            report["actions"].append("Semgrep rejected SEMGREP_APP_TOKEN (HTTP 403: invalid or revoked). The code scan "
                                     "will fail until it's fixed. Get the current company token, or unset it.")
        expected = os.environ.get("SVD_SEMGREP_ORG", "").strip()
        got = tools["semgrep"].get("organisation")
        if expected and got != expected and tools["semgrep"].get("org_slug") != expected:
            report["actions"].append(
                f"Semgrep is logged in to organisation '{got or 'none'}', not '{expected}'. Set SEMGREP_APP_TOKEN "
                "to a token from the company Semgrep organisation, or run `semgrep login` with that account.")
    tools["locust"] = {"version": versions["locust"]}
    if versions["locust"] == "missing":
        report["actions"].append("Install Locust: pip install locust (or install uv so it runs via uvx)")
    runner = find_uv_runner()
    tools["uv"] = {"available": bool(runner), **({"path": runner[0]} if runner else {})}

    det = report["project_detection"]
    try:
        cfg = load_config(root)
    except ConfigError as e:
        cfg = None
        report["actions"].append(f"Fix the project settings file: {e}")
    det.update(python=info.is_python, javascript=info.is_js, test_runner=info.test_runner,
               test_runners=info.test_runners,
               jest_folders=[d.relative_to(root).as_posix() or "." for d in info.jest_dirs],
               locustfile=str(info.locustfile) if info.locustfile else None,
               openapi=str(info.openapi_file) if info.openapi_file else None,
               project_svd_rules=str(info.svd_rules_dir) if info.svd_rules_dir else None,
               skipped_by_scanners=info.venvs + (cfg.exclude if cfg else []),
               settings_file=str(cfg.path) if cfg and cfg.path else None)
    if cfg and cfg.suites:
        det["test_suites_from_settings"] = [{"name": s.name, "command": s.command} for s in cfg.suites]
    elif "pytest" in info.test_runners:
        unsafe = unsafe_pytest_files(root)
        if unsafe and not (cfg and cfg.allow_unsafe_pytest):
            det["pytest_refused"] = [h["file"] for h in unsafe]
            report["actions"].append(
                f"The functional check won't run pytest: {len(unsafe)} test file(s) use nose-style setup()/"
                "teardown(), which pytest 8 doesn't call, so they'd run without their isolation"
                + (" and some of them wipe data" if any(h["destructive"] for h in unsafe) else "")
                + ". Add the command the project really uses to .svd.toml as a [[functional.suite]].")
    if cfg and cfg.locustfile:
        det["locustfile"] = str(root / cfg.locustfile)
    if "pytest" in info.test_runners and not (cfg and cfg.suites):
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
    if "jest" in info.test_runners and not (cfg and cfg.suites):
        missing = [d for d in info.jest_dirs
                   if not any((d / "node_modules" / ".bin" / n).exists() for n in ("jest", "jest.cmd"))]
        det["jest_installed"] = not missing
        for d in missing:
            report["actions"].append(f"Install Jest in {d.relative_to(root).as_posix() or '.'}: npm install --save-dev jest")
    if not info.has_tests and not (cfg and cfg.suites):
        report["actions"].append("No test suite detected; the functional check will be NOT_RUN (a failure).")
    if not info.locustfile and not (cfg and cfg.locustfile):
        report["actions"].append("No locustfile.py: one will be generated (svd_generate_locustfile to review it first).")
    report["ok"] = not any(a.startswith(("Install Snyk", "Authenticate", "Install Semgrep", "The Snyk token", "Semgrep rejected")) for a in report["actions"])
    return report
