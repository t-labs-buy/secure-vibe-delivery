"""Snyk Open Source, Snyk Code and Snyk Secrets: commands and parsers."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from ..models import Finding, SecretFinding, norm_severity
from .secrets_util import masked_from_source

EXCLUDES = ".venv,venv,env,node_modules,.svd,dist,build"
SECRET_RULE = re.compile(r"Hardcoded.*(Secret|Password|Credential|Key|Token)|Secret|Password", re.I)


def _load_json(text: str) -> Any:
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Snyk occasionally prints banners before the JSON document
        i = min([p for p in (text.find("{"), text.find("[")) if p >= 0], default=-1)
        if i < 0:
            return None
        try:
            return json.loads(text[i:])
        except json.JSONDecodeError:
            return None


def open_source_argv(snyk: list[str], python_cmd: Optional[list[str]]) -> list[str]:
    argv = [*snyk, "test", "--all-projects", f"--exclude={EXCLUDES}", "--json"]
    if python_cmd and len(python_cmd) == 1 and Path(python_cmd[0]).exists():
        argv.append(f"--command={python_cmd[0]}")
    return argv


def parse_open_source(stdout: str) -> tuple[Optional[str], list[Finding], dict]:
    """Returns (error, findings, meta). error is set if the scan could not run."""
    data = _load_json(stdout)
    if data is None:
        return "Snyk produced no JSON output", [], {}
    projects = data if isinstance(data, list) else [data]
    findings: dict[tuple, Finding] = {}
    errors, meta = [], {"projects": [], "dependency_count": 0}
    for p in projects:
        if p.get("error") and not p.get("vulnerabilities"):
            errors.append(p["error"])
            continue
        meta["projects"].append(p.get("displayTargetFile") or p.get("projectName") or "")
        meta["dependency_count"] += int(p.get("dependencyCount") or 0)
        for v in p.get("vulnerabilities", []):
            key = (v.get("id"), v.get("packageName"), v.get("version"))
            sev = norm_severity(v.get("severityWithCritical") or v.get("severity"))
            if v.get("malicious"):
                sev = "critical"
            ids = v.get("identifiers") or {}
            f = findings.get(key)
            if f is None:
                fixed = v.get("fixedIn") or []
                upgrade = [u for u in (v.get("upgradePath") or []) if u]
                hint = (f"Upgrade {v.get('packageName')} to {', '.join(fixed)}" if fixed
                        else "No fixed version yet: consider an alternative package or an approved exception")
                if upgrade:
                    hint += f" (upgrade path: {upgrade[0]})"
                f = Finding(
                    tool="snyk-open-source", category="library", rule_id=v.get("id", ""), severity=sev,
                    title=v.get("title", ""), package=v.get("packageName", ""), version=v.get("version", ""),
                    fixed_in=fixed, identifiers=(ids.get("CVE") or []) + (ids.get("GHSA") or [])[:1],
                    cwe=ids.get("CWE") or [], fix_hint=hint, sources=["snyk-open-source"],
                    url=f"https://security.snyk.io/vuln/{v.get('id', '')}",
                    message=" → ".join(v.get("from", [])[1:]) if v.get("from") else "",
                )
                findings[key] = f
    if errors and not meta["projects"]:
        return "; ".join(errors), [], meta
    if errors:
        meta["partial_errors"] = errors
    return None, list(findings.values()), meta


def parse_code(stdout: str, root: Path) -> tuple[Optional[str], list[Finding], list[SecretFinding]]:
    data = _load_json(stdout)
    if data is None:
        return "Snyk Code produced no JSON output", [], []
    if isinstance(data, dict) and data.get("ok") is False and data.get("error"):
        return data["error"], [], []
    findings: list[Finding] = []
    secrets: list[SecretFinding] = []
    for run in data.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rule = rules.get(res.get("ruleId"), {})
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            rel = loc.get("artifactLocation", {}).get("uri", "")
            region = loc.get("region", {})
            line = int(region.get("startLine") or 0)
            title = rule.get("shortDescription", {}).get("text") or rule.get("name", "")
            msg = res.get("message", {}).get("text", "")
            if SECRET_RULE.search(res.get("ruleId", "")) and "Hardcoded" in res.get("ruleId", ""):
                secrets.append(SecretFinding(
                    scanner="snyk-code", rule_id=res.get("ruleId", ""), kind=title or "Hard-coded secret",
                    file=rel, line=line, message=msg, sources=["snyk-code"],
                    masked_value=masked_from_source(root, rel, line, region.get("startColumn", 0),
                                                    (region.get("endColumn") or 0) + 1),
                ))
                continue
            findings.append(Finding(
                tool="snyk-code", category="code", rule_id=res.get("ruleId", ""),
                severity=norm_severity(res.get("level")), title=title, message=msg, file=rel, line=line,
                cwe=rule.get("properties", {}).get("cwe", []), sources=["snyk-code"],
                fix_hint=_first_prevention_tip(rule.get("help", {}).get("markdown", "")),
            ))
    return None, findings, secrets


def _first_prevention_tip(md: str) -> str:
    m = re.search(r"## Best practices for prevention\s*\n(.*?)(?:\n\n|\Z)", md, re.S)
    if not m:
        return ""
    tips = [t.strip("-* ").strip() for t in m.group(1).splitlines() if t.strip().startswith(("-", "*"))]
    return " ".join(tips[:2])[:400]


def secrets_unavailable(stdout: str, stderr: str, exit_code: Optional[int]) -> Optional[str]:
    """Return a reason string if `snyk secrets test` is not usable on this install/plan."""
    data = _load_json(stdout)
    if isinstance(data, dict) and data.get("ok") is False and data.get("error"):
        return data["error"]
    blob = (stdout + stderr).lower()
    if "unknown command" in blob or "description: help reference" in blob or "cli help" in blob:
        return "`snyk secrets` is not available in this Snyk CLI version"
    if exit_code not in (0, 1):
        return f"`snyk secrets test` exited with code {exit_code}"
    return None


def parse_secrets(stdout: str, root: Path) -> list[SecretFinding]:
    """Snyk Secrets emits SARIF like Snyk Code."""
    data = _load_json(stdout) or {}
    out: list[SecretFinding] = []
    for run in data.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            rel = loc.get("artifactLocation", {}).get("uri", "")
            region = loc.get("region", {})
            line = int(region.get("startLine") or 0)
            rule = rules.get(res.get("ruleId"), {})
            out.append(SecretFinding(
                scanner="snyk-secrets", rule_id=res.get("ruleId", ""),
                kind=rule.get("shortDescription", {}).get("text") or res.get("ruleId", ""),
                file=rel, line=line, message=res.get("message", {}).get("text", ""), sources=["snyk-secrets"],
                masked_value=masked_from_source(root, rel, line, region.get("startColumn", 0),
                                                (region.get("endColumn") or 0) + 1),
            ))
    return out
