"""Snyk IaC: risky settings in infrastructure files (Terraform, Kubernetes, CloudFormation, Azure ARM).

The check only runs when such files exist. We find them ourselves and pass them to Snyk by name,
so virtual environments and node_modules (which often ship sample YAML) are never scanned.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ..detect import iter_files
from ..models import Finding, norm_severity
from .snyk import _load_json, org_args

MAX_FILES = 300
_K8S = re.compile(r"^\s*apiVersion\s*:", re.M)
_K8S_KIND = re.compile(r"^\s*kind\s*:\s*\w+", re.M)
_CFN = re.compile(r"AWSTemplateFormatVersion|^\s*Type\s*:\s*['\"]?AWS::|\"Type\"\s*:\s*\"AWS::", re.M)
_ARM = re.compile(r"schema\.management\.azure\.com/schemas/[^\"]*deploymentTemplate", re.I)
_HELM_SKIP = re.compile(r"\{\{")  # unrendered Helm templates aren't valid YAML for Snyk


def kind_of(path: Path, text: str) -> Optional[str]:
    """Which IaC format a file is, or None."""
    if path.suffix == ".tf":
        return "terraform"
    if path.suffix in (".yaml", ".yml"):
        if _CFN.search(text):
            return "cloudformation"
        if _K8S.search(text) and _K8S_KIND.search(text) and not _HELM_SKIP.search(text):
            return "kubernetes"
    if path.suffix == ".json":
        if _ARM.search(text):
            return "arm"
        if _CFN.search(text):
            return "cloudformation"
        if '"apiVersion"' in text and '"kind"' in text:
            return "kubernetes"
    return None


def find_files(root: Path) -> list[tuple[str, str]]:
    """[(path relative to root, kind)] for every infrastructure file Snyk IaC can scan."""
    out = []
    for f in iter_files(root, (".tf", ".yaml", ".yml", ".json"), limit=5000):
        if f.name in ("package.json", "package-lock.json", "tsconfig.json", "composer.json") or \
                f.name.startswith(("svd-", ".")) or "locust" in f.name:
            continue
        try:
            if f.stat().st_size > 2_000_000:
                continue
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        k = kind_of(f, text)
        if k:
            out.append((f.relative_to(root).as_posix(), k))
    return sorted(out)[:MAX_FILES]


def argv(snyk: list[str], files: list[str]) -> list[str]:
    return [*snyk, "iac", "test", *files, "--json", "--severity-threshold=low", *org_args()]


def _error_text(stdout: str, stderr: str, exit_code: Optional[int]) -> str:
    text = (stdout or "") + "\n" + (stderr or "")
    if re.search(r"SNYK-0005|Authentication (error|credentials)|not authenticated|snyk auth", text, re.I):
        return "Snyk isn't signed in (or the sign-in expired): run svd_setup, or `snyk auth`"
    if "FailedToGetIacOrgSettings" in text:
        return "Snyk couldn't read the organisation's IaC settings (usually an expired sign-in or no access to the organisation)"
    line = next((l.strip() for l in text.splitlines() if l.strip()), "")
    return line[:300] or f"snyk iac test failed (exit code {exit_code})"


def parse(stdout: str, stderr: str = "", exit_code: Optional[int] = 0) -> tuple[Optional[str], list[Finding], dict]:
    """Returns (error, findings, meta). error is set when the scan couldn't run."""
    data = _load_json(stdout)
    if data is None:
        return _error_text(stdout, stderr, exit_code), [], {}
    results = data if isinstance(data, list) else [data]
    findings: list[Finding] = []
    meta: dict = {"files_scanned": 0, "file_errors": []}
    errors = []
    for r in results:
        if not isinstance(r, dict):
            continue
        issues = r.get("infrastructureAsCodeIssues")
        if issues is None:
            if r.get("error"):
                errors.append(str(r["error"]))
                meta["file_errors"].append(f"{r.get('path') or r.get('targetFile') or ''}: {r['error']}"[:200])
            continue
        meta["files_scanned"] += 1
        target = r.get("targetFile") or r.get("displayTargetFile") or ""
        for i in issues:
            if i.get("isIgnored"):
                continue
            desc = i.get("iacDescription") or {}
            issue = i.get("issue") or desc.get("issue") or ""
            impact = i.get("impact") or desc.get("impact") or ""
            resolve = i.get("resolve") or desc.get("resolve") or ""
            path = i.get("path") or []
            where = ".".join(str(p) for p in path) if isinstance(path, list) else str(path)
            findings.append(Finding(
                tool="snyk-iac", category="iac", rule_id=i.get("publicId") or i.get("id", ""),
                severity=norm_severity(i.get("severity")), title=i.get("title") or issue,
                message=" ".join(x for x in (issue, impact) if x).strip() + (f" (at {where})" if where else ""),
                file=target, line=int(i.get("lineNumber") or 0), fix_hint=resolve,
                url=i.get("documentation") or "", identifiers=[i.get("subType") or ""] if i.get("subType") else [],
                sources=["snyk-iac"]))
    if not meta["files_scanned"] and errors:
        return errors[0][:300], [], meta
    findings.sort(key=lambda f: (-{"critical": 4, "high": 3, "medium": 2, "low": 1}.get(f.severity, 0), f.file, f.line))
    return None, findings, meta

