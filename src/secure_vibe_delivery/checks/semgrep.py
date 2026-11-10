"""Semgrep code scan (auto + AI-mistake rules) and secrets fallback."""
from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Optional

from ..models import Finding, SecretFinding, norm_severity
from .secrets_util import extract_secret, mask, read_span

EXCLUDES = [".venv", "venv", "env", "node_modules", ".svd", "dist", "build", "coverage"]


def rules_path(name: str) -> str:
    return str(resources.files("secure_vibe_delivery").joinpath("rules", name))


def _excl() -> list[str]:
    out = []
    for e in EXCLUDES:
        out += ["--exclude", e]
    return out


def code_argv(semgrep: list[str], project_rules: Optional[Path]) -> list[str]:
    argv = [*semgrep, "scan", "--config", "auto", "--config", rules_path("ai-mistakes.yml")]
    if project_rules:
        argv += ["--config", str(project_rules)]
    return argv + _excl() + ["--json", "--quiet", "--metrics", "auto", "."]


def secrets_argv(semgrep: list[str], registry: bool = True) -> list[str]:
    """registry=True adds Semgrep's p/secrets (downloaded from the Semgrep registry). The bundled
    svd-secrets rules are local files and need no account, network or paid plan."""
    configs = ["--config", "p/secrets"] if registry else []
    return [*semgrep, "scan", *configs, "--config", rules_path("svd-secrets.yml"), *_excl(), "--json", "--quiet",
            "--metrics", "off", "."]


def _short_id(check_id: str) -> str:
    return check_id.rsplit(".", 1)[-1]


def _load(stdout: str) -> Optional[dict]:
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return None


def parse_code(stdout: str) -> tuple[Optional[str], list[Finding], list[str]]:
    data = _load(stdout)
    if data is None:
        return "Semgrep produced no JSON output", [], []
    fatal = [e.get("message", "") for e in data.get("errors", []) if e.get("level") == "error"
             and e.get("type") in ("SemgrepError", "InvalidRuleSchemaError", "RuleParseError")]
    if fatal and not data.get("results"):
        return "; ".join(fatal)[:500], [], []
    warnings = [e.get("message", "")[:200] for e in data.get("errors", [])][:20]
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        cwe = meta.get("cwe") or []
        cwe = [c.split(":")[0].strip() for c in (cwe if isinstance(cwe, list) else [cwe])]
        rid = _short_id(r.get("check_id", ""))
        findings.append(Finding(
            tool="semgrep", category="code", rule_id=rid, severity=norm_severity(extra.get("severity")),
            title=rid.replace("-", " "), message=extra.get("message", "").strip(),
            file=r.get("path", ""), line=int(r.get("start", {}).get("line") or 0), cwe=cwe,
            fix_hint=(extra.get("fix") or "").strip()[:300], url=(meta.get("source") or ""),
            sources=["semgrep" + (" (svd-rules)" if rid.startswith("svd-") else "")],
        ))
    return None, findings, warnings


def parse_secrets(stdout: str, root: Optional[Path] = None) -> tuple[Optional[str], list[SecretFinding]]:
    """When Semgrep isn't logged in it replaces source lines with "requires login" and omits
    metavariables, so the value to mask is read from the file itself (root) instead."""
    data = _load(stdout)
    if data is None:
        return "Semgrep secrets scan produced no JSON output", []
    fatal = [e.get("message", "") for e in data.get("errors", []) if e.get("level") == "error"]
    if fatal and not data.get("results"):
        return "; ".join(fatal)[:500], []
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        lines = extra.get("lines") or ""
        if "requires login" in lines:
            lines = ""
        s, e = r.get("start", {}), r.get("end", {})
        one_line = s.get("line") == e.get("line")
        span = ""
        if lines:
            span = (lines.splitlines()[0][max(0, s.get("col", 1) - 1): max(0, e.get("col", 1) - 1)]
                    if one_line else "") or lines
        elif root is not None and r.get("path"):
            span = read_span(root, r["path"], int(s.get("line") or 0),
                             s.get("col", 0) if one_line else 0, e.get("col", 0) if one_line else 0)
        # A regex capture group ($1) is the secret itself, when the rule defines one
        captured = ((extra.get("metavars") or {}).get("$1") or {}).get("abstract_content")
        value = captured or (extract_secret(span) if span else "")
        out.append(SecretFinding(
            scanner="semgrep", rule_id=_short_id(r.get("check_id", "")),
            kind=meta.get("secret_kind") or meta.get("secret_type") or _short_id(r.get("check_id", "")).replace("-", " "),
            file=r.get("path", ""), line=int(s.get("line") or 0),
            masked_value=mask(value) if value else "****",
            message=extra.get("message", "").strip()[:300],
            sources=["semgrep p/secrets" if not _short_id(r.get("check_id", "")).startswith("svd-") else "semgrep svd-secrets"],
        ))
    return None, out


def scrub_raw(stdout: str) -> str:
    """Drop source lines from Semgrep JSON so raw secret values aren't persisted."""
    data = _load(stdout)
    if data is None:
        return ""
    for r in data.get("results", []):
        for k in ("lines", "fingerprint", "metavars", "dataflow_trace", "fix"):
            r.get("extra", {}).pop(k, None)
    return json.dumps(data)
