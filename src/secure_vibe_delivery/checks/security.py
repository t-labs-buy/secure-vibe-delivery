"""Security check: is it safe? Snyk (Open Source, Code, Secrets) + Semgrep + package provenance."""
from __future__ import annotations

import time

from ..models import SEVERITY_ORDER, CheckResult, Finding, SecretFinding, Status, SubCheck
from ..proc import resolve_tool, run_cmd
from . import packages, semgrep, snyk
from .context import CheckContext


def _sev(f: Finding) -> int:
    return SEVERITY_ORDER.get(f.severity, 0)


def merge_code_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that Snyk Code and Semgrep (or several rules) report on the same line."""
    groups: dict[tuple, list[Finding]] = {}
    for f in findings:
        groups.setdefault((f.file, f.line), []).append(f)
    merged = []
    for group in groups.values():
        group.sort(key=lambda f: (-_sev(f), 0 if f.tool == "snyk-code" else 1))
        primary = group[0].model_copy(deep=True)
        primary.sources = sorted({s for f in group for s in f.sources})
        primary.cwe = sorted({c for f in group for c in f.cwe})
        others = [f"{f.tool}:{f.rule_id}" for f in group[1:]]
        if others:
            primary.identifiers = primary.identifiers + others
        if not primary.fix_hint:
            primary.fix_hint = next((f.fix_hint for f in group if f.fix_hint), "")
        merged.append(primary)
    return sorted(merged, key=lambda f: (-_sev(f), f.file, f.line))


GENERIC_KINDS = ("hard-coded credential", "hardcoded", "generic")


def merge_secrets(secrets: list[SecretFinding]) -> list[SecretFinding]:
    groups: dict[tuple, list[SecretFinding]] = {}
    for s in secrets:
        groups.setdefault((s.file, s.line), []).append(s)
    out = []
    for group in groups.values():
        group.sort(key=lambda s: any(g in s.kind.lower() for g in GENERIC_KINDS))
        primary = group[0].model_copy(deep=True)
        primary.sources = sorted({src for s in group for src in s.sources})
        out.append(primary)
    return sorted(out, key=lambda s: (s.file, s.line))


async def run(ctx: CheckContext) -> CheckResult:
    res = CheckResult(name="security", started_at=time.time())
    root = ctx.root
    code_findings: list[Finding] = []
    lib_findings: list[Finding] = []
    secrets: list[SecretFinding] = []
    not_run: dict[str, str] = {}
    scanners: dict[str, str] = {}

    snyk_bin = resolve_tool("snyk")
    semgrep_bin = resolve_tool("semgrep")

    # --- Snyk Open Source -------------------------------------------------------------
    if snyk_bin:
        ctx.log("Snyk Open Source: scanning libraries")
        argv = snyk.open_source_argv(snyk_bin, ctx.info.python_cmd if ctx.info.is_python else None)
        p = await run_cmd(argv, root, timeout=900)
        res.commands.append(p.record("snyk-open-source", argv, ctx.raw_dir))
        err, libs, meta = snyk.parse_open_source(p.stdout)
        if err:
            hint = ""
            if "getting dependencies" in err.lower() and ctx.info.is_python:
                hint = (" Hint: Snyk needs the project's packages installed in a venv that has pip "
                        "(e.g. `python -m venv .venv && .venv/bin/pip install -r requirements.txt`).")
            if "no supported" in err.lower() or p.exit_code == 3:
                hint = " Snyk found no supported manifest (requirements.txt, package.json, ...)."
            not_run["snyk-open-source"] = err[:400] + hint
        else:
            lib_findings = libs
            scanners["snyk-open-source"] = f"{meta.get('dependency_count', 0)} dependencies"
            res.data["snyk_open_source"] = meta
    else:
        not_run["snyk-open-source"] = "Snyk CLI not installed (brew tap snyk/tap && brew install snyk)"

    # --- Snyk Code --------------------------------------------------------------------
    if snyk_bin:
        ctx.log("Snyk Code: scanning our code")
        argv = [*snyk_bin, "code", "test", "--json"]
        p = await run_cmd(argv, root, timeout=900)
        res.commands.append(p.record("snyk-code", argv, ctx.raw_dir))
        err, code, code_secrets = snyk.parse_code(p.stdout, root)
        if err or p.exit_code not in (0, 1):
            not_run["snyk-code"] = (err or p.stderr.strip() or f"exit code {p.exit_code}")[:400]
        else:
            code_findings += code
            secrets += code_secrets
            scanners["snyk-code"] = f"{len(code)} issues"
    else:
        not_run["snyk-code"] = "Snyk CLI not installed"

    # --- Semgrep ----------------------------------------------------------------------
    if semgrep_bin:
        ctx.log("Semgrep: OWASP rules + AI-mistake rules")
        argv = semgrep.code_argv(semgrep_bin, ctx.info.svd_rules_dir)
        p = await run_cmd(argv, root, timeout=900)
        res.commands.append(p.record("semgrep", argv, None))
        (ctx.raw_dir / "semgrep.masked.json").write_text(semgrep.scrub_raw(p.stdout))
        err, sg, warnings = semgrep.parse_code(p.stdout)
        if err:
            not_run["semgrep"] = err
        else:
            code_findings += sg
            scanners["semgrep"] = f"{len(sg)} issues"
            if warnings:
                res.data["semgrep_warnings"] = warnings
    else:
        not_run["semgrep"] = "Semgrep not installed and uvx not available (brew install semgrep)"

    # --- Secrets: Snyk Secrets, else Semgrep fallback ---------------------------------
    secrets_scanner = None
    if snyk_bin:
        ctx.log("Snyk Secrets: checking for keys and passwords")
        argv = [*snyk_bin, "secrets", "test", "--json"]
        p = await run_cmd(argv, root, timeout=600)
        reason = snyk.secrets_unavailable(p.stdout, p.stderr, p.exit_code)
        rec = p.record("snyk-secrets", argv, None)
        res.commands.append(rec)
        if reason is None:
            secrets += snyk.parse_secrets(p.stdout, root)
            secrets_scanner = "snyk-secrets"
        else:
            res.data["snyk_secrets_unavailable"] = reason
    if secrets_scanner is None:
        if semgrep_bin:
            ctx.log("Secrets fallback: Semgrep p/secrets + svd-secrets rules")
            argv = semgrep.secrets_argv(semgrep_bin, registry=True)
            p = await run_cmd(argv, root, timeout=600)
            err, sec = semgrep.parse_secrets(p.stdout, root)
            label = "semgrep (p/secrets + svd-secrets)"
            if err:
                # p/secrets comes from the Semgrep registry: no network, or a change in what it serves
                # without an account, must not leave the project with no secret scan at all.
                res.data["semgrep_registry_secrets_error"] = err[:300]
                ctx.log("p/secrets unavailable; retrying with the bundled svd-secrets rules only")
                res.commands.append(p.record("semgrep-secrets-registry", argv, None))
                argv = semgrep.secrets_argv(semgrep_bin, registry=False)
                p = await run_cmd(argv, root, timeout=600)
                err, sec = semgrep.parse_secrets(p.stdout, root)
                label = "semgrep (bundled svd-secrets rules only)"
            res.commands.append(p.record("semgrep-secrets", argv, None))
            (ctx.raw_dir / "semgrep-secrets.masked.json").write_text(semgrep.scrub_raw(p.stdout))
            if err:
                not_run["secrets"] = err
            else:
                secrets += sec
                secrets_scanner = label
        else:
            not_run["secrets"] = "No secret scanner available: Snyk Secrets unsupported and Semgrep missing"
    res.data["secrets_scanner"] = secrets_scanner

    # --- Package provenance -----------------------------------------------------------
    ctx.log("Package provenance: checking every dependency is real and not brand-new")
    try:
        prov, prov_meta = await packages.check(root)
        res.data["provenance"] = prov_meta
        checked = prov_meta.get("checked", 0)
        total = prov_meta["python_packages"] + prov_meta["npm_packages"]
        if total and not checked:
            not_run["provenance"] = "Could not reach PyPI / npm registries"
        lib_findings += prov
    except Exception as e:  # network or parse failure
        not_run["provenance"] = f"{type(e).__name__}: {e}"[:300]
        prov = []

    # --- Assemble ---------------------------------------------------------------------
    code_findings = merge_code_findings(code_findings)
    secrets = merge_secrets(secrets)
    res.findings = code_findings + sorted(lib_findings, key=lambda f: -_sev(f))
    res.secrets = secrets
    res.data["scanners"] = scanners
    res.data["not_run"] = not_run

    code_hi = [f for f in code_findings if f.severity in ("critical", "high")]
    lib_crit = [f for f in lib_findings if f.category == "library" and f.severity == "critical"]
    lib_high = [f for f in lib_findings if f.category == "library" and f.severity == "high"]
    pkg_bad = [f for f in lib_findings if f.category == "package"]

    def sub(id_, label, failing, scanners_needed, ok_detail, bad_detail):
        missing = [s for s in scanners_needed if s in not_run]
        if missing:
            return SubCheck(id=id_, label=label, status=Status.NOT_RUN,
                            detail="Didn't run: " + "; ".join(f"{m}: {not_run[m]}" for m in missing))
        return SubCheck(id=id_, label=label, status=Status.FAIL if failing else Status.PASS,
                        detail=bad_detail if failing else ok_detail)

    res.subchecks = [
        sub("secrets", "No keys or passwords in code", secrets, ["secrets"],
            f"0 found by {secrets_scanner}", f"{len(secrets)} exposed secret(s)"),
        sub("code", "0 critical or high issues in our code", code_hi, ["snyk-code", "semgrep"],
            f"{len(code_findings)} lower-severity issue(s)", f"{len(code_hi)} critical/high issue(s)"),
        sub("libraries", "0 critical issues in libraries", lib_crit, ["snyk-open-source"],
            f"0 critical ({len(lib_high)} high, fix soon)", f"{len(lib_crit)} critical library issue(s)"),
        sub("packages", "All libraries real and known (no unknown or brand-new packages)", pkg_bad,
            ["provenance"], f"{res.data.get('provenance', {}).get('checked', 0)} package(s) verified",
            f"{len(pkg_bad)} suspicious package(s)"),
        SubCheck(id="own-data", label="Users see only their own data", status=Status.WARN,
                 detail="Manual: prove with wrong-case tests (user A can't read user B's data)"),
        SubCheck(id="review", label="Change reviewed by a second person", status=Status.WARN,
                 detail="Manual: someone who didn't prompt the AI must review it"),
    ]
    auto = [s for s in res.subchecks if s.id not in ("own-data", "review")]
    if any(s.status == Status.FAIL for s in auto):
        res.status = Status.FAIL
    elif any(s.status == Status.NOT_RUN for s in auto):
        res.status = Status.NOT_RUN if all(s.status == Status.NOT_RUN for s in auto) else Status.FAIL
    else:
        res.status = Status.PASS
    res.summary = (f"{len(secrets)} secret(s), {len(code_hi)} critical/high code issue(s), "
                   f"{len(lib_crit)} critical + {len(lib_high)} high library issue(s), "
                   f"{len(pkg_bad)} suspicious package(s)")
    if not_run:
        res.summary += f"; {len(not_run)} scanner(s) didn't run"
    res.finished_at = time.time()
    return res
