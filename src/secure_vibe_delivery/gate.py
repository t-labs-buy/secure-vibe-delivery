"""Go-live gate: roadmap thresholds → verdict and a prioritised must-fix list."""
from __future__ import annotations

from .models import EXPOSURE_TEXT, SEVERITY_ORDER, CheckResult, RunState, Status, SubCheck, blocking_secrets

CHECKS = ["security", "functional", "performance"]
MANUAL = {"own-data", "review"}

VERDICT_TEXT = {
    "NO-GO": "Not ready for go-live: at least one must-pass check failed or didn't run.",
    "PROVISIONAL": "Every automated check passed, but performance ran in quick mode. "
                   "Run mode='gate' (15 minutes at 1.5x peak) before go-live.",
    "GO": "Every automated check passed. Go-live needs the Delivery Lead's sign-off on the manual items.",
}


def ensure_all(state: RunState) -> dict[str, CheckResult]:
    """Checks that weren't requested still appear, as NOT_RUN: a skipped scan is a failure."""
    out = dict(state.results)
    for name in CHECKS:
        if name not in out:
            out[name] = CheckResult(name=name, status=Status.NOT_RUN,
                                    reason_not_run="Not requested in this run",
                                    summary="Not requested in this run",
                                    subchecks=[SubCheck(id=name, label=f"{name.title()} checks ran",
                                                        status=Status.NOT_RUN, detail="Not requested in this run")])
    return out


def verdict(results: dict[str, CheckResult]) -> str:
    auto = [s for r in results.values() for s in r.subchecks if s.id not in MANUAL]
    if any(s.status in (Status.FAIL, Status.NOT_RUN) for s in auto):
        return "NO-GO"
    perf = results.get("performance")
    if perf and any(s.id == "load" and s.status == Status.WARN for s in perf.subchecks):
        return "PROVISIONAL"
    return "GO"


def must_fix(results: dict[str, CheckResult], limit: int | None = None) -> list[dict]:
    """Roadmap order: leaked keys → critical/high code and infrastructure → critical libraries → packages → tests → perf."""
    items: list[dict] = []
    sec = results.get("security")
    if sec:
        # Only values in git (or about to be) are must-fix. Keys in git-ignored files, test fixtures
        # and documentation examples stay listed on the Secrets tab.
        for s in blocking_secrets(sec.secrets):
            where = EXPOSURE_TEXT.get(s.exposure)
            items.append({"priority": 1, "severity": "critical", "check": "security", "kind": "Exposed secret",
                          "title": f"{s.kind} in {s.file}:{s.line}", "where": f"{s.file}:{s.line}",
                          "detail": f"Masked value {s.masked_value}. Found by {', '.join(s.sources)}."
                                    + (f" Where it is: {where}." if where else ""),
                          "fix": "Rotate it (issue a new one, cancel the old one), then load it from the environment "
                                 "or a secret manager. Deleting the line isn't enough: it stays in git history."})
        for f in sec.findings:
            if f.category == "code" and f.severity in ("critical", "high"):
                items.append({"priority": 2, "severity": f.severity, "check": "security", "kind": "Code issue",
                              "title": f.title or f.rule_id, "where": f"{f.file}:{f.line}",
                              "detail": f.message, "fix": f.fix_hint, "sources": f.sources, "cwe": f.cwe})
        for f in sec.findings:
            if f.category == "iac" and f.severity in ("critical", "high"):
                items.append({"priority": 2, "severity": f.severity, "check": "security", "kind": "Infrastructure",
                              "title": f.title or f.rule_id, "where": f"{f.file}:{f.line}" if f.line else f.file,
                              "detail": f.message, "fix": f.fix_hint, "sources": f.sources})
        for f in sec.findings:
            if f.category == "library" and f.severity == "critical":
                items.append({"priority": 3, "severity": "critical", "check": "security", "kind": "Library",
                              "title": f"{f.package}@{f.version}: {f.title}", "where": f.package,
                              "detail": ", ".join(f.identifiers), "fix": f.fix_hint})
        for f in sec.findings:
            if f.category == "package":
                items.append({"priority": 4, "severity": f.severity, "check": "security", "kind": "Package",
                              "title": f"{f.package}: {f.title}", "where": f.package, "detail": f.message,
                              "fix": f.fix_hint})
    fun = results.get("functional")
    if fun:
        for f in fun.findings:
            items.append({"priority": 5, "severity": "high", "check": "functional", "kind": "Failing test",
                          "title": f.title, "where": f"{f.file}:{f.line}" if f.line else f.file,
                          "detail": f.message.splitlines()[0][:300] if f.message else "", "fix": f.fix_hint})
        cov = next((s for s in fun.subchecks if s.id == "coverage"), None)
        if cov and cov.status == Status.FAIL:
            items.append({"priority": 6, "severity": "medium", "check": "functional", "kind": "Coverage",
                          "title": cov.detail, "where": "", "detail": "See the least-covered files in the functional section.",
                          "fix": "Add tests for the least-covered files first, starting with the wrong-case tests."})
    perf = results.get("performance")
    if perf:
        for s in perf.subchecks:
            if s.status == Status.FAIL:
                items.append({"priority": 7, "severity": "high", "check": "performance", "kind": "Performance",
                              "title": f"{s.label}: {s.detail}", "where": "", "detail": "",
                              "fix": "See the per-endpoint table in the performance dashboard."})
        for f in perf.findings:
            items.append({"priority": 7, "severity": f.severity, "check": "performance", "kind": "Endpoint",
                          "title": f.title, "where": "", "detail": f.message, "fix": f.fix_hint})
    for r in results.values():
        for s in r.subchecks:
            if s.status == Status.NOT_RUN:
                items.append({"priority": 8, "severity": "high", "check": r.name, "kind": "Didn't run",
                              "title": s.label, "where": "", "detail": s.detail,
                              "fix": "A scan that didn't run counts as a failure. Fix the cause and re-run."})
    from .skills import guide_for
    for i in items:
        g = guide_for(i["kind"], i.get("cwe"))
        if g:
            i["guide"] = g
    items.sort(key=lambda i: (i["priority"], -SEVERITY_ORDER.get(i["severity"], 0)))
    return items[:limit] if limit else items
