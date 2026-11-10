"""Secure-health score: one 0-100 number (and a letter grade) for how the project did across every
check that ran.

Principles:
- A check that didn't run scores 0, the same as a failure.
- Security carries half the weight, because a security problem blocks go-live on its own.
- Partial credit reflects how bad a failure is: one medium issue costs far less than a critical one.
- Two caps keep the number honest: an exposed secret or a critical issue holds the score at 59 or
  below, and any check that didn't run holds it at 79 or below.
"""
from __future__ import annotations

from .models import CheckResult, Status

CHECK_WEIGHTS = {"security": 50, "functional": 25, "performance": 25}
GRADES = [(90, "A", "Excellent"), (80, "B", "Good"), (70, "C", "Fair"), (60, "D", "Poor"), (0, "F", "Failing")]


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


def _sub(r: CheckResult, sid: str):
    return next((s for s in r.subchecks if s.id == sid), None)


def _not_run(r: CheckResult, sid: str) -> bool:
    s = _sub(r, sid)
    return s is None or s.status == Status.NOT_RUN


def _component(label: str, weight: float, score: float, detail: str, not_run: bool = False) -> dict:
    return {"label": label, "weight": weight, "score": 0.0 if not_run else round(_clamp(score), 3),
            "detail": "Didn't run (scores 0)" if not_run else detail, "not_run": not_run}


def _security(r: CheckResult) -> list[dict]:
    code = [f for f in r.findings if f.category == "code"]
    libs = [f for f in r.findings if f.category == "library"]
    pkgs = [f for f in r.findings if f.category == "package"]
    c = {s: sum(1 for f in code if f.severity == s) for s in ("critical", "high", "medium", "low")}
    lb = {s: sum(1 for f in libs if f.severity == s) for s in ("critical", "high", "medium", "low")}
    return [
        _component("No exposed secrets", 30, 0.0 if r.secrets else 1.0,
                   f"{len(r.secrets)} exposed secret(s)" if r.secrets else "None found", _not_run(r, "secrets")),
        _component("Issues in our code", 30,
                   1 - (c["critical"] * 0.5 + c["high"] * 0.25 + c["medium"] * 0.05 + c["low"] * 0.01),
                   f"{c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low "
                   "(each critical −50%, high −25%, medium −5%, low −1%)", _not_run(r, "code")),
        _component("Vulnerable libraries", 25,
                   1 - (lb["critical"] * 0.5 + lb["high"] * 0.04 + lb["medium"] * 0.01),
                   f"{lb['critical']} critical, {lb['high']} high, {lb['medium']} medium "
                   "(each critical −50%, high −4%, medium −1%)", _not_run(r, "libraries")),
        _component("Real, established packages", 15, 0.0 if pkgs else 1.0,
                   f"{len(pkgs)} suspicious package(s)" if pkgs else "All verified", _not_run(r, "packages")),
    ]


def _functional(r: CheckResult) -> list[dict]:
    counts = r.data.get("counts", {}) or {}
    total = counts.get("total", 0) or 0
    passed = counts.get("passed", 0) or 0
    cov = r.data.get("coverage_pct")
    thr = r.data.get("coverage_threshold") or 70
    wc = _sub(r, "wrong-case")
    return [
        _component("Tests passing", 55, passed / total if total else 0.0,
                   f"{passed} of {total} passed", _not_run(r, "tests") or not total),
        _component("Code coverage", 35, (cov or 0) / thr,
                   f"{cov}% against a {thr:.0f}% target (full marks at the target)", cov is None),
        _component("Wrong-case tests present", 10, 1.0 if wc and wc.status == Status.PASS else 0.0,
                   "Found" if wc and wc.status == Status.PASS else "No tests for refused requests found",
                   wc is None),
    ]


def _performance(r: CheckResult) -> list[dict]:
    agg = r.data.get("aggregate") or {}
    if not agg:
        return [_component("Load test", 100, 0, "", True)]
    target = r.data.get("p95_target_ms") or 1000
    fail = agg.get("failure_pct", 0.0)
    p95 = agg.get("p95", 0.0)
    crash = _sub(r, "crashes")
    return [
        _component("Failed requests", 35, 1.0 if fail < 1 else 1 - (fail - 1) / 4,
                   f"{fail}% failed (full marks under 1%, zero at 5%)"),
        _component("p95 response time", 35, 1.0 if p95 <= target else 1 - (p95 - target) / target,
                   f"p95 {p95:.0f} ms against {target} ms (full marks within target, zero at twice it)"),
        _component("No crashes", 30, 1.0 if crash and crash.status == Status.PASS else 0.0,
                   crash.detail if crash else "", crash is None),
    ]


def grade_for(score: int) -> tuple[str, str]:
    for floor, letter, word in GRADES:
        if score >= floor:
            return letter, word
    return "F", "Failing"


def compute(results: dict[str, CheckResult], quick_mode: bool) -> dict:
    builders = {"security": _security, "functional": _functional, "performance": _performance}
    checks = {}
    overall = 0.0
    any_not_run = False
    for name, weight in CHECK_WEIGHTS.items():
        r = results[name]
        comps = builders[name](r) if r.status != Status.NOT_RUN or r.subchecks else []
        if not comps or (r.status == Status.NOT_RUN and all(c["not_run"] for c in comps)):
            comps = [_component(f"{name.title()} checks", 100, 0, "", True)]
        total_w = sum(c["weight"] for c in comps)
        score = sum(c["weight"] * c["score"] for c in comps) / total_w
        any_not_run = any_not_run or any(c["not_run"] for c in comps)
        for c in comps:
            c["points"] = round(weight * c["weight"] / total_w * c["score"], 1)
            c["max_points"] = round(weight * c["weight"] / total_w, 1)
        checks[name] = {"score": round(score * 100), "weight": weight, "points": round(score * weight, 1),
                        "components": comps}
        overall += score * weight
    raw = round(overall)
    caps = []
    sec = results["security"]
    critical = sum(1 for f in sec.findings if f.severity == "critical")
    if sec.secrets or critical:
        caps.append((59, f"{len(sec.secrets)} exposed secret(s) and {critical} critical issue(s): "
                         "the score is held at 59 or below until they're fixed"))
    if any_not_run:
        caps.append((79, "at least one check didn't run, so the score is held at 79 or below"))
    final = min([raw] + [c[0] for c in caps])
    letter, word = grade_for(final)
    return {
        "score": final, "raw_score": raw, "grade": letter, "grade_word": word,
        "caps": [c[1] for c in caps if c[0] < raw],
        "checks": checks,
        "note": "Quick-mode load test: the performance part is indicative." if quick_mode and
                results["performance"].data.get("aggregate") else "",
        "method": "Security 50 points, functional 25, performance 25. Each part earns points in proportion to "
                  "how well it did; a check that didn't run earns 0.",
    }
