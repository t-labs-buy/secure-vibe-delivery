"""The Overview hero: a headline that says where the project stands, the path to go-live as five gates,
and a note on where the score's points went."""
from __future__ import annotations

import math

from ..models import CheckResult, RunState, Status

# node state for the stepper: done | fail | pending | notrun | signoff
_STATE = {Status.PASS: "done", Status.FAIL: "fail", Status.WARN: "pending", Status.NOT_RUN: "notrun"}


def _sub(r: CheckResult | None, sid: str):
    return next((s for s in (r.subchecks if r else []) if s.id == sid), None)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def gates(st: RunState, results: dict[str, CheckResult], must_fix: list[dict]) -> list[dict]:
    sec, fun, perf = results.get("security"), results.get("functional"), results.get("performance")
    out = []

    # 1. Security: blockers are the must-fix items that come from security
    blockers = sum(1 for i in must_fix if i["check"] == "security" and i["kind"] != "Didn't run")
    s_state = _STATE.get(sec.status, "notrun") if sec else "notrun"
    out.append({"label": "Security", "state": s_state,
                "sub": "didn't run" if s_state == "notrun" else _plural(blockers, "blocker"),
                "tab": "security"})

    # 2. Functional: tests passed out of total (coverage shows in the tab)
    counts = (fun.data.get("counts") or {}) if fun else {}
    total = counts.get("total", 0)
    f_state = "notrun"
    if fun and fun.status != Status.NOT_RUN:
        auto = [s for s in fun.subchecks if s.id in ("tests", "coverage")]
        f_state = ("fail" if any(s.status == Status.FAIL for s in auto) else
                   "notrun" if any(s.status == Status.NOT_RUN for s in auto) else "done")
    f_sub = "didn't run" if f_state == "notrun" else (f"{counts.get('passed', 0)}/{total} tests" if total else "no tests")
    if f_state == "fail" and total and not (counts.get("failed", 0) + counts.get("errors", 0)):
        cov = fun.data.get("coverage_pct")
        f_sub = f"coverage {cov}%" if cov is not None else f_sub
    out.append({"label": "Functional", "state": f_state, "sub": f_sub, "tab": "functional"})

    # 3. The load test's results (failures, p95, crashes), whatever its length
    quick = st.options.mode != "gate"
    p_auto = [s for s in (perf.subchecks if perf else []) if s.id in ("failures", "latency", "crashes")]
    if not perf or perf.status == Status.NOT_RUN or not p_auto or any(s.status == Status.NOT_RUN for s in p_auto):
        l_state, l_sub = "notrun", ("no test URL given" if not st.options.target_url else "didn't run")
    else:
        l_state = "fail" if any(s.status == Status.FAIL for s in p_auto) else "done"
        agg = perf.data.get("aggregate") or {}
        l_sub = f"p95 {agg['p95']:.0f} ms" if agg.get("p95") is not None else "ran"
    out.append({"label": "Quick load" if quick else "Load test", "state": l_state, "sub": l_sub, "tab": "performance"})

    # 4. The full-length (15-minute) gate run at 1.5x peak
    users = (perf.data.get("users") if perf else None) or math.ceil(1.5 * st.options.peak_users)
    load = _sub(perf, "load")
    if l_state == "notrun":
        g_state = "notrun"
    elif load and load.status == Status.PASS:
        g_state = l_state  # the gate run is the load test above
    else:
        g_state = "pending"
    out.append({"label": "Gate load run", "state": g_state, "sub": f"15 min · {users} users", "tab": "performance"})

    # 5. Sign-off: always a person, never automatic
    out.append({"label": "Sign-off", "state": "signoff", "sub": "Delivery Lead", "tab": "checklist"})
    return out


def hero(st: RunState, results: dict[str, CheckResult], verdict: str, score: dict, must_fix: list[dict]) -> dict:
    g = gates(st, results, must_fix)
    cleared = sum(1 for x in g if x["state"] == "done")
    blocking = [i for i in must_fix if i["kind"] != "Didn't run"]
    not_run = [x["label"].lower() for x in g[:4] if x["state"] == "notrun"]
    failed = [x["label"].lower() for x in g[:4] if x["state"] == "fail"]
    perf = results.get("performance")
    users = (perf.data.get("users") if perf else None) or math.ceil(1.5 * st.options.peak_users)

    if verdict == "GO":
        head = ("Cleared for ", "GO", ".", "good")
        text = ("Every automated check passed, including the 15-minute gate load run at 1.5× peak. "
                "What's left is the Delivery Lead's sign-off on the manual items in the go-live checklist.")
    elif verdict == "PROVISIONAL":
        head = ("One step from ", "GO", ".", "accent")
        text = ("Every automated check passed. The load test ran as the 2-minute quick test, so the performance "
                f"result is indicative. A 15-minute gate run at 1.5× peak ({users} users) turns this into GO.")
    else:
        n = len(blocking)
        head = (("", _plural(n, "blocker"), " before GO.", "bad") if n else ("Not ready for ", "GO", " yet.", "bad"))
        parts = []
        if failed:
            parts.append(f"{_join(failed).capitalize()} failed")
        if not_run:
            phrase = f"{_join(not_run)} didn't run, which counts as a failure"
            parts.append(phrase if parts else phrase[0].upper() + phrase[1:])
        text = ("; ".join(parts) + ". ") if parts else ""
        if blocking:
            first = blocking[0]
            text += f"Start with the must-fix list: {first['kind'].lower()}, {first['title']}."
        else:
            text += "Fix what stopped the checks from running and re-run."

    # the ring shows the rounded score; the note uses the unrounded points so its numbers add up
    lost = (round(100 - score["score"], 1) if score.get("caps") else
            round(100 - sum(c["points"] for chk in score["checks"].values() for c in chk["components"]), 1))
    comps = [(c["max_points"] - c["points"], c["label"])
             for chk in score["checks"].values() for c in chk["components"]]
    comps.sort(reverse=True)
    if lost <= 0:
        note = "No points lost."
    elif score.get("caps"):
        note = f"{_fmt(lost)} points lost. " + score["caps"][0][0].upper() + score["caps"][0][1:] + "."
    elif comps and comps[0][0] > 0:
        part = round(comps[0][0], 1)
        share = "all of them" if abs(part - lost) < 0.05 else f"{_fmt(part)} of them"
        note = f"{_fmt(lost)} point{'s' if lost != 1 else ''} lost, {share} in “{comps[0][1]}”."
    else:
        note = f"{_fmt(lost)} points lost."

    # every automated check as one unit, for the summary's dot strip
    names = {"security": "Security", "functional": "Functional", "performance": "Performance"}
    units = [{"check": k, "label": f"{names.get(k, k.title())}: {sc.label}", "detail": sc.detail,
              "status": sc.status.value}
             for k in ("security", "functional", "performance") if results.get(k)
             for sc in results[k].subchecks if sc.id not in ("own-data", "review")]
    tally = {k: sum(1 for u in units if u["status"] == k) for k in ("PASS", "FAIL", "NOT_RUN", "WARN")}

    peak = st.options.peak_users
    return {"units": units, "tally": tally, "head": head, "text": text, "gates": g, "cleared": cleared, "total": len(g),
            "score_note": note, "peak": peak, "tested_users": users if perf and perf.status != Status.NOT_RUN else None}


def _fmt(x: float) -> str:
    return f"{x:.1f}".rstrip("0").rstrip(".")


def _join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]
