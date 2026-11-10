"""Performance check: can it cope? Locust at 1.5x the expected peak."""
from __future__ import annotations

import csv
import math
import re
import time
from pathlib import Path
from typing import Optional

import httpx

from ..models import CheckResult, Finding, Status, SubCheck
from ..proc import resolve_tool, run_cmd
from . import locustgen
from ..detect import venv_exe
from .context import CheckContext

CRASH_ERRORS = re.compile(r"ConnectionRefused|RemoteDisconnected|ConnectionResetError|ConnectionError|"
                          r"BadStatusLine|EOF occurred|Connection aborted|NewConnectionError", re.I)


def _f(v: str) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def parse_duration(s: str) -> int:
    total = 0
    for n, unit in re.findall(r"(\d+)\s*([hms]?)", s):
        total += int(n) * {"h": 3600, "m": 60, "s": 1, "": 1}[unit]
    return total


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def parse_results(prefix: Path) -> dict:
    stats = read_csv(Path(f"{prefix}_stats.csv"))
    history = read_csv(Path(f"{prefix}_stats_history.csv"))
    failures = read_csv(Path(f"{prefix}_failures.csv"))
    exceptions = read_csv(Path(f"{prefix}_exceptions.csv"))
    endpoints, agg = [], {}
    for r in stats:
        row = {
            "type": r.get("Type", ""), "name": r.get("Name", ""),
            "requests": int(_f(r.get("Request Count"))), "failures": int(_f(r.get("Failure Count"))),
            "median": _f(r.get("Median Response Time")), "avg": _f(r.get("Average Response Time")),
            "min": _f(r.get("Min Response Time")), "max": _f(r.get("Max Response Time")),
            "rps": _f(r.get("Requests/s")), "p50": _f(r.get("50%")), "p95": _f(r.get("95%")),
            "p99": _f(r.get("99%")),
        }
        row["failure_pct"] = round(100 * row["failures"] / row["requests"], 2) if row["requests"] else 0.0
        if r.get("Name") == "Aggregated":
            agg = row
        else:
            endpoints.append(row)
    series = []
    for r in history:
        if r.get("Name") != "Aggregated":
            continue
        series.append({
            "t": int(_f(r.get("Timestamp"))), "users": int(_f(r.get("User Count"))),
            "rps": round(_f(r.get("Requests/s")), 2), "fps": round(_f(r.get("Failures/s")), 2),
            "p50": _f(r.get("50%")) if r.get("50%") not in ("N/A", "") else None,
            "p95": _f(r.get("95%")) if r.get("95%") not in ("N/A", "") else None,
            "requests": int(_f(r.get("Total Request Count"))), "failures": int(_f(r.get("Total Failure Count"))),
        })
    if series:
        t0 = series[0]["t"]
        for s in series:
            s["t"] -= t0
    fails = [{"method": f.get("Method", ""), "name": f.get("Name", ""), "error": f.get("Error", ""),
              "count": int(_f(f.get("Occurrences")))} for f in failures]
    excs = [{"count": int(_f(e.get("Count"))), "message": e.get("Message", ""),
             "traceback": (e.get("Traceback") or "")[:1500]} for e in exceptions]
    return {"aggregate": agg, "endpoints": sorted(endpoints, key=lambda e: -e["requests"]),
            "series": series, "failures": sorted(fails, key=lambda f: -f["count"]), "exceptions": excs}


async def _probe(url: str) -> tuple[bool, str]:
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=True) as c:
            r = await c.get(url)
            return r.status_code < 500, f"HTTP {r.status_code}"
    except httpx.HTTPError as e:
        return False, f"{type(e).__name__}: {e}"[:200]


def _locust_cmd(ctx: CheckContext) -> Optional[list[str]]:
    p = venv_exe(ctx.root, "locust")
    if p:
        return [str(p)]
    return resolve_tool("locust")


async def run(ctx: CheckContext) -> CheckResult:
    res = CheckResult(name="performance", started_at=time.time())
    o = ctx.options
    users = math.ceil(1.5 * o.peak_users)
    duration = o.duration or ("15m" if o.mode == "gate" else "2m")
    res.data = {"mode": o.mode, "peak_users": o.peak_users, "users": users, "spawn_rate": o.spawn_rate,
                "duration": duration, "p95_target_ms": o.response_time_p95_ms, "target_url": o.target_url}
    labels = {
        "load": f"Run at 1.5x expected users ({users}) for 15 minutes",
        "failures": "Under 1% failed requests",
        "latency": f"p95 response time within target ({o.response_time_p95_ms} ms)",
        "crashes": "No crashes under load",
    }

    def not_run(reason: str) -> CheckResult:
        res.reason_not_run = reason
        res.summary = reason
        res.subchecks = [SubCheck(id=k, label=v, status=Status.NOT_RUN, detail=reason) for k, v in labels.items()]
        res.finished_at = time.time()
        return res

    if not o.target_url:
        return not_run("No target_url given. Pass the test environment's URL (never production) to load-test it.")
    locust = _locust_cmd(ctx)
    if not locust:
        return not_run("Locust not available: pip install locust (or install uv so it can run via uvx)")

    ok, detail = await _probe(o.target_url)
    res.data["preflight"] = detail
    if not ok:
        return not_run(f"Target {o.target_url} isn't reachable before the test ({detail}). Start the app first.")

    # Locustfile: explicit > project's > generated
    lf: Optional[Path] = None
    if o.locustfile:
        lf = (ctx.root / o.locustfile).resolve()
        if not lf.exists():
            return not_run(f"locustfile {o.locustfile} not found")
        res.data["locustfile_source"] = "given"
    elif ctx.info.locustfile:
        lf = ctx.info.locustfile
        res.data["locustfile_source"] = "project"
    else:
        src, how = locustgen.generate(ctx.root, o.target_url, ctx.info.openapi_file)
        lf = ctx.run_dir / "locustfile.generated.py"
        lf.write_text(src)
        res.data["locustfile_source"] = f"generated ({how})"
    res.data["locustfile"] = str(lf)

    prefix = ctx.run_dir / "locust"
    html = ctx.run_dir / "locust-native.html"
    argv = [*locust, "-f", str(lf), "--headless", "-u", str(users), "-r", str(o.spawn_rate), "-t", duration,
            "--host", o.target_url, "--csv", str(prefix), "--csv-full-history", "--html", str(html),
            "--only-summary", "--stop-timeout", "10", "--loglevel", "WARNING"]
    ctx.log(f"Locust: {users} users, +{o.spawn_rate}/s, holding for {duration} against {o.target_url}")
    p = await run_cmd(argv, ctx.root, timeout=parse_duration(duration) + 240)
    res.commands.append(p.record("locust", argv, ctx.raw_dir))
    data = parse_results(prefix)
    res.data.update(data)
    res.data["native_report"] = str(html) if html.exists() else ""
    agg = data["aggregate"]
    if not agg or not agg.get("requests"):
        tail = (p.stderr[-800:] or p.stdout[-800:] or p.error).strip()
        return not_run(f"Locust produced no requests (exit {p.exit_code}). {tail}")

    after_ok, after_detail = await _probe(o.target_url)
    res.data["postflight"] = after_detail
    crash_fails = [f for f in data["failures"] if CRASH_ERRORS.search(f["error"])]
    crash_count = sum(f["count"] for f in crash_fails)

    fail_pct = agg["failure_pct"]
    p95 = agg["p95"]
    held = parse_duration(duration)
    full = o.mode == "gate" and held >= 900
    subs = [
        SubCheck(id="load", label=labels["load"], status=Status.PASS if full else Status.WARN,
                 detail=(f"{users} users for {duration}" if full else
                         f"Quick run: {users} users for {duration}. Indicative only; run mode='gate' for go-live")),
        SubCheck(id="failures", label=labels["failures"], status=Status.PASS if fail_pct < 1 else Status.FAIL,
                 detail=f"{fail_pct}% of {agg['requests']} requests failed"),
        SubCheck(id="latency", label=labels["latency"],
                 status=Status.PASS if p95 <= o.response_time_p95_ms else Status.FAIL,
                 detail=f"p95 {p95:.0f} ms, p50 {agg['p50']:.0f} ms, p99 {agg['p99']:.0f} ms"),
        SubCheck(id="crashes", label=labels["crashes"],
                 status=Status.PASS if after_ok and not crash_count else Status.FAIL,
                 detail=("App healthy after the run, no connection errors" if after_ok and not crash_count else
                         f"{crash_count} connection error(s); health after run: {after_detail}")),
    ]
    res.subchecks = subs
    for e in data["endpoints"]:
        if e["requests"] and e["failure_pct"] >= 1:
            res.findings.append(Finding(tool="locust", category="performance", rule_id="endpoint-failures",
                                        severity="high", title=f"{e['type']} {e['name']}: {e['failure_pct']}% failed",
                                        message=f"{e['failures']} of {e['requests']} requests failed",
                                        sources=["locust"], fix_hint="See the failures table for the error returned."))
        if e["requests"] and e["p95"] > o.response_time_p95_ms:
            res.findings.append(Finding(tool="locust", category="performance", rule_id="endpoint-slow",
                                        severity="medium", title=f"{e['type']} {e['name']}: p95 {e['p95']:.0f} ms",
                                        message=f"Over the {o.response_time_p95_ms} ms target (median {e['median']:.0f} ms)",
                                        sources=["locust"],
                                        fix_hint="Profile this endpoint: look for slow queries, blocking calls or missing caching."))
    if data["exceptions"]:
        res.data["exceptions_note"] = "Exceptions inside the locustfile itself; fix the test script."
    if any(s.status == Status.FAIL for s in subs):
        res.status = Status.FAIL
    elif any(s.status == Status.WARN for s in subs):
        res.status = Status.WARN
    else:
        res.status = Status.PASS
    res.summary = (f"{agg['requests']} requests at {agg['rps']:.1f} req/s; {fail_pct}% failed; "
                   f"p95 {p95:.0f} ms (target {o.response_time_p95_ms} ms)")
    res.finished_at = time.time()
    return res
