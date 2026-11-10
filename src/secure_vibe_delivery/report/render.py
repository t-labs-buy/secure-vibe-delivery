"""Render the self-contained HTML report and summary.json."""
from __future__ import annotations

import json
import shutil
import time
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape
from markupsafe import Markup

from .. import gate, scoring
from .. import summary as summaries
from .commands import history as command_history
from .commands import timeline as command_timeline
from .overview import hero as overview_hero
from ..models import SEVERITY_ORDER, CheckResult, RunState, Status

_env = Environment(loader=PackageLoader("secure_vibe_delivery", "report/templates"),
                   autoescape=select_autoescape(["html", "j2"]), trim_blocks=True, lstrip_blocks=True)


def _json_script(data) -> Markup:
    """JSON safe to embed inside <script type="application/json">."""
    s = json.dumps(data, default=str).replace("</", "<\\/").replace("<!--", "<\\!--")
    return Markup(s)


def _fmt_dur(seconds: float | None) -> str:
    if not seconds:
        return "-"
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s:02d}s" if m else f"{s}s"


_env.filters["dur"] = _fmt_dur
_env.filters["sevrank"] = lambda s: SEVERITY_ORDER.get(s, 0)


def server_version() -> str:
    try:
        from importlib.metadata import version
        return version("secure-vibe-delivery")
    except Exception:
        return "unknown"


def _hms(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%H:%M:%S")


def journal_lines(st: RunState) -> list[str]:
    out = []
    for i, e in enumerate(sorted(st.journal, key=lambda e: e["t"]), 1):
        line = f"{i:>3}. {_hms(e['t'])} [{e['kind']}] {e['text']}"
        if e["kind"] == "command":
            line += (f"\n       in: {e.get('cwd', '')}\n       exit: {e.get('exit_code')}  "
                     f"time: {e.get('duration_s')}s" + ("  TIMED OUT" if e.get("timed_out") else "")
                     + (f"  error: {e['error']}" if e.get("error") else ""))
        out.append(line)
    return out


def write_run_log(st: RunState, run_dir: Path, reports_dir: Path) -> Path:
    """The full step-by-step log as plain text, next to the report and in the run folder."""
    head = [f"secure-vibe-delivery run log", f"run {st.run_id}  verdict {st.verdict}",
            f"project {st.options.project_path}", ""]
    text = "\n".join(head + journal_lines(st)) + "\n"
    (run_dir / "run-log.txt").write_text(text)
    if st.report_path:
        p = Path(st.report_path).with_name(Path(st.report_path).stem + "-runlog.txt")
        p.write_text(text)
        return p
    return run_dir / "run-log.txt"


def build_summary(st: RunState, results: dict[str, CheckResult]) -> dict:
    v = st.verdict or gate.verdict(results)
    score = scoring.compute(results, st.options.mode != "gate")
    must = gate.must_fix(results)
    auto = summaries.automatic(results, v, score, must)
    return {
        "score": score, "overview_summary": st.ai_summary or auto, "automatic_summary": auto,
        "tool": "secure-vibe-delivery", "run_id": st.run_id, "project": st.options.project_path,
        "generated_at": datetime.now().isoformat(timespec="seconds"), "mode": st.options.mode,
        "verdict": v, "verdict_text": gate.VERDICT_TEXT[v],
        "checks": {k: {"status": r.status.value, "summary": r.summary,
                       "subchecks": [s.model_dump(mode="json") for s in r.subchecks]} for k, r in results.items()},
        "secrets": [s.model_dump(mode="json") for s in results["security"].secrets],
        "must_fix": must,
        "tool_versions": st.tool_versions,
        "code_version": st.code_version,
    }


def render_report(st: RunState, results: dict[str, CheckResult], run_dir: Path, reports_dir: Path,
                  html_path: Path | None = None) -> tuple[Path, Path]:
    """Writes the report. Pass html_path to rebuild an existing report in place (same file name)."""
    stamp = (html_path.stem.replace("svd-report-", "") if html_path else datetime.now().strftime("%Y%m%d-%H%M%S"))
    summary = build_summary(st, results)
    sec, fun, perf = results["security"], results["functional"], results["performance"]

    native_rel = ""
    if perf.data.get("native_report") and Path(perf.data["native_report"]).exists():
        native = reports_dir / f"svd-report-{stamp}-locust.html"
        shutil.copyfile(perf.data["native_report"], native)
        native_rel = native.name

    code = [f for f in sec.findings if f.category == "code"]
    libs = sorted([f for f in sec.findings if f.category == "library"],
                  key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.package, f.rule_id))
    pkgs = [f for f in sec.findings if f.category == "package"]
    iac_issues = [f for f in sec.findings if f.category == "iac"]
    iac_counts = {s: sum(1 for f in iac_issues if f.severity == s) for s in ("critical", "high", "medium", "low")}
    sev_counts = {s: sum(1 for f in code if f.severity == s) for s in ("critical", "high", "medium", "low")}
    lib_counts = {s: sum(1 for f in libs if f.severity == s) for s in ("critical", "high", "medium", "low")}

    not_run = sec.data.get("not_run", {})
    report_data = {
        "series": perf.data.get("series", []),
        "target": perf.data.get("p95_target_ms"),
        "severity": [
            {"label": "Our code", "counts": sev_counts,
             "notRun": "snyk-code" in not_run and "semgrep" in not_run},
            {"label": "Libraries", "counts": lib_counts, "notRun": "snyk-open-source" in not_run},
        ] + ([{"label": "Infrastructure", "counts": iac_counts, "notRun": "snyk-iac" in not_run}]
             if sec.data.get("iac", {}).get("files") else []),
        "coverage": [{"label": f["file"], "value": f["pct"]} for f in fun.data.get("coverage_files", [])[:10]],
        "coverageTarget": fun.data.get("coverage_threshold"),
        "endpoints": [{"label": f"{e['type']} {e['name']}", "value": e["p95"]}
                      for e in sorted(perf.data.get("endpoints", []), key=lambda e: -e["p95"])[:12] if e["requests"]],
    }
    checklist = [(name, r) for name, r in results.items()]
    commands = [(name, c) for name, r in results.items() for c in r.commands]
    html = _env.get_template("report.html.j2").render(
        st=st, opts=st.options, summary=summary, results=results, sec=sec, fun=fun, perf=perf,
        code=code, libs=libs, pkgs=pkgs, iac_issues=iac_issues, iac_counts=iac_counts, sev_counts=sev_counts, lib_counts=lib_counts,
        must_fix=summary["must_fix"], verdict=summary["verdict"], verdict_text=summary["verdict_text"],
        report_json=_json_script(report_data), native_rel=native_rel, checklist=checklist, commands=commands,
        Status=Status, generated=datetime.now().strftime("%d %b %Y, %H:%M"),
        duration=_fmt_dur((st.finished_at or time.time()) - st.created_at),
        project_name=Path(st.options.project_path).name,
        score=summary["score"], overview=summary["overview_summary"],
        journal=sorted(st.journal, key=lambda e: e["t"]), hms=_hms, runlog_rel=f"svd-report-{stamp}-runlog.txt",
        server_version=server_version(), history=command_history(st.journal), timeline=command_timeline(st, results),
        hero=overview_hero(st, results, summary["verdict"], summary["score"], summary["must_fix"]),
    )
    html_path = reports_dir / f"svd-report-{stamp}.html"
    html_path.write_text(html)
    summary["report_path"] = str(html_path)
    summary_path = reports_dir / f"svd-report-{stamp}.summary.json"
    summary_path.write_text(json.dumps(summary, indent=1, default=str))
    (run_dir / "report.html").write_text(html)
    return html_path, summary_path
