"""Background pipeline runs. MCP clients time out long tool calls, so runs execute as asyncio
tasks inside the server and the client polls `svd_status`. State is persisted to disk so a
report can still be found after the server restarts."""
from __future__ import annotations

import asyncio
import json
import secrets
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

from . import gate
from .checks import functional, performance, security
from .checks.context import CheckContext
from .detect import detect
from .doctor import tool_versions
from .models import RunOptions, RunState, Status
from .report.render import render_report

RUNNERS = {"security": security.run, "functional": functional.run, "performance": performance.run}


def svd_dir(project: Path) -> Path:
    d = project / ".svd"
    d.mkdir(parents=True, exist_ok=True)
    gi = d / ".gitignore"
    if not gi.exists():
        gi.write_text("# secure-vibe-delivery output; keep it out of git\n*\n")
    return d


class RunManager:
    def __init__(self) -> None:
        self.runs: dict[str, RunState] = {}
        self.dirs: dict[str, Path] = {}
        self.tasks: dict[str, asyncio.Task] = {}

    # ---- persistence -----------------------------------------------------------------
    def _save(self, state: RunState) -> None:
        d = self.dirs[state.run_id]
        tmp = d / "state.json.tmp"
        tmp.write_text(state.model_dump_json(indent=1))
        tmp.replace(d / "state.json")

    def load(self, run_id: str, project_path: Optional[str] = None) -> Optional[RunState]:
        if run_id in self.runs:
            return self.runs[run_id]
        if project_path:
            p = Path(project_path).expanduser().resolve() / ".svd" / "runs" / run_id / "state.json"
            if p.exists():
                st = RunState.model_validate_json(p.read_text())
                if st.state in ("queued", "running"):
                    st.state, st.error = "error", "The server restarted while this run was in progress."
                return st
        return None

    def latest(self, project_path: str) -> Optional[RunState]:
        runs = Path(project_path).expanduser().resolve() / ".svd" / "runs"
        if not runs.exists():
            return None
        ids = sorted((p.name for p in runs.iterdir() if (p / "state.json").exists()), reverse=True)
        return self.load(ids[0], project_path) if ids else None

    # ---- execution -------------------------------------------------------------------
    def start(self, opts: RunOptions) -> RunState:
        root = Path(opts.project_path).expanduser().resolve()
        opts.project_path = str(root)
        run_id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)
        d = svd_dir(root) / "runs" / run_id
        d.mkdir(parents=True, exist_ok=True)
        st = RunState(run_id=run_id, options=opts, created_at=time.time(),
                      progress={c: "queued" for c in gate.CHECKS if c in opts.checks})
        self.runs[run_id], self.dirs[run_id] = st, d
        self._save(st)
        self.tasks[run_id] = asyncio.create_task(self._run(st, root, d))
        return st

    async def _run(self, st: RunState, root: Path, d: Path) -> None:
        st.state = "running"

        def log(msg: str) -> None:
            st.messages.append(f"{time.strftime('%H:%M:%S')} {msg}")
            st.messages[:] = st.messages[-200:]
            self._save(st)

        try:
            st.tool_versions = await tool_versions(root)
            info = detect(root)
            log(f"Project: {'Python ' if info.is_python else ''}{'JavaScript ' if info.is_js else ''}"
                f"tests={info.test_runner or 'none'}")
            ctx = CheckContext(root=root, run_dir=d, info=info, options=st.options, log=log)
            for name in gate.CHECKS:
                if name not in st.options.checks:
                    continue
                if (name != "security" and st.options.stop_on_security_fail
                        and st.results.get("security") and st.results["security"].status != Status.PASS):
                    st.progress[name] = "skipped"
                    log(f"{name}: skipped because security didn't pass (stop_on_security_fail)")
                    continue
                st.current, st.progress[name] = name, "running"
                log(f"{name}: started")
                st.results[name] = await RUNNERS[name](ctx)
                st.progress[name] = "done"
                log(f"{name}: {st.results[name].status.value}: {st.results[name].summary}")
            st.current = "report"
            results = gate.ensure_all(st)
            st.verdict = gate.verdict(results)
            reports = svd_dir(root) / "reports"
            reports.mkdir(exist_ok=True)
            html_path, summary_path = render_report(st, results, d, reports)
            st.report_path, st.summary_path = str(html_path), str(summary_path)
            st.state = "done"
            log(f"Verdict {st.verdict}. Report: {html_path}")
        except Exception as e:  # keep the server alive; surface the error to the client
            st.state, st.error = "error", f"{type(e).__name__}: {e}"
            (d / "error.txt").write_text(traceback.format_exc())
            log(f"Run failed: {st.error}")
        finally:
            st.current, st.finished_at = "", time.time()
            self._save(st)

    async def wait(self, run_id: str, seconds: float) -> None:
        task = self.tasks.get(run_id)
        if task and seconds > 0:
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=seconds)
            except asyncio.TimeoutError:
                pass


def status_view(st: RunState) -> dict:
    elapsed = (st.finished_at or time.time()) - st.created_at
    view = {
        "run_id": st.run_id, "state": st.state, "current_check": st.current, "progress": st.progress,
        "elapsed_s": round(elapsed), "recent_log": st.messages[-8:],
        "checks": {k: {"status": v.status.value, "summary": v.summary} for k, v in st.results.items()},
    }
    if st.state == "running" and st.current == "performance":
        dur = st.options.duration or ("15m" if st.options.mode == "gate" else "2m")
        view["hint"] = f"Load test in progress ({dur}). Poll again in about 30-60 seconds."
    if st.state == "done":
        view.update(verdict=st.verdict, report_path=st.report_path, summary_path=st.summary_path,
                    next="Call svd_report for the must-fix list.")
    if st.error:
        view["error"] = st.error
    return view


def report_view(st: RunState, top: int = 10) -> dict:
    if st.state != "done" or not st.summary_path:
        return {"run_id": st.run_id, "state": st.state, "error": st.error,
                "message": "The run hasn't finished yet; poll svd_status."}
    summary = json.loads(Path(st.summary_path).read_text())
    return {
        "run_id": st.run_id, "verdict": summary["verdict"], "verdict_text": summary["verdict_text"],
        "report_path": st.report_path, "report_url": Path(st.report_path).as_uri(),
        "summary_path": st.summary_path, "checks": summary["checks"],
        "must_fix_total": len(summary["must_fix"]), "must_fix_top": summary["must_fix"][:top],
        "instructions": "Open report_path in a browser. Fix items in priority order, then run svd_run again: "
                        "every fix is followed by a full re-scan.",
    }
