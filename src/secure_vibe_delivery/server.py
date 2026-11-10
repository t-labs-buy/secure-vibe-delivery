"""secure-vibe-delivery MCP server.

Runs the Secure Vibe Delivery pipeline (security → functional → performance) on a project and
writes a self-contained HTML go-live report.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal, Optional

try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import MCPServer
except ImportError:  # SDK 1.x
    from mcp.server.fastmcp import FastMCP as MCPServer

from .checks import locustgen
from .detect import detect
from .doctor import doctor
from . import installer
from .jobs import RunManager, open_in_browser, report_view, status_view
from .models import RunOptions
from .onboarding import Onboarding
from .proc import resolve_tool
from . import skills as skill_store

INSTRUCTIONS = """Secure Vibe Delivery runs three kinds of check on an AI-built project before go-live:
security (Snyk Open Source, Snyk Code, Snyk Secrets or a Semgrep fallback, Semgrep with AI-mistake rules,
package provenance), functional (pytest or Jest with a 70% coverage gate) and performance (Locust at 1.5x
the expected peak). It writes an HTML report with a GO / PROVISIONAL / NO-GO verdict.

First use: if svd_doctor or svd_run reports that setup is needed (Snyk missing or not signed in), offer
the one-time setup and walk the person through it step by step with svd_setup. Call it with no step
first: it changes nothing and returns the step list plus the current step's explanation and question.
Explain, ask, and wait for the person's answer; only then call svd_setup with the step in on_yes. One
step per answer. Never ask for or handle passwords: sign-in happens only in their browser.

Fixing: this server also serves skills (step-by-step know-how) as resources at skill://<skill>/<path>:
fix-security-findings, rotate-exposed-secrets, write-wrong-case-tests, write-locustfiles and
write-svd-rules. Each must-fix item in svd_report has a "guide" pointing at the one file that explains
how to fix it. Read it (as a resource, or with svd_skill) before fixing that item, and read further
references only when the file you're reading points to them. svd_skills lists every skill.

Workflow: svd_doctor → svd_run (returns a run_id at once) → poll svd_status until state is "done"
→ svd_report. Runs take minutes (a mode="gate" load test holds for 15 minutes), so poll rather than wait.
A check that didn't run counts as a failure. Performance needs target_url pointing at a running TEST
environment, never production."""

mcp = MCPServer("secure-vibe-delivery", instructions=INSTRUCTIONS)
skill_store.register(mcp)
runs = RunManager()
onboarding = Onboarding()


def _project(path: Optional[str]) -> str:
    p = Path(path or os.getcwd()).expanduser().resolve()
    if not p.is_dir():
        raise ValueError(f"project_path {p} is not a directory")
    return str(p)


@mcp.tool()
async def svd_doctor(project_path: Optional[str] = None) -> dict:
    """Check that the pipeline's tools are installed and usable for this project: Snyk CLI (and whether
    it's authenticated and whether Snyk Secrets is on the plan), Semgrep, Locust, and the project's own
    test tools (pytest + pytest-cov in its venv, or Jest). Returns versions and the actions to fix anything
    missing. Run this first.

    Args:
        project_path: Absolute path to the project root. Defaults to the server's working directory.
    """
    return await doctor(_project(project_path))


@mcp.tool()
async def svd_run(
    project_path: Optional[str] = None,
    target_url: Optional[str] = None,
    mode: Literal["quick", "gate"] = "quick",
    peak_users: int = 100,
    response_time_p95_ms: int = 1000,
    checks: Optional[list[Literal["security", "functional", "performance"]]] = None,
    locustfile: Optional[str] = None,
    coverage_threshold: float = 70.0,
    stop_on_security_fail: bool = False,
    duration: Optional[str] = None,
    wait_seconds: int = 0,
    allow_incomplete: bool = False,
    open_report: bool = True,
) -> dict:
    """Start the full Secure Vibe Delivery pipeline in the background and return a run_id immediately.
    Poll svd_status(run_id) until state is "done", then call svd_report(run_id).

    Args:
        project_path: Absolute path to the project root. Defaults to the server's working directory.
        target_url: Base URL of the running TEST environment for the Locust load test, e.g.
            http://127.0.0.1:8000. Never production. Without it the performance check is NOT_RUN (a failure).
        mode: "quick" (default) holds the load for 2 minutes and gives an indicative result;
            "gate" holds 1.5x peak for 15 minutes, as the roadmap requires for go-live.
        peak_users: Expected peak concurrent users. Locust runs ceil(1.5 x peak_users).
        response_time_p95_ms: Agreed p95 response-time target in milliseconds.
        checks: Subset of ["security", "functional", "performance"]. Default: all three. Checks left
            out appear in the report as NOT_RUN, so the verdict stays NO-GO.
        locustfile: Path (relative to the project) of a locustfile to use. Default: the project's
            locustfile.py, or a generated one.
        coverage_threshold: Minimum line coverage percentage. Default 70.
        stop_on_security_fail: Skip functional and performance checks if security doesn't pass.
        duration: Override the hold time, e.g. "5m". Only a 15m+ run in gate mode counts for go-live.
        wait_seconds: Optionally wait up to this many seconds (max 50) for the run to finish before returning.
        open_report: Open the finished HTML report in the person's default browser (default true).
            The environment variable SVD_OPEN_REPORT=0 turns this off on a machine.
        allow_incomplete: Run even if Snyk isn't installed or signed in. The Snyk scans then show as
            "didn't run" and the verdict is NO-GO. By default the server stops and asks for setup first.
    """
    wanted = list(checks or ["security", "functional", "performance"])
    if "security" in wanted and not allow_incomplete:
        signed_in = await installer.snyk_signed_in()
        if not signed_in:
            return {
                "state": "setup_required",
                "reason": "Snyk isn't installed" if signed_in is None else "Snyk isn't signed in yet",
                "tell_the_user": ["Before the first check, there's a short one-time setup for the Snyk "
                                  "security scanner. I can walk you through it step by step. Shall we start?"],
                "next": "If they agree, call svd_setup with no step and walk them through it one step at a time. "
                        "Then call svd_run again once it reports ready. (Or pass allow_incomplete=true to run "
                        "without Snyk; the verdict will be NO-GO.)",
            }
    opts = RunOptions(
        project_path=_project(project_path), target_url=target_url, mode=mode, peak_users=max(1, peak_users),
        response_time_p95_ms=response_time_p95_ms, checks=wanted,
        locustfile=locustfile, coverage_threshold=coverage_threshold, stop_on_security_fail=stop_on_security_fail,
        duration=duration, open_report=open_report,
    )
    st = runs.start(opts)
    await runs.wait(st.run_id, min(max(wait_seconds, 0), 50))
    view = status_view(st)
    if st.state != "done":
        view["next"] = "Poll svd_status with this run_id every 30-60 seconds until state is 'done'."
    return view


@mcp.tool()
async def svd_setup(
    step: Optional[Literal["status", "install_snyk", "sign_in_snyk", "check_snyk_code", "sign_in_semgrep",
                           "skip_semgrep", "check"]] = None,
    wait_seconds: int = 0,
) -> dict:
    """Guided one-time setup for new users, one step at a time.

    Call with no step first. That changes nothing: it returns the setup steps with their status, and
    current_step with a plain explanation, the question to ask the person (ask_the_user) and the step
    to call if they agree (on_yes). Explain the step in your own words, ask, and WAIT for their reply.
    Only when they agree, call svd_setup again with that step:
      install_snyk    - download the official Snyk CLI from snyk.io (checksum-verified, into this
                        server's own folder; nothing is installed system-wide)
      sign_in_snyk    - open the free Snyk sign-up / sign-in page in their browser
      check_snyk_code - after the person turns on "Enable Snyk Code" in their Snyk settings and saves,
                        confirm it took effect
      sign_in_semgrep - optional: open Semgrep's sign-in page
      skip_semgrep    - skip the optional Semgrep sign-in
      check           - re-check progress (use wait_seconds up to 50 while a download or sign-in runs)
    Never run a step the person hasn't agreed to, and never ask for a password.

    Args:
        step: The step to perform. Omit (or "status") to only report where setup stands.
        wait_seconds: Wait up to this many seconds (max 50) for a download or sign-in before reporting.
    """
    return await onboarding.step(step, wait_seconds)


@mcp.tool()
async def svd_status(run_id: Optional[str] = None, project_path: Optional[str] = None,
                     wait_seconds: int = 0) -> dict:
    """Progress of a pipeline run: which check is running, per-check results so far and recent log lines.
    When state is "done" it includes the verdict and report path.

    Args:
        run_id: The id returned by svd_run. If omitted, the latest run for project_path is shown.
        project_path: Needed to find runs from before a server restart, or with no run_id.
        wait_seconds: Optionally wait up to this many seconds (max 50) for the run to finish first.
    """
    st = runs.load(run_id, project_path) if run_id else runs.latest(_project(project_path))
    if st is None:
        return {"error": f"No run found for run_id={run_id!r}. Pass project_path to look on disk."}
    await runs.wait(st.run_id, min(max(wait_seconds, 0), 50))
    return status_view(st)


@mcp.tool()
async def svd_report(run_id: Optional[str] = None, project_path: Optional[str] = None, top: int = 10,
                     open: bool = False) -> dict:
    """The finished run's verdict, the path to the HTML report, and the top must-fix items in the
    roadmap's priority order (leaked keys → critical/high code issues → critical libraries → packages →
    failing tests → coverage → performance). Secrets are always masked.

    Args:
        run_id: The id returned by svd_run. If omitted, the latest run for project_path is used.
        project_path: Needed to find runs from before a server restart, or with no run_id.
        top: How many must-fix items to return (the HTML report has all of them).
        open: Open the HTML report in the person's browser again (it opens automatically when a run finishes).
    """
    st = runs.load(run_id, project_path) if run_id else runs.latest(_project(project_path))
    if st is None:
        return {"error": f"No run found for run_id={run_id!r}."}
    if open and st.state == "done" and st.report_path:
        st.report_opened = await open_in_browser(st.report_path) or st.report_opened
    return report_view(st, top=max(1, top))


@mcp.tool()
async def svd_write_summary(
    overall: str,
    went_well: list[str],
    needs_attention: list[str],
    fix_first: list[str],
    run_id: Optional[str] = None,
    project_path: Optional[str] = None,
    reopen: bool = True,
) -> dict:
    """Add your written summary to the finished report's Overview tab, then rebuild the report in place
    (and reopen it). Write it from the run's results (svd_report and its summary_path) in plain language
    a non-specialist understands. Never include secret values: use the masked values only.

    Args:
        overall: Two to four sentences: the verdict, the score, and what matters most.
        went_well: Short items for what passed or looks healthy (up to 8).
        needs_attention: Short items for where the issues are (up to 8).
        fix_first: The few items that need immediate attention, most urgent first (up to 8).
        run_id: The run to update. Defaults to the latest run for project_path.
        project_path: Needed when the run isn't in this server's memory.
        reopen: Open the updated report in the browser.
    """
    st = runs.load(run_id, project_path) if run_id else runs.latest(_project(project_path))
    if st is None or st.state != "done" or not st.report_path:
        return {"error": "No finished run found to add a summary to."}
    from .gate import ensure_all
    from .report.render import render_report
    from .summary import ai as ai_summary
    try:
        st.ai_summary = ai_summary(overall, went_well, needs_attention, fix_first)
    except ValueError as e:
        return {"error": str(e)}
    run_dir = Path(st.options.project_path) / ".svd" / "runs" / st.run_id
    html, summary_path = render_report(st, ensure_all(st), run_dir, Path(st.report_path).parent,
                                       html_path=Path(st.report_path))
    st.summary_path = str(summary_path)
    (run_dir / "state.json").write_text(st.model_dump_json(indent=1))
    opened = await open_in_browser(str(html)) if reopen else False
    return {"report_path": str(html), "summary_added": True, "reopened": opened,
            "tell_the_user": "The summary is in the report's Overview tab"
                             + (" (the updated report just opened in your browser)." if opened else ".")}


@mcp.tool()
async def svd_skills() -> dict:
    """List the skills this server provides: step-by-step know-how for fixing what the report finds.
    Returns each skill's name, description and the address (skill://...) and SHA-256 digest of each of
    its files, without the contents. Read a skill's SKILL.md only when a task needs it (svd_skill or the
    skill:// resource), and its reference files only when SKILL.md points to them."""
    return {"skills": skill_store.listing(),
            "how_to_use": "Pick the skill whose description fits the task, read its SKILL.md, then read only "
                          "the reference files it points to. These skills are instructions only (no scripts)."}


@mcp.tool()
async def svd_skill(uri: str) -> dict:
    """Read one skill file, for clients that can't read MCP resources directly. Pass a skill:// address
    from svd_skills or from a must-fix item's "guide" (for example
    skill://fix-security-findings/references/sql-injection.md), or just a skill name for its SKILL.md.
    Relative paths inside a skill file (like references/x.md) are relative to that skill's folder.

    Args:
        uri: skill://<skill>/<path>, <skill>/<path>, or <skill>.
    """
    f = skill_store.read(uri)
    if f is None:
        return {"error": f"No skill file at {uri!r}. Call svd_skills for the list."}
    return f


@mcp.tool()
async def svd_generate_locustfile(project_path: Optional[str] = None, target_url: Optional[str] = None,
                                  overwrite: bool = False) -> dict:
    """Generate a starter locustfile.py for the project from its OpenAPI spec (local file or
    <target_url>/openapi.json) or from routes found in the code (FastAPI, Flask, Express). Review and
    edit it so it reflects the 3-5 journeys users do most, then run svd_run.

    Args:
        project_path: Absolute path to the project root.
        target_url: Running test environment, used to fetch an OpenAPI spec if there's no local one.
        overwrite: Replace an existing locustfile.py.
    """
    root = Path(_project(project_path))
    info = detect(root)
    dest = root / "locustfile.py"
    src, how = locustgen.generate(root, target_url, info.openapi_file)
    if dest.exists() and not overwrite:
        dest = root / "locustfile.generated.py"
    dest.write_text(src)
    return {"path": str(dest), "derived_from": how,
            "next": "Review the tasks and weights, add journeys that need parameters, then call svd_run."}


@mcp.prompt(name="secure-vibe-delivery")
def secure_vibe_delivery_prompt(target_url: str = "", mode: str = "quick", peak_users: str = "100") -> str:
    """Run the full Secure Vibe Delivery pipeline on the current project and summarise what to fix."""
    url = f' target_url="{target_url}",' if target_url else ""
    return f"""Run the Secure Vibe Delivery pipeline on this project.

1. Call svd_doctor with the absolute path of the current project. If Snyk is missing or not signed
   in, offer the one-time setup and, if I agree, walk me through svd_setup one step at a time, waiting
   for my answer at each step. Mention
   any "Recommended" actions (such as signing in to Semgrep), but carry on.
2. {"" if target_url else "Ask me for the test environment URL for the load test (or confirm I want to skip performance). "}Call svd_run with project_path,{url} mode="{mode}", peak_users={peak_users}.
3. Poll svd_status every 30-60 seconds until state is "done". Give me a one-line update each time.
4. Call svd_report. Write the report's Overview summary from the results and add it with
   svd_write_summary (plain language, no secret values). Tell me the verdict, the secure-health score,
   that the HTML report has opened in my browser (or give me its path if report_opened is false), and summarise the
   must-fix items in priority order. Never print secret values; use the masked values.
5. Offer to fix the top items, starting with exposed secrets (which also need rotating) and
   critical/high code issues. Before fixing an item, read the skill file in its "guide" field and
   follow it. Then re-run the pipeline."""


@mcp.prompt(name="setup")
def setup_prompt() -> str:
    """One-time setup, walked through step by step: get Snyk, sign up / sign in, optional Semgrep."""
    return """Walk me through setting up secure-vibe-delivery for the first time, one step at a time, in simple
language. I may be new to all of this.

1. Call svd_setup with no step. Show me the steps as a short checklist with their status.
2. For the current step: explain in two or three plain sentences what it is and why it's needed, then
   ask me the question. Stop and wait for my answer. Don't start anything I haven't agreed to.
3. When I agree, call svd_setup with that step. Tell me what happened and what to do next. If a page
   opens in my browser, tell me exactly what to do there, and give me the link in case it didn't open.
   Never ask me for a password: I sign in only in the browser.
4. When I say I'm done with a step, call svd_setup with step "check" (wait_seconds 30) and move to the
   next step the same way.
5. When setup is complete, tell me I'm ready and offer to run a check on this project."""


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
