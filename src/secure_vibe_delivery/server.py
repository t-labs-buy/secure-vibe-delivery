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
from .jobs import RunManager, report_view, status_view
from .models import RunOptions
from .onboarding import Onboarding
from .proc import resolve_tool

INSTRUCTIONS = """Secure Vibe Delivery runs three kinds of check on an AI-built project before go-live:
security (Snyk Open Source, Snyk Code, Snyk Secrets or a Semgrep fallback, Semgrep with AI-mistake rules,
package provenance), functional (pytest or Jest with a 70% coverage gate) and performance (Locust at 1.5x
the expected peak). It writes an HTML report with a GO / PROVISIONAL / NO-GO verdict.

First use: if svd_doctor or svd_run reports that setup is needed (Snyk missing or not signed in), call
svd_setup. It downloads Snyk if needed and starts a one-time browser sign-up / sign-in. Relay its
"tell_the_user" lines to the person in plain words, give them any sign-in link, and call svd_setup
again (wait_seconds up to 50) until "ready" is true. Never ask for or handle passwords yourself.

Workflow: svd_doctor → svd_run (returns a run_id at once) → poll svd_status until state is "done"
→ svd_report. Runs take minutes (a mode="gate" load test holds for 15 minutes), so poll rather than wait.
A check that didn't run counts as a failure. Performance needs target_url pointing at a running TEST
environment, never production."""

mcp = MCPServer("secure-vibe-delivery", instructions=INSTRUCTIONS)
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
                "tell_the_user": ["Before the first check, Snyk needs a one-time setup: I can download it and "
                                  "open a free sign-up / sign-in page in your browser. Shall I start?"],
                "next": "Call svd_setup, then call svd_run again once it reports ready. "
                        "(Or pass allow_incomplete=true to run without Snyk; the verdict will be NO-GO.)",
            }
    opts = RunOptions(
        project_path=_project(project_path), target_url=target_url, mode=mode, peak_users=max(1, peak_users),
        response_time_p95_ms=response_time_p95_ms, checks=wanted,
        locustfile=locustfile, coverage_threshold=coverage_threshold, stop_on_security_fail=stop_on_security_fail,
        duration=duration,
    )
    st = runs.start(opts)
    await runs.wait(st.run_id, min(max(wait_seconds, 0), 50))
    view = status_view(st)
    if st.state != "done":
        view["next"] = "Poll svd_status with this run_id every 30-60 seconds until state is 'done'."
    return view


@mcp.tool()
async def svd_setup(
    install_snyk: bool = True,
    sign_in_snyk: bool = True,
    sign_in_semgrep: bool = False,
    wait_seconds: int = 0,
) -> dict:
    """One-time setup for new users. Downloads the Snyk CLI if it's missing (official build from snyk.io,
    checksum-verified, into this server's own cache folder: nothing is installed system-wide), and starts
    the free Snyk sign-up / sign-in in the person's browser. Optionally starts the Semgrep sign-in too.

    Each call moves things forward and returns at once; call it again to follow progress. Relay the
    "tell_the_user" lines to the person in plain words, including any sign-in link. When "ready" is true,
    the person can run svd_run. Only call this when the person agrees to set up.

    Args:
        install_snyk: Download Snyk if it isn't installed.
        sign_in_snyk: Start the Snyk sign-in if not signed in (required for the security checks).
        sign_in_semgrep: Also start the optional Semgrep sign-in (more detailed results).
        wait_seconds: Wait up to this many seconds (max 50) for downloads or sign-ins to finish first.
    """
    return await onboarding.step(install_snyk, sign_in_snyk, sign_in_semgrep, wait_seconds)


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
async def svd_report(run_id: Optional[str] = None, project_path: Optional[str] = None, top: int = 10) -> dict:
    """The finished run's verdict, the path to the HTML report, and the top must-fix items in the
    roadmap's priority order (leaked keys → critical/high code issues → critical libraries → packages →
    failing tests → coverage → performance). Secrets are always masked.

    Args:
        run_id: The id returned by svd_run. If omitted, the latest run for project_path is used.
        project_path: Needed to find runs from before a server restart, or with no run_id.
        top: How many must-fix items to return (the HTML report has all of them).
    """
    st = runs.load(run_id, project_path) if run_id else runs.latest(_project(project_path))
    if st is None:
        return {"error": f"No run found for run_id={run_id!r}."}
    return report_view(st, top=max(1, top))


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
   in, offer the one-time setup and, if I agree, follow the steps of svd_setup until it's ready. Mention
   any "Recommended" actions (such as signing in to Semgrep), but carry on.
2. {"" if target_url else "Ask me for the test environment URL for the load test (or confirm I want to skip performance). "}Call svd_run with project_path,{url} mode="{mode}", peak_users={peak_users}.
3. Poll svd_status every 30-60 seconds until state is "done". Give me a one-line update each time.
4. Call svd_report. Tell me the verdict, give me the path to the HTML report, and summarise the
   must-fix items in priority order. Never print secret values; use the masked values.
5. Offer to fix the top items, starting with exposed secrets (which also need rotating) and
   critical/high code issues, then re-run the pipeline."""


@mcp.prompt(name="setup")
def setup_prompt(include_semgrep: str = "yes") -> str:
    """One-time setup: install Snyk if needed and sign up / sign in to Snyk (and optionally Semgrep)."""
    semgrep = include_semgrep.strip().lower() in ("yes", "y", "true", "1")
    return f"""Help me set up secure-vibe-delivery for the first time. Use simple language.

1. Explain in two sentences what will happen: you'll download Snyk from snyk.io if it isn't installed
   (into the server's own folder, nothing system-wide), then a browser window opens for a free Snyk
   account{', and another for a free Semgrep account (optional, for more detailed results)' if semgrep else ''}.
2. Call svd_setup with sign_in_semgrep={'true' if semgrep else 'false'}.
3. Tell me each "tell_the_user" line, including any sign-in link, in plain words. Never ask me for a
   password: sign-in happens only in the browser.
4. Call svd_setup again with wait_seconds=45 until "ready" is true, giving me a short update each time.
5. When ready, tell me I'm set, and that I can now ask you to "run secure vibe delivery on this project"."""


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
