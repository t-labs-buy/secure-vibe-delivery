"""Guided one-time setup, driven by repeated svd_setup calls.

Each call moves things forward without blocking for long: it starts the Snyk download if Snyk
is missing, starts the browser sign-ins, and reports in plain words what the person should do
next. Calling it again picks up where the last call left off.
"""
from __future__ import annotations

import asyncio
import time
from typing import Optional

from . import installer
from .proc import resolve_tool

SIGN_IN_EXPIRES_S = 15 * 60


class Onboarding:
    def __init__(self) -> None:
        self.install_state = "idle"  # idle | downloading | ready | failed
        self.install_error = ""
        self.downloaded = 0
        self.install_task: Optional[asyncio.Task] = None
        self.snyk = installer.SignIn("snyk")
        self.semgrep = installer.SignIn("semgrep")
        self._sign_in_after_install = False

    # -- helpers -------------------------------------------------------------------------
    def _expire(self, si: installer.SignIn) -> None:
        if si.state in ("starting", "waiting_for_browser") and time.time() - si.started_at > SIGN_IN_EXPIRES_S:
            try:
                si.proc.terminate()
            except Exception:
                pass
            si.state, si.detail = "failed", "The sign-in link expired. Run setup again for a fresh one."

    async def _install(self) -> None:
        self.install_state, self.install_error, self.downloaded = "downloading", "", 0
        try:
            await installer.install_snyk(progress=lambda n: setattr(self, "downloaded", n))
            self.install_state = "ready"
            if self._sign_in_after_install and self.snyk.state in ("idle", "failed"):
                installer.start_snyk_auth(self.snyk)
        except Exception as e:
            self.install_state, self.install_error = "failed", f"{type(e).__name__}: {e}"[:300]

    async def wait(self, seconds: float) -> None:
        end = time.time() + max(0, min(seconds, 50))
        while time.time() < end:
            busy = (self.install_state == "downloading" or
                    self.snyk.state in ("starting", "waiting_for_browser") or
                    self.semgrep.state in ("starting", "waiting_for_browser"))
            if not busy:
                return
            await asyncio.sleep(1)

    # -- one step ------------------------------------------------------------------------
    async def step(self, install_snyk: bool, sign_in_snyk: bool, sign_in_semgrep: bool,
                   wait_seconds: int) -> dict:
        for si in (self.snyk, self.semgrep):
            self._expire(si)

        # Snyk program
        if resolve_tool("snyk") is None and self.install_state != "downloading":
            if install_snyk:
                self._sign_in_after_install = sign_in_snyk
                self.install_task = asyncio.create_task(self._install())
                await asyncio.sleep(0.5)
        # Snyk sign-in
        snyk_ok = await installer.snyk_signed_in()
        if snyk_ok:
            self.snyk.state = "signed_in"
        elif snyk_ok is False and sign_in_snyk and self.snyk.state in ("idle", "failed", "signed_in"):
            installer.start_snyk_auth(self.snyk)
        # Semgrep sign-in (optional)
        semgrep_ok = await installer.semgrep_signed_in()
        if semgrep_ok:
            self.semgrep.state = "signed_in"
        elif semgrep_ok is False and sign_in_semgrep and self.semgrep.state in ("idle", "failed", "signed_in"):
            installer.start_semgrep_login(self.semgrep)

        # give a freshly started sign-in a moment to print its link
        for _ in range(20):
            if all(si.state not in ("starting",) for si in (self.snyk, self.semgrep)):
                break
            await asyncio.sleep(0.5)
        if wait_seconds:
            await self.wait(wait_seconds)
            snyk_ok = await installer.snyk_signed_in()
            semgrep_ok = await installer.semgrep_signed_in()
            if snyk_ok:
                self.snyk.state = "signed_in"
            if semgrep_ok:
                self.semgrep.state = "signed_in"
        return self.view(snyk_ok, semgrep_ok)

    # -- what to tell the person ---------------------------------------------------------
    def view(self, snyk_ok: Optional[bool], semgrep_ok: Optional[bool]) -> dict:
        snyk_path = resolve_tool("snyk")
        tell: list[str] = []
        snyk = {"installed": bool(snyk_path), "signed_in": bool(snyk_ok)}
        if self.install_state == "downloading":
            snyk["install"] = f"downloading ({self.downloaded // (1 << 20)} MB so far)"
            tell.append("Downloading Snyk from snyk.io. This takes a minute; I'll check again shortly.")
        elif self.install_state == "failed":
            snyk["install"] = f"failed: {self.install_error}"
            tell.append(f"I couldn't download Snyk ({self.install_error}). Install it yourself: "
                        "brew tap snyk/tap && brew install snyk (Mac) or npm install -g snyk (Windows).")
        elif self.install_state == "ready":
            snyk["install"] = f"downloaded to {snyk_path[0] if snyk_path else ''} (checksum verified)"
        if snyk_path and not snyk_ok:
            if self.snyk.state == "waiting_for_browser":
                snyk["sign_in"] = "waiting for you in the browser"
                tell.append("A browser window should have opened for Snyk. Sign up (it's free) or log in there, "
                            "then come back. If no window opened, use this link: " + self.snyk.url)
            elif self.snyk.state == "failed":
                snyk["sign_in"] = f"didn't finish: {self.snyk.detail}"
                tell.append("The Snyk sign-in didn't finish. Ask me to run setup again for a fresh link.")
            elif self.snyk.state == "starting":
                snyk["sign_in"] = "starting"
            else:
                snyk["sign_in"] = "not started"
                tell.append("Snyk needs a one-time sign-in. Ask me to run setup to start it.")
        elif snyk_ok:
            snyk["sign_in"] = "done"

        semgrep = {"available": semgrep_ok is not None, "signed_in": bool(semgrep_ok), "optional": True}
        if semgrep_ok is None:
            tell.append("Semgrep isn't available. Install uv (it runs Semgrep for you).")
        elif not semgrep_ok:
            if self.semgrep.state == "waiting_for_browser":
                semgrep["sign_in"] = "waiting for you in the browser"
                tell.append("For Semgrep (optional), sign up or log in in the browser window, or use this link: "
                            + self.semgrep.url)
            elif self.semgrep.state == "manual":
                semgrep["sign_in"] = "run it yourself"
                tell.append(self.semgrep.detail)
            elif self.semgrep.state == "failed":
                semgrep["sign_in"] = f"didn't finish: {self.semgrep.detail}"
            else:
                semgrep["sign_in"] = "not started (optional)"
                tell.append("Optional: a free Semgrep sign-in gives more detailed results. "
                            "Ask me to run setup with Semgrep sign-in if you'd like it.")
        else:
            semgrep["sign_in"] = "done"

        ready = bool(snyk_path) and bool(snyk_ok)
        if ready:
            tell.insert(0, "Snyk is installed and signed in, so you're ready. Ask me to run secure vibe delivery "
                           "on your project.")
        busy = self.install_state == "downloading" or "waiting" in (self.snyk.state + self.semgrep.state)
        return {
            "ready": ready, "snyk": snyk, "semgrep": semgrep, "tell_the_user": tell,
            "next": ("Call svd_setup again (with wait_seconds up to 50) to see when this finishes." if busy and not ready
                     else "Call svd_run to check a project." if ready else "Call svd_setup to continue."),
        }
