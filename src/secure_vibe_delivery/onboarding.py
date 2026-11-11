"""Guided one-time setup: a step-by-step walkthrough driven by repeated svd_setup calls.

Nothing happens without the person's go-ahead. A call with no step only reports where setup
stands and what the next step is, with a plain explanation and a question for the assistant to
ask. Each action (download Snyk, open the Snyk sign-in, open the Semgrep sign-in) is its own step,
run only when the assistant passes that step after the person agrees.
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Optional

from . import installer
from .proc import resolve_tool

SIGN_IN_EXPIRES_S = 15 * 60
STEPS = ("install_snyk", "sign_in_snyk", "enable_snyk_code", "sign_in_semgrep")

ASSISTANT_RULES = (
    "Walk the person through setup one step at a time. Show them the step list, explain the current "
    "step in your own plain words, ask the question in ask_the_user, and WAIT for their answer. Only "
    "when they agree, call svd_setup with the step named in on_yes. Never run a step they haven't "
    "agreed to, never combine steps, and never ask for a password (sign-in happens only in their browser)."
)


def plan(snyk_installed: bool, downloading: bool, download_failed: str, snyk_signed_in: bool,
         snyk_waiting: bool, snyk_url: str, semgrep_available: bool, semgrep_signed_in: bool,
         semgrep_waiting: bool, semgrep_url: str, semgrep_skipped: bool, semgrep_manual: str,
         download_mb: int = 0, snyk_code: Optional[bool] = True, snyk_code_asked: bool = False) -> dict:
    """Pure function: the walkthrough's step list and the one step to talk about now."""
    s1 = "done" if snyk_installed else "in_progress" if downloading else "to_do"
    s2 = "done" if snyk_signed_in else "waiting_for_you" if snyk_waiting else "to_do"
    code_ok = snyk_code is True
    sc = "done" if code_ok else "waiting_for_you" if snyk_code_asked else "to_do"
    if semgrep_signed_in:
        s3 = "done"
    elif semgrep_skipped:
        s3 = "skipped"
    elif semgrep_waiting or semgrep_manual:
        s3 = "waiting_for_you"
    else:
        s3 = "optional"
    steps = [
        {"n": 1, "id": "install_snyk", "title": "Get the Snyk scanner", "status": s1},
        {"n": 2, "id": "sign_in_snyk", "title": "Create your free Snyk account, or sign in", "status": s2},
        {"n": 3, "id": "enable_snyk_code", "title": "Turn on Snyk Code in your Snyk settings", "status": sc},
        {"n": 4, "id": "sign_in_semgrep", "title": "Sign in to Semgrep (optional)", "status": s3},
    ]

    if not snyk_installed:
        if downloading:
            current = {
                "step": 1, "explain": f"Snyk is downloading from snyk.io ({download_mb} MB so far). It's a large file, "
                                      "so this can take a minute or two.",
                "ask_the_user": "Shall I check again in a moment?",
                "on_yes": {"step": "check", "wait_seconds": 45},
            }
        else:
            current = {
                "step": 1,
                "explain": ("Snyk is the main security scanner. It checks the libraries your project uses and the code "
                            "itself for known security problems. It isn't installed on this computer yet. I can "
                            "download the official copy from snyk.io (about 170 MB), check it against the checksum "
                            "Snyk publishes, and keep it in this tool's own folder. Nothing is installed system-wide."
                            + (f" (The last download failed: {download_failed}.)" if download_failed else "")),
                "ask_the_user": "Shall I download Snyk now?",
                "on_yes": {"step": "install_snyk"},
                "on_no": "Setup pauses. They can install Snyk themselves (brew tap snyk/tap && brew install snyk on "
                         "a Mac, npm install -g snyk on Windows) and ask you to continue setup afterwards.",
            }
    elif not snyk_signed_in:
        if snyk_waiting:
            current = {
                "step": 2,
                "explain": ("The Snyk page should be open in their browser. There they sign up for a free account "
                            "(or log in if they already have one), then click to grant access to the Snyk command-line "
                            "tool. When the page says they can return, they're done there. If no page opened, they "
                            "can use this link: " + snyk_url),
                "ask_the_user": "Let me know once you've finished on the Snyk page.",
                "on_yes": {"step": "check", "wait_seconds": 30},
            }
        else:
            current = {
                "step": 2,
                "explain": ("Snyk needs a free account, used only to run the scans. When they're ready, I'll open "
                            "Snyk's sign-in page in their browser. There they'll: 1) sign up with their work email, or "
                            "log in if they already have an account; 2) click to grant access to the Snyk command-line "
                            "tool; 3) come back here. Their password goes only to snyk.io, never into this chat."),
                "ask_the_user": "Ready for me to open the Snyk sign-in page in your browser?",
                "on_yes": {"step": "sign_in_snyk"},
                "on_no": "Setup pauses here; they can ask you to continue setup whenever they're ready.",
            }
    elif not code_ok:
        howto = ("1) go to app.snyk.io (they're already signed in); 2) open Settings, at the bottom of the left-hand "
                 "menu; 3) choose Snyk Code; 4) switch on the \"Enable Snyk Code\" toggle; 5) click Save changes.")
        if snyk_code_asked and snyk_code is False:
            current = {
                "step": 3,
                "explain": "Snyk still reports Snyk Code as switched off. Check the toggle is on and that they clicked "
                           "Save changes: " + howto + " It can take a minute to take effect.",
                "ask_the_user": "Let me know when it's on and saved, and I'll check again.",
                "on_yes": {"step": "check_snyk_code"},
            }
        else:
            current = {
                "step": 3,
                "explain": ("Signed in. One setting to switch on: Snyk Code, the part of Snyk that reads the code you "
                            "and the AI wrote. It's off by default in new Snyk accounts, and without it the code scan "
                            "can't run, which counts as a failure. In their browser: " + howto),
                "ask_the_user": "Let me know once you've turned on Enable Snyk Code and saved.",
                "on_yes": {"step": "check_snyk_code"},
            }
    elif s3 in ("optional",) and semgrep_available:
        current = {
            "step": 4,
            "explain": ("Snyk is ready, so the checks can run now. One optional extra: a free Semgrep account makes "
                        "Semgrep's results more detailed (it shows the exact line of code it found). If they'd like "
                        "it, I'll open Semgrep's sign-in page the same way. Skipping is fine."),
            "ask_the_user": "Would you like to sign in to Semgrep too, or skip it?",
            "on_yes": {"step": "sign_in_semgrep"},
            "on_no": {"step": "skip_semgrep"},
        }
    elif s3 == "waiting_for_you":
        current = {
            "step": 4,
            "explain": (semgrep_manual or ("The Semgrep page should be open in their browser. They sign up or log in "
                                           "there, then confirm. If no page opened, they can use this link: "
                                           + semgrep_url)),
            "ask_the_user": "Let me know once you've finished with Semgrep (or say skip).",
            "on_yes": {"step": "check", "wait_seconds": 30},
            "on_no": {"step": "skip_semgrep"},
        }
    else:
        current = {
            "step": None,
            "explain": "Setup is complete: Snyk is installed and signed in" +
                       (", and so is Semgrep." if semgrep_signed_in else ".") +
                       " They can now ask you to run secure vibe delivery on a project.",
            "ask_the_user": "Would you like me to run a check on this project now?",
            "on_yes": {"tool": "svd_run"},
        }
    return {"ready": snyk_installed and snyk_signed_in and code_ok, "steps": steps, "current_step": current,
            "instructions_for_assistant": ASSISTANT_RULES}


class Onboarding:
    def __init__(self) -> None:
        self.install_state = "idle"  # idle | downloading | ready | failed
        self.install_error = ""
        self.downloaded = 0
        self.install_task: Optional[asyncio.Task] = None
        self.snyk = installer.SignIn("snyk")
        self.semgrep = installer.SignIn("semgrep")
        self.semgrep_skipped = False
        self.snyk_code: Optional[bool] = None   # None = not known yet
        self.snyk_code_asked = False
        self.snyk_code_confirmed = False

    def _expire(self, si: installer.SignIn) -> None:
        if si.state in ("starting", "waiting_for_browser") and time.time() - si.started_at > SIGN_IN_EXPIRES_S:
            try:
                si.proc.terminate()
            except Exception:
                pass
            si.state, si.detail = "failed", "the sign-in link expired"

    async def _install(self) -> None:
        self.install_state, self.install_error, self.downloaded = "downloading", "", 0
        try:
            await installer.install_snyk(progress=lambda n: setattr(self, "downloaded", n))
            self.install_state = "ready"
        except Exception as e:
            self.install_state, self.install_error = "failed", f"{type(e).__name__}: {e}"[:300]

    async def _wait_for_link(self, si: installer.SignIn) -> None:
        for _ in range(20):
            if si.state != "starting":
                return
            await asyncio.sleep(0.5)

    async def _wait(self, seconds: float) -> None:
        end = time.time() + max(0, min(seconds, 50))
        while time.time() < end:
            if self.install_state == "downloading":
                await asyncio.sleep(1)
                continue
            if self.snyk.state in ("starting", "waiting_for_browser") or \
               self.semgrep.state in ("starting", "waiting_for_browser"):
                await asyncio.sleep(1)
                continue
            return

    async def step(self, step: Optional[str] = None, wait_seconds: int = 0) -> dict:
        for si in (self.snyk, self.semgrep):
            self._expire(si)
        note = ""
        if step == "install_snyk":
            if resolve_tool("snyk"):
                note = "Snyk was already installed."
            elif self.install_state != "downloading":
                self.install_task = asyncio.create_task(self._install())
                await asyncio.sleep(0.5)
        elif step == "sign_in_snyk":
            if not resolve_tool("snyk"):
                note = "Snyk isn't installed yet, so step 1 comes first."
            elif await installer.snyk_signed_in():
                note = "Already signed in to Snyk."
            elif self.snyk.state not in ("starting", "waiting_for_browser"):
                installer.start_snyk_auth(self.snyk)
                await self._wait_for_link(self.snyk)
        elif step == "sign_in_semgrep":
            self.semgrep_skipped = False
            if await installer.semgrep_signed_in():
                note = "Already signed in to Semgrep."
            elif self.semgrep.state not in ("starting", "waiting_for_browser"):
                installer.start_semgrep_login(self.semgrep)
                await self._wait_for_link(self.semgrep)
        elif step == "check_snyk_code":
            self.snyk_code_asked = True
            self.snyk_code = await installer.snyk_code_enabled()
            if self.snyk_code is None:
                # Snyk couldn't confirm either way (e.g. network); trust the person's word.
                self.snyk_code_confirmed = True
                note = "Couldn't confirm the Snyk Code setting automatically; going by what you said."
        elif step == "skip_semgrep":
            self.semgrep_skipped = True
            if self.semgrep.state in ("starting", "waiting_for_browser"):
                try:
                    self.semgrep.proc.terminate()
                except Exception:
                    pass
                self.semgrep.state = "idle"
        elif step not in (None, "", "check", "status"):
            note = (f"Unknown step '{step}'. Valid steps: install_snyk, sign_in_snyk, check_snyk_code, "
                    "sign_in_semgrep, skip_semgrep, check.")
        if wait_seconds:
            await self._wait(wait_seconds)

        snyk_signed = await installer.snyk_signed_in()
        if snyk_signed and self.snyk_code is not True and not self.snyk_code_confirmed and not self.snyk_code_asked:
            # Find out once whether Snyk Code is already on, so people who have it on skip the step.
            self.snyk_code = await installer.snyk_code_enabled()
        semgrep_signed = await installer.semgrep_signed_in()
        if snyk_signed:
            self.snyk.state = "signed_in"
        if semgrep_signed:
            self.semgrep.state = "signed_in"
        out = plan(
            snyk_installed=bool(resolve_tool("snyk")), downloading=self.install_state == "downloading",
            download_failed=self.install_error if self.install_state == "failed" else "",
            snyk_signed_in=bool(snyk_signed), snyk_waiting=self.snyk.state in ("starting", "waiting_for_browser"),
            snyk_url=self.snyk.url, semgrep_available=semgrep_signed is not None,
            semgrep_signed_in=bool(semgrep_signed),
            semgrep_waiting=self.semgrep.state in ("starting", "waiting_for_browser"),
            semgrep_url=self.semgrep.url, semgrep_skipped=self.semgrep_skipped,
            semgrep_manual=self.semgrep.detail if self.semgrep.state == "manual" else "",
            download_mb=self.downloaded // (1 << 20),
            snyk_code=True if (self.snyk_code or self.snyk_code_confirmed) else self.snyk_code,
            snyk_code_asked=self.snyk_code_asked,
        )
        if self.snyk.state == "failed" and not snyk_signed:
            note = (note + " " if note else "") + f"The last Snyk sign-in didn't finish ({self.snyk.detail}); it can be started again."
        if note:
            out["note"] = note
        if os.name == "nt":
            out["platform_note"] = ("On Windows, Semgrep's sign-in needs the person to run "
                                  f"`{installer.semgrep_login_command()}` in PowerShell.")
        return out
