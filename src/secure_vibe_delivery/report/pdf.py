"""A PDF copy of the report, printed by the Chrome or Edge already on the machine (headless, no window).

Best effort: when no Chromium-based browser is found, or printing fails, the run carries on and the
report's own "Print / Save as PDF" button still works in any browser.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Optional

from ..proc import journal_step, run_cmd

_MAC = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
]
_WIN_REL = [
    r"Google\Chrome\Application\chrome.exe",
    r"Microsoft\Edge\Application\msedge.exe",
    r"Chromium\Application\chrome.exe",
]
_LINUX = ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "brave-browser"]


def find_browser() -> Optional[str]:
    """Path to a Chromium-based browser that can print to PDF, or None. SVD_PDF_BROWSER overrides."""
    override = os.environ.get("SVD_PDF_BROWSER", "").strip()
    if override:
        return override if Path(override).exists() or shutil.which(override) else None
    if os.environ.get("SVD_PDF", "").strip().lower() in ("0", "false", "no", "off"):
        return None
    if sys.platform == "darwin":
        return next((p for p in _MAC if Path(p).exists()), None)
    if sys.platform == "win32":
        roots = [os.environ.get(k) for k in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA")]
        for root in filter(None, roots):
            for rel in _WIN_REL:
                p = Path(root) / rel
                if p.exists():
                    return str(p)
        return None
    return next((shutil.which(n) for n in _LINUX if shutil.which(n)), None)


def argv(browser: str, html: Path, pdf: Path) -> list[str]:
    # ?print=1 tells the report's script to show every tab and unfold every section before printing
    url = html.resolve().as_uri() + "?print=1"
    return [browser, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
            "--no-pdf-header-footer", "--hide-scrollbars", "--window-size=820,1160",
            "--virtual-time-budget=8000", "--run-all-compositor-stages-before-draw",
            f"--print-to-pdf={pdf}", url]


async def export(html: Path, browser: Optional[str] = None) -> tuple[Optional[Path], str]:
    """Print html to a PDF beside it. Returns (pdf path or None, reason when None)."""
    browser = browser or find_browser()
    if not browser:
        return None, "No Chrome, Edge or Chromium found to make the PDF; use the report's Print / Save as PDF button"
    pdf = html.with_suffix(".pdf")
    if pdf.exists():
        pdf.unlink()
    p = await run_cmd(argv(browser, html, pdf), html.parent, timeout=120)
    if pdf.exists() and pdf.stat().st_size > 1000:
        journal_step("output", f"PDF copy written: {pdf}")
        return pdf, ""
    reason = (p.stderr.strip().splitlines() or [f"exit code {p.exit_code}"])[-1][:200]
    return None, f"The browser couldn't print the PDF ({reason})"


async def render_with_pdf(st, results, run_dir: Path, reports_dir: Path, html_path: Optional[Path] = None):
    """Render the report with a Download PDF button, print the PDF, and drop the button if printing fails."""
    from .render import render_report
    browser = find_browser()
    html, summary = render_report(st, results, run_dir, reports_dir, html_path=html_path, pdf=bool(browser))
    pdf, reason = (await export(html, browser)) if browser else (None, "")
    if browser and not pdf:
        journal_step("decision", reason)
        html, summary = render_report(st, results, run_dir, reports_dir, html_path=html, pdf=False)
    return html, summary, pdf, reason
