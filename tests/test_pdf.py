import asyncio
import shutil
from pathlib import Path

import pytest

from secure_vibe_delivery import gate
from secure_vibe_delivery.models import CheckResult, RunOptions, RunState, Status, SubCheck
from secure_vibe_delivery.report import pdf


def _state(tmp_path):
    st = RunState(run_id="t", options=RunOptions(project_path=str(tmp_path)), state="done", created_at=0)
    st.results = {"security": CheckResult(name="security", status=Status.PASS,
                                          subchecks=[SubCheck(id="secrets", label="s", status=Status.PASS)])}
    return st, gate.ensure_all(st)


def test_argv_prints_the_report_in_print_mode(tmp_path):
    a = pdf.argv("/bin/chrome", tmp_path / "r.html", tmp_path / "r.pdf")
    assert a[0] == "/bin/chrome" and "--headless=new" in a and f"--print-to-pdf={tmp_path / 'r.pdf'}" in a
    assert a[-1].startswith("file://") and a[-1].endswith("?print=1")


def test_can_be_switched_off(monkeypatch):
    monkeypatch.delenv("SVD_PDF_BROWSER", raising=False)
    monkeypatch.setenv("SVD_PDF", "0")
    assert pdf.find_browser() is None


def test_no_browser_means_no_button_and_no_pdf(tmp_path, monkeypatch):
    monkeypatch.setattr(pdf, "find_browser", lambda: None)
    st, res = _state(tmp_path)
    html, _, out, _ = asyncio.run(pdf.render_with_pdf(st, res, tmp_path, tmp_path))
    text = html.read_text()
    assert out is None and "Download PDF" not in text and "Print / Save as PDF" in text


def test_failed_print_removes_the_button(tmp_path, monkeypatch):
    monkeypatch.setattr(pdf, "find_browser", lambda: "/nonexistent/chrome")
    st, res = _state(tmp_path)
    html, _, out, reason = asyncio.run(pdf.render_with_pdf(st, res, tmp_path, tmp_path))
    assert out is None and reason and "Download PDF" not in html.read_text()


@pytest.mark.skipif(not (pdf.find_browser() or shutil.which("google-chrome")), reason="no Chromium browser here")
def test_real_pdf_is_written(tmp_path):
    st, res = _state(tmp_path)
    html, _, out, _ = asyncio.run(pdf.render_with_pdf(st, res, tmp_path, tmp_path))
    assert out and out.read_bytes()[:5] == b"%PDF-" and out.name == html.with_suffix(".pdf").name
    assert f'href="{out.name}"' in html.read_text()
