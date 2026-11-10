import hashlib
import os

import httpx
import pytest

from secure_vibe_delivery import installer

FAKE = b"#!/bin/sh\necho 1.1308.4\n"


def _client_factory(sha: str):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(".sha256"):
            return httpx.Response(200, text=f"{sha}  snyk-test\n")
        return httpx.Response(200, content=FAKE)
    real = httpx.AsyncClient

    def make(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)
    return make


@pytest.mark.skipif(os.name == "nt", reason="uses a shell-script stand-in for the Snyk binary")
async def test_install_snyk_verifies_checksum(tmp_path, monkeypatch):
    monkeypatch.setenv("SVD_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(installer.httpx, "AsyncClient", _client_factory(hashlib.sha256(FAKE).hexdigest()))
    dest = await installer.install_snyk()
    assert dest.exists() and os.access(dest, os.X_OK)
    assert installer.cached_snyk() == dest


async def test_install_snyk_rejects_bad_checksum(tmp_path, monkeypatch):
    monkeypatch.setenv("SVD_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(installer.httpx, "AsyncClient", _client_factory("0" * 64))
    with pytest.raises(RuntimeError, match="checksum"):
        await installer.install_snyk()
    assert installer.cached_snyk() is None
    assert not any(tmp_path.rglob("snyk*"))  # nothing left behind


def test_snyk_asset_per_platform(monkeypatch):
    cases = [("darwin", "posix", "arm64", "snyk-macos-arm64"), ("darwin", "posix", "x86_64", "snyk-macos"),
             ("linux", "posix", "x86_64", "snyk-linux"), ("linux", "posix", "aarch64", "snyk-linux-arm64"),
             ("win32", "nt", "AMD64", "snyk-win.exe"), ("win32", "nt", "ARM64", "snyk-win.exe")]
    for plat, osname, machine, expected in cases:
        monkeypatch.setattr(installer.sys, "platform", plat)
        monkeypatch.setattr(installer.os, "name", osname)
        monkeypatch.setattr(installer.platform, "machine", lambda m=machine: m)
        monkeypatch.setattr(installer.Path, "exists", lambda self: False)  # not Alpine
        assert installer.snyk_asset() == expected, (plat, machine)


def test_cache_dir_override(tmp_path, monkeypatch):
    monkeypatch.setenv("SVD_CACHE_DIR", str(tmp_path / "c"))
    assert installer.cache_dir() == tmp_path / "c"


def _plan(**kw):
    from secure_vibe_delivery.onboarding import plan
    base = dict(snyk_installed=False, downloading=False, download_failed="", snyk_signed_in=False,
                snyk_waiting=False, snyk_url="", semgrep_available=True, semgrep_signed_in=False,
                semgrep_waiting=False, semgrep_url="", semgrep_skipped=False, semgrep_manual="")
    base.update(kw)
    return plan(**base)


def test_walkthrough_asks_before_each_step():
    p = _plan()
    assert p["current_step"]["step"] == 1 and p["current_step"]["on_yes"] == {"step": "install_snyk"}
    assert "?" in p["current_step"]["ask_the_user"] and not p["ready"]
    p = _plan(snyk_installed=True)
    assert p["current_step"]["on_yes"] == {"step": "sign_in_snyk"}          # asks before opening the page
    assert "work email" in p["current_step"]["explain"]
    p = _plan(snyk_installed=True, snyk_waiting=True, snyk_url="https://app.snyk.io/x")
    assert "https://app.snyk.io/x" in p["current_step"]["explain"] and p["current_step"]["on_yes"]["step"] == "check"
    # signed in but Snyk Code switched off: the walkthrough stops at the toggle
    p = _plan(snyk_installed=True, snyk_signed_in=True, snyk_code=False)
    c = p["current_step"]
    assert not p["ready"] and c["step"] == 3 and c["on_yes"] == {"step": "check_snyk_code"}
    assert "Enable Snyk Code" in c["explain"] and "Save changes" in c["explain"]
    p = _plan(snyk_installed=True, snyk_signed_in=True, snyk_code=False, snyk_code_asked=True)
    assert "still reports" in p["current_step"]["explain"]
    p = _plan(snyk_installed=True, snyk_signed_in=True, snyk_code=True)
    assert p["ready"] and p["current_step"]["step"] == 4 and p["current_step"]["on_no"] == {"step": "skip_semgrep"}
    p = _plan(snyk_installed=True, snyk_signed_in=True, semgrep_skipped=True)
    assert p["current_step"]["step"] is None and [s["status"] for s in p["steps"]] == ["done", "done", "done", "skipped"]


def test_snyk_code_off_message_detected():
    from secure_vibe_delivery.installer import SNYK_CODE_OFF
    assert SNYK_CODE_OFF.search("Snyk Code is not enabled for this organization")
    assert SNYK_CODE_OFF.search("Snyk Code is not supported for your current organization: ``.")
    assert not SNYK_CODE_OFF.search("Authentication error (SNYK-0005)")
