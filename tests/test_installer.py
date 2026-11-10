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
