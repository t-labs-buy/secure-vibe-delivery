"""uv / uvx lookup when uvx isn't on PATH (e.g. Windows after `pip install --user uv`)."""
from secure_vibe_delivery import proc


def _no_path(monkeypatch):
    monkeypatch.setattr(proc.shutil, "which", lambda name: None)


def test_uvx_beside_uv_env(monkeypatch, tmp_path):
    _no_path(monkeypatch)
    (tmp_path / "uv.exe").write_text("")
    (tmp_path / "uvx.exe").write_text("")
    monkeypatch.setenv("UV", str(tmp_path / "uv.exe"))
    assert proc.find_uv_runner() == [str(tmp_path / "uvx.exe")]
    assert proc.resolve_tool("semgrep") == [str(tmp_path / "uvx.exe"), "--python", "3.12", "semgrep"]


def test_uv_tool_run_when_no_uvx(monkeypatch, tmp_path):
    _no_path(monkeypatch)
    (tmp_path / "uv").write_text("")
    monkeypatch.setenv("UV", str(tmp_path / "uv"))
    assert proc.find_uv_runner() == [str(tmp_path / "uv"), "tool", "run"]


def test_nothing_found(monkeypatch):
    _no_path(monkeypatch)
    monkeypatch.delenv("UV", raising=False)
    assert proc.find_uv_runner() is None
    assert proc.resolve_tool("locust") is None
