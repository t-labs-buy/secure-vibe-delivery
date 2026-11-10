import asyncio
import subprocess

from secure_vibe_delivery import gate, vcs
from secure_vibe_delivery.models import CheckResult, RunOptions, RunState, Status, SubCheck
from secure_vibe_delivery.report.render import render_report


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@example.com", "PATH": "/usr/bin:/bin:/opt/homebrew/bin",
                        "HOME": str(cwd)})


def _repo(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "app.py").write_text("print('hi')\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "First version")
    _git(tmp_path, "remote", "add", "origin", "https://user:ghp_secret123@github.com/acme/app.git")
    return tmp_path


def test_clean_repo(tmp_path):
    s = asyncio.run(vcs.snapshot(_repo(tmp_path)))
    assert s["is_git"] and len(s["commit"]) == 40 and s["short"] == s["commit"][:12]
    assert s["branch"] == "main" and s["subject"] == "First version"
    assert s["dirty"] is False and s["changed_count"] == 0
    assert s["remote"] == "https://github.com/acme/app.git"  # credentials removed
    assert "clean" not in vcs.describe(s) and "no uncommitted changes" in vcs.describe(s)


def test_uncommitted_changes_ignore_own_output(tmp_path):
    root = _repo(tmp_path)
    (root / "app.py").write_text("print('changed')\n")
    (root / "new dir").mkdir()
    (root / "new dir" / "x.py").write_text("")
    (root / ".svd" / "runs").mkdir(parents=True)
    (root / ".svd" / "runs" / "state.json").write_text("{}")
    s = asyncio.run(vcs.snapshot(root))
    assert s["dirty"] and s["changed_count"] == 2 and s["untracked_count"] == 1
    assert "M app.py" in s["changed"] and "?? new dir/x.py" in s["changed"]
    assert not any(".svd" in c for c in s["changed"])


def test_not_a_repo(tmp_path):
    s = asyncio.run(vcs.snapshot(tmp_path))
    assert s["is_git"] is False and "git repository" in s["reason"]


def test_change_during_run_detected(tmp_path):
    root = _repo(tmp_path)
    start = asyncio.run(vcs.snapshot(root))
    (root / "app.py").write_text("print('edited mid-run')\n")
    end = asyncio.run(vcs.snapshot(root))
    assert vcs.changed_during_run(start, end)
    assert not vcs.changed_during_run(start, start)


def _render(tmp_path, code_version):
    st = RunState(run_id="t", options=RunOptions(project_path=str(tmp_path)), state="done", created_at=0,
                  code_version=code_version)
    st.results = {"security": CheckResult(name="security", status=Status.PASS,
                                          subchecks=[SubCheck(id="secrets", label="s", status=Status.PASS)])}
    results = gate.ensure_all(st)
    st.verdict = gate.verdict(results)
    html, summary = render_report(st, results, tmp_path, tmp_path)
    return html.read_text(), summary.read_text()


def test_report_shows_code_version(tmp_path):
    root = _repo(tmp_path)
    (root / "app.py").write_text("x = 1\n")
    s = asyncio.run(vcs.snapshot(root))
    html, summary = _render(tmp_path, s)
    assert s["short"] in html and "1 uncommitted change(s)" in html and "Commit and re-run before sign-off" in html
    assert f"Commit {s['short']}" in html  # sign-off line
    assert s["commit"] in summary and "ghp_secret123" not in html + summary


def test_report_without_git_or_old_runs(tmp_path):
    html, _ = _render(tmp_path, {"is_git": False, "reason": "This folder isn't a git repository"})
    assert "Put the project under git" in html
    html, _ = _render(tmp_path, {})
    assert "didn't record the code version" in html


def test_project_in_subfolder_only_counts_its_own_changes(tmp_path):
    root = _repo(tmp_path)
    (root / "svc").mkdir()
    (root / "svc" / "main.py").write_text("x = 1\n")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "Add svc")
    (root / "app.py").write_text("changed outside the project\n")
    s = asyncio.run(vcs.snapshot(root / "svc"))
    assert s["subfolder"] == "svc" and s["dirty"] is False
    (root / "svc" / "main.py").write_text("x = 2\n")
    s = asyncio.run(vcs.snapshot(root / "svc"))
    assert s["changed"] == ["M svc/main.py"]
