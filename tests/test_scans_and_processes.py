"""Scanner exclusions, secret exposure grading, and process-group cleanup."""
import asyncio
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from secure_vibe_delivery import gate, scoring
from secure_vibe_delivery.checks import semgrep, snyk
from secure_vibe_delivery.checks.security import classify_exposure, in_excluded
from secure_vibe_delivery.models import CheckResult, RunOptions, RunState, SecretFinding, Status, SubCheck
from secure_vibe_delivery.proc import run_cmd


def test_semgrep_and_snyk_skip_the_project_venvs():
    argv = semgrep.code_argv(["semgrep"], None, ["hindsight-venv", "tools/.venv-x"])
    pairs = list(zip(argv, argv[1:]))
    assert ("--exclude", "hindsight-venv") in pairs and ("--exclude", "tools/.venv-x") in pairs
    assert ("--exclude", "node_modules") in pairs
    argv = semgrep.secrets_argv(["semgrep"], registry=False, exclude=["hindsight-venv"])
    assert ("--exclude", "hindsight-venv") in list(zip(argv, argv[1:]))
    os_argv = snyk.open_source_argv(["snyk"], None, ["hindsight-venv", "tools/.venv-x"])
    excl = next(a for a in os_argv if a.startswith("--exclude="))
    assert "hindsight-venv" in excl and ".venv-x" in excl and "tools/" not in excl  # Snyk takes names only


@pytest.mark.parametrize("path, expected", [
    ("hindsight-venv/lib/python3.13/site-packages/x.py", True),
    ("./hindsight-venv/a.py", True),
    ("frontend/node_modules/jest-snapshot/build/index.js", True),
    ("lib/site-packages/a.py", True),
    (".env", False),
    ("backend/api/app.py", False),
    ("hindsight-venv-notes.md", False),
])
def test_findings_in_third_party_folders_are_dropped(path, expected):
    assert in_excluded(path, ["hindsight-venv"]) is expected


def _secret(file, kind="AI provider API key", rule="svd-ai-key"):
    return SecretFinding(scanner="semgrep", kind=kind, rule_id=rule, file=file, line=1, masked_value="sk-a****")


def _git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


async def test_exposure_tells_committed_from_local_and_fixtures(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text(".env\n")
    (tmp_path / "config.py").write_text("KEY = 'x'\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_auth.py").write_text("PASSWORD = 'alice-pass'\n")
    (tmp_path / "README.md").write_text("password: a-long-password\n")
    _git(tmp_path, "add", ".gitignore", "config.py", "tests/test_auth.py", "README.md")
    (tmp_path / ".env").write_text("KEY=x\n")
    (tmp_path / "notes.py").write_text("KEY = 'x'\n")  # neither committed nor ignored
    secrets = [
        _secret("config.py"), _secret(".env"), _secret("notes.py"),
        _secret("tests/test_auth.py", "Use of Hardcoded Passwords", "python/HardcodedPassword"),
        _secret("tests/test_keys.py"),  # a provider key in a test is still a real key
        _secret("README.md", "Hard-coded credential", "svd-hardcoded-credential"),
    ]
    await classify_exposure(tmp_path, secrets, is_git=True)
    got = {s.file: s.exposure for s in secrets}
    assert got == {"config.py": "committed", ".env": "local", "notes.py": "untracked",
                   "tests/test_auth.py": "test-fixture", "tests/test_keys.py": "untracked",
                   "README.md": "docs"}
    assert [s.file for s in secrets if s.blocking] == ["config.py", "notes.py", "tests/test_keys.py"]


async def test_outside_git_every_secret_counts(tmp_path):
    secrets = [_secret(".env"), _secret("app.py")]
    await classify_exposure(tmp_path, secrets, is_git=False)
    assert all(s.exposure == "unknown" and s.blocking for s in secrets)


def test_only_exposed_secrets_fail_the_gate_and_the_score():
    local = _secret(".env")
    local.exposure = "local"
    fixture = _secret("tests/test_a.py", "Hard-coded credential")
    fixture.exposure = "test-fixture"
    sec = CheckResult(name="security", status=Status.PASS, secrets=[local, fixture],
                      subchecks=[SubCheck(id="secrets", label="No keys", status=Status.PASS)])
    results = {"security": sec}
    assert not [i for i in gate.must_fix(results) if i["kind"] == "Exposed secret"]
    st = RunState(run_id="t", options=RunOptions(project_path="."), state="done", created_at=0, results=results)
    sc = scoring.compute(gate.ensure_all(st), quick_mode=False)
    comp = next(c for c in sc["checks"]["security"]["components"] if c["label"] == "No exposed secrets")
    assert comp["score"] == 1.0
    assert not any("exposed secret" in c and not c.startswith("0 ") for c in sc["caps"])
    committed = _secret("config.py")
    committed.exposure = "committed"
    sec.secrets.append(committed)
    items = [i for i in gate.must_fix(results) if i["kind"] == "Exposed secret"]
    assert len(items) == 1 and "in git" in items[0]["detail"]


@pytest.mark.skipif(sys.platform == "win32", reason="process groups are POSIX here")
async def test_a_timed_out_command_takes_its_children_with_it(tmp_path):
    pidfile = tmp_path / "child.pid"
    script = tmp_path / "parent.py"
    script.write_text(textwrap.dedent(f"""
        import subprocess, sys, time, pathlib
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        pathlib.Path({str(pidfile)!r}).write_text(str(child.pid))
        time.sleep(60)
    """))
    res = await run_cmd([sys.executable, str(script)], tmp_path, timeout=3)
    assert res.timed_out
    child = int(pidfile.read_text())
    for _ in range(50):
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        # a killed child may linger as a zombie until init reaps it; check its state
        state = subprocess.run(["ps", "-o", "stat=", "-p", str(child)], capture_output=True, text=True).stdout
        if not state.strip() or state.strip().startswith("Z"):
            break
        time.sleep(0.1)
    else:
        pytest.fail("the child process outlived the timed-out command")


@pytest.mark.skipif(sys.platform == "win32", reason="process groups are POSIX here")
async def test_a_worker_left_behind_by_a_finished_command_is_ended(tmp_path):
    pidfile = tmp_path / "worker.pid"
    script = tmp_path / "parent.py"
    script.write_text(textwrap.dedent(f"""
        import subprocess, sys, pathlib
        w = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pathlib.Path({str(pidfile)!r}).write_text(str(w.pid))
    """))
    res = await run_cmd([sys.executable, str(script)], tmp_path, timeout=30)
    assert res.exit_code == 0
    worker = int(pidfile.read_text())
    await asyncio.sleep(0.3)
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(worker)], capture_output=True, text=True).stdout.strip()
    assert not state or state.startswith("Z")
