from secure_vibe_delivery.models import CheckResult, RunOptions, RunState, Status
from secure_vibe_delivery.report.commands import _ticks, exit_meaning, timeline


def _cmd(t, text, dur, code=0):
    return {"t": t, "kind": "command", "text": text, "duration_s": dur, "exit_code": code, "cwd": "/p"}


def _state():
    st = RunState(run_id="t", options=RunOptions(project_path="/p"), state="done", created_at=100, finished_at=330)
    st.journal = [
        {"t": 100, "kind": "setup", "text": "Run started"},
        _cmd(100, "/bin/snyk --version", 2), _cmd(102, "/bin/semgrep --version", 1.8),
        _cmd(104, "/bin/snyk test --all-projects --json", 14.7, 2),
        _cmd(119, "/bin/snyk secrets test --json", 3.8, 2),
        _cmd(123, "/bin/semgrep scan --config p/secrets --config svd-secrets.yml .", 4.9),
        {"t": 128, "kind": "network", "text": "Looked up 3 names", "step": "provenance", "duration_s": 2},
        _cmd(131, ".venv/bin/python -m pytest -q --cov=.", 1.9, 1),
        _cmd(210, "uvx locust -f locustfile.py --headless -u 150", 120),
    ]
    sec = CheckResult(name="security", status=Status.FAIL, data={
        "not_run": {"snyk-open-source": "Snyk isn't signed in"},
        "snyk_secrets_unavailable": "Not on your Snyk plan."})
    fun = CheckResult(name="functional", status=Status.FAIL)
    perf = CheckResult(name="performance", status=Status.PASS)
    return st, {"security": sec, "functional": fun, "performance": perf}


def test_rows_merge_place_and_classify():
    st, res = _state()
    tl = timeline(st, res)
    rows = {r["label"]: r for r in tl["rows"]}
    assert list(rows) == ["Tool version checks", "Snyk Open Source", "Snyk Secrets", "Secrets · Semgrep fallback",
                          "Package provenance", "pytest + coverage", "Locust load test"]
    v = rows["Tool version checks"]
    assert len(v["commands"]) == 2 and v["check"] == "setup" and v["start_text"] == "0:00"
    assert "it worked" in v["commands"][0]["exit_text"]
    oss = rows["Snyk Open Source"]
    assert oss["skipped"] and oss["why"] == "Snyk isn't signed in" and "scan failed" in oss["commands"][0]["exit_text"]
    assert rows["Snyk Secrets"]["skipped"] and "Semgrep's secret rules" in rows["Snyk Secrets"]["why"]
    assert not rows["Secrets · Semgrep fallback"]["skipped"]
    assert rows["Package provenance"]["commands"] == [] and rows["pytest + coverage"]["check"] == "functional"
    loc = rows["Locust load test"]
    assert loc["check"] == "performance" and abs(loc["left"] + loc["width"] - 100) < 0.01
    assert tl["total_text"] == "3 minutes 50 seconds"


def test_ticks_and_exit_text():
    assert [t["label"] for t in _ticks(228)] == ["0:00", "1:00", "2:00", "3:00", "3:48"]
    assert exit_meaning("pytest", 5) == "Exit 5 means no tests were found."
    assert exit_meaning("snyk", None).startswith("It timed out")


def test_empty_journal():
    st = RunState(run_id="t", options=RunOptions(project_path="/p"), state="done", created_at=0)
    assert timeline(st, {})["rows"] == []
