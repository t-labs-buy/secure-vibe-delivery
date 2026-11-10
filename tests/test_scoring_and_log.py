from pathlib import Path

from secure_vibe_delivery import gate, scoring, summary
from secure_vibe_delivery.models import CheckResult, Finding, RunOptions, RunState, SecretFinding, Status, SubCheck
from secure_vibe_delivery.proc import JOURNAL, run_cmd
from secure_vibe_delivery.report.render import render_report


def sub(i, st=Status.PASS, d=""):
    return SubCheck(id=i, label=i, status=st, detail=d)


def perfect():
    sec = CheckResult(name="security", status=Status.PASS,
                      subchecks=[sub("secrets"), sub("code"), sub("libraries"), sub("packages")])
    fun = CheckResult(name="functional", status=Status.PASS, subchecks=[sub("tests"), sub("coverage"), sub("wrong-case")],
                      data={"counts": {"total": 10, "passed": 10}, "coverage_pct": 85.0, "coverage_threshold": 70})
    perf = CheckResult(name="performance", status=Status.PASS,
                       subchecks=[sub("load"), sub("failures"), sub("latency"), sub("crashes")],
                       data={"aggregate": {"failure_pct": 0.0, "p95": 200, "requests": 500, "rps": 10.0, "p50": 50,
                                            "p99": 300, "max": 400},
                             "p95_target_ms": 1000, "users": 15, "peak_users": 10, "spawn_rate": 10,
                             "duration": "15m", "target_url": "http://x", "locustfile_source": "project",
                             "endpoints": [], "series": [], "failures": [], "exceptions": []})
    return {"security": sec, "functional": fun, "performance": perf}


def test_perfect_run_scores_100():
    s = scoring.compute(perfect(), quick_mode=False)
    assert s["score"] == 100 and s["grade"] == "A" and not s["caps"]


def test_secret_or_critical_caps_at_59():
    r = perfect()
    r["security"].secrets = [SecretFinding(scanner="x", file="a.py", line=1, masked_value="AKIA****")]
    s = scoring.compute(r, quick_mode=False)
    assert s["raw_score"] > 59 and s["score"] == 59 and s["grade"] == "F" and s["caps"]


def test_not_run_scores_zero_and_caps_at_79():
    r = perfect()
    r["performance"] = CheckResult(name="performance", status=Status.NOT_RUN,
                                   subchecks=[sub("failures", Status.NOT_RUN)])
    s = scoring.compute(r, quick_mode=False)
    assert s["checks"]["performance"]["score"] == 0 and s["score"] <= 75


def test_severity_gives_partial_credit():
    r = perfect()
    r["security"].findings = [Finding(tool="t", category="code", severity="medium")] * 2
    s = scoring.compute(r, quick_mode=False)
    assert 90 < s["score"] < 100


def test_automatic_summary_lists_fails_and_fix_first():
    r = perfect()
    r["functional"].subchecks[0] = sub("tests", Status.FAIL, "9/10 passed")
    sc = scoring.compute(r, False)
    a = summary.automatic(r, "NO-GO", sc, [{"kind": "Failing test", "title": "test_x", "where": "t.py:3"}])
    assert any("tests" in x for x in a["needs_attention"]) and a["fix_first"] == ["Failing test: test_x (t.py:3)"]
    assert "NO-GO" in a["overall"] and str(sc["score"]) in a["overall"]


def test_ai_summary_is_escaped_in_report(tmp_path):
    st = RunState(run_id="t", options=RunOptions(project_path=str(tmp_path)), state="done", created_at=0)
    st.results = perfect()
    st.ai_summary = summary.ai("All good <script>alert(1)</script>", ["<b>tests</b> pass"], [], ["none"])
    html, _ = render_report(st, gate.ensure_all(st), tmp_path, tmp_path)
    text = html.read_text()
    assert "<script>alert(1)</script>" not in text and "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "Written by your AI assistant" in text


async def test_journal_records_every_command(tmp_path):
    log = []
    token = JOURNAL.set(log)
    try:
        await run_cmd(["python3", "-c", "print('hi')"], tmp_path, timeout=30)
    finally:
        JOURNAL.reset(token)
    assert log and log[0]["kind"] == "command" and "print('hi')" in log[0]["text"] and log[0]["exit_code"] == 0
    assert log[0]["cwd"] == str(tmp_path)
