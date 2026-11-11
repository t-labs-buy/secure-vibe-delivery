"""Custom test suites from .svd.toml, combined coverage, results added after a run, and the run
state that's newer on disk than in memory."""
import json
import sys
import textwrap
from pathlib import Path

from secure_vibe_delivery import config, gate
from secure_vibe_delivery.checks import functional
from secure_vibe_delivery.checks.context import CheckContext
from secure_vibe_delivery.detect import detect
from secure_vibe_delivery.jobs import RunManager
from secure_vibe_delivery.models import CheckResult, RunOptions, RunState, Status, SubCheck

OUT = Path(__file__).parent / "fixtures" / "tool_outputs"

COVPY = {"totals": {"percent_covered": 50.0, "covered_lines": 500, "num_statements": 1000},
         "files": {"app/a.py": {"summary": {"percent_covered": 20.0, "missing_lines": 80, "num_statements": 100}},
                   "app/b.py": {"summary": {"percent_covered": 90.0, "missing_lines": 10, "num_statements": 100}}}}
ISTANBUL = {"total": {"lines": {"total": 100, "covered": 90, "pct": 90.0}},
            "/x/frontend/src/a.js": {"lines": {"total": 100, "covered": 90, "pct": 90.0}}}


def ctx_for(root: Path) -> CheckContext:
    (root / ".svd").mkdir(exist_ok=True)
    return CheckContext(root=root, run_dir=root / ".svd", info=detect(root),
                        options=RunOptions(project_path=str(root)), config=config.load(root))


def test_coverage_formats_are_both_read(tmp_path):
    (tmp_path / "c.json").write_text(json.dumps(COVPY))
    (tmp_path / "s.json").write_text(json.dumps(ISTANBUL))
    py = functional.parse_coverage(tmp_path / "c.json", tmp_path)
    js = functional.parse_coverage(tmp_path / "s.json", tmp_path)
    assert (py.pct, py.covered, py.statements) == (50.0, 500, 1000)
    assert py.files[0]["file"] == "app/a.py"  # least covered first
    assert (js.pct, js.covered, js.statements) == (90.0, 90, 100)
    assert functional.parse_coverage(tmp_path / "missing.json", tmp_path) is None


def test_coverage_is_combined_by_line_count():
    big = functional.Coverage(50.0, 500, 1000)
    small = functional.Coverage(90.0, 90, 100)
    both = functional.combine_coverage([big, small, None])
    assert both.pct == round(100 * 590 / 1100, 1)  # 53.6, not the 70 a plain average would give


async def test_custom_suite_with_junit_and_coverage(tmp_path):
    junit = (OUT / "junit.xml").read_text()
    script = tmp_path / "run_tests.py"
    script.write_text(textwrap.dedent(f"""
        import json, pathlib
        out = pathlib.Path("out"); out.mkdir(exist_ok=True)
        (out / "junit.xml").write_text({junit!r})
        (out / "coverage.json").write_text({json.dumps(COVPY)!r})
        raise SystemExit(1)
    """))
    (tmp_path / ".svd.toml").write_text(textwrap.dedent(f"""
        [[functional.suite]]
        name = "backend"
        command = '"{sys.executable}" run_tests.py'
        junit = "out/junit.xml"
        coverage = "out/coverage.json"
    """))
    res = await functional.run(ctx_for(tmp_path))
    assert res.data["counts"] == {"total": 4, "passed": 3, "failed": 1, "errors": 0, "skipped": 0}
    assert res.data["coverage_pct"] == 50.0
    assert res.status == Status.FAIL and len(res.findings) == 1
    assert res.data["suites"][0]["name"] == "backend"
    assert res.commands and res.commands[0].exit_code == 1


async def test_custom_suite_without_junit_uses_the_exit_code(tmp_path):
    (tmp_path / ".svd.toml").write_text(f"[[functional.suite]]\nname = 'smoke'\ncommand = '\"{sys.executable}\" -c \"pass\"'\n")
    res = await functional.run(ctx_for(tmp_path))
    assert res.data["counts"]["total"] == 1 and res.data["counts"]["passed"] == 1
    tests = next(s for s in res.subchecks if s.id == "tests")
    assert tests.status == Status.PASS
    cov = next(s for s in res.subchecks if s.id == "coverage")
    assert cov.status == Status.NOT_RUN  # no coverage file named, so coverage wasn't measured


async def test_a_stale_results_file_is_not_trusted(tmp_path):
    import os
    out = tmp_path / "out"
    out.mkdir()
    (out / "junit.xml").write_text((OUT / "junit.xml").read_text())
    os.utime(out / "junit.xml", (1_000_000, 1_000_000))  # written long ago, not by this run
    (tmp_path / ".svd.toml").write_text(
        f"[[functional.suite]]\nname = 'b'\ncommand = '\"{sys.executable}\" -c \"pass\"'\njunit = 'out/junit.xml'\n")
    res = await functional.run(ctx_for(tmp_path))
    assert res.data["counts"]["total"] == 1  # exit code, not the old file's 4 tests
    assert "wasn't written by this run" in res.data["coverage_note"]


def test_a_suite_that_did_not_run_fails_the_check():
    ran = functional.SuiteResult(name="pytest", runner="pytest",
                                 counts={"total": 2, "passed": 2, "failed": 0, "errors": 0, "skipped": 0},
                                 coverage=functional.Coverage(80.0, 80, 100))
    missing = functional.SuiteResult(name="jest (frontend)", runner="jest", reason_not_run="npx not found")
    res = functional.assemble(CheckResult(name="functional"), Path("."), 70, [ran, missing])
    tests = next(s for s in res.subchecks if s.id == "tests")
    assert tests.status == Status.FAIL and "jest (frontend)" in tests.detail
    assert res.data["runner"] == "pytest + jest (frontend)"


def test_results_from_files(tmp_path):
    (tmp_path / "cov.json").write_text(json.dumps(COVPY))
    res = functional.result_from_files(tmp_path, OUT / "junit.xml", tmp_path / "cov.json", 70,
                                       name="backend tests", note="Run against a sandbox database")
    assert res.data["counts"]["total"] == 4 and res.data["coverage_pct"] == 50.0
    assert res.data["external"] and res.data["external_note"] == "Run against a sandbox database"
    assert {s.id: s.status for s in res.subchecks}["coverage"] == Status.FAIL


async def test_replace_result_rebuilds_the_report_and_keeps_the_summary(tmp_path, monkeypatch):
    from secure_vibe_delivery.report import pdf
    from secure_vibe_delivery.report.render import render_report

    async def no_pdf(st, results, run_dir, reports_dir, html_path=None):
        html, summary = render_report(st, results, run_dir, reports_dir, html_path=html_path)
        return html, summary, None, ""
    monkeypatch.setattr(pdf, "render_with_pdf", no_pdf)

    runs = RunManager()
    d = tmp_path / ".svd" / "runs" / "r1"
    d.mkdir(parents=True)
    reports = tmp_path / ".svd" / "reports"
    reports.mkdir()
    sec = CheckResult(name="security", status=Status.PASS,
                      subchecks=[SubCheck(id="secrets", label="No keys", status=Status.PASS)])
    st = RunState(run_id="r1", options=RunOptions(project_path=str(tmp_path), checks=["security"]),
                  state="done", created_at=0, results={"security": sec},
                  report_path=str(reports / "svd-report-r1.html"),
                  ai_summary={"source": "ai", "overall": "Written earlier", "went_well": [],
                              "needs_attention": [], "fix_first": []})
    runs.runs["r1"], runs.dirs["r1"] = st, d
    result = functional.result_from_files(tmp_path, OUT / "junit.xml", None, 70, name="tests")
    st = await runs.replace_result(st, result)
    assert "functional" in st.results and "functional" in st.options.checks
    assert st.verdict == gate.verdict(gate.ensure_all(st))
    assert st.ai_summary["overall"] == "Written earlier"
    assert "tests" in Path(st.report_path).read_text()
    saved = RunState.model_validate_json((d / "state.json").read_text())
    assert "functional" in saved.results


def test_a_newer_state_on_disk_wins_over_memory(tmp_path):
    import os
    import time
    runs = RunManager()
    d = tmp_path / "r2"
    d.mkdir()
    st = RunState(run_id="r2", options=RunOptions(project_path=str(tmp_path)), state="done", created_at=0)
    runs.runs["r2"], runs.dirs["r2"] = st, d
    runs._save(st)
    assert runs.load("r2") is st
    newer = st.model_copy(deep=True)
    newer.verdict = "GO"
    (d / "state.json").write_text(newer.model_dump_json())
    later = time.time() + 5
    os.utime(d / "state.json", (later, later))
    assert runs.load("r2").verdict == "GO"


def test_report_shows_each_suite_and_separates_lower_risk_secrets(tmp_path):
    from secure_vibe_delivery.models import SecretFinding
    from secure_vibe_delivery.report.render import render_report
    py = functional.SuiteResult(name="pytest", runner="pytest",
                                counts={"total": 10, "passed": 9, "failed": 1, "errors": 0, "skipped": 0},
                                coverage=functional.Coverage(50.0, 500, 1000))
    js = functional.SuiteResult(name="jest (frontend)", runner="jest", where="frontend",
                                counts={"total": 5, "passed": 5, "failed": 0, "errors": 0, "skipped": 0},
                                coverage=functional.Coverage(90.0, 90, 100))
    fun = functional.assemble(CheckResult(name="functional"), tmp_path, 70, [py, js])
    local = SecretFinding(scanner="semgrep", kind="AI provider API key", file=".env", line=3,
                          masked_value="sk-a********AAAA", exposure="local")
    committed = SecretFinding(scanner="semgrep", kind="AWS access key ID", file="app.py", line=9,
                              masked_value="AKIA********MPLE", exposure="committed")
    sec = CheckResult(name="security", status=Status.FAIL, secrets=[local, committed],
                      subchecks=[SubCheck(id="secrets", label="No keys", status=Status.FAIL)])
    st = RunState(run_id="t", options=RunOptions(project_path=str(tmp_path)), state="done", created_at=0,
                  results={"security": sec, "functional": fun})
    results = gate.ensure_all(st)
    st.verdict = gate.verdict(results)
    html, _ = render_report(st, results, tmp_path, tmp_path)
    text = Path(html).read_text()
    assert "Test suites" in text and "jest (frontend)" in text and "1100" in text
    assert "Secrets (1)" in text and "Lower risk, not counted (1)" in text
    assert "git-ignored, local only" in text and "in git" in text
