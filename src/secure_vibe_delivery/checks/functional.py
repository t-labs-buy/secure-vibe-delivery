"""Functional check: does it work? pytest (Python) or Jest (JavaScript), with coverage."""
from __future__ import annotations

import json
import re
import shutil
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from ..detect import iter_files
from ..models import CheckResult, Finding, Status, SubCheck
from ..proc import run_cmd
from .context import CheckContext

WRONG_CASE = re.compile(
    r"\b(401|403|404)\b|unauthori[sz]ed|forbidden|permission|not[_ ]?logged[_ ]?in|anonymous|"
    r"other[_ ]?user|another[_ ]?user|not[_ ]?owner|wrong[_ ]?user|access[_ ]?denied|lower[_ ]?role",
    re.I,
)

OMIT_DIRS = (".venv", "venv", "env", "tests", "test", "node_modules", ".svd", "build", "dist")


def coveragerc(root: Path) -> str:
    """Omit patterns anchored at the project root. Unanchored ones like */tests/* would also omit
    every file of a project that happens to live under some directory called tests."""
    r = str(root)
    lines = ["[run]", "omit ="]
    lines += [f"    {r}/{d}/*" for d in OMIT_DIRS]
    lines += ["    */site-packages/*", f"    {r}/test_*.py", f"    {r}/*/test_*.py", f"    {r}/*_test.py",
              f"    {r}/*/*_test.py", f"    {r}/conftest.py", f"    {r}/*/conftest.py", f"    {r}/locustfile.py"]
    return "\n".join(lines) + "\n"


def _has_cov_config(root: Path) -> bool:
    if (root / ".coveragerc").exists():
        return True
    for f, marker in (("setup.cfg", "[coverage:"), ("tox.ini", "[coverage:"), ("pyproject.toml", "[tool.coverage")):
        p = root / f
        if p.exists() and marker in p.read_text(errors="ignore"):
            return True
    return False


def parse_junit(path: Path) -> tuple[dict, list[Finding]]:
    counts = {"total": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    failures: list[Finding] = []
    if not path.exists():
        return counts, failures
    tree = ET.parse(path)
    for tc in tree.iter("testcase"):
        counts["total"] += 1
        name = f"{tc.get('classname', '')}::{tc.get('name', '')}".strip(":")
        fail = tc.find("failure")
        err = tc.find("error")
        if tc.find("skipped") is not None:
            counts["skipped"] += 1
        elif fail is not None or err is not None:
            node = fail if fail is not None else err
            counts["failed" if fail is not None else "errors"] += 1
            text = (node.get("message") or "") + "\n" + (node.text or "")
            line = 0
            m = re.search(r"([\w/.-]+\.py):(\d+)", node.text or "")
            file = tc.get("file") or (m.group(1) if m else "")
            if m:
                line = int(m.group(2))
            failures.append(Finding(tool="pytest", category="test", rule_id="test-failure", severity="high",
                                    title=name, message=text.strip()[:1500], file=file, line=line,
                                    sources=["pytest"],
                                    fix_hint="Fix the code, or the test if the test is wrong; "
                                             "check it against the original request, not the current code."))
        else:
            counts["passed"] += 1
    return counts, failures


def parse_jest(path: Path, root: Path) -> tuple[dict, list[Finding]]:
    data = json.loads(path.read_text())
    counts = {"total": data.get("numTotalTests", 0), "passed": data.get("numPassedTests", 0),
              "failed": data.get("numFailedTests", 0), "errors": data.get("numRuntimeErrorTestSuites", 0),
              "skipped": data.get("numPendingTests", 0) + data.get("numTodoTests", 0)}
    failures = []
    for suite in data.get("testResults", []):
        rel = str(Path(suite.get("name", "")).resolve().relative_to(root)) if suite.get("name", "").startswith(
            str(root)) else suite.get("name", "")
        if suite.get("status") == "failed" and not suite.get("assertionResults"):
            failures.append(Finding(tool="jest", category="test", rule_id="suite-error", severity="high",
                                    title=f"{rel} failed to run", message=(suite.get("message") or "")[:1500],
                                    file=rel, sources=["jest"]))
        for a in suite.get("assertionResults", []):
            if a.get("status") == "failed":
                loc = a.get("location") or {}
                failures.append(Finding(tool="jest", category="test", rule_id="test-failure", severity="high",
                                        title=a.get("fullName", ""), file=rel, line=int(loc.get("line") or 0),
                                        message="\n".join(a.get("failureMessages", []))[:1500], sources=["jest"],
                                        fix_hint="Fix the code, or the test if the test is wrong."))
    return counts, failures


def wrong_case_scan(root: Path) -> list[str]:
    hits = []
    for p in iter_files(root, (".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"), limit=4000):
        n = p.name
        if not (n.startswith("test_") or n.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts",
                                                      ".test.tsx", ".spec.tsx", ".test.jsx")) or "tests" in p.parts
                or "__tests__" in p.parts):
            continue
        try:
            if WRONG_CASE.search(p.read_text(errors="ignore")):
                hits.append(str(p.relative_to(root)))
        except OSError:
            continue
    return hits


async def run(ctx: CheckContext) -> CheckResult:
    res = CheckResult(name="functional", started_at=time.time())
    root, info, run_dir = ctx.root, ctx.info, ctx.run_dir
    thr = ctx.options.coverage_threshold
    if not info.has_tests:
        res.reason_not_run = "No test suite found (no pytest tests or Jest config). Add tests before go-live."
        res.subchecks = [SubCheck(id="tests", label="All tests pass", status=Status.NOT_RUN, detail=res.reason_not_run),
                         SubCheck(id="coverage", label=f"{thr:.0f}%+ of code covered", status=Status.NOT_RUN,
                                  detail=res.reason_not_run)]
        res.summary = res.reason_not_run
        res.finished_at = time.time()
        return res

    coverage_pct = None
    coverage_note = ""
    files_cov: list[dict] = []
    if info.test_runner == "pytest":
        py = info.python_cmd
        probe = await run_cmd([*py, "-c", "import pytest, importlib.util as u; "
                                         "print('cov' if u.find_spec('pytest_cov') else 'nocov')"], root, timeout=60)
        if probe.exit_code != 0:
            res.reason_not_run = (f"pytest isn't installed in the project environment ({' '.join(py)}). "
                                  "Install it: pip install pytest pytest-cov")
        else:
            has_cov = "nocov" not in probe.stdout
            junit = run_dir / "junit.xml"
            cov_json = run_dir / "coverage.json"
            argv = [*py, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--rootdir={root}", f"--junitxml={junit}", "-o",
                    "junit_family=xunit1"]
            if has_cov:
                argv += ["--cov=.", f"--cov-report=json:{cov_json}", "--cov-report=term"]
                if not _has_cov_config(root):
                    rc = run_dir / "coveragerc"
                    rc.write_text(coveragerc(root))
                    argv.append(f"--cov-config={rc}")
            else:
                coverage_note = "pytest-cov not installed in the project environment (pip install pytest-cov)"
            ctx.log("pytest: running the test suite with coverage")
            p = await run_cmd(argv, root, timeout=1800)
            res.commands.append(p.record("pytest", argv, ctx.raw_dir))
            if p.exit_code in (None, 3, 4) or (p.exit_code == 5):
                res.reason_not_run = {5: "pytest collected no tests", 4: "pytest usage error",
                                      3: "pytest internal error"}.get(p.exit_code, p.error or "pytest crashed")
                res.reason_not_run += ": " + (p.stdout[-600:] + p.stderr[-600:]).strip()
            counts, failures = parse_junit(junit)
            if cov_json.exists():
                cj = json.loads(cov_json.read_text())
                coverage_pct = round(cj.get("totals", {}).get("percent_covered", 0.0), 1)
                files_cov = sorted(
                    [{"file": f, "pct": round(v["summary"]["percent_covered"], 1),
                      "missing": v["summary"].get("missing_lines", 0)} for f, v in cj.get("files", {}).items()],
                    key=lambda x: x["pct"])
    else:  # jest
        npx = shutil.which("npx")
        if not npx:
            res.reason_not_run = "npx not found; install Node.js"
            counts, failures = {}, []
        else:
            out = run_dir / "jest.json"
            covdir = run_dir / "jest-coverage"
            argv = [npx, "--no-install", "jest", "--ci", "--coverage", "--coverageReporters=json-summary",
                    "--coverageReporters=text-summary", f"--coverageDirectory={covdir}", "--json",
                    f"--outputFile={out}", "--passWithNoTests=false"]
            ctx.log("Jest: running the test suite with coverage")
            p = await run_cmd(argv, root, timeout=1800)
            res.commands.append(p.record("jest", argv, ctx.raw_dir))
            counts, failures = ({}, [])
            if out.exists():
                counts, failures = parse_jest(out, root)
            else:
                res.reason_not_run = "Jest did not produce results: " + (p.stderr[-800:] or p.error).strip()
            summ = covdir / "coverage-summary.json"
            if summ.exists():
                cs = json.loads(summ.read_text())
                coverage_pct = round(cs.get("total", {}).get("lines", {}).get("pct", 0.0), 1)
                files_cov = sorted([{"file": str(Path(f).relative_to(root)) if f.startswith(str(root)) else f,
                                     "pct": v["lines"]["pct"], "missing": v["lines"]["total"] - v["lines"]["covered"]}
                                    for f, v in cs.items() if f != "total"], key=lambda x: x["pct"])
    if res.reason_not_run and not counts.get("total"):
        counts = counts or {}
    res.findings = failures
    wc = wrong_case_scan(root)
    res.data = {"runner": info.test_runner, "counts": counts, "coverage_pct": coverage_pct,
                "coverage_threshold": thr, "coverage_files": files_cov[:50], "coverage_note": coverage_note,
                "wrong_case_test_files": wc,
                "coverage_basis": "total line coverage (used as the measure for new code)"}

    total = counts.get("total", 0)
    bad = counts.get("failed", 0) + counts.get("errors", 0)
    if res.reason_not_run or total == 0:
        t_sub = SubCheck(id="tests", label="All tests pass", status=Status.NOT_RUN,
                         detail=res.reason_not_run or "no tests ran")
    else:
        t_sub = SubCheck(id="tests", label="All tests pass", status=Status.FAIL if bad else Status.PASS,
                         detail=f"{counts.get('passed', 0)}/{total} passed, {bad} failed, {counts.get('skipped', 0)} skipped")
    if coverage_pct is None:
        c_sub = SubCheck(id="coverage", label=f"{thr:.0f}%+ of code covered", status=Status.NOT_RUN,
                         detail=coverage_note or "coverage was not measured")
    else:
        c_sub = SubCheck(id="coverage", label=f"{thr:.0f}%+ of code covered",
                         status=Status.PASS if coverage_pct >= thr else Status.FAIL,
                         detail=f"{coverage_pct}% covered (target {thr:.0f}%)")
    w_sub = SubCheck(id="wrong-case", label="Login and permission (wrong-case) tests exist",
                     status=Status.PASS if wc else Status.WARN,
                     detail=(f"Found in {len(wc)} test file(s)" if wc else
                             "No tests found for refused requests (401/403, another user's data, lower role)"))
    res.subchecks = [t_sub, c_sub, w_sub]
    if any(s.status == Status.FAIL for s in (t_sub, c_sub)):
        res.status = Status.FAIL
    elif any(s.status == Status.NOT_RUN for s in (t_sub, c_sub)):
        res.status = Status.NOT_RUN if t_sub.status == Status.NOT_RUN else Status.FAIL
    else:
        res.status = Status.WARN if w_sub.status == Status.WARN else Status.PASS
    res.summary = f"{t_sub.detail}; {c_sub.detail}"
    res.finished_at = time.time()
    return res
