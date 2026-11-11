"""Functional check: does it work? Every test suite the project has (pytest, Jest, or the commands in
.svd.toml), with coverage."""
from __future__ import annotations

import ast
import json
import re
import shutil
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..config import Suite, suite_argv
from ..detect import iter_files
from ..models import CheckResult, CommandRecord, Finding, Status, SubCheck
from ..proc import journal_step, run_cmd
from .context import CheckContext

WRONG_CASE = re.compile(
    r"\b(401|403|404)\b|unauthori[sz]ed|forbidden|permission|not[_ ]?logged[_ ]?in|anonymous|"
    r"other[_ ]?user|another[_ ]?user|not[_ ]?owner|wrong[_ ]?user|access[_ ]?denied|lower[_ ]?role",
    re.I,
)

OMIT_DIRS = (".venv", "venv", "env", "tests", "test", "node_modules", ".svd", "build", "dist")

# Statements that wipe data. In a test that is meant to run against a throwaway database, they are
# harmless; in one whose isolation never ran, they hit the real one.
DESTRUCTIVE_SQL = re.compile(r"\b(TRUNCATE\s+(TABLE\s+)?\w|DROP\s+(TABLE|DATABASE|SCHEMA)\b|DELETE\s+FROM\s+\w+\s*(;|[\"']))",
                             re.I)
NOSE_HOOKS = {"setup", "teardown"}


def coveragerc(root: Path) -> str:
    """Omit patterns anchored at the project root. Unanchored ones like */tests/* would also omit
    every file of a project that happens to live under some directory called tests."""
    r = root.as_posix()  # coverage matches "/" against either separator, so this works on Windows too
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


# --- safety: tests pytest would run without their isolation ---------------------------------------

def _is_test_file(p: Path) -> bool:
    return p.name.startswith("test_") or p.name.endswith("_test.py")


def unsafe_pytest_files(root: Path) -> list[dict]:
    """Test files whose setup pytest won't run.

    pytest 8 removed nose support: a module-level setup()/teardown(), or a setup()/teardown()
    method on a test class, is no longer called. Tests written to rely on one then run without it,
    which matters most when the hook is what points them at a throwaway database. Each hit says
    which hooks the file has and whether it also contains statements that wipe data."""
    hits = []
    for p in iter_files(root, (".py",), 4000):
        if not _is_test_file(p):
            continue
        try:
            text = p.read_text(errors="ignore")
            tree = ast.parse(text)
        except (OSError, SyntaxError, ValueError):
            continue
        hooks = [n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and n.name in NOSE_HOOKS]
        for cls in (n for n in tree.body if isinstance(n, ast.ClassDef) and n.name.startswith("Test")):
            hooks += [f"{cls.name}.{m.name}" for m in cls.body
                      if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name in NOSE_HOOKS]
        if hooks:
            hits.append({"file": p.relative_to(root).as_posix(), "hooks": sorted(set(hooks)),
                         "destructive": bool(DESTRUCTIVE_SQL.search(text))})
    return sorted(hits, key=lambda h: (not h["destructive"], h["file"]))


def unsafe_reason(hits: list[dict]) -> str:
    wiping = [h["file"] for h in hits if h["destructive"]]
    files = ", ".join(h["file"] for h in hits[:6]) + (f" and {len(hits) - 6} more" if len(hits) > 6 else "")
    msg = (f"Not run under pytest, to protect your data: {len(hits)} test file(s) ({files}) use nose-style "
           "setup()/teardown(), which pytest 8 no longer calls, so those tests would run without the "
           "isolation they were written to have")
    if wiping:
        msg += (f"; {len(wiping)} of them also TRUNCATE/DROP/DELETE data, which would then hit the real "
                "database")
    return msg + (". Run the tests the way they're meant to be run and give that command to SVD as a "
                  "[[functional.suite]] in .svd.toml (or convert the hooks to setup_module()/teardown_module() "
                  "or fixtures). Set functional.allow_unsafe_pytest = true only after checking the files.")


# --- result parsers --------------------------------------------------------------------------------

def parse_junit(path: Path, tool: str = "pytest") -> tuple[dict, list[Finding]]:
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
            failures.append(Finding(tool=tool, category="test", rule_id="test-failure", severity="high",
                                    title=name, message=text.strip()[:1500], file=file, line=line,
                                    sources=[tool],
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


@dataclass
class Coverage:
    pct: float
    covered: int  # lines covered, so suites in different languages can be combined by weight
    statements: int
    files: list[dict] = field(default_factory=list)


def parse_coverage(path: Path, root: Path) -> Optional[Coverage]:
    """coverage.py's JSON report (coverage json) or Istanbul's coverage-summary.json (Jest, nyc, vitest)."""
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(data.get("totals"), dict):  # coverage.py
        t = data["totals"]
        files = [{"file": f, "pct": round(v["summary"]["percent_covered"], 1),
                  "missing": v["summary"].get("missing_lines", 0)}
                 for f, v in data.get("files", {}).items() if v.get("summary", {}).get("num_statements")]
        return Coverage(round(t.get("percent_covered", 0.0), 1), int(t.get("covered_lines", 0)),
                        int(t.get("num_statements", 0)), sorted(files, key=lambda x: (x["pct"], -x["missing"])))
    if isinstance(data.get("total"), dict):  # Istanbul summary
        lines = data["total"].get("lines", {})

        def rel(f: str) -> str:
            try:
                return Path(f).resolve().relative_to(root).as_posix()
            except ValueError:
                return f
        files = [{"file": rel(f), "pct": v["lines"]["pct"], "missing": v["lines"]["total"] - v["lines"]["covered"]}
                 for f, v in data.items() if f != "total" and v.get("lines", {}).get("total")]
        return Coverage(round(float(lines.get("pct", 0.0)), 1), int(lines.get("covered", 0)),
                        int(lines.get("total", 0)), sorted(files, key=lambda x: (x["pct"], -x["missing"])))
    return None


def combine_coverage(parts: list[Coverage]) -> Optional[Coverage]:
    """One number across suites: lines covered over lines measured, so a big backend isn't outvoted
    by a small frontend."""
    parts = [c for c in parts if c is not None]
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    covered, statements = sum(c.covered for c in parts), sum(c.statements for c in parts)
    pct = round(100 * covered / statements, 1) if statements else 0.0
    files = sorted((f for c in parts for f in c.files), key=lambda x: (x["pct"], -x["missing"]))
    return Coverage(pct, covered, statements, files)


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


# --- suites ----------------------------------------------------------------------------------------

@dataclass
class SuiteResult:
    name: str
    runner: str
    counts: dict = field(default_factory=dict)
    failures: list[Finding] = field(default_factory=list)
    coverage: Optional[Coverage] = None
    coverage_note: str = ""
    reason_not_run: str = ""
    commands: list[CommandRecord] = field(default_factory=list)
    where: str = "."

    def view(self) -> dict:
        c = self.counts or {}
        return {"name": self.name, "runner": self.runner, "where": self.where, "counts": c,
                "coverage_pct": self.coverage.pct if self.coverage else None,
                "lines": self.coverage.statements if self.coverage else None,
                "reason_not_run": self.reason_not_run, "coverage_note": self.coverage_note}


async def run_pytest(ctx: CheckContext) -> SuiteResult:
    root, run_dir, py = ctx.root, ctx.run_dir, ctx.info.python_cmd
    s = SuiteResult(name="pytest", runner="pytest")
    unsafe = unsafe_pytest_files(root)
    if unsafe and not ctx.config.allow_unsafe_pytest:
        s.reason_not_run = unsafe_reason(unsafe)
        journal_step("decision", "pytest not run: " + "; ".join(
            f"{h['file']} ({', '.join(h['hooks'])}{', wipes data' if h['destructive'] else ''})" for h in unsafe[:10]))
        return s
    probe = await run_cmd([*py, "-c", "import pytest, importlib.util as u; "
                                     "print('cov' if u.find_spec('pytest_cov') else 'nocov')"], root, timeout=60)
    if probe.exit_code != 0:
        s.reason_not_run = (f"pytest isn't installed in the project environment ({' '.join(py)}). "
                            "Install it: pip install pytest pytest-cov")
        return s
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
        s.coverage_note = "pytest-cov not installed in the project environment (pip install pytest-cov)"
    ctx.log("pytest: running the test suite with coverage")
    p = await run_cmd(argv, root, timeout=1800)
    s.commands.append(p.record("pytest", argv, ctx.raw_dir))
    if p.exit_code in (None, 3, 4, 5):
        s.reason_not_run = {5: "pytest collected no tests", 4: "pytest usage error",
                            3: "pytest internal error"}.get(p.exit_code, p.error or "pytest crashed")
        s.reason_not_run += ": " + (p.stdout[-600:] + p.stderr[-600:]).strip()
    s.counts, s.failures = parse_junit(junit)
    s.coverage = parse_coverage(cov_json, root)
    return s


async def run_jest(ctx: CheckContext, d: Path) -> SuiteResult:
    root = ctx.root
    where = d.relative_to(root).as_posix() if d != root else "."
    s = SuiteResult(name="jest" if where == "." else f"jest ({where})", runner="jest", where=where)
    npx = shutil.which("npx")
    if not npx:
        s.reason_not_run = "npx not found; install Node.js"
        return s
    tag = "" if where == "." else "-" + re.sub(r"[^a-zA-Z0-9_.-]", "_", where)
    out = ctx.run_dir / f"jest{tag}.json"
    covdir = ctx.run_dir / f"jest-coverage{tag}"
    argv = [npx, "--no-install", "jest", "--ci", "--coverage", "--coverageReporters=json-summary",
            "--coverageReporters=text-summary", f"--coverageDirectory={covdir}", "--json",
            f"--outputFile={out}", "--passWithNoTests=false"]
    ctx.log(f"Jest: running the test suite with coverage{'' if where == '.' else ' in ' + where}")
    p = await run_cmd(argv, d, timeout=1800)
    s.commands.append(p.record(f"jest{tag}", argv, ctx.raw_dir))
    if out.exists():
        s.counts, s.failures = parse_jest(out, root)
    else:
        s.reason_not_run = "Jest did not produce results: " + (p.stderr[-800:] or p.error).strip()
    s.coverage = parse_coverage(covdir / "coverage-summary.json", root)
    return s


def _fresh(path: Optional[Path], since: float) -> Optional[Path]:
    """The file, if the suite's command wrote it during this run (not left over from an earlier one)."""
    if path is None or not path.is_file():
        return None
    return path if path.stat().st_mtime >= since - 1 else None


async def run_custom(ctx: CheckContext, suite: Suite) -> SuiteResult:
    """A command from .svd.toml. JUnit XML gives per-test results; without it the command's exit code
    is the result (one pass or one failure). Coverage comes from the file it names, if any."""
    root = ctx.root
    s = SuiteResult(name=suite.name, runner="command")
    argv = suite_argv(suite.command)
    ctx.log(f"{suite.name}: running `{suite.command}` (from {ctx.config.path.name if ctx.config.path else '.svd.toml'})")
    started = time.time()
    p = await run_cmd(argv, root, timeout=suite.timeout)
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", suite.name)
    s.commands.append(p.record(f"suite-{safe}", argv, ctx.raw_dir))
    if p.exit_code is None:
        s.reason_not_run = f"`{suite.command}` didn't finish: {p.error or 'no exit code'}"
        return s
    junit = _fresh(root / suite.junit, started) if suite.junit else None
    if suite.junit and junit is None:
        s.coverage_note = f"{suite.junit} wasn't written by this run, so the exit code is the result"
    if junit:
        s.counts, s.failures = parse_junit(junit, tool=suite.name)
    else:
        ok = p.exit_code == 0
        s.counts = {"total": 1, "passed": int(ok), "failed": int(not ok), "errors": 0, "skipped": 0}
        if not ok:
            s.failures = [Finding(tool=suite.name, category="test", rule_id="suite-failed", severity="high",
                                  title=f"{suite.name}: `{suite.command}` exited with {p.exit_code}",
                                  message=(p.stdout[-1200:] + "\n" + p.stderr[-600:]).strip(),
                                  sources=[suite.name],
                                  fix_hint="Open the command's output in the run log; write JUnit XML "
                                           "(functional.suite.junit) to see each failing test here.")]
    if suite.coverage:
        cov_path = _fresh(root / suite.coverage, started)
        s.coverage = parse_coverage(cov_path, root) if cov_path else None
        if s.coverage is None:
            s.coverage_note = (f"{suite.coverage} wasn't written by this run or isn't coverage.py JSON / an "
                               "Istanbul coverage-summary.json")
    return s


async def run(ctx: CheckContext) -> CheckResult:
    res = CheckResult(name="functional", started_at=time.time())
    root, info = ctx.root, ctx.info
    thr = ctx.options.coverage_threshold

    suites: list[SuiteResult] = []
    if ctx.config.suites:
        journal_step("decision", f"Running the {len(ctx.config.suites)} test suite(s) from "
                                 f"{ctx.config.path.name if ctx.config.path else '.svd.toml'} instead of "
                                 "auto-detecting pytest / Jest")
        for suite in ctx.config.suites:
            suites.append(await run_custom(ctx, suite))
    elif not info.has_tests:
        res.reason_not_run = ("No test suite found (no pytest tests, no Jest tests, no [[functional.suite]] in "
                              ".svd.toml). Add tests before go-live.")
        res.subchecks = [SubCheck(id="tests", label="All tests pass", status=Status.NOT_RUN, detail=res.reason_not_run),
                         SubCheck(id="coverage", label=f"{thr:.0f}%+ of code covered", status=Status.NOT_RUN,
                                  detail=res.reason_not_run)]
        res.summary = res.reason_not_run
        res.finished_at = time.time()
        return res
    else:
        if "pytest" in info.test_runners:
            suites.append(await run_pytest(ctx))
        for d in info.jest_dirs:
            suites.append(await run_jest(ctx, d))

    return assemble(res, root, thr, suites)


def assemble(res: CheckResult, root: Path, thr: float, suites: list[SuiteResult],
             runner: Optional[str] = None, extra: Optional[dict] = None) -> CheckResult:
    """Combine the suites' results into the functional check: one test count, one coverage figure
    (weighted by lines) and the three sub-checks. A suite that didn't run is never a pass."""
    counts = {"total": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    for s in suites:
        for k in counts:
            counts[k] += int((s.counts or {}).get(k, 0))
        res.findings += s.failures
        res.commands += s.commands
    cov = combine_coverage([s.coverage for s in suites])
    not_run = [s for s in suites if s.reason_not_run and not (s.counts or {}).get("total")]
    if not_run:
        res.reason_not_run = " | ".join(f"{s.name}: {s.reason_not_run}" for s in not_run)
    notes = [f"{s.name}: {s.coverage_note}" for s in suites if s.coverage_note]

    wc = wrong_case_scan(root)
    res.data = {"runner": runner or " + ".join(s.name for s in suites), "counts": counts,
                "coverage_pct": cov.pct if cov else None,
                "coverage_threshold": thr, "coverage_files": (cov.files if cov else [])[:50],
                "coverage_note": "; ".join(notes), "wrong_case_test_files": wc,
                "suites": [s.view() for s in suites],
                "coverage_basis": "total line coverage (used as the measure for new code)"
                                  + (", combined across suites by line count" if len(suites) > 1 else ""),
                **(extra or {})}

    total = counts["total"]
    bad = counts["failed"] + counts["errors"]
    if total == 0 or len(not_run) == len(suites):
        t_sub = SubCheck(id="tests", label="All tests pass", status=Status.NOT_RUN,
                         detail=res.reason_not_run or "no tests ran")
    elif not_run:
        t_sub = SubCheck(id="tests", label="All tests pass", status=Status.FAIL,
                         detail=f"{counts['passed']}/{total} passed, {bad} failed; didn't run: "
                                + ", ".join(s.name for s in not_run))
    else:
        t_sub = SubCheck(id="tests", label="All tests pass", status=Status.FAIL if bad else Status.PASS,
                         detail=f"{counts['passed']}/{total} passed, {bad} failed, {counts['skipped']} skipped")
    if cov is None:
        c_sub = SubCheck(id="coverage", label=f"{thr:.0f}%+ of code covered", status=Status.NOT_RUN,
                         detail=res.data["coverage_note"] or "coverage was not measured")
    else:
        c_sub = SubCheck(id="coverage", label=f"{thr:.0f}%+ of code covered",
                         status=Status.PASS if cov.pct >= thr else Status.FAIL,
                         detail=f"{cov.pct}% covered (target {thr:.0f}%)")
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


def result_from_files(root: Path, junit: Optional[Path], coverage: Optional[Path], threshold: float,
                      name: str, note: str = "") -> CheckResult:
    """A functional result built from files a test run outside SVD wrote (svd_add_results)."""
    s = SuiteResult(name=name, runner="external")
    if junit:
        s.counts, s.failures = parse_junit(junit, tool=name)
    if coverage:
        s.coverage = parse_coverage(coverage, root)
        if s.coverage is None:
            s.coverage_note = f"{coverage.name} isn't coverage.py JSON or an Istanbul coverage-summary.json"
    if not junit:
        s.reason_not_run = "no test results given (pass a JUnit XML file)"
    res = CheckResult(name="functional", started_at=time.time())
    return assemble(res, root, threshold, [s], runner=f"{name} (results added after the run)",
                    extra={"external": True, "external_note": note})
