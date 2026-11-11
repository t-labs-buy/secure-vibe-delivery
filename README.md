# secure-vibe-delivery

AI coding assistants write working code fast; whether that code is safe is a separate question.
Simply put, `secure-vibe-delivery` is an MCP server (Model Context Protocol, the standard way coding
assistants call outside tools) that checks a project three ways and hands back one HTML report with
a go-live verdict: **GO**, **PROVISIONAL** or **NO-GO**, plus a fix list in priority order.

| Check | Question | Tools | Must pass |
|---|---|---|---|
| Security (essential) | Is it safe? | Snyk Open Source, Snyk Code, Snyk Secrets (or Semgrep's secret rules), Snyk IaC (when there are Terraform, Kubernetes, CloudFormation or ARM files), Semgrep with AI-mistake rules, a package-existence check | No leaked keys · no critical/high issues in our code or infrastructure files · no critical library issues · no unknown or brand-new packages |
| Functional | Does it work? | pytest and Jest (each suite the project has), or the project's own test commands, with coverage | All tests pass · at least 70% coverage |
| Performance | Can it cope? | Locust | 1.5× expected peak users for 15 min · under 1% failed requests · p95 within target · no crashes |

A check that didn't run counts as a failure, never as a pass.

**New here?** Read the plain-English [tutorial](https://t-labs-buy.github.io/secure-vibe-delivery/tutorial.html).

## Install

Follow the **[install guide](https://t-labs-buy.github.io/secure-vibe-delivery/install.html)**. It walks through setup on a Mac or Windows,
for Claude Code (terminal or VS Code extension) and GitHub Copilot Chat in VS Code, with
troubleshooting. Tip: Ctrl-click (⌘-click on a Mac) a link to open it in a new tab.

## First run

Ask your assistant **"Set up secure-vibe-delivery for me"**. It walks you through a short checklist one
step at a time, asking before each step: get the Snyk scanner (it can download it), create a free Snyk
account or sign in in your browser, turn on **Enable Snyk Code** in your Snyk settings (Settings →
Snyk Code → toggle on → **Save changes**), and an optional Semgrep sign-in. You never type a password
into the chat.
Then:

> Run secure vibe delivery on this project against http://127.0.0.1:8000 with 100 peak users

Use a test environment, never production. Without an address, performance shows as "didn't run".
By default the load test is a 2-minute quick run; say "use gate mode" for the 15-minute go-live
run. When the check finishes, the HTML report opens in your browser automatically (set
`SVD_OPEN_REPORT=0` to turn that off); it's also saved in the project's `.svd/reports/` folder,
with a PDF copy beside it when Chrome or Edge is installed (the report's **Download PDF** button), or
**Print / Save as PDF** from the report in any browser. Secret values in both are always masked.

**What the project needs:** for Python, a virtual environment with the project's packages, `pytest`,
`pytest-cov` and `pip`; for JavaScript, `jest` installed. Custom Semgrep rules in `svd-rules/` run
alongside the bundled ones. A project with a Python backend and a Jest frontend (in the root or a
folder such as `frontend/`) gets both suites run, each listed in the report, with coverage combined by
line count.

**pytest that would hurt your data is refused.** pytest 8 no longer calls nose-style module-level
`setup()`/`teardown()` (or those methods on test classes). Tests that rely on one, often to point
themselves at a throwaway database, would run against the real one instead. When test files use these
hooks, the functional check doesn't start pytest; it says which files and why, and `svd_doctor` warns
before you run. Give the server the command the project really uses (next section).

## Project settings: `.svd.toml`

Optional, at the project root. Everything in it has a default.

```toml
[[functional.suite]]                  # run these instead of auto-detected pytest / Jest
name = "backend"
command = "scripts/run_tests.sh"      # through the shell, from the project root
junit = ".svd/functional/junit.xml"   # optional: per-test results (otherwise the exit code)
coverage = ".svd/functional/coverage.json"   # coverage.py JSON or Istanbul coverage-summary.json
timeout = 3600                        # seconds, default 1800

[functional]
allow_unsafe_pytest = false           # true only after checking the nose-style files are safe

[performance]
locustfile = "loadtest/locustfile.py" # otherwise found in the root, loadtest/, load/, perf/...
env_file = ".env"                     # variables Locust's process gets; names are logged, values never
env = { LOADTEST_LLM = "0" }          # set after env_file

[security]
exclude = ["generated"]               # extra folders the scanners skip
```

Result files the suite didn't write during this run are ignored, so stale results can't pass a check.

**Third-party code isn't scanned.** Every virtualenv in the project is skipped, whatever it's called
(anything with a `pyvenv.cfg`), along with `node_modules` and `site-packages`, so their example keys
and old code don't bury your own findings.

**Secrets are graded by where they live.** A value in git (or not ignored, so the next `git add .`
would commit it) fails the check. A key in a git-ignored file such as `.env`, a made-up password in a
test, and an example in documentation are listed as lower risk and don't fail it. Provider keys (AWS,
GitHub, AI providers...) always count, wherever they appear. Outside a git repository, every secret
counts.

## Tools and options

| Tool | Does |
|---|---|
| `svd_setup` | Guided one-time setup, one step at a time |
| `svd_doctor` | Check that everything is installed and signed in |
| `svd_run` | Start a check in the background; returns a `run_id` |
| `svd_status` | Progress of a run |
| `svd_report` | Verdict, report path and top must-fix items |
| `svd_generate_locustfile` | Starter load-test script from the project's API |
| `svd_write_summary` | The assistant adds its written summary to the report's Overview |
| `svd_add_results` | Add test results (JUnit XML, coverage JSON) from a run done outside the server to a finished report |
| `svd_skills` / `svd_skill` | List and read the fixing skills (below) |

## Skills: the know-how for fixing

Besides tools, the server serves five [Agent Skills](https://senthilcaesar.github.io/blogs/#/posts/skills-over-mcp)
as MCP resources at `skill://<skill>/<file>`, following the Skills over MCP convention (SEP-2640):
`fix-security-findings`, `rotate-exposed-secrets`, `write-wrong-case-tests`, `write-locustfiles` and
`write-svd-rules`. Each must-fix item in a report links to the one guide that explains how to fix it,
so the assistant reads only what the fix needs. They're instructions only (no scripts), and every
file is listed with its SHA-256 digest. Updating the server updates the skills for everyone.

The report names the exact code it checked (git commit, branch, and any uncommitted changes), so a
sign-off covers a known version. Its Overview also shows a secure-health score (0–100, graded A–F) and a summary your
assistant writes. The Logs tab holds a full run log of every step, and the History tab lists every
command in order, with a Copy button and a hover note on what each one checks.

Useful `svd_run` options: `target_url`, `mode` (`quick`/`gate`), `peak_users` (default 100),
`response_time_p95_ms` (default 1000), `checks`, `coverage_threshold` (default 70). Optional
environment settings: `SVD_SNYK_ORG` (a Snyk organisation ID), `SNYK_TOKEN` / `SEMGREP_APP_TOKEN`
(instead of browser sign-in), `SVD_CACHE_DIR` (where the downloaded Snyk lives), `SVD_PDF=0` (no PDF copy) or `SVD_PDF_BROWSER`
(which browser prints it). Keep tokens out of
committed files: this repository is public.

## Update or remove

Releases are git tags; change `@v0.1.14` to a newer tag to update. To remove the server from Claude
Code: `claude mcp remove secure-vibe-delivery -s user`. For Copilot, delete its `mcp.json` entry.

## Development

```bash
uv venv --python 3.12 .venv && uv pip install -e ".[dev]"
.venv/bin/python -m pytest
```

`tests/fixtures/vulnapp` is a deliberately broken FastAPI app (planted fake keys, `eval`, an SQL
injection, old libraries, a failing test). Running the server against it should give NO-GO with
every planted issue listed.

## Known limits

Coverage is measured across the whole codebase, not only new code. The nose-style check reads test
files' top-level code; setup done some other unusual way isn't recognised. The wrong-case test check is a
heuristic. Crashes under load are inferred from connection errors and a health check. Gitleaks and
CodeQL are deliberately left out. The report can tell you a key is in the code; it can't tell you
who copied it before you rotated it.
