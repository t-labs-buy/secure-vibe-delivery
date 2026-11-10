# secure-vibe-delivery

AI coding assistants write working code fast; whether that code is safe is a separate question.
Simply put, `secure-vibe-delivery` is an MCP server (Model Context Protocol, the standard way coding
assistants call outside tools) that checks a project three ways and hands back one HTML report with
a go-live verdict: **GO**, **PROVISIONAL** or **NO-GO**, plus a fix list in priority order.

| Check | Question | Tools | Must pass |
|---|---|---|---|
| Security (essential) | Is it safe? | Snyk Open Source, Snyk Code, Snyk Secrets (or Semgrep's secret rules), Semgrep with AI-mistake rules, a package-existence check | No leaked keys · no critical/high issues in our code · no critical library issues · no unknown or brand-new packages |
| Functional | Does it work? | pytest or Jest, with coverage | All tests pass · at least 70% coverage |
| Performance | Can it cope? | Locust | 1.5× expected peak users for 15 min · under 1% failed requests · p95 within target · no crashes |

A check that didn't run counts as a failure, never as a pass.

**New here?** Read the plain-English [tutorial](https://t-labs-buy.github.io/secure-vibe-delivery/tutorial.html).

## Install

Follow the **[install guide](https://t-labs-buy.github.io/secure-vibe-delivery/install.html)**. It walks through setup on a Mac or Windows,
for Claude Code (terminal or VS Code extension) and GitHub Copilot Chat in VS Code, with
troubleshooting. Tip: Ctrl-click (⌘-click on a Mac) a link to open it in a new tab.

## First run

Ask your assistant **"Set up secure-vibe-delivery for me"**. It downloads Snyk if needed and opens a
free Snyk sign-up (and optionally Semgrep's) in your browser; you sign in there, never in the chat.
Then:

> Run secure vibe delivery on this project against http://127.0.0.1:8000 with 100 peak users

Use a test environment, never production. Without an address, performance shows as "didn't run".
By default the load test is a 2-minute quick run; say "use gate mode" for the 15-minute go-live
run. The report lands in the project's `.svd/reports/` folder; open the `.html` file in a browser.
Secret values in it are always masked.

**What the project needs:** for Python, a virtual environment with the project's packages, `pytest`,
`pytest-cov` and `pip`; for JavaScript, `jest` installed. Custom Semgrep rules in `svd-rules/` run
alongside the bundled ones.

## Tools and options

| Tool | Does |
|---|---|
| `svd_setup` | One-time setup: fetch Snyk, start the browser sign-ins |
| `svd_doctor` | Check that everything is installed and signed in |
| `svd_run` | Start a check in the background; returns a `run_id` |
| `svd_status` | Progress of a run |
| `svd_report` | Verdict, report path and top must-fix items |
| `svd_generate_locustfile` | Starter load-test script from the project's API |

Useful `svd_run` options: `target_url`, `mode` (`quick`/`gate`), `peak_users` (default 100),
`response_time_p95_ms` (default 1000), `checks`, `coverage_threshold` (default 70). Optional
environment settings: `SVD_SNYK_ORG` (a Snyk organisation ID), `SNYK_TOKEN` / `SEMGREP_APP_TOKEN`
(instead of browser sign-in), `SVD_CACHE_DIR` (where the downloaded Snyk lives). Keep tokens out of
committed files: this repository is public.

## Update or remove

Releases are git tags; change `@v0.1.3` to a newer tag to update. To remove the server from Claude
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

Coverage is measured across the whole codebase, not only new code. The wrong-case test check is a
heuristic. Crashes under load are inferred from connection errors and a health check. Gitleaks and
CodeQL are deliberately left out. The report can tell you a key is in the code; it can't tell you
who copied it before you rotated it.
