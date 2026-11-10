# secure-vibe-delivery

An AI coding agent can write a working `/calc` endpoint in seconds. Whether that endpoint runs
`eval(expr)` on whatever a visitor types is a separate question, and it's the one this server
answers. Simply put, `secure-vibe-delivery` is an MCP server (Model Context Protocol, the standard
way coding assistants call outside tools) that runs the Secure Vibe Delivery pipeline on a project
and hands back one HTML report with a go-live verdict.

The pipeline has three checks, each asking one plain question:

| Check | Question | Tools | Must pass |
|---|---|---|---|
| Security (essential) | Is it safe? | Snyk Open Source, Snyk Code, Snyk Secrets (or a Semgrep fallback), Semgrep with AI-mistake rules, a package-provenance check | 0 leaked keys · 0 critical/high issues in our code · 0 critical library issues · no unknown or brand-new packages |
| Functional (required) | Does it work? | pytest or Jest, with coverage | all tests pass · at least 70% line coverage |
| Performance (required) | Can it cope? | Locust | 1.5× expected peak users, held 15 min · under 1% failed requests · p95 within target · no crashes |

## Why a server, and not a script?

The checks themselves aren't new; the roadmap's guide already lists every command. The trouble is
that running them by hand forces a trade-off. Either every developer remembers a dozen commands
and the order they go in, or the checks drift into CI where nobody sees them until a pull request
fails. A shell script fixes the remembering, but the catch is that the agent that wrote the code
can't read the results, so a person still copies findings back into the chat.

An MCP server removes that trade-off. The same coding agent that wrote the code calls the
pipeline, reads a must-fix list ordered the way the roadmap orders it, and can start fixing at
once. One install works in Claude Code, Codex, VS Code, Gemini CLI and Antigravity, because they
all speak MCP.

## How it works

A run takes minutes, and a go-live load test holds for 15. Most clients give up on a single tool
call after about 60 seconds, so the server works like a coat-check ticket: `svd_run` starts the
pipeline in the background and returns a `run_id` at once, and the agent polls with that ticket.

- `svd_doctor`: checks that Snyk (and its login), Semgrep, Locust and the project's own test tools are present, and lists what to install.
- `svd_run`: starts the pipeline and returns a `run_id`.
- `svd_status`: shows which check is running, results so far and recent log lines.
- `svd_report`: returns the verdict, the report path and the top must-fix items.
- `svd_generate_locustfile`: writes a starter load-test script from the project's OpenAPI spec or routes, for review.

There is also a prompt, `secure-vibe-delivery`, that walks the agent through all of these in order.
In Claude Code it appears as `/mcp__secure-vibe-delivery__secure-vibe-delivery`.

Our example endpoint shows the order of play. Security runs first. Snyk Code traces the `expr`
query parameter into `eval` and calls it Code Injection; Semgrep's bundled rule `svd-eval-of-text`
flags the same line. The server merges the two reports into one finding, so the must-fix list
shows one row reported by both tools rather than two rows to argue about. Then pytest runs in the
project's own virtual environment, because tests import the project's code and only that
environment has its dependencies. Last, Locust plays 1.5 × `peak_users` simulated visitors
against the test URL you give it.

Crucially, **a check that didn't run counts as a failure.** If Snyk isn't logged in, or no
`target_url` was given, that line of the checklist reads *Didn't run*, and the verdict is NO-GO.
A green build with a skipped scanner is a build nobody checked.

The verdict has three values:

- **NO-GO**: a must-pass item failed or didn't run.
- **PROVISIONAL**: everything automated passed, but performance ran in quick mode (2 minutes).
- **GO**: everything automated passed in `mode="gate"`. Two items still need a person: "users see only their own data" and "a second person reviewed the change". The report gives them tick-boxes for the Delivery Lead.

### Secrets are masked, everywhere

Snyk Secrets depends on the Snyk plan. When it isn't available (the CLI says so plainly:
*"Snyk Secrets is not supported for org …"*), the server falls back to Semgrep's `p/secrets` ruleset
plus a bundled set of high-signal patterns (`rules/svd-secrets.yml`: AWS, GitHub, Slack, Stripe,
Google and AI-provider keys, private keys, hard-coded passwords). The bundled set exists because
`p/secrets` skips AWS's documented example key, which made the fallback look clean on a project
that wasn't. Snyk Code's own hard-coded-secret findings are folded in too.

None of this needs a paid Semgrep plan. Semgrep's paid *Semgrep Secrets* product adds live-key
validation and history scanning, but the server doesn't use it: `p/secrets` runs with the free CLI,
and the bundled rules are local files that need no account or network. If `p/secrets` can't be
fetched, the scan retries with the bundled rules alone rather than counting as not run. Without a
Semgrep login, Semgrep hides the matched source line (it prints `requires login`), so the server
reads the line from the file itself to mask it.

Values are masked as soon as they're parsed (`AKIAIOSFODNN7EXAMPLE` becomes `AKIA********MPLE`),
and the raw scanner output saved to disk is scrubbed. In practice, the HTML report is safe to
attach to a ticket: it says which line holds a key and tells you to rotate it, without becoming a
second copy of the key.

## Install

You need [uv](https://docs.astral.sh/uv/) (which supplies `uvx`) and the Snyk CLI. `uvx` downloads
a suitable Python (3.11–3.13) for the server by itself. Semgrep and Locust are used from your `PATH`
if present, otherwise they run through `uvx` automatically.

```bash
brew install uv
brew tap snyk/tap && brew install snyk   # once per laptop
brew install semgrep                     # optional: otherwise uvx runs it
```

### Accounts: Snyk and Semgrep

Each developer uses their own free accounts, set up once per laptop.

**Snyk (required).** Sign up at [app.snyk.io/signup](https://app.snyk.io/signup), then connect the
CLI to your account. A browser window opens; log in there.

```bash
snyk auth
```

Without this, the three Snyk scans (libraries, code, secrets) can't run, and a scan that didn't
run counts as a failure, so every report would say NO-GO.

**Semgrep (recommended).** Sign up at [semgrep.dev/login](https://semgrep.dev/login), then:

```bash
semgrep login
```

Semgrep works without an account, so this one is optional. Logged in, Semgrep's output keeps the
matched source lines instead of replacing them with `requires login`, and rules that need a login
become available. Scans still run on your laptop with `semgrep scan`: nothing is uploaded to
Semgrep's dashboard.

`svd_doctor` checks both and tells you what's missing. Snyk Secrets isn't included in every Snyk
plan; where it's missing, the server uses Semgrep's secret rules instead (see above).

The server is installed straight from the public repository
[github.com/t-labs-buy/secure-vibe-delivery](https://github.com/t-labs-buy/secure-vibe-delivery),
pinned to a release tag, so everyone runs the same version. `uvx` fetches it on first launch, which
takes a few seconds; after that it starts from a cache. No GitHub login is needed.

### Claude Code

For all your projects:

```bash
claude mcp add --scope user secure-vibe-delivery -- \
  uvx --from git+https://github.com/t-labs-buy/secure-vibe-delivery@v0.1.2 secure-vibe-delivery
```

For one project, shared with the team: copy [`examples/claude-code/.mcp.json`](examples/claude-code/.mcp.json)
to the project root and commit it. Claude Code asks each person to approve the server the first time
they open the project. Type `/mcp` in a session to confirm `secure-vibe-delivery` is connected.

### VS Code (GitHub Copilot Chat)

Copy [`examples/vscode/mcp.json`](examples/vscode/mcp.json) to `.vscode/mcp.json` in the project
and commit it, or add the same entry to your own configuration with *MCP: Open User
Configuration*. Start the server from the **Start** link VS Code shows above the entry (or run
*MCP: List Servers* from the command palette), then use it from Copilot Chat in **Agent** mode.
If you added it while a chat was open, run *Developer: Reload Window* and start a new chat.

> **Using the Claude Code extension inside VS Code?** It doesn't read VS Code's `mcp.json`.
> Claude Code keeps its own list of servers, so set it up with the [Claude Code](#claude-code)
> steps above, even though you're working in VS Code.

### Other clients

**Codex** (`~/.codex/config.toml`). The first `uvx` launch downloads dependencies, so give it time to start:

```toml
[mcp_servers.secure-vibe-delivery]
command = "uvx"
args = ["--from", "git+https://github.com/t-labs-buy/secure-vibe-delivery@v0.1.2", "secure-vibe-delivery"]
startup_timeout_sec = 60
```

**Gemini CLI** (`~/.gemini/settings.json`) and **Antigravity** (MCP Store → Manage MCP Servers →
View raw config, which opens `~/.gemini/config/mcp_config.json`; some older guides cite
`~/.gemini/antigravity/mcp_config.json`, so check which file your install reads): use the
`mcpServers` block from `examples/claude-code/.mcp.json`, without the `"type"` line.

Optional settings, for any client's `env`: `SVD_SNYK_ORG` sends Snyk scans to a particular Snyk
organisation (use its **ID**: `snyk secrets test` ignores a slug), and `SNYK_TOKEN` /
`SEMGREP_APP_TOKEN` replace `snyk auth` / `semgrep login` on machines where you can't log in
interactively. Put tokens only in personal config files, never in one you commit: this repository
is public.

### Upgrading

Releases are git tags. To move to a new one, change the `@v0.1.x` tag in the command or
config file.

## Using it

Ask the agent to "run secure vibe delivery on this project against http://127.0.0.1:8000", or use
the prompt. A typical call:

```text
svd_run(project_path="/abs/path/to/app", target_url="http://127.0.0.1:8000",
        mode="quick", peak_users=100, response_time_p95_ms=1000)
```

| Option | Default | Meaning |
|---|---|---|
| `target_url` | none | Running **test** environment. Never production. Without it, performance is NOT_RUN. |
| `mode` | `quick` | `quick` holds the load for 2 min (indicative); `gate` holds it for 15 min (go-live). |
| `peak_users` | 100 | Expected peak; Locust runs ceil(1.5 × this). |
| `response_time_p95_ms` | 1000 | The p95 target agreed with the client. |
| `checks` | all three | A subset; the rest show as NOT_RUN. |
| `coverage_threshold` | 70 | Minimum line coverage, %. |
| `locustfile` | auto | Otherwise the project's `locustfile.py`, otherwise a generated one. |
| `stop_on_security_fail` | false | Skip the other checks when security fails. |
| `duration` | none | Override the hold time, e.g. `5m`. |

Output lands in the project, under `.svd/` (which gets its own `.gitignore`):

- `.svd/reports/svd-report-<time>.html`: the report (verdict, must-fix list, secrets, security detail, functional results, performance dashboard, go-live checklist, appendix).
- `.svd/reports/svd-report-<time>.summary.json`: the same data for machines.
- `.svd/reports/svd-report-<time>-locust.html`: Locust's own report.
- `.svd/runs/<run_id>/`: raw (scrubbed) tool output and state.

The report is one self-contained file with light and dark themes, and it works offline (the
JetBrains Mono web font falls back to the system monospace font). The performance charts have a
hover crosshair and a data-table fallback.

### Things the project needs

- **Python:** a virtual environment (`.venv`, `venv` or `env`) with the project's packages, `pytest` and `pytest-cov` installed, and `pip` present. Snyk's Python scanner shells out to pip, so a uv-made venv without pip fails with *"Something went wrong getting dependencies"*. Fix: `uv pip install pip`.
- **JavaScript:** `jest` in `devDependencies`, installed in `node_modules`.
- **Your own Semgrep rules:** put them in `svd-rules/` at the project root and they run alongside the bundled ones.

## Development

```bash
uv venv --python 3.12 .venv && uv pip install -e ".[dev]"
.venv/bin/python -m pytest
```

`tests/fixtures/vulnapp` is a deliberately broken FastAPI app: `eval`, `verify=False`, an f-string
SQL query, planted fake keys, old library pins, a failing test, low coverage and a slow endpoint.
To run the whole pipeline against it:

```bash
cd tests/fixtures/vulnapp
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -r requirements.txt pip
.venv/bin/uvicorn app:app --port 8765 &
# then from a client: svd_run(project_path=<abs path to vulnapp>, target_url="http://127.0.0.1:8765", peak_users=20, duration="45s")
```

The expected result is NO-GO, with every planted issue in the must-fix list.

## What it doesn't do (yet)

Coverage is measured across the whole codebase, not just the lines a change touched. The roadmap
asks for 70% of *new* code, and diff coverage is the obvious next step. The "wrong-case tests"
check is a heuristic: it looks for tests that assert 401/403 responses or another user's access, and
can't tell whether those tests are any good. And "no crashes under load" is inferred from connection
errors and a health check after the run, since Locust can't see a server restart directly. Gitleaks
and CodeQL are deliberately left out. The server can tell you a key is in the code; it can't tell
you who copied it before you rotated it.
