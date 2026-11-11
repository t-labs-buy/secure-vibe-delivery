# Secure Vibe Delivery — System Architecture

Secure Vibe Delivery is an MCP server that checks an AI-built project before go-live. A developer or reviewer asks their AI assistant (Claude Code or Copilot Chat) to check a project; the server runs security, functional and performance checks with local tools, applies a go-live gate and writes an HTML/PDF report with a GO / PROVISIONAL / NO-GO verdict.

## Components

| Name | Type | Layer | Responsibility | Tech |
|---|---|---|---|---|
| AI Assistant | Frontend | People & assistant | The chat the developer types into. It calls the server's tools, polls long runs, and explains the result. | Claude Code or GitHub Copilot Chat · VS Code or terminal |
| MCP Server | Backend API | MCP interface | Exposes nine `svd_*` tools and two prompts to the assistant. It routes each tool call to the component that does the work. | Python · MCP SDK (FastMCP) · stdio, launched by `uvx` from a git tag |
| Fixing Skills | Backend API | MCP interface | Serves five step-by-step fixing guides as `skill://` resources. Each must-fix item in the report points at one guide. | Markdown files bundled in the package · `svd_skills`, `svd_skill` |
| Guided Setup | Backend API | Orchestration | Walks the person through one-time setup one step per answer. It downloads the Snyk CLI if missing and starts the Snyk and Semgrep sign-ins in the browser. | `svd_setup` · httpx download into the server's own cache folder |
| Doctor | Backend API | Orchestration | Reports which tools are installed and signed in, and what kind of project it is looking at. | `svd_doctor` |
| Run Pipeline | Worker | Orchestration | Runs a check as a background job so the tool call returns at once with a **run_id**. It detects the project, runs the checks in order, then calls the gate and the renderer. | asyncio background task · `svd_run`, `svd_status` |
| Locustfile Generator | Backend API | Orchestration | Writes a starter load-test script from the project's OpenAPI spec, its routes, or `GET /`. | `svd_generate_locustfile` |
| Security Check | Worker | Checks | Runs the Snyk scans and Semgrep, and checks package provenance (every direct dependency must exist and not be brand-new). | Python · subprocesses + httpx |
| Functional Check | Worker | Checks | Runs the project's own tests with coverage and applies the coverage gate. | pytest or Jest · 70% coverage gate |
| Performance Check | Worker | Checks | Runs a load test at 1.5× the expected peak against a test environment and checks the p95 response time. | Locust · quick mode or 15-minute gate mode |
| Local Toolchain | CLI | Scanners & runners | The command-line tools the checks drive. Semgrep and Locust run through `uvx` when they aren't installed; the tool resolver finds each one (PATH → Snyk cache → uvx via the `UV` variable). | Snyk CLI · Semgrep · pytest / Jest · Locust |
| Go-Live Gate | Backend API | Gate & reporting | Turns check results into the verdict and a ranked must-fix list. A check that didn't run counts as a failure. | Python rules |
| Report Renderer | Backend API | Gate & reporting | Builds the self-contained HTML report with the health score, and prints a PDF copy. | Jinja2 template · headless Chrome / Edge for PDF |
| Run Records | Database | Outputs | Keeps each run's state, raw tool output, `summary.json`, run log and the reports. | Files in the project's `.svd/runs` and `.svd/reports` |

## External dependencies

| Name | Provides | Required? | If unavailable |
|---|---|---|---|
| Snyk cloud | Vulnerability database, Snyk Code analysis, Secrets and IaC scanning, sign-in, CLI download | Required | Snyk scans don't run, so the security check fails and the verdict is NO-GO. |
| Semgrep registry | Semgrep rules and an optional sign-in for more detailed results | Required (sign-in optional) | Semgrep scans don't run; without them the code scan and the backup secret scan fail, so NO-GO. |
| PyPI and npm registries | Package age and existence for provenance; downloads for tools run through `uvx` | Required | Provenance can't be confirmed, and Semgrep or Locust can't be fetched if not installed. |
| Test environment | The running test copy of the project's app, never production | Required for performance | The performance check doesn't run, so NO-GO. |
| Chrome or Edge | Headless printing of the PDF copy | Optional | No PDF; the HTML report is still written. |

## Connections

| From | To | Protocol | Auth | Pattern | What flows |
|---|---|---|---|---|---|
| Developer | AI Assistant | Chat | Local session | request/response | The request in plain words, and the answer |
| AI Assistant | MCP Server | MCP over stdio | None (local child process) | request/response | `svd_*` tool calls and their results |
| AI Assistant | MCP Server | MCP over stdio | None | polling (assistant calls `svd_status` until state is "done") | Run progress |
| MCP Server | Fixing Skills | In-process call | None | request/response | A fixing guide's text |
| MCP Server | Guided Setup | In-process call | None | request/response | The current setup step and question |
| MCP Server | Doctor | In-process call | None | request/response | Tool, sign-in and project status |
| MCP Server | Run Pipeline | In-process call | None | fire-and-forget (asyncio task) | Run options; returns a **run_id** at once |
| MCP Server | Locustfile Generator | In-process call | None | request/response | A starter locustfile path |
| Guided Setup | Local Toolchain | Subprocess | Browser sign-in (Snyk OAuth, Semgrep login) | request/response | `snyk auth`, `semgrep login` |
| Guided Setup | Snyk cloud | HTTPS | None | request/response | Snyk CLI download |
| Doctor | Local Toolchain | Subprocess | Stored tool tokens | request/response | `--version`, `snyk whoami`, `semgrep show deployment` |
| Run Pipeline | Security Check | In-process call | None | request/response | Check context; returns a check result |
| Run Pipeline | Functional Check | In-process call | None | request/response | Check context; returns a check result |
| Run Pipeline | Performance Check | In-process call | None | request/response | Check context; returns a check result |
| Security Check | Local Toolchain | Subprocess | Stored Snyk / Semgrep tokens | request/response | `snyk test / code / secrets / iac`, `semgrep` JSON output |
| Security Check | PyPI and npm registries | HTTPS | None | request/response | Package metadata for provenance |
| Functional Check | Local Toolchain | Subprocess | None | request/response | pytest or Jest run with coverage |
| Performance Check | Local Toolchain | Subprocess | None | request/response | Locust run with the load profile; CSV stats |
| Local Toolchain | Snyk cloud | HTTPS | Snyk token | request/response | Dependency lists and source for analysis; findings |
| Local Toolchain | Semgrep registry | HTTPS | Optional Semgrep token | request/response | Rules |
| Local Toolchain | PyPI and npm registries | HTTPS | None | request/response | Semgrep and Locust packages for `uvx` |
| Local Toolchain | Test environment | HTTP(S) | Whatever the app needs | request/response | Load-test traffic |
| Run Pipeline | Go-Live Gate | In-process call | None | request/response | Check results; returns the verdict and must-fix list |
| Run Pipeline | Report Renderer | In-process call | None | request/response | Run state and results |
| Report Renderer | Chrome or Edge | Subprocess (headless) | None | request/response | HTML in, PDF out |
| Report Renderer | Run Records | File write | None | request/response | **HTML report**, PDF, `summary.json`, run log |
| Run Pipeline | Run Records | File write | None | request/response | Run state, raw tool output |
| Run Pipeline | Developer | Opens the default browser | None | fire-and-forget | The **HTML report** |

## The key connection

The server never calls Snyk's API itself. Every Snyk scan is the Security Check starting the Snyk CLI as a local subprocess, and the CLI talks to Snyk cloud over HTTPS with the token the person got from a browser sign-in during guided setup (`snyk auth`). So whether a check works depends on the tool resolver finding the CLI on that machine: on PATH, in the server's own cache (downloaded by setup), or, for Semgrep and Locust, through `uvx` located via the `UV` variable.

## Primary end-to-end scenario

A developer asks for a go-live check of their project, with a test copy of the app running.

### Ask and start the run

1. The Developer asks the AI Assistant to check the project before go-live.
2. The AI Assistant calls `svd_doctor` on the MCP Server, which asks the Doctor; the Doctor asks the Local Toolchain for versions and sign-ins and returns that everything is ready.
3. The AI Assistant calls `svd_run` on the MCP Server, which starts the Run Pipeline as a background job and returns a **run_id** at once.

### Scan for security problems

4. The Run Pipeline detects the project type and starts the Security Check.
5. The Security Check runs the Snyk scans and Semgrep through the Local Toolchain.
6. The Local Toolchain sends the dependency list and code to Snyk cloud and fetches rules from the Semgrep registry, and returns the findings.
7. The Security Check asks the PyPI and npm registries how old each direct dependency is, and returns the **security result** to the Run Pipeline.

### Prove it works and copes with load

8. The Run Pipeline starts the Functional Check, which runs the project's tests with coverage through the Local Toolchain and returns the **functional result**.
9. The Run Pipeline starts the Performance Check, which runs Locust through the Local Toolchain.
10. Locust sends load at 1.5× the expected peak to the Test environment, and the Performance Check returns the **performance result**.
11. Meanwhile the AI Assistant polls `svd_status` on the MCP Server for progress.

### Decide and report

12. The Run Pipeline hands the three results to the Go-Live Gate, which returns the **verdict** and the **must-fix list**.
13. The Run Pipeline asks the Report Renderer for the report; it builds the **HTML report** with the health score and prints the **PDF report** with headless Chrome or Edge.
14. The Report Renderer writes the **HTML report**, the **PDF report**, `summary.json` and the run log to Run Records.
15. The Run Pipeline opens the **HTML report** in the Developer's browser.
16. The AI Assistant calls `svd_report` for the **verdict** and the top items of the **must-fix list**, reads the matching guide from the Fixing Skills, and explains the result to the Developer.

## Side paths and scheduled flows

- **Guided setup (first use, optional afterwards):** when the Doctor reports Snyk missing or not signed in, the assistant walks the person through `svd_setup`, which downloads the Snyk CLI and starts the browser sign-ins.
- **Locustfile generation (optional):** when the project has no load-test script, `svd_generate_locustfile` writes a starter one before the run.
- There are no scheduled jobs; nothing runs unless the assistant calls a tool.

## Deployment constraints

- The server runs as a child process of the assistant, started with `uvx --from git+…@<tag>`; `uvx` must be reachable by the assistant (on PATH, or registered by full path).
- The checks run sequentially in one background task inside that process; a run's state is saved to `.svd/runs` so `svd_status` and `svd_report` can find it after a server restart.
- The performance check must point at a test environment, never production.
