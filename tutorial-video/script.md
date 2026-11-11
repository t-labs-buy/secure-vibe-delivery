# Secure Vibe Delivery — how a go-live check works — script

Recorded from the animated architecture demo · example figures are illustrative. Total running time: **3:25**.

Generated from `scenes.json` by `tools/build.py`; edit `scenes.json`, not this file.
Narration: Kokoro-82M (open source), voice `af_heart`. Each screen action is timed to a cue phrase in the voice-over.

| # | Time | Scene | On-screen caption |
|---|---|---|---|
| 0 | 0:00–0:10 | title | (card) |
| 1 | 0:10–0:29 | idea | Three questions before go-live: safe, working, ready for real traffic |
| 2 | 0:29–0:49 | cast | An MCP server: you ask your AI assistant, it calls the server's tools |
| 3 | 0:49–1:02 | ask | Step 1 · The developer asks; the Doctor confirms the tools are ready |
| 4 | 1:02–1:18 | run | Step 2 · svd_run starts a background job and returns a run ID at once |
| 5 | 1:18–1:42 | security | Step 3 · Security: Snyk and Semgrep run locally; packages are checked too |
| 6 | 1:42–2:00 | function | Step 4 · Functional: the project's own tests, with a 70% coverage gate |
| 7 | 2:00–2:17 | load | Step 5 · Performance: Locust at 1.5× peak, against a test copy only |
| 8 | 2:17–2:38 | verdict | Step 6 · The gate decides; the report is written and opened |
| 9 | 2:38–2:54 | fix | Step 7 · The must-fix list, each item with a step-by-step guide |
| 10 | 2:54–3:11 | key | Snyk is reached only through the local Snyk command-line tool |
| 11 | 3:11–3:25 | close | (card) |

### 0. 0:00–0:10 · title

**Voice-over** (23 words, 10.2 s):

> Hello, and welcome. In the next few minutes, I'll show you how Secure Vibe Delivery checks an AI-built project before it goes live.

### 1. 0:10–0:29 · idea

**Screen:** The demo at rest; point to the three checks, then the Go-Live Gate.

**Caption:** Three questions before go-live: safe, working, ready for real traffic

**Voice-over** (42 words, 19.6 s):

> AI assistants write code quickly, but someone still has to ask: is it safe, does it work, and can it cope with real traffic? Secure Vibe Delivery answers those three questions with real tools, and gives one verdict: go, provisional, or no-go.

### 2. 0:29–0:49 · cast

**Screen:** Point to Developer, AI Assistant, MCP Server, then the Local tools box.

**Caption:** An MCP server: you ask your AI assistant, it calls the server's tools

**Voice-over** (44 words, 19.6 s):

> It's an MCP server, so you never run it yourself. You ask your AI assistant, such as Claude Code or Copilot Chat, and the assistant calls the server's tools. Everything runs on your own machine, using local tools like Snyk, Semgrep, pytest and Locust.

### 3. 0:49–1:02 · ask

**Screen:** Step three times: Developer → AI Assistant, AI Assistant → MCP Server, MCP Server ⇄ Doctor.

**Caption:** Step 1 · The developer asks; the Doctor confirms the tools are ready

**Voice-over** (27 words, 13.3 s):

> Here's one real request. The developer asks for a go-live check. First, the assistant calls the Doctor, which confirms that every tool is installed and signed in.

### 4. 1:02–1:18 · run

**Screen:** Step three times: start the run, background job, run_id back to the assistant.

**Caption:** Step 2 · svd_run starts a background job and returns a run ID at once

**Voice-over** (40 words, 16.2 s):

> Then it starts the run. A full check takes several minutes, so the server doesn't make the assistant wait. It starts a background job and hands back a run ID straight away. The assistant checks on progress whenever it likes.

### 5. 1:18–1:42 · security

**Screen:** Step six times, through Security Check → Run Pipeline.

**Caption:** Step 3 · Security: Snyk and Semgrep run locally; packages are checked too

**Voice-over** (51 words, 23.9 s):

> Security comes first. The security check runs the Snyk scans and Semgrep as local programs. They look for vulnerable packages, risky code and hard-coded secrets. It also checks that every package really exists and isn't brand new, which catches packages an AI may have made up. In this example, security fails.

### 6. 1:42–2:00 · function

**Screen:** Step four times, through the polling step.

**Caption:** Step 4 · Functional: the project's own tests, with a 70% coverage gate

**Voice-over** (34 words, 17.4 s):

> Next, the functional check runs the project's own tests with pytest or Jest, and measures coverage. The gate is seventy percent. Here it's eighty-two, so this check passes. Meanwhile, the assistant polls for progress.

### 7. 2:00–2:17 · load

**Screen:** Step five times, through Performance Check → Run Pipeline.

**Caption:** Step 5 · Performance: Locust at 1.5× peak, against a test copy only

**Voice-over** (40 words, 17.3 s):

> Then performance. Locust sends one and a half times the expected peak traffic to a test copy of your app, never to production. A quick run gives an early answer; a fifteen-minute gate run is needed before a full go.

### 8. 2:17–2:38 · verdict

**Screen:** Two-second pause, then step four times, through Run Records → Developer.

**Caption:** Step 6 · The gate decides; the report is written and opened

**Voice-over** (43 words, 21.2 s):

> Now the gate decides. Any check that fails, or doesn't run, means no-go. The report renderer writes an HTML report with a health score, plus a PDF copy, into the project's dot S V D folder, and opens it in the developer's browser.

### 9. 2:38–2:54 · fix

**Screen:** Step three times, to the end.

**Caption:** Step 7 · The must-fix list, each item with a step-by-step guide

**Voice-over** (35 words, 15.3 s):

> Finally, the assistant fetches the verdict and the must-fix list. Each item links to a step-by-step guide from the server's skills, so the assistant can explain what to fix first, and help you fix it.

### 10. 2:54–3:11 · key

**Screen:** Open the Security Check ⇄ Snyk CLI · Semgrep connection inspector, then close it.

**Caption:** Snyk is reached only through the local Snyk command-line tool

**Voice-over** (43 words, 17.4 s):

> One thing worth remembering: the server never calls Snyk directly. It runs the Snyk command-line tool on your machine, signed in through your browser. So a check only works when the tools can be found, and the one-time setup takes care of that.

### 11. 3:11–3:25 · close

**Voice-over** (30 words, 14.5 s):

> To try it, follow the install guide at t-labs-buy dot github dot io, slash secure-vibe-delivery. Then just ask your assistant to check your project before go-live. Thank you for watching.
