# Secure Vibe Delivery tutorial video: script

A tutorial for developers and delivery leads on what the secure-vibe-delivery MCP server does, told
by stepping through the animated architecture demo one request at a time.
Recorded from the live demo at `https://t-labs-buy.github.io/secure-vibe-delivery/architecture/demo/index.html`
(no sign-in), voiced by Kokoro.

## Script

| # | On screen | Narration |
|---|---|---|
| **1. Intro** (0:00–0:12) | Title card: *Secure Vibe Delivery: checking an AI-built project before go-live* | "Hello, and welcome. In the next few minutes, I'll show you how Secure Vibe Delivery checks an AI-built project before it goes live." |
| **2. The idea** (0:12–0:33) | The demo at rest. Point to **Security Check**, **Functional Check** and **Performance** in the **Checks** box, then to **Go-Live Gate** | "AI assistants write code quickly, but someone still has to ask: is it safe, does it work, and can it cope with real traffic? Secure Vibe Delivery answers those three questions with real tools, and gives one verdict: go, provisional, or no-go." |
| **3. The cast** (0:33–0:55) | Point to **Developer**, **AI Assistant** and **MCP Server** in turn, then sweep across the **Local tools** box | "It's an MCP server, so you never run it yourself. You ask your AI assistant, such as Claude Code or Copilot Chat, and the assistant calls the server's tools. Everything runs on your own machine, using local tools like Snyk, Semgrep, pytest and Locust." |
| **4. Ask** (0:55–1:09) | Click **Step** three times: *Developer → AI Assistant*, *AI Assistant → MCP Server*, *MCP Server ⇄ Doctor*. Let each speech bubble show | "Here's one real request. The developer asks for a go-live check. First, the assistant calls the Doctor, which confirms that every tool is installed and signed in." |
| **5. Start the run** (1:09–1:29) | Click **Step** three times: *AI Assistant → MCP Server*, *MCP Server → Run Pipeline*, *MCP Server → AI Assistant*. Point to the *run_id 7f3a* bubble | "Then it starts the run. A full check takes several minutes, so the server doesn't make the assistant wait. It starts a background job and hands back a run ID straight away. The assistant checks on progress whenever it likes." |
| **6. Security** (1:29–1:54) | Click **Step** six times, through *Security Check → Run Pipeline*. Point to **Snyk CLI · Semgrep**, then **Snyk · Semgrep**, then **PyPI · npm** as each lights up | "Security comes first. The security check runs the Snyk scans and Semgrep as local programs. They look for vulnerable packages, risky code and hard-coded secrets. It also checks that every package really exists and isn't brand new, which catches packages an AI may have made up. In this example, security fails." |
| **7. Function** (1:54–2:11) | Click **Step** four times, through *AI Assistant ⇄ MCP Server* (the polling step). Point to **pytest / Jest**, then to the *82% ≥ 70%* bubble | "Next, the functional check runs the project's own tests with pytest or Jest, and measures coverage. The gate is seventy percent. Here it's eighty-two, so this check passes. Meanwhile, the assistant polls for progress." |
| **8. Load** (2:11–2:31) | Click **Step** five times, through *Performance Check → Run Pipeline*. Point to **Locust**, then **Test Environment** | "Then performance. Locust sends one and a half times the expected peak traffic to a test copy of your app, never to production. A quick run gives an early answer; a fifteen-minute gate run is needed before a full go." |
| *Pause* (2:31–2:33) | Two seconds with no narration; the cursor moves to **Go-Live Gate** | — |
| **9. Verdict** (2:33–2:54) | Click **Step** four times, through *Run Records → Developer*. Let the file-transfer panel play, then point to the *NO-GO, health score 61* bubble | "Now the gate decides. Any check that fails, or doesn't run, means no-go. The report renderer writes an HTML report with a health score, plus a PDF copy, into the project's dot S V D folder, and opens it in the developer's browser." |
| **10. Fix** (2:54–3:12) | Click **Step** three times, to the end. Point to **Skills**, then to the last bubble from **AI Assistant** | "Finally, the assistant fetches the verdict and the must-fix list. Each item links to a step-by-step guide from the server's skills, so the assistant can explain what to fix first, and help you fix it." |
| **11. The key idea** (3:12–3:33) | Click the link between **Security Check** and **Snyk CLI · Semgrep** to open the connection inspector, then close it | "One thing worth remembering: the server never calls Snyk directly. It runs the Snyk command-line tool on your machine, signed in through your browser. So a check only works when the tools can be found, and the one-time setup takes care of that." |
| **12. Close** (3:33–3:49) | Closing card: *Ask your assistant: "Check this project before go-live"*, with the install guide address `t-labs-buy.github.io/secure-vibe-delivery/install.html` | "To try it, follow the install guide at t-labs-buy dot github dot io, slash secure-vibe-delivery. Then just ask your assistant to check your project before go-live. Thank you for watching." |

Scenes change with straight cuts; the demo stays on one page from scene 2 to scene 11.

## Before recording

- **Page:** open the standalone demo (`architecture/demo/index.html`), not the tabbed page, so the demo fills the frame. Light mode.
- **Start state:** click **Restart** before the take so the counter shows *0 / 28* and the **Activity log** is empty. Don't press **Play**; every scene advances with **Step**.
- **Step counts:** the scenes use 3 + 3 + 6 + 4 + 5 + 4 + 3 = 28 steps. Wait for each step's animation to finish before the next click; **Step** is disabled while one plays.
- **Saved layout:** use a fresh browser profile, or the demo may show a layout someone saved earlier. The demo ignores layouts saved before layout v2.
- **Connection inspector (scene 11):** clicking a link opens its inspector. Close it with its close button. Don't click **✂ Remove**, which cuts the link and blocks later steps.
- **Example figures:** the numbers in the speech bubbles (82% coverage, p95 410 ms, health score 61, run_id 7f3a) are illustrative, not from a real run. The narration says "In this example" before the first one.
- **Data written:** none. The demo only animates; it runs no checks and stores nothing except a layout you choose to save.
- **Names for the voice:** check that Kokoro says these correctly before the full render: *Snyk* ("sneak"), *Semgrep*, *pytest* ("pie-test"), *Jest*, *Locust*, *MCP*, *Copilot*, *PyPI* (shown on screen only), *.svd* (written as "dot S V D"), *t-labs-buy*.
- **Version:** the install guide currently installs v0.1.14; the narration doesn't name a version, so it stays correct after the next release.
