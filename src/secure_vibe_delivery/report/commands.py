"""Plain-language explanations for the commands a run records, shown in the report's History tab."""
from __future__ import annotations

import re
import shlex

# (pattern searched in the command text, short title, what it checks / achieves). First match wins,
# so the more specific patterns come first.
_RULES: list[tuple[str, str, str]] = [
    (r"\bsnyk\b.*\s--version\b", "Snyk version check",
     "Confirms the Snyk command-line tool is installed and records its version, so the report shows exactly "
     "which scanner produced the security results."),
    (r"\bsnyk\b.*\bwhoami\b", "Snyk sign-in check",
     "Asks Snyk which account is signed in. Snyk scans need a signed-in account; without one they can't run."),
    (r"\bsnyk\b.*\bsecrets\s+test\b", "Snyk Secrets: hard-coded keys and passwords",
     "Scans every file for secrets written into the code: API keys, cloud credentials, tokens and passwords. "
     "A leaked key lets anyone use your accounts, so any hit blocks go-live. Values are masked in this report."),
    (r"\bsnyk\b.*\bcode\s+test\b", "Snyk Code: security flaws in your own code",
     "Reads your source code for dangerous patterns such as SQL injection, running user input as code, "
     "turned-off HTTPS checks and unsafe file access. Critical and high issues block go-live."),
    (r"\bsnyk\b.*\btest\b", "Snyk Open Source: vulnerable libraries",
     "Checks every third-party library your project depends on (requirements, pyproject, package.json) against "
     "Snyk's database of known vulnerabilities. Critical issues in libraries block go-live."),
    (r"\bsemgrep\b.*\s--version\b", "Semgrep version check",
     "Confirms Semgrep is installed and records its version for the report."),
    (r"\bsemgrep\b.*\bshow\s+deployment\b", "Semgrep sign-in check",
     "Checks whether Semgrep is signed in. Signing in unlocks Semgrep's registry rules; results still stay on "
     "your machine."),
    (r"\bsemgrep\b.*(p/secrets|svd-secrets)", "Semgrep secrets scan (fallback)",
     "Used when Snyk Secrets isn't available. Searches the code for keys, tokens and passwords with Semgrep's "
     "public secret rules plus secure-vibe-delivery's own rules (svd-secrets.yml). Values are masked."),
    (r"\bsemgrep\b.*\bscan\b", "Semgrep: AI-mistake rules and community rules",
     "Scans your code with Semgrep's recommended rules (--config auto) plus the bundled ai-mistakes rules, "
     "which catch mistakes AI assistants often make: eval/exec on input, verify=False, SQL built from strings. "
     "It is a second opinion next to Snyk Code."),
    (r"\blocust\b.*\s--version\b", "Locust version check",
     "Confirms the Locust load-testing tool can run and records its version."),
    (r"\blocust\b", "Locust load test: can it cope?",
     "Sends traffic from many simulated users at 1.5x your expected peak to the test URL, then measures "
     "response times (p95), the share of failed requests and crashes. Quick mode runs about 2 minutes; "
     "gate mode runs 15 minutes, as the roadmap requires."),
    (r"find_spec\(", "Test tooling check",
     "Looks inside the project's Python environment to see whether pytest and the coverage plugin are "
     "installed, so the test run can measure coverage."),
    (r"-m\s+pytest\b|\bpytest\b", "pytest: does it work?",
     "Runs the project's automated tests and measures code coverage: how much of the code the tests "
     "actually run. Every test must pass and coverage must reach the target (70% by default)."),
    (r"\bjest\b", "Jest: does it work?",
     "Runs the project's JavaScript tests and measures code coverage. Every test must pass and coverage "
     "must reach the target (70% by default)."),
    (r"\bnpm\b|\bnpx\b|\bnode\b", "Node.js tooling",
     "Runs a Node.js tool the checks need, such as reporting the installed version."),
    (r"\bgit\b", "Git information",
     "Reads repository information (such as the current commit) so the report can say which version of the "
     "code was checked."),
    (r"\bpython[0-9.]*\b.*\s--version\b|\s--version\b", "Version check",
     "Records the version of a tool used in this run, so results can be reproduced later."),
]


def explain(command: str) -> dict:
    """{"title", "what"} for a command line; a generic answer when nothing matches."""
    for pattern, title, what in _RULES:
        if re.search(pattern, command):
            return {"title": title, "what": what}
    return {"title": "Supporting command",
            "what": "A helper step the run needed. Its exit code and duration are shown beside it."}


def tool_name(command: str) -> str:
    """The program's short name (snyk, semgrep, pytest...) for the History table."""
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    names = [re.split(r"[\\/]", p)[-1] for p in parts[:4]]
    for n in names:
        if n in ("snyk", "semgrep", "locust", "jest", "pytest", "git", "npm", "npx", "node"):
            return n
    if "-m" in parts and "pytest" in parts:
        return "pytest"
    return names[0] if names else ""


def history(journal: list[dict]) -> list[dict]:
    """Every command from the run, in order, with its explanation."""
    out = []
    for e in sorted(journal, key=lambda e: e["t"]):
        if e.get("kind") != "command":
            continue
        out.append({**e, "tool": tool_name(e["text"]), **explain(e["text"])})
    return out
