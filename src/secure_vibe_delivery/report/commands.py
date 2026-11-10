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
    (r"\bsnyk\b.*\biac\s+test\b", "Snyk IaC: risky infrastructure settings",
     "Checks the project's infrastructure files (Terraform, Kubernetes, CloudFormation, Azure ARM) for risky "
     "settings: storage buckets open to the public, databases reachable from the whole internet, containers "
     "running as root or privileged, missing encryption. Critical and high issues block go-live."),
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


# --- timeline for the Logs tab ------------------------------------------------------------

# explanation title (prefix) -> (row label, check, key in security not_run that means "this scanner didn't work")
_ROWS: list[tuple[str, str, str, str]] = [
    ("Snyk version", "Tool version checks", "setup", ""),
    ("Semgrep version", "Tool version checks", "setup", ""),
    ("Locust version", "Tool version checks", "setup", ""),
    ("Version check", "Tool version checks", "setup", ""),
    ("Node.js tooling", "Tool version checks", "setup", ""),
    ("Snyk sign-in", "Sign-in checks", "setup", ""),
    ("Semgrep sign-in", "Sign-in checks", "setup", ""),
    ("Git information", "Code version (git)", "setup", ""),
    ("Snyk Open Source", "Snyk Open Source", "security", "snyk-open-source"),
    ("Snyk Code", "Snyk Code", "security", "snyk-code"),
    ("Semgrep: AI-mistake", "Semgrep · OWASP + AI rules", "security", "semgrep"),
    ("Snyk IaC", "Snyk IaC · infrastructure", "security", "snyk-iac"),
    ("Snyk Secrets", "Snyk Secrets", "security", ""),
    ("Semgrep secrets", "Secrets · Semgrep fallback", "security", "secrets"),
    ("Test tooling", "Test tooling check", "functional", ""),
    ("pytest", "pytest + coverage", "functional", ""),
    ("Jest", "Jest + coverage", "functional", ""),
    ("Locust load test", "Locust load test", "performance", ""),
]

_EXIT = {
    "snyk": {0: "no issues found", 1: "issues were found", 2: "the scan failed", 3: "no supported files were found"},
    "semgrep": {0: "the scan finished", 1: "findings were reported"},
    "pytest": {0: "every test passed", 1: "some tests failed", 2: "the run was interrupted",
               3: "pytest hit an internal error", 4: "pytest was called wrongly", 5: "no tests were found"},
    "jest": {0: "every test passed", 1: "some tests failed"},
    "locust": {0: "the load test finished", 1: "some requests failed during the load test"},
    "git": {0: "", 128: "this folder isn't a git repository"},
    "helper": {0: "it worked"},
}


def exit_meaning(tool: str, code) -> str:
    if code is None:
        return "It timed out or couldn't start."
    meaning = _EXIT.get(tool, {}).get(code)
    if meaning is None:
        meaning = "it failed" if code else ""
    return f"Exit {code} means {meaning}." if meaning else f"Exit {code}."


def _fmt_clock(seconds: float) -> str:
    seconds = max(0, int(round(seconds)))
    return f"{seconds // 60}:{seconds % 60:02d}"


def _fmt_total(seconds: float) -> str:
    seconds = int(round(seconds))
    m, s = divmod(seconds, 60)
    if not m:
        return f"{s} second{'s' if s != 1 else ''}"
    return f"{m} minute{'s' if m != 1 else ''} {s} second{'s' if s != 1 else ''}"


def _ticks(total: float) -> list[dict]:
    step = next((s for s in (5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600) if total / s <= 6), 3600)
    out, t = [], 0
    while t < total - step * 0.35:  # leave room for the end label
        out.append({"pct": round(t / total * 100, 3), "label": _fmt_clock(t)})
        t += step
    out.append({"pct": 100.0, "label": _fmt_clock(total), "end": True})
    return out


def timeline(st, results: dict) -> dict:
    """Rows for the "What ran, and for how long" chart: one bar per step, placed on the run's clock."""
    journal = sorted(st.journal, key=lambda e: e["t"])
    if not journal:
        return {"rows": [], "ticks": [], "total_text": ""}
    sec = results.get("security")
    sec_data = sec.data if sec else {}
    not_run = sec_data.get("not_run", {})
    check_status = {k: (r.status.value if r else "") for k, r in results.items()}

    steps = []
    for e in journal:
        if e.get("kind") == "command":
            ex = explain(e["text"])
            label, check, key = "Other commands", "setup", ""
            for prefix, lab, chk, k in _ROWS:
                if ex["title"].startswith(prefix):
                    label, check, key = lab, chk, k
                    break
            skipped, why = False, ""
            if check == "security":
                if label == "Snyk Secrets":
                    why = sec_data.get("snyk_secrets_unavailable") or ""
                    if why:
                        why += " Semgrep's secret rules were used instead."
                elif key and key in not_run:
                    why = not_run[key]
                elif "p/secrets" in e["text"] and sec_data.get("semgrep_registry_secrets_error"):
                    why = ("Semgrep's registry secret rules weren't available, so it ran again with the bundled "
                           "rules only: " + sec_data["semgrep_registry_secrets_error"])
                skipped = bool(why)
            elif check in ("functional", "performance") and check_status.get(check) == "NOT_RUN":
                r = results.get(check)
                skipped, why = True, (getattr(r, "reason_not_run", "") or "The check didn't produce results")
            if not skipped and e.get("exit_code") is None:
                skipped, why = True, "It timed out or couldn't start."
            tool = tool_name(e["text"]) if check != "setup" and not ex["title"].startswith("Test tooling") else "helper"
            steps.append({"label": label, "check": check, "t": e["t"], "dur": float(e.get("duration_s") or 0),
                          "skipped": skipped, "why": why[:400], "commands": [{
                              "text": e["text"], "exit": e.get("exit_code"), "dur": e.get("duration_s"),
                              "title": ex["title"], "what": ex["what"], "exit_text": exit_meaning(tool, e.get("exit_code")),
                              "cwd": e.get("cwd", "")}]})
        elif e.get("step") == "provenance" and e.get("duration_s") is not None:
            steps.append({"label": "Package provenance", "check": "security", "t": e["t"], "dur": float(e["duration_s"]),
                          "skipped": "provenance" in not_run, "why": not_run.get("provenance", ""),
                          "commands": [], "note": e["text"]})

    # merge back-to-back steps that share a row (e.g. the version checks at the start)
    rows: list[dict] = []
    for s in steps:
        last = rows[-1] if rows else None
        if last and last["label"] == s["label"]:
            end = max(last["t"] + last["dur"], s["t"] + s["dur"])
            last["dur"] = end - last["t"]
            last["commands"] += s["commands"]
            last["skipped"] = last["skipped"] and s["skipped"]
            last["why"] = last.get("why") or s.get("why", "")
        else:
            rows.append(dict(s))
    seen: dict[str, int] = {}
    for r in rows:  # a row label that comes back later (git at the start and end) gets a suffix
        seen[r["label"]] = seen.get(r["label"], 0) + 1
        if seen[r["label"]] > 1:
            r["label"] += " (again)"

    start = journal[0]["t"]
    end = max([r["t"] + r["dur"] for r in rows] + [st.finished_at or 0, journal[-1]["t"]])
    total = max(end - start, 1.0)
    for r in rows:
        r["start_s"] = r["t"] - start
        r["left"] = round(r["start_s"] / total * 100, 3)
        r["width"] = round(max(r["dur"] / total * 100, 0.6), 3)
        r["left"] = min(r["left"], 100 - r["width"])
        r["start_text"] = _fmt_clock(r["start_s"])
        r["dur_text"] = f"{r['dur']:.2f}".rstrip("0").rstrip(".") + "s" if r["dur"] < 600 else _fmt_total(r["dur"])
        r["label_inside"] = r["width"] >= 9
        exits = [c["exit"] for c in r["commands"]]
        r["exit_text"] = "" if not exits else ("exit " + ", ".join("-" if x is None else str(x) for x in exits[:4]))
    return {"rows": rows, "ticks": _ticks(total), "total": total, "total_text": _fmt_total(total),
            "checks": sorted({r["check"] for r in rows}), "any_skipped": any(r["skipped"] for r in rows)}
