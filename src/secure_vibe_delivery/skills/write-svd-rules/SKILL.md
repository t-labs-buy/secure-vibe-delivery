---
name: write-svd-rules
description: Write and test the team's own Semgrep rules for mistakes AI coding tools often make, kept in a project's svd-rules/ folder, which secure-vibe-delivery runs alongside its bundled rules. Use when the same risky pattern keeps appearing, or the person asks to add a rule.
---

# Write svd-rules

A Semgrep rule describes the shape of a bad line of code, and Semgrep flags every line with that
shape. secure-vibe-delivery already bundles rules for running text as code, disabled HTTPS
checks and SQL built from strings. Put any extra rules in the project's `svd-rules/` folder
and every check runs them automatically.

## When a rule is worth writing

- The same mistake has appeared more than once (in reports or reviews).
- It's specific to the team or project: a banned internal function, a required wrapper,
  a framework setting that must always be on.
- It can be described by the code's shape. Rules can't judge intent or business logic.

## Steps

1. **Write down the bad pattern and the good one**, with a real example of each.
2. **Write the rule** in `svd-rules/<rule-name>.yml` (`references/rule-examples.md`). Use an
   ID starting `svd-`, a message that says what's wrong **and** what to do instead, and a
   severity: `ERROR` for security problems (counts as high), `WARNING` otherwise.
3. **Write a test file** with the same name and the language's extension
   (`svd-rules/<rule-name>.py`), marking lines that must match and lines that must not
   (`references/testing-rules.md`).
4. **Run the tests:** `semgrep --test svd-rules/`. All must pass.
5. **Run it on the project** (`semgrep scan --config svd-rules/ .`) and check for false
   alarms before relying on it.
6. **Commit both files** so the whole team gets the rule.

Keep rules narrow. A rule that fires on good code teaches people to ignore it.
