---
name: fix-security-findings
description: Fix the security issues in a secure-vibe-delivery report the right way, one finding at a time, with the fix pattern for each kind of issue (SQL injection, code injection, disabled HTTPS checks, SSRF, vulnerable or suspicious libraries) and the exception process when a fix has to wait. Use when working through a report's must-fix list.
---

# Fix security findings

Work through the report's must-fix list in its order: exposed secrets first (use the
`rotate-exposed-secrets` skill), then critical and high issues in our own code, then critical
library issues, then suspicious packages. One finding at a time.

## For each finding

1. **Find its kind.** Each must-fix item has a `guide` pointing at the reference below that
   matches it. If it has none, use the finding's CWE number and the table here.
2. **Read that one reference**, then read the flagged code and enough around it to understand
   where the data comes from.
3. **Make the smallest fix that removes the cause.** Change the pattern (parameters instead of
   string building, an allow-list instead of free input). Don't hide the symptom.
4. **Add or adjust a test** that would have caught it: the malicious input is rejected, or the
   query uses parameters.
5. **Re-run the check** (`svd_run`). Every fix is followed by a full re-scan, because a fix can
   break something else.

| CWE | Issue | Reference |
|---|---|---|
| CWE-89 | SQL built from input | `references/sql-injection.md` |
| CWE-94, CWE-95 | Text run as code (`eval`, `exec`, `new Function`) | `references/code-injection.md` |
| CWE-295 | HTTPS / TLS certificate checks switched off | `references/tls-verification.md` |
| CWE-918 | Server fetches a URL the user chose (SSRF) | `references/ssrf.md` |
| Library or package finding | Vulnerable, unknown or brand-new dependency | `references/dependency-upgrades.md` |
| Anything else | Follow the finding's own link and rule text | `references/other-findings.md` |

## Rules

- **Never suppress a finding to get a green result.** No `# nosemgrep`, no Snyk ignore, no
  deleting the test, unless it's a documented exception (`references/exceptions.md`).
- **Don't change behaviour beyond the fix** without asking the person first.
- **If a fix would be large or risky**, explain the options and let the person decide.
- **Tell the person what you changed and why** in plain words, finding by finding.
