---
name: rotate-exposed-secrets
description: Deal with passwords, API keys and tokens found in code by a secure-vibe-delivery report. Rotate (replace and cancel) each one at its provider first, then load secrets from the environment instead of the code. Use when a report lists exposed secrets.
---

# Rotate exposed secrets

A key found in the code must be treated as **already leaked**. Deleting the line doesn't help:
the old value stays in the project's git history, in old copies, in CI logs and backups. The
only real fix is to make the old value useless by rotating it.

## Order matters

1. **Tell the person, plainly, which secrets were found** (type, file, line, masked value) and
   that each must be rotated. Never print or ask for the real value.
2. **Rotate at the provider first.** Rotating is done by a person in the provider's console:
   you can't do it for them. Give them the exact steps for each provider from
   `references/providers.md`. The order is: create the new key, update every place that uses
   it, then disable and delete the old key.
3. **Change the code to read the secret from the environment** (`references/loading-secrets.md`):
   replace the hard-coded value with an environment variable, add a `.env.example` listing the
   variable names without values, and make sure `.env` is in `.gitignore`.
4. **Confirm with the person** that the old key is disabled before calling it done.
5. **Re-run the check** (`svd_run`) and confirm the Secrets tab is empty.

## About git history

Once the old key is cancelled, the copy in history is harmless. Rewriting history (for example
with `git filter-repo`) is optional, disruptive (everyone must re-clone) and never a substitute
for rotating. Mention it only if the person asks or company policy requires it.

## Never

- Never move a secret into another file in the repository (a config file, a test fixture,
  a commented-out line). It's still a leaked secret.
- Never "fix" it by masking or splitting the string so scanners miss it.
- Never paste a real secret into the chat, a commit message or the report.
