# When a finding can't be fixed yet: exceptions

The roadmap allows an exception only with **all four** of:

1. a **written reason** (why it can't be fixed now, and why the risk is acceptable meanwhile);
2. a **named owner** who will fix it;
3. an **end date no more than 90 days away**;
4. **approval from the Delivery Lead**.

An exception is never a way to get a green result. Don't create one yourself: draft it and
ask the person to get it approved.

## Recording it so the scanners know

- **Snyk Open Source** (library issues): after approval,
  `snyk ignore --id=SNYK-PYTHON-EXAMPLE-123456 --expiry=YYYY-MM-DD --reason="<reason> Owner: <name>. Approved: <Delivery Lead>"`
  This writes a `.snyk` file; commit it. The expiry makes the issue come back automatically.
- **Snyk Code** (issues in our code): ignores are managed in the Snyk web app for the project.
- **Semgrep**: a comment on the flagged line, with the rule ID and the reason:
  `# nosemgrep: svd-sql-string-join -- reason, owner, expiry YYYY-MM-DD, approved by <name>`

Add the exception to the report's go-live checklist record (the "Exceptions approved" line)
so the Delivery Lead signs off knowingly.
