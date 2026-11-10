# Testing a rule

Put a test file next to the rule with the same name: `svd-rules/svd-requests-without-timeout.yml`
is tested by `svd-rules/svd-requests-without-timeout.py`. Mark the line **after** each comment:

```python
import requests

# ruleid: svd-requests-without-timeout
requests.get("https://example.com")

# ok: svd-requests-without-timeout
requests.get("https://example.com", timeout=10)

# ok: svd-requests-without-timeout
requests.Session()
```

- `# ruleid: <id>`: the next line **must** be flagged.
- `# ok: <id>`: the next line **must not** be flagged.

Run all rule tests:

```bash
semgrep --test svd-rules/
```

The output lists each rule with any missed matches (should have flagged) and false alarms
(shouldn't have). Fix the rule until every test passes, then add an `ok:` case for each
false alarm you find on real code.
