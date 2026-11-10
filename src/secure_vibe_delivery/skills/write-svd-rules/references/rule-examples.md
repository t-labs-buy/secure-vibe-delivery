# Rule examples

## Ban a function, with the safe alternative in the message

```yaml
rules:
  - id: svd-no-pickle-loads
    languages: [python]
    severity: ERROR
    message: pickle.loads on untrusted data can run code. Use json.loads, or a safe format.
    metadata: {cwe: ["CWE-502"], category: security}
    pattern-either:
      - pattern: pickle.loads(...)
      - pattern: pickle.load(...)
```

## Match a call only when an argument has a certain value

```yaml
rules:
  - id: svd-flask-debug-on
    languages: [python]
    severity: WARNING
    message: Flask debug mode exposes an interactive console. Turn it off outside local development.
    pattern: $APP.run(..., debug=True, ...)
```

## Flag the bad shape, except when a safe wrapper is used

```yaml
rules:
  - id: svd-requests-without-timeout
    languages: [python]
    severity: WARNING
    message: HTTP call without a timeout can hang a worker forever. Pass timeout=10 (or similar).
    patterns:
      - pattern: requests.$METHOD($URL, ...)
      - pattern-not: requests.$METHOD($URL, ..., timeout=$T, ...)
      - metavariable-regex:
          metavariable: $METHOD
          regex: ^(get|post|put|patch|delete|head)$
```

## JavaScript: string-built SQL

```yaml
rules:
  - id: svd-js-sql-template
    languages: [javascript, typescript]
    severity: ERROR
    message: SQL built with a template string. Use placeholders and a values array.
    metadata: {cwe: ["CWE-89"], category: security}
    pattern-either:
      - pattern: $DB.query(`...${$X}...`, ...)
      - pattern: $DB.query("..." + $X, ...)
```

Building blocks: `...` matches anything, `$NAME` captures a value, `pattern-either` means any
of these, `patterns` means all of these, `pattern-not` excludes a shape, `pattern-inside`
limits matches to inside another shape (for example, inside a request handler).
