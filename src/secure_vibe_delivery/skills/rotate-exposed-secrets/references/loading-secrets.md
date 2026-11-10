# Loading secrets from the environment

## Python

```python
import os

AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]          # fails fast if missing
DB_PASSWORD = os.environ.get("DB_PASSWORD")                    # optional value
```

For local development, `python-dotenv` reads a `.env` file into the environment:

```python
from dotenv import load_dotenv
load_dotenv()  # call once at start-up, before reading os.environ
```

Frameworks have their own helpers (Django settings reading `os.environ`, Pydantic
`BaseSettings`); use the one the project already uses.

## JavaScript / TypeScript

```js
const apiKey = process.env.STRIPE_SECRET_KEY;
if (!apiKey) throw new Error("STRIPE_SECRET_KEY is not set");
```

For local development: `import "dotenv/config";` at the top of the entry file (with the
`dotenv` package), or Node's built-in `node --env-file=.env app.js`.

## Files to add or check

- **`.env`**: the real values, for this machine only. Add `.env` to `.gitignore`.
- **`.env.example`**: the same variable names with empty or dummy values, committed so others
  know what to set:

```
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
DB_PASSWORD=
```

## In production and CI

Use the platform's secret store (GitHub Actions secrets, Azure Key Vault, AWS Secrets Manager,
the hosting provider's environment settings), not a committed file.
