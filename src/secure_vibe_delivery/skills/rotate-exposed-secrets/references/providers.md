# How to rotate common secrets

These steps are done by the person in each provider's web console or CLI. Create the
replacement first, update everything that uses it, then cancel the old one.

| Secret | Where it looks like | Rotate it |
|---|---|---|
| AWS access key | `AKIA…` plus a 40-character secret | IAM console → Users → the user → Security credentials → Create access key. Update the apps, then on the old key choose Deactivate, check nothing broke, and Delete. Prefer IAM roles over long-lived keys where possible. |
| GitHub token | `ghp_…`, `github_pat_…`, `gho_…` | GitHub → Settings → Developer settings → Personal access tokens → delete the old token, generate a new one with the fewest permissions needed. For a GitHub App or OAuth app, regenerate its secret in the app's settings. |
| Slack token | `xoxb-…`, `xoxp-…` | api.slack.com/apps → the app → OAuth & Permissions → rotate or reinstall to issue new tokens; for webhooks, delete and recreate the incoming webhook. |
| Stripe key | `sk_live_…`, `rk_live_…` | Stripe Dashboard → Developers → API keys → the key's menu → Roll key; choose when the old one expires. |
| Google API key | `AIza…` | Google Cloud console → APIs & Services → Credentials → the key → Regenerate key (or create a new one and delete the old). Add API and application restrictions. |
| OpenAI / Anthropic key | `sk-…`, `sk-proj-…`, `sk-ant-…` | The provider's console → API keys → create a new key, update apps, revoke the old key. Check recent usage for spend you don't recognise. |
| Database password | `password = "…"`, connection strings | Change the user's password in the database (or create a new user), update the app's secret store, then remove the old credentials. |
| Private key | `-----BEGIN … PRIVATE KEY-----` | Generate a new key pair, install the new public key or certificate everywhere the old one was trusted (servers' `authorized_keys`, certificate stores), then remove the old one; revoke the certificate if one was issued. |
| Other passwords or tokens | Any `secret = "…"` | Change it at whatever system issued it, then follow the same order. |

After rotating, check the provider's logs for use of the old key since it was committed.
If there's unexpected use, treat it as a security incident and tell the Delivery Lead.
