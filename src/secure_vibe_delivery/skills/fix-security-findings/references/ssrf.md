# Server-side request forgery, SSRF (CWE-918)

**The problem:** the server fetches a URL the user supplied. An attacker can point it at
internal addresses the server can reach but they can't: cloud metadata endpoints
(`169.254.169.254`), admin panels, databases on the private network.

**The fix, strongest first:**

1. **Don't take a URL at all.** Take an ID or a name and look up the real URL on the server.
2. **Allow-list.** Accept only URLs whose scheme is `https` and whose host is on a fixed list.
3. **If arbitrary URLs are a genuine feature** (a link-preview service), resolve the host and
   refuse private, loopback, link-local and metadata addresses, and don't follow redirects to
   them. This is easy to get wrong; prefer 1 or 2.

```python
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.partner.example", "files.partner.example"}

def safe_fetch(url: str):
    u = urlparse(url)
    if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
        raise ValueError("URL not allowed")
    return requests.get(url, timeout=5, allow_redirects=False)
```

Always set a timeout. Return a 400 error for refused URLs.

## Test that proves it

Request `http://169.254.169.254/latest/meta-data/` and `http://localhost:8000/admin` through the
endpoint and assert both are refused.
