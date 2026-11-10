# HTTPS / TLS certificate checks switched off (CWE-295)

**The problem:** `verify=False` (Python requests/httpx), `rejectUnauthorized: false` or
`NODE_TLS_REJECT_UNAUTHORIZED=0` (Node) turn off the check that the server really is who it
claims to be. Anyone on the network path can then read or change the traffic.

**The fix:** remove the switch. If it was added because a certificate isn't trusted, trust that
certificate properly instead.

```python
# Before
requests.get(url, verify=False)

# After: the default verifies certificates
requests.get(url, timeout=10)

# Internal or company certificate authority: point at its bundle
requests.get(url, verify="/etc/ssl/certs/company-ca.pem", timeout=10)
```

```js
// Before
https.request({ host, rejectUnauthorized: false });

// After: default verification, or supply the company CA
https.request({ host, ca: fs.readFileSync("company-ca.pem") });
```

Never set `NODE_TLS_REJECT_UNAUTHORIZED=0` anywhere, including CI. If a test server uses a
self-signed certificate, give the test client that certificate rather than disabling checks.

Ask the person which certificate authority their internal services use if the code was
calling an internal host; don't guess a path.
