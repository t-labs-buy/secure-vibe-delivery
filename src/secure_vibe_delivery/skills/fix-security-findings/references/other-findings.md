# Findings without a specific guide

1. **Read the finding in full**: its title, message, rule ID, CWE and the link (Snyk findings
   link to Snyk's vulnerability page; Semgrep findings to the rule).
2. **Understand the data flow**: where does the flagged value come from (user input, a file,
   another service), and where does it end up?
3. **Apply the general pattern for its CWE**: validate input against what's allowed (allow-lists
   beat block-lists), encode output for where it's going (HTML, SQL, shell, URL), use the
   framework's safe API instead of building strings, and fail closed.
4. **Common cases:**
   - Command injection (CWE-78): use `subprocess.run([...], shell=False)` with an argument
     list; never pass user input through a shell.
   - Path traversal (CWE-22): resolve the path and check it stays inside the intended folder;
     prefer IDs over file names from users.
   - Cross-site scripting (CWE-79): rely on the template engine's auto-escaping; never mark
     user content as safe HTML.
   - Weak hashing for passwords (CWE-916): use `argon2`, `bcrypt` or `scrypt`, not MD5 or SHA-1.
   - Debug mode on (CWE-489): turn it off outside local development.
5. **If you're not sure the finding is real**, explain why to the person and let them decide;
   a false positive is recorded as an exception, never silently ignored.
