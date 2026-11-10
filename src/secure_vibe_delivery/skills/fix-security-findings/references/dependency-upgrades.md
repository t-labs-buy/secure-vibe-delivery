# Vulnerable, unknown or brand-new libraries

## A library with a known vulnerability

The report names the package, the installed version and the version that fixes it ("fixed in").

1. **Upgrade to the lowest fixed version** in the same major version if one exists; it's the
   least likely to break things. Jumping major versions can change behaviour: read the
   library's changelog for breaking changes first.
2. **Update the place the version is pinned**, not just the installed copy:
   - Python: `requirements.txt` (`package==x.y.z`), or `pyproject.toml`, then reinstall
     (`pip install -r requirements.txt`, or `uv lock --upgrade-package package` for uv).
   - JavaScript: `npm install package@x.y.z` (updates `package.json` and the lock file).
3. **If the vulnerable package is a dependency of a dependency**, upgrade the parent that
   pulls it in (the report's "via" line shows the chain). As a last resort, npm `overrides`
   or a pip constraint can force the safe version.
4. **Run the tests**, then re-run the check.
5. **No fixed version yet?** Consider an alternative package, or file an exception
   (`exceptions.md`). Don't leave it silent.

## An unknown package ("does not exist on PyPI/npm")

This is the "slopsquatting" risk: AI tools sometimes suggest packages that don't exist, and
attackers register those names. Check the name for a typo of a real package. Remove it, or
replace it with the real, well-known package. If it truly comes from a private company
registry, say so to the person and confirm the registry is configured.

## A brand-new package (first published under 30 days ago)

Before trusting it, check: who maintains it, does it link to a real source repository, does
the repository match the published code, how many downloads does it have. If in doubt, choose
an established alternative and tell the person why.
