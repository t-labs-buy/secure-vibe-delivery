"""Skills served over MCP: the know-how for fixing what the report finds.

Each skill is a folder with a SKILL.md (frontmatter name + description, then instructions) and
optional reference files, following the Agent Skills format. Following the Skills over MCP
convention (SEP-2640), every file is served as an MCP resource at skill://<skill>/<path>, and the
listing carries a manifest with each file's size and SHA-256 digest so a host can verify what it
reads. The skills are instructions only: no scripts.

Assistants should read skills progressively: the list (name + description) first, SKILL.md only
when a task needs that skill, and a reference file only when SKILL.md points to it.
"""
from __future__ import annotations

import hashlib
from functools import lru_cache
from importlib import resources
from typing import Optional

import yaml

SCHEME = "skill://"


def _root():
    return resources.files("secure_vibe_delivery").joinpath("skills")


def _frontmatter(text: str) -> dict:
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    return yaml.safe_load(text[3:end]) or {} if end > 0 else {}


@lru_cache(maxsize=1)
def catalog() -> dict:
    """{skill name: {"frontmatter", "uri", "files": {path: {"uri", "size", "digest", "text"}}}}"""
    out: dict = {}
    root = _root()
    for folder in sorted((p for p in root.iterdir() if p.is_dir()), key=lambda p: p.name):
        skill_md = folder.joinpath("SKILL.md")
        if not skill_md.is_file():
            continue
        files = {}

        def walk(node, prefix=""):
            for child in sorted(node.iterdir(), key=lambda p: p.name):
                rel = f"{prefix}{child.name}"
                if child.is_dir():
                    walk(child, rel + "/")
                elif child.name.endswith(".md"):
                    data = child.read_bytes()
                    files[rel] = {"uri": f"{SCHEME}{folder.name}/{rel}", "size": len(data),
                                  "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                                  "text": data.decode("utf-8")}
        walk(folder)
        out[folder.name] = {"frontmatter": _frontmatter(files["SKILL.md"]["text"]),
                            "uri": f"{SCHEME}{folder.name}/SKILL.md", "files": files}
    return out


def listing() -> list[dict]:
    """What a skills/list answer carries: frontmatter plus the file manifest (no file contents)."""
    return [{"name": name, "uri": s["uri"], "frontmatter": s["frontmatter"],
             "resources": [{"uri": f["uri"], "size": f["size"], "digest": f["digest"]}
                           for f in s["files"].values()]}
            for name, s in catalog().items()]


def read(uri_or_path: str) -> Optional[dict]:
    """Read one skill file by skill://name/path, or name/path. Only files in the manifest can be
    read, so a path like ../../secret can never escape the skills folder."""
    ref = uri_or_path.strip()
    if ref.startswith(SCHEME):
        ref = ref[len(SCHEME):]
    name, _, path = ref.partition("/")
    skill = catalog().get(name)
    if not skill:
        return None
    f = skill["files"].get(path or "SKILL.md")
    if not f:
        return None
    return {"uri": f["uri"], "digest": f["digest"], "size": f["size"], "text": f["text"],
            "source": "secure-vibe-delivery"}


# --- which guide fits which must-fix item -----------------------------------------------

_CWE_GUIDES = {
    "CWE-89": "fix-security-findings/references/sql-injection.md",
    "CWE-94": "fix-security-findings/references/code-injection.md",
    "CWE-95": "fix-security-findings/references/code-injection.md",
    "CWE-295": "fix-security-findings/references/tls-verification.md",
    "CWE-918": "fix-security-findings/references/ssrf.md",
}


def guide_for(kind: str, cwe: Optional[list[str]] = None, check: str = "") -> Optional[str]:
    """The skill file that explains how to fix a must-fix item, as a skill:// URI."""
    if kind == "Exposed secret":
        path = "rotate-exposed-secrets/SKILL.md"
    elif kind == "Code issue":
        path = next((_CWE_GUIDES[c] for c in (cwe or []) if c in _CWE_GUIDES),
                    "fix-security-findings/references/other-findings.md")
    elif kind == "Infrastructure":
        path = "fix-security-findings/references/infrastructure-settings.md"
    elif kind in ("Library", "Package"):
        path = "fix-security-findings/references/dependency-upgrades.md"
    elif kind in ("Failing test", "Coverage"):
        path = ("write-wrong-case-tests/references/coverage.md" if kind == "Coverage"
                else "write-wrong-case-tests/SKILL.md")
    elif kind in ("Performance", "Endpoint"):
        path = "write-locustfiles/references/reading-results.md"
    elif kind == "Didn't run":
        return None
    else:
        return None
    return SCHEME + path


def register(mcp) -> None:
    """Serve every skill file as an MCP resource at skill://<skill>/<path>."""
    for name, s in catalog().items():
        desc = s["frontmatter"].get("description", "")
        for rel, f in s["files"].items():
            def make(text: str):
                return lambda: text
            mcp.resource(f["uri"], name=f"{name}/{rel}",
                         description=(desc if rel == "SKILL.md" else f"Reference for the {name} skill"),
                         mime_type="text/markdown")(make(f["text"]))
