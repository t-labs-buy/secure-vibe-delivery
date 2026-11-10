"""Secret masking. Raw secret values must never leave this module."""
from __future__ import annotations

import re
from pathlib import Path

_QUOTED = re.compile(r"""['"`]([^'"`]{4,})['"`]""")


def mask(value: str) -> str:
    value = value.strip()
    if not value:
        return "****"
    if len(value) >= 16:
        return f"{value[:4]}{'*' * 8}{value[-4:]}"
    if len(value) >= 8:
        return f"{value[:2]}{'*' * 8}"
    return "*" * 8


def extract_secret(matched: str) -> str:
    """Pull the likely secret out of a matched span (prefers the last quoted literal)."""
    quoted = _QUOTED.findall(matched)
    if quoted:
        return quoted[-1]
    if "=" in matched or ":" in matched:
        return re.split(r"[:=]", matched, maxsplit=1)[-1].strip().strip("'\"`;,")
    return matched.strip()


def read_span(root: Path, rel: str, line: int, col_start: int = 0, col_end: int = 0) -> str:
    try:
        lines = (root / rel).read_text(errors="replace").splitlines()
        text = lines[line - 1]
    except (OSError, IndexError):
        return ""
    if col_start and col_end and col_end > col_start:
        return text[col_start - 1: col_end - 1]
    return text


def masked_from_source(root: Path, rel: str, line: int, col_start: int = 0, col_end: int = 0) -> str:
    """Mask the secret on a source line. Scanners' column spans sometimes cover the variable name
    rather than the value, so look at the whole line and prefer its quoted literal."""
    full = read_span(root, rel, line)
    if not full:
        return "****"
    if _QUOTED.search(full):
        return mask(extract_secret(full))
    span = read_span(root, rel, line, col_start, col_end) or full
    return mask(extract_secret(span))


def scrub(text: str, secrets: list[str]) -> str:
    for s in secrets:
        if s and len(s) >= 4:
            text = text.replace(s, mask(s))
    return text
