"""Overview summaries: an automatic one built from the results, and an AI-written one supplied by the
person's coding assistant through svd_write_summary (the assistant is the LLM; this server has none)."""
from __future__ import annotations

import re
from typing import Optional

from .models import CheckResult, Status

MANUAL = {"own-data", "review"}
LIMITS = {"overall": 1500, "item": 400, "items": 8}


def automatic(results: dict[str, CheckResult], verdict: str, score: dict, must_fix: list[dict]) -> dict:
    went_well, attention = [], []
    total = passed = 0
    for name, r in results.items():
        for s in r.subchecks:
            if s.id in MANUAL:
                continue
            total += 1
            line = f"{name.title()}: {s.label} ({s.detail})" if s.detail else f"{name.title()}: {s.label}"
            if s.status == Status.PASS:
                passed += 1
                went_well.append(line)
            elif s.status in (Status.FAIL, Status.NOT_RUN):
                attention.append(("Didn't run: " if s.status == Status.NOT_RUN else "") + line)
            else:
                attention.append("Warning: " + line)
    fix_first = [f"{i['kind']}: {i['title']}" + (f" ({i['where']})" if i.get("where") else "")
                 for i in must_fix[:3]]
    overall = (f"Verdict {verdict}, secure-health score {score['score']}/100 (grade {score['grade']}, "
               f"{score['grade_word'].lower()}). {passed} of {total} automated checks passed.")
    if must_fix:
        overall += f" Start with: {fix_first[0]}."
    return {"source": "automatic", "overall": overall, "went_well": went_well[:LIMITS["items"]],
            "needs_attention": attention[:LIMITS["items"]], "fix_first": fix_first}


def _clean(text: str, limit: int) -> str:
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    return text[:limit]


def ai(overall: str, went_well: list[str], needs_attention: list[str], fix_first: list[str],
       masked_secrets: Optional[list[str]] = None) -> dict:
    """Validate and trim what the assistant wrote. HTML is escaped when rendered."""
    def items(xs):
        return [c for c in (_clean(x, LIMITS["item"]) for x in (xs or [])[:LIMITS["items"]]) if c]
    out = {"source": "ai", "overall": _clean(overall, LIMITS["overall"]), "went_well": items(went_well),
           "needs_attention": items(needs_attention), "fix_first": items(fix_first)}
    if not out["overall"]:
        raise ValueError("overall is required")
    return out
