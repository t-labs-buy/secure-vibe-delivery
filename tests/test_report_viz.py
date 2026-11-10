import json
import re

from secure_vibe_delivery import gate
from secure_vibe_delivery.models import CheckResult, Finding, RunOptions, RunState, Status, SubCheck
from secure_vibe_delivery.report.render import render_report


def _render(tmp_path):
    code = [Finding(tool="semgrep", category="code", severity="high", title=f"SQL built from input {i}",
                    file="app.py", line=30 + i) for i in range(14)]
    libs = [Finding(tool="snyk-open-source", category="library", severity="critical", title="RCE",
                    package="requests", version="2.19.0")]
    sec = CheckResult(name="security", status=Status.FAIL, findings=code + libs, data={"not_run": {}},
                      subchecks=[SubCheck(id="code", label="c", status=Status.FAIL),
                                 SubCheck(id="libraries", label="l", status=Status.FAIL)])
    st = RunState(run_id="t", options=RunOptions(project_path=str(tmp_path)), state="done", created_at=0)
    st.results = {"security": sec}
    results = gate.ensure_all(st)
    st.verdict = gate.verdict(results)
    html, _ = render_report(st, results, tmp_path, tmp_path)
    return html.read_text()


def test_severity_chart_carries_exact_locations(tmp_path):
    text = _render(tmp_path)
    data = json.loads(re.search(r'<script type="application/json" id="reportData">(.*?)</script>', text, re.S).group(1))
    code_row, lib_row = data["severity"][0], data["severity"][1]
    high = code_row["where"]["high"]
    assert high["items"][0] == {"where": "app.py:30", "title": "SQL built from input 0"}
    assert len(high["items"]) == 12 and high["more"] == 2  # capped, the rest counted
    assert lib_row["where"]["critical"]["items"][0]["where"] == "requests@2.19.0"


def test_score_breakdown_is_a_chart_with_a_table_view(tmp_path):
    text = _render(tmp_path)
    assert 'class="sm-scale"' in text and text.count('class="sm-group"') == 3
    assert "data-viz-tip=" in text and "Show as a table" in text
    assert 'id="code-version"' in text and text.count('id="code-version"') == 1
