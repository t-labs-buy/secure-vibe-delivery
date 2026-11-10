import json
from pathlib import Path

from secure_vibe_delivery import gate
from secure_vibe_delivery.checks import locustgen, semgrep
from secure_vibe_delivery.checks.secrets_util import mask, masked_from_source
from secure_vibe_delivery.models import CheckResult, RunOptions, RunState, Status, SubCheck
from secure_vibe_delivery.report.render import render_report

OUT = Path(__file__).parent / "fixtures" / "tool_outputs"
APP = Path(__file__).parent / "fixtures" / "vulnapp"
RAW_SECRETS = ["AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "SuperSecret123!"]


def _res(name, *subs):
    st = Status.FAIL if any(s[1] == Status.FAIL for s in subs) else Status.PASS
    return CheckResult(name=name, status=st, subchecks=[SubCheck(id=i, label=i, status=s) for i, s in subs])


def _state(results, mode="gate"):
    st = RunState(run_id="t", options=RunOptions(project_path=str(APP), mode=mode), state="done", created_at=0)
    st.results = results
    return st


def test_not_run_is_a_failure():
    st = _state({"security": _res("security", ("secrets", Status.PASS))})
    results = gate.ensure_all(st)  # functional + performance weren't requested
    assert results["functional"].status == Status.NOT_RUN
    assert gate.verdict(results) == "NO-GO"


def test_manual_items_do_not_block_and_quick_is_provisional():
    results = {
        "security": _res("security", ("secrets", Status.PASS), ("own-data", Status.WARN), ("review", Status.WARN)),
        "functional": _res("functional", ("tests", Status.PASS), ("wrong-case", Status.WARN)),
        "performance": _res("performance", ("load", Status.WARN), ("failures", Status.PASS)),
    }
    assert gate.verdict(results) == "PROVISIONAL"
    results["performance"] = _res("performance", ("load", Status.PASS), ("failures", Status.PASS))
    assert gate.verdict(results) == "GO"


def test_mask():
    assert mask("AKIAIOSFODNN7EXAMPLE") == "AKIA********MPLE"
    assert "Secret" not in mask("SuperSecret123!")
    assert mask("abc") == "********"
    # Snyk's span covers the variable name on this line; the value must still be what's masked
    line = next(i for i, l in enumerate((APP / "app.py").read_text().splitlines(), 1) if "DB_PASSWORD" in l)
    assert masked_from_source(APP, "app.py", line, 1, 12) == mask("SuperSecret123!")


def test_report_never_contains_raw_secrets(tmp_path):
    _, secrets = semgrep.parse_secrets((OUT / "semgrep_secrets.json").read_text())
    sec = CheckResult(name="security", status=Status.FAIL, secrets=secrets,
                      subchecks=[SubCheck(id="secrets", label="No keys", status=Status.FAIL)])
    st = _state({"security": sec})
    results = gate.ensure_all(st)
    st.verdict = gate.verdict(results)
    html, summary = render_report(st, results, tmp_path, tmp_path)
    text = html.read_text() + summary.read_text()
    for raw in RAW_SECRETS + ["ghp_u8jz"]:
        assert raw not in text
    data = json.loads(summary.read_text())
    assert data["verdict"] == "NO-GO"
    assert data["must_fix"][0]["kind"] == "Exposed secret"


def test_locustgen_from_openapi():
    spec = {"paths": {"/products": {"get": {}}, "/products/{id}": {"get": {}}, "/login": {"post": {}},
                      "/search": {"get": {"parameters": [{"in": "query", "name": "q", "required": True}]}},
                      "/docs": {"get": {}}}}
    gets, todos = locustgen.from_openapi(spec)
    assert gets == ["/products"]
    assert "GET /products/{id}" in todos and "POST /login" in todos and "GET /search" in todos


def test_locustgen_from_routes_compiles():
    src, how = locustgen.generate(APP, None, None)
    assert "routes" in how
    assert "self.client.get('/products')" in src and "/calc" in src
    compile(src, "locustfile.py", "exec")

