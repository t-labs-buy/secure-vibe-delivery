import json
from pathlib import Path

from secure_vibe_delivery import gate, scoring
from secure_vibe_delivery.checks import iac
from secure_vibe_delivery.models import CheckResult, Finding, RunOptions, RunState, Status, SubCheck
from secure_vibe_delivery.report.commands import explain
from secure_vibe_delivery.report.render import render_report
from secure_vibe_delivery.skills import guide_for, read

OUT = Path(__file__).parent / "fixtures" / "tool_outputs"
APP = Path(__file__).parent / "fixtures" / "vulnapp"


def test_find_files_picks_infrastructure_and_skips_noise(tmp_path):
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
    (tmp_path / "deploy.yaml").write_text("apiVersion: v1\nkind: Pod\nmetadata: {name: x}\n")
    (tmp_path / "stack.yml").write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")
    (tmp_path / "azure.json").write_text('{"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"}')
    (tmp_path / "chart").mkdir()
    (tmp_path / "chart" / "dep.yaml").write_text("apiVersion: v1\nkind: Pod\nmetadata: {name: {{ .Values.name }}}\n")
    (tmp_path / "config.yaml").write_text("debug: true\n")
    (tmp_path / "package.json").write_text('{"name": "x"}')
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "k8s.yaml").write_text("apiVersion: v1\nkind: Pod\n")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "x.tf").write_text("")
    found = dict(iac.find_files(tmp_path))
    assert found == {"azure.json": "arm", "deploy.yaml": "kubernetes", "infra/main.tf": "terraform",
                     "stack.yml": "cloudformation"}


def test_no_infrastructure_in_the_test_app():
    assert iac.find_files(APP) == []


def test_argv_passes_files_by_name():
    a = iac.argv(["snyk"], ["main.tf", "k8s/deploy.yaml"])
    assert a[:5] == ["snyk", "iac", "test", "main.tf", "k8s/deploy.yaml"] and "--json" in a


def test_parse_recorded_output():
    err, findings, meta = iac.parse((OUT / "snyk_iac.json").read_text(), "", 1)
    assert err is None
    assert meta["files_scanned"] == 2 and meta["file_errors"]
    assert [f.severity for f in findings] == ["critical", "high", "medium"]  # ignored issue dropped, sorted
    s3 = next(f for f in findings if f.rule_id == "SNYK-CC-TF-127")
    assert s3.file == "main.tf" and s3.line == 3 and s3.category == "iac"
    assert "acl" in s3.fix_hint and s3.url.startswith("https://security.snyk.io")
    sg = next(f for f in findings if f.rule_id == "SNYK-CC-TF-1")
    assert "0.0.0.0/0" in sg.message and "cidr_blocks" in sg.fix_hint  # falls back to iacDescription


def test_parse_signed_out_stack_trace():
    trace = "FailedToGetIacOrgSettingsError: Failed to fetch IaC organization settings\n    at /snapshot/..."
    err, findings, _ = iac.parse(trace, "", 2)
    assert findings == [] and "organisation" in err
    err, _, _ = iac.parse("", " ERROR   Authentication error (SNYK-0005)", 2)
    assert "signed in" in err


def test_parse_no_valid_files_is_an_error():
    err, findings, _ = iac.parse(json.dumps({"ok": False, "error": "Could not find any valid IaC files", "code": 2114}), "", 3)
    assert err and findings == []


def _sec_with_iac(findings):
    return CheckResult(name="security", status=Status.FAIL, findings=findings,
                       data={"iac": {"files": ["main.tf"], "kinds": ["terraform"]}, "not_run": {}, "scanners": {}},
                       subchecks=[SubCheck(id="secrets", label="s", status=Status.PASS),
                                  SubCheck(id="iac", label="iac", status=Status.FAIL)])


def test_scoring_gate_and_report_include_infrastructure(tmp_path):
    _, findings, _ = iac.parse((OUT / "snyk_iac.json").read_text(), "", 1)
    sec = _sec_with_iac(findings)
    st = RunState(run_id="t", options=RunOptions(project_path=str(APP)), state="done", created_at=0)
    st.results = {"security": sec}
    results = gate.ensure_all(st)
    comps = {c["label"]: c for c in scoring.compute(results, False)["checks"]["security"]["components"]}
    assert comps["Safe infrastructure settings"]["score"] == 0.22  # 1 − critical 0.5 − high 0.25 − medium 0.03
    items = [i for i in gate.must_fix(results) if i["kind"] == "Infrastructure"]
    assert len(items) == 2  # critical + high; medium doesn't block
    assert items[0]["guide"] == "skill://fix-security-findings/references/infrastructure-settings.md"
    assert read(items[0]["guide"])["text"].startswith("# Risky infrastructure settings")
    st.verdict = gate.verdict(results)
    html, _ = render_report(st, results, tmp_path, tmp_path)
    text = html.read_text()
    assert "Infrastructure settings (3)" in text and "S3 bucket is publicly readable" in text


def test_no_infrastructure_means_no_iac_score_component():
    sec = CheckResult(name="security", status=Status.PASS,
                      subchecks=[SubCheck(id="secrets", label="s", status=Status.PASS)])
    st = RunState(run_id="t", options=RunOptions(project_path=str(APP)), state="done", created_at=0)
    st.results = {"security": sec}
    comps = scoring.compute(gate.ensure_all(st), False)["checks"]["security"]["components"]
    assert "Safe infrastructure settings" not in [c["label"] for c in comps]


def test_history_explains_iac_command():
    assert explain("/opt/homebrew/bin/snyk iac test main.tf --json")["title"].startswith("Snyk IaC")
    assert guide_for("Infrastructure").endswith("infrastructure-settings.md")
