from pathlib import Path

from secure_vibe_delivery.checks import functional, performance, semgrep, snyk
from secure_vibe_delivery.checks.security import merge_code_findings, merge_secrets

OUT = Path(__file__).parent / "fixtures" / "tool_outputs"
APP = Path(__file__).parent / "fixtures" / "vulnapp"


def test_snyk_open_source_dedupes_and_hints():
    err, libs, meta = snyk.parse_open_source((OUT / "snyk_test.json").read_text())
    assert err is None
    assert libs and meta["dependency_count"] > 0
    keys = {(f.rule_id, f.package, f.version) for f in libs}
    assert len(keys) == len(libs)  # one finding per vuln, not per dependency path
    crypto = [f for f in libs if f.package == "cryptography"]
    assert crypto and all(f.fix_hint for f in crypto)
    assert {f.severity for f in libs} <= {"critical", "high", "medium", "low"}


def test_snyk_open_source_error_is_reported():
    err, libs, _ = snyk.parse_open_source('{"ok": false, "error": "Something went wrong getting dependencies"}')
    assert err and not libs
    assert snyk.parse_open_source("")[0]


def test_snyk_code_splits_secrets_from_code_issues():
    err, code, secrets = snyk.parse_code((OUT / "snyk_code.json").read_text(), APP)
    assert err is None
    rules = {f.rule_id for f in code}
    assert {"python/CodeInjection", "python/Sqli", "python/SSLVerificationBypass"} <= rules
    assert secrets and all(s.scanner == "snyk-code" for s in secrets)
    assert all("*" in s.masked_value for s in secrets)


def test_snyk_secrets_unavailable_detected():
    out = (OUT / "snyk_secrets.json").read_text()
    assert "not supported" in snyk.secrets_unavailable(out, "", 2)
    assert snyk.secrets_unavailable("", "CLI help\nAvailable commands", 0)


def test_semgrep_code_parse_and_merge():
    err, sg, _ = semgrep.parse_code((OUT / "semgrep.json").read_text())
    assert err is None
    assert any(f.rule_id == "svd-eval-of-text" for f in sg)
    _, sn, _ = snyk.parse_code((OUT / "snyk_code.json").read_text(), APP)
    merged = merge_code_findings(sg + sn)
    lines = [(f.file, f.line) for f in merged]
    assert len(lines) == len(set(lines))
    eval_line = next(f for f in merged if "svd-eval-of-text" in " ".join(f.identifiers) or f.rule_id == "svd-eval-of-text")
    assert eval_line.severity == "high"


def test_semgrep_secrets_masked_and_merged():
    err, sec = semgrep.parse_secrets((OUT / "semgrep_secrets.json").read_text())
    assert err is None and len(sec) >= 3
    merged = merge_secrets(sec)
    assert len({(s.file, s.line) for s in merged}) == len(merged)
    kinds = {s.kind for s in merged}
    assert "AWS access key ID" in kinds and "GitHub token" in kinds
    assert all("AKIAIOSFODNN7EXAMPLE" not in s.masked_value for s in merged)


def test_scrub_raw_drops_source_lines():
    raw = semgrep.scrub_raw((OUT / "semgrep_secrets.json").read_text())
    assert "AKIAIOSFODNN7EXAMPLE" not in raw and "ghp_" not in raw


def test_junit_parse():
    counts, failures = functional.parse_junit(OUT / "junit.xml")
    assert counts["total"] == 4 and counts["failed"] == 1
    assert failures[0].title.endswith("test_discount_bug")


def test_locust_parse():
    data = performance.parse_results(OUT / "locust")
    agg = data["aggregate"]
    assert agg["requests"] > 0 and agg["p95"] > 0
    assert any(e["name"] == "/slow" for e in data["endpoints"])
    assert data["series"] and data["series"][0]["t"] == 0


def test_parse_duration():
    assert performance.parse_duration("15m") == 900
    assert performance.parse_duration("1h2m3s") == 3723
    assert performance.parse_duration("45s") == 45


def test_coveragerc_is_anchored(tmp_path):
    rc = functional.coveragerc(tmp_path / "tests" / "proj")
    assert "*/tests/*" not in rc
    assert f"{tmp_path}/tests/proj/tests/*" in rc


def test_semgrep_secrets_logged_out_masks_from_source():
    # Logged out, Semgrep replaces source lines with "requires login" and drops metavariables
    raw = (OUT / "semgrep_secrets_nologin.json").read_text()
    assert "requires login" in raw
    err, sec = semgrep.parse_secrets(raw, APP)
    assert err is None and len(sec) == 5
    masked = {s.line: s.masked_value for s in merge_secrets(sec)}
    assert masked[11] == "AKIA********MPLE"
    assert masked[13].startswith("ghp_")
    assert not any(v.startswith("re*") for v in masked.values())


def test_secrets_argv_bundled_only_needs_no_registry():
    argv = semgrep.secrets_argv(["semgrep"], registry=False)
    assert "p/secrets" not in argv and any(a.endswith("svd-secrets.yml") for a in argv)
