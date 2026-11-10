import hashlib
import re

from secure_vibe_delivery import gate, skills
from secure_vibe_delivery.models import CheckResult, Finding, SecretFinding, Status

EXPECTED = {"fix-security-findings", "rotate-exposed-secrets", "write-wrong-case-tests",
            "write-locustfiles", "write-svd-rules"}


def test_all_five_skills_with_valid_frontmatter():
    cat = skills.catalog()
    assert set(cat) == EXPECTED
    for name, s in cat.items():
        fm = s["frontmatter"]
        assert fm["name"] == name, name                       # Agent Skills: name matches folder
        assert 40 < len(fm["description"]) <= 1024, name
        words = len(s["files"]["SKILL.md"]["text"].split())
        assert words < 1500, (name, words)                    # well under the ~5,000-token guidance


def test_every_referenced_file_exists():
    for name, s in skills.catalog().items():
        for ref in set(re.findall(r"`(references/[\w.-]+\.md)`", s["files"]["SKILL.md"]["text"])):
            assert ref in s["files"], (name, ref)


def test_manifest_digests_match_content():
    for s in skills.catalog().values():
        for f in s["files"].values():
            assert f["digest"] == "sha256:" + hashlib.sha256(f["text"].encode()).hexdigest()
            assert f["uri"].startswith("skill://")


def test_read_by_uri_name_and_rejects_escape():
    assert skills.read("skill://fix-security-findings/references/sql-injection.md")["text"].startswith("# SQL injection")
    assert skills.read("rotate-exposed-secrets")["uri"] == "skill://rotate-exposed-secrets/SKILL.md"
    for bad in ["skill://fix-security-findings/../../server.py", "../../server.py", "skill://nope/SKILL.md",
                "skill://fix-security-findings/references/../SKILL.md"]:
        assert skills.read(bad) is None, bad


def test_no_scripts_in_skills():
    for s in skills.catalog().values():
        assert all(p.endswith(".md") for p in s["files"])


def test_guides_point_at_real_files():
    for kind, cwe in [("Exposed secret", None), ("Code issue", ["CWE-89"]), ("Code issue", ["CWE-95"]),
                      ("Code issue", ["CWE-295"]), ("Code issue", ["CWE-918"]), ("Code issue", ["CWE-79"]),
                      ("Library", None), ("Package", None), ("Failing test", None), ("Coverage", None),
                      ("Performance", None), ("Endpoint", None)]:
        g = skills.guide_for(kind, cwe)
        assert g and skills.read(g), (kind, cwe, g)
    assert skills.guide_for("Code issue", ["CWE-89"]).endswith("sql-injection.md")
    assert skills.guide_for("Didn't run") is None


def test_must_fix_items_carry_guides():
    sec = CheckResult(name="security", status=Status.FAIL,
                      secrets=[SecretFinding(scanner="x", kind="AWS key", file="a.py", line=1, masked_value="AKIA****")],
                      findings=[Finding(tool="snyk-code", category="code", severity="high", title="SQL Injection",
                                        file="a.py", line=3, cwe=["CWE-89"])])
    items = gate.must_fix({"security": sec})
    by_kind = {i["kind"]: i for i in items}
    assert by_kind["Exposed secret"]["guide"] == "skill://rotate-exposed-secrets/SKILL.md"
    assert by_kind["Code issue"]["guide"].endswith("/sql-injection.md")
