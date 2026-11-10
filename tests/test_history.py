import shlex

from secure_vibe_delivery.proc import command_line
from secure_vibe_delivery.report.commands import explain, history, tool_name


def test_each_check_command_gets_its_own_explanation():
    cases = {
        "/opt/homebrew/bin/snyk secrets test --json": "Snyk Secrets",
        "/opt/homebrew/bin/snyk code test --json": "Snyk Code",
        "snyk test --all-projects --json": "Snyk Open Source",
        "semgrep scan --config p/secrets --config svd-secrets.yml .": "Semgrep secrets",
        "semgrep scan --config auto --config ai-mistakes.yml .": "AI-mistake",
        "uvx --python 3.12 locust -f locustfile.py --headless -u 30": "Locust load test",
        "uvx --python 3.12 locust --version": "Locust version",
        ".venv/bin/python -m pytest -q --cov=.": "pytest",
        "npx --no-install jest --ci --coverage": "Jest",
    }
    for cmd, expected in cases.items():
        assert expected in explain(cmd)["title"], cmd


def test_unknown_command_still_explained():
    assert explain("frobnicate --x")["what"]


def test_tool_name_and_history_order():
    assert tool_name("/opt/homebrew/bin/semgrep scan .") == "semgrep"
    assert tool_name("/v/.venv/bin/python -m pytest -q") == "pytest"
    j = [{"t": 2, "kind": "command", "text": "snyk code test --json", "cwd": "."},
         {"t": 1, "kind": "decision", "text": "chose x"},
         {"t": 0, "kind": "command", "text": "semgrep --version", "cwd": "."}]
    h = history(j)
    assert [x["tool"] for x in h] == ["semgrep", "snyk"]


def test_logged_command_is_copy_pasteable_and_redacted():
    argv = ["/x/python", "-c", "import pytest; print('cov')", "--token=abc123"]
    line = command_line(argv)
    assert shlex.split(line)[:3] == argv[:3]
    assert "abc123" not in line
