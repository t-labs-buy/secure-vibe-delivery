"""Project settings (.svd.toml), detection of several suites, venvs and locustfiles, and the
pytest safety guard."""
import json
import textwrap
from pathlib import Path

import pytest

from secure_vibe_delivery import config
from secure_vibe_delivery.checks import functional
from secure_vibe_delivery.detect import detect, find_venvs


def write(root: Path, rel: str, text: str = "") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(text))
    return p


def make_venv(root: Path, rel: str) -> None:
    write(root, f"{rel}/pyvenv.cfg", "home = /usr/bin\n")
    write(root, f"{rel}/lib/python3.12/site-packages/pkg/keys.py", 'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n')


# --- settings file ---------------------------------------------------------------------------------

def test_no_settings_file_gives_defaults(tmp_path):
    cfg = config.load(tmp_path)
    assert cfg.path is None and cfg.suites == [] and not cfg.allow_unsafe_pytest


def test_settings_file_is_read(tmp_path):
    write(tmp_path, ".svd.toml", """
        [functional]
        allow_unsafe_pytest = true
        [[functional.suite]]
        name = "backend"
        command = "scripts/run.sh 70"
        junit = "out/junit.xml"
        coverage = "out/coverage.json"
        timeout = 60
        [performance]
        locustfile = "loadtest/locustfile.py"
        env_file = ".env"
        env = { LOADTEST_LLM = "0" }
        [security]
        exclude = ["generated"]
    """)
    cfg = config.load(tmp_path)
    assert cfg.path.name == ".svd.toml"
    assert [(s.name, s.command, s.junit, s.coverage, s.timeout) for s in cfg.suites] == [
        ("backend", "scripts/run.sh 70", "out/junit.xml", "out/coverage.json", 60)]
    assert cfg.allow_unsafe_pytest
    assert cfg.locustfile == "loadtest/locustfile.py" and cfg.locust_env == {"LOADTEST_LLM": "0"}
    assert cfg.exclude == ["generated"]


def test_a_broken_settings_file_says_what_to_fix(tmp_path):
    write(tmp_path, ".svd.toml", "[[functional.suite]]\nname = 'x'\n")
    with pytest.raises(config.ConfigError, match="needs a command"):
        config.load(tmp_path)
    write(tmp_path, ".svd.toml", "[functional\n")
    with pytest.raises(config.ConfigError, match="can't be read"):
        config.load(tmp_path)


def test_locust_env_reads_the_env_file_and_settings_win(tmp_path):
    write(tmp_path, ".env", """
        # comment
        export LOADTEST_PASSWORD='a secret'
        DATABASE_URL="postgresql://u:p@localhost/db"
        LOADTEST_LLM=1  # turned on here
        not a line
    """)
    write(tmp_path, ".svd.toml", '[performance]\nenv_file = ".env"\nenv = { LOADTEST_LLM = "0" }\n')
    env, names = config.locust_env(tmp_path, config.load(tmp_path))
    assert env["LOADTEST_PASSWORD"] == "a secret"
    assert env["DATABASE_URL"] == "postgresql://u:p@localhost/db"
    assert env["LOADTEST_LLM"] == "0"  # the settings file's value wins over the env file
    assert names == sorted(env)


def test_a_missing_env_file_is_an_error(tmp_path):
    write(tmp_path, ".svd.toml", '[performance]\nenv_file = ".env.test"\n')
    with pytest.raises(config.ConfigError, match="not found"):
        config.locust_env(tmp_path, config.load(tmp_path))


# --- detection -------------------------------------------------------------------------------------

def test_venvs_are_found_by_pyvenv_cfg_whatever_their_name(tmp_path):
    make_venv(tmp_path, "hindsight-venv")
    make_venv(tmp_path, ".venv-loadtest")
    make_venv(tmp_path, "tools/lint/env")
    write(tmp_path, "app/main.py", "x = 1\n")
    assert find_venvs(tmp_path) == [".venv-loadtest", "hindsight-venv", "tools/lint/env"]


def test_a_locustfile_in_a_subfolder_is_found(tmp_path):
    write(tmp_path, "app.py", "")
    write(tmp_path, "loadtest/locustfile.py", "")
    assert detect(tmp_path).locustfile == tmp_path / "loadtest" / "locustfile.py"
    write(tmp_path, "locustfile.py", "")
    assert detect(tmp_path).locustfile == tmp_path / "locustfile.py"  # the root one wins


def test_a_locustfile_inside_a_venv_is_ignored(tmp_path):
    write(tmp_path, "app.py", "")
    make_venv(tmp_path, "myenv")
    write(tmp_path, "myenv/locustfile.py", "")
    assert detect(tmp_path).locustfile is None


def test_python_backend_and_jest_frontend_are_both_suites(tmp_path):
    write(tmp_path, "requirements.txt", "flask\n")
    write(tmp_path, "tests/test_app.py", "def test_x():\n    assert True\n")
    write(tmp_path, "frontend/package.json", json.dumps({"devDependencies": {"jest": "^30"}}))
    write(tmp_path, "frontend/src/app.test.js", "test('x', () => {});\n")
    info = detect(tmp_path)
    assert info.test_runners == ["pytest", "jest"]
    assert info.jest_dirs == [tmp_path / "frontend"]
    assert info.test_runner == "pytest" and info.has_tests


def test_jest_listed_without_any_tests_is_not_a_suite(tmp_path):
    write(tmp_path, "requirements.txt", "")
    write(tmp_path, "tests/test_app.py", "")
    write(tmp_path, "package.json", json.dumps({"devDependencies": {"jest": "^30"}}))
    assert detect(tmp_path).test_runners == ["pytest"]


# --- pytest safety guard ---------------------------------------------------------------------------

NOSE_STYLE = """
    import psycopg
    TEST_DATABASE = "app_test"

    def setup():
        # creates a throwaway database and points DATABASE_URL at it
        pass

    def teardown():
        pass

    def test_clear():
        psycopg.connect().execute("TRUNCATE TABLE documents CASCADE")
"""


def test_nose_style_hooks_are_found_and_wiping_files_come_first(tmp_path):
    write(tmp_path, "backend/tests/test_store.py", NOSE_STYLE)
    write(tmp_path, "backend/tests/test_class.py", """
        class TestThing:
            def setup(self):
                pass
            def test_a(self):
                pass
    """)
    write(tmp_path, "backend/tests/test_fine.py", """
        def setup_module():
            pass
        def test_a():
            pass
    """)
    hits = functional.unsafe_pytest_files(tmp_path)
    assert [h["file"] for h in hits] == ["backend/tests/test_store.py", "backend/tests/test_class.py"]
    assert hits[0]["hooks"] == ["setup", "teardown"] and hits[0]["destructive"]
    assert hits[1]["hooks"] == ["TestThing.setup"] and not hits[1]["destructive"]
    reason = functional.unsafe_reason(hits)
    assert "pytest 8" in reason and "real database" in reason and "[[functional.suite]]" in reason


def test_a_helper_named_setup_in_a_non_test_file_is_not_flagged(tmp_path):
    write(tmp_path, "app/setup_helpers.py", "def setup():\n    pass\n")
    assert functional.unsafe_pytest_files(tmp_path) == []


async def test_pytest_is_refused_for_nose_style_tests(tmp_path):
    from secure_vibe_delivery.checks.context import CheckContext
    from secure_vibe_delivery.models import RunOptions, Status
    write(tmp_path, "requirements.txt", "")
    write(tmp_path, "tests/test_store.py", NOSE_STYLE)
    info = detect(tmp_path)
    ctx = CheckContext(root=tmp_path, run_dir=tmp_path / ".svd", info=info,
                       options=RunOptions(project_path=str(tmp_path)))
    (tmp_path / ".svd").mkdir()
    res = await functional.run(ctx)
    assert res.status == Status.NOT_RUN
    assert "to protect your data" in res.reason_not_run
    assert not res.commands  # pytest never started
