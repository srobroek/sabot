"""assert-executed.sh proves a tool is the real tool and that it did positive work.

A host hook rewrote `cargo` to `rtk` inside the container and produced rc=0 with 0 tests
selected across 11 targets: exit zero, no error, and a report byte-identical to a clean
pass. rc=0 is not evidence anything ran.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

SKILL = Path(__file__).resolve().parents[1] / ".apm" / "skills" / "sabotage"
SCRIPT = SKILL / "scripts" / "assert-executed.sh"
BODY = SCRIPT.read_text()

EXIT_USAGE = 2
EXIT_IDENTITY = 6
EXIT_CMD = 7
EXIT_NO_WORK = 8

REAL_TEST_OUTPUT = (
    "running 12 tests\n"
    "test parse::rejects_overflow ... ok\n"
    "test parse::accepts_bounds ... ok\n"
    "test result: ok. 12 passed; 0 failed\n"
)


def stub(bin_dir: Path, name: str, body: str) -> Path:
    bin_dir.mkdir(parents=True, exist_ok=True)
    p = bin_dir / name
    p.write_text(f"#!/bin/sh\n{body}\n")
    p.chmod(0o755)
    return p


def run(*args: str, bin_dir: Path | None = None):
    env = dict(os.environ)
    if bin_dir is not None:
        env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    return subprocess.run(
        ["sh", str(SCRIPT), *args], capture_output=True, text=True, env=env
    )


# --- usage errors must never exit 0 ----------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        (),                                     # no command at all
        ("--tool", "cargo"),                    # a tool but nothing to run
        ("--bogus-flag",),
        ("--tool",),                            # flag with no value
        ("--min-units", "many", "--", "true"),  # not a number
        ("--parse", "/nonexistent/log"),
        ("--tool", "cargo", "--check-only", "--", "true"),
    ],
    ids=["no-command", "tool-only", "unknown-flag", "missing-value", "min-units-nan",
         "missing-parse-file", "check-only-with-command"],
)
def test_a_usage_error_exits_2_and_never_0(args):
    # A wrapper that exits 0 on its own usage error, having run nothing, is the fail-open
    # this whole script guards against.
    p = run(*args)
    assert p.returncode == EXIT_USAGE, p.stderr


def test_an_illegal_tool_name_is_rejected_rather_than_executed():
    p = run("--tool", "cargo; rm -rf /", "--check-only")
    assert p.returncode == EXIT_USAGE


# --- identity --------------------------------------------------------------


def test_a_tool_reporting_another_name_fails_identity(tmp_path):
    # The measured incident: `cargo` resolved fine and answered as `rtk`.
    bin_dir = tmp_path / "bin"
    stub(bin_dir, "cargo", 'echo "rtk 0.3.1"')
    p = run("--tool", "cargo", "--check-only", bin_dir=bin_dir)
    assert p.returncode == EXIT_IDENTITY
    assert "IDENTITY FAIL" in p.stderr
    assert "INVALID" in p.stderr


def test_a_tool_that_does_not_resolve_fails_identity(tmp_path):
    p = run("--tool", "definitelynotinstalled", "--check-only", bin_dir=tmp_path / "bin")
    assert p.returncode == EXIT_IDENTITY
    assert "does not resolve inside the container" in p.stderr


def test_a_tool_answering_only_the_bare_version_subcommand_passes(tmp_path):
    # `go --version` exits 2, so `<tool> version` has to be tried too.
    bin_dir = tmp_path / "bin"
    stub(bin_dir, "go", '[ "$1" = version ] && echo "go version go1.22.1" || exit 2')
    p = run("--tool", "go", "--check-only", bin_dir=bin_dir)
    assert p.returncode == 0
    assert "IDENTITY ok" in p.stderr


def test_a_tool_answering_neither_version_form_fails_identity(tmp_path):
    bin_dir = tmp_path / "bin"
    stub(bin_dir, "cargo", "exit 1")
    p = run("--tool", "cargo", "--check-only", bin_dir=bin_dir)
    assert p.returncode == EXIT_IDENTITY


# --- positive work ---------------------------------------------------------


def test_rc_zero_with_zero_tests_selected_is_not_executed(tmp_path):
    log = tmp_path / "out.log"
    p = run("--out", str(log), "--", "sh", "-c",
            "printf 'running 0 tests\\ntest result: ok. 0 passed\\n'")
    assert p.returncode == EXIT_NO_WORK
    assert "NOT EXECUTED" in p.stderr
    assert "rc=0 is NOT evidence" in p.stderr


def test_silent_success_is_not_executed(tmp_path):
    # A command that printed nothing and exited 0 is the shape of a tool that never ran.
    p = run("--out", str(tmp_path / "out.log"), "--", "true")
    assert p.returncode == EXIT_NO_WORK


def test_a_real_test_run_exits_0(tmp_path):
    p = run("--out", str(tmp_path / "out.log"), "--", "sh", "-c",
            f"printf '{REAL_TEST_OUTPUT}'".replace("\n", "\\n"))
    assert p.returncode == 0, p.stderr
    assert "EXECUTED units=12" in p.stderr


def test_min_units_is_enforced_above_the_default(tmp_path):
    p = run("--min-units", "50", "--out", str(tmp_path / "out.log"), "--", "sh", "-c",
            f"printf '{REAL_TEST_OUTPUT}'".replace("\n", "\\n"))
    assert p.returncode == EXIT_NO_WORK


def test_work_followed_by_failure_is_the_commands_own_status(tmp_path):
    # Distinct from "no work": this run has to be classified before it is called a defect.
    script = "printf 'running 3 tests\\ntest a::b ... FAILED\\n'; exit 101"
    p = run("--out", str(tmp_path / "out.log"), "--", "sh", "-c", script)
    assert p.returncode == EXIT_CMD
    assert "classify-failure.py" in p.stderr


def test_the_command_output_reaches_stdout(tmp_path):
    p = run("--out", str(tmp_path / "out.log"), "--", "sh", "-c",
            f"printf '{REAL_TEST_OUTPUT}'".replace("\n", "\\n"))
    assert "test parse::rejects_overflow" in p.stdout


# --- parse mode ------------------------------------------------------------


def test_parse_mode_accepts_a_captured_log(tmp_path):
    log = tmp_path / "captured.log"
    log.write_text(REAL_TEST_OUTPUT)
    p = run("--parse", str(log))
    assert p.returncode == 0


def test_parse_mode_rejects_a_captured_log_that_selected_nothing(tmp_path):
    log = tmp_path / "captured.log"
    log.write_text("running 0 tests\n")
    p = run("--parse", str(log))
    assert p.returncode == EXIT_NO_WORK


def test_parse_mode_counts_go_and_pytest_output(tmp_path):
    for text in ("=== RUN   TestParse\n--- PASS: TestParse (0.01s)\n",
                 "collected 7 items\ntests/test_x.py::test_y PASSED\n"):
        log = tmp_path / "captured.log"
        log.write_text(text)
        assert run("--parse", str(log)).returncode == 0, text


# --- counting finished tests, once each --------------------------------------


PYTEST_DEFAULT = (
    "============================= test session starts ==============================\n"
    "platform linux -- Python 3.12.3, pytest-8.3.2, pluggy-1.5.0\n"
    "rootdir: /target\n"
    "collected 12 items\n"
    "\n"
    "tests/test_parse.py ............                                         [100%]\n"
    "\n"
    "============================== 12 passed in 0.05s ==============================\n"
)


def parse(tmp_path, text: str, *args: str):
    log = tmp_path / "captured.log"
    log.write_text(text)
    return run("--parse", str(log), *args)


def test_standard_non_verbose_pytest_output_is_executed(tmp_path):
    # Default pytest prints no `file::test` line; only -v does. A passing suite in the
    # default format was recorded as NOT EXECUTED.
    p = parse(tmp_path, PYTEST_DEFAULT)
    assert p.returncode == 0, p.stderr
    assert "units=12 named=1" in p.stderr


def test_a_collected_suite_that_ran_nothing_is_not_executed(tmp_path):
    # `collected N items` is discovery. Every test skipped is no work at all.
    text = ("collected 3 items\n\n"
            "tests/test_x.py::test_a SKIPPED\ntests/test_x.py::test_b SKIPPED\n"
            "tests/test_x.py::test_c SKIPPED\n\n"
            "============================== 3 skipped in 0.01s ==============================\n")
    p = parse(tmp_path, text)
    assert p.returncode == EXIT_NO_WORK, p.stderr
    assert "units=0" in p.stderr


def test_a_go_test_counts_once_not_once_per_line(tmp_path):
    # `=== RUN` starts a test and `--- PASS:` finishes it; summing both doubled every test.
    text = "=== RUN   TestParse\n--- PASS: TestParse (0.01s)\nPASS\n"
    p = parse(tmp_path, text)
    assert p.returncode == 0, p.stderr
    assert "units=1 " in p.stderr
    assert parse(tmp_path, text, "--min-units", "2").returncode == EXIT_NO_WORK


def test_a_skipped_go_test_is_not_work(tmp_path):
    p = parse(tmp_path, "=== RUN   TestNeedsNet\n--- SKIP: TestNeedsNet (0.00s)\nPASS\n")
    assert p.returncode == EXIT_NO_WORK, p.stderr


def test_a_rust_target_counts_its_summary_not_its_banner_and_lines(tmp_path):
    # 3 started, 1 ignored: the summary says 2 ran, and the per-test lines are not added.
    text = ("running 3 tests\ntest a::one ... ok\ntest a::two ... ok\ntest a::three ... ignored\n"
            "test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out\n")
    p = parse(tmp_path, text)
    assert p.returncode == 0, p.stderr
    assert "units=2 " in p.stderr


def test_a_target_that_died_mid_run_is_work_then_failure_not_unrun(tmp_path):
    # An empty lib target, then an integration target killed after one test finished.
    script = ("printf 'running 0 tests\\ntest result: ok. 0 passed; 0 failed; 0 ignored\\n"
              "running 5 tests\\ntest io::reads ... ok\\n"
              "error: test failed (signal: 11, SIGSEGV: invalid memory reference)\\n'; exit 101")
    p = run("--out", str(tmp_path / "out.log"), "--", "sh", "-c", script)
    assert p.returncode == EXIT_CMD, p.stderr


# --- shape -----------------------------------------------------------------


def test_the_exec_path_never_pipes_into_tee():
    # A pipeline reports the status of its LAST stage, so `cmd | tee log` discards the
    # failure entirely.
    code = [ln for ln in BODY.splitlines() if not ln.lstrip().startswith("#")]
    assert not [ln for ln in code if "tee" in ln]


def test_the_command_status_is_captured_immediately_after_the_run():
    lines = [ln.strip() for ln in BODY.splitlines()]
    i = lines.index('"$@" > "$LOG" 2>&1')
    assert lines[i + 1] == "RC=$?"
