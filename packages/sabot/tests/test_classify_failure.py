"""classify-failure.py gives every caller one verdict on a failed contained run.

A resource fault is an INVALID run: not a finding, not a target defect. A campaign lost
nine unexecuted harnesses to reading a memory-cgroup SIGKILL as a missing system library.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1] / ".apm" / "skills" / "sabotage"
SCRIPT = SKILL / "scripts" / "classify-failure.py"

EXIT_USAGE = 2
EXIT_RESOURCE = 10
EXIT_NOT_EXECUTED = 11


def run(log: str | None, *args: str) -> tuple[int, dict]:
    """Run the classifier over `log` on stdin and return (rc, parsed json)."""
    p = subprocess.run(
        [sys.executable, str(SCRIPT), *args, "--json"],
        input=log if log is not None else "",
        capture_output=True,
        text=True,
    )
    return p.returncode, (json.loads(p.stdout) if p.stdout.strip() else {})


LINKER_OOM = """\
   Compiling pv_ipc v0.1.0
error: linking with `cc` failed: signal: 9 (SIGKILL: kill)
collect2: fatal error: ld terminated with signal 9 [Killed]
"""

ENOSPC = """\
error: failed to write /artifacts/.build/deps/libpv.rlib
Caused by: No space left on device (os error 28)
"""

CORRUPT_STORE = """\
docker: Error response from daemon: failed to register layer:
  error reading from server: input/output error
"""


# --- memory: the degrade-first ladder --------------------------------------


def test_linker_sigkill_is_a_memory_fault_not_a_missing_library():
    rc, v = run(LINKER_OOM, "--rc", "101", "--log", "-", "--mem-mb", "2048",
                "--host-mem-mb", "16384")
    assert rc == EXIT_RESOURCE
    assert v["verdict"] == "resource:memory"
    assert v["invalid_run"] is True


def test_the_first_retry_degrades_the_recipe_and_keeps_the_cap():
    # run-layout.md: a build SIGKILLed at 2048 MiB finished at 739 MiB with -j 1 and debug
    # info off. Raising the cap first is the step the ladder puts second.
    rc, v = run(LINKER_OOM, "--rc", "101", "--log", "-", "--mem-mb", "2048",
                "--host-mem-mb", "16384")
    assert rc == EXIT_RESOURCE
    assert v["retry_allowed"] is True
    assert v["retry_step"] == 1
    assert v["retry_raises_cap"] is False
    assert v["retry_jobs"] == 1
    assert v["retry_mem_mb"] == 2048
    assert v["retry_env"] == {"CARGO_PROFILE_TEST_DEBUG": "0", "CARGO_PROFILE_DEV_DEBUG": "0",
                              "CARGO_INCREMENTAL": "0"}


def test_the_degraded_recipe_needs_no_known_cap():
    rc, v = run(LINKER_OOM, "--rc", "101", "--log", "-")
    assert rc == EXIT_RESOURCE
    assert v["retry_allowed"] is True
    assert v["retry_step"] == 1
    assert "retry_mem_mb" not in v


def test_the_second_retry_raises_the_cap_once_keeping_the_degraded_recipe():
    # 2048 MiB SIGKILLed ld; the same package linked at 6144.
    rc, v = run(LINKER_OOM, "--rc", "101", "--log", "-", "--mem-mb", "2048",
                "--host-mem-mb", "16384", "--attempt", "2")
    assert rc == EXIT_RESOURCE
    assert v["retry_allowed"] is True
    assert v["retry_step"] == 2
    assert v["retry_raises_cap"] is True
    assert v["retry_mem_mb"] == 6144
    assert v["retry_jobs"] == 1
    assert v["retry_env"]["CARGO_PROFILE_TEST_DEBUG"] == "0"


def test_rc_137_alone_is_read_as_the_memory_cap():
    rc, v = run("the container went away\n", "--rc", "137", "--log", "-",
                "--mem-mb", "2048", "--host-mem-mb", "16384")
    assert rc == EXIT_RESOURCE
    assert v["verdict"] == "resource:memory"


def test_a_third_attempt_gets_no_further_escalation():
    # One raise, recorded as a budget deviation. A campaign that keeps doubling trades
    # every other node's memory for one node's evidence.
    rc, v = run(LINKER_OOM, "--rc", "101", "--log", "-", "--mem-mb", "6144",
                "--host-mem-mb", "65536", "--attempt", "3")
    assert rc == EXIT_RESOURCE
    assert v["retry_allowed"] is False
    assert "ladder is spent" in v["retry_reason"]


def test_an_escalation_past_what_the_host_has_is_refused():
    # Asking 6 GiB of a 4 GiB VM must fail at preflight, not at the linker.
    rc, v = run(LINKER_OOM, "--rc", "101", "--log", "-", "--mem-mb", "2048",
                "--host-mem-mb", "4096", "--attempt", "2")
    assert rc == EXIT_RESOURCE
    assert v["retry_allowed"] is False
    assert "ceiling" in v["retry_reason"]


def test_the_raise_without_a_known_cap_cannot_be_computed():
    rc, v = run(LINKER_OOM, "--rc", "101", "--log", "-", "--attempt", "2")
    assert rc == EXIT_RESOURCE
    assert v["retry_allowed"] is False
    assert "--mem-mb" in v["retry_reason"]


def test_an_attempt_below_one_is_a_usage_error():
    p = subprocess.run([sys.executable, str(SCRIPT), "--rc", "101", "--attempt", "0"],
                       capture_output=True, text=True)
    assert p.returncode == EXIT_USAGE


def test_the_ladder_is_the_one_run_preflight_records():
    # One owner for the ladder: preflight.json records run-preflight.py's RETRY_LADDER,
    # and the classifier must walk the same steps rather than a copy of its own.
    import importlib.util
    spec = importlib.util.spec_from_file_location("rp", SKILL / "scripts" / "run-preflight.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for attempt, step in enumerate(mod.RETRY_LADDER, 1):
        _, v = run(LINKER_OOM, "--rc", "101", "--log", "-", "--mem-mb", "2048",
                   "--host-mem-mb", "65536", "--attempt", str(attempt))
        assert (v["retry_step"], v["retry_raises_cap"], v["retry_env"]) == (
            step["step"], step["raises_cap"], step["env"])


def test_a_fuzz_inputs_failed_allocation_is_a_target_finding_not_the_cap():
    # Under a memory cgroup the kernel SIGKILLs; the allocator reporting a failed request
    # is the program asking for an absurd size, which an input drove.
    log = ("INFO: Running with entropic power schedule\n"
           "memory allocation of 18446744073709551615 bytes failed\n"
           "==12== ERROR: libFuzzer: deadly signal\n")
    rc, v = run(log, "--rc", "134", "--log", "-", "--mem-mb", "2048")
    assert rc == 0, v
    assert v["verdict"] == "target-defect"
    assert v["invalid_run"] is False


def test_the_compilers_failed_allocation_is_still_the_cap():
    log = ("   Compiling big v0.1.0\nmemory allocation of 1048576 bytes failed\n"
           "error: could not compile `big` (lib)\n")
    rc, v = run(log, "--rc", "101", "--log", "-", "--mem-mb", "2048")
    assert rc == EXIT_RESOURCE
    assert v["verdict"] == "resource:memory"


# --- disk and the container store: never auto-retried ----------------------


def test_enospc_is_never_auto_retried():
    # Retrying into a full disk is what corrupted the container store.
    rc, v = run(ENOSPC, "--rc", "101", "--log", "-", "--mem-mb", "2048",
                "--host-mem-mb", "65536")
    assert rc == EXIT_RESOURCE
    assert v["verdict"] == "resource:disk"
    assert v["retry_allowed"] is False
    assert v["remediation"][0].startswith("stop")


def test_a_corrupt_container_blob_is_a_resource_fault_not_a_finding():
    rc, v = run(CORRUPT_STORE, "--rc", "125", "--log", "-")
    assert rc == EXIT_RESOURCE
    assert v["verdict"] == "resource:disk"
    assert v["invalid_run"] is True


def test_disk_beats_memory_when_both_signs_appear():
    # A full disk kills the linker too; retrying it with more memory refills the disk.
    rc, v = run(LINKER_OOM + ENOSPC, "--rc", "137", "--log", "-", "--mem-mb", "2048",
                "--host-mem-mb", "65536")
    assert rc == EXIT_RESOURCE
    assert v["verdict"] == "resource:disk"
    assert v["retry_allowed"] is False


def test_every_resource_verdict_leaves_an_outstanding_teardown_item():
    # A run that dies on ENOSPC is exactly the run whose residue nobody cleans up.
    for log in (LINKER_OOM, ENOSPC, CORRUPT_STORE):
        _, v = run(log, "--rc", "101", "--log", "-")
        assert v["outstanding_teardown"] is True


# --- not executed: never "0 findings" --------------------------------------


def test_a_test_binary_that_selected_nothing_is_not_executed():
    rc, v = run("running 0 tests\ntest result: ok. 0 passed\n", "--rc", "0", "--log", "-")
    assert rc == EXIT_NOT_EXECUTED
    assert v["verdict"] == "invalid:not-executed"
    assert "false clean" in v["retry_reason"]


def test_a_history_scan_over_zero_commits_is_not_executed():
    # gitleaks git mode on a worktree whose .git is a pointer file: 0 commits, exit 0.
    rc, v = run("scanned 0 commits for leaks\n", "--rc", "0", "--log", "-")
    assert rc == EXIT_NOT_EXECUTED
    assert v["verdict"] == "invalid:not-executed"


def test_a_ruleset_that_needed_the_network_is_not_executed():
    # Stock registry packs cannot load under --network none, so no rule ever applied.
    log = "opengrep: could not fetch ruleset p/rust: Temporary failure in name resolution\n"
    rc, v = run(log, "--rc", "2", "--log", "-")
    assert rc == EXIT_NOT_EXECUTED
    assert v["verdict"] == "invalid:not-executed"


def test_a_nonzero_opengrep_status_is_not_executed():
    rc, v = run("OG_RC=2\n", "--rc", "0", "--log", "-")
    assert rc == EXIT_NOT_EXECUTED


def test_the_wrapper_recording_executed_zero_is_not_executed():
    rc, v = run("executed=0\nreason=--require-cmd unsatisfied\n", "--rc", "6", "--log", "-")
    assert rc == EXIT_NOT_EXECUTED


# --- target defects and the rc=0 trap --------------------------------------


def test_a_real_assertion_failure_is_a_target_defect():
    log = "test parse::rejects_overflow ... FAILED\nassertion failed: left == right\n"
    rc, v = run(log, "--rc", "101", "--log", "-")
    assert rc == 0
    assert v["verdict"] == "target-defect"
    assert v["invalid_run"] is False


def test_rc_zero_over_a_clean_looking_log_is_inconclusive_not_a_pass():
    # rc=0 is not evidence anything ran: a rewritten toolchain produced rc=0 with 0 tests.
    rc, v = run("done\n", "--rc", "0", "--log", "-")
    assert rc == 0
    assert v["verdict"] == "inconclusive"
    assert "not evidence" in v["retry_reason"]


def test_an_empty_lib_target_does_not_hide_a_real_failing_test():
    # A workspace prints `running 0 tests` for every target with no tests. Reading that
    # line alone called a run with a real FAILED test not-executed.
    log = ("running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored\n\n"
           "running 3 tests\ntest parse::accepts ... ok\ntest parse::rejects_overflow ... FAILED\n"
           "test result: FAILED. 2 passed; 1 failed; 0 ignored\n")
    rc, v = run(log, "--rc", "101", "--log", "-")
    assert rc == 0, v
    assert v["verdict"] == "target-defect"


def test_a_scanner_usage_error_is_not_executed_not_a_product_finding():
    log = "usage: scanner [OPTIONS] PATH\nscanner: error: invalid argument --wat\n"
    rc, v = run(log, "--rc", "2", "--log", "-", "--mem-mb", "2048", "--host-mem-mb", "8192")
    assert rc == EXIT_NOT_EXECUTED, v
    assert v["verdict"] == "invalid:not-executed"


def test_a_failure_with_no_recognized_sign_is_inconclusive_not_a_target_defect():
    # Attribution needs positive evidence; a bare nonzero status is not a product finding.
    rc, v = run("something went wrong\n", "--rc", "1", "--log", "-")
    assert rc == 0
    assert v["verdict"] == "inconclusive"
    assert "nothing attributes it to the target" in v["retry_reason"]


def test_a_crash_signal_while_compiling_is_not_a_target_defect():
    log = ("error: could not compile `big` (lib)\nCaused by: process didn't exit "
           "successfully: `rustc --crate-name big` (signal: 11, SIGSEGV: invalid memory reference)\n")
    rc, v = run(log, "--rc", "101", "--log", "-")
    assert v["verdict"] == "inconclusive", v


def test_a_test_binary_segfault_is_a_target_defect():
    log = ("running 4 tests\nerror: test failed, to rerun pass `--lib`\nCaused by: process "
           "didn't exit successfully: `/artifacts/.build/debug/deps/pv-1a2b` "
           "(signal: 11, SIGSEGV: invalid memory reference)\n")
    rc, v = run(log, "--rc", "101", "--log", "-")
    assert v["verdict"] == "target-defect", v


# --- interface -------------------------------------------------------------


def test_a_missing_log_file_is_a_usage_error(tmp_path):
    p = subprocess.run(
        [sys.executable, str(SCRIPT), "--rc", "1", "--log", str(tmp_path / "nope.log")],
        capture_output=True, text=True,
    )
    assert p.returncode == EXIT_USAGE


def test_a_missing_rc_is_a_usage_error():
    p = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
    assert p.returncode == EXIT_USAGE


def test_json_carries_the_verdict_evidence_and_exit_code():
    _, v = run(LINKER_OOM, "--rc", "101", "--log", "-", "--mem-mb", "2048",
               "--host-mem-mb", "16384")
    assert v["schema"] == "sabot-failure/1"
    for key in ("verdict", "invalid_run", "retry_allowed", "retry_reason",
                "outstanding_teardown", "remediation", "evidence", "exit_code"):
        assert key in v
    assert v["evidence"]["memory"]


def test_human_output_names_the_evidence_and_the_teardown_step():
    p = subprocess.run(
        [sys.executable, str(SCRIPT), "--rc", "101", "--log", "-"],
        input=ENOSPC, capture_output=True, text=True,
    )
    assert p.returncode == EXIT_RESOURCE
    assert "verdict=resource:disk" in p.stdout
    assert "outstanding teardown item" in p.stdout
    assert "run-teardown.py" in p.stdout
