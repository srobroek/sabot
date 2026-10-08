#!/usr/bin/env python3
"""assert-scan.py must tell a clean scan from a scan that never happened.

Two tools produced the identical false clean from unrelated causes: opengrep exited 2
having scanned 0 files while the PREVIOUS run's JSON sat on disk and read as clean, and
a spurious rc=8 iteration blanked an ast-grep JSON to 0 bytes, which read as 0 findings
for its key injection rule. Zero findings and "the scanner did not run" are the same
bytes unless something asserts the difference.

Stdlib plus pytest only. No network, no real scanner.
"""

from __future__ import annotations

import json
import stat
import subprocess
import sys
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / ".apm" / "skills" / "sabotage" / "scripts" / "assert-scan.py"
)

EXIT_USAGE = 2
EXIT_TOOL_FAILED = 7
EXIT_NOT_EXECUTED = 11


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *args],
                          capture_output=True, text=True, timeout=60)


def fake_scanner(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "scanner.sh"
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IRWXU)
    return path


def semgrep_report(scanned: list[str], results: list[dict] | None = None) -> str:
    return json.dumps({"results": results or [], "paths": {"scanned": scanned}})


# --- the stale-output class --------------------------------------------------


def test_a_stale_report_left_by_a_previous_run_is_not_read_as_this_run(tmp_path):
    out = tmp_path / "scan.json"
    out.write_text(semgrep_report(["a.py", "b.py"]))  # last run's clean result
    scanner = fake_scanner(tmp_path, "exit 2\n")      # this run scans nothing
    r = run("--output", str(out), "--tool", "opengrep", "--", str(scanner))
    assert r.returncode == EXIT_NOT_EXECUTED, r.stdout + r.stderr
    assert "NOT EXECUTED" in r.stderr


def test_a_blanked_zero_byte_report_is_not_zero_findings(tmp_path):
    out = tmp_path / "scan.json"
    scanner = fake_scanner(tmp_path, f": > {out}\nexit 8\n")
    r = run("--output", str(out), "--tool", "ast-grep", "--", str(scanner))
    assert r.returncode == EXIT_NOT_EXECUTED
    assert "zero-byte" in r.stderr


def test_the_output_is_deleted_and_its_absence_confirmed_before_the_run(tmp_path):
    out = tmp_path / "scan.json"
    out.write_text(semgrep_report(["stale.py"]))
    # The scanner records whether the path was already gone when it started.
    witness = tmp_path / "witness"
    scanner = fake_scanner(tmp_path, (
        f'if [ -e "{out}" ]; then echo present > "{witness}"; '
        f'else echo absent > "{witness}"; fi\n'
        f"cat > {out} <<'EOF'\n" + semgrep_report(["x.py"]) + "\nEOF\n"
    ))
    r = run("--output", str(out), "--", str(scanner))
    assert r.returncode == 0, r.stdout + r.stderr
    assert witness.read_text().strip() == "absent"


def test_no_output_written_at_all_is_not_executed(tmp_path):
    out = tmp_path / "scan.json"
    r = run("--output", str(out), "--", str(fake_scanner(tmp_path, "exit 0\n")))
    assert r.returncode == EXIT_NOT_EXECUTED
    assert "no output" in r.stderr


def test_an_unparseable_report_is_not_executed(tmp_path):
    out = tmp_path / "scan.json"
    scanner = fake_scanner(tmp_path, f"printf 'not json' > {out}\n")
    r = run("--output", str(out), "--", str(scanner))
    assert r.returncode == EXIT_NOT_EXECUTED
    assert "unparseable" in r.stderr


# --- the coverage assertion -------------------------------------------------


def test_zero_files_scanned_is_not_executed_even_at_rc_zero(tmp_path):
    out = tmp_path / "scan.json"
    scanner = fake_scanner(tmp_path, f"cat > {out} <<'EOF'\n" + semgrep_report([]) + "\nEOF\n")
    r = run("--output", str(out), "--tool", "opengrep", "--", str(scanner))
    assert r.returncode == EXIT_NOT_EXECUTED
    assert "0 file(s) scanned" in r.stderr


def test_zero_findings_over_a_nonzero_file_count_is_a_pass(tmp_path):
    # The assertion is about coverage. A scanner that really looked and found nothing
    # must not be reported as broken.
    out = tmp_path / "scan.json"
    scanner = fake_scanner(
        tmp_path, f"cat > {out} <<'EOF'\n" + semgrep_report(["a.py", "b.py"]) + "\nEOF\n"
    )
    r = run("--output", str(out), "--json", "--", str(scanner))
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads(r.stdout)
    assert doc["files_scanned"] == 2
    assert doc["findings"] == 0
    assert doc["verdict"] == "executed"


def test_min_files_threshold_is_enforced(tmp_path):
    out = tmp_path / "scan.json"
    scanner = fake_scanner(
        tmp_path, f"cat > {out} <<'EOF'\n" + semgrep_report(["only.py"]) + "\nEOF\n"
    )
    assert run("--output", str(out), "--min-files", "5", "--", str(scanner)).returncode == (
        EXIT_NOT_EXECUTED
    )


def test_a_threshold_of_zero_is_refused_because_it_disables_the_only_real_check(tmp_path):
    out = tmp_path / "scan.json"
    r = run("--output", str(out), "--min-files", "0", "--", "/bin/true")
    assert r.returncode == EXIT_USAGE


def test_a_sarif_report_counts_its_artifact_locations(tmp_path):
    out = tmp_path / "scan.sarif"
    sarif = {"runs": [{"results": [
        {"locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/a.rs"}}}]},
        {"locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/b.rs"}}}]},
    ]}]}
    scanner = fake_scanner(tmp_path, f"cat > {out} <<'EOF'\n" + json.dumps(sarif) + "\nEOF\n")
    r = run("--output", str(out), "--format", "sarif", "--json", "--", str(scanner))
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["files_scanned"] == 2


def test_a_tool_this_script_was_never_taught_still_counts_its_files(tmp_path):
    # A new scanner must not score zero and read as NOT EXECUTED when it did run.
    out = tmp_path / "scan.json"
    doc = {"matches": [{"file": "x.ts"}, {"file": "y.ts"}, {"file": "x.ts"}]}
    scanner = fake_scanner(tmp_path, f"cat > {out} <<'EOF'\n" + json.dumps(doc) + "\nEOF\n")
    r = run("--output", str(out), "--json", "--", str(scanner))
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["files_scanned"] == 2


# --- unreported coverage is not zero coverage --------------------------------


def writes(tmp_path: Path, out: Path, doc, rc: int = 0) -> Path:
    """A fake scanner that writes `doc` as JSON to `out` and exits `rc`."""
    return fake_scanner(
        tmp_path, f"cat > {out} <<'EOF'\n" + json.dumps(doc) + f"\nEOF\nexit {rc}\n")


def test_a_clean_shellcheck_report_is_unreported_coverage_not_not_executed(tmp_path):
    # shellcheck's and ast-grep's clean JSON is `[]`: no finding, and no field for the files
    # read. It scored 0 files, so every clean scan from either tool read as NOT EXECUTED.
    out = tmp_path / "sc.json"
    r = run("--output", str(out), "--tool", "shellcheck", "--json", "--",
            str(writes(tmp_path, out, [])))
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads(r.stdout)
    assert doc["verdict"] == "executed"
    assert doc["coverage_reported"] is False
    assert doc["files_scanned"] is None
    assert "UNREPORTED" in doc["message"]


def test_a_clean_trivy_report_with_no_results_is_unreported_coverage(tmp_path):
    out = tmp_path / "trivy.json"
    clean = {"SchemaVersion": 2, "ArtifactName": ".", "ArtifactType": "filesystem"}
    r = run("--output", str(out), "--tool", "trivy", "--json", "--",
            str(writes(tmp_path, out, clean)))
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["coverage_reported"] is False


def test_a_clean_bandit_report_counts_the_files_in_its_metrics(tmp_path):
    # bandit lists every scanned file under `metrics`, findings or not.
    out = tmp_path / "bandit.json"
    clean = {"errors": [], "results": [], "metrics": {
        "./a.py": {"loc": 3, "nosec": 0}, "./b.py": {"loc": 9, "nosec": 0},
        "_totals": {"loc": 12, "nosec": 0}}}
    r = run("--output", str(out), "--tool", "bandit", "--json", "--",
            str(writes(tmp_path, out, clean)))
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads(r.stdout)
    assert doc["files_scanned"] == 2
    assert doc["coverage_reported"] is True


def test_a_bandit_report_over_no_file_is_still_not_executed(tmp_path):
    out = tmp_path / "bandit.json"
    empty = {"errors": [], "results": [], "metrics": {"_totals": {"loc": 0, "nosec": 0}}}
    r = run("--output", str(out), "--tool", "bandit", "--",
            str(writes(tmp_path, out, empty)))
    assert r.returncode == EXIT_NOT_EXECUTED
    assert "0 file(s) scanned" in r.stderr


def test_an_errors_only_report_is_not_positive_work(tmp_path):
    # The file named in an error is the file the scanner could NOT read.
    out = tmp_path / "scan.json"
    errors_only = {"errors": [{"path": "bad.py", "type": "SyntaxError"}], "results": []}
    r = run("--output", str(out), "--tool", "opengrep", "--",
            str(writes(tmp_path, out, errors_only)))
    assert r.returncode == EXIT_NOT_EXECUTED, r.stdout + r.stderr
    assert "error(s)" in r.stderr


def test_an_errored_file_does_not_add_to_a_findings_based_count(tmp_path):
    out = tmp_path / "scan.json"
    doc = {"results": [{"path": "a.py"}], "errors": [{"path": "bad.py"}]}
    r = run("--output", str(out), "--json", "--", str(writes(tmp_path, out, doc)))
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["files_scanned"] == 1


def test_unreported_coverage_at_a_nonzero_exit_is_not_executed(tmp_path):
    out = tmp_path / "sc.json"
    r = run("--output", str(out), "--tool", "shellcheck", "--",
            str(writes(tmp_path, out, [], rc=3)))
    assert r.returncode == EXIT_NOT_EXECUTED


def test_unreported_coverage_cannot_meet_an_explicit_file_threshold(tmp_path):
    out = tmp_path / "sc.json"
    r = run("--output", str(out), "--min-files", "3", "--",
            str(writes(tmp_path, out, [])))
    assert r.returncode == EXIT_NOT_EXECUTED
    assert "--min-files 3" in r.stderr


# --- exit-code discipline ---------------------------------------------------


def test_a_usage_error_exits_2_and_never_0(tmp_path):
    # A wrapper that exits 0 on its own usage error, having run nothing, is the same
    # fail-open this script exists to close.
    assert run().returncode == EXIT_USAGE
    assert run("--output", str(tmp_path / "o.json")).returncode == EXIT_USAGE


def test_a_real_scan_that_then_fails_is_7_not_a_clean_result(tmp_path):
    out = tmp_path / "scan.json"
    body = f"cat > {out} <<'EOF'\n" + semgrep_report(["a.py"], [{"path": "a.py"}]) + "\nEOF\nexit 1\n"
    r = run("--output", str(out), "--tool", "opengrep", "--", fake_scanner(tmp_path, body).as_posix())
    assert r.returncode == EXIT_TOOL_FAILED
    assert "classify-failure.py" in r.stderr


def test_verify_only_asserts_over_an_output_it_did_not_produce(tmp_path):
    out = tmp_path / "scan.json"
    out.write_text(semgrep_report(["a.py"]))
    assert run("--output", str(out), "--verify-only").returncode == 0
    out.write_text(semgrep_report([]))
    assert run("--output", str(out), "--verify-only").returncode == EXIT_NOT_EXECUTED


def test_verify_only_refuses_a_command(tmp_path):
    out = tmp_path / "scan.json"
    out.write_text(semgrep_report(["a.py"]))
    assert run("--output", str(out), "--verify-only", "--", "/bin/true").returncode == EXIT_USAGE


def test_the_utf8_locale_is_forced_on_the_scanner(tmp_path):
    # One curly quote in a generated rule file killed opengrep under the default locale,
    # so the check and the runtime have to agree on the locale.
    out = tmp_path / "scan.json"
    scanner = fake_scanner(tmp_path, (
        f'printf \'{{"paths":{{"scanned":["%s"]}},"results":[]}}\' "$LC_ALL" > {out}\n'
    ))
    r = run("--output", str(out), "--json", "--", str(scanner))
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(out.read_text())["paths"]["scanned"] == ["C.UTF-8"]
    assert json.loads(r.stdout)["locale_env"]["LC_ALL"] == "C.UTF-8"


def test_an_output_directory_is_refused_rather_than_deleted(tmp_path):
    outdir = tmp_path / "results"
    outdir.mkdir()
    (outdir / "keep.json").write_text("{}")
    r = run("--output", str(outdir), "--", "/bin/true")
    assert r.returncode == EXIT_NOT_EXECUTED
    assert (outdir / "keep.json").exists(), "a directory output must never be deleted"


def test_a_partly_parsed_file_is_reported_though_it_counts_as_scanned(tmp_path):
    """`paths.scanned` counts a file opened, not a file the rules reached.

    Measured on this package: opengrep exited 0 having "scanned" run-contained.sh while
    a PartialParsing error covered 3 of its 500 lines (the `${2:?message}` form), so none
    of the 301 rules ever ran there. The file count cannot see it. A partial parse is a
    coverage gap, not a failed run, so the check reports it without changing the exit.
    """
    out = tmp_path / "og.json"
    out.write_text(json.dumps({
        "results": [],
        "paths": {"scanned": ["a.sh", "b.sh"]},
        "errors": [{"code": 3, "level": "warn", "type": [
            "PartialParsing", [{"path": "b.sh", "start": {"line": 105, "col": 39}}]]}],
    }))
    r = run("--output", str(out), "--tool", "opengrep", "--verify-only", "--json")
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads(r.stdout)
    assert doc["partial_parse_files"] == ["b.sh"]
    check = next(c for c in doc["checks"] if c["name"] == "fully_parsed")
    assert check["ok"] is False, doc["checks"]


def test_no_parse_errors_reports_fully_parsed(tmp_path):
    out = tmp_path / "og.json"
    out.write_text(semgrep_report(["a.sh"]))
    r = run("--output", str(out), "--tool", "opengrep", "--verify-only", "--json")
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads(r.stdout)
    assert doc["partial_parse_files"] == []
    assert next(c for c in doc["checks"] if c["name"] == "fully_parsed")["ok"] is True
