#!/usr/bin/env python3
"""Tests for the shipped fuzz-cli.py harness.

The harness is the package's only executable detector, so a silent failure in it
turns every campaign into a false clean bill of health. These tests therefore
concentrate on the negative controls: the harness must FAIL on a broken target.

Run: pytest packages/sabot/tests/test_fuzz_cli.py
Stdlib plus pytest only. No network.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

HARNESS = (
    Path(__file__).resolve().parents[1]
    / ".apm" / "skills" / "sabotage" / "scripts" / "fuzz-cli.py"
)


def run_harness(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HARNESS), *args],
        capture_output=True, text=True, timeout=180,
    )


def write_exec(path: Path, body: str) -> Path:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IRWXU)
    return path


# --------------------------------------------------------------------------
# Positive controls: a well-behaved target produces no findings.
# --------------------------------------------------------------------------


GOOD_GUARD = '''#!/usr/bin/env python3
"""A guard that always emits valid JSON and denies its target pattern.

Reads stdin as BYTES and decodes with a replacement policy: a text-mode read
raises on invalid UTF-8, which is a crash the harness correctly reports.
"""
import json, re, sys

BAD = re.compile(r"(^|[;&|]\\s*|\\b(?:env|sudo|nice|xargs)\\s+)rm\\s+-[rf]{2}\\s+/\\s*$")

def main():
    raw = sys.stdin.buffer.read().decode("utf-8", "replace")
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    ti = payload.get("tool_input")
    cmd = ti.get("command", "") if isinstance(ti, dict) else ""
    if not isinstance(cmd, str):
        cmd = ""
    decision = "deny" if BAD.search(cmd.strip()) else "allow"
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": decision}}))
    return 0

if __name__ == "__main__":
    sys.exit(main())
'''


def test_wellbehaved_target_structural_clean(tmp_path):
    t = write_exec(tmp_path / "good.py", GOOD_GUARD)
    r = run_harness("--target", str(t), "--mode", "json",
                    "--artifacts-dir", str(tmp_path / "a"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "0 findings" in r.stdout


def test_structural_corpus_actually_runs_many_cases(tmp_path):
    """A pass must come from real invocations, not from an empty corpus."""
    t = write_exec(tmp_path / "good.py", GOOD_GUARD)
    r = run_harness("--target", str(t), "--mode", "json",
                    "--artifacts-dir", str(tmp_path / "a"), "--json-report")
    report = json.loads(r.stdout)
    assert report["runs"] >= 20, f"only {report['runs']} invocations"
    assert report["findings"] == []


def test_vectors_pass_on_correct_guard(tmp_path):
    t = write_exec(tmp_path / "good.py", GOOD_GUARD)
    vec = tmp_path / "v.json"
    vec.write_text(json.dumps([
        {"name": "plain", "payload": {"tool_input": {"command": "rm -rf /"}},
         "expect": "deny", "why": "catastrophic"},
        {"name": "env-wrapper", "payload": {"tool_input": {"command": "env rm -rf /"}},
         "expect": "deny", "why": "wrapper must not evade"},
        {"name": "benign", "payload": {"tool_input": {"command": "ls -la"}},
         "expect": "allow", "why": "must not over-block"},
    ]))
    r = run_harness("--target", str(t), "--mode", "json", "--vectors", str(vec),
                    "--skip-structural", "--artifacts-dir", str(tmp_path / "a"))
    assert r.returncode == 0, r.stdout


# --------------------------------------------------------------------------
# Negative controls: the harness MUST fail on each broken target. A harness
# that cannot fail is worthless, so these are the important tests.
# --------------------------------------------------------------------------


def test_detects_crash_on_malformed_input(tmp_path):
    t = write_exec(tmp_path / "crasher.py", '''#!/usr/bin/env python3
import json, sys
payload = json.loads(sys.stdin.read())   # raises on any non-JSON input
print(json.dumps({"ok": True}))
''')
    r = run_harness("--target", str(t), "--mode", "json",
                    "--artifacts-dir", str(tmp_path / "a"))
    assert r.returncode == 1
    assert "CRASH" in r.stdout


def test_detects_hang(tmp_path):
    t = write_exec(tmp_path / "hanger.py", '''#!/usr/bin/env python3
import time
time.sleep(600)
''')
    r = run_harness("--target", str(t), "--mode", "json", "--timeout", "2",
                    "--artifacts-dir", str(tmp_path / "a"))
    assert r.returncode == 1
    assert "HANG" in r.stdout


def test_detects_unparsable_output(tmp_path):
    t = write_exec(tmp_path / "garbage.py", '''#!/usr/bin/env python3
import sys
sys.stdin.read()
print("not json at all")
''')
    r = run_harness("--target", str(t), "--mode", "json",
                    "--artifacts-dir", str(tmp_path / "a"))
    assert r.returncode == 1
    assert "UNPARSABLE" in r.stdout


def test_detects_bypass(tmp_path):
    """A guard anchored on the raw string misses the wrapper form."""
    t = write_exec(tmp_path / "weak.py", '''#!/usr/bin/env python3
import json, sys
raw = sys.stdin.read()
try:
    p = json.loads(raw) if raw.strip() else {}
except Exception:
    p = {}
if not isinstance(p, dict):
    p = {}
ti = p.get("tool_input")
cmd = ti.get("command", "") if isinstance(ti, dict) else ""
if not isinstance(cmd, str):
    cmd = ""
decision = "deny" if cmd.startswith("rm -rf /") else "allow"
print(json.dumps({"hookSpecificOutput": {"permissionDecision": decision}}))
''')
    vec = tmp_path / "v.json"
    vec.write_text(json.dumps([
        {"name": "plain", "payload": {"tool_input": {"command": "rm -rf /"}},
         "expect": "deny", "why": "baseline"},
        {"name": "env-wrapper", "payload": {"tool_input": {"command": "env rm -rf /"}},
         "expect": "deny", "why": "wrapper prefix must not evade the guard"},
    ]))
    r = run_harness("--target", str(t), "--mode", "json", "--vectors", str(vec),
                    "--skip-structural", "--artifacts-dir", str(tmp_path / "a"))
    assert r.returncode == 1
    assert "BYPASS" in r.stdout
    assert "env-wrapper" in r.stdout
    # The plain form is still blocked, so exactly one vector fails.
    assert r.stdout.count("BYPASS") == 1


def test_detects_over_blocking(tmp_path):
    """A guard that denies everything is as broken as one that denies nothing."""
    t = write_exec(tmp_path / "paranoid.py", '''#!/usr/bin/env python3
import json, sys
sys.stdin.read()
print(json.dumps({"hookSpecificOutput": {"permissionDecision": "deny"}}))
''')
    vec = tmp_path / "v.json"
    vec.write_text(json.dumps([
        {"name": "benign", "payload": {"tool_input": {"command": "ls -la"}},
         "expect": "allow", "why": "must not over-block"},
    ]))
    r = run_harness("--target", str(t), "--mode", "json", "--vectors", str(vec),
                    "--skip-structural", "--artifacts-dir", str(tmp_path / "a"))
    assert r.returncode == 1
    assert "CONTRACT" in r.stdout


def test_flags_ask_as_stall(tmp_path):
    """`ask` blocks an autonomous agent, so the harness reports it."""
    t = write_exec(tmp_path / "asker.py", '''#!/usr/bin/env python3
import json, sys
sys.stdin.read()
print(json.dumps({"hookSpecificOutput": {"permissionDecision": "ask"}}))
''')
    vec = tmp_path / "v.json"
    vec.write_text(json.dumps([
        {"name": "catastrophic", "payload": {"tool_input": {"command": "rm -rf /"}},
         "expect": "deny", "why": "must deny outright"},
    ]))
    r = run_harness("--target", str(t), "--mode", "json", "--vectors", str(vec),
                    "--skip-structural", "--artifacts-dir", str(tmp_path / "a"))
    assert r.returncode == 1
    assert "STALL" in r.stdout


def test_missing_decision_counts_as_allow(tmp_path):
    """No decision means the guard did not object, which is a bypass when it
    should have denied. Silence must not read as a block."""
    t = write_exec(tmp_path / "silent.py", '''#!/usr/bin/env python3
import sys
sys.stdin.read()
''')
    vec = tmp_path / "v.json"
    vec.write_text(json.dumps([
        {"name": "catastrophic", "payload": {"tool_input": {"command": "rm -rf /"}},
         "expect": "deny", "why": "silence is not a block"},
    ]))
    r = run_harness("--target", str(t), "--mode", "json", "--vectors", str(vec),
                    "--skip-structural", "--artifacts-dir", str(tmp_path / "a"))
    assert r.returncode == 1
    assert "BYPASS" in r.stdout


def run_vectors(tmp_path: Path, guard_body: str, vectors: list) -> subprocess.CompletedProcess:
    t = write_exec(tmp_path / "guard.py", "#!/usr/bin/env python3\n" + guard_body)
    vec = tmp_path / "v.json"
    vec.write_text(json.dumps(vectors))
    return run_harness("--target", str(t), "--mode", "json", "--vectors", str(vec),
                       "--skip-structural", "--artifacts-dir", str(tmp_path / "a"))


DENY_RM = [{"name": "catastrophic", "payload": {"tool_input": {"command": "rm -rf /"}},
            "expect": "deny", "why": "must deny"}]


def test_a_deny_by_exit_2_with_the_reason_on_stderr_is_a_deny(tmp_path):
    """Claude Code's documented deny: exit 2, reason on stderr, nothing on stdout.
    Reading stdout alone scored it as an allow, a false BYPASS on every deny vector."""
    r = run_vectors(tmp_path, (
        "import sys\nsys.stdin.read()\n"
        "print('Blocked: rm -rf is not allowed', file=sys.stderr)\nsys.exit(2)\n"
    ), DENY_RM)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "BYPASS" not in r.stdout


def test_exit_2_blocks_even_when_stdout_says_allow(tmp_path):
    r = run_vectors(tmp_path, (
        "import json, sys\nsys.stdin.read()\n"
        "print(json.dumps({'hookSpecificOutput': {'permissionDecision': 'allow'}}))\n"
        "sys.exit(2)\n"
    ), DENY_RM)
    assert r.returncode == 0, r.stdout + r.stderr


def test_an_exit_2_on_a_benign_vector_is_over_blocking(tmp_path):
    r = run_vectors(tmp_path, "import sys\nsys.stdin.read()\nsys.exit(2)\n", [
        {"name": "benign", "payload": {"tool_input": {"command": "ls"}},
         "expect": "allow", "why": "must not over-block"}])
    assert r.returncode == 1
    assert "CONTRACT" in r.stdout
    assert "exit 2" in r.stdout


def test_the_legacy_block_decision_is_a_deny_not_a_contract_breach(tmp_path):
    """`{"decision": "block"}` is the deprecated Claude Code form and the Codex form."""
    r = run_vectors(tmp_path, (
        "import json, sys\nsys.stdin.read()\nprint(json.dumps({'decision': 'block'}))\n"
    ), DENY_RM)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "CONTRACT" not in r.stdout


def test_a_guard_that_errors_without_a_decision_fails_open(tmp_path):
    """Any other nonzero exit with no decision is a non-blocking error: the call runs."""
    r = run_vectors(tmp_path, "import sys\nsys.stdin.read()\nsys.exit(1)\n", DENY_RM)
    assert r.returncode == 1
    assert "BYPASS" in r.stdout
    assert "non-blocking error" in r.stdout


def test_a_vector_that_is_not_an_object_is_refused_not_a_crash(tmp_path):
    """A string element crashed validation on `vec.get`, so the harness died with a
    traceback that read as a defect instead of naming the unusable vector."""
    t = write_exec(tmp_path / "guard.py", "#!/usr/bin/env python3\nimport sys\nsys.stdin.read()\n")
    vec = tmp_path / "v.json"
    vec.write_text(json.dumps(["bad-vector", *DENY_RM]))
    r = run_harness("--target", str(t), "--vectors", str(vec), "--skip-structural")
    assert r.returncode == 2, r.stdout + r.stderr
    assert "vector[0]: not an object (got str)" in r.stderr
    assert "Traceback" not in r.stderr


ALLOW = "import json, sys\nsys.stdin.read()\nprint(json.dumps({'decision': 'approve'}))\n"


def test_a_vector_with_no_payload_is_refused_not_run_as_empty_input(tmp_path):
    """`payload` is required, but a missing one was sent as zero bytes, so the vector ran
    and passed against empty input instead of the case its author wrote."""
    r = run_vectors(tmp_path, ALLOW,
                    [{"name": "benign", "expect": "allow", "why": "must allow"}])
    assert r.returncode == 2, r.stdout + r.stderr
    assert "vector[0] (benign): no `payload`" in r.stderr


def test_an_explicitly_empty_payload_still_runs(tmp_path):
    r = run_vectors(tmp_path, ALLOW,
                    [{"name": "empty", "payload": "", "expect": "allow", "why": "empty input"}])
    assert r.returncode == 0, r.stdout + r.stderr


def test_names_that_share_a_repro_file_are_refused(tmp_path):
    """'case/x' and 'case_x' both saved to vector_case_x.input, so the second finding's
    payload overwrote the first's and replaying the first reproduced the wrong input."""
    r = run_vectors(tmp_path, ALLOW, [
        {"name": "case/x", "payload": "a", "expect": "allow", "why": "one"},
        {"name": "case_x", "payload": "b", "expect": "allow", "why": "two"}])
    assert r.returncode == 2, r.stdout + r.stderr
    assert "vector[1] (case_x): its repro file vector_case_x.input is also vector[0]'s" \
        in r.stderr


# --------------------------------------------------------------------------
# Reproducibility and hygiene
# --------------------------------------------------------------------------


def test_persists_reproducing_input(tmp_path):
    t = write_exec(tmp_path / "crasher.py", '''#!/usr/bin/env python3
import json, sys
json.loads(sys.stdin.read())
''')
    art = tmp_path / "artifacts"
    r = run_harness("--target", str(t), "--mode", "json", "--artifacts-dir", str(art),
                    "--json-report")
    report = json.loads(r.stdout)
    assert report["findings"], "expected findings"
    saved = [f["input"] for f in report["findings"] if f["input"]]
    assert saved, "no reproducing input was persisted"
    for path in saved:
        assert Path(path).exists(), f"claimed input missing: {path}"


def test_writes_nothing_outside_artifacts_dir(tmp_path):
    """A campaign must not pollute the target tree."""
    workdir = tmp_path / "repo"
    workdir.mkdir()
    t = write_exec(workdir / "crasher.py", '''#!/usr/bin/env python3
import json, sys
json.loads(sys.stdin.read())
''')
    art = tmp_path / "artifacts"
    before = set(p.name for p in workdir.iterdir())
    run_harness("--target", str(t), "--mode", "json", "--artifacts-dir", str(art))
    after = set(p.name for p in workdir.iterdir())
    assert before == after, f"target dir mutated: {after - before}"


def test_text_mode_skips_json_contract(tmp_path):
    """A text-mode target has no JSON contract, so plain output is not a finding."""
    t = write_exec(tmp_path / "cat.py", '''#!/usr/bin/env python3
import sys
sys.stdin.buffer.read()
print("plain text output")
''')
    r = run_harness("--target", str(t), "--mode", "text",
                    "--artifacts-dir", str(tmp_path / "a"))
    assert r.returncode == 0, r.stdout


def test_traceback_on_stderr_is_a_crash_even_with_exit_zero(tmp_path):
    """A target that swallows its own exit code still crashed."""
    t = write_exec(tmp_path / "liar.py", '''#!/usr/bin/env python3
import json, sys, traceback
try:
    json.loads(sys.stdin.read())
except Exception:
    traceback.print_exc()
print(json.dumps({"ok": True}))
sys.exit(0)
''')
    r = run_harness("--target", str(t), "--mode", "json",
                    "--artifacts-dir", str(tmp_path / "a"))
    assert r.returncode == 1
    assert "CRASH" in r.stdout


# --------------------------------------------------------------------------
# Usage errors
# --------------------------------------------------------------------------


def test_missing_target_exits_two(tmp_path):
    r = run_harness("--target", str(tmp_path / "nope.py"))
    assert r.returncode == 2


def test_malformed_vectors_file_exits_two(tmp_path):
    t = write_exec(tmp_path / "good.py", GOOD_GUARD)
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    r = run_harness("--target", str(t), "--vectors", str(bad))
    assert r.returncode == 2


def test_vectors_must_be_a_list(tmp_path):
    t = write_exec(tmp_path / "good.py", GOOD_GUARD)
    obj = tmp_path / "obj.json"
    obj.write_text('{"name": "x"}')
    r = run_harness("--target", str(t), "--vectors", str(obj))
    assert r.returncode == 2


def test_warns_when_no_vectors_supplied(tmp_path):
    """A structural-only run must say bypass detection did not happen."""
    t = write_exec(tmp_path / "good.py", GOOD_GUARD)
    r = run_harness("--target", str(t), "--mode", "json",
                    "--artifacts-dir", str(tmp_path / "a"))
    assert "no --vectors file" in r.stdout


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
