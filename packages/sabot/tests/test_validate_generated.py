#!/usr/bin/env python3
"""Tests for the shipped validate-generated.py artifact gate.

Every case here is a generated artifact that a campaign accepted and should not have: a
zero-byte repro, a commented-out rule, a curly quote that killed the scanner, a harness
that does not exist, a harness that does not build.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / ".apm" / "skills" / "sabotage" / "scripts" / "validate-generated.py"
)

GOOD_RULES = """rules:
  - id: pv-no-unwrap-at-boundary
    languages: [rust]
    message: unwrap at an IPC boundary
    severity: WARNING
    pattern: $X.unwrap()
"""


def run(*args, path_dir: Path | None = None):
    env = dict(os.environ)
    if path_dir is not None:
        env["PATH"] = str(path_dir)
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, env=env,
    )


def stub(dir_path: Path, name: str, body: str) -> Path:
    dir_path.mkdir(parents=True, exist_ok=True)
    p = dir_path / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return p


def loader(tmp_path: Path, body: str = 'echo "found 1 rule"\nexit 0\n') -> Path:
    """A PATH holding only a stub scanner.

    Every rules case needs one: with the real semgrep on PATH each check_tool_load call
    costs seconds and reaches for a registry, and a test that invokes a real scanner is
    testing the scanner.
    """
    bindir = tmp_path / "bin"
    stub(bindir, "opengrep", body)
    return bindir


def checks(out: str) -> dict[str, str]:
    doc = json.loads(out)
    return {c["check"]: c["status"] for c in doc["checks"]}


# --- usage ------------------------------------------------------------------


def test_missing_kind_is_a_usage_error():
    assert run("somefile.yml").returncode == 2


def test_unknown_kind_is_a_usage_error(tmp_path):
    f = tmp_path / "x.yml"
    f.write_text(GOOD_RULES)
    assert run("--kind", "notathing", str(f)).returncode == 2


# --- existence and emptiness ------------------------------------------------


def test_a_harness_that_does_not_exist_fails_loudly(tmp_path):
    # One fuzzer reported authoring fuzz/ trees that were absent from disk entirely.
    p = run("--kind", "harness", str(tmp_path / "fuzz" / "targets" / "parse.rs"), "--json")
    assert p.returncode == 1
    assert checks(p.stdout)["exists"] == "fail"
    assert "does not exist" in p.stdout


def test_a_zero_byte_repro_is_a_failure_not_an_empty_result(tmp_path):
    empty = tmp_path / "crash-01.input"
    empty.write_bytes(b"")
    p = run("--kind", "corpus", str(empty), "--json")
    assert p.returncode == 1
    assert checks(p.stdout)["non_empty"] == "fail"


def test_a_non_empty_corpus_input_passes_without_a_shape_check(tmp_path):
    seed = tmp_path / "seed-07.input"
    seed.write_bytes(b"\x00\xff\x41not utf-8 and that is fine")
    p = run("--kind", "corpus", str(seed), "--json")
    assert p.returncode == 0
    assert "shape" not in checks(p.stdout)


def test_a_directory_is_not_a_generated_file(tmp_path):
    p = run("--kind", "rules", str(tmp_path), "--json")
    assert p.returncode == 1
    assert checks(p.stdout)["exists"] == "fail"


# --- encoding ---------------------------------------------------------------


def test_a_curly_quote_in_a_rule_file_fails_with_its_location(tmp_path):
    # One non-ASCII character made opengrep exit 2 having scanned 0 files, while the
    # previous run's JSON on disk read as a clean scan.
    f = tmp_path / "rules-code.yml"
    f.write_text(GOOD_RULES.replace("unwrap at", "unwrap’s at"))
    p = run("--kind", "rules", str(f), "--json", path_dir=loader(tmp_path))
    assert p.returncode == 1
    assert checks(p.stdout)["encoding"] == "fail"
    assert "U+2019" in p.stdout


def test_normalize_rewrites_the_curly_quote_and_leaves_the_file_valid(tmp_path):
    f = tmp_path / "rules-code.yml"
    f.write_text(GOOD_RULES.replace("unwrap at", "unwrap’s at"))
    p = run("--kind", "rules", str(f), "--normalize", "--json", path_dir=loader(tmp_path))
    assert checks(p.stdout)["encoding"] == "pass"
    body = f.read_text()
    assert "’" not in body
    assert "unwrap's at" in body
    assert checks(p.stdout)["shape"] == "pass"


def test_normalize_is_off_by_default(tmp_path):
    f = tmp_path / "rules-code.yml"
    original = GOOD_RULES.replace("unwrap at", "unwrap’s at")
    f.write_text(original)
    run("--kind", "rules", str(f), "--json", path_dir=loader(tmp_path))
    assert f.read_text() == original


def test_the_report_carries_the_utf8_locale_the_runtime_must_set(tmp_path):
    f = tmp_path / "rules-code.yml"
    f.write_text(GOOD_RULES)
    doc = json.loads(run("--kind", "rules", str(f), "--json", path_dir=loader(tmp_path)).stdout)
    assert doc["locale_env"]["LC_ALL"] == "C.UTF-8"


# --- commented-out and shape ------------------------------------------------


def test_a_fully_commented_out_rule_is_reported_as_never_having_existed(tmp_path):
    # pv-react-table-not-virtualized shipped this way and was recorded as skipped/INVALID
    # rather than as a rule that never existed. It is valid YAML and loads zero rules.
    f = tmp_path / "rules-code-frontend-ts.yml"
    f.write_text("rules:\n" + "".join(f"# {ln}\n" for ln in GOOD_RULES.splitlines()[1:]))
    p = run("--kind", "rules", str(f), "--json", path_dir=loader(tmp_path))
    assert p.returncode == 1
    assert checks(p.stdout)["not_commented_out"] == "fail"
    assert "NEVER EXISTED" in p.stdout


def test_a_rules_file_with_no_rules_key_fails_the_shape_check(tmp_path):
    f = tmp_path / "rules-code.yml"
    f.write_text("- id: orphan\n  pattern: $X\n")
    p = run("--kind", "rules", str(f), "--json", path_dir=loader(tmp_path))
    assert p.returncode == 1
    assert checks(p.stdout)["shape"] == "fail"
    assert "no top-level `rules:` key" in p.stdout


def test_tab_indentation_fails_the_shape_check(tmp_path):
    f = tmp_path / "rules-code.yml"
    f.write_text("rules:\n\t- id: tabbed\n\t  pattern: $X\n")
    p = run("--kind", "rules", str(f), "--json", path_dir=loader(tmp_path))
    assert p.returncode == 1
    assert "tab indentation" in p.stdout


def test_a_commented_out_rule_and_a_live_rule_together_pass_the_comment_check(tmp_path):
    f = tmp_path / "rules-code.yml"
    f.write_text(GOOD_RULES + "#  - id: pv-disabled\n#    pattern: $Y\n")
    p = run("--kind", "rules", str(f), "--json", path_dir=loader(tmp_path))
    assert checks(p.stdout)["not_commented_out"] == "pass"


# --- tool load --------------------------------------------------------------


def test_an_absent_scanner_is_unvalidated_and_never_a_pass(tmp_path):
    f = tmp_path / "rules-code.yml"
    f.write_text(GOOD_RULES)
    empty_path = tmp_path / "emptybin"
    empty_path.mkdir()
    p = run("--kind", "rules", str(f), "--json", path_dir=empty_path)
    assert p.returncode == 3
    assert checks(p.stdout)["tool_load"] == "unvalidated"


def test_a_scanner_loading_zero_rules_fails(tmp_path):
    f = tmp_path / "rules-code.yml"
    f.write_text(GOOD_RULES)
    bindir = tmp_path / "bin"
    stub(bindir, "opengrep", 'echo "Configuration is valid - found 0 rules"\nexit 0\n')
    p = run("--kind", "rules", str(f), "--json", path_dir=bindir)
    assert p.returncode == 1
    assert checks(p.stdout)["tool_load"] == "fail"


def test_a_scanner_exiting_zero_with_no_rule_count_fails_closed(tmp_path):
    # rc=0 is not evidence the tool accepted the file.
    f = tmp_path / "rules-code.yml"
    f.write_text(GOOD_RULES)
    bindir = tmp_path / "bin"
    stub(bindir, "opengrep", "exit 0\n")
    p = run("--kind", "rules", str(f), "--json", path_dir=bindir)
    assert p.returncode == 1
    assert "no loaded-rule count" in p.stdout


def test_a_scanner_rejecting_the_file_fails_with_its_output(tmp_path):
    f = tmp_path / "rules-code.yml"
    f.write_text(GOOD_RULES)
    bindir = tmp_path / "bin"
    stub(bindir, "opengrep", 'echo "invalid rule schema: missing message" >&2\nexit 2\n')
    p = run("--kind", "rules", str(f), "--json", path_dir=bindir)
    assert p.returncode == 1
    assert "missing message" in p.stdout


def test_a_valid_rule_file_the_tool_loads_passes_every_check(tmp_path):
    f = tmp_path / "rules-code.yml"
    f.write_text(GOOD_RULES)
    bindir = tmp_path / "bin"
    stub(bindir, "opengrep", 'echo "Configuration is valid - found 1 valid rule"\nexit 0\n')
    p = run("--kind", "rules", str(f), "--json", path_dir=bindir)
    assert p.returncode == 0
    assert set(checks(p.stdout).values()) == {"pass"}


def test_semgrep_is_the_fallback_when_opengrep_is_absent(tmp_path):
    f = tmp_path / "rules-code.yml"
    f.write_text(GOOD_RULES)
    bindir = tmp_path / "bin"
    stub(bindir, "semgrep", 'echo "found 2 rules"\nexit 0\n')
    p = run("--kind", "rules", str(f), "--json", path_dir=bindir)
    assert p.returncode == 0
    assert "semgrep loaded 2" in p.stdout


# --- json artifacts ---------------------------------------------------------


def test_unparseable_scanner_json_fails(tmp_path):
    f = tmp_path / "opengrep-code.json"
    f.write_text("{truncated")
    p = run("--kind", "json", str(f), "--json")
    assert p.returncode == 1
    assert checks(p.stdout)["shape"] == "fail"


def test_json_parsing_to_an_empty_document_is_not_executed_not_zero_findings(tmp_path):
    # A spurious iteration blanked an ast-grep output, which read as 0 findings for its
    # injection rule.
    f = tmp_path / "astgrep-code.json"
    f.write_text("[]")
    p = run("--kind", "json", str(f), "--json")
    assert p.returncode == 1
    assert "NOT EXECUTED" in p.stdout


def test_a_real_scanner_json_document_passes(tmp_path):
    f = tmp_path / "opengrep-code.json"
    f.write_text(json.dumps({"results": [{"check_id": "x"}], "errors": []}))
    assert run("--kind", "json", str(f), "--json").returncode == 0


# --- harness buildability ---------------------------------------------------


def test_a_python_harness_that_does_not_compile_fails(tmp_path):
    f = tmp_path / "harness_parse.py"
    f.write_text("def go(:\n    pass\n")
    p = run("--kind", "harness", str(f), "--json")
    assert p.returncode == 1
    assert checks(p.stdout)["compiles"] == "fail"
    assert "coverage gap reported as coverage" in p.stdout


def test_a_python_harness_that_compiles_passes(tmp_path):
    f = tmp_path / "harness_parse.py"
    f.write_text("def go(data: bytes) -> None:\n    bytes(data)\n")
    p = run("--kind", "harness", str(f), "--json")
    assert p.returncode == 0
    assert checks(p.stdout)["compiles"] == "pass"


def test_a_rust_harness_with_no_cargo_manifest_above_it_fails(tmp_path):
    f = tmp_path / "fuzz_targets" / "parse.rs"
    f.parent.mkdir()
    f.write_text("fn main() {}\n")
    p = run("--kind", "harness", str(f), "--json")
    assert p.returncode == 1
    assert "no Cargo.toml" in p.stdout


def test_a_harness_in_an_unknown_language_is_unvalidated_not_a_pass(tmp_path):
    f = tmp_path / "harness.zig"
    f.write_text("pub fn main() void {}\n")
    p = run("--kind", "harness", str(f), "--json")
    assert p.returncode == 3
    assert checks(p.stdout)["compiles"] == "unvalidated"


def test_a_go_harness_without_an_image_is_unvalidated_not_a_pass(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n")
    f = tmp_path / "harness.go"
    f.write_text("package main\n")
    empty_path = tmp_path / "emptybin"
    empty_path.mkdir()
    p = run("--kind", "harness", str(f), "--json", path_dir=empty_path)
    assert p.returncode == 3
    assert checks(p.stdout)["compiles"] == "unvalidated"


def test_a_rust_build_check_never_runs_cargo_on_the_host(tmp_path):
    # `cargo check` runs build.rs and proc macros, and SKILL.md's hard rules put every
    # build-script execution in a container. The old check ran it wherever it was called.
    crate = tmp_path / "fuzz"
    (crate / "fuzz_targets").mkdir(parents=True)
    (crate / "Cargo.toml").write_text("[package]\nname='f'\n")
    f = crate / "fuzz_targets" / "parse.rs"
    f.write_text("fn main() {}\n")
    marker = tmp_path / "cargo-ran"
    bindir = tmp_path / "bin"
    stub(bindir, "cargo", f'touch "{marker}"\nexit 0\n')
    p = run("--kind", "harness", str(f), "--json",
            path_dir=Path(f"{bindir}:{os.environ['PATH']}"))
    assert p.returncode == 3, p.stdout
    assert checks(p.stdout)["compiles"] == "unvalidated"
    assert not marker.exists(), "cargo ran on the host"


def _module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("validate_generated", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_contained_builds_use_the_package_context(tmp_path):
    # A single-file `go vet x.go` or `tsc x.ts` rejects a harness that imports siblings.
    mod = _module()
    (tmp_path / "go.mod").write_text("module x\n")
    (tmp_path / "pkg" / "fz").mkdir(parents=True)
    go = tmp_path / "pkg" / "fz" / "h.go"
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "tsconfig.json").write_text("{}")
    (tmp_path / "web" / "src").mkdir()
    ts = tmp_path / "web" / "src" / "h.ts"
    (tmp_path / "Cargo.toml").write_text("[package]\nname='x'\n")
    (tmp_path / "fuzz_targets").mkdir()
    rs = tmp_path / "fuzz_targets" / "p.rs"
    assert mod.contained_build(go, tmp_path)[0] == "cd /target && go vet ./pkg/fz"
    assert mod.contained_build(ts, tmp_path)[0] == "tsc --noEmit -p /target/web"
    assert mod.contained_build(rs, tmp_path)[0] == (
        "cargo check --quiet --offline --manifest-path /target/Cargo.toml")


def test_a_contained_build_keeps_a_hostile_path_one_argument(tmp_path):
    # The command runs under `sh -c`. An unquoted `bad; true; #` directory split it into
    # a failing cargo check, then `true`, so the shell exited 0 and the check read PASS.
    import shlex
    mod = _module()
    crate = tmp_path / "bad; true; #"
    (crate / "fuzz_targets").mkdir(parents=True)
    (crate / "Cargo.toml").write_text("[package]\nname='x'\n")
    (crate / "go.mod").write_text("module x\n")
    (crate / "tsconfig.json").write_text("{}")
    cmd = mod.contained_build(crate / "fuzz_targets" / "p.rs", tmp_path)[0]
    assert shlex.split(cmd)[-1] == "/target/bad; true; #/Cargo.toml"
    cmd = mod.contained_build(crate / "fuzz_targets" / "h.go", tmp_path)[0]
    assert shlex.split(cmd)[:2] == ["cd", "/target/bad; true; #"]
    cmd = mod.contained_build(crate / "fuzz_targets" / "h.ts", tmp_path)[0]
    assert shlex.split(cmd)[-1] == "/target/bad; true; #"


def test_an_explicitly_empty_seed_is_accepted(tmp_path):
    # An empty input is a legitimate parser test and a legitimate minimal reproducer.
    seed = tmp_path / "empty.input"
    seed.write_bytes(b"")
    p = run("--kind", "input", str(seed), "--allow-empty", "--json")
    assert p.returncode == 0, p.stdout
    assert checks(p.stdout)["non_empty"] == "pass"


def test_allow_empty_does_not_excuse_an_empty_harness(tmp_path):
    f = tmp_path / "h.py"
    f.write_bytes(b"")
    p = run("--kind", "harness", str(f), "--allow-empty", "--json")
    assert p.returncode == 1
    assert checks(p.stdout)["non_empty"] == "fail"


# --- reporting --------------------------------------------------------------


def test_the_json_report_names_the_failing_check(tmp_path):
    f = tmp_path / "rules-code.yml"
    f.write_text("# rules:\n#   - id: only-a-comment\n")
    doc = json.loads(run("--kind", "rules", str(f), "--json", path_dir=loader(tmp_path)).stdout)
    assert doc["ok"] is False
    assert doc["exit_code"] == 1
    failing = [c["check"] for c in doc["checks"] if c["status"] == "fail"]
    assert "not_commented_out" in failing


def test_text_mode_says_invalid_on_stderr(tmp_path):
    f = tmp_path / "crash.input"
    f.write_bytes(b"")
    p = run("--kind", "corpus", str(f))
    assert "INVALID" in p.stderr


def test_text_mode_distinguishes_unvalidated_from_invalid(tmp_path):
    f = tmp_path / "rules-code.yml"
    f.write_text(GOOD_RULES)
    empty_path = tmp_path / "emptybin"
    empty_path.mkdir()
    p = run("--kind", "rules", str(f), path_dir=empty_path)
    assert p.returncode == 3
    assert "UNVALIDATED" in p.stderr
    assert "never as valid" in p.stderr


def test_semantics_are_declared_out_of_scope(tmp_path):
    f = tmp_path / "seed.input"
    f.write_bytes(b"x")
    doc = json.loads(run("--kind", "corpus", str(f), "--json").stdout)
    assert "control" in doc["semantics"]
