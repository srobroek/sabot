"""lint-recipes.py rejects invocations measured to return a clean result while running less
than they reported, or nothing at all.

Every rule below was copied verbatim from a reference by an agent and produced a false
clean. One fixture per rule must be flagged and one working counter-example must not be.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SKILL = Path(__file__).resolve().parents[1] / ".apm" / "skills" / "sabotage"
SCRIPT = SKILL / "scripts" / "lint-recipes.py"

EXIT_VIOLATION = 1
EXIT_USAGE = 2

# (rule id, an invocation that must be flagged, an invocation that must not be)
CASES = [
    ("bd-plural-label",
     "bd list --labels sab-finding --json",
     "bd list --label sab-finding --json"),
    ("bd-set-metadata",
     """bd update $ID --set-metadata '{"tier":"PROVEN"}'""",
     """bd update $ID --metadata '{"tier":"PROVEN"}'"""),
    ("cargo-test-fail-fast",
     "cargo test --workspace",
     "cargo test --workspace --no-fail-fast"),
    ("cargo-locked",
     "cargo build --locked --release",
     "cargo build --release"),
    ("gitleaks-git-mode",
     "gitleaks detect --source . --report-format json",
     "gitleaks dir . --report-format json"),
    ("opengrep-config-auto",
     "opengrep scan --config auto --json .",
     "opengrep scan --config /opt/rules --json ."),
    ("opengrep-metrics",
     "opengrep scan --config /opt/rules --metrics off .",
     "opengrep scan --config /opt/rules ."),
    ("login-shell",
     "bash -lc 'echo hello'",
     "bash -c 'echo hello'"),
    ("tee-swallows-status",
     "cargo check | tee /artifacts/check.log",
     "cargo check > /artifacts/check.log 2>&1"),
    ("rm-rf-unexpanded",
     'rm -rf "$WORKDIR"',
     "rm -rf /artifacts/.build/incremental"),
    ("shared-cargo-target",
     "CARGO_TARGET_DIR=/tmp/shared-target cargo build",
     "CARGO_TARGET_DIR=$SABOT_BUILD_DIR cargo build"),
]


def run(*args: str):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True
    )


def lint(tmp_path: Path, text: str, name: str = "recipe.sh"):
    f = tmp_path / name
    f.write_text(text if text.endswith("\n") else text + "\n")
    p = run(str(f), "--json")
    return p, json.loads(p.stdout)["violations"]


@pytest.mark.parametrize("rule,bad,_good", CASES, ids=[c[0] for c in CASES])
def test_each_rule_flags_its_measured_invocation(tmp_path, rule, bad, _good):
    p, hits = lint(tmp_path, bad)
    assert p.returncode == EXIT_VIOLATION
    assert rule in {h["rule"] for h in hits}, hits


@pytest.mark.parametrize("rule,_bad,good", CASES, ids=[c[0] for c in CASES])
def test_the_working_form_of_each_invocation_is_clean(tmp_path, rule, _bad, good):
    p, hits = lint(tmp_path, good)
    assert rule not in {h["rule"] for h in hits}, hits


def test_a_clean_file_exits_0(tmp_path):
    p, hits = lint(tmp_path, "cargo test --workspace --no-fail-fast\ngitleaks dir .\n")
    assert p.returncode == 0
    assert hits == []


def test_a_nonexistent_path_is_a_usage_error(tmp_path):
    assert run(str(tmp_path / "nope.sh")).returncode == EXIT_USAGE


def test_json_names_the_rule_the_line_and_the_symptom(tmp_path):
    p, hits = lint(tmp_path, "true\nbd list --labels sab-finding\n")
    assert p.returncode == EXIT_VIOLATION
    hit = next(h for h in hits if h["rule"] == "bd-plural-label")
    assert hit["line"] == 2
    assert hit["file"].endswith("recipe.sh")
    # The message names the observable symptom, because a lint that only says "forbidden"
    # gets suppressed rather than fixed.
    assert "silently" in hit["why"].lower()
    assert json.loads(p.stdout)["schema"] == "sabot-recipe-lint/1"


def test_the_allow_marker_exempts_a_documented_counter_example(tmp_path):
    # The lint's own source and the reference prose have to name the bad invocation in
    # order to forbid it.
    p, hits = lint(tmp_path, "bd list --labels sab-finding  # lint-recipes: allow\n")
    assert p.returncode == 0
    assert hits == []


def test_human_output_prints_the_symptom_under_each_hit(tmp_path):
    f = tmp_path / "recipe.sh"
    f.write_text("cargo test --workspace\n")
    p = run(str(f))
    assert p.returncode == EXIT_VIOLATION
    assert "cargo-test-fail-fast" in p.stdout
    assert "3 of 22" in p.stdout
    assert "1 violation(s)" in p.stdout


def test_a_directory_is_walked_and_skip_dirs_are_ignored(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hook.sh").write_text("cargo test\n")
    (tmp_path / "ok.sh").write_text("cargo test --no-fail-fast\n")
    p = run(str(tmp_path), "--json")
    assert p.returncode == 0
    assert json.loads(p.stdout)["violations"] == []


def test_the_shipped_skill_and_agents_pass_their_own_lint():
    # The package ships the recipes this linter forbids unless its own tree is held to
    # them: `--metrics off` as a MUST, `cargo test` without --no-fail-fast in three run
    # recipes, and gosec piped through tee were all live in the shipped references.
    p = run(str(SKILL), str(SKILL.parents[1] / "agents"), "--json")
    assert p.returncode == 0, p.stdout
    assert json.loads(p.stdout)["violations"] == []


def test_every_self_hit_on_the_rule_table_sits_on_a_pattern_or_message_line(tmp_path):
    # The linter's own rule table has to name each bad invocation in order to forbid it,
    # so a self-hit is expected. It must land on the table, not on an executable recipe:
    # a hit anywhere else means the linter itself ships one of these invocations.
    p = run(str(SCRIPT), "--json")
    body = SCRIPT.read_text().splitlines()
    for hit in json.loads(p.stdout)["violations"]:
        line = body[hit["line"] - 1].lstrip()
        assert line.startswith(('r"', '"', "'")), hit


# --- recipe context: a lint that is mostly noise gets suppressed ---------------


def test_a_markdown_table_row_forbidding_an_invocation_is_not_an_instance_of_it(tmp_path):
    # The first real-tree pass reported 54 violations of which 40 were the documentation
    # of the rules themselves. Suppressing a whole rule set because it cries wolf is the
    # same fail-open the rules exist to close.
    doc = tmp_path / "surfaces.md"
    doc.write_text(
        "| `gitleaks detect` | never: git mode on a worktree sees 0 commits |\n"
        "MUST NOT pass `--config auto`, since stock packs cannot load offline.\n"
    )
    assert run(str(doc), "--json").returncode == 0


def test_a_fenced_recipe_in_the_same_file_is_still_flagged(tmp_path):
    doc = tmp_path / "surfaces.md"
    doc.write_text(
        "Prose naming `gitleaks detect` to forbid it.\n\n"
        "```sh\ngitleaks detect --report-format json\n```\n"
    )
    hits = json.loads(run(str(doc), "--json").stdout)["violations"]
    assert [h["rule"] for h in hits] == ["gitleaks-git-mode"]
    assert hits[0]["line"] == 4


def test_include_prose_still_shows_every_mention(tmp_path):
    doc = tmp_path / "surfaces.md"
    doc.write_text("| `gitleaks detect` | never |\n")
    assert run(str(doc), "--json").returncode == 0
    hits = json.loads(run(str(doc), "--json", "--include-prose").stdout)["violations"]
    assert [h["rule"] for h in hits] == ["gitleaks-git-mode"]


def test_a_shell_comment_explaining_a_rule_is_not_a_recipe(tmp_path):
    script = tmp_path / "wrap.sh"
    script.write_text(
        "# `cmd | tee log` discards the failure, so this writes to a file instead\n"
        "cmd > log 2>&1\n"
    )
    assert run(str(script), "--json").returncode == 0


def test_a_commented_recipe_is_still_caught_with_include_prose(tmp_path):
    script = tmp_path / "wrap.sh"
    script.write_text("# cargo test --workspace\n")
    assert json.loads(run(str(script), "--json", "--include-prose").stdout)["violations"]


def rules_hit(tmp_path: Path, text: str, name: str = "surface.md") -> list[str]:
    doc = tmp_path / name
    doc.write_text(text)
    return [h["rule"] for h in json.loads(run(str(doc), "--json").stdout)["violations"]]


RECIPE_TABLE = ("| Tool | Tier | Run recipe | Catches |\n"
                "|------|------|-----------|---------|\n")


def test_a_run_recipe_table_cell_is_a_recipe(tmp_path):
    # The surface docs keep their commands in a Run recipe column. Skipping every table
    # skipped exactly the cells an agent copies.
    row = "| opengrep | default-on | `opengrep scan --metrics off --config /opt/r .` | SAST |\n"
    assert rules_hit(tmp_path, RECIPE_TABLE + row) == ["opengrep-metrics"]


def test_a_piped_recipe_in_a_cell_stays_one_cell(tmp_path):
    row = "| ruff | default-on | `ruff check . | tee /artifacts/r.log` | lint |\n"
    assert rules_hit(tmp_path, RECIPE_TABLE + row) == ["tee-swallows-status"]


def test_a_table_column_that_is_not_a_recipe_is_still_prose(tmp_path):
    text = ("| Tool | Notes |\n|---|---|\n"
            "| opengrep | `opengrep scan --metrics off` exits 2, so never pass it |\n")
    assert rules_hit(tmp_path, text) == []


def test_an_instruction_to_run_a_forbidden_flag_is_flagged(tmp_path):
    # `MUST Pass --metrics off` instructed the very invocation the lint forbids.
    assert rules_hit(tmp_path, "MUST Pass `--metrics off`. Four nodes measured it.\n") == [
        "opengrep-metrics"]


def test_only_the_imperative_sentence_of_an_instruction_is_a_recipe(tmp_path):
    # The sentences after a MUST explain it, and often quote the failure they prevent.
    text = ("MUST Run `cargo test --no-fail-fast --manifest-path /target/Cargo.toml`. A "
            "`cargo test` without it stops at the first failing binary.\n")
    assert rules_hit(tmp_path, text) == []


def test_a_prohibition_inside_a_fenced_spawn_prompt_is_prose(tmp_path):
    # A brief is often a fenced prompt; its NOT lines forbid, they do not run.
    text = ("```\nYou triage crashes.\n"
            "NOT Never run `cargo test --workspace` without the fail-fast flag off.\n```\n")
    assert rules_hit(tmp_path, text) == []


@pytest.mark.parametrize("guarded", [
    'rm -rf "${CTX:?}"',
    "rm -rf ${probe:?}/out",
    'cleanup() { rm -rf "${STAGE:?}"; :; }',
])
def test_a_colon_question_guarded_delete_is_validated_not_unexpanded(tmp_path, guarded):
    # `${VAR:?}` aborts the shell when VAR is unset or empty: the path cannot collapse.
    assert rules_hit(tmp_path, guarded + "\n", name="layer.sh") == []


@pytest.mark.parametrize("unsafe", [
    'rm -rf "${CTX}"',
    'rm -rf "${CTX?}/x"',
    'rm -rf "${a:?}" "$b"',
    'rm -rf -- "$(mktemp -d)"',
])
def test_an_unguarded_expansion_in_any_argument_is_still_flagged(tmp_path, unsafe):
    assert rules_hit(tmp_path, unsafe + "\n", name="layer.sh") == ["rm-rf-unexpanded"]


# --- rule precision -----------------------------------------------------------


def test_cargo_install_locked_is_correct_and_not_flagged(tmp_path):
    # Pinning a TOOL build with --locked is right; the hazard is --locked on the target's
    # own workspace, which fails before compilation and reads as zero findings.
    script = tmp_path / "layer.sh"
    script.write_text('cargo install cargo-fuzz --locked --version "$V"\n')
    assert run(str(script), "--json").returncode == 0


def test_locked_on_the_targets_workspace_is_still_flagged(tmp_path):
    script = tmp_path / "layer.sh"
    script.write_text("cargo check --workspace --locked\n")
    hits = json.loads(run(str(script), "--json").stdout)["violations"]
    assert [h["rule"] for h in hits] == ["cargo-locked"]


def test_gitleaks_detect_no_git_is_filesystem_mode_and_not_flagged(tmp_path):
    script = tmp_path / "scan.sh"
    script.write_text("gitleaks detect --no-git --report-format json\n")
    assert run(str(script), "--json").returncode == 0
