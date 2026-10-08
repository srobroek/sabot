#!/usr/bin/env python3
"""Tests for the node surface, guarding the two ways its fuzzer has shipped unrunnable.

Jazzer.js has now been installed, asserted, and unable to fuzz twice: first the arm64
prebuilt addon failed at dlopen behind a passing `jazzer --version` (bs-156), then a global
npm install nested the @jazzer.js peers where core does not look for them. Both times the
image reported the fuzzer present. So the build must assert a CRASH, not a version string.

Reads the Dockerfile as text. No container, no network.

Run: pytest packages/sabot/tests/test_node_surface.py
"""

import re
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1] / ".apm/skills/sabotage"
DOCKERFILE = SKILL / "references/containers/Dockerfile.node"
MATRIX = SKILL / "references/tool-coverage-matrix.md"
BODY = DOCKERFILE.read_text()


def test_jazzer_is_not_installed_globally():
    """`npm i -g @jazzer.js/core` nests the peers under core/node_modules/.

    Measured, core resolves them as SIBLINGS, so every run died before its first input:
    "ENOENT ... @jazzer.js/bug-detectors/dist/internal", while --version still answered.
    """
    # Anchored past a leading `RUN` or `&&`, not a bare substring: the rationale comment
    # below quotes the broken command verbatim, so an unanchored search flags its own docs.
    globals_ = re.findall(r"^\s*(?:RUN\s+|&&\s*)?npm i -g ([^\\\n]*)", BODY, re.M)
    assert globals_, "the image still installs something globally; check this test"
    for line in globals_:
        assert "jazzer" not in line, \
            "a global install puts the @jazzer.js peers where core cannot find them"


def test_jazzer_is_installed_into_a_prefix_dir_and_symlinked():
    assert "/opt/jazzer" in BODY, "install locally so the @jazzer.js peers stay siblings"
    assert re.search(r"npm i @jazzer\.js/core", BODY), "a LOCAL install, not -g"
    assert "ln -sf /opt/jazzer/node_modules/.bin/jazzer /usr/local/bin/jazzer" in BODY, \
        "the campaign invokes `jazzer`, so the local binary needs to be on PATH"


def test_the_sibling_layout_is_asserted_not_assumed():
    assert "test -d /opt/jazzer/node_modules/@jazzer.js/bug-detectors/dist/internal" in BODY, \
        "assert the exact path whose absence killed every run"


def test_the_build_requires_a_real_crash_not_a_version_string():
    """--version answered in BOTH failure modes, so it proves nothing about fuzzing."""
    assert "grep -q 'Uncaught Exception'" in BODY, \
        "the build must fuzz a seeded target and require the crash report"
    assert "-runs=" in BODY, "run the fuzzer, do not just load it"


def test_retire_is_still_pinned_by_sha_and_baked():
    """retire.js fetches its definitions per run; unbaked it finds nothing offline."""
    assert "RETIREJS_SHA=" in BODY
    assert "jsrepository-v5.json" in BODY


def test_jazzer_tmpdir_dependency_is_recorded():
    """Under --read-only with no writable TMPDIR it exits 77 and prints no crash at all.

    The wrapper supplies TMPDIR=/scratch/tmp, so the shipped path works; the risk is a
    hand-rolled docker run, where a found bug is reported as three lines of INFO noise.
    """
    matrix = MATRIX.read_text()
    assert re.search(r"writable\s+`?TMPDIR`?", matrix, re.I), \
        "record the TMPDIR dependency: without it a real crash reports as noise"
    wrapper = (SKILL / "scripts/run-contained.sh").read_text()
    assert "TMPDIR=/scratch/tmp" in wrapper, "the wrapper must supply a writable TMPDIR"


def test_measured_fixture_results_are_recorded():
    matrix = MATRIX.read_text()
    for tool in ("Jazzer.js", "fast-check"):
        row = next(l for l in matrix.splitlines() if l.startswith(f"| {tool} "))
        assert "VERIFIED" in row, f"{tool} ran against node-parser; record the measurement"


def test_eslint_plugin_is_pinned_with_renovate_lines():
    """The plugin's peer range is `eslint: ^9 || ^10`, so both sides need a pin."""
    for pin in ("ARG ESLINT_VERSION=9.39.5", "ARG NO_UNSANITIZED_VERSION=4.1.5"):
        assert pin in BODY, f"missing {pin}"
    assert "# renovate: datasource=npm depName=eslint\n" in BODY
    assert "# renovate: datasource=npm depName=eslint-plugin-no-unsanitized\n" in BODY


def test_eslint_config_imports_the_plugin_by_absolute_path():
    """Flat config is an ES module and ESM resolution ignores NODE_PATH, so a bare import
    fails from any directory outside the install prefix."""
    joined = BODY.replace("\\\n", " ")
    assert "/opt/eslint/node_modules/eslint-plugin-no-unsanitized/index.js" in joined
    assert "ERR_MODULE_NOT_FOUND" in BODY, \
        "the reason for the absolute path must stay recorded"


def test_eslint_probe_requires_both_rules_to_report():
    """A plugin that loads while contributing no rules leaves eslint exiting 0 on a file
    with two XSS sinks in it."""
    joined = BODY.replace("\\\n", " ")
    assert "grep -q 'no-unsanitized/property'" in joined
    assert "grep -q 'no-unsanitized/method'" in joined
    assert "innerHTML" in BODY and "document.write" in BODY


def test_eslint_runs_with_no_config_lookup():
    """Without it eslint walks up from the target, and a config in the target repo replaces
    these two rules: a scan that exits cleanly having checked something else."""
    joined = BODY.replace("\\\n", " ")
    assert "--no-config-lookup" in joined
    assert "sabot.config.mjs" in joined


def test_matrix_records_retire_scans_installed_code():
    """A `package.json` with no node_modules beside it produced exit 0 and no findings on
    three known-vulnerable pins."""
    matrix = MATRIX.read_text()
    assert "scans INSTALLED `node_modules`, NOT declared dependencies" in matrix
    assert "15 vulnerable-component reports offline" in matrix
    assert "zero SCANNED rather than" in matrix


def test_matrix_records_the_eslint_measurement():
    matrix = MATRIX.read_text()
    assert "ABSOLUTE PATH (ESM ignores `NODE_PATH`)" in matrix
    assert "no-unsanitized/method` on `document.write`" in matrix


def test_the_node_image_is_built_on_the_shared_base():
    """FROM node:22 discarded the base, so gitleaks, opengrep, trivy and the baked DBs were
    absent from an image documented as base + node."""
    froms = re.findall(r"^FROM\s+(\S+)(?:\s+AS\s+(\S+))?", BODY, re.MULTILINE)
    assert froms, "Dockerfile.node has no FROM"
    final_image, final_alias = froms[-1]
    assert final_image == "${BASE}" and not final_alias, \
        f"the final stage must be FROM ${{BASE}}, got FROM {final_image}"
    assert re.search(r"^ARG BASE=sabot/base:1$", BODY, re.MULTILINE)
    # Node is copied in from a named stage, never inherited from it.
    stages = {alias for _, alias in froms if alias}
    for alias in stages:
        assert f"COPY --from={alias} " in BODY, f"stage {alias} is declared but never used"
    assert "COPY --from=node /usr/local/bin/node " in BODY
    assert "USER breaker" in BODY, "run as the base's uid-1000 user"
