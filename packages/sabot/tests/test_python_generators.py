#!/usr/bin/env python3
"""Tests for the python surface's generator and reducer tier.

This tier carries the inverse of the usual false-clean. HypoFuzz constrains only a floor on
hypothesis, and a newer hypothesis crashed every worker while printing `Found a failing
input for every test!` on a test with no bug in it: a fabricated finding, not a missed one.
So the pin and the two-directional probe are both asserted here.

Reads the Dockerfile and the matrix as text. No container, no network.

Run: pytest packages/sabot/tests/test_python_generators.py
"""

from pathlib import Path

SKILL = Path(__file__).resolve().parents[1] / ".apm/skills/sabotage"
DOCKERFILE = SKILL / "references/containers/Dockerfile.python"
MATRIX = SKILL / "references/tool-coverage-matrix.md"
BODY = DOCKERFILE.read_text()
# Join continuations first: these invocations span lines, so a per-line search reports a
# flag missing that is present on the next one.
JOINED = BODY.replace("\\\n", " ")


def test_generator_tier_is_pinned():
    for pin in (
        "hypofuzz==25.11.1",
        "schemathesis==4.24.3",
        "grammarinator==26.1",
        "shrinkray==26.7.6.1",
    ):
        assert pin in BODY, f"{pin} is unpinned; a campaign stops being reproducible"


def test_hypothesis_is_repinned_below_the_breaking_release():
    """HypoFuzz sets only `>=6.140.2`, so an unpinned resolve takes a version that crashes
    it. The pin is what keeps the fuzzer working, so it may not be dropped silently."""
    assert "'hypothesis[cli,watchdog]==6.145.1'" in BODY
    assert "slice_comments" in BODY, \
        "the pin needs the upstream AttributeError recorded, or it reads as arbitrary"


def test_shrinkray_pin_records_the_llama_dependency():
    assert "llama-cpp-python" in BODY
    assert "26.7.7.0" in BODY, "the comment must name the release that introduced it"


def test_hypofuzz_probe_runs_in_both_directions():
    """One direction alone passes on a crashed worker: the broken pin found nothing AND
    claimed a failure."""
    assert "test_clean.py" in BODY and "test_seeded.py" in BODY
    assert "Found a failing input" in JOINED, \
        "without this check the false-positive direction goes unnoticed"
    assert "Falsifying example: test_seeded" in JOINED, \
        "the seeded counterexample must be shown to replay, not merely to be reported"


def test_hypofuzz_clean_property_is_unfalsifiable():
    """`st.integers()` is unbounded, so a bound like `n < 10**9` is a real bug and the
    probe fails on a healthy install."""
    assert "assert isinstance(n, int)" in BODY
    clean_probe = JOINED.split("test_clean.py")[0].rsplit("printf", 1)[-1]
    assert "10**9" not in clean_probe, "a bounded property makes this probe self-failing"
    assert "st.integers()` is" in BODY, "the reason must stay recorded next to the probe"


def test_hypofuzz_probe_greps_attributeerror_not_traceback():
    """Killing the fuzzer under `timeout` always leaves multiprocessing teardown
    tracebacks, so a Traceback check fails on every healthy run."""
    assert "grep -q 'AttributeError' clean.log" in JOINED
    assert "grep -qi 'AttributeError\\|Traceback'" not in JOINED
    assert "Finalize object" in BODY, "the reason for the narrower grep must stay recorded"


def test_grammarinator_probe_sets_pythonpath():
    """grammarinator-generate imports the processed grammar as a module, so without the
    output directory on PYTHONPATH it fails ModuleNotFoundError."""
    assert "PYTHONPATH=. grammarinator-generate" in JOINED
    assert "ModuleNotFoundError" in BODY


def test_grammarinator_probe_checks_the_output_matches_the_grammar():
    """A generator that emits empty files passes a `test -s` on nothing useful."""
    assert "grep -qE '^[ab]+$'" in JOINED, \
        "assert the output is in the grammar's language, not merely non-empty"


def test_grammarinator_output_template_is_not_double_escaped():
    """`%%d` in a RUN is passed through literally, so grammarinator writes one file named
    `out_%%d.txt` and the three-file loop fails."""
    assert "-o out_%d.txt" in JOINED
    assert "out_%%d.txt" not in BODY


def test_dharma_probe_uses_a_bundled_grammar():
    """Using the shipped grammar tree proves the install carried it, and avoids failing on
    hand-written grammar syntax."""
    assert "dist-packages/dharma/grammars/json.dg" in JOINED


def test_shrinkray_probe_requires_real_reduction():
    """A reducer that returns its input unchanged turns a campaign into a single-input
    test (the radamsa/zzuf lesson)."""
    assert 'test "$(wc -c < big.txt)" -lt 30' in JOINED


def test_semgrep_is_not_installed():
    """install-tools.sh dropped semgrep because opengrep in the base gave the same
    output, yet this image still installed and asserted it."""
    assert "semgrep" not in JOINED.replace("semgrep was dropped", "")


def test_first_tier_and_atheris_are_pinned():
    for pin in ("'hypothesis==6.145.1'", "bandit==", "ruff==", "atheris=="):
        assert pin in JOINED, f"{pin} is unpinned; a campaign stops being reproducible"


def test_hypofuzz_replay_generates_nothing():
    """A plain pytest replay finds n=0 for `assert n != 0` by its own generation, so it
    passed whether or not HypoFuzz saved anything. Only a reuse-only replay reads the
    saved example and nothing else."""
    assert "[Phase.reuse] if os.environ.get(\"SABOT_REPLAY_ONLY\")" in JOINED
    assert "! SABOT_REPLAY_ONLY=1 pytest -q test_seeded.py" in JOINED


def test_matrix_records_the_measured_results():
    matrix = MATRIX.read_text()
    for claim in (
        "hypothesis pin MUST be held",
        "registers `hypothesis fuzz`",
        "3 unique failures offline",
        "No module named 'TGenerator'",
        "167 bytes of generated JSON",
        "60 bytes down to 11 offline",
    ):
        assert claim in matrix, f"matrix does not record: {claim}"


def test_matrix_records_the_false_positive():
    """This tier's defect is a fabricated finding, and the matrix hunts false cleans, so
    the inverted case has to be spelled out or a reader will not expect it."""
    matrix = MATRIX.read_text()
    assert "FALSE POSITIVE" in matrix
    assert "reports a defect that is not" in matrix
