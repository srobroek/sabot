#!/usr/bin/env python3
"""report-json.py must rank, dedup, and group mechanically rather than editorially.

One run produced ~251 findings with no ranking or dedup mechanism at all, and 224 loci
were collapsed onto a single boundary BY HAND. Its most valuable conclusion -- eight
independent built-but-never-wired instances -- was produced by no step at all. These
tests assert that the collapse, the ordering, the count balance, and the NOT-EXECUTED
register fall out of the bead graph.

Stdlib plus pytest only. No network, no bd.
"""

from __future__ import annotations

import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / ".apm" / "skills" / "sabotage" / "scripts" / "report-json.py"
)

FULL_FIELDS = {
    "run_id": "run-A", "tier": "PROVEN", "by": "challenger", "source": "harness",
    "impact": "HIGH", "locus": "a.rs:1", "surface": "code", "node": "e.1",
    "evidence": "/art/x.json", "control_passed": True,
    "dedup_key": "code:a.rs:1:cwe-190", "root_cause": "unchecked arithmetic",
    "not_executed_reason": None, "cwe": "CWE-190",
}


def finding(bid, **over):
    meta = dict(FULL_FIELDS)
    meta.update(over)
    return {
        "id": bid, "issue_type": "task", "title": over.pop("title", f"finding {bid}"),
        "status": "open", "metadata": meta,
        "labels": ["sab-finding", "sab-surface", "sab-audit"],
        "dependencies": [{"depends_on_id": "e.1", "type": "parent-child"}],
    }


def export(extra, threat="memory safety at the IPC boundary", coverage=True,
           surfaces=("code",)):
    lines = [{
        "_type": "issue", "id": "e", "issue_type": "epic", "title": "run",
        "status": "open",
        "metadata": {"run_id": "run-A", "target": "repo", "threat": threat},
    }]
    for i, name in enumerate(surfaces, 1):
        lines.append({
            "id": f"e.{i}", "issue_type": "task", "title": f"surface: {name}",
            "status": "open",
            "metadata": {"run_id": "run-A", "surface": name, "scope": ["**/*"]},
            "labels": ["sab-surface", "sab-audit", "non-work"],
            "dependencies": [{"depends_on_id": "e", "type": "parent-child"}],
        })
    if coverage:
        lines.append({
            "id": "e.1.90", "issue_type": "task", "title": "coverage", "status": "open",
            "metadata": {"run_id": "run-A", "surface": "code",
                         "scanners_run": ["opengrep"], "scanners_skipped": [],
                         "harnesses_run": 2, "harnesses_total": 2},
            "labels": ["sab-coverage", "sab-surface", "sab-audit", "non-work"],
            "dependencies": [{"depends_on_id": "e.1", "type": "parent-child"}],
        })
    return lines + list(extra)


@pytest.fixture
def bd_factory(tmp_path):
    def make(lines):
        jsonl = "\n".join(json.dumps(o) for o in lines)
        bd = tmp_path / "bd"
        bd.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"payload = {jsonl!r}\n"
            "if len(sys.argv) > 1 and sys.argv[1] == 'export':\n"
            "    print(payload)\n"
            "else:\n"
            "    sys.exit(0)\n"
        )
        bd.chmod(bd.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        return str(bd)
    return make


def report(bd_factory, lines, expect_rc=0):
    bd = bd_factory(lines)
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--bd", bd, "--run-id", "run-A"],
        capture_output=True, text=True,
    )
    assert r.returncode == expect_rc, r.stdout + r.stderr
    return json.loads(r.stdout), r


# --- dedup ------------------------------------------------------------------


def test_a_dedup_key_on_two_wisps_is_one_group_and_independent_confirmation(bd_factory):
    doc, _ = report(bd_factory, export([
        finding("e.1.1"),
        finding("e.1.2", by="self", source="stock-pack"),
    ]))
    assert len(doc["groups"]) == 1
    g = doc["groups"][0]
    assert g["instance_count"] == 2
    assert g["confirmed_independently"] is True
    assert sorted(g["instances"]) == ["e.1.1", "e.1.2"]


def test_a_group_reports_one_tier_the_strongest_any_instance_carries(bd_factory):
    # A group reported at its weakest instance understates what was proven.
    doc, _ = report(bd_factory, export([
        finding("e.1.1", tier="HARDENING"),
        finding("e.1.2", tier="PROVEN"),
    ]))
    g = doc["groups"][0]
    assert g["tier"] == "PROVEN"
    assert g["tiers_seen"] == ["HARDENING", "PROVEN"]


def test_a_derived_dedup_key_is_marked_as_derived(bd_factory):
    # The finder knows the class; a later pass reconstructing it from a title guesses, so
    # a group built on a fallback key must not read as the finder's judgment.
    doc, _ = report(bd_factory, export([finding("e.1.1", dedup_key=None)]))
    assert doc["groups"][0]["dedup_key_derived"] is True


def test_the_summary_counts_groups_resting_on_a_derived_key(bd_factory):
    """A per-group flag nothing totals is invisible in a 383-finding report.

    Measured: one campaign filed 383 findings and stamped `dedup_key` on none of them,
    so every group was built from a key this script reconstructed at report time and the
    challenger's prescribed `uniq -d` dedup returned nothing over seven real
    cross-surface duplicate loci. The per-group `dedup_key_derived` flag was already
    correct; nobody reading the summary could see that it was set everywhere.
    """
    doc, _ = report(bd_factory, export([
        finding("e.1.1", dedup_key=None),
        finding("e.1.2", dedup_key="code:b.rs:9:cwe-22", locus="b.rs:9"),
    ]))
    assert doc["summary"]["groups_on_a_derived_dedup_key"] == 1
    assert doc["summary"]["counts"]["groups"] == 2


def test_distinct_keys_stay_distinct_groups(bd_factory):
    doc, _ = report(bd_factory, export([
        finding("e.1.1", dedup_key="code:a.rs:1:cwe-190"),
        finding("e.1.2", dedup_key="code:b.rs:9:cwe-22", locus="b.rs:9"),
    ]))
    assert len(doc["groups"]) == 2


# --- ranking ----------------------------------------------------------------


def test_tier_outranks_impact(bd_factory):
    doc, _ = report(bd_factory, export([
        finding("e.1.1", tier="HARDENING", impact="CRITICAL",
                dedup_key="k1", locus="a.rs:1"),
        finding("e.1.2", tier="PROVEN", impact="LOW", dedup_key="k2", locus="b.rs:2"),
    ]))
    assert [g["dedup_key"] for g in doc["groups"]] == ["k2", "k1"]
    assert doc["groups"][0]["rank"] == 1


def test_the_epics_stamped_threat_orders_groups_that_tie(bd_factory):
    # The threat has been stamped since the interview and had never been used to order
    # anything, so a run aimed at one fear reported in bead order.
    doc, _ = report(bd_factory, export([
        finding("e.1.1", dedup_key="unrelated", root_cause="a slow loop",
                cwe="CWE-400", locus="z.rs:1"),
        finding("e.1.2", dedup_key="aligned", root_cause="unchecked write at the IPC boundary",
                cwe="CWE-787", locus="a.rs:1"),
    ], threat="memory safety at the IPC boundary"))
    assert [g["dedup_key"] for g in doc["groups"]] == ["aligned", "unrelated"]
    assert doc["groups"][0]["threat_aligned"] is True
    assert doc["summary"]["threat_aligned_groups"] == 1


def test_instance_count_breaks_a_tie_before_locus(bd_factory):
    doc, _ = report(bd_factory, export([
        finding("e.1.1", dedup_key="one", locus="a.rs:1", root_cause="x"),
        finding("e.1.2", dedup_key="many", locus="b.rs:1", root_cause="x"),
        finding("e.1.3", dedup_key="many", locus="b.rs:2", root_cause="x"),
    ], threat=None))
    assert [g["dedup_key"] for g in doc["groups"]] == ["many", "one"]


def test_a_refuted_group_sorts_below_an_untiered_one(bd_factory):
    # Refuted is a decision; untiered is an unfinished job, and burying it hides work.
    doc, _ = report(bd_factory, export([
        finding("e.1.1", tier="REFUTED", dedup_key="refuted", locus="a.rs:1"),
        finding("e.1.2", tier=None, dedup_key="untiered", locus="b.rs:1"),
    ], threat=None))
    assert [g["dedup_key"] for g in doc["groups"]] == ["untiered", "refuted"]


# --- systemic patterns ------------------------------------------------------


def test_root_cause_rollup_sits_above_the_findings_and_counts_instances(bd_factory):
    doc, _ = report(bd_factory, export([
        finding("e.1.1", dedup_key="a", locus="a.rs:1",
                root_cause="built but never wired"),
        finding("e.1.2", dedup_key="b", locus="b.rs:1",
                root_cause="built but never wired"),
        finding("e.1.3", dedup_key="c", locus="c.rs:1", root_cause="a different defect"),
    ]))
    top = doc["systemic_patterns"][0]
    assert top["root_cause"] == "built but never wired"
    assert top["group_count"] == 2
    assert top["instance_count"] == 2
    assert doc["summary"]["systemic_pattern_count"] == 2


def test_a_root_cause_spanning_surfaces_is_flagged_cross_surface(bd_factory):
    doc, _ = report(bd_factory, export([
        finding("e.1.1", dedup_key="a", surface="code", locus="a.rs:1",
                root_cause="built but never wired"),
        finding("e.1.2", dedup_key="b", surface="infra", locus="ci.yml:1",
                root_cause="built but never wired"),
    ], surfaces=("code", "infra")))
    assert doc["systemic_patterns"][0]["cross_surface"] is True
    assert doc["systemic_patterns"][0]["surfaces"] == ["code", "infra"]


# --- counts that balance ----------------------------------------------------


def test_the_three_counts_are_derived_and_balance(bd_factory):
    doc, _ = report(bd_factory, export([
        finding("e.1.1", dedup_key="a", locus="a.rs:1"),
        finding("e.1.2", dedup_key="a", locus="a.rs:1"),
        finding("e.1.3", dedup_key="b", locus="b.rs:1"),
    ]))
    counts = doc["summary"]["counts"]
    assert counts["groups"] == 2
    assert counts["instances"] == 3
    assert counts["grouped_instances"] == 3
    assert counts["balances"] is True
    assert counts["wisps"] >= counts["instances"]


# --- the NOT-EXECUTED register ---------------------------------------------


def test_a_not_executed_reason_is_a_register_line_not_an_absence(bd_factory):
    doc, _ = report(bd_factory, export([
        finding("e.1.1", tier=None, impact=None,
                not_executed_reason="opengrep stock packs cannot load under --network none"),
    ]))
    kinds = {r["kind"]: r for r in doc["not_executed"]}
    assert "finding-placeholder" in kinds
    assert "--network none" in kinds["finding-placeholder"]["reason"]
    assert doc["summary"]["not_executed_count"] >= 1


def test_a_failed_control_marks_the_locus_untested(bd_factory):
    # A benign control that also failed means the harness proved nothing about the code.
    doc, _ = report(bd_factory, export([finding("e.1.1", control_passed=False)]))
    assert any(r["kind"] == "control-failed" for r in doc["not_executed"])


def test_a_surface_with_no_coverage_record_is_a_gap_not_an_empty_list(bd_factory):
    # The fail-open: gaps were derived only from the coverage records that EXIST, so a
    # surface that filed none produced coverage_gaps: [] and exit 0.
    doc, _ = report(bd_factory, export(
        [finding("e.1.1")], surfaces=("code", "infra"), coverage=True,
    ))
    assert doc["summary"]["surfaces_without_a_coverage_record"] == ["infra"]
    assert any(r["kind"] == "no-coverage-record" and r["surface"] == "infra"
               for r in doc["not_executed"])


def test_unrun_harnesses_and_skipped_scanners_reach_the_register(bd_factory):
    lines = export([finding("e.1.1")], coverage=False)
    lines.append({
        "id": "e.1.90", "issue_type": "task", "title": "coverage", "status": "open",
        "metadata": {"run_id": "run-A", "surface": "code",
                     "scanners_run": ["opengrep"], "scanners_skipped": ["codeql"],
                     "harnesses_run": 0, "harnesses_total": 13},
        "labels": ["sab-coverage", "sab-surface", "sab-audit", "non-work"],
        "dependencies": [{"depends_on_id": "e.1", "type": "parent-child"}],
    })
    doc, _ = report(bd_factory, lines)
    kinds = {r["kind"] for r in doc["not_executed"]}
    assert {"scanner-skipped", "harnesses-unrun"} <= kinds
    assert any("13 of 13" in r["reason"] or "13 authored" in r["reason"]
               for r in doc["not_executed"] if r["kind"] == "harnesses-unrun")


def test_entry_points_never_executed_reach_the_register_though_every_harness_ran(bd_factory):
    """A harness ratio measures the harnesses, not the surface.

    Measured: one node reported 13 of 13 harnesses run against 706 entry points, and
    another enumerated 199 Tauri command handlers and executed 0 of them because the
    image could not compile the crate. Both read as complete coverage from
    `harnesses_run == harnesses_total` alone, and with only the harness counts kept in
    KEEP_META the 199 reached no part of the report.
    """
    lines = export([finding("e.1.1")], coverage=False)
    lines.append({
        "id": "e.1.90", "issue_type": "task", "title": "coverage", "status": "open",
        "metadata": {"run_id": "run-A", "surface": "code",
                     "scanners_run": ["opengrep"], "scanners_skipped": [],
                     # every authored harness ran, so the harness ratio is silent
                     "harnesses_run": 13, "harnesses_total": 13,
                     "entry_points_total": 199, "entry_points_executed": 0},
        "labels": ["sab-coverage", "sab-surface", "sab-audit", "non-work"],
        "dependencies": [{"depends_on_id": "e.1", "type": "parent-child"}],
    })
    doc, _ = report(bd_factory, lines)
    assert not any(r["kind"] == "harnesses-unrun" for r in doc["not_executed"])
    gaps = [r for r in doc["not_executed"] if r["kind"] == "entry-points-unexecuted"]
    assert gaps, doc["not_executed"]
    assert "199 of 199" in gaps[0]["reason"]
    # and the raw ratio survives shape() into the coverage record itself
    cov = next(c for c in doc["coverage"] if c["id"] == "e.1.90")
    assert cov["entry_points_total"] == 199
    assert cov["entry_points_executed"] == 0


def test_a_scanner_skip_count_is_a_register_line_and_never_a_traceback(bd_factory):
    """`scanners_skipped` holds NAMES; a count in its place names none of them.

    Measured: 21 of 22 coverage wisps in one campaign stamped both scanner fields as
    integers and one as a comma string. Iterating the int raised TypeError, so the entire
    report died instead of naming the wisp -- a mis-stamp on one surface erased 388
    findings from the output.
    """
    lines = export([finding("e.1.1")], coverage=False)
    lines.append({
        "id": "e.1.90", "issue_type": "task", "title": "coverage", "status": "open",
        "metadata": {"run_id": "run-A", "surface": "code",
                     "scanners_run": 4, "scanners_skipped": 9,
                     "harnesses_run": 2, "harnesses_total": 2},
        "labels": ["sab-coverage", "sab-surface", "sab-audit", "non-work"],
        "dependencies": [{"depends_on_id": "e.1", "type": "parent-child"}],
    })
    doc, _ = report(bd_factory, lines)          # rc 0: no traceback
    bad = [r for r in doc["not_executed"] if r["kind"] == "scanner-skip-list-not-stamped"]
    assert bad, doc["not_executed"]
    assert "9" in bad[0]["reason"]
    # and no fabricated skip lines stand in for the nine unnamed scanners
    assert not any(r["kind"] == "scanner-skipped" for r in doc["not_executed"])


def test_clean_claimed_for_a_skipped_scanner_reaches_the_register(bd_factory):
    """A tool that did not run cannot have produced a clean result.

    Measured: one node stamped clippy as "not installed for toolchain 1.97.1" AND filed a
    finding that clippy obtained zero lint findings on the crate. Clippy was installed the
    whole time -- run later it checked 513 crates and returned zero warnings. The
    conclusion was right, which is exactly why nothing caught the fabrication.
    """
    lines = export([
        finding("e.1.1", tier="HARDENING", impact="LOW",
                title="clippy obtains zero lint findings on desktop_shell"),
    ], coverage=False)
    lines.append({
        "id": "e.1.90", "issue_type": "task", "title": "coverage", "status": "open",
        "metadata": {"run_id": "run-A", "surface": "code",
                     "scanners_run": ["opengrep"],
                     "scanners_skipped": [{"tool": "clippy", "reason": "not installed"}],
                     "harnesses_run": 2, "harnesses_total": 2},
        "labels": ["sab-coverage", "sab-surface", "sab-audit", "non-work"],
        "dependencies": [{"depends_on_id": "e.1", "type": "parent-child"}],
    })
    doc, _ = report(bd_factory, lines)
    bad = [r for r in doc["not_executed"]
           if r["kind"] == "clean-claimed-for-a-skipped-scanner"]
    assert bad, doc["not_executed"]
    assert "clippy" in bad[0]["reason"]
    assert bad[0]["id"] == "e.1.1"


def test_the_contradiction_names_the_tool_whose_clause_claims_the_clean(bd_factory):
    """A finding may name several tools, agreeing with the skip for some of them.

    Measured, from a real title: "clippy obtains zero lint findings on desktop_shell ...
    and rustfmt plus cargo-nextest are absent from the image". Matching the clean-claim
    anywhere in the string blamed cargo-nextest, which this title calls ABSENT -- agreeing
    with the coverage record rather than contradicting it. The contradiction is clippy's,
    and naming the wrong tool in a gap register is its own fail-open.
    """
    lines = export([
        finding("e.1.1", tier="HARDENING", impact="LOW",
                title="clippy obtains zero lint findings on desktop_shell, "
                      "and rustfmt plus cargo-nextest are absent from the image"),
    ], coverage=False)
    lines.append({
        "id": "e.1.90", "issue_type": "task", "title": "coverage", "status": "open",
        "metadata": {"run_id": "run-A", "surface": "code",
                     "scanners_run": ["opengrep"],
                     "scanners_skipped": [{"tool": "clippy", "reason": "not installed"},
                                          {"tool": "rustfmt", "reason": "absent"},
                                          {"tool": "cargo-nextest", "reason": "absent"}],
                     "harnesses_run": 2, "harnesses_total": 2},
        "labels": ["sab-coverage", "sab-surface", "sab-audit", "non-work"],
        "dependencies": [{"depends_on_id": "e.1", "type": "parent-child"}],
    })
    doc, _ = report(bd_factory, lines)
    bad = [r for r in doc["not_executed"]
           if r["kind"] == "clean-claimed-for-a-skipped-scanner"]
    assert bad, doc["not_executed"]
    reasons = " ".join(r["reason"] for r in bad)
    assert "clippy" in reasons
    assert "cargo-nextest" not in reasons, "a tool the finding calls absent is no contradiction"


def test_a_clean_claim_for_a_scanner_that_actually_ran_is_not_flagged(bd_factory):
    # The check is on the contradiction, not on the word "zero": a tool that ran and
    # found nothing is a legitimate result and must not be registered as a gap.
    lines = export([
        finding("e.1.1", tier="HARDENING", impact="LOW",
                title="clippy obtains zero lint findings on desktop_shell"),
    ], coverage=False)
    lines.append({
        "id": "e.1.90", "issue_type": "task", "title": "coverage", "status": "open",
        "metadata": {"run_id": "run-A", "surface": "code",
                     "scanners_run": ["clippy"], "scanners_skipped": [],
                     "harnesses_run": 2, "harnesses_total": 2},
        "labels": ["sab-coverage", "sab-surface", "sab-audit", "non-work"],
        "dependencies": [{"depends_on_id": "e.1", "type": "parent-child"}],
    })
    doc, _ = report(bd_factory, lines)
    assert not any(r["kind"] == "clean-claimed-for-a-skipped-scanner"
                   for r in doc["not_executed"])


# --- stamping discipline ----------------------------------------------------


def test_a_missing_required_field_is_a_stamping_gap_not_a_blank_column(bd_factory):
    lines = export([finding("e.1.1")])
    del lines[-1]["metadata"]["evidence"]        # omitted, not null
    del lines[-1]["metadata"]["control_passed"]
    doc, _ = report(bd_factory, lines)
    issues = " ".join(g["issue"] for g in doc["stamping_gaps"])
    assert "evidence" in issues and "control_passed" in issues


def crash(bid, **meta):
    return {
        "id": bid, "issue_type": "task", "title": f"crash {bid}", "status": "open",
        "metadata": dict({"run_id": "run-A"}, **meta),
        "labels": ["sab-crash", "sab-surface", "sab-audit", "non-work"],
        "dependencies": [{"depends_on_id": "e.1", "type": "parent-child"}],
    }


def test_a_minimized_crash_input_survives_into_the_report(bd_factory):
    """The whole value of a crash wisp is a file on disk, so the path must reach shape().

    Measured: KEEP_META["crashes"] kept 2 of the 9 keys the triager brief prescribes, so
    the minimization was dropped even when stamped correctly.
    """
    doc, _ = report(bd_factory, export([crash("e.1.50",
        state="minimized", kind="robustness", input_path="/art/orig.fits",
        minimized_path="/art/min.fits", minimized_bytes=65, original_path="/art/orig.fits",
        repro_cmd="cargo test -p fits-header -- --exact parse", repro_rc=101,
        dedup_key="code:a.rs:1:panic", duplicate_of=None,
        stack_hash="ab12", class_closed_by=None,
    )]))
    c = doc["crashes"][0]
    assert c["minimized_path"] == "/art/min.fits"
    assert c["repro_cmd"].startswith("cargo test")
    assert c["minimized_bytes"] == 65
    assert c["repro_rc"] == 101
    assert c["kind"] == "robustness"
    assert not any(g["bucket"] == "crashes" for g in doc["stamping_gaps"])


def test_a_crash_stamped_under_invented_key_names_is_a_gap_not_a_blank_record(bd_factory):
    """A triager may stamp anything; `bd update` exits 0 for every key name.

    Measured: one triager minimized 6 crashes to 65/185/71/81/2880/3 bytes, wrote 7 files
    to disk, reported "comments + metadata written", and had written 0 comments plus keys
    of its own invention (`min_input`, `min_bytes`, `dedup`, `triage_class`). Every crash
    record rendered blank and no part of the report said the inputs existed.
    """
    doc, _ = report(bd_factory, export([crash("e.1.50",
        min_input="/art/min.fits", min_bytes=65, dedup="a|b", triage_class="robustness",
        triaged=True,
    )]))
    gap = next(g for g in doc["stamping_gaps"] if g["bucket"] == "crashes")
    for key in ("state", "kind", "minimized_path", "repro_cmd", "repro_rc", "dedup_key"):
        assert key in gap["issue"], f"{key} must be named as missing"
    assert doc["summary"]["stamping_gaps"] >= 1


def harness(bid, **meta):
    return {
        "id": bid, "issue_type": "task", "title": f"harness {bid}", "status": "open",
        "metadata": dict({"run_id": "run-A"}, **meta),
        "labels": ["sab-harness", "sab-surface", "sab-audit", "non-work"],
        "dependencies": [{"depends_on_id": "e.1", "type": "parent-child"}],
    }


def test_a_harness_with_no_control_path_is_a_gap_not_a_silent_untierable_result(bd_factory):
    """`control_path` decides whether a hostile result carries a verdict at all.

    Measured: 23 of 23 harness wisps in one campaign omitted it, two briefs MUST it, and
    KEEP_META dropped the field anyway -- so a challenger asking for the control had
    nowhere to read it and every guard assertion on the run was untierable in silence.
    """
    doc, _ = report(bd_factory, export([harness("e.1.60",
        entry_point="src/native.rs:114", harness_path="/fuzz/reveal.rs", runner="cargo fuzz",
    )]))
    gap = next(g for g in doc["stamping_gaps"] if g["bucket"] == "harnesses")
    assert "control_path" in gap["issue"] and "expected" in gap["issue"]


def test_a_control_path_that_is_stamped_reaches_the_report(bd_factory):
    doc, _ = report(bd_factory, export([harness("e.1.61",
        entry_point="src/native.rs:114", harness_path="/fuzz/reveal.rs", runner="cargo fuzz",
        control_path="/fuzz/reveal_control.rs", expected="fail", input_shape="path",
        state="open",
    )]))
    assert doc["harnesses"][0]["control_path"] == "/fuzz/reveal_control.rs"
    assert not any(g["bucket"] == "harnesses" for g in doc["stamping_gaps"])


def test_control_path_none_is_accepted_for_a_harness_asserting_no_guard(bd_factory):
    """"none" is the deliberate answer, and it must not read as an omission.

    A harness that asserts a parser does not panic has no guard to control for, so
    demanding a control file there would push authors to stamp a path that does not exist.
    """
    doc, _ = report(bd_factory, export([harness("e.1.62",
        entry_point="src/parse.rs:20", harness_path="/fuzz/parse.rs", runner="cargo fuzz",
        control_path="none", expected="pass", state="executed",
    )]))
    assert not any(g["bucket"] == "harnesses" for g in doc["stamping_gaps"])


def coverage_wisp(bid, **meta):
    base = {"run_id": "run-A", "surface": "code", "scanners_run": ["opengrep"],
            "scanners_skipped": [], "harnesses_run": 2, "harnesses_total": 2}
    base.update(meta)
    return {
        "id": bid, "issue_type": "task", "title": "coverage", "status": "open",
        "metadata": base, "labels": ["sab-coverage", "sab-surface", "sab-audit", "non-work"],
        "dependencies": [{"depends_on_id": "e.1", "type": "parent-child"}],
    }


def test_a_wisp_left_claimed_at_report_time_is_registered(bd_factory):
    """An agent cannot close a wisp, so the release is a status change back to `open`.

    Measured: 161 of 193 harness wisps were left `in_progress` at the end of one campaign.
    Resume reads in_progress as in-flight and the gremlin's discovery query filters on
    open, so a resumed run would have read all 161 as still running and found none of them
    as work. A claim never released is the same as a harness lost.
    """
    w = harness("e.1.100", entry_point="a.rs:1", harness_path="/h/a.rs",
                runner="cargo fuzz", control_path="none", expected="pass", state="executed")
    w["status"] = "in_progress"
    doc, _ = report(bd_factory, export([w]))
    entry = next(r for r in doc["not_executed"] if r["kind"] == "wisp-left-claimed")
    assert entry["id"] == "e.1.100"


def test_a_released_wisp_is_not_flagged(bd_factory):
    doc, _ = report(bd_factory, export([harness("e.1.101",
        entry_point="a.rs:1", harness_path="/h/a.rs", runner="cargo fuzz",
        control_path="none", expected="pass", state="executed")]))
    assert not any(r["kind"] == "wisp-left-claimed" for r in doc["not_executed"])


def test_a_scanner_run_list_stamped_as_a_count_is_registered(bd_factory):
    """`scanners_run: 7` claims coverage while naming no tool that produced it.

    Measured: 23 of 27 coverage records stamped it as a count and one as a string, while
    findings on two surfaces recorded `source: stock-pack` for lints clippy actually
    produced. Neither claim could be checked against the other.
    """
    doc, _ = report(bd_factory, export([finding("e.1.1")], coverage=False) +
                    [coverage_wisp("e.1.98", scanners_run=7, entry_points_total=10,
                                   entry_points_executed=10)])
    entry = next(r for r in doc["not_executed"]
                 if r["kind"] == "scanner-run-list-not-stamped")
    assert entry["id"] == "e.1.98"


def test_a_scanner_run_list_of_names_is_not_flagged(bd_factory):
    doc, _ = report(bd_factory, export([finding("e.1.1")], coverage=False) +
                    [coverage_wisp("e.1.99", scanners_run=["clippy", "opengrep"],
                                   entry_points_total=10, entry_points_executed=10)])
    assert not any(r["kind"] == "scanner-run-list-not-stamped" for r in doc["not_executed"])


def test_an_absent_entry_point_ratio_is_registered_not_read_as_full_coverage(bd_factory):
    """The unstamped-ratio check needed two ints to fire, so omitting the field passed.

    Measured: 24 of 27 coverage records in one campaign carried no `entry_points_total`,
    leaving what fraction of each surface was reached unknown while the harness counts read
    complete. The brief already says to stamp 0 with the mechanism when counting is blocked.
    """
    doc, _ = report(bd_factory, export([finding("e.1.1")], coverage=False) +
                    [coverage_wisp("e.1.95")])
    entry = next(r for r in doc["not_executed"]
                 if r["kind"] == "entry-point-ratio-not-stamped")
    assert entry["id"] == "e.1.95"


def test_a_total_with_no_executed_count_is_registered_too(bd_factory):
    # "706 entry points" and no reached count reads identically to having reached all 706.
    doc, _ = report(bd_factory, export([finding("e.1.1")], coverage=False) +
                    [coverage_wisp("e.1.96", entry_points_total=706)])
    entry = next(r for r in doc["not_executed"]
                 if r["kind"] == "entry-point-ratio-not-stamped")
    assert "706" in entry["reason"]


def test_a_stamped_zero_of_n_is_the_unexecuted_line_not_the_unstamped_one(bd_factory):
    # 0 of 199 is a stamped, honest answer: it belongs in the coverage register as an
    # unexercised surface, never as a stamping omission.
    doc, _ = report(bd_factory, export([finding("e.1.1")], coverage=False) +
                    [coverage_wisp("e.1.97", entry_points_total=199,
                                   entry_points_executed=0)])
    kinds = {r["kind"] for r in doc["not_executed"]}
    assert "entry-points-unexecuted" in kinds
    assert "entry-point-ratio-not-stamped" not in kinds


def test_the_summary_totals_where_findings_came_from(bd_factory):
    """A skill rule requires the report to say when stock packs carried the campaign.

    `source` was kept per finding and totalled nowhere, so the rule had no mechanism:
    nobody reads 386 findings to compute the mix by hand. A combined stamp counts toward
    both halves, because `harness+synthesized-rule` did use a recon rule.
    """
    doc, _ = report(bd_factory, export([
        finding("e.1.90", source="stock-pack", dedup_key="k1"),
        finding("e.1.91", source="synthesized-rule", dedup_key="k2", locus="b.rs:2"),
        finding("e.1.92", source="harness+synthesized-rule", dedup_key="k3", locus="c.rs:3"),
    ]))
    assert doc["summary"]["by_source"] == {
        "stock-pack": 1, "synthesized-rule": 2, "harness": 1}
    assert doc["summary"]["findings_from_recon_rules"] == 2
    assert doc["summary"]["stock_pack_only"] is False


def test_a_campaign_carried_entirely_by_stock_packs_says_so(bd_factory):
    # Stock packs are the borrowed detectors and carry no knowledge of this repo, so a run
    # resting on them alone aimed nothing and did no recon.
    doc, _ = report(bd_factory, export([finding("e.1.93", source="stock-pack")]))
    assert doc["summary"]["stock_pack_only"] is True
    assert doc["summary"]["findings_from_recon_rules"] == 0


def test_a_reproduce_command_stamped_under_repro_cmd_reaches_the_report(bd_factory):
    """The brief asked for "the reproduce command" and named no key.

    Measured: 0 of 386 findings stamped `repro`, 7 stamped `repro_cmd`, and KEEP_META kept
    only `repro` -- so every reproduce command on the run's PROVEN findings was dropped.
    Same shape as the crash keys, from the same cause.
    """
    doc, _ = report(bd_factory, export([finding("e.1.80",
        repro_cmd="cargo test -p app-core -- --exact validate_reveal_path", repro_rc=101,
    )]))
    assert doc["findings"][0]["repro_cmd"].startswith("cargo test")
    assert doc["findings"][0]["repro_rc"] == 101


def test_a_reproduce_command_with_no_exit_code_reaches_the_register(bd_factory):
    # Running it yields a number with nothing to compare against, and the harden route
    # decides FIXED against NOT FIXED by quoting the rc before and after.
    doc, _ = report(bd_factory, export([finding("e.1.81",
        repro_cmd="cargo test -p app-core -- --exact path_preview",
    )]))
    entry = next(r for r in doc["not_executed"] if r["kind"] == "repro-without-an-exit-code")
    assert entry["id"] == "e.1.81"


def test_a_finding_with_no_reproduce_command_is_not_flagged_for_a_missing_rc(bd_factory):
    doc, _ = report(bd_factory, export([finding("e.1.82")]))
    assert not any(r["kind"] == "repro-without-an-exit-code" for r in doc["not_executed"])


def test_a_broken_harness_with_no_re_author_wisp_reaches_the_register(bd_factory):
    """A harness that reports itself broken closes nothing on its own.

    Measured: one campaign ran roughly a dozen harnesses that reported themselves broken --
    one honestly at rc=3 saying its own canary never fired -- and filed ZERO re-author
    wisps. Every one of those entry points read as uncovered rather than as needing a
    rewrite, and the allowlist breadth one was written to measure is still untested.
    """
    doc, _ = report(bd_factory, export([harness("e.1.70",
        entry_point="scripts/gitleaks-allowlist-coverage.sh:1",
        harness_path="/h/allowlist.sh", runner="fuzz-cli", control_path="none",
        expected="fail", state="invalid",
    )]))
    entry = next(r for r in doc["not_executed"]
                 if r["kind"] == "broken-harness-with-no-re-author-route")
    assert entry["id"] == "e.1.70"
    assert "gitleaks-allowlist-coverage.sh:1" in entry["locus"]


def test_a_broken_harness_a_re_author_wisp_supersedes_is_not_flagged(bd_factory):
    # The register is for a broken harness with NO route back. Once the wisp exists the
    # rewrite is tracked, so flagging it again would train authors to ignore the register.
    doc, _ = report(bd_factory, export([
        harness("e.1.71", entry_point="a.sh:1", harness_path="/h/a.sh", runner="fuzz-cli",
                control_path="none", expected="fail", state="invalid"),
        harness("e.1.72", entry_point="a.sh:1", harness_path="/h/a.sh", runner="fuzz-cli",
                control_path="none", expected="fail", state="open",
                supersedes="e.1.71", reason="fails-in-own-fixture"),
    ]))
    assert not any(r["kind"] == "broken-harness-with-no-re-author-route"
                   for r in doc["not_executed"])


def test_a_harness_with_no_state_is_a_gap_because_broken_and_clean_look_alike(bd_factory):
    # Measured: 192 of 193 harness wisps in one campaign carried no `state`, so a harness
    # that never ran and one that ran clean were the same record.
    doc, _ = report(bd_factory, export([harness("e.1.73",
        entry_point="a.rs:1", harness_path="/h/a.rs", runner="cargo fuzz",
        control_path="none", expected="pass",
    )]))
    gap = next(g for g in doc["stamping_gaps"] if g["bucket"] == "harnesses")
    assert "state" in gap["issue"]


def test_an_explicit_null_is_accepted_where_a_field_does_not_apply(bd_factory):
    doc, _ = report(bd_factory, export([finding("e.1.1", repro=None, path=None)]))
    assert not any("required field" in g["issue"] for g in doc["stamping_gaps"])


# --- bd query discipline ----------------------------------------------------


def test_an_empty_export_is_refused_rather_than_rendered_as_a_clean_audit(tmp_path):
    # `bd` discovers its store relative to cwd, and `--labels` silently returns nothing
    # on a query, which once made a whole wisp set read as "no work exists".
    bd = tmp_path / "bd"
    bd.write_text("#!/bin/sh\nexit 0\n")
    bd.chmod(bd.stat().st_mode | stat.S_IEXEC)
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--bd", str(bd), "--run-id", "run-A"],
        capture_output=True, text=True,
    )
    assert r.returncode == 3
    assert "returned NOTHING" in r.stderr


def test_a_failing_bd_names_the_repo_root_requirement(tmp_path):
    bd = tmp_path / "bd"
    bd.write_text("#!/bin/sh\necho boom >&2\nexit 1\n")
    bd.chmod(bd.stat().st_mode | stat.S_IEXEC)
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--bd", str(bd), "--run-id", "run-A"],
        capture_output=True, text=True,
    )
    assert r.returncode == 3
    assert "repo root" in r.stderr


def test_a_bead_with_no_sab_audit_label_is_a_gap(bd_factory):
    """The label a project's own queries exclude on.

    Without it every campaign bead sits in the project's backlog. Measured: 680 beads in a
    product repo's store, 329 of them not product defects, and the project's "close every
    bead" release gate blocked on the audit's own bookkeeping.
    """
    f = finding("e.1.2")
    f["labels"] = ["sab-finding", "sab-surface"]
    doc, _ = report(bd_factory, export([f]))
    gap = next(g for g in doc["stamping_gaps"] if "sab-audit" in g["issue"])
    assert gap["id"] == "e.1.2"


def test_a_fully_labelled_bead_is_not_flagged(bd_factory):
    f = finding("e.1.2")
    f["labels"] = ["sab-finding", "sab-surface", "sab-audit"]
    f["priority"] = 1
    doc, _ = report(bd_factory, export([f]))
    assert not any(g["id"] == "e.1.2" for g in doc["stamping_gaps"])


def test_a_refuted_finding_needs_non_work_as_well(bd_factory):
    """REFUTED is a record the run disproved, so it is not a defect to close out."""
    f = finding("e.1.2", tier="REFUTED", impact="LOW")
    f["labels"] = ["sab-finding", "sab-surface", "sab-audit"]
    f["priority"] = 4
    doc, _ = report(bd_factory, export([f]))
    gap = next(g for g in doc["stamping_gaps"] if g["id"] == "e.1.2")
    assert "non-work" in gap["issue"]


def test_a_finding_inside_the_artifacts_dir_is_audit_tooling_not_a_product_defect(bd_factory):
    """A misfiring synthesized rule is real and worth fixing, and it is not a product bug.

    Detected from the locus, because only 2 of the 6 such findings in one campaign said so
    in their title.
    """
    doc, _ = report(bd_factory, export([
        finding("e.1.2", locus=".sabot/run-A/artifacts/rules-code.yml"),
        finding("e.1.3", locus="src/a.rs:1"),
    ]))
    tooling = {f["id"] for f in doc["findings"] if f.get("audit_tooling")}
    assert tooling == {"e.1.2"}
    assert doc["summary"]["audit_tooling_findings"] == 1
    assert doc["summary"]["product_defects"] == 1


def test_a_product_dir_named_artifacts_is_still_a_product_defect(bd_factory):
    """A substring test for `/artifacts/` dropped src/artifacts/parser.py from the
    product's defects. Only the run's own artifacts dir is audit tooling."""
    doc, _ = report(bd_factory, export([
        finding("e.1.2", locus="src/artifacts/parser.py:10"),
        finding("e.1.3", locus="/repo/src/artifacts/parser.py:12"),
    ]))
    assert not [f["id"] for f in doc["findings"] if f.get("audit_tooling")]
    assert doc["summary"]["product_defects"] == 2


def test_the_stamped_artifacts_dir_and_the_container_mount_are_audit_tooling(bd_factory):
    lines = export([
        finding("e.1.2", locus="/work/repo/audit-out/rules/code.yml:4"),
        finding("e.1.3", locus="audit-out/harness.py:2"),
        finding("e.1.4", locus="/artifacts/rules-code.yml:7"),
        finding("e.1.5", locus="/work/repo/src/main.rs:1"),
    ])
    lines[0]["metadata"].update(target="/work/repo", artifacts="/work/repo/audit-out")
    doc, _ = report(bd_factory, lines)
    tooling = {f["id"] for f in doc["findings"] if f.get("audit_tooling")}
    assert tooling == {"e.1.2", "e.1.3", "e.1.4"}
    assert doc["summary"]["product_defects"] == 1


def test_a_derived_dedup_key_leaves_the_surface_out(bd_factory):
    """The canonical key is `<locus>:<class>`. The same locus filed from two surfaces is
    independent confirmation of one finding, not two findings."""
    doc, _ = report(bd_factory, export([
        finding("e.1.1", dedup_key=None, surface="code"),
        finding("e.2.1", dedup_key=None, surface="shell"),
    ], surfaces=("code", "shell")))
    assert [g["dedup_key"] for g in doc["groups"]] == ["a.rs:1:cwe-190"]
    assert sorted(doc["groups"][0]["instances"]) == ["e.1.1", "e.2.1"]


def test_a_refuted_finding_left_open_is_registered(bd_factory):
    """The no-delete rule keeps the wisp and its refutation, not its open status.

    Measured: 35 of 36 REFUTED findings in one campaign were still open at report time.
    """
    doc, _ = report(bd_factory, export([finding("e.1.2", tier="REFUTED", impact="LOW")]))
    kinds = [r["kind"] for r in doc["not_executed"]]
    assert "refuted-finding-left-open" in kinds


def test_a_closed_refuted_finding_is_not_registered(bd_factory):
    f = finding("e.1.2", tier="REFUTED", impact="LOW")
    f["status"] = "closed"
    doc, _ = report(bd_factory, export([f]))
    assert not any(r["kind"] == "refuted-finding-left-open" for r in doc["not_executed"])


def test_priority_that_disagrees_with_the_two_axes_is_a_gap(bd_factory):
    """Measured: 14 of 21 surfaces entirely P2, with the run's two worst findings there too.

    A PROVEN CRITICAL is P0 by the table, so a P2 on one is a gap naming the value it wants.
    """
    f = finding("e.1.2", tier="PROVEN", impact="CRITICAL")
    f["labels"] = ["sab-finding", "sab-surface", "sab-audit"]
    f["priority"] = 2
    doc, _ = report(bd_factory, export([f]))
    gap = next(g for g in doc["stamping_gaps"] if "priority" in g["issue"])
    assert "P0" in gap["issue"]


def test_a_priority_matching_the_table_is_not_flagged(bd_factory):
    f = finding("e.1.2", tier="HARDENING", impact="LOW")
    f["labels"] = ["sab-finding", "sab-surface", "sab-audit", "non-work"]
    f["priority"] = 4
    doc, _ = report(bd_factory, export([f]))
    assert not any("priority" in g["issue"] for g in doc["stamping_gaps"])


def test_a_p_prefixed_priority_string_is_read_as_its_number(bd_factory):
    """bd accepts `P0` and `0`, so a string form must not read as a mismatch."""
    f = finding("e.1.2", tier="PROVEN", impact="HIGH")
    f["labels"] = ["sab-finding", "sab-surface", "sab-audit"]
    f["priority"] = "P1"
    doc, _ = report(bd_factory, export([f]))
    assert not any("priority" in g["issue"] for g in doc["stamping_gaps"])


def test_a_chain_finding_is_not_counted_as_an_additional_product_defect(bd_factory):
    """A chain composes findings already counted.

    Read from the `sab-chain` label, not the title: one campaign had one bead labelled
    `sab-chain` and a DIFFERENT one titled "CHAIN", so the two signals named disjoint beads.
    """
    c = finding("e.1.9")
    c["labels"] = ["sab-finding", "sab-surface", "sab-chain"]
    doc, _ = report(bd_factory, export([finding("e.1.2"), c]))
    assert doc["summary"]["chains"] == 1
    assert doc["summary"]["product_defects"] == 1


def test_a_subtree_whose_parent_edge_points_elsewhere_is_still_reached(bd_factory):
    """The defect that rendered a 680-bead campaign as an empty report at exit 0.

    21 surface nodes carried ids under the run epic while their `parent-child` edges pointed
    at unrelated project beads. A walk trusting the edge alone reached 0 of 680, so the
    prefix is walked as well as the edge, and the disagreement is reported.
    """
    f = finding("e.1.2")
    f["dependencies"] = [{"depends_on_id": "unrelated-project-bead", "type": "parent-child"}]
    doc, _ = report(bd_factory, export([f]))
    assert [x["id"] for x in doc["findings"]] == ["e.1.2"], "the finding must still be found"
    gap = next(g for g in doc["stamping_gaps"] if "parent-child edge" in g["issue"])
    assert "unrelated-project-bead" in gap["issue"]


def test_an_agreeing_parent_edge_is_not_flagged(bd_factory):
    doc, _ = report(bd_factory, export([finding("e.1.2")]))
    assert not any("parent-child edge" in g["issue"] for g in doc["stamping_gaps"])
