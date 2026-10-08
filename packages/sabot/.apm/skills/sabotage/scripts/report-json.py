#!/usr/bin/env python3
"""Export one sabot campaign from beads as a structured report JSON.

Runs `bd export` (which emits every issue with its metadata, labels, dependency
edges, and comment bodies), keeps only the beads for the given run_id, drops the
fields a report never uses (owner, timestamps, priority, created_by, counts), and
reshapes each bead into the schema the report generator and a machine reader consume.

Wisps ARE beads here (a task bead with a sab-* label), so the export already holds
them; nothing separate is persisted. The correlation edges (discovered-from,
caused-by, relates-to) ride on each bead's `dependencies`, so a finding keeps its
link to the harness, crash, or chain it came from.

Usage:
  report-json.py --run-id run-<id> [--bd bd] [-o out.json]

THE BEAD METADATA BLOB IS THE REPORT. This is a renderer over the graph, not a prose
assembler: ranking, grouping by root cause, and dedup are mechanical here because doing
them by hand does not scale and did not happen. One run produced ~251 findings with no
ranking or dedup at all, and 224 loci were collapsed onto a single boundary by hand.

Emits to stdout (or -o) a single JSON object:
  {
    "run_id", "threat", "epic": {...}, "surfaces": [...], "harnesses": [...],
    "crashes": [...], "findings": [...], "coverage": [...],
    "groups": [...],              # dedup_key collapse, ranked, one tier per group
    "systemic_patterns": [...],   # root_cause rollup, above the findings
    "not_executed": [...],        # one line per unexercised dimension, with its reason
    "stamping_gaps": [...],
    "summary": {"by_tier", "by_impact", "counts", "coverage_gaps",
                "surfaces_without_a_coverage_record", ...}
  }

`summary.counts` carries groups, instances, and wisps plus a `balances` flag: every
instance belongs to exactly one group, so a count table that has to add up is the check.

Exit codes: 0 ok; 2 usage; 3 bd missing, export failed, or the export was EMPTY (which is
the wrong cwd or an empty store, not a run without findings); 4 no beads for run_id;
5 the count table does not balance, so a finding was dropped between graph and report.
"""

import argparse
import json
import posixpath
import re
import shutil
import subprocess
import sys
from pathlib import PurePosixPath


# Which sab-* label sorts a bead into which bucket. Order matters: the first match
# wins, so sab-surface (inherited by every child) is checked last.
# Order matters twice over. The first match wins, so the MORE SPECIFIC label is checked
# first: a pattern wisp is created with `sab-finding,sab-pattern` because it IS a finding
# (it has a tier, an impact, and a priority), and checking `sab-finding` first sorted all 8
# patterns on one run into `findings` and left the patterns bucket empty. `sab-surface` is
# checked last for the opposite reason -- every child inherits it.
LABEL_BUCKET = [
    ("sab-pattern", "patterns"),
    ("sab-rule", "rules"),
    ("sab-harness", "harnesses"),
    ("sab-crash", "crashes"),
    ("sab-finding", "findings"),
    ("sab-coverage", "coverage"),
    ("sab-surface", "surfaces"),
]

# Metadata fields kept per bucket. Everything else in metadata is dropped so the
# report schema stays stable even when a bead carries extra stamps.
KEEP_META = {
    # `coverage_ratio` is the declared-sample fraction: a node covering 13 of 706 entry
    # points is a 2% audit, and dropping the ratio here is why one campaign stamped it on
    # every node under a MUST and no part of the report could state it.
    "surfaces": ["surface", "scope", "coverage_ratio"],
    # A rule wisp had no bucket at all: with `sab-rule` absent from LABEL_BUCKET it fell
    # through to `surfaces` on its inherited `sab-surface` label, kept `surface`/`scope`
    # (neither of which it carries), and rendered as an empty surface row. `validated`
    # is the field the gremlin's own MUST turns on -- a rule that failed its fixtures is
    # handed forward disabled, and the report has to say which.
    "rules": ["rule_path", "positive_fixture", "positive_matches", "negative_fixture",
              "negative_matches", "rules_loaded", "validated"],
    # The step-12 synthesis output. Bucketed `findings` before this existed, so every
    # pattern tripped FINDING_REQUIRED on ten keys a pattern never has, and its instance
    # count and node span -- the whole reason a pattern outranks its instances -- were
    # dropped as unkept metadata.
    "patterns": ["kind", "instances", "nodes", "impact", "root_cause"],
    # `control_path` and `expected` decide whether a harness result carries a verdict at
    # all: a hostile failure beside a failing control confirms and refutes nothing. Dropping
    # them here is why a challenger asking for the control had nowhere to read it. Measured:
    # all 23 harness wisps in one campaign carried no control_path, two briefs MUST it, and
    # no part of the pipeline noticed.
    # `supersedes` and `reason` are what make a re-author wisp a re-author wisp; without
    # them it renders as another harness and the request it carries is invisible.
    "harnesses": ["entry_point", "runner", "harness_path", "input_shape", "control_path",
                  "expected", "state", "supersedes", "reason"],
    # The triager's own brief prescribes nine keys; keeping two of them dropped the
    # minimization entirely. Measured: a triager minimized 6 crashes to 65/185/71/81/2880/3
    # bytes, wrote the files to disk, and stamped them under its own invented names
    # (`min_input`, `min_bytes`, `dedup`, `triage_class`). Every crash record in the report
    # rendered blank, and nothing said the seven files existed.
    "crashes": ["input_path", "stack_hash", "state", "kind", "minimized_path",
                "minimized_bytes", "original_path", "repro_cmd", "repro_rc", "dedup_key",
                "duplicate_of", "class_closed_by"],
    # `repro_cmd` and `repro_rc` beside `repro`: the brief asked for "the reproduce command,
    # when one exists" without naming a key, so challengers stamped `repro_cmd` and the
    # renderer kept only `repro`. Measured: 0 of 386 findings stamped `repro`, 7 stamped
    # `repro_cmd`, and every reproduce command on the run's PROVEN findings was dropped --
    # the same shape as the crash keys, from the same cause of an unnamed field.
    # `found_by`, the group keys, and the step-15 stamps were each declared by a MUST and
    # then dropped here. The group keys are the sharpest case: the challenger normalizes
    # `root_cause` and elects a representative, and this renderer recomputed the grouping
    # from scratch because the stamps it needed were filtered out one function earlier.
    # `ticket_id` is the guard against filing the same ticket twice on a resumed run, so
    # dropping it made the guard unreadable by the only thing that reports it.
    "findings": ["tier", "by", "source", "impact", "locus", "path", "cwe", "repro",
                 "repro_cmd", "repro_rc",
                 "surface", "node", "evidence", "control_passed", "dedup_key",
                 "root_cause", "not_executed_reason", "found_by", "ticket_id",
                 "group_role", "group_of", "instance_count",
                 "state", "patch_files", "regression_test", "rule_graduated",
                 "verified_by", "verification"],
    # entry_points_* is the ratio a harness count cannot express: "13 of 13 harnesses ran"
    # beside 706 entry points is a 2% surface reported as complete. Measured: one node
    # enumerated 199 Tauri handlers and executed 0, and with only the harness counts kept
    # here that number reached no part of the report.
    # `skips` carries the REASON per skipped tool, which a name in `scanners_skipped`
    # cannot: "absent" and "declined" and "requires network" are different gaps, and the
    # NOT-EXECUTED register exists to distinguish them. `not_executed_reason` does the
    # same for a blocked entry-point count.
    # `partial_parse_files` is the coverage claim a file count cannot make. A partially
    # parsed file still counts in `paths.scanned`, so it looks covered while no rule reached
    # the unparsed region: opengrep exited 0 over this package having left 3 lines of
    # `run-contained.sh` unanalysed by all 301 rules. `gremlin-brief.md` MUSTs reporting it
    # and nothing here read it, which a self-audit of this package found and filed PROVEN.
    "coverage": ["scanners_run", "scanners_skipped", "harnesses_run", "harnesses_total",
                 "entry_points_total", "entry_points_executed", "surface", "skips",
                 "not_executed_reason", "partial_parse_files"],
}

# Every field a MUST in this package requires an agent to stamp, with the file:line that
# declares it. A MUST with no detector is the root cause behind every measured stamping
# count in this file's comments: the rule is written, agents follow or ignore it, and
# nothing reads the result until a human queries the store by hand months later.
#
# The declaring citation is part of the data because a gap message that names the rule is
# actionable, and one that only names a key sends the reader looking for which brief asked
# for it. `tests/test_report_json_grouping.py` asserts every entry here is either kept by
# its bucket or checked by a required-list, so a field cannot be declared and then
# silently dropped -- which is exactly what happened to 13 of them.
DECLARED_FIELDS = {
    "surfaces": [
        ("coverage_ratio", "workflow.md step 2, sizing"),
    ],
    # No `findings` entry. Its unconditional fields are already covered by
    # FINDING_REQUIRED_AT_CREATION and would double-report here, and every remaining
    # declared finding field is CONDITIONALLY mandatory: `found_by` only on a finding filed
    # outside its agent's assigned surface, and the group keys only on a finding belonging
    # to a group. A detector cannot tell "not applicable" from "not stamped" for any of
    # them. Listed here, `found_by` alone raised a gap on all 395 findings in one campaign
    # and would bury the unconditional gaps beside it. All four stay in KEEP_META, so a
    # stamped value still reaches the report.
    # No `harnesses` or `crashes` entry either: HARNESS_REQUIRED and CRASH_REQUIRED already
    # cover every unconditional field on both, and a second check would raise two gaps for
    # one missing stamp. This table exists for the buckets and fields that had NO detector,
    # which is what leaves it uneven.
    "coverage": [
        ("entry_points_total", "gremlin-brief.md, coverage record"),
        ("entry_points_executed", "gremlin-brief.md, coverage record"),
        ("skips", "gremlin-brief.md, coverage record"),
    ],
    "rules": [
        ("rule_path", "scout-brief.md, rule wisp"),
        ("positive_matches", "scout-brief.md, rule wisp"),
        ("negative_matches", "scout-brief.md, rule wisp"),
        ("rules_loaded", "scout-brief.md, rule wisp"),
        ("validated", "scout-brief.md, rule wisp"),
    ],
    "patterns": [
        ("kind", "workflow.md step 12"),
        ("instances", "workflow.md step 12"),
        ("nodes", "workflow.md step 12"),
    ],
}

# The epic's fields carry the same rule. `remediation_route` and `tracker` are the sharpest
# case: both are pinned at the interview under a MUST, read a session later by step 15, and
# measured absent from every epic in one campaign because nothing ever looked.
DECLARED_EPIC_FIELDS = [
    ("remediation_route", "interview.md, route selection"),
    ("artifacts", "workflow.md step 1"),
    ("global_scan_refs", "workflow.md step 4"),
    ("baseline_test_ref", "workflow.md step 4"),
    ("self_read_ref", "workflow.md step 4"),
]


def declared_gaps(rec, bucket):
    """Fields a MUST requires on this bucket and this record does not carry.

    Reported as one gap per record rather than one per field, because a wisp missing six
    stamps is one authoring mistake and six rows would rank it above six real defects.
    """
    missing = [(k, src) for k, src in DECLARED_FIELDS.get(bucket, []) if k not in rec]
    return missing


# The epic's own keep-list, which was four hardcoded names at the render call. The route
# and the tracker are what step 15 acts on, pinned at the interview and read a session
# later, so a report that omits them cannot say what the campaign decided to do with its
# own findings. The three pre-pass refs are the evidence that the whole-tree scanners,
# the baseline suite, and the self-read ran at all.
EPIC_KEEP = ("target", "base_sha", "budget", "artifacts", "remediation_route", "tracker",
             "threat", "checkout_path", "global_scan_refs", "baseline_test_ref",
             "self_read_ref")

# Every one of these must be PRESENT on a finding wisp, with an explicit null where it
# does not apply. A missing key and a deliberate null read identically to a renderer, so
# an omission becomes a blank column that looks like a considered "not applicable".
# Split by PHASE, because the finder and the challenger stamp different halves and a
# single list made a compliant run fail by construction. `gremlin-brief.md` instructs the
# finder to leave `tier`, `by`, and `impact` UNSET -- judging its own output is the one
# thing the role separation forbids -- while this list required all three at creation.
# Measured: 90 of 388 findings in one campaign carried no `by`, read at the time as 90
# agents ignoring a MUST; the briefs had in fact been followed and the validator was
# asking the finder for the challenger's work.
FINDING_REQUIRED_AT_CREATION = [
    "source", "locus", "surface", "node", "evidence", "dedup_key", "root_cause",
]
FINDING_REQUIRED_ONCE_TIERED = [
    "tier", "by", "impact", "control_passed", "not_executed_reason",
]

# A finding is past the tiering phase once it carries a tier, so the tier is its own phase
# marker and no separate stamp is needed to know which list applies.
def finding_required(meta):
    req = list(FINDING_REQUIRED_AT_CREATION)
    if meta.get("tier"):
        req += FINDING_REQUIRED_ONCE_TIERED
    return req


FINDING_REQUIRED = FINDING_REQUIRED_AT_CREATION + FINDING_REQUIRED_ONCE_TIERED

# The same rule for a crash wisp, which is the one bucket whose whole value is a file on
# disk. A crash with no path to its input is unreproducible whatever its title claims, and
# a triager that stamped under non-canonical names produced exactly that shape: six wisps,
# seven minimized files present, nothing in the report reaching them.
CRASH_REQUIRED = ["state", "kind", "minimized_path", "repro_cmd", "repro_rc", "dedup_key"]

# And for a harness wisp. `control_path` takes an explicit "none" when the harness asserts
# no guard, because the challenger's tiering rule turns on knowing which of those two it is.
# Measured: 23 of 23 harness wisps in one campaign omitted it while two briefs MUST it, so
# every guard assertion on the run was untierable and nothing in the pipeline said so.
# NOT phase-split, unlike the finding list, because a harness has no reliable phase marker.
# The gremlin RELEASES a claimed wisp back to `open` with `state` stamped, so `open` means
# either "authored, never claimed" or "claimed, run, and released without the stamp" -- and
# the second is the defect worth catching. Measured: 161 of 193 wisps in one campaign came
# back to `open` unstamped, which a status-based split would have read as never-claimed and
# passed. The fuzzer instead stamps `state:pending` at creation, per the state table in
# `beads-store.md`, so a compliant create satisfies this list on the first write.
HARNESS_REQUIRED = ["entry_point", "harness_path", "runner", "control_path", "expected",
                    "state"]

# Every campaign bead carries this label, so a bead belonging to an audit is separable
# from the project's own backlog by one query. Without it a project's "close every bead"
# release gate counts the audit's own records as outstanding work: measured, one campaign
# left 680 beads in a product repo's store, of which only 351 were product defects, and
# the gate blocked on its own bookkeeping.
AUDIT_LABEL = "sab-audit"

# Buckets that are never a product defect. A harness, a crash record, a coverage record,
# and a surface root are all audit bookkeeping, so each carries `non-work` as well as its
# own label. Measured: 22 surface roots, 24 coverage records, and 6 crash records reached
# the end of one campaign with no `non-work` label, because the label rule named only
# harness, crash, and coverage wisps and nothing checked any of them.
NON_DEFECT_BUCKETS = ("harnesses", "crashes", "coverage", "surfaces")

# A finding whose locus is inside the run's own artifacts dir is a defect in the AUDIT, not
# in the product: a synthesized rule that misfires, a scanner substitute that emits nothing.
# It is worth keeping and worth fixing, and it must never be counted as a product finding.
# Measured: 6 findings in one campaign had a locus under `.sabot/run-<id>/artifacts/`, all
# 6 tiered PROVEN or REACHABLE, none labelled, and only 2 of the 6 carried the `TOOLING:`
# title prefix -- so the title is not the detector and the locus is.
#
# Matched by path COMPONENT against this run's own artifacts root, never by substring: a
# substring test for `/artifacts/` labelled a product file such as src/artifacts/parser.py
# as audit tooling and dropped it from the product's defect total.
#
# run-contained.sh mounts the run's artifacts volume here, so a locus recorded from inside
# a contained run names the run's artifacts by this path.
CONTAINER_ARTIFACTS = ("/", "artifacts")
# workflow.md step 1's default artifacts dir under the target, with `{run_id}` filled in.
DEFAULT_ARTIFACTS = (".sabot", "{run_id}", "artifacts")

# Priority derived from the two axes, so it carries the information the axes carry rather
# than the creating agent's default. Measured: 14 of 21 surfaces in one campaign were 100%
# P2, and the two worst findings in the whole run sat at P2 beside 82 MEDIUM ones -- a
# reader sorting by priority saw nothing. A tier and an impact are already on every
# finding, so the priority is a function of them and never an independent judgement.
PRIORITY_BY_TIER_IMPACT = {
    ("PROVEN", "CRITICAL"): 0, ("REACHABLE", "CRITICAL"): 0,
    ("PROVEN", "HIGH"): 1, ("REACHABLE", "HIGH"): 1,
    ("PROVEN", "MEDIUM"): 2, ("REACHABLE", "MEDIUM"): 2,
    ("PROVEN", "LOW"): 3, ("REACHABLE", "LOW"): 3,
    ("HARDENING", "CRITICAL"): 2, ("HARDENING", "HIGH"): 2,
    ("HARDENING", "MEDIUM"): 3, ("HARDENING", "LOW"): 4,
    ("REFUTED", "CRITICAL"): 4, ("REFUTED", "HIGH"): 4,
    ("REFUTED", "MEDIUM"): 4, ("REFUTED", "LOW"): 4,
}

# Ranking, in order. Five keys, because a run producing hundreds of findings is read
# top-down and then abandoned; the reader's attention is the scarce resource.
TIER_RANK = {"PROVEN": 0, "REACHABLE": 1, "HARDENING": 2, "REFUTED": 4}
IMPACT_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
UNTIERED_RANK = 3          # between HARDENING and REFUTED: unjudged, not dismissed
UNRANKED_IMPACT = 4


def run_export(bd):
    """`bd export --all` from the repo root.

    An EMPTY result and a FAILED query are distinguished deliberately. `bd` discovers its
    store relative to cwd, and on a query `--labels` (plural) is accepted and silently
    returns nothing, which once made a whole wisp set read as "no work exists". So an
    empty export is reported as an empty export, never as an absence of findings.
    """
    try:
        out = subprocess.run(
            [bd, "export", "--all"],
            capture_output=True, text=True, check=True,
        ).stdout
    except FileNotFoundError:
        sys.exit(f"report-json: {bd} not on PATH")  # exit 1 via message
    except subprocess.CalledProcessError as e:
        sys.stderr.write(e.stderr or "")
        sys.stderr.write(
            f"report-json: `{bd} export --all` failed. Run it from the repo root: the "
            "store is discovered relative to cwd, so a bd that answers in $HOME and not "
            "here is the same as no bd at all.\n"
        )
        sys.exit(3)
    if not out.strip():
        sys.stderr.write(
            f"report-json: `{bd} export --all` returned NOTHING. That is an empty store "
            "or the wrong cwd, not a run with no findings. Refusing to render an empty "
            "report that would read as a clean audit.\n"
        )
        sys.exit(3)
    return out


def parse_meta(bead):
    m = bead.get("metadata")
    if isinstance(m, str):
        try:
            m = json.loads(m)
        except ValueError:
            m = {}
    return m or {}


def edges(bead):
    """Non-parent dependency edges, reshaped to (type, to). parent-child is the tree
    and is represented by `parent`, so it is not repeated as a correlation edge."""
    out = []
    for d in bead.get("dependencies") or []:
        etype = d.get("type", "")
        if etype == "parent-child":
            continue
        out.append({"type": etype, "to": d.get("depends_on_id")})
    return out


def parent(bead):
    for d in bead.get("dependencies") or []:
        if d.get("type") == "parent-child":
            return d.get("depends_on_id")
    return None


def comments(bead):
    return [c.get("text", "") for c in bead.get("comments") or []]


# When an agent drops a wisp's own label, only the inherited `sab-surface` remains.
# The metadata shape still identifies the kind, so classify by it as a fallback and
# let the caller flag the mislabel -- the same defend-in-depth as the run_id gap.
META_SIGNATURE = [
    ("harnesses", ("entry_point", "harness_path")),
    ("coverage", ("harnesses_total", "scanners_run")),
    ("crashes", ("input_path", "stack_hash")),
    ("findings", ("tier", "locus")),
]


def bucket_of(bead):
    labels = set(bead.get("labels") or [])
    own = [b for lbl, b in LABEL_BUCKET if lbl in labels and lbl != "sab-surface"]
    if own:
        return own[0], False  # a real own-label match
    meta = parse_meta(bead)
    for bucket, keys in META_SIGNATURE:
        if any(k in meta for k in keys):
            return bucket, True  # inferred from metadata: the own label was dropped
    if "sab-surface" in labels:
        return "surfaces", False
    return None, False


def _path_parts(path: str) -> tuple[str, ...]:
    return PurePosixPath(posixpath.normpath(path)).parts


def artifacts_roots(epic_meta: dict, run_id) -> set[tuple[str, ...]]:
    """Path-component prefixes that name THIS run's artifacts dir, in every form a locus
    takes: the stamped absolute path, that path relative to the target (a locus is
    relative to the repo), the default `.sabot/<run_id>/artifacts`, and the in-container
    mount."""
    roots = {CONTAINER_ARTIFACTS}
    bases = [_path_parts(b) for b in (epic_meta.get("target"), epic_meta.get("checkout_path"))
             if isinstance(b, str) and b.startswith("/")]
    stamped = epic_meta.get("artifacts")
    if isinstance(stamped, str) and stamped.strip():
        own = _path_parts(stamped.strip())
        roots.add(own)
        roots.update(own[len(b):] for b in bases if len(own) > len(b) and own[:len(b)] == b)
    if run_id:
        default = tuple(part.format(run_id=run_id) for part in DEFAULT_ARTIFACTS)
        roots.add(default)
        roots.update(b + default for b in bases)
    return roots


def audit_tooling(bead, roots: set[tuple[str, ...]]) -> bool:
    """True when this finding's locus is inside the run's own artifacts, which makes it a
    defect in the audit rather than in the product. Read from the locus, not the title:
    only 2 of 6 such findings in one campaign announced themselves in their title."""
    locus = parse_meta(bead).get("locus")
    if not isinstance(locus, str) or not locus.strip():
        return False
    # `file:line`, `file:line:col`, and `file:start-end` all name the file before the colon.
    parts = _path_parts(re.sub(r"(:\d+(-\d+)?)+$", "", locus.strip()))
    return any(parts[:len(root)] == root for root in roots)


def label_gaps(bead, bucket, tooling: bool):
    """The labels this bead should carry and does not. `tooling` is `audit_tooling()`
    for a finding.

    Kept separate from the emitted record: `labels` and `priority` are noise a report never
    renders, so they are read off the raw bead here and dropped by `shape`.
    """
    labels = set(bead.get("labels") or [])
    want = []
    if AUDIT_LABEL not in labels:
        want.append(AUDIT_LABEL)
    non_defect = bucket in NON_DEFECT_BUCKETS or (
        bucket == "findings"
        and (parse_meta(bead).get("tier") == "REFUTED" or tooling)
    )
    if non_defect and "non-work" not in labels:
        want.append("non-work")
    return want


def priority_gap(bead, bucket):
    """The priority this finding should carry and does not, or None.

    Only findings are ranked. A bookkeeping record has no severity to express, so leaving
    its priority alone is correct rather than an omission.
    """
    if bucket != "findings":
        return None
    meta = parse_meta(bead)
    want = PRIORITY_BY_TIER_IMPACT.get((meta.get("tier"), meta.get("impact")))
    if want is None:
        return None
    have = bead.get("priority")
    if isinstance(have, str):
        try:
            have = int(have.lstrip("Pp"))
        except ValueError:
            have = None
    return None if have == want else want


def shape(bead, bucket):
    meta = parse_meta(bead)
    kept = {k: meta[k] for k in KEEP_META.get(bucket, []) if k in meta}
    rec = {
        "id": bead.get("id"),
        "title": bead.get("title"),
        "status": bead.get("status"),
        "parent": parent(bead),
        **kept,
    }

    # `state` arrives by EITHER route, and the metadata stamp is not the documented one.
    # `beads-store.md`'s state table prescribes `bd set-state`, which writes a
    # `state:<value>` LABEL and an event bead and touches no metadata, so an agent that
    # followed the table produced a record this renderer could not see. Measured: 161 wisps
    # released with `bd set-state` carried the label and no metadata `state`, and every
    # gap check that reads `state` treated all 161 as unstamped. The label wins where both
    # exist, because `set-state` is the atomic path and a stale metadata stamp is exactly
    # what it replaces.
    if "state" in KEEP_META.get(bucket, []):
        for label in bead.get("labels") or []:
            if label.startswith("state:"):
                rec["state"] = label.split(":", 1)[1]
                break
    if "sab-chain" in set(bead.get("labels") or []):
        # A chain is an escalation built from findings already counted, so it is a real
        # result and not an additional defect. Read from the label, not the title: one
        # campaign had one bead labelled `sab-chain` and a DIFFERENT one titled "CHAIN",
        # so the two signals named disjoint beads and neither was complete.
        rec["chain"] = True
    ce = edges(bead)
    if ce:
        rec["edges"] = ce
    cm = comments(bead)
    if cm:
        rec["notes"] = cm
    return rec


def parents_of(bead):
    """Every candidate parent: the `parent-child` edge targets AND the id prefix.

    Both, never one. bd ids are hierarchical (a child of `x.1` is `x.1.n`), and the edge
    is supposed to agree with the prefix. When it does not, preferring the edge silently
    detaches the whole subtree from the epic. Measured: a 680-bead campaign's 21 surface
    nodes carried ids under the run epic and `parent-child` edges pointing at twelve
    unrelated project beads, so a walk that trusted the edge alone reached 0 of 680 and
    the report rendered an empty run at exit 0 -- a clean audit, by the bytes.
    """
    out = []
    for d in bead.get("dependencies") or []:
        if d.get("type") == "parent-child" and d.get("depends_on_id"):
            out.append(d["depends_on_id"])
    bid = bead.get("id") or ""
    if "." in bid:
        prefix = bid.rsplit(".", 1)[0]
        if prefix not in out:
            out.append(prefix)
    return out


def parent_of(bead):
    """The single parent a record renders, preferring the edge."""
    p = parents_of(bead)
    return p[0] if p else None


def misparented(bead, run_ids):
    """The edge targets that disagree with this bead's id prefix.

    An audit bead parented into the project's own tree is how a campaign's records become
    indistinguishable from the project's backlog, and it is what detaches a subtree from
    the epic. Returned for the register rather than silently repaired.
    """
    bid = bead.get("id") or ""
    if "." not in bid:
        return []
    prefix = bid.rsplit(".", 1)[0]
    return [
        d["depends_on_id"]
        for d in (bead.get("dependencies") or [])
        if d.get("type") == "parent-child" and d.get("depends_on_id")
        and d["depends_on_id"] != prefix
    ]


def resolve_epic(beads, epic_id, run_id):
    """Find the epic by id, or by run_id when only that was given."""
    for b in beads:
        if epic_id and b.get("id") == epic_id:
            return b
    if run_id:
        for b in beads:
            if b.get("issue_type") == "epic" and parse_meta(b).get("run_id") == run_id:
                return b
    return None


def descendants(beads, epic_id):
    """Every bead under the epic, by walking parent-child edges (with id-prefix
    fallback). Structure is the scope: a finding belongs to the run because it
    descends from the epic, not because an agent remembered to stamp run_id."""
    children = {}
    for b in beads:
        for p in parents_of(b):
            children.setdefault(p, []).append(b.get("id"))
    by_id = {b.get("id"): b for b in beads}
    out, stack = {}, [epic_id]
    while stack:
        node = stack.pop()
        for cid in children.get(node, []):
            if cid not in out and cid in by_id:
                out[cid] = by_id[cid]
                stack.append(cid)
    return out


def threat_terms(threat):
    """The epic's stamped threat, split into comparable terms.

    The threat has been stamped on the epic since the interview and has never once been
    used for ordering, so a run aimed at one fear reported its findings in bead order.
    """
    if not threat:
        return []
    out = []
    for term in str(threat).replace("/", " ").replace(",", " ").split():
        term = term.strip().lower()
        if len(term) > 3:
            out.append(term)
    return out


def threat_aligned(finding, terms):
    """Whether a finding matches the user's stated threat. Cheap and textual on purpose:
    a CWE-to-threat ontology would be a guess dressed as a mapping."""
    if not terms:
        return False
    haystack = " ".join(
        str(finding.get(k) or "").lower()
        for k in ("title", "cwe", "root_cause", "surface", "locus", "path")
    )
    return any(term in haystack for term in terms)


def dedup_key_of(finding):
    """The wisp's own key, or a derived fallback.

    Derived is recorded as derived: the finder knows the vulnerability class and a later
    pass reconstructing it from a one-line title is guessing, so a group built on a
    fallback key must be visible as such rather than presented as the finder's judgment.

    The derived key has the canonical `<locus>:<class>` shape and leaves the surface out,
    so the same locus filed from two surfaces collapses onto one group as independent
    confirmation instead of reading as two findings.
    """
    key = finding.get("dedup_key")
    if isinstance(key, str) and key.strip():
        return key.strip().lower(), False
    derived = ":".join(
        str(finding.get(k) or "?").strip().lower()
        for k in ("locus", "cwe")
    )
    return derived, True


def group_findings(findings, threat):
    """Collapse instances onto dedup_key, then onto root_cause.

    224 loci were collapsed onto a single boundary BY HAND in one run. Both collapses are
    now data: a dedup_key on more than one wisp is the same finding found twice, which is
    independent confirmation rather than two findings, and a shared root_cause is one
    defect with many loci.
    """
    terms = threat_terms(threat)
    by_key = {}
    for f in findings:
        key, derived = dedup_key_of(f)
        slot = by_key.setdefault(key, {"instances": [], "derived_key": derived})
        slot["instances"].append(f)
        slot["derived_key"] = slot["derived_key"] or derived

    groups = []
    for key, slot in by_key.items():
        instances = sorted(
            slot["instances"],
            key=lambda f: (
                TIER_RANK.get(f.get("tier"), UNTIERED_RANK),
                IMPACT_RANK.get(f.get("impact"), UNRANKED_IMPACT),
                str(f.get("locus") or ""),
                str(f.get("id") or ""),
            ),
        )
        rep = instances[0]
        tiers = sorted({i.get("tier") or "UNTIERED" for i in instances})
        groups.append({
            "dedup_key": key,
            "dedup_key_derived": slot["derived_key"],
            "representative": rep.get("id"),
            "title": rep.get("title"),
            # One tier per group: the strongest evidence any instance carries, because a
            # group reported at its weakest instance understates what was proven.
            "tier": min(tiers, key=lambda t: TIER_RANK.get(t, UNTIERED_RANK)),
            "tiers_seen": tiers,
            "impact": rep.get("impact"),
            "surface": rep.get("surface"),
            "root_cause": rep.get("root_cause"),
            "locus": rep.get("locus"),
            "cwe": rep.get("cwe"),
            "evidence": rep.get("evidence"),
            "instance_count": len(instances),
            "instances": [i.get("id") for i in instances],
            "loci": sorted({str(i.get("locus")) for i in instances if i.get("locus")}),
            "confirmed_independently": len(instances) > 1,
            "threat_aligned": any(threat_aligned(i, terms) for i in instances),
        })

    groups.sort(key=lambda g: (
        TIER_RANK.get(g["tier"], UNTIERED_RANK),          # 1 evidence tier
        IMPACT_RANK.get(g["impact"], UNRANKED_IMPACT),     # 2 impact
        0 if g["threat_aligned"] else 1,                   # 3 the epic's stamped threat
        -g["instance_count"],                              # 4 how many loci it covers
        str(g["locus"] or ""),                             # 5 locus, for a stable order
    ))
    for i, g in enumerate(groups, 1):
        g["rank"] = i
        g["group_role"] = "representative"
    return groups


def systemic_patterns(groups):
    """Roll groups up by root_cause. The most valuable conclusion of one whole campaign
    -- eight independent built-but-never-wired instances -- was produced by no step at
    all, so the rollup is a section rather than a reader's inference."""
    by_cause = {}
    for g in groups:
        cause = (g.get("root_cause") or "").strip()
        if not cause:
            continue
        slot = by_cause.setdefault(cause, {
            "root_cause": cause, "groups": [], "instance_count": 0,
            "surfaces": set(), "tiers": set(),
        })
        slot["groups"].append(g["representative"])
        slot["instance_count"] += g["instance_count"]
        if g.get("surface"):
            slot["surfaces"].add(g["surface"])
        slot["tiers"].add(g["tier"])
    out = []
    for slot in by_cause.values():
        out.append({
            "root_cause": slot["root_cause"],
            "group_count": len(slot["groups"]),
            "instance_count": slot["instance_count"],
            "groups": slot["groups"],
            "surfaces": sorted(slot["surfaces"]),
            "tier": min(slot["tiers"], key=lambda t: TIER_RANK.get(t, UNTIERED_RANK)),
            # A defect appearing on more than one surface is a systemic pattern rather
            # than a local bug, and that is the distinction a reader acts on.
            "cross_surface": len(slot["surfaces"]) > 1,
        })
    out.sort(key=lambda r: (-r["instance_count"], -r["group_count"], r["root_cause"]))
    return out


def not_executed_register(findings, coverage, surfaces, harnesses=()):
    """One line per unexercised dimension, with its reason.

    `not_executed_reason` is a first-class field rather than an absence, because a
    scanner that failed to run was repeatedly recorded as "0 findings" -- the same bytes
    as a clean result.
    """
    register = []
    for f in findings:
        reason = f.get("not_executed_reason")
        if isinstance(reason, str) and reason.strip():
            register.append({"kind": "finding-placeholder", "id": f.get("id"),
                             "surface": f.get("surface"), "locus": f.get("locus"),
                             "reason": reason.strip()})
        elif f.get("control_passed") is False:
            # A control that did not fire means the locus is UNTESTED: the harness proved
            # nothing about the code, only that it ran.
            register.append({
                "kind": "control-failed", "id": f.get("id"),
                "surface": f.get("surface"), "locus": f.get("locus"),
                "reason": "the benign control did not pass, so this locus is UNTESTED "
                          "and the finding cannot be trusted either way",
            })
    # A reproduce command with no expected exit code cannot be replayed to a verdict: the
    # reader runs it, gets a number, and has nothing to compare it against. Measured: two
    # findings carried a command and no rc, and the hardener's own gate quotes the rc before
    # and after a patch to decide FIXED against NOT FIXED.
    for f in findings:
        cmd = f.get("repro_cmd") or f.get("repro")
        if isinstance(cmd, str) and cmd.strip() and f.get("repro_rc") is None:
            register.append({
                "kind": "repro-without-an-exit-code", "id": f.get("id"),
                "surface": f.get("surface"), "locus": f.get("locus"),
                "reason": "a reproduce command is recorded with no expected exit code, so "
                          "running it produces a number with nothing to compare against. "
                          "The harden route decides FIXED against NOT FIXED by quoting the "
                          "rc before and after, and cannot run at all without it",
            })

    # A wisp still claimed at report time is a claim nobody released. An agent cannot close
    # a wisp, so the release is a status change back to `open`, and resume reads
    # `in_progress` as in-flight while the gremlin's discovery query filters on `open`.
    # Measured: 161 of 193 harness wisps were left claimed at the end of one campaign. A
    # resumed run would have read all 161 as still running and discovered none as work, so a
    # claim never released is the same as a harness lost.
    for h in harnesses:
        if h.get("status") == "in_progress":
            register.append({
                "kind": "wisp-left-claimed", "id": h.get("id"),
                "surface": h.get("surface"), "locus": h.get("entry_point"),
                "reason": "this wisp is still in_progress at report time, so a resumed run "
                          "reads it as in-flight and the gremlin's open-status discovery "
                          "query will not find it. Release a claim back to open with the "
                          "state stamped once the harness has run",
            })

    # A REFUTED finding the audit itself disproved and left open outlives the run as
    # apparent work. The no-delete rule keeps the wisp and its refutation; it does not ask
    # for the wisp to stay open. Measured: 35 of 36 REFUTED findings in one campaign were
    # still open at report time, so a third of the run's "outstanding" findings were ones it
    # had already dismissed.
    for f in findings:
        if f.get("tier") == "REFUTED" and f.get("status") != "closed":
            register.append({
                "kind": "refuted-finding-left-open", "id": f.get("id"),
                "surface": f.get("surface"), "locus": f.get("locus"),
                "reason": "this finding is REFUTED and still open, so it reads as outstanding "
                          "work in every backlog query. Close it with reason `refuted`, "
                          "keeping the wisp and its refutation, which is what the no-delete "
                          "rule requires",
            })

    # A harness the gremlin found broken leaves its entry point uncovered, and the brief
    # requires a re-author wisp naming what to rewrite. Nothing enforced that. Measured: one
    # campaign ran roughly a dozen harnesses that reported themselves broken -- one at rc=3
    # saying its own canary never fired -- and filed ZERO re-author wisps, so every one of
    # those entry points read as uncovered rather than as needing a rewrite. Separately, 192
    # of 193 harness wisps carried no `state` at all, which makes a broken harness and a
    # clean run the same record.
    superseded = {h.get("supersedes") for h in harnesses if h.get("supersedes")}
    for h in harnesses:
        if h.get("state") in ("invalid", "broken") and h.get("id") not in superseded:
            register.append({
                "kind": "broken-harness-with-no-re-author-route", "id": h.get("id"),
                "surface": h.get("surface"), "locus": h.get("entry_point"),
                "reason": "this harness is invalid and no wisp supersedes it, so its entry "
                          "point is UNTESTED with no route back. File the re-author wisp "
                          "the gremlin brief prescribes; a harness that reports itself "
                          "broken closes nothing on its own",
            })
    # `budget_exhausted` says coverage was STILL GROWING when the clock ran out, which is a
    # different claim from a harness that ran to a plateau: the first names a gap that more
    # budget would close and the second does not. `beads-store.md` MUSTs distinguishing it
    # from `reported`, and nothing here read it, so both arrived as the same clean record. A
    # self-audit of this package caught it in the same sweep that found `partial_parse_files`
    # and `total_s`, after two rounds of dismissing it as a status value.
    for h in harnesses:
        if h.get("state") == "budget_exhausted":
            register.append({
                "kind": "harness-stopped-on-the-clock", "id": h.get("id"),
                "surface": h.get("surface"), "locus": h.get("entry_point"),
                "reason": "this harness hit its wall-clock cap with coverage still climbing, "
                          "so its entry point is PARTIALLY tested and more budget would test "
                          "it further. State the remaining budget it asked for; a harness "
                          "stopped by the clock is not a harness that found nothing",
            })

    for c in coverage:
        # `scanners_skipped` is a list of NAMES. A count in its place is not a smaller
        # version of the field: "9 skipped" identifies none of the nine, and nothing
        # downstream can say which invariant went unchecked. Measured: 21 of 22 coverage
        # wisps in one campaign stamped both scanner fields as integers and one as a comma
        # string, and iterating an int raised TypeError -- the whole report died rather
        # than naming the wisp. Register the mis-stamp instead of crashing on it, and
        # never silently coerce it into a name.
        skipped = c.get("scanners_skipped")
        if isinstance(skipped, (int, float)) or isinstance(skipped, str):
            register.append({
                "kind": "scanner-skip-list-not-stamped", "id": c.get("id"),
                "surface": c.get("surface"), "locus": None,
                "reason": f"scanners_skipped is {skipped!r}, not a list of scanner names, "
                          "so no skipped scanner can be named and no invariant traced to "
                          "the tool that went unrun",
            })
            skipped = []
        for name in (skipped or []):
            register.append({"kind": "scanner-skipped", "id": c.get("id"),
                             "surface": c.get("surface"), "locus": None,
                             "reason": str(name)})
        # `scanners_run` carries the same mis-stamp and matters for the same reason from the
        # other direction: a run list of `7` claims coverage that names no tool, so nothing
        # can check the claim against what the image holds or against a finding's `source`.
        # Measured: 23 of 27 coverage records stamped it as a count, one as a string, while
        # findings on two surfaces recorded `source: stock-pack` for lints that clippy
        # actually produced -- a mismatch no reader could have caught either way.
        ran = c.get("scanners_run")
        if isinstance(ran, (int, float, str)):
            register.append({
                "kind": "scanner-run-list-not-stamped", "id": c.get("id"),
                "surface": c.get("surface"), "locus": None,
                "reason": f"scanners_run is {ran!r}, not a list of scanner names, so this "
                          "record claims coverage without naming a single tool that "
                          "produced it and no finding's source can be checked against it",
            })
        run, total = c.get("harnesses_run"), c.get("harnesses_total")
        if isinstance(run, int) and isinstance(total, int) and run < total:
            register.append({
                "kind": "harnesses-unrun", "id": c.get("id"),
                "surface": c.get("surface"), "locus": None,
                "reason": f"{total - run} of {total} authored harness(es) never executed",
            })
        # A harness ratio measures the harnesses, not the surface. "13 of 13 ran" beside
        # 706 entry points is 2% coverage reported as complete, and one node enumerated
        # 199 handlers and executed 0 of them.
        ep_run, ep_total = c.get("entry_points_executed"), c.get("entry_points_total")
        if not isinstance(ep_total, int):
            # The brief says stamp `entry_points_executed: 0` with the mechanism in
            # `not_executed_reason` when the count is blocked, because an absent ratio is
            # the same blank as a full one. Nothing enforced it, and the check above needs
            # two ints to fire at all -- so omitting the field silently bought a pass.
            # Measured: 24 of 27 coverage wisps carried no entry_points_total, leaving the
            # surface ratio unknown almost everywhere while the harness counts read complete.
            register.append({
                "kind": "entry-point-ratio-not-stamped", "id": c.get("id"),
                "surface": c.get("surface"), "locus": None,
                "reason": "this coverage record carries no entry_points_total, so what "
                          "fraction of the surface was reached is unknown. A harness ratio "
                          "measures the harnesses; stamp the count, or stamp 0 with the "
                          "mechanism when counting is blocked",
            })
        elif not isinstance(ep_run, int):
            register.append({
                "kind": "entry-point-ratio-not-stamped", "id": c.get("id"),
                "surface": c.get("surface"), "locus": None,
                "reason": f"this coverage record counts {ep_total} entry point(s) and does "
                          "not say how many were reached, which reads identically to "
                          "having reached all of them",
            })
        elif ep_run < ep_total:
            register.append({
                "kind": "entry-points-unexecuted", "id": c.get("id"),
                "surface": c.get("surface"), "locus": None,
                "reason": f"{ep_total - ep_run} of {ep_total} entry point(s) on this "
                          "surface were never executed, whatever the harness count says",
            })
    # A finding asserting a scanner found nothing, on a surface whose own coverage says
    # that scanner was SKIPPED, is a clean nobody earned. Measured: one node stamped
    # clippy as "not installed for toolchain 1.97.1" AND filed a HARDENING finding that
    # clippy obtained zero lint findings on the crate. Clippy was installed the whole
    # time; run later it checked 513 crates and returned zero warnings. The conclusion
    # happened to be right, which is precisely why nothing caught it -- so the check is on
    # the contradiction, never on whether the claim looks plausible.
    for c in coverage:
        skipped = c.get("scanners_skipped")
        if not isinstance(skipped, list):
            continue
        names = set()
        for entry in skipped:
            tool = entry.get("tool") if isinstance(entry, dict) else entry
            if isinstance(tool, str) and tool.strip():
                names.add(tool.strip().lower())
        if not names:
            continue
        for f in findings:
            if f.get("surface") != c.get("surface"):
                continue
            text = f"{f.get('title') or ''}. {f.get('root_cause') or ''}".lower()
            # Match the clean-claim within the CLAUSE naming the tool, not anywhere in the
            # finding. One real title read "clippy obtains zero lint findings ... and
            # rustfmt plus cargo-nextest are absent from the image": a whole-string match
            # blamed nextest, which that title calls absent -- agreeing with the skip
            # rather than contradicting it. The contradiction was clippy's, and naming the
            # wrong tool in a gap register is its own fail-open.
            for clause in re.split(r"[.;]|,\s*(?:and|plus|but)\s+", text):
                claims_clean = any(p in clause for p in (
                    "zero", "no finding", "0 finding", "clean", "nothing", "no lint"))
                if not claims_clean:
                    continue
                for tool in sorted(names):
                    if tool not in clause:
                        continue
                    register.append({
                        "kind": "clean-claimed-for-a-skipped-scanner", "id": f.get("id"),
                        "surface": f.get("surface"), "locus": f.get("locus"),
                        "reason": f"this finding asserts {tool} found nothing, while "
                                  f"coverage wisp {c.get('id')} records {tool} as SKIPPED "
                                  "on the same surface. A tool that did not run cannot "
                                  "have produced a clean result, so one of the two is "
                                  "wrong and neither may be reported as coverage",
                    })

    covered = {c.get("surface") for c in coverage if c.get("surface")}
    for s in surfaces:
        name = s.get("surface")
        if name and name not in covered:
            # The fail-open this closes: gaps used to be derived only from the coverage
            # records that EXIST, so a surface that filed none produced an empty gap list
            # and a clean exit.
            register.append({
                "kind": "no-coverage-record", "id": s.get("id"), "surface": name,
                "locus": None,
                "reason": "the surface node filed no sab-coverage record, so nothing "
                          "states what ran on it. Absence of a record is not coverage.",
            })
    register.sort(key=lambda r: (r["kind"], str(r["surface"]), str(r["id"])))
    return register


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epic", help="the run epic bead id (preferred)")
    ap.add_argument("--run-id", help="the run_id metadata (resolves the epic when --epic is absent)")
    ap.add_argument("--bd", default="bd")
    ap.add_argument("-o", "--out")
    args = ap.parse_args()

    if not args.epic and not args.run_id:
        sys.exit("report-json: --epic or --run-id is required")
    if not shutil.which(args.bd):
        sys.exit(3)

    beads = []
    for line in run_export(args.bd).splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            beads.append(json.loads(line))
        except ValueError:
            continue

    epic = resolve_epic(beads, args.epic, args.run_id)
    if epic is None:
        sys.exit(4)  # epic not found
    epic_id = epic.get("id")
    run_id = parse_meta(epic).get("run_id")
    own_artifacts = artifacts_roots(parse_meta(epic), run_id)

    report = {
        "run_id": run_id,
        "epic_id": epic_id,
        "epic": None,
        "surfaces": [], "harnesses": [], "crashes": [],
        "findings": [], "coverage": [],
        "patterns": [], "rules": [],
        "stamping_gaps": [],
    }
    report["epic"] = shape(epic, "epic")
    report["epic"].update(
        {k: parse_meta(epic).get(k)
         for k in EPIC_KEEP
         if k in parse_meta(epic)}
    )

    # The epic is one bead, so its gaps were never covered by the per-bucket loop below.
    # Measured: one campaign's epic carried none of remediation_route, tracker,
    # global_scan_refs, baseline_test_ref, or self_read_ref -- five MUSTs, nothing stamped,
    # and the report that read the epic asked for four keys and never missed the rest.
    # The campaign ceiling. `workflow.md` MUSTs an owner for `total_s`, and nothing read it:
    # one campaign exceeded its 1800s ceiling by roughly 50x with no part of the pipeline
    # noticing, because the budget was stamped at step 3 and never compared to anything. A
    # self-audit of this package found that and filed it PROVEN. Reported as a gap when the
    # ceiling is absent, since a budget with no ceiling bounds nothing.
    budget = report["epic"].get("budget") or {}
    if isinstance(budget, dict) and not budget.get("total_s"):
        report["stamping_gaps"].append({
            "id": report["epic"].get("id"), "bucket": "epic",
            "issue": "the budget carries no `total_s`, so the campaign has no wall-clock "
                     "ceiling to be measured against. One run overran an 1800s ceiling by "
                     "roughly 50x and nothing detected it, because the only record of the "
                     "ceiling was the stamp nobody read.",
        })

    epic_missing = [(k, src) for k, src in DECLARED_EPIC_FIELDS
                    if k not in report["epic"]]
    if epic_missing:
        names = ", ".join(f"{k} ({src})" for k, src in epic_missing)
        report["stamping_gaps"].append({
            "id": report["epic"].get("id"), "bucket": "epic",
            "issue": f"run epic missing declared field(s): {names}. The remediation route "
                     "is the sharpest: step 15 reads it off the epic rather than "
                     "re-deciding it, so an unstamped route means a later session cannot "
                     "know what the user chose.",
        })

    # Select by descent from the epic, not by a run_id stamp: a properly parented
    # finding is never silently dropped, even when its run_id was not stamped.
    for bid, bead in descendants(beads, epic_id).items():
        bucket, mislabeled = bucket_of(bead)
        if not bucket:
            continue
        rec = shape(bead, bucket)
        tooling = bucket == "findings" and audit_tooling(bead, own_artifacts)
        if tooling:
            # Flagged on the record so the report can total product defects apart from the
            # audit's own. A tiered defect in a synthesized rule is real work and belongs in
            # the report; counted among the product's findings it inflates them.
            rec["audit_tooling"] = True
        report[bucket].append(rec)

        stray = misparented(bead, run_id)
        if stray:
            report["stamping_gaps"].append({
                "id": bid, "bucket": bucket,
                "issue": f"parent-child edge(s) point at {stray}, which is not this bead's id "
                         f"prefix. An audit bead parented into the project's own tree is "
                         "indistinguishable from the project's backlog, and a walk that "
                         "trusted the edge alone reached 0 of 680 beads on one campaign and "
                         "rendered an empty report at exit 0. Reparent it under its surface "
                         "node with `bd dep add`.",
            })

        want_labels = label_gaps(bead, bucket, tooling)
        if want_labels:
            report["stamping_gaps"].append({
                "id": bid, "bucket": bucket,
                "issue": f"bead missing label(s): {want_labels}. Every campaign bead carries "
                         f"{AUDIT_LABEL!r} so a project's own release gate can exclude an "
                         "audit's records from its backlog, and every bookkeeping record "
                         "carries 'non-work' so it is not counted as a defect. Measured: one "
                         "campaign left 680 beads in a product repo, 329 of them non-defects, "
                         "and the project's \"close every bead\" gate blocked on them.",
            })

        want_priority = priority_gap(bead, bucket)
        if want_priority is not None:
            report["stamping_gaps"].append({
                "id": bid, "bucket": bucket,
                "issue": f"priority is {bead.get('priority')!r} and this finding's tier and "
                         f"impact make it P{want_priority}. Priority is a function of the two "
                         "axes, never a separate judgement. Measured: 14 of 21 surfaces in one "
                         "campaign were entirely P2, and the run's two worst findings sat at P2 "
                         "beside 82 MEDIUM ones, so sorting by priority ordered nothing.",
            })

        # The generic detector. Every entry it reads is a field some MUST in this package
        # requires, and before this existed a compliant stamp and a missing one produced
        # the same report.
        undeclared = declared_gaps(rec, bucket)
        if undeclared:
            names = ", ".join(f"{k} ({src})" for k, src in undeclared)
            report["stamping_gaps"].append({
                "id": bid, "bucket": bucket,
                "issue": f"declared-mandatory field(s) not stamped: {names}. Each is "
                         "required by the cited rule, and each was unchecked until now: "
                         "the counts behind these rules were all found by querying a live "
                         "store by hand, months after the campaign that produced them.",
            })

        bead_run = parse_meta(bead).get("run_id")
        if bead_run != run_id:
            report["stamping_gaps"].append(
                {"id": bid, "bucket": bucket, "run_id": bead_run, "issue": "missing run_id"}
            )
        if mislabeled:
            want = {"harnesses": "sab-harness", "crashes": "sab-crash",
                    "findings": "sab-finding", "coverage": "sab-coverage"}.get(bucket, bucket)
            report["stamping_gaps"].append(
                {"id": bid, "bucket": bucket, "issue": f"classified as {bucket} by metadata; {want} label missing"}
            )

    # A field missing from a finding wisp is a blank column the report cannot fill, and
    # it is indistinguishable from a deliberate null unless it is named here.
    for f in report["findings"]:
        missing = [k for k in finding_required(f) if k not in f]
        if missing:
            report["stamping_gaps"].append({
                "id": f.get("id"), "bucket": "findings",
                "issue": f"finding wisp missing required field(s): {missing}. Use an "
                         "explicit null where a field does not apply; an omission reads "
                         "as a considered 'not applicable'.",
            })

    # A crash whose input the report cannot name is unreproducible, and it renders exactly
    # like a crash that was never minimized. Named rather than blanked, so a triager that
    # stamped under its own key names is visible instead of silently discarded.
    for c in report["crashes"]:
        missing = [k for k in CRASH_REQUIRED if k not in c]
        if missing:
            report["stamping_gaps"].append({
                "id": c.get("id"), "bucket": "crashes",
                "issue": f"crash wisp missing required field(s): {missing}. The minimized "
                         "input may well exist on disk; without these keys no part of this "
                         "report can reach it, and the crash reads as untriaged.",
            })

    # A harness wisp with no control_path leaves every guard it asserts untierable, and a
    # blank field reads the same as a harness that deliberately asserts no guard.
    for h in report["harnesses"]:
        missing = [k for k in HARNESS_REQUIRED if k not in h]
        if missing:
            report["stamping_gaps"].append({
                "id": h.get("id"), "bucket": "harnesses",
                "issue": f"harness wisp missing required field(s): {missing}. Stamp "
                         "control_path as \"none\" when the harness asserts no guard; the "
                         "challenger cannot tier a hostile result without knowing whether a "
                         "benign control existed and passed.",
            })

    threat = parse_meta(epic).get("threat")
    report["threat"] = threat
    report["groups"] = group_findings(report["findings"], threat)
    report["systemic_patterns"] = systemic_patterns(report["groups"])
    report["not_executed"] = not_executed_register(
        report["findings"], report["coverage"], report["surfaces"], report["harnesses"]
    )

    by_tier, by_impact, by_source = {}, {}, {}
    for f in report["findings"]:
        by_tier[f.get("tier", "UNTIERED")] = by_tier.get(f.get("tier", "UNTIERED"), 0) + 1
        if f.get("impact"):
            by_impact[f["impact"]] = by_impact.get(f["impact"], 0) + 1
        # A skill rule requires the report to SAY when a campaign was carried by stock
        # packs, because stock packs are the borrowed detectors and a run relying on them
        # did no recon. `source` was kept per finding and totalled nowhere, so the rule had
        # no mechanism: nobody reads 386 findings to compute the mix by hand.
        src = f.get("source") or "unstamped"
        for part in str(src).split("+"):
            part = part.strip() or "unstamped"
            by_source[part] = by_source.get(part, 0) + 1

    # Coverage gaps come from a set DIFFERENCE against the detected surfaces, not from a
    # walk of the records that happen to exist: a surface that filed no coverage record
    # used to produce an empty gap list and exit 0.
    covered = {c.get("surface") for c in report["coverage"] if c.get("surface")}
    surface_names = {s.get("surface") for s in report["surfaces"] if s.get("surface")}
    gaps = [c["id"] for c in report["coverage"]
            if c.get("harnesses_run") != c.get("harnesses_total")]
    missing_records = sorted(surface_names - covered)

    # Three counts that must balance. Derived, never asserted: a table that has to add up
    # is the check, and a hand-written count cannot disagree with itself.
    instance_count = len(report["findings"])
    grouped_instances = sum(g["instance_count"] for g in report["groups"])
    report["summary"] = {
        "by_tier": by_tier,
        "by_impact": by_impact,
        "by_source": by_source,
        # The recon question, answered as a fraction rather than left to a reader's
        # impression. A campaign whose findings all came from stock packs aimed nothing at
        # this repo, and the rule requiring the report to say so had nothing computing it.
        "stock_pack_only": bool(by_source) and set(by_source) <= {"stock-pack"},
        "findings_from_recon_rules": by_source.get("synthesized-rule", 0),
        # The count a reader actually wants, and the one a bare finding total misstates. A
        # REFUTED finding is one the run disproved, an audit-tooling finding is a defect in
        # the run's own rules, and a chain composes findings already counted -- none of the
        # three is a product defect. Measured: a campaign reporting 641 hardening beads held
        # 351 product defects, and the difference was read as a backlog.
        "product_defects": sum(
            1 for f in report["findings"]
            if f.get("tier") != "REFUTED" and not f.get("audit_tooling")
            and not f.get("chain")
        ),
        "refuted": by_tier.get("REFUTED", 0),
        "audit_tooling_findings": sum(1 for f in report["findings"] if f.get("audit_tooling")),
        "chains": sum(1 for f in report["findings"] if f.get("chain")),
        "counts": {
            "groups": len(report["groups"]),
            "instances": instance_count,
            "wisps": len(report["findings"]) + len(report["crashes"])
                     + len(report["harnesses"]) + len(report["coverage"]),
            "grouped_instances": grouped_instances,
            "balances": grouped_instances == instance_count,
            "note": "every instance belongs to exactly one group, so grouped_instances "
                    "must equal instances. A mismatch means a finding was dropped "
                    "between the graph and the report.",
        },
        # A group built on a key this script derived is the finder's judgment reconstructed
        # from a title, and it reads in the report exactly like a stamped one. Measured: a
        # 383-finding campaign stamped `dedup_key` on none of them, so every group was
        # derived and the challenger's prescribed `uniq -d` dedup returned nothing over
        # seven real cross-surface duplicate loci.
        "groups_on_a_derived_dedup_key": sum(
            1 for g in report["groups"] if g["dedup_key_derived"]
        ),
        "coverage_gaps": gaps,
        "surfaces_without_a_coverage_record": missing_records,
        "not_executed_count": len(report["not_executed"]),
        "systemic_pattern_count": len(report["systemic_patterns"]),
        "stamping_gaps": len(report["stamping_gaps"]),
        "threat_aligned_groups": sum(1 for g in report["groups"] if g["threat_aligned"]),
    }

    out = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(out + "\n")
    else:
        print(out)

    if not report["summary"]["counts"]["balances"]:
        sys.stderr.write(
            "report-json: the count table does not balance: "
            f"{grouped_instances} grouped instance(s) against {instance_count} "
            "finding(s). A finding was dropped between the graph and the report; the "
            "report above understates the run.\n"
        )
        return 5
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
