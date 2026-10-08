# Hardener Brief Template

Construct one Brief per approved finding at step 15. `hardener` patches product code,
writes a regression test, graduates the rule into the repo's own lint config when the
approval covers that, and re-runs the exact scanner and harness that produced the
finding.

Pass the approval verbatim and one finding id. Approval for one finding approves that
finding alone.

---

```
You apply ONE approved fix for a sabot campaign on this repository, then prove it
holds by re-running the exact checks that found it. You leave every change
uncommitted.

## Scope
- Run epic: <bead id>
- Finding to fix: <finding wisp id>, `locus` <file:line>, tier <TIER>, impact <LEVEL>
- Working directory: <repo root, or the worktree path for a ref target>
- Artifacts dir: <absolute path>
- Approval, verbatim: <the user's own words approving THIS finding>

Read the finding wisp before you touch anything:
    bd show <finding> --json > <artifacts>/fix-<finding>.json

## One approval, one finding
Approval names a finding id and covers that defect's complete fix: the locus, the
direct callers the fix requires, and the tests whose expectation it legitimately
changes. A neighbouring locus with the same root cause, a second instance in the same
group, and a defect you notice while patching are all unapproved.

| Situation | Action |
|---|---|
| the approved finding, including a caller or test its fix requires | patch it |
| another instance sharing its `root_cause` | file a follow-up wisp with `discovered-from`, and report it as awaiting approval |
| a defect you found while reading | file a finding wisp, do not patch |
| the fix changes behavior the approval did not cover: a public contract, a numeric bound, or a caller outside the finding's call path | stop and report ESCALATED with the file list and what the real fix requires |

MUST Quote the approval in your return, and name the single finding id it covers. A group of instances patched under one approval spends an approval nobody gave.

## Never make a failing check pass by weakening the check
This is the defect class the whole campaign documents, and this project's own suite
hit it twice. A check edited to stop failing reports success while measuring nothing.

| Prohibited edit | What it looks like | What it costs |
|---|---|---|
| relaxing an assertion instead of fixing the code | an assertion that a required file exists rewritten to accept the file being absent | the check now passes on the exact condition it was written to catch |
| leaving an assertion measuring the build profile | a panic-on-overflow assertion that fires under `debug` alone, while the release profile sets no `overflow-checks` | the shipped binary wraps silently and the test suite stays green |
| widening a suppression, an allowlist, or an ignore file | adding the new locus to `.semgrepignore`, a baseline, or an `#[allow]` | the finding disappears from the report with the defect in place |
| deleting or skipping the failing test | `#[ignore]`, a commented-out assertion, a narrowed glob | the regression has no guard |
| loosening a rule so it stops matching | editing the synthesized rule rather than the code | every future instance goes unreported |

MUST Assert the VALUE rather than the panic wherever the consequence is profile-dependent, and run the verification against a release build when the release profile differs. A `debug_assert!` and an unchecked arithmetic overflow both measure the profile.
NOT Never edit a test, an assertion, a rule, a suppression, a baseline, or a lint config in the direction of accepting the defect. Report the fix as BLOCKED instead, and say which check you would have had to weaken.

## A verification re-run inherits every execution guarantee
Re-run the exact scanner invocation and the exact harness that produced the finding,
inside the container per `references/isolation.md`. Prove each one ran:

| Check | Command evidence | Failure reading |
|---|---|---|
| the test binary ran the tests | a nonzero test count and the named test in the output | `running 0 tests` at rc=0 is NOT EXECUTED, and a filter that matches nothing exits 0 |
| the regression test fails before the patch | run it against the pre-patch tree first, and record the failure | a test passing before the fix guards nothing |
| the scanner output is fresh | the result file's mtime is after the run started, and the scanned-file count is nonzero | a stale result file from an earlier attempt reads as a completed clean scan |
| the rule loaded | the tool's own loaded-rule count matches the rule file | a rule that loads zero reports zero findings |
| the harness control still passes | the control's own result | a hostile case passing beside a failing control proves nothing |
| the run hit no resource limit | SIGKILL/137, an OOM message, ENOSPC, a lost log | an INVALID run verifies nothing in either direction |

MUST Paste the verbatim invocation and its output line for every check above. A wrapper's exit code proves nothing about whether the tool inside it ran.
MUST Re-run the SAME scanner invocation and the SAME harness that produced the finding, not a substitute. A different invocation verifies a different claim.
MUST Report the fix as UNVERIFIED when any check above cannot be run, and say which. An unverified fix presented as verified is worse than an open finding, because it closes the finding.

## Graduate the rule, not just the instance
A regression test guards one locus. Only the rule guards the next one. When the
recorded approval covers graduation, land the detecting rule in the repo's own
configuration so CI runs it; without that approval, record the rule as proposed and
leave the config alone.

| Where the finding came from | What to land |
|---|---|
| a synthesized semgrep or ast-grep rule | the rule file at the repo's own lint-config path, wired into the config the repo's CI invokes |
| a clippy lint | the lint in the workspace lint config, by name. Verify the group: two productive lints in one run live in clippy's `restriction` group, which the workspace `all` plus `pedantic` config never selects, so a fix with no config change left the class unguarded |
| a stock pack rule | the pack, or the single rule, in the repo's scanner config |
| a harness | the harness at the repo's own test or fuzz-target path, wired into the runner CI invokes |

Verify the graduation rather than asserting it: run the repo's own check entry point
(`just check`, `make lint`, the CI command) and show the new rule or lint appearing in
its output. A rule added to a file that no entry point reads is not wired.

MUST Show the graduated rule firing from the repo's own check command, before and after the config edit, naming the entry point. A rule that does not fire from that entry point is NOT GRADUATED. One run's two productive lints live in clippy's `restriction` group, which the workspace `all` plus `pedantic` config never selects, so the rule sat where CI never looks.
MUST Report a graduation you could not wire, with the entry point that would need to change. That is a wiring patch for the repo's owner rather than a silent gap.

### Lint-config edits go one direction only
A lint config is product code. Editing it needs the same explicit per-finding
approval as the code patch, and it appears as its own line in the report rather than
folded into the fix.

| Permitted | Forbidden |
|---|---|
| add a rule | remove or downgrade any rule |
| raise an existing rule's level | lower a level, or narrow a rule's scope |
| move a lint out of a group the config does not reach | add an `allow`, `nosec`, `.semgrepignore` entry, baseline entry, or any new suppression |
| remove an unreasoned suppression | widen an existing suppression's scope |

The suppression census from step 4 makes the forbidden direction diffable. Record
both counts before and after, from the project's own config:

    # before the patch, and again after
    jq '[.suppressions[]] | length' <security config>
    jq '[.suppressions[] | select((.reason // "") == "")] | length' <security config>

| Count movement | Verdict |
|---|---|
| either count lower, or both unchanged | permitted |
| either count higher | FORBIDDEN. Revert the config edit and report the fix as BLOCKED |

MUST Paste both counts from before and after the patch. One target's config held 331 suppressions with 82 unreasoned, so the pair of numbers is the check on the edit's direction.
MUST List every lint-config edit as its own report line, naming the finding that approved it. A config change folded into a code fix is an approved patch plus an unapproved one.
NOT Never make a check pass by editing the check's configuration. That is the same defect as editing the check's assertion.

## Regression test
Write one test per PROVEN finding, beside the repo's existing tests, in the repo's own
convention. Prove the pre-patch failure and the post-patch pass, and stamp it:

    TEST=$(bd create "regression: <finding title>" --parent <finding> --labels sab-harness,sab-audit,non-work --no-inherit-labels --json \
      --metadata '{"run_id":"<RUN_ID>","test_path":"<abs>","test_name":"<name>","pre_patch":"fail","post_patch":"pass"}' | jq -r '.id')
    bd dep add "$TEST" <finding> --type validates

MUST Pass `--no-inherit-labels` on the regression wisp. Parented to the finding, it would otherwise inherit `sab-finding` and every finding query, the challenger's work list included, would count it as a second finding.

## What you MUST NOT do
- Patch anything the approval does not name.
- Commit, push, stage, or open a pull request. Leave every change uncommitted.
- Weaken a check, a test, a rule, a suppression, or a lint config. A lint-config edit runs in the permitted direction alone, per the table above, and under its own approval.
- Set or change an evidence tier. Stamp the fix; `sabot-challenger` re-tiers on the re-run.
- Close the finding wisp. The main thread closes at report time.
- Report a fix as verified on a wrapper exit code alone.

## Stamp the fix
    bd update <finding> --metadata '{"patch_files":["<abs>"],"regression_test":"<TEST id>","rule_graduated":"<config path or null>","verified_by":["<scanner invocation>","<harness wisp id>"],"verification":"<verified|UNVERIFIED>"}'
    bd set-state <finding> state=patched --reason "patched; verification=<verified|UNVERIFIED>"
    bd update <finding> --status in_progress
    bd comment <finding> "PATCHED files=<n> test=<TEST id> rule=<config path> verification=<verified|UNVERIFIED> evidence=<abs artifact path>"
Use `bd set-state`, never a metadata `state`, per `references/beads-store.md`. Read
the wisp back after stamping.

## Return
The Hardener Output format from your agent definition: the approval quoted, the single
finding id, the files changed with a one-line description each, the pre-patch failure
and post-patch pass output for the regression test, the verbatim re-run output for
every check in the execution-guarantee table, each lint-config edit as its own line
with the suppression counts before and after, the entry-point output showing the
graduated rule firing, and any follow-up wisp ids awaiting approval. State that
nothing is committed.
```

---

## Filling guidance

- **Quote the approval verbatim.** A paraphrased approval is not an approval, and
  the hardener has no other way to know what was covered.
- **Name the exact scanner invocation and harness wisp.** A hardener that
  reconstructs the invocation verifies a different claim than the one approved.
- **Say which build profile the verification must use.** A release-profile
  consequence verified under `debug` is unverified.
- **State the repo's own check entry point.** Graduation means CI runs the rule, and
  the entry point is the only place that can be shown.
- **One finding per Brief.** Batching two findings into one hardener makes the
  verification output ambiguous about which patch it proves.
