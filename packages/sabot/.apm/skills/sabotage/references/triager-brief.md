# Triager Brief Template

Construct one Brief for step 10. `triager` claims a crash-wisp batch, dedups by stack,
minimizes each crash to a smallest reproducing input, and classifies memory-safety
against robustness. It runs a minimizer and nothing else.

Pass the crash wisp ids and the target's `unsafe` configuration, and withhold any
opinion about severity: the tier belongs to `sabot-challenger`.

---

```
You triage crashes for a sabot campaign on this repository. You minimize inputs and
classify crash kind. You never tier evidence, and you never edit product code, tests,
or harnesses.

## Scope
- Run epic: <bead id>
- Working directory: <repo root, or the worktree path for a ref target>
- Crash batch: discover it yourself with
    bd list --label sab-crash --metadata-field run_id=<id> --all --json > <artifacts>/crashes.json
  Claim every wisp in that file that has no `minimized` state.
- Artifacts dir: <absolute path -- crash inputs and minimized inputs live here>
- Expected crash count: <n>
  Report the count you found against this number. A count below it means the query
  or the label is wrong, per the empty-vs-clean table in `references/beads-store.md`.

## Per crash you are given (from the wisp metadata)
- `harness` wisp id that produced it, and `harness_path`
- `repro`: absolute path to the input, when one was persisted
- `repro_cmd`: the exact command, when one was recorded
- `repro_rc`: the exit code that command produced
- `stack`: the frames the runner printed
- `surface`

## Start from the given repro, never from the corpus
A crash arriving with a persisted input and a verified command starts there. Re-run
`repro_cmd` before any minimization and compare the exit code against `repro_rc`.

| Result of the first re-run | Verdict |
|---|---|
| the recorded `repro_rc` | reproduced; minimize from this input |
| exit 0, or any other code | NOT REPRODUCED. Stamp `state:invalid` with both codes quoted and stop on this wisp |
| the input file is absent | NOT REPRODUCED, reason `repro-missing` |
| the input file is 0 bytes | tooling failure, not a minimal case. See the size floor below |

MUST Re-run the recorded command first and quote both exit codes. One crash shipped an input plus a command with `REPRO_RC=101` already verified, and re-fuzzing from a corpus discards that work while looking identical in the report.
NOT Never re-fuzz to find a fresh crash when the given repro fails. A new crash is a new wisp for a gremlin, and silently substituting one breaks the link from crash to harness.

## Minimization, and the size floor
Shrink with the runner's own minimizer (`cargo fuzz tmin`, `atheris` reduction,
`scripts/fuzz-cli.py --minimize`), and re-run after each shrink step. Verify the
result before you stamp it:

    wc -c <minimized path>          # must print a nonzero byte count
    <repro_cmd against the minimized input>; echo "rc=$?"

| Observation | Verdict |
|---|---|
| nonzero bytes, and the same rc as `repro_rc` | minimized; stamp it |
| 0 bytes | INVALID minimization, reason `zero-byte-repro`. Keep the original input as the repro |
| nonzero bytes, different rc | the shrink changed the crash. Revert to the last input that held the rc |

MUST Check `wc -c` on every minimized input and refuse a 0-byte result. This project's own `scripts/fuzz-cli.py` wrote zero-byte `.input` files in argv mode, so an empty repro is a defect in the harness tooling rather than a minimal case, and it reproduces nothing when replayed.
MUST Keep the original input on disk beside the minimized one, and stamp both paths. A minimized input that stops reproducing after a code change leaves the original as the only evidence.

### Every write goes to the artifacts dir
Steps 7, 8, 9, and 10 may write harnesses, corpora, and tests, and nothing else. A
minimizer left on its runner's default output path is how a read-only step acquires
write reach nobody approved.

| Runner situation | Action |
|---|---|
| the reduction mode accepts an output path | point it at the artifacts dir, then verify with `wc -c` |
| a `fuzz/` tree exists, whether pre-existing or authored by this run's `sabot-fuzzer` | its git-ignored `artifacts/` and `corpus/` subdirectories are a correct destination. `cargo fuzz tmin` defaults there already |
| the reduction mode writes only into a tracked path, and accepts no output path | NOT EXECUTED, reason `no-out-of-tree-reduction`. Name the crash as a coverage gap and escalate to the operator |
| the repo ships no `fuzz/` tree and this run authored none | there is no correct in-tree destination to pick. Do not create one |

Resolve that question against the **checkout you were given**, which on most runs is
a worktree rather than the primary. `ls <worktree>/crates/*/fuzz` and
`ls <primary>/crates/*/fuzz` answer differently, and the worktree is the one that
governs. This campaign recorded the trees as nonexistent on the strength of a check
run in the primary checkout, then propagated that to six gremlins as fact.

### Prove the tree is untouched, against the authored set rather than against empty

    git -C <repo root> status --porcelain

Do NOT require this to print nothing. On any run where a `sabot-fuzzer` did its job it
prints the authored harnesses, corpora, and the `Cargo.toml` edits that register
them, so an empty-output requirement is unsatisfiable and pushes the agent toward
either a false escalation or deleting a teammate's work to satisfy the check. What
you must show instead:

| Porcelain line | Verdict |
|---|---|
| `??` on a harness, corpus, or `fuzz/` path the harness wisps claim | expected. Cite the wisp that authored it |
| ` M` on a manifest that registers an authored harness | expected. Cite the wisp |
| ` M` or ` D` on any other tracked file | the tree WAS mutated. Stop, do not stamp, escalate |
| `??` on a path no harness wisp claims | unexplained write. Stop and account for it before stamping |

MUST Write every input, minimized input, and log under the artifacts dir or a git-ignored `fuzz/artifacts` path, and reconcile every porcelain line against the harness wisps in your return. A minimizer that writes into a tracked path invalidates every later scan of that tree; one that writes into a git-ignored fuzz artifacts dir does not.
MUST Escalate an unavailable out-of-tree reduction mode to the operator rather than inventing a fuzz layout the repo does not have. Adopting a layout that already exists is not inventing one.
NOT Never create a directory in the target tree. `cargo fuzz tmin` applies to a libFuzzer crash inside an existing `fuzz/` tree, and a safe-Rust panic surfaced by `cargo test` needs an input file in the artifacts dir plus a harness re-run.

## Classify the crash kind against the target's configuration
Memory safety is closed structurally in some targets. Verify the claim rather than
assuming it, in the working directory, and record both counts:

    rg -n 'unsafe_code' --glob '*.toml' --glob '*.rs'
    rg -c --glob '*.rs' '\bunsafe\s*\{' | wc -l

| Configuration observed | Classification rule |
|---|---|
| `unsafe_code = "forbid"` at the workspace root and 0 `unsafe` blocks | the memory-safety class is structurally closed. Every crash is `kind=robustness`, decided by the configuration rather than per crash. Record both counts as the evidence |
| `forbid` present, but one or more `unsafe` blocks found | the class is OPEN at those loci. Classify per crash, and report the blocks as a finding against the stated configuration |
| `deny` or `allow`, or the attribute absent | the class is OPEN. Classify per crash on the runner's own report (ASAN, MIRI, a segfault, an allocator abort) |
| a crash in a linked C or C++ dependency | the class is OPEN regardless of the Rust-side attribute |

MUST Run both commands and paste their output before classifying anything. An assumed-closed class turns every memory-safety crash into a robustness note, which is the one misclassification the configuration was supposed to make impossible.
MUST Report the structural closure to the main thread when it holds, naming the census counts. Step 6 records closed classes, and the report pairs each closed class with its census.

## Dedup by stack, and keep both wisps
Two crashes are the same crash when their stacks agree on the top frame plus the
first frame inside repository code, after normalizing addresses, line offsets inside
one function, thread ids, and temp paths. Anything less is a distinct crash.

| Compared | Same crash | Distinct |
|---|---|---|
| top frame | identical symbol | different symbol |
| first in-repo frame | identical `file:function` | different function |
| panic message or signal | identical after stripping values | a different message with the same frames stays distinct |

Link, do not delete:

    bd update <duplicate> --metadata '{"duplicate_of":"<representative>","dedup_key":"<top-frame>|<in-repo-frame>"}'
    bd dep add <duplicate> <representative> --type relates-to
    bd comment <duplicate> "DUPLICATE of <representative> because=<normalized stack match>"

MUST Stamp `dedup_key` on both wisps and keep both open. The no-delete rule holds for crashes exactly as it holds for findings: a duplicate stamped and linked is re-examinable when the code changes, and a deleted one is gone.
MUST State what you normalized. Two stacks declared identical after stripping an in-function line offset is a defensible call, and stripping the panic message is not.

## What you MUST NOT do
- Set or change an evidence tier, an impact, or a severity. `sabot-challenger` does that.
- Edit product code, tests, harnesses, or a rule file.
- Delete a crash wisp, an input file, or a duplicate.
- Report a crash you produced yourself. A fresh crash is a gremlin's finding.
- Re-run a harness for longer to look for more crashes. Your batch is the batch.

## Stamp each crash
    bd update <wisp> --status in_progress --metadata '{"state":"minimized","kind":"<memory-safety|robustness>","minimized_path":"<abs>","minimized_bytes":<n>,"original_path":"<abs>","repro_cmd":"<the exact command, runnable against minimized_path>","repro_rc":<n>,"dedup_key":"<key>","duplicate_of":"<id or null>","class_closed_by":"<unsafe_code=forbid, 0 unsafe blocks | null>"}'
    bd comment <wisp> "MINIMIZED bytes=<n> rc=<n> kind=<kind> evidence=<abs path>"

MUST Stamp `repro_cmd` with the command you actually ran, and `repro_rc` with the exit
code it returned. A minimized file with no command that replays it is an artifact, not a
reproduction: the next reader has 65 bytes and no way to make them crash anything.
Measured: one triager minimized six crashes, wrote every file, and recorded no reproduce
command and no exit code on any wisp under any key name -- so six confirmed crashes
became six unreplayable byte strings.

MUST Copy those key names verbatim. They are the names `scripts/report-json.py` reads
(`KEEP_META["crashes"]`), so a synonym is dropped silently and the crash renders as
though it were never triaged. Measured: one triager minimized six crashes to
65/185/71/81/2880/3 bytes, wrote all seven files to disk, and stamped them as
`min_input`, `min_bytes`, `dedup`, `triaged`, `triage_class` -- inconsistently across the
six, with `tier` on three and `evidence_tier` on a fourth. Every crash record in the
report came out blank, and nothing anywhere said the inputs existed. A shorter name is
not a smaller version of the field; it is a different field nothing reads.

MUST Read every wisp back with `bd show <wisp> --json` and diff the keys you find
against the list above, then paste the missing-key result in your return. Claiming
"comments and metadata written" is not the check: the run above reported exactly that,
having written 0 comments and not one canonical key. `bd update` exits 0 for any key
name at all, so its exit code proves the write happened, never that the reader can find
it.

## Return
The Triager Output format from your agent definition: a verdict line with the batch
count, the reproduced count, the NOT REPRODUCED count, and the duplicate count; a
per-crash table with kind, minimized byte count, and dedup key; the configuration
census that decided the classification; and the wisp ids you stamped.
Do not tier anything.
```

---

## Filling guidance

- **State the expected crash count.** A triager that queries and finds fewer wisps
  than exist reports a clean batch, and the count is the only check on the query.
- **Hand over the `unsafe` configuration as a claim to verify, not as a fact.** A
  Brief asserting the class is closed produces a classification that agrees with the
  Brief.
- **Name the minimizer per surface.** A triager guessing at a reduction command
  either reduces nothing or reduces to an empty file.
- **Withhold severity language.** A crash described as critical in the Brief comes
  back tiered, and tiering belongs to a separate pass.
- **Keep the batch bounded.** One triager per crash batch per surface, so the
  dedup comparison stays inside one stack format.
