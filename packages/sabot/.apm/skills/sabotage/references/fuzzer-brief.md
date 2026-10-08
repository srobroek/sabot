# Fuzzer Brief Template

Construct one Brief per surface for step 7. `sabot-fuzzer` writes harnesses, corpora, and
attack scenarios, and executes nothing. Pass facts only: the surface with its entry
points and conventions, and the wisp to file against.

Spawn the fuzzers in parallel, one message with several Agent calls, one per
surface in the step-5 recon.

---

```
You author attack material for the **<SURFACE>** surface of this repository. You
write harnesses and corpora. You run nothing.

## Scope
- Surface: <code | shell | agents | infra | robustness>
- Files: <explicit resolved paths for this surface, not "the whole repo">
- Working directory: <repo root, or the worktree path for a ref target>
- Exclude: <generated, vendored, fixtures>
- Surface node bead: <bead id -- file every harness wisp under this parent>
- run_id: <the epic's run_id -- stamp it on every wisp you create, verbatim>
- Artifacts dir: <absolute path -- write harness files and corpora here or at the
  repo-convention path, and record which>

## Invariants recon derived (assert these)
<the falsifiable claims from step 5: what the code assumes and never checks, each
with a file:line. These are what your harnesses assert. An invariant here beats a
generic never-panics harness, because it catches logic bugs a crash never reveals.>

## Trust boundaries recon mapped
<where data crosses from less trusted to more trusted, with a file:line each, plus
what the code assumes holds after each boundary. Aim harnesses at the assumption.>

## Idiom deviations recon found
<the places this repo departs from its own pattern, with the census count. Each one
is a candidate for a repo-specific rule or a targeted harness.>

## Entry points to cover
<the reachable entry points found in step 2: parse functions, CLI commands, hook
scripts, HTTP handlers, config readers, agent definitions. One line each with a
file:line. This is your STARTING work list -- it sets the initial focus so you do
not sweep the whole repo, not a ceiling. Harness a reachable entry point you find
that this list missed WITHIN this surface and the resolved file set, and record it
on the surface node. Do not cross into another surface or outside the scope globs;
an entry point beyond them is a note for the orchestrator, not yours to harness.>

## Attack-vector baseline recon ranked (write these first)
<the boundary-anchored vectors from `escalation.md`, ranked by the blast radius of
the assumption each breaks. Each names a boundary file:line and the vector class its
shape invites. Author the highest-ranked first, since the budget is finite and the
top boundary is where a proven finding pays for the run.>

## Input shape per entry point (from recon, do not re-infer)
<the input protocol recon recorded for each entry point: raw bytes, single JSON,
JSONL, msgpack, protobuf, argv, env, or a schema/grammar the repo ships. This picks
the generator in `fuzz-tools.md`, and recon already determined it, so read it here
rather than re-deriving it. A wrong pick spends the whole budget failing at the
parser. Stamp it on the harness wisp as `input_shape`.>

## Repo conventions (mirror these)
- Fuzz target location: <fuzz/fuzz_targets/ | *_test.go | tests/fuzz/ | none found>
- Test runner: <cargo test --no-fail-fast | go test | pytest | vitest> (a fail-fast runner over many binaries reports the first failure, not the surface, which is an INVALID run rather than a low finding count)
- Existing fixtures to seed from: <paths>
- Property-test library already in the project: <proptest | hypothesis | fast-check | none>

## Your references
Read `references/harnesses.md` FIRST for invariant selection and placement rules.
Read `references/surfaces/<SURFACE>.md` for the attack checklist this surface
demands. For the agents surface, read `references/corpora/prompt-injection.md`.
Do not improvise a catalogue.

## Budget context (you do not run anything; this shapes what you write)
- Per-harness wall-clock: <wall_s>s
- A harness that cannot reach its target inside that window is the wrong harness:
  narrow the entry point instead of widening the input space.

## Authoring ban (safety)
Never author an input whose effect is irreversible, even though `gremlin` runs it in
a container: fuzz the code path that RECEIVES `rm -rf`/`mkfs`/`DROP TABLE`, never a
harness that EXECUTES it. A destructive-looking payload is data the target parses
(`{"command":"rm -rf /"}` fed to a guard), not a command the harness runs. See
`references/isolation.md`.

## What to produce
1. One harness per reachable entry point, at the repo-convention path, with the
   invariant stated in a comment at the top.
2. A seed corpus per harness, drawn from the repo's own fixtures first.
3. For CLIs, hooks, and MCP servers: a vectors JSON file for
   `scripts/fuzz-cli.py` instead of a bespoke harness, covering every wrapper and
   quoting form in the surface checklist plus one benign vector per guarded
   pattern.
4. A benign control for every harness that asserts a guard, paired with the hostile
   one and named `<harness>_control`. The control feeds an input the guard MUST
   accept. Without it, a failing hostile harness proves nothing: the failure may be
   the guard working, the harness being broken, or the fixture not building. Stamp
   `control_path` on the wisp. One control per assertion, and never two assertions in
   one test: a shared test stops at the first panic and leaves the second assertion
   unfired while appearing to have run.

   MUST Stamp `control_path` on every harness wisp, as the literal string `none` when the harness asserts no guard. Omitting the field and deliberately having no control are the same blank to every later reader, and the challenger's tiering rule turns on telling them apart. Measured: 245 harness wisps across one 21-surface campaign, and not one carried the field; two briefs required it, the report dropped it from its kept metadata, and every guard assertion on the run was untierable without anything saying so.
5. One harness wisp per harness, filed with the command below (not from memory).
   `--parent <surface>` and `run_id` are both required, or the harness is invisible
   to the gremlin's discovery query and never runs:

     HARNESS=$(bd create "harness: <entry point>" --parent <surface-bead> --labels sab-harness,sab-audit,non-work --json \
       --metadata '{"run_id":"<RUN_ID>","entry_point":"<file:line>","runner":"<cargo fuzz|pytest|fuzz-cli>","harness_path":"<path>","control_path":"<path or none>","expected":"<pass|fail>","input_shape":"<from recon>"}' | jq -r '.id')

## Prove the files exist before you return
Run `wc -l` over every path you claim to have written, and paste the output verbatim
into your return, one line per file. Every `harness_path` and `control_path` you
stamped must appear in it. Anything absent from that output you did not write, and
must not report as written.

A run lost two surfaces to this: a fuzzer reported authoring `fuzz/` trees under two
crates, the trees never existed, the claim reached the dispatch table as a new repo
convention, and two gremlins were sent to run harnesses that were never on disk.

Every authored artifact needs the same proof, not harnesses alone:

| Artifact | Proof in the return |
|---|---|
| harness, control, seed corpus | `wc -l` over the path |
| scenario or attack-vector file | `wc -l` over the path |
| rule file | `wc -l` plus the tool's own `rules_loaded` count, per `scout-brief.md` |
| a directory you created (`fuzz/`, `corpus/`) | `ls -ld` over the directory |

MUST Author and verify in one step, before the return. A claim made in one step and checked in another is a claim nobody checks, and the receiving gremlin treats an unproven path as NOT EXECUTED.

## Return
The Fuzzer Output format from your agent definition: a coverage block, a harness
table, and the wisp ids you created. Do not execute a harness, and do not report
findings; finding them is the gremlin's job.
```

---

## Filling guidance

- **One surface per fuzzer is the floor.** Split a surface exceeding roughly 5k
  LOC across several fuzzers by subtree or crate, each with a narrowed file list.
- **Pass the entry points, not a hypothesis.** `sabot-fuzzer` decides which invariant
  fits each entry point; handing it your guess about which function is at fault narrows
  the search wrongly.
- **State the convention explicitly.** A fuzzer that guesses the fuzz-target
  location writes files the project's test command never finds.
- **Never ask a fuzzer to run its own harness.** The write and execute split is
  what keeps a silently-broken harness from reporting a clean result.
- **Require the `wc -l` block in the return, and check it against the wisp
  metadata.** A fuzzer's report that it wrote a file is not evidence the file exists,
  and verifying costs one command.
- **Ask for the expected outcome per harness, and the control that makes it legible.**
  A harness the fuzzer expects to FAIL is a prediction, and a prediction with no
  passing control is unreadable when it comes back either way.
