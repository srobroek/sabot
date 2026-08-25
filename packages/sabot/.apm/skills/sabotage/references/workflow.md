# Workflow

The full step-by-step procedure. LOAD this before step 1. The SKILL.md list is the
index; this file is the operating detail.

## Step 0: mode and preconditions

Determine interactive or non-interactive first, since it decides whether the
blocking gates apply. Interactive is the default; non-interactive requires a
positive signal, which being handed a target is not:

| Condition | Mode |
|---|---|
| Any invocation without a non-interactive signal, even one that named a target | interactive (DEFAULT): both gates block, so ask and wait |
| The invocation says CI / cron / non-interactive, or you are a spawned sub-agent with no channel back to a human | non-interactive: skip the gates and use defaults; record every gap |

Check the two hard preconditions before anything else, and ABORT loudly (non-zero
exit, a message naming what is missing) if either fails, before opening the run graph
or spawning an agent: a container runtime must be present (`isolation.md`, No
container runtime) and `bd` must be present (`beads-store.md`). Neither is
degradable; there is no static-only or fallback-store run.

Determine the scope mode: `quick`, `full` (default), `audit-only`, or
`harness-only`.

## Step 1: open the run

1. Resolve the artifacts dir. A caller-supplied path (a spawn prompt naming an
   artifacts dir) wins; otherwise default to `<primary>/.sabot/run-<id>/artifacts`.
   Create it, and stamp the resolved path so every agent writes to the same place.
2. Create the run epic with `run_id`, `target`, `base_sha`, and `artifacts`
   metadata. The `budget` key is stamped after step 3.
3. Hold the surface nodes until step 2 has detected which surfaces exist.

MUST Let a caller-supplied artifacts dir override the default, since a sub-run spawned with an explicit path must write where the caller expects rather than forking a second location.
MUST Stamp the resolved artifacts dir on the epic before spawning any agent, so every Brief carries one path and agents do not scatter output across two dirs.

## Step 2: resolve the target and detect surfaces

1. When the user named no target, STOP and ask per the SKILL.md two-step. Do not
   assume whole repo.
2. LOAD `targeting.md`. Resolve to an explicit file list plus a base ref, and
   decide in-place or worktree checkout.
3. Detect surfaces by mapping the resolved file list against
   `surfaces/index.md`. Include `robustness` on every run.
4. Create one surface node per detected surface, with a `scope` glob array.
5. Enumerate entry points per surface, since these become the fuzzer's work list:
   parse functions, CLI commands, hook scripts, request handlers, config readers,
   agent definitions. Record each with a `file:line`.

### Sizing the nodes

A surface is a class of attack; a NODE is the unit one set of agents runs against. A
surface usually exceeds a node in size, and a node too large is sampled rather than
tested.

An atomic unit of sabotage is **one trust boundary's worth of code that one agent can
enumerate, cover with harnesses, and read inside one budget.** In a Rust workspace
that is usually one crate or one crate family sharing a boundary; in a script tree,
one directory of scripts sharing an entry shape.

Size each candidate node against the entry-point count step 2 recorded, and split or
merge before creating any bead:

| Signal | Verdict | Action |
|---|---|---|
| entry points > 4x the harness count the budget affords | TOO LARGE | split by subtree until each part fits |
| the globs span unrelated trust boundaries | TOO LARGE | split by boundary, one node each |
| harnessable share of entry points < 50% | TOO LARGE | split, and label the residue a declared sample with its ratio |
| the node cannot be reasoned about without reading a sibling's globs | TOO SMALL | merge with that sibling |
| the globs overlap a sibling's | TOO SMALL | move the overlap to one node and record which |
| entry points fit the budget, one boundary, no glob overlap | RUNNABLE | create the node |

MUST Compute `harnessable / total entry points` per node and stamp it on the node as `coverage_ratio` before spawning anything. One node in one run covered 13 of 706 entry points, which is a sample, and no artifact said so. A ratio on the bead makes the sample declared instead of discovered at report time.
MUST Split a node rather than sampling it. A node that cannot be covered inside the budget becomes several nodes; where a residue must stay uncovered, name it a declared sample with its ratio in the coverage wisp.
MUST Translate an operator's stated unit into node beads explicitly. An instruction like "one run per crate" is a sizing decision, and leaving it unrecorded means the orchestrator improvises the split and nothing checks it.
MUST Decide node size and parallelism together. Each node holds a container for the length of its run, so the node count and the concurrent-container ceiling are one decision: total nodes divided by the affordable concurrency gives the number of waves, and a node sized past the budget adds a wave rather than coverage.

MUST Treat a file count of ZERO as a claim to verify rather than an empty surface, and re-run the count with the tool's own hidden-file and ignore-file filters disabled. `fd` and `rg` both skip dotdirs and honour `.gitignore` by default, so a target whose code lives under a dotted directory counts as empty and its surface reads as absent. Measured: `fd -e sh . packages/sabot` returned 0 while `fd -u -e sh .` returned 10, every one of them under `.apm/`; a campaign that trusted the first number would have reported a clean shell audit of ten unopened files. This is the same shape as the empty-query rule in `beads-store.md`, applied to detection instead of to `bd`.
MUST Record the entry points before step 5. A fuzzer given no entry points invents its own scope and writes harnesses for code nobody calls.
MUST Record each entry point as a bare `file:line` with no threat annotation. Do not mark which entries "map onto the stated threat", label a parser "hostile-response", or rank them by suspected relevance. That annotation is the orchestrator's hypothesis, and it reaches the sabot-scout through the entry-point list and narrows the census to the guessed spot. The user's threat orders the REPORT (stamped on the epic), never the recon input.

## Step 3: probe, propose, wait

1. Run `install-tools.sh --probe` (host preflight: runtime + `bd` + `git`, and which
   surface images exist). Then DELEGATE provisioning to a spawned agent rather than
   running the builds inline: the build layers, `cargo fetch`, `npm ci`, and
   `--assert-tools` output are exactly the noisy tool payloads that flood the
   orchestrator's context. Spawn one provisioner (a `general-purpose` agent) Briefed
   with the target dir, the detected surfaces, and the base image tags, told to run
   the `isolation.md` Provisioning flow: build any missing surface image, extend each
   with the target's dev-deps via
   `scripts/build-ext-image.sh --target <dir> --base sabot/<surface>:1 --tag sabot/<surface>-ext:1`
   (it runs `detect-stacks.py`, writes a thin Dockerfile copying only the
   manifests+lockfiles, and builds the layer keyed on the lock), then `--assert-tools`
   each ext image. It returns a thin pointer only: the resolved ext-image tags plus
   the stack map, with each per-image assert result written to the artifacts dir.
   Tools run in the image, not on the host.

MUST Delegate the image build, dev-dep bake, and `--assert-tools` to a spawned provisioner that returns only the ext-image tags, the stack map, and the assert result. Building inline pours every `docker build` and `cargo fetch` line into the orchestrator's context, which is the fat-payload-in-orchestrator anti-pattern step 14 forbids; the orchestrator manages the run, it does not build it.
MUST Have the provisioner VERIFY the image is complete before it returns success: run `scripts/install-tools.sh --probe` (which asserts every tool in the manifest answers inside its image) and, for the ext image, `run-contained.sh --assert-tools` over the full surface tool list. A missing tool is a build failure the provisioner FIXES in that same step (add the tool to the fragment, rebuild) before returning, not a gap it reports for a later retry. The provisioner returns success only when every expected tool answered; a "built" image that lacks `zizmor`, `osv-scanner`, or any manifest tool is an incomplete build, and a campaign that trusts it returns a meaningless clean for that dimension.
NOT Never return a provisioned image on a partial tool set and let the campaign retry-install the rest. The image ships the complete toolset in one deterministic build; a scanner discovered missing at scan time has already produced a false clean for its threat dimension.
MUST Build and extend the surface image autonomously here, without a separate confirmation gate. The interview already authorized the toolset; provisioning the image to hold it executes that approved plan rather than deciding anything new. The blast-radius opt-ins (live-spawn, DAST) stay gated; the image build does not.
2. Build the proposal per `installer.md`: every viable tool for each detected
   surface, default-on pre-selected ON, opt-in shown OFF with its reason.
3. Build the budget table per `fuzzing.md`, stating the harness count and the
   worst-case wall-clock so the user approves a duration.
4. Stop and wait. "go" installs every missing default-on tool, accepts the
   budget, and proceeds.
5. Stamp the approved budget onto the run epic, so a resumed campaign reuses it.

## Step 4: repo-global pre-pass (scanners, baseline suite, self-read, and the project's own security config)

Several facts are the same for every surface, so computing them per surface runs the
same work N times in parallel. Run them once here, before the fan-out, and stamp the
results on the epic for every agent to read. DELEGATE the whole step to one spawned
pre-pass agent. That agent writes every output to the artifacts dir and returns only
the stamp values (`global_scan_refs`, `baseline_test_ref`, `self_read_ref`, and the
suppression list) as paths and counts:

- executes the whole-tree scanners in the provisioned image,
- runs the baseline test suite,
- reads the repo self-doc and the project security config.

The orchestrator stamps those on the epic; it never holds the scanner or test output
itself.

| Pre-pass work | Run once | Stamp on epic |
|---|---|---|
| Repo-global scanners: `dep-audit`/`secrets-scan` (or osv-scanner, gitleaks, cargo-audit), each whole-tree | one invocation, JSON to the artifacts dir | `global_scan_refs` (paths) |
| The union of cross-surface scanner invocations: one `(tool, config, file-set)` run each, routed to owning surfaces via `surfaces/index.md` | one invocation per distinct tuple | `global_scan_refs` |
| Baseline test suite (what already fails, per `surfaces/robustness.md`) | one run | `baseline_test_ref` |
| Repo self-read: the falsifiable guarantees, documented limits, `SECURITY.md` scope, and git-incident notes | one read | `self_read_ref` |

Each sabot-scout then reads `self_read_ref` instead of re-parsing the docs, and each
gremlin cites `global_scan_refs` instead of re-running a whole-tree scanner. A
surface gremlin runs only its own surface-specific scanners.

MUST Run every repo-global scanner and the repo self-read once here, not per surface. A whole-tree dependency or secret scan run once per surface is the same scan N times, and the self-read re-parses the README and git history N times.
MUST Delegate this step to a spawned agent that writes its output to the artifacts dir and returns only the stamp values (paths and counts). Running the whole-tree scanners and the baseline suite inline floods the orchestrator with the output it exists to keep OUT of its context, the same fat-payload rule as step 14.
MUST Record a pre-pass scanner in each surface's coverage as "covered by pre-pass" rather than "not run", so the coverage table credits work the surface did not repeat.
MUST Route a pre-pass finding to its owning surface per `surfaces/index.md`, so a secret in a workflow file is attributed to infra and a shared finding is not double-counted across surfaces.

### The project's own security config

Before running any scanner, find and read every config that governs it:

| Look for | Effect on findings |
|---|---|
| `.semgrepignore`, `.banditrc`, `#[allow(...)]`, `# nosec`, `//nolint` | a rule the project disabled with a stated reason caps at HARDENING |
| A scanner baseline file | anything in the baseline is pre-existing, so a diff run reports only what is new |
| `SECURITY.md`, an accepted-risk doc | a documented accepted risk is cited rather than re-reported |
| `.gitleaksignore`, a secrets allowlist | an allowlisted value is not a finding |

Count them, because the counts are the finding:

| Number | Meaning for the report |
|---|---|
| total suppressions | the size of the deliberately-unscanned surface |
| suppressions with a stated reason | each caps a related finding at HARDENING |
| suppressions with no stated reason | each caps nothing, and the count is itself a HARDENING finding |
| documented accepted risks | cited rather than re-reported |

MUST Honor the project's config. Reporting a deliberately disabled rule as a new finding destroys the report's credibility, and the user stops reading it.
MUST Cap a finding at HARDENING only against a suppression that states a reason. An unreasoned suppression earns no cap, so a finding it covers is tiered on its own evidence.
MUST Report the unreasoned-suppression count as its own HARDENING finding with the four counts above. One run measured 331 suppressions of which 82 carried no reason; the bare total would have read as 331 deliberate decisions.

## Step 5: recon

LOAD `recon.md` and follow it. Produce the trust map, invariant list, idiom census,
and synthesized rules, then record each on the run epic and carry them into every
Brief. Then LOAD `escalation.md` and build the attack-vector baseline from those
artifacts: the ranked, boundary-anchored vectors that become the fuzzer's work list.

MUST Recon before authoring, since a fuzzer with no invariants writes never-panics harnesses and nothing else.
MUST Aim the standard packs here. An unaimed pack floods the report and the reader stops separating signal from volume.

## Step 6: census the structurally closed finding classes

A language or build setting can make a whole vulnerability class unreachable in this
repo. Establish that once, here, and re-aim the campaign onto the classes that
remain.

| Signal | Class it closes | Consequence for the run |
|---|---|---|
| `unsafe_code = "forbid"` workspace-wide with zero `unsafe` blocks | memory safety in Rust | crashes are logic defects; step 10 is a probable no-op |
| a memory-safe language with no FFI and no native extension | memory safety | same |
| every input arrives from the local filesystem or the local user | remote attack surface | reframe onto local and inter-process boundaries |
| no `eval`/`exec`/template rendering of untrusted input | injection into the host language | reframe onto SQL, shell, and path construction |

MUST Census a closed class rather than asserting it. "0 `unsafe` blocks over 44 crates, `unsafe_code = "forbid"` at `Cargo.toml:31`" closes the class; "this is safe Rust" does not.
MUST Re-aim the campaign when a class is closed, and say so in the report. One run staffed a whole role for memory safety against a repo that forbids `unsafe`: 15 node-runs produced 0 crash wisps and the triager did nothing. The budget belonged on logic, ordering, and durability invariants.
MUST Keep the class in the report as a closed class with its census, since "we found no memory-safety bugs" and "memory-safety bugs are structurally impossible here" are different claims and only the second is worth reading.

## Step 7: author the attack plan

Spawn one `fuzzer` per surface, in parallel, Briefed from `fuzzer-brief.md`. Each
writes harnesses, corpora, vectors, and repo-specific rules from recon's
invariants. It files a wisp per artifact and runs nothing.

`harness-only` mode stops here and reports what was written.

## Step 8: attack

Spawn one `gremlin` per surface node, in parallel, Briefed from
`gremlin-brief.md`. Each one:

1. Runs its surface's scanners, the packs recon aimed, and the rules recon synthesized.
2. Claims and executes the harness wisps for its surface, inside the budget.
3. Reads the code against recon's trust map, then the surface attack checklist.
4. Clears candidates against the surface false-positive traps.
5. Files crash wisps and finding wisps.

MUST Treat a scanner crash as INVALID and fix the invocation, since "0 findings" from a tool that never ran is the most damaging possible report line.
MUST Verify each harness reached its target using the runner's coverage output, because a harness wired to nothing looks exactly like a clean result.
MUST Name the campaign-wide ceiling's observer, which is the main thread and no other role. A gremlin sees its own per-harness cap alone, so nothing measures the total unless the orchestrator records elapsed wall-clock against the approved `total_s` at each wave boundary and stops to re-approve before exceeding it. One run's approved `total_s` was 1800 and the run passed it roughly fiftyfold with no role positioned to notice.
MUST Reserve the budget for the scanners recon aimed ON before allocating any of it to builds. `clippy` and the stock `opengrep` pack were dropped on three nodes of one run because a multi-target build consumed the clock, and recon had aimed both ON. A cheap mandated check that loses to an expensive optional build is a plan the budget table did not model.

### Lateral channel

Surfaces run in parallel, so a blocker or a corrected fact one gremlin discovers has
no route to its siblings. In one run a build panic on a read-only mount blocked
several nodes for half the campaign because the node that diagnosed it had nowhere to
publish the diagnosis.

1. Create `<artifacts>/operational-notes.md` at step 8 open, and name its absolute
   path in every gremlin Brief as both readable and appendable.
2. Every gremlin appends a dated section for any fact that changes what a SIBLING
   would do: a blocker and its workaround, a tool that cannot run in the image, a
   measured environment fact, a retraction of something the Brief asserted.
3. Every gremlin reads the file before its first tool call and again before filing
   coverage, since notes land while it works.
4. The orchestrator broadcasts anything that invalidates in-flight work to the live
   gremlins directly rather than waiting for them to poll.

MUST Give the lateral channel a written home before the fan-out. A channel improvised mid-run reaches only the agents still alive when it appears.
MUST Validate an environment fact on ONE node before writing it into every Brief. One run asserted that `/artifacts` was a per-container volume discarded on exit, fanned that to every gremlin, and the shared host bind filled the host disk: one node lost its whole test pass and another lost its harness attribution. A wrong recipe costs once per child it reached.
MUST Append a retraction to the lateral channel with the original wording quoted, and renumber nothing. Editing a numbered instruction in place leaves readers citing an instruction whose text has changed under them.

## Step 9: live-spawn agentic fuzzing (opt-in)

Requires the user to opt in on a PR, commit, or range target, against the specific
skills or agents the user names. Every generated case runs against every named
target, inside a Worktrunk lease with canaries seeded outside it. See
`references/agentic-fuzz.md` for the gates, containment, and tiering.

MUST Refuse live-spawn on a whole-repo target and say why, since it would attack every definition present.
MUST Read the canaries and collect the artifacts before discarding the lease.
MUST Record this stage as GRANTED, DECLINED, or NOT-OFFERED in the report. A skipped step with no disposition line is invisible, which is how one run silently skipped a step the numbering rendered as a sub-bullet.

## Step 10: triage crashes

`triager` claims each crash batch. It dedups by stack, minimizes every input, then
classifies memory-safety against robustness. Each minimized crash becomes a
finding wisp, and its crash wisp closes.

Skip this step when step 6 closed the memory-safety class and no crash wisp exists,
and record it as skipped-because-closed with the crash count. Spawning a triager over
zero crashes spends a role on nothing.

## Step 11: prove or refute

`challenger` claims every untiered finding wisp and stamps a tier plus an impact,
Briefed from `challenger-brief.md`. Nothing is deleted. Where several findings share
a primitive, the challenger tests whether they chain per `escalation.md` and tiers
the chain at its endpoint impact, since two MEDIUM primitives that reach code
execution together are a CRITICAL that separate rows hide.

`quick` mode skips this step, and its report states that every finding is untiered.

**Solo / non-interactive runs.** A single agent that ran the finding step cannot
also be the independent `challenger` without breaking "neither judges its own
output". The report must say which honest path was taken:
- **Spawn `challenger` anyway** when the run can spawn an agent (the default, even
  non-interactively): it is a fresh context that did not produce the findings, so
  the independence holds.
- **Tier inline, marked provisional** only when spawning is impossible (a leaf
  agent with no spawn budget). Every tier is then stamped `by=self` and the report
  headlines that no independent pass ran, so a reader never mistakes a self-tier
  for a challenged one.

MUST Prefer spawning `challenger` even in a non-interactive run, since independence comes from a fresh context rather than from a human being present.
MUST Mark an inline tier `by=self` and headline the missing independent pass when spawning was impossible, because a self-judged finding presented as challenged is the dishonesty the two-agent split exists to prevent.

## Step 12: synthesize the systemic patterns

Run one pass over the tiered finding set looking for the defect SHAPE that repeats
across nodes. Individual findings are the input; the output is a small set of named
patterns, each with its instance list and its own impact. Query the graph rather than
re-reading replies:

    bd list --label sab-finding --metadata-field run_id=<id> --all --json > <artifacts>/findings.json
    jq -r '.[].metadata.root_cause' <artifacts>/findings.json | sort | uniq -c | sort -rn

Any `root_cause` appearing across two or more surface nodes is a candidate pattern.
For each one, file a pattern wisp on the epic:

    bd create "pattern: <name>" --parent <epic> --labels sab-finding,sab-pattern --json \
      --metadata '{"run_id":"<id>","kind":"systemic-pattern","instances":["<id>","<id>"],"nodes":["<node>","<node>"],"impact":"<LEVEL>","root_cause":"<phrase>"}'

MUST Run this step on every run that produced more than one node's findings, and assign it explicitly (the main thread, or a `challenger` continued after tiering). One campaign's central conclusion, eight independent built-but-never-wired mechanisms whose self-checks all failed open, was noticed in passing by the orchestrator and was produced by no step in this file.
MUST Rank a pattern by its instance count and its span across nodes, and report it above the individual findings. A defect appearing on eight nodes is an engineering-practice finding, and its per-node rows read as eight unrelated bugs.
MUST File each pattern as its own wisp with its instance ids. A pattern living only in the report's prose is lost to the next campaign, which re-derives it or misses it.
NOT Never let a pattern replace its instances. The instances keep their rows and their fixes; the pattern is an additional finding, per the no-delete rule.

## Step 13: network stage (opt-in)

Requires a separate opt-in the user names; "run sabotage" is not it. LOAD
`network-stage.md` and follow it. The stage runs once, in a container WITH egress,
and it performs lookups rather than attacks: secret liveness, a fresh advisory DB
against the baked one, action-tag drift, and the registry-only rule packs. A tool
that only needs a one-time DOWNLOAD belongs in the image instead.

MUST Record this stage as GRANTED, DECLINED, or NOT-OFFERED in the report, per `network-stage.md`. A declined stage is a known coverage boundary; an unmentioned one reads as full coverage.

## Step 14: report

Generate the structured JSON with `scripts/report-json.py --epic <epic-id> -o
<artifacts>/run-<id>.json`, then emit the markdown per `report-template.md` from that
JSON rather than from the agents' replies. The script reads the finding set from the
beads export, so the report matches the durable graph. Cite bead IDs, list every
written artifact by path, and state every coverage gap.

MUST Emit the report with the gaps unresolved. This step has no precondition: an unrun harness, a surface with no coverage record, an untiered finding, and an INVALID run are what the report is FOR, so waiting for them to be fixed withholds it exactly when it says the most. The coverage gate in `beads-store.md` governs closing a surface node, never this step, and fixing anything is step 15, on explicit approval.
MUST Fix a stamping gap here rather than reporting it. A campaign bead missing `sab-audit`, a non-defect record missing `non-work`, a priority disagreeing with the tier-impact table, and a REFUTED finding left open each cost one `bd update`, and none is evidence about the target, so none belongs in the NOT-EXECUTED register. `report-json.py` lists them under `stamping_gaps` for exactly that pass.
MUST Manage the run by reading the graph, not by holding agent returns. Every agent returns a thin pointer (counts, bead ids, artifact paths) and writes its findings to wisps and artifacts, so the orchestrator's context stays flat across any number of surfaces and never compacts. Read the fat payloads from the wisps the returns point at, only when the report needs them.

## Step 15: patch

Only on explicit approval. Spawn `hardener` per approved finding, then re-run the
relevant scanners from step 8 and the relevant harnesses from step 10 to verify.

`audit-only` refuses this step even when approval is offered. It means "do not FIX
the findings", not "write nothing". A regression test that reproduces a PROVEN
finding documents the bug, so it is written even in audit-only (the fix that makes
it pass is what audit-only withholds). See the write policy below.

## Failure handling

| Failure | Response |
|---|---|
| A scanner is absent | skip, warn, record an install hint, report the dimension as a gap |
| A scanner crashes | INVALID: fix the invocation and rerun, and never report it as clean |
| A harness fails to build | INVALID: report it as an untested entry point |
| A harness hits its cap with coverage climbing | `budget_exhausted`: report the gap with the remaining budget |
| An agent dies mid-campaign | resume from beads per `beads-store.md`, since its wisps survive |
| The budget runs out with harnesses unrun | stop, and list every unrun harness as a gap |
| A crash does not reproduce | a harness bug rather than a target bug, recorded as INVALID |
| A harness file named in a wisp does not exist on disk | NOT EXECUTED, never a pass: `state:invalid` on the wisp plus a re-author wisp back to `fuzzer` |
| A harness runs but its benign control fails | both surfaces UNTESTED: no verdict either way, and nothing resting on it may be tiered above HARDENING |
| A gremlin finds a defect outside its scope globs | file it under the surface node whose globs contain the locus per `beads-store.md`, do not investigate, do not drop |
| A Brief premise turns out to be false | file a premise-correction comment on the surface node and state it in the return, for the report's premise-corrections section |
| A read-only agent needs a write to make its best measurement | escalate per `escalation.md`; record the measurement as blocked-by-role rather than dropping it |
| A wrapper or scanner exits 0 having done nothing | INVALID: an exit code proves no execution, so require a positive artifact such as a nonzero test count with named tests, or parsed scanner JSON |

MUST State every gap in the report. A campaign that hides what it could not check reads as a clean bill of health.
MUST Treat an exit code from any wrapper script as unproven until a positive in-container artifact confirms execution. Wrappers measured returning 0 while running nothing, in one run: the container runner on its own usage errors, a host hook that rewrote the build tool, the container CLI while printing an I/O error.

## Debug mode

OFF by default. Turn it ON only when the user asks to debug the sabot run
itself, which adds the raw scanner invocations, exit codes, and per-harness exec
counts to the report.
