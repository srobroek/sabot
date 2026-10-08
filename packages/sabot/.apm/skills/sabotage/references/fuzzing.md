# Fuzzing: budgets, runners, crash capture

Execution rules for `gremlin`. Everything here runs against local code in this
repo or worktree, with no network target and no live load probe.

## Budget

The budget is approved by the user at step 3 and stored in the run epic's
`budget` metadata, so a resumed campaign reuses it rather than re-asking.

A compiled target is built before it is fuzzed, and the two phases have different
resource profiles and different failure modes. One number for both is what killed a
node: `mem_mb=2048` is a workable address-space cap for a fuzz process and is the exact
value at which `ld` was SIGKILLed linking one cdylib, costing that node 0 of 9 harnesses
while the failure was first misread as a missing system library.

### Fuzz phase, per harness

| Knob | Default | Meaning |
|---|---|---|
| `wall_s` | 60 | seconds per harness |
| `jobs` | 4 | concurrent fuzz processes |
| `mem_mb` | 2048 | address-space cap per process |

### Build phase, per surface

| Knob | Default | Meaning |
|---|---|---|
| `build_mem_mb` | 6144 | container memory for compile and link |
| `build_jobs` | 1 | `-j`; a cold workspace check measured 6m35s at `-j 1` |
| `build_s` | 1200 | wall ceiling for one surface's build |
| `free_disk_mb` | 4096 | host headroom required before a container starts |
| `copy_out_mb` | 512 | ceiling on the findings payload copied back |

The build defaults are calibrated, not guessed: 6144 with
`CARGO_PROFILE_TEST_DEBUG=0` / `CARGO_PROFILE_DEV_DEBUG=0` linked the cdylib that 2048
killed. `codegen-units=1` and `-C link-arg=-Wl,--no-keep-memory` were tried on the same
failure and proved unnecessary. `RUSTFLAGS=-Wl,--no-keep-memory` is not a linker flag at
all -- rustc parses it as `-W l,...` and emits E0602 unknown-lint on every crate.

Cold compile, image build, and copy-out dominate a real campaign's wall clock. The image
bakes the target's dependency set, and a full per-surface rebuild is still the norm.

Propose both tables alongside the tool table, with the count of harnesses and the
resulting worst-case wall-clock, so the user approves a duration rather than a number
they have to multiply themselves.

MUST Run every cheap mandated check to completion BEFORE the first compile. A static scanner costs seconds and a cold workspace build costs minutes, so a build that overruns voids whichever checks were queued behind it: three nodes lost `clippy` and their stock pack this way, having aimed both ON at recon. Order by cost, and report a check that a build displaced as a coverage gap naming the build.
MUST Enforce the cap in the runner rather than by watching the clock. Use each fuzzer's own time flag, and wrap anything lacking one in `timeout`.
MUST Cap memory with `ulimit -v` or the runner's own flag, because an unbounded-allocation finding otherwise takes the developer's machine down with it.
MUST Pass `--mem <build_mem_mb>` to `run-contained.sh` for any build or test step, and `--mem <mem_mb>` only for a fuzz step. The wrapper enforces whichever it is given as a cgroup limit; it cannot know which phase a command belongs to.
MUST Treat disk as a budget dimension. `run-contained.sh` refuses to start below `--min-free-mb` and refuses a copy-out above `--max-copy-mb`, both as exit codes, because the campaign that had no disk dimension filled a 460 GiB host volume to 100%, containerd could not grow its sparse disk, image blobs began returning `input/output error`, and no container could start on any image.
MUST Stamp `state:budget_exhausted` when a harness hits its cap while coverage is still growing, since that distinguishes "found nothing" from "ran out of time".
MUST Escalate memory at most ONCE, to `build_mem_mb`, and record it as an explicit budget deviation naming the measured symptom. Treat a second escalation as a research question and stop.
NOT Never retry into a disk failure. Stop, report, tear down the build residue, verify headroom, then resume. Retrying into a full disk is what corrupted the runtime.
NOT Never raise the budget mid-campaign without asking. A budget the user approved is the authorization for the run.

### Time: the campaign ceiling and the per-run deadline

Memory and disk are **safety** limits: exceeding either destroys the run and the container
runtime with it, so the wrapper enforces both and refuses rather than asks. Time is a
**budget** the user approves at step 3, and it has three parts, each held by the one party
positioned to observe it:

| Limit | Set | Observed and enforced by |
|---|---|---|
| `wall_s` | step 3, per harness | the runner's own time flag (table below) |
| `total_s` | step 3, for the whole campaign, stamped in the epic's `budget` | the main thread, at every wave boundary |
| a per-run deadline | optional, only when the user asks for one | the container, via `run-contained.sh --timeout <s>` |

`total_s` defaults to the worst-case wall-clock the budget table states: the harness count
times `wall_s`, divided across the affordable concurrency and rounded up to whole waves,
plus the build phase. A 21-node run once overran an approved 1800 s ceiling roughly
fiftyfold because no role compared elapsed time to it: the phases are parallel subagents
with no shared clock. The orchestrator dispatches every wave, so it is the one observer
that sees the total.

MUST Stamp `total_s` in the approved budget. `report-json.py` reports a budget without it as a stamping gap.
MUST Compare elapsed wall-clock against `total_s` on the main thread before dispatching each wave, and stop to re-approve before a wave would exceed it. Never hand the campaign ceiling to a gremlin, which sees only its own harness caps.
MUST Pass a user-set per-run deadline as `run-contained.sh --timeout <s>`, so the container stops itself. Never implement that deadline by having an agent watch the clock.
MUST Treat a per-run deadline's expiry as a normal outcome with partial results. The wrapper sends SIGTERM, waits 30 s, then SIGKILLs, and copies the findings out either way; the status file records `rc=124 deadline=1`.
MUST Record every harness that had not yet run at a deadline or at the `total_s` stop as a coverage gap with its remaining budget, so partial results are never read as a complete pass.

### A resource failure is an INVALID run

Each symptom below is the wrapper's limit or the host's limit. Report it as INVALID, and
never as a target defect, a finding, or a clean scan:

| Symptom | Read as |
|---|---|
| exit 137, or an OOM-killer line in the log | memory cap hit. `run-contained.sh` labels 137 and names the link escalation. |
| `ld` killed, or `cargo` exit 101 with a signal-killed linker child | link memory, not a missing library. Escalate to `build_mem_mb` once. |
| `signal: 9, SIGKILL` on a mid-sized crate (`syn`, `redb`) at a cap the workspace built under before | the cap is not the whole budget. See below. |
| `No space left on device`, ENOSPC | host disk. Stop the campaign; do not retry. |
| `input/output error` on a containerd blob, or "image not found" on an image that exists | the runtime's content store is corrupt, downstream of a full disk. HALT; no host fallback. |
| copy-out refused or timed out | the evidence stayed in the container, so the run reads exactly like one that never happened. INVALID. |

#### The cap is not the budget: check the VM, and keep the build tree out of a tmpfs

`--memory` bounds the container, but on macOS and Windows the container runtime is itself a
VM with a fixed allocation, and a `--tmpfs` is charged to that same pool as it fills.

| Measured | Value |
|---|---|
| host memory | 48 GB |
| what the Docker VM actually held | 7.7 GB |
| `--tmpfs /scratch` holding the build tree | 8 GB |
| result | `syn`, `redb`, and one workspace crate SIGKILLed at a cap that workspace had compiled under before |
| after moving the tree to a volume, tmpfs to 512m, `build_jobs=2` | compiled in 8m26s, 5.34 GiB peak |

MUST Read the runtime's OWN memory total before setting `build_mem_mb`, not the host's. `docker info --format '{{.MemTotal}}'` reports the VM. A cap above what the VM has is not a cap; it is an unbounded build with a number written next to it.
MUST Put a build or target directory on a volume, never in a `--tmpfs`. A tmpfs holding build output is charged to the same memory the compiler needs, so the tree competes with the process producing it. The runner then reports a SIGKILL, which reads like a link-memory problem.
NOT Never read a SIGKILL as a target defect or a harness result. It measured nothing.

## Runners

| Language | Command | Time flag | Crash artifact |
|---|---|---|---|
| Rust | `cargo fuzz run <target> -- -max_total_time=<wall_s> -rss_limit_mb=<mem_mb>` | `-max_total_time` | `fuzz/artifacts/<target>/crash-*` |
| Rust (property) | `cargo test --release --no-fail-fast <name>` with `PROPTEST_CASES=<n>` | case count | `proptest-regressions/*.txt` |
| Go | `go test -fuzz=<Fuzz> -fuzztime=<wall_s>s -parallel=<jobs>` | `-fuzztime` | `testdata/fuzz/<Fuzz>/*` |
| Python | `python -m atheris <harness>.py -max_total_time=<wall_s>` | `-max_total_time` | stderr repro plus written input |
| Python (property) | `pytest --hypothesis-show-statistics` | derive from `deadline` and `max_examples` | `.hypothesis/examples/` |
| JS/TS | `npx jazzer <harness> -- -max_total_time=<wall_s>` | `-max_total_time` | crash file in cwd |
| JS/TS (property) | `npx vitest run` with fast-check | `numRuns` | counterexample in the failure output |
| C/C++ | `<harness> -max_total_time=<wall_s> -rss_limit_mb=<mem_mb>` | `-max_total_time` | `crash-*` in cwd |
| C/C++ (AFL++, NOT BAKED: an approved extension image must add it) | `afl-fuzz -i <in> -o <out> -V <wall_s> -m <mem_mb> -- <bin> @@` | `-V` | `<out>/default/crashes/*` |
| Any CLI or hook | `scripts/fuzz-cli.py --target <t> --timeout <s> --mem-mb <m> --vectors <f>` | `--timeout` per invocation | `--artifacts-dir` |

MUST Build with sanitizers where the language offers them: `RUSTFLAGS="-Zsanitizer=address"` under `cargo fuzz`, `-fsanitize=address,undefined` for C and C++, and `-race` for Go concurrency harnesses. A memory bug without a sanitizer is silent corruption rather than a crash.
MUST Persist the corpus between runs, since a corpus thrown away makes every campaign start from zero.
DEFAULT Seed from the repo's own test fixtures and testdata before generating inputs, because a real message shape reaches deeper code than random bytes.

## Coverage honesty

A campaign that finds nothing has to distinguish four cases, since they demand
different remediation and only one of them is good news:

| Observation | Report as |
|---|---|
| Harness ran to its cap, coverage plateaued, no crash | genuine clean result for that entry point |
| Harness ran to its cap, coverage still climbing | `budget_exhausted`, a coverage gap with a stated remaining budget |
| Harness failed to build or link | `invalid`, since nothing was tested |
| Harness ran but the entry point rejected every input early | `invalid`, because a harness whose inputs all fail validation tests the validator alone |

MUST Read the fuzzer's own coverage or exec-per-second output rather than inferring from the absence of crashes. A harness wired to nothing reports zero crashes exactly like a target with no bugs.
MUST Check that a harness reached the code it targets, using the runner's coverage counters or a deliberate assertion the harness should trip on a known-bad input.

## Tool selection

Runners above are the execution layer. The generator, mutator, minimizer, and
coverage tool come from `fuzz-tools.md`, picked by the input shape recon recorded.

## Crash capture

Every crash becomes a crash wisp with its input persisted, then goes to
`triager`:

1. Copy the crashing input to `<artifacts>/crash-<surface>-<n>.<ext>`.
2. Record the runner's stack or panic message, plus the exact command that
   reproduces it.
3. Create the crash wisp with `input_path` and `stack_hash` metadata per
   `beads-store.md`.
4. Continue the campaign. A crash stops its own harness, not the run.

MUST Verify a crash reproduces from the persisted input before filing it, because a crash that only happens under the fuzzer's own state is a harness bug.
MUST Record the exact reproduce command in the wisp, since a crash nobody can rerun cannot be fixed or verified.

## Safety

Execution runs in a container, not on the host, and not merely in a worktree. The
container contract, the authoring ban on irreversible inputs, and the host tripwire
are in `references/isolation.md`; the rules below assume that isolation is in place.

MUST Run against local code only, inside the container of `references/isolation.md`. A fuzz target that opens a network connection beyond loopback is out of scope and gets rewritten or dropped.
MUST Run in a worktree when a harness writes files, keeping the campaign out of the user's working tree.
MUST Cap concurrency at the approved `jobs`, and lower it when the machine is the developer's own workstation.
NOT Fork bombs, disk-filling loops, and any PoC that deletes or overwrites a path outside the artifacts dir are all banned.
NOT Never point a harness at a shared database, a staging environment, or any service the user does not run locally.
