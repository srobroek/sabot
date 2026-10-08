# Harness patterns

Authoring rules for `fuzzer`. A harness is code that feeds a target inputs and
asserts an invariant. `fuzzer` writes it and runs nothing; `gremlin` executes it.

## Where harnesses go

Mirror the repo's own convention, since a harness the project's test command
cannot find is a harness nobody runs again:

| Repo already has | Put it in |
|---|---|
| `fuzz/fuzz_targets/` | `fuzz/fuzz_targets/fuzz_<name>.rs` |
| `*_test.go` with `Fuzz` functions | the package's `<file>_test.go` |
| `tests/` with hypothesis | `tests/test_<name>_properties.py` |
| `tests/fuzz/` | `tests/fuzz/<name>.py` |
| no fuzz convention at all | `tests/fuzz/` for a new dir, and state the choice in the report |

MUST Leave every harness uncommitted and list its path in the report, since committing is the user's call.
MUST Match the repo's existing test idiom for its runner and naming, and place fixtures where the repo already keeps them. A harness in a foreign style gets deleted rather than maintained.
NOT Never overwrite an existing harness. Add a new one beside it, because the existing corpus and regression history live with the old file.

## Choosing the generator

The tool comes from `fuzz-tools.md`, chosen by the entry point's input shape that
recon recorded. A structure-aware generator reaches real logic in seconds where a
byte mutator spends the whole budget failing at the parser.

MUST Pick the generator from `fuzz-tools.md` rather than hand-writing a corpus a listed tool would produce, since a hand-written corpus is smaller, less varied, and unmaintained.
MUST Use the schema, `.proto`, or grammar the repo already ships when one exists, because the repo has already described its own input shape.

## Invariant catalogue

Pick invariants in this order, since the earlier ones catch more per line of
harness:

| Invariant | Shape | Catches |
|---|---|---|
| Never panics on arbitrary bytes | `f(arbitrary) does not crash` | the whole crash class, and it needs no oracle |
| Round trip | `parse(render(x)) == x` | encoding loss, precision drift, escaping bugs |
| Idempotence | `f(f(x)) == f(x)` | duplicate work, double-apply corruption |
| Agreement with a reference | `fast(x) == simple(x)` | optimization bugs, wrong fast paths |
| Invariant preservation | a documented property holds after every operation | state-machine violations |
| Monotonicity or bounds | output stays within a stated range | overflow, off-by-one, unbounded growth |
| Differential across versions | old and new agree on the same input | regressions during a migration |

MUST State the invariant in a comment at the top of every harness, because a harness whose assertion nobody understands gets deleted at the first false positive.
DEFAULT Prefer a never-panics harness first when the target has no obvious oracle, since it requires no expected output and still finds real bugs.

## Every guard harness ships a benign control

A harness that asserts a guard produces an unreadable result on its own. Its failure
has three candidate causes the runner output cannot separate: the guard held, the
harness is broken, the fixture never built.

| Pair | Feeds | A pass means | A fail means |
|---|---|---|---|
| hostile `<name>` | an input the guard must reject | the guard holds, or the harness never reached it | the guard is bypassable, IF the control passed |
| benign `<name>_control` | an input the guard must accept | the harness reaches the guard and the guard is not over-blocking | the harness or fixture is broken, and the hostile result yields no verdict |

MUST Write the control beside every harness asserting a guard, and stamp `control_path` on the harness wisp. In one run, two hostile harnesses failed with their benign controls also failing, so both loci were reported UNTESTED rather than as findings.
MUST Assert one invariant per test. A test holding two assertions stops at the first panic and leaves the second unfired, so an untested assertion reads as covered. One run lost an assertion this way, and four more to an early panic in a shared test.
MUST Assert the VALUE the code computes rather than the absence of a panic whenever the panic depends on the build profile. A `debug_assert!` measures the profile; an arithmetic overflow panics in debug and wraps silently in release when the release profile sets no `overflow-checks`. A wrapped size or offset feeding a filesystem or SQL decision is worse than a crash, because nothing announces it.
MUST State the expected outcome (`pass` or `fail`) on every harness wisp. A harness whose failure IS the finding is a prediction, and a prediction with no recorded expectation is read as a broken harness.

## Per-target patterns

**Parser or deserializer.** Take `&[u8]` or `bytes` directly, feed it to the parse
entry point, and assert no panic. Add a round trip when a renderer exists. Seed
from every fixture in the repo's testdata.

**CLI or hook.** Use the shipped `scripts/fuzz-cli.py` rather than writing a new
harness. `fuzzer`'s job here is the vectors file. Run `fuzz-cli.py --vectors-help`
for the authoritative schema; do not infer it from the script.

Each vector is one JSON object with four fields:

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | unique label; also names the persisted repro file |
| `payload` | yes | a dict or list is sent as JSON; a string is sent raw on stdin |
| `expect` | yes | `deny` · `allow` · `ask` · `no-crash` · `nonzero-exit` · `zero-exit` |
| `why` | yes | one line: what invariant the vector tests |

```json
[{"name": "env-wrapper bypass",
  "payload": {"tool_name": "Bash", "tool_input": {"command": "env rm -rf /"}},
  "expect": "deny",
  "why": "a wrapper prefix must not move the command out of guard position"}]
```

Verdict semantics that trip authors: a decision the target never emits counts as
`allow` (silence is not a block, so a guard that emits nothing on a catastrophic
command is a BYPASS); an `ask` verdict is flagged STALL because it blocks an
autonomous agent. Cover every wrapper form from `surfaces/shell.md`, plus one
benign vector per guarded pattern to catch over-blocking.

**Function with a precondition.** Generate inputs that satisfy the precondition
with a filter or a custom generator, since a harness whose inputs all fail
validation tests the validator alone.

**Stateful API.** Generate a sequence of operations rather than one input, then
assert the invariant after each step. `proptest` state machines, `hypothesis`
`RuleBasedStateMachine`, and fast-check model-based testing all express this.

**Concurrency.** Spawn N workers over shared state, run under the language's race
detector, and assert the final state matches a serial execution. Determinism is
not expected; corruption is the finding.

**Config or schema reader.** Feed malformed config and assert the program exits
with a clear message rather than a traceback. Startup denial from a bad config is a
real robustness finding.

**Agent or skill definition.** No in-container executable harness exists; the
opt-in live-spawn stage (`agentic-fuzz.md`) is the only route that runs the
definition for real, under its own consent. `fuzzer` writes a scenario table crossing each payload class from
`references/corpora/prompt-injection.md` against each entry point where untrusted
content enters, and `gremlin` evaluates whether the definition contains a rule
that stops it.

## Seed corpus

MUST Seed from the repo's own fixtures, testdata, and recorded requests first, because a valid message shape reaches deeper code in seconds than random bytes reach in an hour.
MUST Include a boundary set alongside real seeds: empty, single byte, maximum documented size, and one past it.
DEFAULT Minimize the seed corpus before a campaign with the runner's own `cmin` or `-merge=1`, since a redundant corpus wastes the budget.

## Regression tests

Every PROVEN finding gets a regression test in the repo's own suite, holding the
minimized input as a fixture:

MUST Write the regression test so it fails against the current code and passes after the fix, since a test that passes before the fix proves nothing.
MUST Write the regression test even in audit-only mode. A test that reproduces a finding describes the bug rather than fixing it, so it is the deliverable audit-only wants; only the product-code change that makes it pass is withheld until step 15.
MUST Place it in the repo's existing test file for that module, since the fuzz corpus sits outside the normal test run.
DEFAULT Name it for the bug rather than the input, so a future reader knows what broke.

## Synthesized rules as regression guards

A rule recon wrote and a finding confirmed belongs in the repo's own lint config,
not only in the campaign's artifacts, once the step-15 approval covers it. It is the cheapest durable check the campaign
can leave behind, because it runs on every commit at no further cost.

| Artifact | Proves | Catches |
|---|---|---|
| Regression test | this instance is fixed | this exact input returning |
| Graduated rule | the pattern is banned | the next instance, anywhere in the repo |

MUST Write the regression test for a confirmed finding, and propose its rule for the class at the step-15 approval.
MUST Place an approved rule where the project's own tooling already looks, per the graduation table in `recon.md`, and only once the step-15 approval names it: the lint config is product configuration that steps 1 to 14 leave untouched.
NOT A rule left only in the artifacts dir stops running the moment the campaign ends, so the report proposes it rather than letting it lapse.

## Anti-patterns

NOT A harness that catches the exception it is meant to detect turns every crash into a pass.
NOT A harness whose input is discarded before reaching the target reports zero crashes exactly like a target with no bugs.
NOT A harness asserting on wall-clock time on a shared machine produces findings that vanish on a quieter run.
NOT A harness requiring network access cannot run in the campaign and is out of scope.
NOT A harness that writes outside the artifacts dir or a worktree pollutes the user's tree.
