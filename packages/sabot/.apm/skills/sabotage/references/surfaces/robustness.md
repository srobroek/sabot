# Surface: Robustness

Runs on every target, always. This surface asks whether the thing breaks: feed it
broken data and walk it to the edges of its declared behaviour. No attacker is
required, and a finding here is real whether or not anyone can reach it
maliciously.

Security surfaces ask "can this be exploited". This one asks "does this work when
the input is wrong", which is the question that catches most of what ships broken.

## Detect

Every target on every run. Prioritize any boundary where data changes hands: a
parser, a deserializer, a CLI argument, an environment variable read, a file
format, a network response, a database row, a subprocess output, or a
version-to-version state file.

## Tools

| Tool | Tier | Class | Run recipe | Catches | Overlap |
|------|------|-------|-----------|---------|---------|
| `scripts/fuzz-cli.py` | default-on | local | see `harnesses.md` | crash, hang, non-parsable output, contract violation on any CLI or JSON-stdin program | the workhorse of this surface |
| hypothesis | default-on | local | `pytest --hypothesis-show-statistics` on the property tests `sabot-fuzzer` wrote | Python: invariant violations across generated inputs | property testing finds classes a fixed corpus never reaches |
| proptest or quickcheck | default-on | local | `cargo test --no-fail-fast` on the property tests `sabot-fuzzer` wrote | Rust: same | native to the language |
| fast-check | default-on | local | the project-local runner, e.g. `./node_modules/.bin/vitest run`, on the property tests | JS/TS: same | native; `npx` cannot fetch under `--network none`, so the runner must already be installed in the target |
| `go test -fuzz` | default-on | local | `go test -fuzz=Fuzz -fuzztime=<budget>` | Go: crashers plus corpus growth | native, and the corpus persists in testdata |
| schemathesis | opt-in | local | `schemathesis run --dry-run <spec>` | API contract violations generated from an OpenAPI spec, off unless a spec exists | requires a local instance to run for real, so dry-run only |
| `timeout` plus `ulimit` | default-on | local | wrap every campaign, see `fuzzing.md` | hangs and runaway memory, distinguishing them from crashes | the budget enforcement primitive |
| existing test suite | default-on | baseline | the repo's own test command | a regression the campaign introduced, and a baseline of what already passes | run before the campaign, so a pre-existing failure is not reported as a finding |

MUST Run the repo's own test suite before the campaign and record the result, because a test already failing on a clean tree is not a sabot finding.
MUST Distinguish a hang from a crash in every report row, since the remediation differs.

## Attack checklist

| # | Attack | Where it hides | Confirm by |
|---|--------|----------------|-----------|
| 1 | Empty and absent input | a parser given `""`, a missing file, an absent env var, `null` where an object is expected | run it and check for a crash rather than a clear error |
| 2 | Boundary values | `0`, `-1`, `1`, `MAX`, `MAX+1`, empty collection, single-element collection, exactly-at-limit | supply each and compare against the documented behaviour |
| 3 | Malformed structure | truncated JSON, unbalanced brackets, a valid JSON scalar where an object is expected, duplicate keys, deeply nested arrays | confirm the error path is reached rather than a panic |
| 4 | Type confusion in a schema | a string where a number is expected, a number as a string, `true` for `"true"`, an array for a scalar | check whether coercion silently produces wrong data rather than an error |
| 5 | Encoding edges | invalid UTF-8, a lone surrogate, a BOM, CRLF against LF, NUL bytes, RTL overrides, combining characters, emoji in an identifier | confirm the value survives a round trip unchanged |
| 6 | Size extremes | a 10 MB single field, a million-element array, a 4 GB stream, a zero-byte file | check memory growth and whether a cap exists |
| 7 | Deep nesting | recursive structures nested a thousand levels | a stack overflow counts as a crash |
| 8 | Duplicate and conflicting input | the same flag twice, a config key set in two files, contradictory options | confirm precedence is documented and matches behaviour |
| 9 | Ordering assumptions | a map iterated as if ordered, a test depending on file-listing order | run twice and compare output |
| 10 | Concurrency | the same operation from several processes, a shared lock file, a cache written concurrently | run N copies and check for corruption, lost writes, or a deadlock |
| 11 | Partial failure and resume | a process killed mid-write, a network call failing halfway, a batch failing on item 5 of 10 | confirm state is either complete or cleanly rolled back |
| 12 | Error-path correctness | the `except`, `catch`, or `Err` branch itself | force each error path and check whether it leaks a resource, logs the wrong thing, or swallows the failure |
| 13 | Idempotence | running the same command twice | a second run should either no-op or report clearly, rather than duplicating or corrupting |
| 14 | State-machine edges | calling operations out of order, an operation on a closed handle, a double release | confirm an invalid transition is rejected rather than accepted |
| 15 | Version and migration edges | reading a state file from an older or newer version, an unknown enum variant | confirm forward and backward behaviour is defined |
| 16 | Environment assumptions | absent `HOME`, a read-only cwd, a full disk, no network, a different locale, no TTY, a narrow terminal | run under each and check for a crash |
| 17 | Resource exhaustion at the cap | file descriptors, connections, threads, temp files | confirm a limit exists and the code degrades rather than dying |
| 18 | Clock and timezone | a DST transition, a leap day, a clock moving backward, a zero or negative duration | check for a negative timeout or an infinite wait |

## Harness patterns

Both shapes below are authored by `sabot-fuzzer` and executed by `gremlin`.

**Property tests** assert an invariant across generated inputs. Best invariants,
in yield order: round-trip (`parse(render(x)) == x`), never-panic on arbitrary
bytes, idempotence (`f(f(x)) == f(x)`), and agreement with a simpler reference
implementation.

**Attack-vector corpora** are hand-written inputs from the checklist above,
covering the classes a generator reaches slowly. `fuzz-cli.py` ships a base corpus
of empty, malformed, oversized, unicode, and deeply nested payloads that applies
to any JSON-stdin program.

MUST Author both shapes. A generator surfaces the input a human would not think of; a hand-written vector covers the case a generator would need hours to construct.
DEFAULT Convert every crash the campaign finds into a regression test in the repo's own suite, since a fixed bug with no test returns.

## Impact calibration

Severity here is about blast radius rather than exploitability:

| Level | Meaning on this surface |
|---|---|
| CRITICAL | data loss or corruption on a plausible input, or an unrecoverable state a user cannot escape |
| HIGH | a crash or hang in a path users hit regularly, a partial write leaving inconsistent state, or a silent wrong answer a caller acts on |
| MEDIUM | a crash on malformed input a user could plausibly supply, a resource leak under repetition, or a non-idempotent command that duplicates work |
| LOW | a crash on input no realistic caller produces, an unclear error message, or a cosmetic ordering instability |

DEFAULT Raise a silent wrong answer one level above the same defect failing loudly, since a crash is visible and a wrong answer is not. Visibility is a factor in the blast radius, not a floor: a wrong answer nobody acts on stays LOW.

## False-positive traps

| Looks like a finding | Clears when |
|---|---|
| A crash on invalid input | the function documents a precondition and every caller in the repo validates it, so the finding drops to LOW as an internal-API note |
| A panic in a test helper | the code is test-only and its failure is the intended signal |
| A hang under the fuzzer | the harness itself blocks on stdin, which makes it a harness bug rather than a target bug |
| Non-deterministic output | the ordering is documented as unspecified and no consumer depends on it |
| A failure under a missing env var | the program exits with a clear message and a nonzero status, which is correct behaviour rather than a break |
| A crash at an extreme size | the limit is documented, enforced, and reported clearly at the boundary |
| A pre-existing test failure | it reproduces on a clean tree at the base ref, making it out of scope for this campaign |
