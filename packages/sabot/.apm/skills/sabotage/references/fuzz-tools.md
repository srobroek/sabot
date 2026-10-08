# Fuzzing tool catalog

The generator, mutator, and minimizer catalog. Pick from here rather than writing
a bespoke corpus, since every tool below is better-tested than anything authored
during a campaign. `sabot-fuzzer` selects the tool per target and records the choice on
the harness wisp; `gremlin` runs what the wisp names.

Each entry lists the **input shape** it fits, the **mechanism**, the invocation,
and what it overlaps. Every invocation runs in the surface image against the target
at `/target`, so a recipe is the bare tool call; the tool is baked into the image at
build (`references/tooling.md`, Where tools come from), not fetched at run time.

## Choosing by input shape

Recon records each target's actual input shape, which decides the tool. A
structure-aware generator reaches real logic in seconds where a byte mutator spends
the whole budget failing at the parser.

| Input shape | Primary tool | Why |
|---|---|---|
| Arbitrary bytes | the language's native fuzzer (`cargo fuzz`, `go test -fuzz`, atheris, jazzer.js) | coverage-guided, so it discovers structure on its own |
| Bytes, no native fuzzer available | radamsa or zzuf | seed-driven mutation with no build integration needed |
| JSON with a known schema | hypothesis-jsonschema, or jsf | generates valid-then-invalid instances from the schema |
| JSON with no schema | genson to infer a schema from the repo's fixtures, then hypothesis-jsonschema | the inference step is the discovery: the schema comes from real samples |
| JSONL or framed streams | radamsa on a seed set, plus a framing-specific harness | mutate within frames, and mutate the framing itself |
| Protobuf | libprotobuf-mutator with libFuzzer | mutates the message tree rather than the wire bytes |
| MessagePack, CBOR, BSON | the language's `arbitrary` or a schema-derived generator, then encode | encode after generating, so every input parses and reaches logic |
| OpenAPI or GraphQL endpoint | schemathesis | derives cases from the spec, including the ones the spec forbids |
| A grammar or DSL | Grammarinator (ANTLR) or dharma | grammar-aware generation, since random bytes never form a valid program |
| Hook or guard decision contract | this package's `scripts/fuzz-cli.py` | asserts verdict invariants, which no general fuzzer knows |
| Function-level properties | hypothesis, proptest, fast-check, jqwik | property assertions rather than crash-only |
| CLI argv and env | radamsa on an argv seed, plus the shell surface checklist | argv and env are inputs, and most CLIs never test them |

MUST Record the input shape on the harness wisp during recon, since the shape picks the tool and a wrong pick wastes the whole budget at the parser.
MUST Prefer a structure-aware generator whenever a schema, grammar, or `.proto` exists in the repo, because the repo already told you the shape.
NOT Never hand-write a corpus a listed tool would generate. A hand-written corpus is smaller and less varied, and it goes unmaintained.

## Generators and mutators

| Tool | Shape | Mechanism | Invocation | Overlap |
|---|---|---|---|---|
| radamsa | any bytes, seed-driven | 40-plus mutation patterns over sample files | `radamsa -n <count> -o <outdir>/fuzz-%n.bin <seeds>/*` (resident: source-only upstream) | the general-purpose default when no native fuzzer fits; no build integration |
| zzuf | any bytes, stdin or file | deterministic bit-flipping with a seed and ratio | `zzuf -s 0:1000 -r 0.001 -c -C 0 <cmd>` (resident; record the seed) | overlaps radamsa; its determinism makes a finding trivially reproducible |
| honggfuzz | any bytes | coverage-guided, with a persistent mode | `honggfuzz -i <corpus> -t <wall_s> -- <bin> ___FILE___` (resident) | alternative to libFuzzer and AFL++; strong at feedback-driven work |
| AFL++ | any bytes, file or stdin | coverage-guided with custom and grammar mutators | `afl-fuzz -i <in> -o <out> -V <wall_s> -m <mem_mb> -- <bin> @@` | the native-code standard, and needs an instrumented build |
| libFuzzer | any bytes, in-process | coverage-guided, in-process | via `cargo fuzz` or `clang -fsanitize=fuzzer` | fastest per exec, and the default for Rust and C or C++ |
| libprotobuf-mutator | protobuf | structure-aware mutation of the message tree | link into a libFuzzer target | the only sane protobuf choice, since byte mutation never keeps a message valid |
| genson | JSON | infers a JSON Schema from observed samples | `uvx genson <fixtures>/*.json > schema.json` | the discovery half: turns the repo's own fixtures into a generator spec |
| hypothesis-jsonschema | JSON with a schema | generates instances from a JSON Schema | `uvx --with hypothesis-jsonschema --with hypothesis pytest` | pairs with genson; covers valid space plus boundaries |
| jsf | JSON with a schema | fake-data generation from a schema | `uvx --from jsf jsf --schema schema.json --instance-count 100` | simpler than hypothesis-jsonschema, and no property assertions |
| schemathesis | HTTP API with a spec | derives cases from OpenAPI or GraphQL | `uvx schemathesis run --dry-run <spec>` | needs a locally running instance for a real run, so dry-run only otherwise |
| Grammarinator | grammar or DSL | generates from an ANTLR grammar | `uvx --from grammarinator grammarinator-process <g4>` then `... grammarinator-generate` | the choice when the input is a language; dharma is the lighter alternative |
| dharma | grammar or DSL | generation from a compact grammar file | `uvx --from dharma dharma -grammars <g> -count <n>` | lighter than Grammarinator, and no ANTLR dependency |
| hypothesis | Python properties | property-based generation with shrinking | `pytest` on the property tests | shrinking is built in, so no separate minimizer is needed |
| hypofuzz | Python properties | coverage-guided hypothesis | `hypothesis fuzz` | adds coverage feedback to existing hypothesis tests |
| proptest, quickcheck | Rust properties | property-based with shrinking | `cargo test` with `PROPTEST_CASES` | same role as hypothesis, and native |
| fast-check | JS/TS properties | property-based with shrinking | `npx vitest run` | same role, and native |
| atheris | Python bytes | coverage-guided libFuzzer for CPython | `python <harness>.py -max_total_time=<wall_s>` | pairs with `atheris_libprotobuf_mutator` for protobuf |
| jazzer.js | JS/TS bytes | coverage-guided libFuzzer for Node | `npx jazzer <harness> -- -max_total_time=<wall_s>` | the JS equivalent of atheris |
| `go test -fuzz` | Go bytes | coverage-guided, built into the toolchain | `go test -fuzz=<Fuzz> -fuzztime=<wall_s>s` | nothing to install, and the corpus persists in testdata |
| `scripts/fuzz-cli.py` | hook and guard decisions | invariant assertion over caller-supplied vectors | see below | asserts verdict correctness, which no general fuzzer can judge |

MUST Verify a tool's route by running it once before the campaign depends on it, since a route that resolves in a registry can still fail to execute.
MUST Confirm a run-time launcher (`uvx`, `npx`, `pipx run`, `go run <url>`) resolves LOCALLY before relying on it. `npx jazzer` is fine when jazzer.js is in the baked `node_modules`; the same form fetches when it is not, and the container is `--network none`. A launcher that has to fetch is a coverage gap, not an invocation. `run-contained.sh --list-tools <image>` states what is actually there.
MUST Seed radamsa, zzuf, AFL++, and honggfuzz from the repo's own fixtures, since a mutator with no seeds produces noise the parser rejects immediately.
MUST Record the seed used with zzuf, because its determinism is the reason to choose it and an unrecorded seed throws that away.
DEFAULT Prefer the language's native coverage-guided fuzzer when one exists, and fall back to radamsa when instrumenting the target is impractical.

## Crash triage and minimization

`triager` uses these rather than shrinking by hand:

| Tool | Role | Invocation |
|---|---|---|
| CASR | crash triage: dedup by stack; severity classification; report generation | `casr-san -o <out>.casrep -- <bin> <input>` then `casr-cluster -d <indir> -o <outdir>` (bake it: `cargo install --locked casr`) |
| afl-tmin | input minimization for AFL++ targets | `afl-tmin -i <crash> -o <min> -- <bin> @@` |
| `cargo fuzz tmin` | input minimization for a libFuzzer target | `cargo +nightly fuzz tmin <target> <input>` (rejects `-j`) |
| afl-cmin | corpus minimization before a campaign | `afl-cmin -i <in> -o <out> -- <bin> @@` |
| shrinkray | generic test-case reducer, any input shape | `shrinkray <interestingness-test> <input>` (bake it; `uvx shrinkray` fetches and cannot run under `--network none`) |
| creduce | C and C++ source reduction | `creduce <interestingness-test> <input>` (bake it into the native image; cvise is not on PyPI) |
| `llvm-symbolizer` | resolve a stripped stack into frames | via ASan's `ASAN_SYMBOLIZER_PATH` |
| hypothesis, proptest shrinking | automatic minimization inside the property runner | built in |
| `-merge=1` (libFuzzer) | corpus minimization | `<harness> -merge=1 <dest> <src>` |

MUST Use CASR or the runner's own dedup rather than eyeballing stacks, since a fuzzer finds one bug many times and a hand count inflates the finding total.
MUST Use afl-tmin, shrinkray, or the property runner's shrinker; a tool-minimized input is reproducible, where a hand-trimmed one is an unverified assertion.
MUST Give the minimizer a SITE-PRESERVING oracle on any harness that can fail more than one way, then re-verify the minimized input still fails at the original `file:line`. A stock minimizer's oracle is "the process died", so on a multi-assertion harness it happily converges on whichever bug is cheapest to reach. Measured on `fits-header`: `cargo fuzz tmin` shrank three separate crash classes to 1-5 bytes that each panicked at a DIFFERENT line than the class they were minimizing, which reads as a spectacular reduction and is a different bug. Discard such a result and re-minimize under an oracle that greps for the target frame.
MUST Verify a minimized input still crashes, since a minimizer that shrank past the bug yields a finding nobody can reproduce.

## Coverage measurement

Coverage is what separates "found nothing" from "tested nothing":

| Tool | Role | Invocation |
|---|---|---|
| `llvm-cov` | line and region coverage for a libFuzzer or AFL++ target | `llvm-cov show <bin> -instr-profile=<profdata>` |
| `cargo llvm-cov` | Rust coverage, fuzz targets included | `cargo llvm-cov --html` |
| `go tool cover` | Go coverage from a fuzz run | `go test -fuzz=<F> -coverprofile=<p>` |
| `coverage.py` | Python coverage under atheris or hypothesis | `coverage run` then `coverage report` |
| afl-plot, afl-whatsup | AFL++ campaign progress, and whether coverage plateaued | `afl-whatsup <outdir>` |
| libFuzzer stderr counters | `cov:` and `ft:` growth per exec | read the campaign log |

MUST Read a coverage or feature counter before reporting a clean result, because a harness wired to nothing produces zero crashes exactly like a target with no bugs.
MUST Report a campaign whose coverage was still climbing at the cap as `budget_exhausted` rather than clean.

## Where `fuzz-cli.py` fits

The shipped harness is narrow on purpose: it verifies the **decision contract** of a
hook, guard, or CLI, which is a correctness question no general fuzzer can answer.
A general fuzzer knows whether a program crashed, and only this harness knows
whether a guard that returned `allow` should have returned `deny`.

| Job | Owner |
|---|---|
| Does it crash, hang, or emit unparsable output on hostile input | radamsa, zzuf, or the native fuzzer, with `fuzz-cli.py` as the zero-setup floor |
| Is the verdict correct for this input | `fuzz-cli.py` with a vectors file, since only the vectors carry the expected verdict |
| Does a wrapper form bypass the guard | `fuzz-cli.py` with wrapper vectors recon derived |
| Does `ask` appear where an autonomous agent needs a decision | `fuzz-cli.py` |

MUST Pair `fuzz-cli.py` with a vectors file for any bypass claim, since its structural pass alone proves only that the target survives hostile input.
MUST Reach for a mutator or native fuzzer once the target's real input space exceeds a JSON object, because the shipped structural corpus is a floor rather than a campaign.
