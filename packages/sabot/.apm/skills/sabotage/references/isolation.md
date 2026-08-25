# Isolation and guardrails

Execution runs in a container, never on the host. A Worktrunk lease is a
filesystem boundary only: it shares the host kernel and network, and runs under the host's own credentials. A campaign
that fuzzes a parser, runs a `build.rs`, or drives a dev server is running code
whose behaviour is the unknown under test, so it runs where a destructive effect
has nowhere to land.

Three layers, strongest first. The container is the wall; the authoring ban keeps
the fuzzer from arming a payload; the host tripwire is the honest backstop that
lives outside the sandbox and cannot be fooled from inside it.

## What runs where

One question decides where a step runs: **does it compile, expand, or run the
target's own code?** If it does, it runs in the container, because that code, not
just the input, is the unknown. The old "static stays on the host" split was wrong: a compiling
linter builds the crate, which runs its `build.rs` and proc-macros, so running
`clippy` or `gosec` "statically" on the host executes the target's build-time code on
the host, the exact thing the container exists to prevent.

| Step | Where | Why |
|---|---|---|
| The recon and tiering AGENTS (the LLM reasoning) | host | a model cannot be containerized; only its tool calls can |
| Pure text reads: `rg`, `ast-grep` search, `semgrep`/`opengrep`, `shellcheck`, `gitleaks`, `zizmor`, reading source | **container** | they execute nothing, but running them in the same image keeps tool versions pinned and the host clean; a text scanner is cheap to containerize and there is no reason to split the toolset across two places |
| Compiling scanners: `clippy`, `gosec`, `cargo audit`, anything that builds the crate | **container** | building the target runs its `build.rs`/proc-macros; on the host that is untrusted code executing on the host |
| Fuzz campaigns, harness execution, `fuzz-cli.py` against a real target | **container** | the target's behaviour on hostile input is the unknown |
| `build.rs`, proc-macro expansion, install scripts | **container** | build-time code runs before any test could catch it |
| Dev-server DAST | **container** | the server is started and driven with payloads |

Every target-touching tool runs in the container. The only thing on the host is the
agent doing the reasoning and the orchestration primitives it needs there (`bd`,
`git`, the container runtime); it shells every scanner, linter, and fuzzer into the
image via `run-contained.sh`.

MUST Run every target-touching tool in the container, not only the fuzzers. A compiling scanner (`clippy`, `gosec`) builds the crate and so runs the target's build code; a text scanner has no host-side reason to exist separately. The host holds the agent and `bd`/`git`/the runtime, nothing that touches target code.
MUST Never run a compiling linter on the host as a "static" pass. It executes the target's `build.rs` and proc-macros on the host, which is the unconfined build-time execution the container exists to prevent.

## No network

Read this before choosing a single tool or flag. Every target-touching command runs with
`--network none`: no DNS, no egress, no proxy, no package registry, no rule registry. It is
this skill's own rule rather than a property of one host, so it holds on every run and there
is no invocation that gets an exception.

"Local host access" means loopback INSIDE the container, reaching a server the campaign
itself started there. A host port, a LAN address, or a public endpoint is out of scope no
matter who asks for it.

MUST Report a tool that needs the network as NOT EXECUTED, with the reason "requires network; container is `--network none`". Never as "0 findings", and never as a retry.
MUST Resolve every remote dependency at IMAGE BUILD time, or in one explicit, separated, network-allowed fetch phase that runs no target code. Rule packs, advisory databases, and dev-deps are all in this class; see Baked offline databases and Provisioning below.
NOT Never grant network to a scan to make it pass. That trades the isolation guarantee for a result, which is the one trade this contract exists to prevent.

## Container contract

```
docker run --rm \
  --network none \                 # no outbound anything; loopback DAST maps a port instead
  --memory 2g --memory-swap 2g \   # the budget's mem cap, kernel-enforced
  --pids-limit 512 \               # fork-bomb ceiling
  --cpus 2 \
  --read-only \                    # image fs is read-only
  --tmpfs /scratch:size=2g \       # writable, RAM-backed, charged to --memory (see below)
  --workdir /scratch \             # cwd is writable; the target is read at /target
  --env HOME=/scratch --env TMPDIR=/scratch \
  --env CARGO_TARGET_DIR=/artifacts/.build/cargo-target \
  --env GOCACHE=/artifacts/.build/go-build \
  --env GOPATH=/scratch/go --env npm_config_cache=/scratch/npm \
  --env LANG=C.UTF-8 --env LC_ALL=C.UTF-8 --env PYTHONUTF8=1 \
  --cap-drop ALL --security-opt no-new-privileges \
  --user 1000:1000 \               # never root
  -v <target>:/target:ro \         # target mounted READ-ONLY
  -v <per-run named volume>:/artifacts \   # findings; copied to the host after the run
  <image> <campaign command reading /target, e.g. cargo test --no-fail-fast --manifest-path /target/Cargo.toml>
```

MUST Mount the target read-only. The campaign reads and attacks it; it never needs to write the target, and a read-only mount makes an accidental mutation impossible.
MUST Pass `--network none` for a fuzz or build run. A harness that needs loopback (dev-server DAST) gets a published port mapping instead, never full network.
MUST Enforce the run's memory, pid, and cpu budget as container flags, since a flag the kernel enforces holds where a `NOT` rule in prose does not.
MUST Run as a non-root user with `--cap-drop ALL` and `--security-opt no-new-privileges`, so a container escape has nothing to escalate to.
MUST Write findings only to `/artifacts`, the single writable path whose contents survive the container.
MUST Direct every build and test toolchain away from the read-only target: `run-contained.sh` sets `--workdir /scratch`, puts `TMPDIR`/`HOME` on the tmpfs and `CARGO_TARGET_DIR`/`GOCACHE` under `/artifacts/.build`, and the command after `--` reads the target at `/target` (e.g. `cargo test --no-fail-fast --manifest-path /target/Cargo.toml`). A `cargo test` left to write `target/` in the read-only mount fails, which reads as a broken harness rather than the isolation working.
MUST Set a UTF-8 locale (`LANG`/`LC_ALL=C.UTF-8`, `PYTHONUTF8=1`), which the wrapper does. Under the default POSIX locale a python scanner dies on the first non-ASCII byte of a rule file: `opengrep` raised `'ascii' codec can't decode byte 0xe2` from `config_resolver.py:241` and exited 2 having scanned 0 files, where the same invocation under UTF-8 returned 41 findings across 14 files. `sabot-scout` synthesizes rule files, so a curly quote in a synthesized rule is the expected case.

### `/artifacts` is a volume that gets copied out, and `/scratch` is RAM

Two claims that read as isolation guarantees are narrower than they look, and both were
measured the hard way.

`/artifacts` is a per-run NAMED VOLUME, not a host bind mount. Nothing the container writes
there touches the host while the run is in progress. After the run, `run-contained.sh`
replicates the whole volume onto the host with `docker cp`, so anything left in it becomes
permanent host residue. A campaign that pointed build output there accumulated 1.2 GiB,
856 MiB, 2.0 GiB, and 5.2 GiB of compiler output across four runs, filled a 460 GiB volume
to 100%, and left containerd unable to grow its sparse disk: image blobs began returning
`input/output error` and no container would start on any image. One copy-out took 600 s and
destroyed the node's log. The wrapper now prunes `/artifacts/.build` and any directory
carrying a `CACHEDIR.TAG` before copying, and refuses a payload above `--max-copy-mb`.

`/scratch` is a tmpfs, and tmpfs pages are charged to the `--memory` cgroup. Measured: `dd`
was SIGKILLed at exactly 2.0 GiB under `--mem 2g --scratch 12g`, so `--scratch` buys
nothing a build can use. A multi-GiB cargo target dir on `/scratch` OOM-kills the build,
which is why build caches default to the disk-backed `/artifacts/.build`.

MUST Treat free host disk as a precondition, not a background condition. `run-contained.sh` reads `df` on the artifacts dir and refuses to start below `--min-free-mb` (default 4096).
MUST Bound the copy-out. Findings are kilobytes; anything at the megabyte scale is build residue that a caller pointed at the wrong path.
NOT Never retry into a disk failure. A full disk corrupts the runtime's content store, and the second attempt lands on a runtime that can no longer read its own images.

### A host shell wrapper can leak into the container

Containerization is not hermetic against a wrapper installed in the shell that launches the
run. One was measured rewriting `cargo` to `rtk` INSIDE the container: it selected 0 tests
across 11 targets and exited 0, which is indistinguishable in a report from a clean surface.
Another rewrite echoed a denied host command back as `rtk df`.

MUST Pass `--require-cmd <names>` for every toolchain a run depends on. The wrapper resolves each name inside the container, prints the resolved path and version, and exits 6 when one does not resolve, so a substitution is visible before the command that depends on it runs.
MUST Distrust an exit code on its own. The wrapper writes `<artifacts>/run-contained.status` with `executed=0|1`, `rc`, and a `reason`, rewritten at every transition; a caller that requires a run to have happened greps `executed=1` rather than reading `$?`, which a host wrapper has been measured returning as 0 alongside a fatal error, and which a `| tee` in the caller's own pipeline discards outright.
MUST Pass `--expect-json <path>` for any scanner whose output a caller will parse. A crashed scanner leaves the previous run's JSON in place; the wrapper deletes the path before the command and afterwards requires a fresh file, parseable JSON, and a nonzero scanned-file count, exiting 7 with `executed=0` otherwise.

### A worktree's `.git` is a file, and repo-aware scanners fail open on it

In a git worktree `.git` is a pointer FILE naming the real gitdir, which lives outside the
mount. `gitleaks git` then finds no history to walk and reports success over zero commits,
which is a clean secrets scan for a repo it never read.

MUST Run a repo-aware scanner in its filesystem mode against a worktree (`gitleaks dir`, `gitleaks detect --no-git`), or mount the real gitdir alongside. History mode over a worktree is NOT EXECUTED.
MUST Confirm the scanner reports a nonzero unit count (commits walked, files scanned) before recording zero findings, since every one of these fails open to an empty result.

### The wrapper's own exit codes

`run-contained.sh` reserves the low codes for its own failures, so a caller can tell
"the campaign command failed" from "the run never happened". Every one of these is an
INVALID run to be reported as a coverage gap, never as zero findings. Code 124 is the one
exception: a user-set deadline expired, which is a normal outcome carrying partial results.

| Code | Meaning |
|---|---|
| 2 | usage error (a missing flag, a bad `--workdir`, an illegal tool name) |
| 3 | no container runtime, the image is absent, or host free disk is below `--min-free-mb` |
| 4 | the findings copy-out failed, or was refused above `--max-copy-mb`; output is stranded in the volume |
| 5 | `--copy-src` staging failed 3 times; the source copy may be incomplete |
| 6 | a `--require-cmd` name does not resolve inside the container |
| 7 | an `--expect-json` output is missing, unparseable, or reports 0 files scanned |
| 124 | a user-set `--timeout` expired; the findings collected so far ARE copied out, and `deadline=1` is recorded |
| other | the contained command's own exit code, passed through |

Code 5 exists because the staging tar is the LEFT side of a pipe. Without `pipefail`
the preamble's status came from the EXTRACTING tar, which succeeds on whatever bytes it
received, so `cd /scratch/src` worked and the build scanned a partial repo. It retries
3 times first: GNU tar returns the same exit 1 whether a file changed mid-read or an
unrelated sibling appeared at the repo root, and only the former persists.

## Assert the tools survived the build

Containerization guarantees a coverage-guided fuzzer is PRESENT (baked into the
image); it does not guarantee the build produced it. A stale or half-built image
that silently lacks `cargo fuzz` or `atheris` produces the exact false-clean the
package exists to catch. So before the fuzz phase trusts a clean result, assert the
surface's critical tool runs inside the image:

```
scripts/run-contained.sh --assert-tools sabot/<surface>:1 <tool[,tool...]>
```

Assert EVERY tool the surface's campaign will invoke, not only the fuzzer. A
missing scanner is the same silent-clean as a missing fuzzer. Pass the full
comma-list the surface doc's Tools table names:

| Surface image | Assert (executables) | Assert (library imports) |
|---|---|---|
| `sabot/rust:1` | `cargo-fuzz,cargo-audit,clippy,cargo-geiger` | none |
| `sabot/python:1` | `bandit,ruff,semgrep` | `python3 -c "import atheris, hypothesis"` |
| `sabot/node:1` | `jazzer,retire` | `node -e 'require("fast-check")'` |
| `sabot/go:1` | `go,gosec,golangci-lint` | none |
| `sabot/base:1` | `opengrep,shellcheck,ripgrep,gitleaks,ast-grep,shfmt,zizmor,actionlint,trivy,osv-scanner,radamsa,zzuf,creduce,hadolint,kube-linter,tflint,poutine,trufflehog` | none |
| `sabot/rust-extras:1` (optional) | `cargo-deny,cargo-vet,cargo-semver-checks,weggli` | none (cargo-careful and Miri are asserted by their baked sysroots, below) |

Each column asks a different question, and conflating them hid a real gap.
`--assert-tools` runs `<tool> --version`, which a LIBRARY can never answer: atheris,
hypothesis, and fast-check don't ship a CLI, so listing them there reported them missing
whether or not they were installed. Libraries are asserted by IMPORT instead, which
is also the stronger check for a native addon. `sabot/node:1` once shipped a
`jazzer` that `npm i -g` installed cleanly and that then died at dlopen against a
too-old glibc.

The probe tries `<tool> --version`, then `cargo <sub> --version`, then `<tool>
version`. That last form is what `go` answers: `go --version` exits 2 on an undefined
flag, so without it the go surface reports its toolchain missing. On the go surface the
toolchain IS the fuzzer, because `go test -fuzz` is built in and there is no separate
fuzz binary to assert.

MUST Point `TMPDIR` at a SUBDIRECTORY of the scratch tmpfs, never at its root. Go
refuses to read a `go.mod` that sits in the system temp root, so with
`TMPDIR=/scratch` and a workdir of `/scratch` every contained go command failed
"directory prefix . does not contain main module" while `go vet` still exited 0.

MUST Invoke TruffleHog with `--no-update`. It checks for a new release on startup and
tries to overwrite its own binary, which on the read-only container aborts the entire
scan with "cannot move binary" and reports zero findings. Pair it with
`--no-verification`, because verification calls each provider's API: offline it can
only detect, and the summary must show `verified_secrets 0` rather than imply it
checked.

MUST Give C-Reduce an interestingness test that names the file by RELATIVE path. The
test runs in a temp dir holding the VARIANT as `./<file>`, so an absolute path re-reads
the unreduced original, every check passes, and the reduction stops early while still
looking like it worked (measured: 182 bytes to 163, with the dead code intact, against
182 to 16 when the path is relative).

MUST Report a tflint run as CORE-ONLY. Provider plugins come from `tflint --init` over
the network, which `--network none` forbids, so the terraform rules that need a provider
never load.

MUST Pass `--cache-dir /opt/sabot-db/trivy` to trivy. Without it the bake is ignored and
trivy tries to pull `mirror.gcr.io/aquasec/trivy-db:2`, which fails on DNS and aborts the
run. The `misconfig` scanner reads a SECOND bundle that is not baked, so add
`--skip-check-update` as well: without it the run stalls about 4.3 seconds on a failed
download before falling back to checks compiled into the binary. That fallback is complete
(measured: the same 12 findings on the `iac` fixture either way), so the flag buys latency,
not coverage.

MUST Pass the db location to osv-scanner as `XDG_CACHE_HOME=/opt/sabot-db/osv`, or as
`OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`. `--offline` alone is the false-clean in this family:
it finds every lockfile, reports the package count it parsed, loads NO database, and says
zero vulnerabilities. The giveaway is on stderr, not stdout (`could not load db for npm
ecosystem: ... no offline version of the OSV database is available`), and the exit code is
127. With the db passed, the same fixture yields 130 advisories, and stderr says `Loaded npm
local db from ...`. Treat the absence of a `Loaded ... local db` line as an INVALID run.

MUST Point semgrep's `--config` at a `<lang>` SUBDIR of `/opt/sabot-db/semgrep-rules`, not
at the rules parent. The bake is the upstream repo checkout, which carries files that are
not rule files, and ONE invalid config aborts the entire scan: pointed at the parent, semgrep
exits 7 having scanned 0 files, on `.pre-commit-config.yaml is missing 'rules' as top-level
key`. A registry name (`p/python`, `--config auto`) fails on DNS instead.

MUST Pass `--config /opt/sabot-db/deny.toml` to cargo-deny unless the target ships its
own `deny.toml`. Without a `db-path`, `cargo deny check advisories` tries to clone the
advisory-db and, on the partial clone `--network none` leaves behind, loads zero
advisories and reports a clean.

MUST Pass `--offline` to cargo-deny BEFORE the subcommand: `cargo deny --offline check
advisories`. It is a top-level flag, and after `check` it is rejected as an unknown
argument. Without it cargo-deny attempts a fetch even with a valid local db.

MUST Point cargo-deny's `db-path` at a WRITABLE PARENT DIRECTORY holding the db under
cargo-deny's own child name, `advisory-db-3157b0e258782691`. Miss any one of these and a
working bake looks like a missing db:

- Writable, because it takes an exclusive lock on `db.lock` inside `db-path` before
  reading and has no flag to skip it. Against the read-only image: "attempted to take an
  exclusive lock on a read-only path". `--offline` does NOT skip the lock.
- Nested, because `db-path` holds one directory per `db-url` rather than the db itself.
  Pointed at a flat copy, cargo-deny tries to clone the child it cannot find and dies on
  DNS under `--network none`.
- Carrying `.git`, because the staleness check reads HEAD's commit timestamp.

`run-contained.sh` copies the 6MB baked db into that shape on the scratch tmpfs.
cargo-audit needs none of it: it reads the baked path directly, read-only and flat.

MUST Override a target's `rust-toolchain.toml` with `RUSTUP_TOOLCHAIN`. The images install
their stable BY VERSION (`1.97.1-<triple>`) and never under the literal name `stable`, so
a pin as ordinary as `channel = "stable"` matches nothing locally and rustup tries to
install it, which needs the network and a writable `/usr/local/rustup` and has neither.
Measured on a real crate, every cargo invocation died before doing any work:

```
info: syncing channel updates for stable-aarch64-unknown-linux-gnu
error: could not create temp file /usr/local/rustup/tmp/...: Read-only file system
```

`run-contained.sh` exports the image's own default toolchain in the preamble, so no recipe
has to:

- The value is read from `/usr/local/rustup/settings.toml`, not from `rustup toolchain
  list`. `list` honours the pin too and re-triggers the same sync.
- It is exported only when unset, and `+nightly` on the command line outranks the variable
  regardless, so cargo-fuzz and Miri still resolve the nightly. **`+nightly` is not
  optional for cargo-fuzz**: `-Zsanitizer=address` is nightly-only, so a bare `cargo fuzz
  build` under the exported stable fails, and the failure reads as the preamble's fault. A
  gremlin diagnosed it that way and exported `RUSTUP_TOOLCHAIN=nightly` per run to work
  around it; re-measured with `+nightly` and the preamble's stable left in place, the build
  finished in 15.8s. Spell the `+nightly`.

This one aborts with a message rather than reporting a clean, but it stops a campaign on
any repo that pins a toolchain, which is most of them.

MUST NOT report cargo-careful as a UB check. It hardens std's debug assertions; it does
not interpret UB. Measured on the `ub-rust` fixture, a read one byte past the end of an
allocation: `cargo careful test` reported it PASSING, while Miri named it. A finding that
needs a UB verdict needs Miri, and a clean careful run is not evidence of its absence.

MUST Invoke Miri as `cargo +nightly miri`. It is a rustup COMPONENT of the pinned dated
nightly, not a binary on `PATH`: `miri --version` reports missing, and `cargo miri` on
the default stable toolchain does too.

MUST Bake the Miri and cargo-careful sysroots at BUILD time, to a path uid 1000 can
read. Each builds a sysroot from `rust-src` at first use, which pulls std's registry
deps and so needs crates.io. `miri --version` answers whether or not that sysroot
exists, which hid the gap until a real run failed "no matching package named
`hashbrown`". At the default `~/.cache` the careful sysroot went to `/root/.cache`,
which the campaign user cannot read, so both are baked under `/deps/cache` and linked into
the container's `XDG_CACHE_HOME`.

MUST Give cargo-semver-checks a `--baseline-root`, not a `--baseline-rev`. The default
resolves the baseline through crates.io, and `--baseline-rev` needs a `.git` that
`--copy-src` strips. Pointed at the read-only `/target`, it runs offline (measured: 196
checks, 58 skipped).

MUST Report cargo-vet's offline result as the limit it is. Without the network it can
only say "you must run `cargo vet init`" or that no audits were imported. That is honest,
but recorded as a bare "no findings" it misreads as a pass.

MUST Set `GOPROXY=off` on the go surface. A build with an unresolved module otherwise
blocks on a proxy dial that `--network none` never completes, then reports a network
error that reads like a broken image instead of naming the missing module.

This table is the same manifest `scripts/install-tools.sh --probe` asserts. The base
image carries the cross-surface and CI/supply-chain scanners (`gitleaks`,
`osv-scanner`, `trivy`, and the workflow-dataflow pair `zizmor`+`actionlint`, plus
`pinact`), since a repo's `.github/workflows` and dependency manifests are read on
every run regardless of language. A tool named here but absent from a built image
FAILS the preflight; the campaign does not start until the image ships the full set.

Exit 0 means every tool answered `--version` inside the image; non-zero names
the missing ones. Assert the complete set once, up front, so a campaign never
discovers a missing scanner mid-run and reports its dimension as clean.

MUST Assert a library by importing it, not by invoking it. A package that pip or npm wrote to disk can still fail to load, and a native addon linked against a newer glibc than the image carries fails only at dlopen: at fuzz time, in a phase whose failure reads as a clean.

MUST Assert EVERY tool the surface's campaign will invoke inside the image up front, not only the coverage-guided fuzzer. An unconfirmed scanner or fuzzer yields a clean result the campaign did not earn; a missing scanner is as silent as a missing fuzzer.
MUST Refuse the fuzz phase and report the surface as uncovered when the assertion fails. Do not use hand-written vectors instead and call it fuzzed. Rebuild the image from `references/containers/` and retry, or record the gap in the report headline.

## Baked offline databases

Several scanners depend on REMOTE data fetched on first use (a vuln DB, an advisory
dir, a rule pack, JS vuln definitions). Under `--network none` that fetch fails and
the tool reports a clean it never earned, the exact false-clean this package exists
to catch.

Each tool in the table below is baked at BUILD time, when the network is available,
and the campaign passes the flag that reads the baked copy and skips the fetch. The
base image holds the shared data under `/opt/sabot-db`; the rust surface adds the
RUSTSEC advisory-db and the fuzz-crate registry.

| Tool | Surface | Baked at build | Offline run flag | Pinned by |
|---|---|---|---|---|
| trivy | base | `/opt/sabot-db/trivy` (`--download-db-only`; Java index skipped) | `--cache-dir /opt/sabot-db/trivy --skip-db-update` | image tag (rolling DB) |
| osv-scanner | base | `/opt/sabot-db/osv` (crates.io, npm, PyPI, Go ecosystems) | `XDG_CACHE_HOME=/opt/sabot-db/osv … --offline-vulnerabilities` | image tag (rolling DB) |
| opengrep / semgrep | base | `/opt/sabot-db/semgrep-rules` (semgrep registry source) | `--config /opt/sabot-db/semgrep-rules/<lang>` | `SEMGREP_RULES_SHA` |
| cargo-audit | rust | `/usr/local/advisory-db` (RUSTSEC) | `--no-fetch --db /usr/local/advisory-db` | `ADVISORY_DB_SHA` |
| cargo-fuzz | rust | `libfuzzer-sys`+`arbitrary` in `/deps/cargo` registry, g++, `nightly` alias | `CARGO_NET_OFFLINE=true cargo +nightly fuzz build` | crate `=` pins |
| retire | node | `/opt/sabot-db/retire/jsrepository-v5.json` | `--jsrepo /opt/sabot-db/retire/jsrepository-v5.json` | `RETIREJS_SHA` |

`run-contained.sh` sets `CARGO_NET_OFFLINE=true` (so cargo resolves the baked
registry instead of the crates.io index it cannot reach) and a UTF-8 locale (opengrep
aborts decoding a non-ASCII source file without one). The XDG_CACHE_HOME osv needs is
set per-recipe, not globally, because run-contained points it at a fresh tmpfs.

MUST Invoke each remote-data tool with its offline flag from the table above under `--network none`. The bare recipe fetches, which fails silently to zero findings under the network-none contract.
MUST Rebuild the surface image (not just re-tag) to refresh a rolling DB. The trivy and osv DBs carry no version pin; a stale image scans against a stale DB, which the report must not present as current.

## The heavy surface: Joern and ZAP

`sabot/heavy:1` is an OPTIONAL escalation image on `sabot/base:1`, reached for when a
finding wants interprocedural dataflow (Joern) or a DAST pass (ZAP). It is separate
because Joern alone unpacks past 1GB and base is inherited by every surface.

MUST Invoke ZAP with `-dir <writable path>` on the scratch tmpfs. ZAP does NOT honour
`$HOME`: it derives its home from the passwd entry and hardcodes `~/.ZAP`, so under the
campaign's `--read-only` rootfs it refuses to start even with `HOME` on the tmpfs, and it
EXITS 0 while doing so. Measured:

```
Unable to create home directory: /home/breaker/.ZAP/
Is the path correct and there's write permission?
```

A wrapper that trusts the exit code therefore records a DAST pass that never ran.
Measured with `-dir /scratch/zaphome`, the same invocation reports 6 alerts.

MUST Report ZAP's PASSIVE half only, and say so. Its rules ship in the bundle and work
offline, but they only see traffic. An active scan needs a live target, which under
`--network none` means a server the campaign itself started inside the container
(measured: `python3 -m http.server` on 127.0.0.1, scanned via `-quickurl`). A report that
does not name which half ran implies coverage the run did not have.

MUST NOT report CodeQL as available on arm64. No linux-arm64 build of it exists; see
`tool-coverage-matrix.md`. A campaign that needs it runs on an x86_64 host, and a report
that would have run it names the gap.

### Known coverage gaps under `--network none`

The opt-in scanners below need remote data with no offline mode, so they stay off
under the network-none contract. An operator who wants one grants network explicitly,
and the report then states that exposure was scanned with network.

- **grype, conftest** (infra.md, opt-in, not baked): each fetches its own DB or policy bundle. grype's is 2.0GB and base is inherited by every surface, so the bake was declined and trivy plus osv-scanner cover the same ecosystems.
- **checkov, hadolint, kube-linter, tflint are NOT gaps** and were wrongly listed here. Each is baked, and each was MEASURED offline under `--network none` on a seeded Terraform and Dockerfile fixture:
  - checkov: 3 failed / 4 passed on an open-port-22 security group (`sabot/scanners:1`, exit 1).
  - hadolint: 3 DL findings, exit 1.
  - tflint: 2 core issues, exit 2. Core only, since `--init` provider plugins do need the network.
  - kube-linter: loads its compiled-in checks, exit 0.

  See the base and infra rows of `tool-coverage-matrix.md`, which is the measured record.
- **nuclei, ZAP** (web.md, dynamic): templates and rules fetched on use. Dynamic DAST already needs the operator to stand up the dev server, so it sits outside the default offline path.

## Provisioning and extending the image

Every target-touching tool runs in the container, so the image must already hold
what the campaign needs: the surface scanners AND the target's own dev-dependencies
(a `cargo test` harness that pulls `proptest` cannot fetch it under `--network none`,
so the dep must be baked in at build time). Provisioning happens once, at step 3,
before the fan-out, while the network is available and no target code runs.

**Detecting the dev-deps.** Do this deterministically with
`scripts/detect-stacks.py`, not by hand: it lists the target's tracked files
(`git ls-files`, so `.gitignore` is honored), finds every manifest, collapses Cargo
workspace members into the root fetch, and emits both the stack map (default JSON,
`--repo <dir>`) and the exact bake commands (`--repo <dir> --bake`). It handles the cases a single-manifest guess
misses, a workspace, a monorepo, and a multi-language target (a Tauri app is Rust
under `src-tauri/` plus a JS frontend). The manifests and their fetch commands:

- **Workspace / monorepo:** glob for every `Cargo.toml`, `package.json`,
  `pyproject.toml`, `go.mod` under the target file set, not just the repo root. A
  Cargo workspace root plus its member crates, or N packages under `packages/`, each
  declare their own dev-deps. Fetch at the workspace root where the toolchain is
  workspace-aware (`cargo fetch` from the workspace root resolves all members;
  `go mod download` per module); otherwise once per package.
- **Multi-language (e.g. Tauri = Rust + a JS frontend):** a single target legitimately
  has both a `Cargo.toml` (often under `src-tauri/`) and a `package.json`. It needs an
  image with BOTH toolchains, so the surface-to-image map is not 1:1 here: extend the
  base with each detected stack's toolchain and bake each manifest's deps. Record
  every stack found so the report states which were provisioned.

Record the manifest map alongside the step-2 entry-point enumeration, which already
walks the file set, and let the provisioning step at step 3 consume
it. Per stack, the toolchain's own resolver fetches exactly what its manifest names:

| Stack | Declares dev-deps in | Bake with |
|---|---|---|
| Rust | `Cargo.toml [dev-dependencies]` + `Cargo.lock` | `cargo fetch` (whole lock), or `cargo fetch` then a throwaway `cargo build --tests` to warm the registry |
| Node | `package.json devDependencies` + lockfile | `npm ci` / `pnpm install --frozen-lockfile` |
| Python | `pyproject.toml` dev group / `requirements-dev.txt` | `uv sync` / `pip install -r` |
| Go | `go.mod` (test deps not separated) | `go mod download` |

**Layered so a source change never rebuilds the world.** `scripts/build-ext-image.sh`
copies ONLY the manifest and lockfile into a temp build context, runs the fetch, and
copies nothing else. The deps become their own cache layer keyed on the lock, so only
a lock change re-fetches. The generated Dockerfile:

```
FROM sabot/rust:1
COPY Cargo.toml Cargo.lock ./          # only the manifest+lock, so the next layer caches on the lock
RUN cargo fetch                         # dev-deps into the image's cargo cache; own layer
# no COPY of the source: the target is mounted read-only at /target at run time
```

Build the ext image at step 3 with the script, which runs `detect-stacks.py`, writes
the thin Dockerfile, and builds it:

```
scripts/build-ext-image.sh --target <dir> --base sabot/<surface>:1 \
                           --tag sabot/<surface>-ext:1
```

The script bakes the dep caches into a persistent `/deps` prefix (it sets
`CARGO_HOME`, `GOMODCACHE`, `npm_config_cache`, `PIP_CACHE_DIR`, `UV_CACHE_DIR` there),
NOT under `/scratch`: `run-contained.sh` mounts `/scratch` as a fresh tmpfs per run,
so a cache baked there is masked at run time. Then `--assert-tools` against the ext
image, then run the campaign against it under the unchanged network-none contract. The
extension NEVER copies the target source into the image (the target is mounted
read-only at run time); it copies only the manifest+lock to drive the fetch, so
nothing about the audited code enters a persisted layer.

MUST Provision at step 3, network-available, before the fan-out. A dep fetched mid-campaign is a fetch the `--network none` gremlin cannot do, so the harness reports a false coverage gap instead of running.
MUST Detect dev-deps from the target's manifest and lockfile, never a hardcoded list. The manifest is the exact declaration; a guessed set bakes the wrong tools and still fails the harness.
MUST Discover every manifest in the resolved target scope, not just a repo-root one. A workspace, monorepo, or multi-language target (a Tauri app is Rust plus a JS frontend) has several, and baking only the root manifest leaves a member crate or the frontend unprovisioned.
MUST Extend the image with a toolchain per detected stack for a multi-language target, and state every stack provisioned in the report. The surface-to-image map is not 1:1 when one target needs both cargo and npm.
MUST Bake the deps as their own layer keyed on the lockfile (copy manifest+lock, fetch, stop), so a source change reuses the cached deps rather than re-fetching every run.
MUST Re-resolve a lockfile the fuzzer created AFTER the bake, inside the container, with `cargo generate-lockfile --offline` (or the stack's equivalent) into the disposable source copy. Provisioning bakes what the target's manifests declared at step 3, and step 7 then writes a `fuzz/` crate whose lockfile the authoring host resolved with network. Measured on `fits-header`: the new `fuzz/Cargo.lock` pinned `proc-macro2 1.0.107` against the image's baked `1.0.106`, and every `cargo fuzz build` died with `attempting to make an HTTP request, but --offline was specified`, which is a provisioned image failing on a dep it holds a different patch of. Re-resolving against the baked registry costs one offline pass; discovering it per gremlin costs one rebuild each.
NOT Never COPY the target source into the image. The target is mounted read-only at run time; copying it into a build layer both defeats the read-only guarantee and persists the audited code in the image.

## No container runtime: fail the whole run, loudly

A container runtime (`docker`, `podman`, `finch`, `nerdctl`) is not optional. Since
every target-touching tool runs in the container (What runs where), no runtime means
the campaign cannot scan or execute anything safely, so it does not run a degraded
subset: it aborts at step 0 with a clear message and a non-zero exit, before opening
the run graph or spawning any agent. A partial "static-only" run is not offered,
because it would present an incomplete audit as a completed one and, for a compiling
scanner, would run the target's build code on the host.

MUST Probe for a container runtime at step 0 (part of the `install-tools.sh --probe` preflight) and, when none is present, ABORT the whole campaign with a loud message naming the missing runtime and a non-zero exit. Do not open the run graph, do not spawn a sabot-scout, do not run a host-side scan.
MUST Abort the run when `bd` is absent too, per `beads-store.md`: no run graph means no durable state, so there is no campaign to run. Both the runtime and `bd` are hard preconditions, not degradable ones.
MUST Never fall back to host execution or a static-only subset when no container is available. A host-only run is the exact unbounded risk the container exists to prevent, and a partial run presents an incomplete audit as a completed campaign.
NOT Never weaken the container contract (add network, drop the mem cap, run root) to make a harness pass. A harness that only runs unconfined is a harness that does not run.

## The authoring ban

The container contains a blast; this stops the fuzzer from arming one. Even inside
isolation, an input whose *purpose* is an irreversible effect is never generated.

MUST Fuzz the code path that RECEIVES a destructive input, never author a harness that EXECUTES the destructive branch. A parser that mishandles `rm -rf /` is the target; running `rm -rf /` is not the test.
NOT Never generate an input class whose effect is irreversible even in the container: a real `rm`/`mkfs`/`dd` to a device; a `DROP`/`TRUNCATE` against a live database; a fork bomb; a disk-filling loop. The finding is that the target accepts the input, not that the effect happened.
MUST Seed a destructive-looking payload as data the target parses, not as a command the harness runs. `{"command":"rm -rf /"}` fed to a guard is a vector; `os.system("rm -rf /")` in a harness is an attack on the machine.

## The host tripwire

The backstop that lives outside the sandbox. A monitor inside the container can be
subverted by what it monitors; a host-side hook watching the filesystem cannot.

This package ships no tripwire hook. It is an optional control the operator wires
into the running session, so a campaign that has not wired one has NO backstop and
its report says exactly that (see the report line below). The container contract and
the authoring ban are the controls that always apply; the tripwire is the extra net
for the operator who wants it, not a guarantee the skill provides on its own.

When wired, it is a `PostToolUse` (or `FileChanged`, where the harness supports it)
hook, scoped to the campaign, that halts on any observable the container should have
prevented:

| Tripwire | Halt because |
|---|---|
| A write anywhere outside `<artifacts>` and the container | the container boundary leaked, or an execution phase ran on the host |
| A canary file (seeded outside the artifacts dir) changed or read | a payload reached beyond its sandbox |
| An outbound connection beyond loopback from a campaign process | `--network none` was bypassed or a phase ran unconfined |
| Disk or inode growth past the budget, a pid/fd runaway | a resource attack the container caps should have bounded |

MUST Seed canaries OUTSIDE the container mounts before an execution phase, and read them after, since a canary reachable by the campaign is a canary that proves reach.
MUST Halt the campaign, preserve the artifacts, and report on any tripwire rather than continuing. A campaign that trips a guardrail and keeps running has already lost the property the guardrail asserts.
MUST Treat a tripwire hit as a finding about the ISOLATION, reported alongside the target findings, since the campaign reaching the host is worse news than anything it found in the target.
NOT Never disable the tripwire to let a campaign finish. The tripwire firing is the campaign telling you it escaped.

## Report line

Every campaign states its isolation posture, so a reader knows what the findings
were produced under. The tripwire line reports its ACTUAL state, and reads
`none wired` when the operator ran no tripwire:

```
Isolation: docker, --network none, mem 2g, pids 512, target ro, non-root (--user 1000:1000).
           host tripwire: none wired (container contract + authoring ban only).
```

or, when the operator wired one:

```
           host tripwire active (artifacts-dir + 3 canaries). No trip.
```

MUST State the isolation posture in the report. A finding produced under an unknown or degraded posture is a finding whose blast radius the reader cannot judge.
MUST Report the tripwire's real state, `none wired` when none ran. Claiming a tripwire that was never wired invents a backstop the campaign did not have, which is worse than admitting there was none.
