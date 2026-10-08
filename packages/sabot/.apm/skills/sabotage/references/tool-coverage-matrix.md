# Tool coverage matrix

This matrix lists every tool sabot advertises, the image that ships it, its OFFLINE
requirement under `--network none` (the campaign's mandatory isolation), and its
end-to-end test status. The "offline req" column is MEASURED, not assumed: run the
tool twice (`--network none` against `--network bridge`) and compare, per the probe
method in `isolation.md`. A tool that exits 0 offline while doing less than it does
online is DEGRADED-SILENT, the false-clean this matrix exists to eliminate.

## Offline-requirement classes

- **self-contained**: offline output equals online; the tool ships all it needs and runs as-is.
- **baked-ok**: needs remote data, baked into the image, works offline.
- **degraded-silent**: exits 0 offline but did less (loaded 0 rules/advisories). MUST fix (bake, or forbid the online-only invocation).
- **fails-loud**: errors offline, safe because the campaign sees the failure.
- **needs-build-dep**: offline operation needs crates/packages/compilers not present.
- **UNMEASURED**: not yet probed.

## Status legend

baked (in an image manifest + verified) · fragment-pending (bake work queued) ·
image-unbuilt (fragment exists, image not built) · fixture-verified (a test repo
proved detection end-to-end).

## base image (cross-surface, infra, secrets, container, generators)

| Tool | Offline req | Bake status | Fixture / test |
|---|---|---|---|
| opengrep | degraded-silent (forbid `--config auto`; local rules only). It has NO `--metrics` flag (it never reports) and exits 2 on it, as on any unknown option. **depends on `LC_ALL=C.UTF-8`**, which `run-contained.sh` already exports, so the campaign path is safe. A BARE `docker run` is not, because the image does not set a locale itself. opengrep then dies in the CONFIG LOADER on any rule file holding a non-ASCII byte (`UnicodeDecodeError: 'ascii' codec can't decode byte 0xe2`), exit 2 with ZERO findings. Measured both ways. Now the only rule engine, so nothing cross-checks it | baked | **node-parser VERIFIED** (a local rule located the seeded prototype-pollution merge at line 11 offline); rust-parser (local rule). **base MEASURED against the baked python pack**: 5 findings / 3 rules / 0 errors with the locale set, exit 2 and 0 findings when no locale is set. Asserted in `install-tools.sh` `IMAGE_DB_base`, which sets the locale itself so the probe does not depend on the caller's environment |
| ripgrep | self-contained | baked | **ub-rust VERIFIED** (14.1.1; matched offline; a search primitive that the campaign drives, with no ruleset of its own) |
| shellcheck | self-contained | baked | **shell VERIFIED** (SC2086/SC2045/SC2035/SC2164 offline, exit 1) |
| shfmt | self-contained | baked | **shell VERIFIED** (`-d` reports an indentation diff offline, exit 1) |
| ast-grep | self-contained | baked | **ub-rust VERIFIED** (0.45.0; `unsafe { $$$BODY }` matched `src/lib.rs:3` offline, JSON out) |
| gitleaks | self-contained (rules embedded); `gitleaks dir` scans a non-git tree | baked | **secrets VERIFIED** (3 offline: private-key, generic-api-key, github-pat) |
| zizmor | self-contained (offline==online) | baked | **infra-ci VERIFIED** |
| actionlint | self-contained (rules compiled in; the shellcheck integration needs the BINARY, present in base, not the network) | baked | **infra-ci VERIFIED** (untrusted-input script-injection on `github.event.pull_request.title`, `[expression]`, exit 1) |
| ~~pinact~~ | fails-loud (SHA resolve needs net, and no local DB can substitute: the tag-to-SHA map IS the remote); the verb is `pinact run --check`, and it needs a WRITABLE tree, so a read-only bind mount makes it exit 0 silently on an unpinned ref | **DROPPED, not installed** (no image or `install-tools.sh` manifest carries it) | measured before the drop: **infra-ci VERIFIED honest offline**, naming the unpinnable ref (`action can't be pinned`, `actions/checkout@main`), reporting the DNS failure for a resolvable tag, exit 3. Dropped because `zizmor --offline` reports the same unpinned refs (`error[unpinned-uses]` on the same fixture), so detection is covered; pinact's unique value is WRITING the pin, which is remediation |
| trivy | **fails-loud ONLY with `--cache-dir /opt/sabot-db/trivy`**; the bare `trivy fs` ignores the bake and dies trying to pull `mirror.gcr.io/aquasec/trivy-db:2`. `misconfig` uses a SECOND bundle that is not baked: without `--skip-check-update` it stalls ~4.3s on a failed download, then falls back to checks embedded in the binary (same 12 findings) | baked (vuln DB; misconfig checks come from the binary) | **deps-vuln + iac + secrets VERIFIED** (77 vulns incl. CVE-2019-14234 Django==2.2.0 and CVE-2019-10744 lodash==4.17.4; 12 misconfigs AWS-0086/0087/0089/0090; 4 secrets) |
| osv-scanner | fails-loud → bake OSV DB, and the db location MUST be passed: `XDG_CACHE_HOME=/opt/sabot-db/osv` (or `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`). Bare `--offline` finds the lockfiles, loads NO db, and reports 0 (`no offline version of the OSV database is available`, exit 127) | baked (4 ecosystems) | **deps-vuln VERIFIED** (130 advisories over 7 packages: 70 on django==2.2.0, 24 urllib3, 10 lodash, incl. PYSEC-2019-10 and GHSA-vh95-rmgr-6w4m) |
| Checkov | self-contained once installed (policies ship in the wheel; the pip install is the network op) | baked (`sabot/scanners:1`, pipx venv) | **iac VERIFIED** (11 failed / 7 passed offline as uid 1000, exit 1, incl. the open-port-22 SG check) |
| hadolint | self-contained (rules compiled in) | baked | **infra-extras VERIFIED** (DL3006/DL3008/DL3009/DL3015 offline) |
| kube-linter | self-contained (checks compiled in) | baked | **infra-extras VERIFIED** (5 checks fired offline) |
| tflint | baked-ok CORE ONLY (`--init` provider plugins need net; report must say core-only) | baked | **infra-extras VERIFIED** (2 core issues offline) |
| Grype | baked DB DECLINED: DB measures 2.0GB (v0.117.0) and base is inherited by every surface; trivy + osv-scanner already cover the same ecosystems | declined | n/a; the coverage is already there via trivy and osv-scanner |
| TruffleHog | baked-ok DETECTION ONLY; needs `--no-update` (self-updater aborts the scan on a read-only fs) + `--no-verification` | baked | **secrets VERIFIED** (2 offline, AWS + Github, both `Verified: false`) |
| Kingfisher | baked-ok DETECTION ONLY; `--no-validate` is mandatory offline, and the update check fails harmlessly (`update_check_status: failed`) | baked (`sabot/scanners:1`) | **secrets MEASURED** (1061 rules applied offline; 1 finding, `kingfisher.aws.2`, `Not Attempted`). Found FEWER than gitleaks on the same fixture: it missed the RSA private key and the `ghp_` PAT |
| GuardDog | self-contained for `scan` on a local path (heuristics ship in the wheel); `verify` queries the registry. **EXITS 0 ON A HIGH-RISK VERDICT** | baked (`sabot/scanners:1`, pipx venv) | **deps-py VERIFIED** (8.0/10 High risk offline, 2 risk categories / 7 issues on a seeded install-time exfil `setup.py`) |
| OSSF-Scorecard | needs-net (GH API), likely irreducible gap | fragment-pending | doc as gap? |
| poutine | self-contained (rules compiled in); subcommand is `analyze_local` | baked | **infra-ci VERIFIED** (injection rule fired offline) |
| Nuclei | baked-ok, and MUST pass BOTH `-templates` and `-ud` at the baked path (see below); `-duc` to stop the updater | baked (`sabot/scanners:1`, 13575 templates, all validating) | **web VERIFIED** (14 findings offline under `--read-only` as uid 1000 against a container-local `http.server`: robots-txt, tech-detect, 10 missing-header matchers) |
| Bearer | fails-loud without baked rules (`0 rules found ... could not be downloaded`); MUST pass `--external-rule-dir` | baked (`sabot/scanners:1`, bearer-rules pinned by SHA) | **code-py VERIFIED** (234 rules evaluated offline; `python_lang_os_command_injection` line 10 + `python_lang_weak_hash_md5` line 6) |
| radamsa | self-contained (mutator); builds from source, needs `libc6-dev` | baked | **python-parser VERIFIED** (33 crashes in 200 mutations offline) |
| zzuf | self-contained (mutator) | baked | **VERIFIED offline** (`-r 0.05 -s 42`: 13 of 40 bytes changed, length preserved) |
| C-Reduce | self-contained (reducer); test script MUST use a RELATIVE path | baked | **VERIFIED** (182 -> 16 bytes offline) |

## rust fragment

| Tool | Offline req | Bake status | Fixture / test |
|---|---|---|---|
| clippy | needs dep graph (ok in ext); a target's `rust-toolchain.toml` MUST be overridden by `RUSTUP_TOOLCHAIN` (see below) | baked | **rust-parser + fits-header VERIFIED** (clean under `-D warnings` offline on a real crate) |
| cargo-fuzz | needs-build-dep (libfuzzer-sys+arbitrary+g++), baked; needs `+nightly`, and `--offline` is NOT accepted (`cargo fuzz build --offline` → `unexpected argument`; the wrapper's `CARGO_NET_OFFLINE` covers it) | baked | **rust-parser + fits-header VERIFIED** (`init` + `build` + `run` offline on a real crate; found a panic in 2 execs) |
| cargo-audit | degraded-silent → bake advisory-db; the db path is `/usr/local/advisory-db`, read flat and read-only | baked | **deps-rust + fits-header VERIFIED** (1216 advisories, RUSTSEC-2020-0071 offline; 56 deps scanned clean on the real crate) |
| cargo-geiger | needs dep graph (ok in ext) | baked | **ub-rust VERIFIED** (4/4 unsafe expressions, `!` verdict, offline, exit 0) |
| AFL++ | needs-build-dep (apt + cargo-afl) | fragment-pending | rust-parser |
| honggfuzz | needs-build-dep (apt + cargo) | fragment-pending | rust-parser |

### The toolchain pin, and what a real crate proved

Every rust row above was measured on a fixture built to be measured. `fits-header` v0.4.2
was not: a published MPL-2.0 crate, taken as-is, run end to end offline. It surfaced a
blocker and a bug that no fixture had shown.

The blocker is `rust-toolchain.toml`. The images install
their stable by version and never under the name `stable`, so the commonest pin in the
ecosystem resolves to nothing local and rustup reaches for the network it does not have on
a filesystem it cannot write. `run-contained.sh` now exports the image's default toolchain
in the preamble (isolation.md, "Override a target's `rust-toolchain.toml`"). A recipe
setting the variable itself still wins, and so does `+nightly`, so cargo-fuzz and Miri are
unaffected.

The bug is the result. Against a crate whose own suite passes 152 tests and whose clippy
is clean under `-D warnings`, cargo-fuzz needed 2 executions to panic the parser:

```
thread '<unnamed>' panicked at src/parse.rs:38:31:
end byte index 8 is not a char boundary; it is inside '\u{fffd}' (bytes 6..9 of string)
```

`from_utf8_lossy` maps an invalid byte to a 3-byte replacement character, so the slice
`card_str[..8]` that assumes 8 bytes is 8 characters lands mid-character and panics. This is
what the surface exists to find, and it is the class that reading the code, running the
tests, and linting all miss: 53 unit tests, 8 doctests, 1216 advisories, and 954KB of
secret-scanning all reported clean on the same commit.

## rust-extras fragment

An OPTIONAL escalation image (`sabot/rust-extras:1`), not part of every campaign: a
rust run starts on `sabot/rust:1` and escalates here when a finding needs a license
view, a UB interpreter, or a semver-break check. Absent is a note in the preflight, not
a failure.

| Tool | Offline req | Bake status | Fixture / test |
|---|---|---|---|
| cargo-deny | degraded-silent → baked advisory-db, and `db-path` must be a WRITABLE PARENT holding the db under `advisory-db-<hash>` with its `.git` intact; `--offline` goes before the subcommand | baked (wrapper copies the db into that shape on tmpfs) | **deps-rust VERIFIED** offline (RUSTSEC-2020-0071; `bans ok, licenses FAILED`) |
| cargo-careful | needs-build-dep: sysroot MUST be baked, and to a uid-1000-readable path (the default `~/.cache` put it in `/root`) | baked (`/deps/cache/cargo-careful`) | **rust-parser VERIFIED** (2 tests pass offline off the baked sysroot). **NOT a substitute for Miri**: on `ub-rust` it reported the seeded out-of-bounds read as passing. It hardens std's debug assertions; it does not interpret UB |
| Miri | needs-build-dep: builds its OWN sysroot from rust-src at first use, which needs crates.io. `miri --version` answers while that sysroot is absent | baked (`/deps/cache/miri`) | **rust-parser VERIFIED** offline after the bake; failed `no matching package named hashbrown` before it. **ub-rust VERIFIED**: `cargo test` reports 1 passed on a read past the end of an allocation, Miri reports `Undefined Behavior: ... at or beyond the end of the allocation of size 3 bytes` |
| cargo-semver-checks | needs a baseline; `--baseline-rev` needs `.git` (stripped by `--copy-src`) and the default resolves through crates.io. `--baseline-root` is the offline form | baked | **rust-parser VERIFIED** (196 checks, 58 skip, via `--baseline-root /target`) |
| cargo-vet | fails-loud offline: needs a `supply-chain/` store, and imports its audits over the network | baked | **deps-rust MEASURED**: `must run 'cargo vet init'`: honest, not a false clean |
| weggli | self-contained (C/C++ pattern; patterns come from the campaign) | baked | **VERIFIED offline** on a seeded `strcpy` into a 16-byte stack buffer: both `{strcpy(_,_);}` and the `{char $b[_]; strcpy($b,$s);}` shape matched |
| proptest | crate, no binary (a dev-dep, baked per-target by build-ext-image.sh) | declined | n/a; installing it globally installs nothing usable |
| CASR | needs gdb, and duplicates what libFuzzer already prints for a rust panic | declined | n/a |

## go fragment

| Tool | Offline req | Bake status | Fixture / test |
|---|---|---|---|
| `go test -fuzz` | self-contained (fuzzer is in the toolchain; no runtime crate to bake) | baked | **go-parser VERIFIED** (found seeded panic offline, crash corpus copied out) |
| gosec | self-contained (rules compiled in) | baked | **go-parser VERIFIED** (G404 offline) |
| golangci-lint | self-contained (linters compiled in) | baked | **go-parser VERIFIED** (ineffassign offline) |
| go vet | self-contained (ships with the toolchain) | baked | **go-parser VERIFIED** on a seeded format mismatch: `fmt.Printf format %d has arg "not-an-int" of wrong type string`, exit 1 |

The go surface needs `GOPROXY=off` and a `TMPDIR` below the scratch root; both are
recorded as MUSTs in `isolation.md`.

## python fragment

| Tool | Offline req | Bake status | Fixture / test |
|---|---|---|---|
| Bandit | self-contained (rules embedded) | baked | **python-parser VERIFIED** (B307 offline) |
| Ruff | self-contained (needs `RUFF_CACHE_DIR` off the read-only target) | baked | **python-parser VERIFIED** (offline) |
| Semgrep | **REMOVED, redundant with opengrep.** Measured against the same baked pack, same fixture, `--network none`: both returned 5 findings, the same 3 rules and 0 errors, so shipping both bought nothing. opengrep is in base, scanners, python and heavy; semgrep was only ever in python. Dropped from `IMAGE_TOOLS_python`; the rules bake is unchanged and stays at `/opt/sabot-db/semgrep-rules`, named for its upstream repo, read by opengrep. Historical traps, should it ever return: `--config` MUST name a `<lang>` SUBDIR (the PARENT aborts the scan on one invalid file, `.pre-commit-config.yaml is missing 'rules'`, exit 7, 0 files scanned), the registry form (`p/python`, `--config auto`) dies on DNS, and it needs `--metrics=off` plus a writable `SEMGREP_SETTINGS_FILE` | rules baked (2156 files, opengrep-owned); binary DECLINED | **MEASURED redundant** against opengrep on the same pack and fixture offline (5 findings / 3 rules / 0 errors from each), so the binary is declined and the opengrep base row carries the coverage |
| atheris | needs-build-dep (clang + `libclang-rt-<major>-dev` + `CXX`), baked | baked | **python-parser VERIFIED** (found seeded IndexError offline) |
| Hypothesis | self-contained (library; assert by import) | baked | **VERIFIED** (6.145.1 imports offline; the pin is asserted by the HypoFuzz probe, see the generator tier) |
| HypoFuzz | baked-ok, and the hypothesis pin MUST be held: HypoFuzz sets only a floor, and a newer hypothesis crashes every worker while it claims a failure (see below). No `hypofuzz` binary; it registers `hypothesis fuzz` | baked (`sabot/python:1`, 25.11.1 against hypothesis 6.145.1) | **VERIFIED** (fuzzed a seeded `n != 0` property offline as uid 1000, recorded the counterexample, and `pytest` replayed it from the example database) |
| schemathesis | self-contained; needs a spec AND a reachable base URL, so offline means serving the API inside the container | baked (`sabot/python:1`, 4.24.3) | **VERIFIED** (3 unique failures offline against a container-local `http.server`: server error, schema-violating request accepted, undocumented status code) |
| Grammarinator | self-contained; `grammarinator-generate` MUST run with the processed grammar's directory on `PYTHONPATH`, or it fails `ModuleNotFoundError: No module named 'TGenerator'` | baked (`sabot/python:1`, 26.1) | **VERIFIED** (processed a 4-rule ANTLR grammar and generated 3 files matching it offline) |
| dharma | self-contained; ships its own grammar tree (`json.dg`, `svg.dg`, `xss.dg`, `url.dg`, `wasm.dg`, `canvas2d.dg`) | baked (`sabot/python:1`, 1.3.2, unpinned: no release since) | **VERIFIED** (167 bytes of generated JSON offline from its bundled `json.dg`) |
| shrinkray | self-contained (reducer); HELD at 26.7.6.1, because 26.7.7.0 takes a hard dependency on `llama-cpp-python`, which needs a C++ toolchain and a baked model to work offline | baked (`sabot/python:1`) | **VERIFIED** (60 bytes down to 11 offline against a `grep -q` interestingness predicate) |

The python generator tier carries one dependency trap. HypoFuzz 25.11.1 requires only
`hypothesis[cli,watchdog]>=6.140.2`, so a resolver takes the newest hypothesis, and against
6.165.10 every fuzz worker died inside HypoFuzz:

```
AttributeError: 'ConjectureResult' object has no attribute 'slice_comments'.
Did you mean: 'span_comments'?
```

`hypothesis fuzz` then printed `Found a failing input for every test!` on a test with no bug
in it. That is a FALSE POSITIVE off a crashed worker, and it is the mirror image of the
false-clean this matrix hunts. A campaign reading that line reports a defect that is not
there.

6.145.1, the newest hypothesis published before HypoFuzz 25.11.1, fuzzes cleanly. 25.11.1
is the newest HypoFuzz, so the pin has to sit on the hypothesis side until upstream caps
its own dependency.

The build therefore probes HypoFuzz in BOTH directions, on an unfalsifiable property and on
a seeded failure, because either direction alone passes on a crashed worker. The passing
property is `isinstance(n, int)` rather than a bound like `n < 10**9`: `st.integers()` is
unbounded and HypoFuzz does exceed any such bound, so a bounded property fails this probe
by finding a real counterexample.

## node fragment

| Tool | Offline req | Bake status | Fixture / test |
|---|---|---|---|
| Jazzer.js | self-contained (prebuilt addon; needs glibc >= 2.38, so trixie); MUST be installed LOCALLY, not `-g` (see below) | baked | **node-parser VERIFIED** (crash + artifact on the seeded no-colon TypeError) |
| fast-check | self-contained (library; reachable via `NODE_PATH`) | baked | **node-parser VERIFIED** (shrunk a counterexample for SEEDED-BUG-2 in 1 test, 4.9.0) |
| retire.js | degraded-silent → bake defs + `--jsrepo`; scans INSTALLED `node_modules`, NOT declared dependencies (see below) | baked | **node-deps VERIFIED** (15 vulnerable-component reports offline, exit 13, across jquery 1.6.2 / lodash 4.17.4 / handlebars 4.0.5) |
| eslint-plugin-no-unsanitized | self-contained once installed; the shipped flat config MUST import the plugin by ABSOLUTE PATH (ESM ignores `NODE_PATH`), and every run MUST pass `--no-config-lookup` | baked (`sabot/node:1`, 4.1.5 on eslint 9.39.5, config at `/opt/eslint/sabot.config.mjs`) | **VERIFIED** (both rules report offline: `no-unsanitized/property` on `innerHTML`, `no-unsanitized/method` on `document.write`) |

Jazzer.js must NOT be installed with `npm i -g`. Measured, `npm i -g @jazzer.js/core`
nests the `@jazzer.js` peers (bug-detectors, fuzzer, hooking, instrumentor) under
`core/node_modules/`, while core resolves them as SIBLINGS, so every run died before its
first input while `jazzer --version` still answered:

```
Error: ENOENT: no such file or directory, scandir
'/usr/local/lib/node_modules/@jazzer.js/bug-detectors/dist/internal'
```

A local install into a prefix dir (`/opt/jazzer`, symlinked onto PATH) produces the flat
layout core expects. The build now runs a real fuzz target and requires an `Uncaught
Exception` in the output, because this is the second time this tool has been installed,
asserted, and unrunnable: the first was the arm64 `dlopen` failure behind a passing
`jazzer --version` (bs-156).

Jazzer.js also needs a WRITABLE `TMPDIR`. `run-contained.sh` supplies one
(`TMPDIR=/scratch/tmp`), so the shipped path is fine, but a hand-rolled `docker run`
without it is not: measured under `--read-only`, the fuzzer still exits 77 on a real crash
while printing only three INFO lines, so the crash, the stack, and the artifact all vanish.
That is a found bug reported as noise, which is worse than a false clean.

retire.js scans INSTALLED code, not declared dependencies. Measured, a `package.json`
pinning jquery 1.6.2, lodash 4.17.4, and handlebars 4.0.5 with no `node_modules` beside it
produced exit 0 and a single line of version banner. Nothing in that output distinguishes
a scan that read the three packages from a scan that read nothing at all. With those three
installed, the same command reported 15 vulnerable components and exit 13. A dependency sweep on a repo that was cloned but never
installed is a false clean, so `npm install` (or a committed `node_modules`) has to precede
retire, and a run that finds zero components has to be treated as zero SCANNED rather than
zero vulnerable.

eslint's plugin loading is the other trap on this surface. eslint 9 requires flat config,
flat config is an ES module, and ESM resolution ignores `NODE_PATH`, so a bare
`import noUnsanitized from "no-unsanitized"` fails from any directory outside the install
prefix:

```
Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'no-unsanitized' imported from
/tmp/p/eslint.config.mjs
```

The image ships `/opt/eslint/sabot.config.mjs`, which imports the plugin by absolute path,
and every run MUST add `--no-config-lookup`. Without it eslint walks up from the target and
a config found in the target repo replaces these two rules, which is a scan that exits
cleanly having checked something else.

## heavy engines (own layer; large)

| Tool | Offline req | Bake status | Fixture / test |
|---|---|---|---|
| CodeQL | needs-build-dep + query packs (~500MB); **NO linux-arm64 build exists** | BLOCKED on arm64, see below | code fixture (x86_64 only) |
| Joern | self-contained once unpacked (CPG build fetches nothing) | **baked** (`sabot/heavy:1`, arm64 zip, sha512-verified) | **VERIFIED** (56813-byte CPG offline as uid 1000; query located the `exec` sink at line 3) |
| OWASP-ZAP | baked-ok PASSIVE ONLY; MUST pass `-dir <writable>` (ignores `$HOME`, and exits 0 while refusing to start) | **baked** (`sabot/heavy:1`, Core zip, 21 bundled add-ons) | **VERIFIED** (6 alerts offline under `--read-only` against a container-local `http.server`) |

CodeQL cannot be baked on this host. Release v2.26.3 of `github/codeql-cli-binaries`
publishes `codeql-linux64.zip` (x86_64), `codeql-osx64.zip`, `codeql-win64.zip`, and the
all-x86-64 `codeql.zip`. There is no linux-arm64 asset, and upstream declined to commit to
one (`codeql-cli-binaries#157`, closed: "I can't make any promises on if or when";
`#97` still open). Emulating x86_64 for a whole-program analysis engine trades a bake for
an unusable runtime, so the arm64 surface treats CodeQL as absent rather than degraded. A
campaign that needs it must run on an x86_64 host, and a report that would have run it must
name the gap.

Joern and ZAP are JVM tools and therefore arch-portable, but base ships no JVM today, so
the heavy layer has to add one before either can be measured.

## The scanners surface: nuclei, bearer, checkov, guarddog, kingfisher

An OPTIONAL escalation image (`sabot/scanners:1`), not part of every campaign. Base is
inherited by all four language surfaces and none of them needs a Terraform policy set, so
these five live in their own layer, like `sabot/rust-extras:1`. Absent is a preflight note.

Nuclei needs BOTH `-templates` and `-ud` pointed at the baked tree. It resolves a
template's `helpers/` payload files against its DEFAULT template directory rather than the
tree given to `-templates`, so with `-templates` alone roughly 5000 templates failed to
compile:

```
[ERR] ... could not load payload file: cause="access to helper file
/opt/sabot-db/nuclei-templates/helpers/wordlists/wp-users.txt denied"
```

`-ud` repoints that default. Every one of those failures is per-template, so nuclei still
runs, still exits, and still reports whatever the surviving templates found.

One upstream template is quarantined at the current pin. `http/cves/2026/CVE-2026-3395.yaml`
fails to unmarshal (`line 52: cannot unmarshal !!str POST /a... into []string`), it is
broken at upstream HEAD as well, and `-et` does not suppress it because `-validate` loads
a template before excluding it. The layer deletes that one file, which keeps the build
gate at zero errors instead of grepping for a success string in output that also carries
errors.

GuardDog EXITS 0 on a high-risk verdict. Measured on a seeded install-time exfiltration
`setup.py`, it reported `High risk (8.0/10)`, 2 risk categories, 7 issues, and exit 0. Any
wrapper gating on the exit code records that package as clean. Parse `risk_score` and
`issues` from `--output-format json` instead.

Kingfisher found LESS than gitleaks on the same fixture: 1 finding against gitleaks' 3,
missing both the RSA private key and the `ghp_` PAT, with 1061 rules applied. It is
additive coverage, not a replacement, and a report that runs only kingfisher on a secrets
sweep understates what is there.

## Irreducible gaps (cannot work offline; document, do not pretend)

- **OSSF-Scorecard**: scores a repo via the GitHub API; no offline mode. Record as a coverage gap in any report that would run it.
- Any tool whose ONLY value is a live network probe (ZAP active scan against a remote, Kingfisher/TruffleHog live-credential validation): offline runs the static half only; the report must say which half ran.

## Seeding a secrets fixture

A secret detector's fixture MUST carry high-entropy synthetic values. Measured on the
`secrets` fixture, the textbook placeholders produce a near-empty result that reads as a
broken detector:

| Seeded value | gitleaks |
|---|---|
| `AKIAIOSFODNN7EXAMPLE` + the matching `wJalrXUt…` secret | no finding (AWS's own doc keys are allowlisted) |
| `ghp_` + 36 repeated `a` | no finding (fails the entropy check) |
| An RSA private-key header | `private-key` |
| `AKIA` + 16 random uppercase, 40 random alphanumerics, `ghp_` + 36 random | `generic-api-key`, `github-pat`, `private-key` |

Generate the values rather than copying them, and keep the fixture OUTSIDE the repo: a
credential-shaped literal in a tracked file trips the commit-time secret scanner, which is
the same class of tool the fixture exists to exercise.
