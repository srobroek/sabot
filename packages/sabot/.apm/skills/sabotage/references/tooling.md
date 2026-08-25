# Tool catalog: cross-cutting index

Per-surface tool tables are authoritative in each `surfaces/<surface>.md`, with
their Tier, Class, and Run recipe columns. This file holds what cuts across
surfaces: the universal run rules, plus the overlap map and analysis classes that
scope each tool.

The tools live in the surface image, not on the host; see `references/isolation.md`
(Provisioning) for how the image is built and dev-deps baked.

## Universal run rules

Every recipe in a surface doc assumes these, so they are not repeated there:

- **There is no network. Ever.** Every target-touching tool runs in a container started
   with `--network none`: no DNS, no egress, no proxy, no package registry, no rule
   registry. This is the skill's own rule (`isolation.md`, No network), not a property of
   one host, so it holds on every run. "Local host access" means loopback *inside* the
   container, for a server the campaign itself started there; a host, LAN, or public
   endpoint is out of scope regardless of who asks. Consequences that decide which flags
   a recipe passes:
   - Any tool that fetches at run time **cannot run**. `opengrep`/`semgrep` registry
     packs -- `p/rust` and every other `p/*` -- fail with `OG_RC=2`.
   - Self-updating vulnerability databases (osv-scanner, trivy, grype, cargo-audit's
     advisory DB) read the copy baked into the image, named by an explicit flag. See
     `isolation.md`, Baked offline databases, for the flag per tool.
   - `cargo`, `npm`/`pnpm`, and `pip` pass their offline flags. A build that reaches the
     network does not run slowly; it fails.
- **Every recipe runs in the container.** A surface doc's recipe is the tool
   invocation; `run-contained.sh` wraps it, so the tool runs against the target
   mounted read-only at `/target`, never on the host. This holds for text scanners
   (`opengrep`, `shellcheck`, `ast-grep`) as well as compiling ones (`clippy`,
   `gosec`) and fuzzers: a compiling scanner builds the crate and so runs the
   target's own build code, which must be confined. The host runs only the agent and
   `bd`/`git`/the runtime.
- **cwd is `/scratch`, the target is read at `/target`.** The container's writable
   cwd is `/scratch`; pass the resolved file set as paths under `/target` (e.g.
   `opengrep --config /opt/sabot-db/semgrep-rules/python /target/src`), and let builds write to `/scratch`
   (`CARGO_TARGET_DIR` etc. are set for you).
- **Shipped assets are absolute.** Reference `corpora/` and any recon-synthesized
   rule by absolute path, since cwd is the target and a skill-relative path silently
   matches nothing.
- **Project config wins.** When the repo configures a scanner, run it so that
   config governs. The recipe's flags are the no-project-config form.
- **Exit codes are a contract.** For most scanners, non-zero means findings
   rather than failure. Distinguish 0 (clean), N (findings, so parse the output),
   and a usage or crash error (INVALID, so fix the invocation and rerun). A
   sub-second run from a tool that must compile is also INVALID.
- **Flag exactly as written.** Go tools use single-dash `-format`, others use
   `--`. Copy the recipe verbatim rather than normalizing it.
- **Suppress default noise the project never opted into.** When a scanner's
   defaults are stricter than the repo's own rules and no project config exists,
   the recipe states its own suppression.
- **An output file is evidence only when this run wrote it.** A crashed scanner leaves
   the previous invocation's JSON in place, and a caller that parses it records a clean
   scan for a run that scanned nothing. Pass the output path as
   `run-contained.sh --expect-json <path>`: the wrapper deletes it before the command and
   afterwards requires a fresh file, parseable JSON, and a nonzero scanned-file count,
   failing with exit 7 and `executed=0` otherwise.

MUST Require a nonzero scanned-file count before recording any zero-finding result, since every scanner reports "resolved no files" and "found no problems" as the same empty output. `opengrep`'s count is `paths.scanned`.
MUST Never substitute a regex grep for a scanner. A missing tool is a reported coverage gap, and a guess dressed as a finding is worse than a gap.

## Structurally closed classes short-circuit tool selection

Check whether a repo has closed a whole finding class by construction BEFORE picking tools
for it. A closed class needs a one-line citation, not a scanner and not a role.

| Signal | Class it closes | What to do |
|---|---|---|
| `unsafe_code = "forbid"` in every crate, and zero `unsafe` blocks | Rust memory safety | cite the lint, skip the memory-safety fuzz phase, and report the class as closed by construction |
| a pure-safe dependency set with no FFI and no C build script | native memory safety | same |
| the repo's own `dep-audit` / `secrets-scan` packages in CI | dependency CVEs, secrets | see the overlap map |

Measured: a campaign spent 15 node-runs and an entire triage role on a target that forbade
`unsafe` at the workspace root, and produced 0 crash wisps. That result was decided by the
lint before the first harness was written.

MUST Record a structurally closed class as closed with its citation, distinct from both "clean" and "not covered", because a reader cannot otherwise tell a proof from an absence of evidence.

## Analysis class

Each tool carries one class, which decides how it scopes to a bounded target:

| Class | Meaning | Bounded-target behaviour |
|---|---|---|
| local | the finding lives inside one file | pass the target file list |
| relational | the finding is a link between the target and other code | scan target plus context, report links touching the target |
| global | a project-wide invariant, such as dependency CVEs or dead code | skip and record "SKIPPED (scoped)" |
| baseline | the analysis is a comparison against a ref | native to a ref target, so run it against the base and headline the delta |

Class matters only for bounded targets. A whole-repo run executes everything.

## Overlap map

A tool that already covers a dimension makes the point tool redundant, so drop the
point tool rather than reporting the same finding twice:

| Dimension | Owner | Point tool becomes |
|---|---|---|
| Python security lints | ruff `S` ruleset | bandit still adds checks ruff lacks, so keep both |
| Go security | golangci-lint with gosec enabled | standalone gosec is redundant |
| Rust panics and overflow | clippy | nothing else needed |
| IaC misconfig | trivy | checkov still adds policy classes, so keep both |
| Dependency CVEs | the repo's `dep-audit` package | osv-scanner and grype are redundant when it ran |
| Secrets | the repo's `secrets-scan` package | gitleaks and trufflehog are redundant when it ran |
| Shell inside CI | actionlint, which embeds shellcheck | a separate shellcheck pass over `run:` blocks is redundant |
| Shell inside Dockerfile | hadolint, which embeds shellcheck | same |
| CI security | zizmor | nothing else does workflow dataflow |
| Interprocedural taint | CodeQL | semgrep is intra-file only, so they do not overlap |

MUST Prefer the repo's own `dep-audit` and `secrets-scan` packages when present, running these scanners only for what those leave uncovered.

## Coverage honesty rules

A skipped tool and a covered dimension are different report lines:

| Situation | Report as |
|---|---|
| A meta-tool that ran already covers the dimension | covered, not a gap |
| Global-class tool on a bounded target | SKIPPED (scoped), which takes precedence over "not installed" |
| Tool absent and the dimension uncovered | SKIPPED (not installed), with the install hint |
| The stack has no tool for this dimension at all | N/A |
| Tool ran and crashed | INVALID, and never clean |

MUST State the skip reason precisely, since "not installed" and "out of scope" demand different remediation from the reader.

## Detection sources

Detection comes from three places, in ascending order of how much this repo it
knows. No generic rules are shipped in the package: a hand-maintained generic rule
duplicates a registry pack and rots silently (a mixed-language rule that passes
`--validate` can still fail at scan time and run against zero files).

| Source | What | Coverage |
|---|---|---|
| Baked rule packs | the semgrep rule trees under `/opt/sabot-db/semgrep-rules/<lang>`, plus bandit, gosec, clippy, shellcheck | generic dangerous patterns, at the revision baked into the image |
| Recon-synthesized | rules `sabot-scout` writes and validates during recon, from this repo's own invariants and the agentic-pattern list in `surfaces/agents.md` | this repo's contracts, and agentic patterns no registry pack covers |
| Shipped corpora | `corpora/prompt-injection.md`, `scripts/fuzz-cli.py` | payload classes and the decision-contract harness |

MUST Point `--config` at the baked tree for the detected language (`/opt/sabot-db/semgrep-rules/<lang>`). A registry shorthand (`p/rust`, `p/python`, `--config auto`) resolves over the network, so under `--network none` it exits `OG_RC=2` having scanned nothing. Record that as NOT EXECUTED, "requires network", and never as zero findings or a retry.
MUST Pass `--metrics off`. Four nodes measured `opengrep` exiting 2 on the metrics call alone, before any rule ran.
MUST Confirm the rule tree resolved to a nonzero file count, since a `--config` path that names no loadable rule scans every file against nothing and reports clean.
MUST Run a recon-synthesized rule against a known-positive from this repo before trusting a zero-match result, since a rule that matches nothing reads exactly like a clean repo.
MUST Run every scanner under a UTF-8 locale, which `run-contained.sh` sets (`LANG=LC_ALL=C.UTF-8`, `PYTHONUTF8=1`). Measured: a synthesized rule file containing one curly quote made `opengrep` raise `'ascii' codec can't decode byte 0xe2` from `config_resolver.py:241` and exit 2 with 0 files scanned; the same invocation under a UTF-8 locale returned 41 findings across 14 files. A hand-rolled `docker run` that skips the wrapper reintroduces this.
## Out of scope: LLM red-teaming

`garak` and `promptfoo` are excluded by design. Both measure whether a *model* can be
made to misbehave, and garak's own README says it does "somewhat similar things to
nmap or Metasploit, but for LLMs". The target here is this codebase, so a model's
alignment score answers a question nobody asked and costs inference to get.

The agents surface stays covered statically: the reading pass against
`corpora/prompt-injection.md`, the tool-grant analysis, `snyk-agent-scan` for MCP
configs, and the shipped `prompt-build.yml` rules for prompts assembled in code.

## Where tools come from

A surface recipe is the bare invocation of a tool that is already in the image
(`opengrep --config ...`, `cargo clippy`, `gosec`). `run-contained.sh` runs it against
the target at `/target`; nothing is fetched at run time, since the campaign runs under
`--network none`. Provisioning happens once, at image build, from
`references/containers/Dockerfile.<surface>` plus the dev-dep bake
(`isolation.md`, Provisioning).

The install forms below are how a Dockerfile PUTS a tool in the image, not how the
campaign calls it. They are here so a new surface image, or an extend layer, installs
the right way:

| Install form (in the Dockerfile) | Used for |
|---|---|
| `apt-get install` | the base OS scanners: ripgrep, shellcheck, jq |
| `pipx install` / `pip install` | Python-packaged scanners and generators: opengrep, zizmor, schemathesis, bandit |
| `npm i -g` / project `npm ci` | JS tools: ast-grep, jazzer.js, fast-check, eslint (project-local via the baked deps) |
| `go install <path>@<version>` | Go tools: gosec |
| `cargo install --locked <tool>` | cargo subcommands: cargo-fuzz, cargo-audit (clippy ships with the toolchain) |
| the base language image | the compiler/toolchain itself: `FROM rust:1-slim`, `FROM python:3-slim`, `FROM node:20-slim` |

MUST Pin every tool the Dockerfile installs to an explicit version (`cargo install --locked <tool> --version x`, `go install ...@vX`, `pip install tool==x`), so the image is reproducible and a scan result does not shift when an upstream releases.
MUST Make the pins of OUR security tooling bot-upgradable, so a scanner or fuzzer we bake does not silently rot. This is the tooling in the committed `Dockerfile.<surface>` (opengrep, cargo-fuzz, gosec, ...), not the target's own dev-deps, which are the target repo's concern. `FROM` tags are read by Dependabot and Renovate natively; a version pinned inside a `RUN` line is NOT (Dependabot ignores it, Renovate needs a `# renovate:` comment), so annotate each `RUN`-line pin with a `# renovate: datasource=... depName=...` line and ship `containers/renovate.json` with the custom manager. On-demand extend layers are transient and inherit their freshness from the committed base, so they pin inline without a bot.
MUST Report a tool absent from the image as a coverage gap (via `--assert-tools`), never substitute a different tool silently.
NOT Never fetch a tool at run time. The campaign is `--network none`; a tool not in the image is a gap the report states, not something the gremlin installs.
