# Targeting

Resolve the user's target into an explicit file list, a base ref, then a checkout
decision. Every later step consumes this resolution rather than re-deriving it.

## Target kinds

| Kind | Argument | Resolves to |
|---|---|---|
| whole repo | none | every tracked file, minus excludes |
| language or area filter | a language or area name | files matching the detected-surface glob, repo-wide |
| directory or module | a path | every tracked file beneath it |
| file(s) | paths | exactly those files |
| one script or hook | a path | that file, plus the harness that drives it |
| one agent or skill | a path | that definition, plus the settings and MCP config governing it |
| uncommitted changes | none | `git diff --name-only HEAD` plus untracked files |
| commit | a SHA | `git diff-tree --no-commit-id --name-only -r <sha>` |
| commit range or branch compare | `a..b` or a branch | `git diff --name-only <base>...<head>` |
| PR | a number | the PR's changed files, with the PR base as the base ref |

MUST Resolve a language or area filter by detected-surface glob rather than by directory path, since the Rust in a repo is rarely confined to one directory.
MUST Offer the ref kinds (commit, range, branch, PR) even on a clean tree, because a user auditing a merged change has nothing uncommitted.
DEFAULT Kinds compose. "The shell in this PR" is the PR file list filtered to the shell surface.

## Excludes

Resolve a whole-repo target from the repo's tracked files (`git ls-files`), so
`.gitignore` is honored and build output, caches, and untracked local scratch never
enter scope. On top of that, drop these from every resolved list unless the user
names one explicitly:

| Exclude | Why |
|---|---|
| anything `.gitignore` ignores | not part of the repo; build output and local scratch, owned by the toolchain |
| anything that reads as agentic-tooling config, the class not just the list: `.claude/`, `.codex/`, `.omp/`, `.agents/`, `.cursor/`, `.aider*`, `.continue/`, `.windsurf/`, `.github/copilot*`, a repo-root `AGENTS.md`/`CLAUDE.md`/`.mcp.json`, `.apm/instructions/**`, `.apm/context/**`, and any sibling that configures a coding assistant rather than shipping in the product | the user's own agent setup, not the product under audit; ignored silently and never offered, a target only when the user names the path |
| generated output | regenerated on build, so a finding there belongs to the generator |
| vendored dependencies | owned upstream, and covered by the dependency scanners instead |
| lockfiles, for surfaces other than infra | scanned as a manifest rather than read as code |
| test fixtures holding deliberately malformed data | that is what they are for |
| `.git`, build caches, `node_modules`, `target`, `.venv` | not source |

MUST Resolve a whole-repo target from `git ls-files` and honor `.gitignore`, since a whole-repo scan of the working tree otherwise pulls in build output, caches, and untracked local files that are not the repo.
MUST Ignore anything that reads as agentic-tooling config silently by default, even when the user asks for "everything", and never present it as an option or an opt-in. The list (`.claude/`, `.codex/`, `.omp/`, `.agents/`, `.cursor/`, `.aider*`, `.continue/`, `.windsurf/`, `.github/copilot*`, a repo-root `AGENTS.md`/`CLAUDE.md`/`.mcp.json`) is a set of examples, not the boundary: judge by whether the file configures a coding assistant rather than shipping in the product, and exclude any sibling that fits even when it is not named here. A repo audit targets the product, not the user's agent configuration, and the sabot skill itself is often installed there. Such a path becomes a target only when the user names it outright (the agents surface, pointed at it).
MUST Report a volume-based exclude that removed a large share of the target (a vendored tree, a generated dir), since a user asking for a whole-repo audit needs to know what was skipped. This does NOT apply to the agentic-tooling config, which is ignored silently and never named in the interview or the confirmation.
NOT Never exclude the repo's own tests wholesale. A test that shells out unsafely or holds a live credential is a real finding.

## Checkout decision

| Target | Checkout |
|---|---|
| whole repo, directory, files, uncommitted | in place, with harnesses written to the working tree and left uncommitted |
| commit, range, branch, PR | a worktree at the head ref, so the campaign never disturbs the user's tree |
| any target where a harness writes files | a worktree, because a fuzz campaign that writes into the working tree pollutes it |

MUST Use a worktree for every ref target, since checking out a ref in place moves the user's HEAD underneath them.
MUST Record the checkout path on the run epic, so every agent works in the same tree.

## Scoping by analysis class

A bounded target changes what a scanner can conclude:

| Class | Behaviour on a bounded target |
|---|---|
| local | pass the target file list directly |
| relational | scan the target plus repo context, and report only links touching the target |
| global | skip it and say so, since file-scoping a whole-program analysis produces false positives |
| baseline | native to a ref target: run against the base and headline what the change introduced |

MUST Skip global-class scanners on a bounded target and record the skip as "SKIPPED (scoped)". The label marks the tool as out of scope; a missing-tool label points the reader at an install instead.
MUST On a ref target, headline what the diff introduced. A regression review asks whether this change made anything worse, a different question from what is wrong with the repo overall.

## Entry-point enumeration

The resolution is incomplete until every entry point is listed, since this is the
fuzzer's work list:

| Look for | Where |
|---|---|
| parse and deserialize functions | anything taking bytes, a string, or a reader and returning a structure |
| CLI commands and argument parsers | `main`, a clap or argparse definition, a subcommand table |
| hook scripts | `.claude/hooks/**`, `.codex/hooks/**`, `.git/hooks/**`, settings hook blocks |
| request handlers | route tables, framework decorators, message consumers |
| config readers | anything reading a file, env var, or flag at startup |
| agent and skill definitions | `SKILL.md`, `*.agent.md`, `.mcp.json` |
| FFI and subprocess boundaries | `unsafe`, `extern`, `subprocess`, `exec` |

MUST Record each entry point with a `file:line`. An entry point named without a locus cannot be handed to a fuzzer.
MUST Report an entry point with no harness as a coverage gap, since an unfuzzed entry point is untested rather than clean.

## Manifest map (for image provisioning)

Alongside the entry points, enumerate every dependency manifest in the resolved
scope, since the image is provisioned from them (see `isolation.md`, Provisioning).
Run `scripts/detect-stacks.py` for this rather than globbing by hand: it reads
`git ls-files` (honoring `.gitignore`), finds every manifest, collapses Cargo
workspace members, and emits the stack map and bake commands. It covers the cases a
repo-root lookup misses, a workspace, a monorepo, or a multi-language target:

| Look for | Stack | Feeds |
|---|---|---|
| every `Cargo.toml` + `Cargo.lock` (workspace root and members) | Rust | `cargo fetch` at the workspace root |
| every `package.json` + lockfile | Node/JS | `npm ci` per package |
| `pyproject.toml` dev group / `requirements-dev.txt` | Python | `uv sync` / `pip install` |
| `go.mod` per module | Go | `go mod download` |

MUST Record every manifest in scope, not only a repo-root one. A Tauri app (Rust under `src-tauri/` plus a JS frontend) or a monorepo has several, and a missed manifest leaves a member crate or the frontend unprovisioned, so its harness cannot run under `--network none`.
MUST Note a multi-language target explicitly, since it needs an image carrying every detected toolchain rather than one surface image.

## Confirm before proceeding

Restate the resolution to the user in one block: the kind, the file count, the
surfaces detected, the base ref, the checkout decision, and the excludes applied.
A resolution the user did not intend wastes the whole campaign.

Report the volume-based excludes (a vendored tree or a generated dir that removed a
large share of the file count), since the user needs to know what a whole-repo audit
skipped. Do NOT restate the agentic-tooling config exclusion (`.claude/`, `.codex/`,
`.agents/`, `.cursor/`): it is ignored silently and never appears in the interview or
the confirmation, since naming it invites a toggle on a directory that holds the
auditor's own skill. It becomes a target only when the user names those paths first.
