# Surface Index

Route the detected target onto surface docs. A "surface" is a class of attack,
not a language: the same Python file belongs to `code.md` for its taint paths and
to `robustness.md` for its input handling. Load only the docs a target actually
touches, and hand each to one `gremlin`.

Each surface doc below is self-contained.

| Surface | Doc | Detect by | Owns |
|---------|-----|-----------|------|
| Code memory and logic | `code.md` | any `*.rs` `*.go` `*.py` `*.ts` `*.js` `*.c` `*.cpp` `*.java` | injection, taint to sink, unsafe blocks, integer overflow, path traversal, deserialization, TOCTOU, authz logic, ReDoS, unbounded allocation |
| Shell and hooks | `shell.md` | `*.sh` `*.bash`, shebang, `.claude/hooks/**`, `.git/hooks/**`, PreToolUse guards | command-position bypass, quoting and word splitting, `$VAR` injection, fail-open inversion, guard evasion, TOCTOU on lock files |
| Agents and prompts | `agents.md` | agentic app code by signature (an LLM SDK or agent-framework import such as `openai`, `anthropic`, `langchain`, `langgraph`, or an AgentCore call; a prompt assembled from a variable; a tool-calling definition), or `SKILL.md`, `*.agent.md`, `.mcp.json`, `settings.json` with hooks or permissions when they are the product | prompt injection, tool over-grant, exfil paths, instruction override, untrusted content reaching context |
| Infra, config, supply chain | `infra.md` | `*.tf` `Dockerfile` `*.yaml` with `kind:`, `.github/workflows/**`, lockfiles | IaC misconfig, container and k8s hardening, CI workflow injection, secrets, dependency CVEs, typosquats, unpinned actions |
| Web and frontend | `web.md` | `*.html` `*.jsx` `*.tsx` `*.vue` `*.svelte`, a frontend framework in `package.json`, a CSP string, a Tauri/Electron webview | DOM-sink XSS, CSP gaps, client-side secrets, CSRF, clickjacking, and live findings against the project's own dev server |
| Build and toolchain | `build.md` | `build.rs`, proc-macro or `[build-dependencies]`, `preinstall`/`postinstall` scripts, `Makefile`/`justfile` recipes, branch-pinned pre-commit | build- and install-time code execution, the xz-tarball vector, malicious build-dependencies, committed git hooks |
| Robustness | `robustness.md` | every target, always | malformed input crashes, boundary values, encoding, resource limits, concurrency, state-machine edges, error-path correctness |

Each doc's attack checklist is a floor for a repo just met, and recon's trust map
and idiom census aim the pass. A checklist worked start to finish without recon
finds the generic bugs and misses this repo's own.

## Routing rules

MUST Include `robustness.md` in every run. It applies to every surface in the table above and covers the stability findings the security surfaces skip.
MUST Route a hook or guard script to both `shell.md` and `robustness.md`. A guard that crashes on malformed stdin is a bypass, so the two surfaces overlap here by design.
MUST Route an agent, skill, or MCP config to `agents.md` even when it contains no code. The absence of a deterministic scanner makes reading the only detection available.
MUST Route a frontend to `web.md` in addition to `code.md`: `code.md` owns server-side taint, `web.md` owns the DOM sinks and the running app, and neither covers the other.
MUST Route `build.rs`, install scripts, and proc macros to `build.md`, since that code runs before any test and no other surface owns build-time execution.
DEFAULT Split a surface across several `gremlin` agents when its file list exceeds roughly 5k LOC, dividing by subtree, crate, or package.
NOT Assigning one language to one surface is wrong: surfaces cross-cut languages, and a language may map to three of them at once.

## Overlap map

Where two surfaces could both claim a finding, the owner is:

| Finding | Owner | Why |
|---------|-------|-----|
| Unquoted `$VAR` in a shell hook | `shell.md` | command-position semantics decide exploitability |
| Unquoted variable in a Dockerfile `RUN` | `infra.md` | hadolint embeds shellcheck, so the infra scanner already covers it |
| A CLI that panics on 4 GB of stdin | `robustness.md` | no attacker path in a local dev tool, though the crash is still real |
| A server that panics on 4 GB of a request body | `code.md` | remote input reaches the allocation, making it a DoS path |
| `WebFetch` output flowing into a tool call | `agents.md` | untrusted content reaching context is the agent-surface core |
| `innerHTML` from a fetched value | `web.md` | a DOM sink, which `code.md`'s server-side taint never traces |
| A server rendering a request value into HTML | `web.md` | the running app confirms it; `code.md` sees only the string build |
| `build.rs` shelling out on a fetched value | `build.md` | it runs at compile time, which `shell.md`'s tool-call model does not cover |
| An unpinned GitHub Action | `infra.md` | supply chain, caught by `zizmor --offline` |

## Authoring

`_template.md` is the authoring template. Every doc carries the same sections:
Detect · Tools · Attack checklist · Harness patterns · Impact calibration ·
False-positive traps.
