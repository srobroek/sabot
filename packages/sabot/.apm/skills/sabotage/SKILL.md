---
name: sabotage
description: Attack code, scripts, hooks, or agents for vulns and robustness bugs, then fuzz and prove them. Use when asked to harden, red-team, or fuzz.
---

# Sabot

Attack a target across five surfaces, prove each finding with a traced path or a
reproducing input, and report on two axes: evidence and impact. Product code stays
untouched until step 15, which requires explicit approval; harnesses and regression
tests are written freely.

Beads hold the run state. Agents hand work to each other through wisps, so a
campaign survives a crash and resumes from the durable graph. LOAD
`references/beads-store.md` before creating anything.

This SKILL is a router. Load the referenced file for each step rather than
inlining its content.

## STOP: interview the user before you touch the target

Ask the four questions below and WAIT for the answers before detecting the stack,
running a scanner, or spawning a `gremlin`. This is the default on every invocation:
interviewing is the assumption, and naming a target does not waive it. A user who
types "run sabotage on this repo" has told you the repo, not the surfaces, tools,
budget, or what they fear, and those are the answers that shape the run. LOAD
`references/interview.md` for how to probe for what the user left unsaid and what an
answer should make you distrust.

Skip the interview ONLY on a positive non-interactive signal: the invocation itself
says non-interactive/CI/cron, or you are a spawned sub-agent with no channel back to
a human. Being handed a target is NOT such a signal. When in doubt, ask. A
non-interactive run then takes the defaults below and records each as a gap.

1. **Which target, and what do you fear most?** Ask in two steps when the user named
   none. Offer every time: `whole repo` · `language/area filter` · `directory/module` ·
   `file(s)` · `one script/hook` · `one agent or skill` · `uncommitted changes` ·
   `commit` · `commit range / branch compare` · `PR`. Kinds compose. Assuming whole
   repo is a scope error. Capture the user's stated fear too; it is stamped on the
   epic as `threat` and orders the report, without being handed to a sabot-scout as a
   hypothesis.
   - **Ignore agentic-tooling config SILENTLY**, per `references/targeting.md`.
     Exclude the whole class, not a fixed list: any file that configures a coding
     assistant rather than shipping in the product (`.claude/`, `.codex/`, `.agents/`,
     `.cursor/`, `.aider*`, `.continue/`, `.windsurf/`, `.github/copilot*`, a
     repo-root `AGENTS.md`/`CLAUDE.md`/`.mcp.json`, and any unlisted sibling that
     fits). None of it is part of any target unless the user names the path outright.
     Do not mention it anywhere in the interview: not in the "whole repo" description,
     not as an excluded item, not as an opt-in, not as an "N/A" line. Describe "whole
     repo" as the product code and stop there. Naming the exclusion invites a toggle
     on config that usually holds the sabot skill itself, so a menu that
     surfaces it offers to audit its own auditor. Such a path becomes a target only
     when the user asks for it by name (the agents surface pointed at it).
   - This silent ignore is about the user's TOOLING config, not about agentic code. A
     production agent in `src/` (a `langgraph`/`langchain`/AgentCore app, a
     prompt-assembly path) IS in scope on a whole-repo run; the sabot-scout detects it by
     signature (see `references/surfaces/agents.md`). Ignore the config dirs; keep
     the app's agentic code.
2. **Which surfaces?** Detect them from the target via `references/surfaces/index.md`,
   then present the detected set for the user to trim or extend, pre-selected ON.
   `robustness` is mandatory and cannot be removed. A surface file-detection missed
   (a frontend with no framework marker, live web DAST the user wants) can be added
   here; a detected surface the user does not want scanned can be dropped. This is
   one message with question 3, not a separate prompt.
3. **Which tools, and what fuzz budget?** Run
   `<skill-dir>/scripts/install-tools.sh --probe` (a host preflight: confirms the
   container runtime, `bd`, and `git`, and which surface images exist; it does not
   install scanners on the host, which now run in the image). In one message, propose
   the full thorough tool set per detected surface as a tiered table (default-on
   pre-selected ON, opt-in shown OFF with a reason) together with a fuzz budget
   table covering wall-clock per harness, parallel jobs, and memory cap. Then wait
   for the reply; "go" installs every missing default-on tool, accepts the budget,
   and runs the default-on set. Do NOT list an action the hard rules forbid (a
   network-host or third-party probe) here, even as unavailable.
4. **What should happen to a confirmed finding?** Offer `harden` (patch it, then
   re-run the finding's own repro to prove it gone), `ticket` (file it in the user's
   tracker with the evidence, repro, and proposed fix), `both`, or `report only`.
   Nothing is the default. When the answer includes `ticket`, ask **which** tracker
   and **how** to reach it, then confirm the resolved destination before anything is
   written. **Never infer the tracker from the git remote**: a GitHub remote does not
   mean GitHub Issues, since issues are often disabled and many teams track in Jira,
   Linear, GitLab, or an internal system while mirroring code to GitHub. Ask whether
   the destination is public, because a ticket describing an unpatched reachable
   finding is a disclosure. See `references/remediation.md`.

The blast-radius opt-ins (live-spawn agentic fuzzing, dev-server DAST) are NOT part
of these four questions. They run real payloads through real grants, so each is a
SEPARATE opt-in asked after the core, and only when its triggering surface is in
scope: live-spawn when agent/skill/MCP definitions are present, DAST when a runnable
web server is. When the trigger is absent, do not offer it at all. See
`references/interview.md`.

A **non-interactive** run (an invocation that says CI/cron/non-interactive, or a
sub-agent with no channel to a human) takes the defaults rather than asking: the
target it was given or the whole repo, the full detected surface set, the budget
defaults from `references/fuzzing.md`, and the installed tools, then records every
default as a gap. Being handed a target does not by itself make a run non-interactive.

**Skill dir vs. target dir.** Tools run with cwd set to the *target* repo, while
this skill's shipped assets (`scripts/`, `references/corpora/`) live in the *skill*
dir. Note the directory holding this `SKILL.md` once as `$SABOT_SKILL_DIR` and
reference every shipped asset by an absolute path beneath it. A skill-relative
path silently matches nothing, and a run that matched nothing looks clean.

**When these agent types are unavailable, DIAGNOSE THE INSTALL FIRST.** The package
ships `sabot-scout`, `fuzzer`, `gremlin`, `triager`, `challenger`, and `hardener` under
`.apm/agents/`, materialised to `agents/*.md` for Claude and deployed by
`apm install` or `claude plugin install`. Absent types are almost always a broken or
missing install rather than a runtime that cannot load them, so before falling back:

1. Confirm the plugin is installed AND enabled (`claude plugin list`). An install
   that succeeded can still refuse to enable on an unresolvable dependency.
2. Run `claude plugin validate --strict <package-dir>`. A manifest error fails the
   whole plugin, so the skill may be reachable while the agents are not.
3. Check the agent frontmatter. Claude Code drops a plugin-shipped agent that
   declares `permissionMode`, `hooks`, or `mcpServers`.
4. Install or repair, then note that the registry is snapshotted at session start:
   a freshly installed type needs a new session before it can be spawned.

Fall back to a generic agent (`general-purpose`, or the runtime's default) with the
SAME Brief ONLY once those four have been checked and the types are still absent,
since every Brief in `references/*-brief.md` is self-contained and names its own
return format. The agent definition sharpens the role; the Brief specifies the work.
Then record BOTH "ran with generic agents" AND the install-diagnosis result as gaps,
naming which of the four checks failed. Reporting the fallback without the diagnosis
is what lets a packaging defect read as a runtime limitation for an entire release.

## Division of labour

The split that keeps findings honest: authors write, the executor executes, and
neither judges its own output.

| Agent | Writes | Executes | Judges |
|-------|--------|----------|--------|
| `sabot-scout` | recon artifacts, repo-specific rules | read-only queries | nothing |
| `fuzzer` | harnesses, corpora, attack scenarios | nothing | nothing |
| `gremlin` | nothing | scanners and harnesses, per surface | nothing |
| `triager` | crash records | minimizer only | crash class |
| `challenger` | nothing | read-only diagnostics | evidence tier |
| `hardener` | product patches | verification re-run | nothing |

## Workflow

Run in order. `references/workflow.md` holds the full procedure; LOAD it first.
Every step below is one numbered entry, including the two opt-in steps, because a
step rendered as a sub-bullet was silently skipped on one live run.

0. **Mode and preconditions.** Decide interactive or non-interactive, check the two
   hard preconditions (a container runtime, `bd`) and ABORT on either, then pin the
   scope mode: `quick`, `full`, `audit-only`, or `harness-only`.
1. **Open the run.** Create the run epic and one surface node per detected surface
   per `references/beads-store.md`. Every later handoff attaches to this graph.
2. **Resolve the target and detect surfaces.** LOAD `references/targeting.md`:
   resolve to an explicit file list plus base ref, choose in-place or worktree
   checkout, confirm scope. Map the target onto surfaces through
   `references/surfaces/index.md`. A repo hits several surfaces at once, and a
   single hook usually hits both shell and robustness. Size each node before
   creating it: split against the entry-point count until each node is one trust
   boundary an agent can enumerate, cover, and read inside the cap, stamp
   `coverage_ratio` on each, and decide the node count together with the
   concurrent-container ceiling.
3. **Probe, propose tools and budget, then wait** (blocking, interactive runs).
   See `references/tooling.md` with `references/installer.md`.
4. **Repo-global pre-pass.** Delegate to one spawned agent: run every whole-tree
   scanner (deps, secrets), the union of cross-surface scanner invocations, the
   baseline test suite, the repo self-read, and the project's own security config
   ONCE, write the output to the artifacts dir, and return only the stamp values.
   Stamp them on the epic; surfaces cite them rather than recomputing per surface.
   Baselines, suppressions, `# nosec` / `#[allow]` / `.semgrepignore`, and
   accepted-risk docs all govern: a rule the project disabled with a stated reason
   caps at HARDENING. Image provisioning and this pre-pass both run in spawned
   agents so their tool output never enters the orchestrator's context.
5. **Recon.** Spawn one `sabot-scout` per surface, in parallel, to derive this repo's own
   threat model: what it claims about itself, where its trust boundaries sit, how it
   does things and which places deviate, plus validated semgrep or ast-grep rules
   for THIS codebase. Standard rulesets are used as they come, and what recon builds
   is the harness around them. LOAD `references/recon.md`; Brief from
   `references/scout-brief.md`.
6. **Census the structurally closed finding classes.** A language or build setting
   can make a whole vulnerability class unreachable here. Census each closed class
   with its counts, re-aim the campaign onto the classes that remain, and keep the
   closed class in the report. See `references/workflow.md`.
7. **Author the attack plan.** Spawn `fuzzer` per surface to write harnesses,
   seed corpora, and attack scenarios for every reachable entry point, mirroring
   the repo's own convention for where fuzz targets live. Scripts, hooks, and CLIs
   get the shipped `scripts/fuzz-cli.py`; agents and skills get
   `references/corpora/prompt-injection.md`. Each finished harness becomes a
   harness wisp. Each harness asserts an invariant recon discovered. Brief from
   `references/fuzzer-brief.md`, patterns in `references/harnesses.md`.
8. **Attack.** Spawn one `gremlin` per surface node, in parallel. Each runs its
   surface's scanners plus the rules recon synthesized, claims the harness wisps
   for its surface, executes them
   inside the approved budget against local code, and reads for what scanners miss:
   trust boundaries, authz logic, guard bypasses, prompt-injection paths, unbounded
   work. Brief from `references/gremlin-brief.md`. Anything absent gets skipped,
   warned about, and recorded with an install hint; a scanner crash is an INVALID
   run, since reporting it as "0 findings" hides the gap. Open
   `<artifacts>/operational-notes.md` here as the lateral channel between parallel
   gremlins.
9. **Live-spawn agentic fuzzing, only when the user opted in.** LOAD
   `references/agentic-fuzz.md`. Generated cases run against the specific skills or
   agents the user named, inside a Worktrunk lease with canaries seeded outside it.
   Refused on a whole-repo target. Record the disposition as GRANTED, DECLINED, or
   NOT-OFFERED.
10. **Triage crashes.** Every crash `gremlin` files becomes a crash wisp. `triager`
    claims each batch, dedups by stack, minimizes to a smallest reproducing input,
    and separates memory-safety from robustness. Brief from
    `references/triager-brief.md`.
11. **Prove or refute.** `challenger` claims the finding wisps and sets each
    evidence tier, Briefed from `references/challenger-brief.md`. A refuted finding
    is recorded as REFUTED alongside the refutation. Findings sharing a `root_cause`
    are grouped, tiered once, and reported with an instance count.
12. **Synthesize the systemic patterns.** Query the tiered finding set for a
    `root_cause` spanning two or more nodes, and file each as a pattern wisp on the
    epic with its instance ids. The main thread performs this step. A shape repeating
    across nodes is the campaign's strongest statement, and no per-finding row
    states it.
13. **Network stage, only when the user opted in.** LOAD
    `references/network-stage.md`. Only a remote service can say whether a leaked
    credential is live, whether the baked OSV/trivy and `cargo-audit` databases are
    stale, and what the registry-only rule packs report. This
    stage runs in a container WITH egress, performs lookups rather than attacks, and
    is DECLINED-by-default with the gaps recorded. A tool that only needs to DOWNLOAD
    something (a Playwright browser, a CodeQL pack) belongs in the image instead: it
    drives loopback offline once installed. Record the disposition as GRANTED,
    DECLINED, or NOT-OFFERED.
14. **Report.** Emit via `references/report-template.md`, citing bead IDs so
    remediation is trackable after the session ends.
15. **Remediate on the route pinned in question 4, only on explicit approval.** LOAD
    `references/remediation.md`. Read the route off the epic rather than choosing one
    now.
    - **`harden`**: spawn `hardener` per approved finding, Briefed from
      `references/hardener-brief.md`. Re-run that finding's own recorded `repro_cmd`
      before and after, quote both exit codes, then re-run the attack and triage
      steps (8 and 10). An unchanged exit code is NOT FIXED and the finding stays
      open.
    - **`ticket`**: verify tracker access and destination, render every ticket body
      to the artifacts dir for approval, then file **one ticket per `root_cause`**
      with its instance list, evidence, repro, and proposed fix. Stamp each created
      id back onto the finding bead so a resumed run cannot double-file.
    - **`both`**: ticket first, then harden the approved subset, noting the ticket id.
    - **`report only`**: stop at step 14.

## Hard rules

MUST Fuzz and attack only local code in this repo or worktree. A network host, public endpoint, or third-party service is out of scope regardless of who asks. The step-13 network stage does not widen this: it looks a local artifact up against a published service, which is using that service as intended, and it still may not probe, fuzz, or attack anything remote.
MUST Attack this codebase rather than a model. An LLM red-team tool measures a model's alignment, which is a different target, so it stays out of scope even on the agents surface.
MUST Cap every campaign with the wall-clock, job, and memory limits set in step 3, and stop when they are reached. The main thread measures elapsed wall-clock against the approved `total_s` at every wave boundary, since a per-harness cap leaves the campaign total unmeasured.
MUST Treat every self-check in this skill's own tooling as a claim to verify. A wrapper's exit code, a "ran successfully" line, and an absent result file are all compatible with nothing having run, and the same fail-open shape appears in a campaign's tooling and in its target.
MUST Record a finding as structured wisp metadata per the schema in `references/beads-store.md` before writing any prose about it. The report is a rendering of that schema, and an agent's reply is discarded when the session ends.
MUST Run every target-touching tool (scanners, fuzzing, DAST, build-script execution) in a container per `references/isolation.md`, never on the host. When no container runtime is present, ABORT the whole run loudly at step 0 with a non-zero exit; do not fall back to the host and do not run a static-only subset.
MUST Abort the run loudly when `bd` is absent (`references/beads-store.md`). The container runtime and `bd` are hard preconditions, not degradable ones.
MUST Never author an input whose effect is irreversible even inside the container. Fuzz the code path that receives `rm -rf` while leaving the command itself unexecuted. See `references/isolation.md`.
MUST Keep every finding. A challenger-refuted finding is reported as REFUTED with its reason, and a finding with no traced path is reported as HARDENING.
MUST Carry both axes plus a `file:line` on every finding: the evidence tier (PROVEN|REACHABLE|HARDENING|REFUTED) and the impact (CRITICAL|HIGH|MEDIUM|LOW).
MUST Keep the write and execute roles apart. `fuzzer` never runs a harness it wrote, and `gremlin` never edits one it runs, because an agent that grades its own output hides its own bugs.
MUST Leave product code untouched in steps 1 to 14. The authoring step (7), the attack step (8), the live-spawn step (9), and the triage step (10) may only write harness files, corpora, and tests; `hardener` patches in step 15 on explicit approval, behind a verification re-run.
MUST Leave every written artifact uncommitted and list it in the report, since committing is the user's call.
MUST Ask which tracker and which access method, and confirm the destination by listing it, before creating any ticket. Never infer the tracker from the git remote. A GitHub remote is not evidence that GitHub Issues is the destination, and a finding filed on a public mirror is a disclosure the user never authorized.
MUST Treat a patch approval and a ticket approval as separate authorizations. Approving a code change does not authorize an external write, and approving a ticket does not authorize touching product code.
MUST Prove a hardened finding gone by re-running that finding's own recorded `repro_cmd` and quoting the exit code before and after. A green test suite is not the evidence, since the suite was green while the bug was live.
MUST Treat robustness findings as first-class: a crash on malformed input with no attacker path is a real finding, tiered by impact.
MUST Detect with real tools from `references/tooling.md` and `references/fuzz-tools.md`. A regex grep is no substitute for a scanner, a hand-written corpus is no substitute for a generator, and a missing tool becomes a reported coverage gap.
MUST Aim the standard rulesets with recon rather than running them unaimed. Stock packs are the borrowed detectors, and the harness around them is derived per repo, so a campaign whose findings all came from stock packs skipped recon, and the report says so.
MUST Graduate every rule behind a confirmed finding into the repo's own lint config, since the regression test guards that one instance and only the rule guards the next.
MUST Route every handoff through a bead or wisp per `references/beads-store.md`. A finding that exists only in an agent's reply dies with the session.
MUST Label every campaign bead `sab-audit`, and every non-defect record `non-work` as well, so the project whose store this is can exclude an audit's records from its own backlog and release gates. A campaign that leaves its bookkeeping indistinguishable from the project's work blocks the project's own gates on it.
MUST Set every finding's priority from the tier-impact table in `references/beads-store.md`, and close a REFUTED finding with reason `refuted` while keeping its wisp and refutation. A uniform priority orders nothing, and a disproved finding left open reads as outstanding work forever.
DEFAULT Resolve language and area filters by detected-surface glob rather than directory path.
DEFAULT Write a regression test for every PROVEN finding, beside the repo's existing tests.
NOT A proof-of-concept that damages state is banned: destructive filesystem writes; fork bombs; exhausting the developer's machine past the approved cap.
NOT Raw scanner output is HARDENING until a path or repro is traced, so do not report it as a finding on its own.

## Scope modes

- **quick**: steps 0 to 8, skipping the authoring step (7) in favour of a smoke campaign over existing harnesses, and skipping the challenger (11).
- **full** (default): every step.
- **audit-only**: steps 0 to 14 that describe findings without fixing them. Regression tests that reproduce a PROVEN finding are still written, since a test describes the bug; only the product-code change is withheld. The `ticket` remediation route is compatible with this mode and `harden` is not, because a ticket describes the work while a patch performs it.
- **harness-only**: steps 0 to 7: author harnesses and corpora, execute nothing.

## References

| File | When to load |
|------|--------------|
| `references/workflow.md` | Always, before step 0 |
| `references/interview.md` | Steps 0, 2, 3: pin target, threat, surfaces, tools, budget, consent |
| `references/beads-store.md` | Step 1: run graph, wisps, handoff, resume |
| `references/escalation.md` | Steps 5, 8, 11: build the attack-vector baseline and chain findings |
| `references/targeting.md` | Step 2: any non-whole-repo target |
| `references/surfaces/index.md` | Step 2: route target to surface docs |
| `references/recon.md` | Step 5: derive the trust map, invariants, and repo-specific rules |
| `references/scout-brief.md` | Step 5: build each `sabot-scout` Brief |
| `references/surfaces/<surface>.md` | Steps 7 to 10: per-surface attacks and tools |
| `references/tooling.md` | Steps 3 to 8: scanner catalog, invocation, overlap, class |
| `references/installer.md` | Step 3: install-flow contract and bundles |
| `references/fuzzer-brief.md` | Step 7: build each `fuzzer` Brief |
| `references/harnesses.md` | Step 7: harness patterns per target kind |
| `references/gremlin-brief.md` | Step 8: build each `gremlin` Brief |
| `references/fuzz-tools.md` | Steps 7 to 10: generator, mutator, minimizer, and coverage catalog |
| `references/isolation.md` | Steps 7 to 10: container contract; authoring ban; host tripwire |
| `references/fuzzing.md` | Step 8: budgets, runners, crash capture |
| `references/corpora/prompt-injection.md` | Steps 7 to 9: agent-surface payloads |
| `references/agentic-fuzz.md` | Steps 7 to 9: generated attacks against a hook, skill, or agent |
| `references/triager-brief.md` | Step 10: build the `triager` Brief |
| `references/challenger-brief.md` | Step 11: build the `challenger` Brief |
| `references/network-stage.md` | Step 13: the egress-only lookups, and secret-verification consent |
| `references/report-template.md` | Step 14: two-axis report format |
| `references/remediation.md` | Step 15: route selection, tracker access, ticket schema, verification |
| `references/hardener-brief.md` | Step 15: build each `hardener` Brief |

## Agents

| Agent | Role | Spawned |
|-------|------|---------|
| `sabot-scout` | Read-only recon: trust map, invariants, idiom census, repo-specific rules | Step 5, one per surface, parallel |
| `fuzzer` | Authors harnesses, corpora, and vectors from recon's invariants; runs nothing | Step 7, one per surface, parallel |
| `gremlin` | Executes scanners, synthesized rules, and harnesses per surface, and reads for what they miss | Step 8, one per surface node, parallel |
| `triager` | Dedups, minimizes, and classifies crashes | Step 10, once per crash batch |
| `challenger` | Read-only exploitability critic; sets the evidence tier | Step 11, once over the finding wisps |
| `hardener` | Applies approved patches and re-verifies | Step 15, only after explicit approval |
