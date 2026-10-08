# Agentic fuzzing: attacking a hook, skill, or agent with generated cases

The executable half of the agents surface. `promptfoo redteam` generates attacks
from a plugin taxonomy and grades whether the target script's response to each
crossed a boundary. `fuzzer` writes the config and the target
script; `gremlin` runs the eval. The existing write and execute split holds, since
promptfoo is one more executable in a run recipe.

This is not LLM red-teaming. The target is a script that invokes YOUR hook, skill,
or agent, so a failure names a defect in this repo rather than in a model.

## Which parts need a model

| Part | Needs a model | Owner |
|---|---|---|
| Generate cases from plugins | yes, once per campaign | `fuzzer` |
| Target script under attack | no | `fuzzer` writes it, `gremlin` runs it |
| Grade the target's response | yes, per case | `gremlin` |

MUST Gate generation and grading before the first call, since both spend tokens. Declare the plugin set, the case count, and the grader, then wait. Measured reference: 3 cases generated plus graded cost 3,296 tokens and 4 seconds wall-clock.
MUST Generate per campaign against that repo's real purpose string, because a case aimed at the wrong purpose tests a boundary the target never claimed.

## The target script must ACT, not echo

The one trap that makes this whole approach lie. A target that merely repeats the
attack passes every case, because the grader looks for a crossed boundary in the
response and an echo crosses nothing, so a stub with no defences at all still
produces a clean result.

| Target kind | The script must |
|---|---|
| Hook or guard | pipe the attack into the real guard and return its verdict JSON, so a wrong `allow` is a graded FAIL |
| CLI or script | run it with the attack as argv or stdin and return its actual output |
| Skill or agent definition | return the definition's own governing rules as the response, so the grader judges whether those rules defeat the attack |
| MCP server | send the attack as a tool call and return the server's reply |

MUST Prove the target acts before trusting a pass. Run one case against a deliberately compliant stub that leaks its instructions and claims to run the injected command; every case must FAIL. A stub that passes means the harness is measuring nothing.
MUST Return the target's real output rather than a summary of it, since the grader reads the response text and a paraphrase hides the violation.
NOT Never make the target script echo the prompt. That is the silent-pass failure that looks identical to a hardened target.

## Plugin selection

promptfoo ships 155 plugins, most of them irrelevant here (bias, finance,
healthcare, compliance). Select only the families that describe this surface:

| Family | Plugins | Attacks |
|---|---|---|
| coding agent | `coding-agent:repo-prompt-injection` · `sandbox-read-escape` · `sandbox-write-escape` · `secret-env-read` · `secret-file-read` · `verifier-sabotage` · `delayed-ci-exfil` · `automation-poisoning` · `network-egress-bypass` · `steganographic-exfil` · `terminal-output-injection` · `procfs-credential-read` · `generated-vulnerability` | the agentic-repo threat model directly |
| agent and protocol | `mcp` · `agentic:memory-poisoning` · `tool-discovery` · `excessive-agency` · `rbac` · `bfla` · `bola` | tool grants, MCP, authorization |
| prompt boundary | `system-prompt-override` · `prompt-extraction` · `ascii-smuggling` · `cca` · `hijacking` · `pliny` · `cyberseceval` | instruction override and smuggling |
| injection sinks | `shell-injection` · `sql-injection` · `ssrf` · `debug-access` · `data-exfil` | reachable sinks behind an agent |

MUST Select plugins from the families above and name the ones left off, since running all 155 floods the report with bias and compliance findings that bury the ones on this surface.
DEFAULT Start with the coding-agent family plus `mcp` when the target is a skill, hook, or MCP config, because those map onto the surface checklist one to one.

## Strategies: a second axis, applicability decided per plugin

A strategy transforms a plugin's payload, so plugins times strategies is the real
case count. Applicability is NOT uniform: the `coding-agent:*` plugins return
`excludeStrategies: [base64, hex, homoglyph, leetspeak, rot13, multilingual,
math-prompt, jailbreak:composite]`, because encoding a repo-injection payload
destroys the realism that makes it land. Those strategies report `Skipped` with
0 cases against that family, and `Success` against `mcp`, `system-prompt-override`,
and `prompt-extraction` (measured).

| Strategy | Cost | Applies to |
|---|---|---|
| `basic` | free | every plugin. The control arm: raw cases, no transform |
| `base64` `hex` `rot13` `leetspeak` `morse` `piglatin` `camelcase` | free, deterministic | prompt-boundary and protocol plugins. Skipped by `coding-agent:*` |
| `homoglyph`, emoji smuggling | free, deterministic | same. Emoji smuggling hides payloads in Unicode variation selectors |
| `layer` | free | chains transforms, keeping the last step's output |
| `retry` | free | replays failed cases as a regression suite |
| `jailbreak:composite` | one attacker call per case, and it multiplied 2 base cases into 10 (measured) | prompt-boundary and protocol plugins. Skipped by `coding-agent:*` |
| `jailbreak:meta` `jailbreak:tree` `best-of-n` `citation` `math-prompt` `gcg` | attacker calls per case | opt-in only |
| `crescendo` `goat` `goblin` `jailbreak:hydra` | multi-turn, several turns per case | live-spawn only, since they need a stateful target |

Default recipe: `basic` plus the free deterministic set plus `retry` plus
`jailbreak:composite`.

MUST State the case count AFTER strategy multiplication at the gate, since `jailbreak:composite` turned 2 base cases into 10 and a per-plugin count understates the run by that factor.
MUST Report a `Skipped` strategy as inapplicable. The plugin excluded it deliberately, and the payload works better without it.
MUST Include `basic` so the run has a control arm, since a finding that only lands under a transform is a different claim from one that lands raw.
DEFAULT Pair the free deterministic strategies with the prompt-boundary and protocol plugins, and leave the `coding-agent:*` family on `basic` plus `retry`.

## Multi-turn: live-spawn only

`crescendo`, `goat`, `goblin`, and `jailbreak:hydra` ramp an attack across turns and
backtrack toward whatever works, so they need a target that holds a session. A
script provider answers once and forgets. These strategies are unusable against it
and apply only to a stateful live-spawned agent.

MUST Run a multi-turn strategy only in live-spawn mode, and only when the target script maintains the session across turns rather than re-spawning per turn.
MUST Multiply the turn budget by the strategy's turn count at the gate, because a multi-turn case costs several agent turns rather than one.
NOT Never claim multi-turn coverage from a single-turn run. The slow-ramp classes go unexercised, and the report says so.

## Config shape

`fuzzer` writes this into the artifacts dir, never the repo root:

```yaml
targets:
  - id: exec:./bs-target-<name>.sh      # the REAL-INVOCATION script
    label: <what is under test>
prompts:
  - "{{prompt}}"
redteam:
  purpose: |
    <the target's OWN claimed contract, quoted from its definition: what it may
    read, what tools it holds, what it must never do. The grader judges against
    this, so a vague purpose grades nothing.>
  numTests: <per plugin>
  plugins:
    - coding-agent:repo-prompt-injection
    - coding-agent:verifier-sabotage
    - mcp
  strategies:
    - basic                 # control arm: raw cases, no transform
    - retry                 # replay previously failed cases as regression
    - jailbreak:composite   # excluded by coding-agent:*, applies to mcp
    - base64                # same
    - homoglyph             # same
```

MUST Quote the purpose from the target's own definition. The grader measures the response against this text, so an invented purpose invents the verdict.
MUST Write the config, the target script, and the generated cases into the artifacts dir, and list them in the report as uncommitted artifacts.

## Run recipe

```
# fuzzer: author only, no execution
npx --yes promptfoo@latest redteam generate --config <artifacts>/promptfooconfig.yaml \
    --output <artifacts>/rt-<surface>.yaml

# gremlin: execute the generated cases
npx --yes promptfoo@latest redteam eval -c <artifacts>/rt-<surface>.yaml \
    --no-cache --grader <provider> -o <artifacts>/rt-<surface>-out.json
```

Read `results.results[].gradingResult.reason` for the per-case verdict. A FAIL
names the boundary crossed, which becomes the finding's evidence.

MUST Pass `--no-cache`, since a cached grade from a previous target is not a result for this one.
MUST Parse the JSON output. The terminal summary gives a pass count with no per-case reason, which cannot be tiered.

## Live-spawn mode: proving a definition finding

A definition cannot act, so grading its rules caps at REACHABLE. Live-spawn closes
that gap by making the target script spawn the real skill or agent and return its
actual reply, which turns a landed attack into a PROVEN finding.

Opt-in, never automatic. It runs real attack payloads through an agent holding real
tools, so it is the most invasive thing this skill does.

Once the user opts in, every case runs against every target the user named. The definition
pass informs the report and does not select the work, because a rule written in
prose is not a guarantee of behaviour: the finding worth most here is the definition
whose rules read correctly while the agent complies anyway. Running only the cases
the definition already fails would never reach it, and "live-spawn found nothing"
would mean nothing beyond "nothing among the cases already suspected".

MUST Run every generated case against every target the user named once opted in, since filtering by the definition pass hides the rules that read well and do not hold.
MUST Report a case the live agent resisted as evidence-backed. A rule proven under attack is a stronger clean result than a rule merely found in the text.

### Gates

MUST Ask which specific skill or agent to invoke, and never infer the set. The user names each target, because spawning an agent the user did not name runs attacks nobody authorized.
MUST Restrict live-spawn to a PR, commit, or range target. A whole-repo run spawns every skill and agent present, which is neither scoped nor affordable; refuse it and say why.
MUST Declare the case count, the agent turns, and the containment before the first spawn, then wait. Each case costs a full agent turn.
MUST Record step 9 in the report as GRANTED, DECLINED, or NOT-OFFERED. A step 9 with no disposition line reads the same as a step 9 that ran and found nothing.
NOT Never escalate to live-spawn on the strength of a REACHABLE finding alone. The escalation is the user's call.

### Containment

The spawned target holds its real tool grant so that write-escape and
network-egress cases can genuinely execute, which means the blast radius comes from
the environment rather than from the grant.

A Worktrunk lease is NOT that environment. It is a working tree: it shares the host
kernel, network, credentials, and home directory (`isolation.md`), so it decides
where the target's cwd is and restricts nothing. The enforced boundary is a
container, as for every other execution phase, and the lease only supplies the tree
mounted into it. Canaries detect an escape after it happened; they prevent nothing.

| Control | Implementation |
|---|---|
| Execution | the spawned agent runs INSIDE a container (non-root, `--cap-drop ALL`, read-only root, the same flags `run-contained.sh` sets), never on the host. No container runtime means no live-spawn: record the stage NOT-OFFERED with that reason |
| Filesystem | a dedicated Worktrunk lease (`wt switch --create <branch> --base <base> --no-cd --format=json`) bind-mounted as the container's only writable tree, discarded afterwards. The target script sets cwd to the mount point |
| Write boundary | the container's mounts are the boundary. Seed canary files in a second, writable path inside the container that is not the lease, so an attempted write beyond the lease is an observable finding rather than damage |
| Network | enforced by the container network, never by the lease. The model endpoint the spawn needs is the one permitted egress, through an allowlisting proxy or firewall rule the harness configures, and every network-egress case points at a `127.0.0.1` sink inside the container. With no enforced egress control, the network-egress cases are NOT EXECUTED rather than run on trust |
| Secrets | seed canary env vars and canary dotfiles whose values appear nowhere else. A canary in the reply, a log, a diff, or a tool argument proves exfil. The only live credential in the container is the model-provider key the spawn itself needs |
| Lifecycle | read the canaries and collect the artifacts, then remove the container and discard the lease |

MUST Run every live-spawn target inside a container whose only writable tree is its own Worktrunk lease, never on the host and never in the primary checkout. A lease alone shares the host's network and credentials, so a write-escape or egress case executing there is the attack succeeding rather than being measured.
MUST Enforce the network boundary with the container network or an allowlisting proxy that permits only the model endpoint, and record the mechanism in the report. A network-egress case with no enforced boundary is NOT EXECUTED, because a loopback sink proves nothing about a host that can reach everything else.
MUST Seed canaries before the run and check them after, because a canary is the only evidence that separates a claimed exfil from a real one.
MUST Point every network case at a loopback sink the harness controls, and treat a request to any other host as a finding rather than as test traffic.
MUST Read the canaries and collect the artifacts before discarding the lease, since a discarded lease takes the evidence with it.
NOT Never grant the spawned agent a credential, a real token, or a path outside its lease, beyond the model-provider key its own invocation needs. A canary proves the reach without handing over anything live.

### Target script shape

```bash
#!/usr/bin/env bash
# Live-spawn target. Runs INSIDE the container. $1 = the generated attack.
# Returns the agent's REAL reply.
set -uo pipefail
cd "$BS_LEASE_PATH" || exit 1          # the lease's mount point in the container
# Canary env var: its value appears nowhere else, so a leak is provable.
export BS_CANARY_TOKEN="$BS_CANARY_TOKEN"
<the harness's own agent invocation, with the definition under test, in this lease>
```

MUST Return the agent's reply verbatim, since the grader reads the response text and a summary hides the violation.
MUST Fail the case loudly when the spawn itself errors, because a spawn failure reported as a pass is a silent zero.

## Tiering an agentic-fuzz finding

| Observation | Tier |
|---|---|
| The target acted on the attack, and the compliant-stub control failed as expected | PROVEN, with the case and the grader's reason as evidence |
| A live-spawned agent acted on the attack, or a canary appeared in its reply, a log, a diff, or a tool argument | PROVEN, naming the canary and the case |
| The target's definition carries no rule against the attack, and the target only reports rather than acts | REACHABLE, since a live agent may act where the script does not. Live-spawn is how this becomes PROVEN |
| The plugin generated a case for a class no entry point reaches in this repo | HARDENING |
| Every case passed and the compliant-stub control also passed | INVALID: the harness measured nothing |

MUST Re-run a failing case once to confirm it reproduces, because generation and grading are both non-deterministic.
MUST Record the plugin id, the grader, and the case text on every finding, since the same plugin regenerates different attacks each run.
MUST Report the compliant-stub control result alongside the findings. A pass rate with no control behind it is unfalsifiable.

## Feeding findings back

A generated case that landed is worth more than one campaign. Promote it into
`corpora/prompt-injection.md` as a payload-class row with the target that fell for
it, so the next campaign starts with it for free and no model call is needed to
rediscover it.

MUST Promote every PROVEN case into the corpus, since the corpus is the offline floor and generation is the paid extension of it.
