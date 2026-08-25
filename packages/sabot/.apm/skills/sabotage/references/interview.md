# Interview: pin the scope before the campaign spends a token

The campaign is only as good as its scope. A wrong target, an unstated surface, or
an unapproved budget wastes the whole run, so the interview exists to remove every
ambiguity that would change what gets attacked or how much it costs.

This is not a script to read out. It is a set of facts that MUST be certain before
step 5, and a way to probe for them that adapts to what the user already said. A
user who names a PR and a threat has answered half of it in one sentence; a user
who says "check my repo" has answered none of it. Ask for what is still unknown,
not for what was already given.

## What MUST be certain before recon

Ask the interview in two separate parts. A **core** every run asks pins what to
attack and how much; a **blast-radius opt-in**, asked only when a triggering surface
is in scope, authorizes the few actions that run real payloads through real grants.
Do not fold the opt-in into the core questions, and never present an action the hard
rules forbid.

### Core (always asked, the four STOP questions)

| Fact | STOP question | Why it changes the run | Unpins the run when |
|---|---|---|---|
| Target | 1 | decides the file list and the base ref | "the repo" without a kind, since scanning the whole repo is a choice the user has to make deliberately |
| User's threat | 1 | what the user fears decides which surface leads and orders the report | absent: the report prioritizes nothing |
| Surfaces | 2 | each surface is a parallel gremlin and a cost | detected set never shown to the user to trim or extend |
| Tools + budget | 3 | decides coverage and wall-clock, and bounds the machine | "go" on an unseen tool set, or a budget the user never approved |
| Remediation route | 4 | decides what step 15 does with a confirmed finding, and whether the run needs tracker access at all | asked only after the report, when the findings are already stale and the user has lost the context to choose |

MUST Resolve all six core facts before spawning a sabot-scout. A campaign that starts under an unpinned scope produces findings for the wrong target and a coverage claim it cannot support.
MUST Record every defaulted fact as a gap in the report. "Whole repo, because none was named" belongs there, since the user may have meant one module.

### Remediation route (core question 4)

Ask what should happen to a confirmed finding, and ask it in the interview rather
than at step 15. The answer changes work that happens much earlier: a run headed for
a tracker must capture a reproduction and a proposed fix in a form that survives
without the session, while a run headed for a patch needs the verification command
recorded per finding. Both routes may be chosen; neither is the default.

| Route | Step 15 becomes | Requires |
|---|---|---|
| `harden` | `hardener` patches one approved finding, then the attack and triage steps (8 and 10) re-run to prove the finding is gone | per-finding approval, as it always has |
| `ticket` | one ticket per surviving finding in the user's tracker, carrying the evidence, the `file:line`, the repro, and the proposed fix | a tracker and an access method the user named and confirmed |
| `both` | ticket every finding, then harden the subset the user approves, and note the ticket id in the patch | both of the above |
| `report only` | nothing. The report is the deliverable | nothing |

**Never infer the tracker from the repository.** A GitHub remote does not mean issues
are the destination: issues are often disabled, or the team tracks in Jira, Linear,
GitLab, or an internal system while mirroring code to GitHub. Ask which system, then
ask how to reach it, then confirm the resolved destination before writing anything.

| Ask | Then confirm back |
|---|---|
| which tracker | the system, and that it is the one the team actually works in |
| how to reach it | the CLI or endpoint, and which credential it uses (`gh`, `glab`, an API token in a named env var, an MCP server already connected) |
| where tickets land | the exact project, repo, board, or queue, plus labels and whether a parent epic should hold them |
| whether to open one at all | a dry run that prints the ticket bodies without creating them, when the user is unsure |

MUST Ask which tracker and which access method, and confirm both, before any ticket is created. Inferring the tracker from the git remote is how a campaign files a public issue on a mirror, and a security finding filed publicly is a disclosure the user never authorized.
MUST Offer a dry run that renders every ticket body without creating anything. The user judges a template from a rendered ticket, not from a description of one.
MUST Treat the ticket route as a separate authorization from the patch route. Approving a patch is not approving an external write, and approving a ticket is not approving a code change.
MUST Ask whether the tracker is public when the findings include anything unpatched. A PROVEN reachable crash in a public issue is a published vulnerability, so the user decides that deliberately or the route stays private.
NOT Never open a ticket for a REFUTED finding, and never open one per instance for findings sharing a `root_cause`. One ticket per root cause with the instance list is what a maintainer can act on; twenty near-duplicates get closed as noise and take the real one with them.

### Blast-radius opt-in (a SEPARATE question, only when applicable)

Live-spawn agentic fuzzing and dev-server DAST run real payloads through real grants,
so they are OFF by default and each is a distinct opt-in the user names, asked AFTER
the core is pinned, and only when its triggering surface was detected. When the
trigger is absent, the option does not exist for this run: do not list it, not even
as "N/A" or "unavailable", since a greyed-out option frames a non-choice as a dial.

| Opt-in | Asked only when | If declined or not triggered |
|---|---|---|
| Live-spawn agentic fuzzing | agent/skill/MCP definitions are in scope AND the user opts in | omitted from the question entirely; the definition-review pass still runs statically |
| Dev-server DAST | a runnable web server is in scope AND the user opts in | omitted entirely; the static web pass still runs |
| LLM access for grading | live-spawn or promptfoo grading was opted into | agentic-fuzz is skipped, and step 9 is recorded DECLINED or NOT-OFFERED |
| Network stage (step 13) | always applicable, since the campaign is always offline | DECLINED, with all four egress-blocked gaps listed as open (`references/network-stage.md`) |
| Secret verification | the network stage was opted into AND a candidate secret was found | live secrets are reported UNVERIFIED by location and type; nothing is sent anywhere |

MUST Ask each blast-radius opt-in as its own question after the core, and only when its triggering surface is in scope. An opt-in offered with no trigger is clutter; an opt-in folded into the core question buries the consent that matters.
MUST Omit entirely any action the hard rules forbid (attacking a network host, a public endpoint, or a third-party service). It is never a menu option, an "N/A" row, or an "unavailable" line. A referenced-but-forbidden target (a CI file that probes a live host) is read statically and not mentioned in the interview at all.
MUST Restate what a granted opt-in will run, against what, before the first spawn, and wait. An offhand "sure" is not the authorization a live-spawn or DAST run requires.
MUST Ask for the network stage and for secret verification separately, and ask the second only after the first is granted and a candidate secret actually exists. Verifying a credential sends it to its provider, which the other five gaps never do, so one "yes" cannot cover both. Name the owner of the secret in the question, because a third party's key is never verified at all.
MUST Ask, when the user opts into agentic grading (promptfoo or live-spawn), which LLM to use: an API key with its provider, a local or self-hosted endpoint, or none (which skips agentic-fuzz). Grading runs host-side, since the agents surface is container-free, so the credential stays in an environment variable on the host and is never baked into an image. Keep this question inside the opt-in block, out of the core.

## How to probe: adapt, do not recite

Run the interview as a loop. Read what the user gave, restate your current
understanding, and ask only for the gap that most changes the run. Stop the moment
the five facts are certain, since an extra question on a scope already pinned is
friction the user reads as indecision.

MUST Restate the resolved scope in one block before recon: target kind, file count, threat, surfaces, base ref, checkout, budget, and every default applied. A scope the user did not intend is caught here or not at all.
MUST Ask the question that resolves the most unknowns first, then re-read. The answer often settles two others, so a fixed order asks questions the last answer already closed.
MUST Prefer a concrete menu over an open question when the axis is closed. "Whole repo, this module, or the diff on your branch?" resolves faster than "what do you want to scan?", because the user recognizes the right answer rather than composing it.
NOT Never batch all five into one wall of questions. A user faced with a form answers the easy ones and skips the one that mattered.

## Reading the answers: what to distrust

An answer can pin a fact and hide a landmine. Probe further when:

| The user says | Distrust because | Probe |
|---|---|---|
| "scan everything" | whole-repo on a large tree is hours of budget and a flooded report | offer the diff or the module they actually changed; confirm they want the whole tree |
| "just check for vulnerabilities" | no threat model means no prioritization | ask which failure would hurt worst, so the answer names a surface rather than the whole repo |
| "it's fine, go" on an unseen tool set | a declined tool is a silent coverage gap they never saw | show the default-on set and the cost once, then accept "go" |
| "yes, fuzz the agents live" | live-spawn runs real payloads through real tool grants | confirm the exact targets, the lease, and the case count before the first spawn |
| "the whole thing is untrusted input" | everything-is-tainted maps no boundary | ask where trusted and untrusted actually meet, naming the concrete edge (an HTTP handler, a CLI argument, a file read, an env var) |
| a target with no ref | a clean tree still has a mergeable change to audit | offer commit / range / branch / PR, since a regression review is a different question |

MUST Convert a vague fear into a falsifiable scope. "I want it secure" becomes "attacker-controlled input must never reach the shell in `hooks/`", which names a surface and a boundary recon can then map.
MUST Treat an offhand "yes, fuzz it live" as a cue to open the blast-radius opt-in properly, not as the approval itself. Route it to that separate question (above), restate what will run and against what, and wait.

## When there is no one to ask

A non-interactive run (CI, a cron job, a sub-agent with no user) cannot interview.
It does not therefore guess: it takes the deterministic defaults and records each as
a gap, so the report states the scope it assumed rather than implying the user chose
it.

| Fact | Non-interactive default |
|---|---|
| Target | the target passed in the spawn, else the whole repo |
| Threat model | none; every surface is treated at equal priority and the report says so |
| Surfaces | the full detected set, robustness always included |
| Tools + budget | the installed tools and the `fuzzing.md` budget defaults |
| Blast-radius | live-spawn, DAST, the network stage, and secret verification are all OFF; each requires an interactive opt-in |
| Remediation route | `report only`, with both `harden` and `ticket` refused |

MUST Refuse live-spawn, dev-server DAST, and the network stage in a non-interactive run. Each needs a target the user named and an explicit human authorization that a defaulted run cannot supply, and a cron job that sends a found credential to its provider has done something no default should be able to authorize.
MUST Default a non-interactive run to `report only` and refuse both remediation routes. A cron job that patches product code or files tickets is writing to the repo and to the team's tracker with nobody having read a finding, and a defaulted route is the one default whose damage outlives the run.
MUST Record every default as a coverage gap. A non-interactive run that hides its assumptions reads as a scoped audit when it was a whole-repo sweep on borrowed defaults.

## Handing the scope forward

The interview feeds step 1 (open the run) and step 2 (resolve the target). Stamp the
resolved scope on the run epic so a resumed campaign reuses it rather than
re-interviewing. The target kind and base ref flow into `targeting.md`; the surfaces
and budget become the surface nodes and the epic's `budget` metadata.

The user's stated threat is stamped on the epic as `threat` metadata, where it
orders the report and ranks which surface leads. Keep it out of the sabot-scout Brief.
A sabot-scout told where the bug is stops censusing, so recon derives the repo's own
threat model independently (see `recon.md` and `scout-brief.md`). The user's fear
prioritizes attention; the derived model is the map recon builds without a
hypothesis.

MUST Stamp the user's threat on the epic for prioritization and reporting, and keep it out of the sabot-scout Brief. A sabot-scout handed a suspected bug narrows its census to that guess and misses the deviations that census exists to find.

The remediation route is stamped on the epic too, as `remediation_route` plus, on the
`ticket` route, the confirmed `tracker`, access method, and destination. Step 15 reads
those rather than re-asking, so a campaign resumed days later remediates where the
user said and not where the git remote points.

MUST Stamp the route and, on the `ticket` route, the confirmed tracker and destination on the epic. Step 15 often runs in a later session than the interview, and a route held only in conversation is a route the resumed run has to guess.
