# Remediation: what step 15 does with a confirmed finding

Step 14 emits the report. Step 15 acts on it, and the route was pinned in the
interview (`references/interview.md`, core question 4) rather than decided here. Two
routes exist and they compose: patch the code, or file the work in the user's
tracker. Both need approval, and approving one is not approving the other.

| Route | What runs | Approval needed |
|---|---|---|
| `harden` | `hardener` per finding, then the attack and triage steps (8 and 10) re-run to prove it gone | per-finding, on the patch |
| `ticket` | one ticket per root cause in the user's tracker | on the tracker, the access method, and the destination |
| `both` | ticket first, then harden the approved subset, stamping the ticket id in the patch | both |
| `report only` | nothing | none |

MUST Read the route off the epic rather than choosing one here. A run that reaches step 15 without a pinned route asks the user then, and records the late question as a gap.

## Route `harden`: patch, then prove the finding is gone

The verification is the point. A patch that compiles is not a fixed finding, and the
only evidence that counts is the original repro failing to reproduce.

| Stage | Requirement |
|---|---|
| before | quote the finding's `repro_cmd` and `repro_rc`, and re-run it to confirm it still reproduces on the unpatched tree |
| patch | the narrowest change that closes the finding, in product code, on an approved finding only |
| after | re-run the same `repro_cmd`. A different exit code is the fix; the same code is not |
| regression | the repro becomes a test beside the repo's existing tests |
| rule | graduate the rule behind the finding into the repo's own lint config, and show it firing from the repo's own check entry point |

MUST Re-run the finding's own recorded `repro_cmd` before and after the patch, and quote both exit codes. A hardener that re-runs the whole suite instead proves the suite passes, which the suite already did while the bug was live.
MUST Treat an unchanged exit code as NOT FIXED and leave the finding open. A patch that looks right and changes nothing is the failure mode this step exists to catch.
NOT Never widen the patch beyond the approved finding. An unrelated cleanup in the same commit makes the verification ambiguous, because the re-run then covers two changes at once.

## Route `ticket`: file it in the tracker the user named

### Verify access before writing anything

A tracker write is an external, outward-facing action, and the credential that would
perform it usually has more reach than this one ticket needs.

| Step | Command shape | Must show |
|---|---|---|
| 1. identity | `gh auth status`, `glab auth status`, or the tracker's own whoami | which account and which scopes |
| 2. destination | list the target project, repo, board, or queue | that it exists and accepts issues |
| 3. visibility | read whether the destination is public | so an unpatched finding is not published by accident |
| 4. dry run | render every ticket body to a file under the artifacts dir | the user approves rendered text |
| 5. create | one call per ticket | the created id, echoed back onto the finding bead |

MUST Confirm the destination is the one the user named, by listing it, before the first create. A tracker inferred from the git remote is the wrong destination often enough that inference is banned outright.
MUST Check whether the destination is public and stop for a decision when any ticket describes an unpatched reachable finding. Filing that publicly is a disclosure, and it is the user's call, never the agent's.
MUST Render every ticket to the artifacts dir first and get approval on the rendered text. A template judged from a description is a template nobody read.
MUST Stamp the created ticket id back onto the finding bead. Without it a resumed run cannot tell a filed finding from an unfiled one, and files it twice.
NOT Never create a ticket for a REFUTED finding. The refutation belongs in the report, and a ticket for a non-bug costs a maintainer the same triage as a real one.

### One ticket per root cause

Findings sharing a `root_cause` were already grouped and tiered once at step 11.
Filing them individually undoes that work and buries the group's strongest instance
among its weakest.

| Finding set | Tickets |
|---|---|
| n findings, one `root_cause` | 1, listing every instance with its `file:line` |
| n findings, n root causes | n |
| a systemic pattern spanning nodes | 1 for the pattern, linked as parent to the per-cause tickets |

### Ticket body

The body has to survive the session, so it carries the evidence rather than
referring to it. Every field comes from the finding bead: its title, or a metadata key
the finding schema in `beads-store.md` defines and `report-json.py` keeps. A key no
agent stamps renders as a blank section, which reads as a ticket with nothing to say.

| Section | Content | From |
|---|---|---|
| title | the defect in one line, no tier prefix | the finding bead's title |
| tier and impact | both axes, stated plainly | `tier`, `impact` |
| location | every `file:line` instance, one per finding sharing the root cause | `locus` |
| evidence | the artifact or exact command that shows the defect | `evidence` |
| reproduction | the exact command and expected exit code, plus the minimized input | `repro_cmd`, `repro_rc`, `repro` |
| why it matters | the reachability chain from entry point to sink, in concrete inputs and outcome | `path` |
| proposed fix | what to change and where, without a patch attached, written at render time from the shared defect | `root_cause` |
| verification | how the fixer proves it closed | the harden route's before/after |
| provenance | the run epic and finding bead ids | beads |

MUST Include the reproduction and the exact `file:line` in every ticket. A ticket a maintainer cannot reproduce from is a ticket that gets closed unresolved, and the finding is then worse off than unreported because it now looks handled.
MUST Describe the proposed fix without attaching a patch on the `ticket` route. A patch in a ticket invites a merge the user did not approve as a code change.
NOT Never paste a credential, token, or key into a ticket body. A finding about a live credential names its location, type, and `file:line`, and nothing else.

## Resuming without double-filing

Step 15 is interruptible, so it must be idempotent. The finding bead's stamped
ticket id is the only reliable record; the tracker's own search is the fallback.

| State | Action |
|---|---|
| bead carries a ticket id | already filed. Skip |
| no ticket id, tracker search finds a matching title | filed but unstamped. Stamp it, do not re-file |
| neither | file it |

## Agents

The package doesn't ship a ticket-filing agent type. Run the `ticket` route from the main
thread, or spawn a generic agent with this file as its Brief, and record which was
used. That is a deliberate choice: a new agent type is invisible to the runtime until
the next session, so a fresh install would silently fall back at exactly the step
that performs external writes.
