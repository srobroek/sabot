# Beads store: run graph, wisps, handoff, resume

A campaign's state lives in the project's beads database (the `bd` CLI). One
database is shared by every worktree, so agents read and write live state with
plain `bd` commands. Large payloads (harness source, crash inputs, scanner JSON)
are files under `<primary>/.sabot/run-<id>/artifacts/`; bead comments cite
them by absolute path.

Beads is mandatory. A finding that exists only in an agent's reply dies with the
session, and a campaign that cannot resume is a campaign that must restart.

## Prerequisite (checked once, at run start)

```
command -v bd >/dev/null || { echo "sabot requires the beads CLI (bd)"; exit 1; }
bd info >/dev/null 2>&1 || bd init --stealth --prefix sab
```

No `bd` on PATH stops the run: tell the user to install beads. There is no
fallback store. A present `bd` with no database gets `bd init --stealth --prefix
sab`, which is git-invisible (writes `.git/info/exclude`, leaves `git status`
clean).

## Invoking `bd` at all: three ways the command silently produces nothing

Every one of these was hit in a real run, and each is indistinguishable from an
empty database.

| Trap | Symptom | Rule |
|---|---|---|
| `--labels` on a query | `bd list --labels sab-harness` returns nothing or errors, and the agent concludes no work exists | **`--label` (singular) on every query.** `--labels` (plural) exists only on `bd create` and `--add-label`. See the flag table below. |
| `--label-pattern` or `--label-regex` | the flag is accepted and filters NOTHING, so the query returns the WHOLE store and every count in the report is the store's size rather than the campaign's | **Never use either flag.** Use `--label` (AND) or `--label-any` (OR) with the labels enumerated. Measured on bd 1.2.2: `--label-pattern 'sab-*'` returned all 927 beads where `--label sab-finding` correctly returned 386, and `--label-pattern 'zzz-nonsense:*'` also returned all 927, so a nonsense pattern and a correct one are indistinguishable. This is the more dangerous direction of the `--labels` trap above: that one returns nothing and reads as "no work exists", while this one returns everything and reads as a successful query. |
| `bd show --json` shape | `bd create --json \| jq -r '.id'` works, and `bd show <id> --json \| jq -r '.metadata.x'` fails with "Cannot index array with string" | `bd show` returns an ARRAY: read it as `.[0].metadata.x`. Both commands take the same flag and return different shapes |
| Unscoped `bd ready` | the campaign's poured steps come back beside the PROJECT's own open beads, and an orchestrator claims project work as campaign work | `bd ready --parent <molecule-root>` on every driving query. Measured: an unscoped call returned three unrelated project beads alongside step 0, all four indistinguishable in the output |
| Wrong cwd | `bd` resolves the database from the repo root, so a call from a subdirectory or a worktree reads a different or absent store | `cd` to the repo root before any `bd` call, and state that root in every Brief |
| Output interception | a token-savings or logging hook truncates `bd show`/`bd list` and spills the body to a file, so the agent parses a summary as the whole answer | Capture with `--json` redirected to a file under the artifacts dir, then read the file. Never parse `bd` output straight out of the terminal. |

| Flag | Valid on | Never on |
|---|---|---|
| `--label <one>` | `bd list`, `bd ready` (repeat the flag for several) | n/a |
| `--labels a,b` | `bd create` | any query |
| `--add-label` | `bd update` | any query |

MUST Distinguish an empty query result from a successful-but-empty surface before concluding there is no work, by re-running the query with the label dropped:

| Labelled count | Unlabelled count | Reading |
|---|---|---|
| 0 | nonzero | the QUERY is wrong; fix the flag or the label and re-run |
| 0 | 0 | the parent has no children, which is a defect to report and never a clean surface |
| nonzero | nonzero | a real work list |

A campaign lost a whole surface to a plural flag that returned nothing and read as
"no harnesses exist".

## Objects

Every campaign bead carries the same `run_id` metadata as the epic. Rollup
queries filter on it, since a rollup by parent or label alone breaks on bd 1.1.2:
`--parent <epic>` returns only direct children (surface nodes), so a finding two
levels down never appears, and a child inherits its parent's labels, so a
label-only query over the shared database over-selects and bleeds across
concurrent campaigns. The `run_id` field scopes every rollup to one run.

`--parent` does NOT mean the same thing on both commands, verified on bd 1.2.2
against a store with correct edges:

| Query | Scope | Use it for |
|---|---|---|
| `bd list --parent <bead>` | direct children only | reading one level, such as the surface nodes under an epic |
| `bd ready --parent <bead>` | every descendant | claiming work under a node, including harness wisps two levels down |

So a gremlin claiming its harnesses wants `bd ready --parent <node> --label
sab-harness --claim`, which reaches grandchildren and claims atomically. A rollup
over a whole campaign needs `--metadata-field run_id`, because
`bd list --parent <epic>` stops at the surface nodes.

| Object | Beads representation |
|---|---|
| Run | one **epic** bead; metadata `run_id`, `target`, `base_sha`, `budget` (JSON), `artifacts` (abs dir), `remediation_route` (`harden`\|`ticket`\|`both`\|`report only`), and on the `ticket` route `tracker` (JSON: system, access method, destination, whether public) |
| Surface node | **task** bead, `--parent <epic>`, labels `sab-surface` + `sab-audit` + `non-work`, metadata `run_id`, `surface`, `scope` (JSON array of globs) |
| Harness wisp | **task** bead, `--parent <surface>`, labels `sab-harness` + `sab-audit` + `non-work`, metadata `run_id`, `entry_point`, `runner`, `harness_path`, `input_shape` |
| Crash wisp | **task** bead, `--parent <surface>`, labels `sab-crash` + `sab-audit` + `non-work`, metadata `run_id`, `input_path`, `stack_hash` |
| Finding wisp | **task** bead, `--parent <surface>`, labels `sab-finding` + `sab-audit` (plus `non-work` once tiered REFUTED, or when the locus is inside the artifacts dir), metadata `run_id`, `tier`, `by`, `source`, `impact`, `locus`, `surface`, `path`, and after step 15 `ticket_id` (the created ticket, so a resumed run cannot file it twice) |
| Coverage record | **task** bead, `--parent <surface>`, labels `sab-coverage` + `sab-audit` + `non-work`, metadata `run_id`, `scanners_run`, `scanners_skipped`, `harnesses_run`, `harnesses_total`, one per surface node |
| Decision | **decision** bead under the epic, for an accepted-risk or scope ruling that outlives one finding |

```
# Capture the id with --json | jq -r .id. Do NOT use --silent to capture an id:
# on bd 1.1.2 --silent prints a multi-line status block, so EPIC becomes
# "  Status: open" and every child create fails "parent issue not found",
# a silently broken run graph. --json emits a parseable object; jq pulls the id.
EPIC=$(bd create "sabot run-<id>" --type epic --json \
  --metadata '{"run_id":"run-<id>","target":"<resolved target>","base_sha":"<sha>","budget":{"wall_s":60,"jobs":4,"mem_mb":2048},"artifacts":"<abs>/.sabot/run-<id>/artifacts"}' \
  | jq -r '.id')
# Every child carries run_id=run-<id> too, since rollups filter on it (see below).
S1=$(bd create "surface: shell" --parent "$EPIC" --labels sab-surface,sab-audit,non-work --json \
  --metadata '{"run_id":"run-<id>","surface":"shell","scope":["packages/*/scripts/**","**/*.sh"]}' \
  | jq -r '.id')
bd dep cycles                 # must stay clean
```

### An audit's beads are not the project's backlog

A campaign writes hundreds of beads into a store the project also uses for its own
work. Nothing about a `sab-*` label tells a project's tooling that the bead belongs
to an audit, so the project's own queries return all of them, including its release
gates.

MUST Label EVERY campaign bead `sab-audit`, alongside its own `sab-*` label. This is the one label a project's own queries can exclude on, so it is what separates an audit's records from the project's work. Measured: one campaign left 680 beads in a product repo's store, of which 329 were not product defects, and the project's "close every bead" release gate blocked on the audit's own bookkeeping.
MUST Label every non-defect record `non-work` too: harness, crash, and coverage wisps, AND surface nodes, AND a finding tiered REFUTED, AND a finding whose locus is inside the run's own artifacts dir. Measured: 22 surface roots, 24 coverage records, and 6 crash records finished one campaign with no `non-work` label, because the rule named only three of the buckets and nothing checked any of them.
MUST Pass `--no-inherit-labels` on every finding create. `bd create --parent` copies the parent's labels onto the child by default, and every surface node carries `non-work`, so a finding parented to one inherits `non-work` and drops out of the project's work queue while the create command that made it named only `sab-finding,sab-audit`. Measured: 51 of 388 findings in one campaign carried `non-work`, of which 36 REFUTED and 6 HARDENING and 2 audit-tooling were correct, leaving 5 PROVEN and 2 REACHABLE product defects excluded from the backlog by a label no agent wrote.
MUST File a defect in the audit's OWN tooling as a finding with its locus inside the artifacts dir, labelled `non-work`. A misfiring synthesized rule is real and worth fixing, and it is not a defect in the product. Measured: 6 such findings in one campaign were tiered PROVEN or REACHABLE and counted among the product's, and only 2 of the 6 announced it in their title, so the locus is the signal and the title is not.
MUST Parent every campaign bead under its own surface node, and verify the edge target matches the bead's id prefix. Measured: one campaign's 21 surface nodes carried ids under the run epic while their `parent-child` edges pointed at twelve unrelated project beads, one of them a task titled "epic: test execution gaps". `report-json.py` walked the edge, reached 0 of 680 beads, and rendered an empty report at exit 0, so a whole campaign read as a clean audit.

### Priority states the two axes, or it states nothing

A finding already states its tier and its impact, so its priority is a function of
those two and never a separate judgement. Left to each creating agent's default it
converges on one value and stops ordering anything.

| Tier | CRITICAL | HIGH | MEDIUM | LOW |
|---|---|---|---|---|
| PROVEN / REACHABLE | P0 | P1 | P2 | P3 |
| HARDENING | P2 | P2 | P3 | P4 |
| REFUTED | P4 | P4 | P4 | P4 |

MUST Set `-p` from the table above whenever you stamp or change a tier or an impact. Measured: 14 of 21 surfaces in one campaign were entirely P2, and the run's two worst findings (an unauthenticated MCP bridge on `0.0.0.0:9223` reaching 204 commands, and that bridge compiled into release builds) sat at P2 beside 82 MEDIUM ones, so sorting by priority ordered nothing.
MUST Close a REFUTED finding with reason `refuted`, keeping the wisp and its refutation. The no-delete rule preserves the RECORD, not its open status. Measured: 35 of 36 REFUTED findings in one campaign were still open at report time, so findings the run had itself disproved read as outstanding work in every backlog query.

MUST Capture a bead id with `bd create ... --json | jq -r '.id'`, never with `--silent`. On bd 1.1.2 `--silent` prints a status block rather than a bare id, so the capture is garbage and the run graph is silently broken from the first child.
MUST Stamp `run_id` on every campaign bead, matching the epic's. Rollups filter on it (see Reading the run), and a bead created without it is invisible to every rollup, so its harness never runs or its finding never reports.
MUST Label harness, crash, and coverage wisps `non-work` as well as their own label, then discover them by their own label rather than by `bd ready`. On bd 1.1.2 `bd ready` still returns a `non-work` wisp, so a discovery query keys on the specific label (`sab-harness`) plus the surface parent, not on the ready queue.
MUST Use `--metadata` for stamps, since it merges with existing keys and never clobbers `surface` or `scope`.

## Handoff chain

Each arrow is a durable write, so the receiving agent reads its input from the
graph rather than from a parent's prose.

| Step | Writer | Creates | Claimed by |
|---|---|---|---|
| 7 | `fuzzer` | harness wisp per entry point | `gremlin` for that surface |
| 8 | `gremlin` | crash wisp per distinct crash, finding wisp per non-crash finding | `triager` (crashes), `challenger` (findings) |
| 10 | `triager` | finding wisp per minimized crash, closes the crash wisp | `challenger` |
| 11 | `challenger` | tier stamp on each finding wisp | main thread at report time |
| 15 | `hardener` | patch record on the finding wisp | main thread for verification |

A `gremlin` discovers its work with:

```
cd <repo root>
bd list --parent <surface> --label sab-harness --status open --json > <artifacts>/wisps-<surface>.json
bd update <harness-wisp> --claim        # atomic, first-wins, sets assignee
```

### Who may close a surface node

`sabot-scout`, `fuzzer`, and `gremlin` all write to the same surface node in sequence, so
closing it is the one verb they cannot each decide for themselves. A closed node
refuses `bd update --claim` ("issue not claimable: status closed") while its wisps
still parent fine, so the work looks scheduled and never runs.

| Agent | May set the node to | Must never |
|---|---|---|
| `sabot-scout` | `in_progress` while working, back to `open` when its artifacts are filed | `closed`; the fuzzer and gremlin still have to claim it |
| `fuzzer` | `in_progress`, back to `open` | `closed` |
| `gremlin` | `in_progress`, back to `open` after filing its `sab-coverage` wisp | `closed` |
| main thread | `closed`, at step 14 only | close a node before its `sab-coverage` wisp exists |

MUST Leave every surface node `open` or `in_progress` until step 14. Only the main thread closes one, and only after the coverage gate passes. A run in which surfaces were closed early spends the rest of the campaign working around a node its own agents cannot claim.
MUST Re-read a surface node's status immediately before spawning an agent against it, and reopen it (`bd update <node> --status open`) when something closed it. A node that self-closed twice in one run is the observed case, not the hypothetical one.

### A handoff you cannot query is not a handoff

MUST Verify your own wisps are discoverable by the documented query before returning. Run the receiving agent's exact discovery command (the `bd list --parent ... --label ...` above) and assert the count equals the number you filed. A mismatch means the label, the parent, or the flag is wrong, and the author fixes it. In one run the orchestrator had to relabel one surface's wisps and reconstruct another's by hand because both shipped invisible to that query.
MUST Report the verified count in your return, not the count you intended to file. "11 wisps filed, 11 returned by the gremlin's discovery query" is checkable; "11 harnesses written" is not.

### An out-of-lane finding goes into the graph, not into your reply

An agent reading its own globs regularly finds a real defect in a neighbouring
surface's tree. Dropping it loses it; filing it under your own surface misattributes
it.

MUST File an out-of-lane finding as a `sab-finding` wisp under the surface node whose scope globs contain the locus, with `metadata.found_by` naming your surface, and draw `relates-to` back to your own surface node. Do not tier it and do not investigate further. In one run two agents found five real defects outside their globs and dropped all five, which survived only because a human hand-carried them into the next dispatch.
MUST Cite an existing finding rather than re-filing it when your locus is already covered by another surface's wisp: `bd dep add <your-note> <their-finding> --type relates-to` and stop. Independent confirmation of someone else's finding is worth more as a citation on their wisp than as a duplicate row.

## Correlation edges

Parenthood scopes a wisp to its surface; a typed `bd dep` edge records how one wisp
produced another, so the correlation is traversable (`bd dep tree <bead>`) rather
than reconstructed from prose. Each agent draws the edge for the link it creates, at
the moment it files the wisp:

| Edge | From -> To | Drawn by | Meaning |
|---|---|---|---|
| `discovered-from` | finding -> harness | `gremlin` | this finding came out of running that harness |
| `discovered-from` | finding -> crash | `triager` | this finding is the minimized form of that crash |
| `caused-by` | crash -> harness | `gremlin` | that harness produced this crash |
| `relates-to` | chain finding -> each constituent | `challenger` | the chain is built from these findings |
| `validates` | regression test wisp -> finding | `hardener` | this test proves that finding is fixed |
| `supersedes` | re-run finding -> prior finding | `hardener` | the verification re-run replaced the original |

```
# gremlin, filing a finding a harness produced:
bd dep add <finding> <harness> --type discovered-from
# challenger, linking a chain to its constituents:
bd dep add <chain> <constituent> --type relates-to
```

MUST Draw the correlation edge when you file the wisp, since an edge added later is an edge usually never added. The report and the raw export traverse these edges to correlate a finding with whatever produced it, so a missing edge is a finding that reads as uncorrelated.
MUST Keep `bd dep cycles` clean after wiring. A correlation edge is a DAG edge; a cycle means a finding was linked as its own ancestor, which breaks traversal.
NOT Never use `blocks` for a correlation. `blocks` gates the ready queue, so a correlation drawn as a blocker would stall the wisp it merely annotates.

## State mapping

`bd set-state` owns the `state:` label dimension: each transition deletes the
prior `state:<value>` label, adds the new one, and emits an event bead as the
transition record.

| Enum state | Bead status | `state:` label | Set by |
|---|---|---|---|
| `pending` | `open` | `state:pending` | creator at `bd create` |
| `claimed` | `in_progress` | `state:claimed` | claim-holder after `bd update --claim` |
| `executed` | `in_progress` | `state:executed` | `gremlin` after a harness runs to its cap |
| `minimized` | `in_progress` | `state:minimized` | `triager` after the input shrinks |
| `tiered` | `in_progress` | `state:tiered` | `challenger` after the verdict |
| `patched` | `in_progress` | `state:patched` | `hardener` after the verification re-run |
| `reported` | `closed` | `state:reported` | main thread at report emit |
| `budget_exhausted` | `open` | `state:budget_exhausted` | `gremlin` when a harness hits its cap with coverage still growing |
| `invalid` | `blocked` | `state:invalid` | `gremlin` when a scanner or harness crashed rather than finding something |

```
bd set-state <bead> state=<name> --reason "<why>"
bd update <bead> --status <status>          # only where status changes
```

MUST Distinguish `budget_exhausted` from `reported`. The first says coverage was still growing when the clock ran out, which is a coverage gap the report has to state.
MUST Distinguish `invalid` from a clean result. A scanner that crashed found nothing because it never ran.

## Finding wisp shape

Every finding carries both axes plus its locus, written as metadata so the report
generator reads structure rather than prose:

```
FINDING=$(bd create "finding: <one-line claim>" --parent <surface> --labels sab-finding,sab-audit --no-inherit-labels --json \
  --metadata '{"run_id":"run-<id>","tier":"PROVEN","by":"challenger","source":"synthesized-rule","impact":"HIGH","locus":"src/auth/token.rs:88","surface":"code","node":"<surface node bead>","cwe":"CWE-190","repro":"<abs path to minimized input>","path":"handle_post -> parse_body -> alloc @ api.rs:41","evidence":"<abs artifact path or exact command>","control_passed":true,"dedup_key":"code:src/auth/token.rs:88:CWE-190","root_cause":"unchecked arithmetic at the IPC boundary","not_executed_reason":null}' \
  | jq -r '.id')
```

This blob is the report. Step 14 renders these fields; a field left off the wisp is a
column the report cannot fill, and prose in an agent's reply is discarded at the end
of the session.

| Field | Values |
|---|---|
| `tier` | `PROVEN` (repro or traced exploit path) · `REACHABLE` (path traced, no repro) · `HARDENING` (no path, or tool-only) · `REFUTED` (challenger disproved it) |
| `by` | who set the tier: `challenger` (an independent pass) or `self` (the finder tiered its own finding inline). The report headlines a `self` tier as unchallenged. |
| `source` | what produced the finding: `synthesized-rule` · `stock-pack` · `harness` · `read`. The report's provenance table groups on it, so a stock-only sweep is visible rather than presented as an audit. |
| `impact` | `CRITICAL` · `HIGH` · `MEDIUM` · `LOW`, calibrated per surface doc |
| `locus` | `file:line`, always |
| `path` | the reachability chain the gremlin recorded, `entry -> ... -> sink` with a `file:line` per hop, so the challenger verifies the recorded path rather than re-tracing it |
| `repro` | absolute path to the minimized input, when one exists |
| `node` | the surface node bead this finding belongs to. `--parent` already sets it, and the field makes it readable from the finding alone by a rollup that queries on `run_id` |
| `evidence` | one absolute artifact path or one exact command. The report's evidence column reads this field, so a finding without it is HARDENING at best |
| `control_passed` | `true` · `false` · `null` (no control applies). `false` means the locus is UNTESTED, so the challenger caps it and the report lists it under NOT-EXECUTED |
| `dedup_key` | `<surface>:<locus>:<class>`, lowercased. a key appearing on more than one wisp marks the same finding found twice, which is independent confirmation rather than two findings |
| `root_cause` | one phrase naming the shared defect, identical across every finding sharing it. The grouping pass and the synthesis step both read this field, and neither can group on prose |
| `not_executed_reason` | `null` on a real finding. On a placeholder wisp standing for an unexercised dimension, one of the gap reasons in `report-template.md` |

MUST Fill every field above on every finding wisp, using `null` where one does not apply rather than omitting the key. A missing key and a deliberate `null` read the same to the report generator, so an omission becomes a silent blank column.
MUST Stamp `dedup_key` and `root_cause` at creation, by the agent that filed the finding. The finder knows the class; a later pass reconstructing it from a one-line title guesses.
MUST Stamp `by=self` when the agent that found a finding also tiered it, and `by=challenger` when an independent pass did. The report cannot tell a self-tier from a challenged one otherwise, so a self-judged finding reads as independently confirmed.
MUST Record `source` on every finding, since a report whose findings are all `source=stock-pack` did no recon, and the provenance table can only say so when the field is on the wisp rather than in prose.

MUST Never delete a finding wisp. A refuted finding is stamped `tier=REFUTED` with the refutation in a comment, then closed with reason `refuted`, because a deleted finding cannot be re-examined when the code changes.
MUST Re-read a finding wisp after stamping a tier. A tier that failed to write leaves the report claiming evidence it does not have.

## Events and audit

Every material verb (`authored executed crashed minimized tiered refuted patched
gap`) is recorded by the acting agent, with identity via `BEADS_ACTOR`, as two
writes:

```
bd audit record --actor <actor> --kind tool_call --tool-name brk.<verb> \
  --issue-id <bead> --exit-code 0
bd comment <bead> "<VERB> <surface> field=… output_ref=<abs artifact path>"
```

Full harness source, scanner JSON, and crash inputs go to
`<artifacts>/<surface>-<verb>-<n>.<ext>`; the comment carries the absolute path
rather than the content.

## Reading the run

Surface nodes are direct children of the epic, so `--parent <epic>` reaches them.
Harnesses, findings, crashes, and coverage records are grandchildren (children of a
surface node), so `--parent <epic>` never returns them on bd 1.1.2; roll them up by
their own label scoped to the run with `--metadata-field run_id=<id>`.

| Question | Command |
|---|---|
| campaign status | `bd list --label sab-surface --parent <epic> --all --json` |
| all findings by tier | `bd list --label sab-finding --metadata-field run_id=<id> --all --json` then group by `metadata.tier` |
| a project's own backlog, audit excluded | the project's query plus `--exclude-label sab-audit`, which is why every campaign bead carries it |
| audit beads missing the audit label | `bd list --metadata-field run_id=<id> --all --json` filtered to those whose `labels` lack `sab-audit` |
| one finding's story | `bd show <bead> --json` with `bd comments <bead>` |
| unexecuted harnesses | `bd list --label sab-harness --metadata-field run_id=<id> --status open --json` |
| coverage record per surface | `bd list --label sab-coverage --metadata-field run_id=<id> --all --json` |
| coverage gaps | harnesses and findings carrying `state:budget_exhausted` or `state:invalid`: `bd list --metadata-field run_id=<id> --all --json` filtered on the `state:` label |
| resume after crash | in-flight = `bd list --metadata-field run_id=<id> --status in_progress --all --json`; agent handle = bead `assignee` |
| stamping gate | `sab-audit` is set on every campaign bead AND `non-work` on every non-defect record AND every REFUTED finding is `closed` AND every finding's priority matches the tier-impact table. Blocks NOTHING. Each condition is record hygiene that one `bd update` fixes, and none of it is evidence about the target |
| coverage gate | `bd dep cycles` clean AND every detected surface node has a `sab-coverage` record AND no `sab-harness` wisp left `open`, `blocked`, or `in_progress` AND every `sab-finding` carries a `tier`. Blocks CLOSING A SURFACE NODE, never the report: an unmet condition here is a coverage gap, which is the report's subject matter |

MUST Emit the report whatever the coverage gate says. An unrun harness, a missing coverage record, and an untiered finding are the report's SUBJECT, so a gate that withheld the report until they were resolved would withhold it exactly when it is most worth reading. The report states each one as a gap; step 15 is where a gap gets fixed, and only on explicit approval.
MUST Fix a stamping-gate failure rather than reporting it. A missing label, a wrong priority, and a REFUTED finding left open are hygiene on the record and cost one `bd update` each; none of them is evidence about the target, so none belongs in the NOT-EXECUTED register.

MUST Roll up grandchildren with `--metadata-field run_id=<id>`, never `--parent <epic>`. On bd 1.1.2 `--parent` returns direct children only, so an epic-parent query for findings or harnesses returns an empty set and the coverage gate passes over unrun, untiered work.
MUST Gate close-out on a `sab-coverage` record existing for every detected surface. A gremlin that died before writing coverage leaves a surface untested, and without this check the report omits it and reads as clean.
MUST Drive that gate from the SURFACE-NODE list, never from the coverage-wisp list. Both directions look identical when they pass and only one of them can fail:

```sh
# WRONG: iterates the records that exist, so a node with no record is never visited
bd list --label sab-coverage --metadata-field run_id="$RUN" --all --json | jq -r '.[].parent'

# RIGHT: iterates the nodes that MUST have one, and names the ones that do not
comm -23 \
  <(bd list --label sab-surface --parent "$EPIC" --all --json | jq -r '.[].id' | sort) \
  <(bd list --label sab-coverage --metadata-field run_id="$RUN" --all --json | jq -r '.[].parent' | sort)
```

Any id the second form prints is a surface with no coverage record. Empty output is the only pass. Measured: one campaign's web node reached the gate with 9 findings and no coverage wisp while all 20 other nodes had one, and the record-driven form reported 20 of 20 covered.
MUST Count a `blocked` (INVALID) harness as unfinished at the gate, not only an `open` one, since an INVALID harness is an untested entry point that would otherwise pass a gate keyed on `open` alone.

## Raw export: the graph IS the persistence

The run graph is the campaign's single store, so no agent writes a parallel findings
file. A wisp IS a bead (a `task` bead with a `sab-*` label and, for coordination
wisps, `non-work`), so `bd export` emits every one with its metadata, labels,
correlation edges, and comment bodies. `scripts/report-json.py` wraps that export.
It filters to one run and reshapes each kept bead into the schema below, dropping the
fields a report never uses.

```
report-json.py --epic <epic-id> -o <artifacts>/run-<id>.json
```

The script selects the run by **descent from the epic** (walking `parent-child`
edges, with the hierarchical bead id as a fallback), not by a `run_id` filter. The
structure is the scope: a finding belongs to the run because it descends from the
epic, so a wisp whose `run_id` an agent forgot to stamp is still collected rather
than silently dropped. The script flags any such wisp in a `stamping_gaps` list, so
the missing stamp is visible instead of costing a finding. (`--run-id <id>` still
works as an alias that resolves the epic.)

The same graph carries work between agents, since each of `sabot-scout`, `fuzzer`,
`gremlin`, `triager`, and `challenger` reads its inputs from the wisps a prior agent
filed (see Handoff chain). Correlation needs no join table: the parent edge places
each wisp on its surface under the epic, and the typed edges (`discovered-from`,
`caused-by`, `relates-to`) link a finding to the harness, crash, or chain it came
from. The `run_id` stamp is a convenience for live `bd list` queries, not the
report's source of truth.

### Report schema

`report-json.py` emits one object: `run_id`, `epic`, and the arrays `surfaces`,
`harnesses`, `crashes`, `findings`, `coverage`, plus a `summary` (`by_tier`,
`by_impact`, `coverage_gaps`). Each record keeps only the report-relevant fields:

| Record (by label) | Fields the script keeps |
|---|---|
| epic (`issue_type=epic`) | `run_id`, `target`, `base_sha`, `budget`, `artifacts` |
| `sab-surface` | `surface`, `scope`, `parent` |
| `sab-harness` | `entry_point`, `runner`, `harness_path`, `input_shape` |
| `sab-crash` | `input_path`, `stack_hash` |
| `sab-finding` | `tier`, `by`, `source`, `impact`, `locus`, `path`, `cwe`, `repro`, plus `edges` to its harness/crash/constituents |
| `sab-coverage` | `scanners_run`, `scanners_skipped`, `harnesses_run`, `harnesses_total` |

MUST Generate the report JSON with `report-json.py`, not a hand-written `bd export` filter. The script owns the schema, so a report never drifts from the shape a machine reader expects.

Only the oversized payloads stay outside the graph, cited by absolute path in a bead
comment. A bead holds the structure and the pointer; the file holds the bytes, so
every query stays small while the blobs remain one `cat` away. Those payloads are the
recon document, the scanner JSON, the harness source, and the crash-input binaries.

MUST Emit the raw `run-<id>.jsonl` from `bd export` alongside the report, since it is the parseable form of everything the markdown summarizes and the only export a later campaign can diff against.
MUST Read the report from the export against the schema above, not from the agents' replies, so the report matches the durable graph and every finding carries its edges.
NOT Never write a finding, tier, or coverage fact to a side file the graph does not also hold. A fact that lives only in a file breaks correlation and dies outside the run, which is the failure the graph exists to prevent.

## Resume

A campaign resumes without re-running finished work. Every list below scopes to the
run with `--metadata-field run_id=<id>`:

1. Read the epic's `budget` metadata rather than re-asking the user, since the
   approved budget is durable.
2. Hand a fresh `gremlin` every harness wisp that is `open`, or `blocked` with
   `state:invalid` (a crashed scanner or unbuilt harness the previous run never
   completed), or `open` with `state:budget_exhausted` (ran out of clock with
   coverage climbing). Skip any carrying `state:executed`.
3. List crash wisps still `open` and hand them to a fresh `triager`.
4. List finding wisps with no `tier` and hand them to `challenger`.
5. Report from the graph.

MUST Include `state:invalid` and `state:budget_exhausted` harnesses in the resume set. An INVALID harness is `blocked` rather than `open`, so a resume that lists only `open` harnesses silently drops the exact entry points the previous run failed to test.
MUST Verify a claim before stealing it. A wisp `in_progress` with a live assignee belongs to a running agent; treat it as dead only when the assignee's session is gone.
NOT Re-running an already-executed harness wastes the budget and produces duplicate crash wisps, so check `state:executed` before dispatch.

### `state` is read from the label, not only from metadata

`bd set-state <id> state=<value> --reason "<why>"` is the documented path in the state
table above. It writes a `state:<value>` LABEL plus an event bead and touches no
metadata, so a reader that looks only at metadata sees nothing.

`report-json.py` reads both, label first. Measured: 161 harness wisps released with
`bd set-state` carried the label and no metadata `state`, and every gap check that reads
`state` counted all 161 as unstamped -- 161 false gaps in one campaign's report, on
records whose agent had followed this file exactly.

MUST Set operational state with `bd set-state`, not with a metadata stamp. It is atomic, it records an event bead as the source of truth, and it removes the previous value of the same dimension rather than leaving two. A hand-written metadata `state` is what `set-state` exists to replace.
