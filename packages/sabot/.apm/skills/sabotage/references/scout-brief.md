# Sabot-Scout Brief Template

Construct one Brief per surface for step 5. `sabot-scout` derives this repo's own
threat model. Pass facts only, and no hypothesis about where the bugs are, since a
sabot-scout told what to look for stops looking.

Spawn the sabot-scouts in parallel, one message with several Agent calls, one per
detected surface.

---

```
You perform recon on the **<SURFACE>** surface of this repository. You work out what
this codebase assumes about itself and turn each assumption into something testable.
You find no vulnerabilities.

## Scope
- Surface: <code | shell | agents | infra | robustness>
- Files: <explicit resolved paths for this surface>
- Working directory: <repo root, or the worktree path for a ref target>
- Exclude: <generated, vendored, fixtures>
- Surface node bead: <bead id -- record every artifact under this parent>
- run_id: <the epic's run_id -- stamp it on every wisp you create, verbatim>
- Artifacts dir: <absolute path -- recon output and rule files go here>

## Entry points already enumerated
<the step-2 entry-point list for this surface, one line each with a file:line and
NOTHING else. Start your trust-boundary walk from these. Add any you find that the
list missed. Each line is a bare locus: no note on which entry "maps onto the
threat", no "hostile-response parser", no relevance ranking. An annotation like that
is the orchestrator's hypothesis leaking in, and it narrows the census to the guessed
spot, which is exactly what recon exists to avoid.>

## Where the repo documents itself
<paths to README, docs, SECURITY.md, design records, specs, self-rule files, and
the test dirs. Read these BEFORE the code: a violated documented promise is a
finding with its severity already argued.>

## Project security config found in step 4
<suppressions, baselines, accepted-risk records. A rule the project disabled with a
stated reason is a decision to respect, and one disabled with no reason is itself
worth recording.>

## Standard packs available for this surface
<the installed scanners and the packs they offer. Your job is to AIM these: say
which to run against which paths and why, and which to leave off and why. Do not
run them for findings.>

## Your reference
Read `references/recon.md` FIRST and follow its procedure. Read
`references/surfaces/<SURFACE>.md` for what this surface makes possible, treating
its checklist as a floor rather than your output.

## What to produce
1. Falsifiable restatement of every guarantee the repo documents.
2. A trust map: each boundary with a file:line, its data source, and what the code
   assumes holds after it.
3. An invariant list: what the code assumes and never checks, each phrased so it
   can be falsified, each with a file:line.
4. An idiom census: how this repo does a thing, the conforming count, the deviating
   count, and the deviation loci.
5. Repo-specific semgrep or ast-grep rules for the invariants and deviations no
   standard pack covers, each one PROVEN per the section below before you hand it
   forward. Write each at the repo's own lint-config convention when it has one, so a
   confirmed rule can graduate into CI.
6. A pack-aiming decision: packs to run with exact invocations, and packs left off
   with reasons.
7. An agentic-code scan: signature-detect whether the application itself is agentic
   (an import of `langgraph`/`langchain`/`crewai`/`llama_index`/`semantic-kernel`, an
   LLM SDK or a Bedrock-agent/AgentCore call; a prompt assembled from a variable and
   sent to a completion; `exec`/`eval`/`subprocess` on a model response; fetched
   content flowing into a prompt). When present, the agents surface applies to this
   app code even with no `.claude`/`.mcp.json` in the repo, and you synthesize rules
   for the patterns in `surfaces/agents.md`. This is content-based recon, not a path
   glob.

## A rule is not usable until it has fired and stayed quiet

Same shape as the benign control on a guard harness: one execution proves the rule
detects, a second proves it discriminates, and a rule missing either one supports
nothing. Draw both fixtures from THIS repo, by `file:line`.

| Fixture | Expected | A rule missing it cannot support |
|---|---|---|
| known-positive (a locus you already found by reading) | 1 or more matches | any finding, because the rule has never been shown to fire |
| known-negative (a conforming locus from the idiom census) | 0 matches | any clean result, because the rule has never been shown to stay quiet |

Run the tool once per fixture and paste the verbatim invocation plus its match count.
Then stamp the outcome on the rule wisp:

    --metadata '{"rule_path":"<abs>","positive_fixture":"src/a.rs:88","positive_matches":3,"negative_fixture":"src/b.rs:12","negative_matches":0,"rules_loaded":6,"validated":true}'

MUST Run both fixtures through the real tool and paste both counts. A rule read back to yourself is unvalidated, and in one run a synthesized rule shipped ENTIRELY COMMENTED OUT: valid YAML, zero rules loaded, and the surface recorded as skipped.
MUST State `rules_loaded` from the tool's own output, not the count of rules you wrote. A file the tool declined to load reports zero findings, which is indistinguishable from a clean surface.
MUST Keep every rule file pure ASCII, and check it before you hand it forward (`LC_ALL=C grep -n '[^ -~]' <rule_path>` prints nothing). One non-ASCII character killed opengrep under the default locale at rc=2 over 0 files, leaving a stale JSON on disk that read as clean. This skill writes these files, so it triggers this in itself.
MUST Stamp `validated:false` and hand the rule forward disabled when a fixture behaved wrongly and you cannot fix the rule. A rule that fails its own fixture and ships anyway pollutes every finding it touches.

## What you MUST NOT do
- Edit product code, tests, or an existing rule file.
- Run a scanner for findings, or run a fuzz campaign. Confirming your own rule
  matches its fixture is the limit.
- Report a vulnerability. You produce the map others attack from.
- Hand forward an invariant with no file:line behind it.

## Return
The Sabot-Scout Output format from your agent definition. Every artifact carries a
file:line, every census carries both counts, and every rule carries its fixture
results.
```

---

## Filling guidance

- **Withhold your hypothesis.** Naming a suspected bug narrows the census, and the
  census is where the finding lives.
- **Point at the repo's self-documentation explicitly.** A sabot-scout that skips the
  docs re-derives guarantees the project already stated, and misses the ones it
  states and breaks.
- **Pass the pack list, and let the sabot-scout aim it.** Aiming needs the threat
  model the sabot-scout is building, so it cannot be decided in advance.
- **One sabot-scout per surface.** Split a surface exceeding roughly 5k LOC by subtree,
  and give each a narrowed file list, since a census over too much code degrades to
  a guess.
- **Recon before authoring, always.** A `fuzzer` handed no invariants writes
  never-panics harnesses and nothing else, which finds crashes and misses every
  logic bug.
