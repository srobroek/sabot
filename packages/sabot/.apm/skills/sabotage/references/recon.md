# Recon: derive this repo's threat model before attacking it

The step that makes the rest worth running. A generic checklist finds generic
bugs, and the interesting ones live in whatever this repo believes about itself.
Recon extracts those beliefs so later steps can attack them.

Nothing here is a fixed list of vulnerabilities. It is a procedure for finding out
what this codebase assumes, then turning each assumption into something testable.

## What recon produces

Four artifacts, all recorded on the run epic and handed to the fuzzers:

| Artifact | Shape | Feeds |
|---|---|---|
| Trust map | every boundary where data crosses from less trusted to more trusted, with a `file:line` | the attack plan for every surface |
| Invariant list | what the code assumes and never checks, phrased as a falsifiable claim | the harnesses and the synthesized rules |
| Idiom census | how this repo does a thing, and every place that deviates | the deviation-hunting rules |
| Repo-specific rules | semgrep or ast-grep rules written for THIS codebase | the scan in step 8 |
| Input-shape map | each entry point's actual input protocol (raw bytes, single JSON, JSONL, msgpack, protobuf, argv, env, a schema or grammar the repo ships) | the generator choice in `fuzz-tools.md` |

## Procedure

### 1. Read what the repo says about itself

Before reading code, read its claims. A violated documented promise is a finding
with the severity already argued for you:

| Source | What to extract |
|---|---|
| README, docs | promised guarantees; supported input ranges; stated limits |
| `SECURITY.md`, threat model docs | what the project says is in and out of scope |
| Design records and specs | invariants a decision depends on |
| Project self-rules or a contributing guide | rules the project holds itself to, since a violated self-rule is a finding |
| Existing tests | what the authors thought could break, and the shape of a legitimate input |
| Commit history on the target files | past incidents, and any fix that landed without a regression test |
| Issue tracker or bead store | known-broken areas, and abandoned hardening work |

MUST Extract at least one falsifiable claim per documented guarantee, since "handles malformed input gracefully" is testable only once restated as "returns an error rather than panicking on any byte sequence".

### 2. Map the trust boundaries

Walk inward from every place data enters, and record where it stops being
checked. The boundary matters more than the sink, because a sink behind a real
check is not a finding:

1. List every entry point (per `targeting.md`).
2. For each, follow the data until it is validated, transformed into a safe type,
   or reaches an operation with consequences.
3. Record the boundary: where validation happens, or where it should have.
4. Note which entry points share a validator, since a single validator is a single
   point of failure worth attacking hard.

MUST Record a `file:line` for each boundary, plus what the code assumes is true after it.
MUST Record each entry point's input shape, plus any schema, `.proto`, or grammar the repo already ships, since the shape picks the generator and a wrong pick spends the whole budget failing at the parser.
MUST Note every entry point whose data reaches a consequence with no boundary at all, because that is the shortest path to a PROVEN finding.

### 3. Census the repo's own idioms

The highest-yield finding class in any mature codebase is the one place that does
it differently. Establish the pattern, then hunt the exception:

| Ask | Then find |
|---|---|
| How does this repo validate input? | the handler that skips the shared validator |
| How does it handle errors? | the path that swallows instead of propagating |
| How does it authorize? | the endpoint missing the check its siblings have |
| How does it build queries or commands? | the one that interpolates while the rest parameterize |
| How does it bound resources? | the read with no cap where its neighbours have one |
| What does its safe wrapper look like? | the caller that bypasses the wrapper |
| How do its hooks decide? | the guard whose default differs from the others |

MUST Count both sides. "3 of 47 handlers skip the auth decorator" is a finding; "a handler lacks a decorator" without the census is noise.
DEFAULT Derive the census with a tool where one fits: `ast-grep` for a structural pattern, `rg` with a count for a textual one, `opengrep` with a rule written on the spot.

### 4. Synthesize repo-specific rules

Turn each invariant and idiom into an executable rule, so the finding is
reproducible and the check survives this campaign:

```yaml
# Derived in recon, not shipped: this repo parameterizes every query through
# db.q(). This rule finds the callers that do not.
rules:
  - id: repo-raw-execute-outside-wrapper
    languages: [python]
    severity: ERROR
    message: Query built outside db.q(), which is this repo's only escaping path.
    patterns:
      - pattern: $CONN.execute($SQL, ...)
      - pattern-not-inside: |
          def q(...):
              ...
```

MUST Write the rule against the invariant discovered here rather than against a generic pattern, since a rule that encodes this repo's own contract has a false-positive rate the generic ruleset cannot match.
MUST Validate every synthesized rule before use, with `opengrep --validate` or `ast-grep scan --dry-run`, because an invalid rule matches nothing and looks clean.
MUST Prove each rule fires on a known-positive and stays quiet on a known-negative, both drawn from this repo by `file:line`, and stamp both counts on the rule wisp. Validation is a precondition of the rule being usable: an unfired rule supports no finding, and an untested-quiet rule supports no clean result. See `scout-brief.md` for the fixture table and the stamp.
MUST Read `rules_loaded` out of the tool's own output and compare it against the number of rules in the file. A rule that parses and loads zero, which is what a fully commented-out rule file does, reports zero findings and reads as clean.
MUST Keep rule files pure ASCII, verified with `LC_ALL=C grep -n '[^ -~]' <file>`. One non-ASCII byte aborted opengrep at rc=2 over 0 files while a stale result JSON stayed on disk.
MUST Write synthesized rules into the artifacts dir and list them in the report, since they are the campaign's most reusable output.
DEFAULT Prefer `ast-grep` for a structural deviation, and `opengrep` when the rule needs dataflow or several languages.

### 5. Aim the standard rulesets

Use every mature ruleset available: the semgrep rules baked into the image at
`/opt/sabot-db/semgrep-rules/<lang>`, bandit's and gosec's built-ins, clippy's lint
groups. These are well-tested detectors and rewriting them wastes the campaign's
time. The package doesn't ship generic rules of its own, because a hand-maintained
generic rule duplicates a pack and can rot silently.

Name the baked path, never the registry shorthand. `p/rust`, `p/javascript`, and
`--config auto` resolve over the network, so under `--network none` they exit
`OG_RC=2` having scanned nothing, and a rule aimed by recon at a pack that never ran
measures nothing at all. A curated pack with no baked equivalent (`p/trailofbits`)
belongs to the network stage; see `references/network-stage.md`.

What recon builds is the **harness around them**. It decides which packs run
against which paths, which of their findings matter here, which of their rules this
repo already decided against, and which repo-specific rules fill what no pack
covers. The tools are borrowed, and the aim is derived.

| Layer | Source | Recon's job |
|---|---|---|
| Standard packs | semgrep registry, bandit, gosec, clippy groups | choose the packs the detected stack and threat model justify, and say why the rest are off |
| Synthesized rules | written here, from this repo's invariants | cover what no pack knows: this repo's own contracts and wrappers |
| Triage | recon's trust map | decide which pack findings sit on a real path and which are HARDENING |

MUST Select packs from what recon found rather than running everything, since an unaimed pack floods the report and the reader stops distinguishing signal from volume.
MUST Treat a pack finding as HARDENING until recon's trust map places it on a path, because a generic match carries no knowledge of this repo.
MUST Drop a pack rule the project has deliberately decided against, and record the decision, since re-reporting it costs credibility.
NOT A campaign whose findings all came from stock packs did no recon. Say so in the report rather than presenting it as a completed audit.

## Rule lifecycle: from campaign artifact to repo regression guard

A synthesized rule that produced a confirmed finding is worth more than the finding
itself. The finding is one bug, and the rule is the whole class, checked on every
commit from then on.

| Rule outcome | Disposition |
|---|---|
| Produced a PROVEN or REACHABLE finding | propose graduation at the step-15 approval; on approval the hardener writes it into the repo's own lint config so CI enforces it |
| Produced only HARDENING findings | keep it in the artifacts dir, and offer it as an opt-in in the report |
| Matched nothing on a repo where the invariant is true | keep it in the artifacts dir as a guard against the invariant being broken later |
| Failed its own known-positive test | INVALID, so record it and never report its zero matches as clean |

Graduating a rule means placing it where the project's existing tooling picks it
up, rather than in a directory only this skill reads. The project's lint config is
product configuration, so recon only records the destination below; the write happens
in step 15, under the approval that names it (`hardener-brief.md`, Lint-config edits):

| Repo already has | Graduate to |
|---|---|
| `.semgrep/` or `semgrep.yml` | a new rule file beside the existing ones |
| `ast-grep` with `sgconfig.yml` | the configured `ruleDirs` path |
| a CI security job | the ruleset that job already invokes |
| pre-commit hooks | a `opengrep` or `ast-grep` hook entry with the rule file |
| no security lint config at all | propose one path in the report, and let the user decide rather than inventing a convention |

MUST Propose every rule behind a confirmed finding for graduation, with its destination from the table above, since a fixed bug whose detection rule was thrown away is a bug free to return. Write it into the project's config only under a step-15 approval that names it; recon and every step before 15 write rules to the artifacts dir alone.
MUST Pair a graduated rule with the regression test for the same finding. The test proves this instance is fixed, and the rule prevents the next instance.
MUST Leave a graduated rule uncommitted and list it in the report, because committing is the user's call.
MUST Keep a rule that matched nothing when its invariant is real, since its value is catching the day someone breaks the invariant.
NOT Never graduate a rule that failed its own fixture test. A rule nobody proved works becomes a permanent false sense of coverage in CI.
MUST Validate a rule by the invocation the gremlin will actually use, over the target tree, and record that exact command beside the fixture counts. A fixture proving the PATTERN matches proves nothing about the rule as shipped, because a scoping key can suppress every match while the pattern stays correct. Measured on `fits-header`: three infra rules were reported fixture-validated at 6/2/1 positives, and the gremlin's mandatory re-verification got zero from all three, including on those same fixtures. A `paths: include: "*.github/workflows/*.yml"` glob was eating every match; stripping it restored exactly recon's counts. The rules were sound and shipped inert, and only the re-verification rule stopped that reading as a clean surface.

## Handing recon forward

Record each artifact on the run epic, and pass them into every Brief:

```
bd comment <epic> "RECON trust_boundaries=<n> invariants=<n> idioms=<n> rules_synthesized=<n> output_ref=<abs path>"
```

The fuzzer Brief carries the invariant list, since an invariant is what a harness
asserts. The gremlin Brief carries the trust map and the synthesized rules, since a
boundary is what an attack crosses.

MUST Recon before authoring. A fuzzer given no invariants writes never-panics harnesses and nothing else, which finds crashes and misses every logic bug.
MUST Re-run recon when the target changes. A trust map derived from a different scope is worse than none, because it directs attention to the wrong boundary.
