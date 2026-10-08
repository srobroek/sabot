# Surface Template

Copy this to add a surface. Fill every section, add a row to `index.md`, and add
any new tool to `tooling.md` plus the surface `Dockerfile` (bake it into the image,
with a pinned version), to that image's `IMAGE_TOOLS_<image>` list in
`scripts/install-tools.sh`, and to the matching row of the assert table in
`isolation.md`, since a tool missing from the manifest is never probed. Nothing else
in the package needs to change.

Target length: under 200 lines. A surface doc is a checklist a `gremlin` works
through, not an essay.

---

## Detect

How the step-2 stack detection recognizes this surface: file globs, filenames,
shebangs, manifest keys, directory conventions.

## Tools

One row per tool. **Tier** is `default-on` or `opt-in`, and an opt-in row states
why it is off. **Class** is `local`, `relational`, `global`, or `baseline` per
`tooling.md`. The **Run recipe** must be runnable as written.

| Tool | Tier | Class | Run recipe | Catches | Overlap |
|------|------|-------|-----------|---------|---------|
| | | | | | |

## Attack checklist

The `gremlin`'s working list. Each entry names the attack, where it hides, and the
observable that confirms it. Order by hit rate, highest first.

| # | Attack | Where it hides | Confirm by |
|---|--------|----------------|-----------|
| 1 | | | |

## Harness patterns

How to fuzz this surface: the runner and the entry point shape, an example input,
and the invariant a crash violates. Point at `harnesses.md` for the generic form
and state only what is specific here.

## Impact calibration

What CRITICAL, HIGH, MEDIUM, and LOW mean on this surface, so severity stays
comparable across runs. Name at least one finding class per level.

## False-positive traps

Patterns that look like findings and are not, with the observable that clears
each. This section is what keeps the report honest.
