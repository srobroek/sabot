"""Every ledger command the package prescribes must survive a campaign-sized store.

Two bd defaults silently cut a campaign down, and both shipped in the copy-paste
commands the agents run:

1. `bd list` returns 50 rows unless told `--limit 0`, and says nothing when it
   truncates. "All findings by tier" over a 388-finding campaign read as 50 findings,
   and the challenger's `uniq -d` dedup compared 50 of 383.
2. `bd create --parent` copies the parent's labels onto the child. Every surface node
   carries `non-work` and `sab-surface`, so a finding filed under one dropped out of the
   project's backlog: 51 of 388 findings in one campaign carried a `non-work` no agent
   wrote. A regression wisp parented to its finding inherited `sab-finding` and counted
   as a second finding.

The commands live in prose, briefs, and the formula, so this reads them as text: every
`bd list` must pass `--limit 0`, and every `bd create ... --parent ... --labels` must
pass `--no-inherit-labels`. No bd, no network.

Run: pytest packages/sabot/tests/test_ledger_queries.py
"""

import re
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
SKILL = PKG / ".apm/skills/sabotage"
DOCS = sorted(
    [SKILL / "SKILL.md"]
    + list(SKILL.glob("references/**/*.md"))
    + list(SKILL.glob("formulas/*.toml"))
    + list((PKG / ".apm/agents").glob("*.agent.md"))
)

PLACEHOLDER = re.compile(r"<[^<>\n]*>")  # `<surface-bead>`: its `>` is not a redirect
TERMINATOR = re.compile(r"`|\||>|;|\)|&&")


def commands(text: str, verb: str) -> list[str]:
    """Each `bd <verb>` invocation in a doc, from the verb to where the command ends.

    Wrapped lines are joined first, because an inline span or a shell continuation
    carries one command across several source lines. A command ends at a closing
    backtick, a pipe, a redirect, `;`, `)`, or `&&`.
    """
    flat = re.sub(r"\n[ \t]*", " ", PLACEHOLDER.sub("X", text))
    out = []
    for match in re.finditer(rf"\bbd {verb}\b", flat):
        rest = flat[match.start():]
        end = TERMINATOR.search(rest)
        out.append((rest[: end.start()] if end else rest).strip())
    return out


def is_query(cmd: str) -> bool:
    """A real `bd list` query, as opposed to a bare mention of the verb or the
    documented `--labels` (plural) anti-pattern."""
    return cmd != "bd list" and "--labels" not in cmd


def is_child_create(cmd: str) -> bool:
    """A `bd create` that makes a child and names its labels. `bd create --parent`
    alone is prose describing the inheritance default."""
    return "--parent" in cmd and "--labels" in cmd


def _all(verb: str):
    for path in DOCS:
        for cmd in commands(path.read_text(), verb):
            yield path.relative_to(PKG), cmd


def test_every_bd_list_query_passes_limit_zero():
    bad = [f"{p}: {c}" for p, c in _all("list") if is_query(c) and "--limit 0" not in c]
    assert not bad, "bd list truncates at 50 rows without --limit 0:\n" + "\n".join(bad)


def test_every_child_create_passes_no_inherit_labels():
    bad = [
        f"{p}: {c}" for p, c in _all("create")
        if is_child_create(c) and "--no-inherit-labels" not in c
    ]
    assert not bad, "bd create --parent copies the parent's labels:\n" + "\n".join(bad)


def test_the_sweep_still_sees_the_commands():
    """A sweep whose extractor silently stops matching passes forever. These floors
    are below today's counts (21 queries, 9 child creates) and well above zero."""
    queries = [c for _, c in _all("list") if is_query(c)]
    creates = [c for _, c in _all("create") if is_child_create(c)]
    assert len(queries) >= 15, queries
    assert len(creates) >= 7, creates


@pytest.mark.parametrize("text, verb, flagged", [
    # the finding create that shipped, wrapped across a shell continuation
    ('F=$(bd create "finding: x" --parent <surface-bead> --labels sab-finding,sab-audit --json \\\n'
     "  --metadata '{\"locus\":\"<file:line>\"}' | jq -r '.id')", "create", True),
    ('F=$(bd create "finding: x" --parent <s> --labels sab-finding --no-inherit-labels --json', "create", False),
    # an inline span wrapped across two prose lines
    ("with `bd list --parent <surface> --label\n   sab-harness --status open --json` (the flag", "list", True),
    ("    bd list --label sab-crash --all --limit 0 --json > <artifacts>/crashes.json", "list", False),
    # a redirect after the command does not hide a missing flag
    ("    bd list --label sab-crash --all --json > <artifacts>/--limit 0.json", "list", True),
])
def test_the_extractor_reads_wrapped_and_redirected_commands(text, verb, flagged):
    (cmd,) = commands(text, verb)
    if verb == "list":
        assert (is_query(cmd) and "--limit 0" not in cmd) is flagged, cmd
    else:
        assert (is_child_create(cmd) and "--no-inherit-labels" not in cmd) is flagged, cmd


@pytest.mark.parametrize("text", [
    "a hook truncates `bd show`/`bd list` and spills the body",
    "`bd list --labels sab-harness` returns nothing or errors",
    "`bd create --parent` copies the parent's labels onto the child by default",
])
def test_prose_mentions_are_not_commands(text):
    for verb in ("list", "create"):
        for cmd in commands(text, verb):
            assert not (verb == "list" and is_query(cmd)), cmd
            assert not (verb == "create" and is_child_create(cmd)), cmd
