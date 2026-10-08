#!/usr/bin/env python3
"""Reject invocations that are measured to fail open. Runs over the skill tree, or a recipe.

    lint-recipes.py PATH [PATH...] [--json] [--include-prose]

Each rule below is an invocation that a campaign copied verbatim and that returned a clean
result while running nothing, or ran less than it reported. Every one was measured. The
lint exists because the rule forbidding it already existed in prose and was violated
anyway.

WHAT COUNTS AS A RECIPE. Only text that can be copied and run: fenced code blocks in
Markdown, the code spans in a table column headed as a recipe (`Run recipe`, `Invocation`,
`Command`), the code spans of a MUST/SHOULD instruction, and non-comment lines in
`.sh`/`.py`. Reference prose has to QUOTE a forbidden invocation in order to forbid it, so
a prohibition (`MUST NOT`, `NEVER`, `NOT`, `Do not`) and any other table row or sentence
saying "never do X" is not an instance of X, even inside a fenced spawn prompt. Flagging
those made the first real-tree pass 54 violations of which 40 were the documentation of
the rules themselves -- and a lint that is mostly noise gets suppressed rather than fixed,
which is the same fail-open this file exists to close. Skipping tables and instructions
outright went the other way: the surface docs keep their commands in a Run recipe column,
and a MUST telling agents to pass opengrep's nonexistent metrics flag went unflagged.
`--include-prose` scans everything for an auditor who wants every mention.

EXIT CODES: 0 clean, 1 a violation was found, 2 usage.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

EXIT_VIOLATION = 1
EXIT_USAGE = 2

SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules"}
TEXT_SUFFIXES = {".md", ".sh", ".py", ".yml", ".yaml", ".json", ".toml", ""}

# (id, regex, why). `why` names the observable symptom, because a lint message that only
# says "forbidden" gets suppressed rather than fixed.
RULES: list[tuple[str, str, str]] = [
    (
        "bd-plural-label",
        r"bd\s+(list|ready|show)\b[^\n]*--labels\b",
        "`--labels` is not the query flag (`--label` is) and SILENTLY returns nothing on a "
        "query. A whole wisp set once read as 'no work exists'.",
    ),
    (
        "bd-set-metadata",
        r"bd\s+update\b[^\n]*--set-metadata\b",
        "`--set-metadata` clobbers the whole object; concurrent stamps lose each other. "
        "Use `--metadata` so keys merge.",
    ),
    (
        "cargo-test-fail-fast",
        r"cargo\s+(\+\S+\s+)?test\b(?![^\n]*--no-fail-fast)",
        "without `--no-fail-fast` a workspace stops at the first failing binary. Measured: "
        "3 of 22 test binaries reached, and the remaining 19 read as unrun-but-fine.",
    ),
    (
        "cargo-locked",
        # `cargo install X --locked` is the CORRECT way to pin a tool build and is not
        # what this rule is about; the hazard is `--locked` on the target's own workspace.
        r"cargo\s+(\+\S+\s+)?(?!install\b)\S+[^\n]*\s--locked\b",
        "`--locked` fails BEFORE compilation, so the surface reports zero findings and "
        "looks clean. The skill's own fuzzer adds dev-dependencies (30 Cargo.toml files "
        "gained proptest), so Cargo.lock is dirty by design.",
    ),
    (
        "gitleaks-git-mode",
        r"gitleaks\s+(detect|git)\b(?![^\n]*--no-git)",
        "git mode on a worktree whose `.git` is a pointer file saw 0 commits and exited 0. "
        "Use `gitleaks dir` for a tree scan (`detect --no-git` is also filesystem mode).",
    ),
    (
        "opengrep-config-auto",
        r"(opengrep|semgrep)\b[^\n]*--config[= ]auto\b",
        "stock registry packs cannot load under `--network none`: OG_RC=2, and across a "
        "15-node campaign no stock ruleset ever executed. Point --config at a baked dir.",
    ),
    (
        "opengrep-metrics",
        r"(opengrep|semgrep)\b[^\n]*--metrics\b|--metrics[= ](off|on|auto)\b",  # lint-recipes: allow (own pattern)
        "`--metrics` exits 2 with zero findings; four nodes hit it independently.",
    ),
    (
        "login-shell",
        r"\bbash\s+-[a-zA-Z]*l[a-zA-Z]*c\b",
        "a login shell re-reads the profile and resets PATH, so `cargo` vanishes inside "
        "the container. `bash -c` and `sh -c` work.",
    ),
    (
        "tee-swallows-status",
        r"\|\s*tee\b(?![^\n]*PIPESTATUS)",
        "a pipeline reports its LAST stage, so `cmd | tee log` discards the failure. "  # lint-recipes: allow
        "Redirect to a file and read `$?`.",
    ),
    (
        "rm-rf-unexpanded",
        # A `${VAR:?}` expansion aborts the shell when VAR is unset or empty, so the path
        # cannot collapse toward `/`: that is the validated form, and flagging it was most
        # of this rule's noise. Every argument is checked, not only the first.
        r"\brm\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*[rR][a-zA-Z]*\s+(?:[^;&|\n]*?\s)?\"?"
        r"\$(?!\{[A-Za-z_][A-Za-z0-9_]*:\?)",
        "an unset variable collapses the path toward `/`. Guard it as `${VAR:?}`, or "
        "resolve and validate the path and then delete a literal.",
    ),
    (
        "shared-cargo-target",
        r"CARGO_TARGET_DIR=(?![^\n]*(\$\{?SABOT_BUILD_DIR|/artifacts/\.build))[^\n]*",  # lint-recipes: allow
        "a shared target dir produced phantom compile errors when a concurrent build "
        "erased branch-new symbols. Use $SABOT_BUILD_DIR (per-node) or /artifacts/.build.",
    ),
]

COMPILED = [(rid, re.compile(pat), why) for rid, pat, why in RULES]

# A line carrying this marker is a documented counter-example rather than a recipe. Both
# the lint's own source and the reference prose need to name the bad invocation to forbid
# it, so without an opt-out the linter would flag its own rules.
ALLOW_MARKER = "lint-recipes: allow"


FENCE = re.compile(r"^\s*(```|~~~)")
CODE_SPAN = re.compile(r"`([^`\n]+)`")

# A steering sentence is prose wherever it sits, a fenced spawn prompt included. A
# prohibition names the bad invocation in order to forbid it; an instruction names what to
# run in its first sentence, so the code spans there are recipes. The sentences after it
# explain, and often quote the very invocation that goes wrong.
_LEAD = r"^\s*(?:[-*>]\s+|\d+\.\s+)?"
PROHIBITION = re.compile(
    _LEAD + r"(?:MUST\s+(?:NOT|[Nn]ever)|SHOULD\s+NOT|NOT|NEVER|Never|Do not|Don't)\b")
INSTRUCTION = re.compile(_LEAD + r"(?:MUST|SHOULD|DEFAULT)\b")

TABLE_ROW = re.compile(r"^\s*\|")
TABLE_RULE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$")
RECIPE_HEADER = re.compile(r"(?i)recipe|invocation|command")


def split_cells(row: str) -> list[str]:
    """A Markdown table row's cells. A `|` inside a code span, or escaped as `\\|`, is
    content rather than a separator, so a piped recipe stays in one cell."""
    body = row.strip()
    body = body[1:] if body.startswith("|") else body
    body = body[:-1] if body.endswith("|") and not body.endswith("\\|") else body
    cells, cur, in_code = [], [], False
    for i, ch in enumerate(body):
        if ch == "`":
            in_code = not in_code
        if ch == "|" and not in_code and (i == 0 or body[i - 1] != "\\"):
            cells.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    cells.append("".join(cur))
    return [c.strip() for c in cells]


def _steered(line: str) -> list[str] | None:
    """What a steering sentence contributes as recipes, or None when it is not one."""
    if PROHIBITION.match(line):
        return []
    if not INSTRUCTION.match(line):
        return None
    # The sentence ends at the first `. ` outside a code span; spans are masked first so a
    # path such as `/artifacts/.build` cannot end it.
    masked = CODE_SPAN.sub(lambda m: "`" + "x" * len(m.group(1)) + "`", line)
    end = re.search(r"[.!?](\s|$)", masked)
    imperative = line[:end.start()] if end else line
    return CODE_SPAN.findall(imperative)


def markdown_recipes(lines: list[str]):
    """Yield (line number, recipe text) for the runnable parts of a Markdown document."""
    in_fence = False
    recipe_cols: set[int] | None = None   # the current table's recipe columns
    for i, line in enumerate(lines):
        n = i + 1
        if FENCE.match(line):
            in_fence = not in_fence
            recipe_cols = None
            continue
        steered = _steered(line)
        if in_fence:
            for text in ([line] if steered is None else steered):
                yield n, text
            continue
        if not TABLE_ROW.match(line):
            recipe_cols = None
            for text in steered or []:
                yield n, text
            continue
        if i + 1 < len(lines) and TABLE_RULE.match(lines[i + 1]):
            recipe_cols = {j for j, cell in enumerate(split_cells(line))
                           if RECIPE_HEADER.search(cell)}
            continue
        if TABLE_RULE.match(line) or not recipe_cols:
            continue
        cells = split_cells(line)
        for j in sorted(recipe_cols):
            if j < len(cells):
                for text in CODE_SPAN.findall(cells[j]):
                    yield n, text


def scan_text(text: str, label: str, include_prose: bool = False) -> list[dict]:
    """Flag runnable recipes. `include_prose` drops the context filter entirely."""
    lines = text.splitlines()
    if include_prose:
        recipes = ((n, line) for n, line in enumerate(lines, 1))
    elif label.endswith((".md", ".markdown")):
        recipes = markdown_recipes(lines)
    else:
        # A comment is an explanation, not an invocation. Every rule here has to be
        # named in a comment somewhere for the message to be readable at all.
        recipes = ((n, line) for n, line in enumerate(lines, 1)
                   if not line.lstrip().startswith("#"))
    out = []
    seen: set[tuple[int, str]] = set()   # one hit per rule per line, however many spans
    for n, text in recipes:
        if ALLOW_MARKER in lines[n - 1]:
            continue
        for rid, rx, why in COMPILED:
            if (n, rid) not in seen and rx.search(text):
                seen.add((n, rid))
                out.append({"rule": rid, "file": label, "line": n,
                            "text": text.strip()[:160], "why": why})
    return out


def iter_files(paths: list[Path]):
    for p in paths:
        if p.is_file():
            yield p
        elif p.is_dir():
            for f in sorted(p.rglob("*")):
                if any(part in SKIP_DIRS for part in f.parts):
                    continue
                if f.is_file() and f.suffix in TEXT_SUFFIXES:
                    yield f


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="lint-recipes.py")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--include-prose", action="store_true",
                    help="also scan prose and comments: every mention, not every recipe")
    args = ap.parse_args(argv)

    roots = [Path(p).expanduser() for p in args.paths]
    for r in roots:
        if not r.exists():
            print(f"lint-recipes: no such path: {r}", file=sys.stderr)
            return EXIT_USAGE

    hits: list[dict] = []
    for f in iter_files(roots):
        try:
            hits.extend(scan_text(f.read_text(errors="replace"), str(f),
                                  include_prose=args.include_prose))
        except OSError:
            pass

    if args.json:
        print(json.dumps({"schema": "sabot-recipe-lint/1", "violations": hits}, indent=2))
    else:
        for h in hits:
            print(f"{h['file']}:{h['line']}: [{h['rule']}] {h['text']}")
            print(f"    {h['why']}")
        print(f"lint-recipes: {len(hits)} violation(s) across "
              f"{len({h['file'] for h in hits})} file(s)")
    return EXIT_VIOLATION if hits else 0


if __name__ == "__main__":
    sys.exit(main())
