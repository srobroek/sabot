#!/usr/bin/env python3
"""The canonical sabot run layout: paths, slugs, environment, and the ignore file.

Every path a campaign writes is derived here, so no agent hand-builds one.

    run-layout.py paths      --run-root DIR [--json]
    run-layout.py env        --run-root DIR [--node ID]
    run-layout.py slug       ID [ID...]
    run-layout.py artifact   --run-root DIR --kind KIND [--node ID] [--ext .md]
    run-layout.py classify   PATH --run-root DIR
    run-layout.py init       --run-root DIR [--node ID]
    run-layout.py gitignore  --run-root DIR

Two invariants the rest of the skill relies on:

DURABILITY IS READABLE FROM THE PATH. Exactly one path segment decides it: anything
under `<run-root>/ephemeral/` is regenerable and deletable by a path glob; everything
else under the run root is evidence. `classify` is that decision, and teardown refuses
to delete anything it does not classify as ephemeral. A campaign that had no such
segment copied per-node build trees into its evidence dir until a 460 GiB host volume
hit 100%, containerd could not grow its sparse disk, image blobs began returning
`input/output error`, and no container would start on any image.

EPHEMERAL IS PER-NODE, NEVER SHARED. `ephemeral/<node-slug>/build` is a distinct
`CARGO_TARGET_DIR` per node because a shared one produced phantom compile errors: a
concurrent node's build erased branch-new symbols and an agent spent a session
debugging an import that was never missing.

Slugging is a function here rather than a prose rule in a brief. Node ids contain `:`
(`code:metadata`) and filenames use `-` (`recon-code-metadata.md`); when a producer and
a consumer slugged differently the consumer read a missing rules file as "0 findings"
instead of a STOP.

Stdlib only. Exit 2 usage, 3 precondition.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import sys
from pathlib import Path

EXIT_USAGE = 2
EXIT_PRECONDITION = 3

EPHEMERAL_SEGMENT = "ephemeral"

# Host-side scratch outside the target repo. A campaign spread ~1.0 GiB of residue over
# five differently-named `~/tmp/sabot-*` dirs that nothing could enumerate; one location
# makes orphan detection a glob. Kept under $HOME because colima mounts $HOME only.
#
# Each run's dir is keyed by the repo AND the run id, never the run id alone: run ids
# such as `run-3` recur across repos, so two campaigns shared one scratch dir and a
# teardown of one deleted the other's live files.
HOST_SCRATCH_PARENT = ".sabot-scratch"

# Paths a previous convention used for the same purpose. Teardown reports these as
# orphaned residue; it never deletes them without an explicit opt-in, because they are
# outside any run root.
LEGACY_HOST_SCRATCH_GLOBS = ("tmp/sabot-*", ".sabot/stage-*")

DURABLE_SUBDIRS = ("artifacts", "logs")
EPHEMERAL_NODE_SUBDIRS = ("build", "cache", "corpora", "src")

PREFLIGHT_NAME = "preflight.json"

_SLUG_STRIP = re.compile(r"[^a-z0-9]+")


def slug(value: str) -> str:
    """Node id or artifact kind -> filename-safe segment.

    Idempotent: slug(slug(x)) == slug(x), so a caller that slugs twice is harmless.
    """
    out = _SLUG_STRIP.sub("-", value.strip().lower()).strip("-")
    if not out:
        raise ValueError(f"{value!r} slugs to nothing; a node id needs one alphanumeric")
    return out


def run_root(path: str | os.PathLike[str]) -> Path:
    """Absolute, symlink-resolved run root. Teardown compares against this, so a
    relative or symlinked root must not survive into a deletion decision."""
    return Path(path).expanduser().resolve()


def host_scratch(root: Path) -> Path:
    """`~/.sabot-scratch/<repo>-<run-id>-<hash>`, unique to this run root.

    The hash is over the resolved run root, so two repos with the same directory name
    still differ; the readable prefix is the first non-dot ancestor (the repo for the
    usual `<repo>/.sabot/<run-id>`) so a human can tell the dirs apart.
    """
    owner = next((p.name for p in root.parents if p.name and not p.name.startswith(".")), "")
    label = "-".join(s for s in (_SLUG_STRIP.sub("-", owner.lower()).strip("-"),
                                 _SLUG_STRIP.sub("-", root.name.lower()).strip("-")) if s)
    key = hashlib.sha256(str(root).encode()).hexdigest()[:12]
    return Path.home() / HOST_SCRATCH_PARENT / f"{label or 'run'}-{key}"


def paths(root: Path, node: str | None = None) -> dict[str, str]:
    """The whole layout as name -> absolute path. `run-layout.py env` is this dict."""
    eph = root / EPHEMERAL_SEGMENT
    out = {
        "SABOT_RUN_ID": root.name,
        "SABOT_RUN_ROOT": str(root),
        "SABOT_ARTIFACTS": str(root / "artifacts"),
        "SABOT_LOGS": str(root / "logs"),
        "SABOT_EPHEMERAL": str(eph),
        "SABOT_HOST_SCRATCH": str(host_scratch(root)),
        "SABOT_PREFLIGHT": str(root / PREFLIGHT_NAME),
        "SABOT_GITIGNORE": str(root / ".gitignore"),
    }
    if node is not None:
        node_slug = slug(node)
        node_root = eph / node_slug
        out.update(
            {
                "SABOT_NODE": node,
                "SABOT_NODE_SLUG": node_slug,
                "SABOT_NODE_EPHEMERAL": str(node_root),
                "SABOT_BUILD_DIR": str(node_root / "build"),
                "SABOT_CACHE_DIR": str(node_root / "cache"),
                "SABOT_CORPORA_DIR": str(node_root / "corpora"),
                "SABOT_SRC_DIR": str(node_root / "src"),
            }
        )
    return out


# Each entry is (name, lifetime, owner). The `env` and `paths --json` output carries it
# so the one place documenting a variable's lifetime is the tool that emits it.
LIFETIMES = {
    "SABOT_RUN_ID": ("campaign", "orchestrator"),
    "SABOT_RUN_ROOT": ("campaign", "orchestrator"),
    "SABOT_ARTIFACTS": ("durable: outlives the run, never auto-deleted", "every node"),
    "SABOT_LOGS": ("durable: outlives the run, never auto-deleted", "every node"),
    "SABOT_EPHEMERAL": ("ephemeral: deleted by run-teardown.py --apply", "orchestrator"),
    "SABOT_HOST_SCRATCH": ("ephemeral: deleted by run-teardown.py --apply", "orchestrator"),
    "SABOT_PREFLIGHT": ("durable: cited by the final report", "run-preflight.py"),
    "SABOT_GITIGNORE": ("durable: regenerated by run-layout.py gitignore", "run-preflight.py"),
    "SABOT_NODE": ("campaign", "one node"),
    "SABOT_NODE_SLUG": ("campaign", "one node"),
    "SABOT_NODE_EPHEMERAL": ("ephemeral: deleted by run-teardown.py --apply", "one node"),
    "SABOT_BUILD_DIR": ("ephemeral: per-node CARGO_TARGET_DIR/GOCACHE, never shared", "one node"),
    "SABOT_CACHE_DIR": ("ephemeral: tool caches", "one node"),
    "SABOT_CORPORA_DIR": ("ephemeral: regenerable from seeds in references/corpora/", "one node"),
    "SABOT_SRC_DIR": ("ephemeral: copied source tree", "one node"),
}


def _resolve_existing_prefix(path: Path, root: Path) -> Path:
    """Absolute, symlink-free form of a path that may not exist yet.

    `Path.resolve()` on a missing path leaves an ancestor symlink unexpanded on some
    platforms, so a deletion target under `/tmp` (a symlink to `/private/tmp` on macOS)
    would compare as outside a run root that resolved. Resolve the deepest existing
    ancestor and re-append the rest.
    """
    if not path.is_absolute():
        path = root / path
    parts: list[str] = []
    probe = Path(os.path.normpath(str(path)))
    while not probe.exists() and probe != probe.parent:
        parts.append(probe.name)
        probe = probe.parent
    return probe.resolve().joinpath(*reversed(parts))


def classify(target: str | os.PathLike[str], root: Path) -> str:
    """'ephemeral' | 'durable' for a path inside the run root.

    Raises ValueError when the path is outside the root: a teardown decision about a
    path it does not own is never 'go ahead', it is a refusal.
    """
    resolved = _resolve_existing_prefix(Path(target).expanduser(), root)
    scratch = _resolve_existing_prefix(host_scratch(root), root)
    if resolved == scratch or scratch in resolved.parents:
        return "ephemeral"
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"{resolved} is outside the run root {root}")
    rel = resolved.relative_to(root) if resolved != root else Path(".")
    return "ephemeral" if rel.parts[:1] == (EPHEMERAL_SEGMENT,) else "durable"


def artifact_path(root: Path, kind: str, node: str | None, ext: str = ".md") -> Path:
    """`<artifacts>/<kind>[-<node-slug>]<ext>` -- the only sanctioned artifact name."""
    stem = slug(kind) if node is None else f"{slug(kind)}-{slug(node)}"
    if not ext.startswith("."):
        ext = "." + ext
    return root / "artifacts" / f"{stem}{ext}"


GITIGNORE_HEADER = "# generated by run-layout.py gitignore -- regenerate, do not hand-edit"

# Lives at <run-root>/.gitignore so the target repo's own .gitignore is untouched: git
# applies a .gitignore to its own directory's subtree, which is exactly the run root.
#
# The decision, stated rather than left incidental: EPHEMERAL is ignored, DURABLE is
# untracked-and-VISIBLE. `git status` therefore shows findings, recon, and the preflight
# record so committing them stays the user's call, while multi-GiB build output can never
# be swept into a commit by `git add .`.
GITIGNORE_BODY = f"""{GITIGNORE_HEADER}
#
# EPHEMERAL -- regenerable, ignored, deleted by run-teardown.py --apply.
/{EPHEMERAL_SEGMENT}/

# DURABLE -- artifacts/, logs/, {PREFLIGHT_NAME} and this file are deliberately NOT
# ignored. They stay untracked and visible in `git status` so the user can choose to
# commit findings; the skill leaves them uncommitted and listed. Adding an ignore rule
# for them hides evidence.
"""


def write_gitignore(root: Path) -> Path:
    dest = root / ".gitignore"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(GITIGNORE_BODY)
    return dest


def init(root: Path, node: str | None = None) -> list[Path]:
    made = []
    for name in DURABLE_SUBDIRS:
        d = root / name
        d.mkdir(parents=True, exist_ok=True)
        made.append(d)
    eph = root / EPHEMERAL_SEGMENT
    eph.mkdir(parents=True, exist_ok=True)
    made.append(eph)
    if node is not None:
        for sub in EPHEMERAL_NODE_SUBDIRS:
            d = eph / slug(node) / sub
            d.mkdir(parents=True, exist_ok=True)
            made.append(d)
    host_scratch(root).mkdir(parents=True, exist_ok=True)
    made.append(host_scratch(root))
    made.append(write_gitignore(root))
    return made


def _fail(msg: str, code: int = EXIT_USAGE) -> "int":
    print(f"run-layout: {msg}", file=sys.stderr)
    return code


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="run-layout.py", add_help=True)
    sub = ap.add_subparsers(dest="cmd")

    def with_root(p, node=False):
        p.add_argument("--run-root", required=True)
        if node:
            p.add_argument("--node")
        return p

    with_root(sub.add_parser("paths"), node=True).add_argument("--json", action="store_true")
    with_root(sub.add_parser("env"), node=True)
    sub.add_parser("slug").add_argument("ids", nargs="+")
    p_art = with_root(sub.add_parser("artifact"), node=True)
    p_art.add_argument("--kind", required=True)
    p_art.add_argument("--ext", default=".md")
    with_root(sub.add_parser("classify")).add_argument("path")
    with_root(sub.add_parser("init"), node=True)
    with_root(sub.add_parser("gitignore"))

    args = ap.parse_args(argv)
    if args.cmd is None:
        ap.print_usage(sys.stderr)
        return _fail("a subcommand is required")

    try:
        if args.cmd == "slug":
            for i in args.ids:
                print(slug(i))
            return 0

        root = run_root(args.run_root)

        if args.cmd == "paths":
            table = paths(root, getattr(args, "node", None))
            if args.json:
                print(
                    json.dumps(
                        {
                            "schema": "sabot-layout/1",
                            "ephemeral_segment": EPHEMERAL_SEGMENT,
                            "paths": [
                                {
                                    "var": k,
                                    "path": v,
                                    "durability": (
                                        "ephemeral"
                                        if "ephemeral" in LIFETIMES[k][0]
                                        else "durable"
                                    ),
                                    "lifetime": LIFETIMES[k][0],
                                    "owner": LIFETIMES[k][1],
                                }
                                for k, v in table.items()
                            ],
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                width = max(len(k) for k in table)
                for k, v in table.items():
                    print(f"{k:<{width}}  {v}    # {LIFETIMES[k][0]}")
            return 0

        if args.cmd == "env":
            for k, v in paths(root, getattr(args, "node", None)).items():
                print(f"export {k}={shlex.quote(v)}")
            return 0

        if args.cmd == "artifact":
            print(artifact_path(root, args.kind, getattr(args, "node", None), args.ext))
            return 0

        if args.cmd == "classify":
            print(classify(args.path, root))
            return 0

        if args.cmd == "init":
            for p in init(root, getattr(args, "node", None)):
                print(p)
            return 0

        if args.cmd == "gitignore":
            print(write_gitignore(root))
            return 0
    except ValueError as exc:
        return _fail(str(exc), EXIT_PRECONDITION)

    return _fail(f"unknown subcommand: {args.cmd}")


if __name__ == "__main__":
    sys.exit(main())
