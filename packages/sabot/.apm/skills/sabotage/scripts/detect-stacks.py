#!/usr/bin/env python3
"""Discover every dependency manifest in a target repo, deterministically.

The image is provisioned from the target's manifests (isolation.md, Provisioning),
and a real target is often a workspace, a monorepo, or multi-language (a Tauri app is
Rust under src-tauri/ plus a JS frontend). Guessing "the manifest" misses one. This
script enumerates them from `git ls-files`, so it honors .gitignore for free, sees
every member of a workspace, and never depends on an agent globbing correctly.

Usage:
  detect-stacks.py [--repo <dir>] [--bake]

  (default) with no --bake, emit the manifest map + detected stacks as JSON.
          bake_units carry {stack, dir, fetch, resolver}, so a caller has everything
          structured. A python unit also carries `requirements`, the pins its fetch
          installs from `.sabot-requirements.txt`, which the caller writes beside the
          manifest. A rust unit carries `system_packages`, the distro -dev packages its
          Cargo.lock's -sys crates link through pkg-config. A unit with no usable
          resolver carries `fetch: null` and a `skip_reason`, so the gap is reported
          rather than masked.
  --bake  emit the provision command lines (`cd <dir> && <fetch>`), one per bake
          unit, for a Dockerfile RUN or an `sh -c` at image build. These are command
          content, not a standalone script: the caller runs them where Docker RUN
          semantics already provide the shell.

Every fetch runs with the network up and executes NO target or dependency code: npm,
pnpm, and yarn run with lifecycle scripts disabled, pip installs wheels only (an sdist
build runs its setup.py), and the project itself is never built. Install scripts are
the exfiltration vector surfaces/build.md describes, and a networked bake is where
they would reach out.

Exit: 0 ok; 2 usage; 3 not a git repo / git absent.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tomllib

# manifest filename -> (stack, lockfiles). The lockfiles are copied into the bake
# context beside the manifest; `detect` picks the resolver from the ones present.
MANIFESTS = {
    "Cargo.toml": ("rust", ["Cargo.lock"]),
    "package.json": ("node", ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"]),
    "pyproject.toml": ("python", ["uv.lock", "poetry.lock", "requirements-dev.txt"]),
    "requirements-dev.txt": ("python", []),
    "go.mod": ("go", ["go.sum"]),
}

# Exported for every node fetch, belt and braces beside each command's own flag: npm and
# pnpm read `npm_config_*`, and yarn berry reads YARN_ENABLE_SCRIPTS.
NODE_NO_SCRIPTS = "export npm_config_ignore_scripts=true YARN_ENABLE_SCRIPTS=false && "

# The node fetch is chosen by the lockfile the repo actually ships, not by a single
# npm-shaped default. Measured: `npm ci || npm install` cannot provision a pnpm
# workspace -- `npm ci` has no package-lock.json to read, and the `npm install` fallback
# then chokes on `workspace:` protocol ranges. `pnpm fetch` reads the lockfile alone and
# runs no lifecycle scripts, which suits a context holding no member package.json files.
NODE_FETCH = [
    ("pnpm-lock.yaml", "pnpm", "(corepack pnpm fetch || pnpm fetch)"),
    ("yarn.lock", "yarn",
     "(corepack yarn install --immutable || yarn install --frozen-lockfile --ignore-scripts)"),
    ("package-lock.json", "npm ci", "npm ci --ignore-scripts"),
]

# The python image ships pip only, so a uv or poetry command never ran: the old
# `uv sync --frozen || pip install -e '.[dev]' || true` died 127 on uv, failed the
# project install on a source-free context, and `|| true` reported the bake as done.
# `--only-binary=:all:` refuses every sdist, whose build would execute setup.py.
PIP_INSTALL = "pip3 install --no-cache-dir --break-system-packages --only-binary=:all: -r"
PIP_REQUIREMENTS = ".sabot-requirements.txt"
PY_DEV_GROUPS = ("dev", "test", "tests")

# Native libraries a -sys crate links through pkg-config, keyed by crate name: (Debian
# -dev package, pkg-config module). The rust image carries none of them, because they
# serve one kind of target, a Tauri or GTK desktop app, and every other Rust campaign
# would pay for the stack. The ext image installs them for a target whose Cargo.lock
# names the crate. Measured on platevault: `tauri = { features = ["wry"] }` pulls
# webkit2gtk-sys -> gtk-sys -> glib-sys, whose build script shells `pkg-config
# glib-2.0 >= 2.70`, and with no .pc file all 199 Tauri command handlers were NOT
# EXECUTED. --network none leaves no run-time repair.
SYS_CRATE_PACKAGES = {
    "glib-sys": ("libglib2.0-dev", "glib-2.0"),
    "gtk-sys": ("libgtk-3-dev", "gtk+-3.0"),
    "webkit2gtk-sys": ("libwebkit2gtk-4.1-dev", "webkit2gtk-4.1"),
    "soup3-sys": ("libsoup-3.0-dev", "libsoup-3.0"),
}

# Agentic-tooling config is not part of any target (targeting.md, Excludes), so its
# manifests are not bake units either. Measured: platevault tracks
# .agents/skills/react-components/package-lock.json, which made a node bake unit inside a
# RUST ext build; the rust base carries no npm, so `npm ci` died 127 and the whole image
# was lost -- a target's assistant config broke provisioning for its actual code.
# Matched on the leading path segment, since these are all repo-root config dirs. The
# list is targeting.md's exclude table; TOOLING_PREFIXES covers the entries that sit
# below a directory that is otherwise product.
TOOLING_DIRS = (
    ".claude", ".codex", ".agents", ".cursor", ".continue", ".windsurf", ".aider",
    ".gemini", ".opencode", ".kiro", ".amazonq", ".roo", ".cline", ".goose", ".omp",
)
TOOLING_PREFIXES = (".github/copilot", ".apm/instructions/", ".apm/context/")


def is_tooling_path(rel):
    """True for a path under a coding-assistant config dir rather than the product."""
    norm = rel.replace("\\", "/")
    head = norm.split("/", 1)[0]
    return (head in TOOLING_DIRS or head.startswith(".aider")
            or norm.startswith(TOOLING_PREFIXES))


def node_fetch(locks):
    for lock, resolver, cmd in NODE_FETCH:
        if lock in locks:
            return resolver, NODE_NO_SCRIPTS + cmd
    return "npm install", NODE_NO_SCRIPTS + "npm install --ignore-scripts"


def cargo_system_packages(repo, directory, locks):
    """The SYS_CRATE_PACKAGES entries whose crate the unit's Cargo.lock names.

    No lockfile means no resolved graph to read, so nothing is inferred: an unlocked
    target's -sys crates surface as a build-script failure, not as a guessed package.
    """
    if "Cargo.lock" not in locks:
        return []
    doc, _ = _read_toml(os.path.join(repo, directory, "Cargo.lock"))
    names = {p.get("name") for p in (doc or {}).get("package", [])}
    return [{"crate": crate, "apt": apt, "pkg_config": pc}
            for crate, (apt, pc) in SYS_CRATE_PACKAGES.items() if crate in names]


def _read_toml(path):
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh), None
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return None, f"unreadable: {exc}"


def uv_lock_pins(path):
    """`name==version` for every registry package in a uv.lock.

    The project itself and path/git sources are skipped: none is on an index, and a
    path source is target code.
    """
    doc, err = _read_toml(path)
    if doc is None:
        return None, f"uv.lock {err}"
    pins = sorted(
        f"{p['name']}=={p['version']}" for p in doc.get("package", [])
        if "registry" in (p.get("source") or {}) and p.get("version")
    )
    return pins, None


def _group_key(name):
    """PEP 735 compares dependency-group names normalized, as PEP 503 does package names."""
    return re.sub(r"[-_.]+", "-", name).lower()


def dependency_group(groups, name, seen=()):
    """The requirement strings of one PEP 735 group, with every include expanded.

    An `{include-group = "x"}` entry is exactly the contents of group x, so dropping the
    table baked nothing for a dev group built from includes. Raises ValueError on an
    include cycle or an included group that does not exist, as the spec requires.
    """
    key = _group_key(name)
    if key in seen:
        raise ValueError(f"dependency-groups include cycle through '{name}'")
    reqs = []
    for entry in groups[key]:
        if isinstance(entry, str):
            reqs.append(entry)
        elif isinstance(entry, dict) and set(entry) == {"include-group"}:
            included = entry["include-group"]
            if _group_key(included) not in groups:
                raise ValueError(f"dependency-groups '{name}' includes unknown group '{included}'")
            reqs += dependency_group(groups, included, (*seen, key))
        else:
            raise ValueError(f"dependency-groups '{name}' has an invalid entry {entry!r}")
    return reqs


def pyproject_requirements(path):
    """The declared runtime plus dev/test requirements of a PEP 621 pyproject."""
    doc, err = _read_toml(path)
    if doc is None:
        return None, f"pyproject.toml {err}"
    project = doc.get("project") or {}
    reqs = list(project.get("dependencies") or [])
    extras = project.get("optional-dependencies") or {}
    groups = {_group_key(k): v for k, v in (doc.get("dependency-groups") or {}).items()}
    for name in PY_DEV_GROUPS:
        reqs += extras.get(name) or []
        if _group_key(name) in groups:
            try:
                reqs += dependency_group(groups, name)
            except ValueError as exc:
                return None, f"pyproject.toml {exc}"
    return sorted(set(reqs)), None


def python_fetch(repo, rel, locks):
    """(resolver, fetch, requirements, skip_reason) for one python manifest."""
    name = os.path.basename(rel)
    directory = os.path.dirname(rel)
    if name == "requirements-dev.txt":
        return "pip", f"{PIP_INSTALL} requirements-dev.txt", None, None
    if "uv.lock" in locks:
        reqs, err = uv_lock_pins(os.path.join(repo, directory, "uv.lock"))
        resolver = "pip (uv.lock pins)"
    else:
        reqs, err = pyproject_requirements(os.path.join(repo, rel))
        resolver = "pip (pyproject.toml requirements)"
    if err:
        return resolver, None, None, err
    if not reqs:
        why = ("no PEP 621 dependencies to install; a poetry-only manifest needs poetry, "
               "which the python image does not ship" if "poetry.lock" in locks
               else "no PEP 621 dependencies to install")
        return resolver, None, None, why
    return resolver, f"{PIP_INSTALL} {PIP_REQUIREMENTS}", reqs, None


def tracked_files(repo):
    """Every tracked file, so .gitignore is honored and untracked scratch is skipped."""
    try:
        out = subprocess.run(
            ["git", "-C", repo, "ls-files"],
            capture_output=True, text=True, check=True,
        ).stdout
    except FileNotFoundError:
        sys.exit(3)
    except subprocess.CalledProcessError:
        sys.exit(3)
    return [line for line in out.splitlines() if line]


def is_cargo_workspace(repo, rel):
    """A Cargo.toml with [workspace] provisions all members from one `cargo fetch`."""
    try:
        with open(os.path.join(repo, rel)) as fh:
            return "[workspace]" in fh.read()
    except OSError:
        return False


def detect(repo):
    files = tracked_files(repo)
    present = set(files)
    manifests = []
    for rel in files:
        name = os.path.basename(rel)
        if name not in MANIFESTS or is_tooling_path(rel):
            continue
        stack, locks = MANIFESTS[name]
        directory = os.path.dirname(rel) or "."
        found_locks = [lk for lk in locks
                       if (os.path.join(directory, lk) if directory != "." else lk) in present]
        entry = {
            "manifest": rel,
            "dir": directory,
            "stack": stack,
            "lockfiles": found_locks,
        }
        if stack == "rust":
            entry.update(resolver="cargo fetch", fetch="cargo fetch")
            entry["workspace_root"] = is_cargo_workspace(repo, rel)
            entry["system_packages"] = cargo_system_packages(repo, directory, found_locks)
        elif stack == "go":
            entry.update(resolver="go mod download", fetch="go mod download")
        elif stack == "node":
            entry["resolver"], entry["fetch"] = node_fetch(found_locks)
        else:
            resolver, fetch, reqs, skip = python_fetch(repo, rel, found_locks)
            entry.update(resolver=resolver, fetch=fetch)
            if reqs is not None:
                entry["requirements"] = reqs
            if skip:
                entry["skip_reason"] = skip
        manifests.append(entry)

    # Collapse Cargo workspace members: if a workspace root exists, its members are
    # provisioned by the root fetch, so a member Cargo.toml needs no separate bake.
    ws_roots = {m["dir"] for m in manifests
                if m["stack"] == "rust" and m.get("workspace_root")}
    def under_ws_root(m):
        if m["stack"] != "rust" or m.get("workspace_root"):
            return False
        return any(m["dir"] == r or m["dir"].startswith(r.rstrip("/") + "/")
                   for r in ws_roots if r != ".")  or ("." in ws_roots and m["dir"] != ".")

    bake_units = [m for m in manifests if not under_ws_root(m)]
    stacks = sorted({m["stack"] for m in manifests})
    return {
        "repo": repo,
        "stacks": stacks,
        "multi_language": len(stacks) > 1,
        "manifests": manifests,
        "bake_units": bake_units,
    }


def bake_lines(result):
    """One provision command line per bake unit: `cd <dir> && <fetch>`.

    The build context is the manifest+lock only (isolation.md), so these run against
    a copied-in manifest at build time (network up), then the target is mounted
    read-only at run. These are command lines for a Dockerfile RUN or `sh -c`, not a
    standalone script, so there is no shebang: the caller supplies the shell. A unit
    with no resolver is a comment naming why, never a silently absent line.
    """
    lines = ["# provision commands from detect-stacks.py; run at image build (network up)"]
    for m in result["bake_units"]:
        if not m["fetch"]:
            lines.append(f"# skipped {m['manifest']}: {m['skip_reason']}")
            continue
        cd = "" if m["dir"] == "." else f'cd "{m["dir"]}" && '
        lines.append(f"{cd}{m['fetch']}")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--bake", action="store_true", help="emit bake shell commands")
    args = ap.parse_args()

    repo = os.path.abspath(args.repo)
    if not os.path.isdir(os.path.join(repo, ".git")):
        # allow a worktree/submodule where .git is a file, or a subdir of a repo
        rc = subprocess.run(["git", "-C", repo, "rev-parse", "--is-inside-work-tree"],
                            capture_output=True, text=True)
        if rc.returncode != 0 or rc.stdout.strip() != "true":
            # Say why. A bare exit 3 sent every caller hunting the wrong fault:
            # build-ext-image.sh could only report "detect-stacks.py failed", which
            # reads as a broken script rather than a target that is not a git repo.
            print(f"detect-stacks: not a git repository: {repo}\n"
                  "  Stack detection reads `git ls-files` so .gitignore is honored.\n"
                  "  Point --repo at a checkout, or `git init` the target first.",
                  file=sys.stderr)
            sys.exit(3)

    result = detect(repo)
    if args.bake:
        sys.stdout.write(bake_lines(result))
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
