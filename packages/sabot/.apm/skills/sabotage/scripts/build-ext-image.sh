#!/usr/bin/env bash
set -euo pipefail

# build-ext-image.sh
#
# Extend a surface image with the TARGET's own dev-dependencies, baked at build
# time so a `--network none` campaign can use them (isolation.md, Provisioning). A
# `cargo test` harness that pulls `proptest` cannot fetch it under the run-time
# network-none contract, so the dep must already be in the image.
#
#   build-ext-image.sh --target <dir> --base <img> --tag <out> [--dry-run]
#     --target   the repo under test (read-only; only its manifests+locks are read)
#     --base     the surface image to extend, e.g. sabot/rust:1
#     --tag      the output image tag, e.g. sabot/rust-ext:1
#     --dry-run  print the generated Dockerfile and exit; build nothing
#
# What it does NOT do: it NEVER copies the target source into the image. The build
# context is a temp dir holding ONLY the discovered manifests and lockfiles, so no
# audited code enters a persisted layer and the read-only-target guarantee holds
# (isolation.md, "Never COPY the target source into the image"). The target is
# mounted read-only at /target at run time by run-contained.sh; this image carries
# only the fetched deps.
#
# The dep caches are baked into a persistent /deps prefix (CARGO_HOME et al), NOT
# under /scratch: run-contained.sh mounts /scratch as a fresh tmpfs per run, which
# would mask anything baked there. run-contained does not override CARGO_HOME, so a
# cargo bake is resolvable offline; the other cache vars it does override at run
# time are set here for the build-time fetch (see the report/caveat in isolation.md).

usage() { sed -n '4,28p' "$0" | sed 's/^# \{0,1\}//'; }

TARGET=""; BASE=""; TAG=""; DRYRUN=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --target)  TARGET="$2"; shift 2 ;;
    --base)    BASE="$2"; shift 2 ;;
    --tag)     TAG="$2"; shift 2 ;;
    --dry-run) DRYRUN=1; shift ;;
    *) printf 'build-ext-image: unknown arg: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[ -n "$TARGET" ] || { echo "build-ext-image: --target required" >&2; exit 2; }
[ -n "$BASE" ]   || { echo "build-ext-image: --base required (a sabot/<surface> image)" >&2; exit 2; }
[ -n "$TAG" ]    || { echo "build-ext-image: --tag required (the output image, e.g. sabot/rust-ext:1)" >&2; exit 2; }
[ -d "$TARGET" ] || { echo "build-ext-image: target is not a dir: $TARGET" >&2; exit 2; }
TARGET="$(cd "$TARGET" && pwd)"

HERE="$(cd "$(dirname "$0")" && pwd)"
DETECT="$HERE/detect-stacks.py"
[ -f "$DETECT" ] || { echo "build-ext-image: detect-stacks.py not next to this script" >&2; exit 3; }

# Discover the manifests/locks/fetch per bake unit deterministically. The default
# JSON output carries the manifest+lock paths (needed for the COPY set) and the fetch
# command in one call, so there is no second re-derivation of the same map.
DETECT_JSON="$(python3 "$DETECT" --repo "$TARGET")" || {
  echo "build-ext-image: detect-stacks.py failed on $TARGET" >&2; exit 3; }

DK=""
if command -v docker >/dev/null 2>&1; then DK="docker"
elif command -v finch >/dev/null 2>&1; then DK="finch"
fi

# --dry-run only prints a Dockerfile, so it stays runnable with no runtime and no base
# image; a real build needs both, and says which one is missing.
if [ "$DRYRUN" -eq 0 ]; then
  [ -n "$DK" ] || { echo "build-ext-image: no container runtime (docker/finch) on PATH" >&2; exit 3; }
  $DK image inspect "$BASE" >/dev/null 2>&1 || {
    echo "build-ext-image: base image not found: $BASE (build it from references/containers/)" >&2; exit 3; }
elif [ -n "$DK" ] && ! $DK image inspect "$BASE" >/dev/null 2>&1; then
  DK=""   # cannot probe an absent base; emit every unit rather than guess a skip
fi

# A surface image carries one stack's toolchain: sabot/rust:1 has cargo and no npm.
# A multi-language target still yields bake units for every stack, and emitting a RUN
# for one the base cannot execute loses the WHOLE image to `npm: not found` (rc=127) --
# measured on platevault, where a single node unit killed a rust ext build after 6
# successful steps. Probe the base for each stack's fetch binary and skip what it cannot
# run, reporting the skip: an unprovisioned stack is a coverage gap for its own surface's
# ext image, not a reason to lose this one.
# SABOT_STACK_SKIP pins the list instead of probing (a test, or a base image not yet
# built). Set it empty to emit every unit; leave it unset to let the base decide.
STACK_SKIP="${SABOT_STACK_SKIP-}"
if [ -n "$DK" ] && [ -z "${SABOT_STACK_SKIP+set}" ]; then
  for probe in rust:cargo node:npm python:pip3 go:go; do
    stack="${probe%%:*}"; bin="${probe##*:}"
    $DK run --rm --network none --entrypoint sh "$BASE" \
      -c "command -v $bin >/dev/null 2>&1" >/dev/null 2>&1 \
      || STACK_SKIP="$STACK_SKIP $stack"
  done
fi
[ -z "$STACK_SKIP" ] || printf 'build-ext-image: base %s cannot provision:%s (units skipped)\n' \
  "$BASE" "$STACK_SKIP" >&2

# Build the Dockerfile and the minimal context (manifests+locks only) from the map,
# with python emitting BOTH so the COPY list and the temp-context file list agree.
CTX="$(mktemp -d "${TMPDIR:-/tmp}/bs-ext-XXXXXX")"
cleanup() { rm -rf "${CTX:?}"; }
trap cleanup EXIT

DOCKERFILE="$(
  BASE="$BASE" TARGET="$TARGET" CTX="$CTX" STACK_SKIP="$STACK_SKIP" \
  python3 - "$DETECT_JSON" <<'PY'
import json, os, shutil, sys

result = json.loads(sys.argv[1])
base = os.environ["BASE"]
target = os.environ["TARGET"]
ctx = os.environ["CTX"]

PY_REQUIREMENTS = ".sabot-requirements.txt"


def cargo_member_manifests(unit):
    """Member Cargo.toml paths a workspace-root `cargo fetch` cannot do without.

    detect-stacks.py collapses members into the root bake unit, which is right for the
    fetch COMMAND and wrong for the build CONTEXT: `cargo fetch` at the root parses every
    path named in `[workspace] members`, so a context holding only the root manifest fails
    before fetching anything. Measured on a 45-member workspace, which is why that ext
    image had to be hand-rolled.
    """
    root = unit["dir"]
    prefix = "" if root == "." else root.rstrip("/") + "/"
    return [
        m["manifest"] for m in result["manifests"]
        if m["stack"] == "rust" and m["manifest"] != unit["manifest"]
        and m["manifest"].startswith(prefix)
    ]

skip = set(os.environ.get("STACK_SKIP", "").split())

# Distro -dev packages the -sys crates of the target link through pkg-config (the
# GTK/webkit stack of a Tauri app), read off the `system_packages` field detect-stacks.py
# emits. No apostrophe in this heredoc: bash 3.2 parses a heredoc inside $(...) as shell
# and an unbalanced quote breaks the whole script. They live here, not
# in the rust image, because only the target that names the crate needs them. The RUN
# asserts pkg-config RESOLVES each module, since an installed pkg-config with no .pc file
# is what left 199 Tauri handlers NOT EXECUTED while the binary answered.
system = {}
for u in result["bake_units"]:
    if u["stack"] in skip or not u["fetch"]:
        continue
    for pkg in u.get("system_packages", []):
        system.setdefault(pkg["apt"], pkg["pkg_config"])

lines = [
    f"FROM {base}",
    # Persistent dep prefix, outside the run-time tmpfs at /scratch. Owned by the
    # non-root breaker uid so the fetch (and a run-time read) needs no root.
    "USER root",
]
if system:
    print(f"build-ext-image: system packages: {' '.join(system)}", file=sys.stderr)
    lines += [
        "RUN apt-get update -q \\",
        f" && apt-get install -y --no-install-recommends {' '.join(system)} \\",
        " && rm -rf /var/lib/apt/lists/* \\",
        f" && for pc in {' '.join(system.values())}; do \\",
        '      pkg-config --exists "$pc" || \\',
        '        { echo "build-ext-image: pkg-config cannot resolve $pc" >&2; exit 1; }; \\',
        "    done",
    ]
lines += [
    "RUN mkdir -p /deps && chown 1000:1000 /deps",
    "USER 1000:1000",
    "ENV CARGO_HOME=/deps/cargo \\",
    "    GOMODCACHE=/deps/go/pkg/mod \\",
    "    npm_config_cache=/deps/npm \\",
    "    PIP_CACHE_DIR=/deps/pip \\",
    "    UV_CACHE_DIR=/deps/uv",
]

# One COPY + one RUN per bake unit, ordered so the dep layer caches on the
# manifest+lock: only a lock change re-fetches. Copy ONLY manifest+lock, never the
# source, so no audited code enters a layer.
for u in result["bake_units"]:
    if u["stack"] in skip:
        continue
    # A unit with no resolver is reported, never emitted as a RUN that cannot succeed and
    # never dropped silently: an unprovisioned stack is a coverage gap for its surface.
    if not u["fetch"]:
        print(f"build-ext-image: skipped {u['manifest']}: {u['skip_reason']}",
              file=sys.stderr)
        continue
    print(f"build-ext-image: {u['manifest']} via {u['resolver']}", file=sys.stderr)
    d = u["dir"]
    dest = "./" if d == "." else f"{d}/"
    copy_rel = [u["manifest"]] + [
        (m if d == "." else f"{d}/{m}") for m in u["lockfiles"]
    ]
    members = cargo_member_manifests(u) if u["stack"] == "rust" else []
    for rel in copy_rel:
        src = os.path.join(target, rel)
        if not os.path.exists(src):
            continue
        dst = os.path.join(ctx, rel)
        os.makedirs(os.path.dirname(dst) or ctx, exist_ok=True)
        shutil.copy2(src, dst)
    # A python unit installs the pins detect-stacks read from the manifest or uv.lock.
    # They are written here rather than resolved in-image, because resolving
    # pyproject.toml there means building the project, and the project build is target
    # code.
    if u.get("requirements"):
        req_rel = os.path.join(os.path.dirname(u["manifest"]), PY_REQUIREMENTS)
        with open(os.path.join(ctx, req_rel), "w") as fh:
            fh.write("\n".join(u["requirements"]) + "\n")
        copy_rel.append(req_rel)
    present = [rel for rel in copy_rel if os.path.exists(os.path.join(ctx, rel))]
    if not present:
        continue
    # --chown is not cosmetic: COPY writes root-owned files whatever USER is in
    # effect, and a fetch REWRITES the lock it was given -- `cargo fetch` failed
    # "failed to write /scratch/Cargo.lock: Permission denied" as uid 1000, aborting
    # the whole ext build. npm and pip rewrite their locks the same way.
    lines.append(f"COPY --chown=1000:1000 {' '.join(present)} {dest}")
    # Rust: `cargo fetch` parses the manifest, which resolves targets by
    # autodiscovery (src/lib.rs, src/main.rs). With only Cargo.toml copied there
    # are zero targets and cargo aborts ("no targets specified in the manifest").
    # Inject an EMPTY stub lib+main so the manifest parses and every dependency
    # resolves; the stub is not the audited source (the real tree mounts read-only
    # at /target at run time), so no product code enters a layer. A committed
    # Cargo.lock, when present, is copied above and makes the fetch exact anyway.
    if u["stack"] == "rust":
        # Each member gets its own COPY: a multi-source COPY resolves the destination as a
        # directory and keeps only basenames, so every member Cargo.toml would collapse
        # onto one path.
        for rel in [u["manifest"]] + members:
            member_dir = os.path.dirname(rel)
            stub_dir = os.path.join(ctx, member_dir, "src")
            os.makedirs(stub_dir, exist_ok=True)
            open(os.path.join(stub_dir, "lib.rs"), "a").close()
            src_dest = "src/" if not member_dir else f"{member_dir}/src/"
            lines.append(f"COPY --chown=1000:1000 {src_dest}lib.rs {src_dest}")
            if rel in members:
                src = os.path.join(target, rel)
                dst = os.path.join(ctx, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)
                lines.append(f"COPY --chown=1000:1000 {rel} {member_dir}/")
    cd = "" if d == "." else f'cd "{d}" && '
    lines.append(f"RUN {cd}{u['fetch']}")

sys.stdout.write("\n".join(lines) + "\n")
PY
)"

printf '%s' "$DOCKERFILE" > "$CTX/Dockerfile"

if [ "$DRYRUN" -eq 1 ]; then
  printf '%s' "$DOCKERFILE"
  exit 0
fi

# Network is ON at build (the default) so the toolchain's own resolver can fetch exactly
# what the manifest names. No target or dependency code runs while it is on: every fetch
# detect-stacks.py emits disables lifecycle scripts or installs wheels only. Re-tagging is
# idempotent; the layer cache keyed on the copied lock skips an unchanged re-fetch.
printf 'build-ext-image: runtime=%s base=%s tag=%s units=%s\n' \
  "$DK" "$BASE" "$TAG" "$(printf '%s' "$DETECT_JSON" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["bake_units"]))')" >&2
# Not `exec`: exec replaces the shell, so the EXIT trap never fired and every build
# leaked its temp context.
rc=0
"$DK" build -f "$CTX/Dockerfile" -t "$TAG" "$CTX" || rc=$?
exit "$rc"
