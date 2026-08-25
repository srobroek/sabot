#!/usr/bin/env bash
set -euo pipefail

# run-contained.sh
#
# The ONE sanctioned way a sabot campaign executes untrusted-shaped work: a
# hostile harness, a build script, a dev server. It runs the command inside a
# locked-down, disposable container and copies back only what the container wrote
# to a named artifacts volume. The agent stays on the host; nothing of the agent
# enters the container.
#
# Isolation, all enforced as flags the kernel honours, proven on this host:
#   -v <target>:/target:ro       target READ-ONLY   (a write to the target is impossible)
#   named volume at /artifacts    the only writable disk path; pruned, copied out, removed
#     The volume is per-run and disposable, but `docker cp` replicates whatever is in it
#     onto the HOST artifacts dir, so a build tree written under /artifacts becomes host
#     residue that nothing deletes. Measured: 1.2 GiB + 856 MiB + 2.0 GiB per-node target
#     dirs plus a 5.2 GiB shared one filled a 460 GiB host volume to 100%, containerd
#     could not grow its sparse disk, several content blobs began returning
#     `input/output error`, and no container could start on any image. One node lost its
#     whole test pass; another lost its harness log to a 600 s `docker cp` over a ~5 GB
#     target dir. Build caches therefore default to /artifacts/.build (see below), which
#     the copy-out prunes, and the copy-out refuses a payload over --max-copy-mb rather
#     than blocking on it.
#   --network none (both modes)   no outbound egress; DAST uses the container's own lo
#   --memory / --pids-limit       cgroup-enforced resource caps
#   --cap-drop ALL --security-opt no-new-privileges   no caps to escalate
#   image default user is non-root (uid 1000, owns /artifacts) so no root, no uid match
#   --read-only root + tmpfs /scratch             nothing else writable
#   workdir=/scratch, TMPDIR/HOME -> /scratch (tmpfs); CARGO_TARGET_DIR/GOCACHE ->
#     /artifacts/.build (disk)   builds write here, not the ro target
#     /scratch is tmpfs and its pages are charged to the --memory cgroup: measured, `dd`
#     was SIGKILLed at exactly 2.0 GiB under `--mem 2g --scratch 12g`, so a multi-GiB
#     cargo target dir on /scratch OOM-kills any workspace build. Build output goes to
#     the disk-backed volume instead. Nothing under /artifacts/.build is copied out.
#     (the command after -- reads the target at /target: `cargo test --manifest-path /target/Cargo.toml`)
#   --rm + disposable volume      no state carried between runs
#
# The container backend is colima/finch/docker; on this host `docker` targets a
# Lima VM (context "colima"), so `docker run` is VM-isolated. Findings are copied
# out with `docker cp`, sidestepping colima's $HOME-only bind-mount scope.
#
#   run-contained.sh --target <dir> --artifacts <dir> --image <img>
#                    [--net none|loopback] [--mem 2g] [--pids 512] [--cpus 2]
#                    [--timeout 300] [--workdir /target|/scratch]
#                    [--scratch 2g] [--copy-src] [--require-cmd cargo,go]
#                    [--min-free-mb 4096] [--max-copy-mb 512]
#                    [--expect-json findings.json] -- <command inside>
#   run-contained.sh --assert-tools <image> <tool[,tool...]>
#   run-contained.sh --list-tools <image>
#
# EXIT CODES. 0-125 are the contained command's own status; the wrapper reserves
# 2 usage error, 3 precondition (no runtime, missing image, host disk below
# --min-free-mb), 4 copy-out failed or refused, 5 --copy-src staging failed,
# 6 --require-cmd unsatisfied inside the container, 7 --expect-json output missing,
# unparseable, or reporting zero files scanned.
#
# --expect-json <artifacts-relative path>, repeatable, is the wrapper's positive-evidence
# check, and the only defence against the failure mode that has now been measured four
# times: a scanner crashes, its output file from an EARLIER run is still on disk, and the
# caller parses that and records "0 findings". The wrapper deletes each named path before
# the command runs and, after the copy-out, requires the file to exist, to parse as JSON,
# and to report a nonzero scanned-file count. Failing any of those writes executed=0 with
# a reason and exits 7, so the run cannot be read as clean. Neither rc=0 nor the mere
# existence of the output file is the signal.
#
# The container also runs under LANG/LC_ALL=C.UTF-8 with PYTHONUTF8=1, because a python
# scanner under the default POSIX locale dies on the first non-ASCII byte of a rule file.
# Measured: opengrep raised `'ascii' codec can't decode byte 0xe2` from
# config_resolver.py:241 and exited 2 having scanned 0 files; the same invocation under a
# UTF-8 locale returned 41 findings across 14 files. `sabot-scout` synthesizes rule files
# and a synthesized rule routinely carries a curly quote or a dash, so this is a defect
# the skill triggers in itself.
#
# An exit code is NOT sufficient evidence the harness ran: this environment has a
# host wrapper that has been measured returning rc=0 while printing a fatal error,
# and a `| tee` in the caller's own pipeline discards the status entirely. So every
# run also writes <artifacts>/run-contained.status, `key=value` lines carrying
# `executed=0|1`, `rc`, `image`, and on a refusal a `reason`. The file is rewritten
# with executed=0 the moment --artifacts is known, so a stale success cannot be read
# as a fresh one. A caller that requires a harness to have run MUST grep
# `executed=1` there rather than trust `$?`.
#
# --scratch takes a SIZE, not a path: it is the tmpfs size for /scratch (default 2g).
# Passing it bare consumes the next argument as the size, and docker then rejects the
# tmpfs mount and kills the container -- a run that failed to start, which reads like a
# tool that found nothing. --copy-src tars the target into /scratch/src (minus target/
# and .git) so a build may write in-tree without touching the read-only mount.
#
# cwd defaults to /target (the repo), because a repo-aware scanner (gitleaks,
# osv-scanner, actionlint, trivy) auto-detects .git and .github/workflows from cwd:
# run one from /scratch and it fails "not a git repository" / "no project found"
# (rc 128/3), which is an INVALID run masquerading as zero findings, not a clean
# result. A build or fuzz step that must WRITE to cwd passes --workdir /scratch and
# reads the target by absolute path (`--manifest-path /target/Cargo.toml`), since
# /target is read-only. Writes are already redirected to /scratch via the env below.

# --assert-tools <image> <tool[,tool...]>: prove each tool runs INSIDE the image
# before any campaign trusts a clean fuzz result. Containerization guarantees a
# tool is PRESENT (baked into the image); this guarantees it SURVIVED the build.
# A missing coverage-guided fuzzer here is the silent-clean the campaign must
# refuse, not footnote. Exits 0 only if every tool answers; non-zero names the
# missing ones so the caller refuses the fuzz phase.
if [ "${1:-}" = "--assert-tools" ]; then
  AT_IMAGE="${2:?--assert-tools needs <image> <tool,tool>}"
  AT_TOOLS="${3:?--assert-tools needs <image> <tool,tool>}"
  DK="$(command -v docker || command -v finch)"
  [ -n "$DK" ] || { echo "assert-tools: no container runtime" >&2; exit 3; }
  "$DK" image inspect "$AT_IMAGE" >/dev/null 2>&1 || { echo "assert-tools: image absent: $AT_IMAGE" >&2; exit 3; }
  missing=""
  IFS=','; for t in $AT_TOOLS; do
    # A tool name interpolates into the in-container `sh -c`, so reject anything
    # outside the safe set for an executable name. Without this a crafted name
    # (`x;id`) would execute in the container.
    case "$t" in
      *[!A-Za-z0-9._-]*|"") echo "assert-tools: illegal tool name: '$t'" >&2; exit 2 ;;
    esac
    # try `<tool> --version`, the cargo-subcommand form `cargo <sub> --version`, then
    # the bare `<tool> version` subcommand. The last form is not decoration: `go
    # --version` exits 2 ("flag provided but not defined"), so without it the go
    # surface's toolchain -- which IS its fuzzer, since `go test -fuzz` is built in --
    # reports as missing and the preflight refuses a working image.
    if ! "$DK" run --rm --network none "$AT_IMAGE" sh -c "command -v $t >/dev/null 2>&1 && { $t --version >/dev/null 2>&1 || $t version >/dev/null 2>&1; } || ${t#cargo-} --version >/dev/null 2>&1 || cargo ${t#cargo-} --version >/dev/null 2>&1" 2>/dev/null; then
      missing="$missing $t"
    fi
  done
  unset IFS
  if [ -n "$missing" ]; then
    echo "assert-tools: MISSING in $AT_IMAGE:$missing  (rebuild the image, or refuse the fuzz phase)" >&2
    exit 1
  fi
  echo "assert-tools: all present in $AT_IMAGE:$AT_TOOLS"
  exit 0
fi

# --list-tools <image>: ask the image what it carries, instead of predicting it. An
# authoring artifact in one campaign asserted nightly and cargo-fuzz were absent from an
# image that shipped both, and separately nobody noticed `just` was absent from every
# image until a whole justfile went unread -- the recipes were runnable as shell all along. The answer is enumerated from the prefixes
# the layer scripts install into, so it needs no hardcoded list to drift out of date.
# Distro binaries under /usr/bin are not listed: they are the base OS, not the toolset,
# and a thousand coreutils names would bury the answer. Use --assert-tools for one of
# those, which probes by name and proves it actually answers.
if [ "${1:-}" = "--list-tools" ]; then
  LT_IMAGE="${2:?--list-tools needs <image>}"
  DK="$(command -v docker || command -v finch)"
  [ -n "$DK" ] || { echo "list-tools: no container runtime" >&2; exit 3; }
  "$DK" image inspect "$LT_IMAGE" >/dev/null 2>&1 || { echo "list-tools: image absent: $LT_IMAGE" >&2; exit 3; }
  exec "$DK" run --rm --network none --user 1000:1000 "$LT_IMAGE" sh -c \
    'for d in /usr/local/bin /usr/local/cargo/bin /opt/pipx/bin /usr/local/go/bin /root/go/bin /home/breaker/go/bin /usr/bin; do
       [ -d "$d" ] || continue
       for f in "$d"/*; do [ -x "$f" ] && [ ! -d "$f" ] && echo "${f##*/}"; done
     done | sort -u'
fi

usage() { sed -n '/^#   run-contained.sh --target/,/^# *$/p' "$0" | sed 's/^# \{0,1\}//'; }

TARGET=""; ARTIFACTS=""; IMAGE=""; NET="none"; MEM="2g"; PIDS="512"; CPUS="2"; TMO="300"
WORKDIR="/target"
SCRATCH="2g"      # tmpfs size; a real cargo/npm build needs GBs, not the old 512m
COPY_SRC=0        # --copy-src: tar the target into /scratch/src (minus target/ + .git)
REQUIRE_CMD=""    # --require-cmd: names that must resolve INSIDE the container
MIN_FREE_MB=4096  # refuse to start below this much free host disk
MAX_COPY_MB=512   # refuse a copy-out payload above this, rather than block on it
EXPECT_JSON=()    # --expect-json: /artifacts-relative outputs this run MUST have written
CMD=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help)   usage; exit 0 ;;
    --require-cmd)  REQUIRE_CMD="$2"; shift 2 ;;
    --min-free-mb)  MIN_FREE_MB="$2"; shift 2 ;;
    --max-copy-mb)  MAX_COPY_MB="$2"; shift 2 ;;
    --expect-json)  EXPECT_JSON+=("$2"); shift 2 ;;
    --target)    TARGET="$2"; shift 2 ;;
    --artifacts) ARTIFACTS="$2"; shift 2 ;;
    --image)     IMAGE="$2"; shift 2 ;;
    --net)       NET="$2"; shift 2 ;;
    --mem)       MEM="$2"; shift 2 ;;
    --pids)      PIDS="$2"; shift 2 ;;
    --cpus)      CPUS="$2"; shift 2 ;;
    --timeout)   TMO="$2"; shift 2 ;;
    --workdir)   WORKDIR="$2"; shift 2 ;;
    --scratch)   SCRATCH="$2"; shift 2 ;;
    --copy-src)  COPY_SRC=1; shift ;;
    --)          shift; CMD=("$@"); break ;;
    *) printf 'run-contained: unknown arg: %s\n' "$1" >&2; exit 2 ;;
  esac
done

case "$WORKDIR" in
  /target|/scratch) : ;;
  *) echo "run-contained: --workdir must be /target or /scratch" >&2; exit 2 ;;
esac

[ -n "$TARGET" ]    || { echo "run-contained: --target required" >&2; exit 2; }
[ -n "$ARTIFACTS" ] || { echo "run-contained: --artifacts required" >&2; exit 2; }
[ -n "$IMAGE" ]     || { echo "run-contained: --image required (a sabot/<surface> image)" >&2; exit 2; }
[ "${#CMD[@]}" -gt 0 ] || { echo "run-contained: a command after -- is required" >&2; exit 2; }
[ -d "$TARGET" ]    || { echo "run-contained: target is not a dir: $TARGET" >&2; exit 2; }
case "$MIN_FREE_MB$MAX_COPY_MB" in
  *[!0-9]*|"") echo "run-contained: --min-free-mb and --max-copy-mb take whole megabytes" >&2; exit 2 ;;
esac
# An --expect-json path interpolates into the in-container `sh -c` that deletes it, so
# reject anything outside a safe relative path. /artifacts-relative only: the guarantee
# is about what THIS run wrote into the findings volume.
for ej in ${EXPECT_JSON[@]+"${EXPECT_JSON[@]}"}; do
  case "$ej" in
    ""|/*|*..*|*[!A-Za-z0-9._/-]*)
      echo "run-contained: --expect-json takes a safe /artifacts-relative path, got '$ej'" >&2; exit 2 ;;
  esac
done
mkdir -p "$ARTIFACTS"
TARGET="$(cd "$TARGET" && pwd)"
ARTIFACTS="$(cd "$ARTIFACTS" && pwd)"

STATUS="$ARTIFACTS/run-contained.status"
# Rewritten at every transition, so the file always describes THIS run. A caller
# requiring `executed=1` is then immune to a masked or forged exit code; leaving a
# previous run's success in place would hand it exactly the false clean it is checking
# for. `reason` is present only on a refusal.
status() { printf 'executed=%s\nrc=%s\nimage=%s\ndeadline=%s\n%s' "$1" "$2" "$IMAGE" \
  "$([ "${2:-}" = 124 ] && echo 1 || echo 0)" "${3:+reason=$3
}" > "$STATUS"; }
status 0 "" "not started"

# The host disk is what actually failed in one campaign, and it failed in the middle of
# a run rather than at preflight: the copied-out build trees of concurrent gremlins ate
# a 460 GiB volume to 100%, at which point containerd could not grow its sparse disk and
# no container could start on any image. Refusing to start is recoverable; discovering it
# mid-build costs the run's evidence. `df -Pm` is POSIX, so the available column is
# megabytes on both macOS and Linux.
FREE_MB="$(df -Pm "$ARTIFACTS" 2>/dev/null | awk 'NR==2 {print $4}')"
case "$FREE_MB" in
  ''|*[!0-9]*) echo "run-contained: WARNING could not read free disk for $ARTIFACTS; skipping the free-space precondition" >&2 ;;
  *) if [ "$FREE_MB" -lt "$MIN_FREE_MB" ]; then
       echo "run-contained: REFUSING to start: ${FREE_MB} MiB free at $ARTIFACTS, below --min-free-mb $MIN_FREE_MB. A container runtime that cannot grow its disk corrupts its own image blobs; free space first (prune build residue and \`docker system prune\`)." >&2
       status 0 "" "host disk ${FREE_MB}MiB below min-free-mb ${MIN_FREE_MB}"
       exit 3
     fi ;;
esac

DK=""
if command -v docker >/dev/null 2>&1; then DK="docker"
elif command -v finch >/dev/null 2>&1; then DK="finch"
else echo "run-contained: no container runtime (docker/finch) on PATH" >&2; status 0 "" "no container runtime"; exit 3; fi
CTX="$($DK context show 2>/dev/null || echo default)"

# Refuse rather than false-clean when the image is absent: a missing image means
# a campaign that would run against nothing.
$DK image inspect "$IMAGE" >/dev/null 2>&1 || {
  echo "run-contained: image not found: $IMAGE  (build it from references/containers/; a corrupt content blob also presents this way, so check \`docker images\` for an input/output error before rebuilding)" >&2
  status 0 "" "image not found: $IMAGE"; exit 3; }

# Both modes deny outbound egress. A DAST run starts its dev server and scans it
# INSIDE the command after `--`, over the container's own loopback interface, which
# `--network none` already provides (`lo` is always up). `--net loopback` is kept as
# an explicit name for that intent; it does NOT add a bridge, because a bridge grants
# full outbound internet and the in-container loopback needs none. There is no
# host-side port map: `docker run` blocks to completion, so a host port could never
# be read back mid-run anyway, and mapping one would only open an egress path.
case "$NET" in
  none|loopback) NETFLAG=(--network none) ;;
  *) echo "run-contained: --net must be none|loopback" >&2; exit 2 ;;
esac

# The target reaches the VM via a $HOME-scoped path (colima mounts $HOME, not /tmp).
# If the target is outside $HOME, copy it into a $HOME staging dir first.
case "$TARGET" in
  "$HOME"/*) MOUNT_SRC="$TARGET" ;;
  *) STAGE="$HOME/.sabot/stage-$$"; mkdir -p "$STAGE"; cp -R "$TARGET/." "$STAGE/"; MOUNT_SRC="$STAGE" ;;
esac

VOL="bs-art-$$-$(date +%s 2>/dev/null || echo r)"
$DK volume create "$VOL" >/dev/null
# The trailing `:` is load-bearing. Under `set -e` an EXIT trap's final status
# REPLACES the script's exit code, and the STAGE test returns 1 whenever the target
# is already under $HOME (no staging copy) -- collapsing every run, pass or fail, to
# exit 1. A caller keying on the exit code then cannot tell a clean run from a broken
# one.
cleanup() { $DK volume rm "$VOL" >/dev/null 2>&1 || true; [ -n "${STAGE:-}" ] && rm -rf "${STAGE:?}"; :; }
trap cleanup EXIT

printf 'run-contained: runtime=%s[%s] image=%s net=%s mem=%s pids=%s\n' \
  "$DK" "$CTX" "$IMAGE" "$NET" "$MEM" "$PIDS" >&2

# CARGO_HOME is a writable tmpfs path (/scratch/cargo), but the target's baked
# dev-deps live in the ext-image's read-only /deps/cargo/registry. Seed the writable
# home with a symlink to that registry so `cargo ... --offline` resolves the baked
# crates without a network fetch and without writing the read-only layer. No-op when
# the image has no baked registry (a base image, or a non-Rust surface). The command
# after the preamble runs via `exec "$@"` so its exit code is preserved.
#
# The same problem, and the same fix, for the baked TOOL CACHES under /deps/cache:
# cargo-careful and Miri each keep a prebuilt sysroot there, but XDG_CACHE_HOME below
# points at the empty tmpfs. Without the link each one decides no sysroot exists and
# rebuilds it, which needs crates.io and dies under --network none on a fetch unrelated
# to the finding being investigated -- measured, `cargo miri test` failed "no matching
# package named hashbrown". Every entry is linked rather than a named list, so a cache
# baked by a later fragment is picked up without touching this wrapper.
#
# The advisory-db is COPIED, not linked, and only for cargo-deny's sake. Three measured
# constraints shape the destination path, and missing any one makes cargo-deny report a
# db it cannot read (which reads as an image problem, not a config one):
#   1. WRITABLE. cargo-deny takes an exclusive lock on db.lock inside db-path before
#      reading; against the read-only image that fails "attempted to take an exclusive
#      lock on a read-only path", and --offline does NOT skip the lock.
#   2. NESTED under a dir named advisory-db-<hash-of-url>. db-path is a parent holding
#      one directory per db-url, not the db itself. Point it at a flat copy and cargo-deny
#      tries to CLONE the missing child, which under --network none dies on DNS.
#   3. CARRYING .git. See layers/rust.sh -- the staleness check reads HEAD's timestamp.
# The hash is cargo-deny's own for the rustsec URL; it is derived from the url string, so
# it is stable as long as db-urls in /opt/sabot-db/deny.toml is unchanged.
# cargo-audit needs none of this: it reads the baked path directly, read-only and flat.
ADB_NEST="advisory-db-3157b0e258782691"
PREAMBLE='mkdir -p "$CARGO_HOME" /scratch/tmp "$XDG_CACHE_HOME" "$CARGO_TARGET_DIR" "$GOCACHE"; [ -d /deps/cargo/registry ] && [ ! -e "$CARGO_HOME/registry" ] && ln -s /deps/cargo/registry "$CARGO_HOME/registry"; for c in /deps/cache/*; do [ -e "$c" ] || continue; [ -e "$XDG_CACHE_HOME/${c##*/}" ] || ln -s "$c" "$XDG_CACHE_HOME/${c##*/}"; done; [ -d /usr/local/advisory-db ] && [ ! -e "/scratch/advisory-db/'"$ADB_NEST"'" ] && mkdir -p /scratch/advisory-db && cp -r /usr/local/advisory-db "/scratch/advisory-db/'"$ADB_NEST"'";'

# A target carrying rust-toolchain.toml overrides the image's toolchain BY NAME, and the
# image installs its stable by version (1.97.1-<triple>), never under the literal name
# `stable`. So a pin as ordinary as `channel = "stable"` finds no local match and rustup
# tries to install one -- which needs the network and a writable /usr/local/rustup, and
# has neither. Measured on a real crate, every cargo invocation died before doing any
# work:
#
#   info: syncing channel updates for stable-aarch64-unknown-linux-gnu
#   error: could not create temp file /usr/local/rustup/tmp/...: Read-only file system
#
# That is a fails-loud, not a false-clean, but it stops the campaign on any repo that
# pins a toolchain -- which is most of them. RUSTUP_TOOLCHAIN outranks the file, so the
# preamble exports the image's own default and the pin is ignored.
#
# The value is READ FROM settings.toml, not from `rustup toolchain list`: list itself
# honours the pin and re-triggers the same sync. It is exported only when unset, so a
# recipe may still pick a toolchain, and `+nightly` on the command line outranks the
# variable either way (measured: cargo-fuzz and Miri still resolve the nightly).
PREAMBLE="$PREAMBLE"' if [ -z "${RUSTUP_TOOLCHAIN:-}" ] && [ -r /usr/local/rustup/settings.toml ]; then t="$(sed -n '"'"'s/^default_toolchain = "\(.*\)"$/\1/p'"'"' /usr/local/rustup/settings.toml)"; [ -n "$t" ] && export RUSTUP_TOOLCHAIN="$t"; fi;'
# --copy-src: a build/fuzz step needs a WRITABLE source tree (cargo writes Cargo.lock
# and target/ beside the manifest), but /target is read-only. Copy the target into
# /scratch/src, excluding its own build dir and .git (the space hogs that overflow
# the tmpfs), and cd there. The audited bytes never change; this is a working copy on
# a disposable tmpfs. The command then runs from /scratch/src.
#
# `pipefail` + the explicit `|| exit 5` are load-bearing. GNU tar exits 1 on "file
# changed as we read it" -- which the host writing into the target during a run
# (another agent, a `.sabot/` artifact write) triggers routinely, measured 26 times in
# one campaign. The creating tar is the LEFT side of a pipe, so without pipefail the
# preamble's status comes from the EXTRACTING tar, which succeeded on whatever bytes it
# got. `cd /scratch/src` then works and the build proceeds against a possibly
# incomplete source tree: a scan of a partial repo that reports as a clean result.
# Measured in sabot/base:1 (tar 1.35): SRC_RC=1 while the pipeline reported 0.
#
# `.sabot` and `.beads` are excluded for the same reason, not as tidiness: they hold the
# run's OWN artifacts dir and its bead store (a live sqlite WAL). A concurrent agent
# writing a finding or claiming a wisp churns them under tar and trips the check above.
# Measured on the fits-header target mid-campaign: 1 in 6 runs failed with `.beads`
# included, 0 in 6 with it excluded. That churn is self-inflicted and says nothing about
# the audited bytes.
#
# The retry is the other half. GNU tar reports the SAME exit 1 whether a file it was
# copying changed mid-read or merely an unrelated sibling entry appeared at the repo root
# (which bumps `.`'s mtime, and tar compares that at the end). Measured after the two
# excludes: 1 in 20 runs against a live repo still failed, always on `.` and never on a
# file, while a static tree failed 0 in 40 -- so the residual is benign root churn, and
# hard-failing on it would abort a campaign for nothing. Retrying separates the two: a
# one-off root bump passes on the next attempt, while a source that is genuinely being
# rewritten keeps failing and still exits 5. Verified both ways -- 20 clean runs against
# the live target, and a file rewritten in a loop under tar still detected.
# exit 5 is distinct from the wrapper's own 2/3/4 so a caller can tell "staging failed"
# from "the contained command failed".
if [ "$COPY_SRC" -eq 1 ]; then
  PREAMBLE="$PREAMBLE"' mkdir -p /scratch/src; SRC_OK=0; for _try in 1 2 3; do rm -rf /scratch/src; mkdir -p /scratch/src; if ( set -o pipefail; tar -C /target --exclude=./target --exclude=./.git --exclude=./.sabot --exclude=./.beads -cf - . | tar -C /scratch/src -xf - ); then SRC_OK=1; break; fi; echo "run-contained: --copy-src staging tar attempt $_try failed, retrying" >&2; done; [ "$SRC_OK" -eq 1 ] || { echo "run-contained: ERROR --copy-src staging tar failed 3 times; the source is changing under us and the copy may be incomplete (treat this run as INVALID, not clean)" >&2; exit 5; }; cd /scratch/src;'
  WORKDIR="/scratch"
fi

# --require-cmd: prove the toolchain INSIDE the container is the toolchain, before the
# command that depends on it runs. Containerization is not hermetic against a host shell
# wrapper: one was measured rewriting `cargo` to `rtk` inside the container, which
# selected 0 tests across 11 targets and exited 0 -- no error, no tests, and a report
# indistinguishable from a clean surface. Another rewrite echoed a denied command back as
# `rtk df`. Printing the resolved path and version makes the substitution visible, and a
# name that does not resolve exits 6 instead of letting the command fail as if the target
# were at fault.
if [ -n "$REQUIRE_CMD" ]; then
  IFS=','; for rc_t in $REQUIRE_CMD; do
    case "$rc_t" in
      *[!A-Za-z0-9._-]*|"") echo "run-contained: illegal --require-cmd name: '$rc_t'" >&2; exit 2 ;;
    esac
    PREAMBLE="$PREAMBLE"' p="$(command -v '"$rc_t"' 2>/dev/null)"; [ -n "$p" ] || { echo "run-contained: --require-cmd '"$rc_t"' does not resolve inside the container" >&2; exit 6; }; echo "run-contained: TOOLCHAIN '"$rc_t"' -> $p $('"$rc_t"' --version 2>&1 | head -1)" >&2;'
  done
  unset IFS
fi

# --expect-json: delete the named output BEFORE the command runs, so this run cannot be
# credited with a file some earlier run wrote. Measured: opengrep raised
# `'ascii' codec can't decode byte 0xe2` from config_resolver.py:241 on a rule file
# containing a curly quote, exited 2 having scanned 0 files, and the caller then read the
# previous invocation's JSON and recorded "0 findings". `sabot-scout` synthesizes those
# rule files, so the skill triggers this on itself. The post-run half of the check is
# below the copy-out: a fresh file, parseable JSON, and a nonzero scanned-file count.
for ej in ${EXPECT_JSON[@]+"${EXPECT_JSON[@]}"}; do
  PREAMBLE="$PREAMBLE"' rm -f "/artifacts/'"$ej"'";'
  rm -f "$ARTIFACTS/$ej"
done

set +e
# Two cwd regimes, selected by --workdir:
#   /target (default): a repo-aware scanner (gitleaks, osv-scanner, actionlint,
#     trivy) auto-detects .git and .github/workflows relative to cwd, so it MUST
#     run from the repo root. /target is read-only, but these scanners only read;
#     any temp write lands in /scratch via HOME/TMPDIR/XDG_CACHE_HOME below.
#   /scratch: a build or fuzz step that writes to cwd (`cargo test`, `go test`, npm)
#     runs here (a tmpfs) and reads the target by absolute path
#     (`--manifest-path /target/Cargo.toml`), never writing the read-only mount.
# CARGO_TARGET_DIR/GOCACHE/etc. point at /scratch regardless, so a build launched
# from /target still writes its output to the writable tmpfs, not the target tree.
#
# TMPDIR is a SUBDIRECTORY of /scratch, never /scratch itself. Go refuses to read a
# go.mod that sits in the temp root ("ignoring go.mod in system temp root"), so with
# TMPDIR=/scratch every contained go command failed "directory prefix . does not
# contain main module" -- while `go vet` still exited 0, which is the false-clean this
# wrapper exists to prevent.
# The deadline belongs to the container, not to an agent watching a clock: a campaign-wide
# time MUST was unobservable in practice and overran by roughly fiftyfold with nothing
# noticing. Expiry here is a graceful, normal outcome -- SIGTERM first so the command can
# flush what it has written, SIGKILL 30 s later if it will not stop -- and the copy-out
# below still runs, so a deadline yields the findings collected up to that point plus
# rc=124 recorded as `deadline=1`. It is never a crash and never a silent truncation.
timeout -k 30 "$TMO" "$DK" run --rm \
  "${NETFLAG[@]}" \
  --memory "$MEM" --memory-swap "$MEM" --pids-limit "$PIDS" --cpus "$CPUS" \
  --read-only --tmpfs "/scratch:size=$SCRATCH,mode=1777,exec" \
  --cap-drop ALL --security-opt no-new-privileges \
  --user 1000:1000 \
  --workdir "$WORKDIR" \
  --env HOME=/scratch \
  --env TMPDIR=/scratch/tmp \
  --env CARGO_HOME=/scratch/cargo \
  --env CARGO_TARGET_DIR=/artifacts/.build/cargo-target \
  --env CARGO_NET_OFFLINE=true \
  --env GOCACHE=/artifacts/.build/go-build \
  --env GOPATH=/scratch/go \
  --env npm_config_cache=/scratch/npm \
  --env RUFF_CACHE_DIR=/scratch/ruff \
  --env XDG_CACHE_HOME=/scratch/cache \
  --env LANG=C.UTF-8 --env LC_ALL=C.UTF-8 \
  --env PYTHONUTF8=1 --env PYTHONIOENCODING=utf-8 \
  -v "$MOUNT_SRC:/target:ro" \
  -v "$VOL:/artifacts" \
  "$IMAGE" \
  sh -c "$PREAMBLE"' exec "$@"' _ "${CMD[@]}"
RC=$?
set -e
status 1 "$RC"
printf 'run-contained: EXECUTED rc=%s image=%s status=%s\n' "$RC" "$IMAGE" "$STATUS" >&2

# 137 is SIGKILL, and inside this wrapper that means the memory cgroup, not a target
# defect. The expensive instance was `ld` linking a large cdylib: linking a
# `libdesktop_shell.so` peaked several times the compile working set and was killed at
# the standard --mem 2g, costing a node 0 of 9 harnesses while the failure was first
# misread as a missing system library. It linked at --mem 6g with
# CARGO_PROFILE_TEST_DEBUG=0; codegen-units=1 and -C link-arg=-Wl,--no-keep-memory were
# tried and turned out unnecessary. cargo itself reports 101 when its child linker is
# killed, so this hint fires on the container-level kill and isolation.md carries the
# ladder for the cargo-level one.
if [ "$RC" -eq 137 ]; then
  echo "run-contained: rc=137 is SIGKILL -- the --memory cap ($MEM), not a target finding. Linking a large cdylib needs several times the compile peak: retry at --mem 6g with CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_DEV_DEBUG=0 before concluding anything about the target." >&2
fi

# Copy findings out of the disposable volume, then the trap removes it. A copy-out
# failure strands every finding in the volume, so it must not read as a clean run:
# exit 4 (distinct from the campaign's own RC) so a caller keying on the exit code
# treats the run as INVALID rather than trusting an empty artifacts dir.
#
# Bounded, and pruned first. `docker cp` has no exclude, and it replicates a build tree
# onto the host as readily as a findings file: one measured run copied a ~5 GB target dir
# for 600 s and lost the harness log it was actually there to collect, while the residue
# it left behind filled the host volume. So a helper container deletes the build caches
# from the volume, then reports the remaining payload size; a payload over --max-copy-mb
# is refused as INVALID rather than copied, because a wrapper blocking for ten minutes on
# a build tree strands the evidence just as thoroughly as a failed copy.
#
# CACHEDIR.TAG is the mechanical half: cargo and go both write one into their output
# directories, so an agent-chosen target dir under /artifacts is recognised without this
# wrapper knowing its name.
PRUNE='rm -rf /artifacts/.build; for d in /artifacts/*/; do [ -f "$d/CACHEDIR.TAG" ] && { echo "run-contained: pruned build cache from the copy-out: ${d}" >&2; rm -rf "$d"; }; done; du -sm /artifacts 2>/dev/null | cut -f1'
PAYLOAD_MB="$($DK run --rm --network none --user 1000:1000 -v "$VOL:/artifacts" "$IMAGE" sh -c "$PRUNE" 2>/dev/null | tail -1)"
case "$PAYLOAD_MB" in
  ''|*[!0-9]*)
    echo "run-contained: WARNING could not prune or size the artifacts volume; copying unbounded" >&2 ;;
  *)
    if [ "$PAYLOAD_MB" -gt "$MAX_COPY_MB" ]; then
      echo "run-contained: REFUSING the copy-out: ${PAYLOAD_MB} MiB of findings exceeds --max-copy-mb $MAX_COPY_MB. Something wrote bulk data to /artifacts that is not a finding; treat this run as INVALID, not clean, and point the writer at /artifacts/.build (pruned, never copied out)." >&2
      status 0 "$RC" "copy-out refused: ${PAYLOAD_MB}MiB over max-copy-mb ${MAX_COPY_MB}"
      exit 4
    fi ;;
esac

COPY_OK=1
cid="$($DK create -v "$VOL:/artifacts" "$IMAGE" true 2>/dev/null)"
if [ -z "$cid" ]; then
  echo "run-contained: ERROR could not open the artifacts volume to copy findings out; output is stranded in $VOL (treat this run as INVALID)" >&2
  COPY_OK=0
else
  if ! $DK cp "$cid:/artifacts/." "$ARTIFACTS/" 2>/dev/null; then
    echo "run-contained: ERROR findings copy-out failed; output may be stranded in $VOL (treat this run as INVALID, not clean)" >&2
    COPY_OK=0
  fi
  $DK rm "$cid" >/dev/null 2>&1 || true
fi
[ "$COPY_OK" -eq 1 ] || { status 0 "$RC" "findings copy-out failed"; exit 4; }

# Positive evidence that THIS run produced the output the caller is about to parse. The
# pre-run rm above removed any stale copy, so existence now means freshness; JSON parsing
# rules out a truncated write; and a scanned-file count of zero means the scanner resolved
# no files (a bad rule path, an encoding abort, a filter that matched nothing), which reads
# identically to a clean repo and must not.
for ej in ${EXPECT_JSON[@]+"${EXPECT_JSON[@]}"}; do
  out="$ARTIFACTS/$ej"
  if [ ! -s "$out" ]; then
    echo "run-contained: ERROR --expect-json $ej was not written by this run; the command produced no parseable output (treat this run as INVALID, not clean)" >&2
    status 0 "$RC" "expected output missing: $ej"
    exit 7
  fi
  # Scanned-file count by tool shape: semgrep/opengrep `paths.scanned`, then a few common
  # aliases. A JSON document that names none of them passes on parseability alone, with the
  # gap stated, rather than being failed for using a shape this check does not know.
  SCANNED="$(python3 - "$out" <<'PY' 2>/dev/null
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as e:
    print("PARSE_ERROR", e); raise SystemExit(0)
if not isinstance(d, dict):
    print("UNKNOWN"); raise SystemExit(0)
for path in (("paths", "scanned"), ("stats", "files"), ("summary", "files_scanned")):
    node = d
    for key in path:
        node = node.get(key) if isinstance(node, dict) else None
    if isinstance(node, list):
        print(len(node)); raise SystemExit(0)
    if isinstance(node, int):
        print(node); raise SystemExit(0)
print("UNKNOWN")
PY
)"
  case "$SCANNED" in
    PARSE_ERROR*)
      echo "run-contained: ERROR --expect-json $ej is not parseable JSON: ${SCANNED#PARSE_ERROR }. The command wrote a partial or non-JSON file (treat this run as INVALID, not clean)" >&2
      status 0 "$RC" "expected output unparseable: $ej"
      exit 7 ;;
    0)
      echo "run-contained: ERROR --expect-json $ej reports 0 files scanned; the scanner resolved no input, so its empty result is not a clean result (treat this run as INVALID)" >&2
      status 0 "$RC" "zero files scanned: $ej"
      exit 7 ;;
    UNKNOWN|"")
      echo "run-contained: WARNING --expect-json $ej parses but names no scanned-file count this check recognizes; freshness is proven, coverage is not" >&2 ;;
    *)
      printf 'run-contained: EVIDENCE %s fresh, %s files scanned\n' "$ej" "$SCANNED" >&2 ;;
  esac
done

status 1 "$RC"
exit "$RC"
