#!/usr/bin/env bash
set -euo pipefail

# install-tools.sh -- host preflight for a sabot campaign.
#
# Every target-touching tool runs in the surface image (references/isolation.md,
# "What runs where"), so this script installs NOTHING on the host. A host-side
# scanner would run the target's build code unconfined, the exact risk the container
# removes.
#
# The preflight is AUTHORITATIVE, not advisory: it asserts each expected tool
# actually answers INSIDE its image (via run-contained.sh --assert-tools, which keys
# on the tool's exit code), and exits non-zero when any is missing. It never prints
# a bare "OK" from an unchecked `<tool> --version`; a tool that errors "no such
# command" is a FAIL, because a missing scanner reported as present is why a whole
# threat dimension (supply chain / CI) came back a meaningless "zero findings".
#
#   install-tools.sh --probe   (default)   preflight: runtime + bd + git + assert every image tool
#   install-tools.sh --probe --images rust,python   only the images this campaign uses
#   install-tools.sh --help
#
# The expected-tool manifest below is the single source of truth. Keep it in lockstep
# with references/isolation.md ("Assert the tools survived the build") and the surface
# Tools tables; a tool added to a surface doc but not here is a tool the preflight will
# not guard.

SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RUN_CONTAINED="$SKILL_DIR/scripts/run-contained.sh"

# image  :  comma-separated EXECUTABLES that MUST answer inside it.
# Kept in sync with isolation.md's assert table and each surface's Tools table.
IMAGE_TOOLS_base="opengrep,shellcheck,ripgrep,gitleaks,ast-grep,shfmt,zizmor,actionlint,trivy,osv-scanner,radamsa,zzuf,creduce,hadolint,kube-linter,tflint,poutine,trufflehog"
IMAGE_TOOLS_rust="cargo-fuzz,cargo-audit,clippy,cargo-geiger"
# semgrep is NOT here: opengrep in base reads the same baked semgrep-rules and
# measured identical output (5 findings, same 3 rules, 0 errors) on the same
# fixture under --network none, so shipping both bought nothing.
IMAGE_TOOLS_python="bandit,ruff"
IMAGE_TOOLS_node="jazzer,retire"
# go ships NO separate fuzz binary: `go test -fuzz` is part of the toolchain, so the
# `go` executable answering here is the fuzzer assertion for this surface.
IMAGE_TOOLS_go="go,gosec,golangci-lint"
SURFACES="base rust python node go"

# OPTIONAL surfaces: escalation images a campaign reaches for by FINDING, not every run.
# Absent is a NOTE, not a failure -- a rust campaign starts on sabot/rust:1 and only
# needs rust-extras once a finding wants cargo-deny's license view, Miri's UB
# interpreter, or a semver-break check. Present-but-broken is still a failure, because
# escalating to an image whose cargo-deny loads zero advisories returns a false clean.
# Naming one in --images makes it required.
# A dash is not legal in a shell variable name, so the lookup below mangles it to _.
# cargo-careful is asserted below, not here: it forwards every argument to cargo, so
# `cargo careful --version` exits 1 listing its subcommands and the probe reads it as
# missing.
IMAGE_TOOLS_rust_extras="cargo-deny,cargo-vet,cargo-semver-checks,weggli"
# scanners: the IaC, malicious-package, DAST-template, and data-flow scanners that carry
# baked remote data (Dockerfile.scanners). checkov is default-on in infra.md and shell.md,
# and an unasserted image let a broken checkov read as a clean IaC pass.
IMAGE_TOOLS_scanners="checkov,guarddog,nuclei,bearer,kingfisher"
# heavy: the JVM engines. Only `joern` is a CLI with a version answer; joern-parse and ZAP
# are proved by doing their work in IMAGE_DB_heavy, since `zap.sh --version` is not a
# version flag and ZAP exits 0 having refused to start.
IMAGE_TOOLS_heavy="joern"
OPTIONAL_SURFACES="rust-extras scanners heavy"

# image  :  shell test that each LIBRARY the harnesses import actually LOADS inside
# the image. A library has no CLI, so the executable probe above cannot see it: it
# reports `atheris --version` missing whether or not the package is installed, which
# is both a false alarm and a blind spot. Loading is the right question anyway --
# atheris and Jazzer.js are native addons, and this image once shipped a jazzer that
# installed cleanly and then died at dlopen (bs-156).
IMAGE_LIBS_python='python3 -c "import atheris, hypothesis"'
IMAGE_LIBS_node='node -e "require(\"fast-check\")"'

# image  :  shell test, run inside the image, that a baked offline DB is PRESENT and
# NON-EMPTY. A present-but-empty DB is the exact false-clean this asserts against: a
# tool that answers --version but scans against zero records returns a meaningless
# clean under --network none. Each expression exits 0 only when the DB has content.
# The count thresholds are lower bounds, not exact, so a DB refresh does not trip them.
#
# For trivy and osv-scanner the file check is NOT sufficient, and this is measured. Both
# shipped a correct, non-empty DB that the tool then did not read: trivy ignores the bake
# unless --cache-dir names it, and osv-scanner's `--offline` loads nothing unless the cache
# dir is passed in the environment, reporting the package count it parsed and zero
# vulnerabilities. Both passed the old file-presence test. So each one now SCANS a probe
# lockfile pinned to a known-vulnerable version and the advisory count must be non-zero --
# the same "assert the work, not the version string" rule the tool probes follow.
#
# osv-scanner exits 1 when it finds vulnerabilities, which the probe lockfile guarantees,
# so 1 is the expected status and the PYSEC count then proves it read the database; any
# other non-zero is a failure. The probe used to be joined with `;`, which handed the
# chain's status to the checks after it: osv-scanner's own status was discarded, and an
# earlier failure was caught only because osv-scanner then never wrote its output.
IMAGE_DB_base='test "$(find /opt/sabot-db/trivy -name trivy.db | wc -l)" -ge 1 \
  && test "$(ls /opt/sabot-db/osv/osv-scanner 2>/dev/null | wc -l)" -ge 1 \
  && test "$(find /opt/sabot-db/semgrep-rules -name "*.yaml" | head -100 | wc -l)" -ge 50 \
  && p="$(mktemp -d)" && printf "Django==2.2.0\n" > "$p/requirements.txt" \
  && trivy --cache-dir /opt/sabot-db/trivy fs --skip-db-update --skip-check-update \
       --scanners vuln --format json -o "$p/t.json" "$p" >/dev/null 2>&1 \
  && test "$(grep -c VulnerabilityID "$p/t.json")" -ge 1 \
  && { XDG_CACHE_HOME=/opt/sabot-db/osv osv-scanner scan source \
       --offline-vulnerabilities --format json --output "$p/o.json" "$p" >/dev/null 2>&1 \
       || [ $? -eq 1 ]; } \
  && test "$(grep -c PYSEC "$p/o.json" 2>/dev/null)" -ge 1 \
  && test "$(ls /opt/sabot-db/semgrep-rules/python 2>/dev/null | wc -l)" -ge 5 \
  && printf "import hashlib\nh = hashlib.md5(b\"x\").hexdigest()\n" > "$p/probe.py" \
  && LC_ALL=C.UTF-8 LANG=C.UTF-8 opengrep scan --quiet --json \
       --config /opt/sabot-db/semgrep-rules/python "$p" > "$p/g.json" 2>/dev/null \
  && test "$(grep -c insecure-hash-algorithm-md5 "$p/g.json")" -ge 1 \
  && rm -rf "${p:?}"'
IMAGE_DB_rust='test "$(ls /usr/local/advisory-db/crates 2>/dev/null | wc -l)" -ge 100 \
  && ls /deps/cargo/registry/cache/*/libfuzzer-sys-*.crate >/dev/null 2>&1 \
  && ls /deps/cargo/registry/cache/*/arbitrary-*.crate >/dev/null 2>&1'
IMAGE_DB_node='test -s /opt/sabot-db/retire/jsrepository-v5.json'
# go bakes no vulnerability DB (gosec and golangci-lint carry their rules in the
# binary), so the assertion is the OFFLINE CONTRACT instead: GOPROXY must be off, or a
# build with a missing module blocks on a proxy dial that --network none never
# completes and then reports a network error that reads like a broken image.
IMAGE_DB_go='test "$(go env GOPROXY)" = "off" && test -d /deps/go/pkg/mod'
# rust-extras adds no DB of its own: it READS the advisory-db baked by the rust surface,
# and cargo-deny only finds it through db-path in the config, so assert the config too.
# Miri and cargo-careful are asserted here rather than in IMAGE_TOOLS. Miri is a nightly
# rustup component, so `miri --version` is not on PATH and only the +nightly form
# answers. cargo-careful has no --version at all, and its sysroot must already exist:
# rebuilding one needs crates.io, which the campaign does not have. Assert the baked
# sysroot is both PRESENT and READABLE as uid 1000, because the first bake wrote it to
# /root/.cache where the campaign user could not read it.
IMAGE_DB_rust_extras='grep -q "^db-path = \"/scratch/advisory-db\"" /opt/sabot-db/deny.toml \
  && test "$(ls /usr/local/advisory-db/crates 2>/dev/null | wc -l)" -ge 100 \
  && cargo +nightly miri --version >/dev/null 2>&1 \
  && ls /deps/cache/cargo-careful >/dev/null 2>&1'
# scanners: the baked trees must hold what layers/scanners.sh counted at build time, and
# checkov's packaged policies must find a seeded misconfiguration. checkov exits 1 on
# failed checks, which the seed guarantees.
IMAGE_DB_scanners='test "$(find /opt/sabot-db/nuclei-templates -name "*.yaml" | wc -l)" -gt 1000 \
  && test "$(find /opt/sabot-db/bearer-rules \( -name "*.yml" -o -name "*.yaml" \) | wc -l)" -gt 100 \
  && p="$(mktemp -d)" \
  && printf "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"p\"\n  acl    = \"public-read\"\n}\n" > "$p/main.tf" \
  && { checkov -d "$p" --compact --quiet > "$p/c.txt" 2>&1 || [ $? -eq 1 ]; } \
  && grep -q CKV_AWS "$p/c.txt" \
  && rm -rf "${p:?}"'
# heavy: Joern's value is the CPG, so it must build one offline, and ZAP must start against
# a writable -dir, because without one it exits 0 having refused to start. Both mirror the
# build probes in layers/heavy.sh. HOME points at the scratch dir, where Joern writes.
IMAGE_DB_heavy='p="$(mktemp -d)" \
  && printf "public class S { static void r(String c) throws Exception { Runtime.getRuntime().exec(c); } }\n" > "$p/S.java" \
  && HOME="$p" joern-parse "$p" --output "$p/cpg.bin" >/dev/null 2>&1 && test -s "$p/cpg.bin" \
  && v="$(zap.sh -cmd -dir "$p/zap" -version 2>&1)" \
  && ! printf "%s" "$v" | grep -q "Unable to create" \
  && printf "%s" "$v" | grep -Eq "[0-9]+\.[0-9]+" \
  && rm -rf "${p:?}"'

# docker and finch only: run-contained.sh, which every campaign step goes through, drives
# no other runtime, so a preflight that accepted podman passed and then every run failed.
find_runtime() {
  for c in docker finch; do
    command -v "$c" >/dev/null 2>&1 && { echo "$c"; return 0; }
  done
  return 1
}

# in_list NAME LIST -- whether NAME is an element of the comma-separated LIST.
in_list() { case ",$2," in *",$1,"*) return 0 ;; esac; return 1; }

# assert_surface <surface> <required|optional> <runtime>
# Prints one block per surface and returns non-zero on a real failure. An ABSENT
# optional image returns 0: escalation images are built on demand. A PRESENT one is
# held to the same bar as a required surface, since a half-built escalation image is
# worse than none -- the campaign trusts it and gets a clean it did not earn.
assert_surface() {
  local s="$1" mode="$2" rt="$3"
  local img="sabot/$s:1" fail=0
  # A dash is not legal in a variable name; IMAGE_TOOLS_rust_extras holds rust-extras.
  local key="${s//-/_}"
  local tools="" libtest="" dbtest="" out=""
  eval "tools=\"\${IMAGE_TOOLS_$key}\""
  if ! "$rt" image inspect "$img" >/dev/null 2>&1; then
    if [ "$mode" = optional ]; then
      echo "    $img  absent (optional escalation image; build from references/containers/Dockerfile.$s when a finding needs it)"
      return 0
    fi
    echo "    $img  ABSENT -- build from references/containers/Dockerfile.$s (then re-run --probe)"
    return 1
  fi
  # --assert-tools exits 0 only when every named tool answers inside the image;
  # non-zero names the missing ones. This is the authoritative check.
  if out="$(bash "$RUN_CONTAINED" --assert-tools "$img" "$tools" 2>&1)"; then
    echo "    $img  OK ($tools)"
  else
    echo "    $img  FAIL -- $out"
    fail=1
  fi
  # Library assertion: prove each imported package LOADS, not merely that pip or
  # npm wrote it to disk. A native addon can install and still fail at dlopen.
  eval "libtest=\"\${IMAGE_LIBS_$key:-}\""
  if [ -n "$libtest" ]; then
    if "$rt" run --rm --network none "$img" sh -c "$libtest" >/dev/null 2>&1; then
      echo "    $img  LIBS OK (harness imports load)"
    else
      echo "    $img  LIBS FAIL -- a harness library is missing or fails to load ($libtest); rebuild from references/containers/Dockerfile.$s"
      fail=1
    fi
  fi
  # Baked-DB assertion: a present tool with an EMPTY DB is a false-clean under
  # --network none (isolation.md, Baked offline databases). Prove the DB has
  # records, not just that the tool answers.
  eval "dbtest=\"\${IMAGE_DB_$key:-}\""
  if [ -n "$dbtest" ]; then
    if "$rt" run --rm --network none "$img" sh -c "$dbtest" >/dev/null 2>&1; then
      echo "    $img  DB OK (baked offline data non-empty)"
    else
      echo "    $img  DB FAIL -- a baked offline DB is missing or empty; rebuild from references/containers/Dockerfile.$s"
      fail=1
    fi
  fi
  return "$fail"
}

probe() {
  echo "sabot host preflight (tools run in the container, not here):"
  local fail=0

  # Container runtime -- without one, the execution phases cannot run at all.
  local rt=""
  rt="$(find_runtime || true)"
  if [ -n "$rt" ]; then
    echo "  runtime:  $rt  (context: $("$rt" context show 2>/dev/null || echo default))"
  else
    echo "  runtime:  MISSING -- no docker or finch (the runtimes run-contained.sh drives). The campaign ABORTS: no runtime, no run (isolation.md, No container runtime)."
    fail=1
  fi

  # Free disk. A campaign filled a 460 GiB volume to 100% with compiler output, after
  # which containerd could not grow its sparse disk, image blobs returned
  # `input/output error`, and no container would start on any image. That is
  # unrecoverable mid-run, so it is a precondition here rather than a runtime surprise.
  # 20 GiB covers a surface image build plus one cold workspace compile.
  local free_mb
  free_mb="$(df -Pm "${TMPDIR:-/tmp}" 2>/dev/null | awk 'NR==2 {print $4}')"
  case "$free_mb" in
    ''|*[!0-9]*) echo "  disk:     UNKNOWN -- could not read df; verify headroom by hand before a build phase." ;;
    *)
      if [ "$free_mb" -lt 20480 ]; then
        echo "  disk:     ${free_mb} MiB free -- BELOW the 20480 MiB a build phase needs. Free space first; a full disk corrupts the runtime's content store and cannot be retried out of."
        fail=1
      else
        echo "  disk:     ${free_mb} MiB free"
      fi ;;
  esac

  # bd + git -- the orchestration primitives the agent needs on the host.
  command -v bd  >/dev/null 2>&1 && echo "  bd:       $(bd version 2>/dev/null | head -1)" || { echo "  bd:       MISSING -- required for the run graph (beads-store.md)."; fail=1; }
  command -v git >/dev/null 2>&1 && echo "  git:      $(git --version 2>/dev/null)"        || { echo "  git:      MISSING -- required to resolve the target (targeting.md)."; fail=1; }

  # Per-image tool assertion. For each built image, prove EVERY expected tool answers
  # inside it. A missing image or a missing tool is a FAIL, not a footnote.
  if [ -n "$rt" ]; then
    echo "  images (asserting every expected tool answers inside each):"
    local s
    for s in $SURFACES; do
      # --images scopes the language images to the ones this campaign uses. base carries
      # the cross-surface scanners every campaign runs, so it is always required.
      if [ -n "$IMAGES" ] && [ "$s" != base ] && ! in_list "$s" "$IMAGES"; then
        echo "    sabot/$s:1  not required (not in --images $IMAGES)"
        continue
      fi
      assert_surface "$s" required "$rt" || fail=1
    done
    for s in $OPTIONAL_SURFACES; do
      if in_list "$s" "$IMAGES"; then
        assert_surface "$s" required "$rt" || fail=1
      else
        assert_surface "$s" optional "$rt" || fail=1
      fi
    done
  fi

  if [ "$fail" -ne 0 ]; then
    echo "preflight: FAILED -- a precondition or a tool is missing above. Fix it before the campaign; a missing scanner reported as present returns a meaningless clean." >&2
    return 1
  fi
  echo "preflight: OK -- runtime, bd, git present and every expected tool answered inside its image."
}

usage() {
  cat <<'EOF'
usage: install-tools.sh [--probe] [--images NAME,NAME...] | --help

  --probe   (default) authoritative host preflight: container runtime, bd, git, and
            an assertion that EVERY expected tool answers inside its surface image.
            Exits non-zero if any precondition or tool is missing.
  --images  the sabot/<name>:1 images this campaign uses, from: rust python node go
            rust-extras scanners heavy. base is always required; a language image not
            named is not asserted, and a named escalation image becomes required.
            Without it every language image is required.

This script installs nothing. Target-touching tools run in the surface image; see
references/isolation.md (Provisioning) and scripts/detect-stacks.py.
EOF
}

IMAGES=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --probe) shift ;;
    --images)
      [ "$#" -ge 2 ] || { echo "install-tools.sh: --images needs a comma-separated list" >&2; usage >&2; exit 2; }
      IMAGES="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "install-tools.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
# An unknown name would assert nothing and pass, which is the fail-open this preflight
# exists to refuse.
if [ -n "$IMAGES" ]; then
  case ",$IMAGES," in *",,"*) echo "install-tools.sh: --images has an empty name" >&2; exit 2 ;; esac
  for name in $(printf '%s' "$IMAGES" | tr ',' ' '); do
    in_list "$name" "$(printf '%s' "$SURFACES $OPTIONAL_SURFACES" | tr ' ' ',')" || {
      echo "install-tools.sh: --images names an unknown image: '$name'" >&2; usage >&2; exit 2; }
  done
fi
probe
