#!/usr/bin/env bash
set -euxo pipefail

# base-extras.sh -- the mutators, reducers, and remaining config/secret scanners for
# the sabot base image.
#
# Split from Dockerfile.base as its own layer so a rebuild of the cross-surface floor
# does not re-download this set, and so the reason each tool is here stays next to it.
#
# WHAT IS HERE
#   radamsa, zzuf   black-box mutators. The fuzzer role reaches for these when a target
#                   has no harness-able API but does parse a file or stream. Both are
#                   self-contained: no rules, no DB, nothing to bake.
#   C-Reduce        test-case reducer. A 182-byte repro that reduces to 16 bytes is the
#                   difference between a report an author can act on and one they cannot.
#                   Its interestingness test MUST reference the file by RELATIVE path:
#                   C-Reduce runs the test in a temp dir with the VARIANT as ./<file>, so
#                   an absolute path re-reads the original, every check passes, and the
#                   reduction stops early while still LOOKING like it worked (measured:
#                   182 -> 163 bytes, with the dead code still in place).
#   hadolint        Dockerfile linter, rules compiled in.
#   kube-linter     k8s manifest linter, checks compiled in.
#   tflint          terraform linter. The CORE ruleset is compiled in; provider plugins
#                   are fetched from GitHub at `tflint --init`, which --network none
#                   forbids, so the campaign runs core-only and the report must say so.
#   poutine         CI/CD supply-chain scanner, rules compiled in.
#   TruffleHog      secret scanner. MUST be invoked with --no-update AND
#                   --no-verification. It checks for a new release on every start and
#                   tries to overwrite its own binary, which on the read-only container
#                   aborts the whole scan with "cannot move binary" and zero findings.
#                   Detectors are compiled in, but VERIFICATION calls each provider's
#                   API, so an offline run is detection-only and must say so: the
#                   summary reports verified_secrets 0 whatever it found.
#
# WHAT IS DELIBERATELY NOT HERE
#   Grype           its vulnerability DB measures 2.0GB (measured, v0.117.0), and the
#                   base image is inherited by every surface. trivy and osv-scanner are
#                   already baked and cover the same ecosystems, so the third scanner
#                   buys overlap at triple the image size. Recorded as a declined bake
#                   in tool-coverage-matrix.md, not a gap.
#   OSSF-Scorecard  scores a repo through the GitHub API with no offline mode. An
#                   irreducible gap, documented as one.
#
# Runs as root at build time (Dockerfile.base invokes it).
#
# Every pinned version carries a '# renovate:' line so containers/renovate.json tracks
# it. radamsa is pinned by commit SHA: it has no release tags, and renovate's semver
# datasource cannot track a bare SHA, so it is advanced by hand.

# renovate: datasource=github-releases depName=hadolint/hadolint
HADOLINT_VERSION=2.15.1
# renovate: datasource=github-releases depName=stackrox/kube-linter
KUBELINTER_VERSION=0.8.3
# renovate: datasource=github-releases depName=terraform-linters/tflint
TFLINT_VERSION=0.64.0
# renovate: datasource=github-releases depName=boostsecurityio/poutine
POUTINE_VERSION=1.1.6
# renovate: datasource=github-releases depName=trufflesecurity/trufflehog
TRUFFLEHOG_VERSION=3.97.0
# radamsa has no release tags; pinned by commit SHA and advanced by hand.
RADAMSA_SHA=5c32c29e9f7d5f0c7fef10fa9a969f78e4bde95f

# zzuf and C-Reduce come from Debian, which is the only packaging either has that does
# not require building a compiler plugin. libc6-dev is NOT optional for the radamsa
# build below: its bundled Owl Lisp compiler fails "compilation terminated" without the
# C headers, and the failure names ol.c rather than the missing package.
apt-get update -q
apt-get install -y --no-install-recommends \
	zzuf creduce gcc make libc6-dev
rm -rf /var/lib/apt/lists/*

# radamsa builds from source: no distro package, no release binary. The build emits
# bin/radamsa plus bin/ol (its Owl Lisp compiler), and only the former is needed at
# campaign time.
git clone -q https://gitlab.com/akihe/radamsa.git /tmp/radamsa
git -C /tmp/radamsa checkout -q "$RADAMSA_SHA"
make -C /tmp/radamsa >/dev/null
install -m 0755 /tmp/radamsa/bin/radamsa /usr/local/bin/radamsa
rm -rf /tmp/radamsa

arch="$(dpkg --print-architecture)"
case "$arch" in
arm64) hl=arm64 kl=arm64 tf=arm64 po=arm64 th=arm64 ;;
amd64) hl=x86_64 kl=amd64 tf=amd64 po=x86_64 th=amd64 ;;
*)
	echo "sabot base-extras: unsupported arch: $arch" >&2
	exit 1
	;;
esac

curl -fsSL -o /usr/local/bin/hadolint \
	"https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-linux-${hl}"
curl -fsSL -o /usr/local/bin/kube-linter \
	"https://github.com/stackrox/kube-linter/releases/download/v${KUBELINTER_VERSION}/kube-linter-linux_${kl}"
curl -fsSL -o /tmp/tflint.zip \
	"https://github.com/terraform-linters/tflint/releases/download/v${TFLINT_VERSION}/tflint_linux_${tf}.zip"
unzip -o -q /tmp/tflint.zip -d /usr/local/bin
rm /tmp/tflint.zip
curl -fsSL "https://github.com/boostsecurityio/poutine/releases/download/v${POUTINE_VERSION}/poutine_Linux_${po}.tar.gz" |
	tar -xz -C /usr/local/bin poutine
curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${th}.tar.gz" |
	tar -xz -C /usr/local/bin trufflehog
chmod +x /usr/local/bin/hadolint /usr/local/bin/kube-linter /usr/local/bin/tflint \
	/usr/local/bin/poutine /usr/local/bin/trufflehog

# Prove each tool RUNS. For the two MUTATORS that is not enough: radamsa and zzuf both
# answer --version while emitting their input unchanged if a build went wrong, and a
# mutator that does not mutate turns a fuzzing campaign into a single-input test that
# reports a clean. Assert the output is NON-EMPTY and DIFFERS from the input: empty
# output differs from any seed, so a mutator that errored at mutate time used to pass.
# pipefail makes that error fail the build too, and no `head` truncates the pipe, so a
# long mutation cannot SIGPIPE the mutator into a false failure.
radamsa --version
zzuf --version
creduce --version
hadolint --version
kube-linter version
tflint --version
poutine version
# --no-update on every invocation, including this one: trufflehog tries to replace its
# own binary at startup, which fails on a read-only filesystem and takes the scan with
# it rather than degrading.
trufflehog --no-update --version

seed=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
for i in 1 2 3 4 5 6 7 8; do
	out="$(printf '%s' "$seed" | radamsa --seed "$i" | tr -d '\0')"
	[ -n "$out" ] && [ "$out" != "$seed" ] && break
done
[ -n "$out" ] && [ "$out" != "$seed" ] || {
	echo "base-extras: radamsa produced no output or its input unchanged in 8 attempts; the mutator is broken" >&2
	exit 1
}
out="$(printf '%s' "$seed" | zzuf -r 0.3 -s 42 | tr -d '\0')"
[ -n "$out" ] && [ "$out" != "$seed" ] || {
	echo "base-extras: zzuf produced no output or its input unchanged; the mutator is broken" >&2
	exit 1
}
echo "base-extras: radamsa and zzuf both mutate; scanners and reducer answer"
