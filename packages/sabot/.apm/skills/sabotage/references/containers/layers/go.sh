#!/usr/bin/env bash
set -eux

# go.sh -- the go language fragment for the sabot base image.
#
# Installs the TOOLCHAIN ITSELF, not just linters. Go's fuzzer is `go test -fuzz`,
# built into the toolchain, so the surface has a coverage-guided fuzzer the moment the
# compiler is present -- no separate fuzz binary to install, and nothing to bake for it
# (contrast cargo-fuzz, which links libfuzzer-sys from the registry). gosec and
# golangci-lint are the code tools on top. Both TYPE-CHECK, so both need the target's
# module deps resolvable, which is what build-ext-image.sh's `go mod download` bake
# provides.
#
# GOPROXY=off and GOFLAGS=-mod=mod are the offline contract. Left at its default, a
# `go build` with a missing dep under --network none blocks on proxy.golang.org until
# the dial times out, then reports a network error that reads like a broken image.
# GOPROXY=off makes the same case fail immediately and name the missing module, which
# is the fails-loud behavior the campaign can act on.
#
# GOMODCACHE points at the shared /deps prefix, the SAME one build-ext-image.sh
# fetches a target's module deps into. GOCACHE is NOT baked: run-contained.sh redirects
# it to the /scratch tmpfs (the image is mounted read-only, so a build cannot write to
# /deps at run time anyway), which means a warmed std-library cache in the image would
# never be read.
#
# Runs as root at build time (Dockerfile.go invokes it); the toolchain lands under
# /usr/local/go so the non-root breaker user can run every tool.
#
# Every version is pinned and annotated with a '# renovate:' line so
# containers/renovate.json tracks it.

# renovate: datasource=golang-version depName=go
GO_VERSION=1.26.6
# renovate: datasource=github-releases depName=securego/gosec
GOSEC_VERSION=2.28.0
# renovate: datasource=github-releases depName=golangci/golangci-lint
GOLANGCI_VERSION=2.12.2

export GOROOT=/usr/local/go
export GOPATH=/deps/go
export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"

# The go distribution names arm64 as arm64 and x86_64 as amd64, matching dpkg, so no
# per-tool arch map is needed here (the base image needs one because each upstream
# release spells the arch differently).
arch="$(dpkg --print-architecture)"
case "$arch" in
arm64 | amd64) ;;
*)
	echo "sabot go: unsupported arch: $arch" >&2
	exit 1
	;;
esac

curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" | tar -xz -C /usr/local

curl -fsSL "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${arch}.tar.gz" |
	tar -xz -C /usr/local/bin gosec
curl -fsSL "https://github.com/golangci/golangci-lint/releases/download/v${GOLANGCI_VERSION}/golangci-lint-${GOLANGCI_VERSION}-linux-${arch}.tar.gz" |
	tar -xz -C /usr/local/bin --strip-components=1 \
		"golangci-lint-${GOLANGCI_VERSION}-linux-${arch}/golangci-lint"
chmod +x /usr/local/bin/gosec /usr/local/bin/golangci-lint

# The module cache prefix, owned by the breaker uid because a later ext-image
# `go mod download` runs as uid 1000 and writes into it.
mkdir -p "$GOPATH/pkg/mod"
chown -R 1000:1000 /deps
chmod -R a+rX /usr/local/go /deps

# Prove each tool RUNS, not merely that the tarball unpacked. gosec and golangci-lint
# are compiled against a specific go version; a mismatch surfaces here rather than at
# campaign time. The gosec check is a real scan of a throwaway module with a seeded
# G404 (weak RNG), because `gosec --version` answers without loading a single rule --
# the degraded-silent case this package exists to catch.
go version
golangci-lint --version
gosec --version
# NOT under /tmp: go refuses to read a go.mod that sits in the system temp root, so a
# probe module in mktemp -d would fail "does not contain main module".
probe=/opt/sabot-go-probe
mkdir -p "$probe"
cat >"$probe/go.mod" <<EOF
module probe

go 1.25
EOF
cat >"$probe/main.go" <<'EOF'
package main

import "math/rand"

func main() { println(rand.Intn(10)) }
EOF
(
	cd "$probe"
	# `|| true` is deliberate: gosec exits non-zero BECAUSE it found the planted G404,
	# so its status cannot distinguish a finding from a crash. The grep below is the
	# real assertion -- a crashed gosec writes no G404 and fails the probe there.
	# Redirected rather than piped through tee, so no pipeline stage owns the status.
	GOFLAGS='' GOPROXY=off gosec ./... >"$probe/out.txt" 2>&1 || true
	grep -q G404 "$probe/out.txt" || {
		cat "$probe/out.txt" >&2
		exit 1
	}
	echo "gosec baked (rules load: G404 found on the probe module)"
)
rm -rf "${probe:?}"
