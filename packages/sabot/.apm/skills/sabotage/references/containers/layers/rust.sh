#!/usr/bin/env bash
set -eux

# rust.sh -- the rust language fragment for the sabot base image.
#
# Installs the TOOLCHAIN ITSELF, not just linters: the target's build/test and the
# dev-dep bake (build-ext-image.sh) need a compiler, and cargo-fuzz's libFuzzer needs
# a nightly toolchain with -Zsanitizer. rustup installs a pinned stable plus a pinned
# nightly; clippy ships inside the toolchain. cargo-fuzz, cargo-audit, and cargo-geiger are the
# rust code/robustness tools on top (cargo-geiger counts unsafe usage across the
# dependency tree, a supply-chain signal for the #2 threat).
#
# OFFLINE DATA baked here so a `--network none` campaign is honest (isolation.md,
# Provisioning): the RUSTSEC advisory-db `cargo audit` reads, and the cargo-fuzz
# runtime crates (libfuzzer-sys, arbitrary) a generated `fuzz/` target links. Without
# these baked, `cargo audit` loads 0 advisories and a fuzz build fails to resolve its
# runtime deps under --network none -- a silent false-clean.
#
# g++ is installed alongside gcc because cargo-fuzz links its libFuzzer target with a
# C++ toolchain (cc-rs invokes `c++`); gcc alone fails "failed to find tool c++".
#
# Runs as root at build time (Dockerfile.rust invokes it); rustup lands under
# /usr/local (RUSTUP_HOME/CARGO_HOME) so the non-root breaker user can run every tool.
#
# Every version is pinned and annotated with a '# renovate:' line so
# containers/renovate.json tracks it. The nightly is DATE-pinned: renovate's semver
# versioning cannot bump a date channel, so it carries no renovate comment and is
# advanced by hand when a toolchain feature requires it. The advisory-db is a rolling
# git repo with no release tags; it is pinned by commit SHA (ADVISORY_DB_SHA) and
# advanced by hand, since renovate's semver datasource cannot track a bare SHA.

# renovate: datasource=github-releases depName=rust-lang/rust
RUST_STABLE=1.97.1
RUST_NIGHTLY=nightly-2026-07-29
# renovate: datasource=crate depName=cargo-fuzz
CARGO_FUZZ_VERSION=0.13.2
# cargo-audit 0.22+ is required to parse the advisory-db's CVSS v4.0 vectors; 0.21.2
# aborts "unsupported CVSS version: 4.0" loading the current db.
# renovate: datasource=crate depName=cargo-audit
CARGO_AUDIT_VERSION=0.22.2
# renovate: datasource=crate depName=cargo-geiger
CARGO_GEIGER_VERSION=0.13.0
# cargo-fuzz 0.13.2 generates a fuzz/ target depending on these; baked so a generated
# target links offline. Kept in lockstep with what `cargo fuzz init` writes.
# renovate: datasource=crate depName=libfuzzer-sys
LIBFUZZER_SYS_VERSION=0.4.13
# renovate: datasource=crate depName=arbitrary
ARBITRARY_VERSION=1.4.2
# RUSTSEC advisory-db, a tag-less rolling repo; pinned by commit SHA and advanced by
# hand (renovate's semver datasource cannot track a bare SHA).
ADVISORY_DB_SHA=69f93e1d081d8b6fbee010e48f0b5e0d13661415

export RUSTUP_HOME=/usr/local/rustup
export CARGO_HOME=/usr/local/cargo
export PATH=/usr/local/cargo/bin:$PATH

# Only the toolchain's own C dependencies are here. A target's native -sys libraries (a
# Tauri app's GTK/webkit stack) are installed by the ext image, from the target's
# Cargo.lock: build-ext-image.sh reads detect-stacks.py's `system_packages` and asserts
# pkg-config resolves each one, so every other Rust campaign does not carry the stack.
apt-get update -q
apt-get install -y --no-install-recommends \
	gcc g++ libc6-dev pkg-config libssl-dev
rm -rf /var/lib/apt/lists/*

# rustup detects the host arch itself, so the download is arch-correct with no map.
curl -fsSL https://sh.rustup.rs |
	sh -s -- -y --no-modify-path --profile minimal \
		--default-toolchain "$RUST_STABLE" --component clippy --component rustfmt
rustup toolchain install "$RUST_NIGHTLY" --profile minimal
rustup component add --toolchain "$RUST_NIGHTLY" rust-src

# A `nightly` channel alias -> the dated toolchain, so `cargo +nightly` (what the
# fuzzing recipe invokes) resolves WITHOUT rustup trying to sync `nightly` over the
# network, which fails under --network none.
ln -sfn "$RUSTUP_HOME/toolchains/${RUST_NIGHTLY}-"* \
	"$RUSTUP_HOME/toolchains/nightly-$(rustc -vV | sed -n 's/^host: //p')"

# The same alias for `stable`, and for the same reason. A target that pins
# `channel = "stable"` in its own rust-toolchain.toml overrides this image's default
# toolchain by NAME, and rustup then tries to sync `stable` over the network -- which
# under --network none fails before a single crate compiles. Measured: the desktop_shell
# crate could not be built at all until RUSTUP_TOOLCHAIN was forced by hand on the docker
# command line, which is a repair no recipe carries and no gremlin would think to add.
# The pinned stable IS what the image installed, so the alias makes the target's own
# pin resolve to it rather than to a fetch.
ln -sfn "$RUSTUP_HOME/toolchains/${RUST_STABLE}-"* \
	"$RUSTUP_HOME/toolchains/stable-$(rustc -vV | sed -n 's/^host: //p')"

cargo install cargo-fuzz --locked --version "$CARGO_FUZZ_VERSION"
cargo install cargo-audit --locked --version "$CARGO_AUDIT_VERSION"
cargo install cargo-geiger --locked --version "$CARGO_GEIGER_VERSION"

# Bake the RUSTSEC advisory-db `cargo audit --no-fetch --db` reads offline. The
# campaign points --db here; without it `cargo audit` loads 0 advisories and reports a
# clean it did not earn.
#
# .git is KEPT rather than deleted. cargo-audit needs only the markdown tree, but
# cargo-deny reads HEAD's commit timestamp to judge whether the db is stale, and against
# a .git-less copy it aborts:
#
#   failed to get 'FETCH_HEAD' metadata: failed to get HEAD timestamp
#   fatal: not a git repository
#
# A SHALLOW fetch of the pinned SHA, not a full clone reduced afterwards. Measured, a
# full clone leaves 3147 reachable commits and 48MB (40MB of it .git) even after
# `gc --prune=now`, because every ref's history is still reachable from the pinned
# commit itself. Fetching one commit gives 6.0MB total with the same 901 crate
# directories and the same HEAD timestamp -- and the wrapper COPIES this tree into a 2g
# tmpfs on every run, so the 8x is per-run cost, not just image size.
git init -q /usr/local/advisory-db
git -C /usr/local/advisory-db remote add origin https://github.com/rustsec/advisory-db
git -C /usr/local/advisory-db fetch -q --depth 1 origin "$ADVISORY_DB_SHA"
git -C /usr/local/advisory-db checkout -q FETCH_HEAD
# The campaign runs as uid 1000 against a repo owned by root, and git refuses "dubious
# ownership" on a repo it does not own -- which cargo-deny surfaces as a missing db
# rather than a permissions problem. The wildcard rather than this one path because
# run-contained.sh copies the db to a tmpfs before cargo-deny reads it (the tool takes
# an exclusive lock, which the read-only image refuses), and the target repo mounted at
# /target is root-owned too. Scoped to a single-purpose audit container that holds no
# repo a campaign should distrust: the target is mounted read-only and never built from
# its own git metadata.
git config --system --add safe.directory '*'

# Bake the cargo-fuzz runtime crates into the /deps/cargo registry so a generated
# fuzz/ target links under --network none. This is the SAME /deps prefix
# build-ext-image.sh fetches a target's dev-deps into and run-contained.sh symlinks
# into the run-time CARGO_HOME, so the fuzz runtime and a target's dev-deps share one
# registry. Owned by the breaker uid so a later ext-image fetch (run as uid 1000) can
# add to it. cargo fetch on a throwaway manifest naming the exact pins populates the
# registry cache+index; the audited source never enters.
mkdir -p /deps
FUZZDEPS="$(mktemp -d)"
cat > "$FUZZDEPS/Cargo.toml" <<EOF
[package]
name = "fuzzdeps"
version = "0.0.0"
edition = "2021"
[dependencies]
libfuzzer-sys = "=$LIBFUZZER_SYS_VERSION"
arbitrary = "=$ARBITRARY_VERSION"
EOF
mkdir -p "$FUZZDEPS/src"
: > "$FUZZDEPS/src/lib.rs"
(cd "$FUZZDEPS" && CARGO_HOME=/deps/cargo cargo fetch)
rm -rf "${FUZZDEPS:?}"
chown -R 1000:1000 /deps

# World-readable so the non-root user reads the toolchain, registry cache, and db.
chmod -R a+rX /usr/local/rustup /usr/local/cargo /usr/local/advisory-db /deps

rustc --version
cargo fmt --version
cargo clippy --version
cargo +nightly --version
cargo-fuzz --version
cargo-audit --version
cargo-geiger --version
test -f /usr/local/advisory-db/crates/time/RUSTSEC-2020-0071.md \
	&& echo "advisory-db baked (pinned $ADVISORY_DB_SHA)"
