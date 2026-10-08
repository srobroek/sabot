#!/usr/bin/env python3
"""Tests for the rust-extras layer: the second tier of rust robustness tools.

The invariant that matters most here is cargo-deny's. It is the one tool in this layer
whose failure mode is loading ZERO advisories and reporting a clean, so the layer must
point it at the baked advisory-db via db-path and must prove it reads it by asserting a
known RUSTSEC id on a probe lockfile.

Reads the layer as text. No container, no network.

Run: pytest packages/sabot/tests/test_rust_extras.py
"""

import re
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1] / ".apm/skills/sabotage"
LAYER = SKILL / "references/containers/layers/rust-extras.sh"
DOCKERFILE = SKILL / "references/containers/Dockerfile.rust-extras"
INSTALL_TOOLS = SKILL / "scripts/install-tools.sh"
ISOLATION = SKILL / "references/isolation.md"
MATRIX = SKILL / "references/tool-coverage-matrix.md"
BODY = LAYER.read_text()

PINNED = [
    "CARGO_DENY_VERSION",
    "CARGO_VET_VERSION",
    "CARGO_CAREFUL_VERSION",
    "CARGO_SEMVER_CHECKS_VERSION",
    "WEGGLI_VERSION",
]


def test_every_crate_is_pinned():
    """An unpinned cargo install makes the image unreproducible."""
    for var in PINNED:
        assert re.search(rf"^{var}=[0-9][^\s]*$", BODY, re.M), f"{var} must be pinned"


def test_pins_carry_renovate_comments():
    for var in PINNED:
        assert re.search(rf"# renovate:[^\n]*\n{var}=", BODY), \
            f"{var} needs a '# renovate:' line so renovate.json can see it"


def test_installs_are_locked():
    """--locked pins the transitive tree; without it a rebuild resolves differently."""
    installs = re.findall(r"^cargo install (\S+)([^\n]*)$", BODY, re.M)
    assert len(installs) == len(PINNED), "one pinned cargo install per tool"
    for name, rest in installs:
        assert "--locked" in rest, f"cargo install {name} must pass --locked"
        assert "--version" in rest, f"cargo install {name} must pass --version"


def test_deny_config_points_at_a_writable_db_path():
    """cargo-deny locks db.lock inside db-path, which a read-only image refuses.

    Measured: --offline does NOT skip that lock, so writability is unconditional.
    """
    assert 'db-path = "/scratch/advisory-db"' in BODY, \
        "the baked path is read-only and cargo-deny cannot take its exclusive lock there"
    assert "/opt/sabot-db/deny.toml" in BODY


def test_wrapper_nests_the_db_under_cargo_denys_own_child_name():
    """db-path is a PARENT holding one dir per db-url, not the db itself.

    Measured against a flat copy, cargo-deny tried to clone the child it could not find
    and died on DNS under --network none -- a failure that reads like a network problem
    rather than a layout one.
    """
    wrapper = (SKILL / "scripts/run-contained.sh").read_text()
    nest = "advisory-db-3157b0e258782691"
    assert nest in wrapper, "the wrapper must create cargo-deny's hashed child dir"
    assert re.search(
        r"cp -r /usr/local/advisory-db .*/scratch/advisory-db/" + r"'?\"?\$?\{?ADB_NEST",
        wrapper,
    ) or f"/scratch/advisory-db/{nest}" in wrapper, \
        "the copy destination must be the nested child, not the flat db-path"


def test_the_baked_advisory_db_is_a_shallow_clone_that_keeps_its_git_dir():
    """cargo-deny reads HEAD's timestamp to judge staleness and aborts without .git.

    Measured: against a .git-less copy it failed "failed to get HEAD timestamp / fatal:
    not a git repository", which reads as a missing db rather than a stripped one.

    Shallow, not full-then-gc: a full clone stays 48MB / 3147 reachable commits even
    after `gc --prune=now`, while one fetched commit is 6.0MB with the same 901 crate
    dirs. The wrapper COPIES this tree into a 2g tmpfs every run, so it is per-run cost.
    """
    rust = (SKILL / "references/containers/layers/rust.sh").read_text()
    assert "rm -rf /usr/local/advisory-db/.git" not in rust, \
        "deleting .git breaks cargo-deny; fetch one commit instead"
    assert "--depth 1" in rust, "bake one commit, do not clone-then-prune"
    assert "safe.directory" in rust, \
        "the campaign runs as uid 1000 against a root-owned repo; git refuses it"


def test_the_rust_layer_leaves_the_tauri_gtk_stack_to_the_ext_image():
    """Only a Tauri target needs the GTK/webkit stack, so the rust image no longer bakes it.

    Measured on platevault: `tauri = { features = ["wry"] }` pulls webkit2gtk-sys ->
    gtk-sys -> glib-sys, whose build script shells `pkg-config glib-2.0 >= 2.70`; with no
    .pc file all 199 Tauri command handlers were NOT EXECUTED. build-ext-image.sh now
    installs the stack for a target whose Cargo.lock names those crates and asserts
    pkg-config resolves it (test_build_ext_image.py), so every other Rust campaign stops
    carrying four desktop libraries.
    """
    rust = (SKILL / "references/containers/layers/rust.sh").read_text()
    for pkg in ("libglib2.0-dev", "libgtk-3-dev", "libwebkit2gtk-4.1-dev",
                "libsoup-3.0-dev"):
        assert pkg not in rust, f"the rust layer still installs {pkg}"
    assert "pkg-config" in rust, "the -sys crates of every target still need pkg-config"
    assert "--component rustfmt" in rust, \
        "cargo-fmt was absent for toolchain 1.97.1, so a fmt check read as a tool gap"


def test_build_proves_cargo_deny_reads_the_baked_db_offline():
    """`docker build` HAS network: without --offline the probe passes on a fresh clone.

    That is how a broken bake shipped once. --offline is a TOP-LEVEL flag; placed after
    `check` it is rejected as unknown, so assert the order too.
    """
    assert "grep -q RUSTSEC-2020-0071" in BODY, \
        "assert a known advisory fires on the probe lockfile"
    assert "check advisories" in BODY
    assert re.search(r"cargo deny --offline .*check advisories", BODY), \
        "--offline must precede the subcommand, or the probe proves nothing offline"
    # --offline gates CRATE downloads too, so the graph must resolve before it applies.
    # Measured: without a prefetch the probe died "failed to download winapi" -- a
    # failure about the registry that says nothing about the advisory-db.
    # Anchored to line starts: the rationale comments quote both commands, and a bare
    # substring search matches the prose above the code.
    fetch = re.search(r"^\s*cargo fetch\b", BODY, re.M)
    deny = re.search(r"^\s*cargo deny --offline\b", BODY, re.M)
    assert fetch and deny and fetch.start() < deny.start(), \
        "resolve the crate graph with the build's network before asserting --offline"
    assert "cargo fetch --locked" not in BODY, \
        "the probe lockfile is hand-written and names no transitive deps; --locked rejects it"


def test_probe_lockfile_carries_source_and_checksum():
    """cargo-deny skips a package with no source, so a bare lockfile finds nothing."""
    assert "source = " in BODY
    assert "checksum = " in BODY


def test_cargo_careful_sysroot_is_built_at_build_time():
    """Rebuilding the sysroot needs crates.io, which the campaign does not have."""
    assert "cargo +nightly careful setup" in BODY, \
        "the careful sysroot cannot be built at campaign time, so bake it"
    # Match a COMMAND, not the word: the comment above it explains why --version is
    # wrong here, so a bare substring check flags its own rationale.
    assert not re.search(r"^cargo (\+\S+ )?careful --version", BODY, re.M), \
        "cargo-careful forwards args to cargo and exits 1 on --version"


def test_careful_sysroot_is_baked_where_uid_1000_can_read_it():
    """Measured: at the default ~/.cache it landed in /root and breaker could not read it."""
    assert "XDG_CACHE_HOME=/deps/cache" in BODY, \
        "the default ~/.cache is root-owned at build time"
    assert 'test -d "$XDG_CACHE_HOME/cargo-careful"' in BODY, \
        "assert setup actually wrote a sysroot rather than trusting its exit code"
    wrapper = (SKILL / "scripts/run-contained.sh").read_text()
    assert "for c in /deps/cache/*" in wrapper, \
        "the wrapper must link every baked cache into the tmpfs XDG_CACHE_HOME"


def test_miri_sysroot_is_baked_too():
    """`miri --version` answers while the sysroot it needs does not exist.

    Measured: a run-time `cargo +nightly miri test --offline` died building one, with
    "no matching package named `hashbrown` found".
    """
    assert "cargo +nightly miri setup" in BODY, \
        "miri builds its own sysroot from rust-src and needs crates.io to do it"
    assert 'test -d "$XDG_CACHE_HOME/miri"' in BODY, \
        "assert setup wrote a sysroot rather than trusting its exit code"


def test_cargo_careful_is_not_in_the_executable_probe():
    """The probe runs `<tool> --version`, which cargo-careful answers with an error."""
    body = INSTALL_TOOLS.read_text()
    m = re.search(r'^IMAGE_TOOLS_rust_extras="([^"]*)"', body, re.M)
    assert m
    assert "cargo-careful" not in m.group(1).split(","), \
        "assert cargo-careful behaviourally; --version reports it missing"


def test_permissions_are_fixed_after_the_last_write():
    """A chmod before `careful setup` leaves the new sysroot root-only for uid 1000."""
    setup = BODY.index("careful setup")
    chmods = [m.start() for m in re.finditer(r"^chmod -R a\+rX", BODY, re.M)]
    assert chmods, "the campaign runs as uid 1000 and needs read access"
    assert max(chmods) > setup, "chmod must run after the last root write"


def test_miri_is_added_to_the_dated_nightly():
    """Miri is a rustup component; adding it to `nightly` would float off the pin."""
    assert "rustup component add --toolchain" in BODY
    assert "miri" in BODY
    assert 'NIGHTLY="$(rustup toolchain list' in BODY, \
        "discover the dated nightly layers/rust.sh pinned rather than assuming one"


def test_semver_checks_build_deps_are_installed():
    """Its libgit2 build script fails with a linker error, not a missing package."""
    for pkg in ("cmake", "zlib1g-dev"):
        assert pkg in BODY, f"{pkg} is needed to build cargo-semver-checks"


def test_declined_tools_are_recorded_with_a_reason():
    """A declined bake must say why, or it reads as an oversight."""
    for tool in ("proptest", "CASR"):
        assert tool in BODY, f"{tool} was considered and declined; record it"


def test_dockerfile_builds_on_the_rust_surface():
    text = DOCKERFILE.read_text()
    assert "ARG BASE=sabot/rust:1" in text, "extras layer on the rust surface, not base"
    assert "rust-extras.sh" in text
    assert "USER breaker" in text, "the campaign must not run as root"


def test_preflight_asserts_the_extras_surface():
    body = INSTALL_TOOLS.read_text()
    m = re.search(r'^IMAGE_TOOLS_rust_extras="([^"]*)"', body, re.M)
    assert m, "rust-extras needs its own preflight manifest"
    tools = m.group(1).split(",")
    for t in ("cargo-deny", "cargo-vet", "cargo-semver-checks", "weggli"):
        assert t in tools, f"{t} is in the image but not asserted by the preflight"


def test_offline_limits_are_documented():
    """cargo-vet and cargo-semver-checks both degrade offline; say how."""
    text = ISOLATION.read_text()
    assert "cargo-vet" in text
    assert "cargo-semver-checks" in text
