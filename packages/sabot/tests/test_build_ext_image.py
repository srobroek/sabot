#!/usr/bin/env python3
"""Tests for build-ext-image.sh, the dev-dep bake into a surface image.

The ext image lets a --network none campaign use the target's dev-deps (a
`cargo test` that pulls `proptest`). The invariant this file guards: the build
context copies ONLY manifests + lockfiles, never the target source, so no audited
code enters a persisted layer (isolation.md, "Never COPY the target source").

The tests read the generated Dockerfile via --dry-run (no build), and drive a real
build path against a stub `docker` on PATH that records its args (the pattern from
test_report_json.py's stub bd / test_detect_stacks.py's real git repos).

Run: pytest packages/sabot/tests/test_build_ext_image.py
Stdlib plus pytest; needs `git` on PATH. No real docker, no network.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / ".apm" / "skills" / "sabotage" / "scripts" / "build-ext-image.sh"
)


def make_repo(root: Path, files: dict[str, str]):
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    # --no-gpg-sign, not just an identity override: a global `commit.gpgsign=true` with an
    # agent-backed signer (1Password's op-ssh-sign) blocks on an interactive approval that
    # never comes under pytest, and the whole suite hangs at this line with no output.
    subprocess.run(
        ["git", "-c", "user.email=t@t.co", "-c", "user.name=t",
         "commit", "--no-gpg-sign", "-qm", "init"],
        cwd=root, check=True,
    )


def dry_run(target: Path, base="sabot/rust:1", tag="sabot/rust-ext:1", stack_skip=""):
    # SABOT_STACK_SKIP pins the base's provisionable stacks so the emitted Dockerfile
    # does not depend on which surface images this host happens to have built.
    r = subprocess.run(
        ["bash", str(SCRIPT), "--target", str(target), "--base", base, "--tag", tag, "--dry-run"],
        capture_output=True, text=True,
        env=dict(os.environ, SABOT_STACK_SKIP=stack_skip),
    )
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_froms_the_given_base(tmp_path):
    make_repo(tmp_path, {"Cargo.toml": "[package]\nname='x'\n", "Cargo.lock": "", "src/lib.rs": "fn x(){}"})
    df = dry_run(tmp_path, base="sabot/rust:1")
    assert df.splitlines()[0] == "FROM sabot/rust:1"


def test_copies_only_manifest_and_lock_never_source(tmp_path):
    make_repo(tmp_path, {
        "Cargo.toml": "[package]\nname='x'\n",
        "Cargo.lock": "# lock\n",
        "src/lib.rs": "fn secret(){}",
        "src/main.rs": "fn main(){}",
    })
    df = dry_run(tmp_path)
    copy_lines = [l for l in df.splitlines() if l.startswith("COPY")]
    assert copy_lines, df
    joined = "\n".join(copy_lines)
    assert "Cargo.toml" in joined
    assert "Cargo.lock" in joined
    # The invariant is about CONTENT, not filenames. Rust needs a src/lib.rs to exist
    # or `cargo fetch` aborts with no targets, so the script writes an EMPTY stub into
    # the build context and copies that. Asserting on the path (`".rs" not in joined`)
    # rejected the legitimate stub; assert the audited bytes stay out instead.
    assert "src/main.rs" not in joined
    assert 'open(os.path.join(stub_dir, "lib.rs"), "a").close()' in SCRIPT.read_text(), \
        "the rust src/lib.rs stub must be CREATED empty, never copied from the target"


def test_one_run_per_bake_unit(tmp_path):
    # multi-language: rust workspace root + a JS frontend => two bake units
    make_repo(tmp_path, {
        "Cargo.toml": "[workspace]\nmembers=['src-tauri']\n",
        "Cargo.lock": "",
        "src-tauri/Cargo.toml": "[package]\nname='app'\n",
        "frontend/package.json": '{"name":"f","devDependencies":{"vite":"^5"}}',
        "frontend/package-lock.json": "{}",
    })
    df = dry_run(tmp_path)
    run_lines = [l for l in df.splitlines() if l.startswith("RUN ") and ("fetch" in l or "npm" in l or "download" in l or "sync" in l)]
    assert len(run_lines) == 2, df
    assert any("cargo fetch" in l for l in run_lines)
    assert any("npm ci" in l for l in run_lines)
    # One fetch covers the workspace, but it resolves EVERY member, so each member
    # manifest has to reach the context: without src-tauri/Cargo.toml cargo exits 101
    # "failed to read .../src-tauri/Cargo.toml", and with a manifest but no target it
    # exits 101 "no targets specified" -- hence the stub lib.rs beside it.
    copied = {f for l in df.splitlines() if l.startswith("COPY") for f in l.split()[2:-1]}
    assert "src-tauri/Cargo.toml" in copied, df
    assert "src-tauri/src/lib.rs" in copied, df


def test_unprovisionable_stack_is_skipped_not_emitted(tmp_path):
    """A base image carries ONE stack's toolchain; a unit it cannot run kills the image.

    Measured on platevault: sabot/rust:1 has no npm, so a single node bake unit failed
    `npm ci` with rc=127 at step 7 of 122 and the whole ext build was lost -- after six
    successful rust steps. A stack the base cannot provision is a gap for that surface's
    own ext image, not a reason to lose this one.
    """
    make_repo(tmp_path, {
        "Cargo.toml": "[package]\nname='x'\n",
        "Cargo.lock": "",
        "frontend/package.json": '{"name":"f"}',
        "frontend/package-lock.json": "{}",
    })
    df = dry_run(tmp_path, base="sabot/rust:1", stack_skip="node")
    steps = [l for l in df.splitlines() if l.startswith(("RUN ", "COPY "))]
    assert any("cargo fetch" in l for l in steps)
    # the unconditional npm_config_cache ENV stays; no npm STEP may be emitted
    assert not [l for l in steps if "npm" in l], df
    assert not [l for l in steps if "frontend" in l], df


def test_copy_precedes_its_run_so_layer_caches_on_lock(tmp_path):
    make_repo(tmp_path, {"Cargo.toml": "[package]\nname='x'\n", "Cargo.lock": ""})
    df = dry_run(tmp_path)
    lines = df.splitlines()
    copy_idx = next(i for i, l in enumerate(lines) if l.startswith("COPY"))
    run_idx = next(i for i, l in enumerate(lines) if l.startswith("RUN cargo fetch") or l == "RUN cargo fetch")
    assert copy_idx < run_idx


def test_every_copy_chowns_to_the_build_uid(tmp_path):
    """A fetch REWRITES the lock it was copied, and COPY writes root-owned files.

    Measured: without --chown, `cargo fetch` as uid 1000 aborted the ext build with
    "failed to write /scratch/Cargo.lock: Permission denied".
    """
    make_repo(tmp_path, {"Cargo.toml": "[package]\nname='x'\n", "Cargo.lock": ""})
    df = dry_run(tmp_path)
    copies = [l for l in df.splitlines() if l.startswith("COPY")]
    assert copies
    for l in copies:
        assert l.startswith("COPY --chown=1000:1000 "), f"unowned copy: {l}"


def test_dep_cache_is_persistent_not_scratch(tmp_path):
    # /scratch is a fresh tmpfs per run (run-contained.sh); baking there is masked.
    make_repo(tmp_path, {"Cargo.toml": "[package]\nname='x'\n", "Cargo.lock": ""})
    df = dry_run(tmp_path)
    assert "CARGO_HOME=/deps/cargo" in df
    assert "/scratch" not in df


TAURI_LOCK = "".join(
    f'[[package]]\nname = "{name}"\nversion = "0.1.0"\n\n'
    for name in ("app", "glib-sys", "gtk-sys", "webkit2gtk-sys", "soup3-sys", "serde")
)


def test_a_tauri_target_gets_its_gtk_stack_in_the_ext_image(tmp_path):
    """The GTK/webkit stack moved out of the rust image into the ext layer.

    A Tauri crate cannot COMPILE without it: glib-sys shells `pkg-config glib-2.0`, and
    with no .pc file 199 platevault handlers were NOT EXECUTED. Every other Rust target
    paid for the stack, so only a target whose lock names the -sys crates installs it.
    """
    make_repo(tmp_path, {"Cargo.toml": "[package]\nname='app'\n", "Cargo.lock": TAURI_LOCK})
    df = dry_run(tmp_path)
    lines = df.splitlines()
    apt = next((i for i, l in enumerate(lines) if "apt-get install" in l), None)
    assert apt is not None, df
    for pkg in ("libglib2.0-dev", "libgtk-3-dev", "libwebkit2gtk-4.1-dev",
                "libsoup-3.0-dev"):
        assert pkg in lines[apt], f"{pkg} missing from {lines[apt]}"
    # Installed as root, before the build drops to the fetch uid.
    assert apt < lines.index("USER 1000:1000")
    assert lines.index("USER root") < apt
    # pkg-config RESOLVING each module is the assertion; the binary answering was not.
    assert 'pkg-config --exists "$pc"' in df
    for pc in ("glib-2.0", "gtk+-3.0", "webkit2gtk-4.1", "libsoup-3.0"):
        assert pc in df


def test_a_plain_rust_target_installs_no_system_packages(tmp_path):
    make_repo(tmp_path, {"Cargo.toml": "[package]\nname='x'\n", "Cargo.lock": ""})
    assert "apt-get" not in dry_run(tmp_path)


def test_a_skipped_rust_unit_contributes_no_system_packages(tmp_path):
    make_repo(tmp_path, {"Cargo.toml": "[package]\nname='app'\n", "Cargo.lock": TAURI_LOCK})
    assert "apt-get" not in dry_run(tmp_path, stack_skip="rust")


@pytest.fixture
def stub_docker(tmp_path):
    """A fake `docker` on PATH: image inspect ok, build records its argv to a file."""
    rec = tmp_path / "docker-argv.txt"
    dk = tmp_path / "docker"
    dk.write_text(
        "#!/usr/bin/env bash\n"
        f'echo "$@" >> "{rec}"\n'
        'case "$1" in\n'
        '  image) exit 0 ;;\n'          # inspect: base present
        '  build) exit 0 ;;\n'
        '  *) exit 0 ;;\n'
        'esac\n'
    )
    dk.chmod(dk.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return dk, rec


def test_build_invokes_runtime_with_tag(tmp_path, stub_docker):
    dk, rec = stub_docker
    repo = tmp_path / "repo"
    repo.mkdir()
    make_repo(repo, {"go.mod": "module x\n", "go.sum": ""})
    env = dict(os.environ, PATH=f"{dk.parent}:{os.environ['PATH']}")
    r = subprocess.run(
        ["bash", str(SCRIPT), "--target", str(repo),
         "--base", "sabot/base:1", "--tag", "sabot/base-ext:1"],
        capture_output=True, text=True, env=env,
    )
    assert r.returncode == 0, r.stderr
    argv = rec.read_text()
    assert "build" in argv
    assert "-t sabot/base-ext:1" in argv


def test_missing_target_exits_2(tmp_path):
    r = subprocess.run(
        ["bash", str(SCRIPT), "--base", "b", "--tag", "t"],
        capture_output=True, text=True,
    )
    assert r.returncode == 2


def test_help_prints_usage_and_exits_zero():
    """The provisioning agent reached for --help, got exit 2, and read the comment
    header instead. An unknown-arg rejection on --help reads as a broken script."""
    r = subprocess.run(["bash", str(SCRIPT), "--help"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    for flag in ("--target", "--base", "--tag", "--dry-run"):
        assert flag in r.stdout, f"usage omits {flag}"
    assert not r.stdout.lstrip().startswith("#"), "usage still carries comment markers"


def test_unknown_arg_still_exits_2():
    r = subprocess.run(["bash", str(SCRIPT), "--bogus"], capture_output=True, text=True)
    assert r.returncode == 2


def _runs(df):
    return [l for l in df.splitlines() if l.startswith("RUN ") and "mkdir -p /deps" not in l]


@pytest.mark.parametrize("lock", ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", None])
def test_node_fetch_runs_no_install_scripts(tmp_path, lock):
    # The bake runs with the network on, so a lifecycle script there is the install-time
    # exfil vector surfaces/build.md describes. Every node resolver must disable them.
    files = {"package.json": '{"name":"x"}'}
    if lock:
        files[lock] = "{}"
    make_repo(tmp_path, files)
    (run,) = _runs(dry_run(tmp_path, base="sabot/node:1", tag="sabot/node-ext:1"))
    assert "npm_config_ignore_scripts=true" in run, run
    assert "YARN_ENABLE_SCRIPTS=false" in run, run
    if lock in ("package-lock.json", None):
        assert "--ignore-scripts" in run, run


def test_python_bake_installs_wheels_only_and_never_builds_the_project(tmp_path):
    # The old fetch was `uv sync --frozen || pip install -e '.[dev]' || true`: uv is not in
    # the image, `-e .` builds the project (target code) from a source-free context, and
    # `|| true` reported every failure as a provisioned stack.
    make_repo(tmp_path, {
        "pyproject.toml": "[project]\nname='x'\ndependencies=['requests>=2']\n"
                          "[project.optional-dependencies]\ndev=['pytest==8.0']\n",
    })
    r = subprocess.run(
        ["bash", str(SCRIPT), "--target", str(tmp_path), "--base", "sabot/python:1",
         "--tag", "t", "--dry-run"],
        capture_output=True, text=True, env=dict(os.environ, SABOT_STACK_SKIP=""),
    )
    assert r.returncode == 0, r.stderr
    (run,) = _runs(r.stdout)
    assert "--only-binary=:all:" in run and ".sabot-requirements.txt" in run, run
    assert "|| true" not in run and "-e " not in run and "uv " not in run, run
    assert "COPY --chown=1000:1000 pyproject.toml .sabot-requirements.txt ./" in r.stdout
    assert "via pip (pyproject.toml requirements)" in r.stderr


def test_python_unit_with_no_resolver_is_reported_not_emitted(tmp_path):
    make_repo(tmp_path, {"pyproject.toml": "[tool.poetry]\nname='x'\n", "poetry.lock": ""})
    r = subprocess.run(
        ["bash", str(SCRIPT), "--target", str(tmp_path), "--base", "sabot/python:1",
         "--tag", "t", "--dry-run"],
        capture_output=True, text=True, env=dict(os.environ, SABOT_STACK_SKIP=""),
    )
    assert r.returncode == 0, r.stderr
    assert not _runs(r.stdout), r.stdout
    assert "skipped pyproject.toml" in r.stderr and "poetry" in r.stderr


def test_build_removes_its_temp_context(tmp_path, stub_docker):
    # `exec docker build` replaced the shell, so the EXIT trap never ran and every real
    # build left a bs-ext-* context behind.
    dk, _ = stub_docker
    repo = tmp_path / "repo"
    repo.mkdir()
    make_repo(repo, {"go.mod": "module x\n", "go.sum": ""})
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    env = dict(os.environ, PATH=f"{dk.parent}:{os.environ['PATH']}", TMPDIR=str(tmp))
    r = subprocess.run(
        ["bash", str(SCRIPT), "--target", str(repo),
         "--base", "sabot/base:1", "--tag", "sabot/base-ext:1"],
        capture_output=True, text=True, env=env,
    )
    assert r.returncode == 0, r.stderr
    assert not list(tmp.glob("bs-ext-*")), "temp build context leaked"
