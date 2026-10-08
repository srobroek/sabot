"""Dockerfile.base verifies every binary it downloads, and pins its base image.

The base image is an auditor's own toolchain. Nine scanner binaries came down over
HTTPS with no checksum and went straight through `tar` or `chmod +x`, on a rolling
`debian:stable-slim`, so a swapped release asset or a moved tag changed what every
campaign ran with nothing to notice. These tests read the Dockerfile as text: the
build itself is exercised by `docker build`, which the suite never runs.
"""

from __future__ import annotations

import re
from pathlib import Path

CONTAINERS = (
    Path(__file__).resolve().parents[1]
    / ".apm" / "skills" / "sabotage" / "references" / "containers"
)
BASE = (CONTAINERS / "Dockerfile.base").read_text()
SUMS = CONTAINERS / "layers" / "base-binaries.sha256"


def pinned():
    rows = {}
    for line in SUMS.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        digest, url = line.split()
        rows[url] = digest
    return rows


def versioned_tools():
    """(depName, version) for every renovate-tracked ARG in the base."""
    return re.findall(
        r"# renovate: datasource=github-releases depName=(\S+)\nARG \w+_VERSION=(\S+)", BASE)


def test_no_download_is_piped_straight_into_tar_or_left_unverified():
    assert not re.search(r"curl [^\n]*\|\s*tar", BASE), "a download is unpacked before it is verified"
    raw_curls = [l for l in BASE.splitlines() if "curl -fsSL" in l and "fetch()" not in l]
    # The only curl left is the one inside fetch(), which verifies before returning.
    assert len(raw_curls) == 1 and '"$dl/$2"' in raw_curls[0], raw_curls
    assert "sha256sum -c --strict" in BASE


def test_every_pinned_digest_is_a_sha256():
    rows = pinned()
    assert rows
    bad = {u: d for u, d in rows.items() if not re.fullmatch(r"[0-9a-f]{64}", d)}
    assert not bad, bad


def test_every_tool_version_has_both_arch_digests():
    # A renovate bump changes the URL; the matching rows must move in the same change,
    # or the build fails on the missing key. This catches the half-done bump in review.
    rows = pinned()
    missing = []
    for dep, version in versioned_tools():
        prefix = f"https://github.com/{dep}/releases/download/"
        urls = [u for u in rows if u.startswith(prefix)]
        if len(urls) != 2 or not all(version in u.split("/")[-2] for u in urls):
            missing.append((dep, version, urls))
    assert not missing, missing
    deps = {dep for dep, _ in versioned_tools()}
    stale = [u for u in rows if not any(u.startswith(f"https://github.com/{d}/") for d in deps)]
    assert not stale, f"digests for tools the base no longer installs: {stale}"


def test_base_image_is_pinned_by_digest():
    (frm,) = re.findall(r"^FROM (\S+)", BASE, re.M)
    assert re.fullmatch(r"debian:[a-z]+-slim@sha256:[0-9a-f]{64}", frm), frm


def test_osv_seed_is_not_masked_and_proves_the_offline_db_loads():
    assert "--download-offline-databases" in BASE
    seed = BASE[BASE.index("seed=\"$(mktemp -d)\""):]
    assert "|| true" not in seed.split("WORKDIR")[0]
    assert '[ "$rc" -le 1 ]' in seed, "only rc 0/1 (no vuln / vuln found) may pass the seed"
    assert "grep -q '\"lodash\"'" in seed and "grep -q '\"requests\"'" in seed


def test_pinact_is_gone_with_its_drop():
    # run-preflight.py and install-tools.sh dropped pinact; the image still installed it.
    assert "pinact" not in BASE.replace("pinact was\n# dropped", "")
