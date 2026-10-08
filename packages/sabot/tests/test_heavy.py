#!/usr/bin/env python3
"""Tests for the heavy layer: the JVM analysis engines in their own image.

Two invariants matter here. The first is that CodeQL's absence is recorded as a PLATFORM
gap rather than left looking like an unfinished bake -- no linux-arm64 build of it exists,
so a report that would have run it must name the gap. The second is Joern's probe: its
value is the CPG, and a version string says nothing about whether a CPG can be built, so
the layer must assert the graph itself.

Reads the layer as text. No container, no network.

Run: pytest packages/sabot/tests/test_heavy.py
"""

import re
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1] / ".apm/skills/sabotage"
LAYER = SKILL / "references/containers/layers/heavy.sh"
DOCKERFILE = SKILL / "references/containers/Dockerfile.heavy"
MATRIX = SKILL / "references/tool-coverage-matrix.md"
BODY = LAYER.read_text()

PINNED = ["JOERN_VERSION", "ZAP_VERSION"]


def test_every_download_is_pinned():
    """An unpinned release URL makes the image unreproducible."""
    for var in PINNED:
        assert re.search(rf"^{var}=v?[0-9][^\s]*$", BODY, re.M), f"{var} must be pinned"


def test_pins_carry_renovate_comments():
    for var in PINNED:
        assert re.search(rf"# renovate:[^\n]*\n{var}=", BODY), \
            f"{var} needs a '# renovate:' line so renovate.json can see it"


def test_joern_download_is_checksum_verified():
    """The layer pulls 1.8GB over the network at build time; verify it."""
    assert "sha512sum -c" in BODY, "verify the Joern zip against its published digest"


def test_joern_arch_is_mapped_not_assumed():
    """Joern spells x86_64 where dpkg says amd64, so the dpkg name cannot be reused."""
    assert "dpkg --print-architecture" in BODY
    assert "joern_arch=x86_64" in BODY, "amd64 must map to Joern's x86_64 spelling"
    assert "joern_arch=arm64" in BODY


def test_joern_install_script_is_not_used():
    """Upstream's install.sh fetches at run time and writes to $HOME; neither works here."""
    assert "install.sh" in BODY, "record why the upstream installer is declined"
    assert not re.search(r"^\s*(bash|sh)\s+\S*install\.sh", BODY, re.M), \
        "the upstream installer fetches at run time against a read-only image"


def test_a_jre_is_installed_because_base_has_none():
    """Measured on sabot/base:1: `java: not found`. Both engines are JVM."""
    assert "default-jre-headless" in BODY, "base ships no JVM; the layer must add one"
    assert "default-jre " not in BODY, "headless: a campaign container has no display"


def test_the_probe_builds_a_real_cpg_not_just_a_version_string():
    """`joern --version` answers while a missing jar or unwritable HOME goes unseen."""
    assert "joern-parse" in BODY, "assert the WORK: parse a source file into a CPG"
    assert 'test -s "$probe/cpg.bin"' in BODY, \
        "assert the graph exists and is non-empty, not just that the command exited 0"


def test_the_probe_home_is_not_root():
    """Joern writes its workspace under $HOME; at /root the breaker user cannot read it."""
    assert re.search(r"^export HOME=/opt/", BODY, re.M), \
        "the probe must not leave root-owned Joern state the campaign cannot use"


def test_zap_uses_the_core_zip():
    """A --network none campaign cannot install add-ons, so the full bundle is dead weight."""
    assert "_Core.zip" in BODY
    assert "Linux.tar.gz" not in BODY


def test_the_zap_zip_is_checksum_verified_before_it_is_unpacked():
    """ZAP ships no checksum file, so an unverified 108MB zip ran in an auditor's image."""
    pin = re.search(r"^ZAP_CORE_SHA256=([0-9a-f]+)$", BODY, re.M)
    assert pin and len(pin.group(1)) == 64, "pin the Core zip's SHA-256 in the layer"
    verify = BODY.find('echo "${ZAP_CORE_SHA256}  /tmp/zap.zip" | sha256sum -c --strict -')
    assert verify != -1, "verify /tmp/zap.zip against the pinned digest"
    assert BODY.index("curl -fsSL -o /tmp/zap.zip") < verify < BODY.index(
        "unzip -q /tmp/zap.zip"), "verify after the download and before the unzip"
    # The digest pin is not a renovate-tracked version: a bump must fail on it.
    assert not re.search(r"# renovate:[^\n]*\nZAP_CORE_SHA256=", BODY)


def test_permissions_are_fixed_after_the_last_write():
    """A chmod before the probe leaves its new $HOME state root-only for uid 1000."""
    probe = BODY.index("joern-parse")
    chmods = [m.start() for m in re.finditer(r"^chmod -R a\+rX", BODY, re.M)]
    assert chmods, "the campaign runs as uid 1000 and needs read access"
    assert max(chmods) > probe, "chmod must run after the last root write"


def test_codeql_absence_is_recorded_as_a_platform_gap():
    """It is not an unfinished bake: no linux-arm64 build of CodeQL exists at all."""
    assert "CodeQL is NOT here" in BODY, "say why, or it reads as an oversight"
    assert "linux-arm64" in BODY
    matrix = MATRIX.read_text()
    assert "NO linux-arm64 build exists" in matrix, \
        "the matrix must not leave CodeQL looking merely fragment-pending"
    assert "codeql-cli-binaries#157" in matrix, "cite the upstream decision"


def test_dockerfile_builds_on_base_not_a_language_surface():
    text = DOCKERFILE.read_text()
    assert "ARG BASE=sabot/base:1" in text, \
        "neither engine reads a language toolchain; stacking would duplicate 1GB per surface"
    assert "heavy.sh" in text
    assert "USER breaker" in text, "the campaign must not run as root"
