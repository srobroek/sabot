#!/usr/bin/env python3
"""Tests for install-tools.sh, the host preflight.

The preflight decides whether a campaign is allowed to start, so its manifests are
the guard against a surface running with a scanner that is absent, or a fuzzer that
installed and cannot load. The invariants here:

  - Nothing installs on the host (a host-side scanner would run the target's build
    code unconfined).
  - A LIBRARY is asserted by import, never by `--version`. atheris, hypothesis, and
    fast-check ship no CLI, so naming them in the executable manifest reported them
    missing whether or not they were installed -- both a false alarm and a blind
    spot (bs-156).

The tests read the script text for its manifests, drive --help/bad-arg paths, run the
probe against a stub runtime, and run the base image's DB assertion against stub
scanners. No container, no network.

Run: pytest packages/sabot/tests/test_install_tools.py
"""

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / ".apm/skills/sabotage/scripts/install-tools.sh"
BODY = SCRIPT.read_text()

# Packages with no executable of that name. Asserting `<name> --version` on one can
# only ever fail, so the executable manifest must not name it.
LIBRARIES_ONLY = ["atheris", "hypothesis", "fast-check"]


def manifest(surface: str) -> list[str]:
    m = re.search(rf'^IMAGE_TOOLS_{surface}="([^"]*)"', BODY, re.M)
    assert m, f"no IMAGE_TOOLS_{surface} manifest in {SCRIPT.name}"
    return m.group(1).split(",")


def test_installs_nothing_on_the_host():
    """A host-side scanner would run the target's build code unconfined."""
    assert "--probe" in BODY
    for installer in ("apt-get install", "brew install", "pip install", "npm i -g"):
        assert installer not in BODY, f"preflight must not install: {installer}"


def test_executable_manifests_name_no_library():
    """A library cannot answer --version; asserting it there is always a false FAIL."""
    for surface in ("base", "rust", "python", "node"):
        for lib in LIBRARIES_ONLY:
            assert lib not in manifest(surface), \
                f"{lib} has no CLI; assert it in IMAGE_LIBS_{surface} by import instead"


def test_library_manifests_import_the_fuzz_harness_packages():
    """The packages a harness imports must be proven to LOAD, not merely installed."""
    assert 'IMAGE_LIBS_python=' in BODY
    assert "import atheris" in BODY, "atheris is the python fuzzer; assert it loads"
    assert "hypothesis" in BODY
    assert 'IMAGE_LIBS_node=' in BODY
    assert "fast-check" in BODY


def test_every_surface_keeps_its_fuzzer_asserted():
    """Each language surface must assert its coverage-guided fuzzer somehow."""
    assert "cargo-fuzz" in manifest("rust")
    assert "jazzer" in manifest("node")
    assert "import atheris" in BODY          # python's fuzzer is a library


def test_probe_failure_is_loud_and_nonzero():
    """A preflight that fails quietly lets the campaign start on a broken image."""
    assert "preflight: FAILED" in BODY
    assert "return 1" in BODY


def test_help_exits_zero():
    r = subprocess.run(["bash", str(SCRIPT), "--help"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "--probe" in r.stdout


def test_unknown_argument_is_a_usage_error():
    r = subprocess.run(["bash", str(SCRIPT), "--wat"], capture_output=True, text=True)
    assert r.returncode == 2
    assert "unknown argument" in r.stderr


# --- the probe, against a fake runtime ---------------------------------------


def executable(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


# `image inspect` succeeds only for the images in FAKE_IMAGES, and `run` fails when its
# arguments contain FAKE_FAIL, so one tool in one image can be made to not answer.
FAKE_RUNTIME = """#!/bin/sh
case "$1" in
  context) echo default ;;
  image) case " $FAKE_IMAGES " in *" $3 "*) exit 0 ;; esac; exit 1 ;;
  run) [ -n "${FAKE_FAIL:-}" ] && case "$*" in *"$FAKE_FAIL"*) exit 1 ;; esac; exit 0 ;;
esac
exit 0
"""


def probe(tmp_path: Path, *args: str, runtime: str = "docker", images: str = "",
          fail: str = "") -> subprocess.CompletedProcess:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    executable(bin_dir / runtime, FAKE_RUNTIME)
    executable(bin_dir / "bd", "#!/bin/sh\necho 'bd version 1.0.0'\n")
    executable(bin_dir / "git", "#!/bin/sh\necho 'git version 2.50.0'\n")
    # A roomy disk, so the free-space precondition never decides these tests.
    executable(bin_dir / "df", "#!/bin/sh\necho 'Filesystem 1M-blocks Used Available'\n"
                               "echo '/dev/x 999999 1 999998'\n")
    env = {**os.environ, "PATH": f"{bin_dir}:/usr/bin:/bin",
           "FAKE_IMAGES": images, "FAKE_FAIL": fail}
    return subprocess.run(["bash", str(SCRIPT), "--probe", *args],
                          capture_output=True, text=True, env=env, timeout=60)


ALL_LANGUAGE = "sabot/base:1 sabot/rust:1 sabot/python:1 sabot/node:1 sabot/go:1"


def test_every_language_image_is_required_without_a_scope(tmp_path):
    r = probe(tmp_path, images="sabot/base:1 sabot/rust:1")
    assert r.returncode == 1, r.stdout
    assert "sabot/python:1  ABSENT" in r.stdout


def test_images_scopes_the_required_set_to_the_campaign(tmp_path):
    # A shell-only or rust-only campaign failed preflight on the images it never uses.
    r = probe(tmp_path, "--images", "rust", images="sabot/base:1 sabot/rust:1")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "sabot/python:1  not required" in r.stdout
    assert "sabot/rust:1  OK" in r.stdout


def test_base_is_required_whatever_the_scope(tmp_path):
    r = probe(tmp_path, "--images", "rust", images="sabot/rust:1")
    assert r.returncode == 1
    assert "sabot/base:1  ABSENT" in r.stdout


@pytest.mark.parametrize("bad", ["bogus", "rust,,go", "base,web"])
def test_an_unknown_or_empty_image_name_is_a_usage_error(tmp_path, bad):
    # An unknown name would assert nothing and pass.
    r = probe(tmp_path, "--images", bad, images=ALL_LANGUAGE)
    assert r.returncode == 2, r.stdout + r.stderr


def test_absent_scanners_and_heavy_images_are_optional_notes(tmp_path):
    r = probe(tmp_path, images=ALL_LANGUAGE)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "sabot/scanners:1  absent (optional" in r.stdout
    assert "sabot/heavy:1  absent (optional" in r.stdout


def test_a_present_scanners_image_with_a_broken_tool_fails(tmp_path):
    # checkov is default-on for infra and shell; an unasserted image let it be broken.
    r = probe(tmp_path, images=ALL_LANGUAGE + " sabot/scanners:1",
              fail="sabot/scanners:1 sh -c command -v checkov ")
    assert r.returncode == 1, r.stdout
    assert "sabot/scanners:1  FAIL" in r.stdout
    assert "checkov" in r.stdout


def test_a_named_escalation_image_is_required(tmp_path):
    r = probe(tmp_path, "--images", "rust,heavy", images="sabot/base:1 sabot/rust:1")
    assert r.returncode == 1
    assert "sabot/heavy:1  ABSENT" in r.stdout


def test_a_runtime_run_contained_cannot_drive_is_no_runtime(tmp_path):
    # run-contained.sh drives docker or finch only; a preflight passing on podman left
    # every contained run to fail.
    r = probe(tmp_path, runtime="podman", images=ALL_LANGUAGE)
    assert r.returncode == 1
    assert "runtime:  MISSING" in r.stdout


def test_the_escalation_manifests_name_their_tools():
    assert set(manifest("scanners")) >= {"checkov", "guarddog", "nuclei", "bearer", "kingfisher"}
    assert "joern" in manifest("heavy")
    m = re.search(r'^OPTIONAL_SURFACES="([^"]*)"', BODY, re.M)
    assert m and set(m.group(1).split()) == {"rust-extras", "scanners", "heavy"}


# --- the base image's DB assertion, run against stub scanners ------------------


DB_BASE = re.search(r"^IMAGE_DB_base='([^']*)'", BODY, re.M).group(1)

TRIVY_HIT = '{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2019-14234"}]}]}'
OSV_HIT = '{"results":[{"packages":[{"vulnerabilities":[{"id":"PYSEC-2019-12"}]}]}]}'


def db_base(tmp_path: Path, trivy_json: str = TRIVY_HIT, osv_rc: int = 1):
    bin_dir = tmp_path / "dbbin"
    bin_dir.mkdir(exist_ok=True)
    # The baked trees: `find` and `ls` report enough entries for every count.
    executable(bin_dir / "find", "#!/bin/sh\ni=0\nwhile [ $i -lt 60 ]; do echo f$i; i=$((i+1)); done\n")
    executable(bin_dir / "ls", "#!/bin/sh\nprintf 'a\\nb\\nc\\nd\\ne\\nf\\n'\n")
    executable(bin_dir / "trivy", '#!/bin/sh\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && out="$2"; '
                                  'shift; done\nprintf "%s\\n" "$FAKE_TRIVY_JSON" > "$out"\n')
    executable(bin_dir / "osv-scanner", '#!/bin/sh\nwhile [ $# -gt 0 ]; do [ "$1" = --output ] '
                                        '&& out="$2"; shift; done\n'
                                        f'printf "%s\\n" \'{OSV_HIT}\' > "$out"\nexit {osv_rc}\n')
    executable(bin_dir / "opengrep", "#!/bin/sh\necho '{\"results\":[{\"check_id\":"
                                     "\"python.lang.security.insecure-hash-algorithm-md5\"}]}'\n")
    env = {**os.environ, "PATH": f"{bin_dir}:/usr/bin:/bin", "FAKE_TRIVY_JSON": trivy_json}
    return subprocess.run(["sh", "-c", DB_BASE], capture_output=True, text=True, env=env,
                          timeout=60)


def test_the_base_db_assertion_passes_when_every_probe_finds_its_advisory(tmp_path):
    # osv-scanner exits 1 BECAUSE it found the seeded vulnerability; that is the pass.
    r = db_base(tmp_path)
    assert r.returncode == 0, r.stderr


def test_a_trivy_that_ignored_its_bake_fails_the_base_db_assertion(tmp_path):
    # Every check is joined with `&&`, so one that fails decides the assertion itself.
    r = db_base(tmp_path, trivy_json='{"Results":[]}')
    assert r.returncode != 0


def test_an_osv_scanner_error_fails_the_base_db_assertion(tmp_path):
    # 127 is osv-scanner's general error; only 0 or 1 is a completed scan.
    r = db_base(tmp_path, osv_rc=127)
    assert r.returncode != 0
