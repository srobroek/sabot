"""Every `# renovate:` pin in the surface images must be one Renovate can update.

renovate.json promises that Renovate keeps each annotated pin current, but two shapes
fell outside it. `managerFilePatterns` matched `Dockerfile.[a-z]+` and
`layers/[a-z]+.sh`, so the hyphenated `Dockerfile.rust-extras`, `layers/base-extras.sh`,
and `layers/rust-extras.sh` were never read. The version capture required a leading
digit, so `JOERN_VERSION=v4.0.604` and `ZAP_VERSION=v2.17.0` matched nothing. Twelve of
the pins carried a comment that no manager acted on, and nothing said so.

This evaluates renovate.json's own patterns against the files, the way the regex custom
manager does, and requires each annotated pin to yield its version. No network.

Run: pytest packages/sabot/tests/test_renovate_pins.py
"""

import json
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
REPO = PKG.parents[1]
CONTAINERS = PKG / ".apm/skills/sabotage/references/containers"
CONFIG = json.loads((CONTAINERS / "renovate.json").read_text())
(MANAGER,) = CONFIG["customManagers"]

PIN = re.compile(r"^# renovate: datasource=\S+ depName=(\S+)\n(?:ARG\s+)?[A-Za-z_]\w*=v?(\S+)$|"
                 r"^# renovate: datasource=\S+ depName=(\S+)\nRUN .*?(?:--version|==|@)\s*v?([0-9][^\s\"']*)",
                 re.M)


def _js(pattern: str) -> re.Pattern:
    """A Renovate (JavaScript) regex as a Python one: only named groups differ."""
    return re.compile(pattern.replace("(?<", "(?P<"))


FILE_PATTERNS = [_js(p.strip("/")) for p in MANAGER["managerFilePatterns"]]
MATCH_STRINGS = [_js(p) for p in MANAGER["matchStrings"]]


def _annotated_files():
    return sorted(
        p for p in CONTAINERS.rglob("*")
        if p.is_file() and p.name != "renovate.json" and "# renovate: datasource=" in p.read_text()
    )


def _pins(path: Path) -> list[tuple[str, str]]:
    """(depName, version) for every annotated pin, read independently of renovate.json."""
    out = []
    for m in PIN.finditer(path.read_text()):
        dep, value = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        out.append((dep, value))
    return out


def _extracted(path: Path) -> dict[str, str]:
    text = path.read_text()
    found = {}
    for rx in MATCH_STRINGS:
        for m in rx.finditer(text):
            found[m.group("depName")] = m.group("currentValue")
    return found


def test_every_annotated_file_is_read_by_the_manager():
    unread = [
        str(p.relative_to(REPO)) for p in _annotated_files()
        if not any(rx.search(str(p.relative_to(REPO))) for rx in FILE_PATTERNS)
    ]
    assert not unread, f"renovate never reads these annotated files: {unread}"


def test_every_annotated_pin_yields_its_version():
    missed = []
    for path in _annotated_files():
        got = _extracted(path)
        for dep, value in _pins(path):
            if got.get(dep) != value:
                missed.append(f"{path.name}: {dep} wants {value!r}, extracted {got.get(dep)!r}")
    assert not missed, "annotated pins renovate cannot update:\n" + "\n".join(missed)


def test_the_sweep_counts_every_annotation():
    """Every `# renovate: datasource=` line is a pin the independent reader parsed, so a
    comment above an unrecognized line shape fails here instead of being skipped. The
    review counted 37 pins at 0.6.0; the base-image checksum work since folded one
    Dockerfile.base ARG away, leaving 36. The floor only guards against a reader that
    silently stops matching."""
    comments = sum(p.read_text().count("# renovate: datasource=") for p in _annotated_files())
    pins = sum(len(_pins(p)) for p in _annotated_files())
    assert pins == comments, (pins, comments)
    assert comments >= 30, comments


def test_a_v_prefixed_tag_is_normalized_for_comparison():
    """The `v` stays in the file, outside the capture, so github-releases tags such as
    `v4.0.605` need stripping before semver compares them to `4.0.604`."""
    assert re.fullmatch(_js(MANAGER["extractVersionTemplate"]).pattern, "v4.0.605")
    assert _js(MANAGER["extractVersionTemplate"]).match("v4.0.605").group("version") == "4.0.605"
