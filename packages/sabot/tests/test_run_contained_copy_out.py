#!/usr/bin/env python3
"""run-contained.sh end to end against a fake container runtime: the copy-out bound and the
rc=137 hint.

The copy-out cap exists because one measured run copied a ~5 GB build tree onto the host
and its residue filled the volume. A sizing helper that failed used to WARN and then copy
the volume unbounded, which is the very payload the cap refuses; a sizing helper that
errored ended the script under `set -e` with the helper's status, which reads as the
contained command's own exit code. Both must refuse the copy-out with exit 4 instead.

The rc=137 hint used to say "retry at --mem 6g", which skips run-layout.md's degrade-first
ladder: the same build finished at 739 MiB at the original cap once the recipe was
degraded.

A stub `docker` on PATH records every call and answers each the way the real CLI does; a
stub `timeout` drops its own options. No container, no network.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1] / ".apm/skills/sabotage"
WRAPPER = SKILL / "scripts/run-contained.sh"

EXIT_COPY_OUT = 4

FAKE_DOCKER = """#!/bin/sh
echo "$*" >> "$FAKE_DOCKER_LOG"
case "$1" in
  context) echo default ;;
  image) exit 0 ;;
  volume) [ "$2" = create ] && echo "$3"; exit 0 ;;
  run)
    case "$*" in
      *"du -sm"*)
        [ -n "${FAKE_PAYLOAD_MB:-}" ] && echo "$FAKE_PAYLOAD_MB"
        exit "${FAKE_PRUNE_RC:-0}" ;;
    esac
    exit "${FAKE_RC:-0}" ;;
  create) echo fake-cid ;;
esac
exit 0
"""

# `timeout -k 30 <secs> <cmd...>`: drop the three option words and run the command.
FAKE_TIMEOUT = '#!/bin/sh\nshift 3\nexec "$@"\n'


def executable(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def run_wrapper(tmp_path: Path, **fake: str):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    executable(bin_dir / "docker", FAKE_DOCKER)
    executable(bin_dir / "timeout", FAKE_TIMEOUT)
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    log = tmp_path / "docker.log"
    env = {
        **os.environ,
        # The target sits under HOME, so the wrapper mounts it in place instead of
        # staging a copy under the real ~/.sabot.
        "HOME": str(tmp_path),
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "FAKE_DOCKER_LOG": str(log),
        **fake,
    }
    p = subprocess.run(
        ["bash", str(WRAPPER), "--target", str(target), "--artifacts", str(tmp_path / "art"),
         "--image", "sabot/base:1", "--min-free-mb", "0", "--", "true"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    calls = log.read_text().splitlines() if log.exists() else []
    status = (tmp_path / "art" / "run-contained.status").read_text()
    return p, calls, status


def copied(calls: list[str]) -> bool:
    return any(c.startswith("cp ") for c in calls)


def test_a_sized_payload_under_the_cap_is_copied_out(tmp_path):
    p, calls, status = run_wrapper(tmp_path, FAKE_PAYLOAD_MB="3")
    assert p.returncode == 0, p.stderr
    assert copied(calls)
    assert "executed=1" in status


def test_an_unsized_payload_is_refused_not_copied_unbounded(tmp_path):
    # The helper ran but printed no size (no `du`, or an unreadable volume).
    p, calls, status = run_wrapper(tmp_path)
    assert p.returncode == EXIT_COPY_OUT, p.stderr
    assert not copied(calls), "an unknown payload size must not be copied out"
    assert "REFUSING the copy-out" in p.stderr
    assert "executed=0" in status
    assert "could not be sized" in status


def test_a_failed_sizing_helper_is_a_refusal_not_the_commands_exit_code(tmp_path):
    # Under `set -e` the failed helper ended the script with its own status (125), which a
    # caller reads as the contained command's.
    p, calls, status = run_wrapper(tmp_path, FAKE_PRUNE_RC="125")
    assert p.returncode == EXIT_COPY_OUT, p.stderr
    assert not copied(calls)
    assert "could not be sized" in status


def test_the_rc_137_hint_degrades_the_recipe_before_raising_the_cap(tmp_path):
    p, _, _ = run_wrapper(tmp_path, FAKE_RC="137", FAKE_PAYLOAD_MB="1")
    assert p.returncode == 137, p.stderr
    hint = next(line for line in p.stderr.splitlines() if "rc=137 is SIGKILL" in line)
    assert "--mem 6g" not in hint
    assert "Degrade the recipe before raising the cap" in hint
    assert "same --mem 2g" in hint
    assert "classify-failure.py" in hint
