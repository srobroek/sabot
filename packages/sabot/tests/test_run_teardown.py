"""run-teardown.py deletes only what the layout classifies as ephemeral, and only on
--apply.

A campaign filled a 460 GiB host volume with per-node build trees it had no way to
enumerate or delete, and two of the deletions it did attempt were denied mid-run. A
cleanup that can escape its own run root is worse than no cleanup.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SKILL = Path(__file__).resolve().parents[1] / ".apm" / "skills" / "sabotage"
SCRIPT = SKILL / "scripts" / "run-teardown.py"
BODY = SCRIPT.read_text()

EXIT_USAGE = 2
EXIT_PRECONDITION = 3
EXIT_REFUSED = 4
EXIT_OUTSTANDING = 5

MB = 1024 * 1024


LAYOUT = SKILL / "scripts" / "run-layout.py"


def scratch_of(root: Path, home: Path) -> Path:
    """The run's host scratch, read from run-layout.py rather than re-derived here."""
    p = subprocess.run(
        [sys.executable, str(LAYOUT), "paths", "--run-root", str(root), "--json"],
        capture_output=True, text=True, env=dict(os.environ, HOME=str(home)), check=True,
    )
    rows = json.loads(p.stdout)["paths"]
    return Path(next(r["path"] for r in rows if r["var"] == "SABOT_HOST_SCRATCH"))


def make_run(tmp_path: Path, run_id: str = "run-20260820a",
             repo: str = "target") -> tuple[Path, Path]:
    """A minimal but recognizable run root, plus the fake HOME its scratch lives under."""
    home = tmp_path / "home"
    root = tmp_path / repo / ".sabot" / run_id
    (root / "artifacts").mkdir(parents=True)
    (root / "ephemeral").mkdir()
    scratch_of(root, home).mkdir(parents=True)
    return root, home


def fill(path: Path, mb: int = 2) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "blob.bin").write_bytes(b"0" * (mb * MB))
    return path


def _invoke(root: Path, home: Path, args: tuple[str, ...]):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--run-root", str(root), *args],
        capture_output=True, text=True, env=dict(os.environ, HOME=str(home)),
    )


def run(root: Path, home: Path, *args: str):
    p = _invoke(root, home, (*args, "--json"))
    return p, (json.loads(p.stdout) if p.stdout.strip() else {})


def human_run(root: Path, home: Path, *args: str):
    """The operator-facing mode. Warnings and outstanding items print here, not in --json."""
    return _invoke(root, home, args)


# --- dry-run is the default -------------------------------------------------


def test_dry_run_deletes_nothing_and_still_reports_the_bytes(tmp_path):
    root, home = make_run(tmp_path)
    build = fill(root / "ephemeral" / "code-metadata" / "build")
    p, rep = run(root, home)
    assert p.returncode == 0
    assert rep["applied"] is False
    assert rep["planned_mb"] >= 2
    assert rep["freed_bytes"] == 0
    assert (build / "blob.bin").exists()


def test_apply_frees_the_bytes_and_reports_them(tmp_path):
    root, home = make_run(tmp_path)
    node = fill(root / "ephemeral" / "code-metadata" / "build")
    p, rep = run(root, home, "--apply")
    assert p.returncode == 0
    assert rep["applied"] is True
    assert rep["freed_mb"] >= 2
    assert not node.exists()


def test_the_ephemeral_parent_dirs_survive_so_a_live_campaign_keeps_its_destinations(tmp_path):
    # Teardown is callable mid-campaign: stop, report, teardown, verify headroom, resume.
    root, home = make_run(tmp_path)
    fill(root / "ephemeral" / "code-metadata" / "build")
    run(root, home, "--apply")
    assert (root / "ephemeral").is_dir()
    assert scratch_of(root, home).is_dir()


def test_durable_evidence_is_never_touched(tmp_path):
    root, home = make_run(tmp_path)
    finding = root / "artifacts" / "recon-code-metadata.md"
    finding.write_text("finding\n")
    fill(root / "ephemeral" / "n" / "build")
    p, _ = run(root, home, "--apply")
    assert p.returncode == 0
    assert finding.read_text() == "finding\n"


# --- refusals ---------------------------------------------------------------


def test_a_symlink_out_of_the_run_root_is_refused_and_never_followed(tmp_path):
    root, home = make_run(tmp_path)
    outside = tmp_path / "precious"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep\n")
    (root / "ephemeral" / "escape").symlink_to(outside)
    p, _ = run(root, home, "--apply")
    assert p.returncode == EXIT_REFUSED
    assert "REFUSED" in p.stderr
    assert (outside / "keep.txt").exists()


def test_a_symlink_to_durable_evidence_is_refused_as_durable(tmp_path):
    root, home = make_run(tmp_path)
    (root / "ephemeral" / "evidence").symlink_to(root / "artifacts")
    p, _ = run(root, home, "--apply")
    assert p.returncode == EXIT_REFUSED
    assert "classifies as durable" in p.stderr


def test_one_refused_path_refuses_the_whole_teardown(tmp_path):
    # Deleting the deletable half and skipping the rest hides which paths were escaped.
    root, home = make_run(tmp_path)
    keeper = fill(root / "ephemeral" / "code-metadata" / "build")
    (root / "ephemeral" / "escape").symlink_to(tmp_path)
    p, _ = run(root, home, "--apply")
    assert p.returncode == EXIT_REFUSED
    assert (keeper / "blob.bin").exists()
    assert "refusing the whole teardown" in p.stderr


def test_a_directory_that_is_not_a_run_root_is_refused(tmp_path):
    # Refusing to treat an arbitrary directory as a run root.
    plain = tmp_path / "somewhere"
    (plain / "ephemeral").mkdir(parents=True)
    p, _ = run(plain, tmp_path / "home")
    assert p.returncode == EXIT_PRECONDITION


def test_a_missing_run_root_is_refused(tmp_path):
    p, _ = run(tmp_path / "nope", tmp_path / "home")
    assert p.returncode == EXIT_PRECONDITION


def test_a_run_root_identified_only_by_its_preflight_record_is_accepted(tmp_path):
    root = tmp_path / "target" / ".sabot" / "run-x"
    (root / "ephemeral").mkdir(parents=True)
    (root / "preflight.json").write_text("{}\n")
    p, _ = run(root, tmp_path / "home")
    assert p.returncode == 0


# --- denied deletions are reported once, never retried ----------------------


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_a_denied_deletion_is_an_outstanding_item_and_is_not_retried(tmp_path):
    # Two deletions were denied by a permission layer mid-campaign. Reaching the same
    # bytes another way is exactly the behaviour that must not happen.
    root, home = make_run(tmp_path)
    locked = fill(root / "ephemeral" / "code-metadata" / "build" / "locked")
    locked.chmod(0o500)
    try:
        p, rep = run(root, home, "--apply")
        assert p.returncode == EXIT_OUTSTANDING
        assert len(rep["outstanding"]) == 1
        assert rep["outstanding"][0]["denied"]
        human = human_run(root, home, "--apply")
        assert human.returncode == EXIT_OUTSTANDING
        assert "not retried" in human.stderr
        assert human.stderr.count("OUTSTANDING teardown item") == 1
    finally:
        locked.chmod(0o700)


# --- orphans and the mid-run ceiling ---------------------------------------


def test_another_runs_residue_is_reported_as_an_orphan(tmp_path):
    root, home = make_run(tmp_path)
    other = root.parent / "run-20260819z" / "ephemeral" / "n" / "build"
    fill(other)
    p, rep = run(root, home)
    assert p.returncode == 0
    kinds = {o["kind"] for o in rep["orphans"]}
    assert "other-run" in kinds
    assert other.exists()


def test_legacy_scratch_is_reported_but_kept_until_explicitly_opted_into(tmp_path):
    # ~1.0 GiB of residue sat in five differently-named ~/tmp/sabot-* dirs. They are
    # outside any run root, so a default teardown may not delete them.
    root, home = make_run(tmp_path)
    legacy = fill(home / "tmp" / "sabot-abc123")
    p, rep = run(root, home)
    assert p.returncode == 0
    assert any(o["kind"] == "legacy-scratch" for o in rep["orphans"])
    assert legacy.exists()

    p2, rep2 = run(root, home, "--apply", "--include-legacy-scratch")
    assert p2.returncode == 0
    assert not legacy.exists()


def test_the_ceiling_check_reports_nonzero_while_the_run_is_still_live(tmp_path):
    # Nothing watched a growing target dir, and that growth filled the host volume.
    root, home = make_run(tmp_path)
    fill(root / "ephemeral" / "code-metadata" / "build", mb=3)
    p, rep = run(root, home, "--check-ceiling-mb", "1")
    assert p.returncode == EXIT_OUTSTANDING
    assert rep["ceiling_exceeded"] is True
    assert "exceed the ceiling" in human_run(root, home, "--check-ceiling-mb", "1").stderr


def test_the_ceiling_check_passes_under_the_limit(tmp_path):
    root, home = make_run(tmp_path)
    fill(root / "ephemeral" / "n" / "build", mb=1)
    p, rep = run(root, home, "--check-ceiling-mb", "500")
    assert p.returncode == 0
    assert rep["ceiling_exceeded"] is False


def test_host_scratch_is_torn_down_with_the_run(tmp_path):
    root, home = make_run(tmp_path)
    scratch = fill(scratch_of(root, home) / "stage")
    p, _ = run(root, home, "--apply")
    assert p.returncode == 0
    assert not scratch.exists()


def test_teardown_never_deletes_another_repos_run_with_the_same_id(tmp_path):
    # host_scratch keyed only on the run-root basename, so project-a's run-1 and
    # project-b's run-1 shared ~/.sabot-scratch/run-1 and one teardown deleted both.
    root_a, home = make_run(tmp_path / "a", run_id="run-1", repo="project-a")
    root_b, _ = make_run(tmp_path / "a", run_id="run-1", repo="project-b")
    assert scratch_of(root_a, home) != scratch_of(root_b, home)
    live = fill(scratch_of(root_b, home) / "stage")
    p, _ = run(root_a, home, "--apply")
    assert p.returncode == 0
    assert (live / "blob.bin").exists(), "teardown of project-a deleted project-b's scratch"


# --- shape -----------------------------------------------------------------


def test_the_script_contains_no_rm_rf():
    # An unset variable collapses the path toward /. Deletion goes through a resolved,
    # already-classified path instead.
    code = ast.parse(BODY)
    code.body = [n for n in code.body
                 if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))]
    executable = ast.unparse(code)
    assert "rm -rf" not in executable
    assert "rmtree" in executable


def test_the_report_schema_is_stable(tmp_path):
    root, home = make_run(tmp_path)
    _, rep = run(root, home)
    assert rep["schema"] == "sabot-teardown/1"
    for key in ("run_root", "applied", "planned", "planned_mb", "freed_mb", "freed_bytes",
                "remaining_ephemeral_mb", "ceiling_mb", "ceiling_exceeded", "outstanding",
                "orphans"):
        assert key in rep
