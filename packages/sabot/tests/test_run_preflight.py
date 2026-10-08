"""run-preflight.py is the single command before a campaign: it fails loudly, or it emits
the record every later step cites.

The free-disk precondition did not exist, and its absence is what caused the outage:
concurrent per-node build trees filled a 460 GiB volume to 100%, containerd could not grow
its sparse disk, and no container would start on any image.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1] / ".apm" / "skills" / "sabotage"
SCRIPT = SKILL / "scripts" / "run-preflight.py"

EXIT_USAGE = 2
EXIT_PRECONDITION = 3

IMAGE = "sabot-base:latest"

DOCKER_STUB = """\
case "$1" in
  info)    echo 17179869184 4 ;;
  context) echo default ;;
  image)   [ "$3" = "%s" ] || exit 1 ;;
  *)       exit 0 ;;
esac
""" % IMAGE

# `bd` discovers its store relative to cwd, so a bd that answers in $HOME and not in the
# repo is the same as no bd at all.
BD_STUB = """\
if [ -f .bd-broken ]; then echo "no bead store here" >&2; exit 1; fi
echo '[]'
"""


def stub(bin_dir: Path, name: str, body: str) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    p = bin_dir / name
    p.write_text(f"#!/bin/sh\n{body}\n")
    p.chmod(0o755)


def make_target(tmp_path: Path, manifest: str = '[package]\nname = "pv"\n') -> Path:
    target = tmp_path / "target"
    target.mkdir(parents=True, exist_ok=True)
    (target / "Cargo.toml").write_text(manifest)
    (target / "Cargo.lock").write_text('[[package]]\nname = "pv"\n')
    (target / "src").mkdir(exist_ok=True)
    (target / "src" / "lib.rs").write_text("pub fn f() {}\n")
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e")
    subprocess.run(["git", "init", "-q"], cwd=target, check=True)
    subprocess.run(["git", "add", "-A"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "seed"], cwd=target, check=True, env=env)
    return target


def make_env(tmp_path: Path) -> tuple[Path, dict]:
    bin_dir = tmp_path / "bin"
    stub(bin_dir, "docker", DOCKER_STUB)
    stub(bin_dir, "bd", BD_STUB)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = dict(os.environ, HOME=str(home))
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    return bin_dir, env


def run(target: Path, env: dict, *args: str, run_id: str = "run-20260820a"):
    p = subprocess.run(
        [sys.executable, str(SCRIPT), "--target", str(target), "--run-id", run_id,
         "--skip-image-probe", *args],
        capture_output=True, text=True, env=env,
    )
    record = target / ".sabot" / run_id / "preflight.json"
    return p, (json.loads(record.read_text()) if record.is_file() else None)


def checks(rec: dict) -> dict[str, bool]:
    return {c["name"]: c["ok"] for c in rec["checks"]}


# --- the ready path ---------------------------------------------------------


def test_a_met_precondition_set_exits_0_and_writes_the_record(tmp_path):
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    p, rec = run(target, env, "--image", IMAGE, "--min-free-mb", "1")
    assert p.returncode == 0, p.stdout + p.stderr
    assert rec["ok"] is True
    assert all(checks(rec).values()), checks(rec)


def test_the_layout_is_created_alongside_the_record(tmp_path):
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    run(target, env, "--min-free-mb", "1")
    root = target / ".sabot" / "run-20260820a"
    assert (root / "artifacts").is_dir()
    assert (root / "ephemeral").is_dir()
    assert (root / ".gitignore").is_file()


# --- each precondition fails loudly, and still leaves a record --------------


def test_a_failed_precondition_exits_3_and_still_writes_the_record(tmp_path):
    # A failed preflight is a RECORD, not a silence: the report cites this file.
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    p, rec = run(target, env, "--min-free-mb", "999999999")
    assert p.returncode == EXIT_PRECONDITION
    assert rec is not None
    assert rec["ok"] is False
    assert checks(rec)["free_disk"] is False
    assert "NOT READY" in p.stderr


def test_a_missing_container_runtime_fails(tmp_path):
    target = make_target(tmp_path)
    bin_dir, env = make_env(tmp_path)
    (bin_dir / "docker").unlink()
    # An empty PATH plus the stub dir leaves no docker and no finch to find.
    env["PATH"] = str(bin_dir)
    p, rec = run(target, env, "--min-free-mb", "1")
    assert p.returncode == EXIT_PRECONDITION
    assert checks(rec)["container_runtime"] is False


def test_bd_that_cannot_answer_from_the_repo_root_fails(tmp_path):
    # A whole wisp set once read as "no work exists"; bd being on PATH proves nothing.
    target = make_target(tmp_path)
    (target / ".bd-broken").touch()
    _, env = make_env(tmp_path)
    p, rec = run(target, env, "--min-free-mb", "1")
    assert p.returncode == EXIT_PRECONDITION
    assert checks(rec)["bd_present"] is True
    assert checks(rec)["bd_runnable_from_repo_root"] is False


def test_a_missing_bd_fails(tmp_path):
    target = make_target(tmp_path)
    bin_dir, env = make_env(tmp_path)
    (bin_dir / "bd").unlink()
    env["PATH"] = f"{bin_dir}{os.pathsep}/usr/bin:/bin"
    p, rec = run(target, env, "--min-free-mb", "1")
    assert p.returncode == EXIT_PRECONDITION
    assert checks(rec)["bd_present"] is False


def test_a_target_that_is_not_a_git_repo_fails(tmp_path):
    target = tmp_path / "loose"
    target.mkdir()
    _, env = make_env(tmp_path)
    p, rec = run(target, env, "--min-free-mb", "1")
    assert p.returncode == EXIT_PRECONDITION
    assert checks(rec)["target_is_git_repo"] is False


def test_an_absent_image_fails_and_names_the_corrupt_blob_possibility(tmp_path):
    # An image absent and an image whose content blob is unreadable present identically.
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    p, rec = run(target, env, "--image", "sabot-nonexistent:latest", "--min-free-mb", "1")
    assert p.returncode == EXIT_PRECONDITION
    assert checks(rec)["images_present"] is False
    assert "corrupt" in rec["images"]["sabot-nonexistent:latest"]["error"]


def test_a_required_tool_not_known_to_be_present_fails(tmp_path):
    # Unprobed is unknown, never empty and never assumed present: `just` was absent from
    # an image and 26 justfile recipes went untested in silence.
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    p, rec = run(target, env, "--image", IMAGE, "--require-tool", "just",
                 "--min-free-mb", "1")
    assert p.returncode == EXIT_PRECONDITION
    assert checks(rec)["required_tools_present"] is False


def test_a_run_id_that_is_not_already_slug_shaped_is_a_usage_error(tmp_path):
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    p, _ = run(target, env, "--min-free-mb", "1", run_id="Run_20260820A")
    assert p.returncode == EXIT_USAGE
    assert "slug-shaped" in p.stderr


def test_a_target_that_is_not_a_directory_is_a_usage_error(tmp_path):
    _, env = make_env(tmp_path)
    p, _ = run(tmp_path / "nope", env, "--min-free-mb", "1")
    assert p.returncode == EXIT_USAGE


# --- the record's contents --------------------------------------------------


def test_the_record_states_the_offline_posture_as_a_field(tmp_path):
    # Agents repeatedly treated a ruleset's network failure as transient and retried.
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    _, rec = run(target, env, "--min-free-mb", "1")
    posture = rec["network_posture"]
    assert posture["mode"] == "none"
    assert posture["egress"] is False
    assert posture["dns"] is False
    assert posture["registries"] is False
    assert "NOT EXECUTED" in posture["consequence"]


def test_the_deadline_is_absent_unless_asked_for(tmp_path):
    # Time is not a safety limit: it is an opt-in, user-owned graceful stop.
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    _, rec = run(target, env, "--min-free-mb", "1")
    assert rec["deadline_s"] is None
    _, rec2 = run(target, env, "--min-free-mb", "1", "--deadline-s", "1800")
    assert rec2["deadline_s"] == 1800


def test_concurrency_is_computed_and_bounded_by_a_named_resource(tmp_path):
    # The campaign that failed ran unbounded, then a hand-picked cap of 3.
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    _, rec = run(target, env, "--min-free-mb", "1")
    conc = rec["concurrency"]
    assert conc["max_parallel_nodes"] >= 1
    assert conc["bound_by"] in ("disk", "memory")
    # The pool is the RUNTIME's, read from `docker info`, not the laptop's.
    assert rec["memory"]["pool_total_mb"] == 16384
    assert rec["memory"]["measured_from_runtime"] is True
    assert rec["memory"]["usable_mb"] == 16384 - rec["memory"]["vm_reserve_mb"]
    assert rec["cpu"]["ncpu"] == 4


def test_concurrency_is_the_memory_arithmetic_not_a_preference(tmp_path):
    # max_concurrent = floor(usable_mem / per_node_cap). A campaign held 3 nodes and read
    # that as the limit; 3 was only correct because every node ran at 2048 MiB.
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    _, rec = run(target, env, "--min-free-mb", "1")
    usable = rec["memory"]["usable_mb"]
    per_node = rec["estimate"]["per_node_mem_mb"]
    assert rec["concurrency"]["max_parallel_nodes"] <= max(1, usable // per_node)
    assert rec["admission"]["usable_mb"] == usable
    assert "admit-node.py" in rec["admission"]["check_with"]


def test_jobs_is_derived_from_cpu_count_and_concurrency(tmp_path):
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    _, rec = run(target, env, "--min-free-mb", "1", "--jobs", "16")
    jobs = rec["cpu"]["jobs_per_node"]
    assert 1 <= jobs <= 4
    assert jobs <= max(1, 4 // rec["concurrency"]["max_parallel_nodes"])


def test_the_retry_ladder_degrades_the_recipe_before_raising_memory(tmp_path):
    # Measured: a build SIGKILLed at 2048 finished at 739 MiB with -j 1 and debug off. The
    # cap was never the fix, so raising it first would have hidden that.
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    _, rec = run(target, env, "--min-free-mb", "1")
    ladder = rec["retry_ladder"]
    assert ladder[0]["raises_cap"] is False
    assert ladder[0]["jobs"] == 1
    assert ladder[-1]["raises_cap"] is True
    assert all("no-keep-memory" not in json.dumps(step) for step in ladder)
    assert any("ENOSPC" in reason for reason in rec["no_auto_retry"])


def test_an_unknown_runtime_pool_is_refused_not_planned_against_the_laptop(tmp_path):
    # sysctl reports the machine, not the VM the containers run in. A laptop figure once
    # filled usable_mb and passed target_fits_memory, so admit-node approved nodes against a
    # pool many times the VM's. An unknown pool must fail the preflight instead.
    target = make_target(tmp_path)
    bindir, env = make_env(tmp_path)
    (bindir / "docker").write_text("#!/bin/sh\ncase \"$1\" in\n  info) exit 1 ;;\n"
                                   "  context) echo default ;;\n  *) exit 0 ;;\nesac\n")
    p, rec = run(target, env, "--min-free-mb", "1")
    assert p.returncode == EXIT_PRECONDITION, p.stdout + p.stderr
    assert checks(rec)["target_fits_memory"] is False
    assert rec["memory"]["measured_from_runtime"] is False
    assert rec["memory"]["usable_mb"] is None
    assert rec["memory"]["pool_total_mb"] is None
    assert rec["admission"]["usable_mb"] is None
    assert rec["concurrency"]["max_parallel_nodes"] == 1
    # The ladder and its env stay in the record, so a refused run still documents them.
    assert rec["retry_ladder"][0]["raises_cap"] is False
    assert rec["retry_ladder"][0]["env"]


def test_the_admission_command_passes_one_cap_per_running_node(tmp_path):
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    _, rec = run(target, env, "--min-free-mb", "1")
    assert "--running-cap" in rec["admission"]["check_with"]
    assert "--running-mb" not in rec["admission"]["check_with"]


def test_a_cdylib_target_is_estimated_larger_than_one_without(tmp_path):
    # 2048 MiB SIGKILLed `ld` linking a single cdylib; the same package linked at 6144.
    plain = make_target(tmp_path / "a")
    cdylib = make_target(
        tmp_path / "b",
        '[package]\nname = "pv"\n\n[lib]\ncrate-type = ["cdylib"]\n',
    )
    _, env = make_env(tmp_path)
    _, rec_plain = run(plain, env, "--min-free-mb", "1")
    _, rec_cdylib = run(cdylib, env, "--min-free-mb", "1")
    assert rec_cdylib["estimate"]["links_cdylib"] is True
    assert rec_plain["estimate"]["links_cdylib"] is False
    assert (rec_cdylib["estimate"]["per_node_mem_mb"]
            > rec_plain["estimate"]["per_node_mem_mb"])


def test_the_estimate_is_derived_from_observable_target_properties(tmp_path):
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    _, rec = run(target, env, "--min-free-mb", "1")
    est = rec["estimate"]
    assert est["workspace_members"] >= 1
    assert est["lock_packages"] == 1
    assert est["per_node_disk_mb"] > 0
    assert est["basis"]


def test_the_record_names_the_query_label_flag(tmp_path):
    # `bd list --labels x` is accepted and silently returns nothing on a query.
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    _, rec = run(target, env, "--min-free-mb", "1")
    assert rec["beads"]["query_label_flag"] == "--label"


def test_the_record_points_at_the_layout_contract(tmp_path):
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    _, rec = run(target, env, "--min-free-mb", "1")
    assert rec["schema"] == "sabot-preflight/1"
    assert rec["layout_contract"].endswith("references/run-layout.md")
    assert (SKILL / "references" / "run-layout.md").is_file()
    assert rec["layout"]["SABOT_ARTIFACTS"].endswith("artifacts")


def test_an_unprobed_image_records_unknown_rather_than_an_empty_tool_set(tmp_path):
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    _, rec = run(target, env, "--image", IMAGE, "--min-free-mb", "1")
    entry = rec["images"][IMAGE]
    assert entry["present"] is True
    assert entry["tools"] is None
    assert "unknown, not empty" in entry["note"]


def test_json_out_redirects_the_record(tmp_path):
    target = make_target(tmp_path)
    _, env = make_env(tmp_path)
    dest = tmp_path / "elsewhere.json"
    p = subprocess.run(
        [sys.executable, str(SCRIPT), "--target", str(target), "--run-id", "run-x",
         "--skip-image-probe", "--min-free-mb", "1", "--json-out", str(dest)],
        capture_output=True, text=True, env=env,
    )
    assert p.returncode == 0, p.stdout + p.stderr
    assert json.loads(dest.read_text())["run_id"] == "run-x"
