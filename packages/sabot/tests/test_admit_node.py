#!/usr/bin/env python3
"""admit-node.py must refuse the node that would OOM, using the measured pool.

The reference runtime is one 8 GiB VM. A campaign held 3 concurrent nodes and read that as
the limit, but 3 only worked because every node was capped at 2048 MiB; the node needing
6144 could not coexist with two of them. An over-committed node is OOM-killed, and an
OOM-killed node reports no findings rather than reporting a failure, so the limit has to be
enforced by an exit code before the container starts.

Stdlib plus pytest only. Starts no container.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / ".apm" / "skills" / "sabotage" / "scripts" / "admit-node.py"
)

EXIT_USAGE = 2
EXIT_REFUSED = 3

# Measured: docker info reports 8307101696 bytes and 4 CPUs; ~7 GiB is usable.
POOL_MB = 8192
USABLE_MB = 7168


def preflight(tmp_path: Path, usable=USABLE_MB, ncpu=4, measured=True) -> Path:
    path = tmp_path / "preflight.json"
    path.write_text(json.dumps({
        "schema": "sabot-preflight/1", "ok": True,
        "memory": {"pool_total_mb": POOL_MB, "usable_mb": usable, "vm_reserve_mb": 1024,
                   "measured_from_runtime": measured},
        "cpu": {"ncpu": ncpu},
    }))
    return path


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *args],
                          capture_output=True, text=True, timeout=60)


# --- the arithmetic ---------------------------------------------------------


def test_three_nodes_at_2048_fit_the_measured_pool(tmp_path):
    p = run("--preflight", str(preflight(tmp_path)), "--mem-cap", "2048",
            "--running-cap", "2048", "--running-cap", "2048", "--json")
    assert p.returncode == 0, p.stderr
    doc = json.loads(p.stdout)
    assert doc["would_use_mb"] == 6144
    assert doc["concurrent_nodes"] == 3


def test_the_6144_node_cannot_join_two_2048_nodes(tmp_path):
    # 6144 + 2x2048 = 10 GiB against an 8 GiB VM. This is the exact dispatch that OOMs.
    p = run("--preflight", str(preflight(tmp_path)), "--mem-cap", "6144",
            "--running-cap", "2048", "--running-cap", "2048")
    assert p.returncode == EXIT_REFUSED
    assert "REFUSED" in p.stderr
    assert "10240" in p.stderr


def test_the_6144_node_is_admitted_alone(tmp_path):
    assert run("--preflight", str(preflight(tmp_path)), "--mem-cap", "6144").returncode == 0


def test_refusal_does_not_suggest_shrinking_the_cap_to_fit(tmp_path):
    # Lowering the cap to squeeze a node in is the failure mode, not the workaround.
    p = run("--preflight", str(preflight(tmp_path)), "--mem-cap", "6144",
            "--running-cap", "2048", "--running-cap", "2048")
    assert p.returncode == EXIT_REFUSED
    assert "Do not" in p.stderr and "OOM" in p.stderr


def test_exactly_filling_the_pool_is_admitted(tmp_path):
    p = run("--preflight", str(preflight(tmp_path, usable=4096)), "--mem-cap", "2048",
            "--running-cap", "2048", "--json")
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["headroom_mb"] == 0


def test_one_mib_over_the_pool_is_refused(tmp_path):
    assert run("--preflight", str(preflight(tmp_path, usable=4095)), "--mem-cap", "2048",
               "--running-cap", "2048").returncode == EXIT_REFUSED


# --- jobs derivation --------------------------------------------------------


@pytest.mark.parametrize("running,expected", [([], 4), (["2048"], 2), (["2048", "2048"], 1)])
def test_jobs_falls_as_concurrency_rises(tmp_path, running, expected):
    # -j 4 against 4 vCPUs with three containers competing is oversubscription; two nodes
    # had to drop to -j 1 to survive.
    args = ["--preflight", str(preflight(tmp_path)), "--mem-cap", "2048", "--json"]
    for cap in running:
        args += ["--running-cap", cap]
    doc = json.loads(run(*args).stdout)
    assert doc["jobs"] == expected


def test_a_requested_jobs_figure_is_a_ceiling_not_a_floor(tmp_path):
    doc = json.loads(run("--preflight", str(preflight(tmp_path)), "--mem-cap", "2048",
                         "--running-cap", "2048", "--jobs", "8", "--json").stdout)
    assert doc["jobs"] == 2


def test_jobs_never_falls_below_one(tmp_path):
    doc = json.loads(run("--preflight", str(preflight(tmp_path, usable=16384, ncpu=2)),
                         "--mem-cap", "2048", "--running-cap", "2048",
                         "--running-cap", "2048", "--running-cap", "2048",
                         "--json").stdout)
    assert doc["jobs"] == 1


# --- an unknown pool is not an unlimited one --------------------------------


def test_a_record_without_a_measured_pool_refuses_rather_than_admits(tmp_path):
    path = tmp_path / "preflight.json"
    path.write_text(json.dumps({"memory": {"usable_mb": None}, "cpu": {"ncpu": 4}}))
    p = run("--preflight", str(path), "--mem-cap", "2048")
    assert p.returncode == EXIT_REFUSED
    assert "not an unlimited one" in p.stderr


def test_a_record_missing_the_memory_block_entirely_refuses(tmp_path):
    path = tmp_path / "preflight.json"
    path.write_text(json.dumps({"schema": "sabot-preflight/1"}))
    assert run("--preflight", str(path), "--mem-cap", "2048").returncode == EXIT_REFUSED


def test_a_pool_not_measured_from_the_runtime_refuses(tmp_path):
    # run-preflight marks a laptop-sourced figure measured_from_runtime=false. The laptop's
    # memory is not the VM's, so admitting against it is the OOM this script prevents.
    p = run("--preflight", str(preflight(tmp_path, usable=65536, measured=False)),
            "--mem-cap", "2048")
    assert p.returncode == EXIT_REFUSED
    assert "not an unlimited one" in p.stderr


def test_a_record_that_omits_measured_from_runtime_refuses(tmp_path):
    path = tmp_path / "preflight.json"
    path.write_text(json.dumps({"memory": {"usable_mb": 7168}, "cpu": {"ncpu": 4}}))
    assert run("--preflight", str(path), "--mem-cap", "2048").returncode == EXIT_REFUSED


# --- usage discipline -------------------------------------------------------


def test_a_missing_record_is_usage_not_admission(tmp_path):
    p = run("--preflight", str(tmp_path / "nope.json"), "--mem-cap", "2048")
    assert p.returncode == EXIT_USAGE


def test_an_unparseable_record_is_usage_not_admission(tmp_path):
    path = tmp_path / "preflight.json"
    path.write_text("not json")
    assert run("--preflight", str(path), "--mem-cap", "2048").returncode == EXIT_USAGE


def test_no_arguments_exits_2(tmp_path):
    assert run().returncode == EXIT_USAGE


def test_a_summed_running_figure_is_not_accepted(tmp_path):
    # A sum loses the node count: three running nodes passed as one --running-mb read as
    # one node, so concurrent_nodes was always 2 and the jobs ceiling was overstated.
    p = run("--preflight", str(preflight(tmp_path)), "--mem-cap", "2048",
            "--running-mb", "4096")
    assert p.returncode == EXIT_USAGE


def test_each_running_cap_counts_as_one_node(tmp_path):
    doc = json.loads(run("--preflight", str(preflight(tmp_path, usable=16384, ncpu=8)),
                         "--mem-cap", "2048", "--running-cap", "2048",
                         "--running-cap", "2048", "--running-cap", "2048",
                         "--json").stdout)
    assert doc["concurrent_nodes"] == 4
    assert doc["jobs"] == 2


@pytest.mark.parametrize("cap", ["-2048", "0"])
def test_a_nonpositive_running_cap_is_a_usage_error(tmp_path, cap):
    # An 8192 MiB node with a -2048 "running" node was admitted into a 7168 MiB pool.
    p = run("--preflight", str(preflight(tmp_path)), "--mem-cap", "8192",
            "--running-cap", cap)
    assert p.returncode == EXIT_USAGE


def test_decide_rejects_a_negative_running_cap_directly():
    spec = importlib.util.spec_from_file_location("admit_node", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    record = {"memory": {"usable_mb": 7168, "measured_from_runtime": True}}
    with pytest.raises(ValueError):
        mod.decide(record, 8192, [-2048], 4)


def test_a_nonpositive_cap_is_refused(tmp_path):
    assert run("--preflight", str(preflight(tmp_path)), "--mem-cap", "0").returncode == EXIT_USAGE
