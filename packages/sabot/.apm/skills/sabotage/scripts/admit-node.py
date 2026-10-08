#!/usr/bin/env python3
"""Decide whether one more node may start. The memory limit, enforced instead of advised.

    admit-node.py --preflight PATH --mem-cap MB [--running-cap MB ...] [--jobs N] [--json]

Pass one `--running-cap` per running node. A single summed figure would lose the node
count, and the node count is what divides the CPUs into `jobs`.

WHY THIS EXISTS. Every container's `--memory` cap is drawn from ONE pool: the runtime VM,
measured at 8 GiB on the reference host. A campaign ran 3 concurrent nodes successfully and
concluded that 3 was the limit, but 3 was only correct because every node happened to be
capped at 2048 MiB. One node needed 6144, and 6144 + 2x2048 = 10 GiB does not fit in 8.

Dispatching past that line does not make the run slower. The kernel OOM-kills a container,
the harness never completes, and the surface reads as findings-free -- an INVALID run that
looks like a clean one. So the limit has to be checked before the node starts, by something
that returns a non-zero exit code, rather than written down in a budget table.

It reads `preflight.json` because that record already measured the pool. A record whose
pool did not come from the container runtime (`memory.measured_from_runtime` not true) is
refused: the laptop's memory is not the VM's, and admitting against it is the OOM this
script exists to prevent.

`--jobs` is capped the same way: -j 4 against 4 vCPUs with three containers competing is
oversubscription, and two nodes had to fall to `-j 1` to survive. Under concurrency the
effective figure is 1, and the budget table's `jobs` is a solo-run ceiling.

EXIT CODES: 0 admitted, 2 usage (including a cap below 1 MiB), 3 REFUSED (would exceed the
pool, or the pool was never measured).

Stdlib only. Starts no container.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

EXIT_USAGE = 2
EXIT_REFUSED = 3


def decide(record: dict, mem_cap: int, running: list[int], requested_jobs: int | None) -> dict:
    """Admission verdict for one candidate node. Raises ValueError on a cap below 1 MiB."""
    if mem_cap < 1 or any(cap < 1 for cap in running):
        raise ValueError("every memory cap must be a positive MiB figure")
    memory = record.get("memory") or {}
    usable = memory.get("usable_mb")
    ncpu = (record.get("cpu") or {}).get("ncpu")
    running_total = sum(running)
    would_use = running_total + mem_cap
    concurrent = len(running) + 1
    jobs_ceiling = max(1, (ncpu or 1) // concurrent)
    jobs = max(1, min(requested_jobs or jobs_ceiling, jobs_ceiling))

    if usable is None or memory.get("measured_from_runtime") is not True:
        return {
            "admitted": False,
            "reason": (
                "the preflight record has no memory.usable_mb measured from the container "
                "runtime, so the pool size is unknown. An unknown pool is not an unlimited "
                "one: re-run run-preflight.py against a live runtime before dispatching."
            ),
            "running_mb": running_total, "would_use_mb": would_use, "usable_mb": None,
            "concurrent_nodes": concurrent, "jobs": jobs,
        }
    admitted = would_use <= usable
    reason = (
        f"{would_use} MiB of {usable} MiB usable across {concurrent} node(s)"
        if admitted else
        f"REFUSED: {running_total} MiB already committed plus {mem_cap} MiB is "
        f"{would_use} MiB, over the {usable} MiB pool. Wait for a node to finish. Do not "
        "lower the cap to fit: a node capped below what it needs is OOM-killed, and an "
        "OOM-killed node reports no findings rather than reporting a failure."
    )
    return {
        "admitted": admitted, "reason": reason, "running_mb": running_total,
        "would_use_mb": would_use, "usable_mb": usable, "headroom_mb": usable - would_use,
        "concurrent_nodes": concurrent, "ncpu": ncpu, "jobs": jobs,
        "jobs_ceiling": jobs_ceiling,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="admit-node.py")
    ap.add_argument("--preflight", required=True, help="the preflight.json for this run")
    ap.add_argument("--mem-cap", type=int, required=True,
                    help="the --memory cap the candidate node would be given, in MiB")
    ap.add_argument("--running-cap", type=int, action="append", default=[],
                    help="repeatable: one running node's cap in MiB, once per running node")
    ap.add_argument("--jobs", type=int, default=None)
    ap.add_argument("--json", dest="as_json", action="store_true")
    args = ap.parse_args(argv)

    path = Path(args.preflight).expanduser()
    try:
        record = json.loads(path.read_text())
    except OSError as exc:
        print(f"admit-node: cannot read the preflight record {path}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ValueError as exc:
        print(f"admit-node: {path} is not JSON: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if not isinstance(record, dict):
        print(f"admit-node: {path} is not a preflight record", file=sys.stderr)
        return EXIT_USAGE

    try:
        verdict = decide(record, args.mem_cap, args.running_cap, args.jobs)
    except ValueError as exc:
        ap.error(str(exc))
    verdict["schema"] = "sabot-admission/1"
    verdict["preflight"] = str(path)

    if args.as_json:
        print(json.dumps(verdict, indent=2, sort_keys=True))
    else:
        stream = sys.stdout if verdict["admitted"] else sys.stderr
        print(f"admit-node: {verdict['reason']}", file=stream)
        print(f"admit-node: jobs={verdict['jobs']}", file=stream)
    return 0 if verdict["admitted"] else EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
