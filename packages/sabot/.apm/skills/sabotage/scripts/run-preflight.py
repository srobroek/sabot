#!/usr/bin/env python3
"""The single command run before a campaign. Fails loudly, or emits the preflight record.

    run-preflight.py --target DIR --run-id ID [--image IMG ...] [--min-free-mb N]
                     [--require-tool NAME ...] [--jobs N] [--deadline-s N]
                     [--skip-image-probe] [--json-out PATH]

Replaces the prose setup checklist. Every hard precondition is checked here and a failure
exits non-zero: a container runtime, `git`, `bd` runnable FROM THE REPO ROOT, each required
image present, and free host disk above a threshold. That last one did not exist, and its
absence is what caused the outage -- concurrent per-node build trees filled a 460 GiB
volume to 100%, containerd could not grow its sparse disk, image blobs began returning
`input/output error`, and no container would start on any image.

Whether it passes or fails, it writes `<run-root>/preflight.json`. A failed preflight is a
RECORD, not a silence, and later steps and the final report cite that file instead of
re-deriving any of it.

NETWORK POSTURE, stated as a field because agents kept treating its consequences as
transient: every target-touching container runs `--network none`. No DNS, no egress, no
proxy, no package or rule registry. "Local host access" means loopback INSIDE the
container. A tool that needs the network is NOT EXECUTED with that as the reason -- never
zero findings, and never a retry.

IMAGE TOOL INVENTORY, because prediction failed in both directions: one authoring artifact
claimed nightly and cargo-fuzz were absent from an image carrying both, while
`cargo-nextest`, `just`, and CodeQL genuinely are absent, and 26 justfile recipes were then
recorded as untested when the correct response was to run each recipe body directly -- a
task runner dispatches shell and is substitutable, so its absence is not a coverage gap
(see surfaces/build.md). The inventory is enumerated from the image, and each tool
carries whether it works offline or needs a baked-in database or ruleset.

RESOURCE ESTIMATE AND CONCURRENCY. Memory, CPU count, and disk are READ FROM THE RUNTIME,
never hardcoded and never taken from the laptop: on the reference host the VM is 8 GiB /
4 CPU / 60 GiB while the machine under it is far larger. Every container's `--memory` cap
is drawn from that one pool, so `max_parallel_nodes = floor(usable_mem / per_node_cap)` is
arithmetic. A campaign that held 3 concurrent nodes was correct only because every node
happened to run at 2048 MiB; one node needing 6144 cannot coexist with two of them, and
dispatching past the line does not run slower -- the kernel OOM-kills a container and the
surface reads as findings-free. `jobs` is derived the same way, since -j 4 against 4 vCPUs
with three containers competing is oversubscription.

Admission is enforced by `admit-node.py`, which reads this record: a node is refused when
the running sum of memory caps would exceed `memory.usable_mb`. A pool the runtime did not
report is UNKNOWN, and an unknown pool fails `target_fits_memory` rather than being
planned against the laptop's memory.

TIME is not a safety limit and is not enforced here. `--deadline-s` is optional and absent
by default; when set it is recorded for the container to stop itself at the deadline and
report a graceful partial result naming what had not yet run.

Stdlib only. Starts no container: `--list-tools` and `docker info` are the only runtime
calls, and `--skip-image-probe` removes the first.

EXIT CODES: 0 ready, 2 usage, 3 a precondition failed.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXIT_USAGE = 2
EXIT_PRECONDITION = 3

_spec = importlib.util.spec_from_file_location("sabot_run_layout", HERE / "run-layout.py")
layout = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(layout)

# Enough headroom for one full per-node target dir on top of the estimate, so the run that
# fills the disk is refused rather than started. The outage began at 6.3 GiB free.
DEFAULT_MIN_FREE_MB = 16384

# Fraction of measured headroom a campaign may plan against. The remainder absorbs the
# container store's own growth, which is what could not grow when the volume hit 100%.
DISK_PLAN_FRACTION = 0.6

# Memory left to the VM itself, subtracted before any node is admitted. Measured: an 8 GiB
# VM has ~7 GiB usable, which is why 6144 + 2x2048 = 10 GiB does not fit and the kernel
# OOM-kills a container instead of running it slowly. An OOM produces an INVALID run that
# reads as a findings-free surface, so this is a safety limit, not a performance knob.
VM_RESERVE_MB = 1024

# Recipe degradation comes BEFORE any memory raise. Measured: a build SIGKILLed at 2048
# completed in 2m47s at 739 MiB under this env with -j 1 -- the cap was never the fix.
DEGRADE_ENV = {
    "CARGO_PROFILE_TEST_DEBUG": "0",
    "CARGO_PROFILE_DEV_DEBUG": "0",
    "CARGO_INCREMENTAL": "0",
}
# Do not add to the ladder: rustc parses `RUSTFLAGS=-Wl,--no-keep-memory` as `-W l,...` and
# emits E0602 on every crate, so it turns an OOM into a total build failure.
RETRY_LADDER = [
    {"step": 1, "action": "degrade the recipe", "jobs": 1, "env": DEGRADE_ENV,
     "raises_cap": False,
     "basis": "measured: 2048 SIGKILLed ld; the same build finished at 739 MiB with this"},
    {"step": 2, "action": "raise --memory once", "jobs": 1, "env": DEGRADE_ENV,
     "raises_cap": True,
     "basis": "only if the degraded recipe still dies; record it as a budget deviation"},
]

# Tools whose absence a campaign must know about before it aims a phase at them, and
# whether each can work with no network. `needs` names the baked-in asset it depends on;
# a tool with a `needs` and no baked asset is NOT EXECUTED, not a clean scan.
#
# The useful distinction for a reader is not "installed" but "usable offline". A
# `needs-network` tool is a real coverage gap even when it is present in the image:
# `trufflehog` is installed and answers `--version`, and it still cannot say whether a
# secret it found is LIVE, because that answer lives at the credential's own provider.
# An unverified secret hit and a verified-clean pass are different results; offline only
# the first is available.
TOOL_POSTURE = {
    "cargo": ("offline", "a vendored or baked registry (CARGO_NET_OFFLINE=true)"),
    "rustc": ("offline", None),
    "cargo-fuzz": ("offline", "a nightly toolchain"),
    "cargo-audit": ("offline", "a baked advisory-db"),
    "cargo-deny": ("offline", "a baked advisory-db nested under advisory-db-<hash>"),
    "cargo-careful": ("offline", "a baked sysroot under /deps/cache"),
    "miri": ("offline", "a baked sysroot under /deps/cache"),
    "cargo-nextest": ("offline", None),
    "clippy-driver": ("offline", None),
    "just": ("offline", None),
    "go": ("offline", "a baked module cache"),
    "node": ("offline", None),
    "opengrep": ("needs-baked-ruleset",
                 "rule packs baked into the image; stock registry packs (p/rust) cannot "
                 "load under --network none and exit non-zero"),
    "semgrep": ("needs-baked-ruleset", "rule packs baked into the image"),
    "gitleaks": ("offline", "a real .git directory, not a worktree pointer file"),
    "osv-scanner": ("needs-baked-db", "a baked OSV database"),
    "trivy": ("needs-baked-db", "a baked vulnerability database"),
    "actionlint": ("offline", None),
    # pinact was DROPPED from the image: zizmor --offline reports the same unpinned
    # refs, and pinact's unique capability is writing the pin, not detecting it.
    "trufflehog": ("needs-network",
                   "each credential provider, to verify a hit is live. Offline it "
                   "reports unverified hits only, and its zero is unproven unless a "
                   "planted canary secret proved it can flag one at all"),
    "grype": ("needs-baked-db", "a baked vulnerability database"),
    "npm": ("needs-network", "the npm registry; `npm audit` is unusable offline"),
    "pip-audit": ("needs-network", "the PyPI advisory feed unless a local database is baked"),
    "ruff": ("offline", None),
    "shellcheck": ("offline", None),
    "codeql": ("needs-baked-db", "a CodeQL bundle and query packs"),
}


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 60):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)


def _first_line(text: str) -> str:
    return next((ln.strip() for ln in text.splitlines() if ln.strip()), "")


def estimate_resources(target: Path) -> dict:
    """Per-node memory and disk from observable target properties.

    Two calibration points from a real campaign, both recorded so a future edit can see
    what the numbers rest on:
      - the standard 2048 MiB cap SIGKILLed `ld` linking a single cdylib; the same package
        linked at 6144 MiB with CARGO_PROFILE_TEST_DEBUG=0.
      - a whole-workspace cargo target dir measured 5.2 GiB over ~45 members, and the
        image already bakes 751 crates, so a cold per-node build is the norm. The disk
        figure therefore assumes a FULL per-node target dir, never a shared one.
    """
    manifests = []
    rc, out = _run(["git", "ls-files"], cwd=target)
    tracked = out.splitlines() if rc == 0 else []
    if tracked:
        manifests = [t for t in tracked if Path(t).name == "Cargo.toml"]
        source_mb = 0
        for rel in tracked:
            try:
                source_mb += (target / rel).stat().st_size
            except OSError:
                pass
        source_mb //= 1024 * 1024
    else:
        manifests = [str(p.relative_to(target)) for p in target.rglob("Cargo.toml")]
        source_mb = 0

    links_cdylib = False
    for rel in manifests:
        try:
            if "cdylib" in (target / rel).read_text(errors="replace"):
                links_cdylib = True
                break
        except OSError:
            pass

    lock = target / "Cargo.lock"
    lock_packages = 0
    if lock.is_file():
        lock_packages = lock.read_text(errors="replace").count("[[package]]")

    members = max(1, len(manifests))
    mem_mb = 6144 if links_cdylib else 2048
    mem_mb += 512 * max(0, (members - 20) // 20)
    # Floored at 1024 MiB: measured per-node Rust target dirs ran 739 MiB to 5.2 GiB, so a
    # per-node disk figure belongs in the low GiB and a sub-GiB estimate is always wrong.
    disk_mb = max(1024, 1024 + 120 * members + 2 * source_mb)

    return {
        "workspace_members": members,
        "links_cdylib": links_cdylib,
        "lock_packages": lock_packages,
        "source_mb": source_mb,
        "per_node_mem_mb": mem_mb,
        "per_node_disk_mb": disk_mb,
        "mem_env_when_linking": {"CARGO_PROFILE_TEST_DEBUG": "0", "CARGO_PROFILE_DEV_DEBUG": "0"},
        "basis": (
            "mem: 6144 when anything links a cdylib (2048 SIGKILLed ld, 6144 linked), "
            "+512 per 20 members over 20. disk: 1024 + 120/member + 2x source, "
            "calibrated on measured per-node target dirs of 739 MiB to 5.2 GiB over ~45 "
            "members, and assuming a full per-node target dir."
        ),
    }


def host_capacity(engine: str | None) -> tuple[int | None, int | None, str, bool]:
    """(memory MiB, vCPUs, source, measured) for the pool every container draws from.

    Measured on the reference host: `colima list` and `docker info` agree at 8 GiB / 4 CPU
    / 60 GiB, while the laptop underneath has far more. Planning against the laptop is how
    a run gets dispatched past the line and OOM-killed, so only the runtime's own answer
    counts. When it cannot answer, the pool is unknown: (None, None, reason, False).
    """
    if engine:
        rc, out = _run([engine, "info", "--format", "{{.MemTotal}} {{.NCPU}}"], timeout=30)
        parts = _first_line(out).split()
        if rc == 0 and len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            if int(parts[0]) > 0:
                return (int(parts[0]) // (1024 * 1024), int(parts[1]),
                        f"{engine} info MemTotal/NCPU", True)
        return (None, None,
                f"unavailable: `{engine} info` did not report MemTotal/NCPU (rc={rc})", False)
    return None, None, "unavailable: no container runtime", False


def free_mb(path: Path) -> int:
    st = shutil.disk_usage(path)
    return st.free // (1024 * 1024)


def image_inventory(engine: str, image: str, timeout: int = 180) -> dict:
    """Ask the image what it carries. run-contained.sh --list-tools enumerates the tool
    prefixes, so nothing here holds a hardcoded list that can drift."""
    rc, out = _run(
        ["bash", str(HERE / "run-contained.sh"), "--list-tools", image], timeout=timeout
    )
    if rc != 0:
        return {"present": False, "error": _first_line(out) or f"--list-tools rc={rc}"}
    have = set(out.split())
    tools = {}
    for name, (posture, needs) in sorted(TOOL_POSTURE.items()):
        tools[name] = {
            "present": name in have,
            "offline": posture == "offline",
            "posture": posture,
            "needs": needs,
        }
    # Present-but-unusable is the category a reader needs and an "installed" list hides.
    # Each of these is an open coverage gap to state in the report, not a skipped extra.
    unusable_offline = sorted(
        name for name, row in tools.items()
        if row["present"] and row["posture"] == "needs-network"
    )
    return {
        "present": True,
        "binary_count": len(have),
        "tools": tools,
        "present_but_unusable_offline": unusable_offline,
        "unusable_offline_consequence": (
            "installed and answering --version, and still NOT EXECUTED under "
            "--network none. Each one is an open coverage gap in the report."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="run-preflight.py")
    ap.add_argument("--target", required=True, help="the repo under audit")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--image", action="append", default=[], help="repeatable")
    ap.add_argument("--require-tool", action="append", default=[], help="repeatable")
    ap.add_argument("--min-free-mb", type=int, default=DEFAULT_MIN_FREE_MB,
                    help="the ONE disk floor: pass the same value to run-contained.sh "
                         "--min-free-mb rather than setting a second threshold")
    ap.add_argument("--jobs", type=int, default=None,
                    help="requested per-node build jobs; capped by NCPU/concurrency")
    ap.add_argument("--deadline-s", type=int, default=None,
                    help="optional, absent by default: a graceful in-container stop")
    ap.add_argument("--skip-image-probe", action="store_true",
                    help="skip --list-tools; the inventory is then unknown, not empty")
    ap.add_argument("--json-out", help="defaults to <run-root>/preflight.json")
    args = ap.parse_args(argv)

    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        print(f"run-preflight: --target is not a dir: {target}", file=sys.stderr)
        return EXIT_USAGE
    if "/" in args.run_id or args.run_id != layout.slug(args.run_id):
        print(
            f"run-preflight: --run-id must already be slug-shaped; "
            f"try {layout.slug(args.run_id)!r}",
            file=sys.stderr,
        )
        return EXIT_USAGE

    root = layout.run_root(target / ".sabot" / args.run_id)
    layout.init(root)
    record_path = Path(args.json_out) if args.json_out else Path(layout.paths(root)["SABOT_PREFLIGHT"])

    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str, fatal: bool = True) -> bool:
        checks.append({"name": name, "ok": bool(ok), "fatal": fatal, "detail": detail})
        return bool(ok)

    engine = next((e for e in ("docker", "finch") if shutil.which(e)), None)
    check("container_runtime", engine is not None,
          f"engine={engine}" if engine else "no docker/finch on PATH")
    ctx = ""
    if engine:
        _, ctx_out = _run([engine, "context", "show"], timeout=20)
        ctx = _first_line(ctx_out)

    git = shutil.which("git")
    check("git_present", git is not None, "git on PATH" if git else "no git on PATH")
    rc, out = _run(["git", "rev-parse", "HEAD"], cwd=target)
    head = _first_line(out) if rc == 0 else ""
    check("target_is_git_repo", rc == 0, head or out.strip()[:200])
    rc, dirty_out = _run(["git", "status", "--porcelain"], cwd=target)
    dirty = bool(dirty_out.strip()) if rc == 0 else None

    # `bd` must answer FROM THE REPO ROOT: the store is discovered relative to cwd, so a
    # `bd` that works in $HOME and not here is the same as no bd at all.
    #
    # The query flag is `--label`, singular. `bd list --labels x` is accepted and SILENTLY
    # returns nothing on a query, and a whole wisp set once read as "no work exists"
    # because of it. Every bd call in this skill uses --label.
    bd = shutil.which("bd")
    check("bd_present", bd is not None, "bd on PATH" if bd else "no bd on PATH")
    bd_ok, bd_detail = False, "not attempted"
    if bd:
        rc, out = _run(["bd", "ready", "--json"], cwd=target, timeout=60)
        if rc != 0:
            bd_detail = f"`bd ready --json` from {target} exited {rc}: {_first_line(out)[:200]}"
        else:
            try:
                json.loads(out or "[]")
                bd_ok, bd_detail = True, f"`bd ready --json` answers from {target}"
            except ValueError:
                bd_detail = "`bd ready --json` did not return JSON from the repo root"
    check("bd_runnable_from_repo_root", bd_ok, bd_detail)

    images: dict[str, dict] = {}
    for img in args.image:
        if not engine:
            images[img] = {"present": False, "error": "no container runtime"}
            continue
        rc, out = _run([engine, "image", "inspect", img], timeout=60)
        if rc != 0:
            images[img] = {"present": False,
                           "error": "absent, or a corrupt content blob presenting as absent"}
            continue
        if args.skip_image_probe:
            images[img] = {"present": True, "tools": None,
                           "note": "inventory not probed (--skip-image-probe): unknown, not empty"}
        else:
            images[img] = image_inventory(engine, img)
    check("images_present", all(v.get("present") for v in images.values()) if images else True,
          ", ".join(f"{k}={'ok' if v.get('present') else v.get('error')}" for k, v in images.items())
          or "no --image given")

    missing_tools: list[str] = []
    for tool in args.require_tool:
        found = any(
            (v.get("tools") or {}).get(tool, {}).get("present") for v in images.values()
        )
        if not found:
            missing_tools.append(tool)
    check("required_tools_present", not missing_tools,
          f"missing from every image: {missing_tools}" if missing_tools
          else f"all present: {args.require_tool}")

    disk_free = free_mb(root)
    check("free_disk", disk_free >= args.min_free_mb,
          f"{disk_free} MiB free at {root}, threshold {args.min_free_mb} MiB")

    est = estimate_resources(target)
    hmem, ncpu, hmem_src, hmem_measured = host_capacity(engine)
    usable_mem = max(0, hmem - VM_RESERVE_MB) if hmem_measured else None
    # An unknown pool is refused, never assumed to fit: the laptop's memory is not the VM's.
    fits_mem = usable_mem is not None and est["per_node_mem_mb"] <= usable_mem
    check("target_fits_memory", fits_mem,
          f"needs {est['per_node_mem_mb']} MiB/node; usable "
          f"{usable_mem if usable_mem is not None else 'UNKNOWN'} MiB of "
          f"{hmem if hmem is not None else 'UNKNOWN'} MiB ({hmem_src})")
    fits_disk = disk_free * DISK_PLAN_FRACTION >= est["per_node_disk_mb"]
    check("target_fits_disk", fits_disk,
          f"needs {est['per_node_disk_mb']} MiB/node; plannable "
          f"{int(disk_free * DISK_PLAN_FRACTION)} MiB of {disk_free} MiB free")

    # max_concurrent = floor(usable_mem / per_node_memory_cap). Arithmetic, not a preference.
    # With the pool unknown the run is refused above, and the only honest figure is 1.
    by_disk = int(disk_free * DISK_PLAN_FRACTION) // max(1, est["per_node_disk_mb"])
    by_mem = (usable_mem // max(1, est["per_node_mem_mb"])) if usable_mem is not None else 1
    max_parallel = max(1, min(by_disk, by_mem))
    # -j 4 against 4 vCPUs with three containers competing is oversubscription; two nodes
    # had to drop to -j 1 to survive. Under concurrency the effective figure is 1.
    jobs = max(1, min(args.jobs or (ncpu or 1), (ncpu or 1) // max_parallel))

    ok = all(c["ok"] for c in checks if c["fatal"])
    record = {
        "schema": "sabot-preflight/1",
        "ok": ok,
        "run_id": args.run_id,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": {"path": str(target), "git_head": head, "dirty": dirty},
        "runtime": {"engine": engine, "context": ctx},
        "network_posture": {
            "mode": "none",
            "egress": False,
            "dns": False,
            "proxy": False,
            "registries": False,
            "loopback": "in-container only",
            "consequence": (
                "a tool needing the network is NOT EXECUTED with that reason. Never zero "
                "findings, never a retry."
            ),
        },
        "layout": layout.paths(root),
        "layout_contract": ".apm/skills/sabotage/references/run-layout.md",
        "disk": {
            "path": str(root), "free_mb": disk_free, "min_free_mb": args.min_free_mb,
            "threshold_owner": (
                "this record. run-contained.sh --min-free-mb and install-tools.sh --probe "
                "read the same df; pass this value down instead of adding a third floor."
            ),
        },
        "memory": {
            "pool_total_mb": hmem,
            "vm_reserve_mb": VM_RESERVE_MB,
            "usable_mb": usable_mem,
            "source": hmem_src,
            "measured_from_runtime": hmem_measured,
            "note": (
                "every container's --memory cap is drawn from this one pool. Dispatching "
                "past it does not run slower; the kernel OOM-kills a container and the "
                "surface reads as findings-free."
            ),
        },
        "cpu": {"ncpu": ncpu, "jobs_per_node": jobs,
                "note": "-j N against N vCPUs with several containers is oversubscription; "
                        "the budget table's `jobs` is a solo-run ceiling"},
        "beads": {"present": bd is not None, "runnable_from_repo_root": bd_ok,
                  "query_label_flag": "--label"},
        "images": images,
        "estimate": est,
        "concurrency": {
            "max_parallel_nodes": max_parallel,
            "bound_by": "disk" if by_disk <= by_mem else "memory",
            "jobs_per_node": jobs,
            "basis": (
                "max_concurrent = floor(usable_mem / per_node_memory_cap), floored by disk. "
                "Full per-node isolation means each node costs its own disk and memory, so "
                "this is arithmetic, not a preference. An unbounded campaign filled the "
                "host volume, and a campaign that held 3 concurrent nodes was only correct "
                "because every node happened to run at 2048 MiB."
            ),
        },
        "admission": {
            "rule": (
                "refuse to dispatch node N+1 when the running sum of --memory caps would "
                "exceed memory.usable_mb. Checkable, not advisory."
            ),
            "usable_mb": usable_mem,
            "check_with": "admit-node.py --preflight <this file> --mem-cap MB "
                          "[--running-cap MB, once per running node]",
        },
        "retry_ladder": RETRY_LADDER,
        "no_auto_retry": [
            "ENOSPC or any disk-full failure: stop, report, tear down, verify headroom, resume",
            "container-store corruption: never retried; the image blobs were the casualty",
        ],
        "deadline_s": args.deadline_s,
        "checks": checks,
    }
    record_path.parent.mkdir(parents=True, exist_ok=True)
    record_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")

    for c in checks:
        print(f"[{'ok ' if c['ok'] else 'FAIL'}] {c['name']}: {c['detail']}")
    print(f"max_parallel_nodes={max_parallel} (bound by {record['concurrency']['bound_by']}), "
          f"jobs_per_node={jobs}")
    print(f"preflight record: {record_path}")
    if not ok:
        failed = [c["name"] for c in checks if c["fatal"] and not c["ok"]]
        print(f"run-preflight: NOT READY: {failed}. The record above says why; do not start "
              "a campaign against an unmet precondition.", file=sys.stderr)
        return EXIT_PRECONDITION
    return 0


if __name__ == "__main__":
    sys.exit(main())
