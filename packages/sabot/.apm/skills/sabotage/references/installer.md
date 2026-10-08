# Installer flow

How sabot handles tool availability. The tools run in the surface image, not
on the host (`references/isolation.md`, What runs where), so step 3 does not install
scanners on the host at all: it builds or extends the image and bakes the target's
dev-deps into it (`isolation.md`, Provisioning). A tool missing from the image
becomes a reported coverage gap, surfaced by `--assert-tools`.

## Host preflight, then image provisioning

The only host requirement is the container runtime plus `bd` and `git`;
`scripts/install-tools.sh --probe --images <images>` is a preflight that confirms these
and asserts the tools of each image the campaign uses. It installs nothing on the host:
a host-side scanner would run the target's code outside the container, so every tool
lives in the image.

1. **Preflight (host):** `install-tools.sh --probe --images <images>` confirms a runtime
   (`docker`/`finch`), `bd`, and `git`, and asserts each named `sabot/<name>:1` image
   (the target's language stacks, such as `rust,node`, or `base` alone; without
   `--images` every language image is required). A missing runtime or missing `bd`
   ABORTS the whole run at step 0 (`isolation.md`, No container runtime); there is no
   degraded run.
2. **Provision (image), after the step-3 approval:** build any missing surface image
   from `references/containers/`, then extend it with the target's dev-deps by running
   `scripts/build-ext-image.sh --target <dir> --base sabot/<surface>:1 --tag sabot/<surface>-ext:1`
   (`isolation.md` Provisioning); it copies only the manifest+lock, so the layer
   caches on the lock. The build waits for the reply to the step-3 proposal, because
   it runs networked installs of the tool set that reply approves.
3. **Assert (image):** `run-contained.sh --assert-tools <image> <tools>` confirms
   every campaign tool answers inside the image before the run trusts a clean result.
   To learn what an image HAS rather than test a guess, `run-contained.sh --list-tools
   <image>` prints its executables. Reach for it before assuming a helper exists: a
   `sabot/node-ext:1` built when the node image still started FROM `node:22` rather
   than the base carried no `python3`, which broke a probe that took it for granted.

MUST Enumerate the image with `--list-tools` when a recipe depends on an interpreter or helper the tool table does not name, since a probe written against the wrong inventory fails in a way that looks like the target's fault.
MUST Provision tools into the image, never onto the host. A scanner on the host runs the target's build code unconfined, the exact risk the container removes.
MUST Treat a missing runtime (or missing `bd`) as a hard abort of the whole run: stop at step 0 before opening the run graph, not merely skip the execution phases. Report a missing image tool as a coverage gap in the report; never let it pass as a silent skip.

When no container runtime exists, the run aborts entirely at step 0: no container, no
campaign. It does not fall back to host tools or a static-only subset (`isolation.md`,
No container runtime). There is no host-install path to reach for.

## Image build notes

These are requirements for the surface `Dockerfile`, not host installs. The
`references/containers/Dockerfile.<surface>` bakes each tool with a pinned version
(see `tooling.md`, Where tools come from); a few carry a toolchain constraint:

| Tool | Build requirement |
|---|---|
| `cargo-fuzz` | a nightly toolchain for `-Zsanitizer=address`; the rust image installs nightly for the fuzz target |
| `atheris` | builds from source against clang and libFuzzer (`libclang-rt-<major>-dev`), with the base image's Debian `python3`. The interpreter is NOT pinned: it is the trixie `python3` package at build time, so a rebuild can move its patch release, and the image's import probe is what catches a break |
| `go test -fuzz` | Go 1.18 or later, built into the toolchain image; nothing extra |

MUST Bake a fuzzer with the toolchain it needs, pinned, and `--assert-tools` it before the run trusts a clean result. A fuzzer that cannot build its instrumented target is unavailable in practice, and the assert catches it up front.
NOT Never provision a fuzzer or its toolchain on the host. It belongs in the image; a host toolchain switch to satisfy a fuzzer is the host contamination the container model removes.
