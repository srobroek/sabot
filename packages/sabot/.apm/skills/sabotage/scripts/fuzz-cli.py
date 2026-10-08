#!/usr/bin/env python3
"""Adversarial harness for any CLI, hook, or JSON-stdin program.

Generalized from packages/orchestrate/scripts/fuzz-evaluator.py, which found real
command-position bypasses in this repo's PreToolUse guards.

Two layers, both aimed at BREAKING the target:

  1. Structural corpus: empty, malformed, oversized, unicode, deeply-nested, and
     type-confused payloads. Every one of them must produce a defined result --
     never a crash, a hang, or unparsable output.
  2. Attack vectors: caller-supplied inputs (command-position wrappers, injection
     strings, traversal paths) each asserted against an EXPECTED verdict. A guard
     that allows what it should block is a bypass.

Findings print to stdout; the run exits non-zero when any finding is recorded, so
CI can gate on it. Nothing is written outside --artifacts-dir.

MODES
  --mode json     target reads a JSON object on stdin and writes JSON to stdout
                  (Claude Code / Codex hook contract). Default.
  --mode text     target reads bytes on stdin; only crash/hang invariants apply.
  --mode argv     payload is passed as a single argv element instead of stdin.

USAGE
  fuzz-cli.py --target ./scripts/guard.py --mode json
  fuzz-cli.py --target ./bin/parse --mode text --timeout 5 --max-bytes 4000000
  fuzz-cli.py --target ./scripts/guard.py --vectors vectors.json --artifacts-dir /tmp/a

VECTORS FILE (JSON list; written by the `sabot-fuzzer` agent)
  [{"name": "env-wrapper bypass",
    "payload": {"tool_name": "Bash", "tool_input": {"command": "env rm -rf /"}},
    "expect": "deny",
    "why": "wrapper prefix must not move the command out of guard position"}]

`expect` is one of: deny · allow · ask · no-crash · nonzero-exit · zero-exit.
For --mode json, deny/allow/ask follow the hook contract (Claude Code, Codex): exit 2 is
deny whatever stdout says; otherwise the decision fields of a JSON object on stdout
decide (hookSpecificOutput.permissionDecision, permissionDecision, or decision, with the
legacy `block`/`approve` read as deny/allow), and no decision is allow.

EXIT
  0  no findings
  1  findings recorded
  2  usage error / target not executable

Stdlib only. No network. Never writes to the target repo.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# --------------------------------------------------------------------------
# Structural corpus: applies to EVERY target regardless of what it does.
# Each entry is (name, payload_bytes_or_obj, note). A crash, hang, or
# unparsable response to any of these is a finding.
# --------------------------------------------------------------------------

_DEEP_NEST_DEPTH = 2000
_BIG_STRING_BYTES = 1_000_000


def structural_corpus(mode: str, max_bytes: int) -> list[tuple[str, bytes, str]]:
    """Return [(name, raw_stdin_bytes, note)] for the always-run corpus."""
    big = "A" * min(_BIG_STRING_BYTES, max_bytes)
    deep_open = b"[" * _DEEP_NEST_DEPTH + b"]" * _DEEP_NEST_DEPTH
    items: list[tuple[str, bytes, str]] = [
        ("empty", b"", "zero-length stdin"),
        ("whitespace", b"   \n\t\n  ", "whitespace only"),
        ("nul-bytes", b"\x00\x00\x00", "NUL bytes"),
        ("not-json", b"this is not json at all", "plain text where JSON expected"),
        ("truncated-json", b'{"tool_name": "Ba', "truncated mid-token"),
        ("json-scalar", b'"just a string"', "valid JSON, wrong shape"),
        ("json-null", b"null", "JSON null"),
        ("json-array", b"[1,2,3]", "array where object expected"),
        ("json-number", b"123", "bare number"),
        ("json-true", b"true", "bare bool"),
        ("empty-object", b"{}", "object with no expected keys"),
        ("dup-keys", b'{"a": 1, "a": 2}', "duplicate keys"),
        ("deep-nest", deep_open, f"{_DEEP_NEST_DEPTH}-deep nesting (stack overflow probe)"),
        ("huge-string", json.dumps({"tool_name": big}).encode(), "1 MB single field"),
        ("invalid-utf8", b'{"tool_name": "\xff\xfe"}', "invalid UTF-8 bytes"),
        ("lone-surrogate", b'{"tool_name": "\\ud800"}', "lone surrogate escape"),
        ("bom-prefix", b"\xef\xbb\xbf{}", "UTF-8 BOM before JSON"),
        ("crlf", b'{"tool_name":"Bash"}\r\n', "CRLF line ending"),
        ("no-trailing-newline", b'{"tool_name":"Bash"}', "no trailing newline"),
        ("two-objects", b'{"a":1}\n{"b":2}', "two JSON objects (JSONL where object expected)"),
        ("negative-numbers", b'{"tool_name": -1, "timeout": -99999}', "negative where positive expected"),
        ("type-confusion", b'{"tool_name": 42, "tool_input": "not-an-object"}', "wrong types throughout"),
        ("null-fields", b'{"tool_name": null, "tool_input": null}', "null in every field"),
        ("unicode-tricks", json.dumps(
            {"tool_name": "Ba\u200bsh", "tool_input": {"command": "rm\u202e -rf /"}}
        ).encode(), "zero-width + RTL override in values (escapes, never literals: a literal invisible char trips every hidden-char audit and is unreviewable in a diff)"),
        ("emoji", json.dumps({"tool_name": "\U0001f600"}).encode(), "emoji in a field"),
        ("prototype-keys", b'{"__proto__": {"x": 1}, "constructor": {"y": 2}}',
         "prototype-pollution-style keys"),
        ("dotted-keys", b'{"a.b.c": 1, "..": 2, "": 3}', "dotted and empty keys"),
    ]
    if mode == "text":
        # A text-mode target has no JSON contract; keep byte-level cases only.
        keep = {"empty", "whitespace", "nul-bytes", "not-json", "huge-string",
                "invalid-utf8", "bom-prefix", "crlf", "no-trailing-newline",
                "deep-nest", "unicode-tricks", "emoji"}
        items = [i for i in items if i[0] in keep]
    return items


# --------------------------------------------------------------------------
# Invocation
# --------------------------------------------------------------------------


class Finding:
    __slots__ = ("kind", "case", "detail", "input_ref")

    def __init__(self, kind: str, case: str, detail: str, input_ref: str = ""):
        self.kind = kind
        self.case = case
        self.detail = detail
        self.input_ref = input_ref

    def __str__(self) -> str:
        ref = f"  input: {self.input_ref}" if self.input_ref else ""
        return f"[{self.kind}] {self.case}: {self.detail}{ref}"


class Runner:
    def __init__(self, target: list[str], mode: str, timeout: int, mem_mb: int,
                 artifacts: Path, env_extra: dict[str, str]):
        self.target = target
        self.mode = mode
        self.timeout = timeout
        self.mem_mb = mem_mb
        self.artifacts = artifacts
        self.env_extra = env_extra
        self.runs = 0

    def _preexec(self):
        """Cap address space in the child so a runaway allocation cannot take the
        machine down. Returns None on platforms without RLIMIT_AS."""
        if self.mem_mb <= 0:
            return None
        try:
            import resource
        except ImportError:
            return None

        limit = self.mem_mb * 1024 * 1024

        def _apply():
            try:
                resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
            except (ValueError, OSError):
                pass

        return _apply

    def invoke(self, payload: bytes, argv_extra: list[str] | None = None):
        """Run the target once. Returns (stdout, stderr, returncode, status)
        where status is one of: ok · timeout · signal · oserror."""
        self.runs += 1
        cmd = list(self.target) + (argv_extra or [])
        env = {**os.environ, **self.env_extra}
        try:
            p = subprocess.run(
                cmd,
                input=payload,
                capture_output=True,
                timeout=self.timeout,
                env=env,
                preexec_fn=self._preexec() if os.name == "posix" else None,
            )
        except subprocess.TimeoutExpired:
            return b"", b"", -1, "timeout"
        except OSError as e:
            return b"", str(e).encode(), -1, "oserror"
        except ValueError as e:
            # An embedded NUL in an argv element raises ValueError out of _fork_exec,
            # which is not an OSError and so escaped the handler above and aborted the
            # whole run. Measured: one NUL vector took all 49 vectors of a justfile
            # harness with it, and the traceback read as a defect in the target. The NUL
            # is refused by execve, not by the target, so this is a vector the OS cannot
            # deliver -- reported as undeliverable rather than as a target result, because
            # calling it a pass would claim the boundary was tested.
            return b"", str(e).encode(), -1, "undeliverable"
        status = "signal" if p.returncode < 0 else "ok"
        return p.stdout, p.stderr, p.returncode, status

    def save_input(self, name: str, payload: bytes, delivery: str = "stdin") -> str:
        """Persist a payload that produced a finding, so it is reproducible.

        A saved repro is round-tripped before its path is handed back. Zero-byte
        `.input` files shipped as "reproducing inputs" for a whole campaign and were
        caught only by a reader who distrusted them and re-persisted all 21 payloads by
        hand; a crash whose repro is empty cannot be minimized, which is the entire job
        of the triager role downstream. An unreadable or short write is therefore loud
        here rather than a silent artifact discovered later.

        `delivery` records HOW the payload reached the target, because an argv payload
        replayed on stdin does not reproduce anything either.
        """
        self.artifacts.mkdir(parents=True, exist_ok=True)
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)[:80]
        path = self.artifacts / f"{safe}.input"

        if not payload:
            raise ValueError(
                f"refusing to write an empty repro for {name!r}: a zero-byte .input "
                "reproduces nothing. If the case genuinely has an empty payload, record "
                "it as a finding with no repro rather than as an empty file."
            )

        path.write_bytes(payload)
        readback = path.read_bytes()
        if readback != payload:
            raise OSError(
                f"repro {path} did not round-trip: wrote {len(payload)} byte(s), read "
                f"back {len(readback)}. The artifact is unusable; do not report it as a "
                "repro."
            )
        (self.artifacts / f"{safe}.delivery").write_text(f"{delivery}\n")
        return str(path.resolve())


def persist(r: "Runner", case: str, payload: bytes, delivery: str) -> str:
    """save_input() with the one legitimately-empty case handled.

    A genuinely empty payload (the `empty` structural case) has no repro to write, and
    that is different from a repro that was LOST. It yields an EMPTY input_ref, so the
    finding reads as having no repro; a zero-byte file presented as a repro is the
    failure this guards, because the field being populated is what a reader trusts.
    """
    try:
        return r.save_input(case, payload, delivery)
    except ValueError:
        return ""


# --------------------------------------------------------------------------
# Verdict extraction (hook contract)
# --------------------------------------------------------------------------

# Legacy decision values, read as their current equivalents. Claude Code's deprecated
# top-level `decision: "block"` and Codex's `decision: "block"` both stop the call, so
# scoring `block` against an expected `deny` reported a spurious CONTRACT finding.
_DECISION_ALIASES = {"block": "deny", "approve": "allow"}

# The hook contract's blocking exit status. A guard that denies by exiting 2 with its
# reason on stderr (the documented Claude Code form) prints nothing on stdout, so reading
# stdout alone scored every such deny as an allow: a false BYPASS on every deny vector.
HOOK_BLOCK_RC = 2


def extract_decision(obj) -> str | None:
    """Pull a hook decision out of a parsed response. Returns the lowercased decision
    with legacy aliases mapped, or None when the response carries no decision at all
    (which the hook contract treats as 'no opinion' -> allow)."""
    if not isinstance(obj, dict):
        return None
    hso = obj.get("hookSpecificOutput")
    candidates = []
    if isinstance(hso, dict):
        candidates += [hso.get("permissionDecision"), hso.get("decision")]
    candidates += [obj.get("permissionDecision"), obj.get("decision")]
    for value in candidates:
        if isinstance(value, str) and value.strip():
            decision = value.strip().lower()
            return _DECISION_ALIASES.get(decision, decision)
    return None


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------


def check_structural(r: Runner, findings: list[Finding], mode: str, max_bytes: int) -> None:
    for name, payload, note in structural_corpus(mode, max_bytes):
        # `repro` is what gets persisted; `stdin_payload` is what the target reads. argv
        # mode used to blank the payload it had just moved into argv, so every repro
        # written after the first argv case was zero bytes.
        repro = payload
        delivery = "stdin"
        stdin_payload = payload
        argv_extra = None
        if mode == "argv":
            try:
                argv_extra = [payload.decode("utf-8", "replace")]
            except Exception:
                argv_extra = ["<undecodable>"]
            stdin_payload = b""
            delivery = "argv"
        out, err, rc, status = r.invoke(stdin_payload, argv_extra)

        case = f"structural/{name}"
        if status == "timeout":
            ref = persist(r, case, repro, delivery)
            findings.append(Finding("HANG", case, f"no exit within {r.timeout}s ({note})", ref))
            continue
        if status == "signal":
            ref = persist(r, case, repro, delivery)
            findings.append(Finding("CRASH", case, f"killed by signal {-rc} ({note})", ref))
            continue
        if status == "oserror":
            findings.append(Finding("INVALID", case, f"could not execute: {err.decode(errors='replace')[:200]}"))
            continue
        if status == "undeliverable":
            # execve refused the argv before the target saw it, so the boundary is
            # UNTESTED rather than clean. Falling through to the expect checks would
            # score a vector the target never received as a pass.
            findings.append(Finding(
                "INVALID", case,
                "the OS refused to deliver this vector "
                f"({err.decode(errors='replace')[:120]}); the target never received it, "
                "so this boundary is UNTESTED"))
            continue

        # A Python traceback on stderr is a crash even when the exit code lies.
        stderr_txt = err.decode("utf-8", "replace")
        if "Traceback (most recent call last)" in stderr_txt:
            ref = persist(r, case, repro, delivery)
            findings.append(Finding("CRASH", case, f"unhandled exception ({note})", ref))
            continue

        if mode != "json":
            continue

        # JSON mode: empty output means "no opinion", which is legal. Any
        # non-empty output MUST parse, or the caller's verdict is undefined.
        body = out.strip()
        if not body:
            continue
        try:
            json.loads(body)
        except json.JSONDecodeError as e:
            ref = persist(r, case, repro, delivery)
            findings.append(
                Finding("UNPARSABLE", case,
                        f"non-JSON stdout on a JSON-contract target ({e.msg}) ({note})", ref))


EXPECT_VERDICTS = ("deny", "allow", "ask", "no-crash", "nonzero-exit", "zero-exit")


def validate_vectors(vectors: list[dict]) -> list[str]:
    """Reject a vectors file before running it. Returns human-readable problems.

    `expect` used to default to `no-crash` and `why` to `""`, so a misspelled or missing
    key silently downgraded the vector to the WEAKEST assertion in the set: the vector
    still ran, still passed, and still counted. A bypass vector that quietly becomes a
    did-not-crash vector is a false clean, so an unusable vector is a loud refusal.
    """
    problems: list[str] = []
    for i, vec in enumerate(vectors):
        # Shape first: a string element used to crash this loop on `vec.get`, so the
        # harness died with a traceback instead of naming the unusable vector.
        if not isinstance(vec, dict):
            problems.append(f"vector[{i}]: not an object (got {type(vec).__name__})")
            continue
        where = f"vector[{i}]" + (f" ({vec.get('name')})" if vec.get("name") else "")
        expect = vec.get("expect")
        if expect is None:
            problems.append(
                f"{where}: no `expect`. It is required: an absent expectation used to "
                f"default to `no-crash`, the weakest verdict, so the vector passed "
                f"without asserting what it was written to assert. One of {EXPECT_VERDICTS}."
            )
        elif str(expect).strip().lower() not in EXPECT_VERDICTS:
            problems.append(
                f"{where}: expect={expect!r} is not one of {EXPECT_VERDICTS}. A "
                f"misspelling used to fall through to `no-crash`."
            )
        if not str(vec.get("why") or "").strip():
            problems.append(
                f"{where}: no `why`. The finding detail is rendered from it, so a "
                f"failure without one cannot be triaged."
            )
        unknown = set(vec) - {"name", "expect", "why", "payload"}
        if unknown:
            problems.append(f"{where}: unknown key(s) {sorted(unknown)}")
    return problems


def check_vectors(r: Runner, findings: list[Finding], vectors: list[dict], mode: str) -> None:
    for i, vec in enumerate(vectors):
        name = vec.get("name") or f"vector-{i}"
        expect = str(vec["expect"]).strip().lower()
        why = vec["why"]
        raw = vec.get("payload")
        if isinstance(raw, (dict, list)):
            payload = json.dumps(raw).encode()
        elif isinstance(raw, str):
            payload = raw.encode()
        elif raw is None:
            payload = b""
        else:
            payload = str(raw).encode()

        # The payload to PERSIST is kept separate from the payload to send on stdin.
        # argv mode used to blank `payload` after moving it into argv, so every
        # save_input() below wrote a zero-byte repro for the rest of the run.
        repro = payload
        delivery = "stdin"
        argv_extra = None
        stdin_payload = payload
        if mode == "argv":
            argv_extra = [payload.decode("utf-8", "replace")]
            stdin_payload = b""
            delivery = "argv"

        out, err, rc, status = r.invoke(stdin_payload, argv_extra)
        case = f"vector/{name}"

        if status == "timeout":
            ref = persist(r, case, repro, delivery)
            findings.append(Finding("HANG", case, f"no exit within {r.timeout}s", ref))
            continue
        if status == "signal":
            ref = persist(r, case, repro, delivery)
            findings.append(Finding("CRASH", case, f"killed by signal {-rc}", ref))
            continue
        if status == "oserror":
            findings.append(Finding("INVALID", case, "could not execute target"))
            continue
        if status == "undeliverable":
            # execve refused the argv before the target saw it, so the boundary is
            # UNTESTED rather than clean. Falling through to the expect checks would
            # score a vector the target never received as a pass.
            findings.append(Finding(
                "INVALID", case,
                "the OS refused to deliver this vector "
                f"({err.decode(errors='replace')[:120]}); the target never received it, "
                "so this boundary is UNTESTED"))
            continue

        if expect == "no-crash":
            continue
        if expect == "nonzero-exit":
            if rc == 0:
                ref = persist(r, case, repro, delivery)
                findings.append(Finding("CONTRACT", case, f"expected nonzero exit, got 0. {why}", ref))
            continue
        if expect == "zero-exit":
            if rc != 0:
                ref = persist(r, case, repro, delivery)
                findings.append(Finding("CONTRACT", case, f"expected exit 0, got {rc}. {why}", ref))
            continue

        # Decision expectations (deny / allow / ask), read the way the hook contract reads
        # them: the exit code first, then stdout.
        body = out.strip()
        parsed = None
        if body:
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                if rc == 0:
                    ref = persist(r, case, repro, delivery)
                    findings.append(Finding("UNPARSABLE", case,
                                            "expected a decision but stdout is not JSON", ref))
                    continue
        if rc == HOOK_BLOCK_RC:
            effective, basis = "deny", f"exit {HOOK_BLOCK_RC} blocks whatever stdout says"
        elif (got := extract_decision(parsed)) is not None:
            effective, basis = got, f"stdout decision, exit {rc}"
        elif rc == 0:
            # No decision emitted means the guard did not object, i.e. allow.
            effective, basis = "allow", "exit 0 with no decision"
        else:
            # Any other status without a decision is a non-blocking error: the hook
            # failed and the call proceeds, which is an allow and a fail-open guard.
            effective, basis = "allow", f"exit {rc} with no decision is a non-blocking error"
        if effective != expect:
            kind = "BYPASS" if expect == "deny" and effective in ("allow", "ask") else "CONTRACT"
            ref = persist(r, case, repro, delivery)
            findings.append(
                Finding(kind, case,
                        f"expected {expect}, got {effective} ({basis}). {why}".strip(), ref))
        if effective == "ask":
            findings.append(
                Finding("STALL", case,
                        "emitted 'ask', which blocks an autonomous agent; guards must "
                        "deny or allow"))


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


VECTORS_SCHEMA = """\
--vectors FILE : a JSON list of attack vectors, one object each. The `sabot-fuzzer`
agent writes this; `gremlin` runs it.

[
  {
    "name":    "env-wrapper bypass",         # required, unique label
    "payload": {"tool_name":"Bash",          # required. dict/list -> sent as JSON;
                "tool_input":{"command":"env rm -rf /"}},   # string -> sent raw
    "expect":  "deny",                       # required, one of the verdicts below
    "why":     "a wrapper prefix must not move the command out of guard position"
  }
]

expect verdicts:
  deny         the target must emit a deny decision (else BYPASS if it allows)
  allow        the target must allow (a benign vector; catches over-blocking)
  ask          the target emits ask  (flagged STALL: blocks an autonomous agent)
  no-crash     any defined result is fine; only crash/hang is a finding
  nonzero-exit the target must exit non-zero
  zero-exit    the target must exit 0

For --mode json, deny/allow/ask follow the hook contract (Claude Code, Codex):
  exit 2                 deny, whatever stdout says (the reason goes to stderr)
  a JSON object          its hookSpecificOutput.permissionDecision, or top-level
                         permissionDecision/decision; legacy block/approve = deny/allow
  no decision            allow (silence is not a block), including a nonzero exit,
                         which the contract treats as a non-blocking error

payload delivery by --mode:
  json  payload sent on stdin as JSON (the default hook contract)
  text  payload sent on stdin as raw bytes
  argv  payload passed as a single argv element instead of stdin
"""


def main(argv: list[str]) -> int:
    # Short-circuit before argparse, so it runs without the required --target.
    if "--vectors-help" in argv:
        print(VECTORS_SCHEMA)
        return 0
    ap = argparse.ArgumentParser(
        prog="fuzz-cli.py",
        description="Adversarial harness for a CLI, hook, or JSON-stdin program.",
    )
    ap.add_argument("--target", required=True,
                    help="path to the program, or a full command in quotes")
    ap.add_argument("--mode", choices=("json", "text", "argv"), default="json")
    ap.add_argument("--vectors", help="JSON file of attack vectors with expected verdicts")
    ap.add_argument("--timeout", type=int, default=10, help="per-invocation seconds (default 10)")
    ap.add_argument("--mem-mb", type=int, default=2048,
                    help="child address-space cap in MB, 0 disables (default 2048)")
    ap.add_argument("--max-bytes", type=int, default=1_000_000,
                    help="cap on generated payload size (default 1000000)")
    ap.add_argument("--artifacts-dir", default="",
                    help="where reproducing inputs are written (default: a temp dir)")
    ap.add_argument("--env", action="append", default=[], metavar="K=V",
                    help="extra environment variable for the target, repeatable")
    ap.add_argument("--skip-structural", action="store_true",
                    help="run only the vectors file")
    ap.add_argument("--json-report", action="store_true",
                    help="emit findings as JSON instead of text")
    ap.add_argument("--vectors-help", action="store_true",
                    help="print the --vectors file schema and exit")
    args = ap.parse_args(argv)

    target_cmd = args.target.split() if " " in args.target else [args.target]
    exe = target_cmd[0]
    if not (Path(exe).is_file() or shutil.which(exe)):
        print(f"fuzz-cli: target not found: {exe}", file=sys.stderr)
        return 2
    if Path(exe).is_file() and not os.access(exe, os.X_OK):
        # Not executable: run it through its interpreter when we can infer one.
        if exe.endswith(".py"):
            target_cmd = [sys.executable] + target_cmd
        elif exe.endswith((".sh", ".bash")):
            target_cmd = ["bash"] + target_cmd
        else:
            print(f"fuzz-cli: target is not executable: {exe}", file=sys.stderr)
            return 2

    env_extra: dict[str, str] = {}
    for pair in args.env:
        if "=" not in pair:
            print(f"fuzz-cli: --env needs K=V, got: {pair}", file=sys.stderr)
            return 2
        k, v = pair.split("=", 1)
        env_extra[k] = v

    artifacts = Path(args.artifacts_dir) if args.artifacts_dir else Path(
        tempfile.mkdtemp(prefix="sabot-"))

    vectors: list[dict] = []
    if args.vectors:
        try:
            vectors = json.loads(Path(args.vectors).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"fuzz-cli: cannot read vectors file: {e}", file=sys.stderr)
            return 2
        if not isinstance(vectors, list):
            print("fuzz-cli: vectors file must be a JSON list", file=sys.stderr)
            return 2
        problems = validate_vectors(vectors)
        if problems:
            for problem in problems:
                print(f"fuzz-cli: {problem}", file=sys.stderr)
            print(
                "fuzz-cli: refusing to run an unusable vectors file. A vector missing "
                "`expect` used to run as `no-crash` and pass, so the bypass it was "
                "written to prove read as a clean result.",
                file=sys.stderr,
            )
            return 2

    r = Runner(target_cmd, args.mode, args.timeout, args.mem_mb, artifacts, env_extra)
    findings: list[Finding] = []

    if not args.skip_structural:
        check_structural(r, findings, args.mode, args.max_bytes)
    if vectors:
        check_vectors(r, findings, vectors, args.mode)

    if args.json_report:
        print(json.dumps({
            "target": " ".join(target_cmd),
            "mode": args.mode,
            "runs": r.runs,
            "artifacts_dir": str(artifacts.resolve()),
            "findings": [
                {"kind": f.kind, "case": f.case, "detail": f.detail, "input": f.input_ref}
                for f in findings
            ],
        }, indent=2))
    else:
        print(f"fuzz-cli: {' '.join(target_cmd)} [mode={args.mode}] "
              f"{r.runs} invocations, {len(findings)} findings")
        if not vectors and not args.skip_structural:
            print("  note: no --vectors file, so only structural invariants were checked; "
                  "bypass detection needs vectors with expected verdicts")
        for f in findings:
            print(f"  {f}")
        if findings:
            print(f"  reproducing inputs: {artifacts.resolve()}")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
