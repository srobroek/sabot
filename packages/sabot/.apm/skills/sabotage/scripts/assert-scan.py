#!/usr/bin/env python3
"""Run a scanner and prove it actually scanned. Wraps any tool that writes an output file.

    assert-scan.py --output FILE [--tool NAME] [--min-files 1] [--format json|sarif|text]
                   [--allow-empty-findings] [--json] -- <command...>
    assert-scan.py --output FILE --verify-only [--min-files 1]

WHY THIS EXISTS. Two unrelated tools produced the IDENTICAL false clean, which makes
this a design gap rather than two bugs:

  - opengrep exited 2 having scanned 0 files (a non-ASCII character in the rule file
    under the default locale), and the PREVIOUS run's JSON was still on disk. The
    reader parsed a stale file and recorded a clean scan.
  - a spurious rc=8 iteration BLANKED an ast-grep JSON output to 0 bytes, which read as
    0 findings for its key injection rule. Re-run with the output deleted and confirmed
    absent, the same rule produced 1 hit with its control firing.

So the guarantee belongs to whatever wraps a scanner invocation, not to any one tool:

  1. DELETE the output path before the run, and CONFIRM it is absent. A result that
     predates the run cannot be evidence of the run.
  2. After the run require the file to EXIST, be NON-EMPTY, and PARSE.
  3. Require a NONZERO count of files actually scanned, from evidence the tool gives:
     its own scanned-file list or count, bandit's per-file `metrics`, or the files its
     findings name. Zero files scanned is NOT EXECUTED regardless of the exit code. An
     `errors` entry is not coverage: a file the tool failed on is a file it did not scan.

Any of those failing is NOT EXECUTED, with the reason recorded. It is never zero
findings and never a retry. "Zero findings" and "the scanner did not run" are the same
bytes on disk unless something asserts the difference.

A scanner legitimately reporting no findings over a nonzero file count is a PASS: the
assertion is about coverage, not about finding something.

Some formats carry no coverage field at all: shellcheck's and ast-grep's clean `[]`, or
a trivy report with no `Results`. That is coverage UNREPORTED, not zero files, and it
used to score 0 and fail every clean scan from those tools. At rc=0, from a report this
run wrote fresh and that parses, it passes with `coverage_reported: false`, and the
caller records the coverage as unreported rather than as a file count. At a nonzero rc,
when the report lists only errors, or under an explicit `--min-files` above 1, nothing
shows the tool scanned anything, so it is NOT EXECUTED.

EXIT CODES. 0 the scan ran and its output is trustworthy; 2 usage (never 0: a wrapper
that exits 0 on its own usage error, having run nothing, is this same fail-open);
7 the scanner ran and did positive work but exited non-zero (classify it with
classify-failure.py before calling it a target defect); 11 NOT EXECUTED.

Stdlib only. Starts no container.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

EXIT_USAGE = 2
EXIT_TOOL_FAILED = 7
EXIT_NOT_EXECUTED = 11

# The locale the check assumes, and the one the runtime must use. A single curly quote
# in a generated rule file killed opengrep outright under the default locale.
LOCALE_ENV = {"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "PYTHONUTF8": "1"}

_FILE_FIELDS = ("path", "file", "filename", "Target", "uri", "absolute_path")

# Report sections that name files the tool did NOT scan: one it failed to parse, or one
# it skipped. Counted as coverage, an errors-only report certified a scan of the very
# files the scanner could not read.
_NOT_COVERAGE_KEYS = ("errors", "skipped")


def _distinct_files(node, seen: set[str], depth: int = 0) -> None:
    """Collect distinct file-ish strings anywhere in a parsed report.

    Deliberately structural rather than per-tool: a new scanner should be usable here
    without a schema entry, because a tool nobody taught this script about must not
    silently score zero and read as NOT EXECUTED when it did run.
    """
    if depth > 12:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _NOT_COVERAGE_KEYS:
                continue
            if key in _FILE_FIELDS and isinstance(value, str) and value:
                seen.add(value)
            elif key == "artifactLocation" and isinstance(value, dict):
                uri = value.get("uri")
                if isinstance(uri, str) and uri:
                    seen.add(uri)
            else:
                _distinct_files(value, seen, depth + 1)
    elif isinstance(node, list):
        for item in node:
            _distinct_files(item, seen, depth + 1)


def scanned_count(doc) -> tuple[int | None, str]:
    """(files scanned, where the count came from), or None when the report holds no count.

    Prefers a count the tool states. Next, bandit's `metrics` holds one entry per file it
    scanned, clean or not. Last, a file that a finding or a scanned target names is a lower
    bound: the tool read it to report on it. A clean report in a format with no coverage
    field has nothing to count, which is UNREPORTED, not zero.
    """
    if isinstance(doc, dict):
        paths = doc.get("paths")
        if isinstance(paths, dict) and isinstance(paths.get("scanned"), list):
            return len(paths["scanned"]), "paths.scanned"
        for key in ("scanned_files", "files_scanned", "filesScanned"):
            value = doc.get(key)
            if isinstance(value, int):
                return value, key
            if isinstance(value, list):
                return len(value), key
        metrics = doc.get("metrics")
        if isinstance(metrics, dict) and "_totals" in metrics:
            return (sum(1 for key in metrics if key != "_totals"),
                    "metrics (bandit: one entry per scanned file)")
    seen: set[str] = set()
    _distinct_files(doc, seen)
    if seen:
        return len(seen), "distinct files named by findings or scanned targets"
    return None, "the report carries no file count and names no scanned file"


def error_count(doc) -> int:
    """Entries in a report's `errors` list: files or rules the tool failed on."""
    if isinstance(doc, dict) and isinstance(doc.get("errors"), list):
        return len(doc["errors"])
    return 0


def partial_parse_files(doc) -> set[str]:
    """Files a semgrep/opengrep run only PARTLY parsed, which `paths.scanned` still counts.

    Measured on this package: opengrep exited 0 having "scanned" run-contained.sh, while
    a JSON `errors` entry recorded PartialParsing over 3 of its 500 lines -- the
    `${2:?message}` form. None of the 301 rules ever reached those lines, so a region of
    a script that governs every contained run was unmeasured and read as clean. A file
    count cannot see this: the file was opened, so it counts as scanned.
    """
    out: set[str] = set()
    if not isinstance(doc, dict):
        return out
    for err in doc.get("errors") or []:
        if not isinstance(err, dict):
            continue
        kind = err.get("type")
        # opengrep nests the locations under the type: ["PartialParsing", [ {path..}, ]]
        if isinstance(kind, list) and kind and kind[0] == "PartialParsing":
            for loc in kind[1] if len(kind) > 1 and isinstance(kind[1], list) else []:
                if isinstance(loc, dict) and loc.get("path"):
                    out.add(str(loc["path"]))
        elif isinstance(kind, str) and "PartialParsing" in kind and err.get("path"):
            out.add(str(err["path"]))
    return out


def findings_count(doc) -> int | None:
    if isinstance(doc, dict):
        for key in ("results", "findings", "Results", "vulnerabilities"):
            value = doc.get(key)
            if isinstance(value, list):
                return len(value)
        runs = doc.get("runs")
        if isinstance(runs, list):
            return sum(
                len(run.get("results", [])) for run in runs if isinstance(run, dict)
            )
    if isinstance(doc, list):
        return len(doc)
    return None


def clear_output(path: Path) -> str | None:
    """Delete the output path and confirm it is gone. Returns a reason on failure."""
    try:
        if path.is_dir():
            return (
                f"{path} is a directory; --output must be the scanner's output FILE so "
                "it can be deleted and its absence confirmed before the run"
            )
        path.unlink(missing_ok=True)
    except OSError as exc:
        return f"could not remove the previous output {path}: {exc}"
    if path.exists():
        return (
            f"{path} still exists after deletion, so a result predating this run could "
            "be read as this run's result"
        )
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="assert-scan.py", add_help=True)
    ap.add_argument("--output", required=True, help="the file the scanner writes")
    ap.add_argument("--tool", default="", help="name, for the messages only")
    ap.add_argument("--min-files", type=int, default=1,
                    help="fewest files the scanner must report having scanned")
    ap.add_argument("--format", choices=("json", "sarif", "text"), default="json")
    ap.add_argument("--allow-empty-findings", action="store_true",
                    help="accepted by default; kept so a caller can be explicit")
    ap.add_argument("--verify-only", action="store_true",
                    help="assert over an output file this script did not produce")
    ap.add_argument("--json", dest="as_json", action="store_true")
    ap.add_argument("command", nargs=argparse.REMAINDER)
    args = ap.parse_args(argv)

    cmd = [a for a in args.command if a != "--"] if args.command else []
    if args.command and args.command[0] == "--":
        cmd = args.command[1:]
    if args.verify_only and cmd:
        ap.error("--verify-only takes no command")
    if not args.verify_only and not cmd:
        ap.error("a command after -- is required")
    if args.min_files < 1:
        ap.error("--min-files must be at least 1: zero files scanned is NOT EXECUTED, "
                 "so a threshold of zero disables the only check that matters here")

    output = Path(args.output).expanduser()
    tool = args.tool or (cmd[0] if cmd else "the scanner")
    report: dict = {
        "schema": "sabot-scan-assertion/1",
        "tool": tool,
        "output": str(output),
        "locale_env": LOCALE_ENV,
        "checks": [],
    }

    def note(name: str, ok: bool, detail: str) -> bool:
        report["checks"].append({"name": name, "ok": ok, "detail": detail})
        return ok

    rc = 0
    if not args.verify_only:
        output.parent.mkdir(parents=True, exist_ok=True)
        problem = clear_output(output)
        if not note("output_cleared_before_run", problem is None,
                    problem or f"{output} absent before the run"):
            return _finish(report, EXIT_NOT_EXECUTED, args.as_json,
                           "the previous output could not be cleared, so a stale result "
                           "could be read as this run's")

        env = {**os.environ, **LOCALE_ENV}
        try:
            proc = subprocess.run(cmd, env=env)
            rc = proc.returncode
        except OSError as exc:
            note("scanner_invoked", False, f"could not execute {cmd[0]}: {exc}")
            return _finish(report, EXIT_NOT_EXECUTED, args.as_json,
                           f"{tool} did not execute")
        note("scanner_invoked", True, f"rc={rc}")
    report["rc"] = rc

    if not note("output_exists", output.is_file(),
                f"{output} exists" if output.is_file()
                else f"{output} was not written, so there is no result to read"):
        return _finish(report, EXIT_NOT_EXECUTED, args.as_json,
                       f"{tool} wrote no output")

    size = output.stat().st_size
    if not note("output_non_empty", size > 0, f"{size} byte(s)"):
        return _finish(report, EXIT_NOT_EXECUTED, args.as_json,
                       f"{tool} left a zero-byte output; a blanked report reads as zero "
                       "findings")

    doc = None
    if args.format == "text":
        note("output_parses", True, "text format: parsing not applicable")
    else:
        try:
            doc = json.loads(output.read_text(errors="replace"))
            note("output_parses", True, f"{args.format} parsed")
        except ValueError as exc:
            note("output_parses", False, f"{args.format} did not parse: {exc}")
            return _finish(report, EXIT_NOT_EXECUTED, args.as_json,
                           f"{tool} wrote an unparseable report")

    if doc is None:
        lines = sum(1 for _ in output.read_text(errors="replace").splitlines() if _.strip())
        files, how = lines, "non-blank lines (text format has no file count)"
    else:
        files, how = scanned_count(doc)
    report["files_scanned"] = files
    report["files_scanned_source"] = how
    report["findings"] = findings_count(doc) if doc is not None else None
    report["coverage_reported"] = files is not None

    if files is None:
        note("coverage_reported", False, f"{how}, which a clean report in a format with "
             "no coverage field also looks like")
        errors = error_count(doc)
        refusal = None
        if errors:
            refusal = (f"{tool}'s report lists {errors} error(s) and names no scanned file. "
                       "An error is a file the tool failed on, not coverage, so an "
                       "errors-only report is not evidence of a scan.")
        elif rc != 0:
            refusal = (f"{tool} exited {rc} and its report carries neither a file count "
                       "nor a finding, so nothing shows it scanned anything.")
        elif args.min_files > 1:
            refusal = (f"--min-files {args.min_files} needs a file count, and {tool}'s "
                       "report format carries none.")
        if refusal:
            return _finish(report, EXIT_NOT_EXECUTED, args.as_json,
                           refusal + " Record it as NOT EXECUTED with that reason.")
    elif not note("nonzero_files_scanned", files >= args.min_files,
                  f"{files} file(s) via {how}, threshold {args.min_files}"):
        return _finish(
            report, EXIT_NOT_EXECUTED, args.as_json,
            f"{tool} reports {files} file(s) scanned. Record this as NOT EXECUTED with "
            "that reason. Zero files scanned and zero findings are the same bytes on "
            "disk; do not report it as a clean scan, and do not retry it as though it "
            "were transient.",
        )

    unparsed = partial_parse_files(doc)
    report["partial_parse_files"] = sorted(unparsed)
    note("fully_parsed", not unparsed,
         "no PartialParsing" if not unparsed
         else f"{len(unparsed)} file(s) only partly parsed: {sorted(unparsed)[:5]}")

    if rc != 0:
        return _finish(
            report, EXIT_TOOL_FAILED, args.as_json,
            f"{tool} scanned {files} file(s) and then exited {rc}; classify it with "
            "classify-failure.py before calling it a target defect",
        )
    if files is None:
        return _finish(report, 0, args.as_json,
                       f"{tool} exited 0 with a fresh, parseable, clean report whose format "
                       "names no scanned file. Record its coverage as UNREPORTED, not as a "
                       "file count.")
    return _finish(report, 0, args.as_json,
                   f"{tool} scanned {files} file(s); "
                   f"{report['findings']} finding(s) recorded"
                   if report["findings"] is not None
                   else f"{tool} scanned {files} file(s)")


def _finish(report: dict, code: int, as_json: bool, message: str) -> int:
    report["ok"] = code == 0
    report["verdict"] = {
        0: "executed",
        EXIT_TOOL_FAILED: "executed-then-failed",
        EXIT_NOT_EXECUTED: "not-executed",
    }.get(code, "usage")
    report["message"] = message
    if as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for check in report["checks"]:
            print(f"[{'ok ' if check['ok'] else 'FAIL'}] {check['name']}: {check['detail']}")
        stream = sys.stdout if code == 0 else sys.stderr
        prefix = "assert-scan: " if code == 0 else "assert-scan: NOT EXECUTED: " \
            if code == EXIT_NOT_EXECUTED else "assert-scan: "
        print(prefix + message, file=stream)
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit as exc:
        # argparse exits 2 on a usage error, which is what this script requires: a
        # wrapper exiting 0 on its own usage error is the fail-open it guards against.
        raise exc
