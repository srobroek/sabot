#!/bin/sh
# assert-executed.sh -- prove a tool is the real tool and that it did positive work.
#
# Runs INSIDE the container, as the command after `run-contained.sh -- `. POSIX sh, no
# bashisms, so it works in any sabot image.
#
#   assert-executed.sh --tool cargo [--tool go] [--min-units 1] [--out FILE] -- <command...>
#   assert-executed.sh --tool cargo --check-only          (identity, run nothing)
#   assert-executed.sh --parse FILE [--min-units 1]       (assert over a captured log)
#
# WHY THIS EXISTS. A host hook was measured rewriting `cargo` to `rtk` inside the
# container. The result was rc=0 with 0 tests selected across 11 targets: exit zero, no
# error, no tests, and a report byte-identical to a clean pass. rc=0 is not evidence
# anything ran.
#
# Two independent assertions, and both must hold:
#   IDENTITY  -- `command -v <tool>` resolves, and the first line of `<tool> --version`
#     names the tool. A substituted binary answers with its own name, which is what makes
#     the rewrite visible. `go --version` exits 2, so `<tool> version` is tried too.
#   POSITIVE WORK -- the output reports a non-zero count of tests that FINISHED and at
#     least one named unit. `running 0 tests`, `0 tests selected`, and an empty selection
#     are failures, not clean results. A collected, skipped, or deselected test is not
#     work.
#
# The command's output is written to a FILE and its status read from `$?`. It is never
# piped into `tee`: a pipeline reports the status of its LAST stage, so `cmd | tee log`
# discards the failure entirely -- one of the measured false cleans.
#
# EXIT CODES. 0 the tool is real and did work; 2 usage error (never 0: a wrapper that
# exits 0 on its own usage error, having run nothing, is the fail-open this whole script
# guards); 6 tool identity failed; 7 the command's own non-zero status; 8 rc=0 but no
# positive work.

set -u

EXIT_USAGE=2
EXIT_IDENTITY=6
EXIT_CMD=7
EXIT_NO_WORK=8

TOOLS=""
MIN_UNITS=1
OUT=""
PARSE=""
CHECK_ONLY=0
CMD_GIVEN=0

die_usage() {
  echo "assert-executed: $1" >&2
  echo "usage: assert-executed.sh --tool NAME [--tool NAME] [--min-units N] [--out FILE] -- <command...>" >&2
  echo "       assert-executed.sh --tool NAME --check-only" >&2
  echo "       assert-executed.sh --parse FILE [--min-units N]" >&2
  exit "$EXIT_USAGE"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --tool)       [ "$#" -ge 2 ] || die_usage "--tool needs a name"; TOOLS="$TOOLS $2"; shift 2 ;;
    --min-units)  [ "$#" -ge 2 ] || die_usage "--min-units needs a number"; MIN_UNITS="$2"; shift 2 ;;
    --out)        [ "$#" -ge 2 ] || die_usage "--out needs a path"; OUT="$2"; shift 2 ;;
    --parse)      [ "$#" -ge 2 ] || die_usage "--parse needs a path"; PARSE="$2"; shift 2 ;;
    --check-only) CHECK_ONLY=1; shift ;;
    -h|--help)    die_usage "help requested" ;;
    --)           shift; CMD_GIVEN=1; break ;;
    *)            die_usage "unknown argument: $1" ;;
  esac
done

case "$MIN_UNITS" in
  ''|*[!0-9]*) die_usage "--min-units takes a whole number, got '$MIN_UNITS'" ;;
esac

if [ -n "$PARSE" ]; then
  [ "$CMD_GIVEN" -eq 0 ] || die_usage "--parse and a command are mutually exclusive"
  [ -f "$PARSE" ] || die_usage "--parse: no such file: $PARSE"
elif [ "$CHECK_ONLY" -eq 1 ]; then
  [ "$CMD_GIVEN" -eq 0 ] || die_usage "--check-only takes no command"
  [ -n "$TOOLS" ] || die_usage "--check-only needs at least one --tool"
else
  [ "$CMD_GIVEN" -eq 1 ] || die_usage "a command after -- is required"
  [ "$#" -gt 0 ] || die_usage "a command after -- is required"
fi

# IDENTITY. A resolved path alone is not enough -- the rewrite that caused the incident
# resolved fine. The version string has to name the tool.
for t in $TOOLS; do
  case "$t" in
    *[!A-Za-z0-9._-]*|"") echo "assert-executed: illegal tool name: '$t'" >&2; exit "$EXIT_USAGE" ;;
  esac
  p="$(command -v "$t" 2>/dev/null || true)"
  if [ -z "$p" ]; then
    echo "assert-executed: IDENTITY FAIL: '$t' does not resolve inside the container" >&2
    exit "$EXIT_IDENTITY"
  fi
  v="$("$t" --version 2>/dev/null | head -1)"
  [ -n "$v" ] || v="$("$t" version 2>/dev/null | head -1)"
  if [ -z "$v" ]; then
    echo "assert-executed: IDENTITY FAIL: '$t' ($p) answered neither --version nor version" >&2
    exit "$EXIT_IDENTITY"
  fi
  if ! printf '%s' "$v" | grep -qi "$t"; then
    echo "assert-executed: IDENTITY FAIL: '$t' resolves to $p but reports itself as '$v'." >&2
    echo "assert-executed: a host hook rewriting a toolchain name inside the container produced rc=0 with 0 tests. Treat this run as INVALID." >&2
    exit "$EXIT_IDENTITY"
  fi
  echo "assert-executed: IDENTITY ok $t -> $p ($v)" >&2
done

[ "$CHECK_ONLY" -eq 1 ] && exit 0

# Run the command, keeping its status. No pipe: `cmd | tee` would hand back tee's status.
if [ -n "$PARSE" ]; then
  LOG="$PARSE"
  RC=0
else
  LOG="${OUT:-${TMPDIR:-/tmp}/assert-executed.$$.log}"
  "$@" > "$LOG" 2>&1
  RC=$?
  cat "$LOG"
fi

# POSITIVE WORK. A unit is a test that finished -- passed or failed. Skipped, ignored,
# deselected, and merely collected tests are not work. Each runner's tests are counted from
# ONE source, so a test that prints both a start line and a result line counts once:
#   rust    per target (`running N tests` opens one): its `test result: ... N passed;
#           M failed` summary, else its `test x ... ok|FAILED` lines
#   nextest `Summary [...] N tests run`
#   go      `--- PASS:` / `--- FAIL:` result lines, subtests included. `=== RUN` is a start.
#           Without -v, a passing package prints only `ok <pkg> <time>s`, counted as one
#           unit per package; `[no tests to run]` and a `(cached)` result are not work.
#   pytest  the closing `N passed, M failed ... in Xs` summary, else the per-test results:
#           `file::test PASSED` (-v) or the `file.py ..F.` progress characters (default)
# A runner that started tests and died before reporting any result (`running N tests` or
# `=== RUN` with no result line after it) counts what it started. That is work followed by
# a failure, for classify-failure.py, not a run that never happened.
UNITS="$(awk '
  function executed(  i, w, n) {
    n = 0
    for (i = 1; i < NF; i++) if ($i ~ /^[0-9]+$/) {
      w = $(i + 1); gsub(/[^a-z]/, "", w)
      if (w == "passed" || w == "failed" || w == "xfailed" || w == "xpassed") n += $i
    }
    return n
  }
  function flush_rust() {
    if (rb) rust += (rsum_seen ? rsum : (rev > 0 ? rev : rban))
    rb = 0; rsum_seen = 0; rsum = 0; rev = 0; rban = 0
  }
  /^running [0-9]+ tests?/          { flush_rust(); rb = 1; rban = $2; next }
  /^test result: /                  { rb = 1; rsum_seen = 1; rsum = executed(); next }
  /^test .* \.\.\. (ok|FAILED)/     { rb = 1; rev++; next }
  /[0-9]+ tests? run/               { for (i = 1; i < NF; i++) if ($i ~ /^[0-9]+$/ && $(i+1) ~ /^tests?$/) nextest += $i; next }
  /^ *--- (PASS|FAIL):/             { gdone++; next }
  /^ *--- SKIP:/                    { gskip++; next }
  /^=== RUN /                       { grun++; next }
  /^ok[ \t]+[^ \t]+[ \t]+[0-9.]+s/ && !/no tests to run/ { gok++; next }
  /^(=+ )?(no tests ran|[0-9]+ [a-z]+(, [0-9]+ [a-z]+)*) in [0-9.]+s/ { psum_seen = 1; psum += executed(); next }
  /^[^ ]+::[^ ]+ (PASSED|FAILED|XFAIL|XPASS)/ { pev++; next }
  /^[A-Za-z0-9_.\/-]+\.py [.FEsxX]+/ { prog = $2; pev += gsub(/[.FxX]/, "", prog); next }
  END {
    flush_rust()
    go = (gdone + gskip > 0) ? gdone : (grun > 0 ? grun : gok)
    py = psum_seen ? psum : pev
    print rust + nextest + go + py
  }
' "$LOG" 2>/dev/null)"
[ -n "$UNITS" ] || UNITS=0

NAMED="$(grep -cE '^(test [A-Za-z0-9_:]+ \.\.\.|--- (PASS|FAIL): |=== RUN |ok[[:space:]]+[^[:space:]]+[[:space:]]+[0-9.]+s|[A-Za-z0-9_./-]+::[A-Za-z0-9_]+ |[A-Za-z0-9_./-]+\.py [.FEsxX]+)' "$LOG" 2>/dev/null || true)"
[ -n "$NAMED" ] || NAMED=0

ZERO_SELECTED=0
if grep -qE '0 tests? selected|no test (targets?|to run)|running 0 tests' "$LOG" 2>/dev/null; then
  ZERO_SELECTED=1
fi

echo "assert-executed: units=$UNITS named=$NAMED zero_selected=$ZERO_SELECTED rc=$RC min_units=$MIN_UNITS" >&2

if [ "$UNITS" -lt "$MIN_UNITS" ] || [ "$NAMED" -lt 1 ] || { [ "$ZERO_SELECTED" -eq 1 ] && [ "$UNITS" -lt "$MIN_UNITS" ]; }; then
  echo "assert-executed: NO POSITIVE WORK: $UNITS unit(s), $NAMED named, below --min-units $MIN_UNITS." >&2
  echo "assert-executed: rc=$RC is NOT evidence anything ran. Record this run as NOT EXECUTED, never as 0 findings." >&2
  exit "$EXIT_NO_WORK"
fi

if [ "$RC" -ne 0 ]; then
  echo "assert-executed: the command did positive work ($UNITS units) and then failed rc=$RC; classify it with classify-failure.py before calling it a target defect" >&2
  exit "$EXIT_CMD"
fi

echo "assert-executed: EXECUTED units=$UNITS named=$NAMED" >&2
exit 0
