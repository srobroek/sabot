# Surface: Shell scripts and hooks

Shell is the highest-yield surface in an agentic repo. A PreToolUse guard is
security-critical code: it runs on every tool call, parsing attacker-influenced
JSON to decide whether a command executes. Every bypass found in this repo's
own guards came from command-position anchoring, quoting, or fail-open inversion.

## Detect

`*.sh`, `*.bash`, `*.zsh`, files whose shebang matches `#!/.*\b(ba|z|k)?sh\b`,
`.claude/hooks/**`, `.codex/hooks/**`, `.git/hooks/**`, OMP extensions (`*.ts` under
`.omp/extensions/` or a plugin's `extensions/`) that register a `pi.on("tool_call", …)`
gate, `.pre-commit-config.yaml` entries with inline shell, `run:` blocks in CI
workflows, and any Python or Node script that shells out through `subprocess`,
`os.system`, or `child_process`.

A hook written in Python still belongs here when it parses shell command strings:
the surface is the decision, not the language.

## Tools

| Tool | Tier | Class | Run recipe | Catches | Overlap |
|------|------|-------|-----------|---------|---------|
| shellcheck | default-on | local | `shellcheck -f json -S style <files>` | unquoted expansion, word splitting, glob injection, `[` vs `[[`, subshell scope loss, unsafe `read` | the floor; nothing else parses shell this well |
| shfmt | default-on | local | `shfmt -d -i 2 -ci .` | formatting drift that hides logic, mismatched heredocs | none |
| opengrep | default-on | local | `opengrep --config /opt/sabot-db/semgrep-rules/bash --config /opt/sabot-db/semgrep-rules/generic --json <files>` (6 + 257 baked rules) | `eval` on interpolated data, `curl \| sh`, unsafe `mktemp` | **baked, offline.** Never `p/bash` or `p/command-injection`: a registry shorthand exits `OG_RC=2` under `--network none`. Complements shellcheck with taint-shaped rules |
| bandit | default-on | local | `bandit -f json -r <paths>` | Python-side `shell=True`, `subprocess` with a formatted string | Python hooks only |
| checkov | opt-in | local | `checkov -d . -o json --framework github_actions` | shell inside CI, off unless workflows are in scope | overlaps zizmor from `infra.md` |
| `scripts/fuzz-cli.py` | default-on | local | see `harnesses.md` | crash, hang, non-JSON output, wrong-allow on a guard | the only tool that proves a bypass |

MUST Run shellcheck with `-S style`, since the default severity hides `SC2086` style findings that are real injection vectors in a guard.
NOT A hook that shellcheck passes is not safe. Shellcheck reads syntax; a fail-open inversion is semantically correct shell.

## Attack checklist

| # | Attack | Where it hides | Confirm by |
|---|--------|----------------|-----------|
| 1 | Command-position anchoring bypass | a guard matching `rm -rf` on the raw string | prefix the command with a wrapper (`env`, `sudo`, `nice`, `xargs`), leading whitespace, a tab, `\|\|`, `;`, `$(...)`, or a trailing quote, then check the verdict flips to allow |
| 2 | Fail-open inversion | the `except` or `|| true` path of a guard | feed malformed stdin; a guard that emits `allow` on a parse error lets everything through, while one that emits `deny` stalls the agent |
| 3 | Unquoted expansion reaching a command | `$1`, `$VAR`, `$(cmd)` inside a command line | pass a value containing a space, `;`, newline, `*`, or `$(id)` and observe execution or splitting |
| 4 | Path traversal past a scope check | a guard comparing prefixes on an unresolved path | use `../`, a symlink, a `//` double slash, or a relative path that resolves outside scope |
| 5 | TOCTOU between check and use | `[ -f "$f" ] && cat "$f"`, lock files, temp files | replace the path with a symlink between the two operations |
| 6 | Insecure temp file | `mktemp` without a template, `$$`-named files, fixed `/tmp` paths | predict the name and pre-create it |
| 7 | Glob and word-split on filenames | `for f in $(ls)`, unquoted `$@` | create a file whose name contains a space, a newline, or a leading dash |
| 8 | Missing `set -euo pipefail` | the top of a script that chains operations | make an early command fail and confirm the script continues past it |
| 9 | `eval` or dynamic dispatch on input | `eval "$cmd"`, `${!var}`, `source "$f"` | supply a value the author never intended as code |
| 10 | Signal and cleanup gap | `trap` absent, or cleanup that removes a variable path | interrupt mid-run and inspect what remains; an unset `$TMPDIR` in `rm -rf "$TMPDIR/x"` deletes the wrong tree |
| 11 | Env var trust | `PATH`, `IFS`, `BASH_ENV`, `LD_PRELOAD` read without validation | prepend a directory to `PATH` containing a fake binary the script calls |
| 12 | Exit-code confusion in a guard | a guard whose meaning depends on exit status and stdout together | emit valid JSON with a nonzero exit, and invalid JSON with a zero exit, then compare verdicts |

## Attacking a live guard without fighting it

A PreToolUse guard under test is often the guard running on your own session, so a
Bash tool call containing an attack payload (a heredoc of `rm -rf /` vectors, a
probe command line) is inspected and denied by the deployed copy before it reaches
the target. That is the guard working, not a test failure, but it blocks authoring.

| Route | How | When |
|---|---|---|
| File over command line | write vectors and probes to a file with the Write tool, never a heredoc or inline Bash; `fuzz-cli.py` reads the file | the default; the payload stays data in a file |
| Subprocess over tool call | `fuzz-cli.py` invokes the guard as a subprocess with the payload on stdin, so the payload never becomes a Bash TOOL CALL and no PreToolUse hook sees it | always true of the harness itself |
| Hook-free session | run the campaign under `claude --bare` (skips hooks) or a `--settings` file with no hooks, in a scratch dir outside the guarded repo | when even authoring trips the live guard |
| Handler over stdin, for an OMP `tool_call` gate | an OMP gate is an in-process TS extension with no stdin, so `fuzz-cli.py` cannot drive it. Import its default export in a `bun test` harness, pass a stub `pi` whose `on("tool_call", fn)` captures the handler, and call that handler with each vector from the file as `{ toolName, input }`: `{ block: true }` is deny, `undefined` is allow, and a returned `input` is a rewrite to re-check. Author the campaign under `omp --no-extensions` when the deployed gate trips authoring | the target is an OMP `tool_call` gate |

MUST Write attack payloads to a file rather than into a Bash command line, since the live guard inspects the command line and a catastrophic-looking payload is denied before the target sees it.
NOT Never disable the deployed guard in place to make room for the campaign. Use a hook-free session or a scratch dir; the guard protecting the working session is not the target.

## Harness patterns

Every hook and CLI goes through the shipped `scripts/fuzz-cli.py`, which asserts
these invariants and reports a violation as a finding. An OMP `tool_call` gate has no
stdin, so its `bun test` harness (the route above) asserts the same invariants on the
handler's return:

| Invariant | Violation is |
|---|---|
| Never crashes or hangs on any stdin | a DoS on the agent loop |
| Always emits parsable output in its declared format | an undefined verdict, which the harness treats as fail-closed |
| A guard's verdict is safe on malformed input | a bypass when it allows, an agent stall when it emits `ask` |
| A guard blocks its target pattern under every wrapper form | a bypass |
| Exit code matches the documented contract | a caller misreading the result |

Seed the corpus with the target's own test fixtures, then add the wrapper and
quoting mutations from the checklist. `sabot-fuzzer` writes the attack-vector list;
`gremlin` runs it.

## Impact calibration

| Level | Meaning on this surface |
|---|---|
| CRITICAL | a guard protecting a catastrophic operation can be bypassed, or a script executes attacker-controlled strings as commands |
| HIGH | a guard fails open on reachable malformed input, or an unquoted expansion reaches a destructive command |
| MEDIUM | a crash or hang on malformed input in a script that runs on every tool call, or a TOCTOU with a plausible race window |
| LOW | a style-level quoting issue with no reachable attacker-controlled value, or a missing `set -e` in a linear script |

## False-positive traps

| Looks like a finding | Clears when |
|---|---|
| Unquoted `$VAR` in a `[[ ]]` test | bash does not word-split inside `[[ ]]`, so no injection exists |
| Unquoted variable holding a known-integer | the value is assigned from `$?`, `$#`, or arithmetic in the same scope |
| `eval` in a completion or init script | the input comes from the shell's own state rather than from a tool call |
| A guard that emits `allow` on unknown input | fail-open is this repo's deliberate policy for non-catastrophic operations, so it caps at HARDENING unless the operation is catastrophic |
| `rm -rf "$dir"` | `$dir` is validated against a fixed prefix and the script sets `set -u`, making the unset-variable case impossible |
| Shellcheck `SC2016` on a single-quoted string | the string is documentation or a literal pattern the author never meant to expand |
