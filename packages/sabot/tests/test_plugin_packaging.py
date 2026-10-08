#!/usr/bin/env python3
"""Tests for the generated native plugin layout, which shipped uninstallable.

Three defects reached the tree at once, and every one of them made the documented
`claude plugin install sabot@sabot` path fail while the test suite stayed green:

1. `dependencies` carried apm's `{git, path}` source-locator objects. Claude Code
   takes a plugin id (a string, or `{name, version}`) and failed the whole manifest
   on it, so the plugin could not be installed at all.
2. The dependency was `beads`, which this marketplace does not ship. The install
   then succeeded and the plugin refused to ENABLE.
3. Every agent carried `permissionMode`, which Claude Code does not accept from a
   plugin-shipped agent.

Without the agents loaded, a campaign silently took SKILL.md's generic-agent
fallback, so a packaging failure read as a runtime limitation.

Reads the generated files as text and JSON. No container, no network, no CLI.

Run: pytest packages/sabot/tests/test_plugin_packaging.py
"""

import json
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
CLAUDE_MANIFEST = json.loads((PKG / ".claude-plugin/plugin.json").read_text())
NATIVE_AGENTS = sorted((PKG / "agents").glob("*.md"))
APM_AGENTS = sorted((PKG / ".apm/agents").glob("*.agent.md"))
AGENT_NAMES = {"sabot-scout", "sabot-fuzzer", "gremlin", "triager", "sabot-challenger", "hardener"}
AGENT_MODELS = PKG / ".apm/agent-models.yml"

# Tool names that let an agent change files. OMP lower-cases a frontmatter tool name
# before matching it, so Claude's `Edit` and OMP's `edit` are one entry each.
WRITE_TOOLS = {"edit", "write", "multiedit", "notebookedit", "ast_edit"}

# Claude Code refuses these on a plugin-shipped agent; each grants authority the
# installing user never reviewed.
FORBIDDEN_FRONTMATTER = ("permissionMode", "hooks", "mcpServers")


def _frontmatter(path: Path) -> str:
    text = path.read_text()
    assert text.startswith("---\n"), f"{path.name} has no frontmatter"
    return text[4 : text.index("\n---", 4)]


def _fields(path: Path) -> dict[str, str]:
    """Top-level `key: value` frontmatter fields, enough for the scalar keys here."""
    out = {}
    for line in _frontmatter(path).splitlines():
        key, sep, value = line.partition(":")
        if sep and key and not key.startswith((" ", "\t")):
            out[key.strip()] = value.strip()
    return out


def _codex_efforts() -> dict[str, str]:
    """agent name -> codex reasoning_effort from agent-models.yml, without PyYAML."""
    efforts, agent = {}, None
    for line in AGENT_MODELS.read_text().splitlines():
        if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
            agent = line.strip()[:-1]
        elif line.strip().startswith("reasoning_effort:") and agent:
            efforts[agent] = line.split(":", 1)[1].strip()
    return efforts


def test_every_agent_is_materialised_natively():
    """A plugin.json `agents` override into .apm/ does not load, so the six types
    have to exist at agents/*.md or the campaign silently runs generic."""
    assert {p.stem for p in NATIVE_AGENTS} == AGENT_NAMES
    assert {p.name[: -len(".agent.md")] for p in APM_AGENTS} == AGENT_NAMES


def test_native_agents_carry_no_forbidden_frontmatter():
    """permissionMode in a plugin-shipped agent is dropped by the loader."""
    bad = []
    for path in NATIVE_AGENTS:
        front = _frontmatter(path)
        for key in FORBIDDEN_FRONTMATTER:
            if any(line.startswith(f"{key}:") for line in front.splitlines()):
                bad.append(f"{path.name}:{key}")
    assert not bad, f"forbidden frontmatter in plugin-shipped agents: {bad}"


def test_native_agents_keep_name_and_description():
    """The generator rewrites frontmatter, so assert it did not strip the keys the
    registry keys on."""
    for path in NATIVE_AGENTS:
        front = _frontmatter(path)
        assert f"name: {path.stem}" in front, f"{path.name} lost its name"
        assert "description:" in front, f"{path.name} lost its description"


def test_apm_sources_name_matches_their_filename():
    """The two trees are the same agent, so a rename that lands in one and not the
    other ships a mismatched pair: the file resolves and the registered type does
    not. `sabot-scout` was renamed out of a collision with omp's bundled `scout`,
    and only the frontmatter decides which name a runtime registers."""
    for path in APM_AGENTS:
        stem = path.name[: -len(".agent.md")]
        assert f"name: {stem}" in _frontmatter(path), \
            f"{path.name} declares a name its filename does not match"


def test_apm_sources_keep_permission_mode():
    """The strip is Claude-only. APM honors permissionMode, so the shared source
    keeps it and the two targets are not collapsed into the weaker contract."""
    assert any("permissionMode:" in _frontmatter(p) for p in APM_AGENTS), \
        "the apm sources lost permissionMode, so the strip edited the wrong tree"


def test_manifest_declares_no_unresolvable_dependency():
    """A dependency this marketplace does not ship installs and then refuses to
    enable, which is worse than no dependency at all."""
    shipped = {p.name for p in (PKG.parent).iterdir() if p.is_dir()}
    for dep in CLAUDE_MANIFEST.get("dependencies", []):
        name = dep["name"] if isinstance(dep, dict) else dep
        assert name in shipped, \
            f"dependency {name!r} is not shipped by this marketplace ({sorted(shipped)})"


def test_manifest_dependencies_use_the_plugin_id_shape():
    """apm's `{git, path}` locator is rejected by Claude Code's validator."""
    for dep in CLAUDE_MANIFEST.get("dependencies", []):
        assert isinstance(dep, (str, dict)), f"unusable dependency entry: {dep!r}"
        if isinstance(dep, dict):
            assert set(dep) <= {"name", "version"}, \
                f"only name/version are accepted, got {sorted(dep)}"
            assert "name" in dep, f"object dependency needs a name: {dep!r}"


def test_generator_scopes_first_party_to_this_repo():
    """The hardcoded srobroek/agentic-packages slug survived the extract into this
    standalone repo and emitted a dependency on a package it no longer ships."""
    gen = (PKG.parents[1] / ".apm/scripts/build-native-plugins.py").read_text()
    assert "_first_party_names" in gen, \
        "first-party membership must be derived from packages/, not a hardcoded slug"
    assert 'srobroek/agentic-packages/packages/([\\w-]+)' not in gen, \
        "the hardcoded first-party repo slug is back"


def test_every_shipped_script_with_a_shebang_is_executable():
    """The docs invoke these by bare path, so a 644 mode is a hard failure.

    Measured by the self-run: `workflow.md` step 14 says to run
    `scripts/report-json.py --epic <id>`, and the file shipped 644, so the documented
    command died `Permission denied`. Ten of fifteen scripts were affected while five
    siblings were 755, which is the shape a git mode bit takes when nothing asserts it.
    """
    scripts = sorted((PKG / ".apm/skills/sabotage/scripts").iterdir())
    assert scripts, "no shipped scripts found"
    bad = [
        p.name for p in scripts
        if p.is_file()
        and p.read_bytes().startswith(b"#!")
        and not p.stat().st_mode & 0o111
    ]
    assert not bad, f"shebang present but not executable: {bad}"


def test_no_agent_sets_effort_without_thinking_level():
    """`effort` is a Claude Code key that OMP does not parse; OMP reads
    `thinking-level`. Every agent once carried `effort: low` alone, so on OMP the
    deepest roles ran at the session default while Codex ran them at xhigh."""
    bad = [
        p.name for p in APM_AGENTS + NATIVE_AGENTS
        if "effort" in _fields(p) and "thinking-level" not in _fields(p)
    ]
    assert not bad, f"effort-only frontmatter, ignored by OMP: {bad}"


def test_thinking_level_and_effort_match_the_codex_map():
    """One role, one depth: Claude `effort`, OMP `thinking-level`, and the Codex
    `reasoning_effort` in agent-models.yml must agree, or a runtime switch silently
    changes how hard each agent thinks."""
    efforts = _codex_efforts()
    assert set(efforts) == AGENT_NAMES, "agent-models.yml must map exactly the six agents"
    for path in APM_AGENTS + NATIVE_AGENTS:
        fields = _fields(path)
        want = efforts[fields["name"]]
        assert fields.get("thinking-level") == want, \
            f"{path.name}: thinking-level {fields.get('thinking-level')!r} != codex {want!r}"
        if "effort" in fields:
            assert fields["effort"] == want, \
                f"{path.name}: effort {fields['effort']!r} != codex {want!r}"


def test_challenger_is_read_only_in_every_runtime():
    """The challenger is the read-only critic, yet its source carried
    `permissionMode: acceptEdits` and no tool list, so nothing but prose kept it from
    editing. A `tools` allowlist binds in both Claude Code and OMP (which lower-cases
    `Read`/`Bash` onto its own names); it must carry no write-capable tool, and the
    source must not grant edits."""
    for path in (PKG / ".apm/agents/sabot-challenger.agent.md", PKG / "agents/sabot-challenger.md"):
        fields = _fields(path)
        assert "permissionMode" not in fields, f"{path.name} still grants edits"
        raw = fields.get("tools", "")
        assert raw.startswith("[") and raw.endswith("]"), \
            f"{path.name} needs an explicit tools allowlist, got {raw!r}"
        tools = {t.strip().lower() for t in raw[1:-1].split(",") if t.strip()}
        assert {"read", "grep", "glob", "bash"} <= tools, f"{path.name}: {sorted(tools)}"
        assert not tools & WRITE_TOOLS, f"{path.name} carries write tools {sorted(tools & WRITE_TOOLS)}"
