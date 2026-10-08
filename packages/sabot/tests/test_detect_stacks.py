#!/usr/bin/env python3
"""Tests for detect-stacks.py, the deterministic manifest-discovery script.

The image is provisioned from what this script finds, so a missed manifest leaves a
member crate or a frontend unprovisioned and its harness cannot run under
--network none. The tests build real git repos so `git ls-files` behaves as it will
in a campaign, and cover the cases a repo-root guess misses: workspace, monorepo,
multi-language, and .gitignore'd files.

Run: pytest packages/sabot/tests/test_detect_stacks.py
Stdlib plus pytest; needs `git` on PATH.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / ".apm" / "skills" / "sabotage" / "scripts" / "detect-stacks.py"
)


def make_repo(root: Path, files: dict[str, str]):
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    # --no-gpg-sign: see test_build_ext_image.py. A global `commit.gpgsign=true` with an
    # agent-backed signer hangs here forever, and pytest shows nothing while it does.
    subprocess.run(
        ["git", "-c", "user.email=t@t.co", "-c", "user.name=t",
         "commit", "--no-gpg-sign", "-qm", "init"],
        cwd=root, check=True,
    )


def run(root: Path, *args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--repo", str(root), *args],
        capture_output=True, text=True,
    )


def test_single_rust_crate(tmp_path):
    make_repo(tmp_path, {"Cargo.toml": "[package]\nname='x'\n", "Cargo.lock": "", "src/lib.rs": ""})
    out = json.loads(run(tmp_path).stdout)
    assert out["stacks"] == ["rust"]
    assert out["multi_language"] is False
    assert len(out["bake_units"]) == 1
    assert out["bake_units"][0]["fetch"] == "cargo fetch"


def test_cargo_workspace_collapses_members(tmp_path):
    make_repo(tmp_path, {
        "Cargo.toml": "[workspace]\nmembers=['crates/*']\n",
        "Cargo.lock": "",
        "crates/a/Cargo.toml": "[package]\nname='a'\n",
        "crates/b/Cargo.toml": "[package]\nname='b'\n",
    })
    out = json.loads(run(tmp_path).stdout)
    # all three manifests discovered...
    assert len(out["manifests"]) == 3
    # ...but only the workspace root is a bake unit (root fetch provisions members)
    assert len(out["bake_units"]) == 1
    assert out["bake_units"][0]["dir"] == "."


def test_multi_language_tauri_shape(tmp_path):
    make_repo(tmp_path, {
        "Cargo.toml": "[workspace]\nmembers=['src-tauri']\n",
        "Cargo.lock": "",
        "src-tauri/Cargo.toml": "[package]\nname='app'\n",
        "frontend/package.json": '{"name":"f","devDependencies":{"vite":"^5"}}',
        "frontend/package-lock.json": "{}",
    })
    out = json.loads(run(tmp_path).stdout)
    assert out["multi_language"] is True
    assert set(out["stacks"]) == {"rust", "node"}
    fetches = {(u["stack"], u["dir"]) for u in out["bake_units"]}
    assert ("rust", ".") in fetches          # workspace root
    assert ("node", "frontend") in fetches   # frontend provisioned separately
    assert len(out["bake_units"]) == 2       # src-tauri member collapsed into root


def test_gitignored_manifest_is_skipped(tmp_path):
    make_repo(tmp_path, {
        "Cargo.toml": "[package]\nname='x'\n",
        ".gitignore": "vendor/\n",
    })
    # an ignored, untracked vendor manifest must not appear
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "package.json").write_text('{"name":"v"}')
    out = json.loads(run(tmp_path).stdout)
    assert out["stacks"] == ["rust"]
    assert all("vendor" not in m["manifest"] for m in out["manifests"])


def test_agentic_tooling_config_is_not_a_bake_unit(tmp_path):
    # Regression: platevault tracks .agents/skills/react-components/package.json, which
    # became a node bake unit in a RUST ext image. `npm ci` in the rust base died 127 and
    # took the whole image with it. Assistant config is out of every target (SKILL.md
    # step 1), so it is out of provisioning too.
    make_repo(tmp_path, {
        "Cargo.toml": "[package]\nname='x'\n",
        ".agents/skills/react-components/package.json": '{"name":"rc"}',
        ".claude/tools/package.json": '{"name":"ct"}',
        ".cursor/helper/pyproject.toml": "[project]\nname='h'\n",
    })
    out = json.loads(run(tmp_path).stdout)
    assert out["stacks"] == ["rust"]
    assert out["multi_language"] is False
    assert [m["manifest"] for m in out["manifests"]] == ["Cargo.toml"]
    assert "npm" not in run(tmp_path, "--bake").stdout


def test_product_code_named_like_an_agent_still_bakes(tmp_path):
    # The exclusion is the leading path segment only. A shipped agentic app under src/
    # is in scope on a whole-repo run, so its manifest must still provision.
    make_repo(tmp_path, {
        "Cargo.toml": "[package]\nname='x'\n",
        "src/agents/package.json": '{"name":"app"}',
    })
    out = json.loads(run(tmp_path).stdout)
    assert out["stacks"] == ["node", "rust"]
    assert any(m["manifest"] == "src/agents/package.json" for m in out["bake_units"])


def test_bake_emits_command_lines(tmp_path):
    make_repo(tmp_path, {"go.mod": "module x\n", "go.sum": ""})
    r = run(tmp_path, "--bake")
    assert r.returncode == 0
    assert "go mod download" in r.stdout
    # command lines for a Dockerfile RUN, not a standalone script -> no shebang
    assert "#!" not in r.stdout


def test_not_a_repo_exits_3(tmp_path):
    r = run(tmp_path)  # tmp_path is not git-init'd
    assert r.returncode == 3


def test_omp_copilot_and_apm_instructions_are_tooling_not_bake_units(tmp_path):
    # targeting.md excludes these; the script used to keep its own shorter list.
    make_repo(tmp_path, {
        "Cargo.toml": "[package]\nname='x'\n",
        ".omp/tools/package.json": '{"name":"o"}',
        ".github/copilot-helpers/package.json": '{"name":"c"}',
        ".apm/instructions/py/pyproject.toml": "[project]\nname='i'\n",
    })
    out = json.loads(run(tmp_path).stdout)
    assert [m["manifest"] for m in out["manifests"]] == ["Cargo.toml"]


def test_python_fetch_fails_loudly_rather_than_or_true(tmp_path):
    # `uv sync --frozen || pip install -e '.[dev]' || true` always exited 0, so a stack
    # the image never provisioned read as provisioned.
    make_repo(tmp_path, {"pyproject.toml": "[project]\nname='x'\ndependencies=['attrs']\n"})
    (unit,) = json.loads(run(tmp_path).stdout)["bake_units"]
    assert "|| true" not in unit["fetch"]
    assert "--only-binary=:all:" in unit["fetch"]
    assert unit["requirements"] == ["attrs"]
    assert unit["resolver"] == "pip (pyproject.toml requirements)"


def test_uv_lock_pins_registry_packages_only(tmp_path):
    make_repo(tmp_path, {
        "pyproject.toml": "[project]\nname='x'\n",
        "uv.lock": (
            "[[package]]\nname='x'\nversion='0.1.0'\nsource={editable='.'}\n"
            "[[package]]\nname='attrs'\nversion='24.2.0'\n"
            "source={registry='https://pypi.org/simple'}\n"
        ),
    })
    (unit,) = json.loads(run(tmp_path).stdout)["bake_units"]
    assert unit["requirements"] == ["attrs==24.2.0"]
    assert unit["resolver"] == "pip (uv.lock pins)"


def test_python_manifest_with_nothing_to_install_carries_a_skip_reason(tmp_path):
    make_repo(tmp_path, {"pyproject.toml": "[tool.poetry]\nname='x'\n", "poetry.lock": ""})
    (unit,) = json.loads(run(tmp_path).stdout)["bake_units"]
    assert unit["fetch"] is None
    assert "poetry" in unit["skip_reason"]
    assert "# skipped pyproject.toml" in run(tmp_path, "--bake").stdout
