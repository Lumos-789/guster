from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from guster import __version__, cli  # noqa: E402
from guster.discover import (  # noqa: E402
    ScanConfig,
    default_roots,
    extra_skill_roots,
    scan,
    scan_local_wiki,
)
from guster.executor import ApplyError, apply_plan, init_home, preflight  # noqa: E402
from guster.hub import attach_hub, init_hub, validate_hub  # noqa: E402
from guster.metrics import compute_metrics  # noqa: E402
from guster.planner import load_plan, plan_init_project, plan_move  # noqa: E402
from guster.policy import extract_filename_date, extract_verified_date, run_policy  # noqa: E402
from guster.util import note_header_date  # noqa: E402
from guster.report import render_report  # noqa: E402
from guster.util import extract_naked_pointers, extract_pointers  # noqa: E402


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class Fixture:
    def __init__(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="guster-test-"))
        self.home = self.tmp / "home"
        self.workspace = self.tmp / "workspace"
        self.hub = self.tmp / "hub"
        self.project = self.workspace / "proj1"
        self.state = self.tmp / "state"

        write(self.home / ".zcode" / "AGENTS.md", "# User rules\n\nKeep it short.\n")
        write(
            self.home / ".agents" / "skills" / "foo" / "SKILL.md",
            "---\nname: foo\ndescription: " + ("x" * 600) + "\n---\n\n# Foo\n",
        )
        write(
            self.home / ".codex" / "skills" / "foo" / "SKILL.md",
            "---\nname: foo\ndescription: a different description\n---\n\n# Foo\n",
        )
        write(self.home / ".agents" / "wiki" / "README.md", "# Wiki\n\n| note |\n|---|\n| `note.md` |\n")
        write(self.home / ".agents" / "wiki" / "note.md", "# Note\n")
        write(self.home / ".zcode" / "secrets" / "token", "secret-value\n")
        write(self.home / ".codex" / "config.toml", "[mcp_servers.foo]\nAuthorization = \"Bearer abcdefghijklmnop\"\n")

        (self.project / ".git").mkdir(parents=True)
        write(self.project / "AGENTS.md", "# Project\n\nSee [`knowledge/missing.md`](knowledge/missing.md).\n")
        write(self.project / ".agents" / "README.md", "# Index\n\n| plan |\n|---|\n| `plans/plan.md` |\n")
        write(self.project / ".agents" / "plans" / "plan.md", "# Plan\n\n**最后更新**: 2026-11-01\n")
        write(self.project / ".agents" / "wiki" / "note.md", "# Unindexed note\n")
        write(self.project / ".agents" / "task-x" / "a.md", "# Task evidence\n")
        write(self.project / ".agents" / "tmp" / "old.md", "# Old scratch\n")
        write(self.project / ".env", "TOKEN=not-a-real-token\n")

        write(self.hub / "AGENTS.md", "# Hub\n")
        write(self.hub / "knowledge" / "README.md", "# Knowledge\n\n| a |\n|---|\n| `general/a.md` |\n")
        write(self.hub / "knowledge" / "general" / "a.md", "# A\n")
        write(self.hub / "knowledge" / "general" / "b.md", "# B\n")
        write(self.hub / "projects" / "p.md", "# Project P\n\n**状态**: active\n")

    def config(self) -> ScanConfig:
        return ScanConfig(
            home=self.home,
            hub=self.hub,
            roots=[self.workspace],
            state_dir=self.state,
            plugin_root=ROOT,
            max_depth=3,
            now="2026-11-03T00:00:00+08:00",
        )

    def registry(self):
        return scan(self.config())

    def cleanup(self) -> None:
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)


class GusterCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = Fixture()

    def tearDown(self) -> None:
        self.fx.cleanup()

    def test_scan_finds_projects_skills_and_artifacts(self) -> None:
        registry = self.fx.registry()
        self.assertEqual(registry["summary"]["projects"], 1)
        self.assertEqual(registry["summary"]["agents_dirs"], 1)
        self.assertGreaterEqual(registry["summary"]["skills"], 1)
        names = [skill["name"] for skill in registry["skills"]]
        self.assertIn("foo", names)
        self.assertTrue(any(item["kind"] == "knowledge" for item in registry["artifacts"]))
        paths = [item["path"] for item in registry["artifacts"]]
        self.assertEqual(len(paths), len(set(paths)), "artifacts must be unique per path")

    def test_policy_finds_drift_budget_and_secrets(self) -> None:
        registry = self.fx.registry()
        result = run_policy(registry, self.fx.config())
        rules = {item["rule"] for item in result["findings"]}
        self.assertIn("skill-budget", rules)
        self.assertIn("skill-copy-drift", rules)
        self.assertIn("orphan-knowledge", rules)
        self.assertIn("broken-pointer", rules)
        self.assertIn("misplaced-artifact", rules)
        self.assertIn("stale-state", rules)
        self.assertIn("secret-outside-root", rules)
        self.assertIn("secret-inline", rules)

    def test_metrics_are_bounded_and_reproducible(self) -> None:
        registry = self.fx.registry()
        policy = run_policy(registry, self.fx.config())
        first = compute_metrics(registry, policy)
        second = compute_metrics(registry, policy)
        self.assertEqual(first["metrics"], second["metrics"])
        self.assertGreaterEqual(first["chi"], 0)
        self.assertLessEqual(first["chi"], 100)
        for value in first["scores"].values():
            self.assertGreaterEqual(value, 0)
            self.assertLessEqual(value, 100)

    def test_init_project_creates_standard_layout(self) -> None:
        target = self.fx.tmp / "new-project"
        plan = plan_init_project(target)
        result = apply_plan(plan, self.fx.state, dry_run=False, yes=True)
        self.assertTrue(result["ok"])
        for slot in ("plans", "wiki", "evidence", "skills", "tmp", "archive"):
            self.assertTrue((target / ".agents" / slot).is_dir())
        self.assertTrue((target / ".agents" / "README.md").is_file())
        self.assertTrue((target / "AGENTS.md").is_file())

    def test_plan_move_creates_backup_and_pointer(self) -> None:
        src = self.fx.project / ".agents" / "task-x"
        dst = self.fx.project / ".agents" / "evidence" / "task-x"
        plan = plan_move(src, dst)
        result = apply_plan(plan, self.fx.state, dry_run=False, yes=True)
        self.assertTrue(result["ok"])
        self.assertTrue((dst / "a.md").is_file())
        self.assertTrue((self.fx.project / ".agents" / "task-x.moved.md").is_file())
        self.assertTrue((Path(result["backup"]) / "002-task-x" / "a.md").is_file())

    def _failing_batch(self, pointer_path) -> dict:
        # move+pointer, a fresh write, then a write onto a directory the second
        # op just created — the batch always fails at op 3 and must roll back.
        agents = self.fx.project / ".agents"
        return {
            "id": "batch-fail",
            "version": 1,
            "operations": [
                {
                    "kind": "move",
                    "src": str(agents / "task-x"),
                    "dst": str(agents / "evidence" / "task-x"),
                    "pointer": {"path": str(pointer_path), "content": "moved\n"},
                },
                {"kind": "write", "path": str(agents / "kb" / "n.md"), "content": "# n\n"},
                {"kind": "write", "path": str(agents / "kb"), "content": "x"},
            ],
        }

    def test_apply_rollback_leaves_no_stale_pointer(self) -> None:
        agents = self.fx.project / ".agents"
        pointer = agents / "task-x.moved.md"
        with self.assertRaises(ApplyError) as caught:
            apply_plan(self._failing_batch(pointer), self.fx.state, dry_run=False, yes=True)
        self.assertIn("rolled back", str(caught.exception))
        self.assertTrue((agents / "task-x" / "a.md").is_file())  # source restored
        self.assertFalse((agents / "evidence" / "task-x").exists())  # destination gone
        self.assertFalse(pointer.exists())  # no pointer lying about a gone destination
        self.assertFalse((agents / "kb" / "n.md").exists())  # fresh write undone too

    def test_apply_rollback_restores_existing_pointer(self) -> None:
        agents = self.fx.project / ".agents"
        pointer = agents / "task-x.moved.md"
        write(pointer, "old pointer\n")
        with self.assertRaises(ApplyError):
            apply_plan(self._failing_batch(pointer), self.fx.state, dry_run=False, yes=True)
        self.assertEqual(pointer.read_text(encoding="utf-8"), "old pointer\n")

    def test_dry_run_does_not_write(self) -> None:
        target = self.fx.tmp / "dry-project"
        plan = plan_init_project(target)
        result = apply_plan(plan, self.fx.state, dry_run=True, yes=False)
        self.assertTrue(result["dry_run"])
        self.assertFalse((target / ".agents").exists())

    def test_init_home_writes_detected_roots_and_requires_a_candidate(self) -> None:
        state = self.fx.tmp / "fresh-state"
        home = self.fx.tmp / "fresh-home"
        (home / "code").mkdir(parents=True)
        result = init_home(state, yes=True, dry_run=False, home=home)
        self.assertTrue(result["ok"])
        config = json.loads((state / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(config["roots"], [str((home / "code").resolve())])
        self.assertNotIn("~", json.dumps(config))

    def test_init_home_fails_loud_without_any_candidate(self) -> None:
        home = self.fx.tmp / "bare-home"
        home.mkdir()
        with self.assertRaises(ValueError) as caught:
            init_home(self.fx.tmp / "bare-state", yes=True, dry_run=False, home=home)
        self.assertIn("--root", str(caught.exception))

    def test_manifest_versions_match(self) -> None:
        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        codex = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        zcode = json.loads((ROOT / ".zcode-plugin" / "plugin.json").read_text(encoding="utf-8"))
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertEqual(package["version"], __version__)
        self.assertEqual(package["version"], codex["version"])
        self.assertEqual(package["version"], zcode["version"])
        self.assertIn(f'version = "{__version__}"', pyproject)

    def test_hub_init_creates_a_lightweight_contract(self) -> None:
        target = self.fx.tmp / "lite-hub"
        state = self.fx.tmp / "lite-state"
        result = init_hub(target, state, yes=True, dry_run=False)
        self.assertTrue(result["ok"], result)
        for rel in (
            ".gitignore",
            "AGENTS.md",
            "README.md",
            "hub.yaml",
            "knowledge/README.md",
            "projects/_registry.md",
            "tools/README.md",
        ):
            self.assertTrue((target / rel).is_file(), rel)
        self.assertTrue((target / "knowledge" / "general" / "start-here.md").is_file())
        self.assertEqual(
            sorted(path.name for path in (target / "tools").iterdir()),
            ["README.md"],
        )
        self.assertFalse((target / "handoff").exists())
        self.assertFalse((target / "reports").exists())
        config = json.loads((state / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(config["hub"], str(target.resolve()))
        self.assertTrue(validate_hub(target)["ok"])

    def test_hub_init_refuses_non_empty_target(self) -> None:
        target = self.fx.tmp / "occupied-hub"
        target.mkdir()
        (target / "keep.md").write_text("# Keep\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            init_hub(target, self.fx.tmp / "occupied-state", yes=True, dry_run=False)
        self.assertTrue((target / "keep.md").is_file())

    def test_hub_init_supports_custom_layout_paths(self) -> None:
        target = self.fx.tmp / "custom-hub"
        state = self.fx.tmp / "custom-state"
        result = init_hub(
            target,
            state,
            yes=True,
            dry_run=False,
            knowledge="notes",
            projects="work",
            tools="scripts",
        )
        self.assertTrue(result["ok"])
        for rel in (
            "notes/README.md",
            "notes/general/start-here.md",
            "work/_registry.md",
            "scripts/README.md",
        ):
            self.assertTrue((target / rel).is_file(), rel)
        self.assertFalse((target / "knowledge").exists())
        self.assertFalse((target / "projects").exists())
        self.assertFalse((target / "tools").exists())
        info = validate_hub(target)
        self.assertTrue(info["ok"], info)
        self.assertEqual(
            info["paths"],
            {"knowledge": "notes", "projects": "work", "tools": "scripts"},
        )

    def test_custom_hub_layout_is_scanned(self) -> None:
        target = self.fx.tmp / "custom-scan-hub"
        state = self.fx.tmp / "custom-scan-state"
        home = self.fx.tmp / "custom-scan-home"
        home.mkdir()
        init_hub(
            target,
            state,
            yes=True,
            dry_run=False,
            knowledge="notes",
            projects="work",
            tools="scripts",
        )
        write(target / "notes" / "general" / "extra.md", "# Extra\n")
        index = target / "notes" / "README.md"
        index.write_text(
            index.read_text(encoding="utf-8") + "| `extra.md` | Extra |\n",
            encoding="utf-8",
        )
        write(
            target / "work" / "card.md",
            "# Card\n\n**最后更新**: 2026-11-03\n",
        )
        config = ScanConfig(
            home=home,
            hub=target,
            roots=[],
            state_dir=state,
            plugin_root=ROOT,
            max_depth=3,
            scope="hub",
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        policy = run_policy(registry, config)
        self.assertEqual(policy["stats"]["knowledge_total"], 2)
        self.assertEqual(policy["stats"]["knowledge_indexed"], 2)
        self.assertEqual(policy["stats"]["state_docs_total"], 2)
        self.assertEqual(policy["stats"]["state_docs_fresh"], 2)
        severities = {item["severity"] for item in policy["findings"]}
        self.assertNotIn("high", severities)
        self.assertNotIn("critical", severities)

    def test_hub_init_rejects_escaping_layout_path(self) -> None:
        target = self.fx.tmp / "escape-hub"
        with self.assertRaises(ValueError):
            init_hub(
                target,
                self.fx.tmp / "escape-state",
                yes=True,
                dry_run=False,
                knowledge="../outside",
            )
        self.assertFalse(target.exists())

    def test_hub_validate_rejects_manifest_path_escape(self) -> None:
        target = self.fx.tmp / "manifest-escape-hub"
        init_hub(target, self.fx.tmp / "manifest-escape-state", yes=True, dry_run=False)
        manifest = target / "hub.yaml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "  knowledge: knowledge", "  knowledge: ../outside"
            ),
            encoding="utf-8",
        )
        info = validate_hub(target)
        self.assertFalse(info["ok"])
        self.assertTrue(any("invalid hub layout" in item for item in info["errors"]))

    def test_hub_validate_catches_unindexed_knowledge(self) -> None:
        target = self.fx.tmp / "indexed-hub"
        init_hub(target, self.fx.tmp / "indexed-state", yes=True, dry_run=False)
        (target / "knowledge" / "general" / "extra.md").write_text("# Extra\n", encoding="utf-8")
        info = validate_hub(target)
        self.assertFalse(info["ok"])
        self.assertTrue(any("not indexed" in item for item in info["errors"]))

    def test_hub_attach_backs_up_existing_config(self) -> None:
        target = self.fx.tmp / "attached-hub"
        state = self.fx.tmp / "attached-state"
        init_hub(target, state, yes=True, dry_run=False)
        config_path = state / "config.json"
        config_path.write_text('{"version": 1, "roots": ["/tmp/old"]}\n', encoding="utf-8")
        result = attach_hub(state, target)
        self.assertTrue(result["ok"])
        self.assertTrue(Path(result["backup"]).is_file())
        config = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual(config["hub"], str(target.resolve()))
        self.assertEqual(config["roots"], ["/tmp/old"])

    def test_legacy_hub_can_be_attached_without_lite_manifest(self) -> None:
        target = self.fx.tmp / "legacy-hub"
        write(target / "AGENTS.md", "# Legacy Hub\n")
        write(target / "knowledge" / "README.md", "# Knowledge\n\n| a |\n|---|\n| `a.md` |\n")
        write(target / "knowledge" / "general" / "a.md", "# A\n")
        write(target / "projects" / "_registry.md", "# Registry\n\n**最后更新**: 2026-11-03\n")
        relaxed = validate_hub(target, strict=False)
        self.assertTrue(relaxed["ok"], relaxed)
        self.assertEqual(relaxed["profile"], "legacy")
        self.assertTrue(relaxed["warnings"])
        self.assertFalse(validate_hub(target, strict=True)["ok"])
        result = attach_hub(self.fx.tmp / "legacy-state", target)
        self.assertTrue(result["ok"])

    def test_fresh_lite_hub_passes_hub_scope_policy(self) -> None:
        target = self.fx.tmp / "clean-hub"
        state = self.fx.tmp / "clean-state"
        home = self.fx.tmp / "clean-home"
        home.mkdir()
        init_hub(target, state, yes=True, dry_run=False)
        config = ScanConfig(
            home=home,
            hub=target,
            roots=[],
            state_dir=state,
            plugin_root=ROOT,
            max_depth=3,
            scope="hub",
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        policy = run_policy(registry, config)
        severities = {item["severity"] for item in policy["findings"]}
        self.assertNotIn("high", severities)
        self.assertNotIn("critical", severities)
        stats = policy["stats"]
        self.assertEqual(stats["knowledge_total"], stats["knowledge_indexed"])
        self.assertEqual(stats["state_docs_total"], stats["state_docs_fresh"])

    def test_hub_scope_excludes_local_wiki_and_machine_secrets(self) -> None:
        config = ScanConfig(
            home=self.fx.home,
            hub=self.fx.hub,
            roots=[],
            state_dir=self.fx.tmp / "hub-only-state",
            plugin_root=ROOT,
            max_depth=3,
            scope="hub",
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        paths = [item["path"] for item in registry["artifacts"]]
        self.assertFalse(any(str(self.fx.home / ".agents" / "wiki") in path for path in paths))
        self.assertEqual(registry["skills"], [])
        secret_paths = [item["path"] for item in registry["secrets"]["files"]]
        self.assertFalse(any(str(self.fx.home / ".zcode" / "secrets") in path for path in secret_paths))
        policy = run_policy(registry, config)
        self.assertEqual(policy["stats"]["scoped_hidden_findings"], 0)
        self.assertNotIn("out-of-scope", {item["rule"] for item in policy["findings"]})

    def test_hub_scope_report_lists_only_scored_dimensions(self) -> None:
        config = ScanConfig(
            home=self.fx.home,
            hub=self.fx.hub,
            roots=[],
            state_dir=self.fx.tmp / "report-state",
            plugin_root=ROOT,
            max_depth=3,
            scope="hub",
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        policy = run_policy(registry, config)
        metrics = compute_metrics(registry, policy)
        report = render_report(registry, policy, metrics)
        self.assertEqual(metrics["dims"], ["ssr", "icr", "frs", "phr"])
        for label in ("Single source", "Index coverage", "State freshness", "Pointer health"):
            self.assertIn(f"| {label} |", report)
        for label in ("Resident budget", "Placement", "Secret isolation"):
            self.assertNotIn(f"| {label} |", report)
        self.assertIn("_Not counted in CHI: Governance simplicity", report)

    def test_machine_scope_report_lists_every_scored_dimension(self) -> None:
        registry = self.fx.registry()
        policy = run_policy(registry, self.fx.config())
        metrics = compute_metrics(registry, policy)
        report = render_report(registry, policy, metrics)
        for label in (
            "Single source",
            "Resident budget",
            "Placement",
            "Index coverage",
            "State freshness",
            "Pointer health",
            "Secret isolation",
        ):
            self.assertIn(f"| {label} |", report)

    def test_project_scope_denominators_match_the_findings_boundary(self) -> None:
        config = ScanConfig(
            home=self.fx.home,
            hub=self.fx.hub,
            roots=[self.fx.project],
            state_dir=self.fx.tmp / "project-scope-state",
            plugin_root=ROOT,
            max_depth=3,
            scope="project",
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        policy = run_policy(registry, config)
        stats = policy["stats"]
        root = self.fx.project.resolve()
        for item in registry["artifacts"]:
            self.assertIn(root, Path(item["path"]).resolve().parents, item["path"])
        knowledge = [item for item in registry["artifacts"] if item["kind"] == "knowledge"]
        self.assertEqual(stats["knowledge_total"], len(knowledge))
        self.assertTrue(knowledge)
        # Project plans are state-plane documents and must stay in the FRS
        # denominator; hub project cards are out of scope and must not.
        state = [item for item in registry["artifacts"] if item.get("plane") == "state"]
        self.assertEqual(stats["state_docs_total"], len(state))
        self.assertEqual(stats["state_docs_total"], 1)
        self.assertEqual(stats["state_docs_fresh"], 1)
        self.assertEqual(
            Path(state[0]["path"]).resolve().parent,
            (self.fx.project / ".agents" / "plans").resolve(),
        )
        hub = str(self.fx.hub.resolve())
        for item in policy["findings"]:
            if item["rule"] == "out-of-scope":
                continue
            self.assertNotIn(hub, item["path"])
        self.assertGreaterEqual(stats["scoped_hidden_findings"], 1)
        metrics = compute_metrics(registry, policy)
        self.assertEqual(metrics["raw"]["agents_indexed"], stats["agents_indexed"])
        report = render_report(registry, policy, metrics)
        self.assertIn(f".agents index {stats['agents_indexed']}/{stats['agents_dirs_total']}", report)

    def test_group_scope_denominators_match_the_findings_boundary(self) -> None:
        config = ScanConfig(
            home=self.fx.home,
            hub=self.fx.hub,
            roots=[self.fx.workspace],
            state_dir=self.fx.tmp / "group-scope-state",
            plugin_root=ROOT,
            max_depth=3,
            scope="group",
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        policy = run_policy(registry, config)
        workspace = self.fx.workspace.resolve()
        for item in registry["artifacts"]:
            self.assertIn(workspace, Path(item["path"]).resolve().parents, item["path"])
        state = [item for item in registry["artifacts"] if item.get("plane") == "state"]
        self.assertEqual(policy["stats"]["state_docs_total"], len(state))
        self.assertEqual(policy["stats"]["state_docs_total"], 1)
        self.assertEqual(policy["stats"]["state_docs_fresh"], 1)
        self.assertGreaterEqual(policy["stats"]["knowledge_total"], 1)

    def test_project_scope_frs_drops_for_a_stale_plan(self) -> None:
        write(
            self.fx.project / ".agents" / "plans" / "plan.md",
            "# Plan\n\n**最后更新**: 2020-01-15\n",
        )
        config = ScanConfig(
            home=self.fx.home,
            hub=self.fx.hub,
            roots=[self.fx.project],
            state_dir=self.fx.tmp / "stale-plan-state",
            plugin_root=ROOT,
            max_depth=3,
            scope="project",
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        policy = run_policy(registry, config)
        stats = policy["stats"]
        self.assertEqual(stats["state_docs_total"], 1)
        self.assertEqual(stats["state_docs_fresh"], 0)
        metrics = compute_metrics(registry, policy)
        self.assertEqual(metrics["scores"]["frs"], 0.0)
        report = render_report(registry, policy, metrics)
        self.assertIn("| State freshness | 0.0 | 0.0 | 0/1 fresh", report)
        self.assertTrue(
            any(
                item["rule"] == "stale-state" and "older than" in item["title"]
                for item in policy["findings"]
            )
        )

    def test_group_scope_frs_counts_each_projects_plans(self) -> None:
        second = self.fx.workspace / "proj2"
        (second / ".git").mkdir(parents=True)
        write(second / "AGENTS.md", "# Project 2\n")
        write(second / ".agents" / "README.md", "# Index\n")
        write(
            second / ".agents" / "plans" / "plan.md",
            "# Plan\n\n**最后更新**: 2020-01-15\n",
        )
        config = ScanConfig(
            home=self.fx.home,
            hub=self.fx.hub,
            roots=[self.fx.workspace],
            state_dir=self.fx.tmp / "group-plans-state",
            plugin_root=ROOT,
            max_depth=3,
            scope="group",
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        policy = run_policy(registry, config)
        stats = policy["stats"]
        self.assertEqual(stats["state_docs_total"], 2)
        self.assertEqual(stats["state_docs_fresh"], 1)
        metrics = compute_metrics(registry, policy)
        self.assertEqual(metrics["scores"]["frs"], 50.0)
        report = render_report(registry, policy, metrics)
        self.assertIn("| State freshness | 0.5 | 50.0 | 1/2 fresh", report)

    def test_project_plan_falls_back_to_owning_repo_git_date(self) -> None:
        import subprocess

        project = self.fx.tmp / "git-plan-project"
        write(project / "AGENTS.md", "# Git plan project\n")
        write(project / ".agents" / "plans" / "plan.md", "# Plan\n")
        subprocess.run(["git", "init", "-q", str(project)], check=True)
        subprocess.run(["git", "-C", str(project), "add", "-A"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(project),
                "-c",
                "user.email=test@example.com",
                "-c",
                "user.name=test",
                "commit",
                "-q",
                "-m",
                "init",
            ],
            check=True,
        )
        config = ScanConfig(
            home=self.fx.home,
            hub=None,
            roots=[project],
            state_dir=self.fx.tmp / "git-plan-state",
            plugin_root=ROOT,
            max_depth=3,
            scope="project",
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        policy = run_policy(registry, config)
        stats = policy["stats"]
        self.assertEqual(stats["state_docs_total"], 1)
        self.assertEqual(stats["state_docs_fresh"], 1)
        self.assertEqual(stats["state_docs_fresh_from_git"], 1)
        self.assertNotIn("stale-state", {item["rule"] for item in policy["findings"]})

    def test_empty_state_denominator_is_not_a_perfect_score(self) -> None:
        hub = self.fx.tmp / "empty-state-hub"
        write(hub / "AGENTS.md", "# Hub\n")
        write(hub / "knowledge" / "README.md", "# Knowledge\n")
        write(hub / "tools" / "README.md", "# Tools\n")
        config = ScanConfig(
            home=self.fx.tmp / "empty-state-home",
            hub=hub,
            roots=[],
            state_dir=self.fx.tmp / "empty-state-state",
            plugin_root=ROOT,
            max_depth=3,
            scope="hub",
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        policy = run_policy(registry, config)
        self.assertEqual(policy["stats"]["state_docs_total"], 0)
        metrics = compute_metrics(registry, policy)
        self.assertIsNone(metrics["scores"]["frs"])
        self.assertIn("frs", metrics["unscored_dims"])
        report = render_report(registry, policy, metrics)
        self.assertIn("| State freshness | n/a | n/a | 0/0 fresh", report)
        self.assertIn("No evidence: SSR, ICR, FRS, PHR", report)

    def test_empty_icr_child_is_excluded_not_counted_as_one(self) -> None:
        hub = self.fx.tmp / "zero-icr-hub"
        state = self.fx.tmp / "zero-icr-state"
        init_hub(hub, state, yes=True, dry_run=False)
        write(hub / "knowledge" / "general" / "extra.md", "# Extra\n")
        config = ScanConfig(
            home=self.fx.tmp / "zero-icr-home",
            hub=hub,
            roots=[],
            state_dir=state,
            plugin_root=ROOT,
            max_depth=3,
            scope="hub",
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        policy = run_policy(registry, config)
        metrics = compute_metrics(registry, policy)
        self.assertEqual(metrics["raw"]["knowledge_total"], 2)
        self.assertEqual(metrics["raw"]["knowledge_indexed"], 1)
        self.assertEqual(metrics["raw"]["agents_dirs_total"], 0)
        self.assertEqual(metrics["metrics"]["icr"], 0.5)
        self.assertNotIn("icr", metrics["unscored_dims"])
        report = render_report(registry, policy, metrics)
        self.assertIn("knowledge 1/2; .agents index 0/0", report)

    def test_hub_scope_report_counts_project_cards_and_omits_empty_workspaces(self) -> None:
        hub = self.fx.tmp / "three-card-hub"
        state = self.fx.tmp / "three-card-state"
        init_hub(hub, state, yes=True, dry_run=False)
        for slug in ("alpha", "beta", "gamma"):
            write(hub / "projects" / f"{slug}.md", f"# {slug}\n\n**最后更新**: 2026-11-01\n")
        config = ScanConfig(
            home=self.fx.tmp / "three-card-home",
            hub=hub,
            roots=[],
            state_dir=state,
            plugin_root=ROOT,
            max_depth=3,
            scope="hub",
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        policy = run_policy(registry, config)
        metrics = compute_metrics(registry, policy)
        report = render_report(registry, policy, metrics)
        self.assertEqual(registry["summary"]["projects"], 0)
        self.assertEqual(registry["summary"]["project_cards"], 3)
        self.assertIn("- Projects: **3** (scanned roots: 0)", report)
        self.assertNotIn("> Workspaces:", report)
        self.assertIn("state: 4", report)

    def test_hub_doctor_reports_project_cards_not_zero(self) -> None:
        hub = self.fx.tmp / "doctor-card-hub"
        state = self.fx.tmp / "doctor-card-state"
        init_hub(hub, state, yes=True, dry_run=False)
        for slug in ("alpha", "beta", "gamma"):
            write(hub / "projects" / f"{slug}.md", f"# {slug}\n\n**最后更新**: 2026-11-01\n")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(
                [
                    "doctor",
                    "--scope",
                    "hub",
                    "--hub",
                    str(hub),
                    "--state-dir",
                    str(state),
                ]
            )
        text = out.getvalue()
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn("- Projects: **3** (scanned roots: 0)", text)
        self.assertNotIn("> Workspaces:", text)

    def test_hub_scan_covers_extended_areas(self) -> None:
        hub = self.fx.tmp / "extended-hub"
        write(hub / "AGENTS.md", "# Hub\n")
        write(hub / "knowledge" / "README.md", "# Knowledge\n")
        write(hub / "projects" / "_registry.md", "# Registry\n\n**最后更新**: 2026-11-03\n")
        write(hub / "tools" / "README.md", "# Tools\n")
        write(hub / "manuals" / "catalog.json", "{}\n")
        write(hub / "cron-tasks" / "README.md", "# Cron\n")
        write(hub / "openspec" / "changes" / "x.md", "# Change\n")
        write(hub / "archive" / "old.md", "# Old\n")
        write(hub / "strategy.md", "# Strategy\n")
        config = ScanConfig(
            home=self.fx.tmp / "extended-home",
            hub=hub,
            roots=[],
            state_dir=self.fx.tmp / "extended-state",
            plugin_root=ROOT,
            max_depth=3,
            scope="hub",
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        rels = {item["rel"] for item in registry["artifacts"]}
        for rel in (
            "manuals/catalog.json",
            "cron-tasks/README.md",
            "openspec/changes/x.md",
            "archive/old.md",
            "strategy.md",
        ):
            self.assertIn(rel, rels)

    def test_state_freshness_uses_filename_date(self) -> None:
        hub = self.fx.tmp / "dated-hub"
        write(hub / "AGENTS.md", "# Hub\n")
        write(hub / "knowledge" / "README.md", "# Knowledge\n")
        write(hub / "projects" / "_registry.md", "# Registry\n\n**最后更新**: 2026-11-03\n")
        write(hub / "tools" / "README.md", "# Tools\n")
        write(hub / "handoff" / "20261101-1200-demo.md", "# Handoff\n")
        config = ScanConfig(
            home=self.fx.tmp / "dated-home",
            hub=hub,
            roots=[],
            state_dir=self.fx.tmp / "dated-state",
            plugin_root=ROOT,
            max_depth=3,
            scope="hub",
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        policy = run_policy(registry, config)
        self.assertEqual(policy["stats"]["state_docs_total"], 2)
        self.assertEqual(policy["stats"]["state_docs_fresh"], 2)
        self.assertNotIn("stale-state", {item["rule"] for item in policy["findings"]})

    def test_state_freshness_falls_back_to_git_commit_date(self) -> None:
        import subprocess

        hub = self.fx.hub
        write(hub / "projects" / "p.md", "# Project P\n\n**状态**: active\n")
        subprocess.run(["git", "init", "-q", str(hub)], check=True)
        subprocess.run(["git", "-C", str(hub), "add", "-A"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(hub),
                "-c",
                "user.email=test@example.com",
                "-c",
                "user.name=test",
                "commit",
                "-q",
                "-m",
                "init",
            ],
            check=True,
        )
        registry = self.fx.registry()
        policy = run_policy(registry, self.fx.config())
        self.assertGreaterEqual(policy["stats"]["state_docs_fresh_from_git"], 1)
        rules = {item["rule"] for item in policy["findings"]}
        self.assertNotIn("stale-state", rules)

    def test_credential_registry_tracks_registered_and_missing_files(self) -> None:
        write(
            self.fx.home / ".agents" / "credentials" / "registry.md",
            "# 凭据索引\n\n"
            "| ID | 归属 | 站点 | 账号 | 类型 | 存放位置 | 变量名 | 使用方 | 状态 |\n"
            "|---|---|---|---|---|---|---|---|---|\n"
            "| t1 | company | Token | me | 令牌 | ~/.zcode/secrets/token | - | tool | canonical |\n"
            "| t2 | personal | Gone | me | 口令 | ~/.zcode/secrets/gone.env | - | tool | canonical |\n",
        )
        registry = self.fx.registry()
        policy = run_policy(registry, self.fx.config())
        stats = policy["stats"]
        self.assertEqual(stats["credentials_registered"], 2)
        self.assertEqual(stats["credentials_by_scope"]["company"], 1)
        self.assertEqual(stats["credentials_missing"], 1)
        rules = {item["rule"] for item in policy["findings"]}
        self.assertIn("secret-undeclared", rules)
        self.assertIn("secret-missing", rules)

    def test_extract_pointers_ignores_file_templates(self) -> None:
        text = (
            "产出 `sites/sNNN.md`、`videos/vNNN.md`、`media/NNN.mp4`，"
            "日报 `Guster/reports/daily-YYYY-MM-DD.md`，草稿 `content/zhihu/draft-NNN.md`，"
            "模板 `./0X-xxx.md`。\n"
            "真正的指针 `plans/real-plan.md` 仍要保留。\n"
        )
        self.assertEqual(extract_pointers(text), ["plans/real-plan.md"])

    def test_home_agents_state_dir_is_not_a_project(self) -> None:
        home = self.fx.tmp / "fresh-home"
        write(home / ".agents" / "guster" / "config.json", "{}\n")
        config = ScanConfig(
            home=home,
            hub=None,
            roots=[home],
            state_dir=self.fx.tmp / "fresh-state",
            plugin_root=ROOT,
            max_depth=3,
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        self.assertEqual(registry["projects"], [])
        policy = run_policy(registry, config)
        self.assertNotIn("misplaced-artifact", {item["rule"] for item in policy["findings"]})

    def test_home_with_agents_md_is_still_a_project(self) -> None:
        home = self.fx.tmp / "project-home"
        write(home / "AGENTS.md", "# Home project\n")
        config = ScanConfig(
            home=home,
            hub=None,
            roots=[home],
            state_dir=self.fx.tmp / "project-home-state",
            plugin_root=ROOT,
            max_depth=3,
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        self.assertEqual([project["path"] for project in registry["projects"]], [str(home)])

    def test_project_and_hub_index_pointers_are_checked(self) -> None:
        write(self.fx.project / ".agents" / "README.md", "# Index\n\n| `plans/gone.md` |\n")
        write(self.fx.hub / "knowledge" / "README.md", "# Knowledge\n\n| `general/gone.md` |\n")
        policy = run_policy(self.fx.registry(), self.fx.config())
        paths = {item["path"] for item in policy["findings"] if item["rule"] == "broken-pointer"}
        self.assertIn(str(self.fx.project / ".agents" / "README.md"), paths)
        self.assertIn(str((self.fx.hub / "knowledge" / "README.md").resolve()), paths)

    def test_extract_pointers_counts_each_target_once(self) -> None:
        text = "See [`knowledge/a.md`](knowledge/a.md) and `knowledge/b.md`.\n"
        self.assertEqual(extract_pointers(text), ["knowledge/a.md", "knowledge/b.md"])

    def test_extract_pointers_ignores_home_paths_in_remote_commands(self) -> None:
        text = (
            "mini 上跑法：`ssh mini` 后 "
            "`VIDEOEDIT_FFMPEG=~/videoedit/bin/ffmpeg python3 ~/videoedit/videoedit.py run`\n"
            "本机路径 `~/.agents/skills/watch-video` 仍然校验。\n"
        )
        self.assertEqual(extract_pointers(text), ["~/.agents/skills/watch-video"])

    def test_extract_naked_pointers_flags_prose_paths_only(self) -> None:
        text = (
            "Naked ones: read docs/setup.md first, then 见tools/run.py:42 直接跑。\n"
            "Covered ones: [`wiki/a.md`](wiki/a.md) and `wiki/b.md` stay invisible.\n"
            "Noise: https://example.com/page.md, draft-NNN.md, package.json, "
            "and the bare directory ~/work/some-repo are not file pointers.\n"
        )
        self.assertEqual(extract_naked_pointers(text), ["docs/setup.md", "tools/run.py"])

    def test_extract_naked_pointers_ignores_code_and_links_entirely(self) -> None:
        text = (
            "```bash\npython3 tools/run.py docs/setup.md\n```\n"
            "Link [setup](docs/setup.md) and code `tools/run.py` are covered forms.\n"
        )
        self.assertEqual(extract_naked_pointers(text), [])

    def test_naked_pointer_finding_fires_on_instruction_docs(self) -> None:
        write(self.fx.project / "AGENTS.md", "# Project\n\nBefore coding read docs/setup.md.\n")
        policy = run_policy(self.fx.registry(), self.fx.config())
        hits = [item for item in policy["findings"] if item["rule"] == "naked-pointer"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "medium")
        self.assertEqual(hits[0]["evidence"]["paths"], ["docs/setup.md"])
        self.assertEqual(policy["stats"]["naked_pointers"], 1)

    def test_waivers_silence_only_the_named_rule_and_path(self) -> None:
        write(
            self.fx.hub / "hub.yaml",
            "name: Test Hub\nschema: 1\nprofile: full\n"
            "doctor:\n"
            "  waivers:\n"
            "    - rule: broken-pointer\n"
            f"      path: {self.fx.project}\n"
            "      reason: upstream-owned AGENTS.md\n",
        )
        policy = run_policy(self.fx.registry(), self.fx.config())
        rules = {item["rule"] for item in policy["findings"]}
        self.assertNotIn("broken-pointer", rules)
        self.assertIn("misplaced-artifact", rules)
        self.assertEqual(len(policy["waived"]), 1)
        self.assertEqual(policy["waived"][0]["waiver_reason"], "upstream-owned AGENTS.md")

    def test_waiver_without_reason_fails_loud(self) -> None:
        write(
            self.fx.hub / "hub.yaml",
            "profile: full\ndoctor:\n  waivers:\n    - rule: broken-pointer\n",
        )
        with self.assertRaises(ValueError):
            run_policy(self.fx.registry(), self.fx.config())

    def test_chi_is_the_documented_weighted_sum(self) -> None:
        registry = {"scope": "machine", "topics": {"total": 10, "multi": 2}}
        stats = {
            "resident_bytes": 10_000,
            "skill_chars": 3_000,
            "agents_dirs_total": 10,
            "agents_dirs_compliant": 9,
            "agents_indexed": 9,
            "knowledge_total": 10,
            "knowledge_indexed": 8,
            "state_docs_total": 10,
            "state_docs_fresh": 6,
            "pointers_checked": 10,
            "pointers_valid": 5,
            "secret_total": 4,
            "secret_undeclared_outside": 1,
            "secret_in_git": 0,
            "secret_tracking_unknown": 0,
            "inline_bearers": 0,
            "governance_docs": 4,
        }
        metrics = compute_metrics(registry, {"stats": stats})
        self.assertEqual(metrics["scores"]["ssr"], 80.0)
        self.assertEqual(metrics["scores"]["rbr"], 100.0)
        self.assertEqual(metrics["scores"]["pcr"], 90.0)
        self.assertEqual(metrics["scores"]["icr"], 85.0)
        self.assertEqual(metrics["scores"]["frs"], 60.0)
        self.assertEqual(metrics["scores"]["phr"], 50.0)
        self.assertEqual(metrics["scores"]["sir"], 75.0)
        expected = (
            0.20 * 0.8
            + 0.15 * 1.0
            + 0.15 * 0.9
            + 0.15 * 0.85
            + 0.15 * 0.6
            + 0.10 * 0.5
            + 0.10 * 0.75
        ) * 100
        self.assertAlmostEqual(metrics["chi"], expected, delta=0.1)

    def test_filename_date_only_counts_a_leading_date(self) -> None:
        self.assertEqual(extract_filename_date(Path("2026-11-05-daily.md")), "2026-11-05")
        self.assertEqual(extract_filename_date(Path("20261101-1200-demo.md")), "2026-11-01")
        self.assertEqual(extract_filename_date(Path("ticket-20261105-notes.md")), "")
        self.assertEqual(extract_filename_date(Path("2026-13-45-nope.md")), "")

    def test_verified_date_ignores_prose_below_the_header(self) -> None:
        body = "\n".join(["# Doc", ""] + ["filler"] * 60 + ["见 old.md，最后更新：2020-01-01"])
        self.assertEqual(extract_verified_date(body), "")
        self.assertEqual(
            extract_verified_date("# Doc\n\n**最后更新**: 2026-02-01\n"), "2026-02-01"
        )

    def test_directory_pointers_are_checked(self) -> None:
        self.assertEqual(extract_pointers("见 `knowledge/general/`"), ["knowledge/general/"])

    def test_registered_outside_credentials_do_not_lower_sir(self) -> None:
        project = self.fx.tmp / "plain-project"
        write(project / "AGENTS.md", "# Plain\n")
        env_path = project / ".env"
        write(env_path, "TOKEN=x\n")
        write(
            self.fx.home / ".agents" / "credentials" / "registry.md",
            "# 凭据索引\n\n"
            "| ID | 归属 | 站点 | 账号 | 类型 | 存放位置 | 变量名 | 使用方 | 状态 |\n"
            "|---|---|---|---|---|---|---|---|---|\n"
            f"| t1 | company | Local | me | env | {env_path} | - | tool | canonical |\n",
        )
        config = ScanConfig(
            home=self.fx.home,
            hub=self.fx.hub,
            roots=[project],
            state_dir=self.fx.tmp / "plain-state",
            plugin_root=ROOT,
            max_depth=3,
            scope="project",
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        policy = run_policy(registry, config)
        stats = policy["stats"]
        self.assertEqual(stats["secret_total"], 1)
        self.assertEqual(stats["secret_undeclared_outside"], 0)
        self.assertEqual(stats["secret_tracking_unknown"], 0)
        metrics = compute_metrics(registry, policy)
        self.assertEqual(metrics["scores"]["sir"], 50.0)

    def test_failed_git_probe_is_loud_and_fails_closed(self) -> None:
        registry = self.fx.registry()
        policy = run_policy(registry, self.fx.config())
        rules = {item["rule"] for item in policy["findings"]}
        self.assertIn("git-unavailable", rules)
        self.assertEqual(policy["stats"]["secret_tracking_unknown"], 1)
        self.assertEqual([project["git_state"] for project in registry["projects"]], ["error"])

    def test_env_files_are_found_beyond_one_level(self) -> None:
        deep = self.fx.project / "server" / "config" / ".env"
        write(deep, "TOKEN=x\n")
        registry = self.fx.registry()
        paths = {item["path"] for item in registry["secrets"]["files"]}
        self.assertIn(str(deep), paths)

    def test_status_reports_the_snapshot_instead_of_mixing_a_stale_scan(self) -> None:
        state = self.fx.tmp / "status-state"
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(self.fx.home)}):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                first = cli.main(
                    ["scan", "--root", str(self.fx.workspace), "--hub", str(self.fx.hub), "--state-dir", str(state)]
                )
                second = cli.main(
                    ["status", "--root", str(self.fx.workspace), "--hub", str(self.fx.hub), "--state-dir", str(state)]
                )
        self.assertEqual(first, 0)
        self.assertEqual(second, 0)
        self.assertIn("cached registry", out.getvalue())

    def test_score_fail_under_gates_the_exit_code(self) -> None:
        state = self.fx.tmp / "gate-state"
        argv = ["score", "--root", str(self.fx.workspace), "--hub", str(self.fx.hub), "--state-dir", str(state), "--no-write"]
        with mock.patch.dict(os.environ, {"HOME": str(self.fx.home)}):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                passing = cli.main(argv + ["--fail-under", "0"])
                failing = cli.main(argv + ["--fail-under", "100"])
        self.assertEqual(passing, 0)
        self.assertEqual(failing, 2)

    def test_workspace_container_is_not_scored_as_a_project(self) -> None:
        ws = self.fx.tmp / "ws"
        write(ws / "AGENTS.md", "# Workspace\n")
        write(ws / ".agents" / "plans" / "p.md", "# Plan\n")
        inner = ws / "inner"
        (inner / ".git").mkdir(parents=True)
        write(inner / "AGENTS.md", "# Inner\n")
        write(inner / ".agents" / "README.md", "# Index\n")
        for slot in ("plans", "wiki", "evidence", "skills", "tmp", "archive"):
            (inner / ".agents" / slot).mkdir(parents=True, exist_ok=True)
        config = ScanConfig(
            home=self.fx.home,
            hub=None,
            roots=[ws],
            state_dir=self.fx.tmp / "ws-state",
            plugin_root=ROOT,
            max_depth=3,
            scope="project",
            now="2026-11-03T00:00:00+08:00",
        )
        registry = scan(config)
        containers = [Path(p["path"]).name for p in registry["projects"] if p["container"]]
        self.assertEqual(containers, ["ws"])
        self.assertEqual(registry["summary"]["containers"], 1)
        policy = run_policy(registry, config)
        self.assertEqual(policy["stats"]["agents_dirs_total"], 1)
        self.assertEqual(policy["stats"]["agents_dirs_compliant"], 1)
        metrics = compute_metrics(registry, policy)
        self.assertEqual(metrics["scores"]["pcr"], 100.0)
        report = render_report(registry, policy, metrics)
        self.assertIn("Projects: **1** (workspace containers: 1)", report)

    def test_placement_reasons_are_reported(self) -> None:
        registry = self.fx.registry()
        policy = run_policy(registry, self.fx.config())
        stats = policy["stats"]
        self.assertEqual(stats["agents_dirs_total"], 1)
        self.assertEqual(stats["agents_dirs_compliant"], 0)
        self.assertEqual(
            stats["agents_dirs_missing_slots"]
            + stats["agents_dirs_missing_index"]
            + stats["agents_dirs_extra_entries"],
            stats["agents_dirs_total"] - stats["agents_dirs_compliant"],
        )
        metrics = compute_metrics(registry, policy)
        report = render_report(registry, policy, metrics)
        self.assertIn("0/1 compliant", report)

    def test_local_wiki_ignores_compatibility_symlinks(self) -> None:
        wiki = self.fx.home / ".agents" / "wiki"
        write(wiki / "code-standards" / "api.md", "# API\n")
        (wiki / "api-alias.md").symlink_to(wiki / "code-standards" / "api.md")
        names = [
            Path(item["path"]).name
            for item in scan_local_wiki(self.fx.home, {})
        ]
        self.assertIn("api.md", names)
        self.assertNotIn("api-alias.md", names)


class PlanValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="guster-plan-test-"))
        self.state = self.tmp / "state"
        self.home = self.tmp / "home"
        self.home.mkdir()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_load_plan_rejects_non_object(self) -> None:
        path = self.tmp / "list-plan.json"
        write(path, "[]")
        with self.assertRaises(ValueError):
            load_plan(path)

    def test_preflight_reports_malformed_operations(self) -> None:
        errors = preflight({"operations": [{"kind": "move"}]})
        self.assertEqual(errors, ["op 1: move needs string field(s): src, dst"])
        errors = preflight({"operations": [{"kind": ["move"]}]})
        self.assertEqual(errors, ["op 1: missing operation kind"])

    def test_apply_reports_a_non_object_plan_without_a_traceback(self) -> None:
        path = self.tmp / "list-plan.json"
        write(path, "[]")
        code, _, err = self.run_cli(["apply", str(path), "--state-dir", str(self.state)])
        self.assertEqual(code, 1)
        self.assertIn("plan must be a JSON object", err)
        self.assertNotIn("Traceback", err)

    def test_apply_reports_a_malformed_operation_without_a_traceback(self) -> None:
        path = self.tmp / "bad-op.json"
        write(path, json.dumps({"version": 1, "operations": [{"kind": "move"}]}))
        code, out, err = self.run_cli(["apply", str(path), "--state-dir", str(self.state)])
        self.assertEqual(code, 4)
        self.assertIn("move needs string field(s): src, dst", out)
        self.assertNotIn("Traceback", err)

    def test_apply_reports_an_unreadable_plan_path(self) -> None:
        code, _, err = self.run_cli(["apply", str(self.tmp), "--state-dir", str(self.state)])
        self.assertEqual(code, 1)
        self.assertIn("cannot read plan", err)
        self.assertNotIn("Traceback", err)

    def test_apply_labels_a_refused_plan_as_failed(self) -> None:
        path = self.tmp / "refused-plan.json"
        write(
            path,
            json.dumps(
                {
                    "version": 1,
                    "operations": [
                        {"kind": "move", "src": str(self.tmp / "missing"), "dst": str(self.tmp / "moved")}
                    ],
                }
            ),
        )
        code, out, _ = self.run_cli(
            ["apply", str(path), "--yes", "--state-dir", str(self.state)]
        )
        self.assertEqual(code, 4)
        self.assertIn("FAILED", out)
        self.assertNotIn("APPLIED", out)

    def test_apply_accepts_an_explicit_dry_run(self) -> None:
        target = self.tmp / "created"
        path = self.tmp / "mkdir-plan.json"
        write(path, json.dumps({"version": 1, "operations": [{"kind": "mkdir", "path": str(target)}]}))
        code, out, _ = self.run_cli(
            ["apply", str(path), "--dry-run", "--state-dir", str(self.state)]
        )
        self.assertEqual(code, 0)
        self.assertIn("DRY RUN", out)
        self.assertFalse(target.exists())

    def test_apply_rejects_dry_run_together_with_yes(self) -> None:
        path = self.tmp / "plan.json"
        write(path, json.dumps({"version": 1, "operations": []}))
        code, _, err = self.run_cli(
            ["apply", str(path), "--dry-run", "--yes", "--state-dir", str(self.state)]
        )
        self.assertEqual(code, 1)
        self.assertIn("mutually exclusive", err)

    def test_build_config_rejects_a_missing_root(self) -> None:
        missing = self.tmp / "missing-root"
        args = cli.build_parser().parse_args(
            ["scan", "--root", str(missing), "--state-dir", str(self.state)]
        )
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            with self.assertRaises(ValueError) as caught:
                cli.build_config(args)
        self.assertIn("workspace root does not exist", str(caught.exception))

    def test_build_config_rejects_a_corrupt_config(self) -> None:
        write(self.state / "config.json", "{broken")
        args = cli.build_parser().parse_args(["scan", "--state-dir", str(self.state)])
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            with self.assertRaises(ValueError) as caught:
                cli.build_config(args)
        self.assertIn("cannot read Guster config", str(caught.exception))


class ExtraSkillRootTests(unittest.TestCase):
    def test_parses_extra_roots_from_env(self):
        value = os.pathsep.join(["alpha=/tmp/a", "beta=/tmp/b"])
        with mock.patch.dict(os.environ, {"GUSTER_EXTRA_SKILL_ROOTS": value}):
            roots = extra_skill_roots()
        self.assertEqual(roots, [("alpha", Path("/tmp/a")), ("beta", Path("/tmp/b"))])

    def test_ignores_malformed_entries(self):
        value = os.pathsep.join(["oops", "=missing-name", "name=", "good=/tmp/g"])
        with mock.patch.dict(os.environ, {"GUSTER_EXTRA_SKILL_ROOTS": value}):
            roots = extra_skill_roots()
        self.assertEqual(roots, [("good", Path("/tmp/g"))])


class StructuredNoteHeaderTests(unittest.TestCase):
    """CTX-09: opt-in structured note headers (Obsidian properties convention)."""

    def setUp(self) -> None:
        self.fx = Fixture()

    def tearDown(self) -> None:
        self.fx.cleanup()

    def _note(self, rel: str, text: str) -> None:
        write(self.fx.hub / "knowledge" / "general" / rel, text)

    def _policy(self):
        return run_policy(self.fx.registry(), self.fx.config())

    def test_parse_note_header_variants(self) -> None:
        from guster.util import parse_note_header

        self.assertIsNone(parse_note_header("# No front-matter\n"))
        self.assertIsNone(parse_note_header("---\ntitle: x\n---\n"))  # no type: not opted in
        header = parse_note_header(
            "---\ntype: pointer\nupdated: 2026-11-09\ntags:\n- a\n- b\n---\n"
        )
        self.assertEqual(header["type"], "pointer")
        self.assertEqual(header["tags"], ["a", "b"])
        self.assertEqual(note_header_date(header), "2026-11-09")
        bad = parse_note_header("---\ntype: pointer\nupdated: 2026-11-09\n")
        self.assertTrue(bad and bad.get("_malformed"))  # fence never closed
        bad_line = parse_note_header("---\ntype: pointer\nnot a pair\n---\n")
        self.assertTrue(bad_line and bad_line.get("_malformed"))
        foam = parse_note_header('---\ntype: "[[pointer]]"\ndate: 2026-11-09\n---\n')
        self.assertEqual(foam["type"], "[[pointer]]")  # Foam-style link value accepted

    def test_well_formed_header_counts_and_passes(self) -> None:
        self._note(
            "card.md",
            "---\ntype: pointer\nupdated: 2026-11-09\n---\n\n# Card\n\n"
            "Truth: [a note](a.md).\n",
        )
        policy = self._policy()
        self.assertGreaterEqual(policy["stats"]["note_headers_total"], 1)
        self.assertFalse(
            [f for f in policy["findings"] if f["rule"] == "note-header-malformed"]
        )

    def test_header_without_date_is_malformed(self) -> None:
        self._note("nodate.md", "---\ntype: fact\n---\n\n# No date\n")
        policy = self._policy()
        hits = [
            f for f in policy["findings"]
            if f["rule"] == "note-header-malformed" and "nodate.md" in f["path"]
        ]
        self.assertEqual(len(hits), 1)
        self.assertIn("date", hits[0]["message"])

    def test_structured_note_body_links_join_pointer_scan(self) -> None:
        self._note(
            "deadlink.md",
            "---\ntype: pointer\nupdated: 2026-11-09\n---\n\n# Dead\n\n"
            "Truth: [missing](./missing.md).\n",
        )
        policy = self._policy()
        hits = [
            f for f in policy["findings"]
            if f["rule"] == "broken-pointer" and "deadlink.md" in f["path"]
        ]
        self.assertEqual(len(hits), 1)

    def test_plain_note_without_header_stays_untouched(self) -> None:
        self._note("plain.md", "# Plain prose\n\nMentions nope/missing.md path?\n")
        policy = self._policy()
        self.assertFalse(
            [f for f in policy["findings"] if "plain.md" in f.get("path", "")]
        )

    def test_parse_note_header_opt_in_wins_over_malformed(self) -> None:
        from guster.util import parse_note_header

        # CTX-09: no type: declared -> not opted in -> None, never malformed,
        # whatever the fence looks like (legacy prose notes must stay silent).
        for text in (
            "---\ntitle: x\n",                              # fence never closed
            "---\nsome prose here\nmore prose\n---\n",      # prose inside the fence
            "----\ntitle: x\n----\n",                       # four-dash opener is no fence
            "----\ntype: pointer\n----\n",                  # same, even with a type line
            "---\nplain prose line\n---\n",                 # non key:value line
        ):
            self.assertIsNone(parse_note_header(text), text)
        # Opted-in headers keep reporting malformedness.
        bad = parse_note_header("---\ntype: pointer\nupdated: 2026-11-09\n")
        self.assertTrue(bad and bad.get("_malformed"))
        bad = parse_note_header("---\ntype: pointer\nnot a pair\n---\n")
        self.assertTrue(bad and bad.get("_malformed"))

    def test_prose_fence_note_without_type_is_not_flagged(self) -> None:
        self._note("prose.md", "---\nsome prose here\nmore prose\n---\n\n# Prose\n")
        policy = self._policy()
        self.assertFalse(
            [f for f in policy["findings"] if f["rule"] == "note-header-malformed"]
        )
        self.assertEqual(policy["stats"].get("note_headers_total", 0), 0)

    def test_parse_note_header_supports_block_scalars(self) -> None:
        from guster.util import parse_note_header

        literal = parse_note_header(
            "---\ntype: pointer\nupdated: |\n  2026-11-11\n---\n\nbody\n"
        )
        self.assertIsNotNone(literal)
        self.assertEqual(literal["updated"], "2026-11-11")
        self.assertEqual(note_header_date(literal), "2026-11-11")
        folded = parse_note_header("---\ntype: pointer\nupdated: >\n  2026-11-11\n---\n")
        self.assertEqual(folded["updated"], "2026-11-11")

    def test_block_scalar_note_counts_and_passes(self) -> None:
        self._note(
            "block.md",
            "---\ntype: pointer\nupdated: |\n  2026-11-09\n---\n\n# Block\n\n"
            "Truth: [a note](a.md).\n",
        )
        policy = self._policy()
        self.assertGreaterEqual(policy["stats"]["note_headers_total"], 1)
        self.assertFalse(
            [f for f in policy["findings"] if f["rule"] == "note-header-malformed"]
        )



class DeclarativeHubZoneTests(unittest.TestCase):
    """Schema-2 hubs and machine zones: declared, not prescribed."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="guster-decl-"))
        self.hub = self.tmp / "hub"
        self.state = self.tmp / "state"
        self.home = self.tmp / "home"
        self.home.mkdir()
        init_hub(self.hub, self.state, yes=True, dry_run=False)

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def _manifest(self) -> Path:
        return self.hub / "hub.yaml"

    def _scan_config(self, **overrides) -> ScanConfig:
        values = dict(
            home=self.home,
            hub=self.hub,
            roots=[],
            state_dir=self.state,
            plugin_root=ROOT,
            max_depth=3,
            now="2026-11-14T00:00:00+08:00",
        )
        values.update(overrides)
        return ScanConfig(**values)

    def test_schema2_hub_without_tools_validates(self) -> None:
        manifest = self._manifest().read_text(encoding="utf-8")
        self.assertIn("schema_version: 2", manifest)
        manifest = "\n".join(
            line for line in manifest.splitlines() if not line.startswith("  tools:")
        )
        self._manifest().write_text(manifest, encoding="utf-8")
        info = validate_hub(self.hub)
        self.assertTrue(info["ok"], info["errors"])
        self.assertNotIn("tools", info["paths"])

    def test_schema2_external_tools_section(self) -> None:
        external = self.tmp / "external-tools"
        write(external / "README.md", "# External tools\n")
        write(external / "wrench" / "AGENTS.md", "# Wrench\n")
        write(external / "wrench" / "README.md", "# Wrench readme\n")
        manifest = self._manifest().read_text(encoding="utf-8").replace(
            "  tools: tools", f"  tools: {external}"
        )
        self._manifest().write_text(manifest, encoding="utf-8")
        info = validate_hub(self.hub)
        self.assertTrue(info["ok"], info["errors"])
        # External sections belong to the machine view: a hub-scoped run
        # filters artifacts it cannot raise findings about.
        registry = scan(self._scan_config())
        tool_paths = [
            item["path"]
            for item in registry["artifacts"]
            if item.get("kind") == "tool" and item.get("scope") == "project"
        ]
        self.assertTrue(any(path.startswith(str(external.resolve())) for path in tool_paths))

    def test_schema2_missing_core_section_rejected(self) -> None:
        manifest = self._manifest().read_text(encoding="utf-8")
        manifest = "\n".join(
            line for line in manifest.splitlines() if not line.startswith("  knowledge:")
        )
        self._manifest().write_text(manifest, encoding="utf-8")
        info = validate_hub(self.hub)
        self.assertFalse(info["ok"])
        self.assertTrue(any("knowledge" in item for item in info["errors"]))

    def test_machine_zone_light_scan_governs_without_slots(self) -> None:
        zone = self.tmp / "zones" / "tools"
        write(
            zone / "common" / "hammer" / "AGENTS.md",
            "# Hammer\n\nSee ~/zones/tools/common/hammer/gone.md for details.\n",
        )
        write(zone / "common" / "hammer" / "README.md", "# Hammer readme\n")
        write(zone / "company" / "saw" / "README.md", "# Saw readme\n")
        write(zone / "company" / "saw" / ".env", "TOKEN=not-a-real-token\n")
        config = self._scan_config(
            zones=[{"path": str(zone), "profile": "light"}],
        )
        registry = scan(config)
        self.assertEqual(registry["zones"][0]["tools"], 2)
        zone_artifacts = [
            item for item in registry["artifacts"] if item.get("scope") == "zone"
        ]
        self.assertEqual(len(zone_artifacts), 3)
        secret_paths = {item["path"] for item in registry["secrets"]["files"]}
        self.assertTrue(any(path.endswith("saw/.env") for path in secret_paths))
        policy = run_policy(registry, config)
        reached = [
            item
            for item in policy["findings"]
            if item["rule"] == "naked-pointer" and "hammer" in item["path"]
        ]
        self.assertTrue(
            reached,
            "zone entry docs must reach pointer checks: the naked ~/path in the "
            "AGENTS.md is only findable if the zone artifact was scanned",
        )

    def test_default_roots_uses_generic_candidates_without_home_fallback(self) -> None:
        (self.home / "IdeaProjects").mkdir()
        self.assertEqual(default_roots(self.home), [])
        (self.home / "code").mkdir()
        (self.home / "dev").mkdir()
        self.assertEqual([root.name for root in default_roots(self.home)], ["code", "dev"])
        (self.home / "Projects").mkdir()
        self.assertEqual(
            [root.name for root in default_roots(self.home)],
            ["Projects", "code", "dev"],
        )

    def test_zone_config_fails_loud_on_missing_path(self) -> None:
        from argparse import Namespace

        self.state.mkdir(parents=True, exist_ok=True)
        (self.state / "config.json").write_text(
            json.dumps({"zones": [{"path": str(self.tmp / "nope"), "profile": "light"}]}),
            encoding="utf-8",
        )
        args = Namespace(hub=None, root=[], scope="auto", state_dir=str(self.state))
        with self.assertRaises(ValueError):
            cli.build_config(args)



class FirstRunCoreCommandTests(unittest.TestCase):
    """0.9.0 phase 1: first-run detection, config discipline, check/zones."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="guster-p1-"))
        self.home = self.tmp / "home"
        self.code = self.home / "code"
        self.proj = self.code / "app"
        (self.proj / ".git").mkdir(parents=True)
        write(self.proj / "AGENTS.md", "# App\n")
        write(self.proj / ".agents" / "README.md", "# Index\n")
        self.state = self.tmp / "state"

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, argv, home=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(home or self.home)}):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def write_config(self, payload) -> None:
        self.state.mkdir(parents=True, exist_ok=True)
        (self.state / "config.json").write_text(json.dumps(payload), encoding="utf-8")

    def scan_state(self):
        return self.run_cli(["scan", "--state-dir", str(self.state)])

    def test_first_run_status_auto_scans_code_with_banner(self) -> None:
        code, out, err = self.run_cli(["status", "--state-dir", str(self.state)])
        self.assertEqual(code, 0, err)
        self.assertIn(f"workspaces: {self.code}", out)
        self.assertIn("auto-scanning", out)
        self.assertIn("`guster init`", out)
        self.assertIn("no hub attached", out)
        code, out, _ = self.run_cli(["status", "--json", "--state-dir", str(self.state)])
        data = json.loads(out)
        self.assertEqual(data["registry"]["workspaces"], [str(self.code)])

    def test_zero_candidates_fail_loud_and_point_to_init(self) -> None:
        bare = self.tmp / "bare-home"
        bare.mkdir()
        code, _, err = self.run_cli(
            ["status", "--state-dir", str(self.tmp / "bare-state")], home=bare
        )
        self.assertEqual(code, 1)
        self.assertIn("guster init --root", err)
        self.assertFalse((self.tmp / "bare-state" / "registry.json").exists())

    def test_roots_string_config_is_a_type_error_not_per_character(self) -> None:
        self.write_config({"version": 1, "roots": str(self.code)})
        code, _, err = self.scan_state()
        self.assertEqual(code, 1)
        self.assertIn("must be a list", err)
        self.assertFalse((self.state / "registry.json").exists())

    def test_roots_bad_shapes_fail_loud(self) -> None:
        cases = [
            ({"roots": []}, "at least one"),
            ({"roots": [str(self.tmp / "gone")]}, "does not exist"),
            ({"roots": ["relative/dir"]}, "absolute"),
            ({"roots": [123]}, "non-empty strings"),
            ({"roots": [str(self.code)], "hub": str(self.tmp / "gone-hub")}, "hub directory does not exist"),
        ]
        for payload, needle in cases:
            with self.subTest(payload=payload):
                self.write_config({"version": 1, **payload})
                code, _, err = self.scan_state()
                self.assertEqual(code, 1, err)
                self.assertIn(needle, err)
                self.assertFalse((self.state / "registry.json").exists())

    def test_non_object_config_fails_loud(self) -> None:
        self.state.mkdir(parents=True, exist_ok=True)
        (self.state / "config.json").write_text("[1]", encoding="utf-8")
        code, _, err = self.scan_state()
        self.assertEqual(code, 1)
        self.assertIn("must be a JSON object", err)

    def test_check_runs_the_full_chain_and_carries_doctor_exit(self) -> None:
        code, out, err = self.run_cli(
            ["check", "--root", str(self.proj), "--scope", "project", "--state-dir", str(self.state)]
        )
        self.assertEqual(code, 2, err)  # fake .git dir -> git-unavailable HIGH
        self.assertIn("# Guster Context Health", out)
        self.assertIn("Recent trend:", out)
        for name in ("registry.json", "findings.json", "metrics.jsonl"):
            self.assertTrue((self.state / name).is_file(), name)

    def test_check_clean_project_returns_zero(self) -> None:
        import subprocess

        clean = self.tmp / "clean" / "app"
        write(clean / "AGENTS.md", "# Clean\n")
        write(clean / ".agents" / "README.md", "# Index\n")
        for slot in ("plans", "wiki", "evidence", "skills", "tmp", "archive"):
            (clean / ".agents" / slot).mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(clean)], check=True)
        subprocess.run(["git", "-C", str(clean), "add", "-A"], check=True)
        subprocess.run(
            ["git", "-C", str(clean), "-c", "user.email=t@example.com", "-c", "user.name=t",
             "commit", "-q", "-m", "init"],
            check=True,
        )
        code, out, err = self.run_cli(
            ["check", "--root", str(clean), "--scope", "project", "--state-dir", str(self.state)]
        )
        self.assertEqual(code, 0, out + err)

    def test_zones_add_list_remove_roundtrip(self) -> None:
        zone = self.tmp / "tools-zone"
        write(zone / "hammer" / "AGENTS.md", "# Hammer\n")
        code, out, err = self.run_cli(["zones", "add", str(zone), "--state-dir", str(self.state)])
        self.assertEqual(code, 0, err)
        config = json.loads((self.state / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(config["zones"], [{"path": str(zone), "profile": "light"}])

        code, out, _ = self.run_cli(["zones", "list", "--state-dir", str(self.state)])
        self.assertEqual(code, 0)
        self.assertIn(str(zone), out)
        self.assertIn("profile=light", out)
        self.assertIn("tools=1", out)

        code, out, _ = self.run_cli(["scan", "--json", "--state-dir", str(self.state)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["zones"][0]["tools"], 1)

        code, _, err = self.run_cli(["zones", "add", str(zone), "--state-dir", str(self.state)])
        self.assertEqual(code, 1)
        self.assertIn("already configured", err)
        code, _, err = self.run_cli(
            ["zones", "add", str(self.tmp / "nope"), "--state-dir", str(self.state)]
        )
        self.assertEqual(code, 1)
        self.assertIn("does not exist", err)

        code, out, _ = self.run_cli(["zones", "remove", str(zone), "--state-dir", str(self.state)])
        self.assertEqual(code, 0)
        config = json.loads((self.state / "config.json").read_text(encoding="utf-8"))
        self.assertNotIn("zones", config)
        code, _, err = self.run_cli(["zones", "remove", str(zone), "--state-dir", str(self.state)])
        self.assertEqual(code, 1)
        self.assertIn("not configured", err)

    def test_zones_empty_list_is_quiet(self) -> None:
        code, out, err = self.run_cli(["zones", "list", "--state-dir", str(self.state)])
        self.assertEqual(code, 0, err)
        self.assertIn("no zones configured", out)

    def test_no_hub_status_exits_zero(self) -> None:
        code, out, err = self.run_cli(["hub", "status", "--state-dir", str(self.state)])
        self.assertEqual(code, 0, err)
        self.assertIn("no hub attached", out)
        code, out, _ = self.run_cli(["hub", "status", "--json", "--state-dir", str(self.state)])
        self.assertEqual(json.loads(out), {"attached": False, "hub": None})

    def test_hub_status_after_init_reports_manifest(self) -> None:
        hub = self.tmp / "hub"
        hub_state = self.tmp / "hub-state"
        init_hub(hub, hub_state, yes=True, dry_run=False)
        code, out, err = self.run_cli(["hub", "status", "--state-dir", str(hub_state)])
        self.assertEqual(code, 0, err)
        self.assertIn("Checks: OK", out)
        self.assertNotIn("(missing)", out)

    def test_hub_attach_hints_a_rescan(self) -> None:
        hub = self.tmp / "hint-hub"
        hub_state = self.tmp / "hint-state"
        init_hub(hub, hub_state, yes=True, dry_run=False)
        code, out, err = self.run_cli(
            ["hub", "attach", "--path", str(hub), "--state-dir", str(hub_state)]
        )
        self.assertEqual(code, 0, err)
        self.assertIn("run `guster scan` to refresh", out)

    def test_hub_init_defaults_to_a_generic_path(self) -> None:
        code, out, err = self.run_cli(["hub", "init", "--yes", "--state-dir", str(self.state)])
        self.assertEqual(code, 0, err)
        self.assertTrue((self.home / "guster-hub" / "hub.yaml").is_file())
        self.assertFalse((self.home / "IdeaProjects").exists())

    def test_validate_hub_wording_says_absent(self) -> None:
        empty = self.tmp / "empty-hub"
        empty.mkdir()
        info = validate_hub(empty)
        self.assertFalse(info["ok"])
        self.assertTrue(any("absent" in item for item in info["errors"]))
        self.assertFalse(any("missing" in item for item in info["errors"]))

    def test_scoped_status_labels_the_state_dir(self) -> None:
        code, out, err = self.run_cli(["status", "--root", str(self.proj)])
        self.assertEqual(code, 0, err)
        self.assertRegex(out, r"scope: project \(state: .*/\.agents/guster/scoped/[0-9a-f]{10}\)")
        code, out, _ = self.run_cli(["status", "--root", str(self.proj), "--json"])
        data = json.loads(out)
        self.assertEqual(data["scope"], "project")
        self.assertIn("/scoped/", data["state_dir"])

    def test_init_project_dry_run_lists_the_missing_tree(self) -> None:
        target = (self.tmp / "no" / "such" / "deep" / "proj").resolve()
        code, out, err = self.run_cli(
            ["init", "--project", str(target), "--state-dir", str(self.state)]
        )
        self.assertEqual(code, 0, err)
        self.assertIn("will be created", out)
        for missing in (target.parent.parent, target.parent, target):
            self.assertIn(str(missing), out)
        self.assertIn(f"mkdir {target / '.agents' / 'plans'}", out)
        self.assertFalse(target.exists())

    def test_bare_init_pins_detected_roots_and_requires_root_when_empty(self) -> None:
        code, out, err = self.run_cli(["init", "--yes", "--state-dir", str(self.state)])
        self.assertEqual(code, 0, err)
        config = json.loads((self.state / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(config["roots"], [str(self.code.resolve())])

        bare = self.tmp / "bare-home"
        bare.mkdir()
        code, _, err = self.run_cli(
            ["init", "--yes", "--state-dir", str(self.tmp / "bare2-state")], home=bare
        )
        self.assertEqual(code, 1)
        self.assertIn("--root", err)

        fresh_state = self.tmp / "rooted-state"
        code, out, err = self.run_cli(
            ["init", "--yes", "--root", str(self.code), "--state-dir", str(fresh_state)]
        )
        self.assertEqual(code, 0, err)
        config = json.loads((fresh_state / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(config["roots"], [str(self.code)])

    def test_doctor_report_shows_first_run_banner(self) -> None:
        code, out, err = self.run_cli(["doctor", "--state-dir", str(self.state)])
        self.assertEqual(code, 2, err)
        self.assertIn("**Unconfigured:** auto-scanning", out)
        self.assertIn("`guster init`", out)
        self.assertIn("**No hub attached**", out)


if __name__ == "__main__":
    unittest.main()
