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
from guster.discover import ScanConfig, extra_skill_roots, scan, scan_local_wiki  # noqa: E402
from guster.executor import apply_plan, init_home, preflight  # noqa: E402
from guster.hub import attach_hub, init_hub, validate_hub  # noqa: E402
from guster.metrics import compute_metrics  # noqa: E402
from guster.planner import load_plan, plan_init_project, plan_move  # noqa: E402
from guster.policy import extract_filename_date, extract_verified_date, run_policy  # noqa: E402
from guster.report import render_report  # noqa: E402
from guster.util import extract_pointers  # noqa: E402


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

    def test_dry_run_does_not_write(self) -> None:
        target = self.fx.tmp / "dry-project"
        plan = plan_init_project(target)
        result = apply_plan(plan, self.fx.state, dry_run=True, yes=False)
        self.assertTrue(result["dry_run"])
        self.assertFalse((target / ".agents").exists())

    def test_init_home_writes_roots_from_the_current_home(self) -> None:
        state = self.fx.tmp / "fresh-state"
        home = self.fx.tmp / "fresh-home"
        home.mkdir()
        result = init_home(state, yes=True, dry_run=False, home=home)
        self.assertTrue(result["ok"])
        config = json.loads((state / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(config["roots"], [str(home.resolve())])
        self.assertNotIn("~", json.dumps(config))

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


if __name__ == "__main__":
    unittest.main()
