from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from guster.discover import ScanConfig, scan, scan_credential_registry, scan_inline_bearers  # noqa: E402
from guster.policy import run_policy  # noqa: E402


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True, capture_output=True)


def commit_all(repo: Path) -> None:
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.com", "add", "-A"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "init"],
        check=True,
        capture_output=True,
    )


class Sandbox(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="guster-boundary-")).resolve()
        self.home = self.tmp / "home"
        self.workspace = self.tmp / "workspace"
        self.hub = self.tmp / "hub"
        self.home.mkdir()
        self.workspace.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def config(self, scope: str = "machine", hub: bool = False) -> ScanConfig:
        return ScanConfig(
            home=self.home,
            hub=self.hub if hub else None,
            roots=[self.workspace],
            state_dir=self.tmp / "state",
            plugin_root=ROOT,
            max_depth=3,
            scope=scope,
            now="2026-11-26T00:00:00+00:00",
        )


class HubNestedRepoBoundaryTests(Sandbox):
    """A repository checked out inside a hub section is a project, never hub
    state or knowledge: the hub walk stops at its git root."""

    def setUp(self) -> None:
        super().setUp()
        self.hub.mkdir()
        write(self.hub / "AGENTS.md", "# Hub\n")
        write(
            self.hub / "hub.yaml",
            "schema_version: 2\npaths:\n  knowledge: knowledge\n  projects: projects\n  tools: tools\n",
        )
        write(self.hub / "knowledge" / "README.md", "# Knowledge\n")
        write(self.hub / "projects" / "card.md", "# card\n")
        write(self.hub / "reports" / "r.md", "# report\n")
        for rel in (
            "projects/outer-repo",
            "projects/outer-repo/inner-repo",
            "reports/bundled-repo",
            "knowledge/general/cloned-notes",
        ):
            repo = self.hub / rel
            make_repo(repo)
            write(repo / "notes.md", "# nested\n")
            write(repo / ".agents" / "plans" / "p.md", "# nested plan\n")
        write(self.hub / "tools" / "hammer" / "AGENTS.md", "# hammer\n")
        make_repo(self.hub / "tools" / "hammer")

    def artifact_paths(self) -> list:
        return sorted(item["path"] for item in scan(self.config(scope="hub", hub=True))["artifacts"])

    def test_hub_sections_stop_at_a_nested_git_root(self) -> None:
        paths = self.artifact_paths()
        self.assertIn(str(self.hub / "projects" / "card.md"), paths)
        self.assertIn(str(self.hub / "reports" / "r.md"), paths)
        for nested in ("outer-repo", "bundled-repo", "cloned-notes"):
            self.assertFalse([p for p in paths if nested in p], nested)

    def test_a_tool_directory_stays_scanned_when_it_is_a_repository(self) -> None:
        tools = [item for item in scan(self.config(scope="hub", hub=True))["artifacts"] if item["kind"] == "tool"]
        self.assertEqual([item["path"] for item in tools], [str(self.hub / "tools" / "hammer" / "AGENTS.md")])

    def test_state_freshness_counts_hub_documents_only(self) -> None:
        stats = run_policy(scan(self.config(scope="hub", hub=True)), self.config(scope="hub", hub=True))["stats"]
        self.assertEqual(stats["state_docs_total"], 1)


class NestedRepoCredentialAttributionTests(Sandbox):
    """Which repository answers "is this file tracked": the nearest one that
    has a .git, never the enclosing workspace root. The root carries a project
    marker (package.json) and holds repositories of its own."""

    def setUp(self) -> None:
        super().setUp()
        container = self.workspace
        write(container / "package.json", '{"name": "container"}\n')
        write(container / ".env", "TOKEN=plain-container\n")
        inner = container / "inner-repo"
        make_repo(inner)
        write(inner / ".env", "TOKEN=tracked\n")
        commit_all(inner)

        outer = self.workspace / "outer-repo"
        make_repo(outer)
        write(outer / ".env", "TOKEN=outer-tracked\n")
        write(outer / "inner-repo" / "uncommitted.txt", "x\n")
        commit_all(outer)
        write(outer / "inner-repo" / ".env", "TOKEN=inner-untracked\n")

    def tracked_flags(self) -> dict:
        files = scan(self.config())["secrets"]["files"]
        return {str(Path(item["path"]).relative_to(self.workspace)): item["git_tracked"] for item in files}

    def test_the_owning_repository_answers_the_tracked_question(self) -> None:
        self.assertEqual(
            self.tracked_flags(),
            {
                ".env": False,
                "inner-repo/.env": True,
                "outer-repo/.env": True,
                "outer-repo/inner-repo/.env": False,
            },
        )

    def test_a_tracked_env_inside_a_nested_repo_is_critical(self) -> None:
        config = self.config()
        rules = {
            (item["rule"], item["path"])
            for item in run_policy(scan(config), config)["findings"]
        }
        self.assertIn(("secret-in-git", str(self.workspace / "inner-repo" / ".env")), rules)
        self.assertIn(("secret-in-git", str(self.workspace / "outer-repo" / ".env")), rules)
        self.assertNotIn(("secret-in-git", str(self.workspace / "outer-repo" / "inner-repo" / ".env")), rules)


class EnvVariantTests(Sandbox):
    def setUp(self) -> None:
        super().setUp()
        self.project = self.workspace / "proj"
        make_repo(self.project)
        write(self.project / "AGENTS.md", "# Project\n")
        for name in (".env", ".env.local", ".env.production", ".env.example", ".env.sample"):
            write(self.project / name, "TOKEN=placeholder\n")
        commit_all(self.project)

    def found(self) -> set:
        return {Path(item["path"]).name for item in scan(self.config())["secrets"]["files"]}

    def test_env_variants_are_credential_files_and_placeholders_are_not(self) -> None:
        self.assertEqual(self.found(), {".env", ".env.local", ".env.production"})

    def test_variants_tracked_by_git_are_critical(self) -> None:
        config = self.config()
        tracked = [
            Path(item["path"]).name
            for item in run_policy(scan(config), config)["findings"]
            if item["rule"] == "secret-in-git"
        ]
        self.assertEqual(sorted(tracked), [".env", ".env.local", ".env.production"])


class InlineBearerTests(Sandbox):
    def setUp(self) -> None:
        super().setUp()
        write(
            self.home / ".zcode" / "cli" / "config.json",
            json.dumps(
                {
                    "mcpServers": {
                        "acme": {
                            "env": {
                                "ACME_API_KEY": "abcdefghijklmnopqrstuvwxyz012345",
                                "apiKey": "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
                                "ACME_SECRET_KEY": "${ACME_SECRET_KEY}",
                                "tokenUrl": "https://example.com/oauth/token",
                            },
                            "headers": {"Authorization": "Bearer abcd1234"},
                        }
                    }
                }
            ),
        )
        write(
            self.home / ".codex" / "config.toml",
            '[mcp_servers.k]\napi_key = "abcdefghijklmnopqrstuvwxyz012345"\n'
            '[mcp_servers.a]\nauth = "Bearer wxyz9876"\n'
            '[mcp_servers.b]\nauth = "Bearer abcd1234"\n',
        )
        write(
            self.home / ".dsh" / "cordis.patch.yml",
            'plugins:\n  - id: x\n    auth_token: "s3cr3t-value-abcdefghij"\n',
        )

    def bearers(self, relative: str) -> dict:
        path = str(self.home / relative)
        return next(item for item in scan_inline_bearers(self.home) if item["path"] == path)

    def test_json_quoted_keys_are_detected_and_env_references_are_not(self) -> None:
        found = self.bearers(".zcode/cli/config.json")
        self.assertEqual(found["count"], 3)
        self.assertEqual(sorted(found["redacted"]), ["****", "ABCD...2345", "abcd...2345"])

    def test_a_short_value_is_masked_instead_of_reproduced(self) -> None:
        toml = self.bearers(".codex/config.toml")
        self.assertEqual(toml["count"], 3)
        self.assertEqual(sorted(toml["redacted"]), ["****", "****", "abcd...2345"])

    def test_toml_and_yaml_keys_keep_working(self) -> None:
        self.assertEqual(self.bearers(".dsh/cordis.patch.yml")["redacted"], ["s3cr...ghij"])


class RegistryCellTests(Sandbox):
    def setUp(self) -> None:
        super().setUp()
        self.env = self.home / ".agents" / "credentials" / "example-host.env"
        write(self.env, "EXAMPLE_HOST_TOKEN=not-a-real-value\n")
        write(
            self.home / ".agents" / "credentials" / "registry.md",
            "| ID | scope | site | account | kind | locations | keys | used_by | status |\n"
            "|---|---|---|---|---|---|---|---|---|\n"
            "| example-host | personal | example.com | me@example.com | token | "
            "`~/.agents/credentials/example-host.env` | `EXAMPLE_HOST_TOKEN` | my-cli | active |\n",
        )

    def test_backticked_cells_read_as_paths_and_names(self) -> None:
        entry = scan_credential_registry(self.home)["entries"][0]
        self.assertEqual(entry["locations"], "~/.agents/credentials/example-host.env")
        self.assertEqual(entry["keys"], "EXAMPLE_HOST_TOKEN")

    def test_the_documented_registry_row_declares_its_file(self) -> None:
        config = self.config()
        policy = run_policy(scan(config), config)
        rules = {item["rule"] for item in policy["findings"]}
        self.assertNotIn("secret-missing", rules)
        self.assertNotIn("secret-undeclared", rules)
        self.assertEqual(policy["stats"]["secret_undeclared_outside"], 0)


class ExtraSkillRootTests(Sandbox):
    def test_a_relative_host_directory_fails_loud(self) -> None:
        from guster.discover import extra_skill_roots

        (self.workspace / "relskills").mkdir()
        with mock.patch.dict(os.environ, {"GUSTER_EXTRA_SKILL_ROOTS": f"mine=relskills"}):
            with self.assertRaises(ValueError) as caught:
                extra_skill_roots()
        self.assertIn("absolute path", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
