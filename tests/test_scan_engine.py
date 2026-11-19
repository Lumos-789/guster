from __future__ import annotations

import contextlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from guster import cli  # noqa: E402
from guster.discover import ScanConfig, scan  # noqa: E402
from guster.hub import init_hub  # noqa: E402
from guster.policy import run_policy  # noqa: E402
from guster.util import is_indexed  # noqa: E402


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


REDACTED_SHAPE = re.compile(r"^[A-Za-z0-9._\-]{1,4}\.\.\.[A-Za-z0-9._\-]{1,4}$")


class ScanEngineSandbox(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="guster-scan-"))
        self.home = self.tmp / "home"
        self.ws = self.tmp / "ws"
        self.state = self.tmp / "state"
        for base in (self.home, self.ws, self.state):
            base.mkdir(parents=True)

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def scan_argv(self, *extra):
        return [
            "scan", "--json", "--scope", "machine", "--root", str(self.ws),
            "--state-dir", str(self.state), *extra,
        ]

    def doctor_argv(self, *extra):
        return [
            "doctor", "--json", "--scope", "machine", "--root", str(self.ws),
            "--state-dir", str(self.state), *extra,
        ]


class InlineBearerRegressionTests(ScanEngineSandbox):
    """An sk- shaped key in any inline config entry is exactly the case the
    detector exists for: it must surface redacted, never crash the scan."""

    SK_TOKEN = "sk-abcdef0123456789fedcba"

    def test_sk_bearer_in_every_inline_config_entry(self) -> None:
        seen = []
        for rel in (".codex/config.toml", ".zcode/cli/config.json", ".dsh/cordis.patch.yml"):
            with self.subTest(entry=rel):
                write(self.home / rel, f'[mcp]\napi_key = "{self.SK_TOKEN}"\n')
                code, out, err = self.run_cli(self.scan_argv())
                self.assertEqual(code, 0, err)
                self.assertNotIn("Traceback", out + err)
                self.assertNotIn(self.SK_TOKEN, out)
                data = json.loads(out)
                record = next(
                    item
                    for item in data["secrets"]["inline_bearers"]
                    if item["path"] == str(self.home / rel)
                )
                self.assertEqual(record["redacted"], ["sk-a...dcba"])
                seen.append(rel)
        self.assertEqual(len(seen), 3)


class CredentialRedactionContractTests(ScanEngineSandbox):
    """README:291 / SKILL.md Gates: credential values are never persisted or
    printed; scans keep only paths and redacted shapes. Asserted across every
    JSON exit and the persisted registry."""

    def setUp(self) -> None:
        super().setUp()
        write(self.home / ".zcode" / "secrets" / "token", "secret-value\n")
        write(
            self.home / ".codex" / "config.toml",
            '[mcp_servers.foo]\nAuthorization = "Bearer abcdefghijklmnop"\n',
        )

    def _assert_no_credential_values(self, text: str) -> None:
        self.assertNotIn("abcdefghijklmnop", text)
        self.assertNotIn("secret-value", text)

    def test_scan_json_never_prints_or_persists_credential_values(self) -> None:
        code, out, err = self.run_cli(self.scan_argv())
        self.assertEqual(code, 0, err)
        self.assertNotIn("Traceback", out + err)
        self._assert_no_credential_values(out)
        data = json.loads(out)
        redacted = [
            shape
            for item in data["secrets"]["inline_bearers"]
            for shape in item["redacted"]
        ]
        self.assertIn("abcd...mnop", redacted)
        for shape in redacted:
            self.assertRegex(shape, REDACTED_SHAPE)
        persisted = (self.state / "registry.json").read_text(encoding="utf-8")
        self._assert_no_credential_values(persisted)
        self.assertIn("abcd...mnop", persisted)

    def test_doctor_json_never_prints_credential_values(self) -> None:
        code, out, err = self.run_cli(self.doctor_argv())
        self.assertEqual(code, 2, out + err)
        self.assertNotIn("Traceback", out + err)
        self._assert_no_credential_values(out)
        result = json.loads(out)
        inline = [f for f in result["findings"] if f["rule"] == "secret-inline"]
        self.assertTrue(inline)
        self.assertIn("abcd...mnop", inline[0]["evidence"]["redacted"])
        for shape in inline[0]["evidence"]["redacted"]:
            self.assertRegex(shape, REDACTED_SHAPE)

    def test_export_json_never_persists_credential_values(self) -> None:
        out_path = self.tmp / "export" / "context-health.json"
        argv = [
            "export", "--format", "json", "--out", str(out_path),
            "--scope", "machine", "--root", str(self.ws), "--state-dir", str(self.state),
        ]
        code, out, err = self.run_cli(argv)
        self.assertEqual(code, 0, err)
        self._assert_no_credential_values(out)
        artifact = out_path.read_text(encoding="utf-8")
        self._assert_no_credential_values(artifact)
        self.assertIn("abcd...mnop", artifact)


class CredentialRegistryWarningTests(ScanEngineSandbox):
    """A broken registry row may carry a pasted secret value; its warning text
    keeps line/column info only, so no exit ever echoes the row."""

    RAW_ROW_TOKEN = "sk-abc123def456gh78"

    def setUp(self) -> None:
        super().setUp()
        write(
            self.home / ".agents" / "credentials" / "registry.md",
            "| ID | scope | site | account | kind | locations |\n"
            f"| broken-row {self.RAW_ROW_TOKEN} | only-two-cells |\n",
        )

    def test_parse_warnings_carry_line_and_columns_only(self) -> None:
        code, out, err = self.run_cli(self.scan_argv())
        self.assertEqual(code, 0, err)
        self.assertNotIn(self.RAW_ROW_TOKEN, out)
        data = json.loads(out)
        self.assertEqual(
            data["secrets"]["registry"]["parse_warnings"],
            [
                "line 2: expected at least 6 columns "
                "(ID|scope|site|account|kind|locations), got 2"
            ],
        )
        persisted = (self.state / "registry.json").read_text(encoding="utf-8")
        self.assertNotIn(self.RAW_ROW_TOKEN, persisted)

    def test_export_json_and_credentials_stdout_carry_no_row_text(self) -> None:
        out_path = self.tmp / "export" / "context-health.json"
        code, _, err = self.run_cli([
            "export", "--format", "json", "--out", str(out_path),
            "--scope", "machine", "--root", str(self.ws), "--state-dir", str(self.state),
        ])
        self.assertEqual(code, 0, err)
        self.assertNotIn(self.RAW_ROW_TOKEN, out_path.read_text(encoding="utf-8"))
        code, out, err = self.run_cli([
            "credentials", "--scope", "machine", "--root", str(self.ws),
            "--state-dir", str(self.state),
        ])
        self.assertEqual(code, 0, err)
        self.assertNotIn(self.RAW_ROW_TOKEN, out)
        self.assertIn("expected at least 6 columns", out)


class RegistryBaselineDriftTests(ScanEngineSandbox):
    def make_project(self, name: str) -> Path:
        project = self.ws / name
        write(project / "AGENTS.md", f"# {name}\n")
        subprocess.run(["git", "init", "-q", str(project)], check=True)
        return project

    def test_corrupt_baseline_is_a_visible_finding(self) -> None:
        (self.state / "registry.json").write_text("{broken", encoding="utf-8")
        code, out, err = self.run_cli(self.doctor_argv("--no-write"))
        self.assertNotEqual(code, 1, err)
        self.assertNotIn("Traceback", out + err)
        result = json.loads(out)
        baseline = [
            f
            for f in result["findings"]
            if f["rule"] == "registry-drift" and "registry baseline corrupt" in f["message"]
        ]
        self.assertEqual(len(baseline), 1)
        self.assertEqual(baseline[0]["severity"], "medium")
        self.assertEqual(result["stats"]["registry_drift_stale_machine"], 0)

    def test_disk_change_with_no_write_still_reports_stale_machine(self) -> None:
        self.make_project("alpha")
        code, out, err = self.run_cli(self.scan_argv())
        self.assertEqual(code, 0, err)
        self.make_project("beta")
        code, out, err = self.run_cli(self.doctor_argv("--no-write"))
        result = json.loads(out)
        stale = [
            f
            for f in result["findings"]
            if f["rule"] == "registry-drift"
            and f["title"] == "Machine registry is out of date with disk"
        ]
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0]["severity"], "low")
        self.assertEqual(result["stats"]["registry_drift_stale_machine"], 1)
        self.assertTrue(any("beta" in item for item in stale[0]["evidence"]["appeared"]))

    def test_previous_registry_param_compares_against_the_capture(self) -> None:
        self.make_project("alpha")
        self.make_project("beta")
        config = ScanConfig(
            home=self.home, hub=None, roots=[self.ws], state_dir=self.state,
            plugin_root=ROOT, max_depth=3, now="2026-11-18T00:00:00+08:00",
        )
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            registry = scan(config)
            result = run_policy(
                registry, config,
                previous_registry={"projects": [{"path": str(self.ws / "alpha")}]},
            )
        stale = [
            f for f in result["findings"]
            if f["title"] == "Machine registry is out of date with disk"
        ]
        self.assertEqual(result["stats"]["registry_drift_stale_machine"], 1)
        self.assertEqual(len(stale), 1)
        fresh_config = ScanConfig(
            home=self.home, hub=None, roots=[self.ws], state_dir=self.tmp / "fresh-state",
            plugin_root=ROOT, max_depth=3, now="2026-11-18T00:00:00+08:00",
        )
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            fresh = run_policy(registry, fresh_config)
        self.assertEqual(fresh["stats"]["registry_drift_stale_machine"], 0)


class IsIndexedLinkFormTests(ScanEngineSandbox):
    def test_llms_txt_link_list_index_form(self) -> None:
        self.assertTrue(
            is_indexed("start-here.md", "- [start here](general/start-here.md): how this hub is organized")
        )
        self.assertTrue(is_indexed("start-here.md", "- [start here](start-here.md): top level"))
        self.assertTrue(is_indexed("data.md", "see [the doc](sub/data.md)"))

    def test_link_form_boundaries(self) -> None:
        self.assertFalse(is_indexed("a.md", "see `data.md` for details"))
        self.assertFalse(is_indexed("a.md", "- [other](data-a.md)"))
        self.assertFalse(is_indexed("a.md", "- [other](a.mdx)"))
        self.assertFalse(is_indexed("a.md", "plain mention of a.md in prose"))

    def test_legacy_four_forms_still_count(self) -> None:
        self.assertTrue(is_indexed("a.md", "| `a.md` | note |"))
        self.assertTrue(is_indexed("start-here.md", "| `general/start-here.md` | how |"))
        self.assertTrue(is_indexed("a.md", "see `a` stem note"))
        self.assertTrue(is_indexed("a.md", "| a | note |"))


class LlmsTxtIndexIntegrationTests(ScanEngineSandbox):
    def setUp(self) -> None:
        super().setUp()
        self.hub = self.tmp / "hub"
        init_hub(self.hub, self.state, yes=True, dry_run=False)

    def test_llms_txt_shaped_knowledge_index_scores_full_coverage(self) -> None:
        write(
            self.hub / "knowledge" / "README.md",
            "# Knowledge Index\n\n"
            "> One curated link per file.\n\n"
            "- [Start Here](general/start-here.md): How this hub is organized\n",
        )
        code, out, err = self.run_cli([
            "doctor", "--json", "--scope", "hub", "--hub", str(self.hub),
            "--state-dir", str(self.state),
        ])
        self.assertNotEqual(code, 1, err)
        result = json.loads(out)
        rules = {f["rule"] for f in result["findings"]}
        self.assertNotIn("orphan-knowledge", rules)
        self.assertEqual(result["stats"]["knowledge_total"], 1)
        self.assertEqual(result["stats"]["knowledge_indexed"], 1)

        code, out, err = self.run_cli([
            "hub", "validate", "--path", str(self.hub), "--state-dir", str(self.state),
        ])
        self.assertEqual(code, 0, out + err)

        code, out, err = self.run_cli([
            "score", "--json", "--scope", "hub", "--hub", str(self.hub),
            "--state-dir", str(self.state),
        ])
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["scores"]["icr"], 100.0)


class PluginManifestTests(ScanEngineSandbox):
    def make_plugin_root(self) -> Path:
        plugins = self.tmp / "plugins"
        for rel in (".codex-plugin/plugin.json", ".zcode-plugin/plugin.json", "package.json"):
            write(plugins / rel, json.dumps({"name": "guster", "version": "0.9.4"}))
        return plugins

    def config(self, plugin_root: Path) -> ScanConfig:
        return ScanConfig(
            home=self.home, hub=None, roots=[self.ws], state_dir=self.state,
            plugin_root=plugin_root, max_depth=3, now="2026-11-18T00:00:00+08:00",
        )

    def test_all_manifests_present_and_agreeing_is_green(self) -> None:
        plugins = self.make_plugin_root()
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            registry = scan(self.config(plugins))
            result = run_policy(registry, self.config(plugins))
        drift = [f for f in result["findings"] if f["rule"] == "host-manifest-drift"]
        self.assertEqual(drift, [])

    def test_missing_manifest_is_a_high_finding(self) -> None:
        plugins = self.make_plugin_root()
        missing_path = plugins / ".codex-plugin" / "plugin.json"
        missing_path.unlink()
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            registry = scan(self.config(plugins))
            result = run_policy(registry, self.config(plugins))
        missing = [
            f for f in result["findings"]
            if f["rule"] == "host-manifest-drift" and "plugin manifest missing" in f["message"]
        ]
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]["severity"], "high")
        self.assertEqual(missing[0]["message"], f"plugin manifest missing: {missing_path}")
        disagree = [
            f for f in result["findings"]
            if f["rule"] == "host-manifest-drift"
            and f["title"] == "Plugin manifests disagree on version"
        ]
        self.assertEqual(len(disagree), 1)
        self.assertIsNone(disagree[0]["evidence"]["versions"]["codex"])


if __name__ == "__main__":
    unittest.main()
