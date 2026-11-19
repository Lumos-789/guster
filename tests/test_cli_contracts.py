from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from guster import cli  # noqa: E402
from guster.discover import ScanConfig  # noqa: E402
from guster.hub import init_hub  # noqa: E402


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


STALE_PLANS = ("2020-a.md", "2020-b.md", "2020-c.md")
ORPHAN_NOTES = ("b1.md", "b2.md", "b3.md")


class Sandbox:
    """A machine-shaped fixture: isolated home, one workspace project (with a
    broken pointer plus three stale state docs) and a hub with one unindexed
    note — enough findings to pin the CLI contracts without extra setup."""

    def __init__(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="guster-contracts-"))
        self.home = self.tmp / "home"
        self.workspace = self.tmp / "workspace"
        self.project = self.workspace / "proj1"
        self.hub = self.tmp / "hub"
        self.state = self.tmp / "state"
        self.home.mkdir(parents=True)

        (self.project / ".git").mkdir(parents=True)
        write(
            self.project / "AGENTS.md",
            "# Project\n\nSee [`knowledge/missing.md`](knowledge/missing.md).\n",
        )
        write(
            self.project / ".agents" / "README.md",
            "# Index\n\n| plan |\n|---|\n| `plans/plan.md` |\n",
        )
        write(self.project / ".agents" / "plans" / "plan.md", "# Plan\n\n**最后更新**: 2026-11-01\n")
        for name in STALE_PLANS:
            write(self.project / ".agents" / "plans" / name, f"# {name}\n\n**最后更新**: 2020-01-15\n")

        write(self.hub / "AGENTS.md", "# Hub\n")
        write(self.hub / "knowledge" / "README.md", "# Knowledge\n\n| a |\n|---|\n| `general/a.md` |\n")
        write(self.hub / "knowledge" / "general" / "a.md", "# A\n")
        for name in ORPHAN_NOTES:
            write(self.hub / "knowledge" / "general" / name, f"# {name}\n")
        write(self.hub / "projects" / "p.md", "# Project P\n\n**状态**: active\n")

        write(
            self.home / ".agents" / "credentials" / "registry.md",
            "# Registry\n\n"
            "| ID | scope | site | account | kind | locations | keys |\n"
            "|---|---|---|---|---|---|---|\n"
            "| a1 | company | example.com | me | token | ~/.agents/credentials/a1 | k1 |\n",
        )
        # the declared location exists, so credentials stay registered without
        # a secret-missing finding (whose ~ examples are not plan-safe paths)
        write(self.home / ".agents" / "credentials" / "a1", "declared-token-material\n")

    def cleanup(self) -> None:
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)


class ContractTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = Sandbox()

    def tearDown(self) -> None:
        self.fx.cleanup()

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(self.fx.home)}):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()


class HubInitPreflightContracts(ContractTestCase):
    """T3/C3/S2: hub init refuses a bad target before touching anything, with
    exit 4 (the documented preflight code), not the generic error exit 1."""

    def test_non_empty_target_refuses_with_exit_4_and_writes_nothing(self) -> None:
        target = self.fx.tmp / "occupied"
        write(target / "keep.md", "# Keep\n")
        code, out, err = self.run_cli(
            ["hub", "init", "--path", str(target), "--yes", "--state-dir", str(self.fx.state)]
        )
        self.assertEqual(code, 4)
        self.assertIn("[guster] hub target is not empty", err)
        self.assertTrue((target / "keep.md").is_file())
        self.assertFalse((self.fx.state / "plans").exists())

    def test_file_target_refuses_with_exit_4(self) -> None:
        target = self.fx.tmp / "plain-file"
        write(target, "not a directory\n")
        code, _, err = self.run_cli(
            ["hub", "init", "--path", str(target), "--yes", "--state-dir", str(self.fx.state)]
        )
        self.assertEqual(code, 4)
        self.assertIn("not a directory", err)

    def test_escaping_layout_refuses_with_exit_4_and_writes_nothing(self) -> None:
        target = self.fx.tmp / "escape"
        code, _, err = self.run_cli(
            [
                "hub", "init", "--path", str(target), "--knowledge", "../outside",
                "--yes", "--state-dir", str(self.fx.state),
            ]
        )
        self.assertEqual(code, 4)
        self.assertIn("must not contain '..'", err)
        self.assertFalse(target.exists())
        self.assertFalse((self.fx.state / "plans").exists())

    def test_preflight_refusal_uses_the_json_envelope(self) -> None:
        target = self.fx.tmp / "occupied-json"
        write(target / "keep.md", "# Keep\n")
        code, out, err = self.run_cli(
            ["hub", "init", "--path", str(target), "--yes", "--json", "--state-dir", str(self.fx.state)]
        )
        self.assertEqual(code, 4)
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertIn("not empty", data["error"])
        self.assertEqual(err, "")


class ExitCodeContracts(ContractTestCase):
    """T4/T5/T6/T7: the exit-code rows the README and SKILL publish."""

    def test_hub_validate_failure_exits_2_with_parseable_json(self) -> None:
        hub = self.fx.tmp / "lite-hub"
        init_hub(hub, self.fx.tmp / "lite-state", yes=True, dry_run=False)
        write(hub / "knowledge" / "general" / "extra.md", "# Extra\n")
        code, out, _ = self.run_cli(
            ["hub", "validate", "--path", str(hub), "--json", "--state-dir", str(self.fx.state)]
        )
        self.assertEqual(code, 2)
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertTrue(any("not indexed" in item for item in data["errors"]))

    def _git_project(self, name: str, leaky: bool) -> Path:
        project = self.fx.tmp / name
        write(project / "AGENTS.md", "# App\n")
        write(project / ".agents" / "README.md", "# Index\n")
        for slot in ("plans", "wiki", "evidence", "skills", "tmp", "archive"):
            (project / ".agents" / slot).mkdir(parents=True, exist_ok=True)
        if leaky:
            write(project / ".env", "TOKEN=not-a-real-token\n")
        subprocess.run(["git", "init", "-q", str(project)], check=True)
        subprocess.run(["git", "-C", str(project), "add", "-A"], check=True)
        subprocess.run(
            [
                "git", "-C", str(project),
                "-c", "user.email=t@example.com", "-c", "user.name=t",
                "commit", "-q", "-m", "init",
            ],
            check=True,
        )
        return project

    def test_check_returns_3_on_critical_findings(self) -> None:
        project = self._git_project("leaky", leaky=True)
        code, _, err = self.run_cli(
            ["check", "--root", str(project), "--scope", "project", "--state-dir", str(self.fx.state)]
        )
        self.assertEqual(code, 3, err)

    def test_check_no_write_leaves_no_state_files_and_default_still_writes(self) -> None:
        project = self._git_project("clean", leaky=False)
        state = self.fx.tmp / "nw-state"
        code, _, err = self.run_cli(
            ["check", "--no-write", "--root", str(project), "--scope", "project", "--state-dir", str(state)]
        )
        self.assertEqual(code, 0, err)
        for name in ("registry.json", "findings.json", "metrics.jsonl"):
            self.assertFalse((state / name).exists(), name)
        code, _, err = self.run_cli(
            ["check", "--root", str(project), "--scope", "project", "--state-dir", str(state)]
        )
        self.assertEqual(code, 0, err)
        for name in ("registry.json", "findings.json", "metrics.jsonl"):
            self.assertTrue((state / name).is_file(), name)

    def test_score_fail_under_not_computable_exits_2(self) -> None:
        hub = self.fx.tmp / "empty-hub"
        write(hub / "AGENTS.md", "# Hub\n")
        write(hub / "knowledge" / "README.md", "# Knowledge\n")
        write(hub / "tools" / "README.md", "# Tools\n")
        code, _, err = self.run_cli(
            [
                "score", "--scope", "hub", "--hub", str(hub), "--no-write",
                "--fail-under", "80", "--state-dir", str(self.fx.state),
            ]
        )
        self.assertEqual(code, 2)
        self.assertIn("not computable", err)

    def test_score_fail_under_json_envelope_is_a_single_json_object(self) -> None:
        hub = self.fx.tmp / "empty-json-hub"
        write(hub / "AGENTS.md", "# Hub\n")
        write(hub / "knowledge" / "README.md", "# Knowledge\n")
        write(hub / "tools" / "README.md", "# Tools\n")
        code, out, _ = self.run_cli(
            [
                "score", "--scope", "hub", "--hub", str(hub), "--no-write",
                "--fail-under", "80", "--json", "--state-dir", str(self.fx.state),
            ]
        )
        self.assertEqual(code, 2)
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertIn("not computable", data["error"])
        self.assertIn("metrics", data)

    def test_hub_status_returns_1_when_the_attached_hub_fails_checks(self) -> None:
        hub = self.fx.tmp / "attached"
        hub_state = self.fx.tmp / "attached-state"
        init_hub(hub, hub_state, yes=True, dry_run=False)
        (hub / "knowledge" / "README.md").unlink()
        code, out, _ = self.run_cli(["hub", "status", "--state-dir", str(hub_state)])
        self.assertEqual(code, 1)
        self.assertIn("error:", out)


class PlanFindingsContracts(ContractTestCase):
    """T1: `plan findings` maps every actionable finding to a manual op and the
    plan itself survives an apply dry run."""

    def test_findings_become_manual_ops_and_apply_dry_run_digests_the_plan(self) -> None:
        argv = [
            "plan", "findings",
            "--root", str(self.fx.workspace), "--hub", str(self.fx.hub),
            "--scope", "machine",
            "--state-dir", str(self.fx.state), "--json",
        ]
        code, out, err = self.run_cli(argv)
        self.assertEqual(code, 0, err)
        plan = json.loads(out)
        self.assertEqual(plan["version"], 1)
        self.assertTrue(plan["operations"])
        manual_ops = [op for op in plan["operations"] if op["kind"] == "manual"]
        self.assertEqual(len(manual_ops), len(plan["operations"]))

        # one broken-pointer finding -> one manual op on the file that owns it
        agents_md = str((self.fx.project / "AGENTS.md").resolve())
        self.assertIn(agents_md, {op["path"] for op in manual_ops})

        # the aggregated orphan-knowledge finding fans out to one op per file
        # (batch-1 contract) with absolute op paths — the plan contract rejects
        # relative ones, so policy must emit absolute examples (review-095
        # ruling B)
        orphan_paths = {
            str((self.fx.hub / "knowledge" / "general" / name).resolve())
            for name in ORPHAN_NOTES
        }
        self.assertEqual(
            {op["path"] for op in manual_ops if op["path"] in orphan_paths},
            orphan_paths,
            "aggregated finding examples must be absolute — fix policy.py "
            "orphan-knowledge relative() → absolute (review-095 ruling B)",
        )

        # the emitted plan is applyable as a dry run
        plan_path = self.fx.tmp / "review-plan.json"
        write(plan_path, out)
        code, out, err = self.run_cli(["apply", str(plan_path), "--json", "--state-dir", str(self.fx.state)])
        self.assertEqual(code, 0, err)
        result = json.loads(out)
        self.assertTrue(result["ok"])
        self.assertTrue(result["dry_run"])


class JsonEnvelopeContracts(ContractTestCase):
    """T9: every --json command prints one parseable JSON object on stdout, and
    command errors keep the {ok: false, error: ...} envelope."""

    def test_score_json_is_parseable(self) -> None:
        code, out, err = self.run_cli(
            [
                "score", "--root", str(self.fx.workspace), "--hub", str(self.fx.hub),
                "--no-write", "--json", "--state-dir", str(self.fx.state),
            ]
        )
        self.assertEqual(code, 0, err)
        data = json.loads(out)
        self.assertIn("chi", data)

    def test_check_json_carries_policy_and_metrics(self) -> None:
        code, out, err = self.run_cli(
            [
                "check", "--root", str(self.fx.workspace), "--hub", str(self.fx.hub),
                "--json", "--state-dir", str(self.fx.state),
            ]
        )
        self.assertEqual(code, 2, err)  # fake .git -> git-unavailable HIGH
        data = json.loads(out)
        self.assertIn("policy", data)
        self.assertIn("metrics", data)
        self.assertTrue(data["policy"]["findings"])

    def test_plan_move_json_is_parseable(self) -> None:
        src = self.fx.tmp / "src-thing"
        write(src / "a.md", "# A\n")
        code, out, err = self.run_cli(
            [
                "plan", "move", "--from", str(src), "--to", str(self.fx.tmp / "dst-thing"),
                "--json", "--state-dir", str(self.fx.state),
            ]
        )
        self.assertEqual(code, 0, err)
        data = json.loads(out)
        self.assertEqual(data["version"], 1)
        self.assertTrue(data["operations"])

    def test_apply_dry_run_json_is_parseable(self) -> None:
        # the write target must sit inside an allowed base (the state dir)
        plan_path = self.fx.tmp / "mkdir-plan.json"
        write(
            plan_path,
            json.dumps(
                {
                    "id": "mkdir-plan",
                    "title": "mkdir",
                    "created_at": "2026-11-19T00:00:00+08:00",
                    "notes": "",
                    "version": 1,
                    "operations": [{"kind": "mkdir", "path": str(self.fx.state / "made-by-plan")}],
                }
            ),
        )
        code, out, err = self.run_cli(
            ["apply", str(plan_path), "--json", "--state-dir", str(self.fx.state)]
        )
        self.assertEqual(code, 0, err)
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertTrue(data["dry_run"])

    def test_credentials_json_is_parseable(self) -> None:
        code, out, err = self.run_cli(
            [
                "credentials", "--root", str(self.fx.workspace), "--hub", str(self.fx.hub),
                "--json", "--state-dir", str(self.fx.state),
            ]
        )
        self.assertEqual(code, 0, err)
        data = json.loads(out)
        self.assertEqual(len(data["entries"]), 1)

    def test_json_errors_stay_a_single_line_envelope_without_prose(self) -> None:
        missing = self.fx.tmp / "no-such-plan.json"
        code, out, err = self.run_cli(
            ["apply", str(missing), "--json", "--state-dir", str(self.fx.state)]
        )
        self.assertEqual(code, 1)
        self.assertEqual(err, "")
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertIn("cannot read plan", data["error"])


class MetricsReferenceContracts(ContractTestCase):
    """The metrics pointer must resolve inside the installed plugin instead of
    assuming the CLI runs from the plugin checkout."""

    def config(self, plugin_root: Path) -> ScanConfig:
        return ScanConfig(
            home=self.fx.home,
            hub=None,
            roots=[],
            state_dir=self.fx.tmp / "ref-state",
            plugin_root=plugin_root,
        )

    def test_line_points_at_an_existing_file(self) -> None:
        line = cli.metrics_reference_line(self.config(ROOT))
        target = line.removeprefix("Definitions & targets: ")
        self.assertFalse(target.startswith("see the"))
        self.assertTrue(Path(target).is_file(), target)

    def test_line_falls_back_when_the_layout_has_no_reference(self) -> None:
        line = cli.metrics_reference_line(self.config(self.fx.tmp))
        self.assertIn("see the guster skill reference (metrics.md)", line)

    def test_score_prints_the_pointer_from_any_cwd(self) -> None:
        cwd = os.getcwd()
        os.chdir(self.fx.tmp)
        try:
            code, out, err = self.run_cli(
                [
                    "score", "--root", str(self.fx.project), "--scope", "project",
                    "--no-write", "--state-dir", str(self.fx.state),
                ]
            )
        finally:
            os.chdir(cwd)
        self.assertEqual(code, 0, err)
        for line in out.splitlines():
            if line.startswith("Definitions & targets: "):
                target = line.removeprefix("Definitions & targets: ")
                if target.startswith("see the"):
                    return
                self.assertTrue(Path(target).is_file(), target)
                return
        self.fail("score output never printed the metrics reference line")


class PreviousRegistryContracts(ContractTestCase):
    """The drift baseline: the old registry is read before the scan replaces
    it; unreadable baselines read as None so run_policy's own strict disk read
    (and its corrupt-baseline finding) stays in charge."""

    def _config(self) -> ScanConfig:
        return ScanConfig(
            home=self.fx.home, hub=None, roots=[],
            state_dir=self.fx.tmp / "prev-state", plugin_root=ROOT,
        )

    def test_missing_baseline_reads_as_none(self) -> None:
        self.assertIsNone(cli.load_previous_registry(self._config()))

    def test_valid_baseline_is_returned_as_is(self) -> None:
        config = self._config()
        write(config.state_dir / "registry.json", '{"version": 1, "projects": []}')
        self.assertEqual(
            cli.load_previous_registry(config), {"version": 1, "projects": []}
        )

    def test_unreadable_baselines_read_as_none(self) -> None:
        for payload in ("{broken", "[]"):
            with self.subTest(payload=payload):
                config = self._config()
                write(config.state_dir / "registry.json", payload)
                self.assertIsNone(cli.load_previous_registry(config))

    def test_corrupt_baseline_surfaces_as_a_finding_not_a_traceback(self) -> None:
        state = self.fx.tmp / "corrupt-state"
        machine = ["--root", str(self.fx.workspace), "--scope", "machine"]
        self.run_cli(["scan", *machine, "--state-dir", str(state)])
        write(state / "registry.json", "{broken")
        code, out, err = self.run_cli(
            ["doctor", *machine, "--no-write", "--json", "--state-dir", str(state)]
        )
        self.assertIn(code, (0, 2, 3))
        self.assertNotIn("Traceback", err)
        policy = json.loads(out)
        self.assertTrue(
            any(item["rule"] == "registry-drift" and "corrupt" in item["title"] for item in policy["findings"]),
            policy["findings"],
        )


if __name__ == "__main__":
    unittest.main()
