from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from guster import cli  # noqa: E402
from guster.executor import ApplyError, apply_plan  # noqa: E402
from guster.planner import load_plan  # noqa: E402
from guster.util import save_json, write_private, write_text  # noqa: E402


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def umask_default() -> int:
    umask = os.umask(0)
    os.umask(umask)
    return 0o666 & ~umask


class Sandbox(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="guster-apply-")).resolve()
        self.home = self.tmp / "home"
        self.workspace = self.tmp / "workspace"
        self.state = self.tmp / "state"
        self.home.mkdir()
        self.workspace.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def plan(self, name: str, operations: list, title: str = "plan") -> Path:
        path = self.tmp / f"{name}.json"
        write(
            path,
            json.dumps(
                {
                    "version": 1,
                    "id": name,
                    "created_at": "2026-11-26T00:00:00+00:00",
                    "title": title,
                    "notes": "",
                    "operations": operations,
                }
            ),
        )
        return path


class FileModeTests(Sandbox):
    def test_an_existing_file_keeps_its_mode_and_a_script_stays_executable(self) -> None:
        doc = self.tmp / "doc.md"
        script = self.tmp / "run.sh"
        write(doc, "old\n")
        write(script, "old\n")
        os.chmod(doc, 0o644)
        os.chmod(script, 0o755)
        write_text(doc, "new\n")
        write_text(script, "new\n")
        self.assertEqual(mode_of(doc), 0o644)
        self.assertEqual(mode_of(script), 0o755)

    def test_a_new_file_gets_the_umask_default(self) -> None:
        fresh = self.tmp / "fresh" / "AGENTS.md"
        write_text(fresh, "new\n")
        self.assertEqual(mode_of(fresh), umask_default())

    def test_state_writes_stay_private(self) -> None:
        registry = self.tmp / "registry.json"
        save_json(registry, {"a": 1})
        self.assertEqual(mode_of(registry), 0o600)
        os.chmod(registry, 0o644)
        write_private(registry, "{}\n")
        self.assertEqual(mode_of(registry), 0o600)

    def test_a_plan_write_does_not_strip_the_executable_bit(self) -> None:
        project = self.workspace / "proj"
        script = project / "entry.sh"
        write(script, "old\n")
        os.chmod(script, 0o755)
        result = apply_plan(
            {
                "version": 1,
                "id": "keep-mode",
                "created_at": "2026-11-26T00:00:00+00:00",
                "title": "keep mode",
                "notes": "",
                "operations": [{"kind": "write", "path": str(script), "content": "new\n"}],
            },
            self.state,
            dry_run=False,
            yes=True,
            extra_bases=[project],
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(mode_of(script), 0o755)


class RollbackTests(Sandbox):
    def test_a_rolled_back_move_leaves_no_empty_directories(self) -> None:
        project = self.workspace / "proj"
        note = project / "src" / "note.md"
        other = project / "src" / "other.md"
        blocker = project / "blocker"
        write(note, "payload\n")
        write(other, "other\n")
        write(blocker, "a regular file where a directory is needed\n")
        plan = self.plan(
            "rollback-dirs",
            [
                # no explicit mkdir: the move creates the nested destination itself
                {"kind": "move", "src": str(note), "dst": str(project / ".agents" / "wiki" / "deep" / "note.md")},
                # passes preflight, fails mid-apply
                {"kind": "move", "src": str(other), "dst": str(blocker / "x.md")},
            ],
        )
        with self.assertRaises(ApplyError) as caught:
            apply_plan(load_plan(plan), self.state, dry_run=False, yes=True, extra_bases=[project])
        self.assertIn("rolled back", str(caught.exception))
        self.assertTrue((project / "src" / "note.md").read_text().startswith("payload"))
        self.assertFalse((project / ".agents").exists(), "destination parents left behind")
        self.assertFalse((project / "blocker" / "x.md").exists())


class InitRootMergeTests(Sandbox):
    def setUp(self) -> None:
        super().setUp()
        self.first = self.workspace / "first"
        self.second = self.workspace / "second"
        self.third = self.workspace / "third"
        for root in (self.first, self.second, self.third):
            root.mkdir()

    def config(self) -> dict:
        return json.loads((self.state / "config.json").read_text(encoding="utf-8"))

    def test_init_root_adds_to_an_existing_config(self) -> None:
        self.run_cli(["init", "--root", str(self.first), "--state-dir", str(self.state), "--yes"])
        (self.home / "code").mkdir()
        write(self.state / "config.json", json.dumps({"version": 1, "roots": ["~/code"], "scan_max_depth": 7}))
        os.chmod(self.state / "config.json", 0o644)
        code, out, err = self.run_cli(
            [
                "init", "--root", str(self.second), "--root", str(self.home / "code"),
                "--state-dir", str(self.state), "--yes",
            ]
        )
        self.assertEqual(code, 0, err)
        # `~/code` is already configured: its absolute spelling is not added twice
        self.assertEqual(self.config()["roots"], ["~/code", str(self.second)])
        self.assertEqual(self.config()["scan_max_depth"], 7)
        self.assertIn("added roots", out)
        self.assertEqual(mode_of(self.state / "config.json"), 0o644)

    def test_a_root_that_is_already_configured_changes_nothing(self) -> None:
        self.run_cli(["init", "--root", str(self.first), "--state-dir", str(self.state), "--yes"])
        before = (self.state / "config.json").read_bytes()
        code, out, err = self.run_cli(
            ["init", "--root", str(self.first), "--state-dir", str(self.state), "--yes"]
        )
        self.assertEqual(code, 0, err)
        self.assertEqual((self.state / "config.json").read_bytes(), before)
        self.assertIn("already configured", out)
        self.assertNotIn("applied: 4", out)

    def test_dry_run_lists_the_config_write_and_touches_nothing(self) -> None:
        self.run_cli(["init", "--root", str(self.first), "--state-dir", str(self.state), "--yes"])
        before = (self.state / "config.json").read_bytes()
        code, out, err = self.run_cli(["init", "--root", str(self.third), "--state-dir", str(self.state)])
        self.assertEqual(code, 0, err)
        self.assertIn("would add roots", out)
        self.assertEqual((self.state / "config.json").read_bytes(), before)

    def test_the_added_root_is_scanned_afterwards(self) -> None:
        for root in (self.first, self.second):
            (root / "proj").mkdir()
            write(root / "proj" / "AGENTS.md", "# Project\n")
        self.run_cli(["init", "--root", str(self.first), "--state-dir", str(self.state), "--yes"])
        self.run_cli(["init", "--root", str(self.second), "--state-dir", str(self.state), "--yes"])
        code, out, err = self.run_cli(["status", "--state-dir", str(self.state), "--json"])
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["registry"]["workspaces"], [str(self.first), str(self.second)])


class PlanContractTests(Sandbox):
    def test_a_manual_path_may_be_empty_or_relative_as_the_schema_says(self) -> None:
        plan = self.plan(
            "manual-free",
            [
                {"kind": "manual", "path": "", "action": "do something", "reason": "because"},
                {"kind": "manual", "path": "docs/README.md", "action": "fix", "reason": "index"},
            ],
        )
        loaded = load_plan(plan)
        self.assertEqual(len(loaded["operations"]), 2)

    def test_executed_operations_still_need_absolute_paths(self) -> None:
        plan = self.plan("write-relative", [{"kind": "write", "path": "relative.md", "content": "x"}])
        with self.assertRaises(ValueError) as caught:
            load_plan(plan)
        self.assertIn("absolute path", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
