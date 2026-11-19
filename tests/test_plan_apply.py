"""Batch-1 apply/plan engine safety tests: C1 (schema-faithful load_plan),
X2 (path boundaries, pointer refusal), X6 (plan id slug), backup collision,
mkdir undo, findings expansion, C2 (absolute paths), H2 (pointer-free moves),
U2 (init refuses a broken existing config)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from guster import cli  # noqa: E402
from guster.executor import ApplyError, apply_plan, rollback  # noqa: E402
from guster.planner import op_move, plan_from_findings, plan_move  # noqa: E402


class PlanApplySafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="guster-plan-apply-"))
        self.home = self.tmp / "home"
        self.state = self.tmp / "state"
        self.home.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    @contextmanager
    def isolated_home(self) -> Iterator[None]:
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            yield

    def run_cli(self, argv: List[str]) -> Tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with self.isolated_home():
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    @staticmethod
    def write(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def plan_file(self, name: str, operations: List[Dict[str, Any]], **top: Any) -> Path:
        plan: Dict[str, Any] = {
            "version": 1,
            "id": "batch1-test",
            "created_at": "2026-11-19T11:00:00+08:00",
            "title": "batch-1 test plan",
            "notes": "",
            "operations": operations,
        }
        plan.update(top)
        path = self.tmp / name
        self.write(path, json.dumps(plan, ensure_ascii=False))
        return path

    # ---- C1: the plan contract is enforced before any write -----------------

    def test_c1_mistyped_content_key_leaves_the_target_untouched(self) -> None:
        victim = self.tmp / "victim.md"
        self.write(victim, "IMPORTANT CONTENT")
        before = victim.read_bytes()
        path = self.plan_file(
            "c1-contnet.json",
            [{"kind": "write", "path": str(victim), "contnet": "replacement"}],
        )
        code, _, err = self.run_cli(["apply", str(path), "--yes", "--state-dir", str(self.state)])
        self.assertEqual(code, 1)
        self.assertIn("unknown key 'contnet'", err)
        self.assertIn("needs 'content'", err)
        self.assertEqual(victim.read_bytes(), before)
        self.assertFalse(self.state.exists(), "a refused plan must not create state dirs")

    def test_c1_minimal_plan_missing_required_keys_fails_loud(self) -> None:
        path = self.tmp / "c1-minimal.json"
        self.write(path, json.dumps({"version": 1, "operations": []}))
        code, _, err = self.run_cli(["apply", str(path), "--yes", "--state-dir", str(self.state)])
        self.assertEqual(code, 1)
        for key in ("id", "title", "created_at", "notes"):
            self.assertIn(f"missing required key '{key}'", err)

    def test_c1_unknown_operation_key_is_rejected(self) -> None:
        path = self.plan_file(
            "c1-unknown-key.json",
            [{"kind": "mkdir", "path": str(self.state / "plans"), "mode": "0777"}],
        )
        code, _, err = self.run_cli(["apply", str(path), "--yes", "--state-dir", str(self.state)])
        self.assertEqual(code, 1)
        self.assertIn("unknown key 'mode'", err)

    def test_c1_non_string_kind_is_rejected_without_a_traceback(self) -> None:
        path = self.plan_file("c1-list-kind.json", [{"kind": ["write"]}])
        code, _, err = self.run_cli(["apply", str(path), "--yes", "--state-dir", str(self.state)])
        self.assertEqual(code, 1)
        self.assertIn("unknown operation kind", err)
        self.assertNotIn("Traceback", err)

    # ---- X2: writes stay inside the allowed bases; pointer moves refused ----

    def test_x2_write_outside_state_dir_is_refused_with_zero_writes(self) -> None:
        outside = self.tmp / "outside" / "target.md"
        path = self.plan_file(
            "x2-outside.json",
            [{"kind": "write", "path": str(outside), "content": "pwned"}],
        )
        code, out, _ = self.run_cli(["apply", str(path), "--yes", "--state-dir", str(self.state)])
        self.assertEqual(code, 4)
        self.assertIn("outside the allowed bases", out)
        self.assertIn(str(self.state), out)
        self.assertFalse(outside.exists())
        self.assertFalse(outside.parent.exists())

    def test_x2_move_with_pointer_is_refused_by_preflight(self) -> None:
        src = self.tmp / "src.txt"
        pointer_target = self.tmp / "pointer-note.md"
        self.write(src, "src\n")
        plan: Dict[str, Any] = {
            "version": 1,
            "id": "pointer-batch",
            "created_at": "2026-11-19T11:00:00+08:00",
            "title": "pointer move",
            "notes": "",
            "operations": [
                {
                    "kind": "move",
                    "src": str(src),
                    "dst": str(self.tmp / "dst.txt"),
                    "pointer": {"path": str(pointer_target), "content": "moved"},
                }
            ],
        }
        with self.isolated_home():
            result = apply_plan(plan, self.state, dry_run=False, yes=True, extra_bases=[self.tmp])
        self.assertFalse(result["ok"])
        self.assertEqual(
            result["errors"],
            [
                "op 1: pointer updates are no longer applied by `apply`; "
                "update the referenced file with a write op"
            ],
        )
        self.assertTrue(src.exists())
        self.assertFalse((self.tmp / "dst.txt").exists())
        self.assertFalse(pointer_target.exists())
        self.assertFalse((self.state / "backups").exists())

    def test_x2_pointer_move_via_cli_fails_with_migration_hint(self) -> None:
        src = self.tmp / "src-cli.txt"
        self.write(src, "src\n")
        path = self.plan_file(
            "x2-pointer-cli.json",
            [
                {
                    "kind": "move",
                    "src": str(src),
                    "dst": str(self.tmp / "dst-cli.txt"),
                    "pointer": {"path": str(self.tmp / "note.md"), "content": "moved"},
                }
            ],
        )
        code, _, err = self.run_cli(["apply", str(path), "--yes", "--state-dir", str(self.state)])
        self.assertEqual(code, 1)
        self.assertIn("pointer updates are no longer applied by `apply`", err)

    def test_x2_extra_bases_admit_the_declared_area(self) -> None:
        hub = self.tmp / "hubroot"
        plan = {
            "version": 1,
            "id": "hub-write",
            "created_at": "2026-11-19T11:00:00+08:00",
            "title": "hub write",
            "notes": "",
            "operations": [{"kind": "write", "path": str(hub / "a.md"), "content": "# hub\n"}],
        }
        with self.isolated_home():
            refused = apply_plan(plan, self.state, dry_run=False, yes=True)
            self.assertFalse(refused["ok"])
            allowed = apply_plan(plan, self.state, dry_run=False, yes=True, extra_bases=[hub])
        self.assertTrue(allowed["ok"], allowed.get("errors"))
        self.assertEqual((hub / "a.md").read_text(encoding="utf-8"), "# hub\n")

    def test_x2_config_roots_extend_the_allowed_bases(self) -> None:
        workspace = self.tmp / "ws"
        workspace.mkdir()
        self.state.mkdir(parents=True)
        self.write(
            self.state / "config.json",
            json.dumps({"version": 1, "roots": [str(workspace)]}),
        )
        target = workspace / "inside.txt"
        path = self.plan_file(
            "x2-roots.json",
            [{"kind": "write", "path": str(target), "content": "ok"}],
        )
        code, out, _ = self.run_cli(["apply", str(path), "--yes", "--state-dir", str(self.state)])
        self.assertEqual(code, 0, out)
        self.assertEqual(target.read_text(encoding="utf-8"), "ok")

    def test_x2_config_hub_extends_the_allowed_bases(self) -> None:
        workspace = self.tmp / "ws"
        hub = self.tmp / "hubroot"
        workspace.mkdir()
        hub.mkdir()
        self.state.mkdir(parents=True)
        self.write(
            self.state / "config.json",
            json.dumps({"version": 1, "roots": [str(workspace)], "hub": str(hub)}),
        )
        src = hub / "knowledge" / "start-here.md"
        self.write(src, "# start\n")
        target = hub / "knowledge" / "reference.md"
        path = self.plan_file(
            "x2-hub.json",
            [{"kind": "move", "src": str(src), "dst": str(target)}],
        )
        code, out, _ = self.run_cli(["apply", str(path), "--yes", "--state-dir", str(self.state)])
        self.assertEqual(code, 0, out)
        self.assertEqual(target.read_text(encoding="utf-8"), "# start\n")
        self.assertFalse(src.exists())

    def test_x2_config_hub_wrong_type_fails_loud(self) -> None:
        workspace = self.tmp / "ws"
        workspace.mkdir()
        self.state.mkdir(parents=True)
        self.write(
            self.state / "config.json",
            json.dumps({"version": 1, "roots": [str(workspace)], "hub": 42}),
        )
        path = self.plan_file(
            "x2-hub-bad.json",
            [{"kind": "mkdir", "path": str(self.state / "plans")}],
        )
        code, _, err = self.run_cli(["apply", str(path), "--yes", "--state-dir", str(self.state)])
        self.assertEqual(code, 1)
        self.assertIn("Guster config 'hub' must be a path string", err)

    def test_x2_hub_init_with_invalid_config_roots_exits_one(self) -> None:
        hub = self.tmp / "hubroot"
        hub.mkdir()
        self.state.mkdir(parents=True)
        self.write(self.state / "config.json", json.dumps({"version": 1, "roots": "oops"}))
        code, _, err = self.run_cli(
            ["hub", "init", "--path", str(hub), "--yes", "--state-dir", str(self.state)]
        )
        self.assertEqual(code, 1)
        self.assertIn("Guster config 'roots' must be a list of absolute paths", err)
        self.assertFalse((hub / "AGENTS.md").exists(), "a config error must not create the hub")

    # ---- X7: symlinks resolve to their real target before boundary checks ----

    def test_x7_symlink_escape_outside_bases_is_refused(self) -> None:
        workspace = self.tmp / "ws"
        outside = self.tmp / "outside"
        workspace.mkdir()
        outside.mkdir()
        real = outside / "real.md"
        self.write(real, "real\n")
        link = workspace / "link.md"
        link.symlink_to(real)
        self.state.mkdir(parents=True)
        self.write(
            self.state / "config.json",
            json.dumps({"version": 1, "roots": [str(workspace)]}),
        )
        path = self.plan_file(
            "x7-escape.json",
            [{"kind": "move", "src": str(link), "dst": str(workspace / "renamed.md")}],
        )
        code, out, _ = self.run_cli(["apply", str(path), "--yes", "--state-dir", str(self.state)])
        self.assertEqual(code, 4)
        self.assertIn("outside the allowed bases", out)
        self.assertEqual(real.read_text(encoding="utf-8"), "real\n")
        self.assertTrue(link.is_symlink())
        self.assertFalse((workspace / "renamed.md").exists())

    def test_x7_symlink_dir_within_bases_follows_target(self) -> None:
        workspace = self.tmp / "ws"
        workspace.mkdir()
        target_dir = workspace / "target-dir"
        target_dir.mkdir()
        real = target_dir / "real.txt"
        self.write(real, "payload\n")
        linkdir = workspace / "linkdir"
        linkdir.symlink_to(target_dir, target_is_directory=True)
        self.state.mkdir(parents=True)
        self.write(
            self.state / "config.json",
            json.dumps({"version": 1, "roots": [str(workspace)]}),
        )
        path = self.plan_file(
            "x7-linkdir.json",
            [{"kind": "move", "src": str(linkdir / "real.txt"), "dst": str(workspace / "moved.txt")}],
        )
        code, out, _ = self.run_cli(["apply", str(path), "--yes", "--state-dir", str(self.state)])
        self.assertEqual(code, 0, out)
        self.assertFalse(real.exists(), "the move follows the symlink to the real file")
        self.assertFalse((linkdir / "real.txt").exists())
        self.assertEqual((workspace / "moved.txt").read_text(encoding="utf-8"), "payload\n")

    # ---- X6: hostile plan ids never escape the backup directory -------------

    def test_x6_escaping_plan_id_is_refused_and_creates_nothing(self) -> None:
        path = self.plan_file(
            "x6-escape.json",
            [{"kind": "mkdir", "path": str(self.state / "plans")}],
            id="../../escaped-backup",
        )
        code, _, err = self.run_cli(["apply", str(path), "--yes", "--state-dir", str(self.state)])
        self.assertEqual(code, 1)
        self.assertIn("safe slug", err)
        self.assertFalse((self.tmp / "escaped-backup").exists())
        self.assertFalse(self.state.exists())

    def test_x6_library_apply_asserts_backup_dir_stays_under_backups(self) -> None:
        plan = {
            "version": 1,
            "id": "../../escaped-backup",
            "created_at": "2026-11-19T11:00:00+08:00",
            "title": "escape",
            "notes": "",
            "operations": [{"kind": "mkdir", "path": str(self.state / "plans")}],
        }
        with self.isolated_home():
            with self.assertRaises(ApplyError) as caught:
                apply_plan(plan, self.state, dry_run=False, yes=True)
        self.assertIn("escapes the backup directory", str(caught.exception))
        self.assertFalse((self.state / "backups").exists())
        self.assertFalse((self.tmp / "escaped-backup").exists())

    # ---- backups: a second run never overwrites the first run's material ---

    def test_same_id_twice_keeps_both_backup_directories(self) -> None:
        data_dir = self.state / "data"
        self.write(data_dir / "victim.md", "first")
        plan = {
            "version": 1,
            "id": "same-id",
            "created_at": "2026-11-19T11:00:00+08:00",
            "title": "twice",
            "notes": "",
            "operations": [
                {"kind": "write", "path": str(data_dir / "victim.md"), "content": "second"}
            ],
        }
        with self.isolated_home():
            first = apply_plan(plan, self.state, dry_run=False, yes=True)
            second = apply_plan(plan, self.state, dry_run=False, yes=True)
        self.assertTrue(first["ok"] and second["ok"])
        backups = self.state / "backups"
        names = sorted(item.name for item in backups.iterdir())
        self.assertEqual(names[0], "same-id")
        self.assertTrue(names[1].startswith("same-id-"), names)
        first_backup = backups / "same-id" / "001-victim.md"
        self.assertEqual(first_backup.read_text(encoding="utf-8"), "first")
        self.assertEqual((data_dir / "victim.md").read_text(encoding="utf-8"), "second")

    # ---- mkdir undo: created directories are rolled back and reported -------

    def test_failed_batch_removes_directories_it_created(self) -> None:
        fresh = self.tmp / "proj" / "fresh"
        plan = {
            "version": 1,
            "id": "mkdir-undo",
            "created_at": "2026-11-19T11:00:00+08:00",
            "title": "mkdir undo",
            "notes": "",
            "operations": [
                {"kind": "mkdir", "path": str(fresh)},
                {"kind": "write", "path": str(fresh / "n.md"), "content": "# n\n"},
                {"kind": "write", "path": str(fresh), "content": "x"},
            ],
        }
        with self.isolated_home():
            with self.assertRaises(ApplyError) as caught:
                apply_plan(plan, self.state, dry_run=False, yes=True, extra_bases=[self.tmp])
        self.assertIn("rolled back", str(caught.exception))
        self.assertFalse(fresh.exists())
        self.assertFalse((self.tmp / "proj").exists(), "the emptied parent is removed too")

    def test_rollback_reports_directories_it_could_not_remove(self) -> None:
        busy = self.tmp / "busy"
        self.write(busy / "keep.txt", "keep")
        residual = rollback([("mkdir", {"path": str(busy)})])
        self.assertEqual(residual, [str(busy)])
        self.assertTrue(busy.is_dir())

    # ---- findings plan: one manual op per evidence example -------------------

    def test_findings_expand_one_manual_op_per_example(self) -> None:
        findings = [
            {
                "severity": "high",
                "rule": "stale-state",
                "path": "/tmp/x/README.md",
                "message": "stale",
                "suggestion": "refresh it",
                "evidence": {"count": 3, "examples": ["/tmp/x/a.md", "/tmp/x/b.md", "/tmp/x/c.md"]},
            },
            {
                "severity": "medium",
                "rule": "orphan-knowledge",
                "path": "/tmp/y/z.md",
                "message": "orphan",
                "suggestion": "index it",
                "evidence": {"count": 1},
            },
        ]
        plan = plan_from_findings(findings)
        manual = [op for op in plan["operations"] if op["kind"] == "manual"]
        self.assertEqual(
            [op["path"] for op in manual],
            ["/tmp/x/a.md", "/tmp/x/b.md", "/tmp/x/c.md", "/tmp/y/z.md"],
        )

    # ---- C2: plans carry absolute paths and never follow apply's CWD --------

    def test_plan_move_resolves_relative_paths_at_plan_time(self) -> None:
        cwd_a = self.tmp / "cwdA"
        self.write(cwd_a / "same.txt", "A-CONTENT")
        cwd_b = self.tmp / "cwdB"
        self.write(cwd_b / "same.txt", "B-DIFFERENT")
        original = Path.cwd()
        os.chdir(cwd_a)
        try:
            plan = plan_move(Path("same.txt"), Path("moved.txt"))
        finally:
            os.chdir(original)
        resolved_a = cwd_a.resolve()
        self.assertEqual(plan["operations"][0], {"kind": "mkdir", "path": str(resolved_a)})
        self.assertEqual(
            plan["operations"][1],
            {"kind": "move", "src": str(resolved_a / "same.txt"), "dst": str(resolved_a / "moved.txt")},
        )

        self.state.mkdir(parents=True)
        self.write(
            self.state / "config.json",
            json.dumps({"version": 1, "roots": [str(cwd_a)]}),
        )
        path = self.tmp / "c2-plan.json"
        self.write(path, json.dumps(plan, ensure_ascii=False))
        os.chdir(cwd_b)
        try:
            code, out, _ = self.run_cli(["apply", str(path), "--yes", "--state-dir", str(self.state)])
        finally:
            os.chdir(original)
        self.assertEqual(code, 0, out)
        self.assertEqual((cwd_a / "moved.txt").read_text(encoding="utf-8"), "A-CONTENT")
        self.assertFalse((cwd_a / "same.txt").exists())
        self.assertEqual((cwd_b / "same.txt").read_text(encoding="utf-8"), "B-DIFFERENT")

    def test_relative_paths_in_a_plan_are_refused(self) -> None:
        path = self.plan_file(
            "c2-relative.json",
            [{"kind": "write", "path": "rel.txt", "content": "x"}],
        )
        code, _, err = self.run_cli(["apply", str(path), "--yes", "--state-dir", str(self.state)])
        self.assertEqual(code, 1)
        self.assertIn("must be an absolute path", err)

    # ---- H2: moves carry no pointer field ------------------------------------

    def test_op_move_has_no_pointer_field(self) -> None:
        op = op_move(Path("/tmp/a.md"), Path("/tmp/b.md"))
        self.assertEqual(sorted(op), ["dst", "kind", "src"])
        cwd = self.tmp / "h2"
        self.write(cwd / "a.md", "a")
        plan = plan_move(cwd / "a.md", cwd / "b.md")
        for operation in plan["operations"]:
            self.assertNotIn("pointer", operation)

    # ---- U2: init refuses a broken existing config instead of no-op ---------

    def test_u2_init_with_broken_existing_config_fails_with_guidance(self) -> None:
        workspace = self.tmp / "ws"
        workspace.mkdir()
        self.state.mkdir(parents=True)
        config = self.state / "config.json"
        self.write(config, json.dumps({"version": 1, "roots": str(workspace)}))
        before = config.read_bytes()
        code, _, err = self.run_cli(
            ["init", "--root", str(workspace), "--yes", "--state-dir", str(self.state)]
        )
        self.assertEqual(code, 1)
        self.assertIn("config exists but invalid", err)
        self.assertIn(f"fix or remove {config}", err)
        self.assertIn("guster init --root", err)
        self.assertEqual(config.read_bytes(), before)

    def test_u2_init_with_valid_existing_config_leaves_it_untouched(self) -> None:
        workspace = self.tmp / "ws"
        workspace.mkdir()
        self.state.mkdir(parents=True)
        config = self.state / "config.json"
        self.write(config, json.dumps({"version": 1, "roots": [str(workspace)]}))
        before = config.read_bytes()
        code, out, _ = self.run_cli(
            ["init", "--root", str(workspace), "--yes", "--state-dir", str(self.state)]
        )
        self.assertEqual(code, 0, out)
        self.assertIn("APPLIED", out)
        self.assertEqual(config.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
