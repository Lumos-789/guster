from __future__ import annotations

import contextlib
import io
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

from guster import cli  # noqa: E402
from guster.util import has_flow_style_rows, parse_register_rows  # noqa: E402

REGISTER_HEADER = "schema: register/v1\nkind: projects\nupdated: '2026-11-26'\n"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def commit_all(repo: Path) -> None:
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.com"]
    subprocess.run(git + ["add", "-A"], check=True, capture_output=True)
    subprocess.run(git + ["commit", "-qm", "init"], check=True, capture_output=True)


class Sandbox(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="guster-cli-fixes-")).resolve()
        self.home = self.tmp / "home"
        self.workspace = self.tmp / "workspace"
        self.project = self.workspace / "proj"
        self.hub = self.tmp / "hub"
        self.state = self.tmp / "state"
        self.home.mkdir()
        self.project.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(self.project)], check=True, capture_output=True)
        write(self.project / "AGENTS.md", "# Project\n")
        write(self.hub / "AGENTS.md", "# Hub\n")
        write(self.hub / "register" / "projects.yaml", REGISTER_HEADER)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def doctor(self, expect: int = 0):
        code, out, err = self.run_cli(
            [
                "doctor", "--scope", "machine", "--root", str(self.workspace), "--hub", str(self.hub),
                "--state-dir", str(self.state), "--json",
            ]
        )
        self.assertEqual(code, expect, err)
        return json.loads(out)["findings"]


class RegisterParserTests(unittest.TestCase):
    def test_keys_after_a_block_list_stay_with_the_row(self) -> None:
        rows = parse_register_rows(
            "projects:\n"
            "  - id: proj-block\n"
            "    aliases:\n"
            "      - block\n"
            "      - blk\n"
            "    spec:\n"
            "      path: /tmp/block\n"
            "    deps:\n"
            "      - other\n"
            "    as_of: '2026-11-26'\n"
            "    status: active\n"
            "    name: Proj Block\n"
        )
        self.assertEqual(
            rows,
            [{"id": "proj-block", "path": "/tmp/block", "as_of": "2026-11-26", "status": "active", "name": "Proj Block"}],
        )

    def test_a_nested_mapping_item_is_neither_a_row_nor_a_leaked_key(self) -> None:
        rows = parse_register_rows(
            "projects:\n"
            "  - id: app\n"
            "    deps:\n"
            "      - id: nested\n"
            "        name: Leaky\n"
            "        spec:\n"
            "          path: /tmp/decoy\n"
            "    name: Real\n"
        )
        self.assertEqual(rows, [{"id": "app", "name": "Real"}])

    def test_a_sub_mapping_under_spec_does_not_override_the_path(self) -> None:
        rows = parse_register_rows(
            "  - id: a\n    spec:\n      path: /real\n      owner:\n        path: /decoy\n    status: active\n"
        )
        self.assertEqual(rows, [{"id": "a", "path": "/real", "status": "active"}])

    def test_inline_flow_spec_is_read_and_flow_rows_are_detected(self) -> None:
        rows = parse_register_rows("projects:\n  - id: f\n    spec: {path: /tmp/f, aliases: [x]}\n")
        self.assertEqual(rows[0]["path"], "/tmp/f")
        self.assertTrue(has_flow_style_rows("projects:\n  - {id: x, spec: {path: /tmp/x}}\n"))
        self.assertFalse(has_flow_style_rows("projects:\n  - id: x\n    spec:\n      path: /tmp/x\n"))


class RegisterFindingTests(Sandbox):
    def register(self, body: str) -> None:
        write(self.hub / "register" / "projects.yaml", REGISTER_HEADER + body)

    def test_a_valid_block_list_row_is_not_reported_as_a_contract_violation(self) -> None:
        self.register(
            "projects:\n  - id: proj\n    aliases:\n      - a\n    spec:\n      path: "
            + str(self.project) + "\n"
        )
        messages = [item["message"] for item in self.doctor() if item["rule"] == "registry-format"]
        self.assertFalse([m for m in messages if "no spec.path" in m], messages)

    def test_flow_style_rows_are_reported_instead_of_reading_as_zero_rows(self) -> None:
        self.register("projects:\n  - {id: proj, spec: {path: " + str(self.project) + "}}\n")
        messages = [item["message"] for item in self.doctor() if item["rule"] == "registry-format"]
        self.assertTrue([m for m in messages if "flow-style" in m], messages)

    def test_the_unscanned_row_hint_names_the_command_that_now_works(self) -> None:
        elsewhere = self.tmp / "elsewhere" / "proj"
        elsewhere.mkdir(parents=True)
        self.register("projects:\n  - id: far\n    spec:\n      path: " + str(elsewhere) + "\n")
        hints = [
            item["suggestion"]
            for item in self.doctor()
            if item["title"] == "Register rows are outside the machine scan"
        ]
        self.assertEqual(len(hints), 1)
        self.assertIn("`guster init --root <dir>`", hints[0])


class StaleChecklistTests(Sandbox):
    def test_every_stale_document_reaches_the_review_checklist(self) -> None:
        write(self.project / ".agents" / "README.md", "# Index\n")
        for day in ("01", "02", "03"):
            write(
                self.project / ".agents" / "plans" / f"old-{day}.md",
                f"# Plan {day}\n\n**最后更新**: 2020-01-{day}\n",
            )
        commit_all(self.project)
        code, out, err = self.run_cli(["plan", "findings", "--root", str(self.project), "--state-dir", str(self.state), "--json"])
        self.assertEqual(code, 0, err)
        stale = [op for op in json.loads(out)["operations"] if op["reason"].startswith("stale-state")]
        self.assertEqual(len(stale), 3)


class CapNoticeTests(Sandbox):
    def test_pointer_findings_are_capped_with_a_notice_that_names_the_rest(self) -> None:
        wiki = self.project / ".agents" / "wiki"
        lines = ["# Index", ""]
        for number in range(1, 106):
            write(
                wiki / f"note-{number}.md",
                f"---\ntype: pointer\nupdated: 2026-11-26\n---\n# note {number}\n\nTruth: [card](../cards/missing-{number}.md)\n",
            )
            lines.append(f"| `note-{number}.md` | t |")
        write(self.project / ".agents" / "README.md", "\n".join(lines) + "\n")
        commit_all(self.project)
        findings = self.doctor(expect=2)
        broken = [item for item in findings if item["rule"] == "broken-pointer"]
        notice = [item for item in findings if item["rule"] == "finding-cap"]
        self.assertEqual(len(broken), 100)
        self.assertEqual(len(notice), 1)
        self.assertEqual(notice[0]["evidence"], {"rule": "broken-pointer", "total": 105, "listed": 100})
        self.assertEqual(notice[0]["severity"], "info")

    def test_secret_in_git_findings_are_capped_the_same_way(self) -> None:
        for number in range(1, 22):
            write(self.project / f"svc{number}" / ".env", "TOKEN=not-a-real-token\n")
        commit_all(self.project)
        findings = self.doctor(expect=3)
        critical = [item for item in findings if item["rule"] == "secret-in-git"]
        notice = [item for item in findings if item["rule"] == "finding-cap"]
        self.assertEqual(len(critical), 20)
        self.assertEqual([item["evidence"] for item in notice], [{"rule": "secret-in-git", "total": 21, "listed": 20}])


class StatusShapeTests(Sandbox):
    def test_an_odd_cached_registry_rescans_instead_of_crashing(self) -> None:
        write(
            self.state / "registry.json",
            '{"summary": null, "workspaces": "not-a-list", "plugin": "guster"}\n',
        )
        code, out, err = self.run_cli(["status", "--root", str(self.workspace), "--state-dir", str(self.state)])
        self.assertEqual(code, 0, err)
        self.assertIn("unexpected shape", err)
        self.assertNotIn("Traceback", out + err)

    def test_status_json_carries_zones_and_the_first_run_markers(self) -> None:
        (self.home / "Projects" / "proj").mkdir(parents=True)
        zone = self.tmp / "zone"
        write(zone / "tool" / "README.md", "# tool\n")
        code, out, err = self.run_cli(["status", "--state-dir", str(self.state), "--json"])
        self.assertEqual(code, 0, err)
        first = json.loads(out)
        self.assertTrue(first["unconfigured"])
        self.assertTrue(first["auto_roots"])
        self.run_cli(["zones", "add", str(zone), "--state-dir", str(self.state)])
        # the cached registry predates the zone: drop it so status rescans
        (self.state / "registry.json").unlink()
        code, out, err = self.run_cli(["status", "--state-dir", str(self.state), "--json"])
        self.assertEqual(code, 0, err)
        second = json.loads(out)
        self.assertEqual([item["path"] for item in second["zones"]], [str(zone)])
        self.assertFalse(second["unconfigured"])


class CredentialsJsonTests(Sandbox):
    def test_parse_warnings_survive_the_json_output(self) -> None:
        write(
            self.home / ".agents" / "credentials" / "registry.md",
            "| ID | scope | site | account | kind | locations | keys |\n"
            "|---|---|---|---|---|---|---|\n"
            "| broken | personal | example.com |\n",
        )
        code, out, err = self.run_cli(
            ["credentials", "--root", str(self.workspace), "--state-dir", str(self.state), "--json"]
        )
        self.assertEqual(code, 0, err)
        warnings = json.loads(out)["parse_warnings"]
        self.assertEqual(len(warnings), 1)
        self.assertIn("line 3", warnings[0])


class ZonesPathTests(Sandbox):
    def test_a_relative_zone_path_is_blamed_on_the_argument(self) -> None:
        (self.tmp / "relzone").mkdir()
        cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            code, _, err = self.run_cli(["zones", "add", "relzone", "--state-dir", str(self.state)])
        finally:
            os.chdir(cwd)
        self.assertEqual(code, 1, err)
        self.assertIn("zone path must be an absolute path", err)
        self.assertNotIn("config.json", err)
        self.assertFalse((self.state / "config.json").exists())


if __name__ == "__main__":
    unittest.main()
