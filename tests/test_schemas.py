from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from guster.executor import apply_plan  # noqa: E402
from guster.hub import plan_init_hub, validate_hub  # noqa: E402
from guster.layout import load_manifest  # noqa: E402
from guster.planner import build_plan, op_manual, op_mkdir, op_move, op_write  # noqa: E402

HUB_SCHEMA_URL = "https://raw.githubusercontent.com/Lumos-789/guster/main/schemas/hub.schema.json"
PLAN_SCHEMA_URL = "https://raw.githubusercontent.com/Lumos-789/guster/main/schemas/plan.schema.json"
DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"

HUB_SCHEMA = json.loads((ROOT / "schemas" / "hub.schema.json").read_text(encoding="utf-8"))
PLAN_SCHEMA = json.loads((ROOT / "schemas" / "plan.schema.json").read_text(encoding="utf-8"))


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def _type_ok(value: Any, expected: Any) -> bool:
    names = [expected] if isinstance(expected, str) else list(expected)
    actual = _json_type(value)
    return any(
        name == actual or (name == "number" and actual in ("integer", "number"))
        for name in names
    )


def _enum_ok(value: Any, options: List[Any]) -> bool:
    return any(
        isinstance(option, bool) == isinstance(value, bool) and option == value
        for option in options
    )


def validate(instance: Any, schema: Dict[str, Any], path: str = "$") -> List[str]:
    """Minimal JSON Schema checker for the keyword subset the schemas use.

    Supports type/enum/required/properties/additionalProperties plus the
    pieces those schemas cannot do without: items, minLength, oneOf, if/then.
    Unknown keywords are ignored, like any conforming validator would.
    """
    errors: List[str] = []
    if "oneOf" in schema:
        passes = sum(1 for sub in schema["oneOf"] if not validate(instance, sub, path))
        if passes != 1:
            errors.append(f"{path}: matches {passes} of {len(schema['oneOf'])} oneOf variants")
    if "enum" in schema and not _enum_ok(instance, schema["enum"]):
        errors.append(f"{path}: {instance!r} is not one of {schema['enum']!r}")
    if "type" in schema and not _type_ok(instance, schema["type"]):
        errors.append(f"{path}: expected type {schema['type']!r}, got {_json_type(instance)}")
    if isinstance(instance, str) and len(instance) < schema.get("minLength", 0):
        errors.append(f"{path}: shorter than minLength {schema['minLength']}")
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required property {key!r}")
        properties = schema.get("properties", {})
        for key, value in instance.items():
            if key in properties:
                errors.extend(validate(value, properties[key], f"{path}.{key}"))
            elif "additionalProperties" in schema:
                extra = schema["additionalProperties"]
                if extra is False:
                    errors.append(f"{path}: unexpected property {key!r}")
                else:
                    errors.extend(validate(value, extra, f"{path}.{key}"))
    if isinstance(instance, list) and "items" in schema:
        for index, item in enumerate(instance):
            errors.extend(validate(item, schema["items"], f"{path}[{index}]"))
    if "if" in schema:
        branch = schema.get("then") if not validate(instance, schema["if"], path) else schema.get("else")
        if branch is not None:
            errors.extend(validate(instance, branch, path))
    return errors


class SchemaShapeTests(unittest.TestCase):
    def test_schemas_are_valid_json_with_expected_shape(self) -> None:
        for schema, url in ((HUB_SCHEMA, HUB_SCHEMA_URL), (PLAN_SCHEMA, PLAN_SCHEMA_URL)):
            with self.subTest(url=url):
                self.assertEqual(schema["$schema"], DRAFT_2020_12)
                self.assertEqual(schema["$id"], url)
                self.assertEqual(schema["type"], "object")
                self.assertTrue(schema["properties"])
                for name, spec in schema["properties"].items():
                    self.assertIsInstance(name, str)
                    self.assertIsInstance(spec, dict)


class HubSchemaTests(unittest.TestCase):
    def test_template_modeline_points_at_hub_schema(self) -> None:
        first_line = (ROOT / "templates" / "hub" / "hub.yaml.tmpl").read_text(
            encoding="utf-8"
        ).splitlines()[0]
        self.assertEqual(
            first_line,
            f"# yaml-language-server: $schema={HUB_SCHEMA_URL}",
        )

    def test_rendered_template_passes_hub_schema(self) -> None:
        template = (ROOT / "templates" / "hub" / "hub.yaml.tmpl").read_text(encoding="utf-8")
        rendered = template
        for key, value in {
            "DATE": "2026-01-01",
            "HUB_NAME": "schema-check-hub",
            "PLUGIN_VERSION": "0.0.0-test",
            "KNOWLEDGE_PATH": "knowledge",
            "PROJECTS_PATH": "projects",
            "TOOLS_PATH": "tools",
        }.items():
            rendered = rendered.replace("{{" + key + "}}", value)
        self.assertNotIn("{{", rendered)
        with tempfile.TemporaryDirectory(prefix="guster-schema-") as tmp:
            manifest_path = Path(tmp) / "hub.yaml"
            manifest_path.write_text(rendered, encoding="utf-8")
            manifest = load_manifest(manifest_path)
        self.assertEqual(
            validate(manifest, HUB_SCHEMA),
            [],
            "rendered hub.yaml template must satisfy hub.schema.json",
        )

    def test_rendered_hub_still_passes_hub_validate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="guster-schema-") as tmp:
            hub = Path(tmp) / "hub"
            state = Path(tmp) / "state"
            plan = plan_init_hub(hub)
            result = apply_plan(plan, state, dry_run=False, yes=True)
            self.assertTrue(result["ok"], result.get("errors"))
            self.assertTrue(validate_hub(hub)["ok"])
            self.assertEqual(validate(load_manifest(hub / "hub.yaml"), HUB_SCHEMA), [])

    def test_waiver_entries_need_rule_and_reason(self) -> None:
        base: Dict[str, Any] = {
            "schema_version": "2",
            "profile": "lite",
            "paths": {"knowledge": "knowledge", "projects": "projects", "tools": "tools"},
        }
        with_waiver = dict(
            base,
            doctor={"waivers": [{"rule": "CTX-03", "reason": "legacy pointer style"}]},
        )
        self.assertEqual(validate(with_waiver, HUB_SCHEMA), [])
        broken = dict(
            base,
            doctor={"waivers": [{"rule": "CTX-03", "path": "notes/old.md"}]},
        )
        errors = validate(broken, HUB_SCHEMA)
        self.assertTrue(any("reason" in error for error in errors), errors)

    def test_schema_2_requires_core_paths(self) -> None:
        self.assertTrue(any("paths" in error for error in validate({"schema_version": "2"}, HUB_SCHEMA)))
        declared = {
            "schema_version": "2",
            "paths": {"knowledge": "kb", "projects": "proj", "tools": "tools"},
        }
        self.assertEqual(validate(declared, HUB_SCHEMA), [])

    def test_unknown_top_level_key_is_rejected(self) -> None:
        errors = validate({"schema_version": "1", "surprise": "x"}, HUB_SCHEMA)
        self.assertTrue(any("surprise" in error for error in errors), errors)


class PlanSchemaTests(unittest.TestCase):
    def test_build_plan_output_passes_plan_schema(self) -> None:
        plan = build_plan(
            "Schema contract check",
            [
                op_mkdir(Path("/tmp/schema-check/kb")),
                op_write(Path("/tmp/schema-check/kb/README.md"), "# Index\n"),
                op_move(
                    Path("/tmp/schema-check/a.md"),
                    Path("/tmp/schema-check/kb/a.md"),
                    pointer={
                        "path": "/tmp/schema-check/a.md.moved.md",
                        "content": "# Moved\n",
                    },
                ),
                op_move(Path("/tmp/schema-check/b.md"), Path("/tmp/schema-check/kb/b.md")),
                op_manual("notes.md", "Review the move", "CTX-09: contract check"),
            ],
            notes="Exercises every operation kind.",
        )
        self.assertEqual(plan["version"], 1)
        self.assertEqual(
            sorted(op["kind"] for op in plan["operations"]),
            ["manual", "mkdir", "move", "move", "write"],
        )
        self.assertEqual(
            validate(plan, PLAN_SCHEMA),
            [],
            "a real build_plan result must satisfy plan.schema.json",
        )

    def test_plan_version_must_be_the_integer_one(self) -> None:
        for bad in ("1", 2, None):
            with self.subTest(version=bad):
                errors = validate({"version": bad}, PLAN_SCHEMA["properties"]["version"])
                self.assertNotEqual(errors, [])

    def test_operations_shape_is_enforced_per_kind(self) -> None:
        cases = {
            "move-without-dst": {"kind": "move", "src": "/tmp/a.md"},
            "move-with-empty-src": {"kind": "move", "src": "", "dst": "/tmp/b.md"},
            "write-without-content": {"kind": "write", "path": "/tmp/a.md"},
            "manual-without-action": {"kind": "manual", "path": "", "reason": "why"},
            "unknown-kind": {"kind": "unlink", "path": "/tmp/a.md"},
        }
        for name, op in cases.items():
            with self.subTest(op=name):
                errors = validate(op, PLAN_SCHEMA["properties"]["operations"]["items"])
                self.assertNotEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
