from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .discover import ScanConfig, default_hub, default_roots, scan
from .executor import ApplyError, apply_plan, init_home
from .hub import attach_hub, default_hub_path, init_hub, validate_hub
from .metrics import compute_metrics, metric_line
from .planner import (
    load_plan,
    plan_from_findings,
    plan_init_project,
    plan_move,
    save_plan,
)
from .policy import run_policy
from .report import redacted_registry, render_report, render_status, write_json, write_report
from .util import human_bytes, json_dumps, load_json, now_iso, save_json


def default_state_dir(home: Path) -> Path:
    return home / ".agents" / "guster"


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", action="append", default=None, help="Workspace root; repeatable.")
    parser.add_argument(
        "--scope",
        choices=["auto", "machine", "hub", "project", "group"],
        default="auto",
        help="Context scope: machine (default), hub, one project, or a group of projects.",
    )
    parser.add_argument("--hub", default=None, help="Guster Hub path.")
    parser.add_argument("--state-dir", default=None, help="Guster state directory.")
    parser.add_argument("--json", action="store_true", help="Emit JSON.")
    parser.add_argument("--quiet", action="store_true", help="Only print errors.")


def build_config(args: argparse.Namespace) -> ScanConfig:
    home = Path.home()
    base_state = Path(args.state_dir).expanduser() if args.state_dir else default_state_dir(home)
    config_path = base_state / "config.json"
    local: Any = {}
    if config_path.is_file():
        try:
            local = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError(f"cannot read Guster config {config_path}: {exc}") from exc
        if not isinstance(local, dict):
            raise ValueError(f"Guster config must be a JSON object: {config_path}")

    if args.hub:
        hub = Path(args.hub).expanduser()
    elif isinstance(local, dict) and local.get("hub"):
        hub = Path(local["hub"]).expanduser()
    else:
        hub = default_hub(home)

    explicit_roots = [Path(item).expanduser() for item in args.root] if args.root else []
    for root in explicit_roots:
        if not root.exists():
            raise ValueError(f"workspace root does not exist: {root.resolve()}")
        if not root.is_dir():
            raise ValueError(f"workspace root is not a directory: {root.resolve()}")
    scope = getattr(args, "scope", "auto") or "auto"
    if scope == "auto":
        scope = "machine" if not explicit_roots else ("project" if len(explicit_roots) == 1 else "group")
    if scope in {"project", "group"} and not explicit_roots:
        raise ValueError("--scope project|group needs at least one --root")
    if scope == "hub":
        roots: List[Path] = []
    elif explicit_roots:
        roots = explicit_roots
    elif isinstance(local, dict) and local.get("roots"):
        roots = [Path(item).expanduser() for item in local["roots"]]
    else:
        roots = default_roots(home)

    state_dir = base_state
    if not args.state_dir and (scope != "machine" or explicit_roots):
        # Scoped runs keep their own registry and trend so they never overwrite
        # the machine-wide view.
        key = "|".join([scope] + sorted(str(root.resolve()) for root in roots) + [str(hub or "")])
        state_dir = base_state / "scoped" / hashlib.sha1(key.encode()).hexdigest()[:10]

    plugin_root = Path(__file__).resolve().parents[2]
    return ScanConfig(
        home=home,
        hub=hub,
        roots=roots,
        state_dir=state_dir,
        plugin_root=plugin_root,
        max_depth=int(local.get("scan_max_depth", 5)) if isinstance(local, dict) else 5,
        scope=scope,
    )


def ensure_state(config: ScanConfig) -> None:
    config.state_dir.mkdir(parents=True, exist_ok=True)
    (config.state_dir / "plans").mkdir(parents=True, exist_ok=True)
    (config.state_dir / "backups").mkdir(parents=True, exist_ok=True)


def do_scan(config: ScanConfig, write: bool = True) -> Dict[str, Any]:
    ensure_state(config)
    registry = scan(config)
    if write:
        save_json(config.state_dir / "registry.json", registry)
    return registry


def load_registry(config: ScanConfig) -> Optional[Dict[str, Any]]:
    path = config.state_dir / "registry.json"
    if not path.is_file():
        return None
    data = load_json(path, None)
    return data if isinstance(data, dict) else None


def evaluate(registry: Dict[str, Any], config: ScanConfig) -> Dict[str, Any]:
    policy_result = run_policy(registry, config)
    metric_result = compute_metrics(registry, policy_result)
    return {"policy": policy_result, "metrics": metric_result}


def append_metric(config: ScanConfig, metric_result: Dict[str, Any]) -> None:
    ensure_state(config)
    path = config.state_dir / "metrics.jsonl"
    line = {
        "at": metric_result.get("generated_at", now_iso()),
        "chi": metric_result.get("chi"),
        **metric_result.get("metrics", {}),
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(line, ensure_ascii=False) + "\n")


def write_findings(config: ScanConfig, policy_result: Dict[str, Any]) -> None:
    ensure_state(config)
    save_json(config.state_dir / "findings.json", policy_result)


def print_scan_summary(registry: Dict[str, Any], config: ScanConfig) -> None:
    summary = registry.get("summary", {})
    print("Guster scan")
    print(f"  workspaces: {', '.join(registry.get('workspaces', []))}")
    print(f"  hub:        {registry.get('hub') or '(none)'}")
    print(f"  projects:   {summary.get('projects', 0)}")
    print(f"  .agents:    {summary.get('agents_dirs', 0)} (indexed {summary.get('agents_with_index', 0)})")
    print(f"  skills:     {summary.get('skills', 0)} unique / {summary.get('skill_copies', 0)} copies")
    print(f"  knowledge:  {summary.get('knowledge', 0)}")
    print(f"  state:      {summary.get('state', 0)}")
    print(f"  evidence:   {summary.get('evidence', 0)}")
    print(f"  credentials:{summary.get('secret_files', 0)} files; {summary.get('inline_bearers', 0)} inline")
    print(f"  registry:   {config.state_dir / 'registry.json'}")


def cmd_status(args: argparse.Namespace) -> int:
    config = build_config(args)
    registry = load_registry(config)
    if registry is None:
        registry = do_scan(config, write=True)
    result = evaluate(registry, config)
    if args.json:
        print(json_dumps({
            "registry": {
                "plugin": registry.get("plugin"),
                "generated_at": registry.get("generated_at"),
                "hub": registry.get("hub"),
                "workspaces": registry.get("workspaces"),
                "summary": registry.get("summary"),
            },
            "metrics": result["metrics"],
            "findings": len(result["policy"]["findings"]),
        }))
    else:
        print(render_status(registry, result["metrics"]))
        print(metric_line(result["metrics"]))
        print(f"findings: {len(result['policy']['findings'])}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    config = build_config(args)
    registry = do_scan(config, write=not args.no_write)
    if args.json:
        print(json_dumps(registry))
    elif not args.quiet:
        print_scan_summary(registry, config)
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    config = build_config(args)
    registry = do_scan(config, write=True)
    result = evaluate(registry, config)
    policy_result = result["policy"]
    if not args.no_write:
        write_findings(config, policy_result)
    findings = policy_result["findings"]
    if args.json:
        print(json_dumps(policy_result))
    elif not args.quiet:
        print(render_report(registry, policy_result, result["metrics"]))
    severities = {item["severity"] for item in findings}
    if "critical" in severities:
        return 3
    if "high" in severities:
        return 2
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    config = build_config(args)
    registry = do_scan(config, write=True)
    result = evaluate(registry, config)
    metric_result = result["metrics"]
    if not args.no_write:
        append_metric(config, metric_result)
    if args.json:
        print(json_dumps(metric_result))
    elif not args.quiet:
        print(f"Guster Context Health: {metric_result['chi']} / 100")
        print("")
        dims = set(metric_result.get("dims") or [])
        for key, value in metric_result["scores"].items():
            if dims and key not in dims:
                continue
            print(f"  {key.upper():4s} {value:6.1f}")
        print("")
        print(metric_line(metric_result))
        print(f"registry: {config.state_dir / 'registry.json'}")
        print(f"metrics:  {config.state_dir / 'metrics.jsonl'}")
    if args.trend:
        path = config.state_dir / "metrics.jsonl"
        if path.is_file():
            lines = path.read_text(encoding="utf-8").splitlines()[-10:]
            print("")
            print("Recent trend:")
            for line in lines:
                try:
                    item = json.loads(line)
                    print(f"  {item.get('at')}  CHI {item.get('chi')}")
                except ValueError:
                    continue
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    config = build_config(args)
    ensure_state(config)
    if args.plan_action == "findings":
        registry = do_scan(config, write=True)
        result = evaluate(registry, config)
        plan = plan_from_findings(result["policy"]["findings"])
    elif args.plan_action == "move":
        src = Path(args.source).expanduser()
        dst = Path(args.destination).expanduser()
        plan = plan_move(src, dst)
    elif args.plan_action == "init":
        plan = plan_init_project(Path(args.project).expanduser())
    else:
        raise SystemExit(f"unknown plan action: {args.plan_action}")

    path = save_plan(config.state_dir, plan)
    if args.json:
        print(json_dumps(plan))
    elif not args.quiet:
        print(f"plan: {path}")
        print(f"operations: {len(plan.get('operations', []))}")
        for index, operation in enumerate(plan.get("operations", []), start=1):
            kind = operation.get("kind")
            if kind == "move":
                print(f"  {index}. move {operation['src']} -> {operation['dst']}")
            elif kind == "mkdir":
                print(f"  {index}. mkdir {operation['path']}")
            elif kind == "write":
                print(f"  {index}. write {operation['path']}")
            elif kind == "append":
                print(f"  {index}. append {operation['path']}")
            elif kind == "manual":
                print(f"  {index}. manual {operation['path']}: {operation['action']}")
        print("review the plan; apply with `guster apply <plan> --yes`.")
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    config = build_config(args)
    ensure_state(config)
    if args.dry_run and args.yes:
        raise ValueError("--dry-run and --yes are mutually exclusive")
    plan = load_plan(Path(args.plan).expanduser())
    result = apply_plan(
        plan,
        config.state_dir,
        dry_run=not args.yes,
        yes=args.yes,
    )
    if args.json:
        print(json_dumps(result))
    elif not args.quiet:
        if result.get("dry_run"):
            mode = "DRY RUN"
        elif result.get("ok"):
            mode = "APPLIED"
        else:
            mode = "FAILED"
        print(f"{mode}: {result.get('plan')}")
        print(f"  applied: {result.get('applied', 0)}")
        print(f"  skipped: {result.get('skipped', 0)}")
        if result.get("backup"):
            print(f"  backup:  {result['backup']}")
        if result.get("errors"):
            for error in result["errors"]:
                print(f"  error: {error}")
    return 0 if result.get("ok") else 4


def cmd_init(args: argparse.Namespace) -> int:
    config = build_config(args)
    if args.project:
        plan = plan_init_project(Path(args.project).expanduser())
        path = save_plan(config.state_dir, plan)
        result = apply_plan(plan, config.state_dir, dry_run=not args.yes, yes=args.yes)
        if not args.json and not args.quiet:
            print(f"plan: {path}")
    else:
        result = init_home(config.state_dir, yes=args.yes, dry_run=not args.yes)
    if args.json:
        print(json_dumps(result))
    elif not args.quiet:
        if result.get("dry_run"):
            mode = "DRY RUN"
        elif result.get("ok"):
            mode = "APPLIED"
        else:
            mode = "FAILED"
        print(f"{mode}: init")
        print(f"  applied: {result.get('applied', 0)}")
        print(f"  skipped: {result.get('skipped', 0)}")
        if result.get("errors"):
            for error in result["errors"]:
                print(f"  error: {error}")
    return 0 if result.get("ok") else 4


def cmd_hub(args: argparse.Namespace) -> int:
    config = build_config(args)
    action = args.hub_action
    target = Path(
        getattr(args, "path", None)
        or getattr(args, "hub", None)
        or config.hub
        or default_hub_path(Path.home())
    ).expanduser()

    if action == "init":
        result = init_hub(
            target,
            config.state_dir,
            yes=args.yes,
            dry_run=not args.yes,
            name=args.name,
            knowledge=args.knowledge,
            projects=args.projects,
            tools=args.tools,
        )
        if args.json:
            print(json_dumps(result))
        elif not args.quiet:
            if result.get("dry_run"):
                mode = "DRY RUN"
            elif result.get("ok"):
                mode = "APPLIED"
            else:
                mode = "FAILED"
            print(f"{mode}: hub {result['hub']}")
            print(f"  plan:     {result.get('plan')}")
            print(f"  applied:  {result.get('applied', 0)}")
            print(f"  skipped:  {result.get('skipped', 0)}")
            if result.get("attach"):
                print(f"  config:   {result['attach']['config']}")
            paths = result.get("paths") or {}
            if paths:
                print(
                    "  paths:    "
                    f"knowledge={paths['knowledge']} "
                    f"projects={paths['projects']} "
                    f"tools={paths['tools']}"
                )
            if result.get("errors"):
                for error in result["errors"]:
                    print(f"  error: {error}")
        return 0 if result.get("ok") else 4

    if action == "attach":
        result = attach_hub(config.state_dir, target)
        if args.json:
            print(json_dumps(result))
        elif not args.quiet:
            print(f"attached: {result['hub']}")
            print(f"  config: {result['config']}")
            if result.get("backup"):
                print(f"  backup: {result['backup']}")
        return 0

    info = validate_hub(target, strict=action == "validate")
    if args.json:
        print(json_dumps(info))
    elif not args.quiet:
        manifest = info.get("manifest") or {}
        print(f"Hub:    {info['hub']}")
        if info.get("profile") == "legacy":
            print("Manifest: legacy (no hub.yaml)")
        else:
            print(
                "Manifest: "
                f"{info.get('profile') or '(missing)'} "
                f"schema={manifest.get('schema_version') or '(missing)'} "
                f"hub={manifest.get('hub_version') or '(missing)'} "
                f"min_guster={manifest.get('min_guster') or '(missing)'}"
            )
        print(f"Plugin: {info['plugin']}")
        paths = info.get("paths") or {}
        if paths:
            print(
                "Paths:  "
                f"knowledge={paths.get('knowledge', '(missing)')} "
                f"projects={paths.get('projects', '(missing)')} "
                f"tools={paths.get('tools', '(missing)')}"
            )
        if info["errors"]:
            for error in info["errors"]:
                print(f"  error: {error}")
        for warning in info["warnings"]:
            print(f"  warning: {warning}")
        if info["ok"]:
            print("Checks: OK")
    if action == "validate":
        return 0 if info["ok"] else 2
    return 0 if info["ok"] else 1


def cmd_link(args: argparse.Namespace) -> int:
    config = build_config(args)
    registry = do_scan(config, write=True)
    result = evaluate(registry, config)
    findings = [item for item in result["policy"]["findings"] if item["rule"] == "broken-pointer"]
    if args.json:
        print(json_dumps({"findings": findings, "stats": result["policy"]["stats"]}))
    elif not args.quiet:
        print(f"broken pointer files: {len(findings)}")
        for item in findings:
            print(f"  {item['path']}")
            for pointer in item.get("evidence", {}).get("pointers", []):
                print(f"    - {pointer}")
    return 0 if not findings else 2


def cmd_export(args: argparse.Namespace) -> int:
    config = build_config(args)
    registry = do_scan(config, write=True)
    result = evaluate(registry, config)
    report = render_report(registry, result["policy"], result["metrics"])
    out = Path(args.out).expanduser() if args.out else config.state_dir / "context-health.md"
    write_report(out, report)
    if args.format == "json":
        json_out = out.with_suffix(".json")
        write_json(json_out, {
            "registry": redacted_registry(registry),
            "policy": result["policy"],
            "metrics": result["metrics"],
        })
        if not args.quiet:
            print(f"report: {out}")
            print(f"json:   {json_out}")
    elif not args.quiet:
        print(f"report: {out}")
    return 0


def cmd_credentials(args: argparse.Namespace) -> int:
    config = build_config(args)
    registry = do_scan(config, write=True)
    info = (registry.get("secrets") or {}).get("registry") or {}
    entries = info.get("entries") or []
    scopes: Dict[str, List[Dict[str, str]]] = {}
    for entry in entries:
        scopes.setdefault(entry.get("scope", "unknown"), []).append(entry)
    if args.json:
        print(json_dumps({"path": info.get("path"), "entries": entries}))
        return 0
    if not args.quiet:
        print(f"registry: {info.get('path') or '(missing)'}")
        for scope in ("company", "personal", "unknown"):
            items = scopes.pop(scope, [])
            if not items:
                continue
            label = {"company": "公司", "personal": "个人", "unknown": "未分类"}[scope]
            print(f"\n{label}（{len(items)}）")
            for entry in items:
                keys = f" [{entry['keys']}]" if entry.get("keys") not in {"", "-"} else ""
                print(f"  {entry['id']:24} {entry['site'][:16]:18} {entry['kind']:8} {entry['status']}{keys}")
        for scope, items in scopes.items():
            print(f"\n{scope}（{len(items)}）")
            for entry in items:
                print(f"  {entry['id']:24} {entry['site'][:16]:18} {entry['kind']:8} {entry['status']}")
    return 0


def cmd_upgrade(args: argparse.Namespace) -> int:
    config = build_config(args)
    registry = do_scan(config, write=True)
    manifests = registry.get("plugin_manifests", {})
    versions = {
        key: value.get("version")
        for key, value in manifests.items()
        if isinstance(value, dict) and value.get("exists")
    }
    if args.json:
        print(json_dumps({"plugin": __version__, "manifests": versions}))
    elif not args.quiet:
        print(f"Guster CLI: {__version__}")
        for key, version in versions.items():
            print(f"  {key}: {version or '(missing)'}")
        if len(set(versions.values())) > 1:
            print("  WARNING: manifest versions differ")
    return 0 if len(set(versions.values())) <= 1 else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guster",
        description="Discover, audit, plan and evolve agent context.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    add_common(common)

    status = subparsers.add_parser("status", parents=[common], help="Show plugin, registry and health status.")
    status.set_defaults(func=cmd_status)

    scan_parser = subparsers.add_parser("scan", parents=[common], help="Discover context assets.")
    scan_parser.add_argument("--no-write", action="store_true", help="Do not write registry.json.")
    scan_parser.set_defaults(func=cmd_scan)

    doctor = subparsers.add_parser("doctor", parents=[common], help="Run policy checks.")
    doctor.add_argument("--no-write", action="store_true", help="Do not write findings.json.")
    doctor.add_argument("--strict", action="store_true", help="Return non-zero on high severity (default already does).")
    doctor.set_defaults(func=cmd_doctor)

    score = subparsers.add_parser("score", parents=[common], help="Compute metrics and CHI.")
    score.add_argument("--write", action="store_true", help="Write metrics (default; kept for explicit scripts).")
    score.add_argument("--no-write", action="store_true", help="Do not append metrics.jsonl.")
    score.add_argument("--trend", action="store_true", help="Show the last 10 metric snapshots.")
    score.set_defaults(func=cmd_score)

    plan = subparsers.add_parser("plan", help="Create a reviewable plan.")
    plan_sub = plan.add_subparsers(dest="plan_action", required=True)
    plan_findings = plan_sub.add_parser("findings", parents=[common], help="Turn findings into a review checklist.")
    plan_findings.set_defaults(func=cmd_plan)
    plan_move_parser = plan_sub.add_parser("move", parents=[common], help="Plan a move with backup and pointer.")
    plan_move_parser.add_argument("--from", dest="source", required=True, help="Source path.")
    plan_move_parser.add_argument("--to", dest="destination", required=True, help="Destination path.")
    plan_move_parser.set_defaults(func=cmd_plan)
    plan_init_parser = plan_sub.add_parser("init", parents=[common], help="Plan a standard .agents layout.")
    plan_init_parser.add_argument("--project", required=True, help="Project root.")
    plan_init_parser.set_defaults(func=cmd_plan)

    apply_parser = subparsers.add_parser("apply", parents=[common], help="Apply a plan.")
    apply_parser.add_argument("plan", help="Plan JSON path.")
    apply_parser.add_argument("--yes", action="store_true", help="Actually write; without it this is a dry run.")
    apply_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Explicit dry run (the default); cannot be combined with --yes.",
    )
    apply_parser.set_defaults(func=cmd_apply)

    init = subparsers.add_parser("init", parents=[common], help="Initialize Guster home or a project layout.")
    init.add_argument("--home", action="store_true", help="Initialize the Guster state home (default when --project is omitted).")
    init.add_argument("--project", default=None, help="Project root; omit to initialize the Guster state home.")
    init.add_argument("--yes", action="store_true", help="Actually write; without it this is a dry run.")
    init.set_defaults(func=cmd_init)

    hub = subparsers.add_parser("hub", help="Create, attach or inspect a Guster Hub.")
    hub_sub = hub.add_subparsers(dest="hub_action", required=True)
    hub_init = hub_sub.add_parser("init", parents=[common], help="Create a lite Guster Hub.")
    hub_init.add_argument("--path", default=None, help="Hub directory; defaults to the attached hub or the conventional Guster Hub path.")
    hub_init.add_argument("--name", default=None, help="Hub display name.")
    hub_init.add_argument("--knowledge", default="knowledge", help="Knowledge root relative to the hub.")
    hub_init.add_argument("--projects", default="projects", help="Project state root relative to the hub.")
    hub_init.add_argument("--tools", default="tools", help="Tool root relative to the hub.")
    hub_init.add_argument("--yes", action="store_true", help="Actually write; without it this is a dry run.")
    hub_init.set_defaults(func=cmd_hub)
    hub_attach = hub_sub.add_parser("attach", parents=[common], help="Attach an existing hub to Guster config.")
    hub_attach.add_argument("--path", default=None, help="Hub directory; defaults to the attached hub or the conventional Guster Hub path.")
    hub_attach.set_defaults(func=cmd_hub)
    hub_status = hub_sub.add_parser("status", parents=[common], help="Show hub manifest and validation status.")
    hub_status.add_argument("--path", default=None, help="Hub directory; defaults to the attached hub or the conventional Guster Hub path.")
    hub_status.set_defaults(func=cmd_hub)
    hub_validate = hub_sub.add_parser("validate", parents=[common], help="Validate a hub against the lite contract.")
    hub_validate.add_argument("--path", default=None, help="Hub directory; defaults to the attached hub or the conventional Guster Hub path.")
    hub_validate.set_defaults(func=cmd_hub)

    link = subparsers.add_parser("link", parents=[common], help="Check context pointers.")
    link.set_defaults(func=cmd_link)

    export = subparsers.add_parser("export", parents=[common], help="Export a redacted health report.")
    export.add_argument("--format", choices=["md", "json"], default="md")
    export.add_argument("--out", default=None, help="Output path.")
    export.set_defaults(func=cmd_export)

    creds = subparsers.add_parser("credentials", parents=[common], help="List registered credentials by scope.")
    creds.set_defaults(func=cmd_credentials)

    upgrade = subparsers.add_parser("upgrade", parents=[common], help="Check plugin manifest versions.")
    upgrade.set_defaults(func=cmd_upgrade)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (ApplyError, OSError, ValueError) as exc:
        if getattr(args, "json", False):
            print(json_dumps({"ok": False, "error": str(exc)}))
        else:
            print(f"[guster] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
