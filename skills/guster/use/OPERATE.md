# Guster USE

## First pass

```bash
guster status
guster scan
guster doctor
guster score --write
```

`scan` writes `~/.agents/guster/registry.json`. `doctor` writes
`~/.agents/guster/findings.json`. `score` appends to
`~/.agents/guster/metrics.jsonl`.

## Review findings

```bash
guster doctor --json
guster plan findings
```

The findings plan is a checklist. It does not write workspace files.

## Structural changes

```bash
guster plan move \
  --from ~/Projects/project/.agents/task-20261103 \
  --to   ~/Projects/project/.agents/evidence/task-20261103

guster apply ~/.agents/guster/plans/<plan>.json --dry-run
guster apply ~/.agents/guster/plans/<plan>.json --yes
```

`apply` backs up the source under `~/.agents/guster/backups/<plan>/` and leaves
a `<name>.moved.md` pointer at the old location.

## New project

```bash
guster plan init --project ~/Projects/new-project
guster apply ~/.agents/guster/plans/<plan>.json --yes
```

This creates:

```text
.agents/
├── README.md
├── plans/
├── wiki/
├── evidence/
├── skills/
├── tmp/
└── archive/
```

It also creates a minimal `AGENTS.md` when absent.

## Export

```bash
guster export --format md
guster export --format json
```

Exports are redacted and safe to share. Credential values are never included.
