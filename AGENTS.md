# Guster Plugin — Agent Instructions

## Role

This repository is the distributable Guster plugin: the control plane for agent context. It discovers, diagnoses, plans and evolves context assets; it is not the Guster Hub data plane.

## Commands

```bash
./bin/guster status
./bin/guster scan
./bin/guster doctor
./bin/guster score --write
./bin/guster plan findings
./bin/guster apply <plan> --yes
./bin/guster hub init --path <hub> --yes
./bin/guster hub status
```

## Boundaries

- Default to read-only on the workspace. `apply --yes`, `init --yes`, `hub init --yes` and `hub attach` are the only writers of workspace files and Guster config; `export --out <path>` writes the report path you name.
- Scanning commands also maintain state under `~/.agents/guster/` (`scoped/<hash>/` for scoped runs): every one of them rewrites `registry.json`, `doctor` writes `findings.json`, `score` appends `metrics.jsonl`. `--no-write` opts out of the command's own state file for `scan`, `doctor` and `score` only.
- Never read or print credential values. Paths and redacted forms only.
- Never auto-commit, auto-push or deploy.
- Keep Codex, ZCode and package versions synchronized.
- The CLI must run on a stock Python 3.9+ install; do not add third-party Python dependencies without a strong reason.
- Keep the governance skill and the narrow hub skill; avoid default MCP tools and resident tool-schema overhead.

## Verification

```bash
python3 -m unittest discover -s tests -v
node --test tests/test_plugin.mjs
python3 -m py_compile src/guster/*.py
```
