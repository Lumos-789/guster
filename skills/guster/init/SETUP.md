# Guster INIT

## Requirements

- Python 3.9+ (no third-party Python dependencies).
- Node 18+ only for the DSH/ZCode plugin adapter tests.
- A writable state directory, default `~/.agents/guster/`.

## Install from a checkout

```bash
cd <checkout>
python3 -m unittest discover -s tests -v
./bin/guster init --home --yes
./bin/guster scan
```

## Create a lite Hub

When there is no data plane yet:

```bash
./bin/guster hub init --path <hub> --yes
./bin/guster hub status
./bin/guster doctor --scope hub
```

Custom core roots:

```bash
./bin/guster hub init --path <hub> --knowledge notes --projects work --tools scripts --yes
```

The lite profile creates `knowledge/`, `projects/` and a `tools/` index plus
the hub contract. `handoff/` and `reports/` are optional and are not created.
No tool is preinstalled. Use `guster hub attach --path <hub>` for an existing
hub.

## Workspace roots

Defaults are derived from the current user: `IdeaProjects` and `ZCodeProject`
under the home directory when they exist, otherwise the home directory itself.
Override per command with `--root`. Persistent config lives in
`~/.agents/guster/config.json`.

## Guster Hub

The plugin reads a hub when present:

- `IdeaProjects/Guster` under the home directory by default (when present).
- Override with `--hub`.

The hub is optional. Without it, Guster still scans ordinary workspaces and
project-local `.agents/` directories.

## Plugin hosts

- Codex: `.codex-plugin/plugin.json`
- ZCode: `.zcode-plugin/plugin.json`
- DSH: `package.json` + `cordis.patch.yml`

All three point at `skills/` (the `guster` and `guster-hub` skills); keep their
versions synchronized.
