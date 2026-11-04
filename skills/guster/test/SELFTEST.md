# Guster TEST

## Automated

```bash
python3 -m unittest discover -s tests -v
node --test tests/test_plugin.mjs
```

The suite covers:

- project and skill discovery;
- resident and skill budgets;
- orphan knowledge and broken pointers;
- credential location and inline bearer detection;
- metric computation and CHI bounds;
- project initialization;
- plan/apply/rollback on a temporary fixture.

## Real machine, read-only

```bash
guster scan --no-write
guster doctor --no-write
guster score --no-write
```

Acceptance:

- no workspace file changed;
- no credential value printed;
- findings match the manual audit;
- CHI is reproducible.

## Plugin manifests

```bash
guster upgrade
```

Codex, ZCode and package versions must match.
