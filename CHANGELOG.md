# Changelog

Notable changes. Earlier history is in `git log`.

## 0.5.4 — 2026-11-04

- Removed three skill sub-pages that nothing pointed at: `init/SETUP.md`,
  `use/OPERATE.md`, `test/SELFTEST.md`. `SKILL.md` carries the workflow itself;
  the sub-pages had drifted and were never loaded.

## 0.5.3 — 2026-11-04

- `doctor` reports exactly the dimensions that enter CHI for the run's scope.
  `--scope hub` no longer prints RBR/PCR/SIR rows it never scores, and the
  always-informational GCR value is labeled `Not counted in CHI`.
- `project` and `group` runs now apply one boundary to artifacts and findings:
  hub knowledge, hub state documents and the machine-level local wiki no longer
  sit in ICR/FRS/PHR denominators while their findings are filtered out. A
  denominator now only contains documents that can raise an in-scope finding,
  so those scopes no longer inherit a score from out-of-scope health.
- Removed the unused `templates/` file skeletons and `schema/*.json`: nothing
  read them, and the project `AGENTS.md` / `.agents/README.md` text already
  lives in `planner.py`. `templates/hub/` is the only shipped template set and
  `package.json` no longer ships `schema/`.

## 0.5.2 — 2026-11-04

- Bad plan files no longer crash: a non-object plan, a malformed operation, or an
  unreadable plan path fails through the `[guster] ...` / plan-error output and a
  non-zero exit.
- `guster apply --dry-run` is accepted as the documented explicit dry run and is
  rejected when combined with `--yes`.
- A missing `--root` workspace and an unreadable or non-object Guster config now
  fail loud instead of silently scanning defaults.
- Pointer health counts each target once per file, so a link whose text is also
  inline code is no longer double-counted.
- Project `.agents/README.md` and hub knowledge indexes are now actually
  pointer-checked; the filter listed them but they were never scanned.
- A refused `apply`, `init` or `hub init` prints `FAILED` instead of `APPLIED`.
- The home directory is no longer classified as a project just because it holds
  the user-level `~/.agents/`; a fresh `init --home` setup scores clean.
- The setup skill points at the shipped `skills/` directory.

## 0.5.1 — 2026-11-03

- Added reasoned `doctor.waivers` and precise pointer checks.
- Fixed double-counting of linked wiki files and OpenSpec state.
- Added `GUSTER_EXTRA_SKILL_ROOTS` for additional skill hosts.
