# Cross-Home And Cross-Host Migration

Audit the source and destination canonical homes. Do not copy a live SQLite file or hand-copy a
partial session tree.

## Export

```bash
python3 scripts/session_guard.py --codex-home <source-home> export <new-bundle-path>
```

Export refuses audit problems and an existing destination path. The bundle contains session trees,
the legacy name index when present, a SQLite backup API snapshot, and SHA-256 manifest. It excludes
credentials, `auth.json`, source `config.toml`, project files, models, and datasets.

The destination must be outside the source Codex home. Export rejects active rollout files,
credential-like filenames, symlinks, and special files before creating output. It builds in a
private staging directory, verifies the complete bundle, and renames it into place only on success;
failures remove the staging directory.

## Transfer And Verify

Transfer the entire bundle as sensitive conversation data. Verify it without writing:

```bash
python3 scripts/session_guard.py verify <bundle>
```

Verification rejects missing, unexpected, symlinked, out-of-bundle, credential-named, or digest-
mismatched files and checks SQLite integrity.

## Import

Prepare the destination's own `config.toml` and authentication first. The destination must contain
no session database or rollout files:

```bash
python3 scripts/session_guard.py --codex-home <empty-destination-home> --compact import <bundle>
```

Import rebases absolute rollout paths into the destination home and preserves names, models,
timestamps, recency, and archive state. It refuses two populated homes because conflict-aware SQLite
and JSONL merging is not implemented.

After import, preview and apply the destination provider mapping:

```bash
python3 scripts/session_guard.py --codex-home <destination-home> --compact plan --deep
python3 scripts/session_guard.py --codex-home <destination-home> --compact restore
```

Before migrating across large Codex version gaps, compare `schema_columns` from verbose audits on
both ends. Stop when required columns or session invariants differ.
