# Compatibility And Version Drift

Treat Codex's session schema and indexing behavior as version-dependent implementation details, not
stable public API guarantees.

Start with:

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" --codex-home <candidate> capabilities
python3 "$SKILL_DIR/scripts/session_guard.py" --codex-home <confirmed-home> --compact audit
```

`capabilities` reports Python/TOML/SQLite versions, lock availability, home existence, discovered
state databases, and supported commands without requiring a database. `audit` selects the newest
usable `state_*.sqlite` containing a `threads` table and reports its actual columns.

Mutation requires `id`, `rollout_path`, `archived`, `model_provider`, `model`, and `name`. Refuse
mutation when any required column is absent. Ignore additional schema columns during provider/name
repair, preserve protected archive/time fields, and snapshot full rows before prune.

File-based `<profile>.config.toml` overlays and legacy inline `[profiles.<name>]` are both supported.
When the installed Codex version resolves profiles differently, use its real output as evidence and
do not force a guessed mapping.

The resume picker/provider-field behavior documented by this project was inferred from tests of
specific Codex CLI builds. If a new build reindexes provider or time fields differently, stop after
the first post-check disagreement, retain the backup, capture a verbose audit, and update fixtures
before extending the mutator.

On platforms without the reported advisory-lock backend, keep operations read-only. Do not emulate
locking or claim mutation safety without platform-specific tests.

When the CLI and an editor show different homes, compare their resolved absolute paths. Environment
variables exported only from a login shell may not reach an editor extension host. Prefer a
user-confirmed discovery fix and reload the editor; never inspect credential-bearing process
environments unless the user explicitly requests that diagnostic.
