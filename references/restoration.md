# Restoration Operations

Use this reference after a compact audit identifies the required non-routine operation.

## Durable Provider Changes

Codex versions may store provider identity in the first `session_meta`, repeated `session_meta`
records, and `event_msg.payload.thread_settings.model_provider_id`. Preview a deep pass first when
the provider has drifted back after reindexing:

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" --codex-home <home> --compact plan --provider <id> --deep
python3 "$SKILL_DIR/scripts/session_guard.py" --codex-home <home> --compact restore --provider <id>
```

Deep mode records every changed line in the manifest so rollback can restore it byte for byte.
`restore` enables deep mode automatically.

## Live Rollout Files

A running session may append to its rollout file. Prefer waiting for it to exit. If the user wants
the remaining sessions migrated now, defer open, growing, or uncertain files:

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" --codex-home <home> --compact restore --provider <id>
```

Report every `deferred_live_sessions` path and rerun after those sessions exit.
Use `restore --fail-live` only when the user wants the entire run to fail instead of deferring them.

## Rename Repair

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" --codex-home <home> --compact repair
```

Restore a legacy name only when the database name is empty, the legacy name equals the title, and
it differs from the first user message. Leave ambiguous names unchanged.

## Stale Database Rows

`stale_database_paths` means a thread row points to a rollout file that no longer exists. Provider
sync cannot repair that. Explain which rows will disappear and obtain user intent before pruning:

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" --codex-home <home> --compact prune
```

Prune only rows whose recorded file is still absent at mutation time. The command backs up the full
row and database. Never delete a row whose rollout file exists. `unindexed_rollout_files` is the
opposite condition and must be reindexed by Codex; prune does not solve it.

## Shared History Across Profiles

When profiles use distinct provider IDs, their resume lists may be disjoint. Preview the configs,
then use one custom shared ID:

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" --codex-home <home> --compact unify --provider shared
```

`unify` backs up `config.toml` and every `*.config.toml`, preserves endpoint/auth fields and comments,
then deep-migrates history in the same operation. Never use the reserved built-in ID `openai` as the
custom target. Never rewrite configs without migrating history in the same run.

## Rollback

Roll back only a named backup under the same Codex home:

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" --codex-home <home> --compact \
  rollback <home>/backups/session-guard-<timestamp>
```

Rollback verifies paths, hashes, database identity, provider fingerprint, and expected before/after
state. If Codex reindexed the modified rows after the backup, report the disagreement instead of
forcing rollback.

## Escalation

Use verbose audit only to inspect compact blockers or rename previews. Run `codex doctor` only when
the database or CLI itself fails to start. Open the resume picker and test one UUID only when picker
behavior is the reported problem or the user explicitly requests end-to-end UI verification.
