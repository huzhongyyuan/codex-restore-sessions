---
name: codex-restore-sessions
description: Quickly audit and restore local Codex sessions after provider, relay, version, home-directory, or server changes while preserving names and archive state. Use when sessions disappear, old sessions cannot resume, rollout JSONL and SQLite disagree, renamed sessions are missing, or sessions must move between Codex homes or servers.
---

# Restore Codex Sessions

Use Python 3.10+ with `scripts/session_guard.py`. Python 3.10 needs `tomli` from
`requirements.txt`; Python 3.11+ uses only the standard library. Never handle credentials.

## Fast Local Restore

For requests such as "恢复所有 session" after a provider or relay change:

1. Resolve the canonical home from `CODEX_HOME`, else `${HOME}/.codex`. Confirm it exists. If VS Code
   visibly uses the same sessions, do not inspect process environments or search extension files.
2. Ensure no other picker/resume process is actively indexing old sessions. Do not stop unrelated
   Codex or VS Code processes unless the user asks.
3. Run one guarded command:

   ```bash
   python3 scripts/session_guard.py --codex-home <absolute-home> --compact switch
   ```

   `switch` already audits before mutation, refuses integrity problems, creates a verified backup,
   applies atomically, and audits again. Do not run separate before/after audits on the happy path.
4. Accept success only when `problems` is empty, every database/JSONL provider equals the target,
   and `threads == rollout_files`. Require a manifest backup path when changes were applied;
   `backup: null` is a valid no-op when everything already matched.
5. Report counts, backup path, and any residual risk. Stop. Do not run `doctor`, open the picker,
   page through all sessions, or resume a UUID routinely.

This is the default path. Treat a successful guarded local switch as routine, reversible maintenance,
not as high-impact checkpoint/resume work merely because sessions can be resumed. Do not add agent
reviews or extra verification passes unless the user requests them or the operation has integrity
failures, cross-home/server transfer, rollback, destructive cleanup, or another independently
high-impact condition. Use `--verbose` only to inspect rename previews or detailed failures.

## Escalate Only When Needed

Run a compact read-only audit when the user asks for diagnosis rather than restoration:

```bash
python3 scripts/session_guard.py --codex-home <absolute-home> --compact audit
```

Use full `audit --verbose` only when compact output reports a problem or rename details are required.
Run `codex doctor --no-color --ascii --all` only for database/CLI startup failures. Open
`codex resume --all --no-alt-screen` and test one migrated UUID only when picker or resume behavior is
the reported problem, or when the user explicitly requests end-to-end verification.

Stop before mutation on malformed metadata, path/ID/archive disagreement, symlink or out-of-home
paths, duplicates, incomplete journals, an unconfirmed home, or observed concurrent indexing.

## Other Modes

- Rename-only repair:

  ```bash
  python3 scripts/session_guard.py --codex-home <absolute-home> --compact repair
  ```

- Roll back one named applied backup:

  ```bash
  python3 scripts/session_guard.py --codex-home <absolute-home> --compact rollback <backup-directory>
  ```

- Unarchive only UUIDs explicitly named by the user with `codex unarchive <UUID>`.
- For cross-server migration, audit both canonical homes. Transfer `sessions`, `archived_sessions`,
  `session_index.jsonl`, and a consistent state database backup, never credentials or source
  `config.toml`. If the destination is nonempty, stop before a schema-aware merge.

## Invariants

- Never mutate without the helper's verified incremental backup and journal.
- Preserve conversation events, names, models, timestamps, recency, and archive fields. Provider
  synchronization must not rewrite historical models unless the user explicitly supplies `--model`.
- Restore a legacy name only when the database name is empty, the legacy name equals the title, and
  it differs from the first user message. Never bulk-apply ambiguous names.
- Preserve archived sessions; never make them visible implicitly.
- Never read, print, hash, copy, or back up API keys, tokens, `auth.json`, or credential variables.
- Never raise `approval_policy` or `sandbox_mode` during restoration.
- Do not blindly retry post-check failures. Report the backup path and current disagreement.

Codex may reindex SQLite model/provider/time fields when a writable picker or resume starts. If that
happens, exit the temporary picker, rerun one compact guarded `switch`, and report the drift. Do not
claim the earlier backup is directly rollback-ready when current row tuples no longer match its
manifest.
