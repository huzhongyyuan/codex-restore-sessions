---
name: codex-restore-sessions
description: Set up or repair a machine's Codex installation. Provision a new host to match a known-good one — several relay/gateway providers as named profiles with `codex-<name>` wrappers, one shared provider id so every profile's resume picker shows the same history, a default permission level, and the `$HOME/.codex` symlink the VS Code extension needs. Also audit and restore existing sessions after provider, relay, profile, version, home-directory, or server changes. Use when setting Codex up on another server, adding a relay/gateway, sessions disappear, old sessions cannot resume, rollout JSONL and SQLite disagree, renamed sessions are missing, database rows point at deleted rollout files, sessions must move between homes or servers, or `codex -p <name> resume` and the VS Code extension show nothing.
---

# Set Up And Restore Codex

Two jobs, two scripts. Python 3.10+; 3.10 needs `tomli` from `requirements.txt`.
Never handle credentials in either.

| Goal | Script |
|---|---|
| Build a machine's Codex setup from scratch: profiles, `codex-<id>` wrappers, permissions, symlink | `scripts/provision_codex.py` |
| Fix or migrate sessions that already exist | `scripts/session_guard.py` |

Provisioning delegates history migration to `session_guard.py`, so a fresh host needs only
`provision_codex.py`. Reach for `session_guard.py` directly when the install is already fine and
only the sessions are wrong.

## Provision A Host

Use for "在别的服务器也配成这样", adding a relay/gateway, or an empty
`codex -p <name> resume`. Run `plan` first and show it; then `apply`; then `verify`.

```bash
cp reference/spec.example.toml <host>.toml     # edit base_url / key paths
python3 scripts/provision_codex.py plan   --spec <host>.toml
python3 scripts/provision_codex.py apply  --spec <host>.toml
python3 scripts/provision_codex.py verify --spec <host>.toml
```

`plan` mutates nothing and prints each change with its reason. `apply` does only what `plan`
listed and backs up every file it touches. `verify` re-derives state from the real `codex`
binary and exits non-zero on drift. Re-running is idempotent.

Keep the spec outside the repo; it carries internal hostnames and absolute paths.
Never create key files for the user — report the path and JSON shape and continue.

It writes `<id>.config.toml` per provider, a marked `codex-<id>` wrapper block in `.bashrc`
that injects each key per call, the shared provider id in every config, the permission
default in the base config, and `$HOME/.codex` -> `codex_home` when they differ.

A missing key file is a reported gap, not a failure. Never repoint an existing
`$HOME/.codex` symlink; it may be another host's real home.

### Reporting a provision run

Per provider: config path, resolved `base_url`, whether the key file was found. Then the shared
id, migration counts with the backup path, and the permission level in plain words.

`provider: <shared id>` in Codex's banner is an **id**, not a vendor — say which `base_url` each
channel actually reaches. When a relay sets `requires_openai_auth = true`, the banner also shows
the official account and weekly-limit bar from `auth.json`; those are official-account values,
stale, and unrelated to the relay. Say so rather than letting them read it as relay quota.

### Known behaviour: profile `model` can be shadowed

When the base config has a `[projects."<cwd>"]` entry matching the working directory, a profile's
**top-level** keys (such as `model`) lose to the base config's. `[model_providers.*]` tables are
unaffected, so routing stays correct — only the model name differs. `verify` reports this as a
warning, not a problem. Pass `-m <model>` when the exact model matters.

### VS Code shows no sessions

Only investigate when the user reports it. The extension resolves
`process.env.CODEX_HOME ?? join(homedir(), ".codex")`. Its host process is forked by the remote
server without a login shell, so a `CODEX_HOME` exported from `.bashrc` never reaches it and it
falls back to an empty `$HOME/.codex`. Confirm by reading `/proc/<extension-host-pid>/environ`,
then fix with the symlink. The user must reload the VS Code window afterward. On hosts where
`$HOME` is ephemeral the symlink does not survive a rebuild — say so instead of calling it durable.

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
4. When the user restores sessions for a specific `codex -p <name>` provider, pass the same
   `--profile <name>`. Without it the target resolves to the base `config.toml` provider and the
   sync would move sessions onto the wrong provider. `audit` lists `available_profiles`.
5. Accept success only when `problems` is empty, every database/JSONL provider equals the target,
   and `threads == rollout_files`. Require a manifest backup path when changes were applied;
   `backup: null` is a valid no-op when everything already matched.
6. Report counts, backup path, and any residual risk. Stop. Do not run `doctor`, open the picker,
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

- Clear rows whose rollout file was deleted outside Codex. `stale_database_paths` blocks every other
  mutating mode and provider sync cannot fix it, so this is the unblocking step:

  ```bash
  python3 scripts/session_guard.py --codex-home <absolute-home> --compact prune
  ```

  Report which sessions disappear before running it when the user has not already asked for prune.
  Rows whose file still exists are never deleted; the command aborts instead.

- Roll back one named applied backup:

  ```bash
  python3 scripts/session_guard.py --codex-home <absolute-home> --compact rollback <backup-directory>
  ```

- Unarchive only UUIDs explicitly named by the user with `codex unarchive <UUID>`.
- For cross-server migration, use the bundle modes rather than copying files by hand:

  ```bash
  # source machine
  python3 scripts/session_guard.py --codex-home <absolute-home> export <bundle>
  # destination machine, after its own config.toml exists and while it has no sessions
  python3 scripts/session_guard.py --codex-home <absolute-home> --compact import <bundle>
  ```

  `verify <bundle>` checks digests without writing. `export` never includes `auth.json` or the
  source `config.toml`; the destination must authenticate with its own credentials. `import`
  refuses a destination that already holds sessions, because merging two populated homes needs
  conflict resolution this tool does not implement. Run `switch` afterwards to sync the imported
  sessions to the destination provider.

- Make several providers share one session list on a machine. The resume picker filters on
  `threads.model_provider` and compares only the provider **id** (`name`, `base_url`, and auth are not
  part of the filter), so profiles with different ids can never see each other's sessions. `unify`
  rewrites `config.toml` and every `*.config.toml` to one id, keeping each channel's own `base_url`,
  `env_key`, and comments, then deep-migrates the history in the same run. This is the one command to
  use when setting a new server up:

  ```bash
  python3 scripts/session_guard.py --codex-home <absolute-home> --compact unify --provider shared
  ```

  A config file with no `[model_providers.*]` table relied on the built-in `openai` provider; `unify`
  recreates it under the shared id with `base_url = "https://chatgpt.com/backend-api/codex"` and
  `requires_openai_auth = true`, so the official channel keeps authenticating through `auth.json`.
  `openai` itself is a reserved id and is rejected as a target. Configs are backed up under
  `backups/unify-<timestamp>/`; report that path and each file's old id. Never rewrite the configs
  without migrating the history in the same step, or every profile ends up seeing zero sessions.

- Provider identity lives in more than one place inside a rollout file: the `session_meta` header
  (which a file may repeat) and `thread_settings.model_provider_id` in `event_msg` records.
  Reindexing reads the latter, so a plain `switch` drifts back to the old provider on the next
  reindex. Use `--deep` whenever the goal is a durable provider change:

  ```bash
  python3 scripts/session_guard.py --codex-home <absolute-home> --compact switch --provider <id> --deep
  ```

  `--deep` rewrites whole files rather than just the first line, so it records every changed line in
  the manifest and `rollback` restores them byte for byte. Prefer it over repeatedly re-running a
  shallow switch when the database keeps reverting.

- A running Codex session keeps appending to its rollout file, so `switch` aborts rather than risk
  losing appends during the rewrite. Prefer waiting for that session to exit. When the user
  wants to proceed anyway, `--skip-live` leaves actively-growing files on their old provider, migrates
  everything else, lists what it deferred in `deferred_live_sessions`, and records the count in the
  state file so the follow-up run is not mistaken for a no-op:

  ```bash
  python3 scripts/session_guard.py --codex-home <absolute-home> --compact switch --provider <id> --skip-live
  ```

## Invariants

- Never mutate without the helper's verified incremental backup and journal.
- Never write a key into any config, `.bashrc`, or file that is not `0600`; never read, print, hash,
  or copy a key value; never `export` a provider key globally. Pass paths, not secrets.
- Never set `CODEX_API_KEY` — Codex treats it as the *official* key and 401s the default provider.
- Every mutated file has a backup path in the report, or nothing was written.
- Preserve conversation events, names, models, timestamps, recency, and archive fields. Provider
  synchronization must not rewrite historical models unless the user explicitly supplies `--model`.
- Restore a legacy name only when the database name is empty, the legacy name equals the title, and
  it differs from the first user message. Never bulk-apply ambiguous names.
- Preserve archived sessions; never make them visible implicitly.
- Never read, print, hash, copy, or back up API keys, tokens, `auth.json`, or credential variables.
  Never place them in a migration bundle, and never copy a source `config.toml` to another machine.
- Never delete a thread row while its rollout file exists.
- Never rewrite the configs for a shared provider id without migrating the history in the same run.
- Never target a reserved built-in provider id (`openai`) when unifying; built-in providers cannot be
  overridden, and a custom id reaches the official endpoint just as well.
- Never rewrite a rollout file that a running Codex session is still appending to. Defer it with
  `--skip-live` and finish after that session exits.
- Never install a bundle into a Codex home that already holds sessions.
- Never raise `approval_policy` or `sandbox_mode` during restoration.
- Do not blindly retry post-check failures. Report the backup path and current disagreement.

Codex may reindex SQLite model/provider/time fields when a writable picker or resume starts. If that
happens, exit the temporary picker, rerun one compact guarded `switch`, and report the drift. Do not
claim the earlier backup is directly rollback-ready when current row tuples no longer match its
manifest.
