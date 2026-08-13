---
name: codex-restore-sessions
description: Restore missing or unresumable local Codex sessions safely across provider, profile, relay, home-directory, host, and CLI changes. Use when session history disappears; SQLite and rollout JSONL disagree; names or archive state need recovery; rows reference missing files; histories must migrate; profiles should share sessions; VS Code and CLI homes differ; or a new host needs equivalent provider profiles without copying credentials.
---

# Restore Codex Sessions

Use the bundled scripts instead of editing SQLite or rollout JSONL by hand. Operate only on a
user-confirmed Codex home. Preserve credentials, conversation events, models, timestamps, names,
recency, and archive state unless the user explicitly requests a supported change.

Python 3.9+ is supported. Python 3.9/3.10 needs `tomli` from `requirements.txt`. Linux and macOS
support guarded mutations; run `capabilities` before assuming mutation support on another platform.

Resolve `SKILL_DIR` to the absolute directory containing this `SKILL.md`. Invoke every bundled
script through `$SKILL_DIR/scripts/...`; never assume the user's current working directory is the
skill directory.

## Select The Workflow

| User intent | First action | Continue with |
|---|---|---|
| Check the usual local home without changing it | `quick_restore.py --check` | Run the recommended action only when requested |
| Restore after a routine provider or relay switch | `quick_restore.py` | Report the returned summary |
| Diagnose missing or inconsistent sessions | `capabilities`, then `doctor` | [references/restoration.md](references/restoration.md) |
| Preview a provider/profile change | `plan` | Apply only when `safe_to_apply` is true |
| Repair names, prune stale rows, unify profiles, or roll back | compact `audit` | [references/restoration.md](references/restoration.md) |
| Move sessions between homes or machines | audit both ends | [references/migration.md](references/migration.md) |
| Configure a fresh host or add provider profiles | provision `plan` | [references/provisioning.md](references/provisioning.md) |
| Codex version/schema behavior is uncertain | `capabilities` and `audit` | [references/compatibility.md](references/compatibility.md) |

Read only the reference required by the selected row.

## Quick Restore

Use the short entry point for the common local case. It resolves `CODEX_HOME`, otherwise
`~/.codex`, and delegates all validation, backup, locking, deep repair, and live-file handling to
the guarded engine.

```bash
python3 "$SKILL_DIR/scripts/quick_restore.py" --check  # read-only
python3 "$SKILL_DIR/scripts/quick_restore.py"          # guarded restore
```

Add `--profile <name>` when the user runs `codex -p <name>`. Use `--codex-home <path>` only when
the user names a different home. The default output is a short human-readable summary; add `--json`
when structured output is required. If live sessions are deferred, report them and rerun after they
exit.

## Discover Capabilities

On an unfamiliar host, run this before touching session state. It succeeds even if the proposed
home does not exist.

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" --codex-home <candidate-home> capabilities
```

Resolve the canonical home from `CODEX_HOME`, otherwise `${HOME}/.codex`, unless the user names a
different home. Confirm the absolute path. If the user invokes Codex with `-p <name>`, pass the same
`--profile <name>` to audit, plan, and switch.

## Diagnose Or Preview

Use doctor for a read-only health verdict and structured next-step recommendation:

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" --codex-home <absolute-home> doctor
```

Recommendations are advisory and never auto-execute. When the user asked only for diagnosis, report
the verdict and stop. Use compact `audit` for raw counts or verbose audit to inspect a reported
blocker.

Use plan when the target provider, model, or deep rollout impact should be previewed:

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" --codex-home <absolute-home> --compact \
  plan --provider <id> --deep
```

`plan` writes nothing and reports database rows, rollout files/records, rename candidates, and
blockers. Do not mutate when `safe_to_apply` is false.

## Run A Guarded Restore

For advanced automation or an explicit target provider, call the guarded engine directly:

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" --codex-home <absolute-home> --compact restore
```

Add the matching `--profile <name>` when restoring for `codex -p <name>`. Use an explicit
`--provider` only when the user or a verified configuration supplies the target. `restore` always
repairs every recognized provider metadata location and defers open, growing, or uncertain rollout
files. It deep-verifies all non-deferred provider records before returning success. Use
the lower-level `switch` flags only for deliberate partial or fail-on-live behavior. Never pass
`--model` unless the user explicitly requests rewriting historical model metadata.

A restore already audits before mutation, refuses integrity problems, creates a verified incremental
backup and journal, writes atomically, and audits again. Do not add redundant audit passes on the
happy path.

Accept success only when:

- `problems` is empty;
- `threads == rollout_files`;
- database and JSONL providers equal the target, except paths explicitly listed as deferred;
- `postconditions.verified` is true;
- a changed run returns a backup path (`backup: null` is a valid no-op).

## Stop Conditions

Stop before mutation on an unconfirmed home, malformed metadata, missing required schema columns,
path/ID/archive disagreement, symlinks or paths outside the home, duplicates, incomplete journals,
or concurrent indexing. Do not stop unrelated Codex or editor processes without permission.

Never read, print, hash, copy, or back up secret values. Never include `auth.json`, source
`config.toml`, API keys, tokens, or credential environment variables in migration output. Session
bundles contain full conversation history even without credentials; treat them as sensitive.

Never raise approval or sandbox permissions as part of session restoration. Provisioning may change
them only when the user supplied them in a reviewed spec; prefer the safe template defaults.

## Report

Report the resolved home, mode, target profile/provider, thread and rollout counts, changes or
deferrals, backup path, and remaining risk. On failure, report the blocker and the last verified
backup; do not blindly retry a post-check failure.
