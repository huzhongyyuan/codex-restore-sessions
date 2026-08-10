#!/usr/bin/env python3
"""Audit and safely migrate local Codex session metadata."""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
import time
import urllib.parse
from collections import Counter
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

try:
    import fcntl
except ImportError:  # Windows audit remains available; mutation requires a portable lock first.
    fcntl = None

STATE_FILE = "session_guard_state.json"
FINGERPRINT_KEYS = ("base_url", "wire_api", "requires_openai_auth", "name")
INCOMPLETE_STATUSES = {"prepared", "applying", "data_applied", "rolling_back"}
MAX_METADATA_LINE = 4 * 1024 * 1024
TRANSFER_ITEMS = ("sessions", "archived_sessions", "session_index.jsonl")
CREDENTIAL_NAMES = {
    "auth.json",
    ".env",
    "credentials.json",
    "provider_keys.env",
    "id_rsa",
    "id_ed25519",
}


def die(message: str) -> None:
    raise SystemExit(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_write(
    path: Path,
    data: bytes,
    mode: int | None = None,
    times_ns: tuple[int, int] | None = None,
) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if mode is not None:
            os.chmod(temp, mode)
        os.replace(temp, path)
        if times_ns is not None:
            os.utime(path, ns=times_ns)
    finally:
        temp.unlink(missing_ok=True)


def write_json(path: Path, value: object) -> None:
    atomic_write(path, (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode())
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def resolve_home(raw: str | None) -> Path:
    home = Path(raw or os.environ.get("CODEX_HOME") or (Path.home() / ".codex")).resolve()
    if not home.is_dir():
        die(f"Codex home is not a directory: {home}")
    return home


def find_db(home: Path) -> Path:
    def version(path: Path) -> int:
        match = re.fullmatch(r"state_(\d+)\.sqlite", path.name)
        return int(match.group(1)) if match else -1

    candidates = sorted(home.glob("state_*.sqlite"), key=version, reverse=True)
    for path in candidates:
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            ok = con.execute(
                "select 1 from sqlite_master where type='table' and name='threads'"
            ).fetchone()
            con.close()
            if ok:
                return path
        except sqlite3.Error:
            continue
    die(f"No usable state_*.sqlite with a threads table under {home}")


def load_toml(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as exc:
        die(f"Malformed TOML in {path}: {exc}")
    if not isinstance(data, dict):
        die(f"TOML root must be a table: {path}")
    return data


def deep_merge(base: dict[str, object], overlay: dict[str, object]) -> dict[str, object]:
    """Layer overlay onto base the way Codex layers `-p <name>.config.toml`.

    Nested tables merge key by key, so a profile may override only `base_url`
    inside `[model_providers.X]` and still inherit `wire_api` from the base file.
    """
    merged = dict(base)
    for key, value in overlay.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = deep_merge(current, value)
        else:
            merged[key] = value
    return merged


def profile_path(home: Path, name: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name) or name in {".", ".."}:
        die(f"Invalid profile name: {name}")
    path = home / f"{name}.config.toml"
    resolved = path.resolve()
    if not resolved.is_relative_to(home) or path.is_symlink():
        die(f"Profile file must be a regular file directly under the Codex home: {path}")
    return path


def available_profiles(home: Path) -> list[str]:
    names = []
    for path in sorted(home.glob("*.config.toml")):
        if path.is_symlink() or not path.is_file():
            continue
        names.append(path.name[: -len(".config.toml")])
    return names


def config_target(home: Path, profile_name: str | None = None) -> dict[str, object]:
    """Resolve the effective provider identity, honouring CLI-style profiles.

    Codex 0.144+ layers `$CODEX_HOME/<name>.config.toml` on top of `config.toml`
    when invoked as `codex -p <name>`. Older releases instead used inline
    `[profiles.<name>]` tables. Both are resolved here so the fingerprint matches
    whichever provider the session was actually recorded under.
    """
    data = load_toml(home / "config.toml")
    profile_kind = None
    if profile_name is not None:
        overlay_path = profile_path(home, profile_name)
        if overlay_path.exists():
            data = deep_merge(data, load_toml(overlay_path))
            profile_kind = "file"
        else:
            profiles = data.get("profiles", {})
            if not isinstance(profiles, dict) or not isinstance(profiles.get(profile_name), dict):
                die(
                    f"Profile not found: expected {overlay_path.name} in the Codex home "
                    f"or a [profiles.{profile_name}] table in config.toml"
                )
            data = deep_merge(data, profiles[profile_name])
            profile_kind = "inline"
    else:
        inline_name = data.get("profile")
        if inline_name is not None:
            profiles = data.get("profiles", {})
            if not isinstance(profiles, dict) or not isinstance(profiles.get(inline_name), dict):
                die(f"Selected profile is missing or invalid: {inline_name}")
            data = deep_merge(data, profiles[inline_name])
            profile_name = inline_name
            profile_kind = "inline"

    provider = data.get("model_provider") or "openai"
    model = data.get("model")
    tables = data.get("model_providers", {})
    if not isinstance(tables, dict):
        die("model_providers must be a table")
    table = tables.get(provider, {})
    identity = {"provider": provider}
    if isinstance(table, dict):
        for key in FINGERPRINT_KEYS:
            if key not in table:
                continue
            value = table[key]
            if key == "base_url" and isinstance(value, str):
                parsed = urllib.parse.urlsplit(value)
                value = urllib.parse.urlunsplit((parsed.scheme, parsed.hostname or "", parsed.path, "", ""))
            identity[key] = value
    fingerprint = sha256(json.dumps(identity, sort_keys=True, default=str).encode())
    return {
        "provider": provider,
        "provider_inferred": "model_provider" not in data,
        "profile": profile_name,
        "profile_kind": profile_kind,
        "model": model,
        "fingerprint": fingerprint,
        "approval_policy": data.get("approval_policy"),
        "sandbox_mode": data.get("sandbox_mode"),
    }



def db_rows(db: Path) -> tuple[list[str], list[dict[str, object]]]:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    columns = [row[1] for row in con.execute("pragma table_info(threads)")]
    wanted = [
        name
        for name in (
            "id",
            "rollout_path",
            "archived",
            "archived_at",
            "model_provider",
            "model",
            "name",
            "title",
            "first_user_message",
            "preview",
            "created_at",
            "updated_at",
            "created_at_ms",
            "updated_at_ms",
            "recency_at",
            "recency_at_ms",
        )
        if name in columns
    ]
    rows = [dict(row) for row in con.execute(f"select {','.join(wanted)} from threads")]
    integrity = con.execute("pragma integrity_check").fetchone()[0]
    con.close()
    if integrity != "ok":
        die(f"Database integrity_check failed: {integrity}")
    return columns, rows


def resolve_rollout(home: Path, raw: str) -> Path:
    path = Path(raw)
    return (path if path.is_absolute() else home / path).resolve()


def first_record(path: Path) -> tuple[bytes, dict[str, object]]:
    with path.open("rb") as stream:
        line = stream.readline(MAX_METADATA_LINE + 1)
    if len(line) > MAX_METADATA_LINE:
        die(f"First JSONL record exceeds {MAX_METADATA_LINE} bytes in {path}")
    try:
        record = json.loads(line)
    except Exception as exc:
        die(f"Malformed first JSONL record in {path}: {exc}")
    if not isinstance(record, dict):
        die(f"First JSONL record must be an object in {path}")
    payload = record.get("payload")
    if record.get("type") != "session_meta" or not isinstance(payload, dict):
        die(f"First JSONL record is not session_meta in {path}")
    return line, record


def legacy_names(home: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    path = home / "session_index.jsonl"
    if not path.exists():
        return result
    with path.open(errors="replace") as stream:
        for line in stream:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            thread_id = item.get("thread_id") or item.get("id")
            name = item.get("thread_name")
            if thread_id and isinstance(name, str):
                result[thread_id] = name
    return result


def scoped_state(state: dict[str, object], profile: str | None) -> dict[str, object]:
    """Return the last-applied record for one profile.

    Each profile tracks its own fingerprint under `profiles`, so switching
    between `codex` and `codex -p relay` does not make either look changed.
    The unscoped top level stays authoritative for the default profile, which
    keeps state files written by earlier versions readable.
    """
    if profile is None:
        return state
    scoped = state.get("profiles")
    if isinstance(scoped, dict) and isinstance(scoped.get(profile), dict):
        return scoped[profile]
    return {}


def merged_state(previous: dict[str, object], record: dict[str, object], profile: str | None) -> dict[str, object]:
    if profile is None:
        merged = dict(record)
        existing = previous.get("profiles")
        if isinstance(existing, dict) and existing:
            merged["profiles"] = existing
        return merged
    merged = {key: value for key, value in previous.items() if key != "invalid"}
    scoped = dict(merged.get("profiles") or {})
    scoped[profile] = record
    merged["profiles"] = scoped
    return merged


def audit(
    home: Path, verbose: bool = False, profile: str | None = None
) -> tuple[dict[str, object], dict[str, object]]:
    db = find_db(home)
    columns, rows = db_rows(db)
    db_paths = [str(resolve_rollout(home, str(row["rollout_path"]))) for row in rows]
    discovered = [
        path
        for folder in ("sessions", "archived_sessions")
        if (home / folder).exists()
        for path in (home / folder).rglob("rollout-*.jsonl")
    ]
    invalid_rollout_paths = [
        str(path) for path in discovered if path.is_symlink() or not path.resolve().is_relative_to(home)
    ]
    disk_paths = {str(path.resolve()) for path in discovered if str(path) not in invalid_rollout_paths}
    providers: Counter[str] = Counter()
    metadata: dict[str, tuple[bytes, dict[str, object], tuple[int, int, int, int]]] = {}
    for path_string in sorted(disk_paths):
        path = Path(path_string)
        line, record = first_record(path)
        stat = path.stat()
        metadata[path_string] = (
            line,
            record,
            (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns),
        )
        providers[str(record["payload"].get("model_provider"))] += 1

    rows_by_path = {str(resolve_rollout(home, str(row["rollout_path"]))): row for row in rows}
    id_path_mismatches = []
    archive_location_mismatches = []
    for path_string, (_, record, _) in metadata.items():
        row = rows_by_path.get(path_string)
        if row is None:
            continue
        payload_id = record["payload"].get("id")
        if payload_id and str(payload_id) != str(row["id"]):
            id_path_mismatches.append(
                {"path": path_string, "database_id": row["id"], "payload_id": payload_id}
            )
        in_archive = Path(path_string).is_relative_to(home / "archived_sessions")
        if bool(row.get("archived")) != in_archive:
            archive_location_mismatches.append(
                {"id": row["id"], "path": path_string, "archived": row.get("archived")}
            )

    legacy = legacy_names(home)
    candidates = []
    ambiguous = []
    for row in rows:
        old = legacy.get(str(row["id"]), "").strip()
        current = str(row.get("name") or "").strip()
        if not old or current:
            continue
        if old == row.get("title") and old != row.get("first_user_message"):
            candidates.append({"id": row["id"], "name": old})
        else:
            ambiguous.append({"id": row["id"], "legacy_name": old})

    target = config_target(home, profile)
    state_path = home / STATE_FILE
    previous = {}
    if state_path.exists():
        try:
            previous = json.loads(state_path.read_text())
        except json.JSONDecodeError:
            previous = {"invalid": True}
        if not isinstance(previous, dict):
            previous = {"invalid": True}
    previous_scope = scoped_state(previous, target["profile"])
    ambiguous_report = [
        {"id": item["id"], "legacy_name_preview": item["legacy_name"][:160]}
        for item in ambiguous
    ]
    incomplete_journals = []
    for manifest_path in (home / "backups").glob("session-guard-*/manifest.json"):
        try:
            status = json.loads(manifest_path.read_text()).get("status")
        except (OSError, json.JSONDecodeError):
            status = "invalid"
        if status in INCOMPLETE_STATUSES or status == "invalid":
            incomplete_journals.append({"path": str(manifest_path.parent), "status": status})
    report = {
        "codex_home": str(home),
        "database": str(db),
        "threads": len(rows),
        "active": sum(not bool(row.get("archived")) for row in rows),
        "archived": sum(bool(row.get("archived")) for row in rows),
        "active_visible_estimate": sum(
            not bool(row.get("archived")) and bool(row.get("preview")) for row in rows
        ),
        "rollout_files": len(disk_paths),
        "stale_database_paths": sorted(set(db_paths) - disk_paths),
        "unindexed_rollout_files": sorted(disk_paths - set(db_paths)),
        "duplicate_database_paths": len(db_paths) - len(set(db_paths)),
        "invalid_rollout_paths": invalid_rollout_paths,
        "id_path_mismatches": id_path_mismatches,
        "archive_location_mismatches": archive_location_mismatches,
        "incomplete_journals": incomplete_journals,
        "jsonl_providers": dict(providers),
        "database_providers": dict(Counter(str(row.get("model_provider")) for row in rows)),
        "database_models": dict(Counter(str(row.get("model")) for row in rows)),
        "rename_candidates": candidates,
        "ambiguous_rename_count": len(ambiguous),
        "ambiguous_renames": ambiguous_report if verbose else ambiguous_report[:20],
        "ambiguous_renames_truncated": not verbose and len(ambiguous_report) > 20,
        "schema_columns": columns,
        "target": target,
        "available_profiles": available_profiles(home),
        "provider_or_relay_changed": previous_scope.get("fingerprint") != target["fingerprint"],
        "previous_fingerprint_known": bool(previous_scope.get("fingerprint")),
    }
    context = {
        "db": db,
        "columns": columns,
        "rows": rows,
        "metadata": metadata,
        "target": target,
        "rename_candidates": candidates,
        "previous_state": previous,
        "previous_scope": previous_scope,
    }
    return report, context


def require_clean(report: dict[str, object], allow_journal: Path | None = None) -> None:
    failures = []
    for key in ("stale_database_paths", "unindexed_rollout_files"):
        if report[key]:
            failures.append(f"{key}={len(report[key])}")
    if report["duplicate_database_paths"]:
        failures.append(f"duplicate_database_paths={report['duplicate_database_paths']}")
    for key in ("id_path_mismatches", "archive_location_mismatches", "invalid_rollout_paths"):
        if report[key]:
            failures.append(f"{key}={len(report[key])}")
    incomplete = [
        item
        for item in report["incomplete_journals"]
        if allow_journal is None or Path(item["path"]).resolve() != allow_journal.resolve()
    ]
    if incomplete:
        failures.append(f"incomplete_journals={len(incomplete)}")
    if failures:
        die("Refusing mutation; audit mismatch: " + ", ".join(failures))


def compact_report(report: dict[str, object]) -> dict[str, object]:
    problem_keys = (
        "stale_database_paths",
        "unindexed_rollout_files",
        "duplicate_database_paths",
        "invalid_rollout_paths",
        "id_path_mismatches",
        "archive_location_mismatches",
        "incomplete_journals",
    )
    problems = {
        key: value if isinstance(value, int) else len(value)
        for key in problem_keys
        if (value := report[key])
    }
    target = report["target"]
    return {
        "codex_home": report["codex_home"],
        "database": report["database"],
        "threads": report["threads"],
        "active": report["active"],
        "archived": report["archived"],
        "active_visible_estimate": report["active_visible_estimate"],
        "rollout_files": report["rollout_files"],
        "problems": problems,
        "jsonl_providers": report["jsonl_providers"],
        "database_providers": report["database_providers"],
        "database_models": report["database_models"],
        "rename_candidate_count": len(report["rename_candidates"]),
        "ambiguous_rename_count": report["ambiguous_rename_count"],
        "target": {
            key: target[key]
            for key in ("provider", "profile", "profile_kind", "model", "approval_policy", "sandbox_mode")
        },
        "available_profiles": report["available_profiles"],
        "provider_or_relay_changed": report["provider_or_relay_changed"],
        "previous_fingerprint_known": report["previous_fingerprint_known"],
    }


def require_mutation_schema(context: dict[str, object]) -> None:
    required = {"id", "rollout_path", "archived", "model_provider", "model", "name"}
    missing = sorted(required - set(context["columns"]))
    if missing:
        die("This Codex database schema cannot be mutated safely; missing columns: " + ", ".join(missing))


@contextlib.contextmanager
def mutation_lock(home: Path):
    if fcntl is None:
        die("Mutating modes are not supported on this platform because advisory locking is unavailable")
    lock_path = home / "backups" / "session-guard.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as stream:
        os.chmod(lock_path, 0o600)
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            die("Another session_guard mutation is running")
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def verify_protected_fields(
    con: sqlite3.Connection,
    rows: list[dict[str, object]],
    columns: list[str],
) -> None:
    protected = [
        name
        for name in (
            "archived",
            "archived_at",
            "created_at",
            "updated_at",
            "created_at_ms",
            "updated_at_ms",
            "recency_at",
            "recency_at_ms",
        )
        if name in columns
    ]
    if not protected:
        return
    expected = {str(row["id"]): tuple(row.get(name) for name in protected) for row in rows}
    actual = {
        str(row[0]): tuple(row[1:])
        for row in con.execute(f"select id,{','.join(protected)} from threads")
    }
    if actual != expected:
        die("Mutation changed archive, recency, or timestamp fields")


def changed_first_line(line: bytes, target_provider: str) -> bytes:
    record = json.loads(line)
    record["payload"]["model_provider"] = target_provider
    ending = b"\n" if line.endswith(b"\n") else b""
    return json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode() + ending


def retarget_record(record: dict[str, object], target_provider: str) -> bool:
    """Point every provider field in one rollout record at `target_provider`.

    Codex records the provider in more than one place: the `session_meta` header
    (which a file may repeat) and `thread_settings.model_provider_id` inside
    `event_msg` records. Reindexing reads the latter, so rewriting only the first
    line lets the database drift back to the old provider. Returns whether
    anything changed.
    """
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return False
    changed = False
    if record.get("type") == "session_meta" and payload.get("model_provider") != target_provider:
        payload["model_provider"] = target_provider
        changed = True
    settings = payload.get("thread_settings")
    if isinstance(settings, dict) and "model_provider_id" in settings:
        if settings["model_provider_id"] != target_provider:
            settings["model_provider_id"] = target_provider
            changed = True
    return changed


def deep_line_changes(path: Path, target_provider: str) -> list[dict[str, object]]:
    """Every line in one rollout file that still names another provider.

    Lines are addressed by index and verified by digest at apply time, so a
    concurrent append (which only adds lines at the end) cannot silently shift
    the rewrite onto the wrong record.
    """
    changes = []
    with path.open("rb") as stream:
        for index, line in enumerate(stream):
            if b"model_provider" not in line:
                continue
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if not isinstance(record, dict):
                continue
            if not retarget_record(record, target_provider):
                continue
            ending = b"\n" if line.endswith(b"\n") else b""
            after = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode() + ending
            changes.append(
                {
                    "index": index,
                    "before_sha256": sha256(line),
                    "after_b64": base64.b64encode(after).decode(),
                    "before_b64": base64.b64encode(line).decode(),
                }
            )
    return changes


def rewrite_lines(change: dict[str, object], use_after: bool) -> None:
    """Replace individual lines of a rollout file atomically.

    Mirrors `replace_first_line`: the file identity and mtime/size are checked
    before and after the copy, every targeted line must still match its recorded
    digest, and the result is fsynced before the rename.
    """
    path = Path(str(change["path"]))
    audit_stat = tuple(change["audit_stat"])
    stat = path.stat()
    if use_after and (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns) != audit_stat:
        die(f"File changed since audit: {path}")
    lines: dict[int, tuple[str, bytes]] = {}
    for item in change["lines"]:
        expected = item["before_sha256"] if use_after else sha256(base64.b64decode(item["after_b64"]))
        replacement = item["after_b64"] if use_after else item["before_b64"]
        lines[int(item["index"])] = (expected, base64.b64decode(replacement))
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = Path(temp_name)
    seen = set()
    try:
        with path.open("rb") as source, os.fdopen(fd, "wb") as output:
            opened = os.fstat(source.fileno())
            if (opened.st_dev, opened.st_ino) != (stat.st_dev, stat.st_ino):
                die(f"File identity changed during migration: {path}")
            for index, line in enumerate(source):
                target = lines.get(index)
                if target is None:
                    output.write(line)
                    continue
                expected, replacement = target
                if sha256(line) != expected:
                    die(f"Concurrent change detected at line {index} in {path}")
                output.write(replacement)
                seen.add(index)
            after_copy = os.fstat(source.fileno())
            if (
                after_copy.st_size != opened.st_size
                or after_copy.st_mtime_ns != opened.st_mtime_ns
            ):
                die(f"Concurrent append detected in {path}")
            output.flush()
            os.fsync(output.fileno())
        missing = sorted(set(lines) - seen)
        if missing:
            die(f"Recorded lines are missing from {path}: {missing}")
        shutil.copystat(path, temp)
        os.replace(temp, path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def create_backup(
    home: Path,
    context: dict[str, object],
    row_changes: list[dict[str, object]],
    file_changes: list[dict[str, object]],
    operation: str,
    state_after: bytes | None,
) -> tuple[Path, dict[str, object]]:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = home / "backups" / f"session-guard-{stamp}"
    backup.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(backup, 0o700)
    source = sqlite3.connect(context["db"])
    copied = sqlite3.connect(backup / "state.sqlite")
    source.backup(copied)
    copied.close()
    source.close()
    os.chmod(backup / "state.sqlite", 0o600)
    check_con = sqlite3.connect(backup / "state.sqlite")
    check = check_con.execute("pragma integrity_check").fetchone()[0]
    check_con.close()
    if check != "ok":
        die(f"Backup integrity_check failed: {check}")
    manifest = {
        "version": 1,
        "operation": operation,
        "created_at_utc": stamp,
        "codex_home": str(home),
        "database": str(context["db"]),
        "database_backup": "state.sqlite",
        "database_backup_sha256": sha256_file(backup / "state.sqlite"),
        "status": "prepared",
        "config_fingerprint_after": context["target"]["fingerprint"],
        "profile": context["target"]["profile"],
        "state_before": (
            base64.b64encode((home / STATE_FILE).read_bytes()).decode()
            if (home / STATE_FILE).exists()
            else None
        ),
        "state_after": base64.b64encode(state_after).decode() if state_after is not None else None,
        "row_changes": row_changes,
        "file_changes": file_changes,
    }
    write_json(backup / "manifest.json", manifest)
    return backup, manifest


def replace_first_line(change: dict[str, object], use_after: bool) -> None:
    path = Path(str(change["path"]))
    audit_stat = tuple(change["audit_stat"])
    stat = path.stat()
    if use_after and (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns) != audit_stat:
        die(f"File changed since audit: {path}")
    expected = change["before"] if use_after else change["after"]
    replacement = change["after"] if use_after else change["before"]
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = Path(temp_name)
    try:
        with path.open("rb") as source, os.fdopen(fd, "wb") as output:
            opened = os.fstat(source.fileno())
            if (opened.st_dev, opened.st_ino) != (stat.st_dev, stat.st_ino):
                die(f"File identity changed during migration: {path}")
            current = source.readline()
            if sha256(current) != expected["sha256"]:
                die(f"Concurrent change detected in {path}")
            output.write(base64.b64decode(replacement["line_b64"]))
            shutil.copyfileobj(source, output, 1024 * 1024)
            after_copy = os.fstat(source.fileno())
            if (
                after_copy.st_size != opened.st_size
                or after_copy.st_mtime_ns != opened.st_mtime_ns
            ):
                die(f"Concurrent append detected in {path}")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temp, stat.st_mode)
        if path.stat().st_mtime_ns != stat.st_mtime_ns or path.stat().st_size != stat.st_size:
            die(f"Concurrent write detected in {path}")
        os.replace(temp, path)
        os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temp.unlink(missing_ok=True)


def live_rollouts(context: dict[str, object], settle_seconds: float = 2.0) -> set[str]:
    """Rollout files still being appended to by a running Codex session.

    A live session holds an open fd and appends as the turn progresses. Rewriting
    the first line goes through a temp file plus rename, so any append that lands
    between the audit stat and the rename is lost. Sample twice and treat anything
    that moves -- or that already drifted from the audit stat -- as live.
    """
    first: dict[str, tuple[int, int]] = {}
    for path_string, (_, _, audit_stat) in context["metadata"].items():
        try:
            stat = Path(path_string).stat()
        except OSError:
            continue
        if (stat.st_size, stat.st_mtime_ns) != (audit_stat[2], audit_stat[3]):
            first[path_string] = (-1, -1)
        else:
            first[path_string] = (stat.st_size, stat.st_mtime_ns)
    time.sleep(settle_seconds)
    live = set()
    for path_string, sample in first.items():
        if sample == (-1, -1):
            live.add(path_string)
            continue
        try:
            stat = Path(path_string).stat()
        except OSError:
            continue
        if (stat.st_size, stat.st_mtime_ns) != sample:
            live.add(path_string)
    return live


def apply_changes(
    home: Path,
    context: dict[str, object],
    provider: str | None,
    model: str | None,
    do_renames: bool,
    operation: str,
    skip_paths: set[str] | None = None,
    deep: bool = False,
) -> Path | None:
    require_mutation_schema(context)
    skip_paths = skip_paths or set()
    skipped_ids = {
        str(row["id"])
        for row in context["rows"]
        if str(resolve_rollout(home, str(row["rollout_path"]))) in skip_paths
    }
    rows: list[dict[str, object]] = context["rows"]
    candidates = {item["id"]: item["name"] for item in context["rename_candidates"]} if do_renames else {}
    row_changes = []
    for row in rows:
        if str(row["id"]) in skipped_ids:
            continue
        after = {
            "model_provider": provider if provider is not None else row.get("model_provider"),
            "model": model if model is not None else row.get("model"),
            "name": candidates.get(row["id"], row.get("name")),
        }
        before = {key: row.get(key) for key in after}
        if before != after:
            row_changes.append({"id": row["id"], "before": before, "after": after})

    file_changes = []
    deep_changes = []
    if provider is not None:
        for path_string, (line, record, audit_stat) in context["metadata"].items():
            if path_string in skip_paths:
                continue
            if deep:
                # In deep mode every provider-bearing line is handled together, so the
                # first line is covered here too rather than by `file_changes`.
                lines = deep_line_changes(Path(path_string), provider)
                if lines:
                    deep_changes.append(
                        {
                            "path": path_string,
                            "audit_stat": list(audit_stat),
                            "lines": lines,
                        }
                    )
                continue
            if record["payload"].get("model_provider") == provider:
                continue
            after = changed_first_line(line, provider)
            file_changes.append(
                {
                    "path": path_string,
                    "audit_stat": list(audit_stat),
                    "before": {"sha256": sha256(line), "line_b64": base64.b64encode(line).decode()},
                    "after": {"sha256": sha256(after), "line_b64": base64.b64encode(after).decode()},
                }
            )
    applied_fingerprint = context["target"]["fingerprint"]
    profile = context["target"]["profile"]
    record = {
        "fingerprint": applied_fingerprint,
        "provider": provider or context["target"]["provider"],
        "model": model or context["target"]["model"],
        "applied_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    if skip_paths:
        # Deferred sessions are still on the old provider, so this run did not finish
        # the migration. Record the count so the next run is not mistaken for a no-op.
        record["deferred_live_sessions"] = len(skip_paths)
    if deep:
        record["deep"] = True
    state = merged_state(context["previous_state"], record, profile)
    state_bytes = (json.dumps(state, ensure_ascii=False, indent=2) + "\n").encode()
    state_needs_change = (
        operation == "switch"
        and context["previous_scope"].get("fingerprint") != applied_fingerprint
    )
    if not row_changes and not file_changes and not deep_changes and not state_needs_change:
        return None

    backup, manifest = create_backup(
        home,
        context,
        row_changes,
        file_changes,
        operation,
        state_bytes if operation == "switch" else None,
    )
    if deep_changes:
        manifest["deep_changes"] = deep_changes
    manifest["status"] = "applying"
    write_json(backup / "manifest.json", manifest)
    con = sqlite3.connect(context["db"], timeout=5)
    changed_files: list[dict[str, object]] = []
    changed_deep: list[dict[str, object]] = []
    try:
        con.execute("begin immediate")
        for change in row_changes:
            current = con.execute(
                "select model_provider, model, name from threads where id=?", (change["id"],)
            ).fetchone()
            expected = change["before"]
            if current != (expected["model_provider"], expected["model"], expected["name"]):
                die(f"Concurrent database change detected for {change['id']}")
            con.execute(
                "update threads set model_provider=?, model=?, name=? where id=?",
                (
                    change["after"]["model_provider"],
                    change["after"]["model"],
                    change["after"]["name"],
                    change["id"],
                ),
            )
        for change in file_changes:
            replace_first_line(change, True)
            changed_files.append(change)
        for change in deep_changes:
            rewrite_lines(change, True)
            changed_deep.append(change)
        verify_protected_fields(con, rows, context["columns"])
        if con.execute("pragma integrity_check").fetchone()[0] != "ok":
            die("Post-update database integrity_check failed")
        con.commit()
    except BaseException:
        con.rollback()
        for change in reversed(changed_deep):
            rewrite_lines(change, False)
        for change in reversed(changed_files):
            replace_first_line(change, False)
        raise
    finally:
        con.close()

    manifest["status"] = "data_applied"
    write_json(backup / "manifest.json", manifest)
    if operation == "switch":
        write_json(home / STATE_FILE, json.loads(state_bytes))
    manifest["status"] = "applied"
    write_json(backup / "manifest.json", manifest)
    return backup


def rollback(home: Path, backup: Path) -> None:
    backup = backup.resolve()
    backup_root = (home / "backups").resolve()
    if not backup.is_relative_to(backup_root) or not backup.name.startswith("session-guard-"):
        die("Rollback backup must be a session-guard directory under this Codex home")
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if not isinstance(manifest, dict) or manifest.get("version") != 1:
        die("Unsupported or malformed rollback manifest")
    if Path(manifest.get("codex_home", "")).resolve() != home:
        die("Backup belongs to a different Codex home")
    status = manifest.get("status")
    if status == "rolled_back":
        return
    if status not in INCOMPLETE_STATUSES | {"applied"}:
        die(f"Manifest cannot be rolled back from status: {status}")
    db = Path(manifest.get("database", "")).resolve()
    if db != find_db(home).resolve():
        die("Manifest database is not the active Codex state database")
    database_backup = backup / manifest.get("database_backup", "")
    if (
        not database_backup.is_file()
        or sha256_file(database_backup) != manifest.get("database_backup_sha256")
    ):
        die("Database backup hash mismatch")
    if manifest.get("operation") == "switch":
        current_fingerprint = config_target(home, manifest.get("profile"))["fingerprint"]
        if current_fingerprint != manifest.get("config_fingerprint_after"):
            die("Refusing rollback because effective provider/relay configuration changed")

    report, context = audit(home, profile=manifest.get("profile"))
    require_clean(report, backup)
    valid_paths = set(context["metadata"])

    def check_rollout_path(raw: str) -> Path:
        path = Path(raw).resolve()
        if (
            str(path) not in valid_paths
            or not path.is_relative_to(home / "sessions")
            and not path.is_relative_to(home / "archived_sessions")
        ):
            die(f"Manifest contains an invalid rollout path: {path}")
        return path

    for change in manifest.get("file_changes", []):
        path = check_rollout_path(change.get("path", ""))
        for side in ("before", "after"):
            line = base64.b64decode(change[side]["line_b64"])
            if sha256(line) != change[side]["sha256"]:
                die(f"Manifest first-line hash mismatch for {path}")
    for change in manifest.get("deep_changes", []):
        path = check_rollout_path(change.get("path", ""))
        for item in change.get("lines", []):
            before = base64.b64decode(item["before_b64"])
            if sha256(before) != item["before_sha256"]:
                die(f"Manifest deep-line hash mismatch for {path} line {item.get('index')}")

    state_path = home / STATE_FILE
    state_before = (
        base64.b64decode(manifest["state_before"])
        if manifest.get("state_before") is not None
        else None
    )
    state_after = (
        base64.b64decode(manifest["state_after"])
        if manifest.get("state_after") is not None
        else None
    )
    current_state = state_path.read_bytes() if state_path.exists() else None
    if manifest.get("operation") == "switch" and current_state not in (state_before, state_after):
        die("Refusing rollback; switch fingerprint state changed after migration")

    manifest["status"] = "rolling_back"
    write_json(manifest_path, manifest)
    con = sqlite3.connect(db, timeout=5)
    try:
        con.execute("begin immediate")
        for change in manifest.get("row_changes", []):
            if change.get("after") is None and change.get("deleted_row") is not None:
                deleted = change["deleted_row"]
                columns = [key for key in deleted if key in context["columns"]]
                if "id" not in columns or "rollout_path" not in columns:
                    die(f"Prune manifest is missing required columns for {change['id']}")
                existing = con.execute(
                    "select 1 from threads where id=?", (change["id"],)
                ).fetchone()
                if existing:
                    continue
                con.execute(
                    f"insert into threads({','.join(columns)}) "
                    f"values({','.join('?' for _ in columns)})",
                    tuple(deleted[key] for key in columns),
                )
                continue
            current = con.execute(
                "select model_provider, model, name from threads where id=?", (change["id"],)
            ).fetchone()
            before = change["before"]
            after = change["after"]
            before_tuple = (before["model_provider"], before["model"], before["name"])
            after_tuple = (after["model_provider"], after["model"], after["name"])
            if current not in (before_tuple, after_tuple):
                die(f"Refusing rollback; database diverged for {change['id']}")
            if current != before_tuple:
                con.execute(
                    "update threads set model_provider=?, model=?, name=? where id=?",
                    (*before_tuple, change["id"]),
                )
        for change in manifest.get("file_changes", []):
            path = Path(change["path"])
            with path.open("rb") as stream:
                current_line = stream.readline(MAX_METADATA_LINE + 1)
            current_hash = sha256(current_line)
            if current_hash == change["before"]["sha256"]:
                continue
            if current_hash != change["after"]["sha256"]:
                die(f"Refusing rollback; rollout diverged: {path}")
            replace_first_line(change, False)
        for change in manifest.get("deep_changes", []):
            path = Path(change["path"])
            # Restore only files still holding the post-migration content; a file already
            # back at its recorded "before" state is left alone, and anything else means
            # the file changed outside this tool.
            wanted = {int(item["index"]): item for item in change["lines"]}
            state = None
            with path.open("rb") as stream:
                for index, line in enumerate(stream):
                    item = wanted.get(index)
                    if item is None:
                        continue
                    digest = sha256(line)
                    if digest == item["before_sha256"]:
                        seen = "before"
                    elif digest == sha256(base64.b64decode(item["after_b64"])):
                        seen = "after"
                    else:
                        die(f"Refusing rollback; rollout diverged: {path} line {index}")
                    if state is None:
                        state = seen
                    elif state != seen:
                        die(f"Refusing rollback; rollout partially rewritten: {path}")
            if state == "after":
                rewrite_lines(change, False)
        expected_rows = list(context["rows"])
        restored_ids = {
            str(change["id"])
            for change in manifest.get("row_changes", [])
            if change.get("after") is None and change.get("deleted_row") is not None
        }
        if restored_ids:
            known = {str(row["id"]) for row in expected_rows}
            for change in manifest.get("row_changes", []):
                identifier = str(change["id"])
                if identifier in restored_ids and identifier not in known:
                    expected_rows.append(change["deleted_row"])
        verify_protected_fields(con, expected_rows, context["columns"])
        if con.execute("pragma integrity_check").fetchone()[0] != "ok":
            die("Rollback integrity_check failed")
        con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()

    if manifest.get("operation") == "switch":
        if state_before is None:
            state_path.unlink(missing_ok=True)
        else:
            atomic_write(state_path, state_before)
    manifest["status"] = "rolled_back"
    manifest["rolled_back_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    write_json(manifest_path, manifest)


OFFICIAL_BASE_URL = "https://chatgpt.com/backend-api/codex"
RESERVED_PROVIDER_IDS = {"openai"}
TOP_LEVEL_PROVIDER = re.compile(
    r"""(?m)^([ \t]*)model_provider([ \t]*=[ \t]*)("[^"\n]*"|'[^'\n]*')([ \t]*)(\#.*)?$"""
)


def config_files(home: Path) -> list[Path]:
    """The base config plus every `-p <name>` profile overlay, in apply order."""
    files = []
    base = home / "config.toml"
    if base.is_file() and not base.is_symlink():
        files.append(base)
    for name in available_profiles(home):
        files.append(profile_path(home, name))
    return files


def insert_top_level(source: str, line: str) -> str:
    """Add a root-level key before the first table header.

    Appending at the end would land the key inside whatever `[table]` comes last,
    silently turning `model_provider` into a child of e.g. `[projects."/path"]`.
    """
    match = re.search(r"(?m)^\[", source)
    if match is None:
        prefix = source if not source or source.endswith("\n") else source + "\n"
        return prefix + line + "\n"
    return source[: match.start()] + line + "\n\n" + source[match.start() :]


def unified_config(source: str, target: str) -> tuple[str, list[str]]:
    """Rewrite one config file so its provider id becomes `target`.

    Only the provider identity changes: the `[model_providers.X]` body keeps its
    `base_url`, `env_key`, `name` and everything else, so each channel still talks
    to its own endpoint with its own credential variable. A file that declares no
    provider table gets one equivalent to the built-in `openai` provider, which
    keeps authenticating through `auth.json`.
    """
    old_ids = [
        match.group(1)
        for match in re.finditer(r"(?m)^\[model_providers\.([A-Za-z0-9._-]+)\]", source)
    ]
    result, replaced = TOP_LEVEL_PROVIDER.subn(
        lambda m: f'{m.group(1)}model_provider{m.group(2)}"{target}"{m.group(4) or ""}{m.group(5) or ""}',
        source,
    )
    for old in old_ids:
        if old == target:
            continue
        result = re.sub(
            r"(?m)^\[model_providers\." + re.escape(old) + r"\]$",
            f"[model_providers.{target}]",
            result,
        )
    if replaced == 0:
        result = insert_top_level(result, f'model_provider = "{target}"')
    if not old_ids:
        # No provider table at all means this file relied on the built-in `openai`
        # provider. Recreate it under the shared id so the official channel joins
        # the same session pool.
        result = result.rstrip("\n") + (
            f"\n\n[model_providers.{target}]\n"
            'name = "OpenAI"\n'
            f'base_url = "{OFFICIAL_BASE_URL}"\n'
            'wire_api = "responses"\n'
            "requires_openai_auth = true\n"
        )
    return result, old_ids


def unify(home: Path, target: str, skip_live: bool) -> dict[str, object]:
    """Point every profile at one provider id and migrate the history to match.

    The resume picker filters on `threads.model_provider` and compares only the id,
    so profiles keep separate session lists until they share an id. Rewriting the
    configs without migrating the history would leave every profile at zero
    sessions, so both halves happen here under one backup.
    """
    if target in RESERVED_PROVIDER_IDS:
        die(
            f"'{target}' is a reserved built-in provider id and cannot be shared. "
            "Choose a custom id such as 'shared'."
        )
    if not re.fullmatch(r"[A-Za-z0-9._-]+", target):
        die(f"Invalid provider id: {target}")

    targets = config_files(home)
    if not targets:
        die(f"No config.toml or *.config.toml found in {home}")

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = home / "backups" / f"unify-{stamp}"
    backup.mkdir(parents=True, mode=0o700)
    rewrites = []
    for path in targets:
        original = path.read_text()
        shutil.copy2(path, backup / path.name)
        updated, old_ids = unified_config(original, target)
        parsed = tomllib.loads(updated)
        if parsed.get("model_provider") != target:
            die(f"Rewritten config does not select the shared provider: {path}")
        if target not in parsed.get("model_providers", {}):
            die(f"Rewritten config has no [model_providers.{target}] table: {path}")
        before = tomllib.loads(original)
        for old in old_ids:
            kept = before.get("model_providers", {}).get(old, {})
            now = parsed["model_providers"][target]
            for key, value in kept.items():
                if key != "name" and now.get(key) != value:
                    die(f"Rewrite would change {key} of [model_providers.{old}] in {path}")
        rewrites.append(
            {"path": str(path), "old_provider_ids": old_ids, "changed": updated != original}
        )
        if updated != original:
            atomic_write(path, updated.encode(), path.stat().st_mode & 0o777)

    report, context = audit(home)
    require_clean(report)
    skip = live_rollouts(context) if skip_live else set()
    session_backup = apply_changes(home, context, target, None, True, "switch", skip, True)
    after, _ = audit(home)
    require_clean(after)
    return {
        "provider": target,
        "config_backup": str(backup),
        "configs": rewrites,
        "session_backup": str(session_backup) if session_backup else None,
        "deferred_live_sessions": sorted(skip),
        "audit": after,
    }


def full_rows(db: Path, ids: list[str]) -> dict[str, dict[str, object]]:
    """Read complete thread rows, including columns the audit does not track.

    A prune must be able to reconstruct the row exactly, and real Codex schemas
    carry NOT NULL columns beyond the audited subset, so the deletion snapshot
    is taken from `select *` rather than the audit projection.
    """
    if not ids:
        return {}
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        placeholders = ",".join("?" for _ in ids)
        rows = {}
        for row in con.execute(f"select * from threads where id in ({placeholders})", ids):
            record = dict(row)
            unsupported = sorted(
                key
                for key, value in record.items()
                if not isinstance(value, (str, int, float, bool, type(None)))
            )
            if unsupported:
                die(
                    "Cannot snapshot a row with non-text column types: "
                    + ", ".join(unsupported)
                )
            rows[str(row["id"])] = record
        return rows
    finally:
        con.close()


def prune(home: Path, context: dict[str, object], report: dict[str, object]) -> Path | None:
    """Delete thread rows whose rollout file no longer exists.

    Codex leaves a row behind when a rollout JSONL is deleted outside the CLI.
    Those rows make every other mode refuse to run, and no amount of provider
    synchronisation can fix them, so removal is the only route forward. Rows are
    only ever removed when the recorded path is absent from disk; a row whose
    file exists is never touched, and the full database is backed up first.
    """
    require_mutation_schema(context)
    stale = set(report["stale_database_paths"])
    if not stale:
        return None
    rows: list[dict[str, object]] = context["rows"]
    doomed = []
    for row in rows:
        path = resolve_rollout(home, str(row["rollout_path"]))
        if str(path) not in stale:
            continue
        if path.exists():
            die(f"Refusing to prune a row whose rollout file exists: {path}")
        doomed.append(row)
    if not doomed:
        return None

    snapshots = full_rows(Path(str(context["db"])), [str(row["id"]) for row in doomed])
    row_changes = []
    for row in doomed:
        snapshot = snapshots.get(str(row["id"]))
        if snapshot is None:
            die(f"Could not read the full row for {row['id']}")
        row_changes.append(
            {
                "id": row["id"],
                "before": {key: row.get(key) for key in ("model_provider", "model", "name")},
                "after": None,
                "deleted_row": snapshot,
            }
        )
    backup, manifest = create_backup(home, context, row_changes, [], "prune", None)
    manifest["status"] = "applying"
    write_json(backup / "manifest.json", manifest)
    survivors = [row for row in rows if row not in doomed]
    con = sqlite3.connect(context["db"], timeout=5)
    try:
        con.execute("begin immediate")
        for row in doomed:
            current = con.execute(
                "select rollout_path from threads where id=?", (row["id"],)
            ).fetchone()
            if current is None:
                die(f"Row vanished before prune: {row['id']}")
            if str(current[0]) != str(row["rollout_path"]):
                die(f"Concurrent database change detected for {row['id']}")
            if resolve_rollout(home, str(current[0])).exists():
                die(f"Rollout file reappeared for {row['id']}; refusing to prune")
            con.execute("delete from threads where id=?", (row["id"],))
        verify_protected_fields(con, survivors, context["columns"])
        if con.execute("pragma integrity_check").fetchone()[0] != "ok":
            die("Post-prune database integrity_check failed")
        con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()
    manifest["status"] = "applied"
    manifest["pruned_ids"] = [row["id"] for row in doomed]
    write_json(backup / "manifest.json", manifest)
    return backup


def assert_no_credentials(names: list[str]) -> None:
    for name in names:
        base = Path(name).name
        if base in CREDENTIAL_NAMES or base.startswith("auth.json"):
            die(f"Refusing to include a credential file in a bundle: {name}")


def export_bundle(home: Path, destination: Path, profile: str | None) -> dict[str, object]:
    """Write a self-describing session bundle for transfer to another machine.

    The bundle carries session history and a consistent database snapshot only.
    Credentials and `config.toml` are deliberately excluded: the destination must
    authenticate with its own keys, and copying a source `config.toml` would
    point the new machine at a relay it may not be entitled to use.
    """
    report, context = audit(home, profile=profile)
    require_clean(report)
    if destination.exists():
        die(f"Export destination already exists: {destination}")
    destination.mkdir(parents=True, mode=0o700)
    os.chmod(destination, 0o700)

    payload = destination / "codex_home"
    payload.mkdir(mode=0o700)
    copied = []
    for name in TRANSFER_ITEMS:
        source = home / name
        if not source.exists():
            continue
        target = payload / name
        if source.is_dir():
            shutil.copytree(source, target, symlinks=False, ignore_dangling_symlinks=False)
        else:
            shutil.copy2(source, target)
        copied.append(name)
    assert_no_credentials([str(path.relative_to(payload)) for path in payload.rglob("*")])

    source_con = sqlite3.connect(context["db"])
    snapshot = sqlite3.connect(destination / "state.sqlite")
    source_con.backup(snapshot)
    snapshot.close()
    source_con.close()
    os.chmod(destination / "state.sqlite", 0o600)
    check_con = sqlite3.connect(destination / "state.sqlite")
    check = check_con.execute("pragma integrity_check").fetchone()[0]
    check_con.close()
    if check != "ok":
        die(f"Exported database integrity_check failed: {check}")

    digests = {
        str(path.relative_to(destination)): sha256_file(path)
        for path in sorted(destination.rglob("*"))
        if path.is_file()
    }
    manifest = {
        "version": 1,
        "kind": "session-bundle",
        "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_codex_home": str(home),
        "source_database": Path(str(context["db"])).name,
        "threads": report["threads"],
        "active": report["active"],
        "archived": report["archived"],
        "rollout_files": report["rollout_files"],
        "jsonl_providers": report["jsonl_providers"],
        "database_providers": report["database_providers"],
        "source_provider": context["target"]["provider"],
        "source_profile": context["target"]["profile"],
        "included": copied,
        "digests": digests,
    }
    write_json(destination / "bundle.json", manifest)
    return {
        "bundle": str(destination),
        "threads": report["threads"],
        "rollout_files": report["rollout_files"],
        "included": copied,
        "excluded_by_design": ["auth.json", "config.toml", "credentials", "project files"],
    }


def verify_bundle(bundle: Path) -> dict[str, object]:
    manifest_path = bundle / "bundle.json"
    if not manifest_path.is_file():
        die(f"Not a session bundle (missing bundle.json): {bundle}")
    manifest = json.loads(manifest_path.read_text())
    if not isinstance(manifest, dict) or manifest.get("kind") != "session-bundle":
        die("Unsupported or malformed bundle manifest")
    if manifest.get("version") != 1:
        die(f"Unsupported bundle version: {manifest.get('version')}")
    digests = manifest.get("digests")
    if not isinstance(digests, dict) or not digests:
        die("Bundle manifest has no digests")
    assert_no_credentials(list(digests))
    for name, expected in sorted(digests.items()):
        path = (bundle / name).resolve()
        if not path.is_relative_to(bundle.resolve()):
            die(f"Bundle manifest references a path outside the bundle: {name}")
        if path.is_symlink() or not path.is_file():
            die(f"Bundle entry is missing or not a regular file: {name}")
        if sha256_file(path) != expected:
            die(f"Bundle digest mismatch: {name}")
    found = {
        str(path.relative_to(bundle))
        for path in bundle.rglob("*")
        if path.is_file()
        and path.name != "bundle.json"
        and not path.name.endswith(("-wal", "-shm", "-journal"))
    }
    unexpected = sorted(found - set(digests))
    if unexpected:
        die("Bundle contains files absent from the manifest: " + ", ".join(unexpected[:5]))
    snapshot = bundle / "state.sqlite"
    # `immutable=1` keeps the check read-only in the strictest sense: opening a
    # WAL-mode database normally creates -wal/-shm sidecars, which the file list
    # above would then reject as unmanifested on the next run.
    con = sqlite3.connect(f"file:{snapshot}?immutable=1", uri=True)
    try:
        if con.execute("pragma integrity_check").fetchone()[0] != "ok":
            die("Bundle database integrity_check failed")
        threads = con.execute("select count(*) from threads").fetchone()[0]
    finally:
        con.close()
    return {
        "bundle": str(bundle),
        "verified_files": len(digests),
        "bundle_threads": threads,
        "manifest_threads": manifest.get("threads"),
        "source_provider": manifest.get("source_provider"),
        "included": manifest.get("included", []),
    }


def import_bundle(home: Path, bundle: Path, profile: str | None) -> dict[str, object]:
    """Install a bundle into an empty Codex home, then sync it to local config.

    Refuses a destination that already holds sessions. Merging two populated
    homes needs schema-aware conflict resolution that this tool does not
    implement, and a blind copy would silently drop history on one side.
    """
    summary = verify_bundle(bundle)
    existing_db = sorted(home.glob("state_*.sqlite"))
    existing_sessions = [
        path
        for folder in ("sessions", "archived_sessions")
        if (home / folder).exists()
        for path in (home / folder).rglob("rollout-*.jsonl")
    ]
    if existing_sessions or existing_db:
        die(
            "Destination Codex home already has session state "
            f"({len(existing_sessions)} rollout files, {len(existing_db)} databases). "
            "Refusing to merge; import only into a home without sessions."
        )
    manifest = json.loads((bundle / "bundle.json").read_text())
    database_name = str(manifest.get("source_database") or "state_5.sqlite")
    if not re.fullmatch(r"state_\d+\.sqlite", database_name):
        die(f"Bundle records an unsafe database filename: {database_name}")

    for name in manifest.get("included", []):
        if name not in TRANSFER_ITEMS:
            die(f"Bundle lists an unexpected transfer item: {name}")
        source = bundle / "codex_home" / name
        if not source.exists():
            die(f"Bundle is missing a declared item: {name}")
        target = home / name
        if source.is_dir():
            shutil.copytree(source, target, symlinks=False)
        else:
            shutil.copy2(source, target)
    shutil.copy2(bundle / "state.sqlite", home / database_name)
    os.chmod(home / database_name, 0o600)

    report, context = audit(home, profile=profile)
    foreign = [
        row
        for row in context["rows"]
        if not resolve_rollout(home, str(row["rollout_path"])).is_relative_to(home)
    ]
    rewritten = None
    if foreign or report["stale_database_paths"]:
        # Imported rows carry the source machine's absolute paths. Rewrite them
        # to this home before any other check, since nothing else can proceed
        # while rows point outside this home.
        rewritten = rebase_paths(home, context, manifest)
        report, context = audit(home, profile=profile)
    require_clean(report)
    return {
        "imported": summary,
        "rebased_rows": rewritten,
        "audit": compact_report(report),
    }


def rebase_paths(home: Path, context: dict[str, object], manifest: dict[str, object]) -> int:
    """Point imported rollout_path values at this Codex home.

    A row is rewritten when its recorded path lies outside this home, which is
    the normal state right after an import. Existence on the local filesystem is
    deliberately not the trigger: when a bundle is imported on the same machine
    that produced it, the source paths still resolve, and leaving them alone
    would make the new home read another home's files. The rewrite is only kept
    when the translated path resolves to a real file inside this home, so a
    genuinely missing session still surfaces as stale.
    """
    source_home = str(manifest.get("source_codex_home") or "").rstrip("/")
    if not source_home:
        die("Bundle does not record its source Codex home; cannot rebase paths")
    con = sqlite3.connect(context["db"], timeout=5)
    changed = 0
    try:
        con.execute("begin immediate")
        for row in context["rows"]:
            raw = str(row["rollout_path"])
            current = resolve_rollout(home, raw)
            if current.is_relative_to(home) and current.is_file():
                continue
            if not raw.startswith(source_home + "/"):
                continue
            candidate = home / raw[len(source_home) + 1 :]
            resolved = candidate.resolve()
            if not resolved.is_relative_to(home) or not resolved.is_file():
                continue
            con.execute(
                "update threads set rollout_path=? where id=? and rollout_path=?",
                (str(resolved), row["id"], raw),
            )
            changed += 1
        verify_protected_fields(con, context["rows"], context["columns"])
        if con.execute("pragma integrity_check").fetchone()[0] != "ok":
            die("Post-rebase database integrity_check failed")
        con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()
    return changed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codex-home")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--compact", action="store_true")
    parser.add_argument(
        "--profile",
        help="Resolve the target provider through $CODEX_HOME/<name>.config.toml, "
        "matching `codex -p <name>`",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("audit")
    switch = sub.add_parser("switch")
    switch.add_argument("--provider")
    switch.add_argument("--model", help="Explicitly rewrite historical thread model metadata")
    switch.add_argument(
        "--skip-live",
        action="store_true",
        help="Leave rollout files that a running Codex session is still appending to "
        "untouched instead of refusing the whole migration; rerun after they exit",
    )
    switch.add_argument(
        "--deep",
        action="store_true",
        help="Also rewrite repeated session_meta records and "
        "thread_settings.model_provider_id, which reindexing otherwise reads to "
        "restore the old provider",
    )
    unify_parser = sub.add_parser(
        "unify",
        help="Point config.toml and every *.config.toml at one provider id, then "
        "deep-migrate the history so all profiles share one session list",
    )
    unify_parser.add_argument("--provider", default="shared")
    unify_parser.add_argument("--skip-live", action="store_true")
    sub.add_parser("repair")
    sub.add_parser("prune", help="Delete thread rows whose rollout file no longer exists")
    export_parser = sub.add_parser("export", help="Write a transferable session bundle")
    export_parser.add_argument("destination")
    verify_parser = sub.add_parser("verify", help="Check a bundle without writing anything")
    verify_parser.add_argument("bundle")
    import_parser = sub.add_parser("import", help="Install a bundle into an empty Codex home")
    import_parser.add_argument("bundle")
    rollback_parser = sub.add_parser("rollback")
    rollback_parser.add_argument("backup")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    home = resolve_home(args.codex_home)
    profile = getattr(args, "profile", None)

    if args.command == "verify":
        print(json.dumps(verify_bundle(Path(args.bundle).resolve()), ensure_ascii=False, indent=2))
        return

    if args.command == "export":
        with mutation_lock(home):
            result = export_bundle(home, Path(args.destination).resolve(), profile)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    if args.command == "import":
        with mutation_lock(home):
            result = import_bundle(home, Path(args.bundle).resolve(), profile)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    if args.command == "rollback":
        with mutation_lock(home):
            rollback(home, Path(args.backup).resolve())
        report, _ = audit(home, args.verbose, profile)
        output = compact_report(report) if args.compact else report
        print(json.dumps({"rolled_back": args.backup, "audit": output}, ensure_ascii=False, indent=2))
        return

    if args.command == "audit":
        report, _ = audit(home, args.verbose, profile)
        print(json.dumps(compact_report(report) if args.compact else report, ensure_ascii=False, indent=2))
        return

    if args.command == "unify":
        with mutation_lock(home):
            result = unify(home, args.provider, args.skip_live)
        if args.compact:
            result["audit"] = compact_report(result["audit"])
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    with mutation_lock(home):
        report, context = audit(home, args.verbose, profile)
        skip: set[str] = set()
        if args.command == "prune":
            backup = prune(home, context, report)
        else:
            require_clean(report)
            if args.command == "switch":
                provider = args.provider or str(context["target"]["provider"])
                if getattr(args, "skip_live", False):
                    skip = live_rollouts(context)
                backup = apply_changes(
                    home, context, provider, args.model, True, "switch", skip, args.deep
                )
            else:
                backup = apply_changes(home, context, None, None, True, "repair")
    after, _ = audit(home, args.verbose, profile)
    require_clean(after)
    output = compact_report(after) if args.compact else after
    print(
        json.dumps(
            {
                "backup": str(backup) if backup else None,
                "deferred_live_sessions": sorted(skip),
                "audit": output,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, sqlite3.Error, ValueError) as exc:
        die(f"{type(exc).__name__}: {exc}")
