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


def config_target(home: Path) -> dict[str, object]:
    path = home / "config.toml"
    data = tomllib.loads(path.read_text()) if path.exists() else {}
    if not isinstance(data, dict):
        die("config.toml root must be a table")
    profile_name = data.get("profile")
    profile = {}
    if profile_name is not None:
        profiles = data.get("profiles", {})
        if not isinstance(profiles, dict) or not isinstance(profiles.get(profile_name), dict):
            die(f"Selected profile is missing or invalid: {profile_name}")
        profile = profiles[profile_name]
    provider = profile.get("model_provider") or data.get("model_provider") or "openai"
    model = profile.get("model") or data.get("model")
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
        "provider_inferred": "model_provider" not in profile and "model_provider" not in data,
        "profile": profile_name,
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


def audit(home: Path, verbose: bool = False) -> tuple[dict[str, object], dict[str, object]]:
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

    target = config_target(home)
    state_path = home / STATE_FILE
    previous = {}
    if state_path.exists():
        try:
            previous = json.loads(state_path.read_text())
        except json.JSONDecodeError:
            previous = {"invalid": True}
        if not isinstance(previous, dict):
            previous = {"invalid": True}
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
        "provider_or_relay_changed": previous.get("fingerprint") != target["fingerprint"],
        "previous_fingerprint_known": bool(previous.get("fingerprint")),
    }
    context = {
        "db": db,
        "columns": columns,
        "rows": rows,
        "metadata": metadata,
        "target": target,
        "rename_candidates": candidates,
        "previous_state": previous,
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
            for key in ("provider", "profile", "model", "approval_policy", "sandbox_mode")
        },
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


def apply_changes(
    home: Path,
    context: dict[str, object],
    provider: str | None,
    model: str | None,
    do_renames: bool,
    operation: str,
) -> Path | None:
    require_mutation_schema(context)
    rows: list[dict[str, object]] = context["rows"]
    candidates = {item["id"]: item["name"] for item in context["rename_candidates"]} if do_renames else {}
    row_changes = []
    for row in rows:
        after = {
            "model_provider": provider if provider is not None else row.get("model_provider"),
            "model": model if model is not None else row.get("model"),
            "name": candidates.get(row["id"], row.get("name")),
        }
        before = {key: row.get(key) for key in after}
        if before != after:
            row_changes.append({"id": row["id"], "before": before, "after": after})

    file_changes = []
    if provider is not None:
        for path_string, (line, record, audit_stat) in context["metadata"].items():
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
    state = {
        "fingerprint": applied_fingerprint,
        "provider": provider or context["target"]["provider"],
        "model": model or context["target"]["model"],
        "applied_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    state_bytes = (json.dumps(state, ensure_ascii=False, indent=2) + "\n").encode()
    state_needs_change = (
        operation == "switch"
        and context["previous_state"].get("fingerprint") != applied_fingerprint
    )
    if not row_changes and not file_changes and not state_needs_change:
        return None

    backup, manifest = create_backup(
        home,
        context,
        row_changes,
        file_changes,
        operation,
        state_bytes if operation == "switch" else None,
    )
    manifest["status"] = "applying"
    write_json(backup / "manifest.json", manifest)
    con = sqlite3.connect(context["db"], timeout=5)
    changed_files: list[dict[str, object]] = []
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
        verify_protected_fields(con, rows, context["columns"])
        if con.execute("pragma integrity_check").fetchone()[0] != "ok":
            die("Post-update database integrity_check failed")
        con.commit()
    except BaseException:
        con.rollback()
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
        current_fingerprint = config_target(home)["fingerprint"]
        if current_fingerprint != manifest.get("config_fingerprint_after"):
            die("Refusing rollback because effective provider/relay configuration changed")

    report, context = audit(home)
    require_clean(report, backup)
    valid_paths = set(context["metadata"])
    for change in manifest.get("file_changes", []):
        path = Path(change.get("path", "")).resolve()
        if (
            str(path) not in valid_paths
            or not path.is_relative_to(home / "sessions")
            and not path.is_relative_to(home / "archived_sessions")
        ):
            die(f"Manifest contains an invalid rollout path: {path}")
        for side in ("before", "after"):
            line = base64.b64decode(change[side]["line_b64"])
            if sha256(line) != change[side]["sha256"]:
                die(f"Manifest first-line hash mismatch for {path}")

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
        verify_protected_fields(con, context["rows"], context["columns"])
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codex-home")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--compact", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("audit")
    switch = sub.add_parser("switch")
    switch.add_argument("--provider")
    switch.add_argument("--model", help="Explicitly rewrite historical thread model metadata")
    sub.add_parser("repair")
    rollback_parser = sub.add_parser("rollback")
    rollback_parser.add_argument("backup")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    home = resolve_home(args.codex_home)
    if args.command == "rollback":
        with mutation_lock(home):
            rollback(home, Path(args.backup).resolve())
        report, _ = audit(home, args.verbose)
        output = compact_report(report) if args.compact else report
        print(json.dumps({"rolled_back": args.backup, "audit": output}, ensure_ascii=False, indent=2))
        return

    if args.command == "audit":
        report, _ = audit(home, args.verbose)
        print(json.dumps(compact_report(report) if args.compact else report, ensure_ascii=False, indent=2))
        return
    with mutation_lock(home):
        report, context = audit(home, args.verbose)
        require_clean(report)
        if args.command == "switch":
            provider = args.provider or str(context["target"]["provider"])
            backup = apply_changes(home, context, provider, args.model, True, "switch")
        else:
            backup = apply_changes(home, context, None, None, True, "repair")
    after, _ = audit(home, args.verbose)
    require_clean(after)
    output = compact_report(after) if args.compact else after
    print(json.dumps({"backup": str(backup) if backup else None, "audit": output}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, sqlite3.Error, ValueError) as exc:
        die(f"{type(exc).__name__}: {exc}")
