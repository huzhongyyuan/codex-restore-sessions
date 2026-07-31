#!/usr/bin/env python3
"""Small end-to-end check for session_guard.py."""

import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).with_name("session_guard.py")


def run(home: Path, *args: str) -> dict:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--codex-home", str(home), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def run_fail(home: Path, *args: str) -> str:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--codex-home", str(home), *args],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    return result.stderr


def rollout(path: Path, thread_id: str, provider: str) -> None:
    path.parent.mkdir(parents=True)
    first = {"type": "session_meta", "payload": {"id": thread_id, "model_provider": provider}}
    path.write_text(json.dumps(first) + "\n" + json.dumps({"type": "event_msg"}) + "\n")


def main() -> None:
    with tempfile.TemporaryDirectory() as raw:
        home = Path(raw)
        active = home / "sessions/2026/01/01/rollout-active.jsonl"
        archived = home / "archived_sessions/rollout-archived.jsonl"
        rollout(active, "active", "old")
        rollout(archived, "archived", "old")
        (home / "config.toml").write_text(
            'model_provider = "new"\nmodel = "new-model"\n'
            'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
            '[model_providers.new]\nbase_url = "https://relay-a.example/v1"\n'
        )
        (home / "session_index.jsonl").write_text(
            json.dumps({"id": "active", "thread_name": "manual name"}) + "\n"
        )
        db = sqlite3.connect(home / "state_5.sqlite")
        db.execute(
            """create table threads(
            id text primary key, rollout_path text not null, archived integer not null,
            archived_at integer, model_provider text not null, model text, name text,
            title text not null, first_user_message text not null, preview text not null)"""
        )
        db.executemany(
            "insert into threads values(?,?,?,?,?,?,?,?,?,?)",
            [
                ("active", str(active), 0, None, "old", "old-model", "", "manual name", "hello", "hello"),
                ("archived", str(archived), 1, 123, "old", "old-model", None, "archived", "archived", "archived"),
            ],
        )
        db.commit()
        db.close()

        initial = run(home, "audit")
        assert initial["archived"] == 1
        assert initial["active_visible_estimate"] == 1
        compact = run(home, "--compact", "audit")
        assert compact["problems"] == {}
        assert compact["rename_candidate_count"] == 1
        assert "ambiguous_renames" not in compact
        switched = run(home, "switch")
        backup = Path(switched["backup"])
        rows = sqlite3.connect(home / "state_5.sqlite").execute(
            "select id, archived, archived_at, model_provider, model, name from threads order by id"
        ).fetchall()
        assert rows == [
            ("active", 0, None, "new", "old-model", "manual name"),
            ("archived", 1, 123, "new", "old-model", None),
        ]
        assert json.loads(active.read_text().splitlines()[0])["payload"]["model_provider"] == "new"
        assert sum(path.stat().st_size for path in backup.iterdir()) < 1024 * 1024
        assert backup.stat().st_mode & 0o777 == 0o700
        assert (backup / "state.sqlite").stat().st_mode & 0o777 == 0o600

        (home / "config.toml").write_text(
            (home / "config.toml").read_text().replace("relay-a.example", "relay-b.example")
        )
        assert "configuration changed" in run_fail(home, "rollback", str(backup))
        (home / "config.toml").write_text(
            (home / "config.toml").read_text().replace("relay-b.example", "relay-a.example")
        )
        manifest_path = backup / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["status"] = "applying"  # Simulate a crash after the data commit.
        manifest_path.write_text(json.dumps(manifest))
        (home / "session_guard_state.json").unlink()
        run(home, "rollback", str(backup))
        rows = sqlite3.connect(home / "state_5.sqlite").execute(
            "select id, archived, archived_at, model_provider, model, name from threads order by id"
        ).fetchall()
        assert rows == [
            ("active", 0, None, "old", "old-model", ""),
            ("archived", 1, 123, "old", "old-model", None),
        ]
        assert json.loads(active.read_text().splitlines()[0])["payload"]["model_provider"] == "old"

        # A same-provider relay change still updates the non-secret fingerprint.
        provider_backup = Path(run(home, "switch")["backup"])
        (home / "config.toml").write_text(
            (home / "config.toml").read_text().replace("relay-a.example", "relay-b.example")
        )
        assert run(home, "audit")["provider_or_relay_changed"] is True
        relay_backup = Path(run(home, "switch")["backup"])
        assert run(home, "audit")["provider_or_relay_changed"] is False
        run(home, "rollback", str(relay_backup))
        assert run(home, "audit")["provider_or_relay_changed"] is True

        # A copied/tampered manifest cannot target a rollout outside this Codex home.
        (home / "config.toml").write_text(
            (home / "config.toml").read_text().replace("relay-b.example", "relay-a.example")
        )
        tampered = home / "backups/session-guard-tampered"
        shutil.copytree(provider_backup, tampered)
        tampered_manifest = json.loads((tampered / "manifest.json").read_text())
        tampered_manifest["file_changes"][0]["path"] = str(home.parent / "outside.jsonl")
        (tampered / "manifest.json").write_text(json.dumps(tampered_manifest))
        assert "invalid rollout path" in run_fail(home, "rollback", str(tampered))
    print("session_guard self-test passed")


if __name__ == "__main__":
    main()
