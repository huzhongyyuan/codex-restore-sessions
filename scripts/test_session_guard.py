#!/usr/bin/env python3
"""Small end-to-end check for session_guard.py."""

import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

SCRIPT = Path(__file__).with_name("session_guard.py")


def run(home: Path, *args: str) -> dict:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--codex-home", str(home), *args],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"session_guard failed for {args}:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
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
    path.parent.mkdir(parents=True, exist_ok=True)
    first = {"type": "session_meta", "payload": {"id": thread_id, "model_provider": provider}}
    path.write_text(json.dumps(first) + "\n" + json.dumps({"type": "event_msg"}) + "\n")


def main() -> None:
    with tempfile.TemporaryDirectory() as raw:
        empty_home = Path(raw)
        empty = run(empty_home, "doctor")
        assert empty["health"] == "empty", empty
        orphan = empty_home / "sessions/2026/01/01/rollout-orphan.jsonl"
        rollout(orphan, "orphan", "openai")
        blocked = run(empty_home, "doctor")
        assert blocked["health"] == "blocked", blocked
        assert blocked["rollout_files_found"] == 1

    with tempfile.TemporaryDirectory() as raw:
        missing = Path(raw) / "not-created"
        capabilities = run(missing, "capabilities")
        assert capabilities["minimum_python"] == "3.9"
        assert capabilities["codex_home_exists"] is False
        assert "plan" in capabilities["commands"]

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
        diagnosed = run(home, "doctor")
        assert diagnosed["read_only"] is True
        assert diagnosed["health"] == "action-recommended", diagnosed
        assert diagnosed["recommendations"][0]["action"] == "restore"
        assert diagnosed["recommendations"][0]["command"][-1] == "restore"
        assert "Invalid provider id" in run_fail(
            home, "restore", "--provider", "../invalid"
        )
        assert not (home / "backups").exists(), "invalid input must fail before locking"
        planned = run(home, "plan")
        assert planned["safe_to_apply"] is True, planned
        assert planned["changes"]["database_provider_rows"] == 2
        assert planned["changes"]["rollout_files"] == 2
        assert planned["changes"]["rename_rows"] == 1
        assert not (home / "backups").exists(), "plan must remain read-only"
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
        assert run(home, "doctor")["health"] == "healthy"

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
    check_profiles()
    check_prune()
    check_skip_live()
    check_deep_switch()
    check_unify()
    check_migration()
    print("session_guard self-test passed")


def check_profiles() -> None:
    """A file profile overlays the base config the way `codex -p <name>` does."""
    with tempfile.TemporaryDirectory() as raw:
        home = Path(raw)
        active = home / "sessions/2026/01/01/rollout-active.jsonl"
        rollout(active, "active", "openai")
        (home / "config.toml").write_text(
            'model_provider = "openai"\nmodel = "base-model"\n'
            '[model_providers.openai]\nname = "openai"\n'
            'base_url = "https://api.openai.com/v1"\nwire_api = "responses"\n'
            'requires_openai_auth = true\n'
            '[model_providers.gw]\nname = "gw"\n'
            'base_url = "https://gateway.example/v1"\nwire_api = "responses"\n'
        )
        # Overriding only base_url must inherit wire_api from the base table.
        (home / "relay.config.toml").write_text(
            'model_provider = "openai"\n[model_providers.openai]\n'
            'base_url = "https://relay.example/v1"\n'
        )
        (home / "gw.config.toml").write_text('model_provider = "gw"\n')
        make_db(home, [("active", str(active), 0, None, "openai", "base-model", "", "t", "u", "p")])

        base = run(home, "audit")
        assert base["target"]["profile"] is None
        assert set(base["available_profiles"]) == {"relay", "gw"}
        gw = run(home, "--profile", "gw", "audit")
        assert gw["target"]["provider"] == "gw", gw["target"]
        assert gw["target"]["profile_kind"] == "file"
        assert gw["target"]["model"] == "base-model", "profile must inherit base model"
        relay = run(home, "--profile", "relay", "audit")
        assert relay["target"]["provider"] == "openai"
        assert relay["target"]["fingerprint"] != base["target"]["fingerprint"], (
            "a relay-only change must alter the fingerprint"
        )
        assert "not found" in run_fail(home, "--profile", "missing", "audit")
        assert "Invalid profile name" in run_fail(home, "--profile", "../escape", "audit")

        # Each profile tracks its own fingerprint, so switching back and forth
        # never makes an already-synced profile look changed.
        run(home, "--profile", "gw", "switch")
        assert run(home, "--profile", "gw", "audit")["provider_or_relay_changed"] is False
        assert run(home, "--profile", "relay", "audit")["provider_or_relay_changed"] is True
        run(home, "--profile", "relay", "switch")
        assert run(home, "--profile", "gw", "audit")["provider_or_relay_changed"] is False
        assert run(home, "--profile", "relay", "audit")["provider_or_relay_changed"] is False
        state = json.loads((home / "session_guard_state.json").read_text())
        assert set(state["profiles"]) == {"gw", "relay"}


def check_prune() -> None:
    """Rows pointing at deleted rollout files are removable and restorable."""
    with tempfile.TemporaryDirectory() as raw:
        home = Path(raw)
        kept = home / "sessions/2026/01/01/rollout-kept.jsonl"
        gone = home / "sessions/2026/01/01/rollout-gone.jsonl"
        rollout(kept, "kept", "openai")
        rollout(gone, "gone", "openai")
        (home / "config.toml").write_text('model_provider = "openai"\n')
        make_db(
            home,
            [
                ("kept", str(kept), 0, None, "openai", "m", "", "t", "u", "p"),
                ("gone", str(gone), 0, None, "openai", "m", "", "t", "u", "p"),
            ],
        )
        gone.unlink()

        assert run(home, "--compact", "audit")["problems"] == {"stale_database_paths": 1}
        diagnosis = run(home, "doctor")
        assert diagnosis["health"] == "blocked"
        assert diagnosis["recommendations"][0]["action"] == "review-and-prune"
        assert diagnosis["recommendations"][0]["requires_confirmation"] is True
        planned = run(home, "plan")
        assert planned["safe_to_apply"] is False
        assert "audit:stale_database_paths=1" in planned["blockers"]
        # Stale rows block every other mutating mode until they are pruned.
        assert "Refusing mutation" in run_fail(home, "switch")
        pruned = run(home, "--compact", "prune")
        assert pruned["audit"]["problems"] == {}
        assert pruned["audit"]["threads"] == 1
        ids = [
            row[0]
            for row in sqlite3.connect(home / "state_5.sqlite")
            .execute("select id from threads")
            .fetchall()
        ]
        assert ids == ["kept"]
        assert run(home, "--compact", "switch")["audit"]["problems"] == {}

        # Rolling back a prune restores the row verbatim.
        run(home, "rollback", pruned["backup"])
        restored = sqlite3.connect(home / "state_5.sqlite").execute(
            "select id, rollout_path, archived, model_provider from threads order by id"
        ).fetchall()
        assert restored == [
            ("gone", str(gone), 0, "openai"),
            ("kept", str(kept), 0, "openai"),
        ], restored

        # A row whose file still exists is never pruned.
        assert run(home, "--compact", "prune")["audit"]["threads"] == 1


def check_skip_live() -> None:
    """A rollout file that keeps growing is deferred, not silently rewritten."""
    with tempfile.TemporaryDirectory() as raw:
        home = Path(raw)
        idle = home / "sessions/2026/01/01/rollout-idle.jsonl"
        busy = home / "sessions/2026/01/01/rollout-busy.jsonl"
        rollout(idle, "idle", "openai")
        rollout(busy, "busy", "openai")
        (home / "config.toml").write_text('model_provider = "shared"\n')
        make_db(
            home,
            [
                ("idle", str(idle), 0, None, "openai", "m", "", "t", "u", "p"),
                ("busy", str(busy), 0, None, "openai", "m", "", "t", "u", "p"),
            ],
        )

        # A continuously-appending writer stands in for a live Codex session.
        appender = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import sys,time\n"
                "p=sys.argv[1]\n"
                "end=time.time()+25\n"
                "while time.time()<end:\n"
                "    open(p,'a').write('{\"type\":\"event_msg\"}\\n')\n"
                "    time.sleep(0.05)\n",
                str(busy),
            ]
        )
        try:
            result = run(home, "--compact", "restore", "--provider", "shared")
        finally:
            appender.terminate()
            appender.wait()

        assert result["deferred_live_sessions"] == [str(busy.resolve())], result[
            "deferred_live_sessions"
        ]
        rows = dict(
            sqlite3.connect(home / "state_5.sqlite")
            .execute("select id, model_provider from threads")
            .fetchall()
        )
        # The idle session migrated; the live one kept its old provider untouched.
        assert rows == {"idle": "shared", "busy": "openai"}, rows
        assert json.loads(idle.read_text().splitlines()[0])["payload"]["model_provider"] == "shared"
        assert json.loads(busy.read_text().splitlines()[0])["payload"]["model_provider"] == "openai"
        # The deferral is recorded so a rerun is not mistaken for a no-op.
        state = json.loads((home / "session_guard_state.json").read_text())
        assert state.get("deferred_live_sessions") == 1, state

        # Once the writer is gone the rerun finishes the job.
        finished = run(home, "--compact", "restore", "--provider", "shared")
        assert finished["deferred_live_sessions"] == []
        rows = dict(
            sqlite3.connect(home / "state_5.sqlite")
            .execute("select id, model_provider from threads")
            .fetchall()
        )
        assert rows == {"idle": "shared", "busy": "shared"}, rows


def deep_rollout(path: Path, thread_id: str, provider: str, extra_meta: bool = True) -> list[str]:
    """A rollout shaped like a real one: repeated session_meta plus thread_settings.

    Returns the exact lines written so a test can assert byte-level preservation of
    everything the migration is not supposed to touch.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps({"type": "session_meta", "payload": {"id": thread_id, "model_provider": provider}}),
        json.dumps({"type": "event_msg", "payload": {"type": "user_message", "message": "你好 ünïcode"}}),
        json.dumps(
            {
                "type": "event_msg",
                "payload": {
                    "type": "thread_settings_applied",
                    "thread_settings": {"model_provider_id": provider, "service_tier": "flex"},
                },
            }
        ),
        json.dumps({"type": "response_item", "payload": {"text": "model_provider mentioned in prose"}}),
        json.dumps(
            {
                "type": "event_msg",
                "payload": {
                    "type": "thread_settings_applied",
                    "thread_settings": {"model_provider_id": provider},
                },
            }
        ),
    ]
    if extra_meta:
        lines.insert(
            2,
            json.dumps({"type": "session_meta", "payload": {"id": thread_id, "model_provider": provider}}),
        )
    path.write_text("\n".join(lines) + "\n")
    return lines


def providers_in(path: Path) -> set:
    """Every provider value the file still names, from either recording site."""
    found = set()
    for line in path.read_text().splitlines():
        d = json.loads(line)
        payload = d.get("payload") or {}
        if d.get("type") == "session_meta":
            found.add(payload.get("model_provider"))
        settings = payload.get("thread_settings") or {}
        if "model_provider_id" in settings:
            found.add(settings["model_provider_id"])
    return found


def check_deep_switch() -> None:
    """`--deep` clears every provider site, preserves the rest, and rolls back."""
    with tempfile.TemporaryDirectory() as raw:
        home = Path(raw)
        one = home / "sessions/2026/01/01/rollout-one.jsonl"
        two = home / "archived_sessions/rollout-two.jsonl"
        deep_rollout(one, "one", "OpenAI")
        deep_rollout(two, "two", "openai", extra_meta=False)
        (home / "config.toml").write_text('model_provider = "shared"\n')
        make_db(
            home,
            [
                ("one", str(one), 0, None, "OpenAI", "m", "", "t", "u", "p"),
                ("two", str(two), 1, 5, "openai", "m", "", "t", "u", "p"),
            ],
        )
        before_one = one.read_text()

        planned = run(home, "plan", "--provider", "shared", "--deep")
        assert planned["safe_to_apply"] is True, planned
        assert planned["changes"]["rollout_files"] == 2
        assert planned["changes"]["rollout_records"] == 7

        # A plain switch only fixes the first line, so stale values survive and
        # reindexing would restore the old provider.
        run(home, "--compact", "switch", "--provider", "shared")
        assert providers_in(one) == {"shared", "OpenAI"}, providers_in(one)

        result = run(home, "--compact", "restore", "--provider", "shared", "--fail-live")
        assert providers_in(one) == {"shared"}, providers_in(one)
        assert providers_in(two) == {"shared"}, providers_in(two)

        # Non-provider content is untouched, including prose that merely mentions
        # the key and a non-ASCII message.
        after_lines = one.read_text().splitlines()
        assert json.loads(after_lines[1])["payload"]["message"] == "你好 ünïcode"
        assert "model_provider mentioned in prose" in one.read_text()
        assert len(after_lines) == len(before_one.splitlines())
        assert json.loads(after_lines[3])["payload"]["thread_settings"]["service_tier"] == "flex"

        # Rolling back restores every line the deep pass rewrote. The first lines stay
        # on "shared" because the earlier plain switch owns that change, not this backup.
        run(home, "rollback", result["backup"])
        assert providers_in(one) == {"shared", "OpenAI"}, providers_in(one)
        assert providers_in(two) == {"shared", "openai"}, providers_in(two)

        # Archive state survived the deep rewrite.
        rows = dict(
            sqlite3.connect(home / "state_5.sqlite")
            .execute("select id, archived from threads")
            .fetchall()
        )
        assert rows == {"one": 0, "two": 1}, rows


def check_unify() -> None:
    """`unify` rewrites every config to one id and migrates history in one step."""
    with tempfile.TemporaryDirectory() as raw:
        home = Path(raw)
        # Base config relies on the built-in `openai` provider and ends in a table,
        # so a naive append would bury model_provider inside [projects].
        (home / "config.toml").write_text(
            'model = "gpt-5.6-luna"\n\n[projects."/work"]\ntrust_level = "trusted"\n'
        )
        (home / "gw.config.toml").write_text(
            '# gateway\nmodel_provider = "gw"  # inline comment\n'
            'model = "gpt-5.6-luna"\n\n'
            "[model_providers.gw]\n"
            'name = "gateway"\n'
            'base_url = "https://gw.example"\n'
            'wire_api = "responses"\n'
            'env_key = "GW_KEY"\n'
        )
        (home / "relay.config.toml").write_text(
            'model_provider = "relay"\n\n[model_providers.relay]\n'
            'name = "relay"\nbase_url = "https://relay.example/v1"\n'
            'wire_api = "responses"\nenv_key = "RELAY_KEY"\n'
        )
        one = home / "sessions/2026/01/01/rollout-one.jsonl"
        deep_rollout(one, "one", "openai")
        make_db(home, [("one", str(one), 0, None, "openai", "m", "", "t", "u", "p")])

        result = run(home, "--compact", "unify", "--provider", "shared")
        assert result["provider"] == "shared"

        base = tomllib.loads((home / "config.toml").read_text())
        gw = tomllib.loads((home / "gw.config.toml").read_text())
        relay = tomllib.loads((home / "relay.config.toml").read_text())
        for name, cfg in (("base", base), ("gw", gw), ("relay", relay)):
            assert cfg["model_provider"] == "shared", (name, cfg.get("model_provider"))
            assert "shared" in cfg["model_providers"], name
        # [projects] must not have absorbed the new root key.
        assert base["projects"]["/work"] == {"trust_level": "trusted"}, base["projects"]
        # Each channel keeps its own endpoint and credential variable.
        assert gw["model_providers"]["shared"]["base_url"] == "https://gw.example"
        assert gw["model_providers"]["shared"]["env_key"] == "GW_KEY"
        assert relay["model_providers"]["shared"]["base_url"] == "https://relay.example/v1"
        assert relay["model_providers"]["shared"]["env_key"] == "RELAY_KEY"
        # The synthesized official provider keeps using auth.json.
        assert base["model_providers"]["shared"]["requires_openai_auth"] is True
        # Comments survive the line-level rewrite.
        assert "# inline comment" in (home / "gw.config.toml").read_text()
        assert "# gateway" in (home / "gw.config.toml").read_text()

        # History migrated deeply, not just the first line.
        assert providers_in(one) == {"shared"}, providers_in(one)
        assert result["audit"]["problems"] == {}
        assert result["audit"]["jsonl_providers"] == {"shared": 1}

        # Config backups are restorable.
        backup = Path(result["config_backup"])
        assert tomllib.loads((backup / "gw.config.toml").read_text())["model_provider"] == "gw"

        # Re-running is a no-op on the configs.
        again = run(home, "--compact", "unify", "--provider", "shared")
        assert all(not item["changed"] for item in again["configs"]), again["configs"]

        # The reserved built-in id is rejected rather than producing a broken config.
        assert "reserved" in run_fail(home, "unify", "--provider", "openai")


def check_migration() -> None:
    """A bundle round-trips into a fresh home and rejects unsafe destinations."""
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        source = root / "source"
        source.mkdir()
        active = source / "sessions/2026/01/01/rollout-active.jsonl"
        archived = source / "archived_sessions/rollout-archived.jsonl"
        rollout(active, "active", "openai")
        rollout(archived, "archived", "openai")
        (source / "config.toml").write_text(
            'model_provider = "openai"\n[model_providers.openai]\n'
            'base_url = "https://api.openai.com/v1"\n'
        )
        (source / "auth.json").write_text('{"OPENAI_API_KEY": "sk-must-not-travel"}')
        (source / "session_index.jsonl").write_text(
            json.dumps({"id": "active", "thread_name": "kept name"}) + "\n"
        )
        make_db(
            source,
            [
                ("active", str(active), 0, None, "openai", "m", "kept name", "t", "u", "p"),
                ("archived", str(archived), 1, 99, "openai", "m", None, "t", "u", "p"),
            ],
        )

        bundle = root / "bundle"

        nested_bundle = source / "sessions/exported-bundle"
        assert "outside" in run_fail(source, "export", str(nested_bundle)).lower()
        assert not nested_bundle.exists()

        # Export preflight rejects links and credential-like files before it
        # creates a destination or reads the linked target.
        outside = root / "outside-auth.json"
        outside.write_text('{"secret":"must-not-be-read"}')
        leak = source / "sessions/leaked-auth.json"
        leak.symlink_to(outside)
        rejected_link = root / "rejected-link-bundle"
        assert "symlink" in run_fail(source, "export", str(rejected_link)).lower()
        assert not rejected_link.exists()
        leak.unlink()

        token_file = source / "sessions/token.json"
        token_file.write_text('{"secret":"must-not-be-hashed"}')
        rejected_credential = root / "rejected-credential-bundle"
        assert "credential" in run_fail(source, "export", str(rejected_credential)).lower()
        assert not rejected_credential.exists()
        token_file.unlink()

        unreadable = source / "sessions/unreadable.bin"
        unreadable.write_bytes(b"not-a-credential")
        unreadable.chmod(0)
        failed_copy = root / "failed-copy-bundle"
        try:
            assert run_fail(source, "export", str(failed_copy))
        finally:
            unreadable.chmod(0o600)
            unreadable.unlink()
        assert not failed_copy.exists()
        assert not list(root.glob(f".{failed_copy.name}.session-guard-*")), (
            "failed export left a staging directory"
        )

        exported = run(source, "export", str(bundle))
        assert exported["threads"] == 2
        assert sorted(exported["included"]) == [
            "archived_sessions",
            "session_index.jsonl",
            "sessions",
        ]
        shipped = {str(p.relative_to(bundle)) for p in bundle.rglob("*") if p.is_file()}
        assert not any("auth.json" in name for name in shipped), shipped
        assert not any(name.endswith("config.toml") for name in shipped), shipped

        verified = verify_only(bundle)
        assert verified["bundle_threads"] == 2
        assert verified["manifest_threads"] == 2

        fake_bundle = root / "fake-bundle"
        fake_bundle.mkdir()
        (fake_bundle / "bundle.json").symlink_to(source / "auth.json")
        assert "not a session bundle" in run_fail(source, "verify", str(fake_bundle)).lower()

        # The destination authenticates with its own config, not the source's.
        dest = root / "dest"
        dest.mkdir()
        (dest / "config.toml").write_text(
            'model_provider = "gw"\n[model_providers.gw]\n'
            'base_url = "https://gateway.example/v1"\n'
        )
        result = run(dest, "--compact", "import", str(bundle))
        assert result["audit"]["problems"] == {}, result
        assert result["audit"]["threads"] == 2
        assert result["rebased_rows"] == 2, "absolute source paths must be rebased"
        rows = sqlite3.connect(dest / "state_5.sqlite").execute(
            "select id, rollout_path, archived, name from threads order by id"
        ).fetchall()
        assert rows[0][0] == "active" and rows[0][3] == "kept name"
        assert rows[1][0] == "archived" and rows[1][2] == 1, "archive state must survive"
        for _, path, _, _ in rows:
            assert Path(path).is_file() and Path(path).resolve().is_relative_to(dest.resolve()), path
        assert not (dest / "auth.json").exists()

        # Importing again would silently merge two histories.
        assert "already has session state" in run_fail(dest, "import", str(bundle))

        # Tampering with any shipped byte is caught before installation.
        third = root / "third"
        third.mkdir()
        (third / "config.toml").write_text('model_provider = "openai"\n')
        (bundle / "codex_home/session_index.jsonl").write_text("tampered\n")
        assert "digest mismatch" in run_fail(third, "import", str(bundle))


def verify_only(bundle: Path) -> dict:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "verify", str(bundle)],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def make_db(home: Path, rows: list[tuple]) -> None:
    db = sqlite3.connect(home / "state_5.sqlite")
    db.execute(
        """create table threads(
        id text primary key, rollout_path text not null, archived integer not null,
        archived_at integer, model_provider text not null, model text, name text,
        title text not null, first_user_message text not null, preview text not null)"""
    )
    db.executemany("insert into threads values(?,?,?,?,?,?,?,?,?,?)", rows)
    db.commit()
    db.close()


if __name__ == "__main__":
    main()
