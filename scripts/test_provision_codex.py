#!/usr/bin/env python3
"""Self-test for provision_codex.py against throwaway Codex homes. No network, no real keys."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "provision_codex.py"
FAKE_KEY = '{"OPENAI_API_KEY": "placeholder-not-a-real-key"}\n'


def run(args: list[str], expect_ok: bool = True) -> str:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True, timeout=300
    )
    if expect_ok and proc.returncode != 0:
        raise AssertionError(f"expected success from {args}:\n{proc.stdout}\n{proc.stderr}")
    if not expect_ok and proc.returncode == 0:
        raise AssertionError(f"expected failure from {args}:\n{proc.stdout}")
    return proc.stdout + proc.stderr


def write_spec(root: Path, home: Path, *, shared: str = "shared", with_key: bool = True,
               official: bool = True, permissions: bool = True, link_home: bool = False) -> Path:
    keydir = root / "keys" / "relay"
    keydir.mkdir(parents=True, exist_ok=True)
    keyfile = keydir / "auth.json"
    if with_key:
        keyfile.write_text(FAKE_KEY)
        os.chmod(keyfile, 0o600)
    lines = [
        f'codex_home = "{home}"',
        f'shared_provider_id = "{shared}"',
        f'bashrc = "{root / "bashrc"}"',
        # Tests must never touch the real $HOME/.codex.
        f"link_home = {'true' if link_home else 'false'}",
    ]
    if permissions:
        lines += ['approval_policy = "never"', 'sandbox_mode = "danger-full-access"']
    if official:
        lines += ["", "[official]", 'model = "gpt-5.6-sol"']
    lines += [
        "",
        "[[providers]]",
        'id = "relay"',
        'name = "relay-label"',
        'base_url = "https://relay.example.com/v1"',
        'env_key = "RELAY_KEY"',
        f'key_file = "{keyfile}"',
        'model = "gpt-5.6-sol"',
        "",
        "[[providers]]",
        'id = "gateway"',
        'base_url = "https://gateway.example.net"',
    ]
    spec = root / "spec.toml"
    spec.write_text("\n".join(lines) + "\n")
    return spec


def fake_home(root: Path) -> Path:
    home = root / "codexhome"
    (home / "sessions").mkdir(parents=True, exist_ok=True)
    (home / "config.toml").write_text(
        'model = "gpt-5.5"\nmodel_provider = "openai"\n\n[projects."/somewhere"]\n'
        'trust_level = "trusted"\n'
    )
    return home


def check_plan_is_readonly(root: Path) -> None:
    home = fake_home(root)
    spec = write_spec(root, home)
    before = {p: p.read_bytes() for p in home.rglob("*") if p.is_file()}
    out = run(["plan", "--spec", str(spec)])
    after = {p: p.read_bytes() for p in home.rglob("*") if p.is_file()}
    assert before == after, "plan mutated files"
    assert not (root / "bashrc").exists(), "plan created bashrc"
    for expected in ("relay.config.toml", "gateway.config.toml", "config.toml", "migrate"):
        assert expected in out, f"plan omitted {expected}:\n{out}"
    print("  plan is read-only and complete")


def check_fresh_home_created(root: Path) -> None:
    """A reviewed apply can provision a configured Codex home from zero."""
    home = root / "fresh-codex-home"
    spec = write_spec(root, home, link_home=False)
    planned = run(["plan", "--spec", str(spec)])
    assert "mkdir" in planned and str(home) in planned, planned
    assert not home.exists(), "plan must not create the configured home"

    result = json.loads(
        run(["apply", "--spec", str(spec), "--migrator", "/nonexistent/x.py"])
    )
    assert home.is_dir() and (home.stat().st_mode & 0o777) == 0o700
    assert (home / "config.toml").is_file()
    assert (home / "relay.config.toml").is_file()
    assert any(item["action"] == "created directory (0700)" for item in result["applied"])
    print("  a missing configured Codex home is planned, created as 0700, and provisioned")


def check_non_directory_home_rejected(root: Path) -> None:
    home = root / "not-a-directory"
    home.write_text("leave me alone")
    spec = write_spec(root, home, link_home=False)
    planned = run(["plan", "--spec", str(spec)])
    assert "is not a directory" in planned, planned
    failed = run(
        ["apply", "--spec", str(spec), "--migrator", "/nonexistent/x.py"],
        expect_ok=False,
    )
    assert "configured Codex home is not a directory" in failed, failed
    assert home.read_text() == "leave me alone"
    print("  a non-directory Codex home is refused without touching it")


def check_apply(root: Path) -> None:
    home = fake_home(root)
    spec = write_spec(root, home)
    out = run(["apply", "--spec", str(spec), "--migrator", "/nonexistent/session_guard.py"])
    result = json.loads(out)

    relay = home / "relay.config.toml"
    with relay.open("rb") as fh:
        data = tomllib.load(fh)
    assert data["model_provider"] == "shared", data
    table = data["model_providers"]["shared"]
    assert table["base_url"] == "https://relay.example.com/v1", table
    assert table["env_key"] == "RELAY_KEY", table
    assert "placeholder" not in relay.read_text(), "key value leaked into profile config"

    with (home / "config.toml").open("rb") as fh:
        base = tomllib.load(fh)
    assert base["model_provider"] == "shared", base
    assert base["approval_policy"] == "never", base
    assert base["sandbox_mode"] == "danger-full-access", base
    assert base["model"] == "gpt-5.6-sol", base
    # Pre-existing table must survive, and the new root key must not fall inside it.
    assert base["projects"]["/somewhere"]["trust_level"] == "trusted", base
    assert "model_provider" not in base["projects"]["/somewhere"], "root key absorbed by [projects]"
    assert base["model_providers"]["shared"]["base_url"].startswith("https://chatgpt.com"), base

    rc = (root / "bashrc").read_text()
    assert "codex-relay()" in rc and "codex-gateway()" in rc, rc
    assert "RELAY_KEY=" in rc, rc
    assert "placeholder" not in rc, "key value leaked into bashrc"
    assert "CODEX_API_KEY" in rc, "bashrc should carry the CODEX_API_KEY warning comment"
    assert 'export RELAY_KEY' not in rc, "key must not be exported globally"

    assert result["migration"].get("skipped"), result["migration"]
    print("  apply writes profiles, base config, wrappers; no secrets leak")


def check_idempotent(root: Path) -> None:
    home = fake_home(root)
    spec = write_spec(root, home)
    run(["apply", "--spec", str(spec), "--migrator", "/nonexistent/x.py"])
    snapshot = {
        "relay": (home / "relay.config.toml").read_text(),
        "base": (home / "config.toml").read_text(),
        "rc": (root / "bashrc").read_text(),
    }
    second = json.loads(
        run(["apply", "--spec", str(spec), "--migrator", "/nonexistent/x.py"])
    )
    assert second["backup_dir"] is None, "no-op apply must not create an empty backup"
    assert (home / "relay.config.toml").read_text() == snapshot["relay"], "profile drifted"
    assert (home / "config.toml").read_text() == snapshot["base"], "base config drifted"
    rc = (root / "bashrc").read_text()
    assert rc == snapshot["rc"], "bashrc drifted"
    assert rc.count("codex-relay()") == 1, "wrapper duplicated on re-run"
    plan = run(["plan", "--spec", str(spec)])
    assert "0 change(s) to apply" in plan or "already correct" in plan, plan
    print("  re-running is idempotent; wrappers are not duplicated")


def check_template_has_safe_timeless_defaults(root: Path) -> None:
    del root
    template = HERE.parent / "assets" / "spec.example.toml"
    with template.open("rb") as stream:
        data = tomllib.load(stream)
    assert data["approval_policy"] == "on-request"
    assert data["sandbox_mode"] == "workspace-write"
    assert data["trusted_projects"] == []
    assert "model" not in data["official"]
    assert all("model" not in provider for provider in data["providers"])
    print("  template defaults are safe and do not pin a model version")


def check_reserved_id_rejected(root: Path) -> None:
    home = fake_home(root)
    spec = write_spec(root, home, shared="openai")
    out = run(["plan", "--spec", str(spec)], expect_ok=False)
    assert "reserved" in out, out
    print("  reserved provider id 'openai' is rejected")


def check_missing_key_is_a_gap(root: Path) -> None:
    home = fake_home(root)
    spec = write_spec(root, home, with_key=False)
    out = run(["plan", "--spec", str(spec)])
    assert "key file missing" in out, out
    # A missing key must not stop the rest of the work.
    applied = json.loads(run(["apply", "--spec", str(spec), "--migrator", "/nonexistent/x.py"]))
    assert any(g["what"].startswith("key file missing") for g in applied["gaps"]), applied
    assert (home / "relay.config.toml").is_file(), "missing key blocked unrelated work"
    print("  missing key file is reported as a gap, work continues")


def check_loose_key_mode_flagged(root: Path) -> None:
    home = fake_home(root)
    spec = write_spec(root, home)
    keyfile = root / "keys" / "relay" / "auth.json"
    os.chmod(keyfile, 0o644)
    out = run(["plan", "--spec", str(spec)])
    assert "world/group readable" in out, out
    print("  world-readable key file is flagged")


def check_unreadable_key_mode_flagged(root: Path) -> None:
    home = fake_home(root)
    spec = write_spec(root, home)
    keyfile = root / "keys" / "relay" / "auth.json"
    os.chmod(keyfile, 0o200)
    out = run(["plan", "--spec", str(spec)])
    assert "not owner-readable" in out, out
    print("  non-readable key file mode is flagged without opening it")


def check_key_contents_are_not_opened(root: Path) -> None:
    home = fake_home(root)
    spec = write_spec(root, home)
    keyfile = root / "keys" / "relay" / "auth.json"
    keyfile.write_text("opaque-to-the-provisioner\n")
    os.chmod(keyfile, 0o600)
    out = run(["plan", "--spec", str(spec)])
    assert "not readable JSON" not in out and "lacks OPENAI_API_KEY" not in out, out
    print("  credential contents are not opened during plan")


def check_codex_api_key_rejected(root: Path) -> None:
    home = fake_home(root)
    spec = root / "bad.toml"
    spec.write_text(
        f'codex_home = "{home}"\nbashrc = "{root / "bashrc"}"\n\n[[providers]]\n'
        'id = "x"\nbase_url = "https://x.example/v1"\nenv_key = "CODEX_API_KEY"\n'
        f'key_file = "{root / "k.json"}"\n'
    )
    out = run(["plan", "--spec", str(spec)], expect_ok=False)
    assert "CODEX_API_KEY" in out, out
    print("  env_key = CODEX_API_KEY is rejected")


def check_symlink_opt_out(root: Path) -> None:
    """link_home = false must produce no symlink change at all."""
    home = fake_home(root)
    spec = write_spec(root, home, link_home=False)
    out = run(["plan", "--spec", str(spec)])
    assert "symlink" not in out, f"link_home=false still planned a symlink:\n{out}"
    print("  link_home = false suppresses the $HOME/.codex symlink")


def check_shell_rc_alias(root: Path) -> None:
    home = fake_home(root)
    spec = write_spec(root, home)
    text = spec.read_text().replace(
        f'bashrc = "{root / "bashrc"}"', f'shell_rc = "{root / "zshrc"}"'
    )
    spec.write_text(text)
    run(["apply", "--spec", str(spec), "--migrator", "/nonexistent/x.py"])
    assert (root / "zshrc").is_file()
    assert "codex-relay()" in (root / "zshrc").read_text()
    assert not (root / "bashrc").exists()
    print("  shell_rc supports Bash/zsh startup files; legacy bashrc still works")


def check_symlink_never_stolen(root: Path) -> None:
    """An existing symlink pointing elsewhere must be refused, not repointed.

    Regression: an earlier version unlinked and repointed it, which clobbered the
    real $HOME/.codex during testing.
    """
    home = fake_home(root)
    decoy_target = root / "someone-elses-home"
    decoy_target.mkdir()
    link = root / "fakehome" / ".codex"
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(decoy_target)

    env = dict(os.environ)
    env["HOME"] = str(link.parent)
    spec = write_spec(root, home, link_home=True)
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "apply", "--spec", str(spec),
         "--migrator", "/nonexistent/x.py"],
        capture_output=True, text=True, timeout=300, env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert os.readlink(link) == str(decoy_target), (
        f"existing symlink was stolen: now -> {os.readlink(link)}"
    )
    assert "refused" in proc.stdout, proc.stdout
    print("  an existing $HOME/.codex symlink is refused, never repointed")


def check_stray_key_rejected(root: Path) -> None:
    """A root-level key written after [[providers]] lands inside it — must fail loudly.

    Regression: `extra` used to forward any unknown key straight into
    [model_providers.<id>], so a misplaced link_home ended up as provider config.
    """
    home = fake_home(root)
    spec = root / "stray.toml"
    spec.write_text(
        f'codex_home = "{home}"\nbashrc = "{root / "bashrc"}"\nlink_home = false\n\n'
        '[[providers]]\nid = "relay"\nbase_url = "https://relay.example.com/v1"\n'
        # This looks top-level but TOML puts it in the provider block.
        "link_home = false\n"
    )
    out = run(["plan", "--spec", str(spec)], expect_ok=False)
    assert "unrecognised key" in out and "link_home" in out, out

    misspelled = root / "typo.toml"
    misspelled.write_text(
        f'codex_home = "{home}"\nbashrc = "{root / "bashrc"}"\nlink_home = false\n'
        'sandbox_mod = "workspace-write"\n'
    )
    out = run(["plan", "--spec", str(misspelled)], expect_ok=False)
    assert "unknown top-level spec key" in out and "sandbox_mod" in out, out
    print("  stray/misspelled spec keys are rejected instead of becoming provider config")


def check_passthrough_table(root: Path) -> None:
    """http_headers is a legitimate sub-table and must render as one."""
    home = fake_home(root)
    spec = root / "hdr.toml"
    spec.write_text(
        f'codex_home = "{home}"\nbashrc = "{root / "bashrc"}"\nlink_home = false\n\n'
        '[[providers]]\nid = "relay"\nbase_url = "https://relay.example.com/v1"\n'
        "request_max_retries = 5\n\n"
        '[providers.http_headers]\n"X-Trace" = "on"\n'
    )
    run(["apply", "--spec", str(spec), "--migrator", "/nonexistent/x.py"])
    with (home / "relay.config.toml").open("rb") as fh:
        data = tomllib.load(fh)
    table = data["model_providers"]["shared"]
    assert table["request_max_retries"] == 5, table
    assert table["http_headers"] == {"X-Trace": "on"}, table
    # The sub-table must not have swallowed the inline keys.
    assert table["base_url"] == "https://relay.example.com/v1", table
    print("  passthrough scalars and sub-tables render as valid TOML")


def check_sensitive_provider_values_rejected(root: Path) -> None:
    """Literal credentials never enter plans, configs, output, or backups."""
    home = fake_home(root)
    spec = root / "literal-secret.toml"
    secret = "Bearer must-not-appear"
    spec.write_text(
        f'codex_home = "{home}"\nbashrc = "{root / "bashrc"}"\nlink_home = false\n\n'
        '[[providers]]\nid = "relay"\nbase_url = "https://relay.example/v1"\n\n'
        f'[providers.http_headers]\nAuthorization = "{secret}"\n'
    )
    out = run(["plan", "--spec", str(spec)], expect_ok=False)
    assert "literal sensitive header" in out, out
    assert secret not in out, "a rejected header value leaked into diagnostics"

    alternate_header = root / "alternate-header.toml"
    alternate_header.write_text(
        f'codex_home = "{home}"\nbashrc = "{root / "bashrc"}"\nlink_home = false\n\n'
        '[[providers]]\nid = "relay"\nbase_url = "https://relay.example/v1"\n\n'
        '[providers.http_headers]\n"X-Goog-Api-Key" = "must-not-appear"\n'
    )
    out = run(["plan", "--spec", str(alternate_header)], expect_ok=False)
    assert "literal sensitive header" in out and "must-not-appear" not in out, out

    url_secret = root / "url-secret.toml"
    url_secret.write_text(
        f'codex_home = "{home}"\nbashrc = "{root / "bashrc"}"\nlink_home = false\n\n'
        '[[providers]]\nid = "relay"\nbase_url = "https://user:must-not-appear@relay.example/v1"\n'
    )
    out = run(["plan", "--spec", str(url_secret)], expect_ok=False)
    assert "username/password" in out, out
    assert "must-not-appear" not in out, "URL credentials leaked into diagnostics"

    query_secret = root / "query-secret.toml"
    query_secret.write_text(
        f'codex_home = "{home}"\nbashrc = "{root / "bashrc"}"\nlink_home = false\n\n'
        '[[providers]]\nid = "relay"\n'
        'base_url = "https://relay.example/v1?client_secret=must-not-appear"\n'
    )
    out = run(["plan", "--spec", str(query_secret)], expect_ok=False)
    assert "credential-like query" in out and "must-not-appear" not in out, out
    print("  literal header, URL, and query credentials are rejected without echoing values")


def check_environment_headers_and_redacted_plan(root: Path) -> None:
    """Environment-backed secrets are allowed while JSON plans hide rendered content."""
    home = fake_home(root)
    spec = root / "env-header.toml"
    marker = "trace-value-not-for-plan-output"
    spec.write_text(
        f'codex_home = "{home}"\nbashrc = "{root / "bashrc"}"\nlink_home = false\n\n'
        '[[providers]]\nid = "relay"\nbase_url = "https://relay.example/v1"\n\n'
        f'[providers.http_headers]\n"X-Trace" = "{marker}"\n\n'
        '[providers.env_http_headers]\nAuthorization = "RELAY_AUTH_HEADER"\n'
    )
    planned = json.loads(run(["plan", "--json", "--spec", str(spec)]))
    assert marker not in json.dumps(planned), "rendered provider content leaked into JSON plan"
    assert all("content" not in change for change in planned["changes"]), planned
    assert any("content_sha256" in change for change in planned["changes"]), planned

    run(["apply", "--spec", str(spec), "--migrator", "/nonexistent/x.py"])
    with (home / "relay.config.toml").open("rb") as stream:
        profile = tomllib.load(stream)
    provider = profile["model_providers"]["shared"]
    assert provider["http_headers"] == {"X-Trace": marker}
    assert provider["env_http_headers"] == {"Authorization": "RELAY_AUTH_HEADER"}
    print("  env-backed sensitive headers work; JSON plans expose hashes, not content")


def main() -> int:
    checks = [
        check_plan_is_readonly,
        check_fresh_home_created,
        check_non_directory_home_rejected,
        check_apply,
        check_idempotent,
        check_template_has_safe_timeless_defaults,
        check_reserved_id_rejected,
        check_missing_key_is_a_gap,
        check_loose_key_mode_flagged,
        check_unreadable_key_mode_flagged,
        check_key_contents_are_not_opened,
        check_codex_api_key_rejected,
        check_symlink_opt_out,
        check_shell_rc_alias,
        check_symlink_never_stolen,
        check_stray_key_rejected,
        check_passthrough_table,
        check_sensitive_provider_values_rejected,
        check_environment_headers_and_redacted_plan,
    ]
    for check in checks:
        with tempfile.TemporaryDirectory() as tmp:
            check(Path(tmp))
    print("provision_codex self-test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
