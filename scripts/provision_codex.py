#!/usr/bin/env python3
"""Provision a host's Codex install from a spec: profiles, wrappers, shared id, permissions.

plan   describe every intended change, mutate nothing
apply  perform exactly what plan listed
verify re-derive state from the real codex binary, non-zero on drift

Never handles secret values. Key files are checked for presence and mode only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9 and 3.10
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        sys.exit("Python 3.9+ is required; on Python 3.9/3.10 run `pip install tomli`.")

OFFICIAL_BASE_URL = "https://chatgpt.com/backend-api/codex"
RESERVED_PROVIDER_IDS = {"openai"}
BLOCK_START = "# >>> codex-provision-host (managed block; edits here are overwritten) >>>"
BLOCK_END = "# <<< codex-provision-host <<<"
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
APPROVAL_POLICIES = {"untrusted", "on-failure", "on-request", "never"}
SANDBOX_MODES = {"read-only", "workspace-write", "danger-full-access"}
SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxyauthorization",
    "xapikey",
    "apikey",
    "xauthtoken",
    "cookie",
    "setcookie",
}
SENSITIVE_QUERY_NAMES = {
    "apikey",
    "accesskey",
    "key",
    "token",
    "accesstoken",
    "auth",
    "authorization",
    "clientsecret",
    "credential",
    "password",
    "secret",
    "secretkey",
    "signature",
    "sig",
}

# Keys accepted inside [model_providers.<id>] beyond the ones we render directly.
# Anything else in a [[providers]] block is a typo, not config — fail loudly rather
# than writing it into a provider table where Codex would reject the whole file.
PROVIDER_PASSTHROUGH = {
    "query_params",
    "http_headers",
    "env_http_headers",
    "request_max_retries",
    "stream_max_retries",
    "stream_idle_timeout_ms",
}

# Recognised top-level spec keys, so a misplaced or misspelled one is caught.
SPEC_KEYS = {
    "codex_home",
    "shared_provider_id",
    "approval_policy",
    "sandbox_mode",
    "trusted_projects",
    "bashrc",
    "shell_rc",
    "link_home",
    "official",
    "providers",
}

# Profile-level Codex keys (siblings of `model`, outside any table) that a spec may
# carry verbatim into <id>.config.toml. Anything outside this set and the ones the
# renderer emits itself is treated as a typo.
PROFILE_PASSTHROUGH = {
    "approvals_reviewer",
    "service_tier",
    "approval_policy",
    "sandbox_mode",
    "model_supports_reasoning_summaries",
    "chatgpt_base_url",
    "disable_response_storage",
}


def die(message: str) -> "NoReturn":  # type: ignore[valid-type]
    sys.exit(f"error: {message}")


def expand(raw: str) -> Path:
    return Path(os.path.expanduser(raw)).resolve() if raw.startswith("~") else Path(raw)


def toml_string(value: str) -> str:
    """Quote a TOML basic string. Values here are ids/urls, never secrets."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def toml_value(value: object) -> str:
    """Render a scalar or flat list. Values here are config, never secrets."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(v) for v in value) + "]"
    return toml_string(str(value))


def toml_key(key: str) -> str:
    """Bare key when possible, quoted otherwise (e.g. "model.v1")."""
    return key if re.fullmatch(r"[A-Za-z0-9_-]+", key) and not key[0].isdigit() else toml_string(key)


def normalized_secret_name(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def sensitive_header_name(value: object) -> bool:
    normalized = normalized_secret_name(value)
    return (
        normalized in SENSITIVE_HEADER_NAMES
        or "authorization" in normalized
        or "apikey" in normalized
        or normalized.endswith(("auth", "token", "secret", "cookie", "signature"))
    )


def sensitive_query_name(value: object) -> bool:
    normalized = normalized_secret_name(value)
    return (
        normalized in SENSITIVE_QUERY_NAMES
        or "apikey" in normalized
        or normalized.endswith(("token", "secret", "password", "credential", "signature"))
    )


def validate_public_provider_config(
    ident: str, base_url: str, extra: dict[str, object]
) -> None:
    """Reject literal credentials before they can enter plans, configs, or backups."""
    if base_url != base_url.strip() or any(character.isspace() for character in base_url):
        die(f"provider {ident}: base_url must not contain whitespace")
    try:
        parsed = urllib.parse.urlsplit(base_url)
    except ValueError:
        die(f"provider {ident}: base_url is malformed")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        die(f"provider {ident}: base_url must be a complete http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        die(f"provider {ident}: base_url must not contain username/password credentials")
    sensitive_url_keys = sorted(
        key
        for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if sensitive_query_name(key)
    )
    if sensitive_url_keys:
        die(
            f"provider {ident}: base_url contains credential-like query key(s) "
            f"{', '.join(sensitive_url_keys)}; inject secrets through environment variables"
        )

    literal_headers = extra.get("http_headers", {})
    if not isinstance(literal_headers, dict):
        die(f"provider {ident}: http_headers must be a TOML table")
    sensitive_headers = sorted(
        str(name)
        for name in literal_headers
        if sensitive_header_name(name)
    )
    if sensitive_headers:
        die(
            f"provider {ident}: literal sensitive header(s) {', '.join(sensitive_headers)} "
            "are forbidden; use env_http_headers so values stay out of specs and plans"
        )

    literal_query = extra.get("query_params", {})
    if not isinstance(literal_query, dict):
        die(f"provider {ident}: query_params must be a TOML table")
    sensitive_query = sorted(
        str(name)
        for name in literal_query
        if sensitive_query_name(name)
    )
    if sensitive_query:
        die(
            f"provider {ident}: literal credential-like query key(s) "
            f"{', '.join(sensitive_query)} are forbidden"
        )

    env_headers = extra.get("env_http_headers", {})
    if not isinstance(env_headers, dict):
        die(f"provider {ident}: env_http_headers must be a TOML table")
    invalid_env_names = sorted(
        str(value) for value in env_headers.values() if not ENV_KEY_RE.match(str(value))
    )
    if invalid_env_names:
        die(
            f"provider {ident}: env_http_headers values must be UPPER_SNAKE_CASE "
            "environment variable names"
        )


def render_table(header: str, body: dict[str, object]) -> list[str]:
    """One [header] block; nested dicts become [header.child] blocks after it."""
    lines = ["", f"[{header}]"]
    nested: list[str] = []
    for key, value in body.items():
        if isinstance(value, dict):
            nested.extend(render_table(f"{header}.{key}", value))
        else:
            lines.append(f"{toml_key(key)} = {toml_value(value)}")
    return lines + nested


@dataclass
class Provider:
    ident: str
    base_url: str
    name: str = ""
    wire_api: str = "responses"
    env_key: str = ""
    key_file: Path | None = None
    key_json_field: str = "OPENAI_API_KEY"
    model: str = ""
    model_reasoning_effort: str = ""
    model_verbosity: str = ""
    requires_openai_auth: bool = True
    extra: dict[str, object] = field(default_factory=dict)
    profile_extra: dict[str, object] = field(default_factory=dict)
    tables: dict[str, object] = field(default_factory=dict)


@dataclass
class Spec:
    codex_home: Path
    shared_provider_id: str
    providers: list[Provider]
    approval_policy: str = ""
    sandbox_mode: str = ""
    trusted_projects: list[Path] = field(default_factory=list)
    official: dict[str, object] = field(default_factory=dict)
    manage_official: bool = True
    bashrc: Path = field(default_factory=lambda: Path.home() / ".bashrc")
    link_home: bool = True


def load_spec(path: Path) -> Spec:
    if not path.is_file():
        die(f"spec not found: {path}")
    with path.open("rb") as stream:
        raw = tomllib.load(stream)

    unknown = sorted(set(raw) - SPEC_KEYS)
    if unknown:
        die(
            f"unknown top-level spec key(s): {', '.join(unknown)}. "
            "A root-level key written after a [[providers]] block belongs to that block in TOML — "
            "move it above the first [table]."
        )

    shared = str(raw.get("shared_provider_id", "shared"))
    if shared in RESERVED_PROVIDER_IDS:
        die(f"shared_provider_id {shared!r} is reserved by Codex and cannot be overridden")
    if not ID_RE.match(shared):
        die(f"shared_provider_id {shared!r} is not a valid TOML bare key")

    home_raw = str(raw.get("codex_home") or os.environ.get("CODEX_HOME") or "~/.codex")
    codex_home = expand(home_raw)

    approval = str(raw.get("approval_policy", ""))
    if approval and approval not in APPROVAL_POLICIES:
        die(f"approval_policy {approval!r} must be one of {sorted(APPROVAL_POLICIES)}")
    sandbox = str(raw.get("sandbox_mode", ""))
    if sandbox and sandbox not in SANDBOX_MODES:
        die(f"sandbox_mode {sandbox!r} must be one of {sorted(SANDBOX_MODES)}")

    providers: list[Provider] = []
    seen: set[str] = set()
    for entry in raw.get("providers") or []:
        ident = str(entry.get("id") or "")
        if not ID_RE.match(ident):
            die(f"provider id {ident!r} is not a valid profile name")
        if ident in RESERVED_PROVIDER_IDS:
            die(f"provider id {ident!r} is reserved by Codex")
        if ident in seen:
            die(f"duplicate provider id {ident!r}")
        seen.add(ident)
        base_url = str(entry.get("base_url") or "")
        if not base_url.startswith(("http://", "https://")):
            die(f"provider {ident}: base_url must be an http(s) URL")
        env_key = str(entry.get("env_key") or "")
        if env_key and not ENV_KEY_RE.match(env_key):
            die(f"provider {ident}: env_key {env_key!r} must be UPPER_SNAKE_CASE")
        if env_key == "CODEX_API_KEY":
            die(
                f"provider {ident}: env_key must not be CODEX_API_KEY — Codex treats it as the "
                "official key and 401s the default provider"
            )
        key_file = expand(str(entry["key_file"])) if entry.get("key_file") else None
        if env_key and key_file is None:
            die(f"provider {ident}: env_key set but no key_file to read it from")
        known = {
            "id", "base_url", "name", "wire_api", "env_key", "key_file", "key_json_field",
            "model", "model_reasoning_effort", "model_verbosity", "requires_openai_auth",
        }
        stray = sorted(
            set(entry) - known - PROVIDER_PASSTHROUGH - PROFILE_PASSTHROUGH - {"tables"}
        )
        if stray:
            die(
                f"provider {ident}: unrecognised key(s) {', '.join(stray)}. "
                "In TOML a root-level key placed after [[providers]] becomes part of that block — "
                "if one of these is meant to be a top-level spec key, move it above the first "
                f"[table]. Provider-table keys: {', '.join(sorted(PROVIDER_PASSTHROUGH))}. "
                f"Profile-level keys: {', '.join(sorted(PROFILE_PASSTHROUGH))}. "
                "Use a [providers.tables.<name>] block for anything else."
            )
        tables = entry.get("tables") or {}
        if not isinstance(tables, dict):
            die(f"provider {ident}: `tables` must be a table of tables")
        extra = {k: v for k, v in entry.items() if k in PROVIDER_PASSTHROUGH}
        validate_public_provider_config(ident, base_url, extra)
        providers.append(
            Provider(
                ident=ident,
                base_url=base_url,
                name=str(entry.get("name") or ident),
                wire_api=str(entry.get("wire_api") or "responses"),
                env_key=env_key,
                key_file=key_file,
                key_json_field=str(entry.get("key_json_field") or "OPENAI_API_KEY"),
                model=str(entry.get("model") or ""),
                model_reasoning_effort=str(entry.get("model_reasoning_effort") or ""),
                model_verbosity=str(entry.get("model_verbosity") or ""),
                requires_openai_auth=bool(entry.get("requires_openai_auth", True)),
                extra=extra,
                profile_extra={k: v for k, v in entry.items() if k in PROFILE_PASSTHROUGH},
                tables=dict(tables),
            )
        )

    if raw.get("bashrc") and raw.get("shell_rc"):
        die("use only one of shell_rc or the legacy bashrc key")
    configured_rc = raw.get("shell_rc") or raw.get("bashrc")
    if configured_rc:
        shell_rc = expand(str(configured_rc))
    else:
        shell_name = Path(os.environ.get("SHELL", "")).name
        shell_rc = Path.home() / (".zshrc" if shell_name == "zsh" else ".bashrc")
    return Spec(
        codex_home=codex_home,
        shared_provider_id=shared,
        providers=providers,
        approval_policy=approval,
        sandbox_mode=sandbox,
        trusted_projects=[expand(str(p)) for p in (raw.get("trusted_projects") or [])],
        official=dict(raw.get("official") or {}),
        manage_official="official" in raw,
        bashrc=shell_rc,
        link_home=bool(raw.get("link_home", True)),
    )


# --------------------------------------------------------------------------- render


def render_profile(provider: Provider, shared: str) -> str:
    """Build a complete <id>.config.toml. Contains no secrets — only an env var name."""
    lines = [
        f"# {provider.ident} profile — `codex -p {provider.ident}` or the codex-{provider.ident} wrapper.",
        "# Written by the codex-provision-host skill; safe to edit by hand.",
        "#",
        f"# provider id is {shared!r}, shared with every other profile so that the resume",
        "# picker shows one merged session list (it filters on threads.model_provider and",
        "# compares only the id — name / base_url / auth do not participate).",
    ]
    if provider.env_key:
        lines += [
            "#",
            f"# The key arrives as ${provider.env_key}, injected per call by the shell wrapper.",
            "# It is never stored here and never exported globally.",
        ]
    lines.append("")
    lines.append(f"model_provider = {toml_string(shared)}")
    for key, value in (
        ("model", provider.model),
        ("model_reasoning_effort", provider.model_reasoning_effort),
        ("model_verbosity", provider.model_verbosity),
    ):
        if value:
            lines.append(f"{key} = {toml_string(value)}")
    for key in sorted(provider.profile_extra):
        lines.append(f"{key} = {toml_value(provider.profile_extra[key])}")
    lines.append("")
    lines.append(f"[model_providers.{shared}]")
    lines.append(f"name = {toml_string(provider.name)}")
    lines.append(f"base_url = {toml_string(provider.base_url)}")
    lines.append(f"wire_api = {toml_string(provider.wire_api)}")
    if provider.requires_openai_auth:
        lines.append("requires_openai_auth = true")
    if provider.env_key:
        lines.append(f"env_key = {toml_string(provider.env_key)}")
    inline: list[str] = []
    tables: list[str] = []
    for key, value in sorted(provider.extra.items()):
        if isinstance(value, dict):
            # e.g. http_headers / query_params: a sub-table must come after all
            # inline keys, or it would swallow them.
            tables.extend(render_table(f"model_providers.{shared}.{key}", value))
        else:
            inline.append(f"{key} = {toml_value(value)}")
    lines.extend(inline)
    lines.extend(tables)
    # Free-form profile tables, e.g. [tui.model_availability_nux].
    for name in sorted(provider.tables):
        body = provider.tables[name]
        if isinstance(body, dict):
            lines.extend(render_table(name, body))
    return "\n".join(lines) + "\n"


def render_wrappers(spec: Spec) -> str:
    """Shell functions that read each key at call time and scope it to one process."""
    out = [
        BLOCK_START,
        "# One wrapper per Codex provider. The key is read from its 0600 file at call",
        "# time and passed only to that single codex process — never exported, never",
        "# written into any config. Do not set CODEX_API_KEY: Codex treats it as the",
        "# official key and 401s the default provider.",
    ]
    for provider in spec.providers:
        out.append("")
        out.append(f"codex-{provider.ident}() {{")
        if provider.env_key and provider.key_file is not None:
            reader = (
                "python3 -c "
                + shell_quote(
                    "import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])"
                )
                + f" {shell_quote(str(provider.key_file))}"
                + f" {shell_quote(provider.key_json_field)}"
            )
            out.append(f'    local __key; __key="$({reader})" || {{')
            out.append(
                f'        printf "codex-{provider.ident}: cannot read key from '
                f'{provider.key_file}\\n" >&2; return 1; }}'
            )
            out.append(f'    {provider.env_key}="$__key" codex -p {provider.ident} "$@"')
        else:
            out.append(f'    codex -p {provider.ident} "$@"')
        out.append("}")
    out.append(BLOCK_END)
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------- base config edit


TOP_LEVEL = r"""(?m)^([ \t]*){key}([ \t]*=[ \t]*)("[^"\n]*"|'[^'\n]*'|true|false)([ \t]*)(\#.*)?$"""


def set_top_level(source: str, key: str, value: str, note: str = "") -> str:
    """Set a root-level key, or insert it before the first [table] if absent.

    Appending at end-of-file would land the key inside the last table, so an
    absent key must be inserted above the first header.
    """
    rendered = f"{key} = {toml_string(value)}"
    pattern = re.compile(TOP_LEVEL.format(key=re.escape(key)))
    match = pattern.search(source)
    if match is not None:
        trailing = f"  {match.group(5)}" if match.group(5) else ""
        return source[: match.start()] + match.group(1) + rendered + trailing + source[match.end():]
    block = (f"{note}\n" if note else "") + rendered + "\n"
    header = re.search(r"(?m)^\[", source)
    if header is None:
        prefix = source if not source or source.endswith("\n") else source + "\n"
        return prefix + block
    return source[: header.start()] + block + "\n" + source[header.start():]


def strip_provider_table(source: str, provider_id: str) -> tuple[str, str]:
    """Remove [model_providers.<id>] and return (remainder, removed_body)."""
    pattern = re.compile(
        r"(?ms)^\[model_providers\." + re.escape(provider_id) + r"\][ \t]*\n(.*?)(?=^\[|\Z)"
    )
    match = pattern.search(source)
    if match is None:
        return source, ""
    return source[: match.start()] + source[match.end():], match.group(1)


def render_base_config(source: str, spec: Spec) -> str:
    """Apply shared id, official provider table, permissions, and trusted projects."""
    result = source
    shared = spec.shared_provider_id

    if spec.manage_official:
        note = (
            "# The official channel uses the shared provider id too, so its history stays\n"
            "# visible to every profile. A custom id keeps ChatGPT OAuth as long as base_url\n"
            "# is the official backend and requires_openai_auth = true (auth reads auth.json).\n"
            f"# Built-in id \"openai\" is reserved and cannot be overridden, hence {shared!r}."
        )
        result = set_top_level(result, "model_provider", shared, note)
        unknown_official = sorted(
            set(spec.official) - {"model", "model_reasoning_effort", "model_verbosity"}
            - PROFILE_PASSTHROUGH
        )
        if unknown_official:
            die(f"[official]: unrecognised key(s) {', '.join(unknown_official)}")
        for key in ("model", "model_reasoning_effort", "model_verbosity", *sorted(PROFILE_PASSTHROUGH)):
            if spec.official.get(key) is not None and key not in ("approval_policy", "sandbox_mode"):
                result = set_top_level(result, key, str(spec.official[key]))

        result, existing = strip_provider_table(result, shared)
        body = existing.strip("\n")
        if "base_url" not in body:
            body = "\n".join(
                [
                    'name = "OpenAI"',
                    f"base_url = {toml_string(OFFICIAL_BASE_URL)}",
                    'wire_api = "responses"',
                    "requires_openai_auth = true",
                ]
            )
        table = f"[model_providers.{shared}]\n{body}\n"
        result = result.rstrip("\n") + "\n\n" + table

    if spec.approval_policy or spec.sandbox_mode:
        note = (
            "# Default permission level; inherited by every profile that does not\n"
            "# override it. danger-full-access means no sandbox at all: generated\n"
            "# commands can read and write anything the user can, including ~/.ssh\n"
            "# and provider key files."
        )
        if spec.approval_policy:
            result = set_top_level(result, "approval_policy", spec.approval_policy, note)
            note = ""
        if spec.sandbox_mode:
            result = set_top_level(result, "sandbox_mode", spec.sandbox_mode, note)

    for project in spec.trusted_projects:
        header = f'[projects."{project}"]'
        if header not in result:
            result = result.rstrip("\n") + f"\n\n{header}\ntrust_level = \"trusted\"\n"

    return result.rstrip("\n") + "\n"


# ----------------------------------------------------------------------------- plan


@dataclass
class Change:
    kind: str            # mkdir | write | bashrc | symlink | migrate
    path: str
    reason: str
    content: str | None = None
    target: str | None = None
    unchanged: bool = False


@dataclass
class Gap:
    what: str
    detail: str


def splice_block(source: str, block: str) -> str:
    """Replace the managed block, or append it. Never duplicates on re-run."""
    start = source.find(BLOCK_START)
    end = source.find(BLOCK_END)
    if start != -1 and end != -1 and end > start:
        tail = source[end + len(BLOCK_END):]
        return source[:start] + block.rstrip("\n") + tail
    prefix = source if not source or source.endswith("\n") else source + "\n"
    if prefix and not prefix.endswith("\n\n"):
        prefix += "\n"
    return prefix + block


def check_key_file(provider: Provider) -> Gap | None:
    """Check only presence, file type, and mode; never open credential contents."""
    path = provider.key_file
    if path is None:
        return None
    if not path.exists():
        return Gap(
            f"key file missing for {provider.ident}",
            f"create {path} as 0600 JSON: "
            f'{{"{provider.key_json_field}": "<key>"}}  '
            f"(mkdir -p {path.parent} && umask 077)",
        )
    if not path.is_file():
        return Gap(
            f"key path for {provider.ident} is not a regular file",
            f"replace {path} with a 0600 JSON file containing {provider.key_json_field}",
        )
    mode = path.stat().st_mode & 0o777
    if not mode & 0o400:
        return Gap(
            f"key file for {provider.ident} is not owner-readable",
            f"chmod 600 {path}  (currently {mode:04o})",
        )
    if mode & 0o077:
        return Gap(
            f"key file for {provider.ident} is world/group readable",
            f"chmod 600 {path}  (currently {mode:04o})",
        )
    return None


def has_session_state(home: Path) -> bool:
    if any(home.glob("state_*.sqlite")):
        return True
    return any(
        folder.exists() and next(folder.rglob("rollout-*.jsonl"), None) is not None
        for folder in (home / "sessions", home / "archived_sessions")
    )


def build_plan(spec: Spec) -> tuple[list[Change], list[Gap]]:
    changes: list[Change] = []
    gaps: list[Gap] = []
    home = spec.codex_home

    if not home.exists():
        changes.append(
            Change(
                kind="mkdir",
                path=str(home),
                reason="create the configured Codex home with owner-only permissions",
            )
        )
    elif not home.is_dir():
        gaps.append(
            Gap(
                f"codex home {home} is not a directory",
                "choose an unused directory path or move the existing object aside",
            )
        )

    for provider in spec.providers:
        path = home / f"{provider.ident}.config.toml"
        desired = render_profile(provider, spec.shared_provider_id)
        current = path.read_text() if path.is_file() else None
        changes.append(
            Change(
                kind="write",
                path=str(path),
                reason=f"profile for `codex -p {provider.ident}`",
                content=desired,
                unchanged=current == desired,
            )
        )
        gap = check_key_file(provider)
        if gap is not None:
            gaps.append(gap)

    base = home / "config.toml"
    base_current = base.read_text() if base.is_file() else ""
    base_desired = render_base_config(base_current, spec)
    reason_bits = []
    if spec.manage_official:
        reason_bits.append(f"official channel on shared id {spec.shared_provider_id!r}")
    if spec.approval_policy or spec.sandbox_mode:
        reason_bits.append(
            f"permissions {spec.approval_policy or '(unchanged)'} / "
            f"{spec.sandbox_mode or '(unchanged)'}"
        )
    if spec.trusted_projects:
        reason_bits.append(f"{len(spec.trusted_projects)} trusted project(s)")
    if reason_bits:
        changes.append(
            Change(
                kind="write",
                path=str(base),
                reason="; ".join(reason_bits),
                content=base_desired,
                unchanged=base_desired == base_current,
            )
        )

    if spec.providers:
        block = render_wrappers(spec)
        rc_current = spec.bashrc.read_text() if spec.bashrc.is_file() else ""
        rc_desired = splice_block(rc_current, block)
        names = ", ".join(f"codex-{p.ident}" for p in spec.providers)
        changes.append(
            Change(
                kind="bashrc",
                path=str(spec.bashrc),
                reason=f"shell wrappers: {names}",
                content=rc_desired,
                unchanged=rc_desired == rc_current,
            )
        )

    default_home = Path.home() / ".codex"
    if spec.link_home and home != default_home:
        if default_home.is_symlink():
            resolved = default_home.resolve()
            changes.append(
                Change(
                    kind="symlink",
                    path=str(default_home),
                    target=str(home),
                    reason="VS Code extension falls back to $HOME/.codex (no login shell)",
                    unchanged=resolved == home,
                )
            )
            if resolved != home:
                gaps.append(
                    Gap(
                        f"{default_home} already links elsewhere",
                        f"points at {resolved}; remove it by hand if {home} is correct",
                    )
                )
        elif default_home.exists():
            gaps.append(
                Gap(
                    f"{default_home} exists and is not a symlink",
                    "the VS Code extension will keep reading it instead of "
                    f"{home}; move it aside by hand if that is wrong",
                )
            )
        else:
            changes.append(
                Change(
                    kind="symlink",
                    path=str(default_home),
                    target=str(home),
                    reason="VS Code extension falls back to $HOME/.codex (no login shell)",
                )
            )

    state_present = has_session_state(home)
    changes.append(
        Change(
            kind="migrate",
            path=str(home),
            reason=(
                f"retarget existing sessions to {spec.shared_provider_id!r} with --deep so all "
                "provider metadata locations are rewritten"
                if state_present
                else "no existing session state to migrate"
            ),
            unchanged=not state_present,
        )
    )
    return changes, gaps


# ---------------------------------------------------------------------------- apply


def backup_dir(home: Path) -> Path:
    root = home / "backups"
    root_existed = root.exists()
    root.mkdir(parents=True, exist_ok=True)
    if not root_existed:
        fsync_directory(home)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    created = Path(tempfile.mkdtemp(prefix=f"provision-{stamp}-", dir=root))
    fsync_directory(root)
    return created


def fsync_directory(path: Path) -> None:
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def fsync_file(path: Path) -> None:
    with path.open("rb") as stream:
        os.fsync(stream.fileno())


def atomic_write(path: Path, content: str, mode: int | None = None) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.provision-", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if mode is None:
            mode = (path.stat().st_mode & 0o777) if path.exists() else 0o644
        os.chmod(temp, mode)
        fsync_file(temp)
        os.replace(temp, path)
        fsync_directory(path.parent)
    finally:
        temp.unlink(missing_ok=True)


def validate_toml(path: Path) -> None:
    with path.open("rb") as stream:
        tomllib.load(stream)


def find_migrator(explicit: str | None) -> Path | None:
    """Locate session_guard.py, which owns history migration."""
    if explicit:
        candidate = expand(explicit)
        return candidate if candidate.is_file() else None
    here = Path(__file__).resolve()
    candidates = [
        # Same scripts/ directory: both live in one skill.
        here.parent / "session_guard.py",
        # Installed as a separate sibling skill.
        here.parent.parent.parent / "codex-restore-sessions" / "scripts" / "session_guard.py",
        Path.home() / ".agents" / "skills" / "codex-restore-sessions" / "scripts"
        / "session_guard.py",
        # Legacy personal skill location used by earlier releases.
        Path.home() / ".codex" / "skills" / "codex-restore-sessions" / "scripts"
        / "session_guard.py",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def run_migration(spec: Spec, migrator: Path, skip_live: bool) -> dict[str, object]:
    command = [
        sys.executable,
        str(migrator),
        "--codex-home",
        str(spec.codex_home),
        "--compact",
        "restore",
        "--provider",
        spec.shared_provider_id,
    ]
    if not skip_live:
        command.append("--fail-live")
    proc = subprocess.run(command, capture_output=True, text=True, timeout=1800)
    tail = (proc.stdout or proc.stderr or "").strip().splitlines()[-25:]
    return {
        "command": " ".join(command),
        "returncode": proc.returncode,
        "output": "\n".join(tail),
    }


def apply_plan(
    spec: Spec, changes: list[Change], migrator: Path | None, skip_live: bool
) -> dict[str, object]:
    if spec.codex_home.exists() and not spec.codex_home.is_dir():
        die(f"configured Codex home is not a directory: {spec.codex_home}")
    backups: Path | None = None
    applied: list[dict[str, str]] = []

    for change in changes:
        if change.unchanged:
            applied.append({"path": change.path, "action": "already correct"})
            continue

        if change.kind == "mkdir":
            path = Path(change.path)
            try:
                path.mkdir(parents=True, mode=0o700, exist_ok=False)
            except FileExistsError:
                die(f"configured Codex home appeared after planning; review before retrying: {path}")
            os.chmod(path, 0o700)
            fsync_directory(path)
            fsync_directory(path.parent)
            applied.append({"path": change.path, "action": "created directory (0700)"})

        elif change.kind in {"write", "bashrc"}:
            path = Path(change.path)
            if path.exists():
                if backups is None:
                    backups = backup_dir(spec.codex_home)
                suffix = hashlib.sha256(str(path).encode()).hexdigest()[:12]
                saved = backups / f"{path.name}.{suffix}"
                shutil.copy2(path, saved)
                fsync_file(saved)
                fsync_directory(saved.parent)
            else:
                saved = None
            assert change.content is not None
            atomic_write(path, change.content)
            if path.suffix == ".toml":
                try:
                    validate_toml(path)
                except Exception as exc:  # restore and stop; a broken config breaks codex
                    if saved is not None:
                        shutil.copy2(saved, path)
                    die(f"{path} would be invalid TOML ({exc}); restored original")
            applied.append(
                {
                    "path": change.path,
                    "action": "written",
                    "backup": str(saved) if saved else "(new file)",
                }
            )

        elif change.kind == "symlink":
            link = Path(change.path)
            assert change.target is not None
            if link.is_symlink():
                # Never steal a link that points somewhere else — it may be another
                # host's real Codex home. plan() already reported this as a gap.
                current = os.readlink(link)
                if Path(current).resolve() != Path(change.target).resolve():
                    applied.append(
                        {
                            "path": change.path,
                            "action": f"refused: already links to {current}",
                        }
                    )
                    continue
                applied.append({"path": change.path, "action": "already correct"})
                continue
            if link.exists():
                applied.append({"path": change.path, "action": "skipped (real path exists)"})
                continue
            link.symlink_to(change.target)
            fsync_directory(link.parent)
            applied.append(
                {"path": change.path, "action": f"symlinked -> {change.target}"}
            )

    result: dict[str, object] = {
        "backup_dir": str(backups) if backups is not None else None,
        "applied": applied,
    }

    migration = next((change for change in changes if change.kind == "migrate"), None)
    if migration is not None and migration.unchanged:
        result["migration"] = {"skipped": "no existing session state to migrate"}
    elif migrator is None:
        result["migration"] = {
            "skipped": "session_guard.py not found next to this script; pass "
            "--migrator <path>, or migrate manually with `restore --provider <id>`"
        }
    else:
        result["migration"] = run_migration(spec, migrator, skip_live)
    return result


# --------------------------------------------------------------------------- verify


BANNER = re.compile(r"^(model|provider|approval|sandbox):[ \t]*(.+?)[ \t]*$")


def find_thread_database(home: Path) -> Path | None:
    """Find the newest usable state database without assuming a schema version."""
    def version(path: Path) -> int:
        match = re.fullmatch(r"state_(\d+)\.sqlite", path.name)
        return int(match.group(1)) if match else -1

    for path in sorted(home.glob("state_*.sqlite"), key=version, reverse=True):
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            present = con.execute(
                "select 1 from sqlite_master where type='table' and name='threads'"
            ).fetchone()
            con.close()
            if present:
                return path
        except sqlite3.Error:
            continue
    return None


def probe_channel(
    spec: Spec, profile: str | None, env_keys: list[str], timeout: int = 90
) -> dict[str, str]:
    """Ask the real codex binary what it resolves. Never passes a real key.

    Reads the banner as it streams and kills the process as soon as all four
    fields are in hand: profiles with a high request_max_retries would otherwise
    keep retrying a placeholder key long past any deadline, and output captured
    via communicate() is lost when the deadline hits.
    """
    command = ["codex"]
    if profile:
        command += ["-p", profile]
    command += ["exec", "--strict-config", "probe"]
    env = dict(os.environ)
    env["CODEX_HOME"] = str(spec.codex_home)
    env.pop("CODEX_API_KEY", None)
    for name in env_keys:
        env.setdefault(name, "placeholder-not-a-real-key")

    wanted = {"model", "provider", "approval", "sandbox"}
    found: dict[str, str] = {}
    try:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )
    except FileNotFoundError:
        return {"error": "codex binary not found on PATH"}

    deadline = time.monotonic() + timeout
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            match = BANNER.match(line.rstrip("\n"))
            if match:
                found[match.group(1)] = match.group(2)
                if wanted <= found.keys():
                    break
            if time.monotonic() > deadline:
                break
    finally:
        proc.kill()
        proc.wait(timeout=10)

    if not found:
        return {"error": f"codex printed no banner within {timeout}s"}
    missing = sorted(wanted - found.keys())
    if missing:
        found["incomplete"] = f"banner lacked {', '.join(missing)}"
    return found


def verify(spec: Spec) -> dict[str, object]:
    env_keys = [p.env_key for p in spec.providers if p.env_key]
    report: dict[str, object] = {"codex_home": str(spec.codex_home), "channels": {}}
    problems: list[str] = []
    warnings: list[str] = []
    channels: dict[str, dict[str, str]] = {}

    targets: list[tuple[str, str | None, str, str]] = []
    if spec.manage_official:
        targets.append(
            ("(default)", None, OFFICIAL_BASE_URL, str(spec.official.get("model") or ""))
        )
    for provider in spec.providers:
        targets.append((provider.ident, provider.ident, provider.base_url, provider.model))

    for label, profile, expected_url, expected_model in targets:
        found = probe_channel(spec, profile, env_keys)
        if "error" in found:
            problems.append(f"{label}: {found['error']}")
            channels[label] = found
            continue
        found["expected_base_url"] = expected_url
        channels[label] = found
        if found.get("provider") != spec.shared_provider_id:
            problems.append(
                f"{label}: provider id is {found.get('provider')!r}, "
                f"expected {spec.shared_provider_id!r} — resume list will not be shared"
            )
        if spec.approval_policy and found.get("approval") != spec.approval_policy:
            problems.append(
                f"{label}: approval is {found.get('approval')!r}, expected {spec.approval_policy!r}"
            )
        if spec.sandbox_mode and found.get("sandbox") != spec.sandbox_mode:
            problems.append(
                f"{label}: sandbox is {found.get('sandbox')!r}, expected {spec.sandbox_mode!r}"
            )
        if expected_model and found.get("model") != expected_model:
            # A trusted-project entry matching the cwd can shadow a profile's
            # top-level keys; the provider table still applies, so routing is fine.
            warnings.append(
                f"{label}: model resolves to {found.get('model')!r}, profile asks for "
                f"{expected_model!r}. Routing is unaffected (base_url still comes from the "
                "profile). A [projects.\"<cwd>\"] entry in the base config can shadow a "
                "profile's root-level keys — pass `-m <model>` or `-c model=...` when the "
                "exact model matters."
            )

    report["channels"] = channels

    # base_url is not in the banner; read it back from each config instead.
    for provider in spec.providers:
        path = spec.codex_home / f"{provider.ident}.config.toml"
        if not path.is_file():
            problems.append(f"{provider.ident}: {path} missing")
            continue
        with path.open("rb") as stream:
            data = tomllib.load(stream)
        table = (data.get("model_providers") or {}).get(spec.shared_provider_id) or {}
        if table.get("base_url") != provider.base_url:
            problems.append(
                f"{provider.ident}: base_url is {table.get('base_url')!r}, "
                f"expected {provider.base_url!r}"
            )
        if provider.env_key and table.get("env_key") != provider.env_key:
            problems.append(
                f"{provider.ident}: env_key is {table.get('env_key')!r}, "
                f"expected {provider.env_key!r}"
            )

    db = find_thread_database(spec.codex_home)
    if db is not None:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)  # mode=ro so the WAL is honoured
        try:
            rows = dict(
                con.execute("SELECT model_provider, COUNT(*) FROM threads GROUP BY 1").fetchall()
            )
        finally:
            con.close()
        report["session_providers"] = rows
        stale = {k: v for k, v in rows.items() if k != spec.shared_provider_id}
        if stale:
            problems.append(
                f"{sum(stale.values())} session(s) still on {sorted(stale)} — invisible in every "
                "resume picker; re-run the migration with --deep"
            )

    for provider in spec.providers:
        gap = check_key_file(provider)
        if gap is not None:
            problems.append(f"{gap.what}: {gap.detail}")

    report["problems"] = problems
    report["warnings"] = warnings
    report["ok"] = not problems
    return report


# ------------------------------------------------------------------------------- cli


def describe_plan(changes: list[Change], gaps: list[Gap]) -> str:
    lines: list[str] = []
    todo = [c for c in changes if not c.unchanged]
    same = [c for c in changes if c.unchanged]
    lines.append(f"{len(todo)} change(s) to apply, {len(same)} already correct\n")
    for change in todo:
        verb = {
            "mkdir": "mkdir   ",
            "write": "write   ",
            "bashrc": "splice  ",
            "symlink": "symlink ",
            "migrate": "migrate ",
        }[change.kind]
        suffix = f" -> {change.target}" if change.target else ""
        lines.append(f"  {verb}{change.path}{suffix}")
        lines.append(f"            {change.reason}")
    if same:
        lines.append("\nalready correct:")
        for change in same:
            lines.append(f"  ok      {change.kind} {change.path} — {change.reason}")
    if gaps:
        lines.append("\ngaps needing a human (everything else still proceeds):")
        for gap in gaps:
            lines.append(f"  !  {gap.what}")
            lines.append(f"     {gap.detail}")
    return "\n".join(lines)


def public_change(change: Change) -> dict[str, object]:
    """Describe a plan without echoing rendered config or header values."""
    result: dict[str, object] = {
        "kind": change.kind,
        "path": change.path,
        "reason": change.reason,
        "target": change.target,
        "unchanged": change.unchanged,
    }
    if change.content is not None:
        encoded = change.content.encode()
        result["content_bytes"] = len(encoded)
        result["content_sha256"] = hashlib.sha256(encoded).hexdigest()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["plan", "apply", "verify"])
    parser.add_argument("--spec", required=True, help="path to the host spec TOML")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--migrator", help="path to session_guard.py if not auto-found")
    parser.add_argument(
        "--no-skip-live",
        action="store_true",
        help="fail instead of deferring open, growing, or uncertain rollout files",
    )
    args = parser.parse_args()

    spec = load_spec(expand(args.spec))

    if args.mode == "verify":
        report = verify(spec)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0 if report["ok"] else 1

    changes, gaps = build_plan(spec)

    if args.mode == "plan":
        if args.json:
            print(
                json.dumps(
                    {
                        "changes": [public_change(c) for c in changes],
                        "gaps": [g.__dict__ for g in gaps],
                    },
                    indent=2,
                    ensure_ascii=False,
                    default=str,
                )
            )
        else:
            print(describe_plan(changes, gaps))
        return 0

    migrator = find_migrator(args.migrator)
    result = apply_plan(spec, changes, migrator, skip_live=not args.no_skip_live)
    result["gaps"] = [g.__dict__ for g in gaps]
    print(json.dumps(result, indent=2, ensure_ascii=False))
    migration = result.get("migration") or {}
    if isinstance(migration, dict) and migration.get("returncode") not in (0, None):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
