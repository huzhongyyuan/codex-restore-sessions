# Provision A Codex Host

Use `$SKILL_DIR/scripts/provision_codex.py` only when the user wants profiles, shell wrappers, a shared session
provider ID, optional permissions, or a `$HOME/.codex` discovery link. Do not use it for a session-
only repair.

Copy the template outside the skill and edit only non-secret configuration:

```bash
cp "$SKILL_DIR/assets/spec.example.toml" <host>.toml
python3 "$SKILL_DIR/scripts/provision_codex.py" plan --spec <host>.toml
```

Review and show the plan before applying. The template defaults to `on-request` plus
`workspace-write` and trusts no project directory. Change permissions only when the user explicitly
selected them.

```bash
python3 "$SKILL_DIR/scripts/provision_codex.py" apply  --spec <host>.toml
python3 "$SKILL_DIR/scripts/provision_codex.py" verify --spec <host>.toml
```

`plan` is read-only. `apply` writes only listed changes, backs up modified files, and skips session
migration when no state exists. `verify` asks the installed Codex binary to resolve each channel and
reports drift. Re-running is idempotent and a no-op does not create an empty backup directory. The
template does not pin a model version; omit `model` to inherit the installed Codex default. JSON
plans expose only content length and SHA-256, not the rendered config body. When the configured
Codex home is absent, plan an explicit directory creation and apply it with mode `0700` before any
profile writes.

Use `shell_rc` to select a Bash- or zsh-compatible startup file; omit it to detect zsh from `$SHELL`
and otherwise use `~/.bashrc`. The legacy `bashrc` spec key remains accepted. Never repoint an
existing `$HOME/.codex` symlink automatically.

For credential files, the provisioning script checks only existence, regular-file type, and mode;
it does not open the contents. Report missing files as gaps. The generated wrapper reads the named
JSON field only when invoked and scopes the resulting environment variable to one Codex process.
Never create the key, display it, put it in config or shell startup text, or export it globally.
Reject credentials embedded in provider URLs, sensitive literal `http_headers`, and credential-like
literal query parameters. Use `env_http_headers` with an uppercase environment-variable name when a
provider requires an authentication header.

Per provider, report the profile path, endpoint, environment variable name, and whether the key file
passed metadata checks. Then report the shared ID, permission level, shell startup file, migration
counts, and every backup path.

Provisioning mutations and shell wrappers require a POSIX-like environment. On another platform,
use `session_guard.py capabilities`, retain audit-only behavior, and report the unsupported step.
