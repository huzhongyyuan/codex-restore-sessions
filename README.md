# Codex Session Guard

> Safely audit, repair, migrate, and roll back local Codex session metadata.

Codex Session Guard 是一个面向 Codex 的本地 skill，用来处理 provider、relay、Codex 版本、
home 目录或服务器切换后出现的 session 消失、无法 resume、名称丢失，以及 SQLite 与 rollout
JSONL 不一致等问题。

它不是项目代码迁移工具，也不会复制凭据。所有修改都会在本地完成，并在写入前创建经过校验的
增量备份与操作 journal。

## 能解决什么

- provider 或 relay 切换后，旧 session 不再显示或无法恢复
- `state_*.sqlite` 与 `sessions/**/*.jsonl` 中的 provider 不一致
- Codex 升级、切换 home 目录后需要审计现有 session
- 在满足严格条件时恢复旧 session 名称
- 保留 active / archived 状态进行跨服务器迁移
- 对一次已记录的修改执行受保护回滚

## 安全设计

- 修改前审计，发现路径、ID、归档位置、重复项或 journal 异常时拒绝写入
- 使用 SQLite backup API 创建一致的数据库备份并校验完整性与 SHA-256
- 原子替换 rollout 元数据首行，保留其余 conversation events
- 修改期间加本地文件锁，并检测并发数据库或文件变化
- provider 同步默认不改写历史 model、名称、时间戳和归档状态
- 不读取、输出、散列、复制或备份 `auth.json`、API key、token 与凭据环境变量
- 不提高 Codex 的 approval policy 或 sandbox mode

## 安装

需要 Python 3.10+。Python 3.11+ 无额外依赖；Python 3.10 需安装 `tomli`。Linux 和 macOS
支持审计与修改；Windows 当前仅支持审计，因为修改路径依赖 `fcntl` 文件锁。

```bash
git clone https://github.com/huzhongyyuan/codex-restore-sessions.git \
  "${CODEX_HOME:-$HOME/.codex}/skills/codex-restore-sessions"
```

仅使用 Python 3.10 时，再运行：

```bash
python3 -m pip install -r \
  "${CODEX_HOME:-$HOME/.codex}/skills/codex-restore-sessions/requirements.txt"
```

重启 Codex 后，可直接说：

```text
恢复所有 session
```

Codex 会读取 `SKILL.md` 并使用受保护的默认流程。

## 命令行使用

以下示例假设仓库位于 `$CODEX_HOME/skills/codex-restore-sessions`；未设置 `CODEX_HOME` 时使用
`$HOME/.codex`。

```bash
SKILL_DIR="${CODEX_HOME:-$HOME/.codex}/skills/codex-restore-sessions"
CODEX_DIR="${CODEX_HOME:-$HOME/.codex}"
```

### 只读审计

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" \
  --codex-home "$CODEX_DIR" --compact audit
```

审计会比较数据库、磁盘 rollout 文件、ID、路径、归档位置、provider 和未完成 journal。它不会
修改任何 session。

### 恢复或同步到当前 provider

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" \
  --codex-home "$CODEX_DIR" --compact switch
```

目标 provider 来自当前 `config.toml`。一次 `switch` 已包含：

1. 写入前完整审计
2. 数据库一致性备份与 manifest
3. SQLite 和 rollout JSONL 的受保护修改
4. 写入后完整审计

成功输出中应满足：

- `problems` 为空
- `threads == rollout_files`
- SQLite 与 JSONL provider 均等于目标 provider
- 有实际修改时返回 `backup` 路径；已经一致时 `backup: null` 是正常 no-op

如需明确指定 provider：

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" \
  --codex-home "$CODEX_DIR" --compact switch --provider openai
```

默认不会改写历史 model。只有明确需要时才传入 `--model`。

### 修复可确认的旧名称

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" \
  --codex-home "$CODEX_DIR" --compact repair
```

只有数据库名称为空、legacy name 与 title 相同，且它不同于首条用户消息时才会恢复。歧义名称
会保留原状，不会批量猜测。

### 回滚

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" \
  --codex-home "$CODEX_DIR" --compact rollback \
  "$CODEX_DIR/backups/session-guard-<timestamp>"
```

回滚只接受当前 Codex home 下、状态和哈希均符合预期的 `session-guard-*` 备份。若 Codex 在修改后
重新索引了相关字段，工具会拒绝盲目回滚。

## 跨服务器迁移

本项目保护的是 Codex session 状态，不迁移项目源码、Git 仓库、模型、数据集或训练结果。

迁移前先分别审计源端与目标端。需要传输的内容是：

- `sessions/`
- `archived_sessions/`
- `session_index.jsonl`
- 通过 SQLite backup API 获得的一致数据库备份

不要传输：

- `auth.json`、API key、token 或其他凭据
- 源服务器的 `config.toml`
- 项目代码、模型权重、数据集和输出文件

如果目标 Codex home 已经包含 session，请停止。当前版本不实现两个非空 SQLite/JSONL 状态的
自动合并；直接覆盖会有数据丢失风险。先在目标端使用其自身凭据和配置，再运行 audit / switch。

## 数据范围

工具只读取 session 索引、SQLite thread 元数据、rollout JSONL 首条 `session_meta` 记录，以及
`config.toml` 中用于识别 provider/relay 的非秘密字段。备份目录默认位于：

```text
$CODEX_HOME/backups/session-guard-<UTC timestamp>/
```

备份包含 SQLite 快照、变更 manifest 和必要的首行 before/after 数据，不包含凭据。

## 已知限制

- Codex 自身可能在 picker/resume 启动后重新索引 provider、model 或时间字段；需要以之后的新审计
  结果为准。
- 工具不自动 unarchive session。
- 工具不强行恢复歧义名称。
- 工具不执行两个非空 Codex home 的 schema-aware merge。
- 常规成功恢复不会自动打开 picker 或逐个 resume UUID；需要端到端 UI 验证时应明确执行。

## 自检

```bash
python3 scripts/test_session_guard.py
```

自检完全在临时目录中运行，覆盖 audit、switch、rename、relay fingerprint、rollback 和恶意 manifest
越界路径拒绝等核心路径。

## 仓库结构

```text
.
├── SKILL.md
├── agents/openai.yaml
└── scripts/
    ├── session_guard.py
    └── test_session_guard.py
```

## License

[MIT](LICENSE)
