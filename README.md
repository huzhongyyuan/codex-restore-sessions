# Codex Session Guard

> Provision a Codex host, and safely audit, repair, migrate, and roll back local session metadata.

两件事，两个脚本：

| 目标 | 脚本 |
|---|---|
| 在新机器上从零搭好：多服务商 profile、`codex-<id>` 包装函数、权限档位、软链接 | `scripts/provision_codex.py` |
| 修已经存在的 session：provider 漂移、名称丢失、跨机迁移、回滚 | `scripts/session_guard.py` |

搭建脚本会调用 session 脚本完成历史迁移，所以新机器只需要跑 `provision_codex.py`。
安装本身没问题、只是 session 不对时，直接用 `session_guard.py`。

两者都不复制凭据。所有修改在本地完成，写入前创建经过校验的增量备份与操作 journal。

> 关于 Codex 内部行为的结论（resume 的过滤字段、rollout 文件里 provider 的记录位置、
> `[projects]` 遮蔽 profile 顶层键）来自对 **codex-cli 0.144.3** 的黑盒实验和 `strings`
> 观察，不是官方文档。换版本请用 `verify` 重新确认。

## 能解决什么

- 想在另一台服务器上配出同样的多服务商 Codex → 一份 spec 文件，见[在新机器上搭一套](#在新机器上搭一套)
- provider 或 relay 切换后，旧 session 不再显示或无法恢复
- `state_*.sqlite` 与 `sessions/**/*.jsonl` 中的 provider 不一致
- 同一台机器上多个 provider profile（`codex -p relay` / `codex -p gateway`）各自记录 session，
  想让它们共享同一份历史 → 一条 `unify` 命令，见[让多个 provider 共享同一份 session](#让多个-provider-共享同一份-session新服务器一条命令)
- 明明改过 provider，下一次 reindex 又漂回旧值 → 需要 `switch --deep`
- VS Code 插件里一条 session 都看不到 → 见[VS Code 插件看不到 session](#vs-code-插件看不到-session)
- 数据库中残留指向已删除 rollout 文件的孤儿行，导致其他模式全部拒绝执行
- Codex 升级、切换 home 目录后需要审计现有 session
- 在满足严格条件时恢复旧 session 名称
- 保留 active / archived 状态进行跨服务器迁移
- 对一次已记录的修改执行受保护回滚

## 在新机器上搭一套

```bash
cp reference/spec.example.toml my-host.toml   # 改 base_url / key 路径
python3 scripts/provision_codex.py plan   --spec my-host.toml   # 只看，不改
python3 scripts/provision_codex.py apply  --spec my-host.toml
python3 scripts/provision_codex.py verify --spec my-host.toml
```

`plan` 什么都不写。`apply` 只做 `plan` 列出的事，每个被改的文件都有备份路径。
`verify` 用真实 `codex` 二进制回读，有偏差就非零退出。重复跑是幂等的。

spec 文件只含路径不含密钥，但会含你的内网域名和绝对路径，**建议放在仓库外**
（`.gitignore` 已排除 `spec.*.toml`）。

key 文件自己建，工具不碰值：

```bash
mkdir -p ~/.codex-providers/relay
umask 077
printf '{"OPENAI_API_KEY": "<key>"}\n' > ~/.codex-providers/relay/auth.json
```

它产出：每个服务商一个 `$CODEX_HOME/<id>.config.toml`（→ `codex -p <id>`）、`.bashrc` 里一个带
标记的 `codex-<id>` 包装函数块（调用时读 key、只注入给那一个进程）、所有 config 统一的
provider id、base config 里的默认权限档位、以及 `codex_home` 不在 `$HOME` 时的
`$HOME/.codex` 软链接。历史迁移交给 `session_guard.py`，始终带 `--deep`。

key 文件缺失只报为 gap，不中断其余工作。已经指向别处的 `$HOME/.codex` 软链接一律拒绝改写。

### 权限档位

`approval_policy` + `sandbox_mode` 写在 base config，所有 profile 继承。

- `never` + `workspace-write` —— 不再弹审批，但写入仍限于工作目录和 `/tmp`。
- `never` + `danger-full-access` —— full access，无审批无沙箱。生成的命令可以读写你能读写的
  一切，包括 `~/.ssh` 和 key 文件。

单次覆盖用 `codex -s workspace-write` 或 `-a on-request`。

### VS Code 插件看不到 session

插件解析的是 `process.env.CODEX_HOME ?? join(homedir(), ".codex")`。它的宿主进程由 remote
server fork，不经过 login shell，所以 `.bashrc` 里 export 的 `CODEX_HOME` 到不了它手上，
于是回退到空的 `$HOME/.codex`。

确认方法是读 `/proc/<extension-host-pid>/environ`。修法是软链接（`link_home = true`）。
加完要重载 VS Code 窗口。注意：如果这台机器的 `$HOME` 是易失的（容器/云开发机常见），
软链接活不过重建，得在每次重建后重新创建。

### 已知行为：profile 的 model 可能被盖掉

base config 里存在匹配当前工作目录的 `[projects."<cwd>"]` 条目时，profile 的**顶层键**
（如 `model`）会被 base config 的同名键盖掉；`[model_providers.*]` 表**不受影响**，所以路由
仍然正确，只是模型名不是 profile 写的那个。

这是在同一个 home 里做 A/B/A 对照测出来的：去掉 `[projects]` → profile 的 model 生效；
加回去 → 变成 base 的 model。`verify` 会把它报成 warning 而不是 problem。需要精确控制模型时
显式传 `-m <model>`。

### provider id 不是服务商名

Codex 启动横幅里的 `provider: <id>` 是 provider **id**，不是服务商。三个 profile 共用
`shared` 这个 id 是为了共享 session 列表，真实端点看各自的 `base_url`。

中转站设了 `requires_openai_auth = true` 时，横幅还会显示官方账号和 weekly limit 进度条 ——
那是 `auth.json` 里官方账号的值、且是陈旧缓存，和中转站无关，不代表消耗了官方额度。

## 安全设计

- 修改前审计，发现路径、ID、归档位置、重复项或 journal 异常时拒绝写入
- 使用 SQLite backup API 创建一致的数据库备份并校验完整性与 SHA-256
- 原子替换 rollout 元数据首行，保留其余 conversation events
- 修改期间加本地文件锁，并检测并发数据库或文件变化
- provider 同步默认不改写历史 model、名称、时间戳和归档状态
- `prune` 只删除 rollout 文件确实不存在的行；文件仍在的行一律拒绝删除
- 迁移 bundle 逐文件校验 SHA-256，目标 home 已有 session 时拒绝导入
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

### 新服务器上让多服务商共享 session

在一台新机器上配好几个服务商（官方 + 内网网关 + 中转）之后，只需要这一条：

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" \
  --codex-home "$CODEX_DIR" --compact unify --provider shared
```

跑完三个通道就共用同一份 session 列表了。原理和逐项行为见
[让多个 provider 共享同一份 session](#让多个-provider-共享同一份-session新服务器一条命令)。

验证方式：

```bash
codex -p <任一 profile> exec 'ping'   # 应打印 provider: shared
codex -p <任一 profile> resume        # 选单内容应与不加 -p 时一致
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

### 多 provider profile

Codex 0.144+ 的 `codex -p <name>` 会把 `$CODEX_HOME/<name>.config.toml` 叠加在 `config.toml`
之上。加 `--profile <name>` 即可按同样的叠加规则解析目标 provider：

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" \
  --codex-home "$CODEX_DIR" --compact --profile relay switch
```

叠加是深合并：profile 里的 `[model_providers.X]` 只写 `base_url` 时，`wire_api` 等字段仍从
`config.toml` 继承，fingerprint 按合并后的结果计算。`audit` 的 `available_profiles` 会列出
home 目录下所有 `*.config.toml`。旧版内联 `[profiles.<name>]` 表同样支持。

每个 profile 在 `session_guard_state.json` 里各自记录 fingerprint，所以在官方与中转之间来回
切换，不会让已经同步过的 profile 显示成"配置已变更"。

#### 让多个 provider 共享同一份 session（新服务器一条命令）

resume 选单是按 `threads.model_provider` 这一个字段过滤的（Codex 内部 SQL 形如
`AND threads.model_provider IN (...)`），**只比 provider id**，`name`、`base_url`、认证方式都
不参与。所以两个 profile 只要 id 不同，session 列表就必然互相看不见。

`unify` 一条命令搞定：

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" \
  --codex-home "$CODEX_DIR" --compact unify --provider shared
```

它按顺序做四件事：

1. 备份 `config.toml` 和所有 `*.config.toml` 到 `backups/unify-<时间戳>/`
2. 把每个文件的 `model_provider` 和 `[model_providers.X]` 表名统一成 `shared`。
   表里的 `base_url`、`env_key`、`name` **原样保留** —— 各服务商仍走自己的端点和密钥变量，
   注释和排版也不动。改写后必须能被 TOML 正确解析、且原有字段一字不差，否则整体报错退出。
3. 深度迁移所有历史 session（等价于 `switch --deep`）
4. 复审，报告每个文件的原 id、迁移条数、两个备份路径

没有 `[model_providers.*]` 表的 config（只有 `model` 加 `[projects]` 那种）说明它用的是内置
`openai` provider，`unify` 会补一份等价的表：`base_url = "https://chatgpt.com/backend-api/codex"`
加 `requires_openai_auth = true`，认证仍读 `auth.json`，官方 ChatGPT 登录态不受影响。

内置 `openai` 是保留 id 不能覆盖，所以目标 id 必须是自定义名（默认 `shared`）；传
`--provider openai` 会被直接拒绝。

**不要只改 config 不迁移历史** —— 旧会话还挂在原 id 名下，结果是三方都看到 0 条。`unify`
把两步绑在一起就是为了避免这个。

想自己改配置的话，模板是这样（三个文件都改，`[model_providers.shared]` 里各自填自己的端点）：

```toml
model_provider = "shared"

[model_providers.shared]
name = "..."                    # 随意,不参与过滤
base_url = "..."                # 各服务商不同
wire_api = "responses"
requires_openai_auth = true
env_key = "..."                 # 各服务商不同;官方通道不写这行
```

改完再跑 `switch --provider shared --deep`。

#### provider 会"漂回去"：必须用 `--deep`

rollout 文件里记 provider 的地方不止一处：

- 首行 `session_meta.payload.model_provider`
- **重复出现的第二个 `session_meta`**
- `event_msg.payload.thread_settings.model_provider_id`（一个文件里可能出现几十上百次）

Codex 重建索引时读的是后两者，所以只改首行的话，下一次 reindex 就会把数据库写回旧 provider。
想让 provider 变更持久，就得加 `--deep`：

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" \
  --codex-home "$CODEX_DIR" --compact switch --provider shared --deep
```

`--deep` 是整文件重写（不是只换首行），所以每一条改动行的 before/after 都进 manifest，
`rollback` 能逐字节还原。已在 3 MB 的真实会话文件上验证过：改动仅限 provider 字段，
回滚后与原文件 sha256 完全一致。

#### 跳过正在写入的会话

正在运行的 Codex 会话会持续往自己的 rollout 文件追加内容。改写走的是临时文件加 rename，
审计与 rename 之间落下的追加会丢失，所以 `switch` 检测到文件变动就会整体拒绝执行。等那个会话
结束再跑即可；不想等就用 `--skip-live`：

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" \
  --codex-home "$CODEX_DIR" --compact switch --provider shared --skip-live
```

活跃文件会被原样跳过（保留旧 provider），其余全部照常迁移，跳过的路径列在返回的
`deferred_live_sessions` 里，同时在 `session_guard_state.json` 记下条数，避免下一次运行被误判成
no-op。那些会话退出后再跑一次即可收尾。

### 清理孤儿行

在 Codex 之外删除 rollout 文件会留下指向空路径的数据库行。这类行会让 `switch` 与 `repair`
全部拒绝执行，而 provider 同步无法修复它们：

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" \
  --codex-home "$CODEX_DIR" --compact prune
```

只有记录路径在磁盘上确实不存在的行才会被删除；文件仍在的行会让命令直接失败退出。删除前
会完整备份数据库，并把整行（含未审计的列）写入 manifest，因此 `rollback` 可以逐字段还原。

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

### 1. 源端导出

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" \
  --codex-home "$CODEX_DIR" export /path/to/bundle
```

导出前会先审计，有完整性问题时直接拒绝。bundle 内含 `sessions/`、`archived_sessions/`、
`session_index.jsonl`，以及通过 SQLite backup API 得到的一致数据库快照，另有 `bundle.json`
记录每个文件的 SHA-256。

**不会包含**：`auth.json`、API key、token、源端 `config.toml`、项目代码与数据集。目标机器必须
用它自己的凭据登录；复制源端 `config.toml` 会把新机器指向它可能无权使用的 relay。

### 2. 传输

用任意方式复制整个 bundle 目录（`rsync -a`、`tar` + `scp` 等）。bundle 内不含凭据，但仍包含
完整对话历史，按敏感数据对待。

### 3. 目标端导入

目标 home 必须已有自己的 `config.toml`，且**不能**已有 session：

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" \
  --codex-home "$CODEX_DIR" --compact import /path/to/bundle
```

导入会逐文件校验 SHA-256（任何一个字节不符即在写入前中止），安装 session 与数据库快照，把
数据库中记录的源端绝对路径改写到本机 home，然后完整审计。改写只在译出的路径确实指向本 home
内的真实文件时才保留。归档状态、session 名称、历史 model 全部原样保留。

导入后如需把 session 同步到本机 provider，再跑一次 `switch`（可带 `--profile`）。

只想检查 bundle 而不写入任何东西：

```bash
python3 "$SKILL_DIR/scripts/session_guard.py" verify /path/to/bundle
```

如果目标 Codex home 已经包含 session，`import` 会拒绝执行。当前版本不实现两个非空
SQLite/JSONL 状态的自动合并；直接覆盖会有数据丢失风险。


## 数据范围

工具只读取 session 索引、SQLite thread 元数据、rollout JSONL 首条 `session_meta` 记录，以及
`config.toml` 中用于识别 provider/relay 的非秘密字段。备份目录默认位于：

```text
$CODEX_HOME/backups/session-guard-<UTC timestamp>/
```

备份包含 SQLite 快照、变更 manifest 和必要的首行 before/after 数据，不包含凭据。

## 已知限制

- Codex 自身可能在 picker/resume 启动后重新索引 provider、model 或时间字段；需要以之后的新审计
  结果为准。默认（不带 `--deep`）的 `switch` 只改首行，因此这种重新索引会把 provider 漂回旧值；
  想持久生效必须用 `--deep`。
- `unify` 改写 config 用的是行级正则（为了保住注释和排版），只认写在顶层的
  `model_provider = "..."` 单行形式；写成多行数组或用其他等价 TOML 写法时不会被识别，
  此时会在第一个表头前新插一行。改写后一定会用 TOML 解析校验，不会留下坏配置。
- 工具不自动 unarchive session。
- 工具不强行恢复歧义名称。
- 工具不执行两个非空 Codex home 的 schema-aware merge。
- `prune` 只处理"行存在、文件不存在"；反向的 `unindexed_rollout_files`（文件存在、行不存在）
  需要 Codex 自己重新索引。
- 迁移假定源端与目标端 Codex 版本的 `threads` schema 兼容；跨大版本迁移前应先在两端各跑一次
  `audit` 比对 `schema_columns`。
- 常规成功恢复不会自动打开 picker 或逐个 resume UUID；需要端到端 UI 验证时应明确执行。

## 自检

```bash
python3 scripts/test_session_guard.py     # session 修复
python3 scripts/test_provision_codex.py   # 新机器搭建
```

`test_session_guard.py` 完全在临时目录中运行，覆盖 audit、switch、rename、relay fingerprint、
rollback、恶意 manifest 越界路径拒绝，以及 profile 叠加与继承、per-profile fingerprint、prune
与其回滚、bundle 导出/校验/导入、凭据排除、非空目标拒绝和 bundle 篡改检测。

新增覆盖：`--skip-live`（真起一个持续追加的写入进程，断言活跃文件保留旧 provider、其余照常迁移、
写入方退出后重跑收尾）、`--deep`（重复 `session_meta` 加多条 `thread_settings` 的 fixture，断言
provider 全部清干净、非 provider 字段与非 ASCII 内容逐字节不变、回滚逐行还原）、`unify`
（带注释 / 无 provider 表 / 顶层键插入位置三种 config，断言 `base_url` 与 `env_key` 未被改动、
注释保留、`[projects]` 没有吞掉新键、重跑是 no-op、保留 id `openai` 被拒绝）。

`test_provision_codex.py` 11 项，同样只在临时目录里跑，断言 `plan` 不写文件、生成的 config 与
`.bashrc` 里不含密钥值、重跑幂等且包装函数不重复、保留 id 与 `CODEX_API_KEY` 被拒绝、缺 key
文件只报 gap、权限过松的 key 文件被标记。其中两条是回归测试：`$HOME/.codex` 已指向别处时必须
拒绝而不是抢占（早期版本会直接重指，测试中曾误伤真实软链接）；写在 `[[providers]]` 之后的顶层键
在 TOML 里属于该块，必须报错而不是被当成 provider 配置写进去。

## 仓库结构

```text
.
├── SKILL.md
├── agents/openai.yaml
├── reference/
│   └── spec.example.toml          # 新机器 spec 模板（只含路径，不含密钥）
└── scripts/
    ├── provision_codex.py         # 搭建：profile / 包装函数 / 权限 / 软链接
    ├── test_provision_codex.py
    ├── session_guard.py           # 修复：audit / switch / unify / migrate / rollback
    └── test_session_guard.py
```

## License

[MIT](LICENSE)
