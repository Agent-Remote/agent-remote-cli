# agent-remote-cli

[English](README.md) | 中文

agent-remote 本地设备管理的 Rust CLI。

该包提供 `agent-remote` 命令。`fclaude` 等工具专用启动器会刻意保持独立，确保常规 `claude` 使用不受影响。

## 命令

```sh
agent-remote init
agent-remote login --server-url https://agent-remote.example.com --username alice
agent-remote status
agent-remote doctor --fix
agent-remote deps status
agent-remote wireguard config
agent-remote wireguard check
agent-remote sync ensure
agent-remote sync status
agent-remote account create --tool claude --name "Claude US" --region US --timezone America/Los_Angeles --tag us
agent-remote account list
agent-remote account bind <account-id>
agent-remote account verify <account-id>
agent-remote account status <account-id>
agent-remote ssh check --session-id <session-id>
agent-remote attach --session-id <session-id> --print-only
agent-remote logout
```

`agent-remote init` 是推荐的首次运行路径。它会引导用户完成：

- 选择控制平面 API URL
- 使用已有 agent-remote 用户账户登录
- 注册本地设备和 SSH 公钥
- 检查托管的外部依赖
- 在可用时获取默认 WireGuard 配置

CLI 初始化流程不会创建用户。服务器完成 bootstrap 后，管理员应从管理控制台创建普通用户。

`agent-remote login` 会在可用时把 token 保存到平台凭据存储：

- macOS：通过 `security` 命令使用 Keychain
- Linux：通过 `secret-tool` 使用 Secret Service

如果系统凭据存储不可用，CLI 会回退到 agent-remote home 目录下仅所有者可访问的文件。SQLite 只保存本地元数据，绝不会保存 access token 或工具账户登录状态。

## 本地路径

默认情况下 CLI 使用：

```text
~/.config/agent-remote/
```

测试或自定义安装时可以覆盖：

```sh
AGENT_REMOTE_HOME=/path/to/state agent-remote doctor --fix
```

托管外部依赖预期位于：

```text
~/.config/agent-remote/bin/
~/.config/agent-remote/dependencies/manifest.json
```

四个发行目标都会内置托管的 `mutagen`、`tmux`、`wg` 和 `wg-quick`；macOS 包还会内置 `wireguard-go`。

当前实现会记录并检查 Mutagen 和 WireGuard helper 的 manifest。发布包会为每个支持的平台包含托管 Mutagen 二进制和 WireGuard helper。

## WireGuard 和 SSH

`agent-remote wireguard config` 会生成或复用本地 X25519 私钥，将其保存在系统凭据存储中（失败时回退到权限为 `0600` 的文件），只向控制平面登记公钥，并以 `0600` 权限写入本地 agent-remote home 下的 `wireguard/agent-remote.conf`。重复执行该命令可以自动修复注册时缺少 WireGuard peer 的设备；私钥绝不会发送到服务端。

`agent-remote wireguard check|up|down` 会调用托管的 `agent-remote-wireguard` helper，并支持用于诊断的 `--dry-run`。四个平台的 CLI 发行包都会内置 `wg`、`wg-quick` 和 `tmux`；macOS 包还会内置所需的 `wireguard-go` userspace backend。helper 会直接使用这些托管二进制，不依赖 Homebrew 或其他系统包。启用隧道可能需要 `sudo`。

`agent-remote attach --session-id <id>` 会向控制平面请求会话级 SSH 授权，在节点上调度 SSH key 同步，然后使用本地 `ssh` 执行节点侧 forced command。

## Workspace 同步

`agent-remote sync ensure` 会识别当前目录，在创建新的远端同步关系前询问用户，向控制平面注册 workspace，创建 sync session，并启动托管 Mutagen session。

启动 Mutagen 前，CLI 会等待节点完成远端 workspace 准备。托管同步 session 使用目录模式 `0770` 和文件模式 `0660`，让账户专属 Native Runtime 身份可以访问 workspace，同时不向其他用户开放。

常用命令：

```sh
agent-remote sync ensure --yes
agent-remote sync status --fail-on-conflict
agent-remote sync pause
agent-remote sync resume
agent-remote sync resolve
agent-remote sync reset
```

CLI 会使用 agent-remote home 中托管的 `bin/mutagen`，或使用同级打包二进制。项目 workspace 默认启用 `.git` 同步，同时排除 lock 文件、hooks、worktrees 以及常见构建/缓存目录。

## 工具账户

`agent-remote account create` 会创建包含地区、时区、locale 和首选节点标签的远端工具账户记录。控制平面会把每个账户固定到可用 runtime backend；客户端会展示该 backend，但不能静默切换。`agent-remote account bind` 会请求控制平面在选定节点上创建临时远端 tmux 登录 session；登录完成后，`agent-remote account verify` 会调度 verifier 任务。CLI 只保存 agent-remote 设备 token；工具登录状态保留在远端节点账户归档中。

`fclaude` 在创建或恢复 session 时会显示选定的 runtime backend。如果控制平面把丢失的 Native Runtime session 对账为 `interrupted`，`fclaude` 会创建有关联关系的 replacement session，而不会 attach 到失效资源或重放之前的命令。

## 开发

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

或者：

```sh
scripts/run-quality-checks.sh
```

## 发布打包

构建 macOS 和 Linux CLI 归档：

```sh
VERSION=0.0.4-fix.1 scripts/package-release.sh
```

发布归档包含：

- `agent-remote`
- `fclaude`
- `agent-remote-wireguard`
- 托管 `mutagen`
- dependency manifest 和第三方声明

打包文件应安装到 agent-remote home，或由平台安装器放到 `PATH` 中。

GitHub Actions 会在 `v*` tag 上运行相同打包流程，并把归档上传到 GitHub Release。

直接安装最新 release：

```sh
curl -fsSL https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.sh | bash
```

安装指定版本或自定义路径：

```sh
curl -fsSL https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.sh | \
  bash -s -- --version 0.0.4-fix.1 --home ~/.config/agent-remote --bin-dir ~/.local/bin
```

安装已下载的发布归档：

```sh
./install.sh
```

安装器会把托管二进制复制到 `AGENT_REMOTE_HOME/bin`，写入 dependency manifest，并默认把 `agent-remote`、`fclaude` 和 `agent-remote-wireguard` 链接到 `~/.local/bin`。它也可以覆盖 GitHub 仓库、版本、target、OS、架构、home 目录、链接目录，以及 symlink/copy 行为。

## 许可证

agent-remote-cli 使用 GPL-3.0-only 许可证。详见 `LICENSE`。

第三方依赖声明见 `THIRD_PARTY_NOTICES.md`。
