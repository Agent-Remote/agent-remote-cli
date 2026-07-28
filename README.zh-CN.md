# agent-remote-cli

<p align="center"><img src="assets/agent-remote-icon.svg" alt="Agent Remote 图标" width="80" height="80"></p>

<p align="center">
  <a href="https://github.com/Agent-Remote/agent-remote-cli/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Agent-Remote/agent-remote-cli/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://codecov.io/gh/Agent-Remote/agent-remote-cli"><img alt="Codecov" src="https://codecov.io/gh/Agent-Remote/agent-remote-cli/graph/badge.svg"></a>
  <a href="https://github.com/Agent-Remote/agent-remote-cli/stargazers"><img alt="GitHub Stars" src="https://img.shields.io/github/stars/Agent-Remote/agent-remote-cli?style=flat&logo=github"></a>
  <img alt="Rust 2021" src="https://img.shields.io/badge/Rust-2021-000000?logo=rust&logoColor=white">
  <a href="LICENSE"><img alt="License: GPL-3.0" src="https://img.shields.io/github/license/Agent-Remote/agent-remote-cli"></a>
</p>

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
agent-remote attach <session-id> --print-only
agent-remote logout [--no-revoke-remote]
```

每个命令和嵌套命令都提供 `--help`。运行时输出支持
`--color auto|always|never`；`auto` 同时遵循 `NO_COLOR` 和 `TERM=dumb`。
错误、警告、成功操作、分区标题、详情和状态表格使用统一的终端样式。

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
- Windows：通过原生 Win32 API 使用 Windows 凭据管理器

如果系统凭据存储不可用，CLI 会回退到 agent-remote home 目录下仅所有者可访问的文件。SQLite 只保存本地元数据，绝不会保存 access token 或工具账户登录状态。

## 本地路径

macOS 和 Linux 默认使用 `~/.config/agent-remote/`，Windows 默认使用
`%LOCALAPPDATA%\agent-remote\`：

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

四个 macOS/Linux 发行目标都会内置托管的 `mutagen`、`tmux`、`wg`、`wg-quick`，以及负责受管主机验证的 SSH/SCP 包装器；macOS 包还会内置 `wireguard-go`。Windows x64 和 ARM64 包内置原生 CLI、Mutagen、兼容用的 `ssh.exe` 和 `scp.exe` 代理，以及对应架构的官方 WireGuard for Windows MSI。该 MSI 提供 Windows 上与 `wg`、`wg-quick` 和隧道后端等价的 tunnel manager、`wg.exe` 与 Wintun 驱动。`tmux` 运行在远端 Linux 节点上，在 Windows 客户端没有原生用途。

当前实现会记录并检查 Mutagen 和 WireGuard helper 的 manifest。发布包会为每个支持的平台包含托管 Mutagen 二进制和 WireGuard helper。

## WireGuard 和 SSH

`agent-remote wireguard config` 会生成或复用本地 X25519 私钥，将其保存在系统凭据存储中（失败时回退到权限为 `0600` 的文件），只向控制平面登记公钥，并写入本地 agent-remote home 下的 `wireguard/agent-remote.conf`。生成的隧道固定使用 `1380` MTU，避免实际路径 MTU 低于 WireGuard 平台默认值时 SSH 密钥交换被静默卡住。该配置在 Unix 上使用 `0600` 权限；在 Windows 上仅允许当前用户完全控制，并允许 WireGuard 的 `LocalSystem` 隧道服务读取。重复执行该命令可以自动修复注册时缺少 WireGuard peer 的设备；私钥绝不会发送到服务端。

`agent-remote wireguard check|up|down` 会调用托管的 `agent-remote-wireguard` helper，并支持用于诊断的 `--dry-run`。macOS 和 Linux 发布包提供所需的托管 WireGuard 工具；Windows 发布包内置官方 WireGuard for Windows MSI，helper 使用 `/installtunnelservice` 和 `/uninstalltunnelservice` 控制其 tunnel service，变更隧道时需要在管理员终端中运行。

`agent-remote attach <id>` 会向控制平面请求会话级 SSH 授权，等待节点完成设备级 SSH key 同步（最长 30 秒），然后使用本地 `ssh` 执行节点侧 forced command。Windows 使用系统的 OpenSSH Client 可选功能。旧的 `--session-id <id>` 写法仍然兼容。

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

CLI 会使用 agent-remote home 中托管的 `bin/mutagen`，或使用同级打包二进制。Mutagen 和直接 attach 的 SSH 连接都使用 agent-remote 独立管理的 `known_hosts`；新的 WireGuard 节点密钥会被自动信任，已记录密钥发生变化时仍会拒绝连接。升级引入新的受管 SSH 环境后，CLI 会重启一次 Mutagen daemon，使其继承受管代理路径。项目 workspace 默认启用 `.git` 同步，同时排除各端独立的 Git index、lock 文件、hooks、worktrees 以及常见构建/缓存目录。Mutagen 创建后会先完成一次初始 flush，远端 runtime 再基于完整 workspace 建立自己的 Git index。当控制面同步关系仍为 active、但本地 Mutagen session 已丢失时，`sync ensure` 会自动重建本地 session。

## 工具账户

`agent-remote account create` 会创建包含地区、时区、locale 和首选节点标签的远端工具账户记录。控制平面会把每个账户固定到可用 runtime backend；客户端会展示该 backend，但不能静默切换。`agent-remote account bind` 会请求控制平面在选定节点上创建临时远端 tmux 登录 session；登录完成后，`agent-remote account verify` 会调度 verifier 任务。CLI 只保存 agent-remote 设备 token；工具登录状态保留在远端节点账户归档中。

`fclaude` 在创建或恢复 session 时会显示选定的 runtime backend。如果控制平面把丢失的 Native Runtime session 对账为 `interrupted`，`fclaude` 会创建有关联关系的 replacement session，而不会 attach 到失效资源或重放之前的命令。

`fclaude list` 默认输出按空格对齐的紧凑表格，session 和 node ID 缩短为 12 位，并从左侧省略过长的工作目录以保留项目名。使用 `fclaude list --no-trunc` 可查看完整值。列表中的短 session ID 可直接传给 `fclaude attach <id>`、`fclaude stop <id>` 或 `fclaude delete <id>`；如果前缀不唯一，命令会拒绝执行。删除仅允许用于 stopped 或 interrupted session；`fclaude delete --all` 会一键删除当前用户处于这两种状态的全部 session。

`agent-remote account list` 和 `agent-remote credentials list` 使用相同的紧凑 ID 规则，并支持 `--no-trunc`。显示出的 account 和 credential profile 短 ID 可直接用于账户绑定、状态查询、配置导入、默认账户选择和凭据绑定等操作。`fclaude --account-id <id>` 同样接受账户短 ID。前缀至少需要 4 个十六进制字符，并且必须唯一匹配一条记录。

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
VERSION=0.0.5-fix.7 scripts/package-release.sh
```

在 Windows PowerShell 中构建 Windows x64 归档（ARM64 可传入 `-Target aarch64-pc-windows-msvc`）：

```powershell
./scripts/package-release.ps1 -Version 0.0.5-fix.7
```

发布归档包含：

- `agent-remote`
- `fclaude`
- `agent-remote-wireguard`
- 托管 `mutagen`
- dependency manifest 和第三方声明

打包文件应安装到 agent-remote home，或由平台安装器放到 `PATH` 中。

GitHub Actions 会在 `v*` tag 上运行相同打包流程，并把归档上传到 GitHub Release。`install-smoke` workflow 还会在 Windows、Linux 和 macOS 原生 runner 的隔离目录中构建并安装发布包，检查所有 manifest 校验和与依赖文件，并实际执行安装后的 CLI。在 Windows 上，该流程还会安装发布包内的 WireGuard MSI，并验证其命令行入口和 `agent-remote-wireguard` 集成。

直接安装最新 release：

```sh
curl -fsSL https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.sh | bash
```

安装指定版本或自定义路径：

```sh
curl -fsSL https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.sh | \
  bash -s -- --version 0.0.5-fix.7 --home ~/.config/agent-remote --bin-dir ~/.local/bin
```

安装已下载的发布归档：

```sh
./install.sh
```

在 x64 或 ARM64 Windows PowerShell 中安装：

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.ps1 -OutFile install.ps1
.\install.ps1 -InstallPrerequisites
```

`-InstallPrerequisites` 会在缺失时安装 Windows OpenSSH Client 可选功能和发布包内置的官方 WireGuard，可能需要管理员 PowerShell。WireGuard 安装不再依赖 `winget` 或额外联网下载；两者已经安装时可省略。升级时，安装器会检测从受管安装目录运行的 Mutagen daemon，在替换被锁定的可执行文件前停止它，并在完成后重新启动；其他 Mutagen 安装不会被停止。安装器会把 `%LOCALAPPDATA%\agent-remote\bin` 加入用户 `PATH`，安装后请打开新终端。

安装器会把托管二进制复制到 `AGENT_REMOTE_HOME/bin`，写入 dependency manifest，并默认把 `agent-remote`、`fclaude` 和 `agent-remote-wireguard` 链接到 `~/.local/bin`。它也可以覆盖 GitHub 仓库、版本、target、OS、架构、home 目录、链接目录，以及 symlink/copy 行为。

## 许可证

agent-remote-cli 使用 GPL-3.0-only 许可证。详见 `LICENSE`。

第三方依赖声明见 `THIRD_PARTY_NOTICES.md`。
