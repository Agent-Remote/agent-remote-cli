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
agent-remote wireguard status
agent-remote sync ensure
agent-remote sync status
agent-remote account create --tool claude --name "Claude US" --region US --timezone America/Los_Angeles --tag us
agent-remote account list
agent-remote account bind <account-id>
agent-remote account verify <account-id>
agent-remote account status <account-id>
agent-remote ssh check --session-id <session-id>
agent-remote attach <session-id> --print-only
agent-remote node install --node <node-id-or-prefix> [--enable-ego-browser] [--yes]
agent-remote device install --source "/path/to/agent-remote-device-macos-0.2.12.zip"
agent-remote device uninstall [--yes]
agent-remote device status
agent-remote device diagnose
agent-remote device revoke [--device <device-id>] [--yes]
agent-remote device rotate-token [--yes]
agent-remote ego-browser setup
agent-remote ego-browser connect [<tool-session-id-or-prefix>]
agent-remote ego-browser status [<binding-id>]
agent-remote ego-browser repair|upgrade
agent-remote ego-browser pause|resume|stop [<binding-id>] [--binding-generation <generation>]
agent-remote ego-browser remove
agent-remote ego-browser forget-this-mac
agent-remote ego-browser register --signer-certificate-sha256 HEX [--server-url URL] # 高级兼容入口
agent-remote ego-browser requests <binding-id>
agent-remote ego-browser cancel-request <binding-id> <request-ledger-id> [--yes]
agent-remote ego-browser revoke [<binding-id>] [--binding-generation <generation>] [--yes]
agent-remote ego-browser delete-binding <binding-id> [--yes]
agent-remote ego-browser delete-device <device-id> [--yes]
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

Server 支持 CLI 登录会话时，用户命令会将仍有效的旧登录迁移为可续期会话，自动轮换短期
访问令牌。会话默认最长 30 天；过期、撤销或账号禁用后才需要重新登录。两种凭据都保存在
凭据存储中，注销会撤销会话。普通设备登记也会保留浏览器管理需要的用户登录。旧版 Server
继续使用原有短期登录行为。浏览器 connect/resume 的 full-trust 确认仍然单独执行。

- macOS：通过 `security` 命令使用 Keychain
- Linux：通过 `secret-tool` 使用 Secret Service
- Windows：通过原生 Win32 API 使用 Windows 凭据管理器

当配置的服务器和当前设备注册均未变化时，重新执行 `agent-remote login` 会复用该设备，
更新设备元数据和 SSH 公钥，并替换设备 token。只有本地未配置 active device 时才会注册新设备，
从而保证 CLI 升级前后已有 workspace 仍绑定同一设备。

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

## 本地设备控制

`agent-remote device install` 接受显式指定的本地发布 ZIP 压缩包，或名称固定为 `Agent Remote Device.app` 的 app bundle。CLI 会限制并校验 ZIP 的大小和成员路径，将其复制到私有临时目录后自动解压；压缩包根目录只能包含该固定 app bundle。community 正式 CLI 随后会在暂存前后验证固定 bundle identifier、编译进 CLI 的项目自签名证书指纹、由同一身份签名的 Network Broker 与 GUI Executor XPC service，以及完整代码签名；只对已验证的暂存 bundle 移除 quarantine，并原子安装到 `~/Applications/Agent Remote Device.app`。允许重装相同语义版本和升级；拒绝降级，以及缺少版本或版本格式无效的 bundle。该命令不会下载或执行项目内容或 API 响应提供的安装地址。community 构建只从受保护的 `production-community-release` 环境取得证书指纹，并将 Gatekeeper 状态显示为 `manual trust`，不会声称已经 Apple 公证。

`agent-remote device status` 显示已安装版本、签名、XPC 和进程状态；`agent-remote device diagnose` 执行相同的严格检查，安装不可信时返回非零状态。`agent-remote device uninstall` 要求 app 已停止，删除固定 app bundle、共享 Broker 凭据、TCC 授权及各 bundle 自有的沙盒数据，但不会撤销远端注册；存在隐藏应用恢复日志时会拒绝继续。`agent-remote device revoke` 要求本地已保存用户 token，未指定 `--yes` 时先确认，通过控制平面撤销指定或当前设备，并删除对应的本地设备凭据与刷新状态。`agent-remote device rotate-token` 只轮换当前 active device，通过控制面取得新令牌后不会打印令牌，并立即覆盖本机平台凭据和共享 Network Broker 凭据；执行前必须先停止活动的设备控制 session。

## Node Enrollment

`agent-remote node install --node <node-id-or-prefix>` 会先在控制工作站验证固定 Node release 的
checksum 与 Sigstore workflow identity，再通过独立 SSH stdin 传输归档并运行暂存 installer；
只有安装成功后才向控制面申请短期加入码。加入码使用另一次 SSH stdin，不会进入 argv、环境
变量、URL、日志或终端输出。重试可以复用字节完全相同的暂存归档，但签发加入码前始终重新运行
installer。固定的 `0.2.23` release 只有在 tag-bound 制品与 Sigstore evidence 完整时才会被接受。

## Ego Browser Bridge 控制

普通流程先运行 `agent-remote ego-browser setup`；准备连接时，再运行 `agent-remote ego-browser connect` 选择并授权一个远端 session。`setup` 复用 `agent-remote login` 保存的服务器与凭据，自动发现已验证 release profile 和证书 pin，确保复用现有 Device identity，且不会自动 claim session。普通使用不需要输入 Server URL、registration token、Device ID 或证书摘要。

运行 `setup`、`repair` 或 `upgrade` 时，会先暂停本机已有的可执行绑定，再重启 Bridge，并保留恢复所需的 generation。存在暂停绑定时，按提示运行 `resume`；没有时再运行 `connect`。暂停失败会阻止安装继续。重复执行 `claim` 或 `connect` 会先检查保留的绑定，再决定是否修改本机执行入口；已有连接保持可用，暂停绑定提示 `resume`。若服务端显示 active 但本机入口关闭，`status` 会提示先 `pause` 对应绑定，再执行 `resume`。高级 `register` 命令要求通过参数或 `EGO_BROWSER_SIGNER_CERTIFICATE_SHA256` 提供已核验的 64 位十六进制证书摘要；缺少或格式错误时，在读取登录凭据前即返回 `signer_certificate_required` 或 `signer_certificate_invalid`，文本和 JSON 使用相同错误码。

已有验证安装时，`setup` 与 `repair` 只运行该 current release 的 owner-only installer，绝不
隐式升级。缺少安装或显式执行 `upgrade` 时使用由 commit 与 SHA-256 固定的 bootstrap；它只能
请求 `release-dependencies.json` 指定的 Bridge 版本、仓库、profile 和签名证书，且不会收到 Server URL、
token、session ID 或 full-trust claim。缺少或无效的 release asset 与 Sigstore evidence
都会 fail closed。

`repair` 通过 Device Client 暂停绑定并保存新的本机 handoff 代次。生命周期恢复仅在
绑定、设备、工具会话均一致时使用服务器的新代次；显式指定的过期代次仍会被拒绝。

安装后，`upgrade` 会显式重新登记保留的设备，更新 Server 上的发布元数据，保留设备 ID、
generation 与密钥。Server 必须支持规范接口的同身份重新登记；普通 `setup` 和 `repair`
不能更新发布元数据。

本机信任以 owner-only 文件绑定准确的 profile ID、profile version、Bridge version 与证书 pin。
例行 `repair` 在四项完全匹配时无需 `--yes`；首次使用或任一项变化都重新确认，非交互调用若未
显式传入 `--yes` 则返回 `trust_confirmation_required`。

`connect` 与 `resume` 会显示全信任警告并要求明确确认。`pause` 可恢复：它保留 paused binding，之后经再次确认的 `resume` 推进到新的 binding generation。`stop` 是终态，之后必须重新 `connect`。省略 ID 时，这些生命周期命令只会使用 active handoff 或唯一候选；无法唯一解析时会 fail closed，不会猜测。浏览器脚本以当前 macOS 用户身份在无 App Sandbox 的环境中运行，可以访问文件、网络、登录数据、子进程以及任意 ego lite Tab 或 Task Space；取消只能终止受监管执行，无法回滚副作用，也不能保证清理主动脱离监管的进程。

`register`、显式 `--server-url` 与 `--signer-certificate-sha256` 仅作为自定义或旧版 release 的高级兼容入口保留。`register` 仍通过 stdin 将保存的 token 传给 Device Client，因此不会出现在进程参数或 CLI 输出中。`status` 显示本地 Bridge 设备与 binding；`status <binding>` 还会显示该 binding 的活动 request。`requests <binding>` 会刷新活动 request ledger，`cancel-request <binding> <request-ledger-id>` 只停止这一条准确执行，不会使整个 binding 失效。binding、request、claim session 和删除命令的 ID 都支持唯一十六进制前缀；`--no-trunc` 显示完整 ID。`delete-binding` 会在 binding 进入终态且撤销通知投递完成后永久删除 binding 及其请求账本；`delete-device` 会在设备已撤销且其全部 binding 历史已删除后永久删除设备。两个删除命令默认要求确认，使用 `--yes` 可跳过确认。

设备尚未撤销或 binding 尚未进入终态时，删除命令返回 `device_not_revoked` 或
`binding_not_terminal` 及对应恢复操作，`--yes` 不会绕过这些条件。身份操作被拒绝时报告实际
本地准入状态，不关闭准入；未经核实的连接和可用性字段保持 `null`。

全局添加 `--json` 可获得机器可读的生命周期输出。成功变更、status、binding 列表和 request
列表都只输出一个 JSON 文档；JSON 模式不会提示输入或猜测候选。该投影明确排除 credential、
private key、脚本、页面数据、Cookie、URL 和 relay ciphertext。

## WireGuard 和 SSH

`agent-remote wireguard config` 会生成或复用本地 X25519 私钥，将其保存在系统凭据存储中（失败时回退到权限为 `0600` 的文件），只向控制平面登记公钥，并写入本地 agent-remote home 下的 `wireguard/agent-remote.conf`。生成的隧道固定使用 `1000` MTU，避免实际路径 MTU 低于 WireGuard 平台默认值时 SSH 密钥交换被静默卡住。该配置在 Unix 上使用 `0600` 权限；在 Windows 上仅允许当前用户完全控制，并允许 WireGuard 的 `LocalSystem` 隧道服务读取。重复执行该命令可以自动修复注册时缺少 WireGuard peer 的设备；私钥绝不会发送到服务端。

`agent-remote wireguard check|up|down` 会调用托管的 `agent-remote-wireguard` helper，并支持用于诊断的 `--dry-run`。`agent-remote wireguard status` 会显示 `wg show` 报告的活动接口和 peer 运行状态，包括 endpoint、最近握手、传输计数和 keepalive 设置；macOS 和 Linux 上的非特权查询被内核拒绝时，会自动通过 `sudo` 重试。macOS 和 Linux 发布包提供所需的托管 WireGuard 工具；Windows 发布包内置官方 WireGuard for Windows MSI，helper 使用 `/installtunnelservice` 和 `/uninstalltunnelservice` 控制其 tunnel service，`status`、`up` 和 `down` 会在需要时通过 UAC 确认框自动请求管理员权限。

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

## Session 端口转发

把一个 Native session 的 loopback TCP 端口转发到当前设备，而不发布 Node 或容器端口：

```sh
agent-remote forward 5173 --session <session-id> --local-port auto --open
fclaude forward 3000
agent-remote forward list
agent-remote forward stop <forward-id>
agent-remote forward stop --session <session-id> --all
```

本地 listener 只绑定 `127.0.0.1`，系统支持时同时绑定 `::1`。默认本地端口与远端相同；端口占用时使用 `--local-port auto`。一条受限 SSH stdio 隧道可多路复用 HTTP、WebSocket/HMR、SSE、gRPC 和普通 TCP 连接。OpenSSH `-L/-R/-D/-W`、任意目标、公网 bind 和 token 持久化继续保持关闭。隧道断开后 CLI 会申请新的一次性 token 并在保留本地 listener 的同时重连，但不会重放已有 stream。

远端应用应监听 runtime loopback，例如 `npm run dev -- --host 127.0.0.1`。当前发布只支持 Native Runtime session；Docker Sandbox session 会返回明确的 capability 错误。

## 工具账户

`agent-remote account create` 会创建包含地区、时区、locale 和首选节点标签的远端工具账户记录。控制平面会把每个账户固定到可用 runtime backend；客户端会展示该 backend，但不能静默切换。`agent-remote account bind` 会请求控制平面在选定节点上创建临时远端 tmux 登录 session；登录完成后，`agent-remote account verify` 会调度 verifier 任务。CLI 只保存 agent-remote 设备 token；工具登录状态保留在远端节点账户归档中。

`fclaude` 在创建或恢复 session 时会显示选定的 runtime backend。如果控制平面把丢失的 Native Runtime session 对账为 `interrupted`，`fclaude` 会创建有关联关系的 replacement session，而不会 attach 到失效资源或重放之前的命令。

`fclaude list` 默认输出按空格对齐的紧凑表格，session 和 node ID 缩短为 12 位，并从左侧省略过长的工作目录以保留项目名。使用 `fclaude list --no-trunc` 可查看完整值。列表中的短 session ID 可直接传给 `fclaude attach <id>`、`fclaude stop <id>` 或 `fclaude delete <id>`；如果前缀不唯一，命令会拒绝执行。删除仅允许用于 stopped、interrupted 或 failed session；`fclaude delete --all` 会一键删除当前用户处于这三种状态的全部 session。 受管会话的 Skill 内容尚未完整保留时，单个和批量删除均返回 `STATE_PENDING`。保留 Node 上的数据，使用 `fclaude stop-status <operation-id> --wait` 观察保存进度后再重试删除。

`agent-remote account list` 和 `agent-remote credentials list` 使用相同的紧凑 ID 规则，并支持 `--no-trunc`。显示出的 account 和 credential profile 短 ID 可直接用于账户绑定、状态查询、配置导入、默认账户选择和凭据绑定等操作。`fclaude --account-id <id>` 同样接受账户短 ID。前缀至少需要 4 个十六进制字符，并且必须唯一匹配一条记录。

`agent-remote account import-config --account <id>` 会等待目标节点完成已接受 Claude 配置的写入；任务失败、取消、过期或 120 秒内未进入终态时，命令以非零状态退出。超时信息会保留 task ID，因为本地停止等待后远端任务仍可能继续完成。可先用 `--dry-run` 预览路径；只有明确需要导入提示词、transcript 和本地路径时才使用 `--include-resume-history`。添加 `--exclude-skills` 可在读取和打包前排除 `~/.claude/skills`，继续迁移其他配置；插件内容和项目历史仍按原选择规则处理，该选项本身不会启用受管目录模式。

`connect` 支持 `fclaude list` 显示的 12 位会话 ID、唯一十六进制前缀或完整 UUID，大小写不敏感；前缀有歧义时需提供更完整的 ID。生命周期命令被拒绝时报告实际读取的本地准入状态，未观测到的连接状态在 JSON 中保持 `null`。`request_not_active` 表示请求已结束或不在活动账本中，应按提示运行 `requests` 刷新列表，无需修复 Bridge；有歧义或格式错误的请求 ID 会单独报告。

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
VERSION="$(cargo metadata --format-version=1 --no-deps | jq -r '.packages[] | select(.name == "agent-remote-cli") | .version')" \
  scripts/package-release.sh
```

在 Windows PowerShell 中构建 Windows x64 归档（ARM64 可传入 `-Target aarch64-pc-windows-msvc`）：

```powershell
$version = ((cargo metadata --format-version=1 --no-deps | ConvertFrom-Json).packages | Where-Object name -eq "agent-remote-cli").version
./scripts/package-release.ps1 -Version $version
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
VERSION=VERSION_TO_INSTALL
curl -fsSL https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.sh | \
  bash -s -- --version "$VERSION" --home ~/.config/agent-remote --bin-dir ~/.local/bin
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


### 安装 Git 与本地技能来源

```sh
agent-remote skill add owner/repo --list
agent-remote skill add https://example.com/team/skills.git --ref main --path one --yes
agent-remote skill add owner/repo --ref refs/tags/v1 --skill one --yes
agent-remote skill add ./skills --list
agent-remote skill add ./my-skill --dry-run
agent-remote skill add ./my-skill --yes
agent-remote skill add ./skills --skill one --skill two --yes
agent-remote skill add ./skills --all --tool claude --yes
agent-remote skill add ./skills --path one --account-id ACCOUNT_UUID --yes
```

`--list` 无需 Server 登录或上传，显示候选名称、描述、相对路径和无效候选。本地列出不联网；
Git 列出会访问仓库并可能读取其原生凭据。仅有一个有效技能时
自动选择；多个候选必须交互选择或提供 `--skill`/`--all`，`--yes` 只代替计划确认。
`--list`、`--all`、`--skill` 互斥；显式子目录不能越出来源根。

安装目标是已登录用户的远端技能库。先把全部选中技能完整复制到私有暂存包，再预览或确认；
上传只读取已捕获字节。计划展示名称、摘要、字节数、范围和预期配置代数。`--dry-run` 不上传，
不新增变更日志。本地来源只上传不透明指纹，不上传可被当成远端地址的本机路径。
直接指定技能目录或通过 `--path` 选择同一目录，其来源身份一致。

全部包通过 Server 校验后，才提交一次原子安装请求；某项失败不能部分安装。相同内容及范围
重复安装为 no-op；已有来源内容改变时要求 update，规则改变使用 enable/disable/inherit。
当前调用内，内容上传重试沿用原计划。若进程在配置提交前结束，再次 add 会重新捕获并确认；
Server 暂存内容仍按上传租约和保留策略处理。

安装 POST 前，本地日志保存精确条目、配置代数和幂等键。受理结果不确定时，重复相同来源参数、
选择和范围（相对路径需在相同工作目录执行），或用 `skill status --last` 查询。恢复使用 Server
已完成的内容，不重读变化或消失的来源，也不刷新原代数。`--no-wait`、超时、提交状态与目标就绪
沿用规则命令语义。

Git 来源需要 PATH 中有原生 Git，支持 GitHub `owner/repo` 简写和不含凭据的 HTTPS 仓库地址。
本地两段相对路径应加 `./`；不支持任意网页、SSH 或 file 传输。`--ref` 接受字面分支名、tag
或完整 commit；省略时记录当前默认分支作为跟踪引用。分支与 tag 同名时必须明确使用
`refs/heads/NAME` 或 `refs/tags/NAME`。包记录完整 commit 与仓库相对子路径；恢复时也需重复
原始 `--ref`，但 Git 来源不依赖当前工作目录。

私有 HTTPS 仓库非交互复用原生 Git credential helper，请先用常规 Git 登录配置好 helper。
认证仅进入本机子进程内存，不进入来源 URL、本地变更日志或 Server 上传。传输忽略继承的 Git
执行配置，禁止 HTTP 重定向并强制 TLS 校验；私有 CA 可通过 `GIT_SSL_CAINFO` 指定。
CLI 从私有 bare 仓库读取原始对象，不运行 checkout、来源 hook、smudge filter、archive 替换
或安装脚本；可执行位、二进制字节与内部链接不依赖本机文件系统表示。选中技能包含未取得的
submodule 或 LFS 指针时返回 `INCOMPLETE_SOURCE`；可先在本机取得完整资产再按本地目录安装。

Git 获取与发现、每个选中包的捕获分别限时 240 秒，各子进程另有更短时限。输出、树条目和
解包内容均有限额。fetch 每 100 ms 监测 512 MiB/100000 条目的暂存阈值，结束后再次检查；
这不是下载网络字节的硬上限，采样间隔内可能超出阈值。正常完成或取消会清理临时对象；
Git 工作期间 Ctrl-C 返回 130。

### 检查和更新技能来源

```sh
agent-remote skill check
agent-remote skill check my-skill
agent-remote skill update my-skill --dry-run
agent-remote skill update my-skill --yes
agent-remote skill update my-skill --ref v2 --stage --yes
agent-remote skill update my-skill --ref v2 --yes
agent-remote skill update my-skill --from ./my-skill --yes
agent-remote skill update --all --yes
```

check 获取完整分支包，与当前默认 revision 比较，不上传、不新增变更日志。结果分别显示
`up_to_date`、`update_available`、`pinned`、`local_source` 或失败。固定 tag/commit 和回滚后的
固定策略会跳过；本地来源更新必须明确提供 `--from`。分支检查始终跟踪已记录分支，不因远端
默认分支改变或出现同名 tag 而切换。网络或来源验证失败返回非零。

单项 Git update 沿用记录的分支；`--ref` 明确选择新分支、tag 或完整 commit，固定策略必须
提供它才能切换。`--from` 只用于本地来源，须提供名称不变的完整技能目录；跨设备更新仍保留
已安装的不透明来源身份。Git 名称或子路径变化返回 `SOURCE_LAYOUT_CHANGED` 并展示预期与实际
内容；已知 tag 移动返回 `SOURCE_DRIFT`，Server 还会独立核查完整来源观测历史。

每项计划先完整捕获，再确认。`--stage` 仅登记单个候选，不改变默认版本、跟踪策略或账户状态，
返回的 revision ID 可用于 pin，不能与 `--all` 组合。内容已由保留 revision 引用时直接复用，
激活已登记候选也无需重复上传文件。更新不清除启用规则或独立 pin。配置 POST 前，日志保存
精确技能、内容、代数和幂等键；重复相同标识、`--ref`、`--from`、stage 选择，会先恢复不确定
请求再读取来源。相对 `--from` 需在原工作目录恢复。

`update --all` 逐技能独立处理，固定与本地来源显示跳过；单项失败后继续处理其他项，部分失败
返回非零。它不接受 `--ref`、`--from`、`--stage`；未提供 `--yes` 时逐项确认。每个新计划各自
读取当前代数，已提交请求不会自动刷新代数重做。批量更新先恢复未确认的自动 Git 更新，即使
当前清单已不再包含该技能。再次运行批量命令会重新评估其余条目，不承诺全局事务或全局操作 ID。

JSON check 和批量更新均输出一个版本 1 封套，`data.items` 逐项保留技能 ID/名称、状态、退出码
和完整结果。批量 `committed=true` 表示至少一项已确认提交，具体提交状态和操作 ID 以各项为准；
失败也汇总到外层 `errors`。成功返回 0，批量部分失败返回 1，参数错误返回 2，等待到期仍 pending
返回 3，中断返回 130。提交过程中中断会保留原始键并明确标记受理未知，不表示已回滚。
`--no-wait` 和 `--timeout` 分别作用于每个已受理操作。

### 技能库查询

Server 开启技能管理功能后，可使用用户登录凭据查询：

```sh
agent-remote skill list
agent-remote skill list --tool claude
agent-remote skill info my-skill --account-id ACCOUNT_UUID
agent-remote skill list --account-id ACCOUNT_UUID --effective
agent-remote skill status OPERATION_UUID --wait --timeout 60
agent-remote --json skill status OPERATION_UUID
```

工具范围与账户范围互斥；按账户列出时必须指定 `--effective`，身份参数使用完整 UUID。
这些命令使用现有用户登录，不使用设备 token。list/info 展示库版本、覆盖规则及字段来源；
账户范围还显示已发布的本地条目（包括停用项）、所属账户、来源检查点和保留的初始版本。
当前视图尚不包含会话固定快照、系统条目、运行 checkpoint 或模型加载证明。

JSON 标准输出只包含一个版本 1 的技能结果封套，保留 `operation_id`、`status`、`committed`、
`retryable`、`data` 和 `errors`；说明写入标准错误。普通 status 可直接查询 pending 状态；
`--wait` 只跟踪原始操作，遇到已知失败、冲突或 superseded 立即结束。等待截止时最后观察仍为
pending 则返回 3，不取消远端操作。后续刷新被拒绝或响应损坏时，错误结果保留最后观察到的
数据、提交标记和原操作 ID。成功查询或完成返回 0，已知失败返回 1，参数错误返回 2，
中断等待返回 130。缺少凭据、Server 不可用或响应损坏时失败，且不输出私有响应详情。
其余状态命令与完整运行态集成仍在开发中。

### 账户状态历史与导出

```sh
agent-remote skill state list my-skill --account-id ACCOUNT_UUID
agent-remote skill state list --scope account-directory --account-id ACCOUNT_UUID
agent-remote skill state info CHECKPOINT_UUID
agent-remote skill state info DIRECTORY_CHECKPOINT_UUID --members --limit 100
agent-remote skill state diff my-skill --account-id ACCOUNT_UUID --limit 100
agent-remote skill state diff --checkpoint CHECKPOINT_UUID --cursor PATH_FROM_PREVIOUS_PAGE
agent-remote skill state export my-skill --checkpoint CHECKPOINT_UUID --output ./skill-state
agent-remote skill state export --scope account-directory --account-id ACCOUNT_UUID --checkpoint DIRECTORY_CHECKPOINT_UUID --output ./directory-state
```

历史涵盖各版本及纪元，区分当前 head、保留/过期内容与来源会话的收尾结果。JSON 的
`data.checkpoints` 与 `data.pending` 各自包含 `items` 和 `next_cursor`，分别通过 `--cursor`
与 `--pending-cursor` 翻页；每页默认 100 条、最多 200 条。待上传记录显示来源 Node，不冒充
可恢复检查点。info 返回 `data.checkpoint` 和可选 `data.members`；`--members` 仅用于目录，
可用 `--limit`/`--cursor` 翻页。查询过期记录返回成功、`status=state_expired`，导出则失败。

diff 只显示类型、权限、大小、摘要、链接等元数据，不猜测语义合并或返回正文；明确标注原始包、
本地初始版本或目录父检查点基线。每页 1–500 条，继续翻页时须使用返回的不可变 `--checkpoint`
及 `--cursor`，不能将游标与会变化的当前 head 选择混用。当前分支未初始化或已过期时明确失败。
名称由 Server 解析；用户库和账户本地条目重名时必须使用完整 skill UUID。

export 校验账户、来源、范围、完整树摘要，以及每个独立文件的长度、SHA-256 和文本/二进制
分类。目标须不存在或为空，父目录须已存在；先写入私有同级暂存目录，全部校验后才原子发布。
便携目录包含 `checkpoint.json`、`manifest.json` 和 `objects/<sha256>`；原始路径、权限、
空目录和链接完整保存在清单中，不在本机创建链接或来源指定的路径。按清单文件条目的摘要查找
对应原始字节。这是可验证内容包，不是已物化运行目录，也不能直接作为 `resolve --directory` 输入。

单项导出未指定 `--account-id` 时使用检查点所属账户；目录导出必须明确账户。单项若含跨 skill
链接，须改用其 backing directory 检查点做目录导出。已明确记录的本地删除可导出带删除元数据
的空清单；缺失内容和仅在 Node 上的待上传数据不会生成“成功”的空包。导出按完整清单大小读取，
包括超过运行额度的字节，目标位置须有足够空间。文件流式下载，每对象最长一小时、响应头及流空闲最长 30 秒。发布前 Ctrl-C 返回 130 并清理暂存；
开始最终原子发布后会等待确切结果。上述命令不写变更日志、不修改 skill 配置和状态 head；Node 导出授权可能同步已注册的 SSH 公钥。

若原在线 Native Node 仍保留停止后的快照内容，包括 Server 配额耗尽无法上传、或本地磁盘预留不足无法冻结时，可执行：

```sh
agent-remote skill state export --scope account-directory --account-id ACCOUNT_UUID --snapshot SNAPSHOT_UUID --output ./frozen-state
```

快照 ID 使用待上传历史的 `snapshot_id` 或托管停止操作 ID。`--snapshot` 与 `--checkpoint`
互斥，快照导出必须明确目录范围和账户，以完整保留跨 skill 链接。本机设备及 SSH 公钥须已注册，
相应私钥须可由 SSH 默认密钥或本地 agent 使用；该传输禁用自定义 SSH 配置和转发。
使用当前用户登录授权，最多等待 60 秒同步节点公钥，随后经既有受限 SSH 通道读取。

来源须有完整冻结捕获，或保留原运行时身份的已停止工作目录。磁盘已满而无法保存终止证据时，
必须已有原调用记录，恢复内容标记为 unclean。后者由 Helper 独立证明原运行时的全部
写入进程已退出，并在读取前后校验完整目录；已有损坏捕获不能回退读取工作目录。冻结快照仍遵守
100000 项 manifest v1 上限；协商后的停止工作目录恢复使用有界内存流式处理全部条目，
包括超过该上限的目录。保留计数溢出检查，不额外按固定 10 GiB 拒绝读取。
导出不会停止会话、创建持久捕获、上传内容、推进 head 或释放 Node 数据。
Node 不可用、原登录/设备/公钥过期或撤销、内容缺失都会失败，不发布不完整包。
网关在传输中持续续期授权，始终绑定原用户令牌、设备、公钥和快照。授权有效且持续取得进展时，
完整传输可以超过 15 分钟；初次扫描和最终复核分别限时 15 分钟，相邻输入进展间隔限时 30 秒。
续期不能超过或替换原用户令牌，也不能恢复已过期或撤销的授权。

冻结导出使用 `agent-remote-skill-node-snapshot-v1` 和 `manifest.json`。停止工作目录恢复使用
`agent-remote-skill-node-recovery-v1`：`recovery.jsonl` 保存完整有序条目，`entries/` 按路径哈希
索引元数据，`objects/` 按内容哈希保存已验证文件。`checkpoint.json` 记录原身份、恢复摘要、
终止分类及计数；JSON 命令输出标明格式，其 `tree_digest` 表示该格式的摘要。恢复包不能伪装为
可直接导入的 manifest v1 检查点，也不代表 Server 发布。当前协商需要匹配的 Node/Helper，
旧网关不支持时明确失败。完整运行时及后端验收仍在进行。

### 检查冲突

```sh
agent-remote skill state conflicts my-skill --account-id ACCOUNT_UUID
agent-remote skill state conflicts --scope account-directory --account-id ACCOUNT_UUID --limit 100
agent-remote skill state diff --conflict CONFLICT_UUID --limit 100
agent-remote skill state diff --conflict CONFLICT_UUID --cursor CURSOR_FROM_PREVIOUS_PAGE
```

列表 JSON 的 `data.publications` 和 `data.migrations` 分别包含 `items`、`next_cursor`。
会话发布冲突用 `--cursor` 翻页，版本迁移冲突用 `--migration-cursor` 翻页；各页默认 100 条、
最多 200 条。名称只解析一次，后续使用稳定来源 ID。会话冲突始终属于完整账户目录；按技能筛选
也包含观察到其未改动分支的尝试。列表包含未解决和已被取代的尝试。

冲突 diff 返回 `data.kind`（`publication` 或 `migration`）、`data.conflict`（详情）和
`data.diff`（元数据页）。详情明确三侧的真实来源、确切版本/引用身份及摘要；会话发布详情还显示
原会话固定的分支和已保存选择。迁移详情保留不可变原始回执，将当前分支漂移单独展示；来源 head
后来前进不会替换原冲突的 incoming。仅在会话查询明确返回 `CONFLICT_NOT_FOUND` 时才查询迁移域。

差异每页 1–500 个路径，不包含文件正文。翻页须保留同一冲突 ID，并原样传回游标：会话游标是路径，
迁移游标则绑定原尝试及三侧摘要。输入缺失或过期时明确失败。检查成功返回 0、`status=ready`、
`committed=false`，即使所查记录仍冲突或已取代；记录当前状态在 `data.conflict.status`。
Ctrl-C 返回 130。查询不保存解决选择、不重算迁移、不改变 head，也不创建本地变更日志。

### 重置和恢复账户状态

```sh
agent-remote skill state reset my-skill --account-id ACCOUNT_UUID --dry-run
agent-remote skill state reset my-skill --account-id ACCOUNT_UUID --yes
agent-remote skill state restore my-skill --account-id ACCOUNT_UUID --checkpoint CHECKPOINT_UUID --yes
agent-remote skill state reset --scope account-directory --account-id ACCOUNT_UUID --dry-run
agent-remote skill state restore --scope account-directory --account-id ACCOUNT_UUID --checkpoint DIRECTORY_CHECKPOINT_UUID --yes
agent-remote skill status OPERATION_UUID
agent-remote skill status --last
```

确认前，Server 完整预览会固定账户、稳定来源、原始版本、安装/状态纪元、目录 head/纪元及库代数。
它分别列出相对当前目录和各目标原有分支的变化；过期分支的不可用基线会明确标注。名称仅解析一次，
提交时使用稳定来源 UUID。`--dry-run` 发送只读预览请求，不新增变更日志、不修改远端状态。
JSON 预览包含 `data.request`、`data.preview` 和 `data.recovering_original_request`。
交互执行只确认这份具体计划一次；非交互执行必须指定 `--yes`。

reset 发布原始内容并保留历史；restore 可恢复兼容且完整保留的历史（包括 detached 输入），
Server 检查用户、账户、来源、原始版本，以及允许的同来源跨安装纪元恢复。目录恢复还要求当前
有效成员集合准确匹配。范围不一致或 head/纪元变化会明确失败，不修改规则或自动刷新已确认计划。
单项操作推进选中分支的状态纪元；目录操作同时推进目录及涉及分支的纪元。现有会话继续使用自己的
固定快照，旧纪元的晚到写入保留为 detached，不自动复活已清空的数据。

实际 POST 前，共用私有日志按 Server/用户保存精确请求及已确认结果树摘要。受理未知时，重复
相同动作、标识、账户、范围和 checkpoint，会先按原键查回执，再考虑任何新选择；只有明确
OPERATION_NOT_FOUND 才重发完全相同的请求。`skill status --last` 会识别状态回执类型；也可在
其他已登录设备用原始操作 UUID 查询。后续重置/恢复不改写已发布回执。不确定命令的 dry-run 先查
原始回执，因此可能显示此前已提交的结果，但本次不会提交变更。

状态发布在 Server 事务中原子完成，成功即返回 `status=published`、`committed=true` 和操作 ID。
支持共用 `--no-wait`/`--timeout` 选项；此类回执没有后续部署目标需要等待。`status --wait` 遵守
原查询期限。规划/确认中断返回 130，不提交新变更；提交中断会保留原键并明确标记提交状态未知。
本地超时或中断均不表示回滚。`skill update --all` 会跳过状态日志，不将它误当作待恢复的包更新。

### 技能规则与回滚

```sh
agent-remote skill disable my-skill --dry-run
agent-remote skill enable my-skill --yes
agent-remote skill disable my-skill --tool claude --yes
agent-remote skill pin my-skill --revision r2 --account-id ACCOUNT_UUID --yes
agent-remote skill unpin my-skill --tool claude --yes
agent-remote skill inherit my-skill --account-id ACCOUNT_UUID --field enabled --yes
agent-remote skill disable my-skill --all-scopes --yes
agent-remote skill rollback my-skill --revision r1 --yes
agent-remote skill remove my-skill --yes --no-wait
agent-remote skill status --last
```

pin、unpin 和 inherit 必须选择工具或账户范围；inherit 不指定字段时恢复两个字段的继承。
`disable --all-scopes` 清除启用覆盖，但保留固定版本。rollback 不指定 revision 时由 Server
选择上一次不同于当前版本的真实激活记录，不按版本编号减一。上述命令只改变用户库及新会话
规则，不改动现有会话快照或学习状态。

账户本地技能支持带 `--account-id` 的 info、list --effective、enable、disable，以及
`inherit --field enabled|all`。本地 inherit 恢复 enabled=true，不复制用户或工具覆盖。
本地条目不支持 pin/unpin、版本继承、remove 或包版本 rollback；历史恢复使用状态恢复流程。
用户库与本地条目重名时必须使用完整稳定 ID。CLI 在保存 ID 前由 Server 解析原始输入，
不会先过滤用户库而绕过同名检查。

修改前读取并确认一份绑定配置代数的具体请求；显式 `--yes` 跳过交互确认。非交互缺少
`--yes` 返回 2；`--dry-run` 无需确认，只读取远端且不提交。默认等待 60 秒，`--timeout`
调整等待时间，`--no-wait` 在受理后返回。已知冲突或目标失败仍返回 1，并保留配置已提交标记。

POST 前，SQLite 按 Server 和用户身份保留完整请求与随机幂等键。临时断线先按原键查回结果，
只有确认没有原操作才重放相同请求；认证失败和配置代数冲突不会被自动重试或重新规划。
结果不确定时，用相同命令及范围恢复原请求；`skill status --last` 仅查询最近本地记录的
operation ID 或幂等键，不提交修改。丢失成功输出时，应使用 `--last` 查回，避免把再次执行
rollback 当作查询。凭据和来源文件字节不会写入该记录表。

通过完整 UUID 解决保留的会话发布冲突或版本迁移冲突：

```sh
agent-remote skill state resolve CONFLICT_ID --path learning/memory.md --use incoming --dry-run
agent-remote skill state resolve CONFLICT_ID --path learning/memory.md --file ./resolved-memory.md --yes
agent-remote skill state resolve CONFLICT_ID --directory ./resolved-discovery-tree --dry-run
agent-remote skill state resolve CONFLICT_ID --use current --yes
```

`--use current|incoming`、`--file`、`--directory` 必须三选一。`--file` 必须带 `--path`，仅处理普通
文件内容冲突；目录、删除、类型与不透明关联单元必须选择完整保存侧或完整目录。路径相对原冲突范围，
不从本地目录名称推断 skill。预览保留三侧的明确身份；迁移同时列出相对目标当前内容、目标原始包的
全部覆盖，以及确切目标 revision 和 modified 标记。

人工内容先固定到私有暂存目录。`--dry-run` 只发送清单元数据，不上传字节、不保存计划、不创建变更
日志；`metadata_only` 候选明确未验证、不可直接发布。一次确认（或 `--yes`）后，CLI 向原冲突专用
入口上传固定字节，执行正式校验预览，与已确认候选核对一致后才保存并提交精确请求。内容存储与解决
受理相互独立。部分选择返回 committed=true、pending、退出码 1，仅保存计划，不发布 checkpoint；
完整选择原子发布，退出码 0。旧比较失效返回 superseded、退出码 1；先检查替代尝试，再明确选择。
`--no-wait`、`--timeout` 不会把同步受理回执变成部署队列。

运行状态采集保留 `.git`、类似 LFS 指针的文本、二进制、普通相对链接、权限与空目录。本地默认文件/
单项上限 1 GiB、完整目录上限 10 GiB、最多 100000 条目；Server 继续执行配置额度和单项限制。
上传使用 64 KiB 有界读取，最长一小时并支持 Ctrl-C。本地绝对链接缺少运行依赖身份，明确拒绝；要
保留已有 runtime_link 元数据应选择保存侧。`--directory` 需要物化后的内容树，不能直接传入可识别的
checkpoint 导出包（`checkpoint.json`、`manifest.json`、`objects/`）。

受理回执丢失或不匹配时，CLI 保留原键和精确请求，明确报告提交状态未知。重复同一命令时，先查询
原回执，再考虑读取本地文件；只有原键明确返回 `OPERATION_NOT_FOUND` 才重放原请求。`skill status ID`
和 `skill status --last` 同样读取原始独立类型回执。恢复时的 `--dry-run` 只查询或预览原请求，不确认
本地日志，因此可显示之前已接受的 committed=true 历史回执。文件字节和凭据不写入恢复日志。提交前
Ctrl-C 不保存选择；提交期间 Ctrl-C 返回 130，并保留提交状态未知的原请求。

在同一已安装 skill 的两个明确版本间迁移账户运行状态：

```sh
agent-remote skill state migrate my-skill --account-id ACCOUNT_UUID --from-revision r2 --to-revision r3 --dry-run
agent-remote skill state migrate my-skill --account-id ACCOUNT_UUID --from-revision r2 --to-revision r3 --yes
```

双方版本接受 UUID、`rN` 或正登记编号。预览固定双方 head/epoch 和目录 head，标明来源原始包或
last-migrated 基线，分别列出目标分支与当前完整目录的变化。来源必须有保留的已发布 checkpoint；
未初始化的目标从其原始包开始，也支持迁往较早登记的版本。操作保持 pin、启用规则和有效使用历史。
没有新来源 checkpoint 时重复迁移会保留双方 head，并记录成功的无变化回执。

确认一次后才保存精确请求并提交；非交互执行需要 `--yes`。确认的冲突保留全部比较输入和 operation ID，
不发布部分 checkpoint，返回退出码 1，`--no-wait` 也不改变此语义。可用 `skill state conflicts` 和
`skill state resolve` 检查、解决冲突。成功发布退出 0；冲突预览退出 1 且不写入。迁移为同步发布，
公共等待选项不会创建虚构部署任务。

受理不明时保留原键，重复相同命令或使用 `skill status --last` 恢复，不重新选择较新 head。
`skill status OPERATION_ID` 和 `--last` 在 `data.result` 返回不可变原结果，另列当前状态、替代 ID
和失效原因；superseded 退出 1。恢复中的 dry-run 只查询或重新预览原请求，不重放或确认本地待恢复记录。
Ctrl-C 退出 130；请求已入日志时保留原键供后续恢复。

预览并永久清理账户中未被引用的状态历史：

```sh
agent-remote skill state prune my-skill --account-id ACCOUNT_UUID --dry-run
agent-remote skill state prune my-skill --account-id ACCOUNT_UUID --yes
agent-remote skill state prune --scope account-directory --account-id ACCOUNT_UUID --dry-run
agent-remote skill state prune --scope account-directory --account-id ACCOUNT_UUID --all-unreferenced --yes
agent-remote skill status --last
```

默认遵守历史保留期限。`--all-unreferenced` 明确提前结束合格历史的等待期，不绕过实际引用和保护。
prune 可整理共享目录视图并永久移除恢复历史。CLI 遍历并校验全部预览页，完整展示候选、依赖、损失组
和整理动作后才确认一次；计划阻塞或发生变化时不提交。`--yes` 也会完整展示。必须指定账户；单项
范围还需要 skill，完整目录范围则不能传 skill。

完整披露暂存在仅当前用户可访问的临时文件中，上限 2 GiB；超过上限则整体失败，不截断后继续提交。
普通 HTTP 响应仍限制为 1 MiB。本地日志只保存精确的小请求和已审阅摘要，包含该请求范围的确认凭据，
不保存完整披露或文件内容；确认凭据绝不打印。

受理未知时重复原命令，或用 `skill status --last` 查询。恢复先查原键，再考虑任何新预览；只有明确
返回 `OPERATION_NOT_FOUND` 才重放原请求，不刷新计划。恢复中的 dry-run 只读；若查不到原回执，
明确报告受理未知、原摘要及 `disclosure_available=false`，不伪造重建的损失清单。

JSON 模式下，新 dry-run 在 `data` 返回 `summary`、`disclosure_rows`、完整 `rows` 和
`recovering_original_request=false`。实际提交将完整审阅输出到 stderr，stdout 只返回一个回执封装。
`skill status OPERATION_ID` 和 `--last` 返回 `data.receipt`、完整 `rows`、`disclosure_rows`
以及独立的 `deletion_progress`。物理删除仍在等待或重试时，逻辑回执仍为 `accepted`；命令的
`--no-wait` 和 `--timeout` 不等待磁盘删除。状态查询的 `--wait --timeout N` 为完整回执、明细、
进度查询及展示设置期限。

Ctrl-C 退出 130。提交前中断不发送清理；提交期间中断保留原键供恢复。流式展示中断或超时可能留下
不完整输出；CLI 直接退出，不追加第二个 JSON 封装，也不等待阻塞的输出管道。

独立查询当前存储情况：

```sh
agent-remote skill status --storage
agent-remote --json skill status --storage
agent-remote skill info my-skill --account-id ACCOUNT_UUID
agent-remote skill state info CHECKPOINT_UUID
```

`status --storage` 展示当前用户的 Server 发布包/运行状态用量、各自上传预留、实际配置额度与保留策略，
以及独立的物理删除数量和字节。它与 operation ID、`--last`、`--wait`、`--timeout` 互斥；只读查询
不创建命令日志、不改变保留时钟。管理员调低额度后用量可能超过上限，诊断仍如实展示。

skill info 在各版本中附加 `retention`，并附加用户总量 `storage`；checkpoint info 将这些字段放在
`data.checkpoint` 内。保留状态区分 `protected`（受保护）、`waiting`（等待中）、`due`（已到期）、
`release_unknown`（释放时间未知）和 `retired`（已退役），保留原释放时间、配置天数及有效截止。
旧记录缺少释放证据时不猜测时间；受保护或已退役对象没有有效截止。`due` 仅表示该历史自身等待结束，
清理仍需完整依赖审阅和重验。旧 Server 可以不提供这些可选详情字段；缺失不解释为零用量或无限保留。

JSON 的存储数据含完整 `policy`、`observed_at`，以及 `deletion` 中的 `pending_tasks`、
`retrying_tasks`、`completed_tasks`、`pending_file_bytes`、`cumulative_deleted_bytes`。
累计删除量汇总已完成任务中记录的文件大小；同一内容重新上传后再次删除会再次计入，不是实测的磁盘释放量或剩余空间。
这些数据属于当前用户的 Server 总量，不是单个 skill 的大小，也不包含 Node 或会话副本的磁盘用量。
原操作状态及不可变回执仍独立查询。

`skill list --include-system` 增加只读系统目录；账户有效查询自动包含系统引用及已知账户本地技能。
账户 list/info 诊断展示精确选中分支、当前 checkpoint、版本选择原因、准备/过期状态、独立的发布和
迁移冲突数量及最新 ID，以及已有证据的最后完整内容同步时间。冲突汇总跨版本和纪元，不代表每项都阻断
下一次启动；旧同步时间可能未知。设备系统项需等启动时验证选中 Node 的能力，目录条目不证明已部署。

`skill list --session SESSION_ID --effective` 查询原会话保存的系统引用、版本、纪元与起始 checkpoint，
支持 `--limit 1..200`（默认 100）及 `--cursor ORIGINAL_NAME`；有后续成员时按输出游标再次查询。
会话范围与账户/工具范围互斥。会话删除后仍可查询保留的快照元数据，内容退役状态单独展示。没有快照的
旧会话标记 `legacy_unrecorded`，不会按当前规则重建。项目发现保持 `not_inspected`，查询不证明模型
已加载。旧 Server 普通 list/info 缺失的新诊断字段仍兼容；会话查询需要新增 Server 接口。

配置准备阶段（`skill add` 及规则修改、remove、rollback）支持在用户认证、原请求查找、来源选择、
交互确认和包上传时按 Ctrl-C，以 130 退出且不提交新的配置请求。Server 上可能仍有上传暂存或已保存的
包内容，中断不代表删除这些内容，也不取消旧的待确认操作。交互选择输入最多 8192 字节，确认输入最多
4096 字节。update 共用有界确认输入，其认证阶段也支持中断。

同一命令的 Ctrl-C 监听贯穿各阶段和本地日志写入，不在阶段切换时丢失信号。可能已发出提交时，JSON
保留原幂等键并明确标记受理未知；已验证的响应保留其确定的提交状态。可通过 `skill status --last` 或
重复原命令恢复。准备中断沿用 `SOURCE_INTERRUPTED`，受理中断使用 `SKILL_INTERRUPTED`。
人类可读模式中断后直接以 130 退出，不追加终端信息，避免未读取的提示/警告管道阻塞退出；JSON 模式
尝试输出相应结果封套；输出中断时内容可能不完整。
来源目录和配置 dry-run 结果使用只负责输出的线程。输出过程中按 Ctrl-C 以 130 退出，不追加第二个 JSON
封套；已写出的内容可能不完整。输出线程不能创建命令日志、上传内容或提交配置。

配置最终回执及单项/批量 update 结果在 stdout 或 stderr 阻塞时也支持中断。收到 Ctrl-C 后，最终输出
最多再等待 250 毫秒即以 130 退出，不追加第二个封套；中断结果本身同样受此限制。已验证回执仍保留在
本地日志，可用 `skill status --last` 查询；输出中断不会改变提交状态或再次提交请求。

state reset/restore、migrate 和 resolve 也持续保留中断信号，并使用可中断的输出边界。在预览或确认时
按 Ctrl-C 不会提交新的状态变更；已上传的冲突解决内容可能仍被保存。尚未开始结果输出时，JSON 报告
`SKILL_INTERRUPTED`；人类可读模式直接以 130 退出，不追加消息。大段预览、dry-run 和最终回执在
stdout/stderr 阻塞时也可中断；最终输出最多等待 250 毫秒，可能不完整，不会追加第二个封套。本地回执
写入期间发生中断，仍保留已验证的 Server 结果及原 operation ID，可用 `skill status --last` 找回；
受理未知时保留原幂等键。

state list/info/diff/conflicts/export 从认证读取到成功或错误输出持续保留 Ctrl-C。输出管道阻塞时，
中断最多再等待 250 毫秒，以 130 退出且不追加第二个封套。export 在本地发布前中断会丢弃暂存；
开始发布后会观察结果，即使结果输出被中断也保留已验证的本地副本。远端状态不变。
通用 skill 查询与 status 暂仍使用各自的中断实现。

全局选项可放在显式子命令前，例如 `fclaude --home PATH stop SESSION`。
若要将命令名作为 Claude 提示文本传入，使用 `--`：`fclaude --home PATH -- stop`。

受管 Skill 会话的 `fclaude stop SESSION [--timeout 60]` 会先打印持久保存操作 ID，再最多等待
指定秒数完成发布。进程停止与数据保存分开报告：`local_durable`、`upload_pending`、`persisted`
均不等于已发布，Node 会独立继续重试。使用现有设备登录执行
`fclaude stop-status OPERATION_ID [--wait] [--timeout 60]` 可再次查询，删除会话后仍有效；操作 ID
为原始快照 UUID。等待超时返回退出码 3，Ctrl+C 返回 130，需要检查的 conflicted/detached/superseded
结果返回 1，published 返回 0；不等待的待完成状态查询返回 0，HTTP 或身份错误返回 1。
旧会话的 stop 仍在提交停止请求后立即返回。

受管 Native 账户首次需要捕获原手工 skills 时，`fclaude` 会显示接管操作 ID，并最多等待
60 秒。已有会话继续运行，Node 等待它们正常结束后才冻结共享原目录。只有 Server 明确
证明“尚未创建会话”的响应才允许进入此等待；原接管提交后，CLI 用同一输入再创建一次。
创建响应不确定时不会自动重发。超时退出 3、Ctrl+C 退出 130、需要恢复或协议错误退出 1；
远端操作继续保留。如果超时发生在创建请求本身，请先用 `fclaude list` 检查再请求新会话。

Skill 操作状态的 JSON 输出会保留 Server 提供的各目标尝试 ID、序号及可重试标志；终端展示
尝试序号和可重试状态，历史缺失字段显示 unknown。`preparing` 使用既有的限时只读等待，查询
不会自行重试部署。

用 `agent-remote skill retry OPERATION_ID --dry-run` 检查原操作已结束的临时失败目标，
再用 `agent-remote skill retry OPERATION_ID --yes` 提交。CLI 发送前保存原配置代数、账户/
尝试身份及计划摘要，不重新获取 Git/本地来源，不修改库配置，也不重复成功项。被取代的操作、
权限失败、未解决冲突、不支持目标及历史未知尝试都会被拒绝。
`--no-wait` 在受理后返回；默认等待 60 秒，可用 `--timeout SECONDS` 调整。超时退出 3，
Ctrl+C 退出 130，均不取消远端任务；整体操作失败仍退出 1。受理结果不确定时，重复同一命令
恢复精确原请求，或用 `agent-remote skill status --last` 只读查询重试回执。仅缺失回执允许
重发保留请求，当前计划变化不能触发自动重新规划。实际 Node 部署调度尚未接通，普通绑定
目标仍明确显示 unsupported；此接口提供持久重试受理，不宣称已有完整部署执行器。

### 检查保留的后端迁移

管理员可对精确的原失败迁移发起一次被动检查：

```sh
agent-remote account recover-runtime ACCOUNT_UUID \
  --original-task migrate_tool_account_runtime:ACCOUNT_UUID:ORIGINAL_UUID \
  --request-id RECOVERY_UUID
agent-remote --json account recovery-status ACCOUNT_UUID --request-id RECOVERY_UUID
```

所有 UUID 均使用完整小写形式，并保留独立选定的恢复 UUID。原任务 ID 来自管理员迁移 API
的受理响应。使用相同账户、原任务和请求键重复提交只返回同一个恢复任务；状态查询不派发
任务。两个命令都要求管理员用户登录，不使用设备令牌。超时或受理响应丢失后，先用原请求键
查询，再重复同一请求。只有前一个恢复检查已经结束，才允许用新键再次检查。

默认检查已有的目标迁移完成证据。添加 `--verify-source` 则验证已经完成的精确源回滚：
必须存在复制前基线、不可变失败证明，且内容、权限和父目录 ACL 均仍匹配。验证成功保留源后端，
将原档案标为 `rolled_back` 并解除该档案的写入禁令。两种动作均保留原失败任务、结果和账户禁用状态，
均不重新复制、不修复权限、不启动回滚。上一启动周期的完整证据还要求当前对应 unit/cgroup 不存在；
不完整迁移继续阻塞，也不启用任何后端能力。

同一请求 UUID 不能更换动作。源验证使用包含 `action: "verify_source"` 的版本 2 绑定；
JSON 输出为 `schema_version: 2`，增加 `source_restoration_confirmed`，并始终保持
`target_completion_confirmed: false`。提交失败保留动作且源确认值为 null；状态查询失败无法推断
已保存动作，查询成功则按经过校验的绑定输出。

中断的后端权限迁移可通过 `account recover-runtime --repair-source` 显式修复，仍需上面的
`--original-task` 和 `--request-id`。Helper 仅在原备份、基线及全部原写入者停止证据有效时
恢复源权限，并单独记录修复结果，保留原任务失败历史。此参数与 `--verify-source` 互斥。
回执不确定时使用同一请求键查询 `account recovery-status`。JSON 使用版本 3 和
`source_restoration_confirmed`；此前禁用的账户保持禁用。

默认恢复的 `--json` 输出单个版本 1 文档，包含 `request_id`、类型化的 `recovery.binding`、
`recovery.status` 和 `target_completion_confirmed`。确认只针对原迁移，不表示较新的账户
状态。受理或查询响应通过校验后退出码为 0，即使任务仍待处理或失败；脚本应检查状态字段。
输入、API 或协议错误退出 1，缺少必填参数退出 2。文本模式的错误诊断写入标准错误；
默认恢复的 JSON 模式在标准输出返回单个版本 1 错误封装，保留已验证的 `account_id`、`request_id`、
`original_task_id`，以及固定的 `error_code`、`message`、`acceptance` 和原请求的查询命令
`next_command`。不可用的身份及 `recovery`、`target_completion_confirmed` 为 null。
提交准备失败为 `not_submitted`，明确的 HTTP 4xx 拒绝仅将本次提交标为 `rejected`；
传输失败、5xx 和损坏的成功响应均为 `unknown`。查询失败也保留受理未知，不推断先前请求
未被受理。输出不回显远端错误正文或凭据诊断。

写入者停止后若冻结失败，`capture_pending` 会报告 `quota_exceeded`、`insufficient_storage`、
`portability_error` 或 `capture_failed`。停止或状态等待以退出码 1 结束，并显示使用原操作 ID
的快照导出命令；此时尚未确认本地持久化。请保留 Node 数据，排除故障后再次查询同一操作。
