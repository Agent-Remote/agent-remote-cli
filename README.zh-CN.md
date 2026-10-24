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

`agent-remote-cli` 是 Agent Remote 的 Rust 本地客户端，负责本地配置、凭据、设备登记、WireGuard、SSH、Mutagen、远程会话操作，以及供 desktop 使用的结构化控制合同。

## 二进制程序

- `agent-remote`：配置、登录、设备、账户、工作区、网络、诊断、Skills 和会话管理。
- `fclaude`：Claude 会话创建、列表、接管、停止/删除和端口转发。
- `agent-remote-wireguard`：用户侧 WireGuard helper。
- `agent-remote-wireguard-broker`：执行获准隧道操作的受保护主机 broker。
- `agent-remote-ssh`、`agent-remote-scp`：受管 SSH 和文件传输 helper。

当前包版本记录在 `Cargo.toml`。除非协调更新 Server、Node 和 desktop 合同，否则必须保持命令名、参数、退出码和机器输出兼容。

## 命令族

```sh
agent-remote init
agent-remote login
agent-remote status
agent-remote doctor
agent-remote sync status
agent-remote sync ensure
agent-remote wireguard check
agent-remote account list
agent-remote device status
agent-remote skill list
fclaude list
fclaude new
fclaude attach <session-id>
fclaude forward <remote-port>
```

使用 `--help` 查看当前准确 schema。`agent-remote` 管理共享状态；`fclaude` 管理远程 Claude 启动器和面向会话的命令。密码、token、MFA 验证码和私钥通过受控输入或平台凭据存储处理，不进入 argv 或 desktop 状态。

## 共享状态与操作安全

选定的 `AGENT_REMOTE_HOME`（或 `--home`）是配置、本地 SQLite 状态和凭据引用的权威位置。CLI 为可能跨进程存活的操作持久化调用方生成的请求键和有界公开回执。传输失败后，状态查询使用原始 key 和完整上下文；不会猜测 latest 对象或生成替代 key 重放 mutation。

会话、账户、配置导入、运行时恢复、同步、端口转发和设备操作都会绑定用户、服务器、设备、工作区、节点和代次等相关字段。未知结果会被保留，并要求用户显式查询或执行恢复动作。

## Desktop 集成

Desktop 使用两个版本化 CLI 接口：

- `--desktop-schema` 描述命令节点、参数、客户端平台和终端能力。
- `--desktop-control` 通过 JSONL 交换请求、有界进度事件和一个最终 result/error，承载结构化读写操作。

登录、设备码审批、凭据、账户导入和 WireGuard 执行等敏感流程仍由 CLI 负责。Desktop 只能收到批准的公开投影。没有专用结构化页面的命令使用经过审阅的受管终端流程；发现 schema 不等于远程操作已成功。

## 远程操作

CLI 协调 WireGuard、SSH、Mutagen 以及 Server/Node API。远程 Claude 会话通过准确会话身份选择，并经 Node 授权 gateway 接入。工作区同步分别展示 Server 状态、本地 Mutagen 状态、冲突和 Agent 状态。端口转发使用 owner-scoped caller key、有界本地监听器和短期 Server 连接授权。

WireGuard 执行路径 fail-closed：配置字节以及 plan/target 摘要必须先审阅，随后才能由获准的平台 broker 执行 `up` 或 `down`。客户端不回退到 sudo、runas、PATH helper 或未验证进程。

## 开发

需要 Rust 2021 和仓库固定的 toolchain。在仓库根目录运行完整门禁：

```sh
bash -n scripts/*.sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
scripts/run-quality-checks.sh
```

使用临时 home、loopback 夹具和一次性 server/node 数据。不要对生产凭据执行验收，也不要在测试输出中保存真实私钥。

## 安装与打包

在类 Unix 主机安装最新发布的 CLI：

```sh
curl -fsSL https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.sh | bash
```

如需固定版本或明确指定 home、链接目录：

```sh
VERSION=VERSION_TO_INSTALL
curl -fsSL https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.sh | \
  bash -s -- --version "$VERSION" --home ~/.config/agent-remote --bin-dir ~/.local/bin
```

Windows 使用 PowerShell 下载并运行 `scripts/install.ps1`。仅当缺少 OpenSSH
Client 或随包提供的 WireGuard 依赖时才使用 `-InstallPrerequisites`；该选项可能需要提权。
构建发布归档：

```sh
VERSION="$(cargo metadata --format-version=1 --no-deps | jq -r '.packages[] | select(.name == "agent-remote-cli") | .version')" \
  scripts/package-release.sh
```

安装已下载的发布归档：

```sh
./install.sh
```

Windows 的等价安装器调用：

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.ps1 -OutFile install.ps1
.\install.ps1 -InstallPrerequisites
```

归档包含 CLI、受管 helper、依赖清单、校验和和第三方声明。安装不会在没有用户明确
选择的情况下替换生产 home。

## 发布

`prepare-release.sh` 和包流程负责构建 CLI 与受管 helper。发布制品必须包含准确版本、源码 commit、依赖声明和校验和。原生 broker 验收独立于合同测试，必须在目标主机运行。协调的 Server、Node 和 desktop 门禁全部通过前不得发布。

## 文档

当前合同集中在 `docs/`：

- `desktop-control.md`、`desktop-schema.md`：desktop 结构化 API。
- `desktop-accounts.md`、`desktop-account-binding.md`、`desktop-account-import.md`、`desktop-account-defaults.md`：账户流程。
- `desktop-session-attach.md`、`desktop-sync.md`、`desktop-port-forward.md`：会话和工作区流程。
- `desktop-wireguard*.md`、`linux-wireguard-broker.md`、`macos-wireguard-broker.md`：网络与 broker 流程。
- `desktop-runtime-recovery.md`、`desktop-mutagen-environment.md`：恢复与共享服务状态。
- `exact-session-attachment-transfer.md`、`verified-session-sync.md`：附件与同步边界。

这些文档描述当前合同；文档过时时以代码和测试为准。

## 脚本入口

仓库保留以下安装、构建、打包和主机验收入口：

```sh
# 构建托管 Mutagen 和 WireGuard helper 输入。
scripts/build-managed-tools.sh
# 准备版本化发布元数据并运行发布检查。
scripts/prepare-release.sh
# 构建 Unix 发布归档。
VERSION="$(cargo metadata --format-version=1 --no-deps | jq -r '.packages[] | select(.name == "agent-remote-cli") | .version')" \
  scripts/package-release.sh
# 安装 Linux/macOS broker 并运行原生 broker 验收。
scripts/install-macos-wireguard-broker.sh
# 使用受保护系统服务时安装 Linux broker。
scripts/install-linux-wireguard-broker.sh
scripts/native-wireguard-broker-acceptance.sh
# 为本地开发安装仓库 hooks。
scripts/install-githooks.sh
# 仓库质量与专项测试门禁。
scripts/run-static-checks.sh
scripts/run-tests.sh
scripts/run-quality-checks.sh
```

Windows 使用 PowerShell 打包和 broker 验收入口：

```powershell
./scripts/package-release.ps1 -Version $version
./scripts/native-wireguard-broker-acceptance.ps1
```

`install.sh` 和 `install.ps1` 是上文说明的终端用户安装器；其他脚本用于构建或主机验证，
不会自行发布版本。

## 许可证

GPL-3.0-only。详见 `LICENSE` 和 `THIRD_PARTY_NOTICES.md`。
