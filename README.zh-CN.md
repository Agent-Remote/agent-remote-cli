# agent-remote-cli

[English](README.md) | 中文

agent-remote-cli 是 agent-remote 的本地 Rust CLI。它提供 `agent-remote` 统一管理命令，以及 `fclaude` 这类工具专用启动器。工具启动器不会覆盖或影响用户本机原生的 `claude` 命令。

## 常用命令

```sh
agent-remote init
agent-remote login --server-url https://agent-remote.example.com --username alice
agent-remote status
agent-remote doctor --fix
agent-remote deps status
agent-remote sync ensure
agent-remote account create --tool claude --name "Claude US" --region US --timezone America/Los_Angeles --tag us
agent-remote account bind <account-id>
agent-remote attach --session-id <session-id>
```

`agent-remote init` 是推荐的首次使用流程，会引导用户配置控制平面地址、登录已有账户、注册本地设备和 SSH 公钥、检查内置依赖，并在可用时获取 WireGuard 配置。

## 本地状态

默认状态目录：

```text
~/.config/agent-remote/
```

发布包会把内置依赖安装到：

```text
~/.config/agent-remote/bin/
~/.config/agent-remote/dependencies/manifest.json
```

CLI 会优先使用系统凭据存储保存 token。macOS 使用 Keychain，Linux 使用 Secret Service。SQLite 只保存本地元数据，不保存访问 token 或 Claude 登录状态。

## 同步和连接

`agent-remote sync ensure` 会按当前目录识别项目，创建远端 workspace 和 Mutagen 同步会话。项目 `.git` 默认同步，常见构建缓存、hook、worktree 和锁目录会排除。

`agent-remote attach` 会向控制平面申请一次会话级 SSH 授权，等待节点同步 forced-command key，然后用本地 SSH 连接远端 tmux shell。

## 发布包

```sh
VERSION=0.0.2 scripts/package-release.sh
```

发布包包含 `agent-remote`、`fclaude`、`agent-remote-wireguard`、内置 Mutagen、依赖 manifest 和第三方声明。下载 release 后可运行：

```sh
./install.sh
```

## 开发

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## 许可证

agent-remote-cli 使用 GPL-3.0-only 许可证。详见 `LICENSE`。

第三方依赖声明见 `THIRD_PARTY_NOTICES.md`。
