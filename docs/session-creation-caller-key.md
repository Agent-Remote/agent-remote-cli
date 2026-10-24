# Rust CLI 会话创建调用方原键合同

Rust CLI 是 desktop 与人工入口共用的 caller key、journal 和恢复实现。本文只描述当前代码语义。

## 持久化范围

每次明确的新建或 replacement 在网络请求前生成规范非零 UUID `request_id`。journal 按 Server 和用户上下文保存：

- tool、account、workspace、project、replacement 和完整 sync target 的公开身份；
- argv digest、意图 digest、准备任务公开 ID、session/task 公开 ID；
- 当前 phase、最后一次只读观察和恢复所需的配置上下文。

不保存 raw argv、环境、提示词、凭据、工作目录内容或响应正文。意图或上下文变化必须生成新的 request key。

## 提交流程

CLI 先冻结并复验准确的账户、workspace、项目、sync target、Node/backend 和 replacement，再向 Server 提交一次 caller-key create。Server 返回明确回执后，CLI 才继续读取任务和 session 观察。

传输错误、进程重启或响应损坏只进入 `unknown`/pending 恢复。恢复始终 GET 原 request key；不会重 POST、猜测最新会话、切换默认账户或替换目标。只有明确证明原请求未受理且没有创建资源时，用户才可以开始一次新的审阅。

## 结果语义

CLI 对外使用 `prepared`、`admission_pending`、`accepted`、`running`、`failed`、`unknown`、`deleted` 等稳定 phase。accepted 表示 Server 已保存受理记录，不代表 Node 进程已启动；running 需要任务/会话观察；deleted 表示资源观察与原回执仍可查询。

上下文、digest、request key、用户或 Server 不匹配时 fail-closed。设备、账户、凭据和原始任务参数继续由各自边界管理。

## 证据与剩余门禁

CLI 的 caller-key、journal、恢复和冲突测试已通过，完整质量门禁已通过。正式发布还需要与真实 Server/Node/SSH/tmux/fclaude 的一次性联调，覆盖响应丢失、重启恢复、replacement、停止/删除和 attachment transfer 清理回执。