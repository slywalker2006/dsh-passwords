# 子用户交互与新建会话修复清单

**状态：** 已完成本地修复，待测试服务器人工验收  
**范围：** `dsh-passwords` 多用户网关；DSH `0.1.2-alpha.5` Remote mux 协议  
**关联：** GitHub Issue #26；子用户在已授权工作区中无法新建会话的反馈

## 结论

两个现象需要分开处理：

1. **Issue #26 已确认是 dsh-passwords 的缺陷。** 子用户发起任务后，`ask_user_question` 产生的 `user-questions/request` Remote waterfall 帧在网关被静默丢弃；管理员 Remote mux 不受该过滤影响，因此管理员重新登录后会看到本应展示给子用户的问题。
2. **“在已分配工作区中无法新建会话”不是 `allowWorkspaceCreate` 的预期限制。** 该权限只控制创建、重命名和删除工作区；DSH 工作区侧边栏的 `+` 会调用 `session/create` 并携带已有 `workspaceId`。在工作区对该子用户可见且不属于其他子用户时，新建会话应可用。

因此，Issue #26 需要修复；新建会话反馈需按实际失败状态码和请求路径复现确认。现有回归测试已覆盖“已授权工作区内 `session/create` 在 `allowWorkspaceCreate: false` 时返回 200”，不能把该权限改成新建会话前置条件。

## 已确认的协议事实

- DSH 的 `@deepseek-ai/dsh-tool-ask-user` 调用 `ctx.userQuestions.ask(...)`。
- DSH `@deepseek-ai/dsh-api-remotes` 将下列 Host 事件通过 `$events` 转发：
  - `user-questions/request`，模式为 `waterfall`
  - `approval/request`，模式为 `waterfall`
- waterfall 帧包含事件名、`eventId`、归属 `agentId` 和请求体。浏览器插件 `@deepseek-ai/dsh-client-ui-user-questions` 按事件归属解析会话并渲染问题卡片。
- 现有 [src/gateway.ts](../../src/gateway.ts) 的 `$events` 子用户过滤仅允许 `ready` 和五种 `emit` 会话事件；`waterfall` 不满足 `value.type === 'emit'`，在约第 1435 行被丢弃。
- 管理员 Remote mux 保持透明转发，正好解释“管理员登录后问题出现”。

## 修复清单

### E. Issue #25 工作区归组与资源分配修复

- [x] `session/create` 的真实 alpha `client-request` 在网关完成工作区路径和所有权校验后使用客户端已有或网关新生成的 `sessionId`，建立 30 秒有界的待确认关系。
- [x] `workspace/follow` 同路径 `upsert` 与 `$events` 的 `api-session/added` 可在创建 unary 响应之前被安全转发；只接受相同工作区路径的待确认 ID，不将其提前写入正式 grant。
- [x] 创建响应必须为同一 `sessionId` 且业务成功；响应身份不一致、业务失败、非 JSON、超限、上游错误或客户端断开都会清理待确认关系，Remote 连接按需关闭。
- [x] 创建成功后才写入用户显式 session grant/access；权限撤销会清理待确认关系，周期 sweep 和单用户 256 条上限防止临时状态累积。
- [x] DSH 插件新增 loopback + internal-secret 保护的 `internal/assignable-resources` 资源快照；工作区列表和网关权限保存均以 DSH 当前 registry/session-query 结果为准。
- [x] 管理员分配列表排除 `missing-dir` 工作区、归档会话、空白会话槽位和明确不存在的持久化会话；存储不可用时返回 502，不回退为 UUID。
- [x] `/gateway/api/permissions` 拒绝不在当前资源快照中的会话/工作区路径；资源权威不可用时 502；空数组和 `__deny__` 仍保留原有语义。

### A. 先补充失败回归用例

- [ ] 在 `test/gateway-proxy-headers.test.ts` 的 Remote mux mock 中增加可控的 waterfall 事件发送能力。
- [ ] 增加 Issue #26 红灯用例：已授予 `session-visible` 且已建立可信 `workspace/follow` 基线的子用户，应收到：

  ```json
  {
    "type": "waterfall",
    "event": "user-questions/request",
    "eventId": "...",
    "agentId": "...",
    "request": { "questions": [] }
  }
  ```

- [ ] 增加同等的 `approval/request` 用例。它使用同一 waterfall 通道，不能只修 `user-questions/request` 而留下审批 UI 不可用。
- [ ] 增加拒绝用例：未知事件、畸形字段、未授权会话、已禁用会话、白名单目录外会话、另一子用户私有工作区的事件均不得转发。
- [ ] 增加权限变更用例：主用户撤销会话、禁用会话或修改目录白名单后，现有子用户 Remote mux 必须关闭；重连后不能收到旧 waterfall。

### B. 证明 waterfall 的会话归属和结果回传

- [ ] 在 alpha.5 依赖中追踪 `carrierKeyOf(this)` 的实际类型，确认 waterfall 帧的 `agentId` 是否等于普通会话 `sessionId`。不得仅根据现有命令路径的惯例假定二者相等。
- [ ] 若 `agentId` 不是可直接验证的 `sessionId`，建立最小、可撤销的 `agentId -> sessionId` 解析方式，并只在可信的 `workspace/follow` / `session/control` 投影内缓存。
- [ ] 查明 DSH 对 waterfall answer/result 的 HTTP 或 Remote 回传端点及请求字段；确认网关代理不会绕过当前用户授权。
- [ ] 回归验证：一个子用户不能提交另一个子用户、管理员或已撤销会话的 `eventId` 结果。

### C. 实施严格的 `$events` waterfall 放行

- [ ] 在 `filterRemoteMuxUserItem()` 中保留默认拒绝策略，不建立“未知 waterfall 透传”分支。
- [ ] 仅接受对象结构完整、字段类型正确、大小受限的 `waterfall` 帧。
- [ ] 白名单仅包含：
  - `user-questions/request`
  - `approval/request`
- [ ] 在转发前按已证明的会话归属执行全部授权条件：
  - 该会话在本次用户 `userSessionAccess` 快照中；
  - 该会话仍在 `user_session_grants` 持久化授权中；
  - 不在 `disabled_sessions`；
  - 会话目录仍命中 `allowed_folders`；
  - 工作区不属于其他子用户。
- [ ] 授权失败、状态未知、缓存尚未建立或帧畸形时丢弃事件，不把事件主体、问题选项或审批内容泄露到浏览器。
- [ ] 明确保持管理员透明转发与现有普通 `emit` 事件脱敏行为不变。

### D. 核验子用户新建会话链路

- [ ] 以子用户身份先打开 `workspace/follow`，确认所选 `workspaceId` 存在于网关的当前用户可见工作区快照。
- [ ] 发送 DSH 实际格式的 `POST /api/session/create` / `POST /api/session.create` 请求，主体使用 `payload.args.request.workspaceId`。
- [ ] 断言：`allowWorkspaceCreate: false`、已授权工作区、无配额/封禁/沙盒拒绝时，新建会话成功，响应会话写入该子用户的 grant 与访问快照。
- [ ] 分别覆盖下列失败原因，确保错误原因不会被错误归类为工作区创建权限：
  - 未建立或已过期的 workspace 基线；
  - `workspaceId` 不在当前用户可见快照；
  - 工作区属于其他子用户；
  - 子用户被封禁；
  - 每小时 token 或每日使用时长配额耗尽；
  - 沙盒配置要求强制执行但内部确认失败；
  - 上传大小限制或 Agent preset 限制（仅在请求实际携带相关字段时）。
- [ ] 验证新会话随后同时出现在 `workspace/follow`、`session.list`、`$events` 和 `session/follow` 中，不发生“创建成功但侧边栏不可见”的快照竞态。

## 非目标与兼容边界

- 不把 `allowWorkspaceCreate` 放宽为任意目录创建会话的权限，也不将其改为新建会话开关。
- 不允许子用户通过 waterfall、回传接口或 session create 请求读取、操作或枚举未分配的会话。
- 不依赖浏览器本地状态作为授权依据；网关以数据库持久化 grant、当前权限和可信上游基线共同判定。
- 不修改 DSH 上游包，不宣称修复上游功能；修复范围仅为 dsh-passwords 对上游 Remote 协议的正确隔离与转发。

## 验收矩阵

| 场景 | 预期结果 |
| --- | --- |
| 子用户已获会话授权，模型调用 `ask_user_question` | 子用户当前会话显示问题，提交答案后任务继续 |
| 子用户已获会话授权，模型请求工具审批 | 子用户当前会话显示审批，结果仅回到该会话 |
| 管理员的提问/审批 | 管理员现有流程不变 |
| 子用户无会话授权或授权已撤销 | 不收到问题/审批，不能回传结果 |
| 子用户选择已分配工作区后点击侧边栏 `+` | 即使未授予工作区创建权限，也可创建该工作区内的新会话 |
| 子用户创建新工作区 | 仍需要 `allowWorkspaceCreate: true`，且新目录经过白名单和归属登记 |
| 主用户变更子用户会话/目录权限 | 既有 Remote mux 连接关闭，重连后按新权限显示 |

## 发布门槛

- [x] Issue #26 waterfall、Issue #25 弱网络工作区 upsert 和资源授权回归用例通过。
- [x] `npm test` 全量通过：245/245。
- [x] `npx tsc -p tsconfig.json --noEmit` 通过。
- [x] `npm run build` 通过。
- [x] `npm audit --omit=dev --registry=https://registry.npmjs.org`：0 vulnerabilities。
- [x] `git diff --check` 通过。
- [ ] 使用管理员和两个子用户完成测试服务器浏览器人工验收：授权、撤销、刷新/重连、提问、审批和新建会话。
- [ ] 修复发布为新版本；不得覆盖已发布的 `2.6.8` npm 包。
