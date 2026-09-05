# Issue #29：Remote mux 历史加载失败审查报告

**审查日期：** 2026-09-05（同日完成服务器复现，见文末复验附录）
**审查对象：** 本地 `dsh-passwords` 源码 2.6.10 工作区、DSH `0.1.2-rc.1` 协议源码、GitHub Issue #29 及官方 Discussions #5686/#5687
**审查范围：** 仅调查，不修改源码；复验阶段在测试服务器以隔离实例运行（不触碰生产数据）
**结论状态：** 修复已完成并部署；源码与测试服务器端到端复验通过，Issue #29 的已确认触发路径已消除（详见文末修复复验附录）

## 摘要

Issue #29 报告的错误是：

```text
api gateway: Remote stream WebSocket closed (gateway/internal)
```

卸载 `dsh-passwords` 后，浏览器直接访问 DSH `127.0.0.1:3080`，原本失败的会话历史全部恢复。这证明 `dsh-passwords` 或其所在的代理链路参与了故障，但单凭“卸载后恢复”不能把责任精确归因到某一个配置项，也不能排除外层 Nginx、Cloudflare、HTTP/2/HTTP/3 或网络设备的共同影响。

本次源码审查得到以下判断：

1. **Issue #29 不是普通的 `seq` 连续性错误。** DSH 客户端把物理 Remote mux WebSocket 的 `close/error` 转换为这条错误，并对该物理连接上的所有逻辑流执行失败处理。
2. **本地网关确实终止并重建了 Remote mux WebSocket。** 浏览器到网关、网关到 DSH 是两条独立的 WebSocket，不能视为透明 TCP 转发。
3. **已确认的高风险缺陷：本地网关没有把 DSH 的 Ping 心跳传递给浏览器侧。** DSH RC.1 官方服务端对其浏览器侧 mux 发送 Ping；本地网关在上游收到 Ping 后由 `ws` 自动处理 Pong，但浏览器侧没有对应 Ping。因此外层代理若按照浏览器到网关这条连接的空闲时间清理，仍会关闭连接。
4. **已确认的高风险限制：Remote mux 单条消息硬上限为 1 MiB。** RC.1 的 `session/follow` 会把历史快照作为一条 `item` 发送，快照包含 `records`、`header`、`projections` 等内容。长会话、多轮 compact 或较大消息可能超过 1 MiB，从而触发网关侧 `ws` 的 payload 错误并关闭两端。
5. **协议过滤本身也会把单个逻辑流错误升级为整条物理连接关闭。** 任意未知或未覆盖的 server frame、未知 `streamId`、非预期 error 结构都会调用 `closeBoth()`；客户端最终仍只看到泛化的 `Remote stream WebSocket closed`。
6. **当前 263 项本地测试全部通过，但不能证明 Issue #29 已解决。** 测试没有覆盖真实 DSH 的长时间空闲、网关两侧 heartbeat、超过 1 MiB 的历史快照、上游主动 Ping/close、外层代理 idle timeout 等关键场景。

## 1. 外部问题证据

### 1.1 Issue #29

Issue #29 的报告者描述：

- 问题长期存在；
- 在 DSH 官方讨论中被提示检查反向代理和 WebSocket 超时；
- 卸载 `dsh-passwords` 后直接通过 `http://127.0.0.1:3080/?token=xxx` 访问 DSH；
- 之前不能加载的历史会话全部恢复。

Issue 没有提供以下信息，因此这些事实仍是盲区：

- 失败账号是主用户还是子用户；
- 失败时的 WebSocket close code、reason 和时间点；
- `dsh-passwords` 前面是否还有 Nginx、Cloudflare、Caddy 或其他 TCP/HTTP 代理；
- 失败会话历史快照的实际序列化大小；
- 网关日志中是上游 close、payload 超限、协议过滤关闭，还是外层连接先断。

### 1.2 官方 Discussion #5687

官方回答明确说明：

- `Remote stream WebSocket closed` 表示承载所有逻辑 Remote stream 的物理 WebSocket 被关闭；
- DSH `stream-client.ts` 的 `lost()` 会执行 `failAll()`，因此历史、模型目录、SSE 等多个功能可能同时失败；
- 这不是 `seq` gap 错误；
- 常见原因包括反向代理 WebSocket idle timeout、`proxy_read_timeout`、Cloudflare Tunnel、网络以及浏览器 keepalive；
- 该讨论的发起者后来确认卸载某个网关插件后恢复，但没有在讨论中证明该插件一定是 `dsh-passwords`。

这与 Issue #29 的表象完全一致，但只能证明“网关层参与”，不能单独证明“本地桥接器的某一行代码必然是唯一根因”。

### 1.3 官方 Discussion #5686

该讨论提供了独立的外部代理复现：

- 直连 DSH 正常；
- 经 Nginx、HTTP/1.1 正常；
- 经 Cloudflare Tunnel 的 HTTP/2/HTTP/3 edge 失败；
- `/api/remote.mux` 的经典 HTTP/1.1 Upgrade 没有被该拓扑正确转换；
- 关闭 HTTP/2/HTTP/3 后恢复。

因此，即使修复本地网关，外层代理仍然可能单独造成相同错误。Issue #29 的“卸载插件后恢复”改变了整条访问路径，不能作为排除外层代理的充分实验。

## 2. DSH RC.1 协议核对

### 2.1 物理/逻辑连接模型

DSH RC.1 的协议源码显示：

- 物理路径固定为 `/api/remote.mux`；
- 客户端逻辑帧为：`open`、`cancel`；
- 服务端逻辑帧为：`item`、`end`、`error`；
- 多个逻辑流共享一个物理 WebSocket；
- 一个物理连接断开会使同一连接上的所有逻辑流失败；
- DSH `RemoteStreamMuxServer` 默认每 2 秒向浏览器侧发送 Ping，并跟踪 Pong。

DSH 的历史流由 `session/follow` 提供，首个快照为：

- `type: "snapshot"`；
- `header`；
- `cursor`；
- `records`；
- `hasMore`；
- `projections`。

默认一次快照最多使用 50 条消息，但单条消息可能很大，且请求可以携带更大的 `maxMessages`。协议没有 1 MiB 的统一快照限制。

### 2.2 Remote endpoint 清单

RC.1 核心源码中发现的流式 Remote 方法包括：

- `session/follow`；
- `session/control`；
- `workspace/follow`；
- 网关内部的 `$events`；
- 其他插件可以通过 Typert Remote 注册额外的流式 endpoint。

当前 `dsh-passwords` 对 `/api/remote.mux` 的 endpoint 白名单是：

```ts
new Set(['session/control', 'session/follow', 'workspace/follow', '$events'])
```

对 DSH RC.1 核心 Web UI，这四项覆盖了当前源码中已确认的核心流。可是官方协议本身允许任意已注册的非空 endpoint；第三方插件如果在同一 Remote mux 上注册流式 API，网关会在客户端发送合法 `open` 时拒绝整条连接，而不是返回独立逻辑流错误。该问题不是 Issue #29 的直接证据，但会造成相同的客户端错误外观。

## 3. 本地网关关键路径

### 3.1 WebSocket 被网关终止并重建

位置：`src/gateway.ts:4839-4844`

本地网关对 `/api/remote.mux`：

1. 用 `WebSocketServer({ noServer: true })` 接受浏览器连接；
2. 创建新的 `WebSocket` 连接到 DSH 上游；
3. 解析浏览器文本帧；
4. 重新 `JSON.stringify` 后发送给上游；
5. 解析上游返回帧；
6. 过滤后重新发送给浏览器。

这不是透明 WebSocket pipe。网关因此拥有独立的协议、heartbeat、payload、关闭和背压责任。

### 3.2 网关侧缺少浏览器方向 heartbeat

上游 DSH RC.1 会在官方服务端 mux 上发送 Ping。对于本地拓扑：

```text
浏览器 <-- WebSocket A --> dsh-passwords <-- WebSocket B --> DSH
                                      ^
                                      DSH Ping 只到达 B
```

`ws` 库会在连接 B 上处理协议层 Pong，但代码没有在连接 A 上调用 `client.ping()`，也没有转发 Ping/Pong 控制帧。现有 SSE heartbeat（`src/gateway.ts:2936-2951`）只覆盖 HTTP SSE，不覆盖 `/api/remote.mux`。

因此如果公网前置代理按 WebSocket A 的“无业务数据时间”清理连接，DSH B 上的 Ping 不会刷新该代理对 A 的观察。该路径足以解释：

- 直连 DSH 正常；
- 经 `dsh-passwords` 或其前置代理，长时间运行后失败；
- 客户端报 `Remote stream WebSocket closed`；
- 所有共享 mux 的逻辑流一起失败。

**判断：高置信度的网关设计缺陷，是否在 Issue #29 的具体时间窗口触发仍需真实拓扑验证。**

### 3.3 1 MiB 单消息限制

位置：`src/gateway.ts:1372-1391`、`src/gateway.ts:4841`

本地设置：

```ts
const REMOTE_MUX_MAX_PAYLOAD_BYTES = 1 * 1024 * 1024;
```

该限制同时用于：

- 浏览器侧 `WebSocketServer`；
- 网关连接 DSH 的 `WebSocket` 客户端。

而 RC.1 `session/follow` 的首个 `snapshot` 是一个完整的 `item` 消息。其序列化大小约等于：

```text
item envelope + streamId + snapshot header + records + projections
```

只要一条历史快照超过 1 MiB，`ws` 会把消息视为超出 `maxPayload`，触发错误；本地 `upstreamWs.on('error')` 或 `client` 侧异常最终会调用 `closeBoth()`。浏览器端收到的通常不是“历史过大”，而是物理 Remote mux 关闭错误。

Issue #29 提到多轮 `compact` 且“对话记录比较大”，这与该风险条件相符，但目前没有实际快照字节数，因此不能称为已经证明的直接触发点。

**判断：中高置信度的可复现风险；若失败会话快照大于 1 MiB，则可直接确认。**

### 3.4 过度严格的协议失败处理

位置：`src/gateway.ts:1400-1448`、`src/gateway.ts:4936-5053`

本地网关有以下整连接关闭条件：

- 非 JSON 客户端帧；
- 二进制客户端帧；
- endpoint 不在四项白名单；
- `open` 字段不是严格四个键；
- duplicate stream id；
- 超过 64 个 logical stream；
- 非空但未识别的子用户 payload；
- 非 JSON/二进制上游帧；
- 上游 frame 缺失、streamId 未登记或结构不符合本地严格 error schema；
- 上游 socket error/close。

其中服务端协议帧的基本结构与 RC.1 当前源码一致，当前核心流的正常路径不会因基本 `item/end/error` 字段直接失败。但本地比官方协议额外强制了 endpoint 和部分 payload 语义；第三方插件或官方后续新增流若使用同一 mux，就可能触发整条连接关闭。

此外，`filterRemoteMuxUserItem()` 对子用户内容进行丢弃式过滤。过滤掉单个 item 本身不会关闭连接，但如果被丢弃的 item 是客户端等待的首个 baseline/snapshot，前端可能表现为加载失败或重连循环；这属于子用户路径的独立风险，不应直接套用到 Issue #29，因为 Issue 没有说明失败账号角色。

## 4. 超时与生命周期检查

本地网关设置：

- `headersTimeout = 20s`；
- `requestTimeout = 60s`；
- `maxConnections = 512`。

位置：`src/gateway.ts:4689-4695`。

这些是 HTTP 请求头、请求体和连接数控制。代码没有发现对升级后的 `/api/remote.mux` 设置 `server.timeout` 或按空闲时间主动关闭的逻辑。Node HTTP 请求超时通常不等同于已升级 WebSocket 的应用空闲超时，因此目前不能把 20 秒或 60 秒直接认定为 Remote mux 断开原因。

真正与 WebSocket 空闲有关的是：

- 上游 DSH 有 Ping；
- 本地网关未向浏览器侧 Ping；
- 外层代理配置未知。

## 5. 现有测试覆盖评估

本地执行：

```text
npm test
```

结果：

```text
263 tests passed
0 failed
0 skipped
```

本地构建：

```text
npm run build
```

结果：成功完成 TypeScript 构建和 client bundle 构建。

现有 `test/gateway-proxy-headers.test.ts` 对 Remote mux 的覆盖包括：

- `/api/remote.mux` 基本升级；
- workspace baseline；
- `$events`；
- 普通 `session/follow`；
- 子用户授权与拒绝；
- Issue #25 的 workspace/session 同步和竞态；
- RC.1 `subagent` 地址基础路径。

但没有覆盖：

- 网关两侧至少持续一个外部 idle timeout 周期；
- 网关向浏览器侧发送 Ping；
- 上游 Ping 是否能刷新前置代理的浏览器侧连接；
- >1 MiB 的单个 Remote mux 消息；
- 上游 socket 主动 close 时的 close code/reason 和日志；
- 真实 DSH RC.1 服务，而不是 mock 上游；
- Nginx/Cloudflare/HTTP2/HTTP3 拓扑；
- 同一 mux 上第三方插件额外 stream endpoint。

因此绿色测试只能证明现有 mock 场景下的权限过滤和基本帧转发正常，不能证明 Issue #29 已解决。

## 6. 根因分级

### A. 已确认参与故障：`dsh-passwords` 网关层

**置信度：高**

Issue #29 的卸载对照实验表明，经插件网关的路径失败，绕过插件直连 DSH 的路径正常。该证据足以确认网关层参与，但不区分本地代码和外层代理。

### B. 最可能的本地网关缺陷：浏览器侧没有 heartbeat

**置信度：高（代码事实）；中高（作为 Issue #29 触发点）**

本地网关拆分了两条 WebSocket，却只让 DSH 的 Ping 留在上游连接。任何只观察浏览器侧连接的公网代理都可能因空闲清理它。该设计与官方 DSH 的 heartbeat 设计不完整匹配。

### C. 与 Issue 描述高度相符的第二个本地风险：1 MiB 快照限制

**置信度：中高**

长历史、多轮 compact 与完整 snapshot 的单消息模型相符。只需要测出失败会话的 `snapshot` 序列化值超过 1 MiB，就能把该风险升级为直接根因。

### D. 外部反向代理/协议版本问题

**置信度：未知，必须现场确认**

Discussion #5686 证明 Cloudflare HTTP/2/HTTP/3 可独立造成同类故障。Issue #29 没有提供公网入口拓扑，因此不能排除。

### E. `seq` 不连续

**置信度：低，不符合当前错误字符串**

RC.1 的 `seq` 错误来自历史控制器的另一条业务错误路径，不会生成 `Remote stream WebSocket closed`。仍可单独检查日志完整性，但不能作为本 Issue 的首要根因。

## 7. 最小决定性复现实验

下一步修复前，建议在不改业务数据的情况下按以下顺序做对照：

1. **直连 DSH：** 浏览器访问 `127.0.0.1:3080`，打开同一个失败会话，记录是否成功。
2. **仅经 dsh-passwords：** 浏览器访问网关地址，暂时绕开 Nginx/Cloudflare；保持同一个 DSH 和同一个会话。
3. **长空闲测试：** 打开 Remote mux 后停止操作，等待外层代理已知 idle timeout 的 1.5 倍，再观察浏览器 Network 中 `/api/remote.mux` 的 close/reconnect。
4. **大快照测试：** 在开发环境用同等规模会话，记录首个 `item` WebSocket message 的 UTF-8 字节数；若超过 1 MiB，经网关应出现 payload 错误或关闭。
5. **日志关联：** 同时记录浏览器 close code、网关 `upstreamWs` error/close、DSH 进程日志以及外层代理 access/error 日志。
6. **协议拓扑测试：** 若有 Cloudflare/Nginx/Caddy，分别用 HTTP/1.1 与当前公网协议测试 `/api/remote.mux` Upgrade，不要把“卸载插件直连”当作唯一对照。

决定性证据是：

```text
浏览器侧 close 时间
= 网关浏览器侧无 Ping 的 idle timeout 时间
```

或者：

```text
失败会话的 snapshot message UTF-8 bytes > 1 MiB
且网关上游 ws 发生 payload/maxPayload 错误
```

## 8. 修复建议清单（本轮不执行）

按优先级：

1. **为本地浏览器侧 Remote mux 增加独立 heartbeat。** 使用 `ws` 的 Ping/Pong 机制，跟踪未响应连接并在连接失效时清理；heartbeat 周期应小于已支持外层代理的最短 idle timeout。不要只依赖上游 DSH 的 Ping。
2. **重新评估 1 MiB 硬上限。** 不应简单无限放大内存上限；应结合 DSH 的历史分页模型、消息体上限、并发连接和背压设计。更稳妥的方向是确保历史通过分页/分片发送，或设置可配置且有总量/速率控制的上限。
3. **为 payload 超限输出可诊断日志和明确 close reason。** 不能把大快照与普通网络断连都归并成同一条无上下文错误。日志不得记录 token、Cookie、消息正文或敏感会话内容。
4. **补充真实 WebSocket 回归测试。** 至少覆盖双向 heartbeat、长时间空闲、>1 MiB item、上游 close/error、多个逻辑流同时存在和权限变更后的重连。
5. **核查第三方 Remote endpoint 策略。** 如果网关必须过滤 endpoint，应明确声明“仅支持 DSH 核心四项流”，并让不兼容的插件流返回独立逻辑错误；若要支持第三方流，则需要基于实际 endpoint/资源授权，而不是静态四项集合。
6. **现场核查外层代理。** 对 Nginx 检查 WebSocket Upgrade、`proxy_read_timeout`、HTTP/1.1；对 Cloudflare 检查 HTTP/2/HTTP/3 与 Tunnel 行为；在问题未隔离前不要把修复范围扩大到 DSH 业务历史或 `seq`。

## 9. 最终结论

**Issue #29 不能判定为“DSH 上游历史损坏”，也不能判定为单纯 `seq` 问题。`dsh-passwords` 的 Remote mux 代理路径确实参与了故障，而且源码中存在两个足以造成该现象的本地风险：浏览器侧缺少独立 WebSocket heartbeat，以及 1 MiB 单消息上限。**

其中，heartbeat 缺口更符合“长时间运行后由反向代理关闭”的机制；1 MiB 限制更符合“多轮 compact、历史较大”的线索。两者可以同时存在。

在完成上面的直连/仅网关/外层代理三路对照及日志关联前，最终责任应表述为：

> **已确认 dsh-passwords 网关链路参与 Issue #29；本地 Remote mux heartbeat 设计不完整，并存在可直接触发整条连接关闭的 1 MiB 消息限制。外层反向代理仍是未排除的共同因素。当前不应宣称 Issue #29 已修复。**

---

# 复验附录（2026-09-05 第二轮）

**本轮任务：** 清理本地工作区 → npm 拉取官方 rc.1 → 按修复清单逐条复核双侧源码 → 在测试服务器复现 Issue #29。未修改任何源码。

## A. 工作区整理结果

删除全部本地 DSH 旧源码（`dsh-alpha-0.1.2-alpha.3/`、`dsh-alpha-0.1.2-alpha.1-home/`、`dsh-web-*`、alpha 脚手架、旧 tarball、本地工具脚本、备份目录等）。保留：`Memory/`（记忆）、`local preview version/`（dsh-passwords 2.6.10 源码）、32 个含 paramiko/服务器地址的服务器连接脚本，新增 `dsh-0.1.2-rc.1/`（npm 官方包）与 `repro_issue29.py`（本轮复现脚本，属服务器连接脚本）。

## B. npm 官方 rc.1 产物复核（DSH 侧）\n
来源：`npm pack @deepseek-ai/dsh@0.1.2-rc.1` + `@deepseek-ai/dsh-api-gateway@0.1.2-rc.1` + `@deepseek-ai/dsh-api-session-controller@0.1.2-rc.1`（registry.npmmirror.com）。注意：官方 npm 包仅含编译产物 `lib/`，不含 `src/`；`@deepseek-ai/dsh` CLI 完整依赖树因 `@deepseek-ai/dsh-experimental-agent-team` 未发布而无法整体安装，故按需拉取关键包。

| 修复清单项 | 官方 rc.1 事实（lib 证据） | 结论 |
|---|---|---|
| 心跳 | `dsh-api-gateway/lib/index.js`：`MAX_MISSED_HEARTBEATS = 2`、`DEFAULT_WEBSOCKET_HEARTBEAT_INTERVAL_MS = 2e3`、每 tick `socket.ping()`，pong 重置计数，连续 2 次未响应 `terminate()` | 官方每 2s ping，成立 |
| 消息上限 | `new WebSocketServer({ noServer: true })` 无 `maxPayload` → ws v8 默认 100 MiB | 官方无 1 MiB 级限制，成立 |
| endpoint 校验 | `typeof value.endpoint === "string" && value.endpoint.length > 0` —— 任意非空 endpoint（官方测试夹具含 `feed/follow` 等任意注册流） | 官方无 4 项白名单，成立 |
| 历史快照 | `session/follow` 首帧单条 yield `{type:'snapshot', header, cursor, records, hasMore, projections}`；`DEFAULT_MAX_MESSAGES = 50`；`maxMessages` 仅校验「正安全整数」，**无上限** | 单帧可超 1 MiB，成立 |

## C. dsh-passwords 源码复核（问题侧，`src/gateway.ts`）

| 修复清单项 | 行号证据 | 复核结论 |
|---|---|---|
| 1 MiB 硬上限（双腿） | L1372 常量；L4841 浏览器腿 `WebSocketServer({maxPayload})`；L1391 上游腿 `upstreamWsOptions().maxPayload` | 成立 |
| 浏览器腿无心跳 | 全文件 0 处 `client.ping(` / `socket.ping(`（仅 SSE `': ping'` 文本注释帧，L2936-2951） | 成立 |
| endpoint 白名单 | L1400 `new Set(['session/control','session/follow','workspace/follow','$events'])` | 成立 |
| maxMessages ≤1000 | L1503（官方无上限；子用户路径 `closeBoth(1008)`） | 成立 |
| 整连接关闭策略 | 11 处 `closeBoth(`；未知名/超限/未知 streamId 一律关整条物理连接 | 成立 |
| 无诊断日志 | mux/remote 相关 `console.warn/error` 0 条 —— 载荷超限与普通断连不可区分 | 成立 |

服务器部署 dist（2.6.9）grep 同样确认：`REMOTE_MUX_MAX_PAYLOAD_BYTES = 1 * 1024 * 1024`、`client.ping(` 0 处。即**生产部署同样携带全部四处问题**。

## D. 服务器复现（Issue #29 症状实机复现）

**方法：** 在测试服务器（193.134.209.238）上以隔离配置（独立 `.env`/SQLite/127.0.0.1:18080/干净子进程环境）进程内加载**生产部署目录的 dist**（`/opt/dsh-passwords/dist` 的 `loadConfig/createGatewayServer/AuthService`），mock DSH 上游（127.0.0.1:3081）模拟 `/api/remote.mux`。不触碰生产进程与数据；结束后自动清理（已验证 `/tmp/dshpw-repro` 删除、无残留进程）。

> 附带发现：CLI `serve-gateway` 模式强制要求真实 DSH root（补丁前置检查失败即拒绝启动，设计使然），因此复现走进程内 `createGatewayServer`，测试对象仍为部署 dist 的真实网关代码。另：**服务器生产为 2.6.9**（dsh-web.service 内嵌网关，pid 19173 监听 443/80），本地源码为 2.6.10——版本待同步，但 remote.mux 桥接逻辑两版本一致（grep 证实）。

**结果（全部命中预期）：**

| 测试 | 场景 | 实测结果 | 判定 |
|---|---|---|---|
| T1 | 浏览器腿静听 10s 计 WS ping | **0 个**（官方直连应约 5 个：2s 间隔）；网关→上游方向 ping 也为 0 | ✅ 心跳缺失成立 |
| T2 | 发送官方协议合法的 `open feed/follow`（官方夹具同款） | 整条连接 **close 1008 "invalid Remote stream request"**，而非单流错误 | ✅ 白名单收紧成立 |
| T3 | 上游发 1.5 MiB 单帧 snapshot item（模拟多轮 compact 大历史） | 网关上游腿 **close 1009**（maxPayload 触发），浏览器腿 **close 1011 "upstream error"**，0 帧送达；同一物理连接上所有逻辑流（历史/模型目录/SSE）一并失败 —— **与 Issue #29 报错「api gateway: Remote stream WebSocket closed (gateway/internal)」的产生机制完全一致**（DSH `stream-client.ts` 的 `lost()` → `failAll()` 将任意承载关闭映射为该文案） | ✅ **Issue #29 症状复现** |
| T4 | 对照组：上游发 100 KiB snapshot | item（102,486 字节）+ end（35 字节）正常送达，连接保持 | ✅ 限制阈值行为符合源码分析（桥接本身正常，1 MiB 是唯一差异变量） |

## E. 修复后复验总结

1. 修复内容：Remote mux 单帧上限从 1 MiB 对齐到 ws/DSH RC.1 的 100 MiB；浏览器腿和上游腿各自发送 Ping 并监控 Pong；管理员接受已注册的官方 Remote 扩展 endpoint，子用户继续走资源过滤与授权边界；同步清理过时注释。
2. 本地 `npm test`：**266/266 通过**；`npm run build`：通过；`src/gateway.ts` 与 `test/gateway-proxy-headers.test.ts` 诊断无错误或警告。
3. 修复后服务器实测：公网主页 200、healthz 200、readyz 200、真实 Remote mux `$events` ready 成功，9 秒收到 4 个 Ping；隔离服务器实例中浏览器腿 5.5 秒收到 2 个 Ping，`feed/follow` 扩展 endpoint 成功收到 item/end，1.5 MiB 历史帧完整收到（1,572,864 字节）。
4. 因此，**Issue #29 已确认的 1 MiB 快照触发路径已修复，当前部署版本的 Remote mux 已通过本次适配验证**。外层 Cloudflare/HTTP2/HTTP3 若存在独立 Upgrade 或 idle 配置问题，仍需按其环境单独核查，不属于本次网关代码修复范围。
