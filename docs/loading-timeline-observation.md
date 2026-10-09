# 加载时间线观测：上游快照准备 / baseline 等待 / 网关分段 / 终端首输出

- 整理日期：2026-10-07（本轮增强）。
- 关联计划：[dsh-mux-heartbeat-review-and-loading-plan-2026-10-07.md](../../dsh-mux-heartbeat-review-and-loading-plan-2026-10-07.md) 第五节「建立加载时间线，按瓶颈选择后续优化」（第 139–150 节）。
- 源码：`server/local preview version`。
- 观测模块：`src/loading-timeline.ts`（**纯观测**，默认关闭、结构白名单）。
- 观测测试：`test/loading-timeline.test.ts`（模块单元测试）、`test/loading-timeline-observation.test.ts`（进程外采样 + 生产埋点集成）。
- 文档性质：观察字段与采集口径说明。**不含**任何线上实测结论。

## 1. 范围与约束

观测能力集中在一个纯模块 `src/loading-timeline.ts`：

- **默认关闭**：`LoadingTimeline` 未显式传入 `enabled` 时动态跟随环境变量 `DSH_LOADING_TIMELINE`；非 `1` 时 `mark()`/`elapsed()` 直接返回、`begin()` 返回哨兵 `0`、`spanSync()`/`spanAsync()` 只执行被观测函数而不计时。零记录、零输出。
- **结构白名单**：记录只含固定 stage 常量与数值/布尔字段。调用方只能提交白名单字段；`mark()` 入口还对 stage 做运行期白名单校验，因此完整 URL、正文、Cookie、JWT、`Authorization` 在类型与运行期都无法进入记录。测试用真实 JWT、正文标记与 URL 形状做回归断言。
- **不改业务协议**：生产埋点是**只读观测**，不改变任何请求/响应形状、字段或状态机。埋点默认关闭，只有显式设置 `DSH_LOADING_TIMELINE=1` 时才会写记录。

采集口径分两层：

| 层 | 位置 | 覆盖的阶段 |
|---|---|---|
| 进程外采样 | 测试进程，经既有公开入口（HTTP 客户端、WS 客户端） | HTTP 整段缓冲首字节/完成、mux 快照/终端首个 item、共享连接是否在传历史 |
| 生产埋点 | `src/proxy.ts`、`src/gateway.ts` 内的 `loadingTimeline.*` 调用 | 上游快照准备、baseline 有界等待、history/page 的 parse/filter/stringify 与事件循环延迟 |

## 2. 两条路径为什么必须分开观察

| 路径 | 关键实现 | 对时延的含义 |
|---|---|---|
| HTTP `session.history` / `session.page` | `bufferUpstream()` 把上游响应体**累积到 `end`** 后才解压（`gunzipBounded`/`decodeUpstreamBody`）、`JSON.parse`、清洗（`sanitizeHiddenUnicodeJson`）、重新序列化并 `res.writeHead/res.end` | 客户端**首字节约等于整段完成时刻**；网络等待与网关同步处理（解压/解析/清洗/序列化）叠加；整段缓存上限 16 MiB（解压后 64 MiB），超限 fail-closed 502 |
| Remote mux 快照 / 终端 | `/api/remote.mux` 上按逻辑流逐帧转发：`upstreamWs.on('message')` → 逐帧 `sendClientItemFrame`；有界发送 `sendMuxFrameBounded`。快照 item 与终端 item 都是**收到即转发** | 首个 item 可在上游结束前到达；但受同一 carrier 的排队、`bufferedAmount` 预算与（子用户）workspace baseline 延迟影响 |

因此「HTTP HAR 的首字节」与「WebSocket 首帧」是两种不同语义，必须分别计时，不能互相替代（第 150 节）。

## 3. 观测字段（结构化白名单）

**stage** 只能取 `LOADING_TIMELINE_STAGES` 中的常量之一；**数值字段**为 `elapsedMs` / `bytesIn` / `bytesOut` / `records` / `count` / `eventLoopDelayMs` / `eventLoopDelayMaxMs`（有限数保留两位小数）；**布尔字段**为 `ok` / `historyInFlight`。未列出的键（`url`、`cookie`、`body`、`authorization` 等）一律丢弃。

| stage | 含义 | 附带字段 | 采集层 |
|---|---|---|---|
| `mux.carrier.open` | carrier 建立 | `elapsedMs`、`ok` | 进程外 |
| `mux.upstream.snapshot.prepare` | 上游快照准备：open 转发 → 上游首个 item | `elapsedMs`、`bytesIn` | 生产埋点 |
| `mux.session.follow.firstItem` | 首个完整 item（客户端视角） | `elapsedMs`、`bytesOut`、`records`、`ok` | 进程外 |
| `mux.terminal.follow.firstOutput` | 终端流 open → 首个下行输出 | `elapsedMs`、`bytesOut`、`ok` | 进程外 |
| `mux.history.inFlightAtTerminalOutput` | 终端首输出到达时快照流是否仍未 `end` | `historyInFlight` | 进程外 |
| `baseline.wait` | workspace/session 基线有界等待 | `elapsedMs`、`ok` | 生产埋点 |
| `http.history.firstByte` / `http.page.firstByte` | HTTP 请求发出 → 首个字节 / 观测窗（缓冲时为「窗口内未出现」） | `elapsedMs`、`ok` | 进程外 |
| `http.history.complete` / `http.page.complete` | 整段完成 | `elapsedMs`、`bytesOut`、`records`、`ok` | 进程外 |
| `gateway.history.parse` / `gateway.page.parse` | 解压/解码 + `JSON.parse` | `elapsedMs`、`bytesIn` | 生产埋点 |
| `gateway.history.filter` / `gateway.page.filter` | 隐藏 Unicode 清洗（含历史沙盒降级） | `elapsedMs` | 生产埋点 |
| `gateway.history.stringify` / `gateway.page.stringify` | `JSON.stringify` 重新序列化 | `elapsedMs`、`bytesOut` | 生产埋点 |
| `gateway.eventLoop.delay` | 事件循环延迟样本（均值/峰值毫秒与样本数） | `eventLoopDelayMs`、`eventLoopDelayMaxMs`、`count` | 生产埋点 |

> 相对上一版：`bytes` 拆分为 `bytesIn`/`bytesOut`；新增 `records`、`eventLoopDelayMs`、`eventLoopDelayMaxMs`、`baseline.wait`、`mux.upstream.snapshot.prepare`、`gateway.{history,page}.{parse,filter,stringify}`、`gateway.eventLoop.delay`。

### 事件循环延迟采样

`EventLoopDelaySampler`（共享实例 `eventLoopDelaySampler`）用 `perf_hooks.monitorEventLoopDelay()` 采集事件循环阻塞直方图：

- **惰性启用**：首次 `sample()` 时才 `enable()`；直方图内部定时器为 `unref`，不会阻止进程退出（实现时已实测）。
- **采样窗口**：每次 `sample()` 取 `mean`/`max`（毫秒）与 `count`，随后 `reset()` 复位窗口；窗口尚未填充（`count === 0`）时跳过，避免记下退化的 `NaN`。
- 生产埋点在 history/page 处理完成后各采样一次；`start()` 关闭时为无操作，`stop()` 幂等。

## 4. 观察用例如何证明「缓冲 vs 增量」

集成测试用**上游 hold**（只发首个 item / 只发响应头，不 `end`）制造对照，不依赖墙钟上界，因而稳定：

1. **HTTP history / page**：上游 `flushHeaders()` 后 hold。缓冲路径在观测窗内不向客户端写任何字节，直到放行整段后才返回 200 → 证明整段缓冲。
2. **Remote mux**：上游下发首个 item 后 hold。客户端在**上游结束之前**即收到 item → 证明增量转发。
3. **同 carrier 并发**：同时开 `session/follow` 与 `terminal/follow`，终端首输出到达时快照流尚未 `end`，记为 `historyInFlight=true`（第 148 节）。
4. **生产埋点**（临时设 `DSH_LOADING_TIMELINE=1` 并复位共享实例后断言）：
   - history/page 请求后共享时间线含 `gateway.{history,page}.{parse,filter,stringify}` 与 `gateway.eventLoop.delay`，且 `bytesIn`/`bytesOut` 为数值；
   - mux 快照 open 后含 `mux.upstream.snapshot.prepare`；
   - 子用户 `session.list` 无基线 → 有界等待后 503 `BASELINE_PENDING`，含 `baseline.wait`（`ok=false`、`elapsedMs` ≈ 超时）。

## 5. 与第 139–150 节的对应关系

| 第 141–148 节要求 | 覆盖情况 | 说明 |
|---|---|---|
| 1 用户操作 → 目录/工作区可用 | 否 | 属浏览器/前端时序，需客户端实测（第 6 节） |
| 2 首批历史开始响应、完整接收、字节数、消息数 | 是 | `http.history.*`/`http.page.*` 记录首字节/完成与 `bytesOut`；**消息数**经 `records` 字段从结构化帧/信封计数（只记数量，不记内容）；上游原始字节数经 `gateway.*.parse` 的 `bytesIn` 记录 |
| 3 网关解压、权限处理、解析、序列化耗时 | 是 | `gateway.{history,page}.{parse,filter,stringify}` 分段计时 |
| 4 浏览器解析、长任务、首个可交互 | 否 | 属浏览器性能轨迹，不在 Node 测试范围 |
| 5 权限基线等待、重试、失败 | 是 | `baseline.wait` 记录有界等待耗时与 `ok`（到达/超时） |
| 6 终端首输出 + 共享连接是否在传历史 | 是 | `mux.terminal.follow.firstOutput` + `mux.history.inFlightAtTerminalOutput` |
| 同步记录事件循环延迟 | 是 | `gateway.eventLoop.delay`（本进程；CPU/内存未纳入） |

## 6. 仍未覆盖 / 需要更多 hook 的字段（本轮不实现）

- **mux 首输出的服务端时刻与 `bufferedAmount`**：当前 mux 只记录「上游首个 item」的到达，未在 `sendClientItemFrame` 前后记录发送时刻、流类别（固定枚举）与 `bufferedAmount`。
- **CPU / 内存**：仅事件循环延迟，未采样 `process.cpuUsage()/memoryUsage()`。
- **浏览器时序**：目录/工作区可用、首个可交互、长任务——需前端轨迹。
- **关闭诊断**：`src/remote-mux-diagnostics.ts` 已单独负责；每条 carrier 一次终止事件（来源/方向/code/缓冲与队列字节/探测状态/耗时），原因用受限分类。

## 7. 隐私约束

- 观测记录**只含** stage 常量与数值/布尔，绝不含正文、Cookie、JWT、`Authorization`、完整 URL（含 query）。
- 生产埋点只写入耗时与 `bytesIn`/`bytesOut`/`records`/`count` 等数值，不写入任何帧内容；`bytesIn`/`bytesOut` 由源码中的 `Buffer.length` 计算，不经过字符串内容。
- 采集 HTTP 时只保留状态码、字节数与耗时；不落盘请求/响应体。
- 模块与埋点**默认关闭**：未显式开启不产生任何输出，避免默认泄漏与噪声。
- 上线任何新埋点前，须遵循计划第 171 行：原因分类受限，日志不得包含原始正文、凭证、完整 URL 或未处理错误字符串。

## 8. 运行方式

```sh
cd "local preview version"
# 纯模块单元测试（默认关闭，无额外输出）
node --import tsx --test test/loading-timeline.test.ts
# 集成用例（默认关闭：只跑回归断言，生产埋点不生效、无额外输出）
node --import tsx --test test/loading-timeline-observation.test.ts
# 显式开启：进程外 recorder 额外输出一行 JSON 摘要，并在集成用例内临时开启生产埋点做断言
DSH_LOADING_TIMELINE=1 node --import tsx --test test/loading-timeline-observation.test.ts
```

在完整门禁中：先 `npm run build`，再 `node --import tsx --test "test/**/*.test.ts"` 会同时运行上述两个测试（本轮改动为纯增量的观测模块与默认关闭埋点）。

## 9. 限制

- 本工具观测的是**网关 ↔ 上游 ↔ 测试客户端**的本地时序，用于区分缓冲与增量，不等价于线上带宽、RTT 或浏览器渲染耗时。
- `gateway.eventLoop.delay` 是**观测进程本身**的事件循环延迟；集成测试与网关同进程，故可代表同一事件循环，但线上不等价于客户端或上游主机。
- HTTP `firstByte` 的「窗口内未出现」是方向性证据（缓冲路径在整段到达前不写响应头）；`gateway.*.parse` 已把解压/解码并入 parse，未单列 `decompress` 段。
- 消息条数、浏览器首个可交互时刻、服务端 CPU/内存等仍需按第 6 节补充 hook 或前端轨迹。
