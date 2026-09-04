# RC.1 子代理基础兼容实施计划

> **给 Claude:** 生成 `task-builder` 代理逐任务实施此计划。

**目标:** 让所有已经能够访问父会话的用户通过 DSH 0.1.2 RC.1 的官方子代理链路使用子代理历史、实时事件、继续任务和中断功能，不增加子代理专属权限配置或额外限制。

**架构:** 保留现有用户登录、父会话授权、目录白名单和封禁校验；对 `SessionAddress.kind === 'subagent'` 增加协议兼容分支，使子代理 child session 不再被错误地当作独立普通工作区会话要求 grant。网关只依据已授权的 `parentSessionId` 建立子代理访问上下文，同时把完整的 parent/child/mode 地址原样传给 DSH，由 DSH 负责验证子代理归属和模式；不把 child ID 写入普通会话授权表，也不开放任意未授权 parent 的 child。

**技术栈:** TypeScript、Node.js `http`/`ws`、Express、DSH 0.1.2-rc.1 ClientConnection/Remote mux、Node test runner、tsx。

---

## 范围与不变约束

1. 只处理子代理基础兼容，不修改 token 上限、Agent preset、SSH、git、文件上传或工作区权限语义。
2. 不新增 `allow_subagent` 或子代理 grant 配置；父会话已可访问的用户自动获得其可用子代理链路。
3. 不将 child session 当成普通 session 写入 `userSessionAccess`、`allowedSessionIds` 或工作区的持久化 grant。
4. 不能通过 child ID 绕过父会话权限：父会话不可见时，`session/follow`、`session/page`、`subagents/prompt`、`subagents/interruptByParent` 均应拒绝。
5. 不过滤或重写 RC.1 `session/follow` 的 snapshot、`cursor`、`records`、`projections`、`seq`、`hasMore`；这样不会破坏 DSH 的连续性检查。
6. 子代理地址的 `mode` 必须原样保留，不能由网关替换为默认模式；parent/child/mode 的真实性由 DSH upstream 校验。

## 计划任务

### 任务 1：建立当前协议和失败基线

**并行:** no  
**被阻塞:** 无  
**拥有的文件:** `src/gateway.ts`, `src/permissions.ts`, `test/gateway-proxy-headers.test.ts`, `test/permissions-pure.test.ts`

**文件:**
- 阅读：`src/gateway.ts:1398-1610`、`src/gateway.ts:4190-4580`、`src/gateway.ts:4830-5050`
- 阅读：`src/permissions.ts:830-885`
- 修改测试：`test/gateway-proxy-headers.test.ts`
- 修改测试：`test/permissions-pure.test.ts`

**步骤 1: 编写失败测试**

新增覆盖以下行为的测试：

```ts
// 子代理地址必须能被提取出 child 与 parent 两个身份；普通 session 仍保持原行为。
assert.deepEqual(
  collectSessionIds({
    address: {
      kind: 'subagent',
      parentSessionId: 'parent-visible',
      childSessionId: 'child-visible',
      mode: 'continuable',
    },
  }),
  new Set(['parent-visible', 'child-visible']),
);
```

在 Remote mux 测试 fixture 中增加：

- 已授权 `parent-visible`、未建立 child grant 的用户打开 `session/follow` 子代理地址；预期能够向 DSH 发送完整地址。
- 上游返回含 `snapshot` 和连续 `event` 的子代理流；预期 snapshot 与 event 原样到达客户端。
- 未授权 `parent-hidden` 的用户使用其 child 地址；预期请求不会到达 DSH。
- `mode: 'one-shot'` 与 `mode: 'continuable'` 均保留。

**步骤 2: 运行测试验证失败**

运行：

```bash
npm test -- --test-name-pattern="subagent|子代理"
```

预期：新增 Remote mux 子代理兼容测试失败，当前 `remoteMuxFollowSessionId()` 只接受 `kind: 'session'`；现有测试不得因本任务而减少。

**步骤 3: 记录基线**

运行：

```bash
npm test
```

记录当前总测试数、通过数和失败数。若基线失败，保留失败名称，后续只修复由本计划引入的失败。

**步骤 4: 完成基线检查**

确认测试 fixture 能区分以下三种情况：

1. 普通 session：使用 `sessionId`。
2. 子代理 session：使用 `parentSessionId`、`childSessionId`、`mode`。
3. 未授权父会话：请求必须在网关边界被拒绝。

---

### 任务 2：增加统一的子代理地址解析和父会话授权判定

**并行:** no  
**被阻塞:** 任务 1  
**拥有的文件:** `src/gateway.ts`, `src/permissions.ts`, `test/permissions-pure.test.ts`

**文件:**
- 修改：`src/gateway.ts:1491-1505` 附近的 `remoteMuxFollowSessionId`
- 修改：`src/permissions.ts:864-885` 附近的会话地址收集逻辑
- 测试：`test/permissions-pure.test.ts`

**步骤 1: 定义内部地址模型**

在网关内部使用窄类型表达两种地址：

```ts
type AuthorizedSessionAddress =
  | { kind: 'session'; sessionId: string }
  | {
      kind: 'subagent';
      parentSessionId: string;
      childSessionId: string;
      mode: 'one-shot' | 'continuable';
    };
```

解析函数必须：

- 要求 plain JSON object；
- 普通地址要求非空、长度不超过 200 的 `sessionId`；
- 子代理地址要求非空、长度不超过 200 的 `parentSessionId` 和 `childSessionId`；
- 只接受 `one-shot` 或 `continuable`；
- 拒绝额外改变语义的伪字段时，不能丢弃官方必需字段；
- 返回完整地址，不只返回 child ID。

**步骤 2: 为 Remote mux 添加父会话判定**

将 `remoteMuxFollowSessionId()` 改造成返回解析后的地址或 `null`，并新增一个内部函数取得授权依据：

```ts
function parentSessionIdOf(address: AuthorizedSessionAddress): string {
  return address.kind === 'session' ? address.sessionId : address.parentSessionId;
}
```

子代理访问判定规则：

- 普通地址：沿用当前 `access.get(sessionId)`、grant、目录、禁用会话检查。
- 子代理地址：只检查 `parentSessionId` 是否满足当前用户现有会话访问规则；不要求 `childSessionId` 出现在普通 grant 或 workspace `sessionIds` 中。
- 用户的父会话被禁用、撤权、移出目录白名单或属于其他子用户时，子代理请求拒绝。
- 子代理 child ID 不写入普通访问快照。

**步骤 3: 保持 DSH 的完整地址校验**

转发 `session/follow` 和 `session/page` 时保留完整 `address` 对象。不得把子代理请求降级成普通 `{ sessionId: childSessionId }`，否则 DSH 会返回 `session/agent-busy` 或绕过 parent/mode 关系验证。

**步骤 4: 运行纯函数测试**

运行：

```bash
npm test -- --test-name-pattern="collectSessionIds|subagent|子代理"
```

预期：地址解析、模式校验、父会话提取和非法输入测试通过。

---

### 任务 3：打通 Remote mux 的子代理 `session/follow`

**并行:** no  
**被阻塞:** 任务 2  
**拥有的文件:** `src/gateway.ts`, `test/gateway-proxy-headers.test.ts`

**文件:**
- 修改：`src/gateway.ts:4940-4998` 的 open/defer/forward 分支
- 修改：`src/gateway.ts:1525-1610` 的 Remote item 过滤分支
- 测试：`test/gateway-proxy-headers.test.ts`

**步骤 1: 编写失败测试**

覆盖：

- 已授权父会话 + 无 child grant：子代理 `session/follow` open 到达上游。
- 上游返回 `snapshot`：完整 snapshot 到达客户端，包括 `header`、`cursor`、`records`、`hasMore`、`projections`。
- 后续事件的 `seq` 不被改写、排序或丢弃。
- 子代理 `one-shot` 和 `continuable` 地址都被原样转发。
- 无效子代理地址、错误 mode、过长 ID、未授权父会话全部 fail-closed。
- workspace baseline 尚未建立时，子代理流继续使用现有等待机制，但等待完成后按父会话授权放行，不要求 child 出现在 workspace baseline。

**步骤 2: 运行测试验证失败**

运行：

```bash
npm test -- --test-name-pattern="Remote.*subagent|子代理.*follow"
```

预期：当前实现因 `remoteMuxFollowSessionId()` 不接受 `kind: 'subagent'` 而失败或返回 WebSocket `1008`。

**步骤 3: 实现最小兼容逻辑**

- `pendingSessionStreams` 保存完整解析后的地址或至少保存父会话 ID与原始请求文本；不能重建时丢失 `mode`。
- `flushPendingSessionStreams()` 对子代理只重新验证父会话和当前权限。
- `filterRemoteMuxUserItem()` 对已完成请求级授权的 `session/follow` 原样返回 DSH frame，维持 RC.1 的 gap-free 语义。
- 权限变更仍关闭用户 Remote mux，使子代理流随父会话权限一起重连。

**步骤 4: 运行专项测试**

运行：

```bash
npm test -- --test-name-pattern="Remote.*subagent|子代理.*follow"
```

预期：新增测试全部通过，普通 session/follow 原有测试仍通过。

---

### 任务 4：打通 HTTP/ClientConnection 的子代理 `session/page`

**并行:** no  
**被阻塞:** 任务 2  
**拥有的文件:** `src/gateway.ts`, `test/gateway-proxy-headers.test.ts`

**文件:**
- 修改：`src/gateway.ts:4547-4578` 的 `needsOwnershipCheck`
- 修改：`src/gateway.ts` 中 `session/page` 请求体解析和转发相关分支
- 测试：`test/gateway-proxy-headers.test.ts`

**步骤 1: 编写失败测试**

新增 `session/page` 请求：

```ts
{
  type: 'client-request',
  rpcId: 'page-subagent',
  method: 'session/page',
  payload: {
    args: {
      request: {
        address: {
          kind: 'subagent',
          parentSessionId: 'parent-visible',
          childSessionId: 'child-visible',
          mode: 'continuable',
        },
        throughSeq: 12,
        maxMessages: 50,
      },
    },
  },
}
```

预期：父会话已授权时正常转发完整请求；父会话未授权时返回 `403` 且上游无请求。

**步骤 2: 运行测试验证失败**

运行：

```bash
npm test -- --test-name-pattern="session/page.*subagent|子代理.*page"
```

预期：当前逻辑会把 child ID 也当成普通 grant 要求，导致已授权父会话的子代理分页被拒绝。

**步骤 3: 实现最小授权分支**

- 从 body 中解析准确的 `request.address`。
- 对 `kind: 'subagent'` 只把 `parentSessionId` 作为当前用户授权依据。
- 在转发前保留完整的 `address` 和分页参数。
- 仍拒绝空地址、未知 mode、非法分页参数和未授权父会话。
- 不能用 `extractSessionId()` 的“找到第一个 ID”结果作为子代理授权依据；该函数保留给普通单 ID 场景，子代理必须走完整地址解析。

**步骤 4: 运行专项测试**

运行：

```bash
npm test -- --test-name-pattern="session/page.*subagent|子代理.*page"
```

预期：分页兼容测试通过，且不影响普通会话 `session/page` 的授权拒绝测试。

---

### 任务 5：放行子代理继续任务和中断调用，但不新增权限模型

**并行:** no  
**被阻塞:** 任务 2  
**拥有的文件:** `src/gateway.ts`, `src/permissions.ts`, `test/gateway-proxy-headers.test.ts`

**文件:**
- 修改：`src/gateway.ts:4190-4580` 的 scoped request 判定
- 修改：`src/permissions.ts:830-831` 的受保护路由注释或正则（仅在实际路由缺失时）
- 测试：`test/gateway-proxy-headers.test.ts`

**步骤 1: 编写失败测试**

覆盖官方 RC.1 子代理调用：

- `subagents/prompt`：已授权父会话、child 未单独 grant 时成功到达上游；未授权父会话 `403`。
- `subagents/interruptByParent`：同上。
- 子代理 prompt 的 `parentSessionId`、`childSessionId` 同时存在时，网关不得把 child 当成普通 workspace session 强制要求 grant。
- `mode` 或目标关系异常时由 DSH 返回业务错误，网关不得改写请求为普通 session。

**步骤 2: 运行测试验证失败**

运行：

```bash
npm test -- --test-name-pattern="subagents/(prompt|interrupt)|子代理.*prompt|子代理.*interrupt"
```

预期：当前 `collectSessionIds()` 会收集 parent 与 child，并由现有 `some(!allowed)` 规则拒绝 child。

**步骤 3: 实现父会话授权判定**

新增一个共用判定函数，供 `session/follow`、`session/page`、`subagents/prompt`、`subagents/interruptByParent` 使用：

```ts
function isSubagentParentAuthorized(
  userId: number,
  parentSessionId: string,
  perms: UserPermissionsRow,
): boolean {
  const cwd = userSessionAccessFor(userId).get(parentSessionId);
  return cwd !== undefined
    && db.hasUserSessionGrant(userId, parentSessionId)
    && !perms.disabled_sessions.includes(parentSessionId)
    && folderAllowed(cwd, perms.allowed_folders)
    && !workspaceOwnedByAnotherSubuser(userId, cwd);
}
```

实际实现应复用已有辅助函数，避免重复产生第二套权限语义。对于子代理请求，校验 parent；对于普通会话请求，继续校验 session ID。child 不登记、不持久化、不加入普通 workspace 列表。

**步骤 4: 运行专项测试**

运行：

```bash
npm test -- --test-name-pattern="subagents|子代理"
```

预期：prompt、interrupt 和历史调用全部通过。

---

### 任务 6：补充端到端顺序、重连和撤权回归测试

**并行:** no  
**被阻塞:** 任务 3、任务 4、任务 5  
**拥有的文件:** `test/gateway-proxy-headers.test.ts`, `test/permissions-pure.test.ts`

**文件:**
- 修改：`test/gateway-proxy-headers.test.ts`
- 修改：`test/permissions-pure.test.ts`

**步骤 1: 编写场景测试**

必须覆盖：

1. 普通用户父会话可用，子代理 follow snapshot 可用。
2. 子用户父会话可用，child 没有独立 grant 仍可用。
3. 父会话撤权后，已建立的子代理 Remote mux 被关闭，旧连接不能继续收到事件。
4. 子用户重新连接后，必须先建立新的父会话基线，再恢复子代理流。
5. snapshot 的 `cursor`、每个 event 的 `seq`、`hasMore`、`projections` 及记录顺序完全保留。
6. parent 可见但 child 不存在或属于另一个 parent 时，请求交给 DSH 校验并返回对应业务错误；网关不把错误地址映射到另一个 session。
7. `one-shot` 子代理只读历史/事件兼容，`continuable` 子代理支持 prompt/interrupt。
8. admin 与普通 user 都能使用相同子代理协议；区别只保留现有父会话可见性规则。

**步骤 2: 运行测试**

运行：

```bash
npm test -- --test-name-pattern="subagent|子代理|Remote"
```

预期：所有新增和既有相关测试通过。

**步骤 3: 检查测试完整性**

确认测试没有通过将 child ID 直接写入 `allowedSessionIds` 来制造假阳性；测试 fixture 应明确验证 child 未被加入普通授权表。

---

### 任务 7：类型检查、全量验证和兼容矩阵更新

**并行:** no  
**被阻塞:** 任务 6  
**拥有的文件:** `docs/compatibility-matrix.md`, `README.md`, `README_en.md`（仅在项目现有兼容说明需要同步时）

**文件:**
- 修改：`docs/compatibility-matrix.md`
- 可选修改：`README.md`
- 可选修改：`README_en.md`

**步骤 1: 运行构建**

运行：

```bash
npm run build
```

预期：TypeScript 编译和客户端构建成功。

**步骤 2: 运行全量测试**

运行：

```bash
npm test
```

预期：全部测试通过，不能只报告子代理专项测试通过。

**步骤 3: 检查差异**

运行：

```bash
git diff --check
git status --short
```

确认没有修改计划范围外的文件，也没有覆盖用户原有未提交变更。

**步骤 4: 更新兼容矩阵**

将 `docs/compatibility-matrix.md` 的 Remote mux 行从“子用户需显式普通 session grant”补充为：

- `session/follow` 支持普通 session 与 RC.1 `subagent` address；
- 子代理沿用父会话访问上下文，不需要单独 child grant；
- snapshot/event 序列字段原样透传；
- 父会话撤权会关闭并重建 Remote mux；
- DSH 仍负责验证 child 是否属于给定 parent 以及 `mode` 是否匹配。

同步英文说明时保持中英文语义一致。

**步骤 5: 最终验收条件**

只有同时满足以下条件才可标记完成：

- 所有已登录用户类型都能使用官方 RC.1 子代理协议；
- 已授权父会话的 child 不再因缺少独立 grant 被拒绝；
- 未授权父会话仍不能借 child ID 访问内容；
- `session/follow` 不破坏 RC.1 的 snapshot/cursor/seq 连续性；
- `session/page`、`subagents/prompt`、`subagents/interruptByParent` 与 Remote mux 规则一致；
- `npm run build` 和 `npm test` 均通过；
- 没有执行部署、重启、发布或版本变更，除非后续明确调度。

## 风险与待确认项

- 本地当前 DSH 依赖是 `0.1.2-rc.1`；如果执行时切换到其他 RC/alpha，需要先重新确认 `SessionAddress` 和 `subagents/*` 的 wire schema，不得靠字段猜测。
- 本计划将“所有用户可用”解释为“所有具有父会话访问权的已认证用户，不需额外子代理权限”；若产品要求完全绕过父会话授权，则会形成跨用户会话泄露风险，不应直接实施。
- 子代理的 `session/follow` snapshot 可能受 Remote mux 单帧 1 MiB 上限影响；本计划不扩大该限制，只增加大快照回归测试并记录为独立可用性问题。
- 本计划不处理 SSH 插件、远程终端权限或第三方 WebSocket 的其它兼容问题。
