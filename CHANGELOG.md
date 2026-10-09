# Changelog

## 2.7.8 - 2026-10-10

### 中文

更新公告：

1. 兼容 DSH `0.2.1-alpha.2`：9 个 `@deepseek-ai/dsh*` 开发依赖、`npm-shrinkwrap.json`、安装器与 bundled Docker 默认运行时统一升级并锁定到官方 alpha.2；声明范围保持 `>=0.2.1-alpha.1 <0.2.2-0` 不变。
2. 新增 Issue #38：目录权限收口为单一 `allowedFolders`（「可读取目录」），可读与可创建合二为一——主用户通过受限目录浏览器为子用户分配，浏览起点取自 `MCP_GATEWAY_DIRECTORY_PICKER_ROOTS`（未配置时默认用户家目录，全盘根永不作为起点，绝不从整机根枚举）。白名单内即可读；开启「新建工作区权限」后，同一批可读目录也是创建范围，子用户可在其中新建文件夹并登记为工作区；白名单外不可读也无法创建。`[]` 沿用既有「不限目录」语义，`['__deny__']` 禁止全部；关闭开关只禁止创建、保留可读范围。不再提供独立的创建根配置。
3. 新增 Issue #39 处理与多用户协作改进：`listAssignableWorkspaces()` 改为批量标题快照、仅对缺标题 session 读取 surface；三个超时/TTL 键纳入 managed env 并支持可选 inventory TTL，修复工作区展示 504 与权限保存 502。权限保存提交后立即撤销旧的 legacy/Remote 订阅发送资格，缩小沙盒异步处理期间的权限撤回窗口；对 `workspaceFiles/changes` 的每个变化帧重新执行工作区、归属与敏感路径检查；归档/解档成功响应与 Remote 归档增量立即更新子用户会话列表投影，较早的慢列表响应不得回滚新归档状态。
4. 修复 Issue #36：当 `DSH_PASSWORDS_ENV_FILE` 指向尚不存在的 `.env` 时，非 root 首次安装会命中「自动 HTTPS 需要 root」门禁并在插件注册前退出。修复为 fail-closed：仅明确关闭自动 HTTPS（`0/false/no`）或同时提供自管证书时允许非 root 首次安装，默认/开启/未知值与单边/空白证书仍要求 root；非 root 安装默认目录改为 `$HOME/dsh-passwords`，非特权首次生成的配置不再硬编码 443/80。
5. 修复 alpha.2 的可选 bind-all 补丁：同时适配 CLI 与 WebServer 配置中的通配监听限制，状态检测、关闭开关恢复和回滚覆盖两处；默认不修改监听限制。
6. 发布包纳入 `docs/`，避免 README 中的相对文档链接在 npm 包内失效；Docker 镜像补充就绪探针与构建期版本断言。

### English

Release notes:

1. DSH `0.2.1-alpha.2` compatibility: the nine `@deepseek-ai/dsh*` dev dependencies, `npm-shrinkwrap.json`, the installers, and the bundled Docker default runtime are upgraded and locked to the official alpha.2; the declared range stays `>=0.2.1-alpha.1 <0.2.2-0`.
2. New in Issue #38: directory authorization is folded into the single `allowedFolders` ("Readable directories"), merging read and create scope. The owner assigns them with the restricted directory browser, whose roots come from `MCP_GATEWAY_DIRECTORY_PICKER_ROOTS` (defaults to the user home when unset; a filesystem root is never a starting point, so the whole disk is never enumerated). Anything inside the allowlist is readable; with "Workspace creation permission" enabled those same readable directories are also the creation scope, so a subuser can create new folders there and register them as workspaces, while anything outside is neither readable nor creatable. `[]` keeps the existing unrestricted-directory semantics and `['__deny__']` denies all; turning the switch off only denies creation and preserves the readable scope. No separate creation-root configuration remains.
3. New Issue #39 handling and multi-user collaboration improvements: `listAssignableWorkspaces()` now uses batched title snapshots and reads surface only for sessions without a title; the three timeout/TTL keys are wired into the managed env with an optional inventory TTL, fixing the workspace-view 504 and the permission-save 502. A permission update immediately revokes legacy and Remote subscription delivery eligibility, shrinking the revocation window while sandbox enforcement completes; every `workspaceFiles/changes` frame re-checks workspace, ownership, and sensitive-path boundaries; archive/unarchive responses and Remote archive updates refresh the subuser session-list projection immediately, so older slow list responses cannot roll back the newer archive state.
4. Fixed Issue #36: when `DSH_PASSWORDS_ENV_FILE` pointed at a not-yet-existing `.env`, a non-root first install hit the "automatic HTTPS needs root" gate and exited before plugin registration. Fixed fail-closed: a non-root first install is allowed only when automatic HTTPS is explicitly off (`0/false/no`) or a self-managed certificate pair is supplied; default/on/unknown values and one-sided or blank certificates still require root. Non-root installs now default to `$HOME/dsh-passwords`, and the non-privileged first-run config no longer hardcodes 443/80.
5. Adapt the opt-in bind-all patch to both alpha.2 wildcard-listener guards (CLI and WebServer configuration), including status checks, switch-off restoration, and rollback. Default listener restrictions remain unchanged.
6. Include `docs/` in the npm package so relative documentation links from the README remain available; the Docker image gains a readiness probe and a build-time version assertion.

验证：本地 `npm run build` 通过；`node --import tsx --test "test/**/*.test.ts"` 全量通过（1 项 Windows 符号链接用例按平台预期跳过）；`npm pack --dry-run` 内容检查通过；测试服务器实际部署 `2.7.8` / DSH `0.2.1-alpha.2`，healthz/readyz/login 均 200、patch 四项全绿；Docker 镜像内置 DSH `0.2.1-alpha.2` 并完成 `:2.7.8` 与 `:latest` 推送。

Validation: local `npm run build` passed; the full `node --import tsx --test "test/**/*.test.ts"` suite passed with one platform-expected Windows symlink skip; the `npm pack --dry-run` content check passed; the test server runs `2.7.8` with DSH `0.2.1-alpha.2`, reporting healthz/readyz/login 200 and all four patches green; the Docker image bundles DSH `0.2.1-alpha.2` and is pushed as `:2.7.8` and `:latest`.

## 2.7.7 - 2026-10-03

### 中文

更新公告：

1. 兼容 DSH `0.2.1-alpha.1`：9 个 `@deepseek-ai/dsh*` 开发依赖、`npm-shrinkwrap.json`、安装器与 bundled Docker 默认运行时统一解析并锁定到官方 alpha.1；版本门禁收窄为单一 patch 线 `>=0.2.1-alpha.1 <0.2.2-0`，接受 alpha.1 起的 `0.2.1` 预发布与稳定 `0.2.1`，拒绝已退役的 `0.1.x` / `0.2.0` 线、`0.2.1-alpha.0` 与所有 `0.2.2+` 身份；`patch off` 回滚旁路不受版本门禁限制。
2. 修复 Issue #35：`GET /gateway/login` 仅在现有 CSRF cookie 通不过双重提交校验时才换发新 token；未认证精确路径 `/favicon.ico` 返回 204（不渲染、不重定向、不下发 cookie），避免 favicon 子请求触发 CSRF cookie 轮换，导致登录或首次配置的首次提交被 403 拒绝。
3. Issue #35 后续（审计 P0）：`csrfMatches` 的签名段改用严格 32 位小写十六进制白名单，替换原先的字符串长度校验。原先「32 个 JS 码元 / 33 个 UTF-8 字节」的多字节签名变体可绕过长度检查，令 `timingSafeEqual` 抛 `RangeError`；该异常发生在 Express 4 不接管的 async 路由内，升级为未处理拒绝并以退出码 1 结束密码门，宿主插件按永久错误不再自动重启。现在畸形 cookie 只照常返回登录页，不再打挂网关。
4. Issue #35 后续（审计 P2）：`POST /gateway/login` 与 `POST /gateway/setup` 先做同源校验再进入限速（仅回环反代采纳 `X-Forwarded-Host`；非浏览器客户端不带 Origin 时保持原行为），堵住「同站子域植入合法 cookie 后跨源自动提交」的 cookie-tossing CSRF；跨源请求同时不消耗受害者 IP 的限速配额。
5. Issue #35 后续（审计 P3）：未认证的浏览器自动探针路径扩为精确集合 `/favicon.ico`、`/apple-touch-icon.png`、`/apple-touch-icon-precomposed.png`、`/manifest.json`、`/manifest.webmanifest`、`/browserconfig.xml`、`/robots.txt`、`/sitemap.xml`，命中一律 204（不渲染、不重定向、不下发 cookie、不转发上游）；非探针路径仍按归一化精确匹配 302，刻意不改成按扩展名或 `Sec-Fetch-Dest`/`Accept` 判断。
6. 跨租户路径保护：会话创建、文件读取和工作区变更会拒绝落入其他子用户拥有的工作区子树，路径 canonicalization 沿最近的现存祖先解析，以保留大小写不敏感文件系统上的实际路径；工作区白名单追加改为只更新目标列，避免并发权限收紧被旧快照覆盖。
7. 同源保护：集中式 API 写路由与代理到 DSH 的状态变更请求在带 Origin 时校验来源，拒绝同站兄弟子域表单 CSRF；反代部署需保留外部 Host。
8. 流与进程健壮性：SSE 过滤按 LF/CRLF/CR 解析并保留跨 chunk UTF-8；无法解析的 session history/page 响应 fail-closed；Remote mux 发送缓冲限制为 2 MiB 余量加单个最大合法帧；插件卸载期间不再创建孤儿网关进程，spawn 错误可正确重试。
9. 客户端可用性与维护：文件下载和目录删除控件支持键盘访问，移除无消费者的客户端导出。
10. 发布打包卫生：`prepack` 在构建前运行 `scripts/clean-dist.mjs`，删除 `src/` 已无同名 `.ts` 的陈旧成对编译产物（例如旧版 `dist/gateway-admin.js`、`gateway-media.js`、`gateway-messages.js`、`gateway-proxy.js`、`plugin-compat.js` 及其 `.d.ts`），避免 `files:["dist/"]` 把旧构建残留打进 npm 包；普通 `npm test` / `npm run build` 不清理 `dist`，保留用户本地已生成产物。
11. 权限模型补充：恢复 `allowSsh` 为官方 Terminal 与第三方 SSH / 宿主端点的统一开关，默认关闭，由主用户在权限卡片「SSH 和终端使用」为子用户显式授权。开启后放行官方 terminal `terminal/*` HTTP unary RPC 与 `terminal/follow`、`terminal/retain` Remote mux 流；对已登记的第三方 SSH / 宿主端点，`allowSsh` 只放行 HTTP 与 WS，匹配的 Remote mux 流仍按 v2.7.5 的 owner-only 逐流拒绝、不受 `allowSsh` 影响，`owner:` 规则在所有通道永远拒绝子用户。关闭时维持无能力 UX 桩 / 403 / `terminal/unavailable`。运行中撤销 `allowSsh` 立即断开旧 Remote mux carrier 并回收终端流。

验证：本地 `npm test` 705/705、独立 dist 回归脚本 `node test/issue-35-standalone.mjs`（A 组 8/8 断言，P0 畸形多字节签名 cookie 未崩溃）、`npm run build`、`npx tsc -p tsconfig.json --noEmit` 与 `git diff --check` 通过；`npm-shrinkwrap.json` 经官方 registry 重建后零版本漂移，280 个 `@deepseek-ai/dsh*` 条目全部锁定 `0.2.1-alpha.1`。第 11 条为发布后权限模型补充说明，其 HTTP/mux/撤销回归与测试服务器验收独立进行，未计入以上验证数字。

### English

Release notes:

1. DSH `0.2.1-alpha.1` compatibility: the nine `@deepseek-ai/dsh*` dev dependencies, `npm-shrinkwrap.json`, the installers, and the bundled Docker default runtime all resolve and lock to the official alpha.1; the version gate is narrowed to the single patch line `>=0.2.1-alpha.1 <0.2.2-0`, accepting the `0.2.1` prereleases from alpha.1 up and stable `0.2.1`, and rejecting the retired `0.1.x` / `0.2.0` lines, `0.2.1-alpha.0`, and every `0.2.2+` identity; the `patch off` rollback bypass stays outside the version gate.
2. Fixed Issue #35: `GET /gateway/login` now rotates the CSRF token only when the existing cookie fails double-submit validation, and an unauthenticated exact `/favicon.ico` request returns 204 (no render, no redirect, no cookie), so the favicon sub-request no longer rotates the CSRF cookie and breaks the first login / first-time setup submit with a 403.
3. Issue #35 follow-up (audit P0): the `csrfMatches` signature check now uses a strict 32-character lowercase-hex allowlist instead of a string-length check. A multibyte signature variant with 32 JS code units but 33 UTF-8 bytes could previously pass the length check and make `timingSafeEqual` throw a `RangeError`; because that throw happens inside an async route Express 4 does not catch, it escalated to an unhandled rejection and terminated the password gate with exit code 1, which the host plugin treats as permanent and never auto-restarts. Malformed cookies now return the login page instead of taking the gateway down.
4. Issue #35 follow-up (audit P2): `POST /gateway/login` and `POST /gateway/setup` now check the request is same-origin before rate limiting (only a loopback reverse proxy may supply `X-Forwarded-Host`; non-browser clients without an Origin keep the previous behavior), closing the cookie-tossing CSRF path where a same-site subdomain plants a valid cookie and auto-submits cross-origin; a cross-origin request also no longer consumes the victim IP's rate-limit quota.
5. Issue #35 follow-up (audit P3): the unauthenticated browser auto-probe paths are now an exact set of `/favicon.ico`, `/apple-touch-icon.png`, `/apple-touch-icon-precomposed.png`, `/manifest.json`, `/manifest.webmanifest`, `/browserconfig.xml`, `/robots.txt`, and `/sitemap.xml`, all answered with 204 (no render, no redirect, no cookie, no upstream forward); non-probe paths still redirect with 302 on an exact normalised match, deliberately not widened to an extension or `Sec-Fetch-Dest`/`Accept` check.
6. Cross-tenant path protection: session creation, file reads, and workspace changes reject targets inside another subuser's owned workspace subtree; path canonicalization resolves through the nearest existing ancestor so case-insensitive filesystems retain their actual path spelling. Workspace allowlist registration updates only its target column so concurrent permission tightening cannot be overwritten by a stale snapshot.
7. Same-origin protection: centralized API writes and proxied DSH state changes validate supplied Origin headers and reject sibling-subdomain form CSRF; reverse proxies must preserve the external Host.
8. Stream and process hardening: SSE filtering handles LF/CRLF/CR and split UTF-8 chunks; unprocessable session history/page responses fail closed; Remote mux buffering permits 2 MiB of queue headroom plus one maximum legal frame; plugin disposal no longer spawns orphan gateways and spawn failures can retry.
9. Client usability and maintenance: file-download and directory-delete controls are keyboard accessible; unused client exports were removed.
10. Packaging hygiene: `prepack` now runs `scripts/clean-dist.mjs` before the build to delete obsolete paired compiled outputs whose `src/` `.ts` source no longer exists (for example the old `dist/gateway-admin.js`, `gateway-media.js`, `gateway-messages.js`, `gateway-proxy.js`, and `plugin-compat.js` plus their `.d.ts`), so `files:["dist/"]` no longer packs leftovers from an older build; ordinary `npm test` / `npm run build` do not clean `dist`, preserving the user's local generated artifacts.
11. Permission-model supplement: restored `allowSsh` as the single switch for official terminal and third-party SSH/host endpoints. It defaults to off and is granted per subuser explicitly by the owner via the "SSH and terminal access" toggle in the permissions card. When enabled, the gateway forwards official terminal `terminal/*` HTTP unary RPCs and `terminal/follow` / `terminal/retain` Remote mux streams; for registered third-party SSH/host endpoints it forwards HTTP and WS only, while matching Remote mux streams keep the v2.7.5 owner-only per-stream rejection and are not opened by `allowSsh`, and `owner:` rules always reject subusers on every channel. When disabled it keeps the no-capability UX stubs / 403 / `terminal/unavailable`. Revoking `allowSsh` at runtime immediately closes the old Remote mux carrier and reclaims terminal streams.

Validation: local `npm test` 705/705, the standalone dist regression script `node test/issue-35-standalone.mjs` (A-group 8/8 assertions, and the malformed multibyte-signature P0 cookie did not crash), `npm run build`, `npx tsc -p tsconfig.json --noEmit`, and `git diff --check` passed. `npm-shrinkwrap.json` was rebuilt against the official registry with zero version drift, with all 280 `@deepseek-ai/dsh*` entries pinned to `0.2.1-alpha.1`. Item 11 is a post-release permission-model supplement; its HTTP/mux/revocation regressions and test-server acceptance are run separately and are not included in the numbers above.

## 2.7.6 - 2026-09-29

### 中文

更新公告：

1. 兼容 DSH `0.2.0-rc.1`，并保留 `0.2.0` 线 alpha/beta/rc 与稳定版的兼容门禁。
2. 修复 Issue #33：解决 Windows `spawn EINVAL`、部署目录 `EBUSY/EPERM`、配置优先级和自动更新重复安装问题。
3. 兼容大多数普通插件，普通插件对子用户开放 HTTP/Remote 与已加载 WebSocket；子用户可在主用户分配的工作区中使用并新建会话，SSH/终端等宿主敏感能力仍仅主用户可用。
4. 修复工作区/会话授权、403/502/503、沙盒、上传下载、目录选择器、插件清单、配置漂移、回滚和多项跨平台生命周期问题；主子用户统一使用网页 browse 目录选择器。

验证：本地 `npm test` 649/649、构建、类型检查、Issue #33 Windows 定向测试、README 安装流程打包验证通过；本地 Windows DSH `0.2.0-rc.1` HTTP 启动与 dsh-passwords 自动拉起通过；测试服务器工作区 E2E 20/20 通过。

### English

Release notes:

1. Compatible with DSH `0.2.0-rc.1`, while retaining the compatibility gate for `0.2.0` alpha/beta/rc prereleases and stable releases.
2. Fixed Issue #33: Windows `spawn EINVAL`, deployment-directory `EBUSY/EPERM`, configuration precedence, and repeated automatic installation.
3. Compatible with most ordinary plugins: ordinary HTTP/Remote and loaded WebSocket surfaces are available to subusers; subusers can use and create sessions in workspaces assigned by the owner, while SSH/terminal and other host-sensitive capabilities remain owner-only.
4. Fixed workspace/session authorization, 403/502/503 responses, sandbox enforcement, upload/download gates, directory picker behavior, plugin manifests, configuration drift, rollback, and multiple cross-platform lifecycle bugs; owners and subusers now use the web browse directory picker.

Validation: local `npm test` 649/649, build, type check, Windows Issue #33 focused tests, and README installation/package checks passed; local Windows DSH `0.2.0-rc.1` HTTP startup and automatic dsh-passwords launch passed; test-server assigned-workspace E2E passed 20/20.

## 2.7.5 - 2026-09-25

### 中文

更新公告：

1. 适配 DSH `0.1.7-rc.2`；兼容门禁维持 `0.1.7` 线，继续接受稳定版及 alpha/beta/rc 预发布版本。
2. 修复 rc.2 子用户会话中的 dsh-schedule 403、目录选择器删除按钮和删除目录后的 workspace/子用户授权联动清理。
3. 修复媒体配额、归档并发、SSE 生命周期、上游超时与插件通知超时；网关按功能拆分为 `proxy`、`admin`、`media`、`messages` 和 `sse-frames` 模块。

### English

Release notes:

1. Adapted to DSH `0.1.7-rc.2`; the compatibility gate remains on the `0.1.7` line and accepts stable and alpha/beta/rc prereleases.
2. Fixed rc.2 subuser dsh-schedule 403 responses, the directory-picker delete button, and linked workspace/subuser authorization cleanup after directory deletion.
3. Fixed media quota accounting, archive concurrency, SSE lifecycle, upstream and plugin notification timeouts; the gateway is split by function into `proxy`, `admin`, `media`, `messages`, and `sse-frames` modules.

验证：本地 `npm test` 577/577、构建、类型检查、打包与 diff 检查通过；测试服务器 2.7.5 / DSH 0.1.7-rc.2 healthz/readyz 与 patch status 正常；多用户 E2E 128 PASS / 0 FAIL / 9 INCONCLUSIVE，未执行 destructive purge。

Validation: `npm test` 577/577, build, type check, package and diff checks passed; test-server 2.7.5 / DSH 0.1.7-rc.2 health/readiness and patch status are healthy; multiuser E2E completed with 128 PASS / 0 FAIL / 9 INCONCLUSIVE. Destructive purge was not run.

## 2.7.4 - 2026-09-23

### 中文

更新公告：

1. 修复主用户与多个子用户并发登录、会话/工作区快照乱序和排序竞态；`workspace/insertBefore` 与 `insertSessionBefore` 只按可见工作区/授权会话校验，不再错误绑定新建工作区权限，Remote job 流按授权 session 收敛。
2. 完成 DSH `0.1.7-alpha.2` 官方面适配：official terminal 与第三方 SSH 共用 `allowSsh`，workspace files、account、job 和 Remote mux 的边界行为保持与官方客户端兼容；按产品决定保留子用户对宿主 account 的只读视图，未知方法及账号登录/变更操作仍拒绝。
3. 新增“保命技能”紧急清理：主用户连续点击头像并验证密码后，可移除 DSH 本体、扩展/插件、会话和相关本地数据；清理器校验计划、路径与进程归属，Docker 环境 fail-closed，dry-run 不执行删除。
4. 更新前端保命技能状态清理、2.7.4 版本元数据和 alpha.2 兼容文档，移除已确认的无效字段、冗余条件与不可达分支。

验证：本地回归测试 546/546、构建、类型检查、打包与 diff 检查通过；测试服务器 2.7.4 / DSH 0.1.7-alpha.2 health/ready 与 patch status 正常。媒体 E2E 有 1 项因历史媒体达到 MEDIA_QUOTA 未通过；真实 destructive purge 未执行。

### English

Release notes:

1. Fixed concurrent owner/subuser sign-ins, out-of-order workspace/session snapshots, and ordering races; `workspace/insertBefore` and `insertSessionBefore` now use visible-workspace and authorised-session checks without being tied to workspace creation permission, while Remote job streams are scoped to the authorised session.
2. Completed the DSH `0.1.7-alpha.2` official-surface adaptation: the official terminal and third-party SSH share `allowSsh`, and workspace files, account, job, and Remote mux boundaries follow the official client contract. Per the product decision, subusers retain the read-only host account view, while unknown methods and account login/mutation operations remain blocked.
3. Added the owner emergency self-destruct function: after rapid avatar clicks and password verification, it can remove the DSH core, extensions/plugins, sessions, and related local data. The helper validates its plan, paths, and process ownership; Docker remains fail-closed and dry-run never deletes files.
4. Updated emergency-cleanup form state, 2.7.4 metadata, and alpha.2 compatibility documentation; removed confirmed dead fields, redundant conditions, and unreachable branches.

Validation: 546/546 local tests, build, type check, package-content and diff checks passed. The test server runs 2.7.4 with DSH 0.1.7-alpha.2; health/readiness and patch checks passed. One media E2E case hit the existing MEDIA_QUOTA limit. Destructive purge was not run.

## 2.7.3 - 2026-09-19

### 中文

1. DSH 依赖锁定与默认安装迁移到 `@deepseek-ai/dsh@0.1.6-alpha.2`：`package.json` 的九个 `@deepseek-ai/dsh*` 开发依赖统一为 alpha.2；`npm-shrinkwrap.json` 用官方 registry 重新生成，锁定树内全部 250 个 `@deepseek-ai/dsh*` 包（含 `@deepseek-ai/dsh` 本体）均为 alpha.2，`resolved` 全部指向 `registry.npmjs.org`，无 alpha.1 残留。
2. 安装器与 bundled Docker 默认固定 `0.1.6-alpha.2`：`install.sh`、`install.bat`、`scripts/install.mjs`、`docker/Dockerfile.bundled`、`docker/docker-compose.yml`、`docker/.env.example`。
3. 对外兼容口径统一为「DSH 0.1.6 线（当前锁定 alpha.2）」：README、README_en、`docs/compatibility-matrix.md` 与 `CONTRIBUTING.md` 同步更新。0.1.6 正式版尚未发布，不宣称稳定版兼容；alpha.2 的依赖树、构建、回归测试与测试服务器真实 profile 验收已通过；历史版本的兼容叙述保持原样。
4. Issue #32 离线内网结论：HTTP 模式通过 `MCP_GATEWAY_AUTO_TLS=0` 关闭 ACME/公网域名依赖，可在内网离线运行登录、权限、文件与管理面；模型回复仍需要可用的上游模型服务。首次安装不承诺无依赖离线安装，离线环境需预置 DSH、项目 tarball、Node 依赖缓存与 npm optional native packages。
5. 生命周期与 alpha.2 收口：退出码 1/30-37 的永久启动失败不再每秒自动重启；profile bundle 只有在自身包清单与主 DSH 版本一致时才允许补丁；Windows 通过 `npm.cmd` 正确探测全局 DSH；权限卡先渲染 overview，模型目录 RPC 设置 5 秒超时；Docker 推送辅助脚本从 bundled Dockerfile 读取 DSH 版本并使用正确的 node entrypoint 校验。
6. 目录删除联动审计修复：只有「受保护通道登记的 dsh-auth 凭据 + 权威上游 workspace/follow 快照」才允许执行 `workspace/delete`（浏览器 `dsh-auth-*` Cookie 不再转发给 loopback 上游；凭据/快照不可用时 fail-closed 并显式报告未同步，本地缓存仅用于报告、绝不驱动删除）；删除后重读上游注册表复核，仍存在的 workspaceId 一律计失败（含复核不可用，不假装成功）；路径包含改为归一化 + 段边界 + 尽力 realpath（父目录回退），Windows 大小写不敏感，前缀兄弟目录不受影响；完整成功的定义收紧为「物理目录已删除 + 上游权威 sidebar 同步确认 + 插件 DB 授权清理成功」；DB 或 sidebar 同步任一失败均把受信的服务端派生元数据（规范化被删根 + 受影响会话）写入 `workspace_cleanup_intents`，返回可重试的 `DB_CLEANUP_FAILED`、`WORKSPACE_SYNC_FAILED` 或 `WORKSPACE_SYNC_UNAVAILABLE`，选择器保留墓碑态并以 `cleanupOnly` 重试（不再次删除文件系统）；若 intent 本身无法持久化，则返回对应 `*_NO_RETRY` 并提示人工处理，绝不虚假宣称可重试；意图只在 DB 与权威 sidebar 均收敛后清除；重建目录时 cleanup-only 返回 `CLEANUP_RETRY_CONFLICT`，保留原 intent 且绝不删除新内容；白名单删空只回落 `__deny__`，并强制失效内存/mux 快照；选择器对已确认删除的行在可重试失败时保留墓碑入口，其他部分失败展示警告并移除行；快照后目录被并发删除（复核时路径消失）按幂等已删除路径继续清理而非 404 跳过，真正被替换仍返回 409；待授权目录（pending）按 owner 全量清理被删树内条目并失效其 mux，路径重建后陈旧授权不再放行；重试准入与 DB 清理共用同一套路径匹配（归一化 + 段边界 + 尽力 realpath + Windows 大小写不敏感），存符号链接/junction 别名的归属与白名单行同样收敛。

### English

1. DSH dependency locking and default installs move to `@deepseek-ai/dsh@0.1.6-alpha.2`: the nine `@deepseek-ai/dsh*` dev dependencies in `package.json` are unified on alpha.2, and `npm-shrinkwrap.json` is regenerated against the official registry. All 250 `@deepseek-ai/dsh*` packages in the lock tree (including the base `@deepseek-ai/dsh`) resolve to alpha.2, every `resolved` URL points at `registry.npmjs.org`, and no alpha.1 entry remains.
2. Installer and bundled Docker defaults pin `0.1.6-alpha.2`: `install.sh`, `install.bat`, `scripts/install.mjs`, `docker/Dockerfile.bundled`, `docker/docker-compose.yml`, and `docker/.env.example`.
3. The public compatibility wording is unified as "the DSH 0.1.6 line (currently pinned to alpha.2)" across the READMEs, `docs/compatibility-matrix.md`, and `CONTRIBUTING.md`. No stable 0.1.6 release is claimed; the alpha.2 dependency tree, build, regression suite, and test-server real-profile validation pass, and historical compatibility notes are unchanged.
4. Issue #32 offline-internal conclusion: HTTP mode disables ACME/public-domain requirements through `MCP_GATEWAY_AUTO_TLS=0`, so login, permissions, files, and administration can run on an isolated internal network; model replies still require an available upstream model service. Initial installation is not advertised as dependency-free offline installation; an offline host must pre-stage DSH, the project tarball, a Node dependency cache, and optional native packages.
5. Alpha.2/lifecycle closeout: permanent startup failures (exit codes 1 and 30-37) no longer trigger one-second autostart loops; profile bundles are patched only when their own manifests match the main DSH version; Windows uses `npm.cmd` for global DSH discovery; the permissions card renders overview before the model-catalog RPC and caps that RPC at five seconds; Docker push helpers read the DSH version from the bundled Dockerfile and verify it with the node entrypoint.
6. Directory-deletion linkage audit fixes: only a registered dsh-auth credential plus an authoritative upstream workspace/follow snapshot may drive `workspace/delete` (browser `dsh-auth-*` cookies are never forwarded to the loopback upstream; missing credentials/snapshot fails closed and reports the unsynchronised state, and the local cache is report-only). Completion now requires physical deletion, confirmed authoritative sidebar synchronization, and successful plugin-DB authorization cleanup. The upstream registry is re-read after deletion and any still-present workspaceId is reported as a failure (including unverifiable reads, so no false success is claimed). Path containment now normalises, respects segment boundaries, best-effort realpaths (with a parent-directory fallback) and is case-insensitive on Windows without matching prefix siblings. Any DB or sidebar-sync failure persists trusted server-derived metadata (the normalised deleted root plus affected session IDs) to `workspace_cleanup_intents` and returns a retryable `DB_CLEANUP_FAILED`, `WORKSPACE_SYNC_FAILED`, or `WORKSPACE_SYNC_UNAVAILABLE`; the picker keeps a tombstone and retries through `cleanupOnly`, which never deletes the filesystem again. If the intent itself cannot be persisted, the corresponding `*_NO_RETRY` response asks for manual handling instead of falsely advertising a retry. Intents are cleared only after both DB cleanup and authoritative sidebar synchronization converge. If a cleanup-only request finds the path recreated, it returns `CLEANUP_RETRY_CONFLICT`, retains the old intent, and never deletes the new content. Whitelist emptying falls back to `__deny__`, and affected in-memory/mux state is invalidated. Pending created-directory grants are purged for every owner whose entry lies inside the deleted tree and those owners' muxes are invalidated, so a recreated path cannot reuse stale authorisation. Retry admission and DB cleanup share one path matcher (normalise, segment boundaries, best-effort realpaths, Windows case folding), so ownership and whitelist rows stored under symlink/junction aliases are cleaned up as well.

## 2.7.2 - 2026-09-16

### 中文

更新公告：

1. 官方适配与第三方插件适配正式分界：网关主体（`src/gateway.ts`、`src/permissions.ts`）不再包含任何第三方插件的路径、字段或请求头知识；官方 DSH `0.1.6-alpha.2` 接口（API 命名空间、事件通道、会话/工作区 RPC、上传/git 官方端点）按宿主适配继续硬编码。全部第三方插件知识集中到唯一的新模块 `src/plugin-compat.ts`。
2. 新增 `MCP_GATEWAY_PLUGIN_COMPAT` 开关，**默认关闭**：关闭时网关对第三方插件保持通用姿态——未登记的第三方路径（`/api/*` 与根级插件路由）对子用户一律 fail-closed，放行只走端点登记表；打开时才启用已知插件的细粒度适配（文件树白名单、上传/下载门控、内容清洗、轮询豁免）。
3. 根级路径通用化：新增官方根级白名单（`/`、`/index.html`、`/favicon.ico`、`/assets/*`、`/plugins/*` 与常见静态扩展名），其余非 `/api` 路径按第三方处理。依据：官方 DSH `0.1.6-alpha.2` 的根级资源模型继续由官方 bundle/静态资源服务提供，未知路径不作为网关已知业务路由。
4. 端点登记表合并为一条变量：`MCP_GATEWAY_SSH_ENDPOINTS`，规则语法 `[owner:][ws:|http:]路径`（前缀均可省略、顺序任意）。`owner:` = 仅主用户（子用户两条通道一律 403）；其余规则 = 子用户需「已登记」+「已勾选 SSH 端点权限」两把钥匙。`ws:`/`http:` 限定通道，不写则两条通道都放行；尾部 `/*` 只匹配直接子路径。
5. 清理历史遗留变量、逻辑与代码：删除 `MCP_GATEWAY_OWNER_ONLY_ENDPOINTS`（并入 `owner:` 前缀）、`MCP_GATEWAY_THIRD_PARTY_DEFAULT`（未登记第三方一律拒绝，取消 proxy 兼容模式）、旧变量 `MCP_GATEWAY_SSH_WS_ENDPOINTS` 的并集读取与启动迁移提示、CLI 弃用信息输出，以及网关内按具体第三方插件命名的放行判定；相关细粒度行为集中到默认关闭的通用兼容层。旧带前缀兼容别名（`parseWebSocketAllowlist`、`webSocketPathAllowed`、`endpointAllowedFor`）同步删除。
6. 未经证实的路径移出官方清单：`/api/live-stats` 不再视为官方命名空间（改按第三方 fail-closed）；`/api/pet/*`、`/api/pair/*` 等无法在官方 DSH `0.1.6-alpha.2` 包中证实的轮询路径从配额豁免移除（同时保留已验证的 0.1.5 兼容边界，以及通用 `heartbeat`/`poll` 正则与官方事件通道）。
7. 安装器模板移除第三方 native 构建许可：`scripts/register-plugin.mjs` 的 `allowBuilds` 只保留官方依赖链（`node-pty`、`protobufjs`），移除 `ssh2`、`cpu-features`；第三方插件需要时由 pnpm 官方提示流程按需添加。
8. 登记表运维可见性：`/gateway/api/overview` 只返回 `endpoints`（带前缀规则）与 `pluginCompat`；移除 2.7.x 兼容字段（`sshWebSocketEndpoints`、`ownerOnlyEndpoints`、`thirdPartyDefault`）。前端 `allowSsh` 开关与设置面板行为不变。
9. Docker Compose 收敛为唯一 bundled 入口：内置 DSH `0.1.6-alpha.2`，转发 `MCP_GATEWAY_SSH_ENDPOINTS` 与 `MCP_GATEWAY_PLUGIN_COMPAT`，移除旧 `MCP_GATEWAY_SSH_WS_ENDPOINTS` 与重复 Compose 文件。
10. 版本标记为 `2.7.2`。本地源码、npm 元数据、Docker 配置和文档统一使用该版本号；是否发布 npm 包与 GitHub Release 仍由发布流程单独决定。
11. 子用户新建工作区工作流收紧（D1）：`workspace/create` 只接受「主用户显式分配的精确目录、该子用户自己创建的工作区子树、刚通过目录选择器成功创建且未过期的目录（30 分钟）」三类凭据，其余一切预存在目录一律 403；目录创建的合法父目录为「授权子树（原始串+真实路径双判定堵符号链接逃逸）、主目录（picker 落点与工作区惯例父目录）、自己刚创建的目录内」，且不得落在另一子用户的工作区子树内（单向包含，共享分配根下建兄弟目录不受影响）；刚创建的目录在过期前作为临时授权根——选择器中立即可见/可进入；`workspace/create` 成功后原子写入所有权与白名单，同步更新 workspaceId→path 映射并向已建立 Remote mux 连接补发过滤后的 upsert，紧随其后的新建会话不再被 403；`directoryPicker/list`（含旧 host.listDirectory）对子用户限权：请求路径必须在授权子树/自己的临时根内（完整列表）或是通往授权根的祖先（响应仅保留通往授权根的条目，其余目录名隐藏），其余 403；`__deny__`（禁止所有工作区）下不开放任何创建/登记通道。另：孤儿所有权行（已删除用户残留）不再阻断目录可见性与登记——判定要求物主存在且为子用户，删用户级联清理所有权行，启动迁移幂等清除历史残留；`permissionPresets` 补入官方命名空间（alpha.2 官方权限预设目录），`terminal` 命名空间故意不开放（远程 shell = 沙箱逃逸）；session.create/fork 上游 4xx/5xx 非 JSON 响应原样透传，不再伪装成 502。
12. 发布收口修复：`patch` 子命令不再强制要求 `SETUP_KEY`（DSH 已卸载/`.env` 已删时回滚仍可完成，稳定退出码 34 保持）；安装器预构建依赖检测补齐 `ws`（避免残缺安装误判已构建）；gate-only Docker 镜像补默认 `CMD`（修复容器静默退出）；`install.sh` 非 root 首次安装提前报错（README 一键命令改用 `sudo bash`）；网关启用 `trust proxy = loopback`（反代后按真实客户端 IP 节流，不再全局共享计数）；目录选择器删除按钮的列表采集只信 `entries` 键（排除 `crumbs` 面包屑与 `truncated` 截断列表，子序列回退同长度歧义时拒绝注入——修复删除按钮可能误绑父目录路径的高危缺陷）；前端状态色令牌改用官方 `--dsw-alias-state-*`（原 `semantic-*` 在 0.1.6-alpha.1 主题包中不存在，深色主题下对比度不足）；聊天轮询把协议层 `ok=false` 纳入失败退避；附件重试回队调度（不再绕过并发上限）；右侧栏文件下载按钮的持续旋转改为点击瞬间轻震反馈（`navigator.vibrate` 渐进增强 + 弹簧回弹，尊重 `prefers-reduced-motion`）。
13. 发布前三件套审查修复（第二轮）：① 聊天上传队列补位——并发槽位释放后立即调度排队附件，第 4 个及之后的图片/视频不再永久卡在 queued 而阻塞发送；② 网关不再被单个叼形 WebSocket 帧击穿——Remote mux 与子用户事件通道的客户端连接补 `error` 监听，未加掩码等协议错误只断开该连接（而非 uncaughtException 终止进程）；③ `npm-shrinkwrap.json` 全部改指官方 npm registry（651 条第三方镜像地址清零，完整性校验不变）；④ `install.sh` 非 root 首次安装提前报错、重跑识别已有安装就地幂等执行，`install.bat` 同样支持就地重跑并规范化安装目录；⑤ `patch` 在补丁目标缺失时以稳定退出码 35 结束（Docker entrypoint 不再把“什么都没补”当成功）；⑥ 插件自动拉起不再为永久性错误（34/35/36）每秒无限重启；⑦ `.dockerignore` 排除 `docs/`、`test/`、`alpha1-observation/` 等非构建上下文。

验证：382/382 本地回归测试、TypeScript 构建、npm pack 内容检查（77 文件）、`git diff --check` 通过；测试服务器已部署 `2.7.2`（备份 `20260916-140748Z`），healthz/readyz/补丁状态全部通过；真实账号 E2E：模型/媒体矩阵 31/31、下载端点与终端伪装 14/14。

### English

Release notes:

1. Official vs third-party adaptation is now a hard boundary: the gateway core (`src/gateway.ts`, `src/permissions.ts`) carries no third-party plugin path, field, or header knowledge; official DSH `0.1.6-alpha.2` interfaces (API namespaces, event channels, session/workspace RPCs, and official upload/git endpoints) remain host adaptations. All third-party plugin knowledge now lives in one module, `src/plugin-compat.ts`.
2. New `MCP_GATEWAY_PLUGIN_COMPAT` switch, **off by default**: with it off the gateway keeps a generic posture — unregistered third-party paths (`/api/*` and root-level plugin routes) are fail-closed for subusers, and access is granted only through the endpoint registry; turning it on enables fine-grained adapters for known plugins (file-tree whitelisting, upload/download gating, content sanitising, polling exemptions).
3. Generic root-level posture: a new official root allowlist (`/`, `/index.html`, `/favicon.ico`, `/assets/*`, `/plugins/*`, plus common static file extensions); every other non-`/api` path is treated as third-party. Rationale: the official DSH `0.1.6-alpha.1` bundle/static resource model serves the known root assets, while unknown paths are not treated as gateway business routes.
4. One unified registry variable: `MCP_GATEWAY_SSH_ENDPOINTS` with rule syntax `[owner:][ws:|http:]path` (prefixes optional, order-agnostic). `owner:` rules are owner-only (subusers get 403 on both transports); all other rules require both the owner registration and the subuser's SSH toggle. `ws:`/`http:` restrict a rule to one transport; a trailing `/*` matches direct child paths only.
5. Removes legacy variables, logic, and code: `MCP_GATEWAY_OWNER_ONLY_ENDPOINTS` (folded into the `owner:` prefix), `MCP_GATEWAY_THIRD_PARTY_DEFAULT` (unregistered third-party paths are always denied; the `proxy` escape hatch is gone), the legacy `MCP_GATEWAY_SSH_WS_ENDPOINTS` union read and its startup migration notice, and the CLI deprecation output. Plugin-specific gateway allowlist matchers are replaced by the generic classifier and the default-off compat layer. Legacy aliases (`parseWebSocketAllowlist`, `webSocketPathAllowed`, `endpointAllowedFor`) are removed as well.
6. Moves unverified paths out of the official list: `/api/live-stats` is no longer treated as an official namespace (fail-closed as third-party), and `/api/pet/*`, `/api/pair/*` and similar polling paths that cannot be verified in the official DSH `0.1.6-alpha.2` packages are no longer exempted from usage accounting (the tested 0.1.5 compatibility boundary, generic `heartbeat`/`poll` patterns, and official event channels remain).
7. Installer template drops third-party native build permissions: `allowBuilds` in `scripts/register-plugin.mjs` now keeps only official dependency-chain entries (`node-pty`, `protobufjs`) and removes `ssh2`/`cpu-features`; third-party plugins add their keys through pnpm's own prompt flow when needed.
8. Registry ops visibility: `/gateway/api/overview` now returns only `endpoints` (prefixed rules) and `pluginCompat`; the 2.7.x compatibility fields (`sshWebSocketEndpoints`, `ownerOnlyEndpoints`, `thirdPartyDefault`) are gone. The frontend `allowSsh` toggle and settings panel behaviour are unchanged.
9. Docker Compose is consolidated to one bundled entrypoint: it includes DSH `0.1.6-alpha.2`, forwards `MCP_GATEWAY_SSH_ENDPOINTS` and `MCP_GATEWAY_PLUGIN_COMPAT`, and removes the legacy `MCP_GATEWAY_SSH_WS_ENDPOINTS` plus the duplicate Compose file.
10. Version marked `2.7.2`; npm and GitHub publication remain separate release steps.
11. Subuser workspace-creation workflow tightened (D1): `workspace/create` accepts only three credentials — a directory the owner explicitly assigned (exact match), the subuser's own created workspace subtree, or a directory just created through the directory picker (30-minute window); every other pre-existing directory is rejected with 403. Directory creation re-checks the parent against the allowed subtree using the filesystem-real path (realpath) to close symlink escapes, and neither directory creation nor registration may reach into another subuser's owned subtree (one-way containment: siblings under a shared assigned root stay allowed). A successful registration atomically records ownership and the folder grant, updates the workspaceId→path mapping, and pushes a filtered upsert to the subuser's live Remote mux connections so an immediately following session create is no longer 403. `directoryPicker/list` (and the legacy `host.listDirectory`) is now gated for subusers: the requested path must be inside the allowed subtree (full listing) or an ancestor on the way to an allowed root (responses keep only entries leading there, hiding unrelated directory names); anything else is 403.
12. Release closeout fixes: the `patch` subcommand no longer requires `SETUP_KEY` (rollback still completes after DSH removal; stable exit code 34 preserved); the installer's prebuilt-runtime check now includes `ws` (incomplete installs are no longer misdetected as built); the gate-only Docker image gains a default `CMD` (fixing silent container exit); `install.sh` fails fast for non-root first installs (the README one-liner now uses `sudo bash`); the gateway enables `trust proxy = loopback` (per-client rate limiting behind a reverse proxy instead of one shared counter); the directory-picker delete button now trusts only `entries` arrays (excluding `crumbs` ancestors and `truncated` listings, and refusing ambiguous equal-length subsequence matches — fixing a hazardous case where the button could bind a parent directory path); frontend state colours use the official `--dsw-alias-state-*` tokens (the previous `semantic-*` names do not exist in the 0.1.6-alpha.1 theme, hurting dark-theme contrast); chat polling counts protocol-level `ok=false` as failure for backoff; attachment retries re-enter the queue scheduler (no longer bypassing the concurrency cap); and the sidebar file-download button replaces its spinning animation with an instant tap feedback (`navigator.vibrate` progressive enhancement plus a spring settle, respecting `prefers-reduced-motion`).
13. Pre-release review fixes (second round): (1) the chat upload queue now promotes queued attachments as soon as a slot frees, so a 4th+ image/video no longer sticks in `queued` and blocks sending; (2) a single malformed WebSocket frame can no longer kill the gateway — the Remote mux carrier and the subuser event channels now handle client `error` events, so protocol failures such as an unmasked frame close that connection instead of raising an uncaughtException; (3) `npm-shrinkwrap.json` now resolves entirely against the official npm registry (the 651 third-party mirror URLs are gone, integrity hashes unchanged); (4) `install.sh` fails fast for non-root first installs and resumes idempotently when a dsh-passwords install already exists, and `install.bat` supports the same in-place resume with a normalised install directory; (5) `patch` exits with stable code 35 when the patch target is missing, so the Docker entrypoint no longer reports success for an unpatched container; (6) the plugin's gateway autostart no longer retries permanent failures (34/35/36) every second; (7) `.dockerignore` excludes `docs/`, `test/`, and `alpha1-observation/` from the build context.

Validation: 382/382 local regression tests (two new WebSocket error-handling regressions), the TypeScript build, the npm pack content check (77 files), and `git diff --check` passed; the test server runs `2.7.2` (backup `20260916-140748Z`) with healthz/readyz and patch status all green; real-account E2E: model/media matrix 31/31, download-endpoint and terminal-stub checks 14/14.


## 2.7.1 - 2026-09-11

### 中文

更新公告：

1. 兼容 DSH `0.1.5` 全版本（alpha.1 / alpha.2 / rc.1 / rc.2）：补丁锚点与 Cookie 桥校验覆盖整个 rc 系列，rc.2 的反馈弹窗与交付文件卡片等界面更新已实测兼容，bundled Docker 内置 DSH `0.1.5-rc.2`。
2. 修复显式 SSH WebSocket 端点尾部通配规则未实际命中的问题；通配只放行直接子路径，不放行基路径或更深路径。
3. 加固自动更新引擎：重复启动不再叠加轮询器，释放时清理定时器；更新接口状态码统一为 202/429/422，不再把业务错误误报为 409。
4. 设置界面与登录页动效按 iOS 手感细化：分区错落进场、开关弹簧滑动、按钮按压反馈、状态与错误进场动画；全部只动 transform/opacity/box-shadow 并尊重 prefers-reduced-motion。
5. 清理无效示例配置项，完成全量逻辑、权限、生命周期、安装与依赖审计，保留旧数据库迁移所需兼容字段。

验证：282/282 本地回归测试、TypeScript 构建、npm 官方 registry 生产依赖审计、发布包内容与 Git 差异检查通过；测试服务器以 DSH `0.1.5-rc.2` 实际部署，反馈与交付文件 bundle 与官方 npm 产物逐字节一致。

### English

Release notes:

1. Compatible with the whole DSH `0.1.5` line (alpha.1 / alpha.2 / rc.1 / rc.2): patch anchors and the Cookie-bridge check cover the full rc series, the rc.2 feedback-dialog and delivered-file-card UI refinements are verified compatible, and the bundled Docker image ships DSH `0.1.5-rc.2`.
2. Fixes explicit SSH WebSocket endpoint suffix wildcards that were accepted by configuration but never matched at upgrade time; wildcards now allow direct child paths only, never the base or deeper descendants.
3. Hardens the automatic-update engine: repeated starts cannot stack polling timers, disposal clears the active timer, and update API statuses are normalized to 202/429/422 instead of misreporting business errors as 409.
4. Refines the settings UI and sign-in page motion to an iOS-like feel: staggered section entrances, spring-loaded toggles, pressed-button feedback, and entrance animations for statuses and errors; all motion stays on transform/opacity/box-shadow and respects prefers-reduced-motion.
5. Removes an ineffective example configuration option and completes a full logic, authorization, lifecycle, installation, and dependency audit while retaining the legacy database field required for migration compatibility.

Validation: 282/282 local regression tests, the TypeScript build, the official-registry production dependency audit, package-content checks, and Git whitespace checks passed; the test server runs DSH `0.1.5-rc.2`, and the feedback/deliverable bundles are byte-identical to the official npm artifacts.

## 2.7.0 - 2026-09-10

### 中文

更新公告：

1. 兼容 DSH `0.1.5` 全系列（alpha.1 / alpha.2 / rc.1）：会话、Remote mux、Cookie 桥与设置补丁全部按 `0.1.5` 边界验证，bundled Docker 内置 DSH `0.1.5-rc.1`。
2. 网关通用化：SSH 端点完全由 `MCP_GATEWAY_SSH_WS_ENDPOINTS` 显式配置，不再探测任何特定插件；非 SSH 第三方 WebSocket 对子用户一律 fail-closed，移除插件专属放行。
3. 退役逐路径 WebSocket 授权（`allowed_websocket_paths`）死代码与废弃环境变量，数据层保留旧列兼容既有数据库。
4. 设置页优化：权限保存确认就地显示在子用户权限块内；添加子用户表单置顶；SSH 权限仅显示开关名称；移除多条静默提示；修复更新状态轮询在「发现新版本但未开始下载」时的空转循环。
5. 清理发布物与文档：安装器、Docker、README、兼容性矩阵与示例配置全部与当前通用模型对齐，移除历史插件残留引用。
6. 本次审计使用模型 deepseek-V4.1-flash。

验证：277/277 本地回归测试、TypeScript 构建、Git 差异检查通过；本地以 DSH `0.1.5-rc.1` 实际部署验证前后端基础功能。

### English

Release notes:

1. Compatible with the whole DSH `0.1.5` line (alpha.1 / alpha.2 / rc.1): sessions, Remote mux, the Cookie bridge and the settings patch are all verified against the `0.1.5` boundaries; the bundled Docker image ships DSH `0.1.5-rc.1`.
2. Gateway generalization: SSH endpoints are configured exclusively through `MCP_GATEWAY_SSH_WS_ENDPOINTS` with no plugin-specific probing; all other third-party WebSocket paths stay fail-closed for subusers.
3. Retires the per-path WebSocket grant dead code (`allowed_websocket_paths`) and deprecated environment variables; the database column is kept for compatibility with existing databases.
4. Settings UI polish: the save confirmation now appears inside the subuser permissions block, the add-subuser form moves to the top, the SSH toggle shows only its label, several passive hints are removed, and the update-status polling no longer spins while a new version is discovered but not yet downloading.
5. Release hygiene: installers, Docker, README, the compatibility matrix and the example configuration are all aligned with the current generic model, with historical plugin-specific references removed.
6. This audit used model deepseek-V4.1-flash.

Validation: 277/277 local regression tests, the TypeScript build, and Git whitespace checks passed; frontend and backend basics were verified against a locally deployed DSH `0.1.5-rc.1`.

## 2.6.11 - 2026-09-05

### 中文

更新公告：

1. 兼容 DSH `0.1.2` 与 `0.1.3` 的接口和运行时结构，bundled Docker 继续以内置 DSH `0.1.2-rc.1` 为主目标。
2. 修复 Issue #29 相关的 Remote mux 历史加载可靠性：浏览器连接增加 heartbeat，支持 DSH `0.1.2`/`0.1.3` 的大历史快照，并校验 `session/follow` 快照身份后再转发。
3. 补齐新会话 API 的子用户资源授权：文件上传与引用、Skill、消息反馈、目标、动态 Cordis runner、模型选择和会话引用检索均在到达 DSH 前按当前会话授权过滤。
4. 清理过期会话授权：保存权限时移除已失效的历史会话，但仍拒绝从未验证过的会话 ID，避免陈旧授权阻塞有效分配。
5. 简化子用户 SSH：主用户配置的主机摘要可供开启 SSH 且勾选 SSH 端点的子用户使用；子用户不能新增、导入、修改主机或使用 cluster/tunnel，主机密码与私钥仍不会返回浏览器。

验证：275/275 本地回归测试、TypeScript 构建、npm 官方 registry 生产依赖审计、发布包内容和 Git 差异检查通过。Docker 镜像发布前以 DSH `0.1.2-rc.1` 构建并核验。

### English

Release notes:

1. Adds compatibility with the DSH `0.1.2` and `0.1.3` API and runtime boundaries; bundled Docker continues to target the included DSH `0.1.2-rc.1` runtime.
2. Fixes Remote mux history-loading reliability related to Issue #29: browser connections now send heartbeats, large DSH `0.1.2`/`0.1.3` history snapshots are supported, and `session/follow` snapshot identity is verified before forwarding.
3. Completes subuser resource authorization for newer session APIs. File uploads and references, Skills, message feedback, goals, dynamic Cordis runner calls, model selection, and session-reference lookup are filtered against the current session grant before reaching DSH.
4. Improves multi-user assignment saves: stale historical session grants are removed while never-validated session IDs remain rejected, so obsolete grants no longer block valid assignments.
5. Simplifies subuser SSH access: an owner-configured host summary can be used by a subuser only when SSH and the SSH endpoint are enabled; subusers cannot add, import, modify hosts, or use cluster/tunnel operations, and passwords/private keys never reach the browser.

Validation: 275/275 local regression tests, the TypeScript build, the official-registry production dependency audit, package-content checks, and Git whitespace checks passed. The Docker image is built with DSH `0.1.2-rc.1` and verified before publication.

## 2.6.10 - 2026-09-04

### 中文

更新公告：

1. 兼容 DSH `0.1.2-rc.1`。安装器、bundled Docker 默认运行时、补丁探测与启动前 Cookie bridge 校验已切换到 rc.1，并继续保留已知 `0.1.2-alpha.1` 至 `alpha.5` 布局的兼容适配。
2. 增加 RC.1 子代理基础兼容：已获父会话授权的用户可使用普通会话与 `subagent` 地址格式的历史分页、实时 `session/follow`、继续任务和中断；`parentSessionId`、`childSessionId` 与 `mode` 原样交由 DSH 校验，child session 不会写入普通授权表。
3. 修复多用户搜索隔离：`session/search` 仅向子用户返回其当前已授权且未被禁用的会话结果，避免暴露未授权会话 ID 与消息摘要。
4. 增加子用户 SSH 连接权限开关和主机 alias 归属隔离。启用后，子用户只能查看、创建和使用自己通过网关认领的 SSH 主机；共享导入、隧道和管理员全局主机仍保持主用户专属。
5. 完整移除部署 profile 中不兼容的 `@linxin666/dsh-web-all` 聚合插件，避免其独立设备配对传输干扰网关认证和造成插件加载失败；DSH 核心 Web App 与 dsh-passwords 保持独立运行。

验证：全量本地回归测试 263/263、TypeScript 构建、npm 官方 registry 生产依赖审计和发布包内容检查通过。Docker 镜像在发布前执行构建并校验内置版本。

### English

Release notes:

1. Adds compatibility with DSH `0.1.2-rc.1`. The installers, bundled Docker runtime, patch detection, and startup Cookie-bridge validation now target rc.1 while retaining adapters for the known `0.1.2-alpha.1` through `alpha.5` layouts.
2. Adds baseline RC.1 subagent compatibility. Users authorized for a parent session can use ordinary and `subagent` address forms for history paging, live `session/follow`, continuation, and interruption. `parentSessionId`, `childSessionId`, and `mode` are forwarded unchanged for DSH validation, and child sessions are not persisted as ordinary grants.
3. Fixes multi-user search isolation: `session/search` now returns only currently authorized, enabled sessions to a subuser, preventing exposure of unauthorized session IDs and message summaries.
4. Adds a subuser SSH permission toggle and per-user SSH host-alias ownership. When enabled, a subuser can only view, create, and use SSH hosts claimed through the gateway; shared imports, tunnels, and administrator-global hosts remain owner-only.
5. Fully removes the incompatible `@linxin666/dsh-web-all` aggregate plugin from the deployment profile. Its independent device-pairing transport could conflict with gateway authentication and trigger plugin-loader failures; the core DSH Web App and dsh-passwords now run independently.

Validation: 263/263 local regression tests, the TypeScript build, the npm official-registry production dependency audit, and package-content checks passed. The Docker image is built and its embedded versions are verified before publication.

## 2.6.9 - 2026-09-03

### 中文

更新公告：

1. 修复弱网络下新建会话的最终工作区归属同步：即使首次 `workspace/follow` 增量丢失，创建成功后也会向现有连接补发经过权限校验的工作区更新，避免会话落入“未分组”。
2. 加强主用户权限分配清单的实时校验：已删除、已归档、目录缺失或当前不可用的工作区/会话不再显示为可分配资源，资源状态不可确认时保存操作安全失败。

验证：本地全量测试、TypeScript 检查、构建、生产依赖审计和发布包内容检查均通过后发布。

### English

Release notes:

1. Fixes final workspace assignment under weak networks: even when the first `workspace/follow` delta is lost, a successful session creation sends a permission-checked compensating workspace update to existing connections, preventing the session from appearing under “Ungrouped”.
2. Strengthens the owner-side assignment inventory with live validation: deleted, archived, missing-directory, or otherwise unavailable workspaces and sessions are no longer assignable, and saving fails closed when the resource authority cannot be confirmed.

Validation: the release is published after the full local test suite, TypeScript check, build, production dependency audit, and package-content checks pass.

## 2.6.8 - 2026-09-03

### 中文

更新公告：

1. 兼容 DSH `0.1.2-alpha.1` 至 `0.1.2-alpha.5`。alpha.1 为源码运行时兼容目标，npm/Docker bundled 安装默认使用并内置 alpha.5。
2. 修复 Issue #25：主用户授予子用户既有工作区和会话后，子用户可以正确看到并选择这些资源；工作区与会话加载竞态不会再把授权资源显示为“无工作区”或在选择后清退。
3. 完善 alpha Remote mux 的多用户隔离：workspace/session 基线、显式会话授权、事件流和权限变更后的连接刷新均按当前用户权限重新校验。
4. 加固子用户权限端到端执行：沙盒确认失败时拒绝创建会话，工作区创建与管理、上传、Git 下载、Agent preset、WebSocket、封禁和逐会话关闭保持独立边界；部分权限更新不会意外恢复既有限制。
5. bundled Docker 默认携带 DSH `0.1.2-alpha.5`，npm 包、GitHub 源码和 Docker 构建使用同一份预构建产物。

验证：本地全量测试、TypeScript 检查、构建、生产依赖审计和发布包内容检查均通过后发布。

### English

Release notes:

1. Supports DSH `0.1.2-alpha.1` through `0.1.2-alpha.5`. Alpha.1 remains a source-runtime compatibility target; npm/Docker bundled installs use and include alpha.5 by default.
2. Fixes Issue #25: when the owner grants an existing workspace and its sessions to a subuser, the subuser can see and select them correctly. Workspace/session loading races no longer turn granted resources into “no workspace” or remove them after selection.
3. Strengthens multi-user isolation for the alpha Remote mux: workspace/session baselines, explicit session grants, event streams, and reconnects after permission changes are revalidated against the current user.
4. Enforces subuser permissions end to end: failed sandbox confirmation rejects session creation; workspace management, uploads, Git downloads, Agent presets, WebSockets, bans, and per-session disablement retain separate boundaries. Partial permission updates cannot accidentally restore existing restrictions.
5. The bundled Docker image now includes DSH `0.1.2-alpha.5`; the npm package, GitHub source, and Docker build use the same prebuilt artifacts.

Validation: the release is published after the full local test suite, TypeScript check, build, production dependency audit, and package-content checks pass.
