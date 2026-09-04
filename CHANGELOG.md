# Changelog

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
