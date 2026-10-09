# Docker 与安装器测试缺口评估

**评估日期：** 2026-10-07
**对象：** `dsh-passwords` 2.7.8 工作区（`D:\ais\server\local preview version`）
**范围：** 4 个已知缺口的可测性/成本评估，及低成本缺口的自动化补充与高成本缺口的替代方案。

## 结论概览

| # | 缺口 | 可测性 | 自动化成本 | 处置 |
| --- | --- | --- | --- | --- |
| 1 | 真实 Docker 构建 / 容器 E2E | 中（需 daemon + 网络 + 数分钟 + root） | 高 | 不写无法运行的测试；给出手动验收清单 + CI 编排方案 |
| 2 | Windows 安装器主流程无自动化 | 引导壳可测，自动装依赖不可测 | 低（引导壳）/ 高（端到端） | 已补引导壳测试；端到端给手动清单 + `windows-latest` CI 方案 |
| 3 | `test/packaging.test.ts` 在 `dist` 缺失时静默 `return` | 高 | 低 | 已修：改为显式断言失败 |
| 4 | Issue #39 未集成验证 `.env` 的 timeout/TTL 影响网关 | 高 | 低 | 已补集成测试，并提取可测的 `resolveInventoryTtlMs` |

判定标准：能在当前环境通过 `npm run build` + `node --import tsx --test "test/**/*.test.ts"`、无需 Docker daemon / 网络 / 特权、且失败即代表真实回归的，直接补测试；其余一律转手动清单或 CI，不写“永远 skip 或永远绿”的伪测试。

## 本次补充的自动化

| 文件 | 覆盖项 | 用例数 |
| --- | --- | --- |
| `test/packaging.test.ts`（改） | `dist/` 缺失时显式失败，杜绝打包回归被静默放过 | 复用原 3 例，其中 1 例由静默改为断言 |
| `test/issue-39-env-timeout-ttl-integration.test.ts`（新增） | `.env` → `deploymentGatewayEnv` → `upstreamResponseHeaderTimeoutMs` / `internalProbeTimeoutMs` / `resolveInventoryTtlMs` 全链路；缺省回落；TTL 有界；env 派生 TTL 真正驱动 loader 缓存 | 4 |
| `test/install-bat.test.ts`（新增） | `install.bat` 交接入口、Node 版本门禁与 `install.sh`/engines 对齐、幂等目录判定、ASCII-only、收尾提示；真实 spawn 引导壳验证退出码透传（Windows 上执行，非 Windows skip） | 7 |
| `src/plugin.ts`（改） | 抽出 `resolveInventoryTtlMs(env)`（与 `internalProbeTimeoutMs` / `upstreamResponseHeaderTimeoutMs` 同形），`apply()` 复用之，无行为变化 | — |

---

## 缺口 1：真实 Docker 构建 / 容器 E2E（未自动化）

**为何不写成自动化测试：** 需要 Docker daemon、外网（npm registry + `@deepseek-ai/dsh` 包）、root、以及单次 5–10 分钟的镜像构建与原生依赖编译。当前测试的运行前提（见 `.github/workflows/ci.yml`：`ubuntu-latest`，`npm ci && npm run build && node --import tsx --test "test/**/*.test.ts"`）不保证这些条件，任何在此处“测 Docker”的用例要么永远 skip，要么造成 CI 不稳定。现有 `test/docker-entrypoint.test.ts`、`test/docker-init.test.ts` 只做**静态契约**与**纯函数**校验，属正确边界。

### 替代方案 A：手动验收清单

前置：一台装了 Docker 的主机；`docker buildx` 可用。

**A. 单容器（gate-only，`docker/Dockerfile`）**

1. `docker build -f docker/Dockerfile -t dshpw:gate .` → 构建成功。
2. 准备已打补丁的 dsh 目录并挂载：
   `docker run --rm -v /path/to/dsh:/opt/dsh -e MCP_DSH_ROOT=/opt/dsh -v dshpw-state:/data/dsh-passwords dshpw:gate`
   → entrypoint 日志：`dsh patch applied`；容器**不**退出。
3. 卷内首个 `docker-init`：`docker run --rm -v dshpw-state:/data/dsh-passwords dshpw:gate cat /data/dsh-passwords/.env`
   → 含随机 `SETUP_KEY`、`MCP_DB_ENC_KEY`、`MCP_GATEWAY_PORT=3088`、`DSH_PASSWORDS_RUNTIME=docker`；`setup-key.txt` 存在且与 `.env` 的 `SETUP_KEY` 一致。
4. 幂等：删掉 `setup-key.txt` 再启动 → 不轮换 `SETUP_KEY`（`docker-init.test.ts` 的纯逻辑已有同断言，这里是端到端复验）。
5. 传入 `-e SETUP_KEY=<已知值>` 启动 → `.env` 采用该值且**不**写 `setup-key.txt`（用户已知，故不留明文）。
6. 上游缺失守护：`MCP_DSH_ROOT` 指向不存在目录 → 容器以非零码退出并打印 `dsh directory not found`。
7. Issue #39 端到端：容器内 `docker exec ... env` 确认 `.env` 中的
   `MCP_GATEWAY_UPSTREAM_HEADER_TIMEOUT_MS` / `MCP_GATEWAY_INTERNAL_PROBE_TIMEOUT_MS` / `MCP_DSH_PASSWORDS_INVENTORY_TTL_MS`
   出现在网关进程环境中（`DSH_PASSWORDS_RUNTIME=docker` 时环境变量优先，是设计预期）。

**B. 打包单容器（bundled，`docker/Dockerfile.bundled`）**

8. `DEEPSEEK_API_KEY=sk-xxx DSH_VERSION=0.2.1-alpha.2 docker compose -f docker/docker-compose.yml up --build`
   → 镜像内 `bundled DSH 0.2.1-alpha.2`，entrypoint 打补丁后 `exec dsh web --no-open` 拉起网关。
9. 宿主侧：`curl -sf http://127.0.0.1:3088/healthz`（及 `/readyz`，若启用）返回 200。
10. 浏览器打开 `https://<公网IP>.sslip.io` → 首次进入 SETUP_KEY 初始化页 → 创建 owner → 子用户权限页可打开（不 504）。
11. 权限页与保存授权在规模语料下不再 504/502（配置了 §7 的三个键后）。

**失败判定：** 任一步骤非预期退出、`.env` 未生成、`SETUP_KEY` 被轮换、健康端点非 200、权限页 504/502 即视为失败。

### 替代方案 B：CI 编排方案（`ubuntu-latest`，非阻塞 nightly）

新增 `.github/workflows/docker-e2e.yml`（`workflow_dispatch` + `schedule`，与主 `ci.yml` 解耦，避免拖慢每个 PR）：

```yaml
name: docker-e2e
on:
  workflow_dispatch:
  schedule:
    - cron: '0 3 * * *'
jobs:
  build-and-smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: docker/setup-buildx-action@v3
      - name: build gate-only image
        run: docker build -f docker/Dockerfile -t dshpw:gate .
      - name: docker-init is idempotent and env-driven (real container)
        run: |
          docker run --rm -v dshpw-state:/data/dsh-passwords -e SETUP_KEY=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n') dshpw:gate docker-init
          docker run --rm -v dshpw-state:/data/dsh-passwords dshpw:gate cat /data/dsh-passwords/.env
      - name: build bundled image
        run: docker build -f docker/Dockerfile.bundled --build-arg DSH_VERSION=0.2.1-alpha.2 -t dshpw:bundled .
```

要点：
- **只验证构建与容器内 `docker-init` 幂等**（确定性、无外网除 registry 外依赖）。真正的网关 E2E（步骤 9–11）需要 `DEEPSEEK_API_KEY` 与 dsh 授权，放 `workflow_dispatch` 人工触发并注入 secret，不并入 push/PR 门禁。
- `docker build` 需拉取 `@deepseek-ai/dsh`，属网络依赖，因此该 job 用 `schedule`/`workflow_dispatch` 而非 `pull_request`，防止上游 registry 抖动阻塞合并。

---

## 缺口 2：Windows 安装器完整流程（部分自动化）

**已自动化的部分**（`test/install-bat.test.ts`）：引导壳的目录定位、与 `install.mjs` 的交接、退出码透传、收尾提示，以及静态契约（版本门禁与 `install.sh`/`engines` 对齐、幂等目录判定、ASCII-only）。这覆盖了主流程的**控制逻辑**，且不需要网络。

**无法确定性地自动化的部分：** `winget install OpenJS.NodeJS.LTS` / `Git.Git`、`git clone`、`npm install -g @deepseek-ai/dsh`、以及 winget 安装后本会话 `PATH` 不刷新需重开的交互——这些依赖网络、管理员权限、真实 winget，且会污染开发机。

### 替代方案 A：手动验收清单

**全新机（无 Node/git/dsh）**

1. 双击 `install.bat` → 检测到缺 Node → winget 自动安装 → 若本会话不可见则提示“新开终端重跑”，退出码非零。
2. 新终端重跑 → Node 版本门禁通过（打印 `Node.js vX.Y.Z OK`）→ 检测缺 git → winget 自动安装 → `git OK`。
3. 检测缺 dsh → 先 `npm config set allow-scripts=...` 再 `npm install -g @deepseek-ai/dsh@0.2.1-alpha.2` → `dsh OK`。
4. 下载项目到 `%USERPROFILE%\dsh-passwords` → 交接 `node scripts\install.mjs` → 首次安装打印 `SETUP_KEY`，`setup-key.txt` 生成且 ACL 已收紧（仅当前用户 + SYSTEM）。
5. 浏览器 `dsh web` → 进入初始化页，用 SETUP_KEY 建 owner。

**幂等 / 覆盖**

6. 再次双击同一目录的 `install.bat` → 识别已有 `dsh-passwords`（`findstr` 命中 `package.json` name）→ 就地重跑，**不**新建目录、**不**覆盖 `.env`、**不**轮换 `SETUP_KEY`。
7. `set DSH_PASSWORDS_DIR=D:\custom` 后双击 → 安装到 `D:\custom`。
8. 目标目录存在但**不是** dsh-passwords → 明确报错退出，不覆盖。
9. 断网重跑（无 `.env`）→ `git clone` 失败 → 打印“项目下载失败，请检查网络”且退出码非零。

**失败判定：** 自动安装步骤静默失败、版本门禁误放行 23 或 22.<19、幂等重跑覆盖 `.env`/轮换密钥、失败时窗口立即关闭或谎报成功，均视为失败。

### 替代方案 B：CI 编排方案（`windows-latest`）

新增 `.github/workflows/windows-installer.yml`（`workflow_dispatch`，非 PR 门禁）：

```yaml
name: windows-installer
on:
  workflow_dispatch:
jobs:
  bootstrap:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v5
      - name: run the real bootstrap shell
        shell: cmd
        run: install.bat
      - name: assert first-run artifacts
        shell: pwsh
        run: |
          $env = "$env:USERPROFILE\dsh-passwords\.env"
          if (!(Test-Path $env)) { throw "installer did not produce .env" }
          if (!(Select-String -Path $env -Pattern '^SETUP_KEY=.+')) { throw "missing SETUP_KEY" }
      - name: second run must be idempotent
        shell: cmd
        run: install.bat
```

注意：
- runner 已预装 Node/git，`winget` 分支基本不会被触发；该 job 真正验证的是**交接 + 首次安装产物 + 幂等重跑**这三段，与本地手动清单 4/6 呼应。
- `install.bat` 结尾的 `pause >nul` 在非交互 stdin 下立即返回，CI 可安全运行（本地 `test/install-bat.test.ts` 的 spawn 用例已用同一机制验证）。
- winget 自动安装分支无法在 runner 上稳定复现，仍由手动清单 1–3 兜底。

---

## 缺口 3：`packaging.test.ts` 静默通过（已修复）

原实现：`if (!existsSync(distDir)) return;` —— `dist/` 不存在时测试直接返回，GitHub 上偶发“dist 没构建出来”会被当成通过。

修复：改为 `assert.equal(existsSync(distDir), true, ...)`。按约定先 `npm run build` 再跑测试，正常执行必定通过；只有当有人跳过构建（直接跑 `node --import tsx --test "test/**/*.test.ts"`）时才会显式失败并提示先构建——这正是想要的行为。

## 缺口 4：Issue #39 的 `.env` timeout/TTL 未集成验证（已补充）

`test/config-env-precedence.test.ts` 已证明这三个键会进 `deploymentGatewayEnv` 快照，但没证明它们**最终改变网关判定**。Issue #39 的修复（header 预算、internal probe 预算、inventory TTL）全部依赖这条链路，缺口的风险是“`.env` 写了但网关仍用默认值”。

新增 `test/issue-39-env-timeout-ttl-integration.test.ts` 把快照原样喂给三个真实消费点：

- `upstreamResponseHeaderTimeoutMs(env)`（`src/proxy.ts`，504 预算）
- `internalProbeTimeoutMs(env)`（`src/gateway.ts`，502 预算）
- `resolveInventoryTtlMs(env)`（`src/plugin.ts`，缓存开关）→ 并实际构造 loader 验证 env 派生出的 TTL 真的启用/禁用缓存。

为让 TTL 消费点可测且不改行为，把 `apply()` 内联的解析抽成导出的纯函数 `resolveInventoryTtlMs`（与另外两个 resolver 同形），`apply()` 调用它——逻辑逐字保留，仅位置变化。
