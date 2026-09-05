# dsh-passwords

[English](README_en.md) | 简体中文

<p align="center">
  <img src="docs/banner.jpg" alt="dsh-passwords" width="100%">
</p>

<p align="center">
  <a href="https://github.com/slywalker2006/dsh-passwords/releases/latest"><img src="https://img.shields.io/github/v/release/slywalker2006/dsh-passwords?style=flat-square" alt="Version"></a>
  &nbsp;
  <a href="https://github.com/slywalker2006/dsh-passwords/stargazers"><img src="https://img.shields.io/github/stars/slywalker2006/dsh-passwords?style=flat-square" alt="Stars"></a>
  &nbsp;
  <a href="https://www.npmjs.com/package/dsh-passwords"><img src="https://img.shields.io/npm/v/dsh-passwords?style=flat-square" alt="npm"></a>
  &nbsp;
  <a href="https://www.npmjs.com/package/dsh-passwords"><img src="https://img.shields.io/npm/dm/dsh-passwords?style=flat-square" alt="Downloads"></a>
  &nbsp;
  <a href="https://github.com/slywalker2006/dsh-passwords/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/slywalker2006/dsh-passwords/ci.yml?style=flat-square&label=CI" alt="CI"></a>
  &nbsp;
  <a href="https://github.com/deepseek-ai/deepseek-harness"><img src="https://img.shields.io/badge/DSH-0.1.2--rc.1-4c6ef5?style=flat-square&labelColor=454a54" alt="DSH"></a>
  &nbsp;
  <img src="https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square" alt="License">
  &nbsp;
  <a href="https://github.com/awesome-dsh-plugin/awesome-dsh-plugin"><img src="https://img.shields.io/badge/Awesome-DSH%20Plugin-9370db?style=flat-square" alt="Awesome DSH Plugin"></a>
  &nbsp;
  <a href="https://github.com/0xsline/awesome-deepseek-harness"><img src="https://img.shields.io/badge/Awesome-DeepSeek%20Harness-4c6ef5?style=flat-square" alt="Awesome DeepSeek Harness"></a>
  &nbsp;
  <a href="https://github.com/Zhiyuan-Fan/Awesome-DeepSeek-Harness-Plugins"><img src="https://img.shields.io/badge/%E6%94%B6%E5%BD%95-Awesome%20%E6%8F%92%E4%BB%B6%E7%B2%BE%E9%80%89-15aabf?style=flat-square" alt="Awesome 插件精选收录"></a>
  &nbsp;
  <a href="https://github.com/bruc3van/awesome-dsh-plugin"><img src="https://img.shields.io/badge/%E6%94%B6%E5%BD%95-DSH%20%E7%B2%BE%E9%80%89%E7%9B%AE%E5%BD%95-1c7ed6?style=flat-square" alt="DSH 精选目录收录"></a>
  &nbsp;
  <a href="https://github.com/imsai-sh/awesome-deepseek-harness-plugins"><img src="https://img.shields.io/badge/%E6%94%B6%E5%BD%95-1024%20%E6%8F%92%E4%BB%B6%E5%95%86%E5%BA%97-0ca678?style=flat-square" alt="1024 插件商店收录"></a>
</p>

<p align="center">
  <strong>给 DeepSeek Harness 加一层服务器级认证网关，使其成为可公网部署的多租户平台</strong><br>
  <em>登录认证 · 自动 HTTPS · 多租户权限 · 会话授权 · 审计加密 · 中英双语</em>
</p>

<div align="center">

[功能](#功能) · [快速开始](#快速开始) · [首次配置](#首次配置) · [卸载](#卸载) · [自动 HTTPS](#自动-https) · [部署拓扑](#部署拓扑) · [配置参考](#配置参考) · [常见问题](#常见问题) · [安全与隐私](#安全与隐私) · [参与贡献](#参与贡献)

</div>

---

dsh 自带的网页界面没有登录与权限控制，公网部署后任何拿到地址的人都能直接使用。dsh-passwords 在 dsh 前面运行一个网关：未登录访问只见到登录页，登录后按账号执行权限与配额控制。项目收录于 [Awesome DeepSeek Harness](https://github.com/0xsline/awesome-deepseek-harness#security--governance)（Security & Governance）与 [Awesome DSH Plugin](https://github.com/awesome-dsh-plugin/awesome-dsh-plugin#security--permissions)（Security & Permissions）。

## 功能

- **登录认证**：首次配置创建主用户，之后所有访问先过登录页；会话 12 小时有效
- **自动 HTTPS**：向 Let's Encrypt 自动签发并续期证书，80 端口自动跳转 443，无需配置
- **多租户**：一个主用户加任意多个子用户，账号管理全部在 dsh 设置页完成
- **权限与配额**：工作区白名单、逐会话开关、每小时 token 上限、每日时长上限、沙盒三档、上传与下载开关、封禁
- **会话授权**：工作区权限不自动包含其中全部会话，主用户逐会话授予；归档状态在工作区列表与会话列表间保持一致
- **运维视图**：主用户可查看全部工作区与会话，下载非敏感普通文件
- **审计与安全**：登录限流与锁定、审计日志、SQLite 静态加密、登出即吊销会话
- **设置页卡片**：远程设置补丁重载、软件更新、账号与权限管理、站内留言，全部中英双语

## 界面截图

| 登录页 · 浅色 | 登录页 · 深色 | 登录页 · English |
|:---:|:---:|:---:|
| <img src="docs/screenshots/white-login.png" width="360"> | <img src="docs/screenshots/black-login.png" width="360"> | <img src="docs/screenshots/white-login-en.png" width="360"> |

| dsh 主界面 · 登录后 | 聊天 / 留言 | 设置页卡片 · 账号管理 |
|:---:|:---:|:---:|
| <img src="docs/screenshots/main-ui.png" width="360"> | <img src="docs/screenshots/chat.png" width="360"> | <img src="docs/screenshots/card-front.png" width="360"> |

| | 设置页卡片 · 权限与配额 | |
|:---:|:---:|:---:|
| | <img src="docs/screenshots/card-back.png" width="360"> | |

## 快速开始

### 前置条件

宿主机安装需要 Node.js 22.19+ 或 24+、可正常运行的 dsh 和 git。请让本插件与 dsh 宿主使用同一 Node 主线版本；DSH `0.1.2-rc.1` 的官方运行要求也是 22.19+ 或 24+。Docker 安装只需要 Docker Engine 或 Docker Desktop 和一个 DeepSeek API key。

### 安装

五种安装方式，任选其一。宿主机安装会自动完成装依赖、编译、生成 SETUP_KEY、注册 dsh 插件、应用远程设置补丁；已有 `.env` 时不覆盖，重复运行安全。

```bash
# 1. Linux / macOS 一键安装
curl -fsSL https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/install.sh | bash

# 2. 先 clone 再安装
git clone https://github.com/slywalker2006/dsh-passwords && cd dsh-passwords
bash install.sh

# 3. npm 全局安装，适用于任意平台
npm install -g dsh-passwords
dsh-passwords install
```

Windows 下载仓库里的 `install.bat` 双击运行。默认安装到 `%USERPROFILE%\dsh-passwords`。

```bash
# 4. Docker
docker run -d \
  --name dsh-passwords \
  --restart unless-stopped \
  --env-file .env \
  -p 127.0.0.1:3088:3088 \
  -v dsh-home:/data/dsh \
  -v dsh-passwords-state:/data/dsh-passwords \
  skywalker237234/dsh-passwords
```

`.env` 至少包含 `DEEPSEEK_API_KEY`。`MCP_GATEWAY_PUBLIC_HOST` 建议填实际访问的域名。容器只在回环地址监听 3088，公网访问由 nginx 或 Caddy 终结 TLS 后转发。初始化完成以日志出现 `dsh patch applied; starting dsh` 为准。

说明：

- 宿主机安装默认目录为 `/opt/dsh-passwords` 或 `$HOME/dsh-passwords`，用 `DSH_PASSWORDS_DIR` 更改；目标目录已存在时报错退出
- SETUP_KEY 打印在安装结束时，同时写入安装目录的 `setup-key.txt`
- Docker 的两个命名卷分别存 dsh profile 与 `.env`、数据库、证书；删除即丢数据
- 分容器部署时给 dsh 容器加 `MCP_DSH_PATCH_ALLOW_BIND_ALL=1`，让网关容器能访问 dsh web

### 首次配置

1. 启动 dsh：`dsh web`。Docker 用户跳过此步，容器内自动启动。
2. 浏览器打开 `https://<服务器地址>`，首次访问自动进入配置页。
3. 输入 SETUP_KEY 创建主用户。此后该地址的所有访问都先过登录页。

首次配置成功后 `setup-key.txt` 自动删除，`.env` 中的密钥自动固化并轮换。

Docker 用户需要先用 nginx 或 Caddy 把 80/443 反代到 `http://127.0.0.1:3088`；一次性 SETUP_KEY 用 `docker exec dsh-passwords cat /data/dsh-passwords/setup-key.txt` 读取。

## 卸载

宿主机安装可在 dsh-passwords 安装目录执行：

```bash
node dist/cli.js uninstall
# 全局 npm 安装也可直接执行：
dsh-passwords uninstall
```

该命令只从 DSH web profile 移除 `dsh-passwords` 的 link 与 bundle，并回滚本插件管理的 dsh 补丁；其他插件和 bundle 会保留。完成后按提示重启 `dsh-web`。

卸载不会删除安装目录、`.env`、数据库、TLS/ACME 证书或其他插件。profile 依赖重建或补丁回滚失败时会恢复原 profile，避免留下半卸载状态。Docker 部署请按所用 Compose 或容器编排停止并移除容器；不要删除命名卷，除非也要永久清除数据。

## 自动 HTTPS

默认探测公网 IP 并用 `<IP>.sslip.io` 向 Let's Encrypt 签发 90 天证书，到期前 30 天自动续期，新证书热加载。有自己的域名时在 `.env` 加 `MCP_GATEWAY_DOMAIN`。签发失败拒绝启动，不降级明文；续期失败但旧证书仍在有效期内时继续使用并后台重试。

| 错误码 | 含义 | 处理 |
|---|---|---|
| 30 | 证书签发失败 | 检查 80/443 放行与占用情况，确认能连通 Let's Encrypt |
| 31 | 拿不到公网 IP 或域名 | 设置 `MCP_GATEWAY_DOMAIN`，或使用 HTTP 模式 |
| 32 | 端口被占用 | 更换 `MCP_GATEWAY_PORT` 或释放端口 |

证书域名使用 `<IP>.sslip.io` 是因为 Let's Encrypt 不给纯 IP 签发证书。直接访问裸 IP 的 https 地址会提示主机名不匹配，从 80 端口入口进入会自动跳转到正确地址。

## 部署拓扑

| 场景 | 做法 |
|---|---|
| 公网服务器，80/443 可用 | 默认配置即可，自动 HTTPS |
| 已有域名证书 | `.env` 填 `MCP_GATEWAY_TLS_CERT` / `MCP_GATEWAY_TLS_KEY`，无需 80 端口 |
| 已有 nginx / Caddy 反代 | 反代终结 TLS，`.env` 设 `MCP_GATEWAY_AUTO_TLS=0` 与高位端口，网关只监听回环 |
| Cloudflare | CF 边缘终结 TLS 转发源站，配置同反代 |
| 纯内网 / 裸 IP 无法开 80 | 使用 HTTP 模式 |

http-01 验证只在签发与续期时访问 80 端口，约每 60 天一次。

## HTTP 模式

默认拒绝明文 HTTP。内网环境确需使用时：

```bash
node scripts/start-http.mjs [端口]    # 默认 8080，需确认风险提示
```

或在 `.env` 写入 `MCP_GATEWAY_AUTO_TLS=0` 与 `MCP_GATEWAY_PORT=8080`，dsh 启动时插件以 HTTP 模式拉起网关。

## 设置页卡片

登录后打开设置，能看到「dsh-passwords · 密码门」卡片。

| 功能 | 使用者 | 说明 |
|---|---|---|
| 重载补丁 | 仅主用户 | dsh 升级后设置页异常时一键重打补丁并重启网页服务 |
| 软件更新 | 状态所有人可见，操作仅主用户 | 自动检查、限速下载、空闲后安装重启，详见下节 |
| 修改密码 / 用户名 | 本人；主用户可操作任何人 | 改密后旧会话全部失效 |
| 子用户管理 | 仅主用户 | 创建、删除子用户 |
| 子用户权限 | 仅主用户 | 工作区白名单、逐会话授权、token 与时长上限、沙盒、上传下载开关、WebSocket 路径授权、封禁 |
| 聊天 / 留言 | 所有登录用户 | 支持标签；子用户消息默认私信主用户，仅主用户可广播 |
| 退出登录 | 所有登录用户 | 登出当前账号 |

密码要求：至少 12 位，含大写、小写、数字、符号。

## 软件更新

- 版本发现走 GitHub Release，包始终从 npm registry 下载并按 `dist.integrity` 的 sha512 校验
- 自动模式：每 24 小时检查，发现新版本后限速下载，平台连续空闲 1 小时后安装重启；主用户可手动跳过等待
- 手动模式：检查只发现版本，第一次点击触发下载，第二次点击安装重启
- 安装保留 `.env`、`data/`、数据库、TLS 与 profile，失败自动回滚
- Docker 更新需显式配置 `MCP_DSH_DOCKER_SELF_UPDATE=1` 与 Compose 相关变量，未配置时只显示宿主机手动命令；Docker socket 等同授予容器宿主控制权限，仅在可信部署启用

## 配置参考

| 变量 | 默认 | 说明 |
|---|---|---|
| `SETUP_KEY` | 安装脚本生成 | 首次配置密钥，配置成功后自动轮换 |
| `MCP_JWT_SECRET` | 从 SETUP_KEY 派生 | 会话签名密钥，生产环境建议 `openssl rand -hex 32` 独立设置 |
| `MCP_DB_PATH` | `./data/platform.db` | SQLite 数据库路径 |
| `MCP_DB_ENC_KEY` | 空 | 字段加密密钥，启用后不可更换；备份数据库必须连同 `.env` |
| `MCP_GATEWAY_HOST` / `MCP_GATEWAY_PORT` | `0.0.0.0` / `443` | 网关监听地址与端口 |
| `MCP_GATEWAY_UPSTREAM` | `http://127.0.0.1:3080` | dsh 网页地址，插件自动指向 |
| `MCP_GATEWAY_WS_ADMIN_ALLOWLIST` | 空 | 仅主用户可用的第三方 WebSocket 路径；支持精确路径与 `/*` 通配，不会出现在子用户授权列表 |
| `MCP_GATEWAY_WS_USER_ALLOWLIST` | 空 | 可由主用户逐项授权给子用户的第三方 WebSocket 路径；支持精确路径与 `/*` 通配 |
| `MCP_GATEWAY_REDIRECT_PORT` | `80` | ACME 验证与 301 跳转端口 |
| `MCP_GATEWAY_DOMAIN` | 空 | 自定义域名，留空用 `<公网IP>.sslip.io` |
| `MCP_GATEWAY_AUTO_TLS` | 开 | `0` 关闭自动 HTTPS |
| `MCP_GATEWAY_TLS_CERT` / `MCP_GATEWAY_TLS_KEY` | 空 | 自有证书，优先于自动 HTTPS |
| `MCP_GATEWAY_PUBLIC_HOST` | 空 | 固定跳转地址，防 Host 伪造 |
| `MCP_GATEWAY_ACME_EMAIL` / `MCP_GATEWAY_ACME_STAGING` | 空 / 关 | 证书提醒邮箱 / LE 测试环境 |
| `MCP_DSH_ROOT` | 自动探测 | dsh 安装目录 |
| `MCP_DSH_RESTART_SERVICE` | `dsh-web` | 重载补丁后重启的 systemd 服务名 |
| `MCP_DSH_AUTO_UPDATE` | 开 | 部署级自动更新总开关 |
| `MCP_DSH_UPDATE_MAX_BPS` | 1MiB/s | 自动下载限速，只能调低 |
| `MCP_DSH_DOCKER_SELF_UPDATE` / `_COMPOSE_DIR` / `_COMPOSE_FILE` / `_IMAGE` / `_SOCKET` | 关 / 空 | Docker 应用内更新的启用开关与 Compose 配置 |
| `MCP_DSH_PATCH_ALLOW_BIND_ALL` | 关 | 分容器拓扑允许 dsh web 绑定 0.0.0.0 |
| `DSH_PASSWORDS_ENV_FILE` | 空 | 手动指定 `.env` 路径 |

## 常用命令

```bash
node dist/cli.js audit --limit 20        # 最近 20 条审计日志
node dist/cli.js patch status            # 远程设置补丁状态
node dist/cli.js patch                   # 重载补丁并重启 dsh-web
node dist/cli.js serve-gateway --port 9000   # 手动启动网关
DSH_PASSWORDS_NO_AUTOSTART=1 dsh web     # 禁止网关自动拉起
curl -s https://地址/gateway/healthz      # 存活检查
curl -s https://地址/gateway/readyz       # 就绪检查，含数据库
```

## 常见问题

<details>
<summary><strong>登录页一直显示首次配置</strong></summary>

用户表为空，按提示输入 SETUP_KEY 重建主用户。

</details>

<details>
<summary><strong>忘记主用户密码</strong></summary>

停服后删除 users 表并重启：

```bash
node -e "const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync('data/platform.db');db.exec('DELETE FROM users;')"
```

</details>

<details>
<summary><strong>错误码 30 / 31 / 32</strong></summary>

见「自动 HTTPS」一节的错误码表。

</details>

<details>
<summary><strong>非 root 绑定 443 失败</strong></summary>

Linux 下 1024 以下端口需要 root，改用 `MCP_GATEWAY_PORT` 高位端口并自行做端口转发。

</details>

<details>
<summary><strong>dsh 报 duplicate loader entry id</strong></summary>

`dsh plugin add` 会把所有声明 bundle 的依赖加入 bundles 层导致冲突。卸载后改用 `node scripts/register-plugin.mjs` 精确注册。

</details>

<details>
<summary><strong>npm 安装 dsh 报 node-pty 构建错误</strong></summary>

放行安装脚本后重装：

```bash
npm config set allow-scripts=@deepseek-ai/dsh-subprocess-local,koffi,node-pty,@google/genai,protobufjs --location=user
```

</details>

<details>
<summary><strong>数据库文件泄露是否有风险</strong></summary>

没有。敏感字段全部加密或散列，密码仅存 bcrypt 哈希，无 `.env` 密钥无法解密。

</details>

<details>
<summary><strong>能否更换 MCP_DB_ENC_KEY</strong></summary>

不能，启用后更换将导致历史数据无法解密。

</details>

<details>
<summary><strong>加载插件慢 / 访问慢</strong></summary>

网关对内容哈希命中的静态资源强制一年期 immutable 缓存，升级后首次访问完整下载一次，之后秒进。访问慢时网关每请求开销约 1-2ms，先检查 TLS 握手：

```bash
curl -so /dev/null -w "TLS:%{time_appconnect}s\n" https://地址/gateway/login
```

通常瓶颈在到服务器的链路延迟。

</details>

### 手动安装

> v2.6.10 的兼容层覆盖 DSH `0.1.2-alpha.1` 至 `alpha.5` 的源码运行时，并额外适配 `0.1.2-rc.1`；alpha.1 未发布 npm 包，npm/Docker 可安装基线包括 `alpha.2+` 与 rc.1，当前锁定并验收 rc.1。安装器会严格检查 Node.js `22.19+` 或 `24+`，并在安装完成后注册插件、探测 dsh 安装目录并应用兼容补丁。自动更新与设置页“重载补丁”会沿用同一补丁链路。

1. `git clone https://github.com/slywalker2006/dsh-passwords && cd dsh-passwords`
2. `npm install && npm run build`
3. `cp .env.example .env`，把 SETUP_KEY 改为 `openssl rand -hex 24` 生成的随机串
4. `node scripts/register-plugin.mjs` 注册插件
5. `node dist/cli.js patch` 应用补丁，找不到 dsh 目录时用 `MCP_DSH_ROOT` 指定

之后启动 dsh，网关自动拉起，按「首次配置」完成初始化。

## 安全与隐私

账号密码只存 bcrypt 哈希；用户名、IP 与审计记录加密落盘；证书签发失败拒绝启动。

- 连续失败锁定按轮次退避，1 到 60 分钟封顶；主用户不受多 IP 轮换的全局锁死影响
- 同一 IP 15 分钟内 30 次失败触发 IP 级节流 30 分钟，应对跨用户名密码喷洒
- 登出即服务端吊销 token；改密、改名后全部旧会话失效
- 第三方插件运维面端点仅主用户可用；上传与下载按权限门控，新子用户默认禁用下载
- 请求超时与并发连接上限抵御 slowloris；路径归一化拦截 `%2f`、双重编码等变体
- 首次配置成功后自动删除 `setup-key.txt` 并固化独立密钥变量

## 语言

界面中英双语，跟随 dsh 语言设置。登录页右上角可手动切换并持久化，CLI 跟随 `LANG` / `LC_ALL`。

## 版本兼容

当前版本 2.6.10。当前开发与部署基线为 DSH `0.1.2-rc.1`；兼容层保留 DSH `alpha.1` 至 `alpha.5` 的已知结构适配，并已针对 rc.1 的官方 npm 运行时完成本地验证。npm 包包含预构建 dist、TypeScript 源码与全部脚本；bundled Docker 镜像与 npm 包出自同一份源码，并内置 DSH `0.1.2-rc.1`。

## 参与贡献

- 提交问题前请阅读 [社区规范清单](docs/community-checklist.md)，并使用 [问题模板](.github/ISSUE_TEMPLATE/bug_report.md) 或 [功能模板](.github/ISSUE_TEMPLATE/feature_request.md)
- 代码贡献请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)，使用 [PR 模板](.github/PULL_REQUEST_TEMPLATE.md)，保持改动聚焦并附测试证据
- 提交前跑 `npm ci && npm run build && npm test`，CI 会在 Node 22/24 上自动执行

## 贡献者

<a href="https://github.com/slywalker2006/dsh-passwords/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=slywalker2006/dsh-passwords" />
</a>

<div align="center">

**觉得有用就点个 Star。**

[报告问题](https://github.com/slywalker2006/dsh-passwords/issues) · [查看 Releases](https://github.com/slywalker2006/dsh-passwords/releases) · [npm 包](https://www.npmjs.com/package/dsh-passwords) · [Awesome 收录](https://github.com/0xsline/awesome-deepseek-harness#security--governance)

</div>

## License

[GNU GPL v3.0 only](https://www.gnu.org/licenses/gpl-3.0.html)，完整文本见 [LICENSE](LICENSE)。

本项目是 dsh 的独立扩展，与 DeepSeek 无隶属关系。
