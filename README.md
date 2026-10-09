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
  <a href="https://github.com/deepseek-ai/deepseek-harness"><img src="https://img.shields.io/badge/DSH-0.2.1--alpha.2-4c6ef5?style=flat-square&labelColor=454a54" alt="DSH"></a>
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
  <strong>让多人远程共用 DeepSeek Harness，按账号管理工作区、会话和用量</strong><br>
  <em>账号登录 · 工作区与会话授权 · 用量配额 · 审计日志 · 中英双语</em>
</p>

<div align="center">

[适用场景](#适用场景) · [功能](#功能) · [快速开始](#快速开始) · [首次配置](#首次配置) · [卸载](#卸载) · [自动 HTTPS](#自动-https) · [部署拓扑](#部署拓扑) · [配置参考](#配置参考) · [常见问题](#常见问题) · [安全与隐私](#安全与隐私) · [参与贡献](#参与贡献)

</div>

---

## 适用场景

| 你想做什么 | dsh-passwords 提供什么 |
|---|---|
| 小团队共用服务器上的 DSH | 独立登录账号、子用户管理与用量配额 |
| 只把指定项目或对话分享给他人 | 工作区白名单与逐会话授权 |
| 集中管理远程访问 | 登录限流、审计日志，以及宿主机自动 HTTPS 或反代部署 |

核心使用流程：主用户创建子账号 → 分配工作区、会话和额度 → 子用户登录并使用获授权的资源。

## 功能

- **登录认证**：首次配置创建主用户；网页与受保护的 API 需要登录，会话 12 小时有效
- **HTTPS 部署**：宿主机直接部署支持自动申请与续期证书、HTTP 跳转 HTTPS（需公网域名可解析及 80/443 可达）；Docker 默认由外层反代提供 HTTPS
- **多租户**：一个主用户加任意多个子用户，账号管理全部在 dsh 设置页完成
- **权限与配额**：目录白名单（可读取目录 `allowedFolders`）、逐会话开关、每小时 token 上限、每日时长上限、沙盒三档、上传与下载开关、SSH 与终端开关、封禁
- **会话授权**：工作区权限不自动包含其中全部会话，主用户逐会话授予；归档状态在工作区列表与会话列表间保持一致
- **运维视图**：主用户可查看全部工作区与会话，下载非敏感普通文件
- **审计与安全**：登录限流与锁定、审计日志、SQLite 中用户名及审计敏感字段加密、密码 bcrypt 哈希、登出即吊销会话
- **设置页卡片**：远程设置补丁重载、软件更新、账号与权限管理、站内留言，全部中英双语

## 界面截图

| 账号管理 | 权限与配额 |
|:---:|:---:|
| <img src="https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/docs/screenshots/card-front.png" width="480"> | <img src="https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/docs/screenshots/card-back.png" width="480"> |

| dsh 主界面 · 登录后 | 聊天 / 留言 |
|:---:|:---:|
| <img src="https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/docs/screenshots/main-ui.png" width="480"> | <img src="https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/docs/screenshots/chat.png" width="480"> |

| 登录页 · 浅色 | 登录页 · 深色 | 登录页 · English |
|:---:|:---:|:---:|
| <img src="https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/docs/screenshots/white-login.png" width="360"> | <img src="https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/docs/screenshots/black-login.png" width="360"> | <img src="https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/docs/screenshots/white-login-en.png" width="360"> |

## 快速开始

### 前置条件

- **Docker**：需要 Docker Engine 或 Docker Desktop 和一个 DeepSeek API key；镜像内置 DSH，不需要先在宿主机安装 Node.js 或 dsh。
- **宿主机**：运行环境需要 Node.js 22.19+（22.x）或 24+、可正常运行的 dsh、git 与 pnpm；一键安装器会检查依赖并按需安装，手动注册插件需要 pnpm。
- **DSH 版本**：版本门禁接受 `>=0.2.1-alpha.1 <0.2.2-0`，当前开发依赖与 Docker 默认运行时锁定 `0.2.1-alpha.2`。通过版本门禁不等于范围内每个版本都已实测，详见[版本兼容](#版本兼容)。

当前发布版本为 `2.7.8`，Docker 镜像内置 DSH `0.2.1-alpha.2`；源码检出以 `package.json` 为准。

### 推荐：Docker 本地试用

先启动容器，再通过浏览器创建主用户。以下多行命令适用于 bash，请将两个密钥占位值替换为自己的值：

```bash
docker run -d \
  --name dsh-passwords \
  --restart unless-stopped \
  -e DEEPSEEK_API_KEY=sk-你的key \
  -e SETUP_KEY=自己设定的强随机串 \
  -p 127.0.0.1:3088:3088 \
  -v dsh-home:/data/dsh \
  -v dsh-passwords-state:/data/dsh-passwords \
  skywalker237234/dsh-passwords:2.7.8
```

Windows PowerShell 可使用同一条命令的一行形式：

```powershell
docker run -d --name dsh-passwords --restart unless-stopped -e "DEEPSEEK_API_KEY=sk-你的key" -e "SETUP_KEY=自己设定的强随机串" -p 127.0.0.1:3088:3088 -v dsh-home:/data/dsh -v dsh-passwords-state:/data/dsh-passwords skywalker237234/dsh-passwords:2.7.8
```

在**运行 Docker 的机器上**打开 `http://127.0.0.1:3088`，输入你设置的 `SETUP_KEY` 创建主用户，此后使用账号密码登录。这个地址只在 Docker 宿主机本机可访问；若容器运行在远程服务器上，请通过 SSH 端口转发访问，或配置 nginx / Caddy 的 HTTPS 反代。

省略 `-e SETUP_KEY` 时，容器会生成随机密钥；首次配置前用下面的命令读取，配置成功后该文件自动删除：

```bash
docker exec dsh-passwords cat /data/dsh-passwords/setup-key.txt
```

新数据卷首次初始化会把传入的 `SETUP_KEY` 写入卷内 `.env`；改变该环境变量不会重建已有账号，Docker 运行时仍按下方的环境变量优先级取值。容器默认监听 `0.0.0.0:3088`，上面的端口映射只向宿主机回环地址发布；公网 HTTPS 由外层反代提供。

`2.7.8` 镜像内置 DSH `0.2.1-alpha.2`，验收记录见 [v2.7.8 发布说明](https://github.com/slywalker2006/dsh-passwords/releases/tag/v2.7.8)。部署后确认 `/gateway/healthz`、`/gateway/readyz` 返回 `ok:true`，并实际登录验证子账号授权；健康检查不能代替权限验收。

<details>
<summary><strong>Docker 进阶配置与数据目录</strong></summary>

- 自定义端口、域名或第三方端点时，可复制 `docker/.env.example` 为 `docker/.env`，通过 `--env-file docker/.env` 传入。Compose 可使用 `docker compose --env-file docker/.env -f docker/docker-compose.yml up -d`。
- Docker 使用容器专用模板。根目录 `.env.example` 用于宿主安装，其端口、TLS 与数据库路径默认值不同，不能直接作为容器的 `--env-file`。
- 公网反代时建议设置 `MCP_GATEWAY_PUBLIC_HOST` 为实际访问的域名；外层反代需要保留外部 Host 并支持 WebSocket。
- `dsh-home` 保存 DSH profile；`dsh-passwords-state` 保存 `.env`、数据库与相关状态。两个卷应持久保留，清理方式见[卸载](#卸载)。
- 分容器部署时给 dsh 容器加 `MCP_DSH_PATCH_ALLOW_BIND_ALL=1`；DSH `0.2.1-alpha.2` 的 `dsh-web-app` 仍需要该补丁才能绑定 `0.0.0.0`。

</details>

### 宿主机安装

安装器会完成依赖安装、编译、生成或补齐缺失密钥、注册插件与应用补丁，并沿用已有配置。以下入口任选一个；不要另外执行目录网站可能提供的 `dsh plugin add`，本项目需要安装器或手动注册脚本精确注册。

**1. Linux / macOS 一键安装**

```bash
curl -fsSL https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/install.sh | sudo bash
```

下载式安装默认使用 `/opt/dsh-passwords`；非 root 运行时默认改用 `$HOME/dsh-passwords`（`/opt` 需要 root），两种情况都可用 `DSH_PASSWORDS_DIR` 指定可写目录。识别到已有安装时会就地重跑。

**2. 从 Git 仓库安装**

```bash
git clone https://github.com/slywalker2006/dsh-passwords && cd dsh-passwords
sudo bash install.sh
```

此入口使用当前源码目录，适合长期维护配置与数据。

**3. npm 全局安装或升级**

首次安装：

```bash
npm install -g dsh-passwords@2.7.8
sudo dsh-passwords install
```

Windows 省略 `sudo`。从更早版本升级时，更新全局包后重跑 `dsh-passwords install` 注册插件并应用补丁；已有 `.env` 与数据库不会被覆盖。

npm 全局目录会随包升级替换。长期部署应将 `DSH_PASSWORDS_ENV_FILE` 指向稳定位置，或使用 Git 安装方式。`nvm` / Homebrew 的 Node 可能不在 `sudo` 的 PATH 中。

**4. Windows 安装器**

下载仓库里的 `install.bat` 双击运行。下载式安装默认使用 `%USERPROFILE%\dsh-passwords`。

宿主机首次安装或补齐缺失密钥时会打印 `SETUP_KEY`，并保存到安装目录的 `setup-key.txt`；重复安装沿用已有密钥，不会再次打印。随后按下面的首次配置流程创建账号。

### 首次配置

1. 宿主机用户启动 dsh：`dsh web`；Docker 内的 dsh 随容器自动启动。
2. 按部署方式打开网关地址，首次访问进入配置页：

   | 部署方式 | 浏览器访问地址 |
   |---|---|
   | 宿主机自动 HTTPS | 启动日志打印的公网 HTTPS 地址，默认 `https://<公网IP>.sslip.io`，或你配置的域名 |
   | Docker 本机试用 | Docker 宿主机上的 `http://127.0.0.1:3088` |
   | nginx / Caddy 等反代 | 外层反代配置的 HTTPS 域名 |
   | 显式 HTTP 模式 | 启动时选择的监听地址与端口；脚本默认 `http://127.0.0.1:8080` |

3. 输入 `SETUP_KEY` 创建主用户，此后使用账号密码登录。
4. 在设置页创建子账号、授予工作区与会话权限，并用子账号验证实际访问范围。

首次配置成功后，标准流程会删除 `setup-key.txt` 并轮换 `.env` 中的 `SETUP_KEY`。会话、内部接口与数据库加密密钥按现有配置保留；自定义部署应确认 `.env` 可写，并将 `.env` 与数据库一并备份。

## 卸载

宿主机安装可在 dsh-passwords 安装目录执行：

```bash
node dist/cli.js uninstall
# 全局 npm 安装也可直接执行：
dsh-passwords uninstall
```

该命令只从 DSH web profile 移除 `dsh-passwords` 的 link 与 bundle，并回滚本插件管理的 dsh 补丁；其他插件和 bundle 会保留。完成后按提示重启 `dsh-web`。

卸载不会删除安装目录、`.env`、数据库、TLS/ACME 证书或其他插件。profile 依赖重建或补丁回滚失败时会恢复原 profile，避免留下半卸载状态。Docker 部署请按所用 Compose 或容器编排停止并移除容器；不要删除命名卷，除非也要永久清除数据。

Docker 内的“保命技能”不会自删容器。确需永久清除所有容器数据时，Compose 可执行 `docker compose down -v`；上面的 `docker run` 部署可先执行 `docker rm -f dsh-passwords`，再执行 `docker volume rm dsh-home dsh-passwords-state`。这些操作会删除数据卷，执行前请备份。

## 自动 HTTPS

此节适用于宿主机直接部署；Docker 默认使用 HTTP，由外层反代提供 HTTPS。

默认探测公网 IP，使用 `<IP>.sslip.io` 域名向 Let's Encrypt 申请证书；有自己的域名时在 `.env` 设置 `MCP_GATEWAY_DOMAIN`。需要 DNS 正确解析、外部可访问 80/443，且这些端口未被其他服务占用。程序读取证书的实际到期时间，每天检查一次，在剩余有效期不超过 30 天时尝试续期并热加载。签发失败拒绝启动；续期失败时继续使用仍有效的旧证书并后台重试。

| 错误码 | 含义 | 处理 |
|---|---|---|
| 30 | 证书签发失败 | 检查 80/443 放行与占用情况，确认能连通 Let's Encrypt |
| 31 | 拿不到公网 IP 或域名 | 设置 `MCP_GATEWAY_DOMAIN`，或使用 HTTP 模式 |
| 32 | 端口被占用 | 更换 `MCP_GATEWAY_PORT` 或释放端口 |

本项目的自动签发流程申请的是域名证书，默认域名为 `<IP>.sslip.io`。请访问启动日志中的 HTTPS 地址；直接访问裸 IP 的 HTTPS 地址可能出现主机名不匹配。默认 80 端口入口会跳转到证书对应的域名。

## 部署拓扑

| 场景 | 做法 |
|---|---|
| 公网宿主机，DNS 与 80/443 可达 | 使用自动 HTTPS，访问日志中打印的域名 |
| 已有域名证书 | `.env` 填 `MCP_GATEWAY_TLS_CERT` / `MCP_GATEWAY_TLS_KEY`，无需 80 端口 |
| 已有 nginx / Caddy 反代 | 宿主网关设 `MCP_GATEWAY_AUTO_TLS=0`、`MCP_GATEWAY_HOST=127.0.0.1`、`MCP_GATEWAY_PORT=8080`；反代提供 HTTPS、保留外部 Host 并转发 WebSocket |
| Docker 公网部署 | 容器内默认 `0.0.0.0:3088`，宿主映射到 `127.0.0.1:3088`，由 nginx / Caddy 提供 HTTPS |
| Cloudflare Tunnel | Tunnel 指向本机网关 HTTP 端口，由公网入口提供 HTTPS；若使用 Cloudflare 普通代理，另行配置源站 TLS |
| 本地或受信内网，无自动签发条件 | 显式使用 HTTP 模式，按需要设置监听地址 |

自动签发使用 http-01 验证，签发与续期期间 80 端口需要从外部可达。

## HTTP 模式

宿主机默认启用自动 HTTPS；Docker 默认在容器内使用 HTTP，由外层反代负责公网 HTTPS。宿主机本地或受信内网需要 HTTP 时，可显式启动：

```bash
node scripts/start-http.mjs [端口] [监听地址]    # 默认 127.0.0.1:8080，需确认提示
```

或在 `.env` 写入 `MCP_GATEWAY_AUTO_TLS=0`、`MCP_GATEWAY_PORT=8080` 与 `MCP_GATEWAY_HOST=127.0.0.1`，由 dsh 启动时拉起网关。需要内网其他机器访问时，再显式选择相应监听地址；HTTP 传输不加密，公网入口应提供 HTTPS。

HTTP 模式不依赖公网 IP、DNS、ACME 或外部 CDN；首次安装仍需 npm/GitHub 可访问，或提前准备项目包、依赖缓存与本地 DSH。模型对话仍需配置模型提供方（例如 `DEEPSEEK_API_KEY`）；没有可用模型服务时，登录、权限、文件与管理功能可运行，但不会产生模型回复。

## 设置页卡片

登录后打开设置，能看到「dsh-passwords · 密码门」卡片。

| 功能 | 使用者 | 说明 |
|---|---|---|
| 重载补丁 | 仅主用户 | dsh 升级后设置页异常时一键重打补丁并重启网页服务 |
| 软件更新 | 状态所有人可见，操作仅主用户 | 自动检查、限速下载、空闲后安装重启，详见下节 |
| 修改密码 / 用户名 | 本人；主用户可操作任何人 | 改密后旧会话全部失效 |
| 子用户管理 | 仅主用户 | 创建、删除子用户 |
| 子用户权限 | 仅主用户 | 目录白名单（可读取目录，用受限目录浏览器分配）、逐会话授权、token 与时长上限、沙盒、上传下载开关、SSH 与终端开关（默认关闭，主用户显式授权，撤销即时生效）、WebSocket 路径授权、封禁 |
| 聊天 / 留言 | 所有登录用户 | 支持标签；子用户消息默认私信主用户，仅主用户可广播 |
| 退出登录 | 所有登录用户 | 登出当前账号 |

子用户目录权限：目录范围唯一由「可读取目录」（`allowedFolders`）决定，主用户通过受限目录浏览器为子用户分配。该浏览器只在配置的浏览起点内逐级浏览，起点来自 `MCP_GATEWAY_DIRECTORY_PICKER_ROOTS`，未配置时默认用户家目录，全盘根永不作为起点，绝不从整机根枚举。白名单内的目录即可读；开启「新建工作区权限」后，同一批可读目录也是创建范围，子用户可在其中新建文件夹并将本人新建文件夹登记为工作区；白名单外不可读，也无法创建。空数组（「所有目录」）沿用既有「不限目录」语义；需要禁止所有目录时使用 `['__deny__']` 哨兵。关闭「新建工作区权限」只禁止创建，保留可读范围。路径校验同时检查词法路径与真实路径，拒绝符号链接逃逸和其他子用户的工作区子树。

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
| `SETUP_KEY` | 安装脚本生成（Docker 可用 `-e SETUP_KEY` 指定） | 首次配置密钥，配置成功后自动轮换 |
| `MCP_JWT_SECRET` | 从 SETUP_KEY 派生 | 会话签名密钥，生产环境建议 `openssl rand -hex 32` 独立设置 |
| `MCP_INTERNAL_SECRET` | 从 SETUP_KEY 派生 | 网关内部管理接口密钥（dsh 插件通知网关用），与 JWT 域分离派生；显式设置后不要随意更换 |
| `MCP_DB_PATH` | 宿主 `./data/platform.db`；Docker `/data/dsh-passwords/platform.db` | SQLite 数据库路径；相对路径锚定 `.env` 所在目录（`DSH_PASSWORDS_ENV_FILE` 指向的目录），而非进程工作目录 |
| `MCP_DB_ENC_KEY` | 安装器生成；手动留空时使用 SETUP_KEY 作为主密钥派生 | 用户名及审计敏感字段的加密密钥；没有自动密钥迁移，不能直接替换。数据库与密钥需配套备份，并分别保护 |
| `MCP_GATEWAY_HOST` / `MCP_GATEWAY_PORT` | `0.0.0.0` / 宿主自动 HTTPS `443`、HTTP 模式 `8080`、Docker `3088` | 网关监听地址与端口；Docker 默认 `0.0.0.0:3088`，示例通过宿主端口映射限制为 `127.0.0.1:3088`；宿主 HTTP 反代需显式设回环地址 |
| `MCP_GATEWAY_UPSTREAM` | `http://127.0.0.1:3080` | dsh 网页地址，插件自动指向 |
| `MCP_GATEWAY_UPSTREAM_TLS_VERIFY` | 开 | 上游 dsh 为 HTTPS/WSS 时校验其证书；`0` 关闭（仅调试，勿用于生产） |
| `MCP_GATEWAY_SSH_ENDPOINTS` | 空 | 登记 DSH 运行时未暴露的传统 HTTP/WS 端点；格式与权限见[端点登记说明](docs/endpoint-registration.md)。 |
| `MCP_GATEWAY_REDIRECT_PORT` | 自动 HTTPS 时 `80`；关闭自动 HTTPS 时不监听 | ACME 验证与 301 跳转端口；显式 `0` 关闭 |
| `MCP_GATEWAY_DOMAIN` | 空 | 自定义域名，留空用 `<公网IP>.sslip.io` |
| `MCP_GATEWAY_AUTO_TLS` | 宿主机开；Docker 镜像默认 `0` | `0` 关闭自动 HTTPS（容器内默认 HTTP，由外层反代提供 HTTPS） |
| `MCP_GATEWAY_TLS_CERT` / `MCP_GATEWAY_TLS_KEY` | 空 | 自有证书，优先于自动 HTTPS |
| `MCP_GATEWAY_PUBLIC_HOST` | 空 | 固定跳转地址，防 Host 伪造 |
| `MCP_GATEWAY_ACME_EMAIL` / `MCP_GATEWAY_ACME_STAGING` | 空 / 关 | 证书提醒邮箱 / LE 测试环境 |
| 高级调优 | 内置默认值已针对普通安装验证；运维覆盖项见 [`docs/advanced-tuning.md`](docs/advanced-tuning.md)，普通用户无需填写 |
| `MCP_DSH_ROOT` | 自动探测 | dsh 安装目录 |
| `MCP_DSH_SETTINGS_FILE` | 自动探测 | dsh `settings.yaml` 路径，网关与 dsh 不在同一台机器时显式指定；留空按 `DSH_HOME/settings.yaml` 等候选位置探测 |
| `MCP_DSH_RESTART_SERVICE` | Linux `dsh-web`；Windows 空 | 重载补丁后的 systemd 服务名；Windows 自动更新安装后需手动重启 DeepSeek Harness |
| `MCP_DSH_AUTO_UPDATE` | 开 | 部署级自动更新总开关 |
| `MCP_DSH_UPDATE_MAX_BPS` | 1MiB/s | 自动下载限速，只能调低 |
| `MCP_DSH_DOCKER_SELF_UPDATE` / `_COMPOSE_DIR` / `_COMPOSE_FILE` / `_IMAGE` / `_SOCKET` | 关 / 空 | Docker 应用内更新的启用开关与 Compose 配置 |
| `MCP_DSH_PATCH_ALLOW_BIND_ALL` | 关 | 分容器拓扑允许 dsh web 绑定 0.0.0.0（`0.2.1-alpha.2` 的 `dsh-web-app` 仍未原生放行，仍需该子补丁） |
| `DSH_PASSWORDS_ENV_FILE` | 空 | 手动指定 `.env` 路径 |

环境变量与 `.env` 的优先级按安装方式不同：Docker 内以容器环境变量（`--env-file docker/.env`）优先于卷内 `.env`；宿主安装相反，部署 `.env` 中的托管键优先于进程中继承的同名环境变量。Docker 的 `SETUP_KEY` 同样遵循运行时环境变量优先级；首次配置后使用账号密码登录，改变该变量不会重建账号。

高级 Remote mux、网关超时和 inventory 覆盖项的默认值与兼容解析见 [`docs/advanced-tuning.md`](docs/advanced-tuning.md)。普通用户无需配置这些变量；已有部署中的覆盖值仍会读取，不会被自动改写。

## 常用命令

```bash
node dist/cli.js audit --limit 20        # 最近 20 条审计日志
node dist/cli.js patch status            # 远程设置补丁状态
node dist/cli.js patch                   # 重载补丁并重启 dsh-web
node dist/cli.js serve-gateway --port 9000   # 只更改端口，TLS 模式仍由配置决定
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

Linux 下 1024 以下端口需要 root，改用 `MCP_GATEWAY_PORT` 高位端口并自行做端口转发。非 root 首次安装还须显式关闭自动 HTTPS（`MCP_GATEWAY_AUTO_TLS=0`）或提供自管证书，否则安装器会要求 root；下载式安装的默认目录会从 `/opt` 改到 `$HOME/dsh-passwords`，也可用 `DSH_PASSWORDS_DIR` 指向其它可写目录。

</details>

<details>
<summary><strong>dsh 报 duplicate loader entry id</strong></summary>

`dsh plugin add` 会把所有声明 bundle 的依赖加入 bundles 层导致冲突。卸载后改用 `node scripts/register-plugin.mjs` 精确注册。

</details>


<details>
<summary><strong>数据库文件泄露是否有风险</strong></summary>

仍有风险。密码保存为 bcrypt 哈希，用户名及审计的 IP、User-Agent、详情等字段加密；留言正文、部分权限配置和工作区路径等内容不属于这项字段加密保护。密码哈希也可能被离线猜测。请分别保护数据库和 `.env` 密钥，并在备份时保留相匹配的版本。

</details>

<details>
<summary><strong>能否更换 MCP_DB_ENC_KEY</strong></summary>

当前没有自动密钥迁移功能，不能直接替换生效的密钥，否则历史加密字段将无法解密。手动配置且尚未完成首次配置时，留空的加密主密钥来自 `SETUP_KEY`，此时也不要直接更换 `SETUP_KEY`。

</details>

<details>
<summary><strong>加载插件慢 / 访问慢</strong></summary>

网关为内容哈希匹配的静态资源设置一年期 immutable 缓存，减少重复下载；实际速度取决于资源大小、服务器负载与网络。排查时可先测量 TLS 握手时间：

```bash
curl -so /dev/null -w "TLS:%{time_appconnect}s\n" https://地址/gateway/login
```

再结合浏览器网络面板中的资源耗时、服务器日志与 DSH 上游响应时间定位瓶颈。

</details>

### 手动安装

> 手动安装适用于已准备好 Node.js、兼容 DSH、git 与 pnpm 的用户。源码插件版本以 `package.json` 为准；DSH 版本要求见[版本兼容](#版本兼容)。使用下面的精确注册脚本，不额外执行 `dsh plugin add`。

1. `git clone https://github.com/slywalker2006/dsh-passwords && cd dsh-passwords`
2. `npm install && npm run build`
3. `cp .env.example .env`，把 SETUP_KEY 改为 `openssl rand -hex 24` 生成的随机串
4. `node scripts/register-plugin.mjs` 注册插件
5. `node dist/cli.js patch` 应用补丁，找不到 dsh 目录时用 `MCP_DSH_ROOT` 指定

之后启动 dsh，网关自动拉起，按「首次配置」完成初始化。

## 安全与隐私

账号密码只存 bcrypt 哈希；用户名及审计的 IP、User-Agent、详情等字段加密落盘。此处是字段加密，不是整个 SQLite 文件加密；工作区、DSH 会话文件与其他磁盘数据也不因此自动加密。宿主机启用自动 HTTPS 时，首次证书签发失败会拒绝启动。

- 连续失败锁定按轮次退避，1 到 60 分钟封顶；主用户不受多 IP 轮换的全局锁死影响
- 同一 IP 15 分钟内 30 次失败触发 IP 级节流 30 分钟，应对跨用户名密码喷洒
- 登出即服务端吊销 token；改密、改名后全部旧会话失效
- 第三方插件运维面端点仅主用户可用；SSH 与终端能力默认关闭，需主用户显式授权（撤销即时生效）；上传与下载按权限门控，新子用户默认禁用下载
- 请求超时与并发连接上限抵御 slowloris；路径归一化拦截 `%2f`、双重编码等变体
- 首次配置成功后自动删除 `setup-key.txt` 并固化独立密钥变量

## 语言

界面中英双语，跟随 dsh 语言设置。登录页右上角可手动切换并持久化，CLI 跟随 `LANG` / `LC_ALL`。

## 版本兼容

| 项目 | 版本与验证范围 |
|---|---|
| 已发布 Docker 镜像 | `2.7.8` + DSH `0.2.1-alpha.2` |
| npm / 源码安装 | npm 使用指定包版本，源码安装使用检出版本；升级步骤见[宿主机安装](#宿主机安装) |
| 从 2.7.7 升级 | 更新全局包或源码检出后重跑安装器并重启 dsh；`.env`、数据库与 DSH profile 均保留 |
| DSH 版本门禁 | `>=0.2.1-alpha.1 <0.2.2-0`：接受 alpha.1 起的 `0.2.1` 预发布与稳定版，拒绝 `0.1.x`、`0.2.0`、`0.2.1-alpha.0` 与 `0.2.2+` |
| 开发与 Docker 默认 DSH 基线 | 锁定 `0.2.1-alpha.2`；范围内其他版本通过门禁不等于已完成部署验收，升级前需验证登录、授权、文件与插件流程 |

## 参与贡献

- 提交问题前请阅读 [社区规范清单](docs/community-checklist.md)，并使用 [问题模板](https://github.com/slywalker2006/dsh-passwords/blob/main/.github/ISSUE_TEMPLATE/bug_report.md) 或 [功能模板](https://github.com/slywalker2006/dsh-passwords/blob/main/.github/ISSUE_TEMPLATE/feature_request.md)
- 代码贡献请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)，使用 [PR 模板](https://github.com/slywalker2006/dsh-passwords/blob/main/.github/PULL_REQUEST_TEMPLATE.md)，保持改动聚焦并附测试证据
- 提交前跑 `npm ci --include=optional && npm run build && node --import tsx --test "test/**/*.test.ts"`（需先构建），CI 会在 Node 22/24 上自动执行

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
