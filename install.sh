#!/usr/bin/env bash
# dsh-passwords 一键安装（Linux/macOS 引导壳；实际安装逻辑在 scripts/install.mjs）
#
# 用法（二选一）:
#   1) curl 直接装:  curl -fsSL https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/install.sh | bash
#   2) 先 clone 再装: git clone https://github.com/slywalker2006/dsh-passwords && cd dsh-passwords && bash install.sh
# Windows 用户请运行 install.bat。
#
# 做什么：检查 Node.js 22.19+ 或 24+ / git / dsh，缺了自动装（apt/dnf/brew）；
# 然后下载项目，交给 scripts/install.mjs 完成安装（pnpm 缺了也会自动装）。
set -euo pipefail

CYAN='\033[0;36m'
RED='\033[0;31m'
GREEN='\033[0;32m'
RESET='\033[0m'

say() { printf "${CYAN}[dsh-passwords]${RESET} %s\n" "$*"; }
ok()  { printf "${GREEN}[dsh-passwords]${RESET} %s\n" "$*"; }
err() { printf "${RED}[dsh-passwords]${RESET} %s\n" "$*" >&2; }

# ── 0. 已在 clone 的项目目录里：直接执行安装 ──
# 从任意 cwd 运行已 clone 的 install.sh 都能定位到自身所在目录。
# curl | bash 时 BASH_SOURCE 是管道而不是落盘文件，自动走下面的 clone 分支。
SCRIPT_SOURCE="${BASH_SOURCE[0]:-$0}"
if [ -f "$SCRIPT_SOURCE" ]; then
  SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$SCRIPT_SOURCE")" && pwd)"
  if [ -f "$SCRIPT_DIR/scripts/install.mjs" ]; then
    exec node "$SCRIPT_DIR/scripts/install.mjs"
  fi
fi

# ── 1. Node.js（缺了自动安装；版本不够直接报错） ──
check_node_version() {
  NODE_VERSION="$(node -v 2>/dev/null || true)"
  if ! printf '%s\n' "$NODE_VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+'; then
    err "无法读取 Node.js 版本（当前：${NODE_VERSION:-unknown}），请安装 Node.js 22.19+ 或 24+ 后重跑。"
    exit 1
  fi
  NODE_MAJOR="$(printf '%s\n' "$NODE_VERSION" | sed -E 's/^v([0-9]+)\..*/\1/')"
  NODE_MINOR="$(printf '%s\n' "$NODE_VERSION" | sed -E 's/^v[0-9]+\.([0-9]+)\..*/\1/')"
  if [ "$NODE_MAJOR" -lt 22 ] || [ "$NODE_MAJOR" -eq 23 ] || { [ "$NODE_MAJOR" -eq 22 ] && [ "$NODE_MINOR" -lt 19 ]; }; then
    err "Node.js 版本不受支持（当前 $NODE_VERSION），需要 22.19+ 或 24+。请升级后重跑本脚本。"
    exit 1
  fi
  ok "Node.js $NODE_VERSION ✓"
}

if command -v node >/dev/null 2>&1; then
  check_node_version
else
  say "未找到 Node.js，正在自动安装…"
  if command -v apt-get >/dev/null 2>&1; then
    # Debian/Ubuntu：用 NodeSource 装 22.x
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - || {
      err "NodeSource 安装失败，请手动安装 Node.js 22.19+ 或 24+（https://nodejs.org/）。"; exit 1; }
    apt-get install -y nodejs || {
      err "apt 安装 nodejs 失败（可能需要 sudo 试试：sudo apt-get install -y nodejs）。"; exit 1; }
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y nodejs || {
      err "dnf 安装 nodejs 失败，请手动安装 Node.js 22.19+ 或 24+（https://nodejs.org/）。"; exit 1; }
  elif command -v brew >/dev/null 2>&1; then
    brew install node@22 || {
      err "brew 安装 node 失败，请手动安装 Node.js 22.19+ 或 24+（https://nodejs.org/）。"; exit 1; }
  else
    err "没有可用的包管理器，请手动安装 Node.js 22.19+ 或 24+（https://nodejs.org/）后重跑。"
    exit 1
  fi
  if ! command -v node >/dev/null 2>&1; then
    err "Node.js 装完仍不可用，可能需要新开一个终端再重跑本脚本。"
    exit 1
  fi
  check_node_version
fi

# ── 2. git（缺了自动安装） ──
if command -v git >/dev/null 2>&1; then
  ok "git $(git --version | sed 's/git version //') ✓"
else
  say "未找到 git，正在自动安装…"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y git || {
      err "apt 安装 git 失败（可能需要 sudo 试试：sudo apt-get install -y git）。"; exit 1; }
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y git || {
      err "dnf 安装 git 失败，请手动安装后重跑。"; exit 1; }
  elif command -v brew >/dev/null 2>&1; then
    brew install git || {
      err "brew 安装 git 失败，请手动安装后重跑。"; exit 1; }
  else
    err "没有可用的包管理器，请手动安装 git 后重跑。"
    exit 1
  fi
  if ! command -v git >/dev/null 2>&1; then
    err "git 装完仍不可用，可能需要新开一个终端再重跑本脚本。"
    exit 1
  fi
  ok "git ✓"
fi

# ── 3. dsh（DeepSeek Harness，缺了自动安装） ──
if command -v dsh >/dev/null 2>&1; then
  ok "dsh ✓"
else
  say "未找到 dsh（DeepSeek Harness），正在自动安装…"
  # dsh 依赖原生构建，npm 新版会拦截脚本，先放行再装
  npm config set allow-scripts=@deepseek-ai/dsh-subprocess-local,koffi,node-pty,@google/genai,protobufjs --location=user || true
  npm install -g @deepseek-ai/dsh@0.1.2-rc.1 || {
    err "dsh 自动安装失败，请手动执行：npm install -g @deepseek-ai/dsh@0.1.2-rc.1"
    err "然后用 DEEPSEEK_API_KEY=sk-你的key dsh web 先跑一次确认能用，再重跑本脚本。"
    exit 1; }
  ok "dsh ✓"
fi

# ── 4. 安装目录（DSH_PASSWORDS_DIR 可自定义） ──
if [ "$(id -u)" = "0" ]; then
  DEST="${DSH_PASSWORDS_DIR:-/opt/dsh-passwords}"
else
  DEST="${DSH_PASSWORDS_DIR:-$HOME/dsh-passwords}"
fi
if [ -d "$DEST" ]; then
  err "目标目录已存在：$DEST"
  err "重装请先手动删除该目录（注意备份里面的 .env 和 data/）。"
  exit 1
fi

# ── 5. 下载项目 + 执行安装 ──
say "下载项目到 $DEST …"
git clone --depth 1 https://github.com/slywalker2006/dsh-passwords.git "$DEST" || {
  err "项目下载失败，请检查网络后重跑。"; exit 1; }
cd "$DEST"
say "开始安装：装依赖 → 编译 → 生成 SETUP_KEY → 注册插件 → 应用补丁…"
node scripts/install.mjs

say ""
ok  "安装完成！"
say "首次配置密钥（SETUP_KEY）见上方输出；也保存在："
say "  $DEST/setup-key.txt（首次配置成功后自动删除）"
say "接下来：启动 dsh（dsh web）→ 浏览器打开 https://<服务器IP>.sslip.io"
say "         → 输入 SETUP_KEY 创建主用户，之后所有人访问都先过登录页。"