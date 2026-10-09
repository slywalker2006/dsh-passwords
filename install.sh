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

# ── 0. 已 clone 源码定位 ──
# clone 安装与 curl 安装共用下面的 Node/git/dsh 预检，避免同一入口存在两套行为。
SCRIPT_SOURCE="${BASH_SOURCE[0]:-$0}"
SOURCE_DIR=""
if [ -f "$SCRIPT_SOURCE" ]; then
  SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$SCRIPT_SOURCE")" && pwd)"
  if [ -f "$SCRIPT_DIR/scripts/install.mjs" ]; then
    SOURCE_DIR="$SCRIPT_DIR"
  fi
fi

# ── 1. 首次安装权限预检（必须先于任何工具安装） ──
# 非 root 仅能重跑已有 .env 的显式 HTTP/反代部署；首次自动 HTTPS 必须监听 80/443。
# 因此 root 要求只在确认是首次安装（目标 .env 尚不存在）时生效，已安装的普通用户可直接重跑。
# 本检查前置于 Node/git/dsh 安装，避免非 root 首次安装先装完依赖才失败。
#
# 与 scripts/install.mjs / src/config.ts 的 autoTls 判定一致：只有运行时「不会绑定特权端口」的
# 部署才允许非 root 首次安装——同时提供用户自管证书（MCP_GATEWAY_TLS_CERT + MCP_GATEWAY_TLS_KEY），
# 或 MCP_GATEWAY_AUTO_TLS 在运行时判定为关闭。关键对齐点：只有 1/true/yes/auto 视为显式开启；
# 空值（未设置）= 自动判断（未自备证书时启用，需要 root）；其余显式值——包括无法识别的值——
# 运行时一律按关闭处理（src/config.ts 的 autoTlsValueIsKnown 为假 ⇒ autoTls=false），故同样免 root。
# 单独设置 DSH_PASSWORDS_RUNTIME=docker 不构成授权（仍需 root）。
nonprivileged_tls_mode() {
  local _cert _key _auto_tls
  # 与 scripts/install.mjs / src/config.ts 一致：证书值先 trim，仅含空白不算自管证书。
  _cert="$(printf '%s' "${MCP_GATEWAY_TLS_CERT:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  _key="$(printf '%s' "${MCP_GATEWAY_TLS_KEY:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  if [ -n "$_cert" ] && [ -n "$_key" ]; then
    return 0
  fi
  _auto_tls="$(printf '%s' "${MCP_GATEWAY_AUTO_TLS:-}" | tr '[:upper:]' '[:lower:]' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  # 空值=自动判断，运行时启用自动 HTTPS，仍需 root。
  if [ -z "$_auto_tls" ]; then
    return 1
  fi
  case "$_auto_tls" in
    # 显式开启=特权端口，需要 root。
    1|true|yes|auto) return 1 ;;
  esac
  # 其余显式值（0/false/no 与无法识别的值）运行时均关闭自动 HTTPS，无需 root。
  return 0
}

require_root() {
  if [ "$(id -u)" = "0" ]; then return 0; fi
  if nonprivileged_tls_mode; then return 0; fi
  err "首次安装需要 root 权限（自动 HTTPS 会监听 80/443）；请使用 sudo 重跑：$1"
  err "非特权部署请显式关闭自动 HTTPS（MCP_GATEWAY_AUTO_TLS=0）或配置 MCP_GATEWAY_TLS_CERT/KEY，"
  err "并按 README 设置高位端口与监听地址后再重跑。"
  exit 1
}

# .env 位置与 scripts/install.mjs 同口径：DSH_PASSWORDS_ENV_FILE 优先，否则包根。
env_file_for() {
  if [ -n "${DSH_PASSWORDS_ENV_FILE:-}" ]; then
    printf '%s' "$DSH_PASSWORDS_ENV_FILE"
  else
    printf '%s/.env' "$1"
  fi
}

# 首次安装 root 门禁：目标 .env（DSH_PASSWORDS_ENV_FILE 优先，否则 <目标目录>/.env）不存在才算首次安装。
# $1 = 目标目录，$2 = 需要用 sudo 重跑的提示命令。三个入口（已 clone / 已下载 / 尚未下载）
# 共用同一判定，与 scripts/install.mjs 的 isFirstInstall 同口径：已预置外部 .env 的部署
# （例如 DSH_PASSWORDS_ENV_FILE 指向持久化路径）在任何入口下都不会被误判为首次安装。
gate_first_install_root() {
  if [ ! -f "$(env_file_for "$1")" ]; then
    require_root "$2"
  fi
}

# ── 安装目标目录（与后续下载步骤同口径） ──
# 显式 DSH_PASSWORDS_DIR 始终优先。未指定时按当前用户选择默认目录：
#   root → /opt/dsh-passwords（历史默认，与 README 一致）；
#   非 root → $HOME/dsh-passwords。非 root 无法在 /opt 下创建目录，若沿用 /opt 默认，
#   非特权首次安装（MCP_GATEWAY_AUTO_TLS=0 或自管证书，已通过 root gate）会在 git clone
#   阶段因权限失败，并被后面的通用报错误报成网络问题（P1）。改写到用户可写目录，也与
#   Windows install.bat 的 %USERPROFILE%\dsh-passwords 默认一致。
# 本函数只决定下载/执行位置，不参与 root gate 判定——是否允许非 root 首次安装仍由
# require_root 决定，安全语义不变。
default_dest() {
  local uid="$1"
  if [ -n "${DSH_PASSWORDS_DIR:-}" ]; then
    printf '%s' "$DSH_PASSWORDS_DIR"
  elif [ "$uid" = "0" ]; then
    printf '%s' '/opt/dsh-passwords'
  elif [ -n "${HOME:-}" ]; then
    printf '%s/dsh-passwords' "$HOME"
  else
    # 非 root 且无 HOME：无法给出安全可写默认，交由调用方显式拒绝。
    printf '%s' ''
  fi
}

# 目标目录是否可写：已存在则检查目录本身，不存在则向上取最近的已存在祖先目录。
# 用于在 git clone 之前把权限问题与网络问题区分开，避免把权限失败误报成下载失败。
dest_writable() {
  local probe="$1" parent
  while [ ! -e "$probe" ]; do
    parent="$(dirname -- "$probe")"
    if [ "$parent" = "$probe" ]; then return 1; fi
    probe="$parent"
  done
  [ -d "$probe" ] && [ -w "$probe" ]
}

CURRENT_UID="$(id -u)"
DEST="$(default_dest "$CURRENT_UID")"
if [ -z "$DEST" ]; then
  err "无法确定安装目录：当前非 root 且未设置 HOME 或 DSH_PASSWORDS_DIR。"
  err "请显式指定可写目录后重跑：DSH_PASSWORDS_DIR=\"/path/to/dsh-passwords\" bash install.sh"
  exit 1
fi

CURL_SUDO_HINT="curl -fsSL https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/install.sh | sudo bash"
if [ -n "$SOURCE_DIR" ]; then
  gate_first_install_root "$SOURCE_DIR" "sudo bash install.sh"
elif [ -d "$DEST" ]; then
  # 已有目录：只有本项目安装且缺目标 .env 才算首次安装；非本项目目录留给后面报错。
  if [ -f "$DEST/package.json" ] && grep -q '"name": "dsh-passwords"' "$DEST/package.json"; then
    gate_first_install_root "$DEST" "$CURL_SUDO_HINT"
  fi
else
  # 目录尚未下载：首次安装判定同样以目标 .env 为准（含外部 DSH_PASSWORDS_ENV_FILE），
  # 不再无条件要求 root（与 scripts/install.mjs 的 isFirstInstall 对齐）。
  gate_first_install_root "$DEST" "$CURL_SUDO_HINT"
fi

# ── 2. Node.js（缺了自动安装；版本不够直接报错） ──
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

# ── 3. git（缺了自动安装） ──
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

# ── 4. dsh（DeepSeek Harness，缺了自动安装） ──
if command -v dsh >/dev/null 2>&1; then
  ok "dsh ✓"
else
  say "未找到 dsh（DeepSeek Harness），正在自动安装…"
  # dsh 依赖原生构建，npm 新版会拦截脚本，先放行再装
  npm config set allow-scripts=@deepseek-ai/dsh-subprocess-local,koffi,node-pty,@google/genai,protobufjs --location=user || true
  npm install -g @deepseek-ai/dsh@0.2.1-alpha.2 || {
    err "dsh 自动安装失败，请手动执行：npm install -g @deepseek-ai/dsh@0.2.1-alpha.2"
    err "然后用 DEEPSEEK_API_KEY=sk-你的key dsh web 先跑一次确认能用，再重跑本脚本。"
    exit 1; }
  ok "dsh ✓"
fi

# ── 5. 执行安装（首次安装的 root 预检已在第 1 节完成） ──
if [ -n "$SOURCE_DIR" ]; then
  exec node "$SOURCE_DIR/scripts/install.mjs"
fi

if [ -d "$DEST" ]; then
  if [ -f "$DEST/package.json" ] && grep -q '"name": "dsh-passwords"' "$DEST/package.json"; then
    # 已有安装：有 .env 属幂等重跑，普通用户可直接执行。
    say "检测到已有 dsh-passwords 安装，就地执行幂等安装…"
    exec node "$DEST/scripts/install.mjs"
  fi
  err "目标目录已存在且不是 dsh-passwords 安装：$DEST"
  exit 1
fi

if [ -z "${DSH_PASSWORDS_DIR:-}" ] && [ "$CURRENT_UID" != "0" ]; then
  say "非 root 安装默认使用用户目录：$DEST（可用 DSH_PASSWORDS_DIR 覆盖；/opt 需要 root）"
fi
if ! dest_writable "$DEST"; then
  err "安装目录不可写且无法创建：$DEST"
  err "请把 DSH_PASSWORDS_DIR 指向当前用户可写的目录后重跑，例如："
  err "  DSH_PASSWORDS_DIR=\"\$HOME/dsh-passwords\" bash install.sh"
  exit 1
fi

say "下载项目到 $DEST …"
git clone --depth 1 https://github.com/slywalker2006/dsh-passwords.git "$DEST" || {
  err "项目下载失败，请检查网络后重跑。"; exit 1; }
exec node "$DEST/scripts/install.mjs"