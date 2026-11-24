#!/usr/bin/env bash
#
# install_ubuntu22.sh — POPOPX Bot Studio 一键生产安装（Ubuntu 22.04 / systemd）
#
# 职责：
#   1. --mode native：装依赖 → 建 popopx-studio 专用系统用户 → 部署代码到
#      /opt/popopx-bot-studio → Python 3.11 venv → 写 0600 的 .env（随机管理员令牌）
#      → 安装 systemd 单元 /etc/systemd/system/popopx-bot-studio.service；
#   2. --mode dev：只做 venv + .env，不碰 apt/系统用户/systemd（非 root 可用）；
#   3. 零二进制捆绑：本机缺少 /usr/local/bin/popopx-cli 且未传 --no-node-download 时，
#      探测 OS/arch → 拉 GitHub Releases 最新资产 → 校验 SHA-256 → 安装为
#      /usr/local/bin/popopx-cli（chmod 755）。
#
# 硬约束（与 prompt.md 一致）：
#   * 服务只绑 127.0.0.1：ExecStart 里写死 --host 127.0.0.1，且不给任何 --lan 后门；
#     非回环只能由运维自己改 .env（STUDIO_HOST + STUDIO_ALLOW_LAN=1），config.py 会拒绝
#     只改 HOST 不设 ALLOW_LAN 的组合。
#   * 每 Bot 隔离目录 <data_dir>/bots/<bot_id>/cli-data，控制端口 5230..5299，严禁 0.0.0.0。
#   * Bot 进程不由 systemd 直接 exec：studio/app/bot_supervisor.py::render_wrapper_script
#     生成 #!/bin/sh 包装脚本（逐 token shlex.quote），使 systemd 的 ExecStart 剥引号拆词
#     不会拆坏 `--server "smp1.popopx.im … smp8.popopx.im"`；本脚本引用的真实 argv 是：
#       popopx-cli --chat-server-port N --database <prefix> --files-folder D \
#                  --temp-folder D --log-level L [--server "smp1..8"]
#   * SMP 集群默认继承二进制内置 smp1..8.popopx.im；只有 BOT_SMP_SERVERS 覆写，
#     本脚本绝不硬编码另一套集群。
#   * 幂等 + 非交互安全（DEBIAN_FRONTEND=noninteractive、apt-get -y、不提示确认）；
#     已存在的 .env 绝不静默覆盖。
#
# 退出码：0 成功 / 1 致命问题 / 2 参数错误 / 70 执行失败。

# CDPATH= 是刻意的（防止 CDPATH 劫持 cd）；shellcheck 的 SC1007 在此为误报
# shellcheck disable=SC1007
set -euo pipefail

# ------------------------------------------------------------ 默认值（可被旗标覆盖）
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

REPO_DIR="$SCRIPT_DIR"
APP_DIR="/opt/popopx-bot-studio"
DATA_DIR=""                      # 空 → native: /var/lib/popopx-studio；dev: <repo>/var/studio
ENV_FILE=""                      # 空 → <app-dir>/.env
SERVICE_USER="popopx-studio"
SERVICE_GROUP="popopx-studio"
UNIT_NAME="popopx-bot-studio"
CLI_BIN="/usr/local/bin/popopx-cli"
PYTHON_BIN=""
PORT="8090"
HOST="127.0.0.1"
MODE="native"
DRY_RUN=0
MODE_CHECK=0
MODE_UNINSTALL=0
NO_NODE_DOWNLOAD=0
FORCE_ENV=0
CLI_REPORT_ONLY=0
SKIP_APT=0
NO_SUDO=0
VERBOSE=0
VENV_DIR=""
VENV_PY=""
UNIT_PATH=""
WORK_DIR=""
PROBLEMS=0
NOTES=0
OS_ID=""
OS_VERSION=""

# CLI 下载源（仅本脚本读取；仓库本身永不含编译产物）
CLI_REPO="${POPOPX_CLI_REPO:-popopx-chat/popopx-chat}"
CLI_VERSION="${POPOPX_CLI_VERSION:-latest}"
CLI_ASSET_URL="${POPOPX_CLI_URL:-}"
CLI_SHA256_PIN="${POPOPX_CLI_SHA256:-}"
GH_API="https://api.github.com"
DEPS="fastapi uvicorn pydantic websockets httpx qrcode cryptography"
APT_PACKAGES="python3.11 python3.11-venv python3-pip curl ca-certificates rsync openssl"

# ------------------------------------------------------------------------ 工具函数
have() { command -v "$1" >/dev/null 2>&1; }
ts() { date '+%H:%M:%S'; }
log() { printf '[%s] %s\n' "$(ts)" "$*"; }
warn() { printf '[%s] warn: %s\n' "$(ts)" "$*" >&2; }
verb() { [ "$VERBOSE" -eq 1 ] && printf '[%s]     %s\n' "$(ts)" "$*"; return 0; }
die() { local code="${2:-1}"; printf '[%s] error: %s\n' "$(ts)" "$1" >&2; exit "$code"; }
problem() { printf '[%s] FAIL: %s\n' "$(ts)" "$*" >&2; PROBLEMS=$((PROBLEMS + 1)); }
note() { printf '[%s]  tip: %s\n' "$(ts)" "$*"; NOTES=$((NOTES + 1)); }
# 把 argv 还原成可读的一行（干跑打印用）。用 %q 而不是 ${arr[*]@Q}：后者要 bash 4.4+。
quote_args() {
  local out="" arg
  for arg in "$@"; do out+="${out:+ }$(printf '%q' "$arg")"; done
  printf '%s' "$out"
}

run() {
  printf '  + %s\n' "$*"
  [ "$DRY_RUN" -eq 1 ] && return 0
  "$@" || die "命令失败（exit=$?）：$*" 70
}
run_ok() {
  printf '  ~ %s\n' "$*"
  [ "$DRY_RUN" -eq 1 ] && return 0
  "$@" 2>/dev/null || return 1
}
as_root() {
  if [ "$(id -u)" -eq 0 ] || [ "$NO_SUDO" -eq 1 ]; then run "$@"; else run sudo "$@"; fi
}
as_root_ok() {
  if [ "$(id -u)" -eq 0 ] || [ "$NO_SUDO" -eq 1 ]; then
    run_ok "$@" || true
  elif have sudo && sudo -n true 2>/dev/null; then
    run_ok sudo -n "$@" || true
  else
    printf '  ~ (skipped, 需要 sudo) %s\n' "$*"
    return 1
  fi
}

usage() {
  cat <<'USAGE'
用法：./install_ubuntu22.sh [选项]

POPOPX Bot Studio 的 Ubuntu 22.04 生产安装器（systemd 服务，只绑 127.0.0.1）。

选项：
  -h, --help                显示本帮助并退出 0
      --mode native|dev     native（默认）= 系统用户 + /opt 部署 + systemd 单元；
                            dev = 只做 venv + .env，不碰 apt/用户/systemd（非 root 可跑）
  -n, --dry-run             打印全部计划动作（含生成的 systemd unit 全文），
                            不做任何改动；非 Ubuntu 机器上也能干跑（apt 步骤仅打印）
      --check               只做诊断（布局/python/依赖/.env 权限/CLI/监听地址/单元），
                            不改动任何东西
      --uninstall           stop + disable 并删除 systemd 单元（默认保留 .env 与数据目录）
      --no-node-download    不下载 popopx-cli（缺少二进制时 Studio 离线降级运行）
      --force-env           允许覆盖已存在的 .env（默认拒绝覆盖并保留原文件）
      --repo-dir PATH       源码仓库根（默认：本脚本所在目录）
      --app-dir PATH        部署目录（默认 /opt/popopx-bot-studio）
      --data-dir PATH       STUDIO_DATA_DIR（默认 /var/lib/popopx-studio）
      --user NAME           服务用户（默认 popopx-studio，绝不使用 root）
      --group NAME          服务组（默认同 --user）：以 useradd --gid 建为服务用户的**主组**，
                            systemd 的 Group= 与数据目录属组都取它；用户已存在但主组不符时
                            自动 usermod -g 收敛（--check 会校验）
      --port N              Studio 端口（默认 8090）
      --cli-bin PATH        popopx-cli 路径（默认 /usr/local/bin/popopx-cli）
      --unit NAME           systemd 单元名（默认 popopx-bot-studio）
      --python PATH         venv 基座 python（默认 python3.11 → python3）
      --skip-apt            跳过 apt 安装步骤
      --no-sudo             不调用 sudo（已是 root，或目标路径当前用户可写）
      --cli-release-report  只解析将要使用的 release 资产与 SHA-256 校验来源，不下载
  -v, --verbose             更多细节

安装脚本级环境变量（不写入 .env）：
  POPOPX_CLI_REPO=popopx-chat/popopx-chat  下载源仓库
  POPOPX_CLI_VERSION=latest|vX.Y.Z          指定 tag
  POPOPX_CLI_URL=https://…                  直接给定资产 URL（跳过 Releases 解析）
  POPOPX_CLI_SHA256=<64hex>                 固定校验值，优先级最高
  GITHUB_TOKEN=…                            私有 fork / 提高限流，只在环境里导出

示例：
  ./install_ubuntu22.sh --dry-run
  sudo ./install_ubuntu22.sh --mode native
  ./install_ubuntu22.sh --mode dev --no-sudo --cli-bin "$HOME/.local/bin/popopx-cli"
  sudo ./install_ubuntu22.sh --uninstall
USAGE
}

# ------------------------------------------------------------------------ 参数解析
parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -h | --help) usage; exit 0 ;;
      --mode) MODE="${2:?--mode 需要参数}"; shift ;;
      -n | --dry-run) DRY_RUN=1 ;;
      --check) MODE_CHECK=1 ;;
      --uninstall) MODE_UNINSTALL=1 ;;
      --no-node-download) NO_NODE_DOWNLOAD=1 ;;
      --force-env) FORCE_ENV=1 ;;
      --repo-dir) REPO_DIR="${2:?--repo-dir 需要参数}"; shift ;;
      --app-dir) APP_DIR="${2:?--app-dir 需要参数}"; shift ;;
      --data-dir) DATA_DIR="${2:?--data-dir 需要参数}"; shift ;;
      --user) SERVICE_USER="${2:?--user 需要参数}"; shift ;;
      --group) SERVICE_GROUP="${2:?--group 需要参数}"; shift ;;
      --port) PORT="${2:?--port 需要参数}"; shift ;;
      --cli-bin) CLI_BIN="${2:?--cli-bin 需要参数}"; shift ;;
      --unit) UNIT_NAME="${2:?--unit 需要参数}"; shift ;;
      --python) PYTHON_BIN="${2:?--python 需要参数}"; shift ;;
      --skip-apt) SKIP_APT=1 ;;
      --no-sudo) NO_SUDO=1 ;;
      --cli-release-report) CLI_REPORT_ONLY=1 ;;
      -v | --verbose) VERBOSE=1 ;;
      *) printf '未知选项：%s（--help 查看用法）\n' "$1" >&2; exit 2 ;;
    esac
    shift
  done

  case "$MODE" in
    native | dev) : ;;
    *) die "--mode 只能是 native 或 dev（收到：${MODE}）" 2 ;;
  esac
  case "$PORT" in '' | *[!0-9]*) die "--port 必须是数字：$PORT" 2 ;; esac
  [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port 超出 1-65535：$PORT" 2
  REPO_DIR=$(CDPATH= cd -- "$REPO_DIR" 2>/dev/null && pwd -P) || die "--repo-dir 不存在：$REPO_DIR" 2

  if [ "$MODE" = "dev" ]; then
    # dev：一切留在仓库内，不建系统用户、不写 /opt、不装 unit
    APP_DIR="$REPO_DIR"
    [ -n "$DATA_DIR" ] || DATA_DIR="$REPO_DIR/var/studio"
    [ -n "$ENV_FILE" ] || ENV_FILE="$REPO_DIR/.env"
  else
    [ -n "$ENV_FILE" ] || ENV_FILE="$APP_DIR/.env"
    [ -n "$DATA_DIR" ] || DATA_DIR="/var/lib/popopx-studio"
  fi

  VENV_DIR="$APP_DIR/.venv"
  VENV_PY="$VENV_DIR/bin/python3"
  UNIT_PATH="/etc/systemd/system/${UNIT_NAME}.service"
  WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/popopx-studio.XXXXXX")
  trap 'rm -rf "$WORK_DIR"' EXIT
}

# ------------------------------------------------------------------ 发行版探测
detect_os() {
  # 幂等：已探测过就不再重复打印
  if [ -n "$OS_ID" ] && [ "$OS_ID" != "unknown" ]; then return 0; fi
  OS_ID="unknown"
  OS_VERSION=""
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-}"
  fi
  log "发行版：$OS_ID ${OS_VERSION}"
}

require_ubuntu() {
  detect_os
  if [ "$OS_ID" = "ubuntu" ]; then
    case "$OS_VERSION" in
      22.*|24.*) : ;;
      *) note "目标发行版是 Ubuntu ${OS_VERSION:-?}（脚本按 22.04 编写，24.04 一般兼容）" ;;
    esac
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    note "本机不是 Ubuntu（检测到 ${OS_ID}）——--dry-run 继续，只打印计划动作"
    return 1
  fi
  die "本脚本仅支持 Ubuntu 22.04（检测到 $OS_ID ${OS_VERSION}）。apt/系统用户/systemd 步骤无法在此执行；
     只想准备 venv + .env 请用 --mode dev；macOS 请用 install_macos.sh。" 1
}

apt_install() {
  if [ "$SKIP_APT" -eq 1 ]; then verb "--skip-apt：跳过包安装"; return 0; fi
  if [ "$MODE" = "dev" ]; then verb "dev 模式：不执行 apt"; return 0; fi
  if ! require_ubuntu; then
    printf '  + [would] DEBIAN_FRONTEND=noninteractive apt-get update\n'
    printf '  + [would] DEBIAN_FRONTEND=noninteractive apt-get install -y %s\n' "$APT_PACKAGES"
    return 0
  fi
  log "安装系统依赖：$APT_PACKAGES"
  export DEBIAN_FRONTEND=noninteractive
  as_root apt-get -qq update
  # shellcheck disable=SC2086  # 软件包列表需要按空格拆分
  as_root apt-get install -y --no-install-recommends $APT_PACKAGES
}

# -------------------------------------------------------------- 仓库布局与 python
check_layout() {
  log "校验仓库布局：$REPO_DIR"
  [ -f "$REPO_DIR/studio/app/main.py" ] || problem "缺少 studio/app/main.py（--repo-dir 指错了？）"
  [ -f "$REPO_DIR/studio/app/config.py" ] || problem "缺少 studio/app/config.py"
  [ -f "$REPO_DIR/studio/requirements.txt" ] || problem "缺少 studio/requirements.txt"
  [ -d "$REPO_DIR/studio/static" ] || problem "缺少 studio/static（Web 管理后台）"
  [ -f "$REPO_DIR/LICENSE" ] || note "仓库根缺少 AGPL-3.0-only LICENSE"
  if find "$REPO_DIR" -maxdepth 3 -type f -size +20M \
      \( -name 'popopx-cli*' -o -name 'simplex-chat*' \) 2>/dev/null | grep -q .; then
    problem "仓库内发现疑似 CLI 编译产物，违反零二进制捆绑，请先移除"
  fi
  [ "$PROBLEMS" -eq 0 ] || die "仓库布局不完整（见 FAIL 行）" 1
}

detect_python() {
  if [ -n "$PYTHON_BIN" ]; then
    { have "$PYTHON_BIN" || [ -x "$PYTHON_BIN" ]; } || die "--python 不可执行：$PYTHON_BIN" 1
  else
    local c
    for c in python3.11 python3 /usr/bin/python3.11 /usr/bin/python3; do
      if have "$c" || [ -x "$c" ]; then PYTHON_BIN="$c"; break; fi
    done
  fi
  [ -n "$PYTHON_BIN" ] || die "未找到 python3（apt-get install -y python3.11 python3.11-venv）" 1
  local ver
  ver="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo unknown)"
  if [ "$ver" = "3.11" ]; then
    log "基座 python：${PYTHON_BIN}（${ver}）"
  else
    note "基座 python 是 ${ver}，Studio 钉住 3.11；Ubuntu 22.04 需 add-apt-repository ppa:deadsnakes/ppa 或用 --python 指定"
  fi
}

venv_ready() {
  [ -x "$VENV_PY" ] && "$VENV_PY" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 9) else 1)' >/dev/null 2>&1
}

deps_present() {
  local py="$1" m
  [ -x "$py" ] || return 1
  for m in $DEPS; do
    "$py" -c "import $m" >/dev/null 2>&1 || return 1
  done
  return 0
}

deploy_app_dir() {
  [ "$MODE" = "native" ] || return 0
  if [ "$(CDPATH= cd -- "$REPO_DIR" && pwd -P)" = "$(CDPATH= cd -- "$APP_DIR" 2>/dev/null && pwd -P 2>/dev/null || echo _)" ]; then
    verb "--app-dir 与 --repo-dir 相同，跳过复制"
    return 0
  fi
  log "部署源码 → ${APP_DIR}（rsync，不含 .git/.venv/var/.env，零二进制）"
  as_root mkdir -p "$APP_DIR"
  if have rsync; then
    as_root rsync -a --delete \
      --exclude '.git/' --exclude '.venv/' --exclude 'var/' --exclude '.env' \
      --exclude '__pycache__/' --exclude '*.py[cod]' \
      "$REPO_DIR/" "$APP_DIR/"
  else
    as_root cp -a "$REPO_DIR/." "$APP_DIR/"
    as_root_ok rm -rf "$APP_DIR/.git" "$APP_DIR/var" "$APP_DIR/.venv" || true
  fi
}

create_service_user() {
  [ "$MODE" = "native" ] || return 0
  # 主组必须显式取 --group。GNU useradd 的 -U/--user-group 会另建一个与用户名同名的组做主组，
  # SERVICE_GROUP 于是被绕开：单元 Group= 与 chown 都指向一个该用户不属于的组，
  # 而 systemd 只要组存在就不报错，属组错配完全是静默的。
  local -a mkgroup=(groupadd --system --force "$SERVICE_GROUP")
  local -a mkuser=(useradd --system --create-home --home-dir "$DATA_DIR"
                   --shell /usr/sbin/nologin --gid "$SERVICE_GROUP" "$SERVICE_USER")
  if ! require_ubuntu; then
    printf '  + [would] %s\n' "$(quote_args "${mkgroup[@]}")"
    printf '  + [would] id -u %s 2>/dev/null || %s\n' "$SERVICE_USER" "$(quote_args "${mkuser[@]}")"
    return 0
  fi
  if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    local current_group=""
    current_group=$(id -gn "$SERVICE_USER" 2>/dev/null || echo "")
    if [ "$current_group" = "$SERVICE_GROUP" ]; then
      log "系统用户 $SERVICE_USER 已存在，主组即 ${SERVICE_GROUP}（幂等，跳过）"
    else
      warn "服务用户 ${SERVICE_USER} 的主组是 ${current_group:-未知}，与 --group ${SERVICE_GROUP} 不符 —— 纠正为主组"
      as_root "${mkgroup[@]}"
      as_root usermod -g "$SERVICE_GROUP" "$SERVICE_USER"
    fi
  else
    log "创建专用系统用户 ${SERVICE_USER}（nologin，主组 ${SERVICE_GROUP}，绝不以 root 运行服务）"
    as_root "${mkgroup[@]}"
    as_root "${mkuser[@]}"
  fi
}

create_venv() {
  if venv_ready; then
    log "venv 已存在：${VENV_DIR}（$("$VENV_PY" -V 2>&1)）—— 跳过创建（幂等）"
  else
    log "创建 Python 虚拟环境 $VENV_DIR"
    run "$PYTHON_BIN" -m venv "$VENV_DIR"
  fi
  if deps_present "$VENV_PY"; then
    log "requirements.txt 依赖齐备，跳过 pip install（幂等）"
  else
    log "安装依赖：studio/requirements.txt"
    run "$VENV_PY" -m pip install --disable-pip-version-check --upgrade pip wheel
    run "$VENV_PY" -m pip install --disable-pip-version-check -r "$APP_DIR/studio/requirements.txt"
  fi
}

random_token() {
  if have openssl; then openssl rand -hex 32; return 0; fi
  "$PYTHON_BIN" -c 'import secrets; print(secrets.token_hex(32))'
}

ensure_env_file() {
  if [ -f "$ENV_FILE" ]; then
    if [ "$FORCE_ENV" -eq 1 ]; then
      warn "--force-env：重建 ${ENV_FILE}（旧 STUDIO_ADMIN_TOKEN 立即失效）"
    else
      warn "检测到已存在的 $ENV_FILE —— 拒绝静默覆盖，保留原内容（要重建请加 --force-env）"
      run chmod 600 "$ENV_FILE"
      return 0
    fi
  else
    log "生成 ${ENV_FILE}（随机 STUDIO_ADMIN_TOKEN，权限 0600）"
  fi
  local tmp="$WORK_DIR/env"
  {
    printf '# POPOPX Bot Studio — install_ubuntu22.sh 生成于 %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf '# 权限必须保持 0600：app/config.py 会检查 .env / studio.state.json / studio.key\n'
    printf 'STUDIO_HOST=127.0.0.1\n'
    printf 'STUDIO_PORT=%s\n' "$PORT"
    printf '# 保持 0：Studio 只绑回环。要对外暴露必须同时改 STUDIO_HOST 并显式置 1。\nSTUDIO_ALLOW_LAN=0\n'
    printf 'STUDIO_ADMIN_TOKEN=%s\n' "$(random_token)"
    printf 'STUDIO_DATA_DIR=%s\n' "$DATA_DIR"
    printf 'STUDIO_ENV_FILE=%s\n' "$ENV_FILE"
    printf 'CLI_BIN_PATH=%s\n' "$CLI_BIN"
    printf 'BOT_WS_PORT_BASE=5230\nBOT_WS_PORT_MAX=5299\n'
    printf '# 留空 = 继承 popopx-cli 内置 smp1..8.popopx.im 双栈集群；仅在自建中继时覆写\nBOT_SMP_SERVERS=\n'
    printf 'STUDIO_LOCALE=en\n'
  } >"$tmp"
  if [ "$MODE" = "native" ]; then
    local -a own=()
    [ "$(id -u)" -eq 0 ] && own=(-o "$SERVICE_USER" -g "$SERVICE_GROUP")
    as_root install -m 600 ${own[@]+"${own[@]}"} "$tmp" "$ENV_FILE"
  else
    run install -m 600 "$tmp" "$ENV_FILE"
  fi
}

prepare_state_dirs() {
  log "准备数据目录 ${DATA_DIR}（0700；bots/<id>/cli-data 由 Studio 逐个创建）"
  run mkdir -p "$DATA_DIR/bots" "$DATA_DIR/backups"
  run chmod 700 "$DATA_DIR" "$DATA_DIR/bots" "$DATA_DIR/backups"
  if [ "$MODE" = "native" ]; then
    as_root chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR"
  fi
}

# ------------------------------------------------- popopx-cli 按需下载 + SHA-256 校验
sha256_of() {
  local f="$1"
  if have sha256sum; then sha256sum "$f" | awk '{print $1}'
  elif have shasum; then shasum -a 256 "$f" | awk '{print $1}'
  elif have openssl; then openssl dgst -sha256 "$f" | awk '{print $NF}'
  else "$PYTHON_BIN" -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$f"
  fi
}

platform_arch() {
  OS_KIND=""
  ARCH_KIND=""
  case "$(uname -s)" in
    Darwin) OS_KIND="macos" ;;
    Linux) OS_KIND="linux" ;;
    *) die "不支持的操作系统：$(uname -s)（仅支持 macOS / Linux）" 1 ;;
  esac
  case "$(uname -m)" in
    x86_64 | amd64) ARCH_KIND="x86_64" ;;
    arm64 | aarch64) ARCH_KIND="aarch64" ;;
    *) die "不支持的 CPU 架构：$(uname -m)（仅支持 x86_64 / arm64-aarch64）" 1 ;;
  esac
  log "目标平台：$OS_KIND/$ARCH_KIND"
}

gh_curl() {
  local url="$1" out="$2"
  local -a hdr=(-H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28')
  if [ -n "${GITHUB_TOKEN:-}" ]; then hdr+=(-H "Authorization: Bearer ${GITHUB_TOKEN}"); fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  + curl -fL %s\n' "$url"
    return 0
  fi
  curl -fsSL --retry 3 --retry-delay 2 --proto '=https' --tlsv1.2 "${hdr[@]}" -o "$out" "$url" ||
    die "下载失败：${url}（私有仓库请导出 GITHUB_TOKEN）" 1
}

try_curl() {
  local url="$1" out="$2"
  local -a hdr=()
  if [ -n "${GITHUB_TOKEN:-}" ]; then hdr=(-H "Authorization: Bearer ${GITHUB_TOKEN}"); fi
  printf '  ? curl -fL %s\n' "$url"
  [ "$DRY_RUN" -eq 1 ] && return 1
  curl -fsSL --retry 2 --proto '=https' --tlsv1.2 ${hdr[@]+"${hdr[@]}"} -o "$out" "$url" 2>/dev/null || return 1
  [ -s "$out" ]
}

release_json() {
  if [ "$CLI_VERSION" = "latest" ]; then
    if try_curl "$GH_API/repos/$CLI_REPO/releases/latest" "$WORK_DIR/release.json"; then
      return 0
    fi
    note "releases/latest 不可用，回退 releases 列表（取最新非草稿/非预发布）"
    gh_curl "$GH_API/repos/$CLI_REPO/releases?per_page=15" "$WORK_DIR/release.json"
  else
    gh_curl "$GH_API/repos/$CLI_REPO/releases/tags/$CLI_VERSION" "$WORK_DIR/release.json"
  fi
}

# 输出机器可读行：TAG / ASSET / CANDIDATE / CHOSEN / SIDECAR / AGGREGATE / ERROR
pick_asset() {
  OS_KIND="$OS_KIND" ARCH_KIND="$ARCH_KIND" CLI_REPO="$CLI_REPO" "$PYTHON_BIN" - \
    "$WORK_DIR/release.json" <<'PY'
import json, os, re, sys

os_kind, arch_kind = os.environ["OS_KIND"], os.environ["ARCH_KIND"]
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as exc:                                   # noqa: BLE001
    print("ERROR\trelease JSON 读取失败：%s" % exc)
    sys.exit(0)
if isinstance(data, dict) and data.get("message"):
    print("ERROR\tGitHub API %s（仓库缺失/私有？可导出 GITHUB_TOKEN，或用 POPOPX_CLI_URL）"
          % data["message"])
    sys.exit(0)

releases = data if isinstance(data, list) else [data]
release = next((r for r in releases if not r.get("draft") and not r.get("prerelease")),
               releases[0] if releases else {})
print("TAG\t%s" % (release.get("tag_name") or release.get("name") or "unknown"))

# 资产名并非字面 “popopx-cli”：品牌前缀 + 平台 + 架构 + 裸可执行 四个条件联合匹配
plat = re.compile(r"(macos|darwin|apple)" if os_kind == "macos"
                  else r"(ubuntu[-_.]?22[._]04|ubuntu|debian|linux|generic)", re.I)
arch = re.compile(r"(x86[-_.]?64|amd64)" if arch_kind == "x86_64" else r"(aarch64|arm64)", re.I)
brand = re.compile(r"^(popopx|simplex)[-_\.]?(chat|cli)", re.I)
container = re.compile(r"(desktop|windows|ios|android|appimage|\.deb$|\.rpm$|\.dmg$|\.msi$|"
                       r"\.apk$|\.zip$|\.tar|\.gz$|\.xz$|\.zst$|\.asc$|\.sig$|_sha256sums|"
                       r"^LICENSE|^README|^checksums?$)", re.I)

def score(name):
    if not brand.match(name) or container.search(name):
        return -1
    if not plat.search(name) or not arch.search(name):
        return -1
    s = 80
    if os_kind == "linux" and re.search(r"ubuntu[-_.]?22[._]04", name, re.I):
        s += 15                       # 目标发行版专用优先于 generic
    if re.search(r"(generic|portable|static)", name, re.I):
        s += 5
    return s

assets = release.get("assets") or []
for a in assets:
    print("ASSET\t%s" % (a.get("name") or ""))
ranked = sorted(((score(a.get("name") or ""), a) for a in assets),
                key=lambda t: (-t[0], len(t[1].get("name") or ""), t[1].get("name") or ""))
ranked = [t for t in ranked if t[0] >= 0]
for sc, a in ranked:
    print("CANDIDATE\t%d\t%s" % (sc, a.get("name")))
if not ranked:
    print("ERROR\t%s 最新 release 中没有匹配 ^popopx[-_.]?(chat|cli) + %s + %s 的裸可执行资产"
          % (os.environ.get("CLI_REPO", "the repo"), os_kind, arch_kind))
    sys.exit(0)
chosen = ranked[0][1]
cname = chosen.get("name") or ""
print("CHOSEN\t%s\t%s\t%s" % (cname, chosen.get("browser_download_url", ""),
                              chosen.get("digest") or ""))
for a in assets:
    on = (a.get("name") or "").lower()
    if on in (cname.lower() + ".sha256", cname.lower() + ".sha256sum", cname.lower() + ".sum"):
        print("SIDECAR\t%s" % a.get("browser_download_url", ""))
    if on in ("_sha256sums", "sha256sums", "sha256sums.txt", "checksums.txt", "checksums.sha256"):
        print("AGGREGATE\t%s" % a.get("browser_download_url", ""))
PY
}

install_popopx_cli() {
  platform_arch
  if [ -x "$CLI_BIN" ] && [ "$CLI_REPORT_ONLY" -eq 0 ]; then
    log "已存在 ${CLI_BIN}（$("$CLI_BIN" --version 2>/dev/null | head -1 || echo '版本未知')）—— 跳过下载（幂等）"
    return 0
  fi
  if [ "$NO_NODE_DOWNLOAD" -eq 1 ] && [ "$CLI_REPORT_ONLY" -eq 0 ]; then
    note "--no-node-download：不下载 popopx-cli。Studio 以离线降级模式运行（Bot 启停不可用，"
    note "      规则/路由/插件/Open API/冷备导出照常）。需要时去掉该旗标重跑，或设置 CLI_BIN_PATH。"
    return 0
  fi
  have curl || die "缺少 curl，无法按需下载 popopx-cli（或用 --no-node-download 跳过）" 1
  detect_python

  log "按需获取 popopx-cli（零二进制捆绑：仓库不含也不提交任何编译产物）"
  log "匹配规则：^popopx[-_.]?(chat|cli) 前缀 + 平台($OS_KIND) + 架构($ARCH_KIND) + 排除 .deb/.rpm/.zip/AppImage/desktop"
  local SIDECAR_URL="" AGG_URL="" ASSET_NAME="" ASSET_URL="" API_DIGEST="" TAG_NAME=""
  if [ -n "$CLI_ASSET_URL" ]; then
    ASSET_NAME="$(basename "$CLI_ASSET_URL")"
    ASSET_URL="$CLI_ASSET_URL"
    log "使用显式 POPOPX_CLI_URL：$ASSET_URL"
    if try_curl "$ASSET_URL.sha256" "$WORK_DIR/sidecar.txt"; then
      log "发现旁挂 ${ASSET_NAME}.sha256，将以其为校验基准"
    fi
    if try_curl "$(dirname "$ASSET_URL")/_sha256sums" "$WORK_DIR/sums.txt"; then
      log "发现汇总校验文件 _sha256sums"
    fi
  else
    release_json
    local parsed="$WORK_DIR/picked.tsv"
    if [ "$DRY_RUN" -eq 1 ]; then
      log "[dry-run] 计划：GET $GH_API/repos/$CLI_REPO/releases/$CLI_VERSION → 按上述规则选资产"
      log "[dry-run] 计划：下载裸二进制 → 计算 SHA-256 → 依次尝试「旁挂 .sha256 / 汇总 _sha256sums / GitHub API asset digest / POPOPX_CLI_SHA256」"
      log "[dry-run] 计划：比对通过才 install -m 755 到 ${CLI_BIN}；三者皆无且无固定值 → 拒绝安装"
      return 0
    fi
    CLI_REPO="$CLI_REPO" pick_asset >"$parsed"
    if grep -q '^ERROR' "$parsed"; then
      die "无法选定 popopx-cli 资产：$(grep '^ERROR' "$parsed" | head -1 | cut -f2-)
      可选处置：导出 GITHUB_TOKEN（私有 fork）、设 POPOPX_CLI_REPO / POPOPX_CLI_VERSION、
      直接给 POPOPX_CLI_URL + POPOPX_CLI_SHA256，或自行安装到 $CLI_BIN 后重跑。" 1
    fi
    TAG_NAME="$(awk -F'\t' '$1=="TAG"{print $2; exit}' "$parsed")"
    ASSET_NAME="$(awk -F'\t' '$1=="CHOSEN"{print $2; exit}' "$parsed")"
    ASSET_URL="$(awk -F'\t' '$1=="CHOSEN"{print $3; exit}' "$parsed")"
    API_DIGEST="$(awk -F'\t' '$1=="CHOSEN"{print $4; exit}' "$parsed")"
    SIDECAR_URL="$(awk -F'\t' '$1=="SIDECAR"{print $2; exit}' "$parsed")"
    AGG_URL="$(awk -F'\t' '$1=="AGGREGATE"{print $2; exit}' "$parsed")"
    [ -n "$ASSET_URL" ] || die "选定资产 URL 为空（internal）" 1
    log "release tag：${TAG_NAME:-unknown}；候选（分数越高越优先）："
    awk -F'\t' '$1=="CANDIDATE"{printf "      %3s  %s\n", $2, $3}' "$parsed"
  fi

  if [ "$CLI_REPORT_ONLY" -eq 1 ]; then
    log "资产名：$ASSET_NAME"
    log "下载地址：$ASSET_URL"
    log "GitHub asset digest：${API_DIGEST:-（API 未提供）}"
    log "旁挂 .sha256：${SIDECAR_URL:-无}"
    log "汇总校验文件：${AGG_URL:-无}"
    log "固定值 POPOPX_CLI_SHA256：${CLI_SHA256_PIN:-无}"
    return 0
  fi

  # --- 下载裸二进制（先取基准文件）
  local bin="$WORK_DIR/$ASSET_NAME"
  if [ -n "$SIDECAR_URL" ] && [ ! -s "$WORK_DIR/sidecar.txt" ]; then
    gh_curl "$SIDECAR_URL" "$WORK_DIR/sidecar.txt"
  fi
  if [ -n "$AGG_URL" ] && [ ! -s "$WORK_DIR/sums.txt" ]; then
    gh_curl "$AGG_URL" "$WORK_DIR/sums.txt"
  fi
  gh_curl "$ASSET_URL" "$bin"
  [ -s "$bin" ] || die "下载文件为空：$ASSET_URL" 1
  local actual expected="" source=""
  actual="$(sha256_of "$bin")"
  log "本地计算 SHA-256：$actual"

  # --- 校验基准，优先级固定；找不到就拒绝安装，绝不静默跳过
  if [ -n "$CLI_SHA256_PIN" ]; then
    expected="${CLI_SHA256_PIN#sha256:}"
    source="POPOPX_CLI_SHA256 固定值（离线已知）"
  elif [ -s "${WORK_DIR}/sidecar.txt" ]; then
    expected="$(awk '{for (i=1;i<=NF;i++) if ($i ~ /^[0-9a-fA-F]{64}$/) {print tolower($i); exit}}' "$WORK_DIR/sidecar.txt")"
    source="发布方旁挂 ${ASSET_NAME}.sha256"
  elif [ -s "${WORK_DIR}/sums.txt" ]; then
    # 汇总文件里的路径可能带 tag 前缀（如 v7.1.4/simplex-chat-…），按 basename 精确匹配
    expected="$(awk -v n="$ASSET_NAME" '{ f=$NF; sub(/^.*\//,"",f); if (f==n) { for (i=1;i<=NF;i++) if ($i ~ /^[0-9a-fA-F]{64}$/) { print tolower($i); exit } } }' "$WORK_DIR/sums.txt")"
    source="发布方汇总校验文件 $(basename "${AGG_URL:-_sha256sums}")"
    [ -n "$expected" ] || note "${source} 中未列出 ${ASSET_NAME}，改用下一个基准来源"
  elif [ -n "$API_DIGEST" ]; then
    expected="${API_DIGEST#sha256:}"
    source="GitHub Releases API 暴露的 asset digest"
  fi
  case "$expected" in
    '' | *[!0-9a-f]*)
      local probed
      probed="旁挂 ${ASSET_NAME}.sha256=$([ -s "$WORK_DIR/sidecar.txt" ] && echo 有 || echo 无)、汇总 $([ -s "$WORK_DIR/sums.txt" ] && echo "有（但未列出该资产）" || echo 无)、API digest=${API_DIGEST:+有}${API_DIGEST:-无}、固定值=${CLI_SHA256_PIN:+有}${CLI_SHA256_PIN:-无}"
      die "拒绝安装：找不到任何可信的 SHA-256 基准。已探测：${probed}。
      硬约束要求「先校验 SHA-256 再安装」，绝不静默跳过。请导出 POPOPX_CLI_SHA256=<上游公告的 64 位十六进制> 重跑。" 1
      ;;
  esac
  if [ "${#expected}" -ne 64 ]; then
    die "SHA-256 基准长度非法（${#expected}，应为 64）：$expected" 1
  fi
  if [ "$expected" != "$actual" ]; then
    die "SHA-256 不匹配！期望=$expected 实际=$actual 基准来源=$source —— 已丢弃下载文件，绝不安装。" 1
  fi
  log "SHA-256 校验通过（基准来源：${source}）"
  case "$source" in
    *digest*)
      warn "注意：该 release 未在二进制旁发布 .sha256 资产，本次以 GitHub API 的 asset digest 作基准。"
      warn "      该值由 GitHub 对其存储的资产计算，可证明下载未被中转篡改，但不等同于上游签名公告；"
      warn "      如需更强保证，请导出 POPOPX_CLI_SHA256=<上游公告值> 让本脚本以固定值复核。"
      ;;
  esac

  # --- 以固定名安装（资产名 ≠ popopx-cli）
  log "安装 $ASSET_NAME → ${CLI_BIN}（chmod 755）"
  run chmod 755 "$bin"
  as_root mkdir -p "$(dirname "$CLI_BIN")"
  as_root install -m 755 "$bin" "$CLI_BIN"
  cli_flag_smoke_test
}

# 冒烟检查：下载物是否真的接受 bot_supervisor.build_cli_argv 生成的参数
cli_flag_smoke_test() {
  [ "$DRY_RUN" -eq 1 ] && return 0
  [ -x "$CLI_BIN" ] || return 0
  local help_text missing="" f
  help_text="$("$CLI_BIN" --help 2>&1 || true)"
  for f in --chat-server-port --database --files-folder --temp-folder --log-level --server; do
    printf '%s\n' "$help_text" | grep -q -- "$f" || missing="$missing $f"
  done
  if [ -n "$missing" ]; then
    note "下载的 $CLI_BIN 未声明这些参数：${missing}（真实 argv 见 studio/app/bot_supervisor.py::build_cli_argv）—— 请确认资产的平台/架构选对了"
  else
    log "CLI argv 自检通过：--chat-server-port --database --files-folder --temp-folder --log-level --server"
  fi
}

# ------------------------------------------------------------ systemd 单元（native）
render_unit() {
  local out="$1"
  cat >"$out" <<UNIT
# POPOPX Bot Studio — 由 install_ubuntu22.sh 生成（重跑安装会覆盖，请勿手工编辑）
# 严格回环：ExecStart 写死 --host 127.0.0.1；本安装器不提供 --lan 后门。
# 令牌不在本文件（unit 全局可读 0644），只存在于 0600 的 ${ENV_FILE}。
# 旗标全部来自 studio/app/main.py::build_parser：--serve --host --port --data-dir --env-file
[Unit]
Description=POPOPX Bot Studio (loopback-only bot factory, ws://127.0.0.1:5230..5299 to popopx-cli)
Documentation=https://github.com/popopx-chat/popopx-bot-studio
After=network.target
# 只监听 127.0.0.1，回环始终存在，因此不依赖 network-online.target

[Service]
Type=exec
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$APP_DIR/studio
Environment=STUDIO_ENV_FILE=$ENV_FILE
Environment=STUDIO_DATA_DIR=$DATA_DIR
Environment=STUDIO_HOST=127.0.0.1
Environment=STUDIO_PORT=$PORT
Environment=CLI_BIN_PATH=$CLI_BIN
Environment=BOT_WS_PORT_BASE=5230
Environment=BOT_WS_PORT_MAX=5299
Environment=PATH=/usr/local/bin:/usr/bin:/bin
ExecStart=$VENV_PY -m app.main --serve --host 127.0.0.1 --port $PORT --data-dir $DATA_DIR --env-file $ENV_FILE
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
KillMode=mixed
UMask=0077

# --- 加固（保守集合，不阻断 venv / 回环监听 / 子进程）---------------------------
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$DATA_DIR
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
MemoryDenyWriteExecute=false
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
}

write_unit() {
  [ "$MODE" = "native" ] || { verb "dev 模式：不安装 systemd 单元"; return 0; }
  local gen="$WORK_DIR/$UNIT_NAME.service"
  render_unit "$gen"
  if have systemd-analyze && require_ubuntu >/dev/null 2>&1; then
    systemd-analyze verify "$gen" >"$WORK_DIR/verify.txt" 2>&1 ||
      note "systemd-analyze verify 有输出（未必是错误）：$(head -3 "$WORK_DIR/verify.txt" | tr '\n' ' ')"
  else
    verb "跳过 systemd-analyze verify（本机不可用或非 Ubuntu）"
  fi
  grep -q '^ExecStart=' "$gen" || die "生成的 unit 缺少 ExecStart" 1
  grep -q -- '--host 127.0.0.1' "$gen" || die "生成的 unit 未绑定 127.0.0.1" 1
  log "安装 systemd 单元 → ${UNIT_PATH}（root:root 0644；服务以 $SERVICE_USER 运行）"
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] unit 全文："
    sed 's/^/      | /' "$gen"
    log "[dry-run] 计划：install -m 644 $gen → $UNIT_PATH"
    return 0
  fi
  as_root install -m 644 -o root -g root "$gen" "$UNIT_PATH"
  as_root_ok chown "$SERVICE_USER:$SERVICE_GROUP" "$APP_DIR/.env" || true
  as_root_ok chown -R "$SERVICE_USER:$SERVICE_GROUP" "$APP_DIR" || true
}

service_control() {
  [ "$MODE" = "native" ] || return 0
  if ! require_ubuntu; then
    printf '  + [would] systemctl daemon-reload\n'
    printf '  + [would] systemctl enable --now %s.service\n' "$UNIT_NAME"
    printf '  + [would] systemctl status --no-pager %s.service\n' "$UNIT_NAME"
    return 0
  fi
  log "重载 systemd 并启动服务"
  as_root systemctl daemon-reload
  as_root systemctl enable --now "$UNIT_NAME.service"
  if run_ok systemctl is-active --quiet "$UNIT_NAME.service"; then
    log "服务状态：active（http://127.0.0.1:$PORT/）"
  else
    note "服务未立即 active，请用 journalctl -u $UNIT_NAME.service -n 50 查看"
  fi
}

uninstall() {
  log "卸载 $UNIT_NAME"
  if ! require_ubuntu; then
    printf '  + [would] systemctl disable --now %s.service\n' "$UNIT_NAME"
    printf '  + [would] rm -f %s && systemctl daemon-reload\n' "$UNIT_PATH"
    return 0
  fi
  as_root_ok systemctl disable --now "$UNIT_NAME.service" || true
  as_root_ok systemctl stop "$UNIT_NAME.service" || true
  if [ -f "$UNIT_PATH" ]; then as_root rm -f "$UNIT_PATH"; else verb "无 $UNIT_PATH"; fi
  as_root_ok systemctl daemon-reload || true
  note "默认保留 $ENV_FILE 与 ${DATA_DIR}（SQLite 账本 + 各 Bot 的 cli-data 密钥）。"
  note "彻底清场请自行执行：sudo userdel -r $SERVICE_USER; sudo rm -rf $APP_DIR '$DATA_DIR'"
  note "未删除 ${CLI_BIN}（可能被其它项目共用）；如需移除：sudo rm -f '$CLI_BIN'"
  log "卸载完成"
}

listening_on() {
  local p="$1"
  if have ss; then
    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|[.:])${p}\$"; then return 0; fi
  elif have netstat; then
    if netstat -ltn 2>/dev/null | grep -Eq "[.:]${p}[[:space:]]"; then return 0; fi
  else
    verb "本机没有 ss/netstat，无法判断端口 $p"
  fi
  return 1
}

check_mode() {
  log "只诊断模式（不改动任何内容）"
  check_layout
  detect_os
  detect_python
  if venv_ready; then
    log "venv：${VENV_PY}（$("$VENV_PY" -V 2>&1)）"
    if deps_present "$VENV_PY"; then log "requirements.txt 依赖齐备"; else note "依赖不全：$DEPS"; fi
  else
    note "缺少 $VENV_DIR —— 去掉 --check 运行安装即可创建"
  fi
  if [ -f "$ENV_FILE" ]; then
    local mode
    mode=$(stat -c '%a' "$ENV_FILE" 2>/dev/null || stat -f '%OLp' "$ENV_FILE" 2>/dev/null || echo '?')
    case "$mode" in
      600 | 400) log "$ENV_FILE 权限 $mode ✔（config.py 要求 0600）" ;;
      *) problem "$ENV_FILE 权限 $mode 宽于 0600：chmod 600 '$ENV_FILE'" ;;
    esac
    if grep -q '^STUDIO_ADMIN_TOKEN=[^=]' "$ENV_FILE"; then
      log "已配置 STUDIO_ADMIN_TOKEN"
    else
      note "$ENV_FILE 未设置 STUDIO_ADMIN_TOKEN（管理路由将全部 401）"
    fi
    if grep -qE '^\s*STUDIO_ALLOW_LAN\s*=\s*(1|true|yes|on)' "$ENV_FILE"; then
      warn "$ENV_FILE 里 STUDIO_ALLOW_LAN 已开启（非回环暴露）"
    fi
  else
    note "尚无 ${ENV_FILE}（安装器会生成随机令牌并写 0600）"
  fi
  if [ -x "$CLI_BIN" ]; then log "$CLI_BIN ✔"; else note "缺少 ${CLI_BIN}：Studio 将以离线降级模式运行"; fi
  if [ "$MODE" = "native" ]; then
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
      log "服务用户 $SERVICE_USER ✔"
      local user_group=""
      user_group=$(id -gn "$SERVICE_USER" 2>/dev/null || echo '?')
      if [ "$user_group" = "$SERVICE_GROUP" ]; then
        log "服务用户主组 $user_group ✔（与 --group 一致）"
      else
        problem "服务用户主组是 ${user_group}，与 --group $SERVICE_GROUP 不符：unit 的 Group= 与属组会静默失配 → sudo usermod -g '$SERVICE_GROUP' $SERVICE_USER"
      fi
    else
      note "服务用户 $SERVICE_USER 不存在"
    fi
    # 组存在性不能用 id -g：GNU id 的 -g 取「某个用户的主组 gid」，喂组名会直接失败，
    # 于是组明明存在也会被报成不存在。查组只能查组数据库。
    if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1 \
       && ! awk -F: -v g="$SERVICE_GROUP" '$1 == g { found = 1 } END { exit !found }' /etc/group 2>/dev/null; then
      note "组 $SERVICE_GROUP 不存在（native 安装会用 groupadd --system --force 创建）"
    fi
    [ "$(id -u "$SERVICE_USER" 2>/dev/null || echo x)" = "0" ] && problem "服务用户是 uid 0（必须以非 root 运行）"
    if [ -d "$DATA_DIR" ]; then
      local data_group=""
      data_group=$(stat -c '%G' "$DATA_DIR" 2>/dev/null || stat -f '%Sg' "$DATA_DIR" 2>/dev/null || echo '?')
      if [ "$data_group" = "$SERVICE_GROUP" ]; then
        log "$DATA_DIR 属组 $data_group ✔"
      else
        problem "$DATA_DIR 属组是 ${data_group}，与 --group $SERVICE_GROUP 不符 → sudo chown -R $SERVICE_USER:$SERVICE_GROUP '$DATA_DIR'"
      fi
    fi
    if [ -f "$UNIT_PATH" ]; then
      log "已安装 $UNIT_PATH"
      if grep -q -- '--host 127.0.0.1' "$UNIT_PATH"; then
        log "unit 绑定 127.0.0.1 ✔（严格回环）"
      else
        problem "unit 未绑定 127.0.0.1（存在对外暴露风险）"
      fi
      grep -Eq '^User=.+' "$UNIT_PATH" || problem "unit 未设置 User=，会以 root 运行"
      have systemctl && systemctl is-active --quiet "$UNIT_NAME.service" && log "服务状态：active"
    else
      verb "未安装 $UNIT_PATH"
    fi
  fi
  if listening_on "$PORT"; then
    warn "端口 $PORT 已在监听 —— 确认它绑在 127.0.0.1 而不是 0.0.0.0"
  else
    verb "端口 $PORT 空闲"
  fi
  if [ "$PROBLEMS" -gt 0 ]; then die "检查发现 $PROBLEMS 项问题（见 FAIL 行）" 1; fi
  log "检查通过（$NOTES 项非致命提示）"
}

# --------------------------------------------------------------------------- main
main() {
  parse_args "$@"
  log "POPOPX Bot Studio · Ubuntu 安装器（mode=$MODE user=$SERVICE_USER app=$APP_DIR data=$DATA_DIR host=$HOST port=$PORT dry-run=${DRY_RUN}）"
  if [ "$MODE_UNINSTALL" -eq 1 ]; then uninstall; return 0; fi
  if [ "$MODE_CHECK" -eq 1 ]; then check_mode; return 0; fi
  if [ "$CLI_REPORT_ONLY" -eq 1 ]; then install_popopx_cli; return 0; fi

  check_layout
  detect_os
  [ "$DRY_RUN" -eq 1 ] && log "[dry-run] 以下是计划动作，本机不会发生任何变更"
  [ "$(id -u)" -eq 0 ] || verb "非 root：特权步骤将通过 sudo 执行"

  apt_install
  detect_python
  create_service_user
  deploy_app_dir
  create_venv
  ensure_env_file
  prepare_state_dirs
  install_popopx_cli
  write_unit
  service_control
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] 结束：未装 apt 包、未建用户、未写 ${UNIT_PATH}、未改 $(dirname "$CLI_BIN")、未下载二进制"
    return 0
  fi
  log "完成。管理后台 http://127.0.0.1:$PORT/ （令牌见 ${ENV_FILE}，权限 600）；"
  log "自检门禁：sudo -u $SERVICE_USER $VENV_PY -m app.main --self-test"
}

main "$@"
