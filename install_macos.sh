#!/usr/bin/env bash
#
# install_macos.sh — POPOPX Bot Studio 一键生产安装（macOS / launchd）
#
# 职责：
#   1. 校验仓库布局与 Python 3.11，按需创建 venv 并安装 studio/requirements.txt；
#   2. 零二进制捆绑：本机缺少 /usr/local/bin/popopx-cli 且未传 --no-node-download 时，
#      探测 OS/arch → 拉 GitHub Releases 最新资产 → 校验 SHA-256 → 安装为
#      /usr/local/bin/popopx-cli（chmod 755）；
#   3. 生成 .env（0600，随机 STUDIO_ADMIN_TOKEN；已存在则绝不静默覆盖）；
#   4. 安装 LaunchDaemon（非 root 运行，plutil -lint 验证）并加载服务。
#
# 硬约束（与 prompt.md 一致）：
#   * Studio 只绑 127.0.0.1；只有显式 --lan 才写 0.0.0.0（同时置 STUDIO_ALLOW_LAN=1）。
#   * 每 Bot 隔离目录 <data_dir>/bots/<bot_id>/cli-data，控制端口 5230..5299，严禁 0.0.0.0。
#   * Bot 进程不由本脚本或 launchd 直接 exec：studio/app/bot_supervisor.py 的
#     render_wrapper_script() 会生成 #!/bin/sh 包装脚本（逐 token shlex.quote），
#     因此 systemd/launchd 的剥引号拆词不会拆坏 `--server "smp1.popopx.im …"`；
#     本脚本引用的真实 argv 与之完全一致：
#       popopx-cli --chat-server-port N --database <prefix> --files-folder D \
#                  --temp-folder D --log-level L [--server "smp1..8"]
#   * SMP 集群默认继承二进制内置的 smp1..8.popopx.im；仅可选 BOT_SMP_SERVERS 覆写，
#     本脚本绝不硬编码另一套集群。
#
# 退出码：0 成功 / 1 致命问题 / 2 参数错误 / 70 执行失败。

# CDPATH= 是刻意的（防止 CDPATH 劫持 cd）；shellcheck 的 SC1007 在此为误报
# shellcheck disable=SC1007
set -euo pipefail

# ------------------------------------------------------------ 默认值（可被旗标覆盖）
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

REPO_DIR="$SCRIPT_DIR"
LABEL="im.popopx.botstudio"
CLI_BIN="/usr/local/bin/popopx-cli"
DATA_DIR=""            # 空 → <repo>/var/studio（app/config.py 的默认）
ENV_FILE=""            # 空 → <repo>/.env
RUN_USER=""            # 空 → 控制台用户（LaunchDaemon 绝不以 root 运行）
RUN_GROUP=""
RUN_HOME=""
PYTHON_BIN=""
PORT="8090"
HOST="127.0.0.1"
LAN=0
DRY_RUN=0
MODE_CHECK=0
MODE_UNINSTALL=0
NO_NODE_DOWNLOAD=0
FORCE_ENV=0
CLI_REPORT_ONLY=0
SKIP_VENV=0
NO_SUDO=0
VERBOSE=0
VENV_DIR=""
VENV_PY=""
PLIST_PATH=""
WORK_DIR=""
PROBLEMS=0
NOTES=0

# CLI 下载源（仅本脚本读取；仓库本身永不含编译产物）
CLI_REPO="${POPOPX_CLI_REPO:-popopx-chat/popopx-chat}"
CLI_VERSION="${POPOPX_CLI_VERSION:-latest}"
CLI_ASSET_URL="${POPOPX_CLI_URL:-}"
CLI_SHA256_PIN="${POPOPX_CLI_SHA256:-}"
GH_API="https://api.github.com"
DEPS="fastapi uvicorn pydantic websockets httpx qrcode cryptography"

# ------------------------------------------------------------------------ 工具函数
have() { command -v "$1" >/dev/null 2>&1; }
ts() { date '+%H:%M:%S'; }
log() { printf '[%s] %s\n' "$(ts)" "$*"; }
warn() { printf '[%s] warn: %s\n' "$(ts)" "$*" >&2; }
verb() { [ "$VERBOSE" -eq 1 ] && printf '[%s]     %s\n' "$(ts)" "$*"; return 0; }
die() { local code="${2:-1}"; printf '[%s] error: %s\n' "$(ts)" "$1" >&2; exit "$code"; }
problem() { printf '[%s] FAIL: %s\n' "$(ts)" "$*" >&2; PROBLEMS=$((PROBLEMS + 1)); }
note() { printf '[%s]  tip: %s\n' "$(ts)" "$*"; NOTES=$((NOTES + 1)); }

# 致命动作：--dry-run 下只打印
run() {
  printf '  + %s\n' "$*"
  [ "$DRY_RUN" -eq 1 ] && return 0
  "$@" || die "命令失败（exit=$?）：$*" 70
}
# 非致命动作：失败仅报告，不中断
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
用法：./install_macos.sh [选项]

POPOPX Bot Studio 的 macOS 生产安装器（launchd LaunchDaemon，默认只绑 127.0.0.1）。

选项：
  -h, --help                显示本帮助并退出 0
  -n, --dry-run             打印全部计划动作与生成的 plist 全文，并用 plutil -lint
                            验证 plist；不写文件、不装服务、不联网下载
      --check               只做诊断（布局/python/依赖/.env 权限/CLI/端口/plist）
      --uninstall           bootout 并删除 LaunchDaemon（保留 .env、数据目录与 CLI）
      --no-node-download    不下载 popopx-cli（缺少二进制时 Studio 离线降级运行）
      --lan                 显式绑定 0.0.0.0 并置 STUDIO_ALLOW_LAN=1（默认 127.0.0.1）
      --force-env           允许覆盖已存在的 .env（默认拒绝覆盖并保留原文件）
      --repo-dir PATH       仓库根（默认：本脚本所在目录）
      --data-dir PATH       STUDIO_DATA_DIR（默认 <repo>/var/studio）
      --user NAME           LaunchDaemon 运行用户（默认当前控制台用户；绝不用 root）
      --group NAME          运行组（默认 NAME 的登录组）
      --port N              Studio 端口（默认 8090）
      --cli-bin PATH        popopx-cli 路径（默认 /usr/local/bin/popopx-cli）
      --label NAME          launchd 标签（默认 im.popopx.botstudio）
      --python PATH         venv 基座 python（默认 python3.11 → python3）
      --skip-venv           跳过 venv 创建与 pip 安装步骤
      --no-sudo           不调用 sudo（配合 --cli-bin 装到用户可写目录，或已是 root）
      --cli-release-report  只解析将要使用的 release 资产与 SHA-256 校验来源，不下载
  -v, --verbose             更多细节

安装脚本级环境变量（不写入 .env）：
  POPOPX_CLI_REPO=popopx-chat/popopx-chat  下载源仓库
  POPOPX_CLI_VERSION=latest|vX.Y.Z          指定 tag
  POPOPX_CLI_URL=https://…                  直接给定资产 URL（跳过 Releases 解析）
  POPOPX_CLI_SHA256=<64hex>                 固定校验值，优先级最高
  GITHUB_TOKEN=…                            私有 fork / 提高限流，只在环境里导出

示例：
  ./install_macos.sh --dry-run
  sudo ./install_macos.sh
  sudo ./install_macos.sh --lan          # 只有确实要对局域网暴露时才用
  sudo ./install_macos.sh --uninstall
USAGE
}

# ------------------------------------------------------------------------ 参数解析
parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -h | --help) usage; exit 0 ;;
      -n | --dry-run) DRY_RUN=1 ;;
      --check) MODE_CHECK=1 ;;
      --uninstall) MODE_UNINSTALL=1 ;;
      --no-node-download) NO_NODE_DOWNLOAD=1 ;;
      --lan) LAN=1 ;;
      --force-env) FORCE_ENV=1 ;;
      --repo-dir) REPO_DIR="${2:?--repo-dir 需要参数}"; shift ;;
      --data-dir) DATA_DIR="${2:?--data-dir 需要参数}"; shift ;;
      --user) RUN_USER="${2:?--user 需要参数}"; shift ;;
      --group) RUN_GROUP="${2:?--group 需要参数}"; shift ;;
      --port) PORT="${2:?--port 需要参数}"; shift ;;
      --cli-bin) CLI_BIN="${2:?--cli-bin 需要参数}"; shift ;;
      --label) LABEL="${2:?--label 需要参数}"; shift ;;
      --python) PYTHON_BIN="${2:?--python 需要参数}"; shift ;;
      --skip-venv) SKIP_VENV=1 ;;
      --no-sudo) NO_SUDO=1 ;;
      --cli-release-report) CLI_REPORT_ONLY=1 ;;
      -v | --verbose) VERBOSE=1 ;;
      *) printf '未知选项：%s（--help 查看用法）\n' "$1" >&2; exit 2 ;;
    esac
    shift
  done

  case "$PORT" in '' | *[!0-9]*) die "--port 必须是数字：$PORT" 2 ;; esac
  [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port 超出 1-65535：$PORT" 2
  REPO_DIR=$(CDPATH= cd -- "$REPO_DIR" 2>/dev/null && pwd -P) || die "--repo-dir 不存在：$REPO_DIR" 2

  [ -n "$DATA_DIR" ] || DATA_DIR="$REPO_DIR/var/studio"
  [ -n "$ENV_FILE" ] || ENV_FILE="$REPO_DIR/.env"
  [ -n "$RUN_USER" ] || RUN_USER="$(default_run_user)"
  [ -n "$RUN_GROUP" ] || RUN_GROUP="$(id -gn "$RUN_USER" 2>/dev/null || echo staff)"
  RUN_HOME=$(dscl . -read "/Users/$RUN_USER" HomeDirectory 2>/dev/null | awk '{print $2}' || true)
  [ -n "$RUN_HOME" ] || RUN_HOME="/Users/$RUN_USER"
  if [ "$LAN" -eq 1 ]; then HOST="0.0.0.0"; else HOST="127.0.0.1"; fi

  VENV_DIR="$REPO_DIR/.venv"
  VENV_PY="$VENV_DIR/bin/python3"
  PLIST_PATH="/Library/LaunchDaemons/${LABEL}.plist"
  WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/popopx-studio.XXXXXX")
  trap 'rm -rf "$WORK_DIR"' EXIT
}

default_run_user() {
  local u=""
  if have stat; then u="$(stat -f '%Su' /dev/console 2>/dev/null || true)"; fi
  if [ -z "$u" ] || [ "$u" = "root" ]; then u="${SUDO_USER:-$(id -un)}"; fi
  [ "$u" = "root" ] && u="$(id -un)"
  printf '%s\n' "$u"
}

# -------------------------------------------------------------- 仓库布局与 python
check_layout() {
  log "校验仓库布局：$REPO_DIR"
  [ -f "$REPO_DIR/studio/app/main.py" ] || problem "缺少 studio/app/main.py（--repo-dir 指错了？）"
  [ -f "$REPO_DIR/studio/app/config.py" ] || problem "缺少 studio/app/config.py"
  [ -f "$REPO_DIR/studio/requirements.txt" ] || problem "缺少 studio/requirements.txt"
  [ -d "$REPO_DIR/studio/static" ] || problem "缺少 studio/static（Web 管理后台）"
  [ -f "$REPO_DIR/LICENSE" ] || note "仓库根缺少 AGPL-3.0-only LICENSE"
  find "$REPO_DIR" -maxdepth 3 -type f -size +20M \
    \( -name 'popopx-cli*' -o -name 'simplex-chat*' \) 2>/dev/null | grep -q . &&
    problem "仓库内发现了疑似 CLI 编译产物，违反零二进制捆绑，请先移除"
  [ "$PROBLEMS" -eq 0 ] || die "仓库布局不完整（见 FAIL 行）" 1
}

# --------------------------------------------- 内置 Needle 3 权重的 SHA-256 完整性门禁
NEEDLE_DIR_REL="studio/assets/models"
NEEDLE_WEIGHT_MAX=$((50 * 1024 * 1024))

needle_python() {
  # 校验器只用标准库，venv 未就绪时也要能跑，否则装到一半就卡在权重检查上。
  if [ -x "$VENV_PY" ]; then printf '%s\n' "$VENV_PY"; else printf '%s\n' "$PYTHON_BIN"; fi
}

verify_needle_weights() {
  local dir="$REPO_DIR/$NEEDLE_DIR_REL"
  local manifest="$dir/needle3.manifest.json"
  local weight="$dir/needle3.cact"
  local verifier="$REPO_DIR/official_tools/verify_needle_assets.py"

  log "校验内置 Needle 3 权重（SHA-256，离线只读）"
  [ -f "$manifest" ] || problem "缺少 ${manifest}：运行期无法校验权重完整性"
  [ -f "$weight" ] || problem "缺少 ${weight}：裁定要求权重随仓库内置，零外网下载"
  [ -f "$dir/LICENSE-needle3.txt" ] || problem "缺少 Needle 3 许可文本 ${dir}/LICENSE-needle3.txt"
  [ -f "$verifier" ] || problem "缺少校验器 ${verifier}"
  [ "$PROBLEMS" -eq 0 ] || return 1

  local size
  size=$(stat -f '%z' "$weight" 2>/dev/null || echo 0)
  case "$size" in ('' | *[!0-9]) size=0 ;; esac
  if [ "$size" -gt "$NEEDLE_WEIGHT_MAX" ]; then
    problem "内置权重 ${size} 字节超过裁定上限 ${NEEDLE_WEIGHT_MAX}（<50MB）"
    return 1
  fi
  local py
  py="$(needle_python)"
  if [ ! -x "$py" ] && ! have "$py"; then
    note "无可用 python，跳过 SHA-256 复核（文件存在性与字节数已检查）"
    return 0
  fi
  local out rc=0
  out="$("$py" "$verifier" --dir "$dir" 2>&1)" || rc=$?
  if [ "$VERBOSE" -eq 1 ]; then printf '%s\n' "$out" | sed 's/^/      | /'; fi
  if [ "$rc" -ne 0 ]; then
    printf '%s\n' "$out" | grep -E 'FAIL|结论|清单|缺少' | head -5 >&2
    problem "内置权重未通过 SHA-256 校验（退出码 ${rc}）：请重新内置 needle3.cact，勿手改清单"
    return 1
  fi
  log "内置权重就绪：${weight}（${size} 字节）—— 启动即可用，无需下载模型"
  return 0
}

detect_python() {
  if [ -n "$PYTHON_BIN" ]; then
    { have "$PYTHON_BIN" || [ -x "$PYTHON_BIN" ]; } || die "--python 不可执行：$PYTHON_BIN" 1
  else
    local c
    for c in python3.11 /opt/homebrew/bin/python3.11 /usr/local/bin/python3.11 python3 /usr/bin/python3; do
      if have "$c" || [ -x "$c" ]; then PYTHON_BIN="$c"; break; fi
    done
  fi
  [ -n "$PYTHON_BIN" ] || die "未找到 python3（brew install python@3.11）" 1
  local ver
  ver="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo unknown)"
  if [ "$ver" = "3.11" ]; then
    log "基座 python：${PYTHON_BIN}（${ver}）"
  else
    note "基座 python 是 ${ver}，Studio 钉住 3.11；可 brew install python@3.11 后用 --python 指定"
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

create_venv() {
  if [ "$SKIP_VENV" -eq 1 ]; then verb "--skip-venv：跳过虚拟环境"; return 0; fi
  if venv_ready; then
    log "venv 已存在：${VENV_DIR}（$("$VENV_PY" -V 2>&1)）—— 跳过创建（幂等）"
  else
    log "创建虚拟环境 $VENV_DIR"
    run "$PYTHON_BIN" -m venv "$VENV_DIR"
  fi
  if deps_present "$VENV_PY"; then
    log "依赖齐备，跳过 pip install（幂等）"
  else
    log "安装依赖：studio/requirements.txt"
    run "$VENV_PY" -m pip install --disable-pip-version-check --upgrade pip wheel
    run "$VENV_PY" -m pip install --disable-pip-version-check -r "$REPO_DIR/studio/requirements.txt"
  fi
  if [ "$(id -u)" -ne 0 ] && [ "$NO_SUDO" -eq 0 ]; then
    as_root_ok chown -R "$RUN_USER:$RUN_GROUP" "$REPO_DIR/.venv" || true
  fi
}

# ------------------------------------------------------------------------------ .env
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
    log "生成 ${ENV_FILE}（随机 STUDIO_ADMIN_TOKEN）"
  fi
  local tmp="$WORK_DIR/env"
  {
    printf '# POPOPX Bot Studio — install_macos.sh 生成于 %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf '# 权限必须保持 0600：app/config.py 会对 .env / studio.state.json / studio.key 做权限检查\n'
    printf 'STUDIO_HOST=%s\n' "$HOST"
    printf 'STUDIO_PORT=%s\n' "$PORT"
    printf 'STUDIO_ALLOW_LAN=%s\n' "$([ "$LAN" -eq 1 ] && echo 1 || echo 0)"
    printf 'STUDIO_ADMIN_TOKEN=%s\n' "$(random_token)"
    printf 'STUDIO_DATA_DIR=%s\n' "$DATA_DIR"
    printf 'STUDIO_ENV_FILE=%s\n' "$ENV_FILE"
    printf 'CLI_BIN_PATH=%s\n' "$CLI_BIN"
    printf 'BOT_WS_PORT_BASE=5230\nBOT_WS_PORT_MAX=5299\n'
    printf '# 留空 = 继承 popopx-cli 内置 smp1..8.popopx.im 双栈集群；仅在自建中继时覆写\nBOT_SMP_SERVERS=\n'
    printf 'STUDIO_LOCALE=en\n'
  } >"$tmp"
  local -a own=()
  [ "$(id -u)" -eq 0 ] && own=(-o "$RUN_USER" -g "$RUN_GROUP")
  as_root install -m 600 ${own[@]+"${own[@]}"} "$tmp" "$ENV_FILE"
}

prepare_state_dirs() {
  log "准备数据目录 ${DATA_DIR}（0700，bots/ 下每 Bot 独立 cli-data）"
  run mkdir -p "$DATA_DIR/bots" "$DATA_DIR/backups"
  run chmod 700 "$DATA_DIR" "$DATA_DIR/bots" "$DATA_DIR/backups"
  as_root_ok chown -R "$RUN_USER:$RUN_GROUP" "$DATA_DIR" || true
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

# 可选探测：存在就用，不存在就算了（旁挂 .sha256 之类）
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
  # latest 取不到（无 latest 标记 / 仓库私有 / 404）时回退 releases 列表，
  # 由 pick_asset 挑第一个非 draft 非 prerelease。
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

# 输出机器可读行：TAG / ASSET / CHOSEN / SIDECAR / AGGREGATE / ERROR
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

# 资产名并非字面 “popopx-cli”：按 品牌前缀 + 平台 + 架构 + 裸可执行 四个条件匹配
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
  log "匹配规则：^popopx[-_.]?(chat|cli) 前缀 + 平台($OS_KIND) + 架构($ARCH_KIND) + 排除 .deb/.dmg/.zip/AppImage/desktop"
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
      log "[dry-run] 计划：下载裸二进制 → 计算 SHA-256 → 与「旁挂 .sha256 / 汇总 _sha256sums / API asset digest / POPOPX_CLI_SHA256」之一比对 → 通过才 install -m 755 到 $CLI_BIN"
      log "[dry-run] 计划：三者皆无且无固定值时 → 拒绝安装（绝不静默跳过校验）"
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

  # --- 下载裸二进制（先取校验基准文件，再取二进制本身）
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

  # --- 校验基准来源，优先级固定；找不到就拒绝安装，绝不静默跳过
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
  if [ "$OS_KIND" = "macos" ]; then
    as_root_ok xattr -d com.apple.quarantine "$CLI_BIN" || true
    if ! as_root_ok codesign --verify --quiet "$CLI_BIN"; then
      note "codesign --verify 未通过（或未授权）；Apple Silicon 上若报 'killed: 9'，执行：sudo codesign --force --sign - $CLI_BIN"
    fi
  fi
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

# ------------------------------------------------------------------- LaunchDaemon
render_plist() {
  local out="$1"
  cat >"$out" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!--
  POPOPX Bot Studio — LaunchDaemon（install_macos.sh 生成；重跑安装会覆盖，请勿手工编辑）
  * 非 root 运行：UserName=$RUN_USER / GroupName=$RUN_GROUP
  * 只绑 ${HOST}（默认 127.0.0.1；仅 --lan 才会写 0.0.0.0 且同时置 STUDIO_ALLOW_LAN=1）
  * STUDIO_ADMIN_TOKEN 不在本文件（plist 全局可读 0644），只存在于 0600 的 $ENV_FILE
  * 参数全部来自 app/main.py::build_parser 真实存在的旗标：--serve --host --port --data-dir --env-file
  * Bot 的 popopx-cli 进程由 Studio 生成的 #!/bin/sh 包装脚本 <data_dir>/bots/<bot_id>/run-cli.sh 启动，
    逐 token 加引号，因此 launchd 剥引号拆词也不会拆坏 --server "smp1.popopx.im … smp8.popopx.im"。
-->
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$VENV_PY</string>
    <string>-m</string>
    <string>app.main</string>
    <string>--serve</string>
    <string>--host</string><string>$HOST</string>
    <string>--port</string><string>$PORT</string>
    <string>--data-dir</string><string>$DATA_DIR</string>
    <string>--env-file</string><string>$ENV_FILE</string>
  </array>
  <key>WorkingDirectory</key><string>$REPO_DIR/studio</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>HOME</key><string>$RUN_HOME</string>
    <key>STUDIO_HOST</key><string>$HOST</string>
    <key>STUDIO_PORT</key><string>$PORT</string>
    <key>STUDIO_ALLOW_LAN</key><string>$([ "$LAN" -eq 1 ] && echo 1 || echo 0)</string>
    <key>STUDIO_DATA_DIR</key><string>$DATA_DIR</string>
    <key>STUDIO_ENV_FILE</key><string>$ENV_FILE</string>
    <key>CLI_BIN_PATH</key><string>$CLI_BIN</string>
    <key>BOT_WS_PORT_BASE</key><string>5230</string>
    <key>BOT_WS_PORT_MAX</key><string>5299</string>
  </dict>
  <key>UserName</key><string>$RUN_USER</string>
  <key>GroupName</key><string>$RUN_GROUP</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key><false/>
    <key>Crashed</key><true/>
  </dict>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Daemon</string>
  <key>SoftResourceLimits</key><dict><key>NumberOfFiles</key><integer>65536</integer></dict>
  <key>StandardOutPath</key><string>$DATA_DIR/launchd.out.log</string>
  <key>StandardErrorPath</key><string>$DATA_DIR/launchd.err.log</string>
</dict>
</plist>
PLIST
}

write_plist() {
  local gen="$WORK_DIR/$LABEL.plist"
  render_plist "$gen"
  if have plutil; then
    if plutil -lint "$gen" >"$WORK_DIR/lint.txt" 2>&1; then
      log "plutil -lint：$(cat "$WORK_DIR/lint.txt")"
    else
      cat "$WORK_DIR/lint.txt" >&2
      die "plist 未通过 plutil -lint，拒绝安装" 1
    fi
  else
    note "本机没有 plutil，跳过 plist 语法验证"
  fi
  log "安装 LaunchDaemon → ${PLIST_PATH}（root:wheel 0644，进程以 $RUN_USER 身份运行）"
  local -a pown=()
  [ "$(id -u)" -eq 0 ] && pown=(-o root -g wheel)
  as_root mkdir -p /Library/LaunchDaemons
  as_root install -m 644 ${pown[@]+"${pown[@]}"} "$gen" "$PLIST_PATH"
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] plist 全文："
    sed 's/^/      | /' "$gen"
    log "[dry-run] 计划：install -m 644 -o root -g wheel → $PLIST_PATH"
  fi
}

load_service() {
  local target="system/$LABEL"
  as_root_ok launchctl bootout "$target" || true
  as_root_ok launchctl enable "$target" || true
  run launchctl bootstrap system "$PLIST_PATH"
  run_ok launchctl kickstart -k "$target" || note "kickstart 未成功，稍后可：sudo launchctl kickstart -k $target"
  log "服务已加载：http://$HOST:$PORT/ （管理后台；健康检查 /healthz）"
}

uninstall() {
  log "卸载 LaunchDaemon $LABEL"
  as_root_ok launchctl bootout "system/$LABEL" || true
  as_root_ok launchctl remove "$LABEL" || true
  if [ -f "$PLIST_PATH" ]; then
    as_root rm -f "$PLIST_PATH"
  else
    verb "无 ${PLIST_PATH}，跳过"
  fi
  note "默认保留 $ENV_FILE 与 ${DATA_DIR}（SQLite 账本 + 各 Bot 的 cli-data 密钥）。"
  note "彻底清场请自行执行：sudo rm -rf '$DATA_DIR' && rm -f '$ENV_FILE'"
  note "未删除 ${CLI_BIN}（可能被其它项目共用）；如需移除：sudo rm -f '$CLI_BIN'"
  log "卸载完成"
}

port_in_use() {
  have lsof || return 1
  lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1
}

check_mode() {
  log "只诊断模式（不改动任何内容）"
  check_layout
  detect_python
  verify_needle_weights || true
  if venv_ready; then
    log "venv：${VENV_PY}（$("$VENV_PY" -V 2>&1)）"
    if deps_present "$VENV_PY"; then log "requirements.txt 依赖齐备"; else note "依赖不全：$DEPS"; fi
  else
    note "缺少 $VENV_DIR —— 去掉 --check 运行安装即可创建"
  fi
  if [ -f "$ENV_FILE" ]; then
    local mode
    mode=$(stat -f '%OLp' "$ENV_FILE" 2>/dev/null || echo '?')
    case "$mode" in
      600 | 400) log "$ENV_FILE 权限 0$mode ✔（config.py 要求 0600）" ;;
      *) problem "$ENV_FILE 权限 0$mode 宽于 0600：chmod 600 '$ENV_FILE'" ;;
    esac
    if grep -q '^STUDIO_ADMIN_TOKEN=[^=]' "$ENV_FILE"; then
      log "已配置 STUDIO_ADMIN_TOKEN"
    else
      note "$ENV_FILE 未设置 STUDIO_ADMIN_TOKEN（管理路由将全部 401）"
    fi
    grep -qE '^STUDIO_ALLOW_LAN=(1|true|yes|on)' "$ENV_FILE" &&
      warn "$ENV_FILE 里 STUDIO_ALLOW_LAN 已开启（非回环暴露）"
  else
    note "尚无 ${ENV_FILE}（安装器或 start_macos.sh 会生成随机令牌并 chmod 600）"
  fi
  if [ -x "$CLI_BIN" ]; then log "$CLI_BIN ✔"; else note "缺少 ${CLI_BIN}：Studio 将以离线降级模式运行"; fi
  if port_in_use; then note "端口 $PORT 已被监听（Studio 可能已在运行）"; else verb "端口 $PORT 空闲"; fi
  if [ -f "$PLIST_PATH" ]; then
    log "已安装 $PLIST_PATH"
    have plutil && plutil -lint "$PLIST_PATH" >/dev/null && log "plutil -lint：OK"
    if grep -q '<string>127.0.0.1</string>' "$PLIST_PATH"; then
      log "plist 绑定 127.0.0.1 ✔（严格回环）"
    else
      warn "plist 未绑定 127.0.0.1 —— 可能曾以 --lan 安装"
    fi
    if grep -q '<key>UserName</key>' "$PLIST_PATH"; then
      log "plist 指定 UserName（非 root）✔"
    else
      problem "plist 缺少 UserName，LaunchDaemon 会以 root 运行"
    fi
    if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
      log "服务状态：已加载"
    else
      note "服务未加载"
    fi
  else
    verb "未安装 $PLIST_PATH"
  fi
  if [ "$PROBLEMS" -gt 0 ]; then die "检查发现 $PROBLEMS 项问题（见 FAIL 行）" 1; fi
  log "检查通过（$NOTES 项非致命提示）"
}

# -------------------------------------------------------------------------- main
main() {
  parse_args "$@"
  log "POPOPX Bot Studio · macOS 安装器（label=$LABEL user=$RUN_USER host=$HOST port=$PORT dry-run=${DRY_RUN}）"
  if [ "$MODE_UNINSTALL" -eq 1 ]; then uninstall; return 0; fi
  if [ "$MODE_CHECK" -eq 1 ]; then check_mode; return 0; fi
  if [ "$CLI_REPORT_ONLY" -eq 1 ]; then install_popopx_cli; return 0; fi

  check_layout
  detect_python
  verify_needle_weights || die "内置 Needle 3 权重不可用，终止安装（见 FAIL 行）" 1
  if [ "$LAN" -eq 1 ]; then
    warn "--lan：将绑定 0.0.0.0 并置 STUDIO_ALLOW_LAN=1 —— 管理后台与 Open API 会暴露到局域网，"
    warn "      请叠加反向代理 + TLS + 防火墙。Bot 控制端口（5230..5299）仍只绑 127.0.0.1。"
  fi
  [ "$DRY_RUN" -eq 1 ] && log "[dry-run] 以下是计划动作，本机不会发生任何变更"
  [ "$(id -u)" -eq 0 ] || verb "非 root：特权步骤将通过 sudo 执行"

  create_venv
  ensure_env_file
  prepare_state_dirs
  install_popopx_cli
  write_plist
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] 计划：launchctl bootout/bootstrap system/$LABEL + kickstart -k"
    log "[dry-run] 结束：未写 ${PLIST_PATH}、未建服务、未改动 $(dirname "$CLI_BIN")、未下载二进制"
    return 0
  fi
  load_service
  log "完成。打开 http://$HOST:$PORT/ （令牌见 ${ENV_FILE}，权限 600）；"
  log "自检门禁：cd studio && .venv 内的 python -m app.main --self-test"
}

main "$@"
