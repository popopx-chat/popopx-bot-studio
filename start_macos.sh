#!/usr/bin/env bash
#
# start_macos.sh — POPOPX Bot Studio 日常开发启动器（macOS）
#
# 做的事（全部幂等、非交互）：
#   1. 定位 python（--python > $POPOPX_PYTHON > python3.11 > 仓库 .venv > python3）；
#   2. 缺 .venv 就建（venv 根 = 仓库根，已在 .gitignore 里）；
#   3. 只有当 fastapi/uvicorn/pydantic/websockets/httpx/qrcode/cryptography 有缺时
#      才执行 pip install -r studio/requirements.txt；装不上则拒绝启动并给出指令；
#   4. 缺 .env 就生成随机 STUDIO_ADMIN_TOKEN 并 chmod 600（已存在绝不覆盖）；
#   5. cd studio && exec .venv/bin/python -m app.main …（默认只绑 127.0.0.1:8090）。
#
# 只使用 app/main.py::build_parser 里真实存在的旗标：
#   --serve --host --port --data-dir --env-file --token --check --self-test --group --version
#
# 严格回环：默认 --host 127.0.0.1；--lan 是唯一显式逃生门（同时导出 STUDIO_ALLOW_LAN=1，
# 仅作用于本次子进程，不写进 .env）。Bot 的 popopx-cli 控制端口（5230..5299）与
# 每 Bot 隔离目录 <data_dir>/bots/<bot_id>/cli-data 由 studio/app/bot_supervisor.py 负责，
# 本脚本不碰；SMP 集群默认继承二进制内置 smp1..8.popopx.im，仅 BOT_SMP_SERVERS 可覆写。

# CDPATH= 是刻意的（防止 CDPATH 劫持 cd）；shellcheck 的 SC1007 在此为误报
# shellcheck disable=SC1007
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_DIR="$SCRIPT_DIR"
STUDIO_DIR="$REPO_DIR/studio"
VENV_DIR="$REPO_DIR/.venv"
ENV_FILE="$REPO_DIR/.env"
DATA_DIR=""
HOST="127.0.0.1"
PORT="8090"
PY_FLAG=""
EXTRA_ARGS=()
ACTION="serve"
LAN=0
SKIP_INSTALL=0
VERBOSE=0
DEPS="fastapi uvicorn pydantic websockets httpx qrcode cryptography"

have() { command -v "$1" >/dev/null 2>&1; }
log() { printf '[start] %s\n' "$*"; }
warn() { printf '[start] warn: %s\n' "$*" >&2; }
verb() { [ "$VERBOSE" -eq 1 ] && printf '[start]     %s\n' "$*"; return 0; }
die() { printf '[start] error: %s\n' "$1" >&2; [ "$#" -gt 1 ] && exit "$2" || exit 1; }

usage() {
  cat <<'USAGE'
用法：./start_macos.sh [选项] [-- 追加 app.main 的旗标]

POPOPX Bot Studio 的 macOS 日常启动器：自动建 .venv、按需装依赖、生成
随机 STUDIO_ADMIN_TOKEN 写入 .env（0600），然后在 127.0.0.1:8090 启动 Studio。

选项：
  -h, --help          显示本帮助并退出 0
      --check         跑 python3 -m app.main --check（只校验配置/权限/依赖，不监听）
      --self-test     跑 python3 -m app.main --self-test（全量自检门禁）
      --group NAME    配合 --self-test，只跑指定分组（可重复）
      --port N        监听端口（默认 8090）
      --host ADDR     监听地址（默认 127.0.0.1）
      --lan           等价于 --host 0.0.0.0，并只为本次进程导出 STUDIO_ALLOW_LAN=1
      --data-dir PATH 覆盖 STUDIO_DATA_DIR（默认 <repo>/var/studio）
      --env-file PATH 指定 .env（默认 <repo>/.env）
      --venv PATH     虚拟环境目录（默认 <repo>/.venv）
      --python PATH   建 venv 用的基座 python（默认 python3.11 → python3）
      --skip-install  依赖不全时也不 pip install，直接拒绝并给出指令
      --token TOKEN   本次进程临时覆盖 STUDIO_ADMIN_TOKEN（不落盘）
      --no-token      .env 已存在但无令牌时也不要生成（管理路由将全部 401）
  -v, --verbose       更多细节

环境变量：
  POPOPX_PYTHON=…     同 --python
  BOT_SMP_SERVERS=…   透传给子进程（留空 = 继承 CLI 内置 smp1..8.popopx.im）

示例：
  ./start_macos.sh                      # 建环境 + 起服务（http://127.0.0.1:8090/）
  ./start_macos.sh --self-test          # 自检门禁
  ./start_macos.sh --check --port 8091
USAGE
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -h | --help) usage; exit 0 ;;
      --check) ACTION="check" ;;
      --self-test) ACTION="self-test" ;;
      --group) EXTRA_ARGS+=(--group "${2:?--group 需要参数}"); shift ;;
      --port) PORT="${2:?--port 需要参数}"; shift ;;
      --host) HOST="${2:?--host 需要参数}"; shift ;;
      --lan) LAN=1; HOST="0.0.0.0" ;;
      --data-dir) DATA_DIR="${2:?--data-dir 需要参数}"; shift ;;
      --env-file) ENV_FILE="${2:?--env-file 需要参数}"; shift ;;
      --venv) VENV_DIR="${2:?--venv 需要参数}"; shift ;;
      --python) PY_FLAG="${2:?--python 需要参数}"; shift ;;
      --skip-install) SKIP_INSTALL=1 ;;
      --token) EXTRA_ARGS+=(--token "${2:?--token 需要参数}"); shift ;;
      --no-token) NO_TOKEN=1 ;;
      -v | --verbose) VERBOSE=1 ;;
      --) shift; break ;;
      *) printf '未知选项：%s（--help 查看用法）\n' "$1" >&2; exit 2 ;;
    esac
    shift
  done
  NO_TOKEN="${NO_TOKEN:-0}"
  while [ "$#" -gt 0 ]; do EXTRA_ARGS+=("$1"); shift; done
  case "$PORT" in '' | *[!0-9]*) die "--port 必须是数字：$PORT" 2 ;; esac
  [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port 超出 1-65535：$PORT" 2
  [ -d "$STUDIO_DIR" ] || die "找不到 ${STUDIO_DIR}（--help 里的 --env-file/--venv 也解决不了布局问题）" 1
  [ -f "$STUDIO_DIR/requirements.txt" ] || die "缺少 $STUDIO_DIR/requirements.txt" 1
  [ -n "$DATA_DIR" ] || DATA_DIR="$REPO_DIR/var/studio"
  VENV_PY="$VENV_DIR/bin/python3"
}

# ------------------------------------------------------------------ python 定位
find_base_python() {
  local c
  if [ -n "$PY_FLAG" ]; then
    { have "$PY_FLAG" || [ -x "$PY_FLAG" ]; } || die "--python 不可执行：$PY_FLAG" 1
    printf '%s\n' "$PY_FLAG"; return 0
  fi
  if [ -n "${POPOPX_PYTHON:-}" ]; then
    { have "$POPOPX_PYTHON" || [ -x "$POPOPX_PYTHON" ]; } || die "POPOPX_PYTHON 不可执行：$POPOPX_PYTHON" 1
    printf '%s\n' "$POPOPX_PYTHON"; return 0
  fi
  if [ -x "$VENV_PY" ]; then printf '%s\n' "$VENV_PY"; return 0; fi
  for c in python3.11 /opt/homebrew/bin/python3.11 /usr/local/bin/python3.11 python3 /usr/bin/python3; do
    if have "$c" || [ -x "$c" ]; then printf '%s\n' "$c"; return 0; fi
  done
  die "未找到 python3。安装方式：brew install python@3.11（或用 --python 指定解释器）" 1
}

ensure_venv() {
  if [ -x "$VENV_PY" ]; then
    verb "venv：${VENV_PY}（$("$VENV_PY" -V 2>&1)）"
    return 0
  fi
  local base
  base="$(find_base_python)"
  log "创建虚拟环境 ${VENV_DIR}（基座 ${base}）"
  "$base" -m venv "$VENV_DIR" || die "venv 创建失败：$base -m venv $VENV_DIR" 1
}

deps_missing() {
  local py="$1" m out=()
  [ -x "$py" ] || { printf '%s\n' "$DEPS"; return 0; }
  for m in $DEPS; do
    "$py" -c "import $m" >/dev/null 2>&1 || out+=("$m")
  done
  [ "${#out[@]}" -gt 0 ] || return 1
  printf '%s\n' "${out[*]}"
}

install_deps() {
  local py="$1" missing
  missing="$(deps_missing "$py" || true)"
  if [ -z "$missing" ]; then
    verb "依赖齐备（${DEPS}）—— 跳过 pip install"
    return 0
  fi
  log "缺失依赖：$missing"
  if [ "$SKIP_INSTALL" -eq 1 ]; then
    die "已指定 --skip-install。请手工执行：
       $py -m pip install -r '$STUDIO_DIR/requirements.txt'" 1
  fi
  log "安装依赖：pip install -r studio/requirements.txt"
  "$py" -m pip install --disable-pip-version-check --upgrade pip wheel ||
    warn "升级 pip 失败，继续安装 requirements"
  "$py" -m pip install --disable-pip-version-check -r "$STUDIO_DIR/requirements.txt" ||
    die "pip install 失败。离线机器可用镜像：
       $py -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r '$STUDIO_DIR/requirements.txt'
       或先 export PIP_INDEX_URL=<你的内网源>" 1
  missing="$(deps_missing "$py" || true)"
  [ -z "$missing" ] || die "装完仍缺：${missing}（venv 或 requirements 与环境不匹配）" 1
}

random_token() {
  if have openssl; then openssl rand -hex 32; return 0; fi
  "$VENV_PY" -c 'import secrets; print(secrets.token_hex(32))' 2>/dev/null ||
    "$VENV_PY" -c 'import os; print(os.urandom(32).hex())'
}

ensure_env() {
  if [ -f "$ENV_FILE" ]; then
    if grep -qE '^\s*STUDIO_ADMIN_TOKEN\s*=\s*\S' "$ENV_FILE"; then
      verb "沿用已有 ${ENV_FILE}（不覆盖）"
    elif [ "$NO_TOKEN" -eq 1 ]; then
      warn "$ENV_FILE 没有 STUDIO_ADMIN_TOKEN 且 --no-token：所有管理路由将返回 401"
    else
      log "向已存在的 $ENV_FILE 追加随机 STUDIO_ADMIN_TOKEN（不覆盖既有内容）"
      printf '\n# 由 start_macos.sh 追加\nSTUDIO_ADMIN_TOKEN=%s\n' "$(random_token)" >>"$ENV_FILE"
    fi
    run_perm
    return 0
  fi
  log "生成 ${ENV_FILE}（随机 STUDIO_ADMIN_TOKEN，权限 0600）"
  umask 077
  {
    printf '# POPOPX Bot Studio — start_macos.sh 生成于 %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf '# 权限必须保持 0600（app/config.py 会检查并告警）\n'
    printf 'STUDIO_HOST=%s\n' "$HOST"
    printf 'STUDIO_PORT=%s\n' "$PORT"
    printf 'STUDIO_ADMIN_TOKEN=%s\n' "$(random_token)"
    printf 'STUDIO_DATA_DIR=%s\n' "$DATA_DIR"
    printf 'CLI_BIN_PATH=/usr/local/bin/popopx-cli\n'
    printf 'BOT_WS_PORT_BASE=5230\nBOT_WS_PORT_MAX=5299\n'
    printf '# 留空 = 继承 CLI 内置 smp1..8.popopx.im 双栈集群\nBOT_SMP_SERVERS=\n'
    # 与 app/config.py 的默认语种保持一致（管理后台支持 18 语种，可自行改 zh-Hans 等）
    printf 'STUDIO_LOCALE=en\n'
  } >"$ENV_FILE"
  chmod 600 "$ENV_FILE"
}

run_perm() {
  local mode
  mode=$(stat -f '%OLp' "$ENV_FILE" 2>/dev/null || stat -c '%a' "$ENV_FILE" 2>/dev/null || echo '?')
  case "$mode" in
    600 | 400) verb "$ENV_FILE 权限 $mode ✔" ;;
    *) warn "$ENV_FILE 权限 $mode 宽于 0600（config.py 会告警）：chmod 600 '$ENV_FILE'"
       chmod 600 "$ENV_FILE" 2>/dev/null || warn "无法修正权限，请手工执行 chmod 600 '$ENV_FILE'" ;;
  esac
}

prepare_data_dir() {
  mkdir -p "$DATA_DIR/bots" "$DATA_DIR/backups"
  chmod 700 "$DATA_DIR" "$DATA_DIR/bots" "$DATA_DIR/backups" 2>/dev/null ||
    warn "数据目录权限未能收紧到 0700：$DATA_DIR"
}

port_busy() {
  have lsof || return 1
  lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1
}

# -------------------------------------------------------------------------- main
main() {
  parse_args "$@"
  log "POPOPX Bot Studio · macOS 启动器（repo=${REPO_DIR##*/} action=$ACTION host=$HOST port=${PORT}）"
  ensure_venv
  install_deps "$VENV_PY"
  # 只有真要起服务时才需要管理员令牌；--check / --self-test 是离线门禁，
  # 不应该为了跑测试而在仓库里造一个 .env（自检里「缺少令牌时给出警告」这类
  # 断言依赖干净环境）。
  if [ "$ACTION" = "serve" ]; then
    ensure_env
  fi
  prepare_data_dir

  if [ "$LAN" -eq 1 ]; then
    export STUDIO_ALLOW_LAN=1
    warn "--lan：本次进程将绑定 0.0.0.0（STUDIO_ALLOW_LAN=1 只影响本次，不写入 .env）。"
  fi

  # 只传 app/main.py 里存在的旗标
  local -a cmd=("$VENV_PY" -m app.main)
  case "$ACTION" in
    serve) cmd+=(--serve --host "$HOST" --port "$PORT" --data-dir "$DATA_DIR" --env-file "$ENV_FILE") ;;
    check) cmd+=(--check --data-dir "$DATA_DIR") ;;
    self-test) cmd+=(--self-test --data-dir "$DATA_DIR") ;;
  esac
  if [ "${#EXTRA_ARGS[@]}" -gt 0 ]; then cmd+=("${EXTRA_ARGS[@]}"); fi

  if [ "$ACTION" = "serve" ] && port_busy; then
    warn "端口 $PORT 已被占用，Studio 很可能已在运行：http://$HOST:$PORT/"
    die "先停掉已有实例，或用 --port 换一个端口" 1
  fi

  if [ ! -f "$STUDIO_DIR/app/main.py" ]; then
    die "缺少 $STUDIO_DIR/app/main.py（仓库布局不完整）" 1
  fi

  # 不把 --token 的值回显到终端/日志
  local -a shown=() masked=0 t
  for t in "${cmd[@]}"; do
    if [ "$masked" -eq 1 ]; then shown+=("***"); masked=0; continue; fi
    [ "$t" = "--token" ] && masked=1
    shown+=("$t")
  done
  log "exec: (cd $STUDIO_DIR && ${shown[*]})"
  cd "$STUDIO_DIR"
  exec "${cmd[@]}"
}

main "$@"
