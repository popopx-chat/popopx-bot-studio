"""Bot 生命周期监督器：包装脚本生成、进程编排、协议编排、二维码与冷备。

本模块只在回环地址上控制外部 ``popopx-cli`` 进程：

* 每个 Bot 独占 ``<state_dir>/bots/<bot_id>/cli-data``，数据库前缀、文件目录、
  临时目录与 ``HOME`` 全部指向该目录，Bot 之间不共享任何状态；
* 控制端口从 ``BOT_WS_PORT_BASE``（默认 5230）递增分配，CLI 自身只监听
  127.0.0.1（``runLocalTCPServer``），Studio 绝不向 0.0.0.0 暴露控制通道；
* 启动命令写入 ``#!/bin/sh`` 包装脚本，每个 token 单独 ``shlex.quote``，因此
  ``--server "smp1 … smp8 …"`` 这类带空格参数不会被 systemd/launchd 的
  ``ExecStart`` 解析剥引号拆词；默认不传 ``--server``，继承二进制内置的
  ``smp1..8.popopx.im`` 双栈集群，可用 ``smp_servers`` / ``BOT_SMP_SERVERS`` 覆写；
* 监督循环捕获 ``WebSocketException`` / ``OSError`` 并指数退避重连，单个 Bot 的
  故障绝不会冒泡到网关。
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import io
import json
import os
import re
import shlex
import secrets
import shutil
import signal
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from websockets.exceptions import WebSocketException

from .config import DEFAULT_CLI_BIN_PATH, SECURE_FILE_MODE, Settings
from .i18n import fill_placeholders, normalize_locale, render_welcome
from .database import Database
from .ws_protocol import (
    CLICommandError,
    CLIWebSocketClient,
    Frame,
    ReconnectPolicy,
    WebSocketProtocolError,
    build_address_settings,
    normalize_event,
)

CLI_BIN_NAME = "popopx-cli"
BUILTIN_SMP_SERVERS: Tuple[str, ...] = tuple(f"smp{i}.popopx.im" for i in range(1, 9))
DB_PREFIX_NAME = "bot"
# popopx-chat Options/SQLite.hs:73,87 - the CLI appends this suffix to --database.
CHAT_DB_SUFFIX = "_chat.db"
WRAPPER_NAME = "run-cli.sh"
LOG_NAME = "cli.log"

STOP_GRACE_SECONDS = 10.0
READY_TIMEOUT_SECONDS = 45.0
READY_POLL_INTERVAL = 0.25
HEALTH_INTERVAL_SECONDS = 5.0
CONNECT_BACKOFF_MAX = 60.0
LOG_TAIL_BYTES = 512_000

BUNDLE_MAGIC = b"PBSB"
BUNDLE_VERSION = 1
BUNDLE_FLAG_ENCRYPTED = 0x01
KDF_SALT_LEN = 16
AES_NONCE_LEN = 12
AES_KEY_LEN = 32
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

QR_BOX_SIZE = 16
QR_BORDER = 4
QR_MIN_PIXELS = 900

_SAFE_MEMBER_RE = re.compile(r"^[A-Za-z0-9._/-]{1,160}$")
_CHAT_REF_RE = re.compile(r"^([@#])([1-9][0-9]{0,18})$")

EventHook = Callable[[str, Any], Awaitable[None]]


class BotSupervisorError(RuntimeError):
    """生命周期操作无法完成（缺二进制、端口耗尽、进程未就绪等）。"""


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------


def split_server_list(raw: str) -> List[str]:
    """Split a whitespace separated SMP server list, keeping ``host:port`` intact."""
    return [item for item in re.split(r"[\s,;]+", (raw or "").strip()) if item]


def resolve_cli_binary(settings: Settings) -> Optional[Path]:
    """Locate ``popopx-cli``: the configured path, then PATH, then the install prefix."""
    configured = Path(settings.cli_bin_path).expanduser()
    if configured.is_file() and os.access(str(configured), os.X_OK):
        return configured.resolve()
    found = shutil.which(CLI_BIN_NAME)
    if found:
        return Path(found).resolve()
    fallback = Path(DEFAULT_CLI_BIN_PATH)
    if fallback.is_file() and os.access(str(fallback), os.X_OK):
        return fallback.resolve()
    return None


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class BotPaths:
    """Every on-disk artifact owned by one Bot."""

    root: Path
    cli_data: Path
    db_prefix: Path
    files_dir: Path
    temp_dir: Path
    wrapper: Path
    log_file: Path
    pid_file: Path

    @classmethod
    def for_bot(cls, settings: Settings, bot_id: str) -> "BotPaths":
        root = settings.bots_dir / bot_id
        cli_data = root / "cli-data"
        return cls(
            root=root,
            cli_data=cli_data,
            db_prefix=cli_data / DB_PREFIX_NAME,
            files_dir=root / "files",
            temp_dir=root / "tmp",
            wrapper=root / WRAPPER_NAME,
            log_file=root / LOG_NAME,
            pid_file=root / "cli.pid",
        )

    def create(self) -> "BotPaths":
        self.root.mkdir(parents=True, exist_ok=True)
        for directory in (self.root, self.cli_data, self.files_dir, self.temp_dir):
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)
        return self


def effective_smp_servers(bot: Dict[str, Any], settings: Settings) -> List[str]:
    """Per-Bot ``smp_servers`` first, then Studio-wide ``BOT_SMP_SERVERS``, else built-in."""
    for raw in (str(bot.get("smp_servers") or ""), str(settings.cli_smp_servers or "")):
        servers = split_server_list(raw)
        if servers:
            return servers
    return []


def build_cli_argv(
    cli_binary: Path | str,
    port: int,
    paths: BotPaths,
    *,
    smp_servers: Sequence[str] = (),
    log_level: str = "important",
    profile_name: str = "",
) -> List[str]:
    """The exact argv used both by the wrapper script and by ``exec``."""
    if not 1 <= int(port) <= 65535:
        raise BotSupervisorError(f"非法控制端口 {port!r}")
    argv = [
        str(Path(cli_binary).expanduser()),
        "--chat-server-port",
        str(int(port)),
        "--database",
        str(paths.db_prefix),
        "--files-folder",
        str(paths.files_dir),
        "--temp-folder",
        str(paths.temp_dir),
        "--log-level",
        log_level,
    ]
    if str(profile_name or "").strip():
        argv += ["--user-display-name", str(profile_name).strip()]
    servers = [str(server).strip() for server in smp_servers if str(server).strip()]
    if servers:
        # The CLI documents a single ``--server`` option holding a space-separated
        # quoted list, so the whole list has to survive as one argv token.
        argv += ["--server", " ".join(servers)]
    return argv


def bot_display_name(bot: Dict[str, Any], fallback: str = "") -> str:
    return str(bot.get("display_name") or bot.get("name") or fallback).strip()


def profile_bootstrap_name(paths: BotPaths, display_name: str) -> str:
    """``--user-display-name`` for an empty cli-data directory, else ``""``.

    With no profile yet the CLI asks for a name on stdin, which is DEVNULL for
    a supervised process (``--headless`` would refuse instead but requires
    ``--relay``, popopx-chat Options.hs:361). Passing the name only before the
    database exists is deliberate: once a profile is stored the CLI exits when
    the argument disagrees with it (Core.hs:79-82), so a permanent flag would
    turn "rename this Bot" into "the CLI never starts again".
    """
    name = str(display_name or "").strip()
    if not name:
        return ""
    if Path(f"{paths.db_prefix}{CHAT_DB_SUFFIX}").exists():
        return ""
    return name


def render_wrapper_script(argv: Sequence[str], *, bot_id: str, paths: BotPaths) -> str:
    """Render a ``#!/bin/sh`` launcher that survives quote-stripping supervisors.

    systemd and launchd hand ``ExecStart``/``ProgramArguments`` to their own
    splitter, which drops quotes and breaks ``--server "a b"`` into two
    arguments. A real shell script quoted token-by-token is immune, and
    ``exec`` keeps ``popopx-cli`` as the unit's main process so stop signals
    reach the CLI instead of an intermediate shell.
    """
    if not argv:
        raise BotSupervisorError("包装脚本需要至少一个 argv token")
    body = " \\\n  ".join(shlex.quote(str(token)) for token in argv)
    return (
        "#!/bin/sh\n"
        f"# POPOPX Bot Studio 自动生成 —— Bot {bot_id}，重启服务时会被覆盖，请勿手工编辑。\n"
        "# 参数逐个加引号：即使 systemd/launchd 剥掉外层引号也不会拆词。\n"
        "set -eu\n"
        f"HOME={shlex.quote(str(paths.cli_data))}\n"
        f"TMPDIR={shlex.quote(str(paths.temp_dir))}\n"
        "export HOME TMPDIR\n"
        f"exec {body}\n"
    )


def write_wrapper(paths: BotPaths, text: str) -> Path:
    paths.root.mkdir(parents=True, exist_ok=True)
    paths.wrapper.write_text(text, encoding="utf-8")
    os.chmod(paths.wrapper, 0o755)
    return paths.wrapper


def parse_chat_ref(ref: str | int) -> Tuple[str, int]:
    """``#42`` -> ``("group", 42)``; ``@7`` or ``7`` -> ``("direct", 7)``."""
    if isinstance(ref, int):
        return "direct", ref
    match = _CHAT_REF_RE.match((ref or "").strip())
    if not match:
        raise BotSupervisorError(f"会话引用 {ref!r} 非法，应为 @<contactId> 或 #<groupId>")
    return ("group" if match.group(1) == "#" else "direct"), int(match.group(2))


@dataclass
class BotRuntime:
    """In-memory state of one supervised Bot."""

    bot_id: str
    name: str
    port: int
    paths: BotPaths
    process: Optional[asyncio.subprocess.Process] = None
    client: Optional[CLIWebSocketClient] = None
    argv: List[str] = field(default_factory=list)
    watcher: Optional[asyncio.Task] = None
    state: str = "stopped"
    pid: int = 0
    started_at: float = 0.0
    restarts: int = 0
    reconnects: int = 0
    events: int = 0
    commands: int = 0
    last_error: str = ""
    provisioned: bool = False

    def as_dict(self) -> Dict[str, Any]:
        alive = self.process is not None and self.process.returncode is None
        return {
            "bot_id": self.bot_id,
            "name": self.name,
            "port": self.port,
            "state": self.state,
            "pid": self.pid,
            "running": alive,
            "connected": bool(self.client and self.client.connected),
            "provisioned": self.provisioned,
            "started_at": self.started_at,
            "uptime": max(0.0, time.time() - self.started_at) if alive else 0.0,
            "restarts": self.restarts,
            "reconnects": self.reconnects,
            "events": self.events,
            "commands": self.commands,
            "last_error": self.last_error,
            "cli_data": str(self.paths.cli_data),
            "wrapper": str(self.paths.wrapper),
            "log": str(self.paths.log_file),
        }


class BotSupervisor:
    """Create, launch, provision, watch and back up external CLI Bot processes."""

    def __init__(
        self,
        settings: Settings,
        database: Database,
        *,
        on_event: Optional[EventHook] = None,
        cli_binary: Optional[Path | str] = None,
        health_interval: float = HEALTH_INTERVAL_SECONDS,
        ready_timeout: float = READY_TIMEOUT_SECONDS,
    ):
        self.settings = settings
        self.db = database
        self.on_event = on_event
        self.cli_binary = Path(cli_binary).expanduser() if cli_binary else resolve_cli_binary(settings)
        self.health_interval = max(0.05, float(health_interval))
        self.ready_timeout = max(0.5, float(ready_timeout))
        self.qr_dir = settings.data_dir / "qr"
        self._runtimes: Dict[str, BotRuntime] = {}
        self._lock = asyncio.Lock()
        self._closing = False

    # ------------------------------------------------------------------ paths
    def paths_for(self, bot_id: str) -> BotPaths:
        return BotPaths.for_bot(self.settings, bot_id)

    def require_binary(self) -> Path:
        if self.cli_binary is None:
            self.cli_binary = resolve_cli_binary(self.settings)
        if self.cli_binary is None or not self.cli_binary.is_file():
            raise BotSupervisorError(
                f"未找到 {CLI_BIN_NAME}：请运行 install_ubuntu22.sh / install_macos.sh 下载，"
                "或在 .env 中设置 CLI_BIN_PATH"
            )
        return self.cli_binary

    def runtime(self, bot_id: str) -> Optional[BotRuntime]:
        return self._runtimes.get(bot_id)

    def client_for(self, bot_id: str) -> CLIWebSocketClient:
        runtime = self._runtimes.get(bot_id)
        if runtime is None or runtime.client is None or not runtime.client.connected:
            raise BotSupervisorError(f"Bot {bot_id} 未连接 CLI 控制通道，请先启动该 Bot")
        return runtime.client

    @property
    def clients(self) -> Dict[str, CLIWebSocketClient]:
        return {
            bot_id: runtime.client
            for bot_id, runtime in self._runtimes.items()
            if runtime.client is not None and runtime.client.connected
        }

    def status(self, bot_id: Optional[str] = None) -> Dict[str, Any]:
        if bot_id is not None:
            runtime = self._runtimes.get(bot_id)
            bot = self.db.get_bot(bot_id, include_deleted=True)
            if bot is None:
                raise BotSupervisorError(f"Bot {bot_id} 不存在")
            live = runtime.as_dict() if runtime else {"bot_id": bot_id, "state": "stopped", "port": bot["port"]}
            return {"bot": bot, "runtime": live}
        return {
            "bots": [runtime.as_dict() for runtime in self._runtimes.values()],
            "summary": self.db.bot_summary(),
            "cli_binary": str(self.cli_binary) if self.cli_binary else "",
            "port_base": self.settings.ws_port_base,
            "port_max": self.settings.ws_port_max,
        }

    # --------------------------------------------------------------- factory
    async def create_bot(
        self,
        name: str,
        *,
        display_name: str = "",
        welcome_text: str = "",
        auto_accept: bool = True,
        accept_incognito: bool = False,
        smp_servers: str = "",
        default_locale: str = "",
        start: bool = True,
    ) -> Dict[str, Any]:
        """Create the ledger row, then (optionally) launch the CLI and provision it."""
        if accept_incognito and not auto_accept:
            raise BotSupervisorError("accept_incognito 需要同时开启 auto_accept")
        if self.db.get_bot_by_name(name) is not None:
            raise BotSupervisorError(f"Bot 名称 {name!r} 已存在")
        port = await self.pick_free_port()
        locale = normalize_locale(default_locale) or self.settings.default_locale
        bot = self.db.create_bot(
            name, port, display_name=display_name, smp_servers=smp_servers, default_locale=locale
        )
        # The CLI only ever sees a literal greeting, so the catalog template is
        # rendered here, in the Bot's own language.
        greeting = (fill_placeholders(welcome_text, bot_name=display_name or name)
                    if welcome_text.strip() else render_welcome(locale, bot_name=display_name or name))
        bot = self.db.update_bot(
            bot["id"],
            welcome_text=greeting,
            auto_accept=1 if auto_accept else 0,
            accept_incognito=1 if accept_incognito else 0,
        )
        runtime = self._ensure_runtime(bot)
        if not start:
            return self.detail(str(bot["id"]))
        await self.start_bot(str(bot["id"]))
        return self.detail(str(bot["id"]))

    def detail(self, bot_id: str) -> Dict[str, Any]:
        bot = self.db.get_bot(bot_id, include_deleted=True)
        if bot is None:
            raise BotSupervisorError(f"Bot {bot_id} 不存在")
        runtime = self._runtimes.get(bot_id)
        out = dict(bot)
        out["runtime"] = runtime.as_dict() if runtime else {"bot_id": bot_id, "state": "stopped", "port": bot["port"]}
        out["reply_rules"] = len(self.db.list_reply_rules(bot_id))
        out["routing_rules"] = len(self.db.list_routing_rules(bot_id))
        out["messages"] = self.db.message_stats(bot_id)
        out["qr_png"] = ""
        if bot.get("permanent_link"):
            out["qr_png"] = self.qr_data_url(str(bot["permanent_link"]))
        return out

    # ------------------------------------------------------------- lifecycle
    async def start_bot(self, bot_id: str, *, provision: bool = True) -> Dict[str, Any]:
        bot = self.db.get_bot(bot_id)
        if bot is None:
            raise BotSupervisorError(f"Bot {bot_id} 不存在或已删除")
        runtime = self._ensure_runtime(bot)
        async with self._lock:
            if runtime.state in {"starting", "running"} and runtime.process is not None:
                return runtime.as_dict()
            runtime.state = "starting"
            runtime.last_error = ""
            try:
                await self._launch(runtime, bot)
                await self._wait_ready(runtime)
                await self._attach(runtime)
                if provision:
                    await self._provision(runtime)
            except Exception as exc:
                runtime.state = "error"
                runtime.last_error = f"{type(exc).__name__}: {exc}"[:500]
                self._record_error(bot_id, runtime.last_error)
                await self._kill(runtime)
                raise
            runtime.state = "running"
            self.db.update_bot(bot_id, status="running", last_error="")
        self._persist_state()
        self._start_watcher(bot_id)
        return runtime.as_dict()

    async def stop_bot(self, bot_id: str, *, reason: str = "stopped") -> Dict[str, Any]:
        runtime = self._runtimes.get(bot_id)
        if runtime is None:
            self._safe_update(bot_id, status="stopped")
            return {"bot_id": bot_id, "state": "stopped", "reason": reason}
        async with self._lock:
            runtime.state = "stopping"
            watcher = runtime.watcher
            runtime.watcher = None
        if watcher is not None and watcher is not asyncio.current_task():
            watcher.cancel()
            await asyncio.gather(watcher, return_exceptions=True)
        async with self._lock:
            await self._detach(runtime)
            await self._kill(runtime)
            runtime.state = "stopped"
            runtime.started_at = 0.0
        self._safe_update(bot_id, status="stopped")
        self._persist_state()
        return {"bot_id": bot_id, "state": runtime.state, "reason": reason}

    async def restart_bot(self, bot_id: str) -> Dict[str, Any]:
        await self.stop_bot(bot_id, reason="restart")
        return await self.start_bot(bot_id)

    async def remove_bot(self, bot_id: str, *, purge_files: bool = True, hard: bool = False) -> Dict[str, Any]:
        await self.stop_bot(bot_id, reason="removed")
        self.db.delete_bot(bot_id, hard=hard)
        self._runtimes.pop(bot_id, None)
        self._drop_state(bot_id)
        if purge_files:
            shutil.rmtree(self.paths_for(bot_id).root, ignore_errors=True)
            (self.qr_dir / f"{bot_id}.png").unlink(missing_ok=True)
        return {"bot_id": bot_id, "removed": True, "purged": purge_files, "hard": hard}

    async def boot(self, *, auto_start_statuses: Sequence[str] = ("running",)) -> Dict[str, Any]:
        """Resume every Bot that was running when Studio last exited."""
        started: List[str] = []
        failed: Dict[str, str] = {}
        for bot in self.db.list_bots():
            runtime = self._ensure_runtime(bot)
            runtime.provisioned = bool(bot.get("permanent_link"))
            if str(bot.get("status")) not in set(auto_start_statuses):
                continue
            try:
                await self.start_bot(str(bot["id"]))
                started.append(str(bot["id"]))
            except Exception as exc:
                failed[str(bot["id"])] = f"{type(exc).__name__}: {exc}"
        return {"started": started, "failed": failed, "total": len(self.db.list_bots())}

    async def shutdown(self) -> None:
        self._closing = True
        for bot_id in list(self._runtimes):
            try:
                await self.stop_bot(bot_id, reason="shutdown")
            except Exception as exc:
                self._runtimes[bot_id].last_error = f"{type(exc).__name__}: {exc}"
        self._persist_state()

    def _ensure_runtime(self, bot: Dict[str, Any]) -> BotRuntime:
        bot_id = str(bot["id"])
        runtime = self._runtimes.get(bot_id)
        if runtime is None:
            runtime = BotRuntime(
                bot_id=bot_id,
                name=str(bot.get("name") or bot_id),
                port=int(bot["port"]),
                paths=self.paths_for(bot_id),
            )
            self._runtimes[bot_id] = runtime
        elif runtime.port != int(bot["port"]):
            runtime.port = int(bot["port"])
        return runtime

    async def _port_open(self, port: int) -> bool:
        """True when something already accepts loopback connections on *port*."""
        writer: Optional[asyncio.StreamWriter] = None
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout=0.5)
        except OSError:
            return False
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
        return True

    async def pick_free_port(self) -> int:
        """A port that is free both in the ledger and on the loopback interface."""
        for candidate in range(self.settings.ws_port_base, self.settings.ws_port_max + 1):
            if self.db.get_bot_by_port(candidate) is None and not await self._port_open(candidate):
                return candidate
        raise BotSupervisorError(
            f"控制端口区间 {self.settings.ws_port_base}-{self.settings.ws_port_max} 已全部占用"
        )

    async def _launch(self, runtime: BotRuntime, bot: Dict[str, Any]) -> None:
        binary = self.require_binary()
        if await self._port_open(runtime.port):
            raise BotSupervisorError(
                f"控制端口 127.0.0.1:{runtime.port} 已被占用（很可能是上次运行遗留的 popopx-cli）："
                "请先调用 adopt_orphans 释放端口，或调大 BOT_WS_PORT_BASE"
            )
        paths = runtime.paths.create()
        argv = build_cli_argv(
            binary,
            runtime.port,
            paths,
            smp_servers=effective_smp_servers(bot, self.settings),
            profile_name=profile_bootstrap_name(paths, bot_display_name(bot, runtime.bot_id)),
        )
        write_wrapper(paths, render_wrapper_script(argv, bot_id=runtime.bot_id, paths=paths))
        runtime.argv = argv
        env = dict(os.environ)
        env["HOME"] = str(paths.cli_data)
        env["TMPDIR"] = str(paths.temp_dir)
        with paths.log_file.open("ab", buffering=0) as log:
            runtime.process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=log,
                stderr=log,
                env=env,
                cwd=str(paths.root),
            )
        runtime.pid = int(runtime.process.pid)
        runtime.started_at = time.time()
        runtime.paths.pid_file.write_text(f"{runtime.pid}\n", encoding="utf-8")
        os.chmod(runtime.paths.pid_file, 0o600)

    async def _wait_ready(self, runtime: BotRuntime) -> None:
        deadline = time.time() + self.ready_timeout
        last_error = ""
        while time.time() < deadline:
            process = runtime.process
            if process is not None and process.returncode is not None:
                raise BotSupervisorError(
                    f"popopx-cli 启动后立即退出（code={process.returncode}），详见 {runtime.paths.log_file}"
                )
            if await self._port_open(runtime.port):
                return
            last_error = f"127.0.0.1:{runtime.port} 拒绝连接"
            await asyncio.sleep(READY_POLL_INTERVAL)
        raise BotSupervisorError(f"Bot 控制端口 127.0.0.1:{runtime.port} 未就绪：{last_error}")

    async def _attach(self, runtime: BotRuntime) -> None:
        if runtime.client is not None:
            try:
                await runtime.client.close()
            except (WebSocketException, OSError) as exc:
                runtime.last_error = f"关闭旧控制通道失败：{exc}"
        client = CLIWebSocketClient(runtime.port, on_event=self._make_handler(runtime.bot_id))
        await client.connect()
        runtime.client = client

    async def _detach(self, runtime: BotRuntime) -> None:
        client, runtime.client = runtime.client, None
        if client is None:
            return
        try:
            await client.close()
        except (WebSocketException, OSError, asyncio.TimeoutError) as exc:
            runtime.last_error = f"关闭控制通道失败：{exc}"

    async def _kill(self, runtime: BotRuntime) -> None:
        process, runtime.process = runtime.process, None
        runtime.pid = 0
        runtime.paths.pid_file.unlink(missing_ok=True)
        if process is None or process.returncode is not None:
            return
        try:
            process.terminate()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(process.wait(), timeout=STOP_GRACE_SECONDS)
        except asyncio.TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                return
            await asyncio.gather(process.wait(), return_exceptions=True)

    # ------------------------------------------------------------- protocol
    async def _provision(self, runtime: BotRuntime) -> Dict[str, Any]:
        """Ensure the CLI profile, the permanent address and the accept/welcome flags."""
        client = runtime.client
        if client is None:
            raise BotSupervisorError("控制通道尚未建立")
        bot = self.db.get_bot(runtime.bot_id)
        if bot is None:
            raise BotSupervisorError(f"Bot {runtime.bot_id} 不存在")
        display_name = bot_display_name(bot, runtime.bot_id)
        settings = self.address_settings(bot)

        user_id = await client.ensure_user(display_name)
        permanent = str(bot.get("permanent_link") or "")
        if permanent:
            shown_long, shown_short, _ = await client.show_address(user_id)
            permanent = shown_long or shown_short or permanent
        else:
            long_link, short_link = await client.create_address(user_id)
            permanent = long_link or short_link
        await client.apply_address_settings(user_id, settings)
        runtime.provisioned = True
        runtime.commands = client.commands_sent
        self.db.update_bot(runtime.bot_id, permanent_link=permanent, contact_address=permanent)
        return {"user_id": user_id, "permanent_link": permanent, "settings": settings}

    def address_settings(self, bot: Dict[str, Any]) -> Dict[str, Any]:
        return build_address_settings(
            business_address=True,
            auto_accept=bool(int(bot.get("auto_accept") or 0)),
            accept_incognito=bool(int(bot.get("accept_incognito") or 0)),
            welcome_text=str(bot.get("welcome_text") or ""),
        )

    async def update_greeting(
        self,
        bot_id: str,
        *,
        welcome_text: Optional[str] = None,
        auto_accept: Optional[bool] = None,
        accept_incognito: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Persist and, when the CLI is reachable, push the welcome/accept settings."""
        bot = self.db.get_bot(bot_id)
        if bot is None:
            raise BotSupervisorError(f"Bot {bot_id} 不存在")
        fields: Dict[str, Any] = {}
        if welcome_text is not None:
            text = str(welcome_text)
            locale = normalize_locale(str(bot.get("default_locale") or "")) or self.settings.default_locale
            name = bot["display_name"] or bot["name"]
            if text.strip():
                # CLI 只转发字面文本，所以自定义文案里的占位符也由 Studio 展开。
                fields["welcome_text"] = fill_placeholders(text, bot_name=name)
            else:
                # 清空欢迎语等于恢复该 Bot 语种的默认模板。
                fields["welcome_text"] = render_welcome(locale, bot_name=name)
        if auto_accept is not None:
            fields["auto_accept"] = 1 if auto_accept else 0
        if accept_incognito is not None:
            fields["accept_incognito"] = 1 if accept_incognito else 0
        if fields:
            bot = self.db.update_bot(bot_id, **fields)
        settings = self.address_settings(bot)
        applied = False
        error = ""
        runtime = self._runtimes.get(bot_id)
        if runtime is not None and runtime.client is not None and runtime.client.connected:
            try:
                await runtime.client.apply_address_settings(1, settings)
                applied = True
            except (
                WebSocketProtocolError,
                CLICommandError,
                WebSocketException,
                OSError,
                asyncio.TimeoutError,
            ) as exc:
                error = f"{type(exc).__name__}: {exc}"
                runtime.last_error = error[:500]
        return {"bot_id": bot_id, "settings": settings, "applied": applied, "error": error}

    async def create_group(self, bot_id: str, name: str) -> Dict[str, Any]:
        group_id = await self.client_for(bot_id).create_group(1, name)
        if group_id is None:
            raise BotSupervisorError("创建群组未返回 groupId")
        return {"group_id": group_id, "ref": f"#{group_id}", "name": name}

    async def create_group_link(self, bot_id: str, group_id: int, role: str = "observer") -> Dict[str, Any]:
        long_link, short_link = await self.client_for(bot_id).create_group_link(group_id, role)
        return {"group_id": group_id, "role": role, "invite_link": long_link, "short_link": short_link}

    async def send_text(
        self,
        bot_id: str,
        chat_ref: str | int,
        text: str,
        *,
        quoted_item_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        chat_type, chat_id = parse_chat_ref(chat_ref)
        client = self.client_for(bot_id)
        events = await client.send_text(chat_type, chat_id, text, quoted_item_id=quoted_item_id)
        runtime = self._runtimes.get(bot_id)
        if runtime is not None:
            runtime.commands = client.commands_sent
        return {
            "bot_id": bot_id,
            "chat_type": chat_type,
            "chat_ref": chat_ref if isinstance(chat_ref, str) else f"@{chat_id}",
            "delivered": len(events),
            "events": [event.as_dict() for event in events],
        }

    def shared_file(self, bot_id: str, file_path: str | Path) -> str:
        """把插件给的文件路径收敛到该 Bot 自己的 ``files`` 目录里。

        ``/_send`` 的 ``filePath`` 是一个「读取本机任意路径并外发」的原语，所以这一层
        必须替身机器人自己把范围锁死：绝对路径、软链接、上级目录都在 ``resolve`` 之后
        重新判定，只有落在 ``paths_for(bot_id).files_dir`` 之下的普通文件才允许通过。
        """
        root = self.paths_for(bot_id).files_dir
        wanted = Path(str(file_path))
        if not wanted.is_absolute():
            wanted = root / wanted
        resolved = wanted.resolve()
        if not resolved.is_file() or root.resolve() not in resolved.parents:
            raise BotSupervisorError(f"只能发送该 Bot files 目录下的普通文件，拒绝 {file_path!r}")
        return str(resolved)

    async def send_content(
        self,
        bot_id: str,
        chat_ref: str | int,
        content: Dict[str, Any],
        *,
        quoted_item_id: Optional[int] = None,
        file_path: str = "",
    ) -> Dict[str, Any]:
        chat_type, chat_id = parse_chat_ref(chat_ref)
        source = self.shared_file(bot_id, file_path) if file_path else ""
        payload = await self.client_for(bot_id).send_content(
            chat_type, chat_id, content, quoted_item_id=quoted_item_id, file_path=source
        )
        return {"bot_id": bot_id, "chat_type": chat_type, "chat_ref": chat_ref, "resp": payload, "file": source}

    async def broadcast_group(self, bot_id: str, group_ids: Sequence[Any], text: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for group in group_ids:
            ref = group if isinstance(group, str) else f"#{group}"
            try:
                results.append(await self.send_text(bot_id, ref, text))
            except (BotSupervisorError, WebSocketProtocolError, CLICommandError, WebSocketException, OSError) as exc:
                results.append({"bot_id": bot_id, "chat_ref": ref, "error": f"{type(exc).__name__}: {exc}"})
        return results

    async def list_contacts(self, bot_id: str) -> List[Dict[str, Any]]:
        return await self.client_for(bot_id).list_contacts(1)

    async def list_groups(self, bot_id: str) -> List[Dict[str, Any]]:
        return await self.client_for(bot_id).list_groups(1)

    async def accept_contact(self, bot_id: str, request_id: int) -> Dict[str, Any]:
        return await self.client_for(bot_id).accept_contact(request_id)

    # ------------------------------------------------------------- watchdog
    def _start_watcher(self, bot_id: str) -> None:
        runtime = self._runtimes.get(bot_id)
        if runtime is None or (runtime.watcher is not None and not runtime.watcher.done()):
            return
        runtime.watcher = asyncio.create_task(self._watch(bot_id), name=f"bot-watch-{bot_id}")

    async def _watch(self, bot_id: str) -> None:
        """Relaunch a dead CLI and reconnect a dropped channel; never raise out."""
        policy = ReconnectPolicy(max_delay=CONNECT_BACKOFF_MAX)
        while not self._closing:
            await asyncio.sleep(self.health_interval)
            runtime = self._runtimes.get(bot_id)
            if runtime is None or self._closing or runtime.state in {"stopping", "stopped", "removed"}:
                return
            try:
                process = runtime.process
                if process is None or process.returncode is not None:
                    code = None if process is None else process.returncode
                    runtime.last_error = f"popopx-cli 进程退出（code={code}）"[:500]
                    runtime.restarts += 1
                    self._record_error(bot_id, runtime.last_error)
                    await asyncio.sleep(policy.next_delay())
                    bot = self.db.get_bot(bot_id)
                    if bot is None:
                        return
                    await self._launch(runtime, bot)
                    await self._wait_ready(runtime)
                    await self._attach(runtime)
                    policy.reset()
                    self.db.update_bot(bot_id, status="running")
                elif runtime.client is None or not runtime.client.connected:
                    runtime.reconnects += 1
                    await asyncio.sleep(policy.next_delay())
                    await self._attach(runtime)
                    policy.reset()
                else:
                    policy.reset()
                if runtime.client is not None:
                    runtime.commands = runtime.client.commands_sent
            except (WebSocketException, OSError, WebSocketProtocolError, CLICommandError, asyncio.TimeoutError) as exc:
                runtime.last_error = f"{type(exc).__name__}: {exc}"[:500]
                self._record_error(bot_id, runtime.last_error)
            except Exception as exc:  # one Bot's bug must never kill the gateway
                runtime.last_error = f"监督循环异常 {type(exc).__name__}: {exc}"[:500]
                self._record_error(bot_id, runtime.last_error)
                return

    def _make_handler(self, bot_id: str) -> Callable[[Frame], Awaitable[None]]:
        async def handler(frame: Frame) -> None:
            runtime = self._runtimes.get(bot_id)
            if runtime is not None:
                runtime.events += 1
            hook = self.on_event
            if hook is None:
                return
            for event in normalize_event(frame):
                try:
                    await hook(bot_id, event)
                except Exception as exc:
                    if runtime is not None:
                        runtime.last_error = f"事件处理异常 {type(exc).__name__}: {exc}"[:500]
                    break

        return handler

    def _record_error(self, bot_id: str, message: str) -> None:
        try:
            self.db.update_bot(bot_id, status="error", last_error=message)
        except Exception:
            pass

    def _safe_update(self, bot_id: str, **fields: Any) -> None:
        try:
            # 生命周期心跳只写状态，绝不能把已软删除的 Bot 悄悄写回 stopped：
            # 关停时每个运行时都会经过这里，否则删掉的 Bot 会重新出现在列表里。
            row = self.db.get_bot(bot_id, include_deleted=True)
            if row is None or str(row.get("status") or "") == "deleted":
                return
            self.db.update_bot(bot_id, **fields)
        except Exception:
            pass

    # ------------------------------------------------------------------- QR
    def qr_png(self, text: str, *, box_size: int = QR_BOX_SIZE) -> bytes:
        """Render *text* as a high-resolution PNG for the Bot factory modal."""
        import qrcode
        from qrcode.constants import ERROR_CORRECT_Q

        qr = qrcode.QRCode(version=None, error_correction=ERROR_CORRECT_Q, box_size=box_size, border=QR_BORDER)
        qr.add_data(text)
        qr.make(fit=True)
        image = qr.make_image(fill_color="#0b1020", back_color="#f5f8ff").convert("RGB")
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        return buf.getvalue()

    def qr_data_url(self, text: str) -> str:
        return "data:image/png;base64," + base64.b64encode(self.qr_png(text)).decode("ascii")

    def save_qr(self, bot_id: str, text: str) -> Path:
        self.qr_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.qr_dir, 0o700)
        path = self.qr_dir / f"{bot_id}.png"
        path.write_bytes(self.qr_png(text))
        os.chmod(path, 0o600)
        return path

    def bot_qr(self, bot_id: str, *, save: bool = True) -> Dict[str, Any]:
        bot = self.db.get_bot(bot_id)
        if bot is None:
            raise BotSupervisorError(f"Bot {bot_id} 不存在")
        link = str(bot.get("permanent_link") or bot.get("contact_address") or "")
        if not link:
            raise BotSupervisorError("该 Bot 还没有永久联系地址，请先启动并完成初始化")
        payload = self.qr_png(link)
        info: Dict[str, Any] = {
            "bot_id": bot_id,
            "link": link,
            "bytes": len(payload),
            "sha256": sha256_bytes(payload),
            "data_url": "data:image/png;base64," + base64.b64encode(payload).decode("ascii"),
        }
        if save:
            info["file"] = str(self.save_qr(bot_id, link))
        return info

    # ---------------------------------------------------------- cold backup
    async def export_bundle(self, bot_id: str, *, passphrase: str = "", dest: Optional[Path | str] = None) -> Dict[str, Any]:
        """Stop the Bot, pack ``cli-data`` + configuration, then resume it."""
        bot = self.db.get_bot(bot_id)
        if bot is None:
            raise BotSupervisorError(f"Bot {bot_id} 不存在")
        runtime = self._runtimes.get(bot_id)
        was_running = runtime is not None and runtime.state == "running"
        if was_running:
            await self.stop_bot(bot_id, reason="backup")
        paths = self.paths_for(bot_id)
        if not paths.cli_data.is_dir():
            raise BotSupervisorError(f"Bot 数据目录不存在：{paths.cli_data}")

        payload = self._build_tar(bot_id, paths)
        encrypted = bool(passphrase)
        blob = encrypt_bundle(payload, passphrase) if encrypted else payload
        out_dir = Path(dest).expanduser() if dest else self.settings.backups_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(out_dir, 0o700)
        suffix = ".botbundleenc" if encrypted else ".botbundle"
        bundle_path = out_dir / f"{bot_id}-{time.strftime('%Y%m%d-%H%M%S', time.localtime())}{suffix}"
        bundle_path.write_bytes(blob)
        os.chmod(bundle_path, 0o600)
        meta = {
            "bundle": str(bundle_path),
            "bot_id": bot_id,
            "bytes": len(blob),
            "sha256": sha256_bytes(payload),
            "encrypted": encrypted,
            "files": len(self._bundle_files(paths)),
            "created_at": time.time(),
        }
        sidecar = bundle_path.with_name(bundle_path.name + ".json")
        sidecar.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(sidecar, 0o600)
        if was_running:
            await self.start_bot(bot_id, provision=False)
        return meta

    def _bundle_files(self, paths: BotPaths) -> List[Path]:
        return [file for file in sorted(paths.cli_data.rglob("*")) if file.is_file()]

    def _build_tar(self, bot_id: str, paths: BotPaths) -> bytes:
        bot = self.db.get_bot(bot_id, include_deleted=True) or {}
        entries: List[Tuple[str, bytes, int]] = []
        for file in self._bundle_files(paths):
            data = file.read_bytes()
            entries.append(
                (f"cli-data/{file.relative_to(paths.cli_data).as_posix()}", data, file.stat().st_mode & 0o777)
            )
        if paths.wrapper.is_file():
            entries.append((WRAPPER_NAME, paths.wrapper.read_bytes(), 0o755))
        if paths.log_file.is_file():
            entries.append((LOG_NAME, paths.log_file.read_bytes()[-LOG_TAIL_BYTES:], 0o600))
        manifest = {
            "format": "popopx-bot-studio-bundle",
            "version": BUNDLE_VERSION,
            "bot_id": bot_id,
            "created_at": time.time(),
            "bot": bot,
            "reply_rules": self.db.list_reply_rules(bot_id),
            "routing_rules": self.db.list_routing_rules(bot_id),
            "plugin_configs": self.db.list_plugin_configs(bot_id),
            "files": [
                {"name": name, "sha256": sha256_bytes(data), "size": len(data)} for name, data, _mode in entries
            ],
        }
        manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2, default=str).encode("utf-8")
        entries.append(("manifest.json", manifest_bytes, 0o600))

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, data, mode in entries:
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                info.mode = mode
                info.mtime = int(time.time())
                tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    async def import_bundle(
        self,
        bundle: Path | str,
        *,
        passphrase: str = "",
        bot_id: Optional[str] = None,
        name: str = "",
        start: bool = False,
    ) -> Dict[str, Any]:
        """Verify, unpack and re-register a cold backup into the ledger."""
        source = Path(bundle).expanduser()
        if not source.is_file():
            raise BotSupervisorError(f"备份包不存在：{source}")
        raw = source.read_bytes()
        encrypted = raw[:4] == BUNDLE_MAGIC
        if encrypted:
            if not passphrase:
                raise BotSupervisorError("该备份包已加密，请提供口令")
            payload = decrypt_bundle(raw, passphrase)
        elif raw.startswith(b"\x1f\x8b"):
            payload = raw
        else:
            raise BotSupervisorError("备份包格式无法识别（既无 PBSB 头也不是 gzip 数据）")

        manifest, restored, skipped = self._unpack_tar(payload)
        if manifest.get("format") != "popopx-bot-studio-bundle":
            raise BotSupervisorError("备份包缺少 Studio manifest")
        for record in manifest.get("files") or []:
            member = str(record.get("name") or "")
            if member in restored and restored[member][0] and sha256_bytes(restored[member][0]) != str(record.get("sha256") or ""):
                raise BotSupervisorError(f"备份包校验失败：{member} 的 SHA-256 不匹配")

        target_id = bot_id or str(manifest.get("bot_id") or "")
        saved_bot = manifest.get("bot") or {}
        live = self._runtimes.get(target_id)
        was_running = live is not None and live.state == "running"
        if was_running:
            # The CLI holds the sqlite files open; unpacking over them would
            # corrupt the restore, so the Bot is stopped for the whole swap.
            await self.stop_bot(target_id, reason="restore")
        if not target_id or self.db.get_bot(target_id, include_deleted=True) is None:
            base = name or str(saved_bot.get("name") or "") or f"restored-{secrets.token_hex(2)}"
            port = await self.pick_free_port()
            row = self.db.create_bot(
                unique_bot_name(base, self.db),
                port,
                display_name=str(saved_bot.get("display_name") or ""),
                smp_servers=str(saved_bot.get("smp_servers") or ""),
            )
            target_id = str(row["id"])
        paths = self.paths_for(target_id)
        paths.create()
        written = 0
        for member, (data, mode) in restored.items():
            if member == WRAPPER_NAME:
                write_wrapper(paths, data.decode("utf-8"))
                continue
            if not member.startswith("cli-data/"):
                continue
            out = paths.cli_data / Path(member).relative_to("cli-data")
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
            # cli-data 存的是 Bot 身份与消息库，打包时的权限位可能来自别台机器：落盘一律收紧。
            os.chmod(out, min(mode or SECURE_FILE_MODE, SECURE_FILE_MODE))
            written += 1

        self.db.update_bot(
            target_id,
            permanent_link=str(saved_bot.get("permanent_link") or ""),
            contact_address=str(saved_bot.get("contact_address") or ""),
            welcome_text=str(saved_bot.get("welcome_text") or ""),
            auto_accept=int(saved_bot.get("auto_accept") or 0),
            accept_incognito=int(saved_bot.get("accept_incognito") or 0),
            status="stopped",
            last_error="",
        )
        for rule in manifest.get("reply_rules") or []:
            self.db.upsert_reply_rule(
                target_id,
                name=str(rule.get("name") or ""),
                trigger_type=str(rule.get("trigger_type") or "exact"),
                pattern=str(rule.get("pattern") or ""),
                reply_text=str(rule.get("reply_text") or ""),
                cooldown_seconds=int(rule.get("cooldown_seconds") or 0),
                enabled=bool(int(rule.get("enabled") or 0)),
                priority=int(rule.get("priority") or 100),
            )
        for cfg in manifest.get("plugin_configs") or []:
            raw_cfg = cfg.get("config")
            self.db.set_plugin_config(
                str(cfg.get("plugin_id") or ""),
                json.loads(raw_cfg) if isinstance(raw_cfg, str) else (raw_cfg or {}),
                bot_id=target_id,
                enabled=bool(int(cfg.get("enabled") or 0)),
            )
        # 路由表没有 (bot, type, pattern) 这类自然键，重复还原会一条条追加；
        # 与账本里字段完全相同的规则视为已存在，保证「还原两次 = 还原一次」。
        known_routing = {routing_rule_signature(row) for row in self.db.list_routing_rules(target_id)}
        for rule in manifest.get("routing_rules") or []:
            signature = routing_rule_signature(rule)
            if signature in known_routing:
                continue
            self.db.upsert_routing_rule(
                target_id,
                name=str(rule.get("name") or ""),
                source_type=str(rule.get("source_type") or "any"),
                source_ref=str(rule.get("source_ref") or ""),
                keyword_mode=str(rule.get("keyword_mode") or "any"),
                keywords=json_list(rule.get("keywords")),
                target_type=str(rule.get("target_type") or "group"),
                target_ref=str(rule.get("target_ref") or ""),
                template=str(rule.get("template") or ""),
                quote_reply=bool(int(rule.get("quote_reply") or 0)),
                cooldown_seconds=int(rule.get("cooldown_seconds") or 0),
                enabled=bool(int(rule.get("enabled") or 0)),
            )
        bot = self.db.get_bot(target_id, include_deleted=True)
        assert bot is not None
        self._ensure_runtime(bot)
        result: Dict[str, Any] = {
            "bot_id": target_id,
            "files": written,
            "skipped": skipped,
            "payload_sha256": sha256_bytes(payload),
            "encrypted": encrypted,
            "verified": True,
        }
        if start or was_running:
            await self.start_bot(target_id, provision=False)
            result["started"] = True
        return result

    @staticmethod
    def _unpack_tar(payload: bytes) -> Tuple[Dict[str, Any], Dict[str, Tuple[bytes, int]], List[str]]:
        """Extract only safe regular files; never follow a member outside the Bot dir."""
        manifest: Dict[str, Any] = {}
        restored: Dict[str, Tuple[bytes, int]] = {}
        skipped: List[str] = []
        try:
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as tar:
                for member in tar.getmembers():
                    if (
                        not _SAFE_MEMBER_RE.match(member.name)
                        or member.name.startswith("/")
                        or ".." in member.name.split("/")
                    ):
                        skipped.append(member.name)
                        continue
                    if member.isdir():
                        continue
                    handle = tar.extractfile(member) if member.isfile() else None
                    if handle is None:
                        skipped.append(member.name)
                        continue
                    data = handle.read()
                    restored[member.name] = (data, member.mode & 0o777)
                    if member.name == "manifest.json":
                        manifest = json.loads(data.decode("utf-8"))
        except (EOFError, tarfile.TarError, OSError, ValueError) as exc:
            raise BotSupervisorError(f"备份包已损坏，无法解包：{type(exc).__name__}: {exc}") from exc
        if not manifest:
            raise BotSupervisorError("备份包内缺少 manifest.json，无法安全还原")
        return manifest, restored, skipped

    # ---------------------------------------------------------- studio state
    def _persist_state(self) -> None:
        """Write ``studio.state.json`` describing the live runtimes (mode 0600)."""
        self.settings.data_dir.mkdir(parents=True, exist_ok=True)
        snapshot = {
            "version": 1,
            "updated_at": time.time(),
            "cli_binary": str(self.cli_binary) if self.cli_binary else "",
            "bots": {
                bot_id: {
                    "name": runtime.name,
                    "port": runtime.port,
                    "pid": runtime.pid,
                    "state": runtime.state,
                    "restarts": runtime.restarts,
                    "reconnects": runtime.reconnects,
                    "last_error": runtime.last_error,
                }
                for bot_id, runtime in self._runtimes.items()
            },
        }
        path = self.settings.state_file
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(path)

    def _drop_state(self, bot_id: str) -> None:
        path = self.settings.state_file
        if not path.is_file():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        data.get("bots", {}).pop(bot_id, None)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(path, 0o600)

    def load_state(self) -> Dict[str, Any]:
        path = self.settings.state_file
        if not path.is_file():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    # ---------------------------------------------------------- pid recovery
    def orphan_pid(self, bot_id: str) -> Optional[int]:
        """A pid left behind by a previous Studio run, if that process still lives."""
        pid_file = self.paths_for(bot_id).pid_file
        if not pid_file.is_file():
            return None
        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
        except ValueError:
            return None
        try:
            os.kill(pid, 0)
        except OSError:
            return None
        return pid

    async def adopt_orphans(self) -> List[int]:
        """Terminate CLI processes Studio lost track of, so the port frees up."""
        killed: List[int] = []
        for bot in self.db.list_bots():
            pid = self.orphan_pid(bot["id"])
            if pid is None:
                continue
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                continue
            killed.append(pid)
        return killed


def unique_bot_name(base: str, db: Database) -> str:
    cleaned = re.sub(r"[^a-z0-9_-]+", "-", (base or "").lower()).strip("-")[:48] or "bot"
    candidate = cleaned
    index = 1
    while db.get_bot_by_name(candidate) is not None:
        index += 1
        candidate = f"{cleaned}-{index}"[:64]
    return candidate


def json_list(value: Any) -> List[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value or "[]")
        except json.JSONDecodeError:
            value = [value]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if str(item).strip()]
    return []


def routing_rule_signature(rule: Dict[str, Any]) -> Tuple[Any, ...]:
    """路由规则的内容指纹，供冷备还原去重（同一份状态还原两次不应翻倍）。"""
    return (
        str(rule.get("name") or ""),
        str(rule.get("source_type") or "any"),
        str(rule.get("source_ref") or ""),
        str(rule.get("keyword_mode") or "any"),
        tuple(json_list(rule.get("keywords"))),
        str(rule.get("target_type") or "group"),
        str(rule.get("target_ref") or ""),
        str(rule.get("template") or ""),
        _flag(rule.get("quote_reply")),
        int(rule.get("cooldown_seconds") or 0),
        _flag(rule.get("enabled")),
    )


def _flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    try:
        return int(value or 0) != 0
    except (TypeError, ValueError):
        return bool(value)


def derive_bundle_key(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise BotSupervisorError("加密口令不能为空")
    return Scrypt(salt=salt, length=AES_KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(
        passphrase.encode("utf-8")
    )


def encrypt_bundle(payload: bytes, passphrase: str) -> bytes:
    """``PBSB`` magic + version/flags + scrypt salt + AES-GCM nonce, then ciphertext+tag."""
    salt = os.urandom(KDF_SALT_LEN)
    nonce = os.urandom(AES_NONCE_LEN)
    header = BUNDLE_MAGIC + bytes([BUNDLE_VERSION, BUNDLE_FLAG_ENCRYPTED]) + salt + nonce
    key = derive_bundle_key(passphrase, salt)
    return header + AESGCM(key).encrypt(nonce, payload, hashlib.sha256(header).digest())


def decrypt_bundle(blob: bytes, passphrase: str) -> bytes:
    fixed = len(BUNDLE_MAGIC) + 2 + KDF_SALT_LEN + AES_NONCE_LEN
    if blob[:4] != BUNDLE_MAGIC:
        raise BotSupervisorError("备份包魔数不匹配")
    if len(blob) < fixed + 16:
        raise BotSupervisorError("加密备份包长度不足")
    if blob[4] != BUNDLE_VERSION:
        raise BotSupervisorError(f"不支持的备份包版本 {blob[4]}")
    header = blob[:fixed]
    salt = blob[len(BUNDLE_MAGIC) + 2 : len(BUNDLE_MAGIC) + 2 + KDF_SALT_LEN]
    nonce = blob[fixed - AES_NONCE_LEN : fixed]
    key = derive_bundle_key(passphrase, salt)
    try:
        return AESGCM(key).decrypt(nonce, blob[fixed:], hashlib.sha256(header).digest())
    except BotSupervisorError:
        raise
    except Exception as exc:
        raise BotSupervisorError("备份包解密失败：口令错误或文件被篡改") from exc
