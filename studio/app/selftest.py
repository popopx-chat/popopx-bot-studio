"""``python3 -m app.main --self-test`` 的全量自检运行器。

分组设计（24 组，按运行顺序；权威清单见文件末尾的 ``SELF_TEST_GROUPS``）：
配置与权限、SQLite 账本、WebSocket 协议帧、进程监督、开通初始化、规则引擎、
路由引擎、网关管线、插件总线、开发者 Open API、Web 后台、i18n 完整性、
Web 实时链路、隐私邀请链接、冷备往返、生态卡片、.ics、安装脚本与交付物纪律、
Mac 节点、A2A、访客门户、替身引擎与替身面板。

自检只依赖 ``studio/tests/fake_popopx_cli.py``（一个同样讲真协议的本地替身），
因此不需要真实的 ``popopx-cli``，也不会连接任何 SMP 服务器。
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import hashlib
import itertools
import io
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .agent_admin import ADMIN_PREFIX as AGENT_API_PREFIX
from .agent_preferences import PREFERENCES_FILENAME
from .agent_runtime import TOOL_NAMES, AgentRuntime, build_sender, wire_identity
from .bot_supervisor import (
    BotSupervisor,
    BotSupervisorError,
    BotPaths,
    BUILTIN_SMP_SERVERS,
    BUNDLE_VERSION,
    BotRuntime,
    CHAT_DB_SUFFIX,
    build_cli_argv,
    bot_display_name,
    derive_bundle_key,
    decrypt_bundle,
    effective_smp_servers,
    encrypt_bundle,
    parse_chat_ref,
    profile_bootstrap_name,
    render_wrapper_script,
    resolve_cli_binary,
    sha256_bytes,
    split_server_list,
    write_wrapper,
)
from .config import (
    DEFAULT_CLI_BIN_PATH,
    DEFAULT_HOST,
    DEFAULT_MAC_NODE_URL,
    DEFAULT_PORT,
    SECURE_DIR_MODE,
    SECURE_FILE_MODE,
    ConfigError,
    Settings,
    is_loopback_host,
    load_env_file,
    load_settings,
    mode_of,
    parse_env_text,
    permission_warnings,
)
from .database import (
    AUDIT_LEVELS,
    AUDIT_STAGES,
    BOT_FIELDS,
    SCHEMA_VERSION,
    TRIGGER_TYPES,
    Database,
    LedgerError,
    connect,
    new_bot_id,
    new_bot_token,
    new_guest_link_id,
    new_negotiation_id,
    new_proposal_id,
)
from .eco_cards import (
    CALLBACK_ALT,
    CALLBACK_APPROVE,
    CALLBACK_DECLINE,
    CALLBACK_KINDS,
    CALLBACK_PREFIX,
    ECO_MARKER,
    REFERENCE_PREFIX,
    SSO_SCAN_PREFIX,
    UPLINK_PREFIXES,
    EcoLimits,
    EcoCardError,
    build_action,
    build_card,
    callback_for,
    callback_payload,
    compact_json,
    confirmation_card,
    decode_message,
    encode_frame,
    escape_whitespace,
    frame_service_card,
    is_uplink_text,
    new_card_id,
    now_ms,
    parse_callback,
    status_card,
)
from .gateway import MAX_UPDATES, BotGateway, ProcessResult, UpdateBuffer
from .guest_portal import LINK_PATH_PREFIX, TOKEN_MASK, TOKEN_MASK_CHARS
from .ics import (
    MAX_OCTETS as ics_MAX_OCTETS,
    build_calendar,
    build_event,
    escape_text,
    event_uid as ics_event_uid,
    fold as ics_fold,
    ics_filename,
    stamp as ics_stamp,
)


def _utf8_ok(piece: str) -> bool:
    """断言辅助：一个物理行必须是完整 UTF-8（折叠不能切断多字节字符）。"""
    try:
        piece.encode("utf-8").decode("utf-8")
    except UnicodeError:
        return False
    return True

from .i18n import (
    CATALOGS,
    FALLBACK_LOCALE,
    LOCALE_LABELS,
    LOCALES,
    WELCOME_PLACEHOLDERS,
    admin_strings,
    assert_catalogs,
    catalog_payload,
    detect_locale,
    extra_keys,
    fill_placeholders,
    is_supported,
    language_menu,
    missing_keys,
    normalize_locale,
    parse_accept_language,
    parity_report,
    placeholder_drift,
    placeholders,
    render_welcome,
    site_strings,
    t as i18n_t,
    welcome_template,
)
from .mac_node_bridge import (
    ACTION_AVAILABILITY,
    ACTION_PROPOSALS,
    COMMAND_PREFIX,
    HEALTH_PATH,
    MAX_SIGNAL_PAYLOAD_CHARACTERS,
    SNAPSHOT_PATH,
    TOKEN_HEADER,
)
from .main import (
    API_PREFIX,
    APP_NAME,
    APP_VERSION,
    CATALOG_MARKER,
    CoreServices,
    HOOK_PREFIX,
    OPEN_API_PREFIX,
    SITE_DIR,
    STATIC_DIR,
    SEND_ERRORS,
    StudioStack,
    TOKEN_COOKIE,
    _LateServices,
    build_stack,
    client_locale,
    create_app,
    ref_for,
    render_page,
    request_token,
    safe_webhook_url,
    token_ok,
)
from .needle3_runtime import ENGINE_FALLBACK, ENGINE_NEEDLE
from .needle_assets import (
    MAX_WEIGHT_BYTES as NEEDLE_MAX_WEIGHT_BYTES,
    WEIGHT_FILE as NEEDLE_WEIGHT_FILE,
    NeedleAssetError,
    ensure_weights,
    load_manifest,
    verify_assets,
)
from .open_api import (
    MAX_TEXT_LENGTH,
    MAX_WEBHOOK_LENGTH,
    OPEN_METHODS,
    PATH_PREFIX,
    ApiError,
    configure as api_configure,
    mounted_paths,
    register_webhook_listener,
    reset_state as api_reset,
    router as open_api_router,
)
from .plugin_manager import (
    CONFIG_FIELD_TYPES,
    MASKED_VALUE,
    PASS,
    PluginContext,
    PluginError,
    PluginManager,
    PluginResult,
    StudioPlugin,
    load_plugin_module,
    plugin_id_field,
)
from .router_engine import (
    TICKET_REPLY_RE,
    RouterEngine,
    RouterError,
    TicketRegistry,
    new_ticket_id,
    parse_targets,
)
from .rule_engine import (
    TRIGGER_RANK,
    InboundMessage,
    RuleEngine,
    RuleError,
    default_context,
    interpolate,
)
from .security.opaque_invite_codec import (
    FORMAT_VERSION as INVITE_FORMAT_VERSION,
    HKDF_INFO as INVITE_HKDF_INFO,
    HKDF_SALT as INVITE_HKDF_SALT,
    INVITE_KEY,
    LINK_PREFIX as INVITE_LINK_PREFIX,
    MASTER_KEY as INVITE_MASTER_KEY,
    MAX_ADDRESS_BYTES as INVITE_MAX_ADDRESS_BYTES,
    MAX_TOKEN_CHARS as INVITE_MAX_TOKEN_CHARS,
    NONCE_BYTES as INVITE_NONCE_BYTES,
    OpaqueInviteError,
    TAG_BYTES as INVITE_TAG_BYTES,
    b64url_decode,
    b64url_encode,
    decode_invite_link,
    derive_invite_key,
    encode_invite_link,
    hkdf_sha256,
    looks_like_opaque_invite,
)
from .ws_protocol import (
    CLITimeoutError,
    CLIWebSocketClient,
    CLICommandError,
    Frame,
    LINK_ROLES,
    NormalizedEvent,
    ReconnectPolicy,
    WebSocketProtocolError,
    build_address_settings,
    cmd_address_settings,
    cmd_create_address,
    cmd_create_group,
    cmd_create_group_link,
    cmd_list_contacts,
    cmd_list_users,
    cmd_send_message,
    cmd_send_plain_text,
    cmd_set_active_user,
    cmd_show_active_user,
    cmd_show_address,
    cmd_short_link_address,
    decode_frame,
    extract_address_settings,
    extract_created_link,
    extract_group_id,
    extract_user_id,
    extract_user_name,
    flatten_error,
    normalize_event,
    normalize_new_chat_items,
    build_frame,
)

ROOT = Path(__file__).resolve().parents[1]
FAKE_CLI = ROOT / "tests" / "fake_popopx_cli.py"
STATIC_PAGE = ROOT / "static" / "index.html"
SITE_PAGE = ROOT.parent / "site" / "index.html"
REPO = ROOT.parent
BUNDLE_MAGIC = b"PBSB"


class SelfTest:
    """Assertion counter with a per-group report line."""

    def __init__(self, settings: Optional[Settings] = None, *, only: Optional[Sequence[str]] = None):
        self.settings = settings
        self.only = list(only) if only else list(SELF_TEST_GROUPS)
        self.assertions = 0
        self.failures = 0
        self.problems: List[str] = []
        self.per_group: Dict[str, Tuple[int, int]] = {}
        self.group = ""
        self.started = 0.0

    # ------------------------------------------------------------ assertions
    def check(self, label: str, condition: Any, detail: str = "") -> bool:
        self.assertions += 1
        verdict = bool(condition)
        if not verdict:
            self.failures += 1
            line = f"FAIL [{self.group}] {label}"
            if detail:
                line += f" -> {detail}"
            self.problems.append(line)
            print("  " + line, flush=True)
        return verdict

    def eq(self, label: str, got: Any, want: Any) -> bool:
        return self.check(label, got == want, f"got={got!r} want={want!r}")

    def ne(self, label: str, got: Any, other: Any) -> bool:
        return self.check(label, got != other, f"both are {got!r}")

    def contains(self, label: str, haystack: str, needle: str) -> bool:
        return self.check(label, needle in haystack, f"{needle!r} not in {haystack[:120]!r}")

    def raises(self, label: str, exc_types: Any, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> bool:
        try:
            result = fn(*args, **kwargs)
        except exc_types:
            return self.check(label, True)
        except Exception as exc:  # noqa: BLE001 - naming the wrong type is the point
            expected = exc_types.__name__ if isinstance(exc_types, type) else "/".join(e.__name__ for e in exc_types)
            return self.check(label, False, f"期望 {expected}，收到 {type(exc).__name__}: {exc}")
        expected = exc_types.__name__ if isinstance(exc_types, type) else "/".join(e.__name__ for e in exc_types)
        return self.check(label, False, f"期望 {expected}，实际未抛错（返回 {result!r}）")

    # --------------------------------------------------------------- running
    def section(self, name: str) -> None:
        self.group = name

    def run_all(self) -> int:
        harness = Harness(self)
        self.started = time.time()
        selected = [name for name in SELF_TEST_GROUPS if name in self.only]
        try:
            for name in selected:
                start_a, start_f = self.assertions, self.failures
                self.section(name)
                print(f"[group] {name}", flush=True)
                try:
                    SELF_TEST_GROUPS[name](self, harness)
                except Exception as exc:  # noqa: BLE001 - a broken group must not hide
                    self.failures += 1
                    self.problems.append(f"FAIL [{name}] 分组异常 {type(exc).__name__}: {exc}")
                    print(f"  FAIL [{name}] 分组异常 {type(exc).__name__}: {exc}", flush=True)
                self.per_group[name] = (self.assertions - start_a, self.failures - start_f)
                print(f"[group] {name}: 断言 {self.per_group[name][0]} 条，失败 {self.per_group[name][1]} 条", flush=True)
        finally:
            harness.close()
        print()
        for name, (count, failed) in self.per_group.items():
            flag = "ok" if failed == 0 else "FAIL"
            print(f"  {name:22} {count:4} 条  {failed:3} 失败  {flag}")
        print(
            f"合计 {self.assertions} 条断言，{len(selected)}/{len(SELF_TEST_GROUPS)} 组，"
            f"{self.failures} 条失败，用时 {time.time() - self.started:.1f}s"
        )
        if self.problems:
            print("\n".join(self.problems[:60]))
        return self.assertions

    @property
    def ok(self) -> bool:
        if self.failures:
            return False
        if not self.full_run:
            return True
        return self.assertions >= MIN_ASSERTIONS and len(self.per_group) >= MIN_GROUPS

    @property
    def full_run(self) -> bool:
        return set(self.only) == set(SELF_TEST_GROUPS)


MIN_ASSERTIONS = 150
MIN_GROUPS = 12


class Harness:
    """One temp data dir, one fake CLI launcher, everything else built on demand."""

    def __init__(self, test: SelfTest):
        self.test = test
        self.root = Path(tempfile.mkdtemp(prefix="popopx-studio-selftest-"))
        os.chmod(self.root, 0o700)
        self.data_dir = self.root / "var" / "studio"
        self.env_file = self.root / ".env"
        self.cli_bin = self.root / "popopx-cli-fake"
        self._clients: List[Any] = []
        self._stacks: List[StudioStack] = []
        self._dbs: List[Database] = []
        self._write_launcher()
        self._write_env()

    # ------------------------------------------------------------------ setup
    def _write_launcher(self) -> None:
        interpreter = sys.executable or "/usr/bin/python3"
        script = (
            "#!/bin/sh\n"
            f'exec "{interpreter}" "{FAKE_CLI}" "$@"\n'
        )
        self.cli_bin.write_text(script, encoding="utf-8")
        os.chmod(self.cli_bin, 0o755)

    def _write_env(self) -> None:
        lines = [
            "STUDIO_HOST=127.0.0.1",
            "STUDIO_PORT=8090",
            "STUDIO_LOCALE=en",
            f"STUDIO_DATA_DIR={self.data_dir}",
            f"CLI_BIN_PATH={self.cli_bin}",
            "BOT_WS_PORT_BASE=5350",
            "BOT_WS_PORT_MAX=5399",
            "STUDIO_ADMIN_TOKEN=self-test-token",
        ]
        self.env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.chmod(self.env_file, SECURE_FILE_MODE)

    def env(self, **overrides: Any) -> Dict[str, str]:
        """A fresh environment mapping; ``None`` deletes a key."""
        base = {
            "STUDIO_HOST": DEFAULT_HOST,
            "STUDIO_PORT": str(DEFAULT_PORT),
            "STUDIO_DATA_DIR": str(self.data_dir),
            "CLI_BIN_PATH": str(self.cli_bin),
            "STUDIO_ADMIN_TOKEN": "self-test-token",
            "BOT_WS_PORT_BASE": "5350",
            "BOT_WS_PORT_MAX": "5399",
        }
        for key, value in overrides.items():
            if value is None:
                base.pop(key, None)
            else:
                base[key] = str(value)
        return base

    def settings(self, **overrides: Any) -> Settings:
        return load_settings(self.env(**overrides))

    def database(self, name: str = "ledger") -> Database:
        db = connect(self.root / f"{name}.db")
        self._dbs.append(db)
        return db

    def stack(self, tag: str = "", *, db: Optional[Database] = None, plugins_dir: Optional[Path] = None, **overrides: Any) -> StudioStack:
        if tag:
            overrides.setdefault("STUDIO_DATA_DIR", str(self.root / "var" / tag))
        settings = self.settings(**overrides)
        settings.ensure_directories()
        built = build_stack(settings, db=db, plugins_dir=plugins_dir, tick_interval=5.0)
        self._stacks.append(built)
        return built

    def client(self, stack: Optional[StudioStack] = None, **overrides: Any):
        from fastapi.testclient import TestClient

        built = stack if stack is not None else self.stack(**overrides)
        app = create_app(stack=built, managed=False)
        client = TestClient(app)
        self._clients.append(client)
        return client, built

    def auth(self) -> Dict[str, str]:
        return {"X-Studio-Token": "self-test-token"}

    def async_run(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        async def runner() -> Any:
            return await fn(*args, **kwargs)

        return asyncio.run(runner())

    def async_in(self, stack: StudioStack, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Run one coroutine against *stack* inside a single fresh loop."""

        async def runner() -> Any:
            try:
                return await fn(stack, *args, **kwargs)
            finally:
                await stack.stop()

        return asyncio.run(runner())

    def close(self) -> None:
        for client in self._clients:
            try:
                client.close()
            except Exception:  # noqa: BLE001 - teardown is best effort
                pass
        for db in self._dbs:
            try:
                db.close()
            except Exception:  # noqa: BLE001
                pass
        for stack in self._stacks:
            try:
                stack.db.close()
            except Exception:  # noqa: BLE001
                pass
        shutil.rmtree(self.root, ignore_errors=True)


# --------------------------------------------------------------------------- 1
def group_config(test: SelfTest, h: Harness) -> None:
    t = test
    parsed = parse_env_text('A=1\nexport B="two words"\nC=3 # trailing\n# comment\nD=\nE="x"\n')
    t.eq("env 解析数量", len(parsed), 5)
    t.eq("普通赋值", parsed["A"], "1")
    t.eq("export 前缀", parsed["B"], "two words")
    t.eq("行尾注释剥离", parsed["C"], "3")
    t.eq("空值保留键", parsed.get("D", "<missing>"), "")
    t.check("注释行不产键", "#" not in parsed and "comment" not in parsed, str(parsed))
    t.eq("非法键名忽略", parse_env_text("=novalue"), {})

    t.eq("回环主机 127", is_loopback_host("127.0.0.1"), True)
    t.eq("回环主机 localhost", is_loopback_host("localhost"), True)
    t.eq("回环主机 ::1", is_loopback_host("::1"), True)
    t.eq("回环主机带方括号", is_loopback_host("[::1]"), True)
    t.eq("回环主机 127.9.9.9", is_loopback_host("127.9.9.9"), True)
    t.eq("非回环 0.0.0.0", is_loopback_host("0.0.0.0"), False)
    t.eq("非回环局域网", is_loopback_host("192.168.1.10"), False)
    t.eq("非回环公网", is_loopback_host("8.8.8.8"), False)
    t.eq("非法第四段", is_loopback_host("127.0.0.999"), False)

    s = h.settings()
    t.eq("默认端口", s.port, 8090)
    t.eq("默认主机", s.host, "127.0.0.1")
    t.eq("默认数据目录", s.data_dir, h.data_dir.resolve())
    t.eq("默认 CLI 路径", str(s.cli_bin_path), str(h.cli_bin))
    t.eq("端口基址", s.ws_port_base, 5350)
    t.eq("端口上限", s.ws_port_max, 5399)
    t.eq("默认语种", s.default_locale, "en")
    t.check("令牌已配置", bool(s.admin_token))
    t.eq("默认常量 CLI 路径", DEFAULT_CLI_BIN_PATH, "/usr/local/bin/popopx-cli")
    t.eq("权限基线", SECURE_FILE_MODE, 0o600)
    t.eq("目录基线", SECURE_DIR_MODE, 0o700)

    t.raises("拒绝非回环监听", ConfigError, load_settings, h.env(STUDIO_HOST="0.0.0.0"))
    lan = load_settings(h.env(STUDIO_HOST="0.0.0.0", STUDIO_ALLOW_LAN="1"))
    t.eq("显式允许 LAN 后放行", lan.host, "0.0.0.0")
    t.eq("LAN 标记", lan.allow_lan, True)
    t.raises("端口越界", ConfigError, load_settings, h.env(STUDIO_PORT="70000"))
    t.raises("端口非数字", ConfigError, load_settings, h.env(STUDIO_PORT="abc"))
    t.raises("端口区间倒挂", ConfigError, load_settings, h.env(BOT_WS_PORT_BASE="5400", BOT_WS_PORT_MAX="5300"))
    t.eq("端口字符串带空格仍解析", load_settings(h.env(STUDIO_PORT=" 8123 ")).port, 8123)

    no_token = load_settings(h.env(STUDIO_ADMIN_TOKEN=None))
    t.check("缺少令牌时给出警告", any("STUDIO_ADMIN_TOKEN" in w for w in no_token.startup_warnings), str(no_token.startup_warnings))
    missing_cli = load_settings(h.env(CLI_BIN_PATH=str(h.root / "nope")))
    t.check("缺少二进制时给出警告", any("CLI 二进制" in w for w in missing_cli.startup_warnings), str(missing_cli.startup_warnings))
    bad_locale = load_settings(h.env(STUDIO_LOCALE="ko"))
    t.eq("不支持语种回退 en", bad_locale.default_locale, "en")
    t.check("不支持语种有警告", any("STUDIO_LOCALE=ko" in w for w in bad_locale.startup_warnings), str(bad_locale.startup_warnings))
    th_locale = load_settings(h.env(STUDIO_LOCALE="th"))
    t.eq("受支持语种生效", th_locale.default_locale, "th")

    loose = h.root / "loose.env"
    loose.write_text("STUDIO_ADMIN_TOKEN=x\n", encoding="utf-8")
    os.chmod(loose, 0o644)
    warnings = permission_warnings([("配置文件", loose)])
    t.eq("0644 触发一条警告", len(warnings), 1)
    t.contains("警告给出 chmod 修法", warnings[0], "chmod 600")
    t.contains("警告包含实际模式", warnings[0], "0644")
    tight = h.root / "tight.env"
    tight.write_text("STUDIO_ADMIN_TOKEN=x\n", encoding="utf-8")
    os.chmod(tight, 0o600)
    t.eq("0600 无警告", permission_warnings([("配置文件", tight)]), [])
    t.eq("缺失路径跳过", permission_warnings([("状态文件", None)]), [])
    t.eq("目录权限为 0700", mode_of(h.root), 0o700)
    t.eq("env 文件权限为 0600", mode_of(h.env_file), 0o600)

    from_file = load_env_file(h.env_file, {"STUDIO_PORT": "9000"})
    t.check("已存在的环境变量优先", "STUDIO_PORT" not in from_file, str(from_file))
    t.eq("其它键从文件读取", from_file.get("STUDIO_LOCALE"), "en")
    os.chmod(h.env_file, 0o640)
    loose_group = permission_warnings([("配置文件", h.env_file)])
    t.check("0640 仍触发安全警告", any("权限为 0640" in w for w in loose_group), str(loose_group))
    os.chmod(h.env_file, SECURE_FILE_MODE)

    s.ensure_directories()
    t.check("数据目录已创建", s.data_dir.is_dir())
    t.check("bots 目录已创建", s.bots_dir.is_dir())
    t.check("backups 目录已创建", s.backups_dir.is_dir())
    t.eq("数据目录权限收紧到 0700", mode_of(s.data_dir), SECURE_DIR_MODE)
    t.eq("bots 目录权限收紧到 0700", mode_of(s.bots_dir), SECURE_DIR_MODE)
    t.eq("backups 目录权限收紧到 0700", mode_of(s.backups_dir), SECURE_DIR_MODE)
    os.chmod(s.backups_dir, 0o755)
    s.startup_warnings.clear()
    s.ensure_directories()
    t.eq("越权目录会被再次收紧", mode_of(s.backups_dir), SECURE_DIR_MODE)
    t.check("收紧动作写进启动警告", any("已收紧" in w for w in s.startup_warnings), str(s.startup_warnings))
    t.eq("bots 路径布局", s.cli_data_dir("bot_x"), s.bots_dir / "bot_x" / "cli-data")
    t.eq("包装脚本路径", s.wrapper_path("bot_x"), s.bots_dir / "bot_x" / "run-cli.sh")
    t.eq("pid 文件路径", s.pid_file("bot_x"), s.bots_dir / "bot_x" / "cli.pid")
    t.eq("状态文件路径", s.state_file.name, "studio.state.json")
    t.eq("默认数据目录函数", Path(DEFAULT_CLI_BIN_PATH).is_absolute(), True)


# --------------------------------------------------------------------------- 2
def group_database(test: SelfTest, h: Harness) -> None:
    t = test
    db = h.database("ledger2")
    t.eq("WAL 模式", db.journal_mode().lower(), "wal")
    t.eq("账本文件权限 0600", mode_of(db.path), SECURE_FILE_MODE)
    t.check("账本旁挂 WAL 也不放行",
            all(mode_of(p) in (None, SECURE_FILE_MODE)
                for p in db.path.parent.glob(db.path.name + "-*")),
            str([(p.name, oct(p.stat().st_mode & 0o777)) for p in db.path.parent.glob(db.path.name + '-*')]))
    t.eq("外键开启", db.foreign_keys_enabled(), True)
    t.eq("迁移到当前版本", db.schema_version(), SCHEMA_VERSION)
    tables = db.table_names()
    for name in ("bots", "reply_rules", "routing_rules", "plugin_configs", "message_logs", "schema_migrations"):
        t.contains(f"表 {name} 存在", ",".join(tables), name)
    t.eq("重复迁移幂等", db.migrate(), [])
    t.eq("迁移目标越界即空操作", db.migrate(target_version=99), [])
    t.eq("越界迁移不降版本", db.schema_version(), SCHEMA_VERSION)

    bot = db.create_bot("support", 5350, display_name="客服小助手", default_locale="th")
    t.check("Bot id 前缀", bot["id"].startswith("bot_"), bot["id"])
    t.eq("初始状态", bot["status"], "draft")
    t.eq("端口写入", bot["port"], 5350)
    t.eq("显示名", bot["display_name"], "客服小助手")
    t.eq("语种写入", bot["default_locale"], "th")
    t.check("自动生成的 token 形如 <id>:secret", re.match(r"^\d{8}:[0-9a-f]{32}$", bot["bot_token"]) is not None, bot["bot_token"])
    t.eq("token 不重复", len({new_bot_token() for _ in range(20)}), 20)
    t.eq("按 id 查回", db.get_bot(bot["id"])["name"], "support")
    t.eq("按名字查回", db.get_bot_by_name("support")["id"], bot["id"])
    t.eq("按 token 查回", db.get_bot_by_token(bot["bot_token"])["id"], bot["id"])
    t.eq("按端口查回", db.get_bot_by_port(5350)["id"], bot["id"])
    t.eq("未知 token 返回 None", db.get_bot_by_token("nope"), None)
    t.eq("未知 id 返回 None", db.get_bot("missing"), None)
    t.raises("重名拒绝", LedgerError, db.create_bot, "support", 5351)
    t.raises("端口冲突拒绝", LedgerError, db.create_bot, "other", 5350)
    t.raises("非法名称拒绝", LedgerError, db.create_bot, "bad name!", 5352)
    unknown_locale = db.create_bot("localex", 5353, default_locale="ko")
    t.eq("未知语种由账本原样保存", unknown_locale["default_locale"], "ko")
    t.eq("未知语种归一化为空串", normalize_locale("ko"), "")
    t.eq("空串由调用点回退到基准语种", normalize_locale("ko") or FALLBACK_LOCALE, "en")
    t.eq("回退语种有词条", len(admin_strings("ko")), len(admin_strings("en")))
    t.raises("名称太短拒绝", LedgerError, db.create_bot, "kr", 5354)

    t.eq("端口分配跳过占用", db.next_free_port(5350, 5399), 5351)
    t.eq("分配后可注册", db.create_bot("second", db.next_free_port(5350, 5399))["port"], 5351)
    t.eq("再次分配继续递增", db.next_free_port(5350, 5399), 5352)
    t.eq("空档区间返回基址", h.database("fresh").next_free_port(6000, 6010), 6000)

    updated = db.update_bot(bot["id"], welcome_text="hi", auto_accept=1, default_locale="de")
    t.eq("更新欢迎语", updated["welcome_text"], "hi")
    t.eq("更新自动通过", int(updated["auto_accept"]), 1)
    t.eq("更新语种", updated["default_locale"], "de")
    t.raises("未知字段拒绝", LedgerError, db.update_bot, bot["id"], nope=1)
    t.raises("非法状态拒绝", LedgerError, db.update_bot, bot["id"], status="paused")
    t.raises("更新不存在 Bot", LedgerError, db.update_bot, "ghost", welcome_text="x")

    second = db.get_bot_by_name("second")
    db.update_bot(second["id"], status="running")
    summary = db.bot_summary()
    t.eq("统计总数", summary["total"], 3)
    t.eq("统计运行中", summary["running"], 1)
    db.update_bot(second["id"], status="error")
    t.eq("统计错误", db.bot_summary()["error"], 1)

    rule = db.upsert_reply_rule(bot["id"], name="greeting", trigger_type="exact", pattern="/start", reply_text="欢迎")
    t.eq("规则类型", rule["trigger_type"], "exact")
    t.check("规则 id 为正整数", isinstance(rule["id"], int) and rule["id"] > 0, str(rule["id"]))
    same = db.upsert_reply_rule(bot["id"], rule_id=rule["id"], name="greeting2", trigger_type="exact", pattern="/start", reply_text="欢迎2")
    t.eq("同 id 更新不新增", (same["id"], same["name"], same["reply_text"]), (rule["id"], "greeting2", "欢迎2"))
    t.eq("规则列表长度", len(db.list_reply_rules(bot["id"])), 1)
    # 冷备恢复走的是另一条连接：UPSERT 命中 DO UPDATE 分支时 last_insert_rowid 不更新，
    # 只信 cursor.lastrowid 会把已存在的规则读成 id 0。
    other = Database(db.path)
    revived = other.upsert_reply_rule(bot["id"], trigger_type="exact", pattern="/start",
                                      reply_text="新连接改写", name="greeting3")
    t.eq("新连接改写已存在的规则命中同一行", revived["id"], rule["id"])
    t.eq("新连接改写后的内容可读回", (revived["reply_text"], revived["name"]), ("新连接改写", "greeting3"))
    t.eq("同 (bot, type, pattern) 不产生第二行", len(db.list_reply_rules(bot["id"])), 1)
    other.close()
    t.raises("非法触发类型", LedgerError, db.upsert_reply_rule, bot["id"], trigger_type="glob", pattern="x", reply_text="y")
    t.raises("空回复拒绝", LedgerError, db.upsert_reply_rule, bot["id"], trigger_type="exact", pattern="x", reply_text="")
    db.upsert_reply_rule(bot["id"], trigger_type="regex", pattern="^价", reply_text="价格", cooldown_seconds=30, enabled=False)
    t.eq("仅启用规则数", len(db.list_reply_rules(bot["id"], enabled_only=True)), 1)
    t.eq("全部规则数", len(db.list_reply_rules(bot["id"])), 2)
    t.eq("触发类型集合", TRIGGER_TYPES, ("exact", "prefix", "regex", "default"))
    db.register_rule_hit(rule["id"])
    t.eq("命中计数增长", db.get_reply_rule(rule["id"])["hits"], 1)
    t.check("删除规则", db.delete_reply_rule(rule["id"]))
    t.eq("重复删除返回 False", db.delete_reply_rule(rule["id"]), False)
    t.eq("跨 Bot 不可见规则", len(db.list_reply_rules("bot_other")), 0)

    route = db.upsert_routing_rule(
        bot["id"], name="转人工", source_type="direct", keyword_mode="contains", keywords=["退款", "人工"],
        target_type="group", target_ref="#42", template="[{sender_name}] {text}", quote_reply=True, cooldown_seconds=5,
    )
    t.eq("路由关键词解码为列表", route["keywords"], ["退款", "人工"])
    t.eq("路由目标", route["target_ref"], "#42")
    t.eq("引用回复开关", int(route["quote_reply"]), 1)
    t.raises("非法 source_type", LedgerError, db.upsert_routing_rule, bot["id"], source_type="sms", target_ref="#1")
    t.raises("转发目标为空拒绝", LedgerError, db.upsert_routing_rule, bot["id"], target_type="group", target_ref="")
    t.raises("未支持的关键词模式拒绝", LedgerError, db.upsert_routing_rule, bot["id"], keyword_mode="all", target_ref="#1")
    t.raises("非 any 模式缺关键词拒绝", LedgerError, db.upsert_routing_rule, bot["id"], keyword_mode="contains", keywords=[], target_ref="#1")
    bcast = db.upsert_routing_rule(bot["id"], name="广播", target_type="broadcast", target_ref="")
    t.eq("广播允许空 target_ref", bcast["target_ref"], "")
    t.eq("路由规则数", len(db.list_routing_rules(bot["id"])), 2)
    t.check("删除路由", db.delete_routing_rule(route["id"]))
    t.check("删除广播路由", db.delete_routing_rule(bcast["id"]))

    cfg = db.set_plugin_config("llm_bridge", {"model": "gpt-4o-mini", "api_key": "sk-1"}, bot_id=bot["id"], enabled=True)
    t.eq("插件配置写入", cfg["config"]["model"], "gpt-4o-mini")
    t.eq("插件启停写入", int(cfg["enabled"]), 1)
    merged = db.effective_plugin_config("llm_bridge", bot["id"])
    t.eq("有效配置是二元组", len(merged), 2)
    t.eq("有效配置内容", merged[1]["api_key"], "sk-1")
    global_cfg = db.set_plugin_config("llm_bridge", {"temperature": 0.2}, enabled=True)
    scoped = db.effective_plugin_config("llm_bridge", bot["id"])[1]
    t.eq("Bot 级覆盖全局", scoped["model"], "gpt-4o-mini")
    t.eq("全局值作为兜底", db.effective_plugin_config("llm_bridge", "bot_none")[1]["temperature"], 0.2)
    t.raises("非法 JSON 配置", LedgerError, db.set_plugin_config, "x", {"bad": {1, 2}})
    t.eq("插件配置列表", len(db.list_plugin_configs()), 2)
    t.eq("单插件查询", db.get_plugin_config("llm_bridge", bot_id=bot["id"])["plugin_id"], "llm_bridge")
    t.eq("不存在的插件配置", db.get_plugin_config("missing"), None)

    log_id = db.log_message(bot["id"], "in", chat_type="direct", chat_ref="@7", sender="u7", text="你好")
    t.check("日志 id 递增", log_id > 0, str(log_id))
    db.log_message(bot["id"], "out", chat_ref="#42", text="已转达", status="forwarded")
    db.log_message(bot["id"], "out", chat_ref="#42", text="失败", status="error", error="timeout")
    t.raises("非法方向", LedgerError, db.log_message, bot["id"], "sideways")
    t.raises("非法状态", LedgerError, db.log_message, bot["id"], "in", status="weird")
    logs = db.recent_logs(bot["id"], limit=10)
    t.eq("日志条数", len(logs), 3)
    t.eq("日志倒序", logs[0]["direction"], "out")
    stats = db.message_stats(bot["id"])
    t.eq("入站计数", stats["incoming"], 1)
    t.eq("出站计数", stats["outgoing"], 2)
    t.eq("分桶按方向与状态", stats["breakdown"], {"in:ok": 1, "out:error": 1, "out:forwarded": 1})
    t.eq("分桶总量等于日志量", sum(stats["breakdown"].values()), 3)
    t.eq("无插件写入时插件榜为空", stats["top_plugins"], {})
    trend = db.message_trend(bot["id"], days=7)
    t.eq("趋势只列有消息的日期", len(trend), 1)
    t.eq("趋势计数为整数", sum(int(row["total"]) for row in trend), 3)
    t.eq("全库日志数", len(db.recent_logs(limit=50)), 3)

    db.log_message(second["id"], "in", chat_ref="@3", text="删除前的留言")
    db.delete_bot(second["id"])
    t.eq("软删除后 get_bot 为空", db.get_bot(second["id"]), None)
    t.check("软删除仍可查", db.get_bot(second["id"], include_deleted=True) is not None)
    t.eq("软删除保留日志", db.recent_logs(second["id"], limit=5)[0]["text"], "删除前的留言")
    t.raises("软删除仍占用名字", LedgerError, db.create_bot, "second", 5499)
    t.raises("软删除仍占用端口", LedgerError, db.create_bot, "reclaim", second["port"])
    db.delete_bot(second["id"], hard=True)
    t.eq("硬删除后不可查", db.get_bot(second["id"], include_deleted=True), None)
    revived = db.create_bot("second", second["port"])
    t.check("硬删除释放名字与端口", revived["id"] != second["id"], revived["id"])

    a, b = new_bot_id(), new_bot_token()
    t.check("id 唯一性样本", len({new_bot_id() for _ in range(50)}) == 50)
    t.check("token 唯一性样本", len({new_bot_token() for _ in range(50)}) == 50)
    t.contains("id 前缀", a, "bot_")
    t.check("token 含分隔符", ":" in b, b)
    t.check("可更新字段白名单覆盖状态", "status" in BOT_FIELDS and "default_locale" in BOT_FIELDS, str(BOT_FIELDS))
    db.close()


# --------------------------------------------------------------------------- 3
def group_ws_protocol(test: SelfTest, h: Harness) -> None:
    t = test
    frame = build_frame("c1", "/_show_address 1")
    decoded = json.loads(frame)
    t.eq("帧包含 corrId", decoded["corrId"], "c1")
    t.eq("帧包含 cmd", decoded["cmd"], "/_show_address 1")
    t.check("帧是单行 JSON", "\n" not in frame, frame)

    address_cmd = cmd_create_address(1)
    t.eq("永久地址命令", address_cmd, "/_address 1")
    short_cmd = cmd_short_link_address(1)
    t.eq("短链地址命令", short_cmd, "/_short_link_address 1")
    t.eq("短链可带 pq_ratchet", cmd_short_link_address(1, pq_ratchet=True), "/_short_link_address 1 pq_ratchet=on")
    t.ne("短链命令不同于永久地址", short_cmd.split()[0], address_cmd.split()[0])
    t.ne("严禁使用不存在的 /address 命令", address_cmd.split()[0], "/address")
    t.raises("非法 userId", WebSocketProtocolError, cmd_create_address, "abc")
    t.raises("负 userId", WebSocketProtocolError, cmd_create_address, -3)
    t.eq("字符串数字可用", cmd_show_address("7"), "/_show_address 7")

    # 探活命令必须与真实协议同名：/user、/users、/_user（popopx-chat Commands.hs:196,205,2705）。
    t.eq("读当前 profile 命令", cmd_show_active_user(), "/user")
    t.eq("列出全部 profile 命令", cmd_list_users(), "/users")
    t.eq("激活既有 profile 命令", cmd_set_active_user(7), "/_user 7")
    t.raises("/_user 非法 userId", WebSocketProtocolError, cmd_set_active_user, "abc")
    t.ne("严禁臆造的 /active_user 探活命令", cmd_show_active_user(), "/active_user")
    t.eq("activeUser 取 userId", extract_user_id({"type": "activeUser", "user": {"userId": 9}}), 9)
    t.eq("user 为 null 时取不到 userId", extract_user_id({"type": "activeUser", "user": None}), None)
    t.eq("usersList 的包裹结构同样可读", extract_user_id({"user": {"userId": 3}, "unreadCount": 0}), 3)
    t.eq("取 localDisplayName", extract_user_name({"user": {"localDisplayName": "客服"}}), "客服")
    t.eq("无 localDisplayName 时退到 profile",
         extract_user_name({"user": {"profile": {"displayName": "名片名"}}}), "名片名")
    t.eq("user 为 null 时名字为空", extract_user_name({"user": None}), "")
    no_active = decode_frame(json.dumps(
        {"corrId": "c1", "resp": {"type": "chatCmdError",
                                  "chatError": {"type": "error", "errorType": {"type": "noActiveUser"}}}}))
    t.eq("noActiveUser 是错误帧", no_active.is_error, True)
    t.eq("错误帧保留 corrId 以便唤醒等待者", no_active.corr_id, "c1")

    settings = build_address_settings(business_address=True, auto_accept=True, accept_incognito=False, welcome_text="欢迎")
    t.eq("businessAddress 为真", settings["businessAddress"], True)
    t.eq("autoAccept 结构", settings["autoAccept"], {"acceptIncognito": False})
    t.eq("autoReply 结构", settings["autoReply"], {"type": "text", "text": "欢迎"})
    t.raises("商业地址禁止匿名接受", WebSocketProtocolError, build_address_settings, business_address=True, accept_incognito=True)
    no_welcome = build_address_settings(business_address=True, auto_accept=False)
    t.eq("关闭自动接受时 autoAccept 为 None", no_welcome["autoAccept"], None)
    t.eq("空欢迎语时 autoReply 为 None", no_welcome["autoReply"], None)
    wire = cmd_address_settings(1, settings)
    t.contains("命令前缀正确", wire, "/_address_settings 1 ")
    t.ne("严禁使用不存在的 /auto_accept", wire.split()[0], "/auto_accept")
    payload = json.loads(wire.split(" ", 2)[2])
    t.eq("线上 JSON 保真", payload["autoAccept"], {"acceptIncognito": False})
    t.contains("欢迎语保留中文", wire, "欢迎")
    t.check("JSON 紧凑无多余空格", " " not in wire.split(" ", 2)[2].replace('\\"', ""), wire)

    group_cmd = cmd_create_group(1, "客服群")
    t.contains("建群命令", group_cmd, "/_group 1")
    link_cmd = cmd_create_group_link(42, "observer")
    t.eq("群短链命令", link_cmd, "/_create link #42 observer")
    t.eq("群链接只允许两种角色", LINK_ROLES, ("observer", "member"))
    t.raises("群链接禁止 admin 角色", WebSocketProtocolError, cmd_create_group_link, 42, "admin")
    t.raises("群链接禁止 owner 角色", WebSocketProtocolError, cmd_create_group_link, 42, "owner")
    t.raises("群链接 groupId 必须是数字", WebSocketProtocolError, cmd_create_group_link, "x")

    send = cmd_send_message("group", 42, text="你好\n第二行", quoted_item_id=77)
    t.contains("发送命令前缀", send, "/_send #42 json ")
    body = json.loads(send.split(" json ", 1)[1])
    t.eq("消息体结构", body[0]["msgContent"], {"type": "text", "text": "你好\n第二行"})
    t.eq("引用项写入", body[0]["quotedItemId"], 77)
    t.check("换行未破坏命令", "\n" not in send, send)
    live = cmd_send_message("direct", 7, text="x", live=True, ttl=30)
    t.contains("live 开关", live, " live")
    t.contains("ttl 参数", live, "ttl=30")
    t.raises("空内容拒绝", WebSocketProtocolError, cmd_send_message, "direct", 7)
    t.raises("非法会话类型", WebSocketProtocolError, cmd_send_message, "channel", 7, text="x")
    t.raises("非数字 chatId", WebSocketProtocolError, cmd_send_message, "group", "x", text="y")
    plain = cmd_send_plain_text("direct", 7, "hi")
    t.eq("纯文本形式", plain, "/_send @7 text hi")
    t.raises("纯文本禁止换行", WebSocketProtocolError, cmd_send_plain_text, "direct", 7, "a\nb")
    t.eq("ref_for direct", ref_for("direct", 7), "@7")
    t.eq("ref_for group", ref_for("group", 42), "#42")
    t.eq("ref_for local", ref_for("local", 3), "*3")
    t.raises("ref_for 非法类型", ValueError, ref_for, "sms", 1)

    ok_frame = decode_frame(json.dumps({"corrId": "c1", "resp": {"type": "activeUser", "user": {"userId": 1}}}))
    t.eq("解码 corrId", ok_frame.corr_id, "c1")
    t.eq("解码 type", ok_frame.resp_type, "activeUser")
    t.eq("错误帧识别", decode_frame(json.dumps({"resp": {"type": "chatCmdError", "chatError": {"error": "syntax"}}})).is_error, True)
    t.raises("非法 JSON 帧", WebSocketProtocolError, decode_frame, "{not json")
    t.raises("非对象帧", WebSocketProtocolError, decode_frame, "[1,2]")
    t.eq("字节帧可解码", decode_frame(b'{"resp":{"type":"x"}}').resp_type, "x")
    t.eq("扁平化错误", flatten_error({"type": "chatCmdError", "chatError": {"error": "syntax", "kind": "bad"}}), "syntax")
    t.eq("深层错误扁平化", flatten_error({"a": {"b": {"error": "notFound"}}}), "notFound")
    t.eq("无错误返回空", flatten_error({"type": "ok"}), "")

    user_payload = {"type": "activeUser", "user": {"userId": 3}}
    t.eq("extract_user_id", extract_user_id(user_payload), 3)
    t.eq("extract_user_id 缺失", extract_user_id({"type": "x"}), None)
    link_payload = {"type": "userContactLinkCreated", "connLinkContact": {"connFullLink": "popopx:/full", "connShortLink": "popopx:/short"}}
    t.eq("extract_created_link", extract_created_link(link_payload), ("popopx:/full", "popopx:/short"))
    t.eq("extract_group_id", extract_group_id({"type": "groupCreated", "groupInfo": {"groupId": 42}}), 42)
    t.eq("extract_address_settings", extract_address_settings({"contactLink": {"addressSettings": {"businessAddress": True}}})["businessAddress"], True)

    event_payload = {
        "type": "newChatItems",
        "chatItems": [{
            "chatInfo": {"type": "direct", "contact": {"contactId": 7, "localDisplayName": "小明", "profile": {"displayName": "小明"}}},
            "chatItem": {
                "chatDir": {"type": "directRcv"},
                "meta": {"itemId": 77, "itemTs": "2026-11-24T08:00:00Z", "itemText": "你好，Bot", "itemStatus": {"type": "received"}},
                "content": {"type": "text", "text": "你好，Bot"},
            },
        }],
    }
    events = normalize_new_chat_items(event_payload)
    t.eq("事件数", len(events), 1)
    ev = events[0]
    t.eq("方向为入站", ev.direction, "in")
    t.eq("会话类型", ev.chat_type, "direct")
    t.eq("会话引用", ev.chat_ref, "@7")
    t.eq("正文", ev.text, "你好，Bot")
    t.eq("itemId", ev.item_id, 77)
    t.eq("发送人", ev.sender_name, "小明")
    t.eq("as_dict 保真", ev.as_dict()["chat_ref"], "@7")
    t.eq("is_incoming", ev.is_incoming, True)
    t.eq("时间戳解析为纪元秒", ev.ts, 1795478400.0)
    sent = normalize_new_chat_items({
        "type": "newChatItems",
        "chatItems": [{
            "chatInfo": {"type": "group", "groupInfo": {"groupId": 42}},
            "chatItem": {"chatDir": {"type": "groupSnd"}, "meta": {"itemId": 1}, "content": {"type": "text", "text": "x"}},
        }],
    })
    t.eq("出站消息被忽略", [e.direction for e in sent], ["out"])
    t.eq("群引用形如 #42", sent[0].chat_ref, "#42")
    calm = ReconnectPolicy(jitter=0.0)
    delays = [calm.next_delay() for _ in range(9)]
    t.eq("退避序列严格按倍递增", delays, [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 60.0, 60.0, 60.0])
    rough = ReconnectPolicy()
    first = [rough.next_delay() for _ in range(1)]
    t.check("默认抖动在 ±25% 内", 0.75 <= first[0] <= 1.25, str(first))
    jittered = ReconnectPolicy(attempts=6)
    spread = {jittered.next_delay() for _ in range(20)}
    t.check("抖动让同一步长产生不同等待", len(spread) > 1, str(sorted(spread))[:80])
    calm.reset()
    t.eq("reset 后回到基址", calm.next_delay(), 1.0)
    t.eq("策略可迭代", len(list(itertools.islice(ReconnectPolicy(jitter=0.0), 5))), 5)

    client = CLIWebSocketClient(5999)
    t.eq("客户端 URL 只绑回环", client.url, "ws://127.0.0.1:5999/")
    t.check("未连接状态", client.connected is False)
    t.check("corr id 递增唯一", len({client.next_corr_id() for _ in range(20)}) == 20)
    t.contains("corr id 前缀", client.next_corr_id("z"), "z")
    t.raises("非法端口拒绝", (WebSocketProtocolError, ValueError, OSError), CLIWebSocketClient, 0)
    t.raises("超范围端口拒绝", (WebSocketProtocolError, ValueError, OSError), CLIWebSocketClient, 70000)
    t.eq("CLICommandError 携带 resp_type", CLICommandError("x", resp_type="chatCmdError").resp_type, "chatCmdError")
    t.eq("CLITimeoutError 是协议错误子类", issubclass(CLITimeoutError, WebSocketProtocolError), True)
    err_frame = Frame(kind="error", corr_id="c1", resp_type="chatCmdError", payload={}, error="syntax")
    t.eq("错误帧标记", err_frame.is_error, True)
    t.eq("错误帧携带原因", err_frame.error, "syntax")
    t.eq("响应帧不是错误", Frame(kind="response", corr_id="c1", resp_type="activeUser").is_error, False)
    t.eq("事件帧可以没有 corrId", Frame(kind="event", corr_id=None, resp_type="newChatItems").corr_id, None)
    event_frame = decode_frame(json.dumps({"resp": event_payload}))
    from_frame = normalize_event(event_frame)
    t.eq("事件帧归一化数量", len(from_frame), 1)
    t.eq("事件帧类型", from_frame[0].event_type, "newChatItems")
    t.eq("事件帧正文", from_frame[0].text, "你好，Bot")
    t.eq("非消息帧不产事件", len(normalize_event(decode_frame(json.dumps({"corrId": "c", "resp": {"type": "response"}})))), 0)


# --------------------------------------------------------------------------- 4
def group_supervisor(test: SelfTest, h: Harness) -> None:
    t = test
    settings = h.settings()
    t.eq("二进制解析到替身", resolve_cli_binary(settings), h.cli_bin.resolve())
    t.eq("缺失二进制返回 None", resolve_cli_binary(h.settings(CLI_BIN_PATH=str(h.root / "ghost"))), None)
    t.eq("sha256 稳定", sha256_bytes(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    t.eq("sha256 长度", len(sha256_bytes(b"x")), 64)

    t.eq("空格分隔", split_server_list("smp1.popopx.im smp2.popopx.im"), ["smp1.popopx.im", "smp2.popopx.im"])
    t.eq("逗号分隔", split_server_list("a.example:443,b.example"), ["a.example:443", "b.example"])
    t.eq("分号与混排", split_server_list(" a ; b , c "), ["a", "b", "c"])
    t.eq("空输入", split_server_list(""), [])
    t.check("内置集群是 smp1..8", BUILTIN_SMP_SERVERS == tuple(f"smp{i}.popopx.im" for i in range(1, 9)), str(BUILTIN_SMP_SERVERS))
    t.eq("默认不覆写 SMP", effective_smp_servers({}, Settings()), [])
    t.eq("Bot 级覆写优先", effective_smp_servers({"smp_servers": "bot.example"}, Settings(cli_smp_servers="global.example")), ["bot.example"])
    t.eq("Studio 级覆写生效", effective_smp_servers({}, Settings(cli_smp_servers="g1.example g2.example")), ["g1.example", "g2.example"])

    paths = BotPaths.for_bot(settings, "bot_demo").create()
    t.eq("隔离数据目录", paths.cli_data, settings.bots_dir / "bot_demo" / "cli-data")
    t.check("目录已创建", paths.cli_data.is_dir() and paths.files_dir.is_dir() and paths.temp_dir.is_dir())
    t.eq("目录权限 0700", mode_of(paths.cli_data), 0o700)
    t.eq("包装脚本文件名", paths.wrapper.name, "run-cli.sh")
    t.eq("日志文件名尾部", paths.log_file.name.endswith(".log"), True)

    plain = build_cli_argv(h.cli_bin, 5231, paths)
    t.eq("argv 首元是二进制", plain[0], str(h.cli_bin))
    t.contains("端口参数", " ".join(plain), "--chat-server-port 5231")
    t.contains("数据库前缀", " ".join(plain), str(paths.db_prefix))
    t.contains("文件目录", " ".join(plain), "--files-folder")
    t.contains("临时目录", " ".join(plain), "--temp-folder")
    t.contains("日志级别", " ".join(plain), "--log-level important")
    t.check("默认不传 --server（继承二进制内置双栈集群）", "--server" not in plain, str(plain))
    overridden = build_cli_argv(h.cli_bin, 5231, paths, smp_servers=list(BUILTIN_SMP_SERVERS))
    t.check("覆写时带 --server", "--server" in overridden, str(overridden))
    server_token = overridden[overridden.index("--server") + 1]
    t.eq("SMP 列表是单个 argv token", server_token.count(" "), 7)
    t.ne("单个 token 未被拆成 8 个参数", len(overridden), len(plain) + 8)
    t.raises("端口越界拒绝", BotSupervisorError, build_cli_argv, h.cli_bin, 0, paths)
    t.raises("端口上限拒绝", BotSupervisorError, build_cli_argv, h.cli_bin, 70000, paths)

    # --user-display-name 只能在空库首启给：库里已有 profile 而名字不符时 CLI 直接退出
    # （popopx-chat Core.hs:79-82），常驻这个参数会把「改名」变成「再也起不来」。
    named = build_cli_argv(h.cli_bin, 5231, paths, profile_name="客服")
    t.contains("首启 argv 含 --user-display-name", " ".join(named), "--user-display-name 客服")
    t.eq("引导名是独立的 argv token", named[named.index("--user-display-name") + 1], "客服")
    t.check("默认不带该参数", "--user-display-name" not in plain, str(plain))
    t.check("纯空白引导名不注入", "--user-display-name" not in build_cli_argv(h.cli_bin, 5231, paths, profile_name="   "), "空白名也被注入")
    t.eq("空库时给出引导名", profile_bootstrap_name(paths, "客服"), "客服")
    Path(f"{paths.db_prefix}{CHAT_DB_SUFFIX}").write_bytes(b"SQLite format 3\x00")
    t.eq("库已存在则不再给名字", profile_bootstrap_name(paths, "客服"), "")
    t.eq("空名字不给引导", profile_bootstrap_name(paths, "  "), "")
    t.eq("display_name 优先于 name", bot_display_name({"display_name": "客服", "name": "cs_th"}), "客服")
    t.eq("无 display_name 时退到 name", bot_display_name({"name": "cs_th"}), "cs_th")
    t.eq("两者皆空时用兜底", bot_display_name({}, "bot_x"), "bot_x")

    script = render_wrapper_script(overridden, bot_id="bot_demo", paths=paths)
    t.contains("shebang 是 sh", script, "#!/bin/sh")
    t.contains("严格模式", script, "set -eu")
    t.contains("HOME 指向隔离目录", script, str(paths.cli_data))
    t.contains("TMPDIR 指向隔离目录", script, str(paths.temp_dir))
    t.contains("导出 HOME/TMPDIR", script, "export HOME TMPDIR")
    t.contains("exec 让 CLI 成为主进程", script, "\nexec ")
    t.check("剥引号后仍不拆词", server_token in script, "缺少带空格的 SMP 列表")
    t.raises("空 argv 拒绝", BotSupervisorError, render_wrapper_script, [], bot_id="x", paths=paths)
    named_script = render_wrapper_script(named, bot_id="bot_demo", paths=paths)
    # exec 行是「反斜杠续行 + 两空格缩进」逐个写参数的，展平之后才能对照 argv 断言。
    flat_script = " ".join(named_script.replace("\\\n", " ").split())
    t.contains("包装脚本也带引导名", flat_script, "--user-display-name '客服'")
    t.contains("包装脚本逐参数续行", named_script, " \\\n  ")
    written = write_wrapper(paths, script)
    t.eq("包装脚本权限 0755", mode_of(written), 0o755)

    # 用真实 /bin/sh 跑一遍包装脚本，证明参数逐个成行、外层引号被剥也不拆词。
    echo = paths.files_dir / "argv_echo.py"
    echo.write_text(
        f'#!{sys.executable}\nimport json, sys\nprint(json.dumps(sys.argv[1:], ensure_ascii=False))\n',
        encoding="utf-8",
    )
    os.chmod(echo, 0o755)
    replay = write_wrapper(paths, render_wrapper_script([str(echo), *overridden[1:]], bot_id="bot_demo", paths=paths))
    proc = subprocess.run(["sh", str(replay)], capture_output=True, text=True)
    if proc.returncode != 0:
        t.check("包装脚本可被 sh 执行", False, proc.stderr[:200])
    else:
        argv_back = json.loads(proc.stdout)
        t.eq("shell 往返后参数数量不变", len(argv_back), len(overridden) - 1)
        t.eq("SMP 列表仍是一个参数", [a for a in argv_back if " " in a], [server_token])
        t.check("单个参数未被拆词", "smp1.popopx.im" not in [a for a in argv_back if " " not in a], str(argv_back)[:200])
        write_wrapper(paths, script)

    t.eq("解析群引用", parse_chat_ref("#42"), ("group", 42))
    t.eq("解析联系人引用", parse_chat_ref("@7"), ("direct", 7))
    t.eq("裸联系人号", parse_chat_ref(9), ("direct", 9))
    t.raises("非法引用拒绝", BotSupervisorError, parse_chat_ref, "42")
    t.raises("空引用拒绝", BotSupervisorError, parse_chat_ref, "")
    t.eq("引用互逆", parse_chat_ref(ref_for("group", 42)), ("group", 42))

    t.eq("状态默认值", BotRuntime_sample().state, "stopped")
    t.check("runtime.as_dict 有 bot_id", "bot_id" in BotRuntime_sample().as_dict(), str(BotRuntime_sample().as_dict()))

    result = h.async_in(h.stack(tag="proc"), live_supervisor)
    for label, condition, detail in result:
        t.check(label, condition, detail)


def BotRuntime_sample() -> BotRuntime:
    return BotRuntime(bot_id="bot_x", name="bot_x", port=5230, paths=BotPaths.for_bot(Settings(), "bot_x"))


def port_busy(port: int) -> bool:
    """True when something already listens on the loopback port (an outside Studio counts)."""
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=0.25):
            return True
    except OSError:
        return False


async def live_supervisor(stack: StudioStack) -> List[Tuple[str, Any, str]]:
    out: List[Tuple[str, Any, str]] = []
    sup = stack.supervisor
    out.append(("启动前无受管客户端", sup.clients == {}, str(sup.clients)))
    bot = await sup.create_bot("ops", display_name="运维机器人", start=True)
    out.append(("创建后进入 running", bot["status"] == "running", bot["status"]))
    out.append(("端口在配置区间内", stack.settings.ws_port_base <= int(bot["port"]) <= stack.settings.ws_port_max, str(bot["port"])))
    out.append(("端口取区间内第一个空闲口",
                all(port_busy(p) for p in range(stack.settings.ws_port_base, int(bot["port"]))),
                f"{stack.settings.ws_port_base}->{bot['port']}"))
    pid_file = stack.settings.pid_file(bot["id"])
    out.append(("pid 文件已写入", pid_file.is_file(), str(pid_file)))
    out.append(("pid 内容与运行时一致", pid_file.read_text().strip() == str(sup.runtime(bot["id"]).pid), pid_file.read_text()))
    out.append(("pid 文件权限 0600", mode_of(pid_file) == 0o600, oct(mode_of(pid_file) or 0)))
    out.append(("控制通道已连接", sup.client_for(bot["id"]).connected is True, "未连接"))
    out.append(("客户端 URL 只绑回环", sup.client_for(bot["id"]).url.startswith("ws://127.0.0.1:"), sup.client_for(bot["id"]).url))
    out.append(("包装脚本已落盘", stack.settings.wrapper_path(bot["id"]).is_file(), "缺 run-cli.sh"))
    out.append(("CLI 日志已落盘", sup.paths_for(bot["id"]).log_file.is_file(), "缺 cli.log"))
    out.append(("进程存活", sup.runtime(bot["id"]).process is not None, "process is None"))
    status = sup.status(bot["id"])
    out.append(("status 报告 running", status["runtime"]["state"] == "running", str(status["runtime"])))
    out.append(("status 汇总总数", sup.status()["summary"]["total"] >= 1, str(sup.status()["summary"])))
    detail = sup.detail(bot["id"])
    out.append(("detail 是账本行本体", detail.get("id") == bot["id"], str(sorted(detail))))
    out.append(("detail 内嵌 runtime", detail["runtime"]["state"] == "running", str(detail["runtime"])))
    out.append(("detail 统计规则数", detail["reply_rules"] == 0, str(detail["reply_rules"])))
    stopped = await sup.stop_bot(bot["id"])
    out.append(("停止后状态回落", stopped["state"] == "stopped", str(stopped)))
    out.append(("停止后 pid 文件清理", not pid_file.exists(), "仍存在"))
    out.append(("停止后客户端清空", sup.clients == {}, str(sup.clients)))
    out.append(("停止后 orphan_pid 为空", sup.orphan_pid(bot["id"]) is None, str(sup.orphan_pid(bot["id"]))))
    started = await sup.start_bot(bot["id"], provision=False)
    out.append(("手动 start 后 running", started["state"] == "running", str(started)))
    again = await sup.restart_bot(bot["id"])
    out.append(("restart 后仍 running", again["state"] == "running", str(again)))
    await sup.stop_bot(bot["id"])
    dead = await sup.remove_bot(bot["id"], purge_files=True)
    out.append(("删除后账本消失", stack.db.get_bot(bot["id"]) is None, "仍存在"))
    out.append(("删除结果 removed", dead["removed"] is True and dead["bot_id"] == bot["id"], str(dead)))
    return out


# --------------------------------------------------------------------------- 5
def _png_size(blob: bytes) -> Tuple[int, int]:
    """Width and height from a PNG's IHDR chunk, without pulling in Pillow."""
    return (int.from_bytes(blob[16:20], "big"), int.from_bytes(blob[20:24], "big"))


def group_provisioning(test: SelfTest, h: Harness) -> None:
    t = test
    for label, condition, detail in h.async_in(h.stack(tag="prov"), live_provisioning):
        t.check(label, condition, detail)


def _fake_cli_magic() -> Tuple[bytes, bytes]:
    """替身存在 ``bot_chat.db`` 里的状态魔数：只从替身取，避免自检与替身各写一份。"""
    tests_dir = str(ROOT / "tests")
    if tests_dir not in sys.path:
        sys.path.insert(0, tests_dir)
    from fake_popopx_cli import DB_HEADER, STATE_TAG  # noqa: PLC0415

    return DB_HEADER, STATE_TAG


def _fake_cli_profile_db(paths: BotPaths) -> Path:
    return Path(f"{paths.db_prefix}{CHAT_DB_SUFFIX}")


def fake_cli_state(paths: BotPaths) -> Dict[str, Any]:
    """读替身 CLI 的 profile 表——真 CLI 也把它存在同一个 ``bot_chat.db`` 里。"""
    _, tag = _fake_cli_magic()
    raw = _fake_cli_profile_db(paths).read_bytes()
    at = raw.rfind(tag)
    if at < 0:
        return {"users": [], "active": None}
    return json.loads(raw[at + len(tag):].decode("utf-8"))


def seed_fake_cli_state(paths: BotPaths, users: List[Dict[str, Any]], active: Any) -> None:
    """把 cli-data 写成冷备还原后的形状：库里有 profile，但 active 指针为空。"""
    header, tag = _fake_cli_magic()
    body = header + tag + json.dumps({"users": users, "active": active}).encode("utf-8")
    _fake_cli_profile_db(paths).write_bytes(body)


async def live_provisioning(stack: StudioStack) -> List[Tuple[str, Any, str]]:
    out: List[Tuple[str, Any, str]] = []
    sup = stack.supervisor
    bot = await sup.create_bot("cs_th", display_name="客服", default_locale="th", start=True)
    bot_id = bot["id"]
    row = stack.db.get_bot(bot_id)
    out.append(("开通后状态为 running", bot["status"] == "running", bot["status"]))
    out.append(("运行时标记已开通", sup.runtime(bot_id).provisioned is True, "provisioned False"))
    out.append(("永久联系地址已写回", row["permanent_link"] == "popopx:/fakepermanentlink", str(row["permanent_link"])))
    out.append(("联系地址与永久链接一致", row["contact_address"] == row["permanent_link"], "不一致"))
    out.append(("欢迎语按泰语模板渲染", "ยินดีต้อนรับสู่" in row["welcome_text"], row["welcome_text"]))
    out.append(("欢迎语已代入 Bot 名称", "客服" in row["welcome_text"], row["welcome_text"]))
    out.append(("欢迎语不残留占位符", "{bot_name}" not in row["welcome_text"], row["welcome_text"]))
    out.append(("欢迎语不残留任何花括号", "{" not in row["welcome_text"], row["welcome_text"]))
    out.append(("自动通过默认开启", int(row["auto_accept"]) == 1, str(row["auto_accept"])))
    out.append(("匿名接受必须保持关闭", int(row["accept_incognito"]) == 0, str(row["accept_incognito"])))
    out.append(("语种落库为 th", row["default_locale"] == "th", row["default_locale"]))
    pushed = sup.address_settings(row)
    out.append(("下发 businessAddress=true", pushed["businessAddress"] is True, str(pushed)))
    out.append(("下发 acceptIncognito=false", pushed["autoAccept"] == {"acceptIncognito": False}, str(pushed)))
    out.append(("下发 autoReply 文本", pushed["autoReply"] == {"type": "text", "text": row["welcome_text"]}, str(pushed)))
    try:
        await sup.create_bot("trap", auto_accept=False, accept_incognito=True)
        out.append(("匿名+不自动 被拒绝", False, "未抛错"))
    except BotSupervisorError:
        out.append(("匿名+不自动 被拒绝", True, ""))

    invite = sup.invite_link(row)
    out.append(("邀请链接是隐私封装", invite.startswith(INVITE_LINK_PREFIX), invite[:40]))
    out.append(("邀请链接可解回永久地址", decode_invite_link(invite) == row["permanent_link"], invite[:40]))
    out.append(("邀请链接不含节点域名", "popopx.im" not in invite and "smp://" not in invite, invite[:40]))
    qr = sup.qr_png(invite)
    out.append(("二维码是 PNG", qr[:8] == b"\x89PNG\r\n\x1a\n", qr[:8].hex()))
    out.append(("二维码体积合理", 200 < len(qr) < 200_000, str(len(qr))))
    big_qr = sup.qr_png(invite, box_size=32)
    out.append(("更大 box 生成更大像素", _png_size(big_qr)[0] > _png_size(qr)[0], f"{_png_size(qr)} vs {_png_size(big_qr)}"))
    out.append(("二维码仍是合法 PNG", big_qr[:8] == b"\x89PNG\r\n\x1a\n", big_qr[:8].hex()))
    info = sup.bot_qr(bot_id, save=True)
    out.append(("bot_qr 返回隐私封装链接", info["link"].startswith(INVITE_LINK_PREFIX), info["link"][:40]))
    out.append(("bot_qr 可解回永久地址", decode_invite_link(info["link"]) == row["permanent_link"], info["link"][:40]))
    out.append(("bot_qr 密文不含明文 smp", "smp://" not in info["link"] and "popopx.im" not in info["link"], info["link"][:40]))
    out.append(("bot_qr 回带原始地址供诊断", info["raw_link"] == row["permanent_link"], str(info["raw_link"])))
    out.append(("bot_qr 标记 opaque", info["opaque"] is True, str(info.get("opaque"))))
    out.append(("bot_qr 带 data url", info["data_url"].startswith("data:image/png;base64,"), info["data_url"][:32]))
    out.append(("bot_qr 校验和 64 位", len(info["sha256"]) == 64, info["sha256"]))
    out.append(("二维码文件已保存", Path(info["file"]).is_file(), info["file"]))
    out.append(("detail 内嵌二维码", bot["qr_png"].startswith("data:image/png;base64,"), str(bot["qr_png"])[:24]))
    out.append(("detail 邀请链接可解", decode_invite_link(bot["invite_link"]) == row["permanent_link"], str(bot["invite_link"])[:40]))

    group = await sup.create_group(bot_id, "客服群")
    out.append(("建群返回 groupId", group["group_id"] == 42, str(group)))
    out.append(("群引用形如 #42", group["ref"] == "#42", group["ref"]))
    link = await sup.create_group_link(bot_id, 42, "observer")
    out.append(("群短链非空", bool(link["short_link"]), str(link)))
    out.append(("群长链非空", bool(link["invite_link"]), str(link)))
    out.append(("角色回显 observer", link["role"] == "observer", str(link)))
    try:
        await sup.create_group_link(bot_id, 42, "owner")
        out.append(("非法群角色被拒绝", False, "未抛错"))
    except WebSocketProtocolError:
        out.append(("非法群角色被拒绝", True, ""))

    sent = await sup.send_text(bot_id, "#42", "已收到您的工单")
    out.append(("发送返回送达回执", sent["delivered"] >= 1, str(sent)))
    out.append(("发送结果会话引用", sent["chat_ref"] == "#42", str(sent["chat_ref"])))
    out.append(("回执事件类型", sent["events"][0]["event_type"] == "newChatItems", str(sent["events"][0])))
    quoted = await sup.send_text(bot_id, "#42", "引用回复", quoted_item_id=91)
    out.append(("引用回复成功", quoted["delivered"] >= 1, str(quoted)))
    content = await sup.send_content(bot_id, "#42", {"type": "text", "text": "图文"})
    out.append(("图文发送返回 resp", content["resp"]["type"] == "newChatItems", str(content["resp"])[:60]))
    try:
        await sup.send_text(bot_id, "bad-ref", "x")
        out.append(("非法引用被拒绝", False, "未抛错"))
    except BotSupervisorError:
        out.append(("非法引用被拒绝", True, ""))

    contacts = await sup.list_contacts(bot_id)
    out.append(("联系人列表来自 CLI", contacts[0]["contactId"] == 7, str(contacts)))
    groups = await sup.list_groups(bot_id)
    out.append(("群组列表来自 CLI", groups[0]["groupInfo"]["groupId"] == 42, str(groups)))
    accepted = await sup.accept_contact(bot_id, 7)
    out.append(("接受联系人成功", accepted["contact"]["contactId"] == 8, str(accepted)))

    edited = await sup.update_greeting(bot_id, welcome_text="新的欢迎语")
    out.append(("更新回执返回设置", edited["settings"]["autoReply"]["text"] == "新的欢迎语", str(edited)[:160]))
    out.append(("欢迎语已落库", stack.db.get_bot(bot_id)["welcome_text"] == "新的欢迎语", "未写入"))
    out.append(("更新后重新下发", sup.address_settings(stack.db.get_bot(bot_id))["autoReply"]["text"] == "新的欢迎语", "未同步"))
    off = await sup.update_greeting(bot_id, auto_accept=False)
    out.append(("关闭自动通过落库", int(stack.db.get_bot(bot_id)["auto_accept"]) == 0, str(stack.db.get_bot(bot_id)["auto_accept"])))
    out.append(("关闭后 autoAccept 为 None", off["settings"]["autoAccept"] is None, "仍开启"))
    out.append(("设置已下发到 CLI", off["applied"] is True, str(off)[:120]))

    untouched = await sup.create_bot("draft_only", start=False)
    out.append(("不启动时保持 draft", untouched["status"] == "draft", untouched["status"]))
    out.append(("不启动时无二维码", untouched["qr_png"] == "", str(untouched["qr_png"])[:20]))

    # ------------------------------------------------------------------ 幂等复启
    # 替身是有状态的：profile 存在 cli-data 的 bot_chat.db 里，和真 CLI 一样活得过进程重启。
    # 旧实现每次开通都发 /_create user，第二次必撞 userExists —— 生产表现是「Bot 一重启就起不来」。
    paths = sup.paths_for(bot_id)
    first = fake_cli_state(paths)
    out.append(("首启只落一个 profile", len(first["users"]) == 1, str(first)))
    out.append(("profile 名取 display_name", bool(first["users"]) and first["users"][0]["localDisplayName"] == "客服", str(first)))
    out.append(("首启把 profile 设为 active", first["active"] == first["users"][0]["userId"], str(first)))
    wrapper = paths.wrapper.read_text()
    out.append(("首启包装脚本带引导名", "--user-display-name" in wrapper, wrapper[-160:]))
    out.append(("引导名在脚本里被引号包住", "'客服'" in wrapper, wrapper[-160:]))

    link_before = stack.db.get_bot(bot_id)["permanent_link"]
    await sup.stop_bot(bot_id)
    await sup.start_bot(bot_id, provision=True)
    second = fake_cli_state(paths)
    row2 = stack.db.get_bot(bot_id)
    out.append(("二次启动状态为 running", row2["status"] == "running", str(row2["status"])))
    out.append(("二次启动不新增 profile", len(second["users"]) == 1, str(second)))
    out.append(("二次启动复用同一 userId", second["active"] == first["active"], f"{second['active']} vs {first['active']}"))
    out.append(("二次启动永久链接不变", row2["permanent_link"] == link_before, str(row2["permanent_link"])))
    out.append(("二次启动后 /user 读到同一 profile", await sup.client_for(bot_id).get_active_user() == first["active"], "读不到"))

    # 冷备还原：库里已有名片但 active 指针为空 —— /user 只会回 noActiveUser，必须靠 /users 裁定。
    await sup.stop_bot(bot_id)
    seed_fake_cli_state(paths, [{"userId": 3, "localDisplayName": "客服", "displayName": "客服"}], None)
    await sup.start_bot(bot_id, provision=True)
    revived = fake_cli_state(paths)
    out.append(("复活沿用既有 userId", revived["active"] == 3, str(revived)))
    out.append(("复活不新建第二个 profile", len(revived["users"]) == 1, str(revived)))
    out.append(("复活后 /user 读到还原的名片", await sup.client_for(bot_id).get_active_user() == 3, "未激活"))

    # 错误帧必须在收到时就交给等待者：旧读循环只认 kind=="response"，
    # 每个 CLI 侧错误都要干等到超时（生产表现为「命令卡 20 秒」）。
    out.append(("控制通道带连接超时", sup.client_for(bot_id).connect_timeout > 0,
                str(sup.client_for(bot_id).connect_timeout)))
    boom_start = time.monotonic()
    try:
        await sup.client_for(bot_id).send_command("/_boom", timeout=8.0)
        out.append(("错误帧立即抛 CLICommandError", False, "未抛错"))
    except CLITimeoutError:
        out.append(("错误帧立即抛 CLICommandError", False, "拖到超时：读循环没把 chatCmdError 交给等待者"))
    except CLICommandError:
        out.append(("错误帧立即抛 CLICommandError", True, ""))
    out.append(("错误帧不拖满超时", time.monotonic() - boom_start < 4.0, f"{time.monotonic() - boom_start:.2f}s"))

    # Studio 重启后的自愈：boot() 只拉起库里标着 running 的 Bot，且必须一次成功。
    await sup.stop_bot(bot_id)
    stack.db.update_bot(bot_id, status="running")
    resumed = await sup.boot(auto_start_statuses=("running",))
    out.append(("boot() 拉起 running 的 Bot", bot_id in resumed["started"], str(resumed)))
    out.append(("boot() 无失败项", resumed["failed"] == {}, str(resumed["failed"])))
    out.append(("boot() 后仍是一个 profile", len(fake_cli_state(paths)["users"]) == 1, str(fake_cli_state(paths))))
    await sup.stop_bot(bot_id)
    await sup.remove_bot(bot_id, purge_files=True)
    await sup.remove_bot(untouched["id"], purge_files=True)
    return out


# --------------------------------------------------------------------------- 6
def group_rules(test: SelfTest, h: Harness) -> None:
    t = test
    db = h.database("rules")
    clock = FakeClock(1000.0)
    rules = RuleEngine(db, bot_name="Studio", sender_rate_limit=3, sender_rate_window_seconds=60, clock=clock)
    bot = db.create_bot("rulebot1", 5360, display_name="客服Bot")
    bid = bot["id"]

    t.eq("插值 sender_name", interpolate("你好 {sender_name}", {"sender_name": "小明"}), "你好 小明")
    t.eq("插值未知键保留", interpolate("{unknown} 保留", {"other": 1}), "{unknown} 保留")
    t.eq("插值 None 变空串", interpolate("[{a}]", {"a": None}), "[]")
    t.eq("插值不执行表达式", interpolate("{expr}", {"expr": "{1+1}"}), "{1+1}")
    t.eq("数字花括号不是占位符", interpolate("{0} {text}", {"0": "x", "text": "你好"}), "{0} 你好")
    t.eq("空模板返回空", interpolate("", {"a": 1}), "")
    t.check("字面大括号不崩", interpolate("比例 {50%} {bot_name}", {"bot_name": "B"}) == "比例 {50%} B", "被改写")
    ctx = default_context(sender_name="小明", bot_name="B", now=1_700_000_000)
    t.eq("上下文含 date", ctx["date"], time.strftime("%Y-%m-%d", time.localtime(1_700_000_000)))
    t.check("上下文 time 格式", re.match(r"^\d{2}:\d{2}:\d{2}$", ctx["time"]) is not None, ctx["time"])
    t.eq("sender_name 兜底 sender", default_context(sender="u7")["sender_name"], "u7")
    t.eq("触发类型优先级序", TRIGGER_RANK, {"exact": 0, "prefix": 1, "regex": 2, "default": 3})

    msg = InboundMessage(bot_id=bid, text="  退款 进度  ", chat_ref="@7", sender="u7", sender_name="小明")
    t.eq("normalize 去首尾空白", msg.normalized, "退款 进度")
    t.eq("first_word 小写", InboundMessage(bot_id=bid, text="/HELP x").first_word, "/help")
    t.eq("空消息 first_word", InboundMessage(bot_id=bid, text="   ").first_word, "")

    exact = db.upsert_reply_rule(bid, trigger_type="exact", pattern="人工", reply_text="正在为您转接 {bot_name}",
                                 cooldown_seconds=3600)
    db.upsert_reply_rule(bid, trigger_type="prefix", pattern="退款", reply_text="退款进度：{text}")
    db.upsert_reply_rule(bid, trigger_type="regex", pattern="^(价|价格)", reply_text="价格表：{price}", priority=50)
    db.upsert_reply_rule(bid, trigger_type="default", pattern="", reply_text="兜底：{sender_name}")
    t.eq("启用规则数", len(rules.enabled_rules(bid, force=True)), 4)

    hit = rules.evaluate(InboundMessage(bot_id=bid, text="人工", chat_ref="@7", sender="u7", sender_name="小明"))
    t.check("精确命中", hit.matched and hit.rule_id == exact["id"], str(hit))
    t.eq("命中插值引擎指定的 Bot 名", hit.reply, "正在为您转接 Studio")
    t.eq("命中状态 ok", hit.status, "ok")
    t.eq("触发类型 exact", hit.trigger_type, "exact")
    t.check("可以发送", hit.should_send)
    t.eq("引擎本身不写命中数", db.get_reply_rule(exact["id"])["hits"], 0)
    db.register_rule_hit(exact["id"])
    t.eq("命中计数由网关入账", db.get_reply_rule(exact["id"])["hits"], 1)
    named = RuleEngine(db, clock=clock)
    t.eq("未指定名字时取 Bot 名", named.evaluate(InboundMessage(bot_id=bid, text="人工", sender="u60")).reply,
         "正在为您转接 rulebot1")

    prefix_hit = rules.evaluate(InboundMessage(bot_id=bid, text="退款 12 号", sender="u8"))
    t.eq("前缀命中模板保留全文", prefix_hit.reply, "退款进度：退款 12 号")
    regex_hit = rules.evaluate(InboundMessage(bot_id=bid, text="价格多少", sender="u9"))
    t.eq("正则命中", regex_hit.trigger_type, "regex")
    t.eq("正则未捕获变量保留", regex_hit.reply, "价格表：{price}")
    default_hit = rules.evaluate(InboundMessage(bot_id=bid, text="随便说点什么", sender="u10"))
    t.eq("默认兜底命中", (default_hit.trigger_type, default_hit.reply), ("default", "兜底：u10"))
    t.eq("禁用规则不参与匹配", len([r for r in rules.enabled_rules(bid, force=True) if not r["enabled"]]), 0)

    cold = rules.evaluate(InboundMessage(bot_id=bid, text="人工", sender="u7"))
    t.eq("冷却期内命中但不回复", (cold.matched, cold.status, cold.reply), (True, "cooldown", ""))
    t.eq("冷却抑制原因", cold.suppressed_by, "rule_cooldown")
    clock.advance(3601)
    warm = rules.evaluate(InboundMessage(bot_id=bid, text="人工", sender="u7"))
    t.eq("冷却窗口过后恢复", warm.status, "ok")

    help_decision = rules.evaluate(InboundMessage(bot_id=bid, text="/help", sender="u1"))
    t.eq("内置 /help 命中", (help_decision.matched, help_decision.trigger_type), (True, "command"))
    t.contains("菜单标题", help_decision.reply, "POPOPX Bot 指令菜单")
    t.contains("无前缀斜杠规则时给出提示", help_decision.reply, "暂无自定义指令")
    slash_bot = db.create_bot("slashbot", 5362)["id"]
    db.upsert_reply_rule(slash_bot, name="价目表", trigger_type="prefix", pattern="/price", reply_text="价目表如下\n第二行")
    rules.invalidate_cache()
    slash_menu = rules.evaluate(InboundMessage(bot_id=slash_bot, text="/help", sender="u1"))
    t.contains("菜单列出斜杠规则", slash_menu.reply, "/price")
    t.contains("菜单取规则名", slash_menu.reply, "价目表")
    t.eq("slash_rules 只收斜杠规则", len(rules.slash_rules(bid)), 0)
    t.eq("slash_rules 计数", len(rules.slash_rules(slash_bot)), 1)
    start_decision = rules.evaluate(InboundMessage(bot_id=bid, text="/start", sender="u2"))
    t.contains("/start 使用欢迎语", start_decision.reply, "欢迎使用")
    t.check("指令集合含内置", set(rules.command_names()) >= {"/help", "/start", "/menu"}, str(rules.command_names()))
    rules.register_command("/ping", lambda message, context: "pong")
    t.eq("自定义指令生效", rules.evaluate(InboundMessage(bot_id=bid, text="/ping", sender="u3")).reply, "pong")
    t.raises("指令名必须以斜杠开头", RuleError, rules.register_command, "ping", lambda message, context: "pong")

    def broken(message: InboundMessage, context: Dict[str, str]) -> str:
        raise RuntimeError("炸了")

    rules.register_command("/boom", broken)
    bad = rules.evaluate(InboundMessage(bot_id=bid, text="/boom", sender="u4"))
    t.eq("坏指令被隔离", (bad.matched, bad.status), (True, "error"))
    t.contains("坏指令记录异常", bad.metadata["error"], "RuntimeError")
    t.eq("坏指令不回复", bad.should_send, False)

    for i in range(6):
        rules.evaluate(InboundMessage(bot_id=bid, text=f"随便{i}", sender="spam"))
    limited = rules.evaluate(InboundMessage(bot_id=bid, text="随便", sender="spam"))
    t.eq("频率限制触发", (limited.matched, limited.status, limited.suppressed_by), (False, "rate_limited", "sender_rate_limit"))
    rules.reset_throttling(bid)
    t.eq("重置频率限制后兜底恢复", rules.evaluate(InboundMessage(bot_id=bid, text="随便", sender="spam")).status, "ok")
    rules.reset_throttling()
    t.eq("全库重置不报错", rules.evaluate(InboundMessage(bot_id=bid, text="随便", sender="spam")).status, "ok")

    preview = rules.preview(bid, "人工", sender="previewer")
    t.eq("预览命中规则", preview.reply, "正在为您转接 Studio")
    t.eq("预览不消耗冷却", rules.evaluate(InboundMessage(bot_id=bid, text="人工", sender="previewer")).status, "ok")
    t.raises("空回复拒绝", LedgerError, db.upsert_reply_rule, bid, trigger_type="exact", pattern="x", reply_text="")
    t.raises("非法触发类型拒绝", LedgerError, db.upsert_reply_rule, bid, trigger_type="fuzzy", pattern="x", reply_text="y")
    exported = rules.export_rules(bid)
    t.eq("导出条目数", len(exported), 4)
    other = db.create_bot("rulebot2", 5361)["id"]
    t.eq("导入到另一个 Bot", rules.import_rules(other, exported), 4)
    t.eq("非法导入项被跳过", rules.import_rules(other, [{"trigger_type": "exact"}]), 0)
    t.eq("缓存失效后重新读取", len(rules.enabled_rules(other)), 4)
    t.eq("不存在的 Bot 无规则", rules.enabled_rules("bot_missing"), [])
    t.eq("空正文只由兜底规则接住", rules.evaluate(InboundMessage(bot_id=bid, text="   ", sender="u1")).trigger_type, "default")
    t.raises("非法正写在入库时拒绝", LedgerError, db.upsert_reply_rule, bid, trigger_type="regex", pattern="^(未闭合", reply_text="x")
    t.raises("指令形正则同样校验", LedgerError, db.upsert_reply_rule, bid, trigger_type="exact", pattern="/ok", reply_text="   ")


class FakeClock:
    def __init__(self, start: float = 1000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class RecordingSupervisor:
    """Supervisor stand-in that only records sends, for pure pipeline assertions."""

    def __init__(self, *, fail: str = ""):
        self.sends: List[Dict[str, Any]] = []
        self.fail = fail
    async def send_text(
        self, bot_id: str, chat_ref: str, text: str, *, quoted_item_id: Optional[int] = None
    ) -> Dict[str, Any]:
        if self.fail:
            raise BotSupervisorError(self.fail)
        self.sends.append(
            {"bot_id": bot_id, "chat_ref": chat_ref, "text": text, "quoted_item_id": quoted_item_id}
        )
        return {"bot_id": bot_id, "chat_ref": chat_ref, "delivered": 1}

    async def send_content(self, bot_id: str, chat_ref: str, content: Dict[str, Any]) -> Dict[str, Any]:
        if self.fail:
            raise BotSupervisorError(self.fail)
        self.sends.append({"bot_id": bot_id, "chat_ref": chat_ref, "content": content})
        return {"bot_id": bot_id, "chat_ref": chat_ref, "delivered": 1}

    def clients(self) -> List[str]:
        return []


def _plugin_dir(h: Harness, tag: str) -> Path:
    """An empty plugin directory: the gateway must run with a bus that has no plugins."""
    directory = h.root / "plugins" / tag
    directory.mkdir(parents=True, exist_ok=True)
    return directory


# --------------------------------------------------------------------------- 7
def group_router(test: SelfTest, h: Harness) -> None:
    t = test
    db = h.database("router")
    clock = FakeClock(2000.0)
    bot = db.create_bot("routebot", 5370, display_name="路由Bot")["id"]
    other = db.create_bot("routebot2", 5371)["id"]
    eng = RouterEngine(db, clock=clock)

    t.eq("单目标解析", parse_targets("#42"), ["#42"])
    t.eq("逗号分隔解析", parse_targets("#1,@2"), ["#1", "@2"])
    t.eq("分号与空白解析", parse_targets(" #1 ; @2 "), ["#1", "@2"])
    t.eq("JSON 数组解析", parse_targets('["#1", "#2"]'), ["#1", "#2"])
    t.eq("JSON 空串过滤", parse_targets('["#1", "  "]'), ["#1"])
    t.eq("空目标解析为空", parse_targets("   "), [])
    t.raises("坏 JSON 目标报错", RouterError, parse_targets, '["#1"')
    t.contains("工单号格式", new_ticket_id(), "#T")
    t.check("工单号是 6 位十六进制", re.match(r"^#T[0-9A-F]{6}$", new_ticket_id()) is not None, new_ticket_id())
    t.eq("工单号唯一", len({new_ticket_id() for _ in range(30)}), 30)
    t.check("工单回复正则存在", TICKET_REPLY_RE is not None)

    reg = TicketRegistry(limit=16)
    token = reg.open_ticket(bot_id=bot, group_ref="#42", chat_ref="@7", sender="u7", sender_name="小明", summary="退款")
    t.eq("登记一条工单", len(reg), 1)
    t.eq("工单号可解析", reg.resolve(bot, token)["chat_ref"], "@7")
    t.eq("解析忽略大小写", reg.resolve(bot, token.lower())["sender_name"], "小明")
    t.eq("去掉 # 前缀也能解析", reg.resolve(bot, token[1:])["ticket_id"], token)
    t.eq("跨 Bot 不共享工单", reg.resolve(other, token), None)
    t.eq("错误前缀无法解析", reg.resolve(bot, "#TFFFFFF"), None)
    answered = reg.mark_answered(bot, token)
    t.eq("回帖计数", int(answered["answers"]), 1)
    t.eq("未知工单不计回帖", reg.mark_answered(bot, "#T000000"), None)
    listed = reg.open_tickets(bot)
    t.eq("工单列表长度", len(listed), 1)
    t.eq("工单列表含会话引用", listed[0]["chat_ref"], "@7")
    t.eq("按 Bot 过滤工单列表", reg.open_tickets(other), [])
    for i in range(30):
        reg.open_ticket(bot_id=bot, group_ref="#42", chat_ref=f"@{i}", sender=f"s{i}")
    t.eq("工单表上限生效", len(reg), 16)
    t.eq("最早工单被逐出", reg.resolve(bot, token), None)

    route = db.upsert_routing_rule(
        bot, name="转客服", source_type="direct", keyword_mode="contains", keywords=["退款", "发票"],
        target_type="group", target_ref="#42", template="[{source_type}] {sender_name}: {text} ({ticket_id})",
        quote_reply=True, cooldown_seconds=60,
    )
    eng.invalidate_cache()
    t.eq("启用路由数", len(eng.enabled_rules(bot)), 1)
    t.eq("其他 Bot 无路由", eng.enabled_rules(other), [])
    msg = InboundMessage(bot_id=bot, text="我要 退款", chat_type="direct", chat_ref="@7", sender="u7", sender_name="小明", ts=2000.0)
    decision = eng.plan(msg)
    t.eq("关键词命中转发", decision.status, "forwarded")
    t.eq("命中规则入列表", decision.matched_rules, [route["id"]])
    t.eq("转发计划数", len(decision.plans), 1)
    plan = decision.plans[0]
    t.eq("计划目标", plan.target_ref, "#42")
    t.eq("计划类型为群", plan.target_type, "group")
    t.eq("模板插值正文", plan.text, "[direct] 小明: 我要 退款 (" + plan.ticket_id + ")")
    t.eq("模板含工单号", plan.ticket_id in plan.text, True)
    t.eq("引用回复开启", plan.quote, True)
    t.eq("被引用会话", plan.quoted_ref, "@7")
    t.eq("回执文案", decision.reply_to_sender, f"已收到您的咨询 {plan.ticket_id}，已转交客服群组处理。")
    t.eq("计划可序列化", sorted(plan.as_dict()), sorted(["rule_id","target_type","target_ref","text","quote","quoted_ref","ticket_id","reason"]))
    t.eq("计划原因", plan.reason, "matched")
    t.eq("决策可转发", decision.forwarded, True)
    again = eng.plan(msg)
    t.eq("冷却期内不再转发", (again.status, again.plans), ("cooldown", []))
    t.eq("冷却不影响其他发送人", len(eng.plan(
        InboundMessage(bot_id=bot, text="发票", chat_type="direct", chat_ref="@8", sender="u8", sender_name="小李", ts=2001.0)
    ).plans), 1)
    clock.advance(61)
    t.eq("冷却到期恢复", len(eng.plan(msg).plans), 1)

    eng.tickets = TicketRegistry()
    no_kw = db.upsert_routing_rule(bot, name="任意", source_type="any", keyword_mode="any",
                                   target_type="group", target_ref="#43", cooldown_seconds=0)
    eng.invalidate_cache()
    broad = eng.plan(InboundMessage(bot_id=bot, text="随便聊聊", chat_type="group", chat_ref="#90", sender="u9", ts=2100.0))
    t.check("any 关键词直接命中", any(p.rule_id == no_kw["id"] for p in broad.plans), str(broad.matched_rules))
    t.eq("群消息不建工单", broad.plans[0].ticket_id, "")
    t.eq("群消息不引用回复", broad.plans[0].quote, False)
    exact_rule = db.upsert_routing_rule(bot, name="精确", source_type="direct", keyword_mode="exact",
                                        keywords=["人工"], target_type="contact", target_ref="@7", cooldown_seconds=0)
    eng.invalidate_cache()
    t.eq("精确匹配生效", len(eng.plan(InboundMessage(bot_id=bot, text="人工", chat_type="direct", chat_ref="@7", sender="u1", ts=2200.0)).plans), 2)
    t.eq("精确模式不匹配长句", any(int(p.rule_id) == int(exact_rule["id"])
                                   for p in eng.plan(InboundMessage(bot_id=bot, text="转人工吧", chat_type="direct", chat_ref="@7", sender="u2", ts=2201.0)).plans), False)
    reg_rule = db.upsert_routing_rule(bot, name="正则", source_type="any", keyword_mode="regex",
                                      keywords=[r"^价\d+"], target_type="group", target_ref="#44", cooldown_seconds=0)
    eng.invalidate_cache()
    t.check("正则关键词命中", any(int(p.rule_id) == int(reg_rule["id"])
                                  for p in eng.plan(InboundMessage(bot_id=bot, text="价99", chat_type="direct", chat_ref="@7", sender="u3", ts=2300.0)).plans))
    t.raises("坏正则关键词在入库时拒绝", LedgerError, db.upsert_routing_rule, bot,
             keyword_mode="regex", keywords=["^(未闭合"], target_ref="#45")
    t.raises("引擎对坏正则抛路由错误", RouterError, eng._keyword_matches,
             {"keyword_mode": "regex", "keywords": ["^(未闭合"]},
             InboundMessage(bot_id=bot, text="任意", chat_type="direct", chat_ref="@7", sender="u5", ts=2400.0))
    t.raises("非法关键词模式拒绝", LedgerError, db.upsert_routing_rule, bot, keyword_mode="fuzzy",
             keywords=["x"], target_ref="#45")
    t.raises("关键词模式缺关键词拒绝", LedgerError, db.upsert_routing_rule, bot, keyword_mode="contains",
             target_ref="#45")
    eng.invalidate_cache()

    # 账本禁止空目标入库，所以给一个干净的 Bot 直接写一行历史脏数据，
    # 验证引擎既不会转发出去，也不会连带影响同会话其它规则的结果。
    ghost_bot = db.create_bot("ghostbot", 5372)["id"]
    ghost = db.conn.execute(
        "INSERT INTO routing_rules (bot_id, name, source_type, keyword_mode, keywords,"
        " target_type, target_ref, created_at) VALUES (?, '无目标', 'direct', 'any', '[]', 'group', '', ?)",
        (ghost_bot, time.time()),
    ).lastrowid
    db.conn.commit()
    eng.invalidate_cache()
    no_target = eng.plan(InboundMessage(bot_id=ghost_bot, text="无人接单", chat_type="direct", chat_ref="@7", sender="u6", ts=2500.0))
    t.eq("缺少目标时不转发", no_target.plans, [])
    t.eq("缺少目标状态", no_target.status, "no_target")
    t.eq("脏规则仍算命中", no_target.matched_rules, [int(ghost)])
    t.check("删除脏规则", db.delete_routing_rule(int(ghost)))
    eng.invalidate_cache()
    t.eq("脏规则删除后回到无匹配",
         eng.plan(InboundMessage(bot_id=ghost_bot, text="无人接单", chat_type="direct", chat_ref="@7", sender="u6", ts=2501.0)).status,
         "no_match")

    db.log_message(bot, "in", chat_type="group", chat_ref="#500", text="x")
    db.log_message(bot, "in", chat_type="group", chat_ref="#501", text="x")
    db.log_message(bot, "in", chat_type="direct", chat_ref="@9", text="x")
    t.eq("已知群组去重排序", eng.known_groups(bot), ["#500", "#501"])
    t.eq("其他 Bot 无已知群组", eng.known_groups(other), [])
    bcast = db.upsert_routing_rule(bot, name="广播", source_type="any", keyword_mode="any",
                                   target_type="broadcast", target_ref="", cooldown_seconds=0)
    eng.invalidate_cache()
    cast = eng.plan(InboundMessage(bot_id=bot, text="公告", chat_type="direct", chat_ref="@7", sender="u7", ts=2600.0))
    t.eq("广播展开已知群组", [p.target_ref for p in cast.plans if int(p.rule_id) == int(bcast["id"])], ["#500", "#501"])
    t.eq("广播计划仍为群类型", {p.target_type for p in cast.plans if int(p.rule_id) == int(bcast["id"])}, {"group"})
    explicit = db.upsert_routing_rule(bot, name="指定广播", target_type="broadcast", target_ref="#777", cooldown_seconds=0)
    eng.invalidate_cache()
    t.eq("广播显式目标优先", [p.target_ref for p in eng.plan(
        InboundMessage(bot_id=bot, text="公告2", chat_type="direct", chat_ref="@7", sender="u8", ts=2700.0)).plans if int(p.rule_id) == int(explicit["id"])], ["#777"])

    plain = RouterEngine(db, default_template="[{source_type}] {sender_name}: {text}", clock=clock)
    solo = plain.plan(InboundMessage(bot_id="bot_missing", text="x", chat_type="direct", chat_ref="@1", sender="s"))
    t.eq("无规则 Bot 不转发", (solo.status, solo.plans, solo.matched_rules), ("no_match", [], []))
    t.eq("空消息也能规划", plain.plan(InboundMessage(bot_id=bot, text="", chat_type="direct", chat_ref="@7", sender="u9")).status, "forwarded")
    stats = eng.stats(bot)
    t.check("统计含工单与规则数", set(stats) == {"open_tickets", "rules"}, str(stats))
    t.eq("全库统计不炸", set(eng.stats()), {"open_tickets", "rules"})

    ticket = eng.tickets.open_ticket(bot_id=bot, group_ref="#42", chat_ref="@77", sender="u77", sender_name="阿伟")
    record, body = eng.reply_to_ticket(bot, f"{ticket} 已为您加急", sender="客服")
    t.eq("工单回帖解析会话", record["chat_ref"], "@77")
    t.eq("回帖正文去掉工单号", body, "已为您加急")
    t.eq("回帖记录工单号", record["ticket_id"], ticket)
    t.eq("回帖计数增长", int(eng.tickets.resolve(bot, ticket)["answers"]), 1)
    t.eq("小写工单号可回帖", eng.reply_to_ticket(bot, f"{ticket.lower()}: 好的")[1], "好的")
    t.eq("裸 T 前缀可回帖", eng.reply_to_ticket(bot, f"T{ticket[2:]} 收到")[1], "收到")
    t.eq("无工单号不回帖", eng.reply_to_ticket(bot, "大家辛苦了")[0], None)
    t.eq("工单号在句中被忽略", eng.reply_to_ticket(bot, f"关于 {ticket} 的处理")[0], None)
    t.eq("空回帖正文被忽略", eng.reply_to_ticket(bot, f"{ticket}   ")[0], None)
    t.eq("未知工单不回帖", eng.reply_to_ticket(bot, "#TAAAAAA 好的")[0], None)
    t.eq("跨 Bot 回帖无效", eng.reply_to_ticket(other, f"{ticket} 好的")[0], None)
    t.eq("Bot 自己转发的消息不被当回帖", eng.reply_to_ticket(bot, f"[{ticket}] [direct] 小明: 我要退款")[0], None)
    db.close()


# --------------------------------------------------------------------------- 8
FAST_PLUGIN_SOURCE = '''"""Self-test plugin: proves the bus runs ahead of the zero-code engines."""
from app.plugin_manager import PASS, PluginResult, StudioPlugin


class FastPlugin(StudioPlugin):
    plugin_id = "selftest_fast"
    name = "自检抢先插件"
    version = "1.0.0"
    description = "自检用：接管指定消息"
    priority = 11

    def __init__(self):
        super().__init__()
        self.calls = 0

    async def on_message(self, event, context):
        self.calls += 1
        if getattr(event, "text", "") == "人工" and getattr(event, "sender", "") == "u7":
            return PluginResult(handled=True, reply="插件抢先接管 u7", status="ok",
                                metadata={"selftest": "fast"})
        return PASS
'''

BOOM_PLUGIN_SOURCE = '''"""Self-test plugin: raises on purpose so the bus must isolate it."""
from app.plugin_manager import PASS, StudioPlugin


class BoomPlugin(StudioPlugin):
    plugin_id = "selftest_boom"
    name = "自检崩溃插件"
    priority = 12

    async def on_message(self, event, context):
        if "人工" in getattr(event, "text", ""):
            raise RuntimeError("插件崩溃")
        return PASS
'''

RELAY_PLUGIN_SOURCE = '''"""Self-test plugin: returns a forward plan for the gateway to deliver."""
from app.plugin_manager import PASS, PluginResult, StudioPlugin


class RelayPlugin(StudioPlugin):
    plugin_id = "selftest_relay"
    name = "自检转发插件"
    priority = 13

    async def on_message(self, event, context):
        text = getattr(event, "text", "")
        if "转发" in text:
            return PluginResult(handled=True, reply="已转发给值班群",
                                forwards=[{"chat_ref": "#61", "text": "值班跟进：" + text}],
                                status="ok")
        return PASS
'''


def group_gateway(test: SelfTest, h: Harness) -> None:
    t = test
    buf = UpdateBuffer(maxlen=3)
    u1 = buf.add("b1", {"event": "message", "text": "一"})
    u2 = buf.add("b1", {"event": "message", "text": "二"})
    u3 = buf.add("b2", {"event": "message", "text": "三"})
    u4 = buf.add("b1", {"event": "message", "text": "四"})
    u5 = buf.add("b1", {"event": "message", "text": "五"})
    got = [u["update_id"] for u in (u1, u2, u3, u4, u5)]
    t.eq("update_id 全局递增", got, [1, 2, 3, 4, 5])
    t.eq("缓冲区按 maxlen 逐出", [item["text"] for item in buf.take("b1")], ["二", "四", "五"])
    t.eq("take 不消费队列", [item["text"] for item in buf.take("b1")], ["二", "四", "五"])
    t.eq("按 Bot 隔离队列", [item["text"] for item in buf.take("b2")], ["三"])
    t.eq("offset 增量拉取", [item["update_id"] for item in buf.take("b1", offset=2)], [4, 5])
    t.eq("limit 只留尾部若干条", [item["text"] for item in buf.take("b1", limit=1)], ["五"])
    t.eq("limit=0 返回全部", len(buf.take("b1", limit=0)), 3)
    t.eq("最新游标", buf.latest("b1"), 5)
    t.eq("未知 Bot 游标为 0", buf.latest("nope"), 0)
    t.eq("未知 Bot 取空", buf.take("nope"), [])
    t.eq("总缓冲条数", len(buf), 4)
    t.eq("UpdateBuffer 默认容量", MAX_UPDATES, 500)
    t.check("update 携带 bot_id", u3["bot_id"] == "b2", str(u3))

    result = ProcessResult(bot_id="b1", handled_by="rules", replied=True, status="matched")
    t.eq("结果序列化键", sorted(result.as_dict()), sorted(["bot_id","handled_by","replied","forwarded","status","reply_text","plans","error"]))
    t.eq("结果默认值", (ProcessResult(bot_id="b2").status, ProcessResult(bot_id="b2").plans), ("ignored", []))

    settings = h.settings(STUDIO_DATA_DIR=str(h.root / "var" / "gw"))
    settings.ensure_directories()
    db = connect(settings.db_file)
    stub = RecordingSupervisor()
    rules = RuleEngine(db, bot_name="网关Bot")
    router = RouterEngine(db, bot_name="网关Bot", clock=FakeClock(3000.0))
    plugins = PluginManager(db, _LateServices(), plugins_dir=_plugin_dir(h, "gw"))
    gateway = BotGateway(settings, db, stub, rules, router, plugins, max_updates=10)
    plugins.services = CoreServices(stub, db, gateway)
    bot = db.create_bot("gwbot", 5372, display_name="网关Bot")["id"]

    event = NormalizedEvent(event_type="newChatItems", direction="in", chat_type="direct", chat_ref="@7",
                            sender="u7", sender_name="小明", text="人工", ts=3000.0, item_id=123, raw={})
    early = gateway.process
    t.check("网关可被调用", callable(early))
    ignored = h.async_run(_process, gateway, bot, NormalizedEvent(event_type="newChatItems", direction="out",
                          chat_type="direct", chat_ref="@7", text="出站回声", ts=3000.0))
    t.eq("出站消息跳过", ignored.status, "skipped")
    t.eq("出站不发送", len(stub.sends), 0)
    blank = h.async_run(_process, gateway, bot, NormalizedEvent(event_type="newChatItems", direction="in",
                       chat_type="direct", chat_ref="@7", text="   ", ts=3000.0))
    t.eq("空白消息跳过", blank.status, "skipped")

    one = h.async_run(_process, gateway, bot, event)
    t.eq("未配置规则时忽略", (one.status, one.replied, one.forwarded), ("no_match", False, 0))
    logs = db.recent_logs(bot, limit=20)
    inbound = [row for row in logs if row["direction"] == "in"]
    t.eq("入站台账已写入", len(inbound), 1)
    t.eq("入站记录正文", inbound[-1]["text"], "人工")
    t.eq("更新队列长度", len(gateway.get_updates(bot)), 1)
    t.eq("更新事件类型", gateway.get_updates(bot)[-1]["event"], "message")
    t.eq("更新携带正文", gateway.get_updates(bot)[-1]["text"], "人工")

    rule = db.upsert_reply_rule(bot, trigger_type="exact", pattern="人工", reply_text="正在转接 {sender_name}",
                                cooldown_seconds=60)
    rules.invalidate_cache()
    hit = h.async_run(_process, gateway, bot, event)
    t.eq("规则命中并回复", (hit.replied, hit.handled_by, hit.status), (True, "rules", "ok"))
    t.eq("回复完成插值", hit.reply_text, "正在转接 小明")
    t.eq("发送引用原消息", stub.sends[-1]["quoted_item_id"], 123)
    t.eq("发送目标为原会话", stub.sends[-1]["chat_ref"], "@7")
    t.eq("命中计数入账", db.get_reply_rule(rule["id"])["hits"], 1)
    t.eq("出站台账状态", [row["status"] for row in db.recent_logs(bot, limit=1) if row["direction"] == "out"][0], "ok")
    cooldown = h.async_run(_process, gateway, bot, event)
    t.eq("冷却期内不再回复", (cooldown.replied, cooldown.reply_text), (False, ""))
    t.eq("冷却决策标注状态", rules.evaluate(InboundMessage(bot_id=bot, text="人工", sender="u7")).status, "cooldown")

    db.upsert_routing_rule(bot, name="退款转群", source_type="direct", keyword_mode="contains", keywords=["退款"],
                           target_type="group", target_ref="#42", quote_reply=True, cooldown_seconds=0)
    router.invalidate_cache()
    ticketed = h.async_run(_process, gateway, bot, NormalizedEvent(
        event_type="newChatItems", direction="in", chat_type="direct", chat_ref="@7", sender="u7",
        sender_name="小明", text="我要退款", ts=3100.0, item_id=200, raw={}))
    t.eq("路由转发成功", (ticketed.forwarded, ticketed.status), (1, "forwarded"))
    t.eq("路由接管后由 router 处理", ticketed.handled_by, "router")
    t.eq("转发计划写入结果", len(ticketed.plans), 1)
    group_send = [s for s in stub.sends if s["chat_ref"] == "#42"][-1]["text"]
    t.check("工单号进入转发文本", "#T" in group_send, group_send[:80])
    t.check("客户收到回执", [s for s in stub.sends if s["chat_ref"] == "@7"][-1]["text"].startswith("已收到您的咨询"),
            str([s for s in stub.sends if s["chat_ref"] == "@7"][-1]["text"]))
    t.check("工单登记表有记录", len(router.tickets) >= 1, str(len(router.tickets)))

    db.upsert_reply_rule(bot, trigger_type="default", pattern="", reply_text="没有理解 {text}")
    rules.invalidate_cache()
    default_hit = h.async_run(_process, gateway, bot, NormalizedEvent(
        event_type="newChatItems", direction="in", chat_type="direct", chat_ref="@8", sender="u8",
        sender_name="小李", text="随便问一句", ts=3200.0, item_id=300, raw={}))
    t.eq("兜底回复已发送", (default_hit.replied, default_hit.reply_text), (True, "没有理解 随便问一句"))
    before_suppressed = len(stub.sends)
    suppressed = h.async_run(_process, gateway, bot, NormalizedEvent(
        event_type="newChatItems", direction="in", chat_type="direct", chat_ref="@7", sender="u7",
        sender_name="小明", text="我要退款", ts=3300.0, item_id=400, raw={}))
    t.eq("路由命中时抑制兜底回复", (suppressed.status, suppressed.reply_text), ("forwarded", ""))
    t.check("仍然完成转发", suppressed.forwarded >= 1, str(suppressed.forwarded))
    t.check("兜底语没有跟着发出去",
            all("没有理解" not in s["text"] for s in stub.sends[before_suppressed:]),
            str(stub.sends[before_suppressed:]))

    plugin_case(test, h, settings)

    broken_stub = RecordingSupervisor(fail="CLI 控制通道未连接")
    broken_gw = BotGateway(settings, db, broken_stub, RuleEngine(db, bot_name="网关Bot"), router, None, max_updates=10)
    fail = h.async_run(_process, broken_gw, bot, event)
    t.eq("发送失败不影响流程", (fail.replied, fail.status), (False, "ok"))
    t.contains("失败被记录", broken_gw.errors[-1], "发送失败 @7")
    t.contains("失败记录含异常类型", broken_gw.errors[-1], "BotSupervisorError")
    broken_out = [row for row in db.recent_logs(bot, limit=10) if row["direction"] == "out"]
    t.check("发送失败写入错误台账", any(row["status"] == "error" for row in broken_out),
            str([(row["status"], row["text"][:20]) for row in broken_out]))
    t.eq("失败不增加投递数", broken_gw.delivered, 0)

    delivered = h.async_run(gateway.deliver, bot, "@7", "管理员代发")
    t.eq("公开投递接口可用", delivered, True)
    t.eq("公开投递走同一发送器", stub.sends[-1]["text"], "管理员代发")
    t.check("投递计数增长", gateway.delivered >= 1, str(gateway.delivered))
    quoted = h.async_run(gateway.deliver, bot, "#42", "带引用", quoted_item_id=9)
    t.eq("带引用投递", (quoted, stub.sends[-1]["quoted_item_id"]), (True, 9))
    t.eq("空会话不发送", h.async_run(gateway.deliver, bot, "", "x"), False)
    t.eq("空正文不发送", h.async_run(gateway.deliver, bot, "@7", ""), False)
    t.eq("空引用不污染发送记录", len([s for s in stub.sends if not s["chat_ref"]]), 0)
    offline = BotGateway(settings, db, RecordingSupervisor(fail="控制通道未建立"), rules, router, None)
    t.eq("控制通道不可用时投递失败", h.async_run(offline.deliver, bot, "@7", "离线投递"), False)
    t.eq("失败的公开投递也不计数字", offline.delivered, 0)

    snap = gateway.snapshot()
    t.eq("快照字段", sorted(snap), sorted(["delivered","queued_updates","errors","uptime","sends_by_bot"]))
    t.check("快照投递数与发送器一致", snap["delivered"] == gateway.delivered, str(snap))
    t.eq("快照按 Bot 统计", sum(snap["sends_by_bot"].values()), gateway.delivered)
    t.check("运行时长非负", snap["uptime"] >= 0.0, str(snap["uptime"]))
    t.eq("空网关错误列表", BotGateway(settings, db, RecordingSupervisor(), rules, router, None).snapshot()["errors"], [])
    many = BotGateway(settings, db, RecordingSupervisor(fail="x" * 400), rules, router, None)
    for index in range(60):
        h.async_run(many.deliver, bot, "@7", f"刷屏 {index}")
    t.eq("错误列表限长 50", len(many.errors), 50)
    t.eq("快照只回显最近 10 条", len(many.snapshot()["errors"]), 10)
    t.eq("错误列表保留最新", many.errors, [many.errors[0]] * 50)
    t.eq("超长错误文本被截断", len(many.errors[0]), 300)

    events = h.async_run(_gateway_events, gateway, bot)
    t.eq("联系人请求进入队列", events["request"]["event"], "receivedContactRequest")
    t.eq("联系人已连接进入队列", events["connected"]["event"], "contactConnected")
    t.eq("无关帧被丢弃", events["other"], None)
    t.eq("消息事件走完整管线", events["message"]["event"], "message")

    ops = h.async_run(_gateway_operator, gateway, router, bot)
    t.eq("工单回帖投递", ops["first"]["delivered"], True)
    t.eq("回帖发回原会话", ops["first"]["chat_ref"], "@7")
    t.eq("回帖正文去掉工单号", ops["first"]["text"], "已处理")
    t.eq("回帖记录工单号", ops["first"]["ticket_id"][:2], "#T")
    t.eq("无工单号时不投递", ops["plain"]["delivered"], False)
    t.eq("无工单号时给出原因", ops["plain"]["reason"], "未找到工单编号")
    t.eq("未知工单同样被拒", ops["ghost"]["delivered"], False)
    t.eq("回帖进入更新队列", ops["event"], "ticket_answered")
    db.close()


async def _process(gateway: BotGateway, bot_id: str, event: NormalizedEvent) -> ProcessResult:
    return await gateway.process(bot_id, event)


async def _gateway_events(gateway: BotGateway, bot_id: str) -> Dict[str, Any]:
    """Feed one of each non-message event type and report what reached the queue."""
    before = {item["update_id"] for item in gateway.get_updates(bot_id, limit=0)}
    await gateway.handle_event(bot_id, NormalizedEvent(event_type="receivedContactRequest", chat_ref="@31", text="我是老王"))
    await gateway.handle_event(bot_id, NormalizedEvent(event_type="contactConnected", chat_ref="@32", text="已连接"))
    await gateway.handle_event(bot_id, NormalizedEvent(event_type="someOtherFrame", chat_ref="@33", text="丢弃"))
    await gateway.handle_event(bot_id, NormalizedEvent(event_type="newChatItems", chat_type="direct",
                     chat_ref="@7", sender="u7", sender_name="小明", text="人工", item_id=500))
    fresh = [item for item in gateway.get_updates(bot_id, limit=0) if item["update_id"] not in before]
    by_event = {item["event"]: item for item in fresh}
    return {
        "request": by_event.get("receivedContactRequest"),
        "connected": by_event.get("contactConnected"),
        "other": by_event.get("someOtherFrame"),
        "message": by_event.get("message"),
    }


async def _gateway_operator(gateway: BotGateway, router: RouterEngine, bot_id: str) -> Dict[str, Any]:
    ticket = router.tickets.open_ticket(bot_id=bot_id, group_ref="#42", chat_ref="@7", sender="u7", sender_name="小明")
    first = await gateway.operator_reply(bot_id, "#42", f"{ticket} 已处理", operator="客服")
    plain = await gateway.operator_reply(bot_id, "#42", "大家辛苦了")
    ghost = await gateway.operator_reply(bot_id, "#42", "#TFFFFFF 好的")
    events = [item for item in gateway.get_updates(bot_id, limit=0) if item["event"] == "ticket_answered"]
    return {"first": first, "plain": plain, "ghost": ghost, "event": events[-1]["event"] if events else ""}


def plugin_case(test: SelfTest, h: Harness, settings: Any) -> None:
    """Prove the bus sits in front of the zero-code engines and cannot wedge them."""
    t = test
    plugins_dir = h.root / "plugins" / "gateway"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    (plugins_dir / "fast.py").write_text(FAST_PLUGIN_SOURCE, encoding="utf-8")
    (plugins_dir / "boom.py").write_text(BOOM_PLUGIN_SOURCE, encoding="utf-8")
    (plugins_dir / "relay.py").write_text(RELAY_PLUGIN_SOURCE, encoding="utf-8")

    db = h.database("gateway_plugins")
    bot = db.create_bot("gwplug", 5373, display_name="插件网关")["id"]
    rule = db.upsert_reply_rule(bot, trigger_type="exact", pattern="人工", reply_text="规则应答")
    db.upsert_routing_rule(bot, name="转群", source_type="direct", keyword_mode="contains", keywords=["转发"],
                           target_type="group", target_ref="#60", cooldown_seconds=0)
    stub = RecordingSupervisor()
    rules = RuleEngine(db, bot_name="插件网关")
    router = RouterEngine(db, bot_name="插件网关", clock=FakeClock(4000.0))
    plugins = PluginManager(db, _LateServices(), plugins_dir=plugins_dir)
    gateway = BotGateway(settings, db, stub, rules, router, plugins, max_updates=10)
    plugins.services = CoreServices(stub, db, gateway)

    outcomes = h.async_run(_plugin_roundtrip, plugins, gateway, bot)
    took_over = outcomes["takeover"]
    t.eq("插件优先于规则", (took_over.handled_by, took_over.status), ("selftest_fast", "plugin"))
    t.eq("插件接管后不再走规则", took_over.reply_text, "插件抢先接管 u7")
    t.eq("接管时只发送一次", outcomes["takeover_sends"], ["插件抢先接管 u7"])
    t.eq("接管时规则不计数", outcomes["takeover_hits"], 0)
    t.eq("转发插件产出计划", outcomes["forward"].forwarded, 1)
    t.eq("转发目标来自插件", outcomes["forward_targets"], ["#61"])
    t.eq("转发插件可回执", outcomes["forward"].reply_text, "已转发给值班群")
    t.eq("插件回复计入投递", outcomes["delivered"], outcomes["send_count"])
    crash = outcomes["crash"]
    t.eq("坏插件不阻断规则", (crash.handled_by, crash.reply_text), ("rules", "规则应答"))
    t.eq("坏插件错误入账", outcomes["crash_errors"], 1)
    t.contains("坏插件记录异常类型", outcomes["crash_last_error"], "RuntimeError")
    t.eq("坏插件仍算一次派发", outcomes["dispatches"], 4)
    t.eq("插件台账写入错误状态", outcomes["error_log"], "error")
    t.eq("崩溃回退后规则才计数", outcomes["final_hits"], 2)
    t.eq("停用后插件不再拦截", outcomes["disabled"].handled_by, "rules")
    t.eq("停用的插件不再被调用", outcomes["fast_calls"], 3)
    db.close()


async def _plugin_roundtrip(plugins: PluginManager, gateway: BotGateway, bot_id: str) -> Dict[str, Any]:
    await plugins.load_async()
    await plugins.set_enabled("selftest_fast", True)
    await plugins.set_enabled("selftest_relay", True)
    sends = gateway.supervisor.sends
    rule_id = gateway.db.list_reply_rules(bot_id)[0]["id"]
    takeover = await gateway.process(bot_id, NormalizedEvent(event_type="newChatItems", chat_ref="@7",
                                   sender="u7", sender_name="小明", text="人工", item_id=600))
    takeover_sends = [item["text"] for item in list(sends)]
    takeover_hits = gateway.db.get_reply_rule(rule_id)["hits"]
    forward = await gateway.process(bot_id, NormalizedEvent(event_type="newChatItems", chat_ref="@7",
                                          sender="u7", sender_name="小明", text="转发给值班", item_id=601))
    forward_targets = [item["chat_ref"] for item in list(sends) if item["chat_ref"] == "#61"]
    await plugins.set_enabled("selftest_boom", True)
    crash = await gateway.process(bot_id, NormalizedEvent(event_type="newChatItems", chat_ref="@8",
                                sender="u8", sender_name="小李", text="人工", item_id=602))
    boom = plugins.get("selftest_boom")
    crash_errors, crash_last_error = boom.errors, boom.last_error
    await plugins.set_enabled("selftest_fast", False)
    disabled = await gateway.process(bot_id, NormalizedEvent(event_type="newChatItems", chat_ref="@7",
                                     sender="u7", sender_name="小明", text="人工", item_id=603))
    status = plugins.health()
    logs = gateway.db.recent_logs(bot_id, limit=40)
    return {
        "takeover": takeover,
        "forward": forward,
        "crash": crash,
        "disabled": disabled,
        "takeover_sends": takeover_sends,
        "forward_targets": forward_targets,
        "takeover_hits": takeover_hits,
        "final_hits": gateway.db.get_reply_rule(rule_id)["hits"],
        "delivered": gateway.delivered,
        "send_count": len(sends),
        "crash_errors": crash_errors,
        "crash_last_error": crash_last_error,
        "dispatches": status["dispatches"],
        "fast_calls": plugins.get("selftest_fast").calls,
        "error_log": next((row["status"] for row in logs if row["plugin_id"] == "selftest_boom"), ""),
    }


# --------------------------------------------------------------------------- 9
BUNDLED_PLUGINS = ("webhook_relay.py", "msg_router.py", "auto_reply.py", "llm_bridge.py", "personal_agent.py")
BUNDLED_IDS = ("auto_reply", "llm_bridge", "msg_router", "personal_agent", "webhook_relay")
ROUTER_PLUGIN_CONFIG = {
    "routes": [{
        "name": "售后", "keywords": ["退款"], "mode": "contains", "source": "direct",
        "targets": ["#42"], "template": "[{ticket_id}] {sender_name}：{text}",
        "receipt": "已建立工单 {ticket_id}",
    }],
    "route_group_replies": True,
}


class RecordingServices:
    """The ``StudioServices`` surface a plugin may touch, with every call recorded."""

    def __init__(self, bots: Sequence[str] = ()):
        self.sends: List[Dict[str, Any]] = []
        self.logs: List[Dict[str, Any]] = []
        self.bots = list(bots)

    async def send_text(
        self, bot_id: str, chat_type: str, chat_id: str, text: str, *,
        quoted_item_id: Optional[int] = None, plugin_id: str = "",
    ) -> Dict[str, Any]:
        self.sends.append({"bot_id": bot_id, "chat_type": chat_type, "chat_id": chat_id,
                           "text": text, "quoted": quoted_item_id, "plugin_id": plugin_id})
        return {"delivered": 1}

    async def send_content(
        self, bot_id: str, chat_type: str, chat_id: str, content: Dict[str, Any], *,
        plugin_id: str = "", file_path: str = "",
    ) -> Dict[str, Any]:
        self.sends.append({"bot_id": bot_id, "chat_type": chat_type, "chat_id": chat_id,
                           "content": content, "plugin_id": plugin_id, "file_path": file_path})
        return {"delivered": 1}

    def log_message(self, bot_id: str, direction: str, **kwargs: Any) -> int:
        self.logs.append({"bot_id": bot_id, "direction": direction, **kwargs})
        return len(self.logs)

    def clients(self) -> List[str]:
        return list(self.bots)


def _enable(h: Harness, mgr: PluginManager, plugin_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
    return h.async_run(mgr.update_config, plugin_id, config, enabled=True)


def _dispatch(
    h: Harness, mgr: PluginManager, bot_id: str, text: str, *, chat_ref: str = "@7",
    chat_type: str = "direct", sender: str = "u7", sender_name: str = "小明",
) -> List[Tuple[str, str, str]]:
    """One message through the bus as ``(plugin_id, status, reply)`` per plugin."""

    async def run() -> List[Tuple[str, str, str]]:
        event = InboundMessage(bot_id=bot_id, text=text, sender=sender, sender_name=sender_name,
                               chat_ref=chat_ref, chat_type=chat_type)
        return [(pid, result.status, result.reply) for pid, result in await mgr.handle_message(event, bot_id=bot_id)]

    return h.async_run(run)


def _handled(
    h: Harness, mgr: PluginManager, bot_id: str, text: str, **kwargs: Any
) -> Optional[Dict[str, Any]]:
    """The first plugin outcome that actually takes the message, or ``None``."""

    async def run() -> Optional[Dict[str, Any]]:
        event = InboundMessage(bot_id=bot_id, text=text, sender=kwargs.get("sender", "u7"),
                               sender_name=kwargs.get("sender_name", "小明"),
                               chat_ref=kwargs.get("chat_ref", "@7"), chat_type=kwargs.get("chat_type", "direct"))
        for pid, result in await mgr.handle_message(event, bot_id=bot_id):
            if result.handled:
                return {"plugin_id": pid, "status": result.status, "reply": result.reply,
                        "forwards": list(result.forwards), "metadata": dict(result.metadata)}
        return None

    return h.async_run(run)


def group_plugins(test: SelfTest, h: Harness) -> None:
    """内置插件：元数据契约、默认惰性、真实行为（含替身机器人 personal_agent）。"""
    t = test
    plugins_dir = ROOT / "plugins"
    t.check("插件目录存在", plugins_dir.is_dir(), str(plugins_dir))
    for name in BUNDLED_PLUGINS:
        t.check(f"内置插件 {name} 在仓库内", (plugins_dir / name).is_file(), str(plugins_dir / name))

    ids: List[str] = []
    for name in BUNDLED_PLUGINS:
        instances = load_plugin_module(plugins_dir / name)
        t.eq(f"{name} 只导出一个插件类", len(instances), 1)
        plugin = instances[0]
        ids.append(plugin.plugin_id)
        t.check(f"{name} 声明 plugin_id", bool(plugin.plugin_id), repr(plugin.plugin_id))
        t.check(f"{name} 优先级是整数", isinstance(plugin.priority, int), repr(plugin.priority))
        t.eq(f"{name} 只监听消息", plugin.scope, "message")
        keys = [plugin_id_field(field) for field in plugin.config_fields]
        t.check(f"{name} 配置字段不重复", len(keys) == len(set(keys)), str(keys))
        t.check(f"{name} 配置字段类型合法",
                all(str(field.get("type")) in CONFIG_FIELD_TYPES for field in plugin.config_fields),
                str([field.get("type") for field in plugin.config_fields]))
        t.check(f"{name} 每个字段都有中文名",
                all(str(field.get("label") or "").strip() for field in plugin.config_fields), str(keys))
        t.eq(f"{name} 默认配置与字段一一对应", set(keys), set(plugin.default_config))
        t.eq(f"{name} 默认开关为真、实例仍未启用", (plugin.default_config.get("enabled"), plugin.enabled), (True, False))
    t.eq("内置插件 id 齐备", tuple(sorted(set(ids))), BUNDLED_IDS)

    db = h.database("plugins_real")
    bot = db.create_bot("plugprobe", 5380, display_name="内置插件")["id"]
    services = RecordingServices()
    mgr = PluginManager(db, services, plugins_dir=plugins_dir, tick_interval=5.0)
    t.eq("内置插件全部就绪", sorted(h.async_run(mgr.load_async).values()), ["ready"] * len(BUNDLED_IDS))
    t.eq("加载零失败", mgr.health()["failures"], {})
    t.eq("注册表清单", mgr.ids(), list(BUNDLED_IDS))
    t.eq("未启用时不参与派发", [p.plugin_id for p in mgr.ordered()], [])
    t.eq("未启用时消息直通引擎", _dispatch(h, mgr, bot, "帮助"), [])

    _enable(h, mgr, "auto_reply", {})
    t.eq("/start 给出欢迎语", _handled(h, mgr, bot, "/start")["reply"],
         "你好 小明，这里是 plugprobe，发送 /menu 查看菜单。")
    t.contains("/menu 渲染指令树", _handled(h, mgr, bot, "/menu")["reply"], "服务列表")
    t.eq("关键词问答命中", _handled(h, mgr, bot, "帮助")["reply"],
         "需要帮助？发送 /menu 查看菜单，或描述具体问题。")
    t.eq("带参数指令插值", _handled(h, mgr, bot, "/order 42")["reply"], "订单 42 正在处理。")
    t.eq("正则关键词命中", _handled(h, mgr, bot, "在吗")["reply"], "在的，请说。")
    t.eq("未知指令无人接管", _handled(h, mgr, bot, "/不存在的指令"), None)
    t.eq("命中来源写入元数据", _handled(h, mgr, bot, "价格")["metadata"]["matched_via"], "keyword:价格")
    _enable(h, mgr, "auto_reply", {"max_replies_per_chat": 1, "window_seconds": 600})
    t.check("限额内首条仍应答", _handled(h, mgr, bot, "帮助") is not None, "被静默")
    t.eq("超出单会话上限后静默", _handled(h, mgr, bot, "帮助"), None)
    _enable(h, mgr, "auto_reply", {"max_replies_per_chat": 0})
    db.upsert_reply_rule(bot, trigger_type="exact", pattern="人工", reply_text="核心规则应答")
    t.eq("核心规则已认领时插件让路", _handled(h, mgr, bot, "人工"), None)
    _enable(h, mgr, "auto_reply", {"defer_to_core": False})
    t.eq("关掉让路后插件接管", _handled(h, mgr, bot, "人工")["metadata"]["matched_via"], "keyword:人工")
    t.check("让路开关写回账本", "defer_to_core" in str(db.get_plugin_config("auto_reply")["config"]))
    h.async_run(mgr.set_enabled, "auto_reply", False)

    _enable(h, mgr, "msg_router", ROUTER_PLUGIN_CONFIG)
    t.eq("没有已连接的 CLI 时路由插件不接管", _handled(h, mgr, bot, "我要退款"), None)
    t.eq("缺席客户端被记成错误", services.logs[-1]["status"], "error")
    services.bots = [bot]
    opened = _handled(h, mgr, bot, "我要退款")
    t.check("工单被创建", opened is not None, str(opened))
    t.eq("路由插件状态", opened["status"], "forwarded")
    t.eq("客户回执带工单号", opened["reply"], f"已建立工单 TK-{opened['metadata']['ticket_id']}")
    t.eq("转发目标来自配置", opened["metadata"]["targets"], ["#42"])
    t.contains("群内文本带工单号", opened["forwards"][0]["text"], "[TK-")
    t.check("工单号用 TK- 前缀避开核心 #T", opened["reply"].startswith("已建立工单 TK-"), opened["reply"])
    t.check("工单号是 6 位十六进制", re.match(r"^[0-9A-F]{6}$", opened["metadata"]["ticket_id"]) is not None,
            str(opened["metadata"]["ticket_id"]))
    t.eq("转发目标会话", opened["forwards"][0]["chat_ref"], "#42")
    t.eq("插件只产计划不代发", len(services.sends), 0)
    second = _handled(h, mgr, bot, "我要退款")
    t.ne("每次咨询开新工单", second["metadata"]["ticket_id"], opened["metadata"]["ticket_id"])
    back = _handled(h, mgr, bot, f"TK-{second['metadata']['ticket_id']} 已处理",
                    chat_ref="#42", chat_type="group", sender="op1")
    t.check("群内回帖转回客户", back is not None, str(back))
    t.eq("回帖目标是客户单聊", back["forwards"][0]["chat_ref"], "@7")
    t.eq("回帖正文去掉工单号", back["forwards"][0]["text"].splitlines()[0], "已处理")
    t.contains("回帖附工单尾注", back["forwards"][0]["text"], "客服回复（工单 TK-")
    t.eq("客户回执说明转交", back["reply"][:3], "已转达")
    t.eq("陌生工单号不被当回帖", _handled(h, mgr, bot, "TK-FFFFFF 别慌",
                                    chat_ref="#42", chat_type="group", sender="op1"), None)
    h.async_run(mgr.set_enabled, "msg_router", False)

    _enable(h, mgr, "llm_bridge", {})
    t.eq("默认配置不接 LLM", _handled(h, mgr, bot, "你好呀"), None)
    _enable(h, mgr, "llm_bridge", {"api_key": "k", "base_url": "http://127.0.0.1:1", "timeout_seconds": 1})
    t.eq("端点不可达时不劫持对话", _handled(h, mgr, bot, "你好呀"), None)
    t.eq("群组消息被 only_direct 挡下", _handled(h, mgr, bot, "你好呀", chat_ref="#42",
                                          chat_type="group"), None)
    h.async_run(mgr.set_enabled, "llm_bridge", False)

    hook_config = {"hook_secret": "ss", "hook_targets": [{"chat_type": "group", "chat_ref": "#42"}],
                   "dedup_window_seconds": 120}
    _enable(h, mgr, "webhook_relay", hook_config)
    bad = h.async_run(mgr.handle_hook, bot, "wrong", {"text": "hi"})
    t.eq("错误密钥拒绝入站钩子", (bad["handled"], bad["status"]), (False, "unauthorized"))
    t.contains("拒绝原因只说密钥不匹配", bad["metadata"]["reason"], "密钥不匹配")
    t.check("错误响应不回显密钥", "ss" not in json.dumps(bad, ensure_ascii=False), str(bad))
    alert = h.async_run(mgr.handle_hook, bot, "ss",
                        {"text": "数据库挂了", "severity": "critical", "source": "db"})
    t.eq("告警被接管", (alert["handled"], alert["status"]), (True, "ok"))
    t.eq("告警投递到一个目标", alert["metadata"]["delivered"], 1)
    t.eq("投递走受限服务面", services.sends[-1]["chat_id"], "#42")
    t.contains("告警正文带级别", services.sends[-1]["text"], "[critical]")
    dup = h.async_run(mgr.handle_hook, bot, "ss", {"text": "数据库挂了", "severity": "critical", "source": "db"})
    t.eq("重复告警被抑制", (dup["handled"], dup["status"]), (True, "suppressed"))
    _enable(h, mgr, "webhook_relay", dict(hook_config, dedup_window_seconds=0, min_severity="warning"))
    before = len(services.sends)
    quiet = h.async_run(mgr.handle_hook, bot, "ss", {"text": "只是提示", "severity": "info"})
    t.eq("低于阈值由插件认领并拒绝", (quiet["handled"], quiet["status"]), (True, "error"))
    t.contains("拒绝原因写明级别不足", quiet["metadata"]["reason"], "severity info < warning")
    t.eq("拒绝不产生任何发送", len(services.sends), before)
    t.eq("停用后钩子无人认领", h.async_run(mgr.set_enabled, "webhook_relay", False) and
         h.async_run(mgr.handle_hook, bot, "ss", {"text": "x"})["status"], "no_plugin")
    t.check("派发消息计数入账", mgr.health()["dispatches"] >= 12, str(mgr.health()["dispatches"]))
    h.async_run(mgr.stop)
    t.eq("停机后插件不再参与派发", mgr.ordered(), [])
    db.close()


# --------------------------------------------------------------------------- 10
class _ApiRouterDouble:
    """``RouterEngine`` 的最小替身：Open API 只用到 ``known_groups``。"""

    def __init__(self, groups: Sequence[str]):
        self.groups = list(groups)

    def known_groups(self, bot_id: str) -> List[str]:
        return list(self.groups)


class _ApiGatewayDouble:
    """``BotGateway`` 的最小替身：只实现 Open API 真正调用的两个方法。"""

    def __init__(self, *, groups: Sequence[str] = (), updates: Optional[List[Dict[str, Any]]] = None):
        self.calls: List[Dict[str, Any]] = []
        self.deliver_ok = True
        self.updates: List[Dict[str, Any]] = list(updates or [])
        self.router = _ApiRouterDouble(groups) if groups else None

    async def deliver(self, bot_id: str, chat_ref: str, text: str, *, quoted_item_id: Optional[int] = None) -> bool:
        self.calls.append(
            {"bot_id": bot_id, "chat_ref": chat_ref, "text": text, "quoted": quoted_item_id}
        )
        return self.deliver_ok

    def get_updates(self, bot_id: str, *, offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        rows = [item for item in self.updates if int(item["update_id"]) > offset]
        return rows[-int(limit):] if limit else rows


class _BoomGateway:
    """任何调用都抛错：验证 Open API 把内部异常折叠成错误封套而不是 500 堆栈。"""

    async def deliver(self, *args: Any, **kwargs: Any) -> bool:
        raise RuntimeError("网关内部炸了")

    def get_updates(self, *args: Any, **kwargs: Any) -> List[Dict[str, Any]]:
        raise RuntimeError("缓冲炸了")


def group_open_api(test: SelfTest, h: Harness) -> None:
    """开发者 Open API：鉴权载体、五个方法、错误封套与回环约束，全部对着注入的网关替身度量。"""
    t = test
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from . import open_api as _api

    settings = h.settings()
    db = h.database("openapi")
    bot = db.create_bot("openapibot", 5380, default_locale="ja")
    token = str(bot["bot_token"])
    second = db.create_bot("openapibot2", 5381)
    other_token = str(second["bot_token"])
    stray = db.create_bot("openapibot4", 5382)  # 无任何日志与规则，用来验证「无群组可播报」

    t.eq("Open API 前缀", OPEN_API_PREFIX, "/api/v1")
    t.eq("五个方法固定顺序", OPEN_METHODS, ("getMe", "sendMessage", "broadcastGroup", "setWebhook", "getUpdates"))
    t.eq("路径内嵌 token 的参数名", PATH_PREFIX, "/bot{path_token}")
    paths = mounted_paths(OPEN_API_PREFIX)
    t.eq("挂载路由数量", len(paths), 10)
    t.check("裸路径与 bot<TOKEN> 路径成对",
            all(f"{OPEN_API_PREFIX}/bot{{path_token}}{m}" in paths for m in ("/getMe", "/getUpdates")),
            str(paths))
    t.eq("文本长度上限", MAX_TEXT_LENGTH, 4000)
    t.eq("Webhook 长度上限", MAX_WEBHOOK_LENGTH, 512)

    gw = _ApiGatewayDouble()
    api_configure(settings=settings, database=db, gateway=gw, supervisor=None)
    app = FastAPI()
    app.include_router(open_api_router, prefix=OPEN_API_PREFIX)
    c = TestClient(app)
    bearer = {"Authorization": f"Bearer {token}"}
    base = f"{OPEN_API_PREFIX}/bot{token}"

    no_auth = c.get(f"{OPEN_API_PREFIX}/getMe")
    t.eq("无 token 拒绝", no_auth.status_code, 401)
    t.eq("拒绝只给封套", sorted(no_auth.json()), ["description", "error_code", "ok"])
    t.eq("错误码等于 HTTP 状态", no_auth.json()["error_code"], no_auth.status_code)
    t.contains("拒绝文案指出两种载体", no_auth.json()["description"], "Authorization: Bearer")
    t.eq("查询串 token 不被接受",
         c.get(f"{OPEN_API_PREFIX}/getMe", params={"token": token}).status_code, 401)
    t.eq("Bearer 头可用", c.get(f"{OPEN_API_PREFIX}/getMe", headers=bearer).status_code, 200)
    t.eq("bearer 大小写不敏感",
         c.get(f"{OPEN_API_PREFIX}/getMe",
               headers={"Authorization": f"bearer {token}"}).json()["result"]["name"], "openapibot")
    t.eq("路径内嵌 token 可用", c.get(f"{base}/getMe").json()["result"]["name"], "openapibot")
    t.eq("错误 token 拒绝", c.get(f"{OPEN_API_PREFIX}/getMe",
                                  headers={"Authorization": "Bearer 1:deadbeef"}).json()["description"],
         "Bot Token 无效或对应 Bot 已删除")
    t.eq("别人的 token 不串号", c.get(f"{base}/getMe").json()["result"]["id"], bot["id"])

    me = c.get(f"{base}/getMe").json()["result"]
    t.eq("getMe 是成功封套", sorted(c.get(f"{base}/getMe").json()), ["ok", "result"])
    t.eq("getMe 给出区域", me["locale"], "ja")
    t.eq("getMe 刻意不含 token", "bot_token" in json.dumps(me), False)
    t.eq("未运行则不能发消息", me["can_send_messages"], False)
    t.eq("默认无 webhook", me["has_webhook"], False)
    t.eq("getMe 回列方法", me["api_methods"], list(OPEN_METHODS))
    t.eq("端口如实回显", me["port"], 5380)
    t.eq("永久链接未生成时不出现", "permanent_link" in me, False)

    sent = c.post(f"{base}/sendMessage", json={"chat_id": "#42", "text": "hi", "quoted_message_id": "7"})
    t.eq("发送成功", sent.status_code, 200)
    t.eq("成功结果字段", sorted(sent.json()["result"]),
         ["bot_status", "chat_ref", "chat_type", "delivered", "log_id", "quoted_message_id", "text"])
    t.eq("会话类型按前缀判定", sent.json()["result"]["chat_type"], "group")
    t.eq("引用编号转成整数", sent.json()["result"]["quoted_message_id"], 7)
    t.eq("投递确实打到网关", (gw.calls[-1]["chat_ref"], gw.calls[-1]["quoted"]), ("#42", 7))
    t.eq("出站写入审计日志", sent.json()["result"]["log_id"] > 0, True)
    t.eq("别名 chat 字段等价",
         c.post(f"{base}/sendMessage", json={"chat": "@7", "body": "别名"}).json()["result"]["chat_ref"], "@7")
    form = c.post(f"{base}/sendMessage", data={"chat_id": "@8", "text": "表单"})
    t.eq("表单与 JSON 等价", (form.status_code, form.json()["result"]["chat_ref"]), (200, "@8"))
    t.eq("缺 chat_id",
         c.post(f"{base}/sendMessage", json={"text": "x"}).json()["description"],
         "缺少 chat_id：应为 @<contactId> 或 #<groupId>")
    t.eq("缺 text", c.post(f"{base}/sendMessage", json={"chat_id": "#1"}).json()["error_code"], 400)
    t.eq("纯空白 text 也算缺",
         c.post(f"{base}/sendMessage", json={"chat_id": "#1", "text": "   "}).json()["error_code"], 400)
    t.eq("非法会话引用被拒",
         c.post(f"{base}/sendMessage", json={"chat_id": "hello there", "text": "x"}).json()["error_code"], 400)
    t.contains("非法引用说明期望格式",
               c.post(f"{base}/sendMessage", json={"chat_id": "hello there", "text": "x"}).json()["description"],
               "@<contactId> 或 #<groupId>")
    t.eq("超长文本被拒",
         c.post(f"{base}/sendMessage", json={"chat_id": "#1", "text": "x" * (MAX_TEXT_LENGTH + 1)}).json()["description"],
         f"text 过长（{MAX_TEXT_LENGTH + 1} > {MAX_TEXT_LENGTH} 字符）")
    t.eq("刚好上限可发送",
         c.post(f"{base}/sendMessage", json={"chat_id": "#1", "text": "x" * MAX_TEXT_LENGTH}).status_code, 200)
    t.eq("引用编号必须是整数",
         c.post(f"{base}/sendMessage",
                json={"chat_id": "#1", "text": "x", "quoted_message_id": "abc"}).json()["description"],
         "quoted_message_id 必须是整数，当前值 'abc'")
    t.eq("坏 JSON 请求体报 400",
         c.post(f"{base}/sendMessage", content=b"{oops",
                headers={"Content-Type": "application/json"}).status_code, 400)
    t.contains("坏 JSON 说明原因",
               c.post(f"{base}/sendMessage", content=b"{oops",
                      headers={"Content-Type": "application/json"}).json()["description"], "不是合法 JSON")
    t.eq("错误方法 405", c.post(f"{base}/getMe").status_code, 405)
    t.eq("未知方法 404", c.get(f"{base}/nope").status_code, 404)

    gw.deliver_ok = False
    out_before = len([r for r in db.recent_logs(bot["id"], limit=500) if r["direction"] == "out"])
    down = c.post(f"{base}/sendMessage", json={"chat_id": "@9", "text": "掉线"})
    t.eq("网关拒绝转成 500", down.status_code, 500)
    t.eq("失败封套仍带结果", sorted(down.json()), ["description", "error_code", "ok", "result"])
    t.eq("失败结果说明未送达", down.json()["result"]["delivered"], False)
    t.contains("失败原因指向控制通道", down.json()["description"], "CLI 控制通道未连接或发送失败")
    t.contains("失败原因带 Bot 状态", down.json()["description"], "Bot 状态 draft")
    out_after = len([r for r in db.recent_logs(bot["id"], limit=500) if r["direction"] == "out"])
    t.eq("失败不重复写审计（网关已记账）", out_after, out_before)
    t.eq("失败时 log_id 归零", down.json()["result"]["log_id"], 0)
    gw.deliver_ok = True

    boom_app = FastAPI()
    boom_app.include_router(open_api_router, prefix=OPEN_API_PREFIX)
    api_configure(settings=settings, database=db, gateway=_BoomGateway(), supervisor=None)
    boom = TestClient(boom_app)
    exploded = boom.post(f"{base}/sendMessage", json={"chat_id": "#1", "text": "x"})
    t.eq("网关内部异常不外泄堆栈", exploded.status_code, 500)
    t.contains("内部异常折叠为类型说明", exploded.json()["description"], "RuntimeError")
    t.check("响应体不含 traceback", "Traceback" not in exploded.text, exploded.text[:200])

    api_configure(settings=settings, database=db, gateway=gw, supervisor=None)
    broad = c.post(f"{base}/broadcastGroup", json={"text": "广播", "chat_ids": ["#1", "#2", "#1"]})
    t.eq("显式目标去重保序", broad.json()["result"]["targets"], ["#1", "#2"])
    t.eq("显式目标全部送达", (broad.json()["result"]["sent"], broad.json()["result"]["failed"]), (2, 0))
    t.eq("逐目标结果", broad.json()["result"]["results"],
         [{"chat_ref": "#1", "ok": True, "error": ""}, {"chat_ref": "#2", "ok": True, "error": ""}])
    t.eq("逗号串同样解析",
         c.post(f"{base}/broadcastGroup", json={"text": "x", "chat_ids": "#3,#4"}).json()["result"]["targets"],
         ["#3", "#4"])
    t.eq("显式目标覆盖学习结果",
         c.post(f"{OPEN_API_PREFIX}/bot{other_token}/broadcastGroup",
                json={"text": "x", "chat_ids": ["@7", "#5"]}).json()["result"]["targets"], ["#5"])
    t.eq("dry_run 不发送",
         c.post(f"{base}/broadcastGroup", json={"text": "x", "chat_ids": "#6", "dry_run": True}).json()["result"],
         {"targets": ["#6"], "total": 1, "dry_run": True, "sent": 0, "failed": 0, "results": []})
    t.eq("播报缺文本",
         c.post(f"{base}/broadcastGroup", json={}).json()["description"], "缺少 text：播报内容不能为空")
    no_group = c.post(f"{OPEN_API_PREFIX}/bot{stray['bot_token']}/broadcastGroup", json={"text": "无人接单"})
    t.eq("无已知群组返回 404", no_group.status_code, 404)
    t.contains("404 提示显式指定目标", no_group.json()["description"], "chat_ids=")
    learned = _ApiGatewayDouble(groups=["#70", "#71"])
    api_configure(settings=settings, database=db, gateway=learned, supervisor=None)
    t.eq("路由群组优先于日志兜底",
         c.post(f"{base}/broadcastGroup", json={"text": "x"}).json()["result"]["targets"], ["#70", "#71"])
    t.eq("学到的群组逐个投递", [call["chat_ref"] for call in learned.calls], ["#70", "#71"])
    api_configure(settings=settings, database=db, gateway=gw, supervisor=None)

    hook_cases = [
        ("https://example.com/hook", 200, ""),
        ("http://localhost:8080/hook", 200, ""),
        ("http://127.0.0.1:9/hook", 200, ""),
        ("http://example.com/hook", 400, "明文 http 只允许回环地址"),
        ("ftp://example.com/hook", 400, "被拒绝：只支持 https 或回环 http"),
        ("example.com/hook", 400, "必须带 scheme"),
        ("https://u:p@example.com/hook", 400, "不能内嵌用户名或密码"),
        ("https://example.com/hook#frag", 400, "不能带 fragment"),
        ("x" * (MAX_WEBHOOK_LENGTH + 1), 400, "Webhook URL 过长"),
    ]
    for url, status, needle in hook_cases:
        resp = c.post(f"{base}/setWebhook", json={"url": url})
        t.eq(f"Webhook {url[:22]!r} 状态", resp.status_code, status)
        if needle:
            t.contains(f"Webhook {url[:22]!r} 原因", resp.json()["description"], needle)
    t.eq("https 自定义端口放行",
         c.post(f"{base}/setWebhook", json={"url": "https://example.com:8443/hook"}).status_code, 200)
    t.eq("回环 IPv6 放行",
         c.post(f"{base}/setWebhook", json={"url": "https://[::1]:9/hook"}).status_code, 200)
    t.eq("缺少 url 键报错",
         c.post(f"{base}/setWebhook", json={}).json()["description"], "缺少 url：注销请传 url=（空串）")
    generated = c.post(f"{base}/setWebhook", json={"url": "https://example.com/a"}).json()["result"]
    t.check("自动生成的密钥是 32 位十六进制",
            re.match(r"^[0-9a-f]{32}$", generated["secret"]) is not None, str(generated))
    t.eq("回执标记生效", generated["active"], True)
    kept = c.post(f"{base}/setWebhook", json={"url": "https://example.com/b", "secret": "dev-secret"}).json()["result"]
    t.eq("显式密钥原样保留", kept["secret"], "dev-secret")
    cleared = c.post(f"{base}/setWebhook", json={"url": ""}).json()["result"]
    t.eq("清空 url 即注销", (cleared["active"], cleared["secret"], cleared["webhook_url"]), (False, "", ""))
    t.eq("注销后落库为空", db.get_bot(bot["id"])["webhook_url"], "")
    t.eq("注销后 getMe 无 webhook", c.get(f"{base}/getMe").json()["result"]["has_webhook"], False)
    seen: List[Tuple[str, str, str]] = []

    async def _audit(row: Dict[str, Any], url: str, secret: str) -> None:
        seen.append((str(row["id"]), url, secret))

    async def _broken(*args: Any) -> None:
        raise RuntimeError("监听器炸了")

    register_webhook_listener(_audit)
    register_webhook_listener(_broken)
    audited = c.post(f"{base}/setWebhook", json={"url": "https://example.com/c", "secret": "s9"})
    t.eq("监听器异常不影响响应", audited.status_code, 200)
    t.eq("监听器收到落库后的 Bot", seen, [(bot["id"], "https://example.com/c", "s9")])
    _api._webhook_listeners[:] = [fn for fn in _api._webhook_listeners if fn not in (_audit, _broken)]
    t.eq("自检不遗留监听器", len(_api._webhook_listeners), 0)

    empty = c.get(f"{base}/getUpdates").json()
    t.eq("空缓冲返回空列表", (empty["result"], empty["count"], empty["oldest"]), ([], 0, None))
    t.eq("缓冲上限随常量", empty["buffer_limit"], 500)
    gw.updates = [{"update_id": i, "bot_id": bot["id"], "event": "message", "text": f"m{i}"} for i in range(1, 6)]
    pulled = c.get(f"{base}/getUpdates", params={"offset": 3}).json()
    t.eq("offset 只取新消息", [u["update_id"] for u in pulled["result"]], [4, 5])
    t.eq("回执 offset 推进到最新", pulled["offset"], 5)
    t.eq("oldest 给出首条", pulled["oldest"], 4)
    t.eq("limit 截断保留最新", [u["update_id"] for u in c.get(
        f"{base}/getUpdates", params={"limit": 2}).json()["result"]], [4, 5])
    t.eq("limit 为 0 被拒", c.get(f"{base}/getUpdates", params={"limit": 0}).json()["description"],
         "limit 必须在 1-500 之间，当前值 0")
    t.eq("limit 越界被拒",
         c.get(f"{base}/getUpdates", params={"limit": 501}).status_code, 400)
    t.eq("负 offset 被拒", c.get(f"{base}/getUpdates", params={"offset": -1}).json()["error_code"], 400)
    t.eq("负 timeout 被拒",
         c.get(f"{base}/getUpdates", params={"timeout": -1}).json()["description"], "timeout 不能为负数")
    waited = c.get(f"{base}/getUpdates", params={"offset": 99, "timeout": 1}).json()
    t.check("短轮询确实等待", waited["long_poll_waited"] >= 0.4, str(waited["long_poll_waited"]))
    t.eq("等待后仍无更新", waited["count"], 0)
    t.eq("长轮询上限 30 秒", _api.MAX_POLL_SECONDS, 30.0)
    instant = c.get(f"{base}/getUpdates", params={"timeout": 600}).json()
    t.check("有更新时立刻返回，不等待", instant["long_poll_waited"] < 0.2, str(instant["long_poll_waited"]))
    t.eq("超大 timeout 也只是上限内等待", instant["count"], 5)

    api_configure(settings=settings, database=db, gateway=None, supervisor=None)
    fallback = c.get(f"{base}/getUpdates").json()
    t.eq("网关缺席时从日志重建", fallback["result"][-1]["source"], "message_logs")
    t.eq("重建的 update 带方向", fallback["result"][-1]["direction"], "out")
    t.eq("重建的 update_id 来自日志主键",
         fallback["result"][0]["update_id"], min(int(r["id"]) for r in db.recent_logs(bot["id"], limit=500)))
    only_db = FastAPI()
    only_db.include_router(open_api_router, prefix=OPEN_API_PREFIX)
    api_configure(settings=settings, database=None, gateway=None, supervisor=None)
    bare = TestClient(only_db)
    nobody = bare.get(f"{base}/getUpdates", headers=bearer)
    t.eq("账本缺席时无法鉴权", (nobody.status_code, nobody.json()["error_code"]), (401, 401))
    t.eq("失败提示 token 无效", nobody.json()["description"], "Bot Token 无效或对应 Bot 已删除")
    api_configure(settings=settings, database=db, gateway=None, supervisor=None)
    stranded = TestClient(app)
    t.eq("无网关时 sendMessage 报 500",
         stranded.post(f"{base}/sendMessage", json={"chat_id": "#1", "text": "x"}).json()["description"],
         "消息网关未初始化（BotGateway 未注入且无法从 app.main 发现）")

    err = ApiError(404, 4242, "很长" * 400)
    t.eq("ApiError 携带状态码", err.as_response().status_code, 404)
    t.eq("ApiError 自定义错误码", err.error_code, 4242)
    t.eq("ApiError 描述截断到 400", len(err.description), 400)
    gone = db.create_bot("openapibot5", 5383)
    db.delete_bot(gone["id"])
    api_configure(settings=settings, database=db, gateway=gw, supervisor=None)
    t.eq("已删除 Bot 的 token 失效",
         c.get(f"{OPEN_API_PREFIX}/bot{gone['bot_token']}/getMe").json()["description"],
         "Bot Token 无效或对应 Bot 已删除")
    api_reset()
    t.eq("自检结束清空注入", _api._configured, None)
    db.close()


# --------------------------------------------------------------------------- 11
def group_web_admin(test: SelfTest, h: Harness) -> None:
    """Web 管理后台的 HTTP 面：鉴权、页面装配、Bot 全生命周期与冷备，全部走真实路由。"""
    t = test
    from fastapi.testclient import TestClient

    admin = h.stack(tag="admin")
    c, _ = h.client(admin)
    a = h.auth()
    api = API_PREFIX

    unauth = c.get(f"{api}/session")
    t.eq("未鉴权访问管理台被拒", unauth.status_code, 401)
    t.eq("401 走 detail 包裹", sorted(unauth.json()), ["detail"])
    t.eq("detail 内是错误封套", sorted(unauth.json()["detail"]), ["description", "error_code", "ok"])
    t.eq("401 提示 token 变量名", unauth.json()["detail"]["description"], "缺少或错误的 STUDIO_ADMIN_TOKEN")
    t.eq("401 声明鉴权头", unauth.headers.get("www-authenticate"), "X-Studio-Token")
    t.eq("错误 token 同样被拒", c.get(f"{api}/session", headers={"X-Studio-Token": "nope"}).status_code, 401)
    t.eq("空 token 被拒", c.get(f"{api}/session", headers={"X-Studio-Token": ""}).status_code, 401)
    t.eq("请求头方式通过", c.get(f"{api}/session", headers=a).status_code, 200)
    t.eq("Bearer 方式通过",
         c.get(f"{api}/session", headers={"Authorization": "Bearer self-test-token"}).json()["authenticated"], True)
    t.eq("查询串方式通过", c.get(f"{api}/session", params={"token": "self-test-token"}).status_code, 200)
    t.eq("Cookie 方式通过",
         c.get(f"{api}/session", cookies={TOKEN_COOKIE: "self-test-token"}).status_code, 200)
    t.eq("大小写不敏感的 Bearer",
         c.get(f"{api}/session", headers={"Authorization": "bearer self-test-token"}).status_code, 200)
    t.eq("错误 scheme 不算 Bearer",
         c.get(f"{api}/session", headers={"Authorization": "Basic self-test-token"}).status_code, 401)

    health = c.get("/healthz").json()
    t.eq("健康检查无需鉴权", health["app"], APP_NAME)
    t.eq("版本号可读", health["version"], APP_VERSION)
    t.eq("健康检查声明回环绑定", health["loopback_only"], True)
    t.eq("健康检查给出语种", health["locale"], "en")
    t.eq("未启动时运行中 Bot 为 0", health["bots"], 0)

    page = c.get("/")
    t.eq("管理台页面 200", page.status_code, 200)
    t.contains("页面是 HTML", page.headers["content-type"], "text/html")
    t.check("目录标记已被替换", CATALOG_MARKER not in page.text, "标记仍在")
    t.check("页面内嵌了词条目录", '"fallback":"en"' in page.text, page.text[:120])
    t.check("内嵌目录含全部 18 语种", all(f'"{lc}"' in page.text for lc in LOCALES), "缺语种")
    t.eq("产品官网可访问", c.get("/site").status_code, 200)
    t.eq("官网带 index.html 路径", c.get("/site/index.html").status_code, 200)
    t.check("官网同样注入目录", CATALOG_MARKER not in c.get("/site").text)
    raw = c.get("/static/index.html")
    t.eq("静态目录直接可取", raw.status_code, 200)
    t.check("磁盘模板保留标记（无构建产物）", CATALOG_MARKER in raw.text, "标记丢失")
    t.check("模板文件与仓库同源", len(raw.content) == (STATIC_DIR / "index.html").stat().st_size,
            f"{len(raw.content)} vs {(STATIC_DIR / 'index.html').stat().st_size}")
    t.check("官网文件在仓库根 site/ 下", (SITE_DIR / "index.html").is_file(), str(SITE_DIR))

    session = c.get(f"{api}/session", headers=a).json()
    t.eq("会话返回全部语种", session["locales"], list(LOCALES))
    t.eq("会话词条数", len(session["strings"]), len(admin_strings("en")))
    t.eq("会话目录自检无问题", session["catalog_problems"], [])
    t.eq("会话版本号", session["version"], APP_VERSION)
    t.eq("会话语种跟随查询串", c.get(f"{api}/session", headers=a, params={"locale": "ru"}).json()["locale"], "ru")
    t.eq("非法语种回退默认", c.get(f"{api}/session", headers=a, params={"locale": "ko"}).json()["locale"], "en")
    t.eq("Accept-Language 参与协商",
         c.get(f"{api}/session", headers={**a, "Accept-Language": "de-DE,de;q=0.9"}).json()["locale"], "de")
    t.eq("无法识别的浏览器语言回退 en",
         c.get(f"{api}/session", headers={**a, "Accept-Language": "ko-KR"}).json()["locale"], "en")

    payload = c.get("/api/i18n/payload").json()
    t.eq("payload 六段词条齐全", sorted(payload), ["admin", "fallback", "labels", "locales", "ok", "site", "welcome"])
    t.eq("payload 语种顺序与后端一致", payload["locales"], list(LOCALES))
    t.eq("payload 每语种都有后台词条", len({k for k in payload["admin"]}), len(LOCALES))
    t.eq("payload 欢迎语覆盖 18 语种", len(payload["welcome"]), len(LOCALES))
    t.eq("payload 语言菜单", len(payload["labels"]), len(LOCALES))
    t.eq("payload 回退语种", payload["fallback"], FALLBACK_LOCALE)
    thai = c.get("/api/i18n", params={"locale": "th"}).json()
    t.eq("按需接口返回指定语种", thai["locale"], "th")
    t.eq("按需接口返回该语种词条", len(thai["admin"]), len(admin_strings("th")))
    t.contains("欢迎语模板保留占位符", thai["welcome"], "{bot_name}")

    parity = c.get(f"{api}/i18n/parity", headers=a).json()
    t.eq("对齐接口列出 18 语种", parity["locales"], list(LOCALES))
    t.eq("对齐接口无问题", parity["problems"], [])
    t.check("后台词条全部对齐", all(v["aligned"] for v in parity["parity"]["admin"].values()),
            str(parity["parity"]["admin"]))
    t.check("官网词条全部对齐", all(v["aligned"] for v in parity["parity"]["site"].values()),
            str(parity["parity"]["site"]))

    config = c.get(f"{api}/config", headers=a).json()
    t.eq("对齐报告逐语种", len(parity["parity"]["admin"]), len(LOCALES))
    t.eq("配置页只说 token 是否配置", config["token_configured"], True)
    t.check("配置页不回显 token 本体", "self-test-token" not in json.dumps(config, ensure_ascii=False),
            json.dumps(config, ensure_ascii=False)[:200])
    t.eq("配置页绑定地址是回环", config["host"], "127.0.0.1")
    t.eq("配置页声明仅回环", config["loopback_only"], True)
    t.eq("配置页允许 LAN 默认关闭", config["allow_lan"], False)
    t.eq("配置页权限告警为空", config["permission_warnings"], [])
    t.check("配置页给出示例端口区间", config["port"] == 8090, str(config["port"]))

    over = c.get(f"{api}/overview", headers=a).json()
    t.eq("总览统计 Bot 数", over["bots"]["total"], 0)
    t.eq("总览运行中数量", over["running"], 0)
    t.eq("总览消息计数是空表", over["messages"]["breakdown"], {})
    t.check("总览带 CLI 路径", over["runtime"]["cli_binary"].endswith("popopx-cli-fake"), over["runtime"]["cli_binary"])
    t.eq("总览端口区间来自配置", (over["runtime"]["port_base"], over["runtime"]["port_max"]), (5350, 5399))

    t.eq("空名单无 Bot", c.get(f"{api}/bots", headers=a).json()["bots"], [])
    t.eq("建 Bot 缺名字 400", c.post(f"{api}/bots", headers=a, json={}).json()["description"], "name 不能为空")
    bad_locale = c.post(f"{api}/bots", headers=a, json={"name": "nope1", "default_locale": "ko"})
    t.eq("不支持的语种直接拒绝", (bad_locale.status_code, bad_locale.json()["error_code"]), (400, 400))
    t.contains("拒绝原因点名语种", bad_locale.json()["description"], "'ko'")
    ugly = c.post(f"{api}/bots", headers=a, json={"name": "BAD NAME", "start": False})
    t.contains("非法名字被账本挡下", ugly.json()["description"], "仅允许小写字母")
    made = c.post(f"{api}/bots", headers=a, json={"name": "webbot", "default_locale": "de", "start": False})
    t.eq("草稿 Bot 创建成功", made.status_code, 200)
    bot = made.json()["bot"]
    bid = str(bot["id"])
    t.eq("未启动时状态为草稿", bot["status"], "draft")
    t.check("端口取区间内第一个空闲口",
            all(port_busy(p) for p in range(admin.settings.ws_port_base, int(bot["port"]))),
            f"{admin.settings.ws_port_base}->{bot['port']}")
    t.check("分配的端口落在配置区间内",
            admin.settings.ws_port_base <= int(bot["port"]) <= admin.settings.ws_port_max, str(bot["port"]))
    t.check("欢迎语按 Bot 语种本地化", bot["welcome_text"].startswith("Willkommen"), bot["welcome_text"])
    t.contains("本地化欢迎语保留 Bot 名", bot["welcome_text"], "webbot")
    t.eq("i18n 回执指出所用语种", made.json()["i18n"]["locale"], "de")
    t.eq("重复名字被拒",
         c.post(f"{api}/bots", headers=a, json={"name": "webbot", "start": False}).json()["ok"], False)
    t.eq("详情能查到", c.get(f"{api}/bots/{bid}", headers=a).json()["bot"]["name"], "webbot")
    detail = c.get(f"{api}/bots/{bid}", headers=a).json()["bot"]
    t.eq("详情给规则条数", (detail["reply_rules"], detail["routing_rules"]), (0, 0))
    t.eq("详情含消息统计", sorted(detail["messages"]), ["breakdown", "incoming", "outgoing", "top_plugins"])
    t.eq("详情含运行时状态", detail["runtime"]["state"], "stopped")
    t.eq("未初始化时二维码为空", detail["qr_png"], "")
    t.eq("未知 Bot 返回 404",
         c.get(f"{api}/bots/bot_absent", headers=a).json()["description"], "Bot bot_absent 不存在")
    t.eq("改显示名",
         c.patch(f"{api}/bots/{bid}", headers=a, json={"display_name": "在线客服"}).json()["bot"]["display_name"],
         "在线客服")
    t.eq("PATCH 非法语种被拒",
         c.patch(f"{api}/bots/{bid}", headers=a, json={"default_locale": "ko"}).status_code, 400)
    empty_patch = c.patch(f"{api}/bots/{bid}", headers=a, json={})
    t.eq("PATCH 空更新被拒", empty_patch.status_code, 400)
    t.contains("PATCH 列出允许字段", empty_patch.json()["description"], "welcome_text")
    greeted = c.patch(f"{api}/bots/{bid}", headers=a, json={"welcome_text": "你好 {bot_name}"}).json()
    t.eq("PATCH 欢迎语走 CLI 设置结构", greeted["greeting"]["settings"]["autoReply"]["text"], "你好 在线客服")
    t.eq("未连接时设置只落库不下发", greeted["greeting"]["applied"], False)
    t.eq("PATCH 后返回的是 Bot 记录", greeted["bot"]["welcome_text"], "你好 在线客服")

    t.eq("未启动时二维码返回 409", c.get(f"{api}/bots/{bid}/qrcode", headers=a).json()["error_code"], 409)
    t.eq("未启动时 PNG 也是 409", c.get(f"{api}/bots/{bid}/qr.png", headers=a).json()["error_code"], 409)
    t.eq("未启动时发送失败", c.post(f"{api}/bots/{bid}/send", headers=a,
                                    json={"chat_ref": "@7", "text": "hi"}).json()["ok"], False)
    t.contains("未启动时提示先启动", c.get(f"{api}/bots/{bid}/contacts", headers=a).json()["description"], "未连接 CLI 控制通道")
    t.eq("发送缺参数 400",
         c.post(f"{api}/bots/{bid}/send", headers=a, json={"text": "hi"}).json()["description"],
         "chat_ref 与 text 均为必填")

    rule = c.post(f"{api}/bots/{bid}/rules", headers=a,
                  json={"trigger_type": "exact", "pattern": "价格", "reply_text": "100 元"})
    t.eq("后台建规则成功", rule.status_code, 200)
    t.eq("规则入库回显关键词", rule.json()["rule"]["pattern"], "价格")
    t.eq("缺 pattern 被拒",
         c.post(f"{api}/bots/{bid}/rules", headers=a, json={"trigger_type": "exact"}).json()["description"],
         "exact 规则必须提供 pattern")
    listed = c.get(f"{api}/bots/{bid}/rules", headers=a).json()
    t.eq("规则列表含新规则", len(listed["rules"]), 1)
    t.eq("内置指令恒在清单里", listed["commands"], ["/help", "/menu", "/start"])
    t.eq("规则条目字段", sorted(listed["rules"][0]),
         sorted(rule.json()["rule"]))
    prev = c.post(f"{api}/rules/preview", headers=a, json={"bot_id": bid, "text": "价格"}).json()
    t.eq("预览命中规则", (prev["matched"], prev["reply"]), (True, "100 元"))
    t.eq("预览说明触发类型", prev["trigger_type"], "exact")
    t.eq("预览标记将会发送", prev["will_send"], True)
    t.eq("预览未被抑制", prev["suppressed_by"], "")
    t.eq("预览给出渲染上下文", sorted(prev["context"]),
         ["bot_name", "chat_ref", "chat_type", "date", "datetime", "sender", "sender_name", "text", "time", "weekday"])
    t.eq("预览回执命中规则号", prev["rule_id"], rule.json()["rule"]["id"])
    t.eq("预览状态字", prev["status"], "ok")
    t.eq("删除规则", c.delete(f"{api}/rules/{rule.json()['rule']['id']}", headers=a).json()["deleted"], 1)
    t.eq("删除后再列表为空", len(c.get(f"{api}/bots/{bid}/rules", headers=a).json()["rules"]), 0)
    t.eq("删除不存在的规则 404",
         c.delete(f"{api}/rules/99999", headers=a).json()["description"], "规则 99999 不存在")

    route = c.post(f"{api}/bots/{bid}/routing", headers=a,
                   json={"name": "转人工", "keywords": ["人工"], "target_type": "group", "target_ref": "#42"})
    t.eq("后台建路由成功", route.status_code, 200)
    t.eq("路由关键词存为列表", route.json()["rule"]["keywords"], ["人工"])
    t.eq("路由规则入库带目标", route.json()["rule"]["target_ref"], "#42")
    rprev = c.post(f"{api}/routing/preview", headers=a,
                   json={"bot_id": bid, "text": "我要人工", "chat_type": "direct", "chat_ref": "@7"}).json()
    t.eq("路由预览命中", rprev["matched_rules"], [int(route.json()["rule"]["id"])])
    t.eq("路由预览给出转发包", len(rprev["plans"]), 1)
    t.eq("路由预览标记将转发", rprev["forwarded"], True)
    t.eq("路由预览状态", rprev["status"], "forwarded")
    t.eq("路由预览目标群组", rprev["plans"][0]["target_ref"], "#42")
    t.eq("转发包字段齐全", sorted(rprev["plans"][0]),
         ["quote", "quoted_ref", "reason", "rule_id", "target_ref", "target_type", "text", "ticket_id"])
    t.check("预览即分配工单号", rprev["plans"][0]["ticket_id"].startswith("#T"), rprev["plans"][0]["ticket_id"])
    t.contains("回执文案带工单号", rprev["reply_to_sender"], rprev["plans"][0]["ticket_id"])
    routing_view = c.get(f"{api}/bots/{bid}/routing", headers=a).json()
    t.eq("路由列表可读", len(routing_view["rules"]), 1)
    t.eq("已知群组从日志学习", routing_view["known_groups"], [])
    t.eq("工单登记在路由视图里", len(routing_view["tickets"]), 1)
    t.eq("工单视图字段", sorted(routing_view["tickets"][0]),
         ["answers", "bot_id", "chat_ref", "group_ref", "opened_at", "sender", "sender_name", "summary",
          "ticket_id", "token"])
    t.eq("工单来源会话", routing_view["tickets"][0]["chat_ref"], "@7")
    t.eq("删除路由", c.delete(f"{api}/routing/{route.json()['rule']['id']}", headers=a).json()["deleted"], 1)
    t.eq("删除不存在的路由 404",
         c.delete(f"{api}/routing/99999", headers=a).json()["description"], "路由规则 99999 不存在")

    plug = c.get(f"{api}/plugins", headers=a).json()
    t.eq("未托管启动时插件尚未装载", plug["plugins"], [])
    t.eq("插件派发计数可读", plug["dispatches"], 0)
    t.eq("未装载时PATCH 插件配置报未知插件",
         c.patch(f"{api}/plugins/auto_reply", headers=a, json={"enabled": True}).json()["description"],
         "未知插件 'auto_reply'")
    logs = c.get(f"{api}/logs", headers=a).json()
    t.eq("日志接口含统计块", sorted(logs), ["logs", "ok", "stats"])
    t.check("失败发送进入台账", any(row["status"] == "error" for row in logs["logs"]),
            json.dumps(logs["logs"][:2], ensure_ascii=False))
    t.eq("日志按时间倒序", [row["id"] for row in logs["logs"]], sorted((row["id"] for row in logs["logs"]), reverse=True))
    t.eq("日志计数与统计一致", logs["stats"]["outgoing"], len([row for row in logs["logs"] if row["direction"] == "out"]))
    ups = c.get(f"{api}/updates", headers=a).json()
    t.eq("更新缓冲为空", (ups["updates"], ups["buffered"]), ([], 0))
    t.eq("备份目录初始为空", c.get(f"{api}/backups", headers=a).json()["backups"], [])
    t.eq("缺 bundle 的还原被拒",
         c.post(f"{api}/backup/import", headers=a, json={}).json()["description"], "bundle 或 base64 必填其一")
    hook_missing = c.post(f"{HOOK_PREFIX}/{bid}/secret123", json={"text": "x"}).json()
    t.eq("未知 webhook 密钥返回 404", hook_missing["error_code"], 404)
    t.eq("未装载插件时钩子无人认领", hook_missing["result"]["status"], "no_plugin")
    t.eq("开放 API 与后台同源挂载",
         c.get(f"{OPEN_API_PREFIX}/getMe").json()["error_code"], 401)
    t.eq("管理台路由不存在返回 404", c.get(f"{api}/nope", headers=a).json()["detail"], "Not Found")
    t.eq("坏 JSON 请求体 400",
         c.post(f"{api}/bots", content=b"{oops",
                headers={**a, "Content-Type": "application/json"}).json()["detail"]["ok"], False)
    t.contains("坏 JSON 说明原因",
               c.post(f"{api}/bots", content=b"{oops",
                      headers={**a, "Content-Type": "application/json"}).json()["detail"]["description"],
               "不是合法 JSON")
    t.eq("标量 JSON 请求体被拒",
         c.post(f"{api}/bots", content=b'"just a string"',
                headers={**a, "Content-Type": "application/json"}).json()["detail"]["description"],
         "请求体必须是 JSON 对象")


# --------------------------------------------------------------------------- 13
def group_i18n(test: SelfTest, h: Harness) -> None:
    """18 语种目录完整性、语言检测与协商、页面词条覆盖、默认欢迎语填充。"""
    t = test
    en_admin = admin_strings("en")
    en_site = site_strings("en")

    t.eq("语种集合逐字对齐 iOS 客户端", LOCALES,
         ("en", "zh-Hans", "zh-Hant", "ja", "bg", "cs", "de", "es", "fi", "fr",
          "hu", "it", "nl", "pl", "ru", "th", "tr", "uk"))
    t.eq("语种总数 18", len(LOCALES), 18)
    t.eq("语种不重复", len(set(LOCALES)), 18)
    t.eq("基准语种是英文", FALLBACK_LOCALE, "en")
    t.check("基准语种在集合内", FALLBACK_LOCALE in LOCALES, FALLBACK_LOCALE)
    t.eq("每个语种都有本地名称", sorted(LOCALE_LABELS), sorted(LOCALES))
    t.eq("本地名称均非空", [c for c, label in LOCALE_LABELS.items() if not label.strip()], [])
    t.eq("简体中文标签", LOCALE_LABELS["zh-Hans"], "简体中文")
    t.eq("繁体中文标签", LOCALE_LABELS["zh-Hant"], "繁體中文")
    t.eq("泰文标签用泰文书写", LOCALE_LABELS["th"], "ไทย")

    for raw, want in (("zh", "zh-Hans"), ("zh_CN", "zh-Hans"), ("zh-Hant-TW", "zh-Hant"),
                      ("zh-hk", "zh-Hant"), ("nl-BE", "nl"), ("de-DE", "de"), ("EN", "en"),
                      ("ja-JP", "ja"), ("fr_fr", "fr"), ("pt", ""), ("ko", ""), ("xx-YY", ""),
                      ("", ""), (None, "")):
        t.eq(f"标签 {raw!r} 归一化", normalize_locale(raw), want)
    t.eq("未收录语种判为不支持", [is_supported(x) for x in ("pt", "ko", "zh")], [False, False, True])
    t.eq("Accept-Language 按权重排序",
         parse_accept_language("de-DE,de;q=0.9,en;q=0.8,fr;q=0.5"), ["de-DE", "de", "en", "fr"])
    t.eq("Accept-Language 保留原始顺序",
         parse_accept_language("zh-CN,zh;q=0.9,en;q=0.8"), ["zh-CN", "zh", "en"])
    t.eq("空请求头解析为空列表", parse_accept_language(""), [])
    t.eq("非法权重不影响解析", parse_accept_language("en;q=abc,fr"), ["fr", "en"])
    t.eq("检测按候选顺序取第一个可用语种", detect_locale(["ko", "nl", "ja"]), "nl")
    t.eq("检测跳过不支持的候选", detect_locale(["pt;q=0.9", "hu"]), "hu")
    t.eq("检测接受嵌套候选", detect_locale([[], ["pt", "th"]]), "th")
    t.eq("无可用候选时回退基准语种", detect_locale([]), FALLBACK_LOCALE)
    menu = language_menu("ja")
    t.eq("语言菜单含 18 项", len(menu), 18)
    t.eq("语言菜单只有一项选中", [row["locale"] for row in menu if row["selected"]], ["ja"])
    t.eq("语言菜单首项", menu[0], {"locale": "en", "label": "English", "selected": False})

    t.eq("目录只有后台与官网两套", sorted(CATALOGS), ["admin", "site"])
    t.eq("后台目录覆盖 18 语种", sorted(CATALOGS["admin"]), sorted(LOCALES))
    t.eq("官网目录覆盖 18 语种", sorted(CATALOGS["site"]), sorted(LOCALES))
    t.eq("后台英文基准词条数", len(en_admin), 99)
    t.eq("官网英文基准词条数", len(en_site), 21)
    for locale in LOCALES:
        t.eq(f"{locale} 后台无缺失词条", missing_keys(locale, "admin"), [])
        t.eq(f"{locale} 后台无多余词条", extra_keys(locale, "admin"), [])
        t.eq(f"{locale} 后台占位符对齐", placeholder_drift(locale, "admin"), [])
        t.eq(f"{locale} 官网无缺失词条", missing_keys(locale, "site"), [])
        t.eq(f"{locale} 官网无多余词条", extra_keys(locale, "site"), [])
        t.eq(f"{locale} 官网占位符对齐", placeholder_drift(locale, "site"), [])
    report = parity_report()
    t.eq("对齐报告含两套目录", sorted(report), ["admin", "site"])
    t.eq("对齐报告逐语种", sorted(report["admin"]), sorted(LOCALES))
    t.check("18 语种全部与 en 逐条对齐",
            all(row["aligned"] for table in report.values() for row in table.values()),
            json.dumps({k: [l for l, r in v.items() if not r["aligned"]] for k, v in report.items()},
                       ensure_ascii=False))
    t.eq("完整性门禁无违规", assert_catalogs(), [])
    t.eq("词条值不含空字符串",
         [(cat, loc, key) for cat in ("admin", "site") for loc in LOCALES
          for key, value in CATALOGS[cat][loc].items() if not str(value).strip()], [])
    t.eq("界面词条不留待插值的占位符", [key for key, value in en_admin.items() if placeholders(value)], [])
    for locale in LOCALES:
        if locale == FALLBACK_LOCALE:
            continue
        admin_diff = sum(1 for key, value in CATALOGS["admin"][locale].items() if value != en_admin[key])
        site_diff = sum(1 for key, value in CATALOGS["site"][locale].items() if value != en_site[key])
        t.check(f"{locale} 后台确有本地化译文", admin_diff >= 40, str(admin_diff))
        t.check(f"{locale} 官网确有本地化译文", site_diff >= 15, str(site_diff))
    t.eq("缺失键回退为键名本身", i18n_t("admin", "de", "no_such_key"), "no_such_key")
    t.eq("未知语种取词回退英文", i18n_t("admin", "ko", "action_cancel"), en_admin["action_cancel"])
    mutable = admin_strings("en")
    mutable["action_cancel"] = "被改坏了"
    t.eq("取词返回副本，不污染目录", admin_strings("en")["action_cancel"], "Cancel")

    t.eq("欢迎语目录覆盖 18 语种", sorted(catalog_payload()["welcome"]), sorted(LOCALES))
    t.eq("欢迎语占位符约定", WELCOME_PLACEHOLDERS, ("bot_name",))
    for locale in LOCALES:
        t.eq(f"{locale} 欢迎语占位符齐备", placeholders(welcome_template(locale)), {"bot_name"})
    t.eq("未知语种欢迎语回退英文", welcome_template("ko"), welcome_template("en"))
    t.eq("日文欢迎语渲染", render_welcome("ja", bot_name="小助手"),
         "小助手 へようこそ。ご用件をお知らせください。担当者から折り返しご連絡します。")
    t.eq("泰文欢迎语渲染", render_welcome("th", bot_name="store"),
         "ยินดีต้อนรับสู่ store แจ้งคำถามไว้ที่นี่ ผู้ให้บริการจะตอบกลับโดยเร็ว")
    t.eq("空机器人名也不留占位符", "{" in render_welcome("en", bot_name=""), False)
    t.eq("渲染不留多余空格", "  " in render_welcome("ru", bot_name="bot"), False)
    t.eq("自定义文案同样展开占位符", fill_placeholders("你好 {bot_name}", bot_name="在线客服"), "你好 在线客服")
    t.eq("未知占位符被清理", fill_placeholders("你好 {nonsense}", bot_name="bot"), "你好")

    c, stack = h.client(STUDIO_LOCALE="ru")
    a = h.auth()
    api = c.get("/api/i18n").json()
    t.eq("i18n 接口字段齐全", sorted(api),
         ["admin", "fallback", "labels", "locale", "locales", "ok", "site", "welcome"])
    t.eq("无请求头时跟随服务端默认语种", api["locale"], "ru")
    t.eq("接口回退语种", api["fallback"], "en")
    t.eq("接口列出 18 语种", api["locales"], list(LOCALES))
    t.eq("接口语言菜单完整", len(api["labels"]), 18)
    t.eq("接口后台词条按语种下发", sorted(api["admin"]), sorted(admin_strings("ru")))
    t.eq("接口官网词条按语种下发", sorted(api["site"]), sorted(site_strings("ru")))
    t.eq("接口欢迎语是模板字符串", api["welcome"], welcome_template("ru"))
    t.eq("服务端默认语种写进健康检查", c.get("/healthz").json()["locale"], "ru")
    for locale in ("ja", "zh-Hant", "th", "de", "uk"):
        forced = c.get("/api/i18n", params={"locale": locale}).json()
        t.eq(f"?locale={locale} 命中该语种欢迎语", forced["welcome"], welcome_template(locale))
        t.eq(f"?locale={locale} 命中该语种词条", sorted(forced["admin"]), sorted(admin_strings(locale)))
    t.eq("查询参数优先于请求头",
         c.get("/api/i18n", params={"locale": "ja"}, headers={"Accept-Language": "de"}).json()["locale"], "ja")
    t.eq("不支持的查询语种回退服务端默认",
         c.get("/api/i18n", params={"locale": "ko"}).json()["locale"], "ru")
    for header, want in (("de-DE,de;q=0.9,en;q=0.8", "de"), ("ru,en;q=0.5", "ru"),
                         ("ko,pt", "ru"), ("zh-CN,zh;q=0.9", "zh-Hans"), ("fr-CA,fr;q=0.9", "fr")):
        t.eq(f"Accept-Language {header} 协商结果",
             c.get("/api/i18n", headers={"Accept-Language": header}).json()["locale"], want)
    t.eq("全量目录接口与后端同源", c.get("/api/i18n/payload").json(), dict(catalog_payload(), ok=True))

    home_raw = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    site_raw = (SITE_DIR / "index.html").read_text(encoding="utf-8")
    payload_json = json.dumps(catalog_payload(), ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    t.eq("后台模板只有一个拼接标记", home_raw.count(CATALOG_MARKER), 1)
    t.eq("官网模板只有一个拼接标记", site_raw.count(CATALOG_MARKER), 1)
    t.eq("静态目录原样返回模板", c.get("/static/index.html").text.count(CATALOG_MARKER), 1)
    for name, page, keys, raw in (("后台", c.get("/").text, sorted(en_admin), home_raw),
                                  ("官网", c.get("/site").text, sorted(en_site), site_raw)):
        t.check(f"{name}页响应不含标记", CATALOG_MARKER not in page, name)
        found = re.search(r'<script type="application/json" id="i18n-catalog">(.*?)</script>', page, re.S)
        t.check(f"{name}页内嵌目录脚本存在", found is not None, name)
        if found is not None:
            t.eq(f"{name}页内嵌目录与后端逐字一致", json.loads(found.group(1)), catalog_payload())
        t.eq(f"{name}页响应等于模板加目录",
             len(page.encode("utf-8")), len(raw.replace(CATALOG_MARKER, payload_json).encode("utf-8")))
    t.eq("后台页 data-i18n 与目录键集完全一致",
         sorted(set(re.findall(r'data-i18n="([a-z0-9_]+)"', home_raw))), sorted(en_admin))
    t.eq("官网页 data-i18n 与目录键集完全一致",
         sorted(set(re.findall(r'data-i18n="([a-z0-9_]+)"', site_raw))), sorted(en_site))
    for name, page in (("后台", home_raw), ("官网", site_raw)):
        t.check(f"{name}页记住用户选择的语种", "localStorage" in page, name)
        t.check(f"{name}页读取浏览器语言列表", "navigator.languages" in page, name)
        t.check(f"{name}页动态生成语种选项", 'createElement("option")' in page, name)
        t.check(f"{name}页有语言切换器", "<select" in page, name)
        t.check(f"{name}页切换语种不刷新页面", "replaceState" in page or "location.reload" not in page, name)

    bots: Dict[str, Dict[str, Any]] = {}
    for locale in LOCALES:
        name = "i18n" + re.sub(r"[^a-z0-9]", "", locale.lower()).ljust(5, "x")
        made = c.post(f"{API_PREFIX}/bots", headers=a,
                      json={"name": name, "start": False, "default_locale": locale}).json()
        bots[locale] = made
        t.eq(f"{locale} 记录该语种", made["i18n"]["locale"], locale)
        t.eq(f"{locale} 欢迎语按该语种填充", made["i18n"]["welcome"], render_welcome(locale, bot_name=name))
    t.eq("18 语种欢迎语互不相同", len({row["i18n"]["welcome"] for row in bots.values()}), 18)
    inherited = c.post(f"{API_PREFIX}/bots", headers=a, json={"name": "i18ninherit", "start": False}).json()
    t.eq("未指定语种时继承服务端默认", inherited["i18n"]["locale"], "ru")
    t.eq("继承的欢迎语是俄文模板", inherited["i18n"]["welcome"],
         render_welcome("ru", bot_name="i18ninherit"))
    blank = c.post(f"{API_PREFIX}/bots", headers=a,
                   json={"name": "i18nblank", "start": False, "welcome_text": "   ", "default_locale": "ja"}).json()
    t.eq("纯空格欢迎语改填该语种默认模板", blank["i18n"]["welcome"], render_welcome("ja", bot_name="i18nblank"))
    custom = c.post(f"{API_PREFIX}/bots", headers=a,
                    json={"name": "i18ncustom", "start": False, "welcome_text": "只有一句", "default_locale": "ja"}).json()
    t.eq("自定义欢迎语原样保留", custom["i18n"]["welcome"], "只有一句")
    bad_locale = c.post(f"{API_PREFIX}/bots", headers=a,
                        json={"name": "i18nbad", "start": False, "default_locale": "ko"}).json()
    t.eq("建 Bot 拒绝不支持的语种", (bad_locale["ok"], bad_locale["error_code"]), (False, 400))
    t.contains("拒绝原因点名语种", bad_locale["description"], "不支持的语种 'ko'")

    target = str(inherited["bot"]["id"])
    patched = c.patch(f"{API_PREFIX}/bots/{target}", headers=a, json={"default_locale": "th"}).json()
    t.eq("改语种不覆盖已写入的欢迎语", patched["bot"]["welcome_text"], render_welcome("ru", bot_name="i18ninherit"))
    t.eq("改语种写入记录", patched["bot"]["default_locale"], "th")
    reset = c.patch(f"{API_PREFIX}/bots/{target}", headers=a, json={"welcome_text": ""}).json()
    t.eq("清空欢迎语恢复新语种默认", reset["bot"]["welcome_text"], render_welcome("th", bot_name="i18ninherit"))
    t.eq("恢复的默认文案同时写进 CLI 设置",
         reset["greeting"]["settings"]["autoReply"]["text"], render_welcome("th", bot_name="i18ninherit"))
    t.eq("未连接 CLI 时设置只落库不下发", reset["greeting"]["applied"], False)
    t.eq("再传空格也视为恢复默认",
         c.patch(f"{API_PREFIX}/bots/{target}", headers=a, json={"welcome_text": "  "}).json()["bot"]["welcome_text"],
         render_welcome("th", bot_name="i18ninherit"))
    named = c.patch(f"{API_PREFIX}/bots/{target}", headers=a,
                    json={"welcome_text": "こんにちは {bot_name}"}).json()
    t.eq("自定义文案里的占位符被展开", named["bot"]["welcome_text"], "こんにちは i18ninherit")
    t.eq("PATCH 拒绝不支持的语种",
         c.patch(f"{API_PREFIX}/bots/{target}", headers=a, json={"default_locale": "xx"}).json()["description"],
         "不支持的语种 'xx'")


def group_web_live(test: SelfTest, h: Harness) -> None:
    """真实托管启动（spawn=False）：Bot 全生命周期、冷备往返与插件配置。"""
    from fastapi.testclient import TestClient

    t = test
    stack = h.stack(tag="live")
    with TestClient(create_app(stack=stack, managed=True, spawn=False)) as c:
        a = h.auth()
        api = API_PREFIX
        listed = c.get(f"{api}/plugins", headers=a).json()
        ids = sorted(p["plugin_id"] for p in listed["plugins"])
        t.eq("托管启动后内置插件全部装载", ids, list(BUNDLED_IDS))
        field_keys = {p["plugin_id"]: [f["key"] for f in p["config_fields"]] for p in listed["plugins"]}
        t.check("插件配置字段随元数据下发", len(field_keys["webhook_relay"]) >= 3, str(field_keys))
        t.eq("未启用时 enabled 为假",
             [p["enabled"] for p in listed["plugins"] if p["plugin_id"] == "auto_reply"], [False])
        patched = c.patch(f"{api}/plugins/auto_reply", headers=a,
                          json={"enabled": True, "config": {"fallback_text": "稍等"}}).json()
        t.eq("后台可启用插件", patched["plugin"]["enabled"], True)
        t.eq("启用后配置写入库", patched["plugin"]["config"]["fallback_text"], "稍等")
        t.eq("插件处理计数入账", listed["failures"], {})

        made = c.post(f"{api}/bots", headers=a, json={"name": "livebot", "start": True}).json()
        bot = made["bot"]
        bid = str(bot["id"])
        t.eq("建 Bot 并直接启动", bot["status"], "running")
        t.eq("启动后拿到永久链接", bot["permanent_link"], "popopx:/fakepermanentlink")
        t.eq("自动接单默认开启", bot["auto_accept"], 1)
        t.eq("隐身默认不自动接单", bot["accept_incognito"], 0)
        t.eq("欢迎语按默认语种填充", bool(bot["welcome_text"]), True)
        runtime = c.get(f"{api}/bots", headers=a).json()["runtime"]["bots"]
        t.eq("运行时报告进程存活", runtime[0]["running"], True)
        t.eq("运行时报告 WS 已连接", runtime[0]["connected"], True)
        t.eq("运行时报告已开通", runtime[0]["provisioned"], True)
        t.check("运行时报告有 pid", int(runtime[0]["pid"]) > 0, str(runtime[0]))
        t.eq("重启返回新状态",
             c.post(f"{api}/bots/{bid}/restart", headers=a, json={}).json()["bot"]["state"], "running")
        t.eq("停止生效", c.post(f"{api}/bots/{bid}/stop", headers=a, json={}).json()["bot"]["state"], "stopped")
        t.eq("再启动", c.post(f"{api}/bots/{bid}/start", headers=a, json={}).json()["bot"]["state"], "running")

        q = c.get(f"{api}/bots/{bid}/qrcode", headers=a).json()
        t.check("二维码链接是隐私封装", q["link"].startswith(INVITE_LINK_PREFIX), q["link"][:40])
        t.eq("二维码链接可解回永久链接", decode_invite_link(q["link"]), bot["permanent_link"])
        t.eq("二维码接口回带原始地址", q["raw_link"], bot["permanent_link"])
        t.eq("二维码接口标记 opaque", q["opaque"], True)
        t.eq("二维码是 PNG base64", q["data_url"][:22], "data:image/png;base64,")
        t.eq("二维码字节数与 sha 一致", len(q["sha256"]), 64)
        png = c.get(f"{api}/bots/{bid}/qr.png", headers=a)
        t.eq("PNG 直出", png.headers["content-type"], "image/png")
        t.eq("PNG 魔数正确", png.content[:4], b"\x89PNG")
        t.check("PNG 非空", len(png.content) > 500, str(len(png.content)))
        raw_png = c.get(f"{api}/bots/{bid}/qr.png", headers=a, params={"raw": "1"})
        t.eq("raw=1 仍是 PNG", raw_png.content[:4], b"\x89PNG")
        t.ne("raw=1 与默认二维码内容不同", raw_png.content, png.content)
        t.eq("send 送达", c.post(f"{api}/bots/{bid}/send", headers=a,
                                 json={"chat_ref": "@7", "text": "在的"}).json()["delivered"], True)
        t.eq("联系人来自 CLI", c.get(f"{api}/bots/{bid}/contacts", headers=a).json()["contacts"],
             [{"contactId": 7, "display_name": "小明"}])
        t.check("群组接口可读", "groups" in c.get(f"{api}/bots/{bid}/groups", headers=a).json())
        t.eq("缺名字的建群请求 400",
             c.post(f"{api}/bots/{bid}/groups", headers=a, json={}).json()["description"], "name 不能为空")
        t.eq("群链接缺 group_id 被拒",
             c.post(f"{api}/bots/{bid}/groups", headers=a,
                    json={"name": "g", "link_role": "member"}).json()["error_code"], 400)
        t.eq("群链接非法角色被拒",
             c.post(f"{api}/bots/{bid}/groups", headers=a,
                    json={"name": "g", "link_role": "admin", "group_id": "42"}).json()["ok"], False)

        plain = c.post(f"{api}/backup/export", headers=a, json={"bot_id": bid}).json()["bundle"]
        t.eq("明文冷备后缀", plain["bundle"].endswith(".botbundle"), True)
        t.eq("冷备未加密", plain["encrypted"], False)
        t.eq("冷备含文件清单", plain["files"], 2)
        t.eq("冷备 sha256 长度", len(plain["sha256"]), 64)
        t.eq("冷备落盘权限 0600", mode_of(Path(plain["bundle"])), SECURE_FILE_MODE)
        enc = c.post(f"{api}/backup/export", headers=a, json={"bot_id": bid, "passphrase": "pp-pp-pp"}).json()["bundle"]
        t.eq("口令冷备后缀加密", enc["bundle"].endswith(".botbundleenc"), True)
        t.eq("口令冷备标记加密", enc["encrypted"], True)
        listed_backups = c.get(f"{api}/backups", headers=a).json()["backups"]
        t.eq("备份目录列出两份", len(listed_backups), 2)
        t.eq("加密标记可读", sorted(row["encrypted"] for row in listed_backups), [False, True])
        blob = base64.b64encode(Path(plain["bundle"]).read_bytes()).decode()
        restored = c.post(f"{api}/backup/import", headers=a, json={"base64": blob, "bot_id": bid}).json()
        t.eq("冷备可回灌", restored["bot"]["verified"], True)
        t.check("回灌校验和是 64 位十六进制",
                re.match(r"^[0-9a-f]{64}$", str(restored["bot"]["payload_sha256"])) is not None,
                str(restored["bot"]))
        t.eq("回灌文件数", restored["bot"]["files"], 2)
        t.eq("回灌无跳过项", restored["bot"]["skipped"], [])
        bad_import = c.post(f"{api}/backup/import", headers=a, json={"base64": "!!!", "bot_id": bid}).json()
        t.eq("坏 base64 冷备还原失败", bad_import["error_code"], 502)
        t.contains("失败原因说明格式", bad_import["description"], "备份包格式无法识别")
        t.check("冷备还原不泄露 traceback", "Traceback" not in json.dumps(bad_import, ensure_ascii=False))

        after = c.get(f"{api}/logs", headers=a, params={"bot_id": bid, "limit": 20}).json()
        t.check("出站发送进入台账", any(row["direction"] == "out" for row in after["logs"]),
                json.dumps(after["logs"], ensure_ascii=False)[:200])
        t.eq("台账按 Bot 过滤", {row["bot_id"] for row in after["logs"]}, {bid})
        buffered = c.get(f"{api}/updates", headers=a).json()
        t.check("网关缓冲有事件", buffered["buffered"] >= 1, str(buffered["buffered"]))
        t.eq("删除并清理目录",
             c.delete(f"{api}/bots/{bid}", headers=a).json()["removed"], bid)
        t.eq("删除后运行时清空",
             c.get(f"{api}/bots", headers=a).json()["runtime"]["bots"], [])
        t.eq("软删除后详情仍可查但标记已删",
             c.get(f"{api}/bots/{bid}", headers=a).json()["bot"]["status"], "deleted")
        gone = c.get(f"{api}/bots/bot_nobody", headers=a)
        t.eq("未知 Bot 详情 404", gone.status_code, 404)
        t.eq("未知 Bot 说明原因", gone.json()["description"], "Bot bot_nobody 不存在")
        t.eq("健康检查回到零", c.get("/healthz").json()["bots"], 0)


TOOL_PATH = REPO / "official_tools" / "export_bot_bundle.py"
_TOOL: Optional[Any] = None


def load_bundle_tool() -> Any:
    """按文件路径加载官方冷备工具——它本来就是这样被独立调用的。"""
    global _TOOL
    if _TOOL is None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("popopx_export_bot_bundle", TOOL_PATH)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules["popopx_export_bot_bundle"] = module
        spec.loader.exec_module(module)
        _TOOL = module
    return _TOOL


def run_bundle_tool(
    args: Sequence[str], env: Dict[str, str], *, stdin: str = "", timeout: int = 180
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL_PATH), *[str(item) for item in args]],
        capture_output=True,
        text=True,
        input=stdin,
        env=env,
        cwd=str(REPO),
        timeout=timeout,
    )


async def bundle_fixture(stack: StudioStack) -> Dict[str, Any]:
    """给冷备工具准备一个「真跑过、有规则、有密钥文件」的 Bot 与一个软删除行。"""
    sup = stack.supervisor
    bot = await sup.create_bot("bundbot", display_name="冷备", default_locale="ru", start=True)
    bot_id = str(bot["id"])
    stack.db.upsert_reply_rule(bot_id, trigger_type="exact", pattern="/hi", reply_text="在的", name="r1")
    stack.db.upsert_reply_rule(bot_id, trigger_type="prefix", pattern="发票", reply_text="稍等", name="r2")
    stack.db.upsert_routing_rule(
        bot_id, name="route1", keywords=["发票"], target_type="group", target_ref="#42", template="转发 {text}"
    )
    stack.db.set_plugin_config("auto_reply", {"fallback_text": "兜底"}, bot_id=bot_id, enabled=True)
    paths = sup.paths_for(bot_id)
    marker = paths.cli_data / "marker.txt"
    marker.write_bytes(b"cold-key-material")
    os.chmod(marker, SECURE_FILE_MODE)
    ghost = await sup.create_bot("ghostbot", start=False)
    await sup.stop_bot(bot_id, reason="self-test")
    stack.db.delete_bot(str(ghost["id"]))
    return {
        "bot_id": bot_id,
        "ghost_id": str(ghost["id"]),
        "port": int(bot["port"]),
        "name": str(bot["name"]),
        "data_dir": str(stack.settings.data_dir),
        "cli_data": sorted(item.name for item in paths.cli_data.iterdir()),
    }


def group_bundle(test: SelfTest, h: Harness) -> None:
    """官方冷备工具：纯函数契约 + 真实子进程往返（导出/校验/迁移/篡改拒绝）。"""
    t = test
    tool = load_bundle_tool()
    bits = h.root / "toolbits"
    bits.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------- 常量与纯函数
    t.eq("工具文件真实存在", TOOL_PATH.is_file(), True)
    t.eq("冷备格式名与运行时一致", tool.BUNDLE_FORMAT, "popopx-bot-studio-bundle")
    t.eq("明文后缀", tool.PLAIN_SUFFIX, ".botbundle")
    t.eq("加密后缀", tool.ENC_SUFFIX, ".botbundleenc")
    t.eq("边车后缀", tool.SIDECAR_SUFFIX, ".json")
    t.eq("边车与包同名再加后缀", tool.sidecar_path(bits / "a.botbundle").name, "a.botbundle.json")
    codes = [
        tool.EXIT_OK, tool.EXIT_RUNTIME, tool.EXIT_USAGE, tool.EXIT_BOT_MISSING,
        tool.EXIT_BOT_DELETED, tool.EXIT_DEST_UNWRITABLE, tool.EXIT_BUNDLE_BAD,
        tool.EXIT_PASSPHRASE, tool.EXIT_LEDGER,
    ]
    t.eq("退出码互不重复", len(set(codes)), 9)
    t.eq("成功码是 0", tool.EXIT_OK, 0)
    t.eq("工具与运行时共用魔数", tool.BUNDLE_MAGIC, BUNDLE_MAGIC)

    blob = bits / "hash.bin"
    blob.write_bytes(b"pbsb-sample-bytes")
    t.eq("sha256_file 等于 hashlib", tool.sha256_file(blob), hashlib.sha256(b"pbsb-sample-bytes").hexdigest())
    t.eq("sha256_file 与运行时同实现", tool.sha256_file(blob), sha256_bytes(b"pbsb-sample-bytes"))
    os.chmod(blob, 0o644)
    t.eq("mode_text 报告真实权限", tool.mode_text(blob), "0644")
    os.chmod(blob, SECURE_FILE_MODE)
    t.eq("mode_text 收紧后为 0600", tool.mode_text(blob), "0600")

    t.eq("边车的 0 不再被读成缺失", tool._sidecar_int(0), 0)
    t.eq("边车正常整数照收", tool._sidecar_int(7), 7)
    t.eq("边车缺失是哨兵 -1", tool._sidecar_int(None), -1)
    t.eq("边车布尔不当数字", tool._sidecar_int(True), -1)
    t.eq("边车字符串不当数字", tool._sidecar_int("3"), -1)

    nested = bits / "out" / "nested"
    made = tool.prepare_dest(nested, bits)
    t.eq("prepare_dest 递归建目录", made.is_dir(), True)
    t.eq("导出目录强制 0700", mode_of(made), SECURE_DIR_MODE)
    t.eq("缺省回退到备份目录", tool.prepare_dest(None, bits), bits.resolve())
    try:
        tool.prepare_dest(blob, bits)
        t.check("目标是文件时被拒绝", False, "未抛 ToolError")
    except tool.ToolError as exc:
        t.eq("文件目标退出码 5", exc.code, tool.EXIT_DEST_UNWRITABLE)
        t.contains("文件目标说明原因", exc.message, "不是目录")
    if os.geteuid() != 0:
        ro = bits / "ro"
        ro.mkdir()
        os.chmod(ro, 0o500)
        try:
            tool.prepare_dest(ro / "sub", bits)
            t.check("目录不可写时被拒绝", False, "未抛 ToolError")
        except tool.ToolError as exc:
            t.eq("不可写目录退出码 5", exc.code, tool.EXIT_DEST_UNWRITABLE)
        os.chmod(ro, 0o700)
    else:
        t.check("root 环境跳过不可写目录用例", True)

    os.environ["POPOPX_SELFSERVICE_PASS"] = "pp-from-env"
    os.environ["POPOPX_SELFSERVICE_EMPTY"] = ""
    t.eq("口令取自环境变量", tool.read_passphrase("POPOPX_SELFSERVICE_PASS"), "pp-from-env")
    try:
        tool.read_passphrase("POPOPX_SELFSERVICE_MISSING")
        t.check("环境变量缺失时报错", False, "未抛 ToolError")
    except tool.ToolError as exc:
        t.eq("环境变量缺失退出码 7", exc.code, tool.EXIT_PASSPHRASE)
    t.raises("环境变量为空时报错", tool.ToolError, tool.read_passphrase, "POPOPX_SELFSERVICE_EMPTY")
    real_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO("pp-from-pipe\nsecond\n")
        t.eq("管道 stdin 取首行", tool.read_passphrase(from_stdin=True), "pp-from-pipe")
        sys.stdin = io.StringIO("")
        t.raises("空 stdin 报错", tool.ToolError, tool.read_passphrase, from_stdin=True)
    finally:
        sys.stdin = real_stdin
    del os.environ["POPOPX_SELFSERVICE_PASS"], os.environ["POPOPX_SELFSERVICE_EMPTY"]

    t.eq("--list 翻译成子命令", tool.normalize_argv(["--list"]), ["list"])
    t.eq("--list 保留其余开关", tool.normalize_argv(["--list", "--all"]), ["list", "--all"])
    t.eq("无 --list 时原样返回", tool.normalize_argv(["export", "--bot", "x"]), ["export", "--bot", "x"])
    t.raises("--list 与子命令冲突", tool.ToolError, tool.normalize_argv, ["--list", "verify"])

    # --------------------------------------------------------------- 真实账本
    stack = h.stack(tag="bund")
    info = h.async_in(stack, bundle_fixture)
    ledger = Database(Path(info["data_dir"]) / "studio.db")
    t.contains("隔离目录含 CLI 数据库", str(info["cli_data"]), "bot_agent.db")
    t.contains("隔离目录含自定义密钥文件", str(info["cli_data"]), "marker.txt")

    t.eq("按 id 解析 Bot", tool.resolve_bot(ledger, info["bot_id"])["name"], "bundbot")
    t.eq("按名称解析 Bot", tool.resolve_bot(ledger, "bundbot")["id"], info["bot_id"])
    t.eq("按端口字符串解析 Bot", tool.resolve_bot(ledger, str(info["port"]))["id"], info["bot_id"])
    t.raises("空引用是用法错误", tool.ToolError, tool.resolve_bot, ledger, "")
    try:
        tool.resolve_bot(ledger, "nope")
        t.check("未知引用报错", False, "未抛 ToolError")
    except tool.ToolError as exc:
        t.eq("未知引用退出码 3", exc.code, tool.EXIT_BOT_MISSING)
    try:
        tool.resolve_bot(ledger, info["ghost_id"])
        t.check("软删除 Bot 被拒绝", False, "未抛 ToolError")
    except tool.ToolError as exc:
        t.eq("已删除 Bot 退出码 4", exc.code, tool.EXIT_BOT_DELETED)

    t.eq("同永久链接的行被认出",
         (tool.find_reuse_row(ledger, {"permanent_link": "popopx:/fakepermanentlink"}) or {}).get("id"),
         info["bot_id"])
    t.eq("无链接时按名称回退",
         (tool.find_reuse_row(ledger, {"name": "bundbot"}) or {}).get("id"), info["bot_id"])
    t.eq("陌生链接不复用", tool.find_reuse_row(ledger, {"permanent_link": "popopx:/other"}), None)
    t.eq("既无链接又无名时不复用", tool.find_reuse_row(ledger, {}), None)
    t.eq("软删除行不参与复用", tool.find_reuse_row(ledger, {"name": "ghostbot"}), None)

    def env_for(**over: Any) -> Dict[str, str]:
        base = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("STUDIO_", "CLI_BIN_", "BOT_WS_", "POPOPX_SELFSERVICE"))
        }
        base.update(h.env(**over))
        return base

    data_dir = info["data_dir"]
    bund_env = env_for(STUDIO_DATA_DIR=data_dir)

    # ------------------------------------------------------------ 子命令契约
    help_proc = run_bundle_tool(["--help"], bund_env)
    t.eq("--help 退出码 0", help_proc.returncode, 0)
    t.contains("--help 列出子命令", help_proc.stdout, "export")
    t.contains("--help 列出 invite", help_proc.stdout, "invite")
    t.contains("--help 说明退出码", help_proc.stdout, "退出码：0 成功")
    t.contains("--help 声明全程离线", help_proc.stdout, "不监听任何端口")
    version = run_bundle_tool(["--version"], bund_env)
    t.eq("--version 退出码 0", version.returncode, 0)
    t.contains("--version 含脚本名", version.stdout, "export_bot_bundle.py")
    bare = run_bundle_tool([], bund_env)
    t.eq("无参数打印用法", bare.returncode, 0)
    t.contains("无参数提示 COMMAND", bare.stdout, "COMMAND")
    bogus = run_bundle_tool(["frobnicate"], bund_env)
    t.eq("非法子命令退出码 2", bogus.returncode, tool.EXIT_USAGE)
    t.contains("非法子命令被用法解析拒绝", bogus.stderr, "invalid choice")
    no_bot = run_bundle_tool(["export", "--json"], bund_env)
    t.eq("export 缺 --bot 退出码 2", no_bot.returncode, tool.EXIT_USAGE)
    unknown = run_bundle_tool(["export", "--bot", "nope", "--json"], bund_env)
    t.eq("未知 Bot 退出码 3", unknown.returncode, tool.EXIT_BOT_MISSING)
    t.contains("未知 Bot 提示可用 --list", json.loads(unknown.stdout)["error"], "--list")
    deleted = run_bundle_tool(["export", "--bot", info["ghost_id"], "--json"], bund_env)
    t.eq("导出软删除 Bot 退出码 4", deleted.returncode, tool.EXIT_BOT_DELETED)

    # ---------------------------------------------------------------- 导出往返
    export_proc = run_bundle_tool(["export", "--bot", "bundbot", "--json"], bund_env)
    t.eq("导出退出码 0", export_proc.returncode, 0)
    exp = json.loads(export_proc.stdout)
    bundle_path = Path(exp["file"]["path"])
    t.eq("导出动作名", exp["action"], "export")
    t.eq("导出结果 ok", exp["ok"], True)
    t.eq("导出报告 format", exp["format"], tool.BUNDLE_FORMAT)
    t.eq("导出报告数据目录", Path(exp["data_dir"]).resolve(), Path(data_dir).resolve())
    t.eq("包落在备份目录里", bundle_path.parent.name, "backups")
    t.eq("明文包后缀", bundle_path.suffix, ".botbundle")
    t.eq("包已落盘", bundle_path.is_file(), True)
    t.eq("包权限 0600", mode_of(bundle_path), SECURE_FILE_MODE)
    t.eq("文件内不加密", exp["file"]["encrypted"], False)
    t.eq("魔数报告 gzip", exp["file"]["magic"], "gzip")
    t.eq("后缀字段一致", exp["file"]["suffix"], tool.PLAIN_SUFFIX)
    t.eq("包体哈希可复算", exp["file"]["file_sha256"], tool.sha256_file(bundle_path))
    t.eq("payload 哈希是 64 位十六进制",
         re.match(r"^[0-9a-f]{64}$", exp["file"]["sha256"]) is not None, True)
    t.eq("未加密包的 payload 即包文件本身", exp["file"]["sha256"], exp["file"]["file_sha256"])
    t.eq("cli-data 文件数（含 marker）", exp["files"], 3)
    t.eq("首次导出无需补建目录", exp["created_dirs"], False)
    t.eq("导出 Bot 视图不带 token", "bot_token" in json.dumps(exp, ensure_ascii=False), False)
    t.eq("导出的 Bot 名", exp["bot"]["name"], "bundbot")
    t.eq("导出时 Bot 已停止", exp["bot"]["status"], "stopped")
    side = Path(exp["sidecar"]["path"])
    t.eq("边车已写出", side.is_file(), True)
    t.eq("边车权限 0600", mode_of(side), SECURE_FILE_MODE)
    t.eq("边车与包同名", side.name, bundle_path.name + ".json")
    t.eq("导出内联校验通过", exp["verify"]["ok"], True)
    t.eq("规则计数随包迁移", exp["verify"]["rules"], {"reply": 2, "routing": 1, "plugin_configs": 1})
    t.eq("校验覆盖全部成员", exp["verify"]["checked"], exp["verify"]["manifest_files"])
    t.eq("cli-data 成员计数", exp["verify"]["cli_data_files"], 3)
    t.eq("无成员被跳过", exp["verify"]["skipped"], [])
    t.eq("包内 bot_id", exp["verify"]["bundle_bot_id"], info["bot_id"])
    t.eq("manifest 版本", exp["verify"]["version"], BUNDLE_VERSION)
    t.eq("校验的边车匹配", exp["verify"]["sidecar"]["matches"], True)
    t.check("mode_findings 覆盖包与边车", len(tool.mode_findings(exp)) >= 2, str(tool.mode_findings(exp)))
    rendered = tool.render_export(exp)
    t.contains("人读导出含路径", rendered, str(bundle_path))
    t.contains("人读导出含校验结论", rendered, "完整性校验通过")
    t.contains("人读导出含边车", rendered, "边车清单")

    raw = bundle_path.read_bytes()
    t.eq("明文包是 gzip", raw[:2], b"\x1f\x8b")
    inner = gzip.decompress(raw)
    t.contains("明文 payload 含密钥文件内容", inner, b"cold-key-material")
    t.contains("明文 payload 含永久链接", inner, b"fakepermanentlink")

    verify_proc = run_bundle_tool(["verify", str(bundle_path), "--json"], bund_env)
    t.eq("独立校验退出码 0", verify_proc.returncode, 0)
    ver = json.loads(verify_proc.stdout)
    t.eq("校验动作名", ver["action"], "verify")
    t.eq("校验 ok", ver["ok"], True)
    t.eq("校验无错误", ver["errors"], [])
    t.eq("校验路径", Path(ver["path"]).name, bundle_path.name)
    t.eq("校验魔数", ver["magic"], "gzip")
    t.eq("校验权限", ver["mode"], "0600")
    t.eq("校验未加密", ver["encrypted"], False)
    t.eq("包内格式名", ver["bundle_format"], tool.BUNDLE_FORMAT)
    t.eq("校验的 bot_id", ver["bundle_bot_id"], info["bot_id"])
    t.eq("校验规则计数", ver["rules"], {"reply": 2, "routing": 1, "plugin_configs": 1})
    t.eq("校验 Bot 名", ver["bot"]["name"], "bundbot")
    t.eq("校验 bot 显示名", ver["bot"]["display_name"], "冷备")
    t.eq("校验不泄露 token 字段", "bot_token" in json.dumps(ver, ensure_ascii=False), False)
    t.eq("校验 payload 哈希可用文件哈希复算", ver["payload_sha256"], tool.sha256_file(bundle_path))
    t.eq("校验 payload 哈希与导出报告一致", ver["payload_sha256"], exp["file"]["sha256"])
    t.eq("校验文件哈希可复算", ver["file_sha256"], tool.sha256_file(bundle_path))
    t.eq("校验创建时间非零", ver["created_at"] > 0, True)
    t.eq("校验无改名警告", ver["sidecar"]["warnings"], [])
    t.eq("人读校验渲染", "完整性校验通过" in tool.render_verify(ver), True)
    text_verify = run_bundle_tool(["verify", str(bundle_path)], bund_env)
    t.eq("人读校验退出码 0", text_verify.returncode, 0)
    t.contains("人读校验含备份包标题", text_verify.stdout, "备份包 ")
    t.contains("人读校验含规则行", text_verify.stdout, "路由 1")

    # ------------------------------------------------------------ 加密冷备
    enc_proc = run_bundle_tool(
        ["export", "--bot", "bundbot", "--passphrase-env", "POPOPX_TEST_PASS", "--json"],
        env_for(STUDIO_DATA_DIR=data_dir, POPOPX_TEST_PASS="pp-pp-pp"),
    )
    t.eq("加密导出退出码 0", enc_proc.returncode, 0)
    enc = json.loads(enc_proc.stdout)
    enc_path = Path(enc["file"]["path"])
    t.eq("加密包后缀", enc_path.suffix, ".botbundleenc")
    t.eq("加密标记", enc["file"]["encrypted"], True)
    t.eq("加密魔数", enc["file"]["magic"], "PBSB")
    t.eq("包首是 PBSB 魔数", enc_path.read_bytes()[:4], b"PBSB")
    t.eq("加密包权限 0600", mode_of(enc_path), SECURE_FILE_MODE)
    t.eq("加密包内联校验通过", enc["verify"]["ok"], True)
    t.eq("加密包校验标记加密", enc["verify"]["encrypted"], True)
    t.check("密文里读不到 Bot 永久链接", b"fakepermanentlink" not in enc_path.read_bytes(), "")
    t.check("密文里读不到规则文本", "在的".encode() not in enc_path.read_bytes(), "")
    no_pass = run_bundle_tool(["verify", str(enc_path), "--json"], bund_env)
    t.eq("加密包缺口令退出码 7", no_pass.returncode, tool.EXIT_PASSPHRASE)
    t.contains("缺口令提示用环境变量", json.loads(no_pass.stdout)["error"], "--passphrase-env")
    with_pass = run_bundle_tool(
        ["verify", str(enc_path), "--passphrase-env", "POPOPX_TEST_PASS", "--json"],
        env_for(POPOPX_TEST_PASS="pp-pp-pp"),
    )
    t.eq("带口令校验加密包退出码 0", with_pass.returncode, 0)
    t.eq("带口令校验 ok", json.loads(with_pass.stdout)["ok"], True)
    wrong = run_bundle_tool(
        ["verify", str(enc_path), "--passphrase-env", "POPOPX_TEST_PASS", "--json"],
        env_for(POPOPX_TEST_PASS="wrong-pass"),
    )
    t.eq("错误口令校验失败", wrong.returncode, tool.EXIT_PASSPHRASE)
    t.contains("错误口令提示解密", wrong.stdout + wrong.stderr, "解密")
    stdin_proc = run_bundle_tool(
        ["verify", str(enc_path), "--passphrase-stdin", "--json"], bund_env, stdin="pp-pp-pp\n"
    )
    t.eq("stdin 口令校验加密包退出码 0", stdin_proc.returncode, 0)
    t.eq("stdin 口令校验 ok", json.loads(stdin_proc.stdout)["ok"], True)
    restore_enc = run_bundle_tool(
        ["restore", str(enc_path), "--passphrase-env", "POPOPX_TEST_PASS", "--json"],
        env_for(STUDIO_DATA_DIR=str(h.root / "var" / "buncul"), POPOPX_TEST_PASS="pp-pp-pp"),
    )
    t.eq("加密包可还原", restore_enc.returncode, 0)
    t.eq("还原结果标记加密", json.loads(restore_enc.stdout)["import"]["encrypted"], True)

    # ---------------------------------------------------------------- 篡改拒绝
    def repack(target: Path, edit: Callable[[str, bytes], bytes]) -> None:
        import tarfile

        entries: List[Tuple[str, bytes, int]] = []
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(target.read_bytes())), mode="r") as src:
            for member in src.getmembers():
                handle = src.extractfile(member)
                entries.append((member.name, edit(member.name, handle.read() if handle else b""), member.mode))
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as out:
            for name, data, mode in entries:
                info_t = tarfile.TarInfo(name)
                info_t.size = len(data)
                info_t.mode = mode
                info_t.mtime = 0
                out.addfile(info_t, io.BytesIO(data))
        target.write_bytes(gzip.compress(buf.getvalue()))

    evil = h.root / "evil.botbundle"
    shutil.copyfile(bundle_path, evil)
    shutil.copyfile(side, h.root / "evil.botbundle.json")
    repack(evil, lambda name, data: data.replace(b"cold-key-material", b"HIJACKED-KEY")
           if name.startswith("cli-data/") else data)
    evil_verify = run_bundle_tool(["verify", str(evil), "--json"], bund_env)
    t.eq("篡改成员校验退出码 6", evil_verify.returncode, tool.EXIT_BUNDLE_BAD)
    evil_json = json.loads(evil_verify.stdout)
    t.eq("篡改成员 ok 为假", evil_json["ok"], False)
    t.contains("篡改被 sha256 指认", json.dumps(evil_json["errors"], ensure_ascii=False), "sha256")
    evil_restore = run_bundle_tool(["restore", str(evil), "--json"], bund_env)
    t.eq("篡改包拒绝还原", evil_restore.returncode, tool.EXIT_BUNDLE_BAD)
    t.contains("拒绝还原说明原因", json.loads(evil_restore.stdout)["error"], "已拒绝还原")
    evil_skip = run_bundle_tool(
        ["restore", str(evil), "--allow-unverified", "--json"],
        env_for(STUDIO_DATA_DIR=str(h.root / "var" / "bunskip")),
    )
    t.eq("--allow-unverified 仍拦不住内容被改的包", evil_skip.returncode, tool.EXIT_BUNDLE_BAD)
    t.contains("拦截原因指向成员 SHA-256", evil_skip.stderr, "SHA-256")
    unverified = run_bundle_tool(
        ["restore", str(bundle_path), "--allow-unverified", "--json"],
        env_for(STUDIO_DATA_DIR=str(h.root / "var" / "bunquick")),
    )
    t.eq("--allow-unverified 还原完好包退出码 0", unverified.returncode, 0)
    t.eq("跳过预校验时不返回校验报告", json.loads(unverified.stdout)["verify"], None)

    orphan = h.root / "orphan.botbundle"
    shutil.copyfile(bundle_path, orphan)
    orphan_verify = run_bundle_tool(["verify", str(orphan), "--json"], bund_env)
    t.eq("删除边车后校验退出码 6", orphan_verify.returncode, tool.EXIT_BUNDLE_BAD)
    t.contains("缺少边车清单被点名", json.loads(orphan_verify.stdout)["errors"][0], "缺少边车清单")

    renamed = h.root / "weekly-2026.botbundle"
    shutil.copyfile(bundle_path, renamed)
    shutil.copyfile(side, h.root / "weekly-2026.botbundle.json")
    rename_verify = run_bundle_tool(["verify", str(renamed), "--json"], bund_env)
    t.eq("改名后的包仍可校验", rename_verify.returncode, 0)
    rename_json = json.loads(rename_verify.stdout)
    t.eq("改名后校验 ok", rename_json["ok"], True)
    t.eq("改名后边车仍匹配", rename_json["sidecar"]["matches"], True)
    t.contains("改名作为警告提示", rename_json["sidecar"]["warnings"][0], "应已改名")
    t.contains("改名警告进 stderr", rename_verify.stderr, "警告：")

    junk = h.root / "junk.botbundle"
    junk.write_bytes(b"definitely-not-a-bundle")
    junk_proc = run_bundle_tool(["verify", str(junk), "--json"], bund_env)
    t.eq("垃圾文件校验退出码 6", junk_proc.returncode, tool.EXIT_BUNDLE_BAD)
    t.contains("垃圾文件说明格式", json.loads(junk_proc.stdout)["error"], "格式无法识别")
    absent = run_bundle_tool(["verify", str(h.root / "nope.botbundle"), "--json"], bund_env)
    t.eq("不存在的包退出码 6", absent.returncode, tool.EXIT_BUNDLE_BAD)
    t.contains("不存在的包说明原因", json.loads(absent.stdout)["error"], "备份包不存在")
    file_dest = run_bundle_tool(["export", "--bot", "bundbot", "--dest", str(bundle_path), "--json"], bund_env)
    t.eq("导出目标是文件时退出码 5", file_dest.returncode, tool.EXIT_DEST_UNWRITABLE)

    # ---------------------------------------------------------------- 跨机迁移
    target_dir = h.root / "var" / "buntarget"
    first = run_bundle_tool(["restore", str(bundle_path), "--json"], env_for(STUDIO_DATA_DIR=str(target_dir)))
    t.eq("跨账本还原退出码 0", first.returncode, 0)
    fst = json.loads(first.stdout)
    t.eq("还原动作名", fst["action"], "restore")
    t.eq("还原报告目标数据目录", Path(fst["data_dir"]).resolve(), Path(target_dir).resolve())
    t.eq("还原报告源包", Path(fst["source"]).name, bundle_path.name)
    t.eq("还原报告格式", fst["format"], tool.BUNDLE_FORMAT)
    t.check("新建了账本行", fst["created_row"] is not None, str(fst["created_row"]))
    new_id = fst["created_row"]["bot_id"]
    t.ne("新行 id 不同于源 id", new_id, info["bot_id"])
    t.eq("新行沿用名称", fst["created_row"]["name"], "bundbot")
    t.eq("新行端口在区间内", 5350 <= int(fst["created_row"]["port"]) <= 5399, True)
    t.eq("还原后 Bot 停在 stopped", fst["bot"]["status"], "stopped")
    t.eq("还原不自动启动", fst["started"], False)
    t.eq("还原 import 校验通过", fst["import"]["verified"], True)
    t.eq("还原 import 文件数", fst["import"]["files"], 3)
    t.eq("还原无跳过成员", fst["import"]["skipped"], [])
    t.eq("还原标记未加密", fst["import"]["encrypted"], False)
    t.eq("还原 payload 哈希与包一致", fst["import"]["payload_sha256"], ver["payload_sha256"])
    t.eq("还原文件数与包声明一致", fst["restored_files"], fst["expected_files"])
    t.eq("还原文件数", fst["restored_files"], 3)
    t.check("还原警告说明新建行", any("已新建行" in w for w in fst["warnings"]), json.dumps(fst["warnings"], ensure_ascii=False))
    t.contains("人读还原渲染含账本路径", tool.render_restore(fst), str(target_dir))
    t.contains("人读还原渲染含 Bot 名", tool.render_restore(fst), "bundbot")

    moved = Database(Path(fst["data_dir"]) / "studio.db")
    row = moved.get_bot(new_id)
    t.eq("新行状态 stopped", row["status"], "stopped")
    t.eq("永久链接随包迁移", row["permanent_link"], "popopx:/fakepermanentlink")
    t.eq("联系地址随包迁移", row["contact_address"], row["permanent_link"])
    t.eq("欢迎语随包迁移（俄语模板）", row["welcome_text"].startswith("Добро пожаловать"), True)
    t.contains("欢迎语含源 Bot 显示名", row["welcome_text"], "冷备")
    t.eq("自动接单设置随包迁移", int(row["auto_accept"]), 1)
    t.eq("匿名接受仍保持关闭", int(row["accept_incognito"]), 0)
    replies = {r["pattern"]: r for r in moved.list_reply_rules(new_id)}
    t.eq("两条自动回复规则都迁过来", sorted(replies), ["/hi", "发票"])
    t.eq("回复文本一致", replies["/hi"]["reply_text"], "在的")
    t.eq("规则名一致", replies["发票"]["name"], "r2")
    t.eq("规则优先级一致", int(replies["发票"]["priority"]), 100)
    routes = moved.list_routing_rules(new_id)
    t.eq("路由规则迁过来 1 条", len(routes), 1)
    t.eq("路由关键词是列表", routes[0]["keywords"], ["发票"])
    t.eq("路由目标群一致", routes[0]["target_ref"], "#42")
    t.eq("路由模板一致", routes[0]["template"], "转发 {text}")
    cfgs = moved.list_plugin_configs(new_id)
    t.eq("插件配置迁过来", [(c["plugin_id"], int(c["enabled"])) for c in cfgs], [("auto_reply", 1)])
    t.eq("插件配置内容一致", cfgs[0]["config"], {"fallback_text": "兜底"})
    t.eq("账本文件权限 0600", mode_of(Path(fst["data_dir"]) / "studio.db"), SECURE_FILE_MODE)
    bot_root = Path(fst["data_dir"]) / "bots" / new_id
    t.eq("Bot 隔离根目录 0700", mode_of(bot_root), SECURE_DIR_MODE)
    t.eq("cli-data 目录 0700", mode_of(bot_root / "cli-data"), SECURE_DIR_MODE)
    restored_modes = {p.name: mode_of(p) for p in (bot_root / "cli-data").iterdir()}
    t.eq("还原的 cli-data 文件一律 0600",
         sorted(restored_modes.values()), [SECURE_FILE_MODE] * 3)
    t.eq("marker 内容一致", (bot_root / "cli-data" / "marker.txt").read_bytes(), b"cold-key-material")
    wrapper = bot_root / "run-cli.sh"
    t.eq("包装脚本随包还原", wrapper.is_file(), True)
    t.eq("包装脚本保留可执行位", mode_of(wrapper) & stat.S_IXUSR, stat.S_IXUSR)
    moved.close()

    second = run_bundle_tool(["restore", str(bundle_path), "--json"], env_for(STUDIO_DATA_DIR=str(target_dir)))
    t.eq("重复还原退出码 0", second.returncode, 0)
    snd = json.loads(second.stdout)
    t.eq("第二次还原不再新建行", snd["created_row"], None)
    t.eq("第二次还原复用同一行", snd["bot"]["bot_id"], new_id)
    t.check("复用被写进警告", any("同址" in w for w in snd["warnings"]), json.dumps(snd["warnings"], ensure_ascii=False))
    again = Database(Path(snd["data_dir"]) / "studio.db")
    t.eq("重复还原不翻倍账本行", len(again.list_bots()), 1)
    t.eq("重复还原不翻倍自动回复规则", len(again.list_reply_rules(new_id)), 2)
    t.eq("重复还原不翻倍路由规则", len(again.list_routing_rules(new_id)), 1)
    t.eq("重复还原不翻倍插件配置", len(again.list_plugin_configs(new_id)), 1)
    t.eq("重复还原端口不变", again.get_bot(new_id)["port"], fst["created_row"]["port"])
    again.close()

    named = run_bundle_tool(
        ["restore", str(bundle_path), "--into", "bundbot", "--replace-rules", "--json"],
        env_for(STUDIO_DATA_DIR=str(target_dir)),
    )
    t.eq("--into 指定 Bot 还原退出码 0", named.returncode, 0)
    nm = json.loads(named.stdout)
    t.eq("--into 命中同一行", nm["bot"]["bot_id"], new_id)
    t.eq("--replace-rules 报告清除的自动回复数", nm["replaced_rules"]["reply"], 2)
    t.eq("--replace-rules 报告清除的路由数", nm["replaced_rules"]["routing"], 1)
    t.check("--replace-rules 写进警告", any("--replace-rules" in w for w in nm["warnings"]), "")
    after = Database(Path(nm["data_dir"]) / "studio.db")
    t.eq("replace 之后规则数仍是 2", len(after.list_reply_rules(new_id)), 2)
    t.eq("replace 之后路由仍是 1", len(after.list_routing_rules(new_id)), 1)
    after.close()

    fresh = run_bundle_tool(
        ["restore", str(bundle_path), "--new-name", "imported-bot", "--json"],
        env_for(STUDIO_DATA_DIR=str(h.root / "var" / "bunfresh")),
    )
    t.eq("--new-name 还原退出码 0", fresh.returncode, 0)
    frj = json.loads(fresh.stdout)
    t.eq("--new-name 生效", frj["created_row"]["name"], "imported-bot")
    t.eq("--new-name 行仍带源显示名", frj["created_row"]["display_name"], "冷备")

    bad_into = run_bundle_tool(["restore", str(bundle_path), "--into", "nosuch", "--json"], bund_env)
    t.eq("--into 未知 Bot 退出码 3", bad_into.returncode, tool.EXIT_BOT_MISSING)
    t.contains("--into 未知 Bot 提示", json.loads(bad_into.stdout)["error"], "不存在")

    # ------------------------------------------------------------------ 邀请链接
    inv = run_bundle_tool(["invite", "--bot", "bundbot", "--json"], bund_env)
    t.eq("invite 退出码 0", inv.returncode, 0)
    invj = json.loads(inv.stdout)
    t.eq("invite 动作名", invj["action"], "invite")
    t.eq("invite ok", invj["ok"], True)
    t.check("invite 链接是隐私封装", invj["link"].startswith(INVITE_LINK_PREFIX), invj["link"][:40])
    t.eq("invite 可解回永久地址", decode_invite_link(invj["link"]), "popopx:/fakepermanentlink")
    t.eq("invite 标记 opaque", invj["opaque"], True)
    t.eq("invite 默认不带原始地址", "permanent_link" in invj["bot"], False)
    t.eq("invite 默认不带 SMP 节点", "smp_servers" in invj["bot"], False)
    t.eq("invite 输出不含明文 smp", "smp://" in inv.stdout, False)
    t.contains("invite 人读渲染含链接", tool.render_invite(invj), invj["link"])
    qr_file = h.root / "invite-qr.png"
    inv_qr = run_bundle_tool(["invite", "--bot", "bundbot", "--qr", str(qr_file), "--json"], bund_env)
    t.eq("invite --qr 退出码 0", inv_qr.returncode, 0)
    qrj = json.loads(inv_qr.stdout)["qr"]
    t.eq("invite 二维码落盘", qr_file.is_file(), True)
    t.eq("invite 二维码权限 0600", mode_of(qr_file), SECURE_FILE_MODE)
    t.eq("invite 二维码 PNG 魔数", qr_file.read_bytes()[:4], b"\x89PNG")
    t.eq("invite 二维码哈希可复算", qrj["sha256"], hashlib.sha256(qr_file.read_bytes()).hexdigest())
    t.eq("invite 二维码报告 box", qrj["box"], 8)
    t.eq("invite 二维码报告权限", qrj["mode"], "0600")
    raw_inv = run_bundle_tool(["invite", "--bot", "bundbot", "--raw", "--json"], bund_env)
    t.eq("invite --raw 退出码 0", raw_inv.returncode, 0)
    rawj = json.loads(raw_inv.stdout)
    t.eq("invite --raw 输出原始地址", rawj["link"], "popopx:/fakepermanentlink")
    t.eq("invite --raw 标记非 opaque", rawj["opaque"], False)
    t.eq("invite --raw 视图带原始地址", rawj["bot"]["permanent_link"], "popopx:/fakepermanentlink")
    inv_unknown = run_bundle_tool(["invite", "--bot", "nope", "--json"], bund_env)
    t.eq("invite 未知 Bot 退出码 3", inv_unknown.returncode, tool.EXIT_BOT_MISSING)
    inv_deleted = run_bundle_tool(["invite", "--bot", info["ghost_id"], "--json"], bund_env)
    t.eq("invite 软删除 Bot 退出码 4", inv_deleted.returncode, tool.EXIT_BOT_DELETED)

    # ------------------------------------------------------------------ 列表
    listing = run_bundle_tool(["list", "--json"], bund_env)
    t.eq("list 退出码 0", listing.returncode, 0)
    lst = json.loads(listing.stdout)
    t.eq("list 动作名", lst["action"], "list")
    t.eq("list ok", lst["ok"], True)
    t.eq("list 计数排除软删除", lst["count"], 1)
    t.eq("list 端口区间", lst["ws_port_range"], [5350, 5399])
    t.eq("list 报告 CLI 存在", lst["cli_present"], True)
    t.eq("list 账本文件", Path(lst["db_file"]).name, "studio.db")
    item = lst["bots"][0]
    t.eq("list 行含 bot_id", item["bot_id"], info["bot_id"])
    t.eq("list 行含端口", item["port"], info["port"])
    t.eq("list 行含状态", item["status"], "stopped")
    t.eq("list 行带隐私邀请链接", decode_invite_link(item["invite_link"]), "popopx:/fakepermanentlink")
    t.eq("list 默认不暴露原始地址", "permanent_link" in item, False)
    t.eq("list 默认不暴露 SMP 节点", "smp_servers" in item, False)
    t.eq("list 行 cli-data 存在", item["cli_data_exists"], True)
    t.eq("list 行 cli-data 文件数", item["cli_data_files"], 3)
    t.eq("list 行列出既有备份包数", len(item["bundles"]), 2)
    t.eq("list 不泄露 token", "bot_token" in json.dumps(lst, ensure_ascii=False), False)
    raw_list = run_bundle_tool(["list", "--raw-links", "--json"], bund_env)
    t.eq("list --raw-links 退出码 0", raw_list.returncode, 0)
    raw_item = json.loads(raw_list.stdout)["bots"][0]
    t.eq("--raw-links 输出原始地址", raw_item["permanent_link"], "popopx:/fakepermanentlink")
    t.eq("--raw-links 输出 SMP 节点字段", "smp_servers" in raw_item, True)
    t.contains("人读列表渲染含数据目录", tool.render_list(lst), data_dir)
    all_proc = run_bundle_tool(["list", "--all", "--json"], bund_env)
    t.eq("list --all 退出码 0", all_proc.returncode, 0)
    t.eq("list --all 含软删除行", json.loads(all_proc.stdout)["count"], 2)
    sugar = run_bundle_tool(["--list"], bund_env)
    t.eq("--list 糖块退出码 0", sugar.returncode, 0)
    t.contains("--list 人读含数据目录", sugar.stdout, "数据目录")
    t.contains("--list 人读含端口区间", sugar.stdout, "控制端口区间")
    clash = run_bundle_tool(["--list", "verify", str(bundle_path)], bund_env)
    t.eq("--list 与子命令冲突退出码 2", clash.returncode, tool.EXIT_USAGE)

    draft = ledger.create_bot("draftbot", 5397)
    no_addr = run_bundle_tool(["invite", "--bot", str(draft["id"]), "--json"], bund_env)
    t.eq("invite 无永久地址退出码 1", no_addr.returncode, tool.EXIT_RUNTIME)
    t.contains("invite 无永久地址说明原因", json.loads(no_addr.stdout)["error"], "永久联系地址")

    ledger.close()


def run_bash(args: Sequence[str], *, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", *[str(item) for item in args]],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        timeout=timeout,
    )


def shell_function_body(path: Path, name: str) -> str:
    """取出 shell 脚本里某个函数的源码（到首个顶格 ``}`` 为止）。"""
    lines = path.read_text(encoding="utf-8").splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith(f"{name}()")), None)
    if start is None:
        return ""
    for i in range(start + 1, len(lines)):
        if lines[i] == "}":
            return "\n".join(lines[start:i])
    return "\n".join(lines[start:])


def code_only(body: str) -> str:
    """丢掉整行注释——探针要判断的是真正执行的命令，不是解释为什么这么写的注释。"""
    return "\n".join(line for line in body.splitlines() if not line.strip().startswith("#"))


def user_group_probe() -> Tuple[int, Dict[str, str]]:
    """真跑一次 ``create_service_user``：桩掉 run/id/groupadd/useradd/usermod，记录下发的 argv。

    干跑只能证明文本长什么样，证不了「用户已存在且主组不符时到底纠正不纠正」，
    而那正是生产上踩到的那一条。返回 (退出码, {场景: 输出})。
    """
    if shutil.which("bash") is None:
        return 0, {}
    source = (REPO / "install_ubuntu22.sh").read_text(encoding="utf-8").splitlines(keepends=True)
    while source and not source[-1].strip():
        source.pop()
    if not source or not source[-1].strip().startswith("main "):
        return 1, {"__err__": f"尾部不是 main 调用：{source[-1:]!r}"}
    probe = r"""
set +eu
D="$1"
LOG="$D/calls.log"
. "$D/inst.sh"
run() { printf '%s\n' "$*" >> "$LOG"; }
id() {
  if [ "$1" = "-u" ]; then
    if [ $# -eq 1 ]; then echo 1000; return 0; fi
    [ "$EXISTING" = 1 ] && { echo 900; return 0; }
    return 1
  fi
  if [ "$1" = "-gn" ]; then echo "$PRIMARY"; return 0; fi
  return 1
}
groupadd() { echo "LEAKED-GROUPADD"; }
useradd() { echo "LEAKED-USERADD"; }
usermod() { echo "LEAKED-USERMOD"; }
require_ubuntu() { return 0; }
NO_SUDO=1
MODE=native
SERVICE_USER=svc-bot
SERVICE_GROUP=studio-ops
DATA_DIR=/var/lib/popopx-studio
for scenario in fresh wronggroup rightgroup; do
  : > "$LOG"
  case "$scenario" in
    fresh) EXISTING=0; PRIMARY="" ;;
    wronggroup) EXISTING=1; PRIMARY="svc-bot" ;;
    rightgroup) EXISTING=1; PRIMARY="studio-ops" ;;
  esac
  printf '@@@ %s\n' "$scenario"
  create_service_user
  printf '%s\n' '--- calls'
  cat "$LOG"
done
"""
    with tempfile.TemporaryDirectory(prefix="pbx-usergroup-") as td:
        Path(td, "inst.sh").write_text("".join(source[:-1]), encoding="utf-8")
        Path(td, "probe.sh").write_text(probe.lstrip(), encoding="utf-8")
        Path(td, "calls.log").write_text("", encoding="utf-8")
        # log/warn 走 stderr、命令记录走 stdout，分开读会打乱场景顺序，先并成一个流。
        done = run_bash(["-c", f'bash "{td}/probe.sh" "{td}" 2>&1'], timeout=120)
    blocks: Dict[str, str] = {}
    for chunk in (done.stdout + done.stderr).split("@@@ ")[1:]:
        name, _, rest = chunk.partition("\n")
        blocks[name.strip()] = rest
    return done.returncode, blocks


def repo_text_files() -> List[Path]:
    """仓库里属于交付物的文本文件（跳过 .git/.venv/运行数据/字节码）。"""
    skip = {".git", ".venv", "var", "node_modules", "__pycache__", ".pytest_cache"}
    found: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(REPO):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            if name in skip or name == ".DS_Store":
                continue
            found.append(Path(dirpath) / name)
    return sorted(found)


def group_install(test: SelfTest, h: Harness) -> None:
    """安装脚本、启动器、Compose 与 .env 模板：语法、旗标、干跑和安全契约。"""
    t = test
    ubuntu = REPO / "install_ubuntu22.sh"
    macos = REPO / "install_macos.sh"
    starter = REPO / "start_macos.sh"
    compose = REPO / "docker-compose.yml"
    env_example = REPO / ".env.example"
    scripts = [ubuntu, macos, starter]

    t.eq("Ubuntu 安装器存在", ubuntu.is_file(), True)
    t.eq("macOS 安装器存在", macos.is_file(), True)
    t.eq("macOS 启动器存在", starter.is_file(), True)
    t.eq("Compose 编排存在", compose.is_file(), True)
    t.eq(".env 模板存在", env_example.is_file(), True)

    for path in scripts:
        name = path.name
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        lines = text.splitlines()
        t.eq(f"{name} 有可执行位", mode_of(path) is not None and bool(mode_of(path) & stat.S_IXUSR), True)
        t.eq(f"{name} 用 env bash", lines[0], "#!/usr/bin/env bash")
        t.contains(f"{name} 严格模式", text, "set -euo pipefail")
        t.eq(f"{name} 不含 CRLF", b"\r" in raw, False)
        t.eq(f"{name} 以换行收尾", raw.endswith(b"\n"), True)
        t.check(f"{name} 篇幅足够", len(lines) > 200, str(len(lines)))
        t.eq(f"{name} bash -n 语法通过", run_bash(["-n", name]).returncode, 0)
        glued = re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*[^\x00-\x7F]", code_only(text))
        t.check(f"{name} 变量名不粘连中文", not glued, str(glued[:3]))
        t.contains(f"{name} 声明回环地址", text, "127.0.0.1")
        t.contains(f"{name} 引用 CLI 安装路径", text, "/usr/local/bin/popopx-cli")
        t.contains(f"{name} 提到 Bot 端口区间", text, "5230")
        t.contains(f"{name} 支持覆写 SMP 集群", text, "BOT_SMP_SERVERS")
        t.contains(f"{name} 用法是中文", text, "用法：")

    for path in (ubuntu, macos):
        text = path.read_text(encoding="utf-8")
        t.check(f"{path.name} 做 SHA-256 校验", "sha256" in text.lower(), "")
        t.contains(f"{path.name} 安装 CLI 后 chmod 755", text, "chmod 755")
        t.contains(f"{path.name} 从 GitHub Releases 取最新", text, "releases/latest")
        t.contains(f"{path.name} 支持 --no-node-download 关闭下载", text, "--no-node-download")
        t.contains(f"{path.name} 拒绝覆盖已有 .env", text, "拒绝覆盖")

    # ------------------------------------------------------------ 旗标与帮助
    help_u = run_bash(["install_ubuntu22.sh", "--help"])
    t.eq("Ubuntu --help 退出码 0", help_u.returncode, 0)
    for flag in ("--mode", "--dry-run", "--check", "--uninstall", "--no-node-download",
                 "--app-dir", "--data-dir", "--user", "--group", "--port", "--cli-bin",
                 "--unit", "--python", "--skip-apt", "--no-sudo", "--cli-release-report"):
        t.contains(f"Ubuntu 帮助含 {flag}", help_u.stdout, flag)
    t.contains("Ubuntu 帮助说明默认只绑回环", help_u.stdout, "只绑 127.0.0.1")
    t.contains("Ubuntu 帮助给出 native 模式三件套", help_u.stdout, "systemd 单元")
    t.contains("Ubuntu 帮助固定下载源", help_u.stdout, "POPOPX_CLI_REPO=popopx-chat/popopx-chat")

    help_m = run_bash(["install_macos.sh", "--help"])
    t.eq("macOS --help 退出码 0", help_m.returncode, 0)
    for flag in ("--dry-run", "--check", "--uninstall", "--no-node-download", "--lan",
                 "--force-env", "--repo-dir", "--data-dir", "--user", "--group", "--port",
                 "--cli-bin", "--label", "--python", "--skip-venv", "--no-sudo", "--cli-release-report"):
        t.contains(f"macOS 帮助含 {flag}", help_m.stdout, flag)
    t.contains("macOS 帮助把 0.0.0.0 限定为显式 --lan", help_m.stdout, "显式绑定 0.0.0.0")
    t.contains("macOS 帮助声明默认 127.0.0.1", help_m.stdout, "默认 127.0.0.1")
    t.contains("macOS 帮助固定下载源", help_m.stdout, "POPOPX_CLI_REPO=popopx-chat/popopx-chat")

    help_s = run_bash(["start_macos.sh", "--help"])
    t.eq("启动器 --help 退出码 0", help_s.returncode, 0)
    for flag in ("--check", "--self-test", "--group", "--port", "--host", "--lan",
                 "--data-dir", "--env-file", "--venv", "--python", "--skip-install"):
        t.contains(f"启动器帮助含 {flag}", help_s.stdout, flag)
    t.contains("启动器默认回环", help_s.stdout, "127.0.0.1:8090")

    for name in ("install_ubuntu22.sh", "install_macos.sh", "start_macos.sh"):
        bad = run_bash([name, "--definitely-not-a-flag"])
        t.eq(f"{name} 未知选项退出码 2", bad.returncode, 2)
        t.contains(f"{name} 未知选项有中文提示", bad.stderr, "未知选项")

    # ---------------------------------------------------------------- 干跑
    env_before = (REPO / ".env").exists()
    dry_u = run_bash(["install_ubuntu22.sh", "--dry-run"])
    t.eq("Ubuntu --dry-run 退出码 0", dry_u.returncode, 0)
    du = dry_u.stdout + dry_u.stderr
    t.contains("Ubuntu 干跑打印单元路径", du, "/etc/systemd/system/popopx-bot-studio.service")
    t.contains("Ubuntu 干跑打印单元名", du, "WantedBy=multi-user.target")
    t.contains("Ubuntu 干跑使用专用系统用户", du, "User=popopx-studio")
    t.contains("Ubuntu 干跑服务组与用户同名", du, "Group=popopx-studio")
    t.contains("Ubuntu 干跑部署到 /opt", du, "ExecStart=/opt/popopx-bot-studio/.venv/bin/python3")
    t.contains("Ubuntu 干跑环境仍绑回环", du, "Environment=STUDIO_HOST=127.0.0.1")
    t.contains("Ubuntu 干跑固定端口 8090", du, "Environment=STUDIO_PORT=8090")
    t.contains("Ubuntu 干跑声明数据目录", du, "Environment=STUDIO_DATA_DIR=/var/lib/popopx-studio")
    t.contains("Ubuntu 干跑含控制端口区间", du, "BOT_WS_PORT_BASE=5230")
    t.contains("Ubuntu 干跑含控制端口上限", du, "BOT_WS_PORT_MAX=5299")

    # ---------------------------------------------------- 服务用户主组与 --group 一致性
    # GNU useradd 的 -U/--user-group 会另建一个与用户名同名的组做主组，--group 于是被绕开：
    # 单元 Group= 与 chown 都指向该用户不属于的组，而 systemd 只要组存在就不报错——错配全静默。
    csu = code_only(shell_function_body(ubuntu, "create_service_user"))
    t.contains("建用户源码含 create_service_user", csu, "create_service_user()")
    t.contains("建用户显式指定主组", csu, '--gid "$SERVICE_GROUP"')
    t.check("绝不使用 --user-group", "--user-group" not in csu, csu[:200])
    t.contains("预建组容忍组已存在", csu, "groupadd --system --force")
    t.contains("主组不符时纠正", csu, "usermod -g")
    t.contains("用 id -gn 读实际主组", csu, "id -gn")

    grp_dry = run_bash(["install_ubuntu22.sh", "--dry-run", "--user", "svc-bot", "--group", "studio-ops"])
    gd = grp_dry.stdout + grp_dry.stderr
    t.eq("自定义组干跑退出码 0", grp_dry.returncode, 0)
    t.contains("自定义组干跑打印预建组", gd, "groupadd --system --force studio-ops")
    t.contains("自定义组干跑打印 --gid", gd, "--gid studio-ops")
    t.check("自定义组干跑不打印 -U", " -U " not in gd, gd[-200:])

    probe_code, probe_cases = user_group_probe()
    t.eq("属组探针退出码 0", probe_code, 0)
    t.check("探针命令全部经 run()", "LEAKED-" not in "".join(probe_cases.values()),
            "有命令绕过 run() 直接执行了")
    fresh = probe_cases.get("fresh", "")
    t.check("探针：空库场景建了用户", "useradd" in fresh, "未建用户")
    t.contains("探针：新建前预建组", fresh, "groupadd --system --force studio-ops")
    t.contains("探针：新建用户带 --gid", fresh, "--gid studio-ops svc-bot")
    t.contains("探针：新建用户仍是 nologin", fresh, "--shell /usr/sbin/nologin")
    t.check("探针：不下发 -U 短旗标", " -U " not in fresh, fresh)
    wrong = probe_cases.get("wronggroup", "")
    t.contains("探针：主组不符时 usermod -g", wrong, "usermod -g studio-ops svc-bot")
    t.check("探针：纠正主组不重建用户", "useradd" not in wrong, wrong)
    t.contains("探针：纠正前显式告警", wrong, "与 --group studio-ops 不符")
    same = probe_cases.get("rightgroup", "")
    t.contains("探针：主组一致时说明幂等跳过", same, "已存在，主组即 studio-ops")
    t.check("探针：主组一致时零改动", same.split("--- calls")[-1].strip() == "", same)

    chk = code_only(shell_function_body(ubuntu, "check_mode"))
    t.contains("--check 校验服务用户主组", chk, "id -gn")
    t.contains("--check 校验数据目录属组", chk, "stat -c '%G'")
    t.contains("--check 用组数据库查组存在", chk, "getent group")
    t.check("--check 不用 id -g 判组存在（喂组名必假阴性）", 'id -g "$SERVICE_GROUP"' not in chk, chk[:200])
    t.contains("Ubuntu 干跑承诺不下载二进制", du, "未下载二进制")
    t.contains("Ubuntu 干跑承诺不建用户", du, "未建用户")
    t.contains("Ubuntu 干跑承诺不写单元", du, "未写 /etc/systemd/system/popopx-bot-studio.service")
    t.contains("Ubuntu 干跑对非 Ubuntu 机器给出提示", du, "本机不是 Ubuntu")

    dry_m = run_bash(["install_macos.sh", "--dry-run"])
    t.eq("macOS --dry-run 退出码 0", dry_m.returncode, 0)
    dm = dry_m.stdout + dry_m.stderr
    t.contains("macOS 干跑打印 plist 路径", dm, "/Library/LaunchDaemons/im.popopx.botstudio.plist")
    t.contains("macOS 干跑打印 launchd 标签", dm, "system/im.popopx.botstudio")
    t.contains("macOS 干跑 plist 含 Label", dm, "<string>im.popopx.botstudio</string>")
    t.contains("macOS 干跑 plist 含 RunAtLoad", dm, "RunAtLoad")
    t.contains("macOS 干跑 plist 含 KeepAlive", dm, "KeepAlive")
    t.contains("macOS 干跑 plist 含崩溃重拉间隔", dm, "ThrottleInterval")
    t.contains("macOS 干跑 plist 注入回环地址", dm, "STUDIO_HOST")
    t.contains("macOS 干跑 plist 含控制端口区间", dm, "<key>BOT_WS_PORT_BASE</key>")
    t.contains("macOS 干跑 plist 含 CLI 路径", dm, "<key>CLI_BIN_PATH</key>")
    t.check("令牌不经 plist 明文注入", "<key>STUDIO_ADMIN_TOKEN</key>" not in dm, "")
    t.contains("macOS 干跑承诺不下载二进制", dm, "未下载二进制")
    t.contains("macOS 干跑承诺不写 plist", dm, "未写 /Library/LaunchDaemons/im.popopx.botstudio.plist")
    t.eq("两次干跑都没有创建 .env", (REPO / ".env").exists(), env_before)

    # -------------------------------------------------- 脚本体的回环与二进制纪律
    ubuntu_text = ubuntu.read_text(encoding="utf-8")
    macos_text = macos.read_text(encoding="utf-8")
    starter_text = starter.read_text(encoding="utf-8")
    bare_wildcard = [
        line for line in (ubuntu_text + macos_text + starter_text).splitlines()
        if re.search(r'^\s*(HOST|STUDIO_HOST)="0\.0\.0\.0"', line)
    ]
    t.eq("默认绑定地址从不写 0.0.0.0", bare_wildcard, [])
    t.check("macOS 的 0.0.0.0 只在 --lan 分支里",
            all("LAN" in line for line in macos_text.splitlines() if re.search(r'HOST="0\.0\.0\.0"', line)), "")
    t.check("启动器的 0.0.0.0 只在 --lan 分支里",
            all("--lan" in line for line in starter_text.splitlines() if re.search(r'HOST="0\.0\.0\.0"', line)), "")
    t.contains("Ubuntu 单元名默认与仓库同名", ubuntu_text, 'UNIT_NAME="popopx-bot-studio"')
    t.contains("Ubuntu 专用用户默认非 root", ubuntu_text, 'SERVICE_USER="popopx-studio"')
    t.contains("macOS 标签固定为 im.popopx.botstudio", macos_text, 'LABEL="im.popopx.botstudio"')
    t.contains("macOS 绝不以 root 跑服务", macos_text, "绝不用 root")
    t.contains("Ubuntu 走 Python 3.11 venv", ubuntu_text, "python3.11")
    t.contains("macOS 走 Python 3.11 venv", macos_text, "python3.11")
    t.contains("启动器自检走 --self-test", starter_text, "--self-test")
    t.contains("启动器生成随机管理令牌", starter_text, "STUDIO_ADMIN_TOKEN")

    # ---------------------------------------------------------------- Compose
    compose_text = compose.read_text(encoding="utf-8")
    active = "\n".join(
        line for line in compose_text.splitlines() if not line.lstrip().startswith("#")
    )
    t.contains("Compose 服务名 studio", compose_text, "  studio:")
    t.contains("Compose 固定 Python 3.11 镜像", compose_text, "image: python:3.11-slim")
    t.contains("Compose 只在宿主机回环发布端口", compose_text, '"127.0.0.1:${STUDIO_HOST_PORT:-8090}:8090"')
    t.check("未注释的通配端口发布不存在",
            not re.search(r'^\s*-\s*"?\d+-\d+:', active, re.M), "")
    t.check("未注释的 0.0.0.0 端口发布不存在",
            not re.search(r'^\s*-\s*"?\d+:\d+', active.replace("127.0.0.1:", ""), re.M), "")
    t.check("Bot 控制端口没有被发布", "5230-5299:5230-5299" not in active, "")
    t.contains("Compose 源码只读挂载", compose_text, ":ro")
    t.contains("Compose 状态目录用命名卷", compose_text, "studio-data:/var/lib/popopx-studio")
    t.contains("Compose 重启策略 unless-stopped", compose_text, "restart: unless-stopped")
    t.contains("Compose 禁提权", compose_text, "no-new-privileges:true")
    t.contains("Compose 丢弃全部 capability", compose_text, "cap_drop:")
    t.contains("Compose 有 /healthz 健康检查", compose_text, "/healthz")
    t.contains("Compose 管理令牌来自环境而非硬编码", compose_text, 'STUDIO_ADMIN_TOKEN: "${STUDIO_ADMIN_TOKEN:-}"')
    t.contains("Compose 数据目录与安装器一致", compose_text, "STUDIO_DATA_DIR: /var/lib/popopx-studio")
    t.contains("Compose 默认控制端口区间", compose_text, "${BOT_WS_PORT_BASE:-5230}")
    t.contains("Compose 端口上限默认 5299", compose_text, "${BOT_WS_PORT_MAX:-5299}")
    t.contains("Compose 不硬编码 SMP 集群", compose_text, 'BOT_SMP_SERVERS: "${BOT_SMP_SERVERS:-}"')
    t.check("Compose 不挂载宿主机 CLI 之外的二进制", ":/usr/local/bin/" not in active, "")
    t.contains("Compose 明确零二进制捆绑", compose_text, "零二进制捆绑")
    t.eq("Compose 权限不是 0777 之类", mode_of(compose) is not None and not (mode_of(compose) & 0o022), True)

    # ------------------------------------------------------------- .env 模板
    env_text = env_example.read_text(encoding="utf-8")
    env_keys = {
        line.split("=", 1)[0].strip()
        for line in env_text.splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "=" in line
    }
    # read_keys 从 config.py 源码里抠出来，而不是手抄一份清单：新增配置项时
    # 只要 load_settings 真的读了它，门禁就会自动要求 .env.example 同步收录。
    config_src = (REPO / "studio" / "app" / "config.py").read_text(encoding="utf-8")
    read_keys: set[str] = set()
    for pattern in (
        r'os\.environ\.get\(\s*"([A-Z0-9_]+)"',
        r'env\.get\(\s*"([A-Z0-9_]+)"',
        r'_int_env\(\s*env,\s*"([A-Z0-9_]+)"',
        r'_bool_env\(\s*env,\s*"([A-Z0-9_]+)"',
        r'_float_env\(\s*env,\s*"([A-Z0-9_]+)"',
    ):
        read_keys.update(re.findall(pattern, config_src))
    t.check("config.py 确实读取了配置项", len(read_keys) >= 20, f"只解析到 {len(read_keys)} 个键名")
    t.eq("模板键都被 config 读取", sorted(env_keys - read_keys), [])
    t.check("模板覆盖全部关键项", read_keys.issubset(env_keys), str(sorted(read_keys - env_keys)))
    t.contains("模板默认回环", env_text, "STUDIO_HOST=127.0.0.1")
    t.contains("模板默认关闭局域网", env_text, "STUDIO_ALLOW_LAN=0")
    t.contains("模板令牌是占位符不是密钥", env_text, "replace-me-with-locally-generated-random-token")
    t.contains("模板端口与 DEFAULT_PORT 一致", env_text, f"STUDIO_PORT={DEFAULT_PORT}")
    t.contains("模板 CLI 路径与 DEFAULT_CLI_BIN_PATH 一致", env_text, f"CLI_BIN_PATH={DEFAULT_CLI_BIN_PATH}")
    t.contains("模板控制端口下限与默认一致", env_text, "BOT_WS_PORT_BASE=5230")
    t.contains("模板控制端口上限与默认一致", env_text, "BOT_WS_PORT_MAX=5299")
    t.eq("模板不含真实令牌形态的取值",
         re.search(r"STUDIO_ADMIN_TOKEN=[A-Za-z0-9]{24,}", env_text) is not None, False)
    t.check("模板有中文注释解释", env_text.count("#") > 20, str(env_text.count("#")))
    example_locale = re.search(r"^STUDIO_LOCALE=(\S+)$", env_text, re.M)
    t.check("模板语种是受支持语种",
            example_locale is not None and is_supported(example_locale.group(1)),
            example_locale.group(0) if example_locale else "缺失")

    # ------------------------------------------- 内置 Needle 3 权重（裁定：随仓库内置、加载前 SHA-256）
    needle_dir = REPO / "studio" / "assets" / "models"
    weight = needle_dir / NEEDLE_WEIGHT_FILE
    t.check("内置权重目录存在", needle_dir.is_dir(), str(needle_dir))
    t.check("权重文件已随仓库内置", weight.is_file(), "运行期不允许联网下载模型")
    t.check("权重附带许可文本", (needle_dir / "LICENSE-needle3.txt").is_file(), "")
    t.check("权重附带清单", (needle_dir / "needle3.manifest.json").is_file(), "")
    if weight.is_file():
        size = weight.stat().st_size
        t.check("内置权重小于 50MB", size <= NEEDLE_MAX_WEIGHT_BYTES,
                f"{size} > {NEEDLE_MAX_WEIGHT_BYTES}")
        report = verify_assets(needle_dir)
        t.eq("内置权重通过 SHA-256 校验", [r["name"] for r in report["checked"] if not r["ok"]], [])
        t.eq("权重校验无错误项", report["errors"], [])
        t.check("校验报告为通过", report["ok"], str(report["errors"]))
        t.eq("清单钉住的权重字节数与磁盘一致", (report["weight_bytes"], Path(report["weight"]).stat().st_size),
             (size, size))
        t.check("校验报告带上游署名", bool(report["attribution"]), report["attribution"][:60])
        manifest = load_manifest(needle_dir)
        t.eq("清单 asset 指向权重文件", manifest.asset, NEEDLE_WEIGHT_FILE)
        t.check("清单声明了来源仓库", bool(manifest.source.get("repository")), str(manifest.source))
        t.check("清单声明了来源版本", bool(manifest.source.get("revision")), str(manifest.source))
        t.check("清单声明了 SPDX 许可", bool(manifest.license.get("spdx")), str(manifest.license))
        t.check("权重摘要在清单里被钉住", len(manifest.weights.sha256), 64)
        t.eq("加载门禁 ensure_weights 通过", ensure_weights(needle_dir).name, NEEDLE_WEIGHT_FILE)

    # 反向对照：摘要被改动的权重必须被门禁拒绝，否则上面的通过没有任何意义。
    fake_dir = h.root / "needle-tampered"
    fake_dir.mkdir(parents=True, exist_ok=True)
    fake_blob = b"tampered-weights"
    (fake_dir / NEEDLE_WEIGHT_FILE).write_bytes(fake_blob)
    (fake_dir / "LICENSE-needle3.txt").write_text("Apache License 2.0", encoding="utf-8")
    (fake_dir / "needle3.manifest.json").write_text(
        json.dumps(
            {
                "asset": NEEDLE_WEIGHT_FILE,
                "purpose": "selftest negative control",
                "source": {"org": "Cactus-Compute", "repository": "needle3", "revision": "x"},
                "license": {"spdx": "Apache-2.0", "text_file": "LICENSE-needle3.txt"},
                "model": {"name": "needle3", "format": "cact"},
                "files": {
                    NEEDLE_WEIGHT_FILE: {"bytes": len(fake_blob), "sha256": "0" * 64},
                    "LICENSE-needle3.txt": {"bytes": 17, "sha256": "1" * 64},
                },
            }
        ),
        encoding="utf-8",
    )
    tampered = verify_assets(fake_dir)
    t.check("篡改后的权重校验报告失败", tampered["ok"] is False, str(tampered["errors"]))
    t.check("篡改后的错误里有摘要不符", any("SHA-256" in e for e in tampered["errors"]),
            str(tampered["errors"]))
    t.raises("加载门禁拒绝篡改权重", NeedleAssetError, ensure_weights, fake_dir)
    verifier = REPO / "official_tools" / "verify_needle_assets.py"
    t.check("离线校验器随仓库交付", verifier.is_file(), str(verifier))
    if verifier.is_file():
        run_v = subprocess.run(
            [sys.executable, str(verifier), "--dir", str(needle_dir), "--quiet"],
            capture_output=True, text=True, timeout=120, check=False,
        )
        t.eq("校验器独立运行退出码为 0", run_v.returncode, 0)
        t.check("校验器输出结论行", "结论" in run_v.stdout, run_v.stdout[-120:])
    for path in (ubuntu, macos):
        text = path.read_text(encoding="utf-8")
        t.contains(f"{path.name} 定义权重门禁", text, "verify_needle_weights() {")
        t.check(f"{path.name} 安装路径调用权重门禁",
                re.search(r"verify_needle_weights[^\n]*\|\| die", text) is not None, "")
        t.check(f"{path.name} 诊断路径调用权重门禁",
                re.search(r"verify_needle_weights[^\n]*\|\| true", text) is not None, "")
        t.contains(f"{path.name} 门禁核对文件名", text, NEEDLE_WEIGHT_FILE)
        t.contains(f"{path.name} 门禁有体积上限", text, "NEEDLE_WEIGHT_MAX=")

    # ------------------------------------------------------ 零二进制捆绑与无桩
    binaries: List[str] = []
    for path in repo_text_files():
        try:
            head = path.read_bytes()[:4]
        except OSError:
            continue
        if head == b"\x7fELF" or head[:4] in {b"\xca\xfe\xba\xbe", b"\xce\xfa\xed\xfe",
                                              b"\xfe\xed\xfa\xce", b"\xef\xfa\xed\xfe"} or head == b"!<ar":
            binaries.append(str(path.relative_to(REPO)))
    t.eq("仓库内没有任何可执行二进制", binaries, [])
    t.eq("仓库内没有 popopx-cli 产物",
         [p.name for p in repo_text_files() if p.name in {"popopx-cli", "popopx-chat"}], [])
    ignore_text = (REPO / ".gitignore").read_text(encoding="utf-8")
    for pattern in (".env", "var/", ".venv/", "*.botbundle", "*.db", "studio.key", "cli.log"):
        t.contains(f".gitignore 忽略 {pattern}", ignore_text, pattern)
    t.contains(".gitignore 保留 .env.example", ignore_text, "!.env.example")

    # 标记本身用拼接写，否则这两条断言会匹配到本文件的源码。
    todo_pat = re.compile(r"\b(" + "TO" + "DO|" + "FIX" + "ME|" + "X" + "XX" + r")\b")
    stub_word = "NotImplemented" + "Error"
    py_files = [p for p in repo_text_files() if p.suffix == ".py"]
    todos = [
        f"{p.relative_to(REPO)}:{no}"
        for p in py_files
        for no, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if todo_pat.search(line)
    ]
    t.eq("Python 源码里没有待办残留", todos, [])
    stubs = [
        f"{p.relative_to(REPO)}:{no}"
        for p in py_files
        for no, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if stub_word in line
    ]
    t.eq("未实现异常只出现在插件基类钩子", len(stubs), 1)
    t.contains("该处正是 StudioPlugin.on_message 基类钩子", stubs[0], "plugin_manager.py")
    plugins_dir = REPO / "studio" / "plugins"
    plugin_files = sorted(p.stem for p in plugins_dir.glob("*.py"))
    t.eq("内置插件文件齐备", plugin_files, sorted(name[:-3] for name in BUNDLED_PLUGINS))
    for module in plugin_files:
        source = (plugins_dir / f"{module}.py").read_text(encoding="utf-8")
        t.contains(f"{module} 覆写了 on_message", source, "async def on_message")
        t.contains(f"{module} 声明了 plugin_id", source, "plugin_id")
    shell_files = [p for p in repo_text_files() if p.suffix == ".sh"]
    t.eq("三个 shell 交付物齐备", sorted(p.name for p in shell_files),
         ["install_macos.sh", "install_ubuntu22.sh", "start_macos.sh"])
    for path in shell_files:
        text = path.read_text(encoding="utf-8")
        t.check(f"{path.name} 没有待办残留", todo_pat.search(text) is None, "")
        t.contains(f"{path.name} 有失败即停", text, "set -euo pipefail")


def group_eco_cards(test: SelfTest, h: Harness) -> None:
    """``::POPOPX_ECO::`` 卡片帧与 ``::CB::`` 回执：逐条对齐客户端解析器的规则。"""
    t = test

    t.eq("ECO 帧标记", ECO_MARKER, "::POPOPX_ECO::")
    t.eq("回执前缀", CALLBACK_PREFIX, "::CB::")
    t.eq("上行前缀集合", UPLINK_PREFIXES, ("::CB::", "::REF::", "::SSO_SCAN::"))

    # ------------------------------------------------------------------ JSON 编码
    t.eq("紧凑 JSON 不转义非 ASCII", compact_json({"a": "中 文"}), '{"a":"中 文"}')
    t.eq("紧凑 JSON 无多余空格", compact_json({"a": 1, "b": [1, 2]}), '{"a":1,"b":[1,2]}')
    t.eq("紧凑 JSON 把换行转义掉", compact_json({"a": "x\ny"}), '{"a":"x\\ny"}')
    t.eq("编码结果永不含裸换行", any(ch in compact_json({"a": "x\r\ny"}) for ch in "\r\n"), False)
    t.raises("紧凑 JSON 拒绝 NaN", EcoCardError, compact_json, {"a": float("nan")})
    escaped = escape_whitespace('{"a":"x y"}')
    t.eq("转义后不含裸空格", " " in escaped, False)
    t.eq("转义写法是 \\u0020", escaped, '{"a":"x\\u0020y"}')
    t.eq("转义后仍是合法 JSON", json.loads(escaped.replace("\\u0020", " ")), {"a": "x y"})

    # ---------------------------------------------------------------------- 动作
    ok_action = build_action(action_id="approve", title="确认", kind="callback",
                             payload=f"{CALLBACK_APPROVE}_ppx1")
    t.eq("callback 动作线上形状", sorted(ok_action), ["action", "id", "payload", "style", "title"])
    t.raises("拒绝未知动作类型", EcoCardError, build_action, action_id="a", title="t", kind=" teleport")
    t.raises("拒绝未知按钮样式", EcoCardError, build_action, action_id="a", title="t",
             kind="callback", payload="p", style="neon")
    t.raises("拒绝 action=none", EcoCardError, build_action, action_id="a", title="t", kind="none")
    t.raises("拒绝含空白的 payload", EcoCardError, build_action, action_id="a", title="t",
             kind="callback", payload="ppxok a b")
    t.raises("拒绝含 :: 的 payload", EcoCardError, build_action, action_id="a", title="t",
             kind="callback", payload="ppx::ok")
    t.raises("拒绝超长 payload", EcoCardError, callback_payload, "x" * (EcoLimits.payload_chars + 1))
    t.eq("接受绝对 URL", "url" in build_action(action_id="u", title="开", kind="open_url",
                                               url="https://meet.popopx.im/a"), True)
    t.raises("拒绝裸域名 URL", EcoCardError, build_action, action_id="u", title="开",
             kind="open_url", url="meet.popopx.im")
    t.raises("拒绝无主机的 URL", EcoCardError, build_action, action_id="u", title="开",
             kind="open_url", url="https:///path")
    t.raises("拒绝非 http 协议", EcoCardError, build_action, action_id="u", title="开",
             kind="open_url", url="file:///etc/passwd")
    t.eq("send_cmd 原样保留命令", build_action(action_id="s", title="命令", kind="send_cmd",
                                               payload="/help")["payload"], "/help")

    # ---------------------------------------------------------------------- 卡片
    card = build_card("ppx_1", "标题", body="正文", fields=[{"label": "时间", "value": "10:00"}],
                      actions=[ok_action], expires_at_ms=now_ms() + 60000)
    t.eq("卡片必备短键齐备", [k for k in ("id", "v", "title", "ut") if k not in card], [])
    t.eq("字段用 label/value 别名也能落地", card["fields"], [{"k": "时间", "v": "10:00"}])
    t.check("过期时间写成 et", card["et"] > now_ms(), str(card.get("et")))
    t.raises("拒绝未知卡片样式", EcoCardError, build_card, "i", "t", style="glass")
    t.raises("拒绝超长标题", EcoCardError, build_card, "i", "标" * (EcoLimits.card_title_chars + 1))
    t.raises("拒绝空标题", EcoCardError, build_card, "i", "   ")
    t.raises("拒绝超长卡片 id", EcoCardError, build_card, "x" * 65, "t")
    t.raises("拒绝超上限字段数", EcoCardError, build_card, "i", "t",
             fields=[{"k": "a", "v": "b"}] * (EcoLimits.max_fields + 1))
    t.raises("拒绝超上限按钮数", EcoCardError, build_card, "i", "t",
             actions=[{"action_id": f"a{i}", "title": "t", "kind": "callback", "payload": f"p{i}"}
                      for i in range(EcoLimits.max_actions + 1)])
    t.raises("拒绝重复按钮 id", EcoCardError, build_card, "i", "t",
             actions=[{"action_id": "a", "title": "1", "kind": "callback", "payload": "p1"},
                      {"action_id": "a", "title": "2", "kind": "callback", "payload": "p2"}])

    # ---------------------------------------------------------------------- 帧编码
    t.raises("非卡片帧不能带可见文案", EcoCardError, encode_frame, {"t": "sh"}, visible_text="hi")
    t.raises("更新帧不能带可见文案", EcoCardError, encode_frame,
             {"t": "sc", "m": "u", "card": card}, visible_text="hi")
    t.raises("拒绝未知帧类型", EcoCardError, encode_frame, {"t": "zz"})
    oversized = build_card("i", "t")
    oversized["body"] = "字" * 9000  # 绕过 build_card 自身的 2000 字符上限，专测整帧预算
    t.raises("拒绝超预算的帧", EcoCardError, frame_service_card, oversized)

    # ------------------------------------------------------------------ 确认卡片闭环
    proposal = new_proposal_id()
    created, message = confirmation_card(
        proposal, title="替身机器人 · 会议确认", body="明天 10:00 与 A 开会",
        fields=[{"k": "时间", "v": "2026-11-27 10:00"}, {"k": "时长", "v": "30 分钟"}],
        decline_label="改期", alt_label="换一个时间",
    )
    t.eq("卡片 id 前缀", created["id"].startswith("ppxpr_"), True)
    t.eq("确认卡片有三枚按钮", len(created["actions"]), 3)
    t.eq("按钮动作依次是批准/拒绝/备选",
         [a["id"] for a in created["actions"]], ["approve", "decline", "alternative"])
    # 回执 payload 的形状是 <kind>_<proposal_id>，而提案 id 本身含下划线，
    # 所以只能按第一个下划线切分——这正是 parse_callback 的做法。
    t.eq("按钮回执前缀依次正确",
         [a["payload"].partition("_")[0] for a in created["actions"]],
         [CALLBACK_APPROVE, CALLBACK_DECLINE, CALLBACK_ALT])
    t.eq("每条回执都带上提案 id",
         {a["payload"].partition("_")[2] for a in created["actions"]}, {proposal})
    t.eq("消息以标记帧结尾", message.splitlines()[-1].startswith(ECO_MARKER), True)
    last_token = message.rsplit("\n", 1)[1]
    t.eq("帧是单个空白 token（客户端从末尾回找）", " " in last_token, False)
    t.eq("帧内不含换行", any(ch in last_token for ch in "\r\n"), False)
    t.check("可见文案在帧之前", message.count(ECO_MARKER), 1)
    t.eq("气泡文案不是帧本身", message.splitlines()[0], "明天 10:00 与 A 开会")
    decoded = decode_message(message)
    t.check("客户端规则能解回这张卡片", decoded is not None, message[:80])
    if decoded:
        t.eq("解出的帧类型", decoded["t"], "sc")
        t.eq("解出的模式", decoded["mode"], "c")
        t.eq("解出的卡片 id", decoded["card"]["id"], created["id"])
        t.eq("解出的按钮数", len(decoded["card"]["actions"]), 3)
    t.eq("回执可被解析回提案", parse_callback(f"{CALLBACK_PREFIX}{CALLBACK_APPROVE}_{proposal}"),
         (CALLBACK_APPROVE, proposal))
    for kind in CALLBACK_KINDS:
        # 客户端发送时自带 ::CB:: 前缀，回执生成器只产出 payload 本体。
        line = CALLBACK_PREFIX + callback_for(kind, proposal)
        t.eq(f"{kind} 回执闭环", parse_callback(line), (kind, proposal))
        t.eq(f"{kind} 回执行被识别为上行", is_uplink_text(line), True)
    t.eq("账本提案 id 天然是合法回执引用",
         parse_callback(CALLBACK_PREFIX + callback_for(CALLBACK_APPROVE, proposal)) is not None, True)
    standalone = encode_frame({"t": "sh"})
    t.eq("控制帧独占整条消息", standalone.startswith(ECO_MARKER) and " " not in standalone, True)
    t.eq("独立控制帧也能被解出", decode_message(standalone)["t"], "sh")

    # 客户端 parseControlText：标记之后含换行 → 整条不再被当作控制帧。
    t.eq("标记后含换行则解析失败", decode_message(f"{ECO_MARKER}{{\"t\":\"sh\"}}\n尾巴"), None)
    t.eq("无标记则不是 ECO 消息", decode_message("普通消息 ::POPOPX_ECO::"), None)
    t.eq("标记后不是 JSON 则忽略", decode_message(f"{ECO_MARKER}not-json"), None)
    t.eq("未知帧类型被忽略", decode_message(f"{ECO_MARKER}{{\"t\":\"zz\"}}"), None)
    t.eq("非 ::CB:: 前缀不解析回执", parse_callback("ppxok_" + proposal), None)
    t.eq("空 payload 不解析回执", parse_callback(f"{CALLBACK_PREFIX}"), None)
    t.eq("含 :: 的 payload 不解析回执", parse_callback(f"{CALLBACK_PREFIX}ppxok::{proposal}"), None)
    t.eq("含空白的 payload 不解析回执", parse_callback(f"{CALLBACK_PREFIX}ppxok_{proposal} x"), None)
    t.eq("未知回执类型不解析", parse_callback(f"{CALLBACK_PREFIX}pay_{proposal}"), None)
    t.eq("非法引用字符不解析", parse_callback(f"{CALLBACK_PREFIX}ppxok_a/b"), None)
    t.eq("超长 payload 不解析", parse_callback(f"{CALLBACK_PREFIX}ppxok_{'x' * 600}"), None)
    t.eq("非字符串不解析回执", parse_callback(None), None)

    # ------------------------------------------------------------------ 就地更新卡片
    update = status_card(created, title="已确认", body="已写入 Mac 日历")
    t.eq("更新帧不带可见文案", "\n" in update, False)
    upd = decode_message(update)
    t.check("更新帧可解回", upd is not None, update[:80])
    if upd:
        t.eq("更新帧模式是 u", upd["mode"], "u")
        t.eq("更新帧沿用同一张卡片 id", upd["card"]["id"], created["id"])
        t.eq("更新帧标题", upd["card"]["title"], "已确认")
        t.eq("更新帧不再带按钮", "actions" in upd["card"], False)

    t.eq("回执行判定：回执", is_uplink_text(f"{CALLBACK_PREFIX}ppxok_{proposal}"), True)
    t.eq("回执行判定：引用", is_uplink_text(f"{REFERENCE_PREFIX}abc"), True)
    t.eq("回执行判定：扫码", is_uplink_text(f"{SSO_SCAN_PREFIX}abc"), True)
    t.eq("回执行判定：普通消息", is_uplink_text("明天几点开会？"), False)
    t.eq("回执行判定：空前缀", is_uplink_text(CALLBACK_PREFIX), False)
    t.eq("回执行判定：含空白", is_uplink_text(f"{CALLBACK_PREFIX}a b"), False)
    t.eq("回执行判定：含 ::", is_uplink_text(f"{CALLBACK_PREFIX}a::b"), False)
    t.eq("回执行判定：非字符串", is_uplink_text(None), False)
    t.check("卡片 id 生成器不重复", len({new_card_id() for _ in range(200)}) >= 199, "")


def group_ics(test: SelfTest, h: Harness) -> None:
    """RFC 5545 生成器：CRLF、75 字节折叠、TEXT 转义、UTC 时间戳。"""
    t = test

    t.eq("TEXT 转义反斜杠优先", escape_text("a\\b"), "a\\\\b")
    t.eq("TEXT 转义分号与逗号", escape_text("a;b,c"), "a\\;b\\,c")
    t.eq("TEXT 换行折成字面 \\n", escape_text("a\nb\r\nc"), "a\\nb\\nc")
    t.eq("TEXT 空值安全", escape_text(None), "")
    t.eq("文本值原样返回", escape_text("_plain"), "_plain")

    short = "SUMMARY:简短"
    t.eq("短行不折叠", ics_fold(short), short)
    long_line = "DESCRIPTION:" + ("会议说明，含中文与标点;逗号," * 30)
    folded = ics_fold(long_line)
    t.check("折叠后含 CRLF 续行", "\r\n " in folded, folded[:40])
    widths = [len(piece.encode("utf-8")) for piece in folded.split("\r\n")]
    t.check("每个物理行不超过 75 字节", all(w <= ics_MAX_OCTETS for w in widths), str(widths[:6]))
    t.check("续行以一个空格开头", all(p.startswith(" ") for p in folded.split("\r\n")[1:]), "")
    t.eq("去折叠后与原文完全一致", folded.replace("\r\n ", ""), long_line)
    cjk = "SUMMARY:" + ("中文" * 60)
    cjk_folded = ics_fold(cjk)
    for piece in cjk_folded.split("\r\n"):
        t.check("折叠不切断多字节字符", _utf8_ok(piece), piece[:24])
    t.eq("中文行去折叠无损", cjk_folded.replace("\r\n ", ""), cjk)

    t.eq("epoch 0 的时间戳", ics_stamp(0), "19700101T000000Z")
    t.eq("时间戳总是 UTC", ics_stamp(1_700_000_000).endswith("Z"), True)
    t.eq("时间戳定长 16", len(ics_stamp(1_700_000_000)), 16)
    uid = ics_event_uid("ppx", "pr_2026/11:27#1")
    t.eq("UID 清洗非法字符", all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"
                               for c in uid.split("@")[0]), True)
    t.contains("UID 固定域后缀", uid, "@bot-studio.popopx")
    t.eq("UID 生成是幂等的", ics_event_uid("ppx", "ref-1"), ics_event_uid("ppx", "ref-1"))
    t.eq("空 UID 前缀也有兜底", ics_event_uid("", ""), "popopx@bot-studio.popopx")

    start = 1_800_000_000.0
    event = build_event(uid=uid, summary="与 A 开会; 项目同步", start_ts=start, end_ts=start + 1800,
                        description="替身机器人代订", location="线上", url="https://meet.popopx.im/x",
                        categories=("POPOPX", "MEET"))
    joined = "\n".join(event)
    t.eq("事件以 BEGIN/END 包裹", (event[0], event[-1]), ("BEGIN:VEVENT", "END:VEVENT"))
    for key in ("UID:", "DTSTAMP:", "DTSTART:", "DTEND:", "SUMMARY:", "STATUS:", "SEQUENCE:", "TRANSP:"):
        t.contains(f"事件含 {key}", joined, key)
    t.contains("起止时间是 UTC", joined, f"DTSTART:{ics_stamp(start)}")
    t.eq("DTEND 比 DTSTART 晚半小时", f"DTEND:{ics_stamp(start + 1800)}" in event, True)
    t.contains("SUMMARY 里的分号被转义", joined, "与 A 开会\\; 项目同步")
    t.contains("URL 原样成行", joined, "URL:https://meet.popopx.im/x")
    t.contains("分类逗号被转义", joined, "CATEGORIES:POPOPX\\,MEET")
    t.eq("省略空的可选字段", any(line.startswith("LOCATION:") for line in build_event(
        uid=uid, summary="s", start_ts=start, end_ts=start + 60)), False)
    t.raises("拒绝结束早于开始", ValueError, build_event, uid=uid, summary="s",
             start_ts=start, end_ts=start)
    t.raises("拒绝非法状态", ValueError, build_event, uid=uid, summary="s", start_ts=start,
             end_ts=start + 60, status="MAYBE")
    t.raises("拒绝非法 METHOD", ValueError, build_calendar,
             [{"uid": uid, "summary": "s", "start_ts": start, "end_ts": start + 60}], method="FORGE")

    text = build_calendar(
        [{"uid": uid, "summary": "会议", "start_ts": start, "end_ts": start + 1800},
         {"uid": ics_event_uid("ppx", "second"), "summary": "第二次, 会议", "start_ts": start + 3600,
          "end_ts": start + 4200, "status": "TENTATIVE"}],
        method="PUBLISH", calendar_name="POPOPX 替身机器人", refresh_interval_minutes=15,
    )
    t.eq("日历以 CRLF 结束", text.endswith("\r\n"), True)
    t.eq("日历内没有裸换行", "\n" in text.replace("\r\n", ""), False)
    t.eq("没有孤立的 LF/CR", b"\n" in text.encode().replace(b"\r\n", b""), False)
    lines = text.split("\r\n")
    t.eq("日历头", lines[0], "BEGIN:VCALENDAR")
    t.eq("日历尾", lines[-2], "END:VCALENDAR")
    t.contains("VERSION 2.0", text, "VERSION:2.0")
    t.contains("GREGORIAN 日历", text, "CALSCALE:GREGORIAN")
    t.contains("PRODID 是本项目", text, "POPOPX")
    t.contains("METHOD 写出", text, "METHOD:PUBLISH")
    t.contains("X-WR-CALNAME", text, "POPOPX")
    t.contains("刷新间隔成对出现", text, "X-PUBLISHED-TTL:PT15M")
    t.contains("REFRESH-INTERVAL", text, "REFRESH-INTERVAL;VALUE=DURATION:PT15M")
    t.eq("两个事件", text.count("BEGIN:VEVENT"), 2)
    t.eq("事件配对闭合", text.count("BEGIN:VEVENT"), text.count("END:VEVENT"))
    t.contains("第二个事件是 TENTATIVE", text, "STATUS:TENTATIVE")
    physical = [p for p in text.split("\r\n")]
    t.check("所有物理行 ≤75 字节", all(len(p.encode("utf-8")) <= ics_MAX_OCTETS for p in physical),
            str([len(p.encode()) for p in physical if len(p.encode()) > ics_MAX_OCTETS][:3]))
    t.eq("去折叠后仍能取回转义前的正文",
         text.replace("\r\n ", "").count("DESCRIPTION:"), 0)
    flat = text.replace("\r\n ", "")
    t.eq("折叠不影响逻辑行计数", flat.count("BEGIN:VEVENT"), 2)

    name = ics_filename("与 A 开会; 项目/同步", start)
    t.contains("文件名带 .ics", name, ".ics")
    t.eq("文件名不含路径分隔符", ("/" in name or "\\" in name), False)
    t.contains("文件名带 UTC 日期", name, ics_stamp(start))
    t.eq("非法字符被替换", any(c in name for c in "; /"), False)
    t.eq("空标题也有兜底文件名", ics_filename("", start).startswith("popopx-meeting-"), True)


AGENT_TABLES = (
    "agent_proposals",
    "a2a_negotiations",
    "guest_links",
    "guest_messages",
    "negotiation_audit",
    "calendar_cache",
)


def group_agent_ledger(test: SelfTest, h: Harness) -> None:
    """账本 v5：替身提案、A2A 协商、访客链接、审计与忙闲缓存的迁移与约束。"""
    t = test
    db = h.database("agent_ledger")

    t.eq("账本 schema 版本推进到 5", SCHEMA_VERSION, 5)
    tables = {row["name"] for row in db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    t.eq("v5 的六张表全部建成", [x for x in AGENT_TABLES if x not in tables], [])
    indexes = {row["name"] for row in db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index' "
        "AND (name LIKE 'idx_agent%' OR name LIKE 'idx_a2a%' OR name LIKE 'idx_guest%' "
        "OR name LIKE 'idx_negot%' OR name LIKE 'idx_cal%')")}
    t.check("v5 建了配套索引", len(indexes) >= 6, str(sorted(indexes)))
    t.eq("重跑迁移不再应用任何版本", db.migrate(target_version=SCHEMA_VERSION), [])
    t.eq("迁移台账记到 5",
         [r["version"] for r in db.conn.execute(
             "SELECT version FROM schema_migrations ORDER BY version")], [1, 2, 3, 4, 5])
    again = {row["name"] for row in db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    t.eq("重跑迁移不会把表建两遍", sorted(again & set(AGENT_TABLES)), sorted(AGENT_TABLES))

    # ---------------------------------------------------------------- 标识符
    ids = [new_proposal_id() for _ in range(200)]
    t.check("提案 id 唯一", len(set(ids)) == len(ids), "")
    t.eq("提案 id 前缀", ids[0].startswith("pr_"), True)
    t.eq("协商 id 前缀", new_negotiation_id().startswith("ng_"), True)
    t.eq("访客链接 id 前缀", new_guest_link_id().startswith("gl_"), True)
    t.check("提案 id 直接可当回执引用", parse_callback(
        CALLBACK_PREFIX + callback_for(CALLBACK_APPROVE, ids[0])) is not None, True)

    bot = db.create_bot("agentledger", 5455, display_name="替身账本")
    other = db.create_bot("agentother", 5456)
    bid = bot["id"]
    obid = other["id"]
    start = time.time()
    peer = "ma_pQ7Zk2mVx3rN8sT1@smp1.popopx.im"  # 对端 SMP 身份（掩码后仍是这一串）

    # ------------------------------------------------------------------ 提案
    proposal = db.create_proposal(
        bid, "create", source="a2a", chat_type="direct", chat_ref="a@smp",
        counterparty="peer", timezone="Asia/Shanghai", start_ts=start + 3600,
        end_ts=start + 5400, duration_minutes=30, summary="与 A 开会",
        payload={"expires_at": start + 7200, "card_id": "ppxpr_x"},
        link_id="", ticket_id="tk1",
    )
    t.eq("新提案默认 pending", proposal["status"], "pending")
    t.eq("提案负载原样读回（dict 不是字符串）", proposal["payload"]["card_id"], "ppxpr_x")
    t.eq("提案时长落库", proposal["duration_minutes"], 30)
    t.eq("未显式给 id 也会生成", bool(proposal["proposal_id"]), True)
    t.raises("拒绝非法动作", LedgerError, db.create_proposal, bid, "teleport")
    t.raises("拒绝非法来源", LedgerError, lambda: db.create_proposal(
        bid, "create", source="telegram"))
    t.raises("拒绝非法提案 id", LedgerError, lambda: db.create_proposal(
        bid, "create", proposal_id="bad id/../x"))
    t.eq("未知提案读不到", db.get_proposal("pr_nope"), None)
    t.eq("空 card_id 不去猜提案", db.find_proposal_by_card(""), None)
    t.eq("刚建好还查不到卡片索引", db.find_proposal_by_card("ppxpr_card1"), None)

    approved = db.update_proposal(proposal["proposal_id"], status="approved", card_id="ppxpr_card1")
    t.eq("批准后状态改写", approved["status"], "approved")
    t.check("终态自动补 decided_at", approved["decided_at"] > 0, str(approved["decided_at"]))
    t.eq("按卡片 id 反查提案", db.find_proposal_by_card("ppxpr_card1")["proposal_id"],
         proposal["proposal_id"])
    t.raises("拒绝未知字段", LedgerError, db.update_proposal, proposal["proposal_id"], hacker="x")
    t.raises("拒绝非法状态", LedgerError, db.update_proposal, proposal["proposal_id"], status="zombie")
    t.raises("拒绝非对象负载", LedgerError, db.update_proposal, proposal["proposal_id"], payload="nope")
    t.raises("拒绝改不存在的提案", LedgerError, db.update_proposal, "pr_nope", status="approved")
    same = db.update_proposal(proposal["proposal_id"])
    t.eq("空更新是读回而非报错", same["status"], "approved")

    fresh = db.create_proposal(bid, "reschedule", payload={"expires_at": start + 99999})
    gone = db.create_proposal(bid, "cancel", payload={"expires_at": start - 10})
    stale = db.create_proposal(obid, "create", payload={})
    db.conn.execute("UPDATE agent_proposals SET created_at = ? WHERE proposal_id = ?",
                    (time.time() - 90000, stale["proposal_id"]))
    expired = db.expire_proposals()
    t.eq("过窗口的 pending 提案被过期化", db.get_proposal(gone["proposal_id"])["status"], "expired")
    t.eq("超一天的 pending 提案也被过期化", db.get_proposal(stale["proposal_id"])["status"], "expired")
    t.eq("未过窗口的提案不受影响", db.get_proposal(fresh["proposal_id"])["status"], "pending")
    t.eq("已批准的提案不会被过期覆盖", db.get_proposal(proposal["proposal_id"])["status"], "approved")
    t.check("过期计数至少覆盖两条", expired >= 2, str(expired))
    t.eq("过期时间写进 decided_at", db.get_proposal(gone["proposal_id"])["decided_at"] > 0, True)

    db.create_proposal(obid, "create", summary="另一台 Bot")
    stats = db.proposal_stats(bid)
    t.check("提案统计按状态汇总", stats["pending"] >= 1, str(stats["totals"]))
    t.eq("统计里有动作×状态的细分", any(k.startswith("create:") for k in stats["breakdown"]), True)
    t.check("按 Bot 过滤统计给出非零细分", sum(1 for v in stats["breakdown"].values() if v > 0) >= 2,
            str(stats["breakdown"]))
    t.eq("全量统计不小于单 Bot", db.proposal_stats()["totals"]["pending"] >= stats["totals"]["pending"], True)
    listed = db.list_proposals(bid, status="approved")
    t.eq("列表按状态过滤", {p["proposal_id"] for p in listed}, {proposal["proposal_id"]})
    t.eq("列表 limit 生效", len(db.list_proposals(bid, limit=1)), 1)
    t.eq("列表可按 bot 为空", db.list_proposals("nope_bot"), [])

    # ------------------------------------------------------------------ 协商
    slots = [{"start": start + 3600, "end": start + 5400, "tz": "Asia/Shanghai"}]
    nego = db.create_negotiation(
        bid, peer, peer_label="老张", channel="a2a", owner_timezone="Asia/Shanghai",
        peer_timezone="Europe/Berlin", window_start=start, window_end=start + 86400,
        duration_minutes=60, expires_at=start + 7200, owner_slots=slots,
    )
    t.eq("协商默认 open", nego["status"], "open")
    t.eq("掩码候选槽原样读回", nego["owner_slots"], slots)
    t.eq("空槽位读回是列表而不是空串", (nego["peer_slots"], nego["intersection"], nego["agreed_slot"]),
         ([], [], {}))
    t.eq("协商首轮 round 为 0", nego["round"], 0)
    t.raises("拒绝非法通道", LedgerError, lambda: db.create_negotiation(bid, peer, channel="sms"))
    t.eq("未知协商读不到", db.get_negotiation("ng_nope"), None)
    found = db.find_open_negotiation(bid, peer)
    t.check("能按对端找到进行中的协商", found is not None and found["negotiation_id"] == nego["negotiation_id"],
            str(found))
    t.eq("空对端不匹配任何协商", db.find_open_negotiation(bid, ""), None)
    t.eq("别的 bot 找不到这条协商", db.find_open_negotiation(obid, peer), None)
    past = db.create_negotiation(bid, "ma@expired.example", expires_at=time.time() - 5)
    t.eq("已过期的 open 协商不再命中", db.find_open_negotiation(bid, "ma@expired.example"), None)
    t.eq("未过期的 open 协商仍在窗口内命中",
         db.find_open_negotiation(bid, peer)["negotiation_id"], nego["negotiation_id"])
    db.update_negotiation(nego["negotiation_id"], round=3, peer_slots=slots,
                          intersection=slots, agreed_slot=slots[0], status="converged",
                          proposal_id=proposal["proposal_id"])
    back = db.get_negotiation(nego["negotiation_id"])
    t.eq("协商轮次可推进", back["round"], 3)
    t.eq("交集与商定槽原样读回", (back["peer_slots"], back["intersection"], back["agreed_slot"]),
         (slots, slots, slots[0]))
    t.eq("收敛后不再是 open", db.find_open_negotiation(bid, peer), None)
    t.raises("拒绝未知协商字段", LedgerError, db.update_negotiation, nego["negotiation_id"], x=1)
    t.raises("拒绝非法协商状态", LedgerError, db.update_negotiation, nego["negotiation_id"], status="paused")
    t.raises("拒绝改不存在的协商", LedgerError, db.update_negotiation, "ng_nope", round=1)
    nstats = db.negotiation_stats(bid)
    t.check("协商统计含总量", nstats["total"] >= 2, str(nstats))
    t.check("协商统计给出平均轮次", isinstance(nstats["avg_rounds"], float), str(nstats["avg_rounds"]))
    t.eq("按状态筛协商", {n["negotiation_id"] for n in db.list_negotiations(bid, status="converged")},
         {nego["negotiation_id"]})

    # ---------------------------------------------------------------- 访客链接
    token = secrets.token_urlsafe(24)
    link = db.create_guest_link(
        bid, token, label="张三", topic="项目同步", max_uses=2, duration_minutes=45,
        timezone="Asia/Shanghai", expires_at=start + 86400, created_by="console",
    )
    t.eq("新链接默认 active", link["status"], "active")
    t.eq("新链接零使用", int(link["uses"]), 0)
    t.eq("可按 token 反查链接", db.get_guest_link(token=token)["link_id"], link["link_id"])
    t.eq("可按 link_id 正查", db.get_guest_link(link["link_id"])["token"], token)
    t.eq("两个都不给不猜链接", db.get_guest_link(), None)
    t.eq("陌生 token 查不到", db.get_guest_link(token="nope"), None)
    t.raises("拒绝空 token", LedgerError, lambda: db.create_guest_link(bid, ""))
    t.raises("拒绝零次可用", LedgerError, lambda: db.create_guest_link(bid, "tk", max_uses=0))
    t.raises("拒绝超上限次数", LedgerError, lambda: db.create_guest_link(bid, "tk", max_uses=1001))
    t.raises("拒绝非法链接 id", LedgerError, lambda: db.create_guest_link(bid, "tk2", link_id="a b"))
    t.raises("拒绝重复 token", LedgerError, lambda: db.create_guest_link(bid, token))

    used1 = db.record_guest_use(link["link_id"], visitor_hash="vh1")
    t.eq("首次访问计数为 1", int(used1["uses"]), 1)
    t.eq("首次访问仍是 active", used1["status"], "active")
    t.eq("记录访客指纹", used1["last_used_at"] > 0, True)
    used2 = db.record_guest_use(link["link_id"], visitor_hash="vh2")
    t.eq("用完配额自动变 exhausted", used2["status"], "exhausted")
    used3 = db.record_guest_use(link["link_id"])
    t.eq("用尽后仍可计数（审计不丢）", int(used3["uses"]), 3)
    t.eq("用尽后状态不回退", used3["status"], "exhausted")
    single = db.create_guest_link(bid, secrets.token_urlsafe(12), max_uses=1)
    t.eq("单次链接一次即尽", db.record_guest_use(single["link_id"])["status"], "exhausted")
    rev = db.create_guest_link(bid, secrets.token_urlsafe(12))
    revoked = db.revoke_guest_link(rev["link_id"])
    t.eq("吊销后状态是 revoked", revoked["status"], "revoked")
    t.check("吊销写下时间戳", revoked["revoked_at"] > 0, str(revoked["revoked_at"]))
    after = db.record_guest_use(rev["link_id"])
    t.eq("吊销的链接不再计数", int(after["uses"]), 0)
    t.eq("吊销链接状态保持", after["status"], "revoked")
    dead = db.create_guest_link(bid, secrets.token_urlsafe(12), expires_at=time.time() - 1)
    live = db.create_guest_link(bid, secrets.token_urlsafe(12), expires_at=time.time() + 3600)
    forever = db.create_guest_link(bid, secrets.token_urlsafe(12))
    t.eq("过期扫描只动过期链接", db.mark_guest_links_expired() >= 1, True)
    t.eq("过期链接状态改写", db.get_guest_link(dead["link_id"])["status"], "expired")
    t.eq("未过期链接不受影响", db.get_guest_link(live["link_id"])["status"], "active")
    t.eq("不设过期时间的链接永不过期", db.get_guest_link(forever["link_id"])["status"], "active")
    db.set_link_proposal(link["link_id"], proposal["proposal_id"])
    t.eq("链接可回写提案", db.get_guest_link(link["link_id"])["proposal_id"], proposal["proposal_id"])
    lstats = db.link_stats(bid)
    t.check("链接统计给出总量与访问量", lstats["total"] >= 6 and lstats["visits"] >= 3, str(lstats))
    t.eq("可按状态筛链接", all(x["status"] == "exhausted" for x in db.list_guest_links(bid, status="exhausted")), True)
    t.eq("链接归属该 bot", db.get_guest_link(forever["link_id"])["bot_id"], bid)
    t.eq("别的 bot 列不到这条链接", [x["link_id"] for x in db.list_guest_links(obid)], [])

    # -------------------------------------------------------------- 访客会话
    mid = db.append_guest_message(bid, link["link_id"], "visitor", "我周三下午有空",
                                 visitor_hash="vh1")
    t.check("访客消息返回自增 id", mid > 0, str(mid))
    db.append_guest_message(bid, link["link_id"], "bot", "为你找到两个候选时段")
    db.append_guest_message(bid, link["link_id"], "owner", "确认", proposal_id=proposal["proposal_id"])
    msgs = db.list_guest_messages(link["link_id"])
    t.eq("会话按时间正序返回", [m["role"] for m in msgs], ["visitor", "bot", "owner"])
    t.eq("会话带 bot 归属", {m["bot_id"] for m in msgs}, {bid})
    t.eq("会话 limit 只截最近 N 条再正序", [m["role"] for m in db.list_guest_messages(link["link_id"], limit=2)],
         ["bot", "owner"])
    t.eq("别的链接读不到", db.list_guest_messages("gl_nope"), [])
    t.raises("拒绝非法角色", LedgerError, db.append_guest_message, bid, link["link_id"], "stranger", "x")
    long_id = db.append_guest_message(bid, link["link_id"], "visitor", "长" * 3000)
    t.eq("超长访客文本被截断", len([m for m in db.list_guest_messages(link["link_id"], limit=500)
                              if m["id"] == long_id][0]["text"]), 2000)

    # -------------------------------------------------------------------- 审计
    log_id = db.log_negotiation("needle", "intent_extract", bot_id=bid, level="info",
                                proposal_id=proposal["proposal_id"], negotiation_id=nego["negotiation_id"],
                                link_id=link["link_id"], chat_ref="a@smp", detail="命中 3 个槽",
                                data={"tools": ["calendar.get_availability"]}, latency_ms=12.5)
    t.check("审计写入返回 id", log_id > 0, str(log_id))
    t.raises("拒绝非法阶段", LedgerError, db.log_negotiation, "bogus", "x")
    t.raises("拒绝非法级别", LedgerError, lambda: db.log_negotiation("needle", "x", level="trace"))
    db.log_negotiation("mac_node", "approve", bot_id=bid, level="error", detail="桥不可达",
                       proposal_id=proposal["proposal_id"])
    db.log_negotiation("guest", "token_replay", bot_id=bid, level="warn")
    recent = db.recent_negotiations(bid, limit=50)
    t.eq("审计按时间倒序", [r["stage"] for r in recent][0] in ("guest", "mac_node", "needle"), True)
    needle_row = [r for r in recent if r["stage"] == "needle"][0]
    t.eq("审计负载读回是 dict", needle_row["data"], {"tools": ["calendar.get_availability"]})
    t.eq("审计延迟原样读回", round(needle_row["latency_ms"], 1), 12.5)
    t.eq("审计长 detail 截到 500 字符", len([r for r in recent if r["stage"] == "needle"]
                                       [0]["detail"]) <= 500, True)
    needle_rows = db.recent_negotiations(bid, stage="needle")
    t.eq("可按阶段筛审计", all(r["stage"] == "needle" for r in needle_rows) and len(needle_rows) >= 1, True)
    t.eq("可按级别筛审计", all(r["level"] == "error" for r in db.recent_negotiations(bid, level="error")), True)
    one = db.recent_negotiations(bid, proposal_id=proposal["proposal_id"])
    t.eq("可按提案筛审计", all(r["proposal_id"] == proposal["proposal_id"] for r in one) and len(one) >= 2, True)
    t.eq("审计 limit 生效", len(db.recent_negotiations(bid, limit=1)), 1)
    t.eq("别的 bot 读不到审计", db.recent_negotiations("nope_bot"), [])
    funnel = db.negotiation_funnel(bid)
    t.check("漏斗给出各阶段计数", funnel["stages"].get("needle", 0) >= 1, str(funnel["stages"]))
    t.eq("漏斗单独给出错误计数", funnel["errors"].get("mac_node", 0), 1)
    t.eq("漏斗不串别的 bot", "guest" in db.negotiation_funnel(obid)["stages"], False)

    # -------------------------------------------------------------- 忙闲缓存
    busy = [{"start": start + 3600, "end": start + 5400}]
    db.cache_busy(bid, "2026-11-27", busy, timezone="Asia/Shanghai", source="mac_node", ttl_seconds=600)
    hit = db.cached_busy(bid, "2026-11-27")
    t.check("缓存命中返回区间", hit is not None and hit["busy"] == busy, str(hit))
    t.eq("缓存记住时区", hit["timezone"], "Asia/Shanghai")
    t.eq("未写入的那天没有缓存", db.cached_busy(bid, "2026-11-28"), None)
    t.eq("别的来源没有缓存", db.cached_busy(bid, "2026-11-27", source="needle"), None)
    db.cache_busy(bid, "2026-11-27", [{"start": start, "end": start + 60}], source="mac_node")
    rows = db.conn.execute("SELECT COUNT(*) FROM calendar_cache WHERE bot_id = ? AND day = ?",
                           (bid, "2026-11-27")).fetchone()[0]
    t.eq("同一天同一来源是覆盖而非叠加", int(rows), 1)
    t.eq("覆盖后读到最新区间", db.cached_busy(bid, "2026-11-27")["busy"][0]["end"], start + 60)
    db.cache_busy(bid, "2026-11-27", busy, source="local_mask", ttl_seconds=600)
    t.eq("不同来源各自成行", int(db.conn.execute(
        "SELECT COUNT(*) FROM calendar_cache WHERE bot_id = ? AND day = ?",
        (bid, "2026-11-27")).fetchone()[0]), 2)
    t.eq("TTL 到期后不再命中", db.cached_busy(bid, "2026-11-27", now=time.time() + 10000), None)
    t.raises("拒绝畸形日期", LedgerError, db.cache_busy, bid, "2026-1-9", busy)
    t.raises("拒绝不存在的日历日", LedgerError, db.cache_busy, bid, "2026-13-99", busy)
    t.raises("拒绝非日期串", LedgerError, db.cache_busy, bid, "today", busy)
    purged = db.purge_calendar_cache(now=time.time() + 10000)
    t.check("清掉全部到期缓存", purged >= 2, str(purged))
    t.eq("清理后读不到任何缓存", db.cached_busy(bid, "2026-11-27", now=time.time() + 10000), None)

    # -------------------------------------------------------------- 汇总快照
    snap = db.agent_snapshot(bid)
    t.eq("快照包含四块控制台数据", sorted(k for k in snap if k != "recent"),
         ["funnel", "guest_links", "negotiations", "proposals"])
    t.check("快照给出最近审计", len(snap["recent"]) >= 1, str(len(snap["recent"])))
    t.eq("快照的提案统计与单查一致", snap["proposals"]["totals"], db.proposal_stats(bid)["totals"])
    t.eq("全量快照也可用", sorted(db.agent_snapshot()["funnel"]), ["errors", "stages"])

    # ------------------------------------------------------------------ 级联删除
    db.delete_bot(bid, hard=True)
    for table in AGENT_TABLES:
        left = int(db.conn.execute(f"SELECT COUNT(*) FROM {table} WHERE bot_id = ?", (bid,)).fetchone()[0])
        t.eq(f"硬删除后 {table} 不再残留", left, 0)
    t.eq("别的 Bot 的提案不受级联影响", int(db.conn.execute(
        "SELECT COUNT(*) FROM agent_proposals WHERE bot_id = ?", (obid,)).fetchone()[0]) >= 1, True)


def group_agent_console(test: SelfTest, h: Harness) -> None:
    """控制台三块新面板的数据面：``/api/agent/*`` 的鉴权、校验、真实读写与访客链接闭环。

    这一组只走 HTTP —— 面板调的就是这些路由；路由背后的账本、引擎、节点桥与门户已各自
    成组。日历节点用注入式假传输，整组一个真实 socket 都不会开。
    """
    t = test
    from .selftest_node import FakeNode  # noqa: PLC0415 - 它反向 import 本模块，顶层互 import 会成环

    base = h.stack(
        tag="agent-console",
        GUEST_PUBLIC_BASE_URL="https://book.popopx.test",
        MAC_NODE_ENABLED="1",
        MAC_NODE_TOKEN="self-test-node-token",
    )
    node = FakeNode()
    node.on(HEALTH_PATH, (200, {"ok": True, "service": "PopopxMacNode", "loopback": True}))
    node.on(SNAPSHOT_PATH, (200, {"ok": True, "viewers": 1}))
    node.on(ACTION_PROPOSALS, (200, {"ok": True, "proposalId": "ppx-pr-1", "approvalReceipt": "r1",
                                     "calendarWritten": False}))
    node.on("/approve", (200, {"ok": True, "calendarWritten": True, "state": "executed",
                               "eventIdentifier": "ppx-bk-9", "sequence": 2}))
    svc = RecordingServices()
    # 面板路由读的是 stack.agent：换成带注入传输的运行时，「确认」才会真的打到假节点。
    base.agent = AgentRuntime(db=base.db, settings=base.settings, sender=build_sender(svc), node_transport=node)
    c, _ = h.client(base)
    a = h.auth()
    api = AGENT_API_PREFIX
    bid = str(base.db.create_bot("console", 5470, display_name="面板Bot")["id"])
    obid = str(base.db.create_bot("consoleother", 5471)["id"])
    peer_addr = "ma_pQ7Zk2mVx3rN8sT1uW6xY7zA8bC9dE0f@smp1.popopx.test"
    # 默认时区跟随本机，不写死：面板断言只要求「读回的就是默认那一份」。
    default_prefs = c.get(f"{api}/prefs/{bid}", headers=a).json()
    default_zone = default_prefs["preferences"]["timezone"]

    # ------------------------------------------------------------------ 鉴权
    unauth = c.get(f"{api}/summary")
    t.eq("未鉴权访问管理面被拒", unauth.status_code, 401)
    t.eq("401 走错误封套", sorted(unauth.json()["detail"]), ["description", "error_code", "ok"])
    t.eq("错误 token 同样被拒", c.get(f"{api}/summary", headers={"X-Studio-Token": "nope"}).status_code, 401)
    t.eq("管理面八条只读路由的返回码",
         [c.get(f"{api}/{name}", headers=a).status_code for name in
          ("summary", "engine", "peers", "proposals", "negotiations", "audit", "guest/links", "node")],
         [200, 200, 400, 200, 200, 200, 200, 200])
    t.eq("peers 是因为缺 bot_id 才报错",
         c.get(f"{api}/peers", headers=a).json()["detail"]["description"], "缺少 bot_id")

    # ------------------------------------------------------------------ 摘要
    s = c.get(f"{api}/summary", headers=a).json()
    t.eq("摘要六段齐全", sorted(s), ["funnel", "guest", "node", "ok", "runtime", "stages"])
    t.eq("面板的阶段下拉与账本同源", s["stages"], list(AUDIT_STAGES))
    t.eq("审计阶段共九段", len(AUDIT_STAGES), 9)
    t.eq("漏斗两段", sorted(s["funnel"]), ["errors", "stages"])
    t.eq("运行时点明插件 id", s["runtime"]["plugin_id"], "personal_agent")
    t.eq("运行时七段", sorted(s["runtime"]),
         ["counts", "errors", "mac_node", "needle", "peers", "plugin_id", "reasoner"])
    t.eq("运行时给出六个计数", sorted(s["runtime"]["counts"]),
         ["a2a", "approvals", "cards", "errors", "handled", "ics"])
    t.eq("摘要里的节点段与 /node 同源", s["node"], c.get(f"{api}/node", headers=a).json()["node"])
    t.eq("节点桥已开启", s["node"]["enabled"], True)
    t.eq("节点桥锁定回环", s["node"]["loopback"], True)
    t.eq("节点桥不跟随重定向", s["node"]["follow_redirects"], False)
    t.eq("节点桥只报「令牌在场」", s["node"]["token_present"], True)
    t.eq("节点桥的令牌是掩码", s["node"]["token"], "***")
    t.check("摘要整份不外泄节点令牌", "self-test-node-token" not in json.dumps(s, ensure_ascii=False),
            str(s["node"])[:160])
    t.eq("访客前缀", s["guest"]["prefix"], LINK_PATH_PREFIX)
    t.eq("访客基址取自配置", s["guest"]["public_base"], "https://book.popopx.test")
    t.eq("基址可用时不给原因", s["guest"]["reason"], "")
    t.eq("未点名 Bot 时不带 bot 段", "bot" not in s, True)
    named = c.get(f"{api}/summary", headers=a, params={"bot_id": bid}).json()["bot"]
    t.eq("点名 Bot 后给出十段", sorted(named),
         ["bot_id", "enabled", "links", "locale", "negotiations", "owner_chat", "peers", "preferences",
          "proposals", "timezone"])
    t.eq("Bot 默认启用替身", named["enabled"], True)
    t.eq("未配置主人会话时为空", named["owner_chat"], "")
    t.eq("未配置语种回退后台语种", named["locale"], "en")
    t.eq("未配置时区等于默认时区", named["timezone"], default_zone)
    t.eq("摘要的偏好段就是 summary", named["preferences"], default_prefs["summary"])
    t.eq("陌生 Bot 的摘要不报错", c.get(f"{api}/summary", headers=a, params={"bot_id": "nope"}).status_code, 200)

    # ------------------------------------------------------------------ 引擎
    eng = c.get(f"{api}/engine", headers=a).json()
    t.eq("引擎面四段", sorted(eng), ["needle", "ok", "reasoner", "tools"])
    t.eq("工具清单与抽取器同源", eng["tools"], list(TOOL_NAMES))
    t.eq("毫秒级抽取器只挂五个工具", len(eng["tools"]), 5)
    t.eq("工具命名空间只有两个", len({name.rsplit(".", 1)[0] for name in eng["tools"]}), 2)
    needle = eng["needle"]
    t.eq("面板刚打开时引擎尚未驻留", needle["weights_path"], "")
    t.eq("未驻留时资产字段为空", [needle["asset_ok"], needle["asset_bytes"], needle["asset_sha256"]],
         [False, 0, ""])
    t.eq("引擎名只有两种取值", needle["engine"] in (ENGINE_NEEDLE, ENGINE_FALLBACK), True)
    t.eq("降级标记与引擎名一致", needle["degraded"], needle["engine"] != ENGINE_NEEDLE)
    t.eq("推理引擎未开启", eng["reasoner"]["enabled"], False)
    t.eq("推理引擎未开启即不可用", eng["reasoner"]["usable"], False)
    t.eq("未配推理 Key 时如实标注", eng["reasoner"]["api_key_configured"], False)
    t.eq("非法引擎动作被拒", c.post(f"{api}/engine", headers=a, json={"action": "spin"}).status_code, 400)
    t.eq("动作错误提示列出三个取值",
         c.post(f"{api}/engine", headers=a, json={"action": "spin"}).json()["description"],
         "action 只能是 load / unload / reload")
    t.eq("缺请求体按非法动作处理", c.post(f"{api}/engine", headers=a).status_code, 400)
    reload = c.post(f"{api}/engine", headers=a, json={"action": "reload"}).json()
    t.eq("重载回显动作", reload["action"], "reload")
    loaded = reload["needle"]
    t.eq("内置权重通过完整性校验", loaded["asset_ok"], True)
    t.eq("权重字节数可读", loaded["asset_bytes"] > 0, True)
    t.eq("权重不超过内置上限", loaded["asset_bytes"] <= NEEDLE_MAX_WEIGHT_BYTES, True)
    t.eq("校验和是 sha256 十六进制", len(loaded["asset_sha256"]), 64)
    t.eq("校验和与内置清单同源", loaded["asset_sha256"], load_manifest().weights.sha256)
    t.eq("重载后指向内置权重文件", loaded["weights_path"].endswith(NEEDLE_WEIGHT_FILE), True)
    t.eq("重载后仍是已校验的资产", reload["needle"]["asset_ok"], True)
    unload = c.post(f"{api}/engine", headers=a, json={"action": "unload"}).json()
    t.eq("卸载后回到确定性路径", unload["needle"]["degraded"], True)
    t.eq("卸载后引擎名如实降级", unload["engine"], ENGINE_FALLBACK)
    t.eq("卸载后不再有已加载标记", c.get(f"{api}/engine", headers=a).json()["needle"]["degraded"], True)
    t.eq("重新加载可用", c.post(f"{api}/engine", headers=a, json={"action": "load"}).status_code, 200)
    t.eq("重新加载后恢复原引擎", c.post(f"{api}/engine", headers=a,
                           json={"action": "reload"}).json()["needle"]["asset_ok"], True)

    # ---------------------------------------------------------------- 试路由
    t.eq("空文本被拒", c.post(f"{api}/extract", headers=a, json={"text": "   "}).status_code, 400)
    t.eq("缺请求体被拒", c.post(f"{api}/extract", headers=a).status_code, 400)
    ext = c.post(f"{api}/extract", headers=a,
                 json={"text": "你明天下午有空吗？我们约 30 分钟。", "bot_id": bid}).json()
    t.eq("试路由五段", sorted(ext), ["bot_id", "extraction", "locale", "ok", "timezone"])
    t.eq("试路由回显 Bot", ext["bot_id"], bid)
    t.eq("试路由语种已归一", ext["locale"] in LOCALES, True)
    t.eq("未显式给时区时取该 Bot 的偏好", ext["timezone"], default_zone)
    t.eq("抽取结果七段", sorted(ext["extraction"]),
         ["calls", "degraded", "engine", "error", "intent", "latency_ms", "text"])
    t.eq("试路由抽出问空档工具", [row["name"] for row in ext["extraction"]["calls"]][:1],
         ["calendar.get_availability"])
    t.eq("抽出的工具全在清单内",
         [row["name"] for row in ext["extraction"]["calls"] if row["name"] not in TOOL_NAMES], [])
    t.eq("毫秒级延迟有上报", ext["extraction"]["latency_ms"] >= 0.0, True)
    t.eq("抽取不报错", ext["extraction"]["error"], "")
    t.eq("试路由不写提案", len(base.db.list_proposals(bid)), 0)
    t.eq("试路由不发消息", len(svc.sends), 0)
    t.eq("试路由不调用日历节点", len(node.calls), 0)
    zone = c.post(f"{api}/extract", headers=a,
                  json={"text": "are you free tomorrow at 3pm?", "timezone": "Europe/Berlin",
                        "locale": "de", "bot_id": bid}).json()
    t.eq("显式时区优先于偏好", zone["timezone"], "Europe/Berlin")
    t.eq("显式语种优先于偏好", zone["locale"], "de")
    t.eq("非法语种回退而不报错",
         c.post(f"{api}/extract", headers=a, json={"text": "hi", "locale": "ko"}).json()["locale"] in LOCALES,
         True)
    t.eq("不点名 Bot 也能试路由", c.post(f"{api}/extract", headers=a,
                          json={"text": "hi"}).json()["bot_id"], "")
    t.eq("不点名 Bot 时不给时区", c.post(f"{api}/extract", headers=a,
                          json={"text": "hi"}).json()["timezone"], "")
    long = c.post(f"{api}/extract", headers=a, json={"text": "周" * 5000}).json()
    t.eq("超长文本被截到 2000 字", len(long["extraction"]["text"]), 2000)

    # ------------------------------------------------------------------ 偏好
    t.eq("偏好读回四段", sorted(default_prefs), ["bot_id", "ok", "preferences", "summary"])
    t.eq("默认只在工作日排期", default_prefs["preferences"]["working_hours"]["days"], [1, 2, 3, 4, 5])
    t.eq("默认工作时段 09:00-18:00",
         [default_prefs["preferences"]["working_hours"]["start"],
          default_prefs["preferences"]["working_hours"]["end"]], ["09:00", "18:00"])
    t.eq("默认午休受保护", default_prefs["preferences"]["buffers"]["protect_lunch"], True)
    t.eq("默认任何落地都要主人确认", default_prefs["preferences"]["negotiation"]["require_owner_approval"], True)
    t.eq("默认单场不超过两小时", default_prefs["preferences"]["meeting"]["max_meeting_minutes"], 120)
    t.eq("默认协商最多三轮", default_prefs["preferences"]["negotiation"]["rounds"], 3)
    t.eq("默认两段屏蔽期", len(default_prefs["preferences"]["blocked_periods"]), 2)
    t.eq("摘要十五段", len(default_prefs["summary"]), 15)
    t.eq("摘要给出文件权限", default_prefs["summary"]["mode"], "0o600")
    t.eq("摘要不回显关键词原文",
         [term for term in ("roadmap", "合同", "复盘") if term in json.dumps(default_prefs["summary"])], [])
    t.eq("陌生 Bot 的偏好读不到", c.get(f"{api}/prefs/nope", headers=a).status_code, 404)
    t.eq("空 bot_id 的偏好读不到", c.get(f"{api}/prefs/", headers=a).status_code, 404)
    t.eq("陌生 Bot 的偏好写不进", c.post(f"{api}/prefs/nope", headers=a, json={"locale": "de"}).status_code, 404)
    t.eq("未知顶层键被拒", c.post(f"{api}/prefs/{bid}", headers=a, json={"hacker": 1}).status_code, 400)
    t.eq("非法语气被拒", c.post(f"{api}/prefs/{bid}", headers=a,
                    json={"copy": {"tone": "shouty"}}).status_code, 400)
    t.eq("非法工作日被拒", c.post(f"{api}/prefs/{bid}", headers=a,
                     json={"working_hours": {"days": [1, 9]}}).status_code, 400)
    t.eq("空工作日被拒", c.post(f"{api}/prefs/{bid}", headers=a,
                   json={"working_hours": {"days": []}}).status_code, 400)
    t.eq("非法钟点被拒", c.post(f"{api}/prefs/{bid}", headers=a,
                   json={"working_hours": {"start": "25:00"}}).status_code, 400)
    t.eq("非数字钟点被拒", c.post(f"{api}/prefs/{bid}", headers=a,
                    json={"working_hours": {"start": "9am"}}).status_code, 400)
    t.eq("起止颠倒被拒", c.post(f"{api}/prefs/{bid}", headers=a,
                   json={"working_hours": {"start": "18:00", "end": "09:00"}}).status_code, 400)
    t.eq("未知屏蔽期字段被拒", c.post(f"{api}/prefs/{bid}", headers=a,
                        json={"blocked_periods": [{"id": "x", "nope": 1}]}).status_code, 400)
    t.eq("越界关键词权重被拒", c.post(f"{api}/prefs/{bid}", headers=a,
                         json={"keywords": {"boost": [{"term": "roadmap", "weight": 99}]}}).status_code, 400)
    t.eq("非法时区被拒", c.post(f"{api}/prefs/{bid}", headers=a,
                  json={"timezone": "Nowhere/Zone"}).status_code, 400)
    t.eq("非法语种被拒", c.post(f"{api}/prefs/{bid}", headers=a, json={"locale": "ko"}).status_code, 400)
    t.check("校验失败带字段名", "locale" in c.post(f"{api}/prefs/{bid}", headers=a,
                              json={"locale": "ko"}).json()["description"], "")
    t.eq("被拒的写入不落盘", c.get(f"{api}/prefs/{bid}", headers=a).json()["preferences"]["timezone"],
         default_zone)
    wrapped = c.post(f"{api}/prefs/{bid}", headers=a,
                     json={"preferences": {"timezone": "Europe/Berlin", "copy": {"tone": "formal"}}}).json()
    t.eq("包一层 preferences 也能写", wrapped["preferences"]["timezone"], "Europe/Berlin")
    t.eq("语气写进偏好", wrapped["preferences"]["copy"]["tone"], "formal")
    flat = c.post(f"{api}/prefs/{bid}", headers=a, json={"locale": "de"}).json()
    t.eq("平铺补丁同样可写", flat["preferences"]["locale"], "de")
    t.eq("补丁是深合并而不是覆盖", flat["preferences"]["copy"]["tone"], "formal")
    t.eq("写后读回一致", c.get(f"{api}/prefs/{bid}", headers=a).json()["preferences"]["timezone"],
         "Europe/Berlin")
    t.eq("摘要跟着写入更新", c.get(f"{api}/prefs/{bid}", headers=a).json()["summary"]["timezone"],
         "Europe/Berlin")
    prefs_file = base.agent.preferences.path_for(bid)
    t.eq("偏好落在该 Bot 的隔离目录", prefs_file.parent, base.settings.agent_dir(bid))
    t.eq("偏好文件名固定", prefs_file.name, PREFERENCES_FILENAME)
    t.eq("偏好文件已生成", prefs_file.is_file(), True)
    t.eq("偏好目录权限 0700", mode_of(prefs_file.parent), SECURE_DIR_MODE)
    t.eq("偏好文件权限 0600", mode_of(prefs_file), SECURE_FILE_MODE)
    reset = c.post(f"{api}/prefs/{bid}/reset", headers=a).json()
    t.eq("重置回到默认时区", reset["preferences"]["timezone"], default_zone)
    t.eq("重置清空语种覆盖", reset["preferences"]["locale"], "")
    t.eq("重置回到默认语气", reset["preferences"]["copy"]["tone"], "concise")
    t.eq("重置后读回也是默认", c.get(f"{api}/prefs/{bid}", headers=a).json()["preferences"]["timezone"],
         default_zone)
    t.eq("陌生 Bot 的重置被拒", c.post(f"{api}/prefs/nope/reset", headers=a).status_code, 404)
    t.eq("两个 Bot 的偏好互不影响",
         c.get(f"{api}/prefs/{obid}", headers=a).json()["preferences"]["timezone"], default_zone)
    t.ne("每个 Bot 各自一份文件", base.agent.preferences.path_for(obid), prefs_file)

    # ------------------------------------------------------------------ 对端
    t.eq("缺 bot_id 的配对被拒", c.post(f"{api}/peers", headers=a,
                          json={"identity": peer_addr}).status_code, 400)
    t.eq("陌生 Bot 的配对被拒", c.post(f"{api}/peers", headers=a,
                         json={"bot_id": "nope", "identity": peer_addr}).status_code, 404)
    t.eq("空身份无法配对", c.post(f"{api}/peers", headers=a,
                    json={"bot_id": bid, "identity": "  "}).status_code, 400)
    t.eq("非法会话引用无法配对", c.post(f"{api}/peers", headers=a,
                          json={"bot_id": bid, "identity": peer_addr, "chat": "nope!"}).status_code, 400)
    t.eq("非法引用的错误提示点名原值",
         "nope!" in c.post(f"{api}/peers", headers=a,
                           json={"bot_id": bid, "identity": peer_addr, "chat": "nope!"}).json()["description"],
         True)
    paired = c.post(f"{api}/peers", headers=a,
                    json={"bot_id": bid, "identity": peer_addr, "label": "老张", "chat": "@9"}).json()
    t.eq("配对响应三段", sorted(paired), ["bot_id", "ok", "peer"])
    t.eq("配对五段视图", sorted(paired["peer"]),
         ["chat", "derived", "identity", "label", "wire_identity"])
    t.eq("配对保留真实地址", paired["peer"]["identity"], peer_addr)
    t.eq("帧内身份换成映射 token", paired["peer"]["wire_identity"][:4], "ppx-")
    t.eq("映射后的身份只剩 id 字符",
         [ch for ch in paired["peer"]["wire_identity"] if not (ch.isalnum() or ch in "-_")], [])
    t.eq("帧内身份与编排层映射一致", paired["peer"]["wire_identity"], wire_identity(peer_addr))
    t.eq("未配密钥时标注派生", paired["peer"]["derived"], True)
    t.eq("配对响应不含密钥字段", "key" in paired["peer"], False)
    t.eq("配对带上主人会话", paired["peer"]["chat"], "@9")
    listed = c.get(f"{api}/peers", headers=a, params={"bot_id": bid}).json()
    t.eq("列表三段", sorted(listed), ["bot_id", "ok", "peers", "self_identity"])
    t.eq("列表含刚配对的一条", len(listed["peers"]), 1)
    t.check("列表带本方身份", bool(listed["self_identity"]), str(listed["self_identity"])[:60])
    t.check("列表不含会话密钥", "key" not in json.dumps(listed["peers"]), str(listed["peers"])[:160])
    t.eq("别的 Bot 列不到这个对端", c.get(f"{api}/peers", headers=a, params={"bot_id": obid}).json()["peers"], [])
    peers_file = base.agent.peers_path(bid)
    t.eq("配对表落在 Bot 隔离目录", peers_file.parent, base.settings.agent_dir(bid))
    t.eq("配对表权限 0600", mode_of(peers_file), SECURE_FILE_MODE)
    raw_peers = json.loads(peers_file.read_text(encoding="utf-8"))
    t.eq("配对表四段", sorted(raw_peers), ["bot_id", "peers", "updated_at", "version"])
    t.eq("配对表里密钥是空串", raw_peers["peers"][0]["key"], "")
    t.check("配对表保留真实地址", peer_addr in peers_file.read_text(encoding="utf-8"), peer_addr[:24])
    removed = c.post(f"{api}/peers/remove", headers=a, json={"bot_id": bid, "identity": peer_addr}).json()
    t.eq("移除已配对返回真", removed["removed"], True)
    t.eq("再移除同一个返回假", c.post(f"{api}/peers/remove", headers=a,
                         json={"bot_id": bid, "identity": peer_addr}).json()["removed"], False)
    t.eq("移除后列表为空", c.get(f"{api}/peers", headers=a, params={"bot_id": bid}).json()["peers"], [])
    t.eq("陌生 Bot 的移除被拒", c.post(f"{api}/peers/remove", headers=a,
                          json={"bot_id": "nope", "identity": peer_addr}).status_code, 404)
    t.eq("空身份的移除返回假", c.post(f"{api}/peers/remove", headers=a,
                        json={"bot_id": bid, "identity": ""}).json()["removed"], False)
    c.post(f"{api}/peers", headers=a, json={"bot_id": bid, "identity": peer_addr, "chat": "@9"})

    # ------------------------------------------------------------ 提案与决定
    now = time.time()
    declined = base.db.create_proposal(
        bid, "create", source="operator", chat_type="direct", chat_ref="@9", timezone="Asia/Shanghai",
        start_ts=now + 3600, end_ts=now + 5400, summary="面板否决")
    t.eq("新建提案是 pending", declined["status"], "pending")
    t.eq("提案号有前缀", declined["proposal_id"][:3], "pr_")
    bad = c.post(f"{api}/proposals/{declined['proposal_id']}/decision", headers=a,
                 json={"decision": "teleport"})
    t.eq("非法决定被拒", bad.status_code, 400)
    t.eq("决定错误提示列出三个取值", bad.json()["description"], "decision 只能是 approve / decline / alternative")
    t.eq("非法决定不改状态", base.db.get_proposal(declined["proposal_id"])["status"], "pending")
    t.eq("非法决定一个节点请求都不发", len(node.calls), 0)
    missing = c.post(f"{api}/proposals/pr_nope/decision", headers=a, json={"decision": "approve"})
    t.eq("不存在的提案返回 404", missing.status_code, 404)
    t.eq("404 走错误封套", sorted(missing.json()), ["description", "error_code", "ok"])
    t.eq("不存在的提案不发消息", len(svc.sends), 0)
    off = c.post(f"{api}/proposals/{declined['proposal_id']}/decision", headers=a,
                 json={"decision": "decline"}).json()
    t.eq("控制台可否决提案", off["status"], "declined")
    t.check("否决给出主人可读的回复", bool(off["reply"].strip()), repr(off["reply"])[:80])
    t.eq("否决不触碰日历节点", len(node.calls), 0)
    t.eq("否决写进 lifecycle 审计",
         [row["event"] for row in base.db.recent_negotiations(bid, stage="lifecycle")][:1], ["declined"])
    revived = c.post(f"{api}/proposals/{declined['proposal_id']}/decision", headers=a,
                     json={"decision": "approve"}).json()
    t.eq("终态提案不会被复活", revived["status"], "declined")
    t.eq("复活尝试不写日历", node.count(ACTION_PROPOSALS), 0)
    t.eq("复活尝试记一条拒绝审计",
         any(row["stage"] == "mac_node" and row["level"] == "warn"
             for row in base.db.recent_negotiations(bid, stage="mac_node")), True)
    sends_before_land = len(svc.sends)
    landed = base.db.create_proposal(bid, "create", source="guest", chat_type="direct", chat_ref="@9",
                                     timezone="Asia/Shanghai", start_ts=now + 7200, end_ts=now + 9000,
                                     summary="面板落地")
    approved = c.post(f"{api}/proposals/{landed['proposal_id']}/decision", headers=a,
                      json={"decision": "approve"}).json()
    t.eq("确认后提案落地", approved["status"], "approved")
    t.eq("确认打了提案接口", node.count(ACTION_PROPOSALS), 1)
    t.eq("确认打了批准接口", node.count("/approve"), 1)
    t.eq("批准带上节点回执", node.last("/approve")["payload"], {"receipt": "r1"})
    t.eq("提案接口带上标题", node.last(ACTION_PROPOSALS)["payload"]["title"], "面板落地")
    t.eq("提案接口带上 ISO 起止",
         sorted(key for key in node.last(ACTION_PROPOSALS)["payload"] if key.endswith("Iso")),
         ["endIso", "startIso"])
    t.eq("确认带上节点令牌", node.last("/approve")["headers"][TOKEN_HEADER], "self-test-node-token")
    t.eq("节点事件号写回账本", approved["proposal"]["node_event_id"], "ppx-bk-9")
    t.eq("确认后审批计数增长", base.agent.status()["counts"]["approvals"], 1)
    ics_rows = [row for row in svc.sends[sends_before_land:] if str(row.get("file_path", "")).endswith(".ics")]
    t.eq("确认后只发一条附件", len(ics_rows), 1)
    t.eq("邀请带插件署名", ics_rows[0]["plugin_id"], "personal_agent")
    t.eq("邀请发到提案里的会话", [ics_rows[0]["chat_type"], ics_rows[0]["chat_id"]], ["direct", 9])
    invite = Path(ics_rows[0]["file_path"])
    t.eq("邀请落在该 Bot 的 invites 目录", invite.parent.name, "invites")
    t.eq("邀请目录权限 0700", mode_of(invite.parent), 0o700)
    t.eq("邀请文件权限 0600", mode_of(invite), SECURE_FILE_MODE)
    t.contains("邀请是真 .ics", invite.read_text(encoding="utf-8"), "BEGIN:VCALENDAR")
    t.eq("账本记下 .ics 路径", base.db.get_proposal(landed["proposal_id"])["ics_path"], str(invite))
    t.eq("ics 计数增长", base.agent.status()["counts"]["ics"], 1)
    t.eq("确认写进 mac_node 审计",
         [row["event"] for row in base.db.recent_negotiations(bid, stage="mac_node")][:1], ["approve"])
    alt = base.db.create_proposal(bid, "reschedule", source="a2a", chat_ref="@9", summary="面板改期",
                                  timezone="Asia/Shanghai", start_ts=now + 10800, end_ts=now + 12600)
    other = c.post(f"{api}/proposals/{alt['proposal_id']}/decision", headers=a,
                   json={"decision": "alternative"}).json()
    t.eq("改选别的时间置为 superseded", other["status"], "superseded")
    t.eq("改选不写日历", node.count(ACTION_PROPOSALS), 1)
    t.eq("改选不再发附件", len([row for row in svc.sends if row.get("file_path")]), 1)
    t.eq("改选的回复是空话术", other["reply"], "")
    again = c.post(f"{api}/proposals/{alt['proposal_id']}/decision", headers=a, json={}).json()
    t.eq("缺 decision 字段按确认处理", again["status"], "superseded")
    t.eq("已改选的提案不再落地", node.count(ACTION_PROPOSALS), 1)
    rows = c.get(f"{api}/proposals", headers=a, params={"bot_id": bid}).json()
    t.eq("提案列表三段", sorted(rows), ["ok", "proposals", "stats"])
    t.eq("列表含全部三条", len(rows["proposals"]), 3)
    t.eq("统计按状态汇总 declined", rows["stats"]["totals"]["declined"], 1)
    t.eq("统计按状态汇总 approved", rows["stats"]["totals"]["approved"], 1)
    t.eq("统计按状态汇总 superseded", rows["stats"]["totals"]["superseded"], 1)
    t.eq("统计把动作与状态拆开计数", "create:approved" in rows["stats"]["breakdown"], True)
    t.eq("按状态筛提案", [row["proposal_id"] for row in
                   c.get(f"{api}/proposals", headers=a,
                         params={"bot_id": bid, "status": "approved"}).json()["proposals"]],
         [landed["proposal_id"]])
    t.eq("非法状态筛出空列表", c.get(f"{api}/proposals", headers=a,
                        params={"bot_id": bid, "status": "zombie"}).json()["proposals"], [])
    t.eq("limit 收窄列表", len(c.get(f"{api}/proposals", headers=a,
                        params={"bot_id": bid, "limit": 1}).json()["proposals"]), 1)
    t.eq("超大 limit 被夹到上限", len(c.get(f"{api}/proposals", headers=a,
                             params={"bot_id": bid, "limit": 99999}).json()["proposals"]), 3)
    t.eq("不点名 Bot 也能列提案",
         len(c.get(f"{api}/proposals", headers=a).json()["proposals"]) >= 3, True)
    t.eq("陌生 Bot 的列表为空", c.get(f"{api}/proposals", headers=a,
                       params={"bot_id": "nope"}).json()["proposals"], [])
    t.eq("陌生 Bot 的统计仍是六档", len(c.get(f"{api}/proposals", headers=a,
                              params={"bot_id": "nope"}).json()["stats"]["totals"]), 6)

    # ------------------------------------------------------------------ 协商
    t.eq("缺对端起手被拒", c.post(f"{api}/negotiate", headers=a, json={"bot_id": bid}).status_code, 400)
    t.eq("陌生 Bot 起手被拒", c.post(f"{api}/negotiate", headers=a,
                       json={"bot_id": "nope", "peer": peer_addr}).status_code, 404)
    calls_before_nego = len(node.calls)
    avail_before_nego = node.count(ACTION_AVAILABILITY)
    sends_before_nego = len(svc.sends)
    start = c.post(f"{api}/negotiate", headers=a,
                   json={"bot_id": bid, "peer": peer_addr, "duration_minutes": 45, "days": 3}).json()
    t.eq("起手回显 Bot 与对端", [start["bot_id"], start["peer"]], [bid, peer_addr])
    t.eq("起手先现算自己的空档", node.count(ACTION_AVAILABILITY) > avail_before_nego, True)
    t.eq("节点没给出忙闲就不起手", start["status"], "no_slots")
    t.check("起手给出失败原因", bool(start["reason"]), str(start)[:160])
    t.eq("起手不建协商记录", base.db.list_negotiations(bid), [])
    t.eq("起手不发消息", len(svc.sends), sends_before_nego)
    t.eq("起手不产生 5xx", c.post(f"{api}/negotiate", headers=a,
                       json={"bot_id": bid, "peer": peer_addr}).status_code, 200)
    t.eq("对端也可以写会话引用", c.post(f"{api}/negotiate", headers=a,
                          json={"bot_id": bid, "peer": "@9"}).json()["peer"], "@9")
    nego = base.db.create_negotiation(bid, peer_addr, channel="a2a", owner_timezone="Asia/Shanghai",
                                      peer_timezone="Europe/Berlin", window_start=now,
                                      window_end=now + 86400, duration_minutes=60, expires_at=now + 7200)
    nlist = c.get(f"{api}/negotiations", headers=a, params={"bot_id": bid}).json()
    t.eq("协商列表三段", sorted(nlist), ["negotiations", "ok", "stats"])
    t.eq("列表含刚建的协商", [row["negotiation_id"] for row in nlist["negotiations"]], [nego["negotiation_id"]])
    t.eq("协商记录的通道", nlist["negotiations"][0]["channel"], "a2a")
    t.eq("协商记录两侧时区",
         [nlist["negotiations"][0]["owner_timezone"], nlist["negotiations"][0]["peer_timezone"]],
         ["Asia/Shanghai", "Europe/Berlin"])
    t.eq("新建协商是 open", nlist["negotiations"][0]["status"], "open")
    t.eq("协商记录原样保存对端引用", nlist["negotiations"][0]["peer_identity"], peer_addr)
    t.check("协商统计给出总量", nlist["stats"]["total"] >= 1, str(nlist["stats"])[:120])
    t.eq("按状态筛协商命中自己", [row["negotiation_id"] for row in
                   c.get(f"{api}/negotiations", headers=a,
                         params={"bot_id": bid, "status": "open"}).json()["negotiations"]],
         [nego["negotiation_id"]])
    t.eq("按别的状态筛为空", c.get(f"{api}/negotiations", headers=a,
                    params={"bot_id": bid, "status": "converged"}).json()["negotiations"], [])
    t.eq("陌生 Bot 的协商列表为空",
         c.get(f"{api}/negotiations", headers=a, params={"bot_id": "nope"}).json()["negotiations"], [])

    # ------------------------------------------------------------------ 审计
    audit = c.get(f"{api}/audit", headers=a, params={"bot_id": bid}).json()
    t.eq("审计三段", sorted(audit), ["audit", "funnel", "ok"])
    t.check("审计有内容", len(audit["audit"]) >= 6, str(len(audit["audit"])))
    t.eq("审计行十三段", sorted(audit["audit"][0]),
         ["bot_id", "chat_ref", "data", "detail", "event", "id", "latency_ms", "level", "link_id",
          "negotiation_id", "proposal_id", "stage", "ts"])
    t.eq("审计阶段全部落在白名单内", sorted({row["stage"] for row in audit["audit"]} - set(AUDIT_STAGES)), [])
    t.eq("审计级别不越出账本白名单", sorted({row["level"] for row in audit["audit"]} - set(AUDIT_LEVELS)), [])
    t.check("节点缺路由的失败记为 error",
            any(row["level"] == "error" for row in audit["audit"]),
            str(sorted({row["level"] for row in audit["audit"]})))
    t.eq("审计按时间倒序",
         [row["ts"] for row in audit["audit"]] == sorted((row["ts"] for row in audit["audit"]), reverse=True),
         True)
    t.eq("审计 data 已解码为对象", isinstance(audit["audit"][0]["data"], dict), True)
    t.check("审计带上提案号", any(row["proposal_id"] for row in audit["audit"]), str(audit["audit"][0])[:160])
    t.eq("漏斗的错误段是字典", isinstance(audit["funnel"]["errors"], dict), True)
    t.eq("漏斗的阶段计数非负", all(int(v) >= 0 for v in audit["funnel"]["stages"].values()), True)
    t.check("漏斗能看到 mac_node 这一段", int(audit["funnel"]["stages"].get("mac_node", 0)) >= 2,
            str(audit["funnel"]["stages"])[:160])
    t.eq("非法 stage 被拒", c.get(f"{api}/audit", headers=a, params={"stage": "bogus"}).status_code, 400)
    t.eq("stage 错误提示列出全部阶段",
         c.get(f"{api}/audit", headers=a, params={"stage": "bogus"}).json()["description"],
         f"stage 只能是 {'/'.join(AUDIT_STAGES)}")
    for stage in AUDIT_STAGES:
        got = c.get(f"{api}/audit", headers=a, params={"bot_id": bid, "stage": stage}).json()["audit"]
        t.eq(f"按 {stage} 筛审计只出该阶段", sorted({row["stage"] for row in got} - {stage}), [])
    t.eq("按级别筛审计", sorted({row["level"] for row in
                       c.get(f"{api}/audit", headers=a, params={"level": "warn"}).json()["audit"]}), ["warn"])
    t.eq("非法级别筛出空列表", c.get(f"{api}/audit", headers=a,
                        params={"level": "verbose"}).json()["audit"], [])
    t.eq("按提案筛审计", sorted({row["proposal_id"] for row in
                      c.get(f"{api}/audit", headers=a,
                            params={"proposal_id": landed["proposal_id"]}).json()["audit"]}),
         [landed["proposal_id"]])
    t.eq("陌生 Bot 的审计为空", c.get(f"{api}/audit", headers=a, params={"bot_id": "nope"}).json()["audit"], [])
    t.eq("审计 limit 生效", len(c.get(f"{api}/audit", headers=a, params={"limit": 2}).json()["audit"]), 2)
    t.eq("非法 limit 不产生 5xx", c.get(f"{api}/audit", headers=a, params={"limit": "abc"}).status_code, 422)
    t.eq("审计里能看到这次否决", any(row["stage"] == "lifecycle" and row["event"] == "declined"
                        for row in c.get(f"{api}/audit", headers=a,
                                         params={"bot_id": bid}).json()["audit"]), True)

    # -------------------------------------------------------------- 访客链接
    t.eq("缺 bot_id 签发被拒", c.post(f"{api}/guest/links", headers=a, json={}).status_code, 400)
    t.eq("陌生 Bot 签发被拒", c.post(f"{api}/guest/links", headers=a,
                       json={"bot_id": "nope"}).status_code, 404)
    t.eq("零访问额度被夹成一次", c.post(f"{api}/guest/links", headers=a,
                          json={"bot_id": bid, "max_uses": 0}).json()["link"]["max_uses"], 1)
    t.eq("超长时长被夹到上限", c.post(f"{api}/guest/links", headers=a,
                    json={"bot_id": bid, "duration_minutes": 9999}).json()["link"]["duration_minutes"], 480)
    t.eq("非法 ttl 被拒", c.post(f"{api}/guest/links", headers=a,
                   json={"bot_id": bid, "ttl_hours": 0}).status_code, 400)
    t.eq("超长 ttl 被拒", c.post(f"{api}/guest/links", headers=a,
                   json={"bot_id": bid, "ttl_hours": 99999}).status_code, 400)
    t.eq("短于最小存活期被拒", c.post(f"{api}/guest/links", headers=a,
                        json={"bot_id": bid, "ttl_hours": 0.001}).status_code, 400)
    t.eq("非法时区签发被拒", c.post(f"{api}/guest/links", headers=a,
                      json={"bot_id": bid, "timezone": "Nowhere/Zone"}).status_code, 400)
    issued = c.post(f"{api}/guest/links", headers=a,
                    json={"bot_id": bid, "label": "张三", "topic": "项目同步", "max_uses": 2,
                          "duration_minutes": 45, "ttl_hours": 24, "timezone": "Asia/Shanghai",
                          "created_by": "console"}).json()
    t.eq("签发响应三段", sorted(issued), ["bot_id", "link", "ok"])
    link = issued["link"]
    t.eq("签发回六段", sorted(link), ["duration_minutes", "expires_at", "link_id", "max_uses", "token", "url"])
    t.eq("链接 id 有前缀", link["link_id"][:3], "gl_")
    t.eq("签发链接带前缀", link["url"].startswith("https://book.popopx.test" + LINK_PATH_PREFIX), True)
    t.eq("链接尾段就是令牌凭据", link["url"].split(LINK_PATH_PREFIX, 1)[1], link["token"])
    t.check("令牌足够长", len(link["token"]) >= 40, str(len(link["token"])))
    t.eq("ttl 落到过期时间", round(link["expires_at"] - now), 24 * 3600)
    t.eq("时长落到链接", link["duration_minutes"], 45)
    listed_links = c.get(f"{api}/guest/links", headers=a, params={"bot_id": bid}).json()
    t.eq("列表响应五段", sorted(listed_links), ["links", "ok", "prefix", "public_base", "stats"])
    t.eq("列表给出公开前缀", listed_links["prefix"], LINK_PATH_PREFIX)
    t.eq("列表给出公开基址", listed_links["public_base"], "https://book.popopx.test")
    row = [item for item in listed_links["links"] if item["link_id"] == link["link_id"]][0]
    t.eq("列表行十九段视图", len(row), 19)
    t.check("列表行不含完整令牌", "token" not in row, sorted(row))
    t.eq("列表只有掩码指纹", row["token_mask"], link["token"][:TOKEN_MASK_CHARS] + TOKEN_MASK)
    t.check("列表整份不外泄令牌", link["token"] not in json.dumps(listed_links, ensure_ascii=False),
            str(listed_links)[:160])
    t.eq("列表行给出 Bot", row["bot_id"], bid)
    t.eq("列表行给出额度", [row["max_uses"], row["uses"], row["remaining"]], [2, 0, 2])
    t.eq("列表行状态", row["status"], "active")
    t.eq("列表行尚未确认", [row["confirmed"], row["ics_ready"]], [False, False])
    t.eq("列表行带回写主题", row["topic"], "项目同步")
    t.eq("列表统计三段", sorted(listed_links["stats"]), ["active", "total", "visits"])
    t.eq("列表统计与链接条数一致", listed_links["stats"]["total"], 3)
    t.eq("陌生 Bot 的列表为空", c.get(f"{api}/guest/links", headers=a,
                        params={"bot_id": "nope"}).json()["links"], [])
    revealed = c.post(f"{api}/guest/links/{link['link_id']}/url", headers=a, json={"bot_id": bid}).json()
    t.eq("取链接响应三段", sorted(revealed), ["link", "link_id", "ok"])
    t.eq("逐条取回的是同一条链接", revealed["link"]["url"], link["url"])
    t.eq("取回视图比列表行只多一个 url",
         sorted(set(revealed["link"]) - set(row)), ["url"])
    t.eq("取回视图不缺列表行的字段", sorted(set(row) - set(revealed["link"])), [])
    t.check("取回视图也不落 token 字段", "token" not in revealed["link"], sorted(revealed["link"]))
    t.eq("不点名 Bot 也能取链接", c.post(f"{api}/guest/links/{link['link_id']}/url", headers=a,
                          json={}).json()["link"]["url"], link["url"])
    t.eq("陌生链接取不到", c.post(f"{api}/guest/links/gl_nope/url", headers=a,
                    json={"bot_id": bid}).status_code, 404)
    t.eq("别的 Bot 取不到这条链接", c.post(f"{api}/guest/links/{link['link_id']}/url", headers=a,
                            json={"bot_id": obid}).status_code, 404)
    t.eq("取链接写进审计",
         [item["event"] for item in base.db.recent_negotiations(bid, stage="guest")
          if item["event"] == "url_reveal"][:1], ["url_reveal"])
    visitor = c.get(f"/book/{link['token']}")
    t.eq("控制台签发的链接访客可直接打开", visitor.status_code, 200)
    t.eq("访客页不带管理令牌", "x-studio-token" in str(visitor.request.headers).lower(), False)
    t.check("访客页不回显完整令牌", link["token"] not in visitor.text, link["token"][:12])
    t.eq("访客页声明不缓存", visitor.headers["cache-control"], "no-store, max-age=0")
    t.eq("访客页禁止索引", visitor.headers["x-robots-tag"], "noindex, nofollow")
    t.eq("访客页禁止嗅探", visitor.headers["x-content-type-options"], "nosniff")
    t.contains("访客页禁止脚本", visitor.headers["content-security-policy"], "script-src 'none'")
    t.eq("访客页不写引用", visitor.headers["referrer-policy"], "no-referrer")
    t.contains("访客页打开记一次访问",
               json.dumps([item["event"] for item in base.db.recent_negotiations(bid, stage="guest")]),
               "visited")
    opened = c.get(f"{api}/guest/links", headers=a, params={"bot_id": bid}).json()
    after = [item for item in opened["links"] if item["link_id"] == link["link_id"]][0]
    t.eq("访客打开一次计一次", after["uses"], 1)
    t.eq("剩余次数随之收窄", after["remaining"], 1)
    t.eq("多一段字符的令牌签名不合法", c.get("/book/" + link["token"] + "x").status_code, 400)
    t.eq("无分隔符的随机串按非法令牌处理", c.get("/book/" + "z" * 48).status_code, 400)
    t.eq("空令牌走缺令牌分支", c.get(LINK_PATH_PREFIX.rstrip("/")).status_code, 400)
    revoked = c.post(f"{api}/guest/links/{link['link_id']}/revoke", headers=a, json={"bot_id": bid}).json()
    t.eq("控制台可吊销链接", revoked["link"]["status"], "revoked")
    t.eq("吊销响应三段", sorted(revoked), ["link", "link_id", "ok"])
    t.check("吊销写了时间戳", revoked["link"]["revoked_at"] > 0, str(revoked["link"]["revoked_at"]))
    t.eq("吊销后取链接被拒", c.post(f"{api}/guest/links/{link['link_id']}/url", headers=a,
                     json={"bot_id": bid}).status_code, 410)
    t.eq("吊销后访客页立即失效", c.get(f"/book/{link['token']}").status_code, 410)
    t.check("失效页不泄露令牌", link["token"] not in c.get(f"/book/{link['token']}").text, link["token"][:12])
    t.eq("重复吊销仍是 revoked", c.post(f"{api}/guest/links/{link['link_id']}/revoke", headers=a,
                          json={"bot_id": bid}).json()["link"]["status"], "revoked")
    t.eq("陌生链接吊销被拒", c.post(f"{api}/guest/links/gl_nope/revoke", headers=a,
                      json={"bot_id": bid}).status_code, 404)
    t.eq("吊销写进审计", any(item["event"] == "revoked"
                  for item in base.db.recent_negotiations(bid, stage="guest")), True)
    doomed = c.post(f"{api}/guest/links", headers=a,
                    json={"bot_id": bid, "label": "临期", "ttl_hours": 1}).json()["link"]
    base.db.conn.execute("UPDATE guest_links SET expires_at = ? WHERE link_id = ?",
                         (time.time() - 10, doomed["link_id"]))
    base.db.conn.commit()
    quiet = c.get(f"{api}/guest/links", headers=a, params={"bot_id": bid}).json()["links"]
    t.check("默认列表过滤过期链接", doomed["link_id"] not in {item["link_id"] for item in quiet},
            str([item["link_id"] for item in quiet]))
    whole = c.get(f"{api}/guest/links", headers=a,
                  params={"bot_id": bid, "include_expired": "true"}).json()["links"]
    t.check("勾选含过期后才出现", doomed["link_id"] in {item["link_id"] for item in whole},
            str([item["link_id"] for item in whole]))
    t.eq("过期链接状态已改写", [item for item in whole if item["link_id"] == doomed["link_id"]][0]["status"],
         "expired")
    t.eq("过期链接访客页 410", c.get(f"/book/{doomed['token']}").status_code, 410)

    # ------------------------------------------------------------------ 节点
    calls_before_node = len(node.calls)
    local = c.get(f"{api}/node", headers=a).json()["node"]
    t.eq("GET 节点状态一个请求都不发", len(node.calls), calls_before_node)
    t.eq("节点状态给出回环基址", local["base_url"], DEFAULT_MAC_NODE_URL)
    t.eq("节点状态标记注入传输", local["transport"], "injected")
    t.eq("节点状态带账本缓存", local["cache"], "ledger")
    t.eq("节点状态列出真实路由", sorted(local["routes"]),
         ["availability", "bookings", "command", "engine_invoke", "health", "proposals", "settings", "snapshot"])
    t.eq("健康检查路由", local["routes"]["health"], HEALTH_PATH)
    t.eq("提案路由带命名空间", local["routes"]["proposals"], "/v1/tools/calendar/proposals")
    t.eq("命令前缀逐字对齐节点", local["command_prefix"], COMMAND_PREFIX)
    t.eq("节点状态里的头已掩码", local["headers"][TOKEN_HEADER], "***")
    t.eq("载荷上限可读", local["payload_char_limit"], MAX_SIGNAL_PAYLOAD_CHARACTERS)
    t.eq("超时上报为数字", local["timeout_seconds"] > 0, True)
    probed = c.post(f"{api}/node/probe", headers=a)
    t.eq("探活可用", probed.status_code, 200)
    t.eq("探活四段", sorted(probed.json()), ["health", "node", "ok", "snapshot"])
    t.eq("探活只发两次 GET", [call["method"] for call in node.calls[-2:]], ["GET", "GET"])
    t.eq("探活先打健康检查", node.calls[-2]["url"].endswith(HEALTH_PATH), True)
    t.eq("探活再打快照", node.calls[-1]["url"].endswith(SNAPSHOT_PATH), True)
    t.eq("探活带上节点令牌", node.calls[-1]["headers"][TOKEN_HEADER], "self-test-node-token")
    t.eq("探活回显健康检查", probed.json()["health"]["service"], "PopopxMacNode")
    t.eq("探活回显快照", probed.json()["snapshot"]["viewers"], 1)
    t.eq("探活恰好加两次调用", c.get(f"{api}/node", headers=a).json()["node"]["calls"],
         local["calls"] + 2)
    t.eq("探活成功后不留失败原因", c.get(f"{api}/node", headers=a).json()["node"]["last_reason"], "")
    idle = len(node.calls)
    c.get(f"{api}/node", headers=a)
    t.eq("探活之后再读节点状态仍然零外发", len(node.calls), idle)
    unreachable = FakeNode()
    unreachable.on(HEALTH_PATH, OSError("connection refused"))
    unreachable.on(SNAPSHOT_PATH, (404, {"error": "no such route", "status": 404}))
    base.agent = AgentRuntime(db=base.db, settings=base.settings, sender=build_sender(svc),
                              node_transport=unreachable)
    sends_before_probe = len(svc.sends)
    down = c.post(f"{api}/node/probe", headers=a)
    t.eq("健康检查失败即 502", down.status_code, 502)
    t.contains("不可达原因写进描述", down.json()["description"], "节点不可达")
    t.eq("不可达只打了一次健康检查", len(unreachable.calls), 1)
    t.eq("不可达时不再打快照", unreachable.count(SNAPSHOT_PATH), 0)
    t.eq("探活失败不改变提案状态", base.db.get_proposal(landed["proposal_id"])["status"], "approved")
    t.eq("探活失败不多发消息", len(svc.sends), sends_before_probe)
    t.check("失败计入节点计数", c.get(f"{api}/node", headers=a).json()["node"]["failures"] >= 1,
            str(c.get(f"{api}/node", headers=a).json()["node"]["failures"]))
    base.agent = AgentRuntime(db=base.db, settings=base.settings, sender=build_sender(svc), node_transport=node)
    hijack = FakeNode()
    base.agent = AgentRuntime(db=base.db, settings=base.settings, sender=build_sender(svc), node_transport=hijack)
    original_url = base.settings.mac_node_url
    try:
        base.settings.mac_node_url = "http://169.254.169.254/latest/meta-data"
        refused = c.post(f"{api}/node/probe", headers=a)
        t.eq("被改成非回环后仍被拒", refused.status_code, 502)
        t.eq("非回环时一个字节都没外送", len(hijack.calls), 0)
        t.eq("状态里如实标注非回环", c.get(f"{api}/node", headers=a).json()["node"]["loopback"], False)
        t.check("拒绝原因写进状态",
                bool(c.get(f"{api}/node", headers=a).json()["node"]["loopback_refusal"]), "")
        t.eq("非回环时确认已落地提案不改状态",
             c.post(f"{api}/proposals/{landed['proposal_id']}/decision", headers=a,
                    json={"decision": "approve"}).status_code, 200)
        t.eq("非回环时同样零外发", len(hijack.calls), 0)
    finally:
        base.settings.mac_node_url = original_url
    base.agent = AgentRuntime(db=base.db, settings=base.settings, sender=build_sender(svc), node_transport=node)
    t.eq("恢复配置后节点仍是回环", c.get(f"{api}/node", headers=a).json()["node"]["loopback"], True)
    t.eq("恢复配置后基址回来了", c.get(f"{api}/node", headers=a).json()["node"]["base_url"],
         DEFAULT_MAC_NODE_URL)

    # ------------------------------------------------------------ 门户关闭时
    offstack = h.stack(tag="agent-console-guestoff", GUEST_ENABLED="0")
    off_client, _ = h.client(offstack)
    off_summary = off_client.get(f"{api}/summary", headers=a).json()
    t.eq("关闭门户时摘要如实标注", off_summary["guest"]["enabled"], False)
    t.eq("关闭门户时如实标注未启用", off_summary["guest"]["enabled"], False)
    t.eq("关闭门户时基址仍只是本机", off_summary["guest"]["public_base"], "http://127.0.0.1:8090")
    t.eq("关闭后列表路由 404", off_client.get(f"{api}/guest/links", headers=a).status_code, 404)
    t.eq("关闭后签发 404", off_client.post(f"{api}/guest/links", headers=a,
                            json={"bot_id": "any"}).status_code, 404)
    t.eq("关闭后取链接 404", off_client.post(f"{api}/guest/links/gl_x/url", headers=a,
                              json={"bot_id": "any"}).status_code, 404)
    t.eq("关闭后吊销 404", off_client.post(f"{api}/guest/links/gl_x/revoke", headers=a,
                            json={"bot_id": "any"}).status_code, 404)
    t.eq("关闭后访客页 404", off_client.get("/book/whatever").status_code, 404)
    t.check("关闭页不泄露开关名", "GUEST_ENABLED" not in off_client.get("/book/whatever").text,
            off_client.get("/book/whatever").text[:120])
    t.eq("关闭门户不影响其余面板",
         [off_client.get(f"{api}/{name}", headers=a).status_code for name in ("summary", "engine", "node")],
         [200, 200, 200])
    t.eq("关闭门户不影响管理鉴权", off_client.get(f"{api}/summary").status_code, 401)

    # -------------------------------------------------------------- 面板装配
    page_html = c.get("/").text
    for marker in ('data-view="agent"', 'data-view="guest"', 'data-view="a2a"',
                   'id="v-agent"', 'id="v-guest"', 'id="v-a2a"', '"' + AGENT_API_PREFIX + '"',
                   'id="f-extract"', 'id="f-guest"', 'id="f-neg"', 'id="t-panel"'):
        t.check(f"页面含 {marker}", marker in page_html, marker)
    panel_keys = ("nav_agent", "nav_guest", "nav_a2a", "agent_prefs", "guest_issue", "a2a_audit")
    en_admin = admin_strings("en")
    for key in panel_keys:
        t.check(f"面板键 {key} 已入英文目录", key in en_admin, sorted(en_admin)[:6])
    t.eq("面板键在全部 18 语种都有译文",
         [f"{loc}/{key}" for key in panel_keys for loc in LOCALES
          if not str(CATALOGS["admin"][loc].get(key, "")).strip()], [])
    t.eq("面板键都在页面上被用到", [key for key in panel_keys if f'data-i18n="{key}"' not in page_html], [])


def group_invite_codec(test: SelfTest, h: Harness) -> None:
    """隐私邀请链接：跨语言向量、随机 nonce、明文不泄漏与篡改拒绝。"""
    t = test
    vectors_path = ROOT / "app" / "security" / "opaque_invite_vectors.json"
    t.eq("向量文件随代码发布", vectors_path.is_file(), True)
    doc = json.loads(vectors_path.read_text(encoding="utf-8"))
    t.eq("向量格式名", doc["format"], "popopx-opaque-invite-v1")
    t.eq("向量链接前缀与实现一致", doc["link_prefix"], INVITE_LINK_PREFIX)
    t.eq("格式版本为 1", INVITE_FORMAT_VERSION, 1)
    t.eq("nonce 12 字节", INVITE_NONCE_BYTES, 12)
    t.eq("tag 16 字节", INVITE_TAG_BYTES, 16)
    t.eq("token 上限 5500 字符", INVITE_MAX_TOKEN_CHARS, 5500)

    kdf = doc["key_derivation"]
    t.eq("向量 IKM 与实现一致", kdf["ikm_hex"], INVITE_MASTER_KEY.hex())
    t.eq("向量 salt 与实现一致", base64.b64decode(kdf["salt_b64"]), INVITE_HKDF_SALT)
    t.eq("向量 info 与实现一致", base64.b64decode(kdf["info_b64"]), INVITE_HKDF_INFO)
    t.eq("派生密钥与向量逐字节一致", INVITE_KEY.hex(), kdf["key_hex"])
    t.eq("derive_invite_key 可复现", derive_invite_key(), INVITE_KEY)
    t.eq("派生密钥 32 字节", len(INVITE_KEY), 32)
    t.ne("派生密钥不等于主密钥", INVITE_KEY, INVITE_MASTER_KEY)
    t.eq("AEAD 算法名", doc["aead"]["algorithm"], "ChaCha20-Poly1305")
    t.eq("AEAD AAD 为空", base64.b64decode(doc["aead"]["aad_b64"]), b"")

    std = doc["standard_vectors"]
    hkdf = std["hkdf_sha256_rfc5869_tc1"]
    t.eq(
        "RFC 5869 TC1 HKDF 向量",
        hkdf_sha256(bytes.fromhex(hkdf["ikm_hex"]), bytes.fromhex(hkdf["salt_hex"]),
                    bytes.fromhex(hkdf["info_hex"]), int(hkdf["length"])).hex(),
        hkdf["okm_hex"],
    )
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: PLC0415

    aead = std["chacha20_poly1305_rfc8439_2_8_2"]
    sealed = ChaCha20Poly1305(bytes.fromhex(aead["key_hex"])).encrypt(
        bytes.fromhex(aead["nonce_hex"]),
        aead["plaintext_utf8"].encode("utf-8"),
        bytes.fromhex(aead["aad_hex"]),
    )
    t.eq("RFC 8439 §2.8.2 密文逐字节一致", sealed[:-16].hex(), aead["ciphertext_hex"])
    t.eq("RFC 8439 §2.8.2 tag 逐字节一致", sealed[-16:].hex(), aead["tag_hex"])

    for vector in doc["vectors"]:
        name = vector["name"]
        nonce = bytes.fromhex(vector["nonce_hex"])
        link = encode_invite_link(vector["address"], nonce=nonce)
        t.eq(f"向量 {name} 编码逐字节一致", link, vector["link"])
        t.eq(f"向量 {name} 解码回原文", decode_invite_link(vector["link"]), vector["address"])
        t.eq(f"向量 {name} token 即去前缀链接", link[len(INVITE_LINK_PREFIX):], vector["token"])
        raw = b64url_decode(vector["token"])
        t.eq(f"向量 {name} 密文长度", len(raw), INVITE_NONCE_BYTES + len(vector["address"].encode("utf-8")) + INVITE_TAG_BYTES)
        t.eq(f"向量 {name} 前 12 字节是 nonce", raw[:INVITE_NONCE_BYTES], nonce)
        t.eq(f"向量 {name} 不含明文节点域名", "popopx.im" in vector["link"], False)
        t.eq(f"向量 {name} 不含明文协议头", "smp://" in vector["link"], False)

    sample = doc["vectors"][0]
    fixed = encode_invite_link(sample["address"], nonce=bytes.fromhex(sample["nonce_hex"]))
    t.eq("固定 nonce 密文不含 smp 子串", "smp" in fixed.lower(), False)

    first = encode_invite_link(sample["address"])
    second = encode_invite_link(sample["address"])
    t.ne("两条新链接 nonce 随机不同", first, second)
    first_raw = b64url_decode(first[len(INVITE_LINK_PREFIX):])
    second_raw = b64url_decode(second[len(INVITE_LINK_PREFIX):])
    t.ne("随机 nonce 逐字节不同", first_raw[:INVITE_NONCE_BYTES], second_raw[:INVITE_NONCE_BYTES])
    t.eq("随机链接仍可解回原文", [decode_invite_link(first), decode_invite_link(second)],
         [sample["address"], sample["address"]])
    t.eq("随机密文不含明文 smp 协议头", "smp://" in first, False)
    t.eq("随机密文不含明文节点域名", "popopx.im" in first, False)
    t.eq("随机密文不含原地址", sample["address"] in first, False)

    token = sample["token"]
    pos = len(token) // 2
    alt = "A" if token[pos] != "A" else "B"
    tampered = INVITE_LINK_PREFIX + token[:pos] + alt + token[pos + 1:]
    t.raises("篡改密文抛 OpaqueInviteError", OpaqueInviteError, decode_invite_link, tampered)
    t.raises("截断链接抛 OpaqueInviteError", OpaqueInviteError, decode_invite_link, sample["link"][:-8])
    t.raises("带填充的 token 被拒", OpaqueInviteError, decode_invite_link, sample["link"] + "=")
    t.raises("错误前缀被拒", OpaqueInviteError, decode_invite_link,
             "https://popopx.im." + token)
    t.raises("原始 smp:// 不是封装链接", OpaqueInviteError, decode_invite_link, sample["address"])
    t.raises("非字符串链接被拒", OpaqueInviteError, decode_invite_link, 12345)
    t.raises("超长 token 被拒", OpaqueInviteError, decode_invite_link, INVITE_LINK_PREFIX + "A" * (INVITE_MAX_TOKEN_CHARS + 1))

    t.raises("11 字节 nonce 被拒", OpaqueInviteError, encode_invite_link, "smp://x", nonce=b"\x00" * 11)
    t.raises("13 字节 nonce 被拒", OpaqueInviteError, encode_invite_link, "smp://x", nonce=b"\x00" * 13)
    t.raises("字符串 nonce 被拒", OpaqueInviteError, encode_invite_link, "smp://x", nonce="0" * 12)
    t.raises("空地址被拒", OpaqueInviteError, encode_invite_link, "")
    t.raises("纯空白地址被拒", OpaqueInviteError, encode_invite_link, "   ")
    t.raises("含换行地址被拒", OpaqueInviteError, encode_invite_link, "smp://a\nb")
    t.raises("含 NUL 地址被拒", OpaqueInviteError, encode_invite_link, "smp://a\x00b")
    t.raises("超长地址被拒", OpaqueInviteError, encode_invite_link, "a" * (INVITE_MAX_ADDRESS_BYTES + 1))
    t.eq("恰好上限的地址可封装", decode_invite_link(encode_invite_link("a" * INVITE_MAX_ADDRESS_BYTES)),
         "a" * INVITE_MAX_ADDRESS_BYTES)
    t.eq("字节级 bytearray nonce 可用", decode_invite_link(
        encode_invite_link("smp://x", nonce=bytearray(range(12)))), "smp://x")
    t.eq("地址两端空白被清理", decode_invite_link(encode_invite_link("  smp://x  ")), "smp://x")
    t.eq("UTF-8 地址往返", decode_invite_link(encode_invite_link("smp://客服@节点/队列")), "smp://客服@节点/队列")

    t.eq("b64url 无填充编码", b64url_encode(b"\xfb\xff"), "-_8")
    t.eq("b64url 往返", b64url_decode(b64url_encode(b"\x00\x01\x02")), b"\x00\x01\x02")
    for bad in ("", "A", "AA==", "A$", "a b"):
        t.raises(f"非法 Base64URL {bad!r} 被拒", OpaqueInviteError, b64url_decode, bad)

    t.eq("封装链接可被前缀识别", looks_like_opaque_invite(sample["link"]), True)
    t.eq("原始地址不被误判", looks_like_opaque_invite(sample["address"]), False)
    t.eq("JSON 向量覆盖三种地址形态", sorted(v["name"] for v in doc["vectors"]),
         ["https-short", "popopx-scheme", "smp-long"])


def _external_group(module: str, key: str) -> Callable[[SelfTest, Harness], None]:
    """延迟导入外部自检模块的分组。

    ``selftest_node`` 之类要反向 ``from .selftest import Harness``，顶层互 import 会成环；
    导入失败会让这一组显式失败，而不是悄悄少跑一组。
    """

    def runner(test: SelfTest, harness: Harness) -> None:
        import importlib

        getattr(importlib.import_module(f".{module}", __package__), "GROUPS")[key](test, harness)

    return runner


SELF_TEST_GROUPS: Dict[str, Callable[[SelfTest, Harness], None]] = {
    "config": group_config,
    "database": group_database,
    "agent_ledger": group_agent_ledger,
    "ws_protocol": group_ws_protocol,
    "supervisor": group_supervisor,
    "provisioning": group_provisioning,
    "rules": group_rules,
    "router": group_router,
    "gateway": group_gateway,
    "plugins": group_plugins,
    "open_api": group_open_api,
    "web_admin": group_web_admin,
    "i18n": group_i18n,
    "web_live": group_web_live,
    "invite_codec": group_invite_codec,
    "bundle": group_bundle,
    "eco_cards": group_eco_cards,
    "ics": group_ics,
    "install": group_install,
    "mac_node": _external_group("selftest_node", "mac_node"),
    "a2a": _external_group("selftest_node", "a2a"),
    "guest_portal": _external_group("selftest_guest", "guest_portal"),
    "agent_engine": _external_group("selftest_agent_engine", "agent_engine"),
    "agent_console": group_agent_console,
}


