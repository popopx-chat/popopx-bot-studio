"""POPOPX Bot Studio — FastAPI 网关、Web 管理后台与自检入口。

启动方式::

    python3 -m app.main                 # 按 .env / 环境变量启动，只绑 127.0.0.1
    python3 -m app.main --self-test     # 全量自检门禁，退出码 0 表示全绿
    python3 -m app.main --check         # 只检查配置与依赖，不监听端口

组件装配顺序固定为：``Settings`` -> ``Database`` -> ``BotSupervisor`` ->
``RuleEngine`` / ``RouterEngine`` -> ``PluginManager`` -> ``BotGateway``。
``BotGateway`` 是插件总线、Open API 与管理后台共用的唯一事件管线。
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hmac
import json
import os
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from .bot_supervisor import (
    BotSupervisor,
    BotSupervisorError,
    build_cli_argv,
    effective_smp_servers,
    render_wrapper_script,
)
from . import open_api
from .config import DEFAULT_HOST, DEFAULT_PORT, Settings, is_loopback_host, load_settings
from .database import Database, LedgerError, connect
from .security.opaque_invite_codec import OpaqueInviteError
from .gateway import BotGateway
from .i18n import (
    FALLBACK_LOCALE,
    LOCALE_LABELS,
    LOCALES,
    admin_strings,
    assert_catalogs,
    catalog_payload,
    normalize_locale,
    parse_accept_language,
    parity_report,
    render_welcome,
    site_strings,
    welcome_template,
)
from .open_api import router as open_api_router
from .plugin_manager import PluginError, PluginManager
from .router_engine import RouterEngine
from .rule_engine import InboundMessage, RuleEngine
from . import agent_admin
from .agent_runtime import AgentRuntime, PLUGIN_ID as AGENT_PLUGIN_ID, build_sender
from .ws_protocol import CLICommandError, WebSocketProtocolError

APP_NAME = "popopx-bot-studio"
APP_VERSION = "1.0.0"
API_PREFIX = "/api/admin"
HOOK_PREFIX = "/api/v1/hooks"
OPEN_API_PREFIX = "/api/v1"
SEND_ERRORS = (
    BotSupervisorError,
    WebSocketProtocolError,
    CLICommandError,
    LedgerError,
    PluginError,
    OSError,
    asyncio.TimeoutError,
)
STATIC_DIR = Path(__file__).resolve().parents[1] / "static"
SITE_DIR = Path(__file__).resolve().parents[2] / "site"
CATALOG_MARKER = "__I18N_CATALOG_JSON__"
TOKEN_COOKIE = "studio_token"


# --------------------------------------------------------------------------- ref
def ref_for(chat_type: str, chat_id: Any) -> str:
    """``("group", 42)`` -> ``"#42"``; mirrors the CLI's own reference syntax.

    Plugins see ``chat_ref`` on every inbound event, so an already-formed
    ``"#42"`` is accepted too: the pair is re-validated, never trusted blindly.
    """
    mapping = {"direct": "@", "group": "#", "local": "*"}
    prefix = mapping.get(chat_type)
    if prefix is None:
        raise ValueError(f"非法 chatType {chat_type!r}")
    raw = str(chat_id).strip()
    if raw[:1] in mapping.values():
        if mapping[chat_type] != raw[0] or not raw[1:].isdigit():
            raise ValueError(f"chatType {chat_type!r} 与会话引用 {chat_id!r} 不一致")
        return f"{raw[0]}{int(raw[1:])}"
    if not raw.isdigit():
        raise ValueError(f"非法 chatId {chat_id!r}")
    return f"{prefix}{int(raw)}"


class CoreServices:
    """The only surface a plugin may reach, implemented on top of the gateway.

    Plugins never learn that a CLI exists: they see ``send_text`` /
    ``send_content`` and the ledger, which keeps third-party code honest about
    the loopback-only invariant.
    """

    def __init__(self, supervisor: BotSupervisor, database: Database, gateway: BotGateway):
        self.supervisor = supervisor
        self.db = database
        self.gateway = gateway

    async def send_text(
        self,
        bot_id: str,
        chat_type: str,
        chat_id: int,
        text: str,
        *,
        quoted_item_id: Optional[int] = None,
        plugin_id: str = "",
    ) -> Dict[str, Any]:
        ref = ref_for(chat_type, chat_id)
        try:
            result = await self.supervisor.send_text(bot_id, ref, text, quoted_item_id=quoted_item_id)
        except SEND_ERRORS as exc:
            self.db.log_message(
                bot_id, "out", chat_type=chat_type, chat_ref=ref, text=text,
                plugin_id=plugin_id, status="error", error=f"{type(exc).__name__}: {exc}",
            )
            raise
        self.db.log_message(
            bot_id, "out", chat_type=chat_type, chat_ref=ref, text=text,
            plugin_id=plugin_id, status="ok",
        )
        return result

    async def send_content(
        self,
        bot_id: str,
        chat_type: str,
        chat_id: int,
        content: Dict[str, Any],
        *,
        plugin_id: str = "",
        file_path: str = "",
    ) -> Dict[str, Any]:
        ref = ref_for(chat_type, chat_id)
        note = str(content.get("text", "")) or (f"file={Path(str(file_path)).name}" if file_path else "")
        try:
            result = await self.supervisor.send_content(bot_id, ref, content, file_path=file_path)
        except SEND_ERRORS as exc:
            self.db.log_message(
                bot_id, "out", chat_type=chat_type, chat_ref=ref,
                text=note, plugin_id=plugin_id,
                status="error", error=f"{type(exc).__name__}: {exc}",
            )
            raise
        self.db.log_message(
            bot_id, "out", chat_type=chat_type, chat_ref=ref,
            text=note, plugin_id=plugin_id, status="ok",
        )
        return result

    def log_message(self, bot_id: str, direction: str, **kwargs: Any) -> int:
        return self.db.log_message(bot_id, direction, **kwargs)

    def clients(self) -> List[str]:
        return sorted(self.supervisor.clients)


@dataclass
class StudioStack:
    """Everything the HTTP layer needs, assembled once per process."""

    settings: Settings
    db: Database
    supervisor: BotSupervisor
    rules: RuleEngine
    router: RouterEngine
    plugins: PluginManager
    gateway: BotGateway
    services: CoreServices
    booted: Dict[str, Any] = field(default_factory=dict)
    agent: Optional[AgentRuntime] = None

    async def start(self, *, spawn: bool = True) -> Dict[str, Any]:
        await self.plugins.load_async()
        self.attach_agent()
        await self.plugins.start()
        if spawn:
            self.booted = await self.supervisor.boot()
        return self.booted

    def attach_agent(self) -> None:
        """把共享运行时交给替身机器人插件（插件自己拿不到 ``Settings``）。"""
        if self.agent is None:
            return
        plugin = self.plugins.get(AGENT_PLUGIN_ID)
        attach = getattr(plugin, "attach", None)
        if callable(attach):
            attach(self.agent)

    async def stop(self) -> None:
        await self.plugins.stop()
        if self.agent is not None:
            self.agent.close()
        await self.supervisor.shutdown()
        self.db.close()

    def overview(self, *, trend_days: int = 7) -> Dict[str, Any]:
        summary = self.db.bot_summary()
        runtime = self.supervisor.status()
        return {
            "app": APP_NAME,
            "version": APP_VERSION,
            "bots": summary,
            "running": summary.get("running", 0),
            "runtime": runtime,
            "messages": self.db.message_stats(),
            "trend": self.db.message_trend(days=trend_days),
            "routing": self.router.stats(),
            "plugins": self.plugins.health(),
            "gateway": self.gateway.snapshot(),
            "agent": self.agent.status() if self.agent is not None else {},
            "locale": self.settings.default_locale,
            "locales": list(LOCALES),
            "host": self.settings.host,
            "port": self.settings.port,
            "loopback_only": is_loopback_host(self.settings.host),
            "cli_binary": str(self.settings.cli_bin_path),
            "cli_present": self.settings.cli_bin_path.exists(),
            "warnings": list(self.settings.startup_warnings),
            "gateway_errors": list(self.gateway.errors[-20:]),
        }


def build_stack(
    settings: Optional[Settings] = None,
    *,
    db: Optional[Database] = None,
    plugins_dir: Optional[Path | str] = None,
    tick_interval: float = 60.0,
) -> StudioStack:
    """Wire the components without touching the network or spawning processes."""
    conf = settings if settings is not None else load_settings()
    conf.ensure_directories()
    ledger = db if db is not None else connect(conf.db_file)
    rules = RuleEngine(ledger, bot_name=APP_NAME)
    router = RouterEngine(ledger, bot_name=APP_NAME)
    supervisor = BotSupervisor(conf, ledger)
    plugins = PluginManager(
        ledger,
        _LateServices(),
        plugins_dir=Path(plugins_dir) if plugins_dir else None,
        tick_interval=tick_interval,
    )
    gateway = BotGateway(conf, ledger, supervisor, rules, router, plugins)
    services = CoreServices(supervisor, ledger, gateway)
    plugins.services = services
    supervisor.on_event = gateway.handle_event
    agent = AgentRuntime(db=ledger, settings=conf, sender=build_sender(services))
    return StudioStack(conf, ledger, supervisor, rules, router, plugins, gateway, services, agent=agent)


class _LateServices:
    """Placeholder so ``PluginManager`` can be constructed before the gateway."""

    async def send_text(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        raise PluginError("服务尚未装配完成")

    async def send_content(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        raise PluginError("服务尚未装配完成")

    def log_message(self, *args: Any, **kwargs: Any) -> int:
        raise PluginError("服务尚未装配完成")

    def clients(self) -> List[str]:
        return []


# ----------------------------------------------------------------------- auth
def request_token(request: Request) -> str:
    header = request.headers.get("x-studio-token", "")
    if header:
        return header.strip()
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    query = request.query_params.get("token", "")
    if query:
        return query.strip()
    return request.cookies.get(TOKEN_COOKIE, "").strip()


def token_ok(request: Request, settings: Settings) -> bool:
    expected = settings.admin_token
    if not expected:
        return False
    supplied = request_token(request)
    if not supplied:
        return False
    return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


def require_admin(request: Request) -> Settings:
    settings: Settings = request.app.state.stack.settings
    if not token_ok(request, settings):
        raise HTTPException(
            status_code=401,
            detail={"ok": False, "error_code": 401, "description": "缺少或错误的 STUDIO_ADMIN_TOKEN"},
            headers={"WWW-Authenticate": "X-Studio-Token"},
        )
    return settings


def stack_of(request: Request) -> StudioStack:
    return request.app.state.stack


async def body_of(request: Request) -> Dict[str, Any]:
    """Accept JSON or form-encoded bodies; an empty body is ``{}``."""
    raw = await request.body()
    if not raw:
        return {}
    ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if ctype in {"application/x-www-form-urlencoded", "multipart/form-data"}:
        form = await request.form()
        return {key: value for key, value in form.items()}
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail={"ok": False, "description": f"请求体不是合法 JSON：{exc}"})
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail={"ok": False, "description": "请求体必须是 JSON 对象"})
    return parsed


def ok(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    data = dict(payload or {})
    data.setdefault("ok", True)
    return data


def fail(status: int, description: str, **extra: Any) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"ok": False, "error_code": status, "description": description, **extra},
    )


def client_locale(request: Request, settings: Settings) -> str:
    """Resolve the language for server-rendered strings for this request."""
    forced = normalize_locale(request.query_params.get("locale", ""))
    if forced:
        return forced
    header = request.headers.get("accept-language", "")
    if header:
        matched = next((loc for loc in map(normalize_locale, parse_accept_language(header)) if loc), "")
        if matched:
            return matched
    return settings.default_locale or FALLBACK_LOCALE


def render_page(page: Path) -> Response:
    """Serve one zero-build page with the i18n catalog spliced into its marker.

    The file on disk stays a template, so the repo ships no generated blob and
    the same HTML degrades to its English source text when opened directly.
    """
    html = page.read_text(encoding="utf-8")
    payload = json.dumps(catalog_payload(), ensure_ascii=False, separators=(",", ":"))
    payload = payload.replace("</", "<\\/")
    if CATALOG_MARKER in html:
        html = html.replace(CATALOG_MARKER, payload)
    return Response(html, media_type="text/html; charset=utf-8")


# ------------------------------------------------------------------- lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    stack: StudioStack = app.state.stack
    state = getattr(app.state, "runtime", None)
    if state is None or not state.get("managed"):
        yield
        return
    await stack.start(spawn=bool(state.get("spawn", True)))
    try:
        yield
    finally:
        await stack.stop()


def create_app(
    settings: Optional[Settings] = None,
    *,
    stack: Optional[StudioStack] = None,
    managed: bool = True,
    spawn: bool = True,
) -> FastAPI:
    """Build the FastAPI application.

    ``managed=False`` keeps startup/shutdown inert, which is what the self-test
    and the Open API tests need: the real app boots external CLI processes.
    """
    built = stack if stack is not None else build_stack(settings)
    app = FastAPI(
        title="POPOPX Bot Studio",
        version=APP_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.state.stack = built
    app.state.runtime = {"managed": managed, "spawn": spawn}
    _register_routes(app)
    _mount_open_api(app, built)
    return app


def _mount_open_api(app: FastAPI, built: StudioStack) -> None:
    """Hand the developer API its live collaborators and audit webhook changes."""
    open_api.configure(
        settings=built.settings,
        database=built.db,
        gateway=built.gateway,
        supervisor=built.supervisor,
    )

    async def audit(bot: Dict[str, Any], url: str, secret: str) -> None:
        built.db.log_message(
            str(bot.get("id") or ""), "out",
            text=f"webhook={'cleared' if not url else url}",
            status="ok", plugin_id="open_api",
        )

    open_api.register_webhook_listener(audit)
    app.include_router(open_api_router, prefix=OPEN_API_PREFIX)


def _register_routes(app: FastAPI) -> None:
    # ------------------------------------------------------------- public
    @app.get("/api/i18n", include_in_schema=False)
    async def api_i18n(request: Request) -> Dict[str, Any]:
        locale = client_locale(request, request.app.state.stack.settings)
        return ok({
            "locale": locale,
            "fallback": FALLBACK_LOCALE,
            "locales": list(LOCALES),
            "labels": LOCALE_LABELS,
            "admin": admin_strings(locale),
            "site": site_strings(locale),
            "welcome": welcome_template(locale),
        })

    @app.get("/api/i18n/payload", include_in_schema=False)
    async def api_i18n_payload() -> Dict[str, Any]:
        return ok(catalog_payload())

    @app.get("/healthz")
    async def healthz(request: Request) -> Dict[str, Any]:
        stack = stack_of(request)
        return ok({
            "app": APP_NAME,
            "version": APP_VERSION,
            "locale": stack.settings.default_locale,
            "bots": len(stack.supervisor.clients),
            "updates": len(stack.gateway.updates),
            "loopback_only": is_loopback_host(stack.settings.host),
        })

    @app.get("/", include_in_schema=False)
    async def index() -> Response:
        page = STATIC_DIR / "index.html"
        if not page.is_file():
            raise HTTPException(status_code=404, detail="管理后台尚未构建，请检查 studio/static/index.html")
        return render_page(page)

    @app.get("/site", include_in_schema=False)
    @app.get("/site/index.html", include_in_schema=False)
    async def site_index() -> Response:
        page = SITE_DIR / "index.html"
        if not page.is_file():
            raise HTTPException(status_code=404, detail="产品官网尚未构建")
        return render_page(page)

    if STATIC_DIR.is_dir():
        from fastapi.staticfiles import StaticFiles

        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # 通道 B 的访客页与控制台的替身机器人面板（见 agent_admin 的模块文档）
    agent_admin.add_book_routes(app)
    agent_admin.add_admin_routes(app)

    # ------------------------------------------------------------- session
    @app.get(f"{API_PREFIX}/session")
    async def admin_session(request: Request, _=Depends(require_admin)) -> Dict[str, Any]:
        stack = stack_of(request)
        locale = client_locale(request, stack.settings)
        return ok({
            "authenticated": True,
            "locale": locale,
            "locales": list(LOCALES),
            "labels": LOCALE_LABELS,
            "strings": admin_strings(locale),
            "catalog_problems": assert_catalogs(),
            "version": APP_VERSION,
        })

    @app.get(f"{API_PREFIX}/overview")
    async def admin_overview(request: Request, _=Depends(require_admin)) -> Dict[str, Any]:
        return ok(stack_of(request).overview())

    # ---------------------------------------------------------------- bots
    @app.get(f"{API_PREFIX}/bots")
    async def bots_list(request: Request, _=Depends(require_admin)) -> Dict[str, Any]:
        stack = stack_of(request)
        bots = stack.db.list_bots()
        for row in bots:
            try:
                row["invite_link"] = stack.supervisor.invite_link(row)
            except OpaqueInviteError:
                row["invite_link"] = ""
        return ok({"bots": bots, "runtime": stack.supervisor.status()})

    @app.post(f"{API_PREFIX}/bots")
    async def bots_create(request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        payload = await body_of(request)
        name = str(payload.get("name") or "").strip()
        if not name:
            return fail(400, "name 不能为空")
        wanted = normalize_locale(str(payload.get("default_locale") or ""))
        if payload.get("default_locale") and not wanted:
            return fail(400, f"不支持的语种 {payload['default_locale']!r}")
        try:
            bot = await stack.supervisor.create_bot(
                name,
                display_name=str(payload.get("display_name") or name),
                welcome_text=str(payload.get("welcome_text") or ""),
                auto_accept=bool(payload.get("auto_accept", True)),
                accept_incognito=bool(payload.get("accept_incognito", False)),
                smp_servers=str(payload.get("smp_servers") or ""),
                default_locale=wanted,
                start=bool(payload.get("start", True)),
            )
        except SEND_ERRORS as exc:
            return fail(502, f"创建 Bot 失败：{type(exc).__name__}: {exc}")
        return ok({"bot": bot, "i18n": {"welcome": bot.get("welcome_text", ""), "locale": bot.get("default_locale", "")}})

    @app.get(f"{API_PREFIX}/bots/{{bot_id}}")
    async def bot_detail(bot_id: str, request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        try:
            detail = stack.supervisor.detail(bot_id)
        except BotSupervisorError as exc:
            return fail(404, str(exc))
        return ok({"bot": detail})

    @app.patch(f"{API_PREFIX}/bots/{{bot_id}}")
    async def bot_update(bot_id: str, request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        if stack.db.get_bot(bot_id) is None:
            return fail(404, f"Bot {bot_id} 不存在")
        payload = await body_of(request)
        allowed = {
            "display_name", "welcome_text", "auto_accept", "accept_incognito",
            "default_locale", "smp_servers", "webhook_url",
        }
        fields = {key: value for key, value in payload.items() if key in allowed}
        if not fields:
            return fail(400, f"没有可更新字段，允许：{sorted(allowed)}")
        if "default_locale" in fields:
            normalized = normalize_locale(str(fields["default_locale"] or ""))
            if str(fields["default_locale"] or "") and not normalized:
                return fail(400, f"不支持的语种 {fields['default_locale']!r}")
            fields["default_locale"] = normalized
        if "webhook_url" in fields:
            try:
                fields["webhook_url"] = safe_webhook_url(str(fields["webhook_url"] or ""))
            except ValueError as exc:
                return fail(400, str(exc))
        receipt: Optional[Dict[str, Any]] = None
        if {"welcome_text", "auto_accept", "accept_incognito"} & set(fields):
            greeting = {key: fields.pop(key) for key in
                        ("welcome_text", "auto_accept", "accept_incognito") if key in fields}
            try:
                receipt = await stack.supervisor.update_greeting(bot_id, **greeting)
            except SEND_ERRORS as exc:
                return fail(502, f"更新 Bot 失败：{type(exc).__name__}: {exc}")
        bot = stack.db.get_bot(bot_id)
        if fields:
            try:
                bot = stack.db.update_bot(bot_id, **fields)
            except LedgerError as exc:
                return fail(400, str(exc))
        out: Dict[str, Any] = {"bot": bot}
        if receipt is not None:
            out["greeting"] = receipt
        return ok(out)

    @app.delete(f"{API_PREFIX}/bots/{{bot_id}}")
    async def bot_delete(bot_id: str, request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        if stack.db.get_bot(bot_id, include_deleted=True) is None:
            return fail(404, f"Bot {bot_id} 不存在")
        purge = (request.query_params.get("purge", "1") != "0")
        try:
            result = await stack.supervisor.remove_bot(bot_id, purge_files=purge)
        except SEND_ERRORS as exc:
            return fail(502, f"删除 Bot 失败：{type(exc).__name__}: {exc}")
        return ok({"removed": bot_id, "purged": purge, "detail": result})

    for verb, action in (("start", "start_bot"), ("stop", "stop_bot"), ("restart", "restart_bot")):
        _lifecycle_route(app, API_PREFIX, verb, action)

    @app.get(f"{API_PREFIX}/bots/{{bot_id}}/qrcode")
    async def bot_qrcode(bot_id: str, request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        try:
            return ok(stack.supervisor.bot_qr(bot_id, save=False))
        except BotSupervisorError as exc:
            return fail(409, str(exc))

    @app.get(f"{API_PREFIX}/bots/{{bot_id}}/qr.png")
    async def bot_qr_png(bot_id: str, request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        bot = stack.db.get_bot(bot_id)
        if bot is None:
            return fail(404, f"Bot {bot_id} 不存在")
        link = str(bot.get("permanent_link") or bot.get("contact_address") or "")
        if not link:
            return fail(409, "该 Bot 还没有永久联系地址")
        raw_mode = str(request.query_params.get("raw") or "").lower() in {"1", "true", "yes", "on"}
        if not raw_mode:
            try:
                link = stack.supervisor.invite_link(bot)
            except OpaqueInviteError as exc:
                return fail(409, f"邀请链接隐私封装失败：{exc}")
        try:
            png = stack.supervisor.qr_png(link, box_size=int(request.query_params.get("box", "8")))
        except (ValueError, OSError) as exc:
            return fail(500, f"二维码生成失败：{exc}")
        return Response(png, media_type="image/png", headers={"Cache-Control": "no-store"})

    @app.post(f"{API_PREFIX}/bots/{{bot_id}}/send")
    async def bot_send(bot_id: str, request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        payload = await body_of(request)
        ref = str(payload.get("chat_ref") or payload.get("to") or "")
        text = str(payload.get("text") or "")
        if not ref or not text:
            return fail(400, "chat_ref 与 text 均为必填")
        delivered = await stack.gateway.deliver(bot_id, ref, text)
        if not delivered:
            return fail(502, f"发送到 {ref} 失败，请查看最近日志")
        return ok({"delivered": True, "chat_ref": ref})

    @app.get(f"{API_PREFIX}/bots/{{bot_id}}/contacts")
    async def bot_contacts(bot_id: str, request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        try:
            return ok({"contacts": await stack.supervisor.list_contacts(bot_id)})
        except SEND_ERRORS as exc:
            return fail(502, f"读取联系人失败：{type(exc).__name__}: {exc}")

    @app.get(f"{API_PREFIX}/bots/{{bot_id}}/groups")
    async def bot_groups(bot_id: str, request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        try:
            return ok({"groups": await stack.supervisor.list_groups(bot_id)})
        except SEND_ERRORS as exc:
            return fail(502, f"读取群组失败：{type(exc).__name__}: {exc}")

    @app.post(f"{API_PREFIX}/bots/{{bot_id}}/groups")
    async def bot_group_create(bot_id: str, request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        payload = await body_of(request)
        name = str(payload.get("name") or "").strip()
        if not name:
            return fail(400, "name 不能为空")
        try:
            if str(payload.get("link_role") or ""):
                raw_gid = str(payload.get("group_id") or "").strip()
                if not raw_gid.isdigit():
                    return fail(400, "生成群链接需要数字 group_id")
                return ok(await stack.supervisor.create_group_link(bot_id, int(raw_gid), str(payload["link_role"])))
            return ok(await stack.supervisor.create_group(bot_id, name))
        except (*SEND_ERRORS, ValueError) as exc:
            return fail(502, f"创建群组/短链失败：{type(exc).__name__}: {exc}")

    # -------------------------------------------------------- reply rules
    @app.get(f"{API_PREFIX}/bots/{{bot_id}}/rules")
    async def rules_list(bot_id: str, request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        if stack.db.get_bot(bot_id) is None:
            return fail(404, f"Bot {bot_id} 不存在")
        return ok({"rules": stack.db.list_reply_rules(bot_id), "commands": stack.rules.command_names()})

    @app.post(f"{API_PREFIX}/bots/{{bot_id}}/rules")
    async def rules_upsert(bot_id: str, request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        if stack.db.get_bot(bot_id) is None:
            return fail(404, f"Bot {bot_id} 不存在")
        payload = await body_of(request)
        try:
            rule = stack.db.upsert_reply_rule(
                bot_id,
                rule_id=payload.get("rule_id"),
                name=str(payload.get("name") or ""),
                trigger_type=str(payload.get("trigger_type") or ""),
                pattern=str(payload.get("pattern") or ""),
                reply_text=str(payload.get("reply_text") or payload.get("reply") or ""),
                cooldown_seconds=int(payload.get("cooldown_seconds") or 0),
                enabled=bool(payload.get("enabled", True)),
                priority=int(payload.get("priority", 100)),
            )
        except (LedgerError, ValueError) as exc:
            return fail(400, str(exc))
        stack.rules.invalidate_cache()
        return ok({"rule": rule})

    @app.delete(f"{API_PREFIX}/rules/{{rule_id}}")
    async def rules_delete(rule_id: int, request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        if not stack.db.delete_reply_rule(rule_id):
            return fail(404, f"规则 {rule_id} 不存在")
        stack.rules.invalidate_cache()
        return ok({"deleted": rule_id})

    @app.post(f"{API_PREFIX}/rules/preview")
    async def rules_preview(request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        payload = await body_of(request)
        bot_id = str(payload.get("bot_id") or "")
        text = str(payload.get("text") or "")
        if not bot_id or not text:
            return fail(400, "bot_id 与 text 均为必填")
        if stack.db.get_bot(bot_id) is None:
            return fail(404, f"Bot {bot_id} 不存在")
        decision = stack.rules.preview(bot_id, text, sender=str(payload.get("sender") or "preview"))
        return ok({
            "matched": decision.matched,
            "will_send": decision.should_send,
            "rule_id": decision.rule_id,
            "trigger_type": decision.trigger_type,
            "reply": decision.reply,
            "status": decision.status,
            "suppressed_by": decision.suppressed_by,
            "context": decision.context,
        })

    # ------------------------------------------------------ routing rules
    @app.get(f"{API_PREFIX}/bots/{{bot_id}}/routing")
    async def routing_list(bot_id: str, request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        if stack.db.get_bot(bot_id) is None:
            return fail(404, f"Bot {bot_id} 不存在")
        return ok({
            "rules": stack.db.list_routing_rules(bot_id),
            "known_groups": stack.router.known_groups(bot_id),
            "tickets": stack.router.tickets.open_tickets(bot_id),
        })

    @app.post(f"{API_PREFIX}/bots/{{bot_id}}/routing")
    async def routing_upsert(bot_id: str, request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        if stack.db.get_bot(bot_id) is None:
            return fail(404, f"Bot {bot_id} 不存在")
        payload = await body_of(request)
        try:
            rule = stack.db.upsert_routing_rule(
                bot_id,
                rule_id=payload.get("rule_id"),
                name=str(payload.get("name") or ""),
                source_type=str(payload.get("source_type") or "any"),
                source_ref=str(payload.get("source_ref") or ""),
                keyword_mode=str(payload.get("keyword_mode") or "any"),
                keywords=_keywords(payload.get("keywords")),
                target_type=str(payload.get("target_type") or "group"),
                target_ref=str(payload.get("target_ref") or ""),
                template=str(payload.get("template") or ""),
                quote_reply=bool(payload.get("quote_reply", True)),
                cooldown_seconds=int(payload.get("cooldown_seconds") or 0),
                enabled=bool(payload.get("enabled", True)),
            )
        except (LedgerError, ValueError) as exc:
            return fail(400, str(exc))
        stack.router.invalidate_cache()
        return ok({"rule": rule})

    @app.delete(f"{API_PREFIX}/routing/{{rule_id}}")
    async def routing_delete(rule_id: int, request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        if not stack.db.delete_routing_rule(rule_id):
            return fail(404, f"路由规则 {rule_id} 不存在")
        stack.router.invalidate_cache()
        return ok({"deleted": rule_id})

    @app.post(f"{API_PREFIX}/routing/preview")
    async def routing_preview(request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        payload = await body_of(request)
        bot_id = str(payload.get("bot_id") or "")
        if not bot_id:
            return fail(400, "bot_id 必填")
        chat_type = str(payload.get("chat_type") or "direct")
        try:
            ref = str(payload.get("chat_ref") or "") or ref_for(chat_type, payload.get("chat_id") or 1)
            message = InboundMessage(
                bot_id=bot_id,
                text=str(payload.get("text") or ""),
                chat_type=chat_type,
                chat_ref=ref,
                sender=str(payload.get("sender") or "preview"),
                sender_name=str(payload.get("sender_name") or "Preview"),
            )
        except ValueError as exc:
            return fail(400, str(exc))
        decision = stack.router.plan(message)
        return ok({
            "forwarded": decision.forwarded,
            "status": decision.status,
            "matched_rules": decision.matched_rules,
            "plans": [plan.as_dict() for plan in decision.plans],
            "reply_to_sender": decision.reply_to_sender,
        })

    # ------------------------------------------------------------ plugins
    @app.get(f"{API_PREFIX}/plugins")
    async def plugins_list(request: Request, _=Depends(require_admin)) -> Any:
        return ok(stack_of(request).plugins.health())

    @app.patch(f"{API_PREFIX}/plugins/{{plugin_id}}")
    async def plugins_update(plugin_id: str, request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        payload = await body_of(request)
        bot_id = str(payload.get("bot_id") or "")
        try:
            if "enabled" in payload and "config" not in payload:
                health = await stack.plugins.set_enabled(plugin_id, bool(payload["enabled"]), bot_id=bot_id)
            else:
                health = await stack.plugins.update_config(
                    plugin_id, dict(payload.get("config") or {}), bot_id=bot_id,
                    enabled=payload.get("enabled"),
                )
        except PluginError as exc:
            return fail(400, str(exc))
        return ok({"plugin": health})

    # ------------------------------------------------------ logs & updates
    @app.get(f"{API_PREFIX}/logs")
    async def logs_list(request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        bot_id = request.query_params.get("bot_id") or None
        limit = int(request.query_params.get("limit", "50") or 50)
        return ok({
            "logs": stack.db.recent_logs(bot_id, limit=max(1, min(limit, 500))),
            "stats": stack.db.message_stats(bot_id),
        })

    @app.get(f"{API_PREFIX}/updates")
    async def updates_list(request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        bot_id = request.query_params.get("bot_id", "")
        offset = int(request.query_params.get("offset", "0") or 0)
        limit = int(request.query_params.get("limit", "50") or 50)
        updates = stack.gateway.get_updates(bot_id, offset=offset, limit=max(1, min(limit, 500)))
        return ok({"updates": updates, "buffered": len(stack.gateway.updates)})

    # ------------------------------------------------------------ backups
    @app.post(f"{API_PREFIX}/backup/export")
    async def backup_export(request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        payload = await body_of(request)
        bot_id = str(payload.get("bot_id") or "")
        if not bot_id:
            return fail(400, "bot_id 必填")
        try:
            info = await stack.supervisor.export_bundle(
                bot_id,
                passphrase=str(payload.get("passphrase") or ""),
                dest=payload.get("dest") or None,
            )
        except SEND_ERRORS as exc:
            return fail(502, f"冷备导出失败：{type(exc).__name__}: {exc}")
        if payload.get("inline"):
            path = Path(info["file"])
            info = {**info, "base64": base64.b64encode(path.read_bytes()).decode("ascii")}
        return ok({"bundle": info})

    @app.post(f"{API_PREFIX}/backup/import")
    async def backup_import(request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        payload = await body_of(request)
        bundle = str(payload.get("bundle") or payload.get("file") or "")
        blob = payload.get("base64") or ""
        if blob:
            target = stack.settings.backups_dir / f"restore-{int(time.time())}.pbsb"
            target.write_bytes(base64.b64decode(blob))
            bundle = str(target)
        if not bundle:
            return fail(400, "bundle 或 base64 必填其一")
        try:
            info = await stack.supervisor.import_bundle(
                bundle,
                passphrase=str(payload.get("passphrase") or ""),
                bot_id=payload.get("bot_id") or None,
                name=str(payload.get("name") or ""),
                start=bool(payload.get("start", False)),
            )
        except SEND_ERRORS as exc:
            return fail(502, f"冷备还原失败：{type(exc).__name__}: {exc}")
        return ok({"bot": info})

    @app.get(f"{API_PREFIX}/backups")
    async def backups_list(request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        # 旁车 .json 只存校验元数据，不是可还原的备份
        items = sorted(
            path
            for pattern in ("*.botbundle", "*.botbundleenc", "*.pbsb")
            for path in stack.settings.backups_dir.glob(pattern)
        )
        return ok({
            "backups": [
                {
                    "file": str(path),
                    "bytes": path.stat().st_size,
                    "mtime": path.stat().st_mtime,
                    "encrypted": path.name.endswith(".botbundleenc"),
                }
                for path in items
            ]
        })

    # -------------------------------------------------------------- hooks
    @app.post(HOOK_PREFIX + "/{bot_id}/{secret}")
    async def inbound_hook(bot_id: str, secret: str, request: Request) -> Any:
        """Alert ingestion; the shared secret is the only credential here."""
        stack = stack_of(request)
        if stack.db.get_bot(bot_id) is None:
            return fail(404, f"Bot {bot_id} 不存在")
        payload = await body_of(request)
        result = await stack.plugins.handle_hook(bot_id, secret, payload)
        if result.get("status") in {"no_plugin", "unauthorized", "error"}:
            return fail(401 if result.get("status") == "unauthorized" else 404,
                        "该 bot 没有启用中的入站 Webhook 插件或密钥不匹配", **{"result": result})
        return ok({"result": result})

    # ---------------------------------------------------------- diagnostics
    @app.get(f"{API_PREFIX}/config")
    async def config_view(request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        settings = stack.settings
        bots = stack.db.list_bots()
        bot = bots[0] if bots else None
        argv: List[str] = []
        wrapper = ""
        if bot is not None:
            paths = stack.supervisor.paths_for(bot["id"])
            argv = build_cli_argv(
                stack.supervisor.cli_binary or settings.cli_bin_path,
                int(bot["port"]),
                paths,
                smp_servers=effective_smp_servers(bot, settings),
            )
            wrapper = render_wrapper_script(argv, bot_id=bot["id"], paths=paths)
        return ok({
            "host": settings.host,
            "port": settings.port,
            "data_dir": str(settings.data_dir),
            "db_file": str(settings.db_file),
            "state_file": str(settings.state_file),
            "bots_dir": str(settings.bots_dir),
            "backups_dir": str(settings.backups_dir),
            "cli_bin_path": str(settings.cli_bin_path),
            "cli_present": settings.cli_bin_path.exists(),
            "ws_port_base": settings.ws_port_base,
            "ws_port_max": settings.ws_port_max,
            "smp_servers": effective_smp_servers(bot, settings) if bot else [],
            "default_locale": settings.default_locale,
            "allow_lan": settings.allow_lan,
            "loopback_only": is_loopback_host(settings.host),
            "token_configured": bool(settings.admin_token),
            "token_masked": _mask(settings.admin_token),
            "warnings": settings.startup_warnings,
            "permission_warnings": settings.security_warnings(),
            "example_argv": argv,
            "wrapper_preview": wrapper,
        })

    @app.get(f"{API_PREFIX}/i18n/parity")
    async def i18n_parity(request: Request, _=Depends(require_admin)) -> Any:
        return ok({"locales": list(LOCALES), "problems": assert_catalogs(), "parity": parity_report()})


def _lifecycle_route(app: FastAPI, prefix: str, verb: str, action: str) -> None:
    """Expose ``start``/``stop``/``restart`` without closing over the loop var."""

    async def endpoint(bot_id: str, request: Request, _=Depends(require_admin)) -> Any:
        stack = stack_of(request)
        method: Callable[[str], Awaitable[Dict[str, Any]]] = getattr(stack.supervisor, action)
        try:
            result = await method(bot_id)
        except SEND_ERRORS as exc:
            return fail(502, f"{verb} 失败：{type(exc).__name__}: {exc}")
        return ok({verb: True, "bot": result})

    app.add_api_route(
        f"{prefix}/bots/{{bot_id}}/{verb}",
        endpoint,
        methods=["POST"],
        name=f"bot_{verb}",
        description=f"对受管 Bot 执行 {verb}",
    )


def safe_webhook_url(url: str) -> str:
    """Outbound webhooks may only be https or loopback http."""
    cleaned = (url or "").strip()
    if not cleaned:
        return ""
    if cleaned.startswith("https://"):
        return cleaned
    if cleaned.startswith("http://"):
        host = cleaned[len("http://"):].split("/")[0].split(":")[0].lower()
        if host in {"localhost", "127.0.0.1"} or host.startswith("127."):
            return cleaned
    raise ValueError("webhook_url 必须是 https 或回环 http 地址")


def _keywords(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.replace("|", ",").split(",") if item.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    raise ValueError("keywords 必须是字符串或字符串数组")


def _mask(secret: str) -> str:
    if not secret:
        return ""
    return f"{secret[:3]}…{len(secret)}" if len(secret) > 12 else "********"


# ------------------------------------------------------------------------ CLI
def _bootstrap_env(args: argparse.Namespace) -> Settings:
    if getattr(args, "env_file", ""):
        os.environ["STUDIO_ENV_FILE"] = str(Path(args.env_file).expanduser())
    if getattr(args, "data_dir", ""):
        os.environ["STUDIO_DATA_DIR"] = str(Path(args.data_dir).expanduser())
    if getattr(args, "port", None):
        os.environ["STUDIO_PORT"] = str(args.port)
    if getattr(args, "host", ""):
        os.environ["STUDIO_HOST"] = str(args.host)
    if getattr(args, "token", ""):
        os.environ["STUDIO_ADMIN_TOKEN"] = str(args.token)
    return load_settings()


def cmd_check(settings: Settings) -> int:
    """Report configuration and dependency health without binding a socket."""
    import importlib

    report = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "python": sys.version.split()[0],
        "settings": {
            "host": settings.host,
            "port": settings.port,
            "data_dir": str(settings.data_dir),
            "cli_bin_path": str(settings.cli_bin_path),
            "default_locale": settings.default_locale,
            "token_configured": bool(settings.admin_token),
        },
        "loopback_only": is_loopback_host(settings.host),
        "dependencies": {},
        "catalog": {"locales": len(LOCALES), "problems": assert_catalogs()},
        "warnings": settings.startup_warnings,
    }
    for module in ("fastapi", "uvicorn", "pydantic", "websockets", "httpx", "qrcode", "cryptography"):
        try:
            imported = importlib.import_module(module)
            report["dependencies"][module] = getattr(imported, "__version__", "ok")
        except ImportError as exc:
            report["dependencies"][module] = f"缺失：{exc}"
    print(json.dumps(report, ensure_ascii=False, indent=2))
    missing = [name for name, value in report["dependencies"].items() if str(value).startswith("缺失")]
    return 1 if missing or report["catalog"]["problems"] else 0


def cmd_serve(settings: Settings, *, reload: bool = False) -> int:
    import uvicorn

    if not is_loopback_host(settings.host) and not settings.allow_lan:
        print(f"拒绝启动：{settings.host} 非回环地址（如需对外暴露请显式 STUDIO_ALLOW_LAN=1）", file=sys.stderr)
        return 78
    for warning in settings.startup_warnings:
        print(f"[warn] {warning}", file=sys.stderr)
    app = create_app(settings)
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="info", reload=False)
    return 0


def cmd_self_test(settings: Optional[Settings] = None, *, groups: Optional[List[str]] = None) -> int:
    from .selftest import SELF_TEST_GROUPS, SelfTest

    unknown = [name for name in (groups or []) if name not in SELF_TEST_GROUPS]
    if unknown:
        print(f"未知自检分组 {unknown}，可选：{list(SELF_TEST_GROUPS)}", file=sys.stderr)
        return 2
    selected = [name for name in SELF_TEST_GROUPS if not groups or name in groups]
    test = SelfTest(settings=settings, only=selected)
    total = test.run_all()
    print(f"自检分组 {len(selected)}/{len(SELF_TEST_GROUPS)} 组，断言 {total} 条，失败 {test.failures} 条")
    return 0 if test.ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m app.main", description="POPOPX Bot Studio")
    parser.add_argument("--self-test", action="store_true", help="运行全量自检门禁（默认不启动服务）")
    parser.add_argument("--group", action="append", dest="groups", metavar="NAME", help="只运行指定自检分组，可重复")
    parser.add_argument("--check", action="store_true", help="只校验配置、权限与依赖")
    parser.add_argument("--serve", action="store_true", help="启动 Web 服务（默认行为）")
    parser.add_argument("--host", default="", help="监听地址，默认 127.0.0.1")
    parser.add_argument("--port", type=int, default=0, help="监听端口，默认 8090")
    parser.add_argument("--data-dir", default="", help="覆盖 STUDIO_DATA_DIR")
    parser.add_argument("--env-file", default="", help="指定 .env 路径")
    parser.add_argument("--token", default="", help="临时覆盖 STUDIO_ADMIN_TOKEN")
    parser.add_argument("--version", action="store_true", help="打印版本")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.version:
        print(f"{APP_NAME} {APP_VERSION}")
        return 0
    settings = _bootstrap_env(args)
    if args.self_test:
        return cmd_self_test(settings, groups=args.groups)
    if args.check:
        return cmd_check(settings)
    return cmd_serve(settings)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
