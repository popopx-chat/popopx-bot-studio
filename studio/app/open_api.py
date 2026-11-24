"""开发者开放 HTTP API —— Botfather 风格的第三方接入口。

prompt.md §3.9 要求：``Authorization: Bearer <BOT_TOKEN>`` 或路径
``/bot<token>/...`` 两种鉴权方式都能用，并提供

=========== ==================== ==========================================
方法          路径                 说明
=========== ==================== ==========================================
GET         ``/getMe``           Bot 身份（id/名称/状态/端口/永久链接/语言）
POST        ``/sendMessage``     向单个会话发送文本（JSON 或表单）
POST        ``/broadcastGroup``  向该 Bot 已知的所有群组播报同一文本
POST        ``/setWebhook``      注册/注销出站 Webhook（仅 https 或回环 http）
GET         ``/getUpdates``      读取网关更新缓冲区（支持 offset/limit/timeout）
=========== ==================== ==========================================

设计约束
--------

* **响应约定**：成功 ``{"ok": true, ...}``，失败
  ``{"ok": false, "error_code": <int>, "description": "<人类可读>"}``，并且
  HTTP 状态码与 ``error_code`` 保持一致（脚本往往同时检查两者）。
* **错误隔离**：本路由内的任何异常（网关、监督器、SQLite、WebSocket）都只影响
  当前请求，绝不冒泡到网关进程。``guard`` 装饰器兜住
  ``ApiError``、真实协议异常类以及最后的 ``Exception`` 兜底。
* **不泄露令牌**：任何响应体都不会回显期望的 Bot Token；无效令牌与缺失令牌的
  描述文案不同但都不会携带令牌内容。
* **回环隔离**：出站 Webhook 只接受 ``https`` 或指向 127.0.0.1/::1/localhost 的
  ``http``，其余一律 400（prompt.md §1 的严格回环约束）。
* **自包含装配**：本模块不依赖 ``main.py``。优先级为
  ``configure()`` 显式注入 -> ``app.main`` 模块级单例（运行时软发现，
  仅查 ``sys.modules``，绝不 import，避免循环导入）-> 惰性打开 SQLite 账本。
  ``main.py`` 只需 ``app.include_router(open_api.router, prefix="/api/v1")``；
  若还想让 ``webhook_relay`` 插件立即感知变更，可选调用
  ``open_api.register_webhook_listener(...)``，本模块不 import plugin_manager。
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import secrets
import sys
import time
import types
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qsl, urlsplit

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from .bot_supervisor import BotSupervisorError, parse_chat_ref
from .config import Settings, is_loopback_host, load_settings
from .database import Database, LedgerError, connect as connect_ledger
from .router_engine import RouterError, parse_targets
from .ws_protocol import CLICommandError, WebSocketProtocolError

log = logging.getLogger("popopx.open_api")

# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------

#: 路径鉴权前缀。Starlette 会把 ``{path_token}`` 编译成 ``(?P<path_token>[^/]+)``。
#: 参数名刻意避开 ``token``，这样 main.py 若把本路由再挂到 ``/api/v1/bot{token}``
#: 前缀下也不会产生重名捕获组。
PATH_PARAM = "path_token"
PATH_PREFIX = f"/bot{{{PATH_PARAM}}}"

#: 与 ``gateway.MAX_UPDATES`` 对齐的上限；不 import gateway 以保持本模块零环依赖。
MAX_LIMIT = 500
DEFAULT_LIMIT = 50
#: 长轮询最长等待，避免占满 uvicorn worker。
MAX_POLL_SECONDS = 30.0
POLL_INTERVAL = 0.25
MAX_TEXT_LENGTH = 4000
MAX_WEBHOOK_LENGTH = 512

#: 真实异常类，逐个来自源码而非臆造：
#: BotSupervisorError(bot_supervisor.py:87)、WebSocketProtocolError /
#: CLICommandError(ws_protocol.py:37/41，CLITimeoutError 是前者的子类)、
#: LedgerError(database.py:30)、RouterError(router_engine.py)、
#: websockets.exceptions.WebSocketException（含 ConnectionClosed*）。
try:  # pragma: no cover - websockets 是 requirements.txt 钉住的依赖
    from websockets.exceptions import WebSocketException

    _WS_BASE: Tuple[type, ...] = (WebSocketException,)
except Exception:  # pragma: no cover - 缺包时退化为 OSError 路径
    _WS_BASE = ()

SAFE_EXCEPTIONS: Tuple[type, ...] = (
    BotSupervisorError,
    WebSocketProtocolError,
    CLICommandError,
    LedgerError,
    RouterError,
    OSError,
    asyncio.TimeoutError,
    *_WS_BASE,
)

OPEN_METHODS = ("getMe", "sendMessage", "broadcastGroup", "setWebhook", "getUpdates")

__all__ = [
    "router",
    "configure",
    "get_state",
    "OpenApiState",
    "require_bot",
    "register_webhook_listener",
    "mounted_paths",
    "ApiError",
    "PATH_PREFIX",
    "SAFE_EXCEPTIONS",
]


# --------------------------------------------------------------------------
# 错误与响应封装
# --------------------------------------------------------------------------


class ApiError(Exception):
    """Open API 内部可控错误：携带 HTTP 状态码与 Botfather 风格错误体。"""

    def __init__(self, status: int, error_code: int, description: str) -> None:
        super().__init__(description)
        self.status = int(status)
        self.error_code = int(error_code)
        self.description = str(description)[:400]

    def as_response(self) -> JSONResponse:
        return fail(self.status, self.error_code, self.description)


@dataclass
class AuthFailure:
    """依赖项的失败返回值。

    依赖里 ``raise`` 会绕过端点外层 try/except（FastAPI 在调用端点*之前*解析
    依赖），因此鉴权失败以值返回，由 :func:`guard` 统一转成 401 JSON。
    """

    status: int
    error_code: int
    description: str


def ok(result: Any, **extra: Any) -> JSONResponse:
    payload: Dict[str, Any] = {"ok": True, "result": result}
    payload.update(extra)
    return JSONResponse(status_code=200, content=payload)


def fail(status: int, error_code: int, description: str, **extra: Any) -> JSONResponse:
    payload: Dict[str, Any] = {
        "ok": False,
        "error_code": int(error_code),
        "description": str(description)[:400],
    }
    payload.update(extra)
    return JSONResponse(status_code=int(status), content=payload)


def _detail(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:300]


# --------------------------------------------------------------------------
# 运行期依赖装配（自包含，不要求 main.py 配合）
# --------------------------------------------------------------------------


@dataclass
class OpenApiState:
    """Open API 需要的四个协作者，全部可为空并逐层降级。"""

    settings: Optional[Settings] = None
    db: Optional[Database] = None
    gateway: Optional[Any] = None  # BotGateway
    supervisor: Optional[Any] = None  # BotSupervisor
    source: str = "unbound"


_configured: Optional[OpenApiState] = None
_boot: Optional[OpenApiState] = None
#: 可选：main.py / webhook_relay 插件注册回调，本模块绝不 import plugin_manager。
_webhook_listeners: List[Callable[[Dict[str, Any], str, str], Awaitable[None]]] = []


def configure(
    *,
    settings: Optional[Settings] = None,
    database: Optional[Database] = None,
    gateway: Optional[Any] = None,
    supervisor: Optional[Any] = None,
) -> OpenApiState:
    """显式注入协作者；``main.py`` 启动时调用一次即可（也可以不调用）。"""
    global _configured, _boot
    _configured = OpenApiState(
        settings=settings, db=database, gateway=gateway, supervisor=supervisor, source="configured"
    )
    _boot = None
    return _configured


def reset_state() -> None:
    """清空注入与惰性引导结果（自检/测试用）。"""
    global _configured, _boot
    _configured = None
    _boot = None


def register_webhook_listener(
    callback: Callable[[Dict[str, Any], str, str], Awaitable[None]]
) -> None:
    """注册 ``(bot_row, url, secret) -> awaitable`` 通知钩子。

    ``POST /setWebhook`` 落库成功后会逐个调用；任何异常都被吞掉，绝不影响 HTTP
    响应。留给你（main.py）把 ``webhook_relay`` 插件接进来。
    """
    if callback not in _webhook_listeners:
        _webhook_listeners.append(callback)


_DISCOVERY = {
    "settings": ("settings",),
    "db": ("db", "database"),
    "gateway": ("gateway", "bot_gateway"),
    "supervisor": ("supervisor", "bot_supervisor"),
}


def _looks_like_db(obj: Any) -> bool:
    return not isinstance(obj, type) and all(callable(getattr(obj, a, None)) for a in ("get_bot_by_token", "update_bot", "log_message"))


def _looks_like_gateway(obj: Any) -> bool:
    return not isinstance(obj, type) and all(callable(getattr(obj, a, None)) for a in ("deliver", "get_updates"))


def _looks_like_supervisor(obj: Any) -> bool:
    return not isinstance(obj, type) and all(callable(getattr(obj, a, None)) for a in ("send_text", "client_for"))


def _looks_like_settings(obj: Any) -> bool:
    return not isinstance(obj, type) and all(hasattr(obj, a) for a in ("db_file", "default_locale"))


_PREDICATES = {
    "db": _looks_like_db,
    "gateway": _looks_like_gateway,
    "supervisor": _looks_like_supervisor,
    "settings": _looks_like_settings,
}


def _carrier_values(carrier: Any) -> List[Any]:
    """列出载体上的候选对象。

    ``starlette.datastructures.State``（``app.state``）把属性存进 ``_state``
    字典而不是 ``__dict__``，所以两个来源都要看。
    """
    values = list(vars(carrier).values())
    internal = getattr(carrier, "_state", None)
    if isinstance(internal, dict):
        values.extend(internal.values())
    return values


def _discover_main() -> Dict[str, Any]:
    """软发现 ``app.main`` 的协作者（只看 ``sys.modules``，绝不 import）。

    先按常见属性名找（``gateway`` / ``db`` / ``database`` / ``supervisor`` …），
    找不到再对模块全局与 ``app.state`` 做一次鸭子类型识别，因此 main.py 用
    ``app.state.led`` 之类的命名也能接上。
    """
    found: Dict[str, Any] = {}
    for name in ("app.main", "main"):
        module = sys.modules.get(name)
        if module is None:
            continue
        carriers = [module]
        state = getattr(getattr(module, "app", None), "state", None)
        if state is not None:
            carriers.append(state)
        for key, names in _DISCOVERY.items():
            if found.get(key) is not None:
                continue
            predicate = _PREDICATES.get(key)
            for carrier in carriers:
                for attr in names:
                    value = getattr(carrier, attr, None)
                    if value is not None and not isinstance(value, type) and (
                        predicate is None or predicate(value)
                    ):
                        found[key] = value
                        break
                if found.get(key) is not None:
                    break
        for carrier in carriers:
            for value in _carrier_values(carrier):
                if isinstance(value, type) or isinstance(value, types.ModuleType):
                    continue
                for key, predicate in _PREDICATES.items():
                    if found.get(key) is None and predicate(value):
                        found[key] = value
    return found


def _bootstrap() -> OpenApiState:
    """在没有网关注入时，尽力自行打开配置与账本；失败也只降级不抛错。"""
    global _boot
    if _boot is not None:
        return _boot
    settings: Optional[Settings] = None
    db: Optional[Database] = None
    try:
        settings = load_settings()
    except Exception as exc:  # ConfigError / OSError 等
        log.warning("open_api: 读取配置失败，降级为无账本模式: %s", _detail(exc))
    if settings is not None:
        try:
            db = connect_ledger(settings.db_file)
        except Exception as exc:  # LedgerError / sqlite3.Error / OSError
            log.warning("open_api: 打开账本 %s 失败: %s", getattr(settings, "db_file", "?"), _detail(exc))
    _boot = OpenApiState(settings=settings, db=db, source="lazy")
    return _boot


def get_state() -> OpenApiState:
    """合并三级来源，返回本次请求可用的协作者集合（永不抛错）。"""
    explicit = _configured
    discovered = _discover_main()
    complete = bool(
        explicit
        and all(getattr(explicit, key, None) is not None for key in ("settings", "db", "gateway", "supervisor"))
    )
    boot = explicit if complete else _bootstrap()

    def pick(key: str) -> Any:
        if explicit is not None and getattr(explicit, key, None) is not None:
            return getattr(explicit, key)
        if key in discovered:
            return discovered[key]
        return getattr(boot, key, None)

    source = "configured" if explicit else ("main" if discovered else boot.source)
    return OpenApiState(
        settings=pick("settings"),
        db=pick("db"),
        gateway=pick("gateway"),
        supervisor=pick("supervisor"),
        source=source,
    )


# --------------------------------------------------------------------------
# 鉴权
# --------------------------------------------------------------------------


def _extract_token(request: Request) -> str:
    """按路径 -> Bearer -> 自定义头的顺序取令牌，绝不记录令牌明文。"""
    path_token = (request.path_params.get(PATH_PARAM) or "").strip()
    if not path_token:
        # main.py 也可能把本路由挂在 /api/v1/bot{token} 前缀下。
        path_token = (request.path_params.get("token") or "").strip()
    if path_token:
        return path_token
    header = (request.headers.get("authorization") or "").strip()
    if header:
        parts = header.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
        if len(parts) == 1:  # 容错：裸令牌
            return parts[0].strip()
    return (request.headers.get("x-bot-token") or "").strip()


def _lookup_bot(token: str) -> Union[Dict[str, Any], AuthFailure]:
    state = get_state()
    if state.db is None:
        return AuthFailure(500, 500, "SQLite 账本不可用，无法校验 Bot Token")
    try:
        bot = state.db.get_bot_by_token(token)  # database.py:340 -> None 表示不存在
    except SAFE_EXCEPTIONS as exc:
        return AuthFailure(500, 500, f"账本查询失败 {_detail(exc)}")
    except Exception as exc:  # pragma: no cover - 兜底，绝不让异常出路由
        return AuthFailure(500, 500, f"账本内部错误 {type(exc).__name__}")
    if not bot:
        # 描述里绝不出现期望令牌。
        return AuthFailure(401, 401, "Bot Token 无效或对应 Bot 已删除")
    return bot


async def require_bot(request: Request) -> Union[Dict[str, Any], AuthFailure]:
    """FastAPI 依赖：解析调用方的 Bot 行。

    失败时返回 :class:`AuthFailure`（由 :func:`guard` 转成 401 JSON），而不是抛异常
    —— 依赖里抛出的异常不会被端点外层 try/except 捕获。
    """
    token = _extract_token(request)
    if not token:
        return AuthFailure(
            401,
            401,
            "缺少 Bot Token：请使用 'Authorization: Bearer <BOT_TOKEN>' 或 /bot<TOKEN>/ 路径",
        )
    return _lookup_bot(token)


def guard(fn: Callable[..., Awaitable[JSONResponse]]) -> Callable[..., Awaitable[JSONResponse]]:
    """把鉴权失败与任何运行期异常收敛成规范的 JSON 错误体（错误隔离硬要求）。"""

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> JSONResponse:
        try:
            for value in kwargs.values():
                if isinstance(value, AuthFailure):
                    return fail(value.status, value.error_code, value.description)
            return await fn(*args, **kwargs)
        except ApiError as exc:
            return exc.as_response()
        except SAFE_EXCEPTIONS as exc:
            log.warning("open_api %s 依赖异常: %s", fn.__name__, _detail(exc))
            return fail(500, 500, f"网关/账本暂不可用 {_detail(exc)}")
        except Exception as exc:  # noqa: BLE001 - 硬约束：本路由绝不弄崩网关
            log.exception("open_api %s 未预期异常", fn.__name__)
            return fail(500, 500, f"内部错误 {type(exc).__name__}")

    return wrapper


# --------------------------------------------------------------------------
# 请求体 / 参数解析
# --------------------------------------------------------------------------


async def _payload(request: Request) -> Dict[str, Any]:
    """把 JSON、``application/x-www-form-urlencoded`` 与 query 参数合并成扁平 dict。

    Botfather 用户习惯 ``curl -d 'chat_id=#1&text=hi'``，因此表单必须和 JSON 等价。
    这里手工解析 urlencoded，避免依赖 python-multipart。
    """
    data: Dict[str, Any] = {}
    ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    try:
        raw = await request.body()
    except SAFE_EXCEPTIONS as exc:
        raise ApiError(400, 400, f"读取请求体失败 {_detail(exc)}") from exc
    if raw:
        decoded = raw.decode("utf-8", "replace").strip()
        as_json: Optional[Dict[str, Any]] = None
        if ctype in {"application/json", "text/json"} or (not ctype and decoded[:1] in {"{", "["}):
            try:
                parsed = json.loads(decoded)
            except json.JSONDecodeError as exc:
                raise ApiError(400, 400, f"请求体不是合法 JSON：{exc}") from exc
            if not isinstance(parsed, dict):
                raise ApiError(400, 400, "JSON 请求体必须是对象")
            as_json = parsed
        elif ctype in {"", "application/x-www-form-urlencoded", "text/plain"}:
            pairs = parse_qsl(decoded, keep_blank_values=True)
            as_json = {key: value for key, value in pairs} if pairs else None
            if as_json is None and decoded[:1] == "{":
                try:
                    parsed = json.loads(decoded)
                    as_json = parsed if isinstance(parsed, dict) else None
                except json.JSONDecodeError:
                    as_json = None
        if as_json is None:
            raise ApiError(
                400,
                400,
                f"不支持的 Content-Type {ctype or '未知'!r}：请使用 application/json "
                "或 application/x-www-form-urlencoded",
            )
        data.update(as_json)
    for key, value in request.query_params.items():
        data.setdefault(key, value)
    return data


def _field(data: Dict[str, Any], *names: str, default: str = "") -> str:
    for name in names:
        if name in data and data[name] not in (None, ""):
            value = data[name]
            if isinstance(value, (list, dict)):
                return json.dumps(value, ensure_ascii=False)
            return str(value).strip()
    return default


def _list_field(data: Dict[str, Any], *names: str) -> List[str]:
    """接受 ``["#1","#2"]``、``"#1,#2"``、``"#1 #2"`` 三种写法。"""
    for name in names:
        value = data.get(name)
        if value in (None, "", []):
            continue
        if isinstance(value, (list, tuple)):
            return [str(item).strip() for item in value if str(item).strip()]
        text = str(value).strip()
        if text.startswith("["):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ApiError(400, 400, f"{name} 不是合法 JSON 数组：{exc}") from exc
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        try:
            return parse_targets(text)  # router_engine.py:75，逗号/分号分隔
        except RouterError as exc:
            raise ApiError(400, 400, f"{name} 无法解析：{exc}") from exc
    return []


def _bool_field(data: Dict[str, Any], *names: str) -> bool:
    return _field(data, *names).lower() in {"1", "true", "yes", "on", "y"}


def _int_field(data: Dict[str, Any], name: str, default: int) -> int:
    raw = data.get(name)
    if raw in (None, ""):
        return default
    try:
        return int(str(raw).strip())
    except ValueError as exc:
        raise ApiError(400, 400, f"{name} 必须是整数，当前值 {raw!r}") from exc


def _as_group_ref(value: str) -> str:
    """``42``/``-42``/``#42`` -> ``#42``；``@7`` 等非群组返回空串。"""
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("-") and text[1:].isdigit():
        text = f"#{text[1:]}"
    elif text.isdigit():
        text = f"#{text}"
    if not text.startswith("#"):
        return ""
    try:
        parse_chat_ref(text)  # bot_supervisor.py:227，非法格式抛 BotSupervisorError
    except BotSupervisorError:
        return ""
    return text


def _normalize_chat_ref(value: str) -> Tuple[str, str]:
    """返回 ``(chat_ref, chat_type)``；格式非法时以 400 拒绝。"""
    text = str(value or "").strip()
    if text.startswith("-") and text[1:].isdigit():  # Telegram 风格的负数群组号
        text = f"#{text[1:]}"
    elif text.isdigit():  # 裸正整数按 parse_chat_ref 的文档视为单聊联系人
        text = f"@{text}"
    try:
        chat_type, _ = parse_chat_ref(text)
    except BotSupervisorError as exc:
        raise ApiError(400, 400, f"{exc}（Open API 要求 @<contactId> 或 #<groupId>）") from exc
    return text, chat_type


def _validate_webhook_url(raw: str) -> str:
    """仅允许 https 或回环 http；其余 400（prompt.md §1 严格回环隔离）。"""
    url = (raw or "").strip()
    if len(url) > MAX_WEBHOOK_LENGTH:
        raise ApiError(400, 400, f"Webhook URL 过长（上限 {MAX_WEBHOOK_LENGTH} 字符）")
    try:
        parts = urlsplit(url)
        port = parts.port  # 非法端口在这里抛 ValueError
    except ValueError as exc:
        raise ApiError(400, 400, f"Webhook URL 无法解析：{exc}") from exc
    scheme = (parts.scheme or "").lower()
    if not scheme:
        raise ApiError(400, 400, "Webhook URL 必须带 scheme，例如 https://host/hook")
    if scheme not in {"https", "http"}:
        raise ApiError(400, 400, f"Webhook 协议 {scheme!r} 被拒绝：只支持 https 或回环 http")
    host = (parts.hostname or "").strip()
    if not host:
        raise ApiError(400, 400, "Webhook URL 缺少主机名")
    if scheme == "http" and not is_loopback_host(host):  # config.py:79
        raise ApiError(
            400, 400, f"明文 http 只允许回环地址（127.0.0.1/::1/localhost），当前为 {host}"
        )
    if parts.username or parts.password:
        raise ApiError(400, 400, "Webhook URL 不能内嵌用户名或密码")
    if parts.fragment:
        raise ApiError(400, 400, "Webhook URL 不能带 fragment")
    if port not in (None, 80, 443) and scheme == "http" and not is_loopback_host(host):
        raise ApiError(400, 400, "非回环 Webhook 不允许自定义端口")
    return parts.geturl()


# --------------------------------------------------------------------------
# 发送与群组目标
# --------------------------------------------------------------------------


async def _deliver(
    state: OpenApiState, bot_id: str, chat_ref: str, text: str, *, quoted: Optional[int] = None
) -> Tuple[bool, str]:
    """通过 ``BotGateway.deliver``（gateway.py:226）投递一条消息。

    网关自身已捕获协议异常并把 ``deliver`` 变成 ``False``；这里再兜一层，防止
    桩实现或未来的网关改版把异常抛出路由。
    """
    gateway = state.gateway
    if gateway is not None and hasattr(gateway, "deliver"):
        try:
            delivered = await gateway.deliver(bot_id, chat_ref, text, quoted_item_id=quoted)
        except SAFE_EXCEPTIONS as exc:
            return False, _detail(exc)
        except Exception as exc:  # noqa: BLE001 - 错误隔离硬要求
            return False, f"{type(exc).__name__}: {exc}"
        return bool(delivered), "" if delivered else "网关拒绝投递（CLI 控制通道未连接或发送失败）"
    supervisor = state.supervisor
    if supervisor is not None and hasattr(supervisor, "send_text"):
        try:  # bot_supervisor.py:699 —— 网关缺席时的直连退路
            await supervisor.send_text(bot_id, chat_ref, text, quoted_item_id=quoted)
            return True, ""
        except SAFE_EXCEPTIONS as exc:
            return False, _detail(exc)
        except Exception as exc:  # noqa: BLE001
            return False, f"{type(exc).__name__}: {exc}"
    raise ApiError(500, 500, "消息网关未初始化（BotGateway 未注入且无法从 app.main 发现）")


def _log_outgoing(state: OpenApiState, bot_id: str, chat_ref: str, chat_type: str, text: str, status: str, error: str = "") -> int:
    if state.db is None:
        return 0
    if status == "error" and state.gateway is not None:
        # BotGateway._send（gateway.py:239）已经把失败写成 status="error"，
        # 这里再写一遍只会在审计日志里造出重复行。
        return 0
    try:
        return state.db.log_message(  # database.py:708
            bot_id,
            "out",
            chat_type=chat_type,
            chat_ref=chat_ref,
            text=text[:2000],
            status=status,
            error=error[:300],
        )
    except SAFE_EXCEPTIONS as exc:
        log.warning("open_api: 审计日志写入失败 %s", _detail(exc))
        return 0
    except Exception as exc:  # noqa: BLE001
        log.warning("open_api: 审计日志写入异常 %s", type(exc).__name__)
        return 0


def _group_targets(state: OpenApiState, bot_id: str, explicit: List[str]) -> List[str]:
    """推导该 Bot 可播报的群组目标（去重、保序）。

    调用方显式给出 ``chat_ids`` 时*只*用它（可预期的覆盖语义）；否则依次取
    路由引擎从 ``message_logs`` 学到的群组（router_engine.py:330 ``known_groups``）
    -> ``routing_rules`` 里的群组目标 -> 直接扫描 ``message_logs`` 兜底。
    """
    refs: List[str] = []
    seen = set()

    def add(value: str) -> None:
        ref = _as_group_ref(value)
        if ref and ref not in seen:
            seen.add(ref)
            refs.append(ref)

    for value in explicit:
        add(value)
    if refs:
        return refs

    router = getattr(state.gateway, "router", None)
    if router is not None and hasattr(router, "known_groups"):
        try:
            for ref in router.known_groups(bot_id) or []:
                add(ref)
        except SAFE_EXCEPTIONS as exc:
            log.warning("open_api: known_groups 失败 %s", _detail(exc))
        except Exception as exc:  # noqa: BLE001
            log.warning("open_api: known_groups 异常 %s", type(exc).__name__)

    if state.db is not None:
        try:
            for rule in state.db.list_routing_rules(bot_id):  # database.py:618
                if str(rule.get("target_type") or "") == "group":
                    for ref in parse_targets(str(rule.get("target_ref") or "")):
                        add(ref)
        except SAFE_EXCEPTIONS as exc:
            log.warning("open_api: 读取路由规则失败 %s", _detail(exc))
        except Exception as exc:  # noqa: BLE001
            log.warning("open_api: 读取路由规则异常 %s", type(exc).__name__)

    if not refs and state.db is not None:
        try:
            for row in state.db.recent_logs(bot_id, limit=500):  # database.py:749
                if str(row.get("chat_type") or "") == "group":
                    add(str(row.get("chat_ref") or ""))
        except SAFE_EXCEPTIONS as exc:
            log.warning("open_api: 扫描消息日志失败 %s", _detail(exc))
        except Exception as exc:  # noqa: BLE001
            log.warning("open_api: 扫描消息日志异常 %s", type(exc).__name__)
    return refs


async def _notify_webhook(bot: Dict[str, Any], url: str, secret: str) -> None:
    for listener in list(_webhook_listeners):
        try:
            await listener(bot, url, secret)
        except Exception as exc:  # noqa: BLE001 - 插件故障不影响 HTTP 响应
            log.warning("open_api: webhook 监听器 %s 失败 %s", getattr(listener, "__name__", listener), _detail(exc))


# --------------------------------------------------------------------------
# 端点实现
# --------------------------------------------------------------------------


def _identity(bot: Dict[str, Any], state: OpenApiState) -> Dict[str, Any]:
    locale = str(bot.get("default_locale") or "") or str(
        getattr(state.settings, "default_locale", "") or "en"
    )
    permanent = str(bot.get("permanent_link") or "")
    result: Dict[str, Any] = {
        "id": bot.get("id", ""),
        "name": bot.get("name", ""),
        "display_name": str(bot.get("display_name") or bot.get("name") or ""),
        "status": bot.get("status", ""),
        "port": int(bot.get("port") or 0),
        "locale": locale,
        "can_send_messages": str(bot.get("status") or "") == "running",
        "auto_accept": bool(int(bot.get("auto_accept") or 0)),
        "accept_incognito": bool(int(bot.get("accept_incognito") or 0)),
        "welcome_text": str(bot.get("welcome_text") or ""),
        "has_webhook": bool(str(bot.get("webhook_url") or "")),
        "api_methods": list(OPEN_METHODS),
    }
    if permanent:  # 账本里已生成永久联系地址时才给出
        result["permanent_link"] = permanent
    contact = str(bot.get("contact_address") or "")
    if contact:
        result["contact_address"] = contact
    return result  # 刻意不返回 bot_token


@guard
async def get_me(request: Request, bot: Dict[str, Any] = Depends(require_bot)) -> JSONResponse:
    """``GET /getMe`` —— 返回 Bot 身份（不含令牌）。"""
    return ok(_identity(bot, get_state()))


@guard
async def send_message(request: Request, bot: Dict[str, Any] = Depends(require_bot)) -> JSONResponse:
    """``POST /sendMessage`` —— 向单个会话发送文本；JSON 与表单等价。"""
    data = await _payload(request)
    raw_ref = _field(data, "chat_id", "chat_ref", "to", "target", "chat")
    if not raw_ref:
        raise ApiError(400, 400, "缺少 chat_id：应为 @<contactId> 或 #<groupId>")
    text = _field(data, "text", "message", "body")
    if not text:
        raise ApiError(400, 400, "缺少 text：消息内容不能为空")
    if len(text) > MAX_TEXT_LENGTH:
        raise ApiError(400, 400, f"text 过长（{len(text)} > {MAX_TEXT_LENGTH} 字符）")
    chat_ref, chat_type = _normalize_chat_ref(raw_ref)
    quoted = None
    quoted_raw = _field(data, "quoted_message_id", "quoted_item_id", "reply_to_message_id")
    if quoted_raw:
        try:
            quoted = int(quoted_raw)
        except ValueError as exc:
            raise ApiError(400, 400, f"quoted_message_id 必须是整数，当前值 {quoted_raw!r}") from exc
    state = get_state()
    delivered, reason = await _deliver(state, str(bot.get("id") or ""), chat_ref, text, quoted=quoted)
    if not delivered:
        log_id = _log_outgoing(state, str(bot.get("id") or ""), chat_ref, chat_type, text, "error", reason)
        return fail(
            500,
            500,
            f"消息未能送达 {chat_ref}：{reason or '网关返回失败'}（Bot 状态 {bot.get('status', '')}）",
            result={"chat_ref": chat_ref, "delivered": False, "log_id": log_id},
        )
    log_id = _log_outgoing(state, str(bot.get("id") or ""), chat_ref, chat_type, text, "ok")
    return ok(
        {
            "chat_ref": chat_ref,
            "chat_type": chat_type,
            "text": text,
            "delivered": True,
            "quoted_message_id": quoted,
            "log_id": log_id,
            "bot_status": bot.get("status", ""),
        }
    )


@guard
async def broadcast_group(request: Request, bot: Dict[str, Any] = Depends(require_bot)) -> JSONResponse:
    """``POST /broadcastGroup`` —— 同一文本群发给该 Bot 已知的所有群组。"""
    data = await _payload(request)
    text = _field(data, "text", "message", "body")
    if not text:
        raise ApiError(400, 400, "缺少 text：播报内容不能为空")
    if len(text) > MAX_TEXT_LENGTH:
        raise ApiError(400, 400, f"text 过长（{len(text)} > {MAX_TEXT_LENGTH} 字符）")
    state = get_state()
    bot_id = str(bot.get("id") or "")
    explicit = _list_field(data, "chat_ids", "group_ids", "groups", "targets", "chat_id")
    targets = _group_targets(state, bot_id, explicit)
    if not targets:
        return fail(
            404,
            404,
            f"Bot {bot_id} 没有可播报的群组：message_logs 与 routing_rules 里都没有 #<groupId> 目标，"
            "可在请求体里用 chat_ids=#12,#34 显式指定，或先在群内让 Bot 收到过消息",
        )
    if _bool_field(data, "dry_run", "preview"):
        return ok({"targets": targets, "total": len(targets), "dry_run": True, "sent": 0, "failed": 0, "results": []})
    results: List[Dict[str, Any]] = []
    sent = 0
    for chat_ref in targets:
        delivered, reason = await _deliver(state, bot_id, chat_ref, text)
        _log_outgoing(state, bot_id, chat_ref, "group", text, "ok" if delivered else "error", reason)
        if delivered:
            sent += 1
        results.append({"chat_ref": chat_ref, "ok": delivered, "error": reason})
    summary = {
        "targets": targets,
        "total": len(targets),
        "sent": sent,
        "failed": len(targets) - sent,
        "results": results,
    }
    if sent == 0:
        return fail(
            500,
            500,
            f"群发全部失败（0/{len(targets)}）：{results[0]['error'] or '网关拒绝投递'}",
            result=summary,
        )
    if sent == len(targets):
        return ok(summary)
    # 部分成功仍然返回 200，但明确标注 partial 与逐目标明细。
    return JSONResponse(
        status_code=200,
        content={
            "ok": True,
            "result": summary,
            "partial": True,
            "description": f"部分成功：{sent}/{len(targets)} 个群组已送达",
        },
    )


@guard
async def set_webhook(request: Request, bot: Dict[str, Any] = Depends(require_bot)) -> JSONResponse:
    """``POST /setWebhook`` —— 注册/注销出站 Webhook（仅 https 或回环 http）。"""
    data = await _payload(request)
    if "url" not in data and "webhook_url" not in data:
        raise ApiError(400, 400, "缺少 url：注销请传 url=（空串）")
    raw_url = _field(data, "url", "webhook_url")
    state = get_state()
    if state.db is None:
        raise ApiError(500, 500, "SQLite 账本不可用，无法持久化 Webhook 配置")
    bot_id = str(bot.get("id") or "")
    secret = _field(data, "secret", "webhook_secret", "secret_token")
    url = "" if raw_url == "" else _validate_webhook_url(raw_url)
    if url and not secret:
        # 出站回调需要一个校验头，未提供就生成一个并回显给开发者。
        secret = str(bot.get("webhook_secret") or "") or secrets.token_hex(16)
    try:
        # database.py:362；webhook_url / webhook_secret 都在 BOT_FIELDS 白名单里
        updated = state.db.update_bot(bot_id, webhook_url=url, webhook_secret=secret)
    except SAFE_EXCEPTIONS as exc:
        raise ApiError(500, 500, f"写入 Webhook 配置失败 {_detail(exc)}") from exc
    # main.py 可在此处接线：open_api.register_webhook_listener(...)
    await _notify_webhook(updated or bot, url, secret if url else "")
    return ok(
        {
            "webhook_url": url,
            "active": bool(url),
            "secret": secret if url else "",
            "updated_at": (updated or {}).get("updated_at", time.time()),
        }
    )


def _read_updates(state: OpenApiState, bot_id: str, offset: int, limit: int) -> List[Dict[str, Any]]:
    gateway = state.gateway
    if gateway is not None and hasattr(gateway, "get_updates"):
        try:
            return list(gateway.get_updates(bot_id, offset=offset, limit=limit) or [])  # gateway.py:268（同步）
        except SAFE_EXCEPTIONS as exc:
            raise ApiError(500, 500, f"读取更新缓冲失败 {_detail(exc)}") from exc
        except Exception as exc:  # noqa: BLE001
            raise ApiError(500, 500, f"网关内部错误 {type(exc).__name__}") from exc
    if state.db is None:
        raise ApiError(500, 500, "消息网关与账本均未初始化，无法提供 getUpdates")
    try:  # 退路：直接从审计日志重建 update 流（gateway 缺席时）
        rows = state.db.recent_logs(bot_id, limit=min(limit, 500))
    except SAFE_EXCEPTIONS as exc:
        raise ApiError(500, 500, f"读取消息日志失败 {_detail(exc)}") from exc
    updates: List[Dict[str, Any]] = []
    for row in reversed(rows):
        update_id = int(row.get("id") or 0)
        if update_id <= offset:
            continue
        updates.append(
            {
                "update_id": update_id,
                "bot_id": bot_id,
                "event": "message",
                "direction": row.get("direction", ""),
                "chat_type": row.get("chat_type", ""),
                "chat_ref": row.get("chat_ref", ""),
                "sender": row.get("sender", ""),
                "text": row.get("text", ""),
                "status": row.get("status", ""),
                "ts": row.get("ts", 0),
                "source": "message_logs",
            }
        )
    return updates[-limit:] if limit else updates


@guard
async def get_updates(request: Request, bot: Dict[str, Any] = Depends(require_bot)) -> JSONResponse:
    """``GET /getUpdates`` —— 读取网关更新缓冲（支持 offset/limit/timeout 短轮询）。"""
    data = dict(request.query_params)
    offset = _int_field(data, "offset", 0)
    if offset < 0:
        raise ApiError(400, 400, "offset 不能为负数")
    limit = _int_field(data, "limit", DEFAULT_LIMIT)
    if not 1 <= limit <= MAX_LIMIT:
        raise ApiError(400, 400, f"limit 必须在 1-{MAX_LIMIT} 之间，当前值 {limit}")
    timeout = float(_int_field(data, "timeout", 0))
    if timeout < 0:
        raise ApiError(400, 400, "timeout 不能为负数")
    timeout = min(timeout, MAX_POLL_SECONDS)
    state = get_state()
    bot_id = str(bot.get("id") or "")
    started = time.monotonic()
    deadline = started + timeout
    updates = _read_updates(state, bot_id, offset, limit)
    while not updates and time.monotonic() < deadline:
        await asyncio.sleep(min(POLL_INTERVAL, max(0.0, deadline - time.monotonic())))
        updates = _read_updates(state, bot_id, offset, limit)
    latest = max((int(item.get("update_id") or 0) for item in updates), default=offset)
    return ok(
        updates,
        count=len(updates),
        offset=latest,
        oldest=updates[0].get("update_id") if updates else None,
        buffer_limit=MAX_LIMIT,
        long_poll_waited=round(time.monotonic() - started, 3),
    )


# --------------------------------------------------------------------------
# 路由注册：每个方法挂两次（裸路径 + /bot<TOKEN> 路径）
# --------------------------------------------------------------------------

router = APIRouter(tags=["open-api"])

_HANDLERS: Dict[str, Tuple[str, Callable[..., Awaitable[JSONResponse]]]] = {
    "/getMe": ("GET", get_me),
    "/sendMessage": ("POST", send_message),
    "/broadcastGroup": ("POST", broadcast_group),
    "/setWebhook": ("POST", set_webhook),
    "/getUpdates": ("GET", get_updates),
}

for _suffix, (_method, _handler) in _HANDLERS.items():
    router.add_api_route(
        _suffix,
        _handler,
        methods=[_method],
        name=f"open_api{_suffix.strip('/')}",
        summary=f"{_method} {_suffix}",
        description=(_handler.__doc__ or "").strip(),
    )
    router.add_api_route(
        f"{PATH_PREFIX}{_suffix}",
        _handler,
        methods=[_method],
        name=f"open_api_path{_suffix.strip('/')}",
        summary=f"{_method} {_suffix}（路径内嵌 Bot Token）",
        description=(_handler.__doc__ or "").strip(),
    )
del _suffix, _method, _handler


def mounted_paths(prefix: str = "/api/v1") -> List[str]:
    """返回实际挂载后的路径清单（供 ``main.py --self-test`` 断言）。"""
    return [f"{prefix}{route.path}" for route in router.routes]
