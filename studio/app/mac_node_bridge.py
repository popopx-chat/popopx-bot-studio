"""Mac Node 回环桥：忙闲读取与确认后的日历落地，只允许 127.0.0.1。

为什么把这几条 HTTP 调用单独做成一个模块，而不是散在编排层里：

1. **闸门必须只有一处。** Mac Node 是本机守护进程，它的控制台令牌 ``X-PPX-Token``
   等于「在本机读写主人日历」的能力。这个能力一旦能被指向别的主机，就等于把令牌
   外送。因此 :func:`guard_loopback_url` 在**每个调用点**、在 socket 打开之前重新
   校验 URL，而不是只在 ``load_settings`` 启动时校验一次：桥接器可以被任何人用任意
   URL 构造出来（``MacNodeBridge(settings)`` 之后 ``settings`` 还是可写的）。
2. **重定向一律不跟随。** ``follow_redirects=False`` 是硬要求：302 指向外网时如果
   跟随，httpx 会把同一个 ``X-PPX-Token`` 头原样带到那台主机上去。所以本模块把
   3xx 当作失败处理，并按 Location 是否回环给出不同 ``reason``。
3. **降级而不是失败。** Mac Node 没启动、没授权、超时是这台 Mac 的常态（合盖、
   刚开机、用户还没在控制台开日历桥）。流水线不能因此断掉，所以忙闲读取失败时回退
   到 ``calendar_cache`` 里的掩码缓存，落地调用则返回结构化失败，永不抛给调用方。

线上字符串逐字符对齐 ``/Users/elliot/popopx-chat/PopopxMacNode`` 的 Swift 实现，
不是凭印象发明：

* ``Sources/PopopxMacNode/Models/MacNodeModels.swift`` —— ``NodeWire.commandPrefix``
  (``::popopx_sys::NODE_CMD::``)、``commandSegmentCount`` (3)、
  ``maxSignalPayloadCharacters`` (1024)、``consolePort`` (18920)、``consoleHost``
  (``127.0.0.1``)、``consoleTokenHeader`` (``X-PPX-Token``)、``consoleTokenQuery``
  (``t``)、``ConsoleRoute`` 路由表；
* ``Sources/PopopxMacNode/WebConsole/LocalWebConsoleServer.swift`` ——
  ``GET /api/health``、``GET /api/snapshot``、``POST /api/engine/invoke``
  （body ``{kind, action, payload}``）、``POST /api/command``（body ``{text}``）、
  ``POST /api/settings``，以及 ``/v1/tools/{domain}/{action}`` 隐私桥接工具面；
* ``Sources/PopopxMacNode/PrivacyBridges/PrivacyToolEngine.swift`` ——
  ``PrivacyToolNamespace``（``calendar`` / ``workspace``）、``PrivacyToolAction``
  （``availability`` / ``proposals`` / ``approve`` / ``reject`` / ``inspect`` /
  ``summarize`` / ``bookings``）、忙闲入参 ``startIso``/``endIso``/``timezone``、
  出参 ``freeSlots:[{start,end}]``、提案入参 ``action``/``title``/``startIso``/
  ``endIso``/``bookingRefId``、出参 ``proposalId``/``approvalReceipt``/
  ``approvePath``/``bookingRefId``、批准入参 ``receipt``、出参
  ``calendarWritten``/``eventIdentifier``。

日历落地因此走的是节点自己的两步式受控通道：``POST /v1/tools/calendar/proposals``
拿到节点签发的 ``approvalReceipt``，再 ``POST <approvePath>`` 把这张回执交回去。
回执只在**主人已经在 ``::POPOPX_ECO::`` 卡片上点了确认**之后才复用（见
:meth:`MacNodeBridge.approve`），桥接器自己从不伪造回执，也从不在确认之前写日历。

令牌永不出现在 :meth:`MacNodeBridge.status`、异常信息或审计 ``detail`` 里：错误
消息只携带路由路径（不带 query），令牌头在日志前一律掩掉。
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone as _UTC
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx

from .config import DEFAULT_MAC_NODE_URL, Settings, is_loopback_host
from .database import Database

# --------------------------------------------------------------- 逐字对齐 Swift
COMMAND_PREFIX = "::popopx_sys::NODE_CMD::"
COMMAND_SEGMENT_COUNT = 3
MAX_SIGNAL_PAYLOAD_CHARACTERS = 1024
CONSOLE_PORT = 18920
CONSOLE_HOST = "127.0.0.1"
TOKEN_HEADER = "X-PPX-Token"
TOKEN_QUERY = "t"

HEALTH_PATH = "/api/health"
SNAPSHOT_PATH = "/api/snapshot"
ENGINE_INVOKE_PATH = "/api/engine/invoke"
ENGINE_TOGGLE_PATH = "/api/engine/toggle"
COMMAND_PATH = "/api/command"
SETTINGS_PATH = "/api/settings"
TOOL_PREFIX = "/v1/tools/"

CALENDAR_NAMESPACE = "calendar"
WORKSPACE_NAMESPACE = "workspace"
ACTION_AVAILABILITY = "availability"
ACTION_PROPOSALS = "proposals"
ACTION_APPROVE = "approve"
ACTION_REJECT = "reject"
ACTION_INSPECT = "inspect"
ACTION_SUMMARIZE = "summarize"
ACTION_BOOKINGS = "bookings"
ID_BEARING_ACTIONS = (ACTION_APPROVE, ACTION_REJECT, ACTION_INSPECT)
TOOL_ACTIONS = (
    ACTION_AVAILABILITY,
    ACTION_PROPOSALS,
    ACTION_APPROVE,
    ACTION_REJECT,
    ACTION_INSPECT,
    ACTION_SUMMARIZE,
    ACTION_BOOKINGS,
)
TOOL_NAMESPACES = (CALENDAR_NAMESPACE, WORKSPACE_NAMESPACE)

#: ``EngineKind`` 的 rawValue 全集（``MacNodeModels.swift``）。
#: 订阅目录里没有日历引擎：日历走 ``/v1/tools/calendar/*``，这里只保留真实存在的十个。
ENGINE_KINDS = (
    "shadow_cos",
    "zero_trust_warroom",
    "zerotrace_studio",
    "solo_autopilot",
    "edge_compute_mesh",
    "morning_tv",
    "phantom_sentinel",
    "chrono_ark",
    "health_sentinel",
    "creator_paywall_hub",
)

REASONS = (
    "disabled",
    "non_loopback",
    "timeout",
    "unreachable",
    "auth",
    "bad_response",
    "unsupported",
)

#: 注入式 transport 与真实 transport 之间的内部约定：body 不是 JSON 对象时，用这个
#: 键把原始文本带回来（不是 Mac Node 的字段，是我们自己的 transport 契约）。
NON_JSON_KEY = "_non_json"

CACHE_SOURCE = "mac_node"
CACHE_TTL_SECONDS = 900.0
MASK = "***"
#: 这些头的值等同于凭据，任何序列化出口都必须掩掉。
SECRET_HEADERS = frozenset(
    {
        "x-ppx-token",
        "authorization",
        "proxy-authorization",
        "cookie",
        "x-api-key",
        "api-key",
        "x-studio-token",
        "token",
        "secret",
        "receipt",
    }
)

#: transport 契约：``(method, url, headers, json_body, timeout) -> (status, body)``。
Transport = Callable[
    [str, str, Dict[str, str], Optional[Dict[str, Any]], float],
    Awaitable[Tuple[int, Dict[str, Any]]],
]

_DATE_RE_TEXT = "%Y-%m-%d"


class MacNodeError(RuntimeError):
    """桥接失败。``reason`` 是编排层唯一需要区分的分类，取自 :data:`REASONS`。"""

    def __init__(self, reason: str, detail: str = "") -> None:
        if reason not in REASONS:
            raise ValueError(f"非法 MacNode 失败原因 {reason!r}，应为 {list(REASONS)}")
        super().__init__(f"[{reason}] {detail}" if detail else f"[{reason}]")
        self.reason = reason
        self.detail = detail


# ------------------------------------------------------------------- URL 闸门
def guard_loopback_url(url: str) -> str:
    """校验 *url* 是字面回环的 http(s) 地址，返回去掉尾部斜杠的规范化值。

    任何不是回环的形态都在**打开 socket 之前**抛 :class:`MacNodeError`
    (``non_loopback``)：非 http 协议、空主机、带 userinfo、十进制 IP、IPv6 映射
    地址、DNS 名，一律拒绝。这里不复用 :func:`app.config.is_loopback_http_url`
    的布尔结果，因为本函数要按拒绝原因给出可执行的 detail。
    """
    candidate = str(url or "").strip()
    if not candidate:
        raise MacNodeError("non_loopback", "URL 为空")
    if any(char.isspace() or ord(char) < 33 or ord(char) == 127 for char in candidate):
        raise MacNodeError("non_loopback", "URL 含空白或控制字符")
    parts = urlsplit(candidate)
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise MacNodeError("non_loopback", f"协议 {parts.scheme or '空'} 不被允许，只支持 http/https")
    if not parts.netloc:
        raise MacNodeError("non_loopback", "URL 缺少主机")
    if "@" in parts.netloc:
        raise MacNodeError("non_loopback", "URL 不得携带 userinfo（会连同令牌一起外送）")
    host = parts.hostname or ""
    if not host:
        raise MacNodeError("non_loopback", "URL 主机为空")
    if not is_loopback_host(host):
        raise MacNodeError("non_loopback", f"主机 {host} 不是回环地址")
    return candidate.rstrip("/")


def route_of(url: str) -> str:
    """错误消息里只带路径，绝不带 query（query 可能装着 ``?t=<token>``）。"""
    try:
        return urlsplit(str(url or "")).path or "/"
    except ValueError:
        return "/"


def mask_secret(value: Any) -> str:
    """凭据掩码：只回答「有没有」，永不回答「是什么」。"""
    text = "" if value is None else str(value)
    return MASK if text else ""


def mask_mapping(values: Optional[Mapping[str, Any]]) -> Dict[str, str]:
    """按头名掩码，供 ``status()`` 与审计 detail 复用。"""
    masked: Dict[str, str] = {}
    for key, value in dict(values or {}).items():
        name = str(key)
        if name.lower() in SECRET_HEADERS:
            masked[name] = mask_secret(value)
        else:
            masked[name] = str(value)
    return masked


def _epoch(text: Any) -> Optional[float]:
    """ISO-8601（含 ``Z``）-> epoch 秒；解析不了返回 ``None`` 而不是抛。"""
    raw = str(text or "").strip()
    if not raw:
        return None
    if raw.endswith(("Z", "z")):
        raw = raw[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(raw).timestamp()
    except ValueError:
        return None


def iso_utc(ts: float) -> str:
    """epoch 秒 -> ``YYYY-MM-DDTHH:MM:SSZ``（``PrivacyStamp.iso`` 的同形输出）。

    注意这与 :func:`app.ics.stamp` 的 ``YYYYMMDDTHHMMSSZ`` **不是**一种格式：节点侧
    ``Date.ppxFromISO8601`` 用的是 ``ISO8601DateFormatter(.withInternetDateTime)``，
    收到 RFC 5545 的 basic 形式会直接 400。
    """
    return datetime.fromtimestamp(float(ts), _UTC.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _zone(zone_id: str):
    """供「取哪一天」这类标签用途：认不出的时区退回 UTC。

    任何要把时区**换算成绝对时间**的地方都必须走 :func:`day_window`：那里退回 UTC
    等于把整日的忙闲挪十二小时，宁可直接拒绝。
    """
    try:
        return ZoneInfo(str(zone_id or "").strip() or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return _UTC.utc


def day_window(day: str, zone_id: str) -> Tuple[float, float]:
    """*day*（``YYYY-MM-DD``）在 *zone_id* 里的本地零点 → 次日零点（epoch 秒）。

    忙闲必须按主人所在时区取整天，否则 ``23:00 Asia/Shanghai`` 会被切成两个自然日。
    """
    try:
        parsed = datetime.strptime(str(day).strip(), _DATE_RE_TEXT)
    except ValueError as exc:
        raise MacNodeError("bad_response", f"忙闲日期非法：{day!r}") from exc
    wanted = str(zone_id or "").strip()
    if wanted:
        try:
            zone = ZoneInfo(wanted)
        except (ZoneInfoNotFoundError, ValueError):
            raise MacNodeError("unsupported", f"时区 {wanted!r} 不可用，桥不把它当 UTC 猜") from None
    else:
        zone = _UTC.utc
    start = parsed.replace(tzinfo=zone)
    return start.timestamp(), (start + timedelta(days=1)).timestamp()


def tool_path(namespace: str, action: str) -> str:
    """``POST /v1/tools/{domain}/{action}``（``ConsoleRoute.toolPrefix``）。"""
    return f"{TOOL_PREFIX}{namespace}/{action}"


def decision_path(namespace: str, proposal_id: str, verb: str) -> str:
    """``POST /v1/tools/{domain}/proposals/{id}/{verb}``（``proposalDecision``）。"""
    return f"{TOOL_PREFIX}{namespace}/{ACTION_PROPOSALS}/{proposal_id}/{verb}"


# --------------------------------------------------------------------- 结果形状
@dataclass
class NodeOutcome:
    """落地调用的统一返回：永不抛异常，``reason`` 为空即成功。"""

    ok: bool
    event_id: str = ""
    reason: str = ""
    detail: Dict[str, Any] | None = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "event_id": self.event_id,
            "reason": self.reason,
            "detail": dict(self.detail or {}),
        }


def _booking_ref(value: Any) -> str:
    """节点只认它自己签发过的预订号（``isSafeId``：字母数字 ``-`` ``_``，≤64）。"""
    text = str(value or "").strip()
    if not text or len(text) > 64:
        return ""
    if any(not (ch.isalnum() or ch in "-_") for ch in text):
        return ""
    return text


class MacNodeBridge:
    """Mac 本机的 ``PopopxMacNode`` 控制台客户端（回环 only）。

    :param settings: 提供 ``mac_node_enabled`` / ``mac_node_url`` / ``mac_node_token``
        / ``mac_node_timeout_seconds``；构造时不校验 URL（``status()`` 要能如实反映
        一个被配错的地址），但每个网络调用都会重新过 :func:`guard_loopback_url`。
    :param transport: 注入的假传输（自检与单测用）；默认走 ``httpx`` 且
        ``follow_redirects=False``。
    :param token: 覆盖 ``settings.mac_node_token``，用于按会话轮换的令牌。
    :param db: 忙闲掩码缓存所在的账本；不给就只读不缓存。
    """

    def __init__(
        self,
        settings: Any,
        *,
        transport: Optional[Transport] = None,
        token: Optional[str] = None,
        db: Optional[Database] = None,
    ) -> None:
        self.settings: Settings = settings
        self._transport: Transport = transport or _httpx_transport
        self._token = str(token if token is not None else getattr(settings, "mac_node_token", "") or "")
        self._db = db
        self.last_reason = ""
        self.last_detail = ""
        self.calls = 0
        self.failures = 0

    # ------------------------------------------------------------------ 只读口
    def enabled(self) -> bool:
        return bool(getattr(self.settings, "mac_node_enabled", False))

    def base_url(self) -> str:
        raw = str(getattr(self.settings, "mac_node_url", "") or DEFAULT_MAC_NODE_URL).strip()
        return raw.rstrip("/") or DEFAULT_MAC_NODE_URL

    def timeout(self) -> float:
        return float(getattr(self.settings, "mac_node_timeout_seconds", 8.0) or 8.0)

    def status(self) -> Dict[str, Any]:
        """控制台可见的桥接状态。**永不含令牌**，凭据类头的值一律掩码。"""
        base = self.base_url()
        try:
            guard_loopback_url(base)
            loopback = True
            refused = ""
        except MacNodeError as exc:
            loopback = False
            refused = exc.detail
        headers = mask_mapping(self._headers())
        return {
            "enabled": self.enabled(),
            "base_url": base,
            "loopback": loopback,
            "loopback_refusal": refused,
            "timeout_seconds": self.timeout(),
            "token_present": bool(self._token),
            "token": mask_secret(self._token),
            "headers": headers,
            "transport": "injected" if self._transport is not _httpx_transport else "httpx",
            "follow_redirects": False,
            "cache": "ledger" if self._db is not None else "none",
            "last_reason": self.last_reason,
            "calls": self.calls,
            "failures": self.failures,
            "routes": {
                "health": HEALTH_PATH,
                "snapshot": SNAPSHOT_PATH,
                "engine_invoke": ENGINE_INVOKE_PATH,
                "command": COMMAND_PATH,
                "settings": SETTINGS_PATH,
                "availability": tool_path(CALENDAR_NAMESPACE, ACTION_AVAILABILITY),
                "proposals": tool_path(CALENDAR_NAMESPACE, ACTION_PROPOSALS),
                "bookings": tool_path(CALENDAR_NAMESPACE, ACTION_BOOKINGS),
            },
            "command_prefix": COMMAND_PREFIX,
            "payload_char_limit": MAX_SIGNAL_PAYLOAD_CHARACTERS,
        }

    # ----------------------------------------------------------------- 内部细节
    def _headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": "popopx-bot-studio/mac-node-bridge"}
        if self._token:
            headers[TOKEN_HEADER] = self._token
        return headers

    def _endpoint(self, path: str) -> str:
        """拼出完整 URL 并在此处（每个调用点）重新做回环闸门。"""
        if not self.enabled():
            raise MacNodeError("disabled", "MAC_NODE_ENABLED 未开启，桥接器不会打开 socket")
        clean = str(path or "")
        if not clean.startswith("/"):
            clean = "/" + clean
        parts = urlsplit(clean)
        if parts.query and _carries_secret(parts.query):
            # 令牌只走头；一旦允许 query 携带，错误消息与访问日志就会把它带出去。
            raise MacNodeError("unsupported", f"路径 {route_of(clean)} 不得在 query 里携带令牌")
        url = guard_loopback_url(self.base_url() + clean)
        return url

    def _audit(self, event: str, *, level: str = "info", detail: str = "", data: Optional[Dict[str, Any]] = None,
               bot_id: str = "", proposal_id: str = "", negotiation_id: str = "", latency_ms: float = 0.0) -> None:
        if self._db is None:
            return
        try:
            self._db.log_negotiation(
                "mac_node",
                event,
                bot_id=bot_id,
                level=level,
                proposal_id=proposal_id,
                negotiation_id=negotiation_id,
                detail=detail[:500],
                data=dict(data or {}),
                latency_ms=latency_ms,
            )
        except Exception:  # noqa: BLE001 - 审计失败绝不能拖垮一次日历调用
            pass

    def _classify(self, status: int, body: Dict[str, Any], path: str = "/") -> MacNodeError:
        """把非 2xx 的应答翻成带 ``reason`` 的失败（detail 里永不含令牌）。"""
        refusal = str(body.get("refusal") or body.get("error") or "").strip()
        if 300 <= status < 400:
            return _redirect_error(self.base_url(), body.get("location"))
        if status in (401, 403):
            return MacNodeError("auth", refusal or f"{path} 鉴权失败：控制台令牌不匹配")
        if status >= 500:
            return MacNodeError("unreachable", refusal or f"Mac Node 在 {path} 返回 {status}")
        return MacNodeError("bad_response", refusal or f"Mac Node 在 {path} 返回 {status}")

    async def _call(self, method: str, url: str, payload: Optional[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
        started = time.perf_counter()
        self.calls += 1
        try:
            raw = await self._transport(method, url, self._headers(), payload, self.timeout())
        except MacNodeError:
            self.failures += 1
            raise
        except (TimeoutError, OSError) as exc:  # noqa: ASYNC101 - 注入式假传输也会走这里
            self.failures += 1
            raise MacNodeError("timeout" if isinstance(exc, TimeoutError) else "unreachable",
                               f"{route_of(url)} 传输层失败：{type(exc).__name__}") from exc
        except Exception as exc:  # noqa: BLE001 - 任何 transport 异常都不得冒到流水线
            self.failures += 1
            raise MacNodeError("unreachable", f"{route_of(url)} 传输层异常：{type(exc).__name__}") from exc
        latency_ms = (time.perf_counter() - started) * 1000.0
        status, body = _unpack_response(raw, route_of(url))
        if 300 <= status < 400:
            # transport 没自己拦下来（例如假传输），这里补一道：绝不跟随。
            self.failures += 1
            raise self._classify(status, body, route_of(url))
        return status, body

    async def request(
        self,
        method: str,
        path: str,
        *,
        payload: Optional[Dict[str, Any]] = None,
        bot_id: str = "",
        proposal_id: str = "",
        negotiation_id: str = "",
    ) -> Dict[str, Any]:
        """一次调用，失败即抛 :class:`MacNodeError`；``availability`` 之上各口的原子入口。"""
        try:
            url = self._endpoint(path)
        except MacNodeError as error:
            # 闸门拒绝时一个字节都没外送，但控制台必须能看到「为什么没落地」：
            # last_reason/last_detail 只在 HTTP 失败分支记账的话，配错地址就等于静默失败。
            self.failures += 1
            self.last_reason, self.last_detail = error.reason, error.detail
            self._audit(
                "request_refused",
                level="error",
                detail=error.detail,
                data={"method": method, "path": route_of(str(path or "")), "reason": error.reason},
                bot_id=bot_id,
                proposal_id=proposal_id,
                negotiation_id=negotiation_id,
            )
            raise
        status, body = await self._call(method, url, payload)
        if status >= 400:
            self.failures += 1
            error = self._classify(status, body, route_of(url))
            self.last_reason, self.last_detail = error.reason, error.detail
            self._audit(
                "request_error",
                level="error",
                detail=error.detail,
                data={"method": method, "path": route_of(url), "status": status},
                bot_id=bot_id,
                proposal_id=proposal_id,
                negotiation_id=negotiation_id,
            )
            raise error
        self.last_reason, self.last_detail = "", ""
        self._audit(
            "request_ok",
            detail=f"{method} {route_of(url)} {status}",
            data={"method": method, "path": route_of(url), "status": status},
            bot_id=bot_id,
            proposal_id=proposal_id,
            negotiation_id=negotiation_id,
        )
        return body

    # ------------------------------------------------------------------ 控制台口
    async def health(self) -> Dict[str, Any]:
        """``GET /api/health``（读路由，Swift 的 ``WEBHealth``）。"""
        return await self.request("GET", HEALTH_PATH)

    async def snapshot(self) -> Dict[str, Any]:
        """``GET /api/snapshot``。"""
        return await self.request("GET", SNAPSHOT_PATH)

    async def push_settings(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """``POST /api/settings``：整套 ``NodeSettings`` 由调用方给出，本层不裁剪。

        名字不能叫 ``settings``：``self.settings`` 是构造时传入的 :class:`Settings`
        实例属性，同名方法会被它永久遮蔽而调不出来。
        """
        if not isinstance(payload, dict):
            raise MacNodeError("bad_response", "settings 载荷必须是 JSON 对象")
        return await self.request("POST", SETTINGS_PATH, payload=payload)

    async def engine(self, kind: str, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """``POST /api/engine/invoke``，body 为 ``{kind, action, payload}``。

        ``kind`` 必须是 ``EngineKind`` 的 rawValue：Swift 侧
        ``guard let kind = EngineKind(rawValue: body.kind)`` 会拒绝其它任何值，
        而日历能力不在 ``EngineKind`` 里，在 ``/v1/tools/calendar/*``。
        """
        clean = str(kind or "").strip()
        if clean not in ENGINE_KINDS:
            raise MacNodeError(
                "unsupported",
                f"引擎 {clean!r} 不是 EngineKind 的取值；日历请走 /v1/tools/calendar/*",
            )
        verb = str(action or "").strip()
        if not verb:
            raise MacNodeError("bad_response", "engine action 不能为空（Swift: action is required）")
        if not isinstance(payload, dict):
            raise MacNodeError("bad_response", "engine payload 必须是 JSON 对象")
        return await self.request(
            "POST", ENGINE_INVOKE_PATH, payload={"kind": clean, "action": verb, "payload": payload}
        )

    async def command(self, text: str) -> Dict[str, Any]:
        """``POST /api/command``，body ``{"text": ::popopx_sys::NODE_CMD::…}``。

        校验按 ``NodeWire.parseCommand`` 的同一套语法规则做在客户端：marker 必须
        原样打头、marker 之后至少 3 段、serviceId 必须是已知服务、payload 长度受
        ``maxSignalPayloadCharacters`` 约束，且这个 1024 的预算**包含** serviceId 与
        action 两段加两个分隔符（Swift 里是 ``used = serviceId.count + action.count + 2``）。
        """
        line = str(text or "").strip()
        if not line.startswith(COMMAND_PREFIX):
            raise MacNodeError("bad_response", f"命令行缺少 {COMMAND_PREFIX} 前缀")
        segments = line[len(COMMAND_PREFIX):].split("::")
        if len(segments) < COMMAND_SEGMENT_COUNT:
            raise MacNodeError("bad_response", "命令行需为 ::serviceId::action::payload 三段")
        service_id = segments[0].strip()
        action = segments[1].strip()
        payload = "::".join(segments[2:]).strip()
        if not service_id or not action or not payload:
            raise MacNodeError("bad_response", "命令行三段都不能为空")
        if service_id not in ENGINE_KINDS and service_id not in TOOL_NAMESPACES:
            raise MacNodeError("unsupported", f"未知服务 id {service_id!r}（NodeWire.isKnownService 为假）")
        used = len(service_id) + len(action) + 2
        if len(payload) > MAX_SIGNAL_PAYLOAD_CHARACTERS - used:
            raise MacNodeError(
                "unsupported",
                f"payload 长 {len(payload)}，超过命令行总预算 {MAX_SIGNAL_PAYLOAD_CHARACTERS - used} 字符",
            )
        return await self.request("POST", COMMAND_PATH, payload={"text": line})

    async def tool(
        self,
        namespace: str,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        proposal_id: str = "",
        bot_id: str = "",
        negotiation_id: str = "",
    ) -> Dict[str, Any]:
        """隐私桥接工具面：``POST /v1/tools/{domain}/{action}[/{id}/{verb}]``。"""
        domain = str(namespace or "").strip()
        verb = str(action or "").strip()
        if domain not in TOOL_NAMESPACES:
            raise MacNodeError("unsupported", f"未知桥接域 {domain!r}，只有 calendar / workspace")
        if verb not in TOOL_ACTIONS:
            raise MacNodeError("unsupported", f"未知工具动作 {verb!r}，应为 {list(TOOL_ACTIONS)}")
        body = dict(payload or {})
        clean_id = _booking_ref(proposal_id)
        if verb in ID_BEARING_ACTIONS:
            if not clean_id:
                raise MacNodeError("bad_response", f"{verb} 需要一个合法的提案 id")
            if body.get("proposalId") not in (None, "", clean_id):
                raise MacNodeError("bad_response", "body 不得把决定指向另一个提案")
            path = decision_path(domain, clean_id, verb)
        else:
            path = tool_path(domain, verb)
        return await self.request(
            "POST", path, payload=body, bot_id=bot_id, proposal_id=clean_id, negotiation_id=negotiation_id
        )

    # -------------------------------------------------------------------- 忙闲
    async def availability(
        self,
        day: str,
        *,
        timezone: str,
        window: Optional[Tuple[float, float]] = None,
        bot_id: str = "",
    ) -> List[Dict[str, Any]]:
        """某天的掩码忙区间 ``[{"start","end","busy":true}]``；失败回退到缓存，最终 ``[]``。

        节点返回的是 ``freeSlots``，忙区间取它在查询窗口内的补集 —— 这样忙闲表
        完全由我们自己算出来，日程标题、参会人、地点在数据结构上就没有机会出现。
        """
        clean_day = str(day or "").strip()
        try:
            lo, hi = day_window(clean_day, timezone) if window is None else (float(window[0]), float(window[1]))
        except (MacNodeError, TypeError, ValueError) as exc:
            self.last_reason = "bad_response"
            self._audit("availability_window", level="warn", detail=str(exc), bot_id=bot_id)
            return []
        started = time.perf_counter()
        try:
            body = await self.tool(
                CALENDAR_NAMESPACE,
                ACTION_AVAILABILITY,
                {"startIso": iso_utc(lo), "endIso": iso_utc(hi), "timezone": str(timezone or "")},
                bot_id=bot_id,
            )
        except MacNodeError as exc:
            self.last_reason = exc.reason
            self._audit(
                "availability_fallback",
                level="warn",
                detail=f"{exc.reason}: {exc.detail}"[:200],
                data={"day": clean_day, "timezone": str(timezone or "")},
                bot_id=bot_id,
                latency_ms=(time.perf_counter() - started) * 1000.0,
            )
            return self._cached_busy(bot_id, clean_day)
        busy = masked_busy(body, lo, hi)
        self._cache_busy(bot_id, clean_day, busy, timezone=timezone)
        self._audit(
            "availability",
            detail=f"{clean_day} 忙 {len(busy)} 段 / 闲 {len(body.get('freeSlots') or [])} 段",
            data={"day": clean_day, "busy": len(busy), "free": len(body.get("freeSlots") or [])},
            bot_id=bot_id,
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )
        return busy

    def _cached_busy(self, bot_id: str, day: str) -> List[Dict[str, Any]]:
        """掩码缓存回退：读到的仍旧只含 start/end，缓存表本身不存日程正文。"""
        if self._db is None or not bot_id:
            return []
        try:
            record = self._db.cached_busy(bot_id, day, source=CACHE_SOURCE)
        except Exception:  # noqa: BLE001 - 降级路径不能因为账本异常而炸
            return []
        if not record:
            return []
        rows: List[Dict[str, Any]] = []
        for item in record.get("busy") or []:
            if not isinstance(item, dict):
                continue
            start, end = item.get("start"), item.get("end")
            if isinstance(start, (int, float)) and isinstance(end, (int, float)) and float(end) > float(start):
                rows.append({"start": float(start), "end": float(end), "busy": True})
        self.last_reason = self.last_reason or "unreachable"
        return rows

    def _cache_busy(self, bot_id: str, day: str, busy: Sequence[Dict[str, Any]], *, timezone: str) -> None:
        if self._db is None or not bot_id:
            return
        try:
            self._db.cache_busy(bot_id, day, list(busy), timezone=str(timezone or ""), source=CACHE_SOURCE,
                                ttl_seconds=CACHE_TTL_SECONDS)
        except Exception:  # noqa: BLE001 - 缓存写失败不影响本次结果
            pass

    async def bookings(self, *, bot_id: str = "") -> List[Dict[str, Any]]:
        """``/v1/tools/calendar/bookings``：POPOPX 自己创建过的预订（节点侧已掩码）。"""
        body = await self.tool(CALENDAR_NAMESPACE, ACTION_BOOKINGS, {}, bot_id=bot_id)
        rows: List[Dict[str, Any]] = []
        for item in body.get("bookings") or []:
            if not isinstance(item, dict):
                continue
            ref = _booking_ref(item.get("bookingRefId"))
            if not ref:
                continue
            rows.append(
                {
                    "booking_ref_id": ref,
                    "status": str(item.get("status") or ""),
                    "start": _epoch(item.get("start")),
                    "end": _epoch(item.get("end")),
                    "sequence": int(item.get("sequence") or 0),
                }
            )
        return rows

    # ------------------------------------------------------------------ 落地
    async def _land(
        self,
        payload: Dict[str, Any],
        *,
        bot_id: str,
        proposal_id: str,
        negotiation_id: str,
        day: str,
        zone: str,
    ) -> NodeOutcome:
        """两步式落地：先 ``proposals`` 拿节点签发的回执，再 ``approve`` 交回去。

        只有 :meth:`approve`（主人已在卡片上点确认）会走到这里，所以「确认之前一个
        字节都不写日历」这条产品约束在本模块里等价于「没人调用 ``_land``」。
        """
        try:
            created = await self.tool(
                CALENDAR_NAMESPACE,
                ACTION_PROPOSALS,
                payload,
                bot_id=bot_id,
                negotiation_id=negotiation_id,
            )
        except MacNodeError as exc:
            return NodeOutcome(False, "", exc.reason, {"stage": "propose", "detail": exc.detail})
        node_id = _booking_ref(created.get("proposalId"))
        receipt = str(created.get("approvalReceipt") or "")
        approve_path = str(created.get("approvePath") or "") or decision_path(CALENDAR_NAMESPACE, node_id, ACTION_APPROVE)
        if created.get("calendarWritten") is True:
            # 节点在提案阶段就写了日历 —— 与本桥的假设相反，宁可停在这里也不重复写。
            # 这一条必须排在回执检查之前：回执缺失只是这一次调用失败，日历已经写了。
            return NodeOutcome(False, "", "unsupported", {"stage": "propose", "detail": "提案阶段就写了日历"})
        if not node_id or not receipt:
            return NodeOutcome(
                False,
                "",
                "bad_response",
                {"stage": "propose", "detail": "节点未返回 proposalId/approvalReceipt，无法执行确认"},
            )
        try:
            done = await self.tool(
                CALENDAR_NAMESPACE,
                ACTION_APPROVE,
                {"receipt": receipt},
                proposal_id=node_id,
                bot_id=bot_id,
                negotiation_id=negotiation_id,
            )
        except MacNodeError as exc:
            return NodeOutcome(
                False,
                _booking_ref(created.get("bookingRefId")),
                exc.reason,
                {"stage": "approve", "detail": exc.detail, "node_proposal_id": node_id},
            )
        event_id = str(done.get("eventIdentifier") or created.get("bookingRefId") or node_id)
        detail = {
            "stage": "approved",
            "node_proposal_id": node_id,
            "booking_ref_id": str(done.get("bookingRefId") or created.get("bookingRefId") or ""),
            "state": str(done.get("state") or ""),
            "calendar_written": bool(done.get("calendarWritten")),
            "sequence": int(done.get("sequence") or 0),
            "executed_at": str(done.get("executedAt") or ""),
        }
        if not detail["calendar_written"]:
            return NodeOutcome(False, event_id, "bad_response", {**detail, "detail": "节点未确认写入日历"})
        if day:
            refreshed = await self.availability(day, timezone=zone, bot_id=bot_id)
            self._cache_busy(bot_id, day, refreshed, timezone=zone)
        return NodeOutcome(True, event_id, "", detail)

    async def create_event(
        self,
        *,
        title: str,
        start_ts: float,
        end_ts: float,
        timezone: str = "",
        location: str = "",
        note: str = "",
        call_link: str = "",
        bot_id: str = "",
        proposal_id: str = "",
        negotiation_id: str = "",
    ) -> Dict[str, Any]:
        """确认后新建日历事件；返回 ``{ok,event_id,reason,detail}``，永不抛。"""
        day, payload, refusal = _draft(
            "create", title=title, start_ts=start_ts, end_ts=end_ts,
            timezone=timezone, location=location, note=note, call_link=call_link,
        )
        if refusal:
            return NodeOutcome(False, "", refusal[0], refusal[1]).as_dict()
        return await self._guarded_land(
            payload, bot_id=bot_id, proposal_id=proposal_id, negotiation_id=negotiation_id,
            day=day, zone=timezone, action="create",
        )

    async def reschedule_event(
        self,
        *,
        booking_ref: str,
        start_ts: float,
        end_ts: Optional[float] = None,
        timezone: str = "",
        bot_id: str = "",
        proposal_id: str = "",
        negotiation_id: str = "",
    ) -> Dict[str, Any]:
        """改期一条 POPOPX 自己创建过的预订（节点只认 ``bookingRefId``）。"""
        ref = _booking_ref(booking_ref)
        if not ref:
            return NodeOutcome(False, "", "bad_response", {"detail": "缺少合法 bookingRefId"}).as_dict()
        if float(start_ts) <= 0:
            return NodeOutcome(False, "", "bad_response", {"detail": "改期需要有效的开始时间"}).as_dict()
        payload: Dict[str, Any] = {"action": "reschedule", "bookingRefId": ref, "startIso": iso_utc(start_ts)}
        if end_ts:
            payload["endIso"] = iso_utc(end_ts)
        if timezone:
            payload["timezone"] = str(timezone)
        return await self._guarded_land(
            payload, bot_id=bot_id, proposal_id=proposal_id, negotiation_id=negotiation_id,
            day=datetime.fromtimestamp(float(start_ts), _zone(timezone)).strftime(_DATE_RE_TEXT),
            zone=timezone, action="reschedule",
        )

    async def cancel_event(
        self,
        *,
        booking_ref: str,
        timezone: str = "",
        bot_id: str = "",
        proposal_id: str = "",
        negotiation_id: str = "",
    ) -> Dict[str, Any]:
        """取消一条 POPOPX 自己创建过的预订。"""
        ref = _booking_ref(booking_ref)
        if not ref:
            return NodeOutcome(False, "", "bad_response", {"detail": "缺少合法 bookingRefId"}).as_dict()
        return await self._guarded_land(
            {"action": "cancel", "bookingRefId": ref},
            bot_id=bot_id, proposal_id=proposal_id, negotiation_id=negotiation_id,
            day="", zone=timezone, action="cancel",
        )

    async def _guarded_land(
        self,
        payload: Dict[str, Any],
        *,
        bot_id: str,
        proposal_id: str,
        negotiation_id: str,
        day: str,
        zone: str,
        action: str,
    ) -> Dict[str, Any]:
        try:
            outcome = await self._land(
                payload, bot_id=bot_id, proposal_id=proposal_id,
                negotiation_id=negotiation_id, day=day, zone=zone,
            )
        except MacNodeError as exc:  # _land 已拦一层，这里兜住闸门本身的异常
            outcome = NodeOutcome(False, "", exc.reason, {"stage": "guard", "detail": exc.detail})
        except Exception as exc:  # noqa: BLE001 - 落地调用的异常绝不允许冒泡
            outcome = NodeOutcome(False, "", "unreachable", {"stage": "guard", "detail": type(exc).__name__})
        self.last_reason = outcome.reason
        level = "info" if outcome.ok else "warn"
        detail_text = f"{action} {outcome.reason or 'ok'} {outcome.detail.get('stage', '')}".strip()
        self._audit(
            f"land_{action}",
            level=level if not outcome.ok else "info",
            detail=detail_text,
            data={
                "action": action,
                "ok": outcome.ok,
                "reason": outcome.reason,
                "stage": str((outcome.detail or {}).get("stage") or ""),
            },
            bot_id=bot_id,
            proposal_id=proposal_id,
            negotiation_id=negotiation_id,
        )
        return outcome.as_dict()

    async def approve(self, proposal: Dict[str, Any]) -> Dict[str, Any]:
        """编排层的唯一确认入口：主人点了「确认」之后落地一条提案。

        终态提案（declined/expired/failed/superseded）一律拒绝复活，返回结构化失败；
        成功则把 ``node_event_id`` 与 ``approved`` 写回账本，并刷新当天掩码忙闲缓存。
        """
        if not isinstance(proposal, dict) or not proposal.get("proposal_id"):
            return NodeOutcome(False, "", "bad_response", {"detail": "提案对象无效"}).as_dict()
        record = dict(proposal)
        pid = str(record.get("proposal_id") or "")
        bot_id = str(record.get("bot_id") or "")
        negotiation_id = str(record.get("negotiation_id") or "")
        zone = str(record.get("timezone") or "")
        status = str(record.get("status") or "")
        if status in ("declined", "expired", "failed", "superseded"):
            outcome = NodeOutcome(False, "", "unsupported", {"detail": f"提案已是终态 {status}，不再落地"})
            self._audit("approve_refused", level="warn", detail=outcome.detail["detail"],
                        bot_id=bot_id, proposal_id=pid, negotiation_id=negotiation_id)
            return outcome.as_dict()
        action = str(record.get("action") or "")
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
        booking_ref = _booking_ref(record.get("node_event_id") or payload.get("booking_ref_id"))
        common = {"bot_id": bot_id, "proposal_id": pid, "negotiation_id": negotiation_id, "timezone": zone}
        if action == "create":
            result = await self.create_event(
                title=str(record.get("summary") or payload.get("title") or ""),
                start_ts=float(record.get("start_ts") or 0),
                end_ts=float(record.get("end_ts") or 0),
                location=str(payload.get("location") or ""),
                note=str(payload.get("note") or ""),
                call_link=str(payload.get("call_link") or ""),
                **common,
            )
        elif action == "reschedule":
            result = await self.reschedule_event(
                booking_ref=booking_ref,
                start_ts=float(record.get("start_ts") or 0),
                end_ts=float(record.get("end_ts") or 0) or None,
                **common,
            )
        elif action == "cancel":
            result = await self.cancel_event(booking_ref=booking_ref, **common)
        else:
            result = NodeOutcome(False, "", "unsupported", {"detail": f"未知提案动作 {action!r}"}).as_dict()
        if self._db is not None:
            try:
                fields: Dict[str, Any] = {"status": "approved" if result["ok"] else "failed"}
                if result["ok"]:
                    fields["node_event_id"] = str(result.get("event_id") or "")
                    fields["error"] = ""
                else:
                    fields["error"] = f"{result.get('reason')}: {str(result.get('detail') or '')}"[:300]
                merged = dict(payload)
                merged["node_outcome"] = {
                    "reason": str(result.get("reason") or ""),
                    "stage": str((result.get("detail") or {}).get("stage") or ""),
                    "booking_ref_id": str((result.get("detail") or {}).get("booking_ref_id") or ""),
                    "calendar_written": bool((result.get("detail") or {}).get("calendar_written")),
                }
                merged["node_outcome"]["at"] = time.time()
                fields["payload"] = merged
                self._db.update_proposal(pid, **fields)
            except Exception as exc:  # noqa: BLE001 - 账本异常不得改写成一次日历失败
                self._audit("approve_ledger", level="warn", detail=f"账本写入失败 {type(exc).__name__}",
                            bot_id=bot_id, proposal_id=pid, negotiation_id=negotiation_id)
        return result


# ------------------------------------------------------------------------- 工具
def _carries_secret(query: str) -> bool:
    """query 里出现令牌类键名就拒绝，这是「异常消息永不含令牌」的结构化保证。"""
    lowered = str(query or "").lower()
    return any(mark in lowered for mark in (f"{TOKEN_QUERY}=", "token=", "secret=", "receipt="))


def _unpack_response(raw: Any, path: str) -> Tuple[int, Dict[str, Any]]:
    if not isinstance(raw, (tuple, list)) or len(raw) != 2:
        raise MacNodeError("bad_response", f"{path} 的 transport 返回形状不是 (status, body)")
    status = raw[0]
    if isinstance(status, bool) or not isinstance(status, int):
        raise MacNodeError("bad_response", f"{path} 的 transport 状态码非法")
    body = raw[1]
    if isinstance(body, dict):
        if NON_JSON_KEY in body:
            raise MacNodeError("bad_response", f"{path} 返回的不是 JSON 对象")
        return int(status), dict(body)
    if body is None:
        return int(status), {}
    raise MacNodeError("bad_response", f"{path} 的响应体不是 JSON 对象")


def _redirect_error(base: str, location: Any) -> MacNodeError:
    """3xx 一律拒绝；Location 指向非回环时按 SSRF 拒绝记账。"""
    target = str(location or "").strip()
    if not target:
        return MacNodeError("unsupported", "Mac Node 返回重定向，桥接器不跟随任何重定向")
    absolute = urljoin(base.rstrip("/") + "/", target)
    try:
        guard_loopback_url(absolute)
    except MacNodeError:
        return MacNodeError("non_loopback", f"重定向指向非回环地址 {route_of(absolute)}，已拒绝")
    return MacNodeError("unsupported", "Mac Node 返回回环重定向，桥接器仍不跟随")


def masked_busy(body: Mapping[str, Any], lo: float, hi: float) -> List[Dict[str, Any]]:
    """把节点的 ``freeSlots`` 变成窗口内的掩码忙区间。

    输出只可能有 ``start``/``end``/``busy`` 三个键 —— 忙闲表在代码层面就没有位置
    放日程标题、参会人或地点。
    """
    free: List[Tuple[float, float]] = []
    for slot in body.get("freeSlots") or []:
        if not isinstance(slot, dict):
            continue
        start = _epoch(slot.get("start"))
        end = _epoch(slot.get("end"))
        if start is None or end is None or end <= start:
            continue
        clipped = (max(lo, start), min(hi, end))
        if clipped[1] > clipped[0]:
            free.append(clipped)
    free.sort()
    busy: List[Dict[str, Any]] = []
    cursor = lo
    for start, end in free:
        if start > cursor:
            busy.append({"start": cursor, "end": start, "busy": True})
        cursor = max(cursor, end)
    if cursor < hi:
        busy.append({"start": cursor, "end": hi, "busy": True})
    return busy


def _draft(
    action: str,
    *,
    title: str,
    start_ts: float,
    end_ts: float,
    timezone: str,
    location: str,
    note: str,
    call_link: str,
) -> Tuple[str, Dict[str, Any], Tuple[str, Dict[str, Any]] | None]:
    """校验 ``/v1/tools/calendar/proposals`` 的 create 入参，返回 (day, payload, refusal)。

    Swift 侧 ``proposeCreate`` 要求 ``title`` 非空、``startIso`` 可解析、结束晚于开始，
    这里提前拒绝，免得把一次注定失败的 POST 打出去。
    """
    if not str(title or "").strip():
        return "", {}, ("bad_response", {"detail": "缺少 title：节点会返回 400"})
    try:
        start = float(start_ts)
        end = float(end_ts)
    except (TypeError, ValueError):
        return "", {}, ("bad_response", {"detail": "起止时间必须是数字"})
    if start <= 0 or end <= start:
        return "", {}, ("bad_response", {"detail": "结束时间必须晚于开始时间"})
    payload: Dict[str, Any] = {
        "action": action,
        "title": str(title).strip()[:240],
        "startIso": iso_utc(start),
        "endIso": iso_utc(end),
    }
    if timezone:
        payload["timezone"] = str(timezone)
    if location:
        payload["location"] = str(location)[:240]
    if note:
        payload["note"] = str(note)[:2000]
    if call_link:
        payload["callLink"] = str(call_link)[:500]
    day = datetime.fromtimestamp(start, _zone(timezone)).strftime(_DATE_RE_TEXT)
    return day, payload, None


async def _httpx_transport(
    method: str,
    url: str,
    headers: Dict[str, str],
    payload: Optional[Dict[str, Any]],
    timeout: float,
) -> Tuple[int, Dict[str, Any]]:
    """真实 transport：回环 only、不跟随重定向、把 JSON 之外的 body 标成非 JSON。"""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.request(method, url, headers=dict(headers), json=payload)
    except httpx.TimeoutException as exc:
        raise MacNodeError("timeout", f"{route_of(url)} 在 {timeout}s 内没有响应") from exc
    except httpx.HTTPError as exc:
        raise MacNodeError("unreachable", f"{route_of(url)} 传输失败：{type(exc).__name__}") from exc
    except OSError as exc:
        raise MacNodeError("unreachable", f"{route_of(url)} 连接失败：{type(exc).__name__}") from exc
    if 300 <= int(response.status_code) < 400:
        raise _redirect_error(url, response.headers.get("location"))
    try:
        body = response.json()
    except ValueError:
        raise MacNodeError("bad_response", f"{route_of(url)} 的响应体不是 JSON") from None
    if not isinstance(body, dict):
        raise MacNodeError("bad_response", f"{route_of(url)} 的响应体不是 JSON 对象")
    return int(response.status_code), body


def bridge_report(bridge: Optional[MacNodeBridge]) -> Dict[str, Any]:
    """给控制台/自检用的安全视图（``None`` 表示未装配桥）。"""
    if bridge is None:
        return {"present": False, "enabled": False, "loopback": False, "token": ""}
    return {"present": True, **bridge.status()}


__all__ = [
    "ACTION_APPROVE",
    "ACTION_AVAILABILITY",
    "ACTION_BOOKINGS",
    "ACTION_INSPECT",
    "ACTION_PROPOSALS",
    "ACTION_REJECT",
    "ACTION_SUMMARIZE",
    "CACHE_SOURCE",
    "CALENDAR_NAMESPACE",
    "COMMAND_PATH",
    "COMMAND_PREFIX",
    "COMMAND_SEGMENT_COUNT",
    "CONSOLE_HOST",
    "CONSOLE_PORT",
    "ENGINE_INVOKE_PATH",
    "ENGINE_KINDS",
    "ENGINE_TOGGLE_PATH",
    "HEALTH_PATH",
    "ID_BEARING_ACTIONS",
    "MASK",
    "MAX_SIGNAL_PAYLOAD_CHARACTERS",
    "NON_JSON_KEY",
    "REASONS",
    "SETTINGS_PATH",
    "SNAPSHOT_PATH",
    "TOOL_ACTIONS",
    "TOOL_NAMESPACES",
    "TOOL_PREFIX",
    "TOKEN_HEADER",
    "TOKEN_QUERY",
    "WORKSPACE_NAMESPACE",
    "MacNodeBridge",
    "MacNodeError",
    "NodeOutcome",
    "bridge_report",
    "day_window",
    "decision_path",
    "guard_loopback_url",
    "iso_utc",
    "masked_busy",
    "mask_mapping",
    "mask_secret",
    "route_of",
    "tool_path",
]
