"""``python3 -m app.selftest_node``：Mac Node 桥与通道 A 协商的离线自检。

两个分组由编排层注册进 :data:`app.selftest.SEL_TEST_GROUPS`（键名 ``mac_node``、``a2a``），
也可以直接 ``python3 -m app.selftest_node`` 单独跑。分组本身无副作用：只用
:meth:`app.selftest.Harness.database` 开的临时账本，不碰真实数据目录，也不改任何全局表。

离线纪律：本文件**不打开 socket、不绑定端口、不访问真实 Mac Node**。每一个网络出口都是
注入的假传输（:class:`FakeNode`），每一次出站帧都由注入的 ``sender`` 截获 —— 断言打在
生产代码路径上，而不是打在替身身上。

覆盖面：SSRF 闸门（userinfo、十进制 IP、DNS 前缀、协议白名单、重定向绝不跟随）、令牌卫生
（``status()``、异常消息、审计 detail 三处都查不出令牌）、节点不可用时的掩码缓存降级、
与 Swift 侧逐字对齐的路由/字段/命令预算、**确认之前一个字节都不写日历**，以及 A2A 的
白名单掩码投影、帧验签/版本/时效/重放/夹带拦截、跨时区与夏令时的交集、协商状态机、
改期重开与「终态行不得悄悄复活」。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

from .a2a import (
    A2A_PREFIX,
    A2A_VERSION,
    FORBIDDEN_KEYS,
    FRAME_KINDS,
    MASKED_KEYS,
    MAX_INTERSECTION,
    MAX_MASKED_SLOTS,
    A2AError,
    Negotiator,
    NonceCache,
    decode_frame,
    encode_frame,
    free_from_busy,
    free_slots,
    intersect_slots,
    mask_slots,
    peek_negotiation_id,
    proposal_card,
    proposal_summary,
    utc_text,
    wall_text,
    _b64e,
    _key_bytes,
)
from .config import DEFAULT_MAC_NODE_URL
from .eco_cards import CALLBACK_APPROVE, CALLBACK_PREFIX, ECO_MARKER, decode_message, parse_callback
from .mac_node_bridge import (
    ACTION_APPROVE,
    ACTION_AVAILABILITY,
    ACTION_BOOKINGS,
    ACTION_PROPOSALS,
    ACTION_REJECT,
    CACHE_SOURCE,
    CALENDAR_NAMESPACE,
    COMMAND_PATH,
    COMMAND_PREFIX,
    ENGINE_INVOKE_PATH,
    ENGINE_KINDS,
    HEALTH_PATH,
    MAX_SIGNAL_PAYLOAD_CHARACTERS,
    MASK,
    NON_JSON_KEY,
    REASONS,
    SNAPSHOT_PATH,
    TOKEN_HEADER,
    TOOL_PREFIX,
    WORKSPACE_NAMESPACE,
    MacNodeBridge,
    MacNodeError,
    NodeOutcome,
    bridge_report,
    day_window,
    decision_path,
    guard_loopback_url,
    iso_utc,
    masked_busy,
    mask_mapping,
    mask_secret,
    route_of,
    tool_path,
)
from .selftest import Harness, SelfTest

NODE_TOKEN = "selftest-node-token-9f3a"
ISO_SHAPE = tuple("Y-m-dTH:M:SZ")


# ------------------------------------------------------------------ 共用替身
class FakeNode:
    """注入式假控制台：按 URL 后缀脚本化应答，并记录每次调用的完整现场。"""

    def __init__(self, **routes: Any) -> None:
        self.routes: Dict[str, Any] = dict(routes)
        self.calls: List[Dict[str, Any]] = []

    def on(self, suffix: str, handler: Any) -> "FakeNode":
        self.routes[suffix] = handler
        return self

    async def __call__(
        self, method: str, url: str, headers: Dict[str, str], payload: Optional[Dict[str, Any]], timeout: float
    ) -> Tuple[int, Dict[str, Any]]:
        self.calls.append({"method": method, "url": url, "headers": dict(headers), "payload": payload,
                           "timeout": timeout})
        for suffix, handler in self.routes.items():
            if str(url).endswith(suffix):
                result = handler(method, url, headers, payload, timeout) if callable(handler) else handler
                if isinstance(result, BaseException):
                    raise result
                return result
        return 404, {"error": "no such route", "status": 404}

    def paths(self) -> List[str]:
        return [route_of(str(call["url"])) for call in self.calls]

    def count(self, suffix: str) -> int:
        return sum(1 for call in self.calls if str(call["url"]).endswith(suffix))

    def last(self, suffix: str) -> Dict[str, Any]:
        for call in reversed(self.calls):
            if str(call["url"]).endswith(suffix):
                return call
        return {}


def _node_settings(h: Harness, *, enabled: bool = True, url: str = DEFAULT_MAC_NODE_URL, token: str = NODE_TOKEN):
    """造一份 Settings 再按需改字段：``load_settings`` 会拒绝非回环 URL，闸门要单独测。"""
    settings = h.settings(MAC_NODE_ENABLED="1" if enabled else None, MAC_NODE_URL=url, MAC_NODE_TOKEN=token)
    if not enabled:
        settings.mac_node_enabled = False
    settings.mac_node_url = url
    settings.mac_node_token = token
    return settings


def _guard_reason(url: str) -> str:
    """闸门拒绝时给出 ``reason``，放行时给出规范化后的 URL（便于同一批断言两种写法）。"""
    try:
        return guard_loopback_url(url)
    except MacNodeError as exc:
        return exc.reason


def _async_reason(h: Harness, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> str:
    """跑一个协程，把 MacNodeError/A2AError 的 ``reason`` 交出来；没抛错返回空串。"""

    async def driver() -> str:
        try:
            await fn(*args, **kwargs)
        except (MacNodeError, A2AError) as exc:
            return str(getattr(exc, "reason", ""))
        return ""

    return h.async_run(driver)


def _berlin_offset(ts: float) -> float:
    """柏林当时的 UTC 偏移（秒）：夏令时跳进/跳出都靠它判定。"""
    return datetime.fromtimestamp(float(ts), ZoneInfo("Europe/Berlin")).utcoffset().total_seconds()


def _raw_frame(payload: Any, key: Any) -> str:
    """绕过 :func:`encode_frame` 的护栏，直接按线上配方签一个任意帧。

    「对端发来一个签名正确但形状恶劣的帧」只能用这种方式造：护栏拦得住我们自己发，
    拦不住对面 —— 解码侧的检查必须由这种帧来测。
    """
    blob = _b64e(payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8"))
    signature = _b64e(hmac.new(_key_bytes(key), blob.encode("ascii"), hashlib.sha256).digest())
    return f"{A2A_PREFIX}{blob}.{signature}"


def _reason_of(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> str:
    """跑一个同步可调用，把 MacNodeError/A2AError 的 ``reason`` 交出来；没抛错返回空串。"""

    try:
        fn(*args, **kwargs)
    except (MacNodeError, A2AError) as exc:
        return str(getattr(exc, "reason", ""))
    return ""


def _async_value(h: Harness, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """跑一个协程并把返回值交出来，异常统一变成 ``{"error": reason}``。"""

    async def driver() -> Any:
        try:
            return await fn(*args, **kwargs)
        except (MacNodeError, A2AError) as exc:
            return {"error": str(getattr(exc, "reason", ""))}

    return h.async_run(driver)


def _local(year: int, month: int, day: int, hour: int, minute: int = 0, tz: str = "Europe/Berlin") -> float:
    return datetime(year, month, day, hour, minute, tzinfo=ZoneInfo(tz)).timestamp()


# ---------------------------------------------------------------- mac_node 组
def group_mac_node(test: SelfTest, h: Harness) -> None:
    t = test
    db = h.database("node_ledger")

    # -- 1. 回环闸门：开 socket 之前的唯一入口 --------------------------------
    t.section("mac_node:loopback-gate")
    t.eq("闸门放行 127.0.0.1", _guard_reason("http://127.0.0.1:18920/api/health"), "http://127.0.0.1:18920/api/health")
    t.eq("闸门放行 localhost", _guard_reason("http://localhost:18920"), "http://localhost:18920")
    t.eq("闸门放行 IPv6 回环", _guard_reason("http://[::1]:18920/api/health"), "http://[::1]:18920/api/health")
    t.eq("闸门放行 127.9.9.9", _guard_reason("http://127.9.9.9:18920"), "http://127.9.9.9:18920")
    t.eq("尾部斜杠归一", _guard_reason("http://127.0.0.1:18920/"), "http://127.0.0.1:18920")
    t.eq("https 回环放行", _guard_reason("https://127.0.0.1:18920/api/health"), "https://127.0.0.1:18920/api/health")
    for label, bad in [
        ("公网域名", "http://evil.example.com:18920/api/health"),
        ("公网 IP", "https://8.8.8.8/"),
        ("通配地址", "http://0.0.0.0:18920"),
        ("局域网", "http://192.168.1.7:18920"),
        ("链路本地元数据", "http://169.254.169.254/latest/meta-data/"),
        ("file 协议", "file:///etc/passwd"),
        ("gopher 协议", "gopher://127.0.0.1:18920/x"),
        ("userinfo 夹带", "http://127.0.0.1@evil.example/api"),
        ("空 URL", ""),
        ("只有空白", "   "),
        ("不是 URL", "not a url"),
        ("缺主机", "http:///api/health"),
        ("DNS 前缀伪装", "http://127.0.0.1.evil.example/api"),
        ("十进制 IP", "http://2130706433/api/health"),
        ("短写 127.1", "http://127.1:18920/api/health"),
        ("IPv6 映射", "http://[::ffff:127.0.0.1]:18920/api/health"),
    ]:
        t.eq(f"拒绝 {label}", _guard_reason(bad), "non_loopback")
    t.contains("userinfo 拒绝理由点明外送", guard_error_text(h, "http://127.0.0.1@evil.example/api"), "userinfo")
    t.eq("路由只留路径不带 query", route_of("http://127.0.0.1:18920/api/health?t=abc"), "/api/health")
    t.eq("空路由归一为斜杠", route_of(""), "/")

    # -- 2. 失败分类与掩码 ----------------------------------------------------
    t.section("mac_node:taxonomy")
    t.eq("分类集合与规格一致", sorted(REASONS), sorted(["disabled", "non_loopback", "timeout", "unreachable",
                                                        "auth", "bad_response", "unsupported"]))
    err = MacNodeError("auth", "鉴权失败")
    t.eq("异常 reason", err.reason, "auth")
    t.eq("异常消息含分类", str(err), "[auth] 鉴权失败")
    t.check("MacNodeError 是 RuntimeError 子类", isinstance(err, RuntimeError))
    t.raises("非法 reason 直接 ValueError", ValueError, MacNodeError, "wat", "x")
    t.eq("令牌掩码：有值", mask_secret(NODE_TOKEN), MASK)
    t.eq("令牌掩码：空值", mask_secret(""), "")
    t.eq("头掩码按名字", mask_mapping({"X-PPX-Token": NODE_TOKEN, "Accept": "application/json"}),
         {"X-PPX-Token": MASK, "Accept": "application/json"})

    # -- 3. 未开关时绝不打开 socket -------------------------------------------
    t.section("mac_node:disabled")
    idle = FakeNode()
    off = MacNodeBridge(_node_settings(h, enabled=False), transport=idle, db=db)
    t.eq("enabled 为假", off.enabled(), False)
    t.eq("disabled 不调用 transport", _async_reason(h, off.health), "disabled")
    t.eq("transport 调用次数", len(idle.calls), 0)
    t.eq("availability 降级为空表", _async_value(h, off.availability, "2026-11-27", timezone="Europe/Berlin"), [])
    t.eq("create_event 不抛只返结构", sorted(_async_value(h, off.create_event, title="x", start_ts=1.0, end_ts=2.0)),
         sorted(["detail", "event_id", "ok", "reason"]))
    refused = _async_value(h, off.create_event, title="x", start_ts=1.0, end_ts=2.0)
    t.eq("未开关的落地 reason", refused["reason"], "disabled")
    t.eq("未开关的落地 ok", refused["ok"], False)

    # -- 4. status()：令牌永不可见 --------------------------------------------
    t.section("mac_node:status")
    bridge = MacNodeBridge(_node_settings(h), transport=FakeNode(), db=db, token=NODE_TOKEN)
    status = bridge.status()
    dumped = json.dumps(status, ensure_ascii=False, sort_keys=True)
    t.check("status 不含令牌", NODE_TOKEN not in dumped, dumped[:200])
    t.eq("status 声明令牌存在", status["token_present"], True)
    t.eq("status 令牌已掩码", status["token"], MASK)
    t.eq("头里的令牌已掩码", status["headers"][TOKEN_HEADER], MASK)
    t.eq("不跟随重定向写死", status["follow_redirects"], False)
    t.eq("注入传输标记", status["transport"], "injected")
    t.eq("账本缓存标记", status["cache"], "ledger")
    t.eq("默认端口", status["base_url"], DEFAULT_MAC_NODE_URL)
    t.eq("命令行前缀与 Swift 同值", status["command_prefix"], "::popopx_sys::NODE_CMD::")
    t.eq("命令 payload 预算", status["payload_char_limit"], 1024)
    t.eq("回环判定", status["loopback"], True)
    t.eq("路由表 health", status["routes"]["health"], HEALTH_PATH)
    t.eq("路由表忙闲", status["routes"]["availability"], "/v1/tools/calendar/availability")
    t.eq("路由表提案", status["routes"]["proposals"], "/v1/tools/calendar/proposals")
    t.eq("桥接报告即 status", bridge_report(bridge)["base_url"], DEFAULT_MAC_NODE_URL)
    t.eq("空桥报告", bridge_report(None)["enabled"], False)
    naked = MacNodeBridge(_node_settings(h, token=""), transport=FakeNode())
    t.eq("无令牌时 token_present 为假", naked.status()["token_present"], False)
    t.eq("无令牌不发头", TOKEN_HEADER in naked._headers(), False)
    t.eq("缺账本时 cache=none", naked.status()["cache"], "none")

    # -- 5. 配错地址时的纵深防御 ----------------------------------------------
    t.section("mac_node:defence-in-depth")
    hijack = FakeNode()
    wrong = MacNodeBridge(_node_settings(h, url="http://127.0.0.1:18920"), transport=hijack, db=db)
    wrong.settings.mac_node_url = "http://evil.example:18920"
    t.eq("调用点重新校验", _async_reason(h, wrong.health), "non_loopback")
    t.eq("非回环时一次都没发出去", len(hijack.calls), 0)
    t.eq("last_reason 记账", wrong.last_reason, "non_loopback")
    t.eq("拒绝也计入 failures", wrong.failures, 1)
    t.check("last_detail 点明被拒主机", "evil.example" in wrong.last_detail, wrong.last_detail)
    wrong.settings.mac_node_url = "http://127.0.0.1:18920"
    t.eq("闸门拒绝时不重置 last_reason（保留最近一次失败）", wrong.last_reason, "non_loopback")
    hijack.on(SNAPSHOT_PATH, (200, {"ok": True}))
    t.eq("改回回环后恢复", _async_reason(h, wrong.snapshot), "")
    t.eq("恢复后确实发了请求", len(hijack.calls), 1)
    t.eq("拼接后的 URL 完整", hijack.calls[0]["url"], DEFAULT_MAC_NODE_URL + SNAPSHOT_PATH)

    # -- 6. 控制台只读路由 ----------------------------------------------------
    t.section("mac_node:console")
    node = FakeNode()
    node.on(HEALTH_PATH, (200, {"ok": True, "service": "PopopxMacNode", "loopback": True}))
    node.on(SNAPSHOT_PATH, (200, {"ok": True, "viewers": 0}))
    live = MacNodeBridge(_node_settings(h), transport=node, db=db)
    t.eq("health 返回体", _async_value(h, live.health), {"ok": True, "service": "PopopxMacNode", "loopback": True})
    t.eq("health 用 GET", node.calls[-1]["method"], "GET")
    t.eq("health 带头", node.calls[-1]["headers"][TOKEN_HEADER], NODE_TOKEN)
    t.eq("超时取自 settings", node.calls[-1]["timeout"], live.timeout())
    t.eq("snapshot 返回体 ok", _async_value(h, live.snapshot).get("ok"), True)
    t.eq("snapshot 路径", node.calls[-1]["url"], DEFAULT_MAC_NODE_URL + SNAPSHOT_PATH)
    t.eq("计数", live.calls, 2)

    # -- 7. 引擎调用面（EngineKind 白名单） -----------------------------------
    t.section("mac_node:engine")
    engine_node = FakeNode()
    engine_node.on(ENGINE_INVOKE_PATH, (200, {"ok": True, "result": {}}))
    eng = MacNodeBridge(_node_settings(h), transport=engine_node, db=db)
    t.eq("合法引擎调用", _async_value(h, eng.engine, "morning_tv", "refresh", {"scope": "today"}).get("ok"), True)
    t.eq("引擎 body 三段", sorted(engine_node.calls[-1]["payload"]), ["action", "kind", "payload"])
    t.eq("引擎 kind 原样", engine_node.calls[-1]["payload"]["kind"], "morning_tv")
    t.eq("引擎路径", engine_node.paths()[-1], ENGINE_INVOKE_PATH)
    t.eq("未知引擎被拒", _async_reason(h, eng.engine, "calendar", "availability", {}), "unsupported")
    t.eq("空 action 被拒", _async_reason(h, eng.engine, "morning_tv", "", {}), "bad_response")
    t.eq("payload 非对象被拒", _async_reason(h, eng.engine, "morning_tv", "x", "nope"), "bad_response")
    t.check("calendar 不是 EngineKind", "calendar" not in ENGINE_KINDS)
    t.eq("EngineKind 数量", len(ENGINE_KINDS), 10)

    # -- 8. 命令行 ::popopx_sys::NODE_CMD:: ----------------------------------
    t.section("mac_node:command")
    cmd_node = FakeNode()
    cmd_node.on(COMMAND_PATH, (200, {"ok": True, "queued": True}))
    cmd = MacNodeBridge(_node_settings(h), transport=cmd_node, db=db)
    line = f"{COMMAND_PREFIX}morning_tv::play::slot=1"
    t.eq("合法命令行", _async_value(h, cmd.command, line).get("queued"), True)
    t.eq("body 字段名 text", sorted(cmd_node.calls[-1]["payload"]), ["text"])
    t.eq("命令行原文外送", cmd_node.calls[-1]["payload"]["text"], line)
    t.eq("缺前缀被拒", _async_reason(h, cmd.command, "morning_tv::play::x"), "bad_response")
    t.eq("段数不足被拒", _async_reason(h, cmd.command, f"{COMMAND_PREFIX}morning_tv::play"), "bad_response")
    t.eq("空段被拒", _async_reason(h, cmd.command, f"{COMMAND_PREFIX}morning_tv::::x"), "bad_response")
    t.eq("未知服务被拒", _async_reason(h, cmd.command, f"{COMMAND_PREFIX}not_a_service::play::x"), "unsupported")
    t.eq("隐私桥接域可作 serviceId", _async_value(h, cmd.command, f"{COMMAND_PREFIX}calendar::ping::x").get("ok"), True)
    spare = MAX_SIGNAL_PAYLOAD_CHARACTERS - len("morning_tv") - len("play") - 2
    t.eq("预算内恰好放得下", _async_value(h, cmd.command, f"{COMMAND_PREFIX}morning_tv::play::{'x' * spare}").get("ok"), True)
    t.eq("超一字符即拒", _async_reason(h, cmd.command, f"{COMMAND_PREFIX}morning_tv::play::{'x' * (spare + 1)}"), "unsupported")

    # -- 9. 隐私工具面路由 ----------------------------------------------------
    t.section("mac_node:tool")
    tool_node = FakeNode()
    tool_node.on(ACTION_AVAILABILITY, (200, {"ok": True, "freeSlots": []}))
    tl = MacNodeBridge(_node_settings(h), transport=tool_node, db=db)
    t.eq("未知桥接域", _async_reason(h, tl.tool, "contacts", ACTION_AVAILABILITY, {}), "unsupported")
    t.eq("未知工具动作", _async_reason(h, tl.tool, CALENDAR_NAMESPACE, "wipe", {}), "unsupported")
    t.eq("决定类动作需 id", _async_reason(h, tl.tool, CALENDAR_NAMESPACE, ACTION_APPROVE, {"receipt": "r"}), "bad_response")
    t.eq("body 不得指向别的提案",
         _async_reason(h, tl.tool, CALENDAR_NAMESPACE, ACTION_APPROVE, {"proposalId": "other"}, proposal_id="mine"),
         "bad_response")
    t.eq("工具路由是 POST", _async_value(h, tl.tool, CALENDAR_NAMESPACE, ACTION_AVAILABILITY, {}).get("ok"), True)
    t.eq("工具路径拼接", tool_node.paths()[-1], f"{TOOL_PREFIX}{CALENDAR_NAMESPACE}/{ACTION_AVAILABILITY}")
    t.eq("决定路径形状", decision_path(CALENDAR_NAMESPACE, "ppx-pr-1", ACTION_REJECT),
         "/v1/tools/calendar/proposals/ppx-pr-1/reject")
    t.eq("工具路径形状", tool_path(WORKSPACE_NAMESPACE, "summarize"), "/v1/tools/workspace/summarize")

    # -- 10. 忙闲：真字段 + 掩码 + 缓存 --------------------------------------
    t.section("mac_node:availability")
    day = "2026-11-27"
    zone = "Europe/Berlin"
    lo, hi = day_window(day, zone)
    t.eq("日窗口起点是本地零点", datetime.fromtimestamp(lo, ZoneInfo(zone)).strftime("%H:%M"), "00:00")
    t.eq("日窗口长 24h", hi - lo, 86400.0)
    busy_node = FakeNode()
    busy_node.on(
        ACTION_AVAILABILITY,
        lambda *_: (200, {
            "ok": True,
            "timezone": zone,
            "slotCount": 2,
            "freeSlots": [
                {"start": iso_utc(lo + 3600), "end": iso_utc(lo + 4 * 3600)},
                {"start": iso_utc(lo + 6 * 3600), "end": iso_utc(hi)},
            ],
        }),
    )
    cached = MacNodeBridge(_node_settings(h), transport=busy_node, db=db)
    bot_id = "bot_node_cache"
    busy = _async_value(h, cached.availability, day, timezone=zone, bot_id=bot_id)
    sent = busy_node.last(ACTION_AVAILABILITY)["payload"]
    t.eq("请求字段 startIso", sorted(sent), ["endIso", "startIso", "timezone"])
    t.check("startIso 是 ISO8601 带 Z", len(sent["startIso"]) == 20 and sent["startIso"].endswith("Z")
            and sent["startIso"][4] == "-" and sent["startIso"][10] == "T", sent["startIso"])
    t.eq("startIso 等于本地零点", sent["startIso"], iso_utc(lo))
    t.eq("endIso 等于次日零点", sent["endIso"], iso_utc(hi))
    t.eq("timezone 原样外送", sent["timezone"], zone)
    t.eq("忙区间数量", len(busy), 2)
    t.eq("忙区间只含三个键", sorted(busy[0]), ["busy", "end", "start"])
    t.eq("第一段忙 = 00:00-01:00", (busy[0]["start"], busy[0]["end"]), (lo, lo + 3600))
    t.eq("第二段忙 = 04:00-06:00", (busy[1]["start"], busy[1]["end"]), (lo + 4 * 3600, lo + 6 * 3600))
    t.check("每段都标 busy", all(row["busy"] is True for row in busy))
    record = db.cached_busy(bot_id, day, source=CACHE_SOURCE)
    t.check("掩码忙表已落缓存", record is not None)
    t.eq("缓存内容与返回一致", record["busy"], busy)
    t.eq("缓存时区", record["timezone"], zone)
    t.eq("缓存来源", record["source"], CACHE_SOURCE)
    t.eq("缓存不过期即可复用", db.cached_busy(bot_id, day, source=CACHE_SOURCE, now=time.time() + 1.0) is not None, True)
    t.eq("过期后读不到", db.cached_busy(bot_id, day, source=CACHE_SOURCE, now=time.time() + 99999.0), None)
    t.eq("坏日期直接空表", _async_value(h, cached.availability, "2026-11-32", timezone=zone, bot_id=bot_id), [])
    t.eq("坏日期不打网络", busy_node.count(ACTION_AVAILABILITY), 1)

    # -- 11. 节点不可用 → 掩码缓存降级 ---------------------------------------
    t.section("mac_node:degradation")
    busy_node.on(ACTION_AVAILABILITY, (503, {"error": "engine off", "status": 503}))
    degraded = _async_value(h, cached.availability, day, timezone=zone, bot_id=bot_id)
    t.eq("503 回退到缓存", degraded, busy)
    t.eq("降级记 last_reason", cached.last_reason, "unreachable")
    cold = MacNodeBridge(_node_settings(h), transport=busy_node, db=db)
    t.eq("无缓存时回退空表", _async_value(h, cold.availability, day, timezone=zone, bot_id="bot_never_cached"), [])
    t.eq("桥接器仍统计失败", cold.failures >= 1, True)
    for label, handler, want in [
        ("401", (401, {"error": "unauthorized", "status": 401}), "auth"),
        ("403", (403, {"ok": False, "refusal": "not_authorized"}), "auth"),
        ("400", (400, {"ok": False, "refusal": "bad_request"}), "bad_response"),
        ("500", (500, {"error": "boom"}), "unreachable"),
    ]:
        probe = FakeNode()
        probe.on(HEALTH_PATH, handler)
        pb = MacNodeBridge(_node_settings(h), transport=probe, db=db)
        t.eq(f"HTTP {label} 分类", _async_reason(h, pb.health), want)
    jumped = FakeNode()
    jumped.on(HEALTH_PATH, (301, {"location": "http://evil.example/api/health"}))
    jb = MacNodeBridge(_node_settings(h), transport=jumped, db=db)
    t.eq("重定向出盒子按 SSRF 拒", _async_reason(h, jb.health), "non_loopback")
    t.eq("重定向不跟随（只一次调用）", len(jumped.calls), 1)
    inside = FakeNode()
    inside.on(HEALTH_PATH, (302, {"location": SNAPSHOT_PATH}))
    ib = MacNodeBridge(_node_settings(h), transport=inside, db=db)
    t.eq("盒内重定向也不跟随", _async_reason(h, ib.health), "unsupported")
    t.eq("重定向消息只含路径", "evil.example" in _async_text(h, jb.health), False)
    timed = FakeNode()
    timed.on(HEALTH_PATH, TimeoutError("read timed out"))
    tb = MacNodeBridge(_node_settings(h), transport=timed, db=db)
    t.eq("传输超时分类", _async_reason(h, tb.health), "timeout")
    refused_node = FakeNode()
    refused_node.on(HEALTH_PATH, OSError("connection refused"))
    rb = MacNodeBridge(_node_settings(h), transport=refused_node, db=db)
    t.eq("连接被拒分类", _async_reason(h, rb.health), "unreachable")
    blew = FakeNode()
    blew.on(HEALTH_PATH, RuntimeError("bugus"))
    bb = MacNodeBridge(_node_settings(h), transport=blew, db=db)
    t.eq("任意 transport 异常都不冒泡", _async_reason(h, bb.health), "unreachable")
    html = FakeNode()
    html.on(HEALTH_PATH, (200, {NON_JSON_KEY: "<html>"}))
    hb = MacNodeBridge(_node_settings(h), transport=html, db=db)
    t.eq("非 JSON 响应分类", _async_reason(h, hb.health), "bad_response")
    shape = FakeNode()
    shape.on(HEALTH_PATH, lambda *_: ("200", {"ok": True}))
    sb = MacNodeBridge(_node_settings(h), transport=shape, db=db)
    t.eq("transport 形状非法", _async_reason(h, sb.health), "bad_response")
    body = FakeNode()
    body.on(HEALTH_PATH, lambda *_: (200, []))
    wb = MacNodeBridge(_node_settings(h), transport=body, db=db)
    t.eq("响应体非对象", _async_reason(h, wb.health), "bad_response")
    secret = MacNodeBridge(_node_settings(h), transport=FakeNode(), db=db)
    t.eq("query 带令牌被拒", _async_reason(h, secret.request, "GET", "/api/health?t=" + NODE_TOKEN), "unsupported")

    # -- 12. 令牌在审计与异常里都不出现 --------------------------------------
    t.section("mac_node:token-hygiene")
    leak_node = FakeNode()
    leak_node.on(HEALTH_PATH, (403, {"error": "token mismatch", "status": 403}))
    leak = MacNodeBridge(_node_settings(h), transport=leak_node, db=db)
    message = _async_text(h, leak.health)
    t.check("异常消息不含令牌", NODE_TOKEN not in message, message)
    t.check("status 不含令牌", NODE_TOKEN not in json.dumps(leak.status(), ensure_ascii=False))
    rows = db.recent_negotiations(limit=200, stage="mac_node")
    t.check("审计有条目", len(rows) > 0, str(len(rows)))
    t.check("审计 detail 不含令牌", all(NODE_TOKEN not in str(row["detail"]) for row in rows))
    t.check("审计 data 不含令牌", all(NODE_TOKEN not in json.dumps(row["data"], ensure_ascii=False) for row in rows))
    t.check("头名出现在 transport 现场", TOKEN_HEADER in leak_node.calls[-1]["headers"])

    # -- 13. 落地：确认之前一个字节都不写 ------------------------------------
    t.section("mac_node:landing")
    start = _local(2026, 11, 27, 14, 0, tz=zone)
    end = start + 3600.0
    land_node = FakeNode()
    land_node.on(ACTION_AVAILABILITY, lambda *_: (200, {"ok": True, "freeSlots": [{"start": iso_utc(start), "end": iso_utc(end)}]}))
    land_node.on(ACTION_BOOKINGS, (200, {"ok": True, "bookings": [
        {"bookingRefId": "ppx-bk-9", "status": "confirmed", "title": "机密标题", "start": iso_utc(start),
         "end": iso_utc(end), "sequence": 1},
        {"bookingRefId": "", "status": "ghost"},
    ]}))
    read_only = MacNodeBridge(_node_settings(h), transport=land_node, db=db)
    bookings = _async_value(h, read_only.bookings, bot_id="bot_land")
    t.eq("bookings 掩码后只剩引用", bookings,
         [{"booking_ref_id": "ppx-bk-9", "status": "confirmed", "start": start, "end": end, "sequence": 1}])
    t.check("bookings 结果不吐标题", "机密标题" not in json.dumps(bookings, ensure_ascii=False), str(bookings))
    t.check("bookings 出站请求不吐标题",
            "机密标题" not in json.dumps(land_node.last(ACTION_BOOKINGS), ensure_ascii=False),
            str(land_node.last(ACTION_BOOKINGS)))
    proposal = db.create_proposal("bot_land", "create", source="a2a", timezone=zone, start_ts=start, end_ts=end,
                                  duration_minutes=60, summary="与 Bob 的会议", negotiation_id="ng_selftest")
    pid = str(proposal["proposal_id"])
    t.eq("确认前无任何 proposals 写调用", land_node.count(ACTION_PROPOSALS), 0)
    t.eq("确认前提案仍是 pending", db.get_proposal(pid)["status"], "pending")

    land_node.on(ACTION_PROPOSALS, (200, {
        "ok": True, "proposalId": "ppx-pr-7", "domain": CALENDAR_NAMESPACE, "action": "create",
        "state": "pending_user_approval", "requiresUserConfirmation": True, "calendarWritten": False,
        "approvalReceipt": "receipt-abc", "rejectReceipt": "receipt-no",
        "approvePath": decision_path(CALENDAR_NAMESPACE, "ppx-pr-7", ACTION_APPROVE),
        "bookingRefId": "ppx-bk-9", "expiresAt": iso_utc(time.time() + 900),
    }))
    land_node.on("/approve", (200, {"ok": True, "proposalId": "ppx-pr-7", "state": "executed", "verb": "approve",
                                    "calendarWritten": True, "fileWritten": False, "sequence": 1,
                                    "executedAt": iso_utc(time.time()), "eventIdentifier": "EV-42",
                                    "bookingRefId": "ppx-bk-9"}))
    t.eq("approve 需要提案对象", _async_value(h, read_only.approve, {"bogus": 1})["reason"], "bad_response")
    result = _async_value(h, read_only.approve, db.get_proposal(pid))
    t.eq("确认后落地成功", result["ok"], True)
    t.eq("事件 id 取节点返回", result["event_id"], "EV-42")
    t.eq("reason 为空", result["reason"], "")
    t.eq("两步式：先提案", land_node.last(ACTION_PROPOSALS)["url"], DEFAULT_MAC_NODE_URL + tool_path(CALENDAR_NAMESPACE, ACTION_PROPOSALS))
    propose_body = land_node.last(ACTION_PROPOSALS)["payload"]
    t.eq("提案字段名与 Swift 对齐", sorted(propose_body),
         sorted(["action", "endIso", "startIso", "timezone", "title"]))
    t.eq("提案 action", propose_body["action"], "create")
    t.eq("提案 title", propose_body["title"], "与 Bob 的会议")
    t.check("提案时间是 ISO8601", propose_body["startIso"] == iso_utc(start) and propose_body["endIso"] == iso_utc(end),
            str(propose_body))
    t.eq("approve 走节点给的 approvePath", land_node.last("/approve")["url"],
         DEFAULT_MAC_NODE_URL + decision_path(CALENDAR_NAMESPACE, "ppx-pr-7", ACTION_APPROVE))
    t.eq("approve body 只带回执", land_node.last("/approve")["payload"], {"receipt": "receipt-abc"})
    t.eq("落地顺序：提案先于批准",
         [p for p in land_node.paths() if "proposals" in p][:2],
         ["/v1/tools/calendar/proposals", "/v1/tools/calendar/proposals/ppx-pr-7/approve"])
    after = db.get_proposal(pid)
    t.eq("账本状态置 approved", after["status"], "approved")
    t.eq("节点事件 id 落账", after["node_event_id"], "EV-42")
    t.eq("node_outcome 落账", after["payload"]["node_outcome"]["stage"], "approved")
    t.eq("落地后刷新忙闲缓存", db.cached_busy("bot_land", day, source=CACHE_SOURCE) is not None, True)
    t.eq("审计写了 land_create", any(row["event"] == "land_create" for row in db.recent_negotiations("bot_land", limit=50)), True)

    # -- 14. 落地的各种失败形状 ----------------------------------------------
    t.section("mac_node:landing-failures")
    early = FakeNode()
    early.on(ACTION_PROPOSALS, (200, {"ok": True, "proposalId": "ppx-pr-1", "calendarWritten": True}))
    eb = MacNodeBridge(_node_settings(h), transport=early, db=db)
    t.eq("节点在提案阶段就写日历 → 不再批准",
         _async_value(h, eb.create_event, title="t", start_ts=start, end_ts=end)["reason"], "unsupported")
    t.eq("不再打 approve 调用", early.count("/approve"), 0)
    flaky = FakeNode()
    flaky.on(ACTION_PROPOSALS, (200, {"ok": True, "proposalId": "ppx-pr-2"}))
    fb = MacNodeBridge(_node_settings(h), transport=flaky, db=db)
    t.eq("缺回执 → bad_response", _async_value(h, fb.create_event, title="t", start_ts=start, end_ts=end)["reason"],
         "bad_response")
    denied = FakeNode()
    denied.on(ACTION_PROPOSALS, (200, {"ok": True, "proposalId": "ppx-pr-3", "approvalReceipt": "r"}))
    denied.on("/approve", (403, {"error": "receipt expired", "status": 403}))
    db.update_proposal(db.create_proposal("bot_land", "create", source="a2a", timezone=zone, start_ts=start,
                                          end_ts=end, summary="另一条")["proposal_id"], status="pending")
    denied_proposal = db.list_proposals("bot_land", status="pending", limit=5)[-1]
    dp = MacNodeBridge(_node_settings(h), transport=denied, db=db)
    denied_result = _async_value(h, dp.approve, db.get_proposal(str(denied_proposal["proposal_id"])))
    t.eq("批准被拒 → auth", denied_result["reason"], "auth")
    t.eq("批准被拒不抛，只返结构", denied_result["ok"], False)
    t.eq("批准被拒时提案置 failed",
         db.get_proposal(str(denied_proposal["proposal_id"]))["status"], "failed")
    t.contains("失败原因落账", str(db.get_proposal(str(denied_proposal["proposal_id"]))["error"]), "auth")
    t.eq("终态提案不得复活", _async_value(h, dp.approve, db.get_proposal(str(denied_proposal["proposal_id"])))["reason"],
         "unsupported")
    t.eq("终态提案仍为 failed", db.get_proposal(str(denied_proposal["proposal_id"]))["status"], "failed")
    t.eq("缺 title 不发 POST", _async_value(h, eb.create_event, title="  ", start_ts=start, end_ts=end)["reason"],
         "bad_response")
    t.eq("倒挂时间不发 POST", _async_value(h, eb.create_event, title="t", start_ts=end, end_ts=start)["reason"],
         "bad_response")
    t.eq("非法 bookingRef 拒改期", _async_value(h, eb.reschedule_event, booking_ref="bad ref!", start_ts=start)["reason"],
         "bad_response")
    t.eq("非法 bookingRef 拒取消", _async_value(h, eb.cancel_event, booking_ref="x" * 90)["reason"], "bad_response")
    move = FakeNode()
    move.on(ACTION_PROPOSALS, (200, {"ok": True, "proposalId": "ppx-pr-4", "approvalReceipt": "r4",
                                     "calendarWritten": False}))
    move.on("/approve", (200, {"ok": True, "calendarWritten": True, "state": "executed", "eventIdentifier": "ppx-bk-9",
                               "sequence": 2}))
    mb = MacNodeBridge(_node_settings(h), transport=move, db=db)
    moved = _async_value(h, mb.reschedule_event, booking_ref="ppx-bk-9", start_ts=start + 7200,
                         end_ts=end + 7200, timezone=zone)
    t.eq("改期成功", moved["ok"], True)
    t.eq("改期 action 字段", move.last(ACTION_PROPOSALS)["payload"]["action"], "reschedule")
    t.eq("改期带 bookingRefId", move.last(ACTION_PROPOSALS)["payload"]["bookingRefId"], "ppx-bk-9")
    cancelled = _async_value(h, mb.cancel_event, booking_ref="ppx-bk-9", timezone=zone)
    t.eq("取消成功", cancelled["ok"], True)
    t.eq("取消 action 字段", move.last(ACTION_PROPOSALS)["payload"]["action"], "cancel")
    t.eq("取消不带多余字段", sorted(move.last(ACTION_PROPOSALS)["payload"]), ["action", "bookingRefId"])

    # -- 15. 忙表推导与时间戳形状 --------------------------------------------
    t.section("mac_node:masks")
    t.eq("iso_utc 形状", iso_utc(_local(2026, 1, 2, 3, 4, tz="UTC") + 5), "2026-01-02T03:04:05Z")
    t.check("iso_utc 不是 ICS basic 形式",
            "T" in iso_utc(time.time()) and "-" in iso_utc(time.time()), iso_utc(time.time()))
    t.eq("空 freeSlots → 整日忙", masked_busy({"freeSlots": []}, lo, hi), [{"start": lo, "end": hi, "busy": True}])
    t.eq("越界段被裁剪", masked_busy({"freeSlots": [{"start": iso_utc(lo - 7200), "end": iso_utc(lo + 7200)}]}, lo, hi),
         [{"start": lo + 7200, "end": hi, "busy": True}])
    t.eq("倒挂段被丢", masked_busy({"freeSlots": [{"start": iso_utc(hi), "end": iso_utc(lo)}]}, lo, hi),
         [{"start": lo, "end": hi, "busy": True}])
    t.eq("非 dict 段被丢", masked_busy({"freeSlots": ["nope", None]}, lo, hi), [{"start": lo, "end": hi, "busy": True}])
    t.eq("无 freeSlots 键 → 整日忙", masked_busy({}, lo, hi), [{"start": lo, "end": hi, "busy": True}])
    t.raises("非法日期字符串", MacNodeError, day_window, "27/11/2026", "Europe/Berlin")
    t.raises("未知时区不猜 UTC", MacNodeError, day_window, "2026-11-27", "Nowhere/Zone")
    t.eq("未知时区的拒绝理由", _reason_of(day_window, "2026-11-27", "Nowhere/Zone"), "unsupported")
    t.eq("空时区按 UTC 取整", day_window("2026-11-27", ""), day_window("2026-11-27", "UTC"))
    t.eq("NodeOutcome 默认形状", NodeOutcome(True).as_dict(), {"ok": True, "event_id": "", "reason": "", "detail": {}})
    t.eq("坏桥接器的忙表为空", _async_value(h, MacNodeBridge(_node_settings(h), transport=FakeNode()).availability,
                                           day, timezone=zone, bot_id="bot_missing_route"), [])


def guard_error_text(h: Harness, url: str) -> str:
    """闸门拒绝时的 detail 文本（供断言点明的原因）。"""

    async def driver() -> str:
        bridge = MacNodeBridge(_node_settings(h), transport=FakeNode(), db=None)
        bridge.settings.mac_node_url = url
        try:
            await bridge.snapshot()
        except MacNodeError as exc:
            return exc.detail
        return ""

    return h.async_run(driver)


def _async_text(h: Harness, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> str:
    """协程抛错时的异常文本；没抛错返回空串。"""

    async def driver() -> str:
        try:
            await fn(*args, **kwargs)
        except (MacNodeError, A2AError) as exc:
            return str(exc)
        return ""

    return h.async_run(driver)


# --------------------------------------------------------------------- a2a 组
def group_a2a(test: SelfTest, h: Harness) -> None:
    t = test
    db = h.database("a2a_ledger")
    clock = 1795600000.0
    key = b"shared-smp-session-key"
    provider = lambda peer: key  # noqa: E731 - 编排层注入的密钥回调

    # -- 1. 白名单掩码投影 ----------------------------------------------------
    t.section("a2a:masking")
    raw = [
        {"start": 100.0, "end": 200.0, "title": "机密评审", "attendees": ["boss@corp"], "location": "会议室 3",
         "summary": "裁员名单", "uid": "u-1", "description": "别发出去"},
        {"start": 300.0, "end": 400.0, "ref": "ppx-ref-1", "notes": "x"},
        (500.0, 600.0),
        {"start": 700.0, "end": 650.0},
        {"start": "abc", "end": 900.0},
        {"start": 800.0, "end": 900.0, "busy": True},
        None,
        42,
    ]
    masked = mask_slots(raw, timezone="Europe/Berlin")
    projected = sorted({k for row in masked for k in row})
    t.eq("投影后只剩白名单键", projected, ["end", "free", "ref", "start", "tz"])
    t.check("白名单与 MASKED_KEYS 一致", set(projected) == set(MASKED_KEYS), str(projected))
    t.check("拒发键从未进入结果", not any(k in FORBIDDEN_KEYS for k in projected), str(projected))
    t.eq("无 ref 的段落只有四个键",
         sorted(mask_slots([{"start": 1.0, "end": 2.0}], timezone="UTC")[0]), ["end", "free", "start", "tz"])
    t.eq("非法条目被丢后的段数", len(masked), 4)
    t.eq("段按开始时间排序", [row["start"] for row in masked], [100.0, 300.0, 500.0, 800.0])
    t.eq("时区随段落带", masked[0]["tz"], "Europe/Berlin")
    t.eq("默认空闲", masked[0]["free"], True)
    t.eq("busy 标记保留", masked[-1]["free"], False)
    t.eq("不透明 ref 保留", masked[1]["ref"], "ppx-ref-1")
    t.check("标题不存在于结果", all("title" not in row for row in masked))
    t.check("参会人不存在于结果", json.dumps(masked, ensure_ascii=False).count("boss@corp") == 0)
    t.check("地点不存在于结果", "会议室 3" not in json.dumps(masked, ensure_ascii=False))
    t.eq("元组输入被接受", mask_slots([(10.0, 20.0)], timezone="UTC"),
         [{"start": 10.0, "end": 20.0, "tz": "UTC", "free": True}])
    t.eq("重复段去重", len(mask_slots([{"start": 1.0, "end": 2.0}, {"start": 1.0, "end": 2.0}], timezone="UTC")), 1)
    t.eq("上限截断", len(mask_slots([{"start": float(i * 10 + 1), "end": float(i * 10 + 10)} for i in range(80)],
                                    timezone="UTC")), MAX_MASKED_SLOTS)
    t.check("脏 ref 被丢", "ref" not in mask_slots([{"start": 1.0, "end": 2.0, "ref": "坏 ref"}], timezone="UTC")[0])
    t.eq("空输入", mask_slots([], timezone="UTC"), [])
    t.eq("free_slots 只留空闲", len(free_slots(masked)), 3)

    # -- 2. 帧编码：线上形状 --------------------------------------------------
    t.section("a2a:wire")
    frame = encode_frame("offer", {"slots": [{"start": 1.0, "end": 2.0}], "dur": 60},
                         negotiation_id="ng_aaaaaaaa0001", sender="popa", key=key, nonce="n0", ts=clock)
    t.check("前缀正确", frame.startswith(A2A_PREFIX), frame[:40])
    token = frame[len(A2A_PREFIX):]
    t.check("单 token 无空白", not any(ch.isspace() for ch in token), token)
    t.check("token 内不含 ::", "::" not in token, token)
    t.eq("payload.签名两段", token.count("."), 1)
    t.check("纯 ASCII", frame.isascii())
    t.check("长度在预算内", len(frame) <= 4096, str(len(frame)))
    again = encode_frame("offer", {"slots": [{"start": 1.0, "end": 2.0}], "dur": 60},
                         negotiation_id="ng_aaaaaaaa0001", sender="popa", key=key, nonce="n0", ts=clock)
    t.eq("同输入同帧（可复现）", again, frame)
    decoded = decode_frame(frame, key=key, now=clock, seen=NonceCache())
    t.eq("解出类型", decoded["kind"], "offer")
    t.eq("解出协商号", decoded["negotiation_id"], "ng_aaaaaaaa0001")
    t.eq("解出发送者", decoded["sender"], "popa")
    t.eq("解出时间戳", decoded["ts"], clock)
    t.eq("解出 nonce", decoded["nonce"], "n0")
    t.eq("解出帧体", decoded["body"], {"slots": [{"start": 1.0, "end": 2.0}], "dur": 60})
    t.eq("版本号", decoded["version"], A2A_VERSION)
    t.eq("六种帧类型", list(FRAME_KINDS), ["offer", "accept", "counter", "confirm", "decline", "sync"])
    t.eq("密钥是 bytes 或字符串皆可", decode_frame(
        encode_frame("sync", {}, negotiation_id="ng_x00000000001", sender="a", key="text-key", ts=clock),
        key="text-key", now=clock, seen=NonceCache())["kind"], "sync")

    # -- 3. 帧校验：签名/版本/时效/重放/夹带 ----------------------------------
    t.section("a2a:frame-security")
    seen = NonceCache()
    t.eq("错误密钥", _reason(h, key=b"other", frame=frame, seen=seen, clock=clock), "signature")
    tampered = A2A_PREFIX + frame[len(A2A_PREFIX):].split(".")[0][:-4] + "AAAA." + frame.split(".")[1]
    t.eq("篡改载荷", _reason(h, key=key, frame=tampered, seen=seen, clock=clock), "signature")
    t.eq("签名与载荷绑定（改一字节即废）", _reason(h, key=key, frame=tampered[:-1] + ("A" if tampered[-1] != "A" else "B"),
                                              seen=seen, clock=clock), "signature")
    t.eq("签名正确但帧体不是 JSON", _reason(h, key=key, frame=_raw_frame(b"plain text, not json", key),
                                       seen=seen, clock=clock), "frame")
    t.eq("签名正确但帧体是数组", _reason(h, key=key, frame=_raw_frame([1, 2], key), seen=seen, clock=clock), "frame")
    t.eq("对端签的未知类型", _reason(h, key=key, frame=_raw_frame(
        {"b": {}, "k": "propose", "n": "ng_raw01", "r": "raw1", "s": "a", "t": int(clock), "v": A2A_VERSION}, key),
        seen=seen, clock=clock), "frame")
    t.eq("对端签的旧版本", _reason(h, key=key, frame=_raw_frame(
        {"b": {}, "k": "offer", "n": "ng_raw01", "r": "raw2", "s": "a", "t": int(clock), "v": A2A_VERSION + 7}, key),
        seen=seen, clock=clock), "version")
    t.eq("对端签的缺 nonce", _reason(h, key=key, frame=_raw_frame(
        {"b": {}, "k": "offer", "n": "ng_raw01", "s": "a", "t": int(clock), "v": A2A_VERSION}, key),
        seen=seen, clock=clock), "frame")
    t.eq("对端签的缺协商号", _reason(h, key=key, frame=_raw_frame(
        {"b": {}, "k": "offer", "r": "raw4", "s": "a", "t": int(clock), "v": A2A_VERSION}, key),
        seen=seen, clock=clock), "frame")
    t.eq("对端签的缺时间戳", _reason(h, key=key, frame=_raw_frame(
        {"b": {}, "k": "offer", "n": "ng_raw01", "r": "raw5", "s": "a", "v": A2A_VERSION}, key),
        seen=seen, clock=clock), "frame")
    t.eq("对端签的帧体非对象", _reason(h, key=key, frame=_raw_frame(
        {"b": "hello", "k": "offer", "n": "ng_raw01", "r": "raw6", "s": "a", "t": int(clock), "v": A2A_VERSION}, key),
        seen=seen, clock=clock), "frame")
    smuggled = _raw_frame({"b": {"slots": [{"start": 1.0, "end": 2.0, "title": "裁员名单"}]},
                           "k": "offer", "n": "ng_raw01", "r": "raw7", "s": "a", "t": int(clock), "v": A2A_VERSION}, key)
    inbound = decode_frame(smuggled, key=key, now=clock, seen=NonceCache())["body"]["slots"]
    t.check("对端夹带的正文被入站投影裁掉",
            "裁员名单" not in json.dumps(mask_slots(inbound, timezone="UTC"), ensure_ascii=False),
            str(inbound))
    t.eq("缺前缀", _reason(h, key=key, frame="::POPOPX_A2A::"[:-2] + token, seen=seen, clock=clock), "frame")
    t.eq("只有前缀", _reason(h, key=key, frame=A2A_PREFIX, seen=seen, clock=clock), "frame")
    t.eq("非帧文本", _reason(h, key=key, frame="随便一句话", seen=seen, clock=clock), "frame")

    future = encode_frame("offer", {}, negotiation_id="ng_a2", sender="a", key=key, ts=clock + 86400)
    t.eq("时间戳超前", _reason(h, key=key, frame=future, seen=seen, clock=clock), "expired")
    stale = encode_frame("offer", {}, negotiation_id="ng_a3", sender="a", key=key, ts=clock - 99999.0)
    t.eq("超过时效窗口", _reason(h, key=key, frame=stale, seen=seen, clock=clock), "expired")
    fresh = encode_frame("offer", {}, negotiation_id="ng_a4", sender="a", key=key, nonce="once", ts=clock)
    t.eq("首次接受", _reason(h, key=key, frame=fresh, seen=seen, clock=clock), "")
    t.eq("重放拒绝", _reason(h, key=key, frame=fresh, seen=seen, clock=clock), "replay")
    t.eq("别的 nonce 可继续", _reason(h, key=key, frame=encode_frame("offer", {}, negotiation_id="ng_a4",
                                                                     sender="a", key=key, nonce="twice", ts=clock),
                                     seen=seen, clock=clock), "")
    t.raises("夹带 title 拒发", A2AError, encode_frame, "offer", {"slots": [{"start": 1.0, "end": 2.0, "title": "x"}]},
            negotiation_id="ng_a5", sender="a", key=key)
    t.raises("夹带 attendees 拒发", A2AError, encode_frame, "counter", {"p": {"attendees": ["a"]}},
             negotiation_id="ng_a6", sender="a", key=key)
    t.raises("嵌套 summary 拒发", A2AError, encode_frame, "offer", {"a": [{"b": {"summary": "s"}}]},
             negotiation_id="ng_a7", sender="a", key=key)
    t.raises("未知类型拒发", A2AError, encode_frame, "propose", {}, negotiation_id="ng_a8", sender="a", key=key)
    t.raises("空协商号拒发", A2AError, encode_frame, "offer", {}, negotiation_id="", sender="a", key=key)
    t.raises("协商号含 :: 拒发", A2AError, encode_frame, "offer", {}, negotiation_id="ng::x", sender="a", key=key)
    t.raises("空密钥拒发", A2AError, encode_frame, "offer", {}, negotiation_id="ng_a9", sender="a", key="")
    t.raises("帧体非对象拒发", A2AError, encode_frame, "offer", ["x"], negotiation_id="ng_aA", sender="a", key=key)
    t.raises("超长帧拒发", A2AError, encode_frame, "offer", {"blob": "y" * 6000}, negotiation_id="ng_aB",
             sender="a", key=key)
    t.check("禁止键集合覆盖日历正文", {"title", "attendees", "location", "summary", "description"} <= set(FORBIDDEN_KEYS))
    t.eq("peek 只看 id 不验签", peek_negotiation_id(frame), "ng_aaaaaaaa0001")
    t.eq("peek 垃圾返回空", peek_negotiation_id("::POPOPX_A2A::notbase64!!.sig"), "")
    t.eq("peek 非帧返回空", peek_negotiation_id("普通消息"), "")
    cache = NonceCache(maxlen=32)
    for index in range(60):
        cache.add(f"n{index}")
    t.eq("nonce 缓存有界", len(cache), 32)
    t.check("旧的已逐出", "n0" not in cache and "n59" in cache)
    cache.clear()
    t.eq("清空", len(cache), 0)

    # -- 4. 交集：时区与夏令时 -----------------------------------------------
    t.section("a2a:intersection")
    fall_lo, fall_hi = _local(2026, 10, 25, 0, 0), _local(2026, 10, 25, 23, 0)
    whole = [{"start": fall_lo, "end": fall_hi}]
    rows = intersect_slots(whole, whole, duration_minutes=60, owner_tz="Europe/Berlin",
                           peer_tz="Europe/Berlin", window=(fall_lo, fall_hi), step_minutes=30)
    labels = [row["owner_text"] for row in rows]
    t.eq("结果按上限截断", len(rows), MAX_INTERSECTION)
    t.eq("墙上时间不重复（回拨小时不双计）", len(set(labels)), len(labels))
    t.check("候选都对齐半点", all(row["owner_text"].endswith((":00", ":30")) for row in rows), str(labels[:3]))
    t.check("分数按降序", [row["score"] for row in rows] == sorted([row["score"] for row in rows], reverse=True))
    t.eq("段长等于时长", rows[0]["end"] - rows[0]["start"], 3600.0)
    t.eq("utc_text 与 start 一致", rows[0]["utc_text"], utc_text(rows[0]["start"]))
    t.eq("结果字段", sorted(rows[0]), ["duration_minutes", "end", "owner_text", "peer_text", "score", "start", "tz",
                                       "utc_text"])
    berlin_ny = intersect_slots([{"start": _local(2026, 11, 3, 8, 0), "end": _local(2026, 11, 3, 20, 0)}],
                                [{"start": _local(2026, 11, 3, 8, 0, tz="America/New_York"),
                                  "end": _local(2026, 11, 3, 20, 0, tz="America/New_York")}],
                                duration_minutes=60, owner_tz="Europe/Berlin", peer_tz="America/New_York",
                                window=(_local(2026, 11, 3, 8, 0), _local(2026, 11, 3, 20, 0)))
    first = berlin_ny[0]
    t.eq("跨时区文本自洽", wall_text(first["start"], "America/New_York"), first["peer_text"])
    t.eq("柏林比纽约晚 6 小时（双方都已回拨）",
         int((datetime.fromtimestamp(first["start"], ZoneInfo("Europe/Berlin")).hour
              - datetime.fromtimestamp(first["start"], ZoneInfo("America/New_York")).hour)), 6)
    spring = intersect_slots([{"start": _local(2026, 3, 29, 0, 0), "end": _local(2026, 3, 29, 23, 0)}],
                             [{"start": _local(2026, 3, 29, 0, 0), "end": _local(2026, 3, 29, 23, 0)}],
                             duration_minutes=60, owner_tz="Europe/Berlin", peer_tz="UTC",
                             window=(_local(2026, 3, 29, 0, 0), _local(2026, 3, 29, 23, 0)))
    t.check("跳进日不产生重复标签", len({row["owner_text"] for row in spring}) == len(spring))
    t.check("跳进日前后各按当时的偏移算",
            all(_berlin_offset(row["start"]) == (7200.0 if row["owner_text"] >= "2026-03-29 03:00" else 3600.0)
                for row in spring), str(spring[0]))
    t.check("不存在的那小时不被排进候选",
            all(row["owner_text"][11:13] != "02" for row in spring), str([row["owner_text"] for row in spring[:5]]))
    blocked = [{"start": _local(2026, 11, 27, 9, 0), "end": _local(2026, 11, 27, 10, 0), "busy": True}]
    cut = intersect_slots([{"start": _local(2026, 11, 27, 9, 0), "end": _local(2026, 11, 27, 11, 0)}],
                          [{"start": _local(2026, 11, 27, 9, 0), "end": _local(2026, 11, 27, 11, 0)}],
                          duration_minutes=60, owner_tz="Europe/Berlin", peer_tz="Europe/Berlin",
                          window=(_local(2026, 11, 27, 9, 0), _local(2026, 11, 27, 11, 0)), blocked=blocked)
    t.eq("忙区间把候选挤到 10:00", [row["owner_text"] for row in cut], ["2026-11-27 10:00"])
    t.eq("完全不相交 → 空", intersect_slots([{"start": 100.0, "end": 200.0}], [{"start": 300.0, "end": 400.0}],
                                            duration_minutes=30, owner_tz="UTC", peer_tz="UTC"), [])
    clipped = intersect_slots([{"start": 100.0, "end": 9000.0}], [{"start": 100.0, "end": 9000.0}],
                              duration_minutes=30, owner_tz="UTC", peer_tz="UTC", window=(100.0, 3700.0))
    t.check("窗口把结果裁掉窗外", clipped and all(100.0 <= row["start"] and row["end"] <= 3700.0 for row in clipped),
            str([(row["start"], row["end"]) for row in clipped]))
    t.eq("窗口里剩的那一段", [(row["start"], row["end"]) for row in clipped], [(1800.0, 3600.0)])
    t.eq("窗口窄到放不下一个对齐后的整段 → 空",
         intersect_slots([{"start": 100.0, "end": 4000.0}], [{"start": 100.0, "end": 4000.0}],
                         duration_minutes=30, owner_tz="UTC", peer_tz="UTC", window=(100.0, 1900.0)), [])
    t.eq("步长 60 分钟只出整点",
         {row["owner_text"][-2:] for row in intersect_slots(
             [{"start": _local(2026, 12, 1, 9, 0), "end": _local(2026, 12, 1, 12, 0)}],
             [{"start": _local(2026, 12, 1, 9, 0), "end": _local(2026, 12, 1, 12, 0)}],
             duration_minutes=30, owner_tz="Europe/Berlin", peer_tz="Europe/Berlin", step_minutes=60)}, {"00"})
    t.eq("时段短于会议 → 空", intersect_slots([{"start": 0.0, "end": 60.0}], [{"start": 0.0, "end": 60.0}],
                                              duration_minutes=60, owner_tz="UTC", peer_tz="UTC"), [])
    t.raises("时长为 0 被拒", A2AError, intersect_slots, [{"start": 1.0, "end": 999.0}], [{"start": 1.0, "end": 999.0}],
             duration_minutes=0, owner_tz="UTC", peer_tz="UTC")
    t.raises("未知时区被拒", A2AError, intersect_slots, [{"start": 1.0, "end": 999.0}], [{"start": 1.0, "end": 999.0}],
             duration_minutes=30, owner_tz="Nowhere/Zone", peer_tz="UTC")
    t.eq("空输入", intersect_slots([], [], duration_minutes=30, owner_tz="UTC", peer_tz="UTC"), [])
    busy_rows = [{"start": _local(2026, 11, 27, 9, 0), "end": _local(2026, 11, 27, 10, 0), "busy": True}]
    freed = free_from_busy(busy_rows, window=(_local(2026, 11, 27, 9, 0), _local(2026, 11, 27, 12, 0)),
                           timezone="Europe/Berlin", min_minutes=15)
    t.eq("忙表反推空闲", [(row["start"], row["end"]) for row in freed],
         [(_local(2026, 11, 27, 10, 0), _local(2026, 11, 27, 12, 0))])
    t.eq("空闲段标记 free", freed[0]["free"], True)
    t.eq("碎片被丢掉", free_from_busy([{"start": _local(2026, 11, 27, 9, 0), "end": _local(2026, 11, 27, 11, 59)}],
                                      window=(_local(2026, 11, 27, 9, 0), _local(2026, 11, 27, 12, 0)),
                                      timezone="Europe/Berlin", min_minutes=15), [])
    t.eq("非法窗口", free_from_busy(busy_rows, window=(100.0, 100.0), timezone="UTC"), [])

    # -- 5. 协商：起手 --------------------------------------------------------
    t.section("a2a:negotiator-start")
    sent: List[Tuple[str, str, str]] = []

    async def deliver(bot_id_arg: str, peer: str, text: str) -> None:
        sent.append((bot_id_arg, peer, text))

    nego = Negotiator(db, sender=deliver, clock=lambda: clock, key_provider=provider)
    owner_lo, owner_hi = _local(2026, 11, 27, 8, 0), _local(2026, 11, 27, 20, 0)
    opened = _async_value(h, nego.start, "bot_a2a", "peer_b",
                          owner_slots=[{"start": _local(2026, 11, 27, 9, 0), "end": _local(2026, 11, 27, 12, 0),
                                         "title": "机密"},
                                        {"start": _local(2026, 11, 27, 14, 0), "end": _local(2026, 11, 27, 17, 0)}],
                          duration_minutes=60, owner_tz="Europe/Berlin", peer_tz="Asia/Tokyo",
                          window=(owner_lo, owner_hi), label="Bob", owner_identity="popa")
    nid = str(opened["negotiation_id"])
    t.eq("起手状态", opened["status"], "open")
    t.eq("起手轮次", opened["round"], 1)
    t.check("协商号形状（ng_ + 12 位十六进制）",
            nid.startswith("ng_") and len(nid) == 15 and nid[3:].isalnum() and not any(c.isspace() for c in nid), nid)
    t.eq("帧前缀", opened["frame"][:len(A2A_PREFIX)], A2A_PREFIX)
    t.check("帧里没有日程标题", "机密" not in opened["frame"], opened["frame"][:80])
    t.eq("掩码段数", len(opened["slots"]), 2)
    t.eq("发送了一次", len(sent), 1)
    t.eq("发给谁", sent[0][:2], ("bot_a2a", "peer_b"))
    row = db.get_negotiation(nid)
    t.eq("账本行通道", row["channel"], "a2a")
    t.eq("账本行状态", row["status"], "open")
    t.eq("账本行 owner_slots 是掩码段", sorted(row["owner_slots"][0]), ["end", "free", "start", "tz"])
    t.eq("账本行时长", row["duration_minutes"], 60)
    t.eq("账本行对方时区", row["peer_timezone"], "Asia/Tokyo")
    t.eq("账本行标签", row["peer_label"], "Bob")
    t.eq("账本行 TTL", row["expires_at"], clock + 3600.0)
    t.eq("审计有 offer 事件", any(r["event"] == "offer" for r in db.recent_negotiations("bot_a2a", stage="a2a")), True)
    t.raises("空掩码时段起手被拒", A2AError, h.async_run, nego.start, "bot_a2a", "peer_b", owner_slots=[],
             duration_minutes=60, owner_tz="UTC", peer_tz="UTC", window=(owner_lo, owner_hi))
    t.raises("窗口倒挂被拒", A2AError, h.async_run, nego.start, "bot_a2a", "peer_b",
             owner_slots=[{"start": 1.0, "end": 2.0}], duration_minutes=60, owner_tz="UTC", peer_tz="UTC",
             window=(owner_hi, owner_lo))
    t.raises("非法对方身份被拒", A2AError, h.async_run, nego.start, "bot_a2a", "bad peer::x",
             owner_slots=[{"start": 1.0, "end": 2.0}], duration_minutes=60, owner_tz="UTC", peer_tz="UTC",
             window=(owner_lo, owner_hi))
    # 会话密钥按对方派生（真实 SMP 就是每联系人一条密钥），所以「换个对方就是换个密钥」
    # 必须由一个真的按 peer 派生的 provider 来测，而不是本组那个恒定的替身。
    per_peer = Negotiator(db, sender=deliver, clock=lambda: clock,
                          key_provider=lambda peer: hashlib.sha256(f"ppx-a2a\0{peer}".encode("utf-8")).digest())
    t.check("同一对方密钥稳定", per_peer.key_for("peer_b") == per_peer.key_for("peer_b"))
    t.check("不同对方密钥不同", per_peer.key_for("peer_b") != per_peer.key_for("peer_c"))
    t.eq("空对方身份取不到密钥", _reason_of(per_peer.key_for, ""), "wrong_peer")
    forged_by_other_peer = encode_frame("counter", {"slots": [{"start": 1.0, "end": 2.0}]}, negotiation_id=nid,
                                        sender="peer_c", key=per_peer.key_for("peer_c"), ts=clock)
    t.eq("拿 peer_c 的密钥伪造 peer_b 的帧", _reason(h, key=per_peer.key_for("peer_b"), frame=forged_by_other_peer,
                                          seen=NonceCache(), clock=clock), "signature")
    no_provider = Negotiator(db, sender=deliver, clock=lambda: clock)
    t.check("没有 provider 时按对方各自生成密钥", no_provider.key_for("peer_x") != no_provider.key_for("peer_y"))
    t.check("生成过的密钥会复用（同一对方）", no_provider.key_for("peer_x") == no_provider.key_for("peer_x"))

    # -- 6. 入站：收敛与拒绝 --------------------------------------------------
    t.section("a2a:negotiator-inbound")
    peer_counter = encode_frame("counter", {"slots": [{"start": _local(2026, 11, 27, 17, 30, tz="Asia/Tokyo"),
                                                        "end": _local(2026, 11, 27, 21, 0, tz="Asia/Tokyo")}],
                                            "dur": 60, "tz": "Asia/Tokyo"},
                                negotiation_id=nid, sender="peer_b", key=key, ts=clock)
    converging = Negotiator(db, sender=deliver, clock=lambda: clock, key_provider=provider)
    converging.set_identity("bot_a2a", "popa")
    outcome = _async_value(h, converging.inbound, "bot_a2a", peer_counter, peer_identity="peer_b")
    proposal = outcome.get("proposal") or {}
    t.eq("入站被处理", outcome["handled"], True)
    t.eq("入站被接受", outcome["accepted"], True)
    t.eq("收敛状态", outcome["status"], "converged")
    t.eq("收敛轮次", outcome["round"], 2)
    t.eq("提案已生成", proposal.get("status"), "pending")
    t.eq("提案来源", proposal.get("source"), "a2a")
    t.eq("提案动作", proposal.get("action"), "create")
    t.eq("提案挂在协商上", proposal.get("negotiation_id"), nid)
    t.eq("提案时长", proposal["end_ts"] - proposal["start_ts"], 3600.0)
    t.eq("提案时区", proposal["timezone"], "Europe/Berlin")
    t.eq("提案不编造标题", proposal["summary"], "")
    t.eq("payload 声明已掩码", proposal["payload"]["masked"], True)
    t.eq("payload 给出双方墙上时间", (proposal["payload"]["owner_text"], proposal["payload"]["peer_text"]),
         ("2026-11-27 10:00", "2026-11-27 18:00"))
    t.eq("恰有一条 pending 提案", len(db.list_proposals("bot_a2a", status="pending")), 1)
    t.eq("账本行置 converged", db.get_negotiation(nid)["status"], "converged")
    t.eq("账本行记下提案", db.get_negotiation(nid)["proposal_id"], proposal["proposal_id"])
    t.eq("回给对端 accept", [entry for entry in sent][-1][2][:len(A2A_PREFIX)], A2A_PREFIX)
    t.eq("出站帧类型", [entry for entry in converging.outbox][-1]["kind"], "accept")
    same = encode_frame("counter", {"slots": [{"start": _local(2026, 11, 27, 17, 30, tz="Asia/Tokyo"),
                                               "end": _local(2026, 11, 27, 21, 0, tz="Asia/Tokyo")}],
                                    "dur": 60}, negotiation_id=nid, sender="peer_b", key=key, ts=clock + 1)
    again_row = _async_value(h, converging.inbound, "bot_a2a", same, peer_identity="peer_b")
    t.eq("重复收敛不再造提案", again_row["proposal"]["proposal_id"], proposal["proposal_id"])
    t.eq("pending 仍只有一条", len(db.list_proposals("bot_a2a", status="pending")), 1)
    t.eq("非 A2A 文本不处理", _async_value(h, converging.inbound, "bot_a2a", "今天天气不错")["handled"], False)
    garbage = _async_value(h, converging.inbound, "bot_a2a", A2A_PREFIX + "!!!.!!!", peer_identity="peer_b")
    # 解码先比 HMAC 再解 JSON：形状都不对的帧连签名都对不上，理由自然是 signature。
    t.eq("垃圾帧被拒", (garbage["handled"], garbage["reason"]), (True, "signature"))
    signed_garbage = _async_value(h, converging.inbound, "bot_a2a", _raw_frame(b"plain text", key),
                                  peer_identity="peer_b")
    t.eq("签名正确但帧体不是 JSON", (signed_garbage["handled"], signed_garbage["reason"]), (True, "frame"))
    forged = encode_frame("counter", {"slots": [{"start": 1.0, "end": 2.0}]}, negotiation_id=nid, sender="peer_b",
                          key=b"not-the-session-key", ts=clock)
    t.eq("伪造签名被拒", _async_value(h, converging.inbound, "bot_a2a", forged, peer_identity="peer_b")["reason"],
         "signature")
    wrong_owner = encode_frame("counter", {"slots": [{"start": 1.0, "end": 2.0}]}, negotiation_id=nid,
                               sender="mallory", key=key, ts=clock)
    t.eq("冒名发送方被拒", _async_value(h, converging.inbound, "bot_a2a", wrong_owner, peer_identity="peer_b")["reason"],
         "wrong_peer")
    other_bot = _async_value(h, converging.inbound, "bot_other", peer_counter, peer_identity="peer_b")
    t.eq("别的 Bot 不推进他人协商", other_bot["accepted"], False)
    t.check("别的 Bot 的拒绝理由属于拦截类",
            other_bot["reason"] in ("replay", "signature", "unknown_negotiation", "wrong_peer"), other_bot["reason"])
    t.eq("别的 Bot 名下没多出提案", len(db.list_proposals("bot_other", status="pending")), 0)
    stranger = _async_value(h, converging.inbound, "bot_stranger", peer_counter, peer_identity="peer_b")
    t.eq("陌生 Bot 不接管他人协商", stranger["accepted"], False)

    # -- 7. accept 帧的数字不可信 --------------------------------------------
    t.section("a2a:accept-trust")
    trust_db = h.database("a2a_trust")
    quiet: List[Tuple[str, str, str]] = []

    async def capture(bot_id_arg: str, peer: str, text: str) -> None:
        quiet.append((bot_id_arg, peer, text))

    owner_only = Negotiator(trust_db, sender=capture, clock=lambda: clock, key_provider=provider)
    opened2 = _async_value(h, owner_only.start, "bot_trust", "peer_t",
                           owner_slots=[{"start": _local(2026, 12, 1, 9, 0), "end": _local(2026, 12, 1, 18, 0)}],
                           duration_minutes=60, owner_tz="Europe/Berlin", peer_tz="UTC",
                           window=(_local(2026, 12, 1, 8, 0), _local(2026, 12, 1, 20, 0)))
    nid2 = str(opened2["negotiation_id"])
    pushed = encode_frame("accept", {"slot": {"start": _local(2026, 12, 1, 2, 0, tz="UTC"),
                                              "end": _local(2026, 12, 1, 3, 0, tz="UTC")}, "dur": 60},
                          negotiation_id=nid2, sender="peer_t", key=key, ts=clock)
    result2 = _async_value(h, owner_only.inbound, "bot_trust", pushed, peer_identity="peer_t")
    t.eq("对端塞凌晨时段 → 不收敛", result2["status"], "open")
    t.eq("没有生成提案", result2.get("proposal"), None)
    t.eq("轮次推进", result2["round"], 2)
    inside = encode_frame("accept", {"slot": {"start": _local(2026, 12, 1, 10, 0), "end": _local(2026, 12, 1, 11, 0)}},
                          negotiation_id=nid2, sender="peer_t", key=key, ts=clock + 2)
    result3 = _async_value(h, owner_only.inbound, "bot_trust", inside, peer_identity="peer_t")
    t.eq("落在本方时段内才收敛", result3["status"], "converged")
    t.eq("收敛时间是本方墙上时间", result3["proposal"]["payload"]["owner_text"], "2026-12-01 10:00")
    t.eq("对端时区文本正确", result3["proposal"]["payload"]["peer_text"], "2026-12-01 09:00")

    # -- 8. 改期重开与终态 ----------------------------------------------------
    t.section("a2a:reopen")
    reopened = _async_value(h, owner_only.counter, nid2,
                            slots=[{"start": _local(2026, 12, 2, 9, 0), "end": _local(2026, 12, 2, 12, 0)}],
                            reason="owner_moves")
    t.eq("重开成功", reopened["ok"], True)
    t.eq("重开后状态", reopened["status"], "open")
    t.eq("重开标记", reopened["reopened"], True)
    # 每一帧都算一轮：起手 1 → 凌晨 accept 2 → 收敛 3 → 本方改期 counter 4。
    t.eq("轮次继续推进", reopened["round"], 4)
    t.eq("改期帧让轮次严格 +1", reopened["round"], int(result3["round"]) + 1)
    t.eq("旧提案置 superseded", trust_db.get_proposal(str(result3["proposal"]["proposal_id"]))["status"], "superseded")
    t.eq("重开后不再挂着旧提案", trust_db.get_negotiation(nid2)["proposal_id"], "")
    t.eq("重开帧类型", [entry for entry in owner_only.outbox][-1]["kind"], "counter")
    declined = _async_value(h, owner_only.decline, nid2, "no_time")
    t.eq("拒绝后状态", declined["status"], "rejected")
    t.eq("拒绝后行状态", trust_db.get_negotiation(nid2)["status"], "rejected")
    t.eq("终态行拒绝重开", _async_value(h, owner_only.counter, nid2,
                                    slots=[{"start": _local(2026, 12, 3, 9, 0), "end": _local(2026, 12, 3, 12, 0)}])["reason"],
         "closed")
    late = encode_frame("counter", {"slots": [{"start": _local(2026, 12, 3, 9, 0), "end": _local(2026, 12, 3, 12, 0)}]},
                        negotiation_id=nid2, sender="peer_t", key=key, ts=clock + 3)
    t.eq("终态行不再被帧驱动", _async_value(h, owner_only.inbound, "bot_trust", late, peer_identity="peer_t")["reason"],
         "closed")
    t.eq("未知协商号重开", _async_value(h, owner_only.counter, "ng_nosuchrow001", slots=[{"start": 1.0, "end": 2.0}])["reason"],
         "unknown_negotiation")
    t.eq("空时段重开被拒", _async_value(h, Negotiator(trust_db, key_provider=provider).counter, nid2, slots=[])["reason"],
         "closed")
    not_converged = _async_value(h, owner_only.confirm, nid2)
    t.eq("未收敛不能确认", not_converged["reason"], "not_converged")
    t.eq("未知 id 确认", _async_value(h, owner_only.confirm, "ng_nosuchrow002")["reason"], "unknown_negotiation")
    t.eq("未知 id 拒绝", _async_value(h, owner_only.decline, "ng_nosuchrow003")["reason"], "unknown_negotiation")

    # -- 9. 对端起手（同一协商号双向） ---------------------------------------
    t.section("a2a:two-sided")
    shared = h.database("a2a_two_sided")
    wire: List[Tuple[str, str, str]] = []

    async def hub(bot_id_arg: str, peer: str, text: str) -> None:
        wire.append((bot_id_arg, peer, text))

    def identities(bot_id_arg: str) -> str:
        return {"bot_left": "popl", "bot_right": "popr"}.get(bot_id_arg, bot_id_arg)

    left = Negotiator(shared, sender=hub, clock=lambda: clock, key_provider=provider, identity=identities)
    right = Negotiator(shared, sender=hub, clock=lambda: clock, key_provider=provider, identity=identities)
    offer = _async_value(h, left.start, "bot_left", "popr",
                         owner_slots=[{"start": _local(2026, 12, 8, 9, 0), "end": _local(2026, 12, 8, 12, 0)}],
                         duration_minutes=60, owner_tz="Europe/Berlin", peer_tz="Asia/Tokyo",
                         window=(_local(2026, 12, 8, 8, 0), _local(2026, 12, 8, 20, 0)), label="左")
    adopted = _async_value(h, right.inbound, "bot_right", offer["frame"], peer_identity="popl",
                           owner_tz="Asia/Tokyo",
                           slots=[{"start": _local(2026, 12, 8, 17, 30, tz="Asia/Tokyo"),
                                   "end": _local(2026, 12, 8, 21, 0, tz="Asia/Tokyo"), "summary": "内部"}],
                           label="右")
    t.eq("右端接下协商", adopted["status"], "converged")
    t.eq("右端提案属于右端 Bot", adopted["proposal"]["bot_id"], "bot_right")
    t.eq("右端提案带对方墙上时间", adopted["proposal"]["payload"]["owner_text"], "2026-12-08 18:00")
    echo = _async_value(h, left.inbound, "bot_left", wire[-1][2], peer_identity="popr")
    t.eq("左端收到 accept 后也收敛", echo["status"], "converged")
    t.eq("两端时段一致", (echo["proposal"]["start_ts"], echo["proposal"]["end_ts"]),
         (adopted["proposal"]["start_ts"], adopted["proposal"]["end_ts"]))
    t.eq("两端各一条提案", len(shared.list_proposals(status="pending")), 2)
    wire_id = peek_negotiation_id(offer["frame"])
    t.eq("发起端线上号就是本机主键", wire_id, nid_of(offer))
    t.eq("回程帧沿用同一线上号", {peek_negotiation_id(text) for _, _, text in wire}, {wire_id})
    t.check("右端本机主键是镜像号（不与左端相同）", adopted["negotiation_id"] != nid_of(offer),
            f"{adopted['negotiation_id']} / {nid_of(offer)}")
    t.eq("右端发出去的帧沿用左端的线上号", right._wire_id(shared.get_negotiation(adopted["negotiation_id"])), wire_id)
    t.eq("出站都是 A2A 帧", all(text.startswith(A2A_PREFIX) for _, _, text in wire), True)
    t.eq("出站帧里没有日历正文", all("summary" not in text and "内部" not in text for _, _, text in wire), True)
    mirror = _async_value(h, right.inbound, "bot_right", wire[-1][2], peer_identity="popl", owner_tz="Asia/Tokyo")
    t.eq("已收敛行的重复 accept 不再外发", (mirror["status"], len(wire)), ("converged", 3))

    # -- 10. 交接口：卡片与摘要 ----------------------------------------------
    t.section("a2a:handoff")
    card, card_text = proposal_card(shared, echo["proposal"], title="与 Bob 的会面", body="已对齐时区",
                                    fields=[{"label": "时间", "value": "10:00"}], visible_text="请确认",
                                    approve_label="确认", decline_label="婉拒", alt_label="换个时间")
    t.eq("卡片 id 落账", shared.get_proposal(str(echo["proposal"]["proposal_id"]))["card_id"], card["id"])
    t.contains("卡片文本带 ECO 标记", card_text, ECO_MARKER)
    t.contains("卡片可见文案在帧之前", card_text.split(ECO_MARKER)[0], "请确认")
    decoded_card = decode_message(card_text)
    t.eq("卡片可解回", decoded_card["card"]["id"], card["id"])
    # 按钮里存的是 ::CB:: **之后**的那段：客户端 isSendablePayload 禁止 payload 含 "::"，
    # 前缀由客户端补，所以 Studio 侧收发两侧的写法都不一样。
    approve_line = decoded_card["card"]["actions"][0]["payload"]
    t.check("按钮 payload 不含 ::CB:: 前缀", not approve_line.startswith(CALLBACK_PREFIX), approve_line)
    t.check("按钮 payload 无 :: 无空白",
            "::" not in approve_line and not any(ch.isspace() for ch in approve_line), approve_line)
    t.eq("按钮 id 是 approve", decoded_card["card"]["actions"][0]["id"], "approve")
    parsed = parse_callback(CALLBACK_PREFIX + approve_line)
    t.eq("回执行能被 parse_callback 认出", parsed is not None, True)
    t.eq("回执能反查提案", (parsed[0], parsed[1]), (CALLBACK_APPROVE, str(echo["proposal"]["proposal_id"])))
    t.eq("裸 payload 不是一条回执行", parse_callback(approve_line), None)
    t.raises("无提案 id 造卡片被拒", A2AError, proposal_card, shared, {}, title="x")
    t.eq("摘要取对方标签与时段", proposal_summary("Bob", echo["proposal"]["payload"]), "Bob · 2026-12-08 10:00")
    t.eq("摘要缺标签时用中性词", proposal_summary("", {"owner_text": "x"}), "POPOPX · x")

    # -- 11. 同步、轮次上限与过期 --------------------------------------------
    t.section("a2a:lifecycle")
    sync_db = h.database("a2a_rounds")
    quiet2: List[Tuple[str, str, str]] = []

    async def hub2(bot_id_arg: str, peer: str, text: str) -> None:
        quiet2.append((bot_id_arg, peer, text))

    # 这条线上一共走 5 帧（起手 + sync + 空时段 + 无重叠 + 无重叠），第 6 帧才越界：
    # max_rounds 定成 5 才能把「空时段仍然开着」和「轮次耗尽才中止」两件事分开测。
    loop = Negotiator(sync_db, sender=hub2, clock=lambda: clock, key_provider=provider, max_rounds=5)
    base = _async_value(h, loop.start, "bot_loop", "peer_l",
                        owner_slots=[{"start": _local(2026, 12, 15, 9, 0), "end": _local(2026, 12, 15, 12, 0)}],
                        duration_minutes=60, owner_tz="Europe/Berlin", peer_tz="UTC",
                        window=(_local(2026, 12, 15, 8, 0), _local(2026, 12, 15, 20, 0)))
    nid3 = str(base["negotiation_id"])
    sync_frame = encode_frame("sync", {}, negotiation_id=nid3, sender="peer_l", key=key, ts=clock)
    synced = _async_value(h, loop.inbound, "bot_loop", sync_frame, peer_identity="peer_l")
    t.eq("sync 被接受", synced["accepted"], True)
    t.eq("sync 回发掩码时段", [entry for entry in loop.outbox][-1]["kind"], "counter")
    empty = encode_frame("counter", {"slots": []}, negotiation_id=nid3, sender="peer_l", key=key, ts=clock + 1)
    first_round = _async_value(h, loop.inbound, "bot_loop", empty, peer_identity="peer_l")
    t.eq("空时段不收敛", first_round["status"], "open")
    t.eq("空时段仍记下原因供控制台复查", sync_db.get_negotiation(nid3)["last_error"], "empty_peer_slots")
    no_overlap = encode_frame("counter", {"slots": [{"start": _local(2026, 12, 16, 1, 0), "end": _local(2026, 12, 16, 3, 0)}]},
                              negotiation_id=nid3, sender="peer_l", key=key, ts=clock + 2)
    _async_value(h, loop.inbound, "bot_loop", no_overlap, peer_identity="peer_l")
    exhausted = _async_value(h, loop.inbound, "bot_loop", encode_frame(
        "counter", {"slots": [{"start": _local(2026, 12, 17, 1, 0), "end": _local(2026, 12, 17, 3, 0)}]},
        negotiation_id=nid3, sender="peer_l", key=key, ts=clock + 3), peer_identity="peer_l")
    t.eq("轮次耗尽后中止", exhausted["status"], "aborted")
    t.eq("中止原因", exhausted["reason"], "limit")
    t.eq("账本行 last_error", sync_db.get_negotiation(nid3)["last_error"], "rounds_exhausted")
    ttl = Negotiator(sync_db, clock=lambda: clock, key_provider=provider, session_ttl_seconds=60.0)
    expiring = _async_value(h, ttl.start, "bot_ttl", "peer_x",
                            owner_slots=[{"start": _local(2026, 12, 20, 9, 0), "end": _local(2026, 12, 20, 12, 0)}],
                            duration_minutes=60, owner_tz="UTC", peer_tz="UTC", window=(1.0, 100000.0))
    moment = [clock]
    ticking = Negotiator(sync_db, clock=lambda: moment[0], key_provider=provider, session_ttl_seconds=60.0)
    moment[0] = clock + 120.0
    t.eq("expire_all 过期行数", _async_value(h, ticking.expire_all), 1)
    t.eq("过期后行状态", sync_db.get_negotiation(str(expiring["negotiation_id"]))["status"], "expired")
    stale_offer = encode_frame("counter", {"slots": [{"start": _local(2026, 12, 20, 9, 0), "end": _local(2026, 12, 20, 12, 0)}]},
                               negotiation_id=str(expiring["negotiation_id"]), sender="peer_x", key=key, ts=moment[0])
    t.eq("过期行拒绝入站帧", _async_value(h, ticking.inbound, "bot_ttl", stale_offer, peer_identity="peer_x")["reason"],
         "closed")
    t.eq("协商漏斗可读", isinstance(sync_db.negotiation_stats("bot_loop"), dict), True)
    t.eq("快照字段安全", sorted(ttl.snapshot(str(expiring["negotiation_id"])))[:3],
         ["agreed_slot", "duration_minutes", "expires_at"])
    t.eq("未知协商快照为空", ttl.snapshot("ng_nosuchrow009"), {})
    bridgeless = Negotiator(sync_db, key_provider=provider)
    t.eq("没有 sender 也能跑（只记 outbox）", _async_value(h, bridgeless.start, "bot_nosender", "peer_n",
                                                        owner_slots=[{"start": 10.0, "end": 20.0}],
                                                        duration_minutes=5, owner_tz="UTC", peer_tz="UTC",
                                                        window=(0.0, 100.0))["status"], "open")
    failing = Negotiator(sync_db, key_provider=provider, sender=broken_sender, clock=lambda: clock)
    t.eq("发送器抛错不外溢", _async_value(h, failing.start, "bot_broken", "peer_broken",
                                       owner_slots=[{"start": 10.0, "end": 20.0}], duration_minutes=5,
                                       owner_tz="UTC", peer_tz="UTC", window=(0.0, 100.0))["status"], "open")
    t.eq("失败写进审计", any(r["event"] == "send_failed" for r in sync_db.recent_negotiations("bot_broken", stage="a2a")),
         True)
    audit_rows = sync_db.recent_negotiations(stage="a2a", limit=200)
    t.check("审计条目存在", len(audit_rows) > 0, str(len(audit_rows)))
    t.check("审计里没有日历正文", all("机密" not in str(r["detail"]) for r in audit_rows))
    t.check("审计里没有帧原文", all(A2A_PREFIX not in json.dumps(r, ensure_ascii=False) for r in audit_rows))
    t.eq("分组不污染其它 stage 集合", {r["stage"] for r in audit_rows}, {"a2a"})


async def broken_sender(bot_id: str, peer: str, text: str) -> None:
    raise ConnectionError("队列写不进去")


def nid_of(result: Dict[str, Any]) -> str:
    return str(result.get("negotiation_id") or "")


def _reason(h: Harness, *, key: Any, frame: str, seen: NonceCache, clock: float) -> str:
    """对 :func:`decode_frame` 的一次断言式调用：返回 reason，通过则空串。"""
    try:
        decode_frame(frame, key=key, now=clock, seen=seen)
    except A2AError as exc:
        return exc.reason
    return ""


# ---------------------------------------------------------------- 独立运行入口
GROUPS: Dict[str, Callable[[SelfTest, Harness], None]] = {
    "mac_node": group_mac_node,
    "a2a": group_a2a,
}


def main() -> int:
    """单独跑这两组：``python3 -m app.selftest_node``（可加 ``mac_node``/``a2a`` 过滤）。"""
    import sys

    only = [arg for arg in sys.argv[1:] if arg in GROUPS] or list(GROUPS)
    test = SelfTest(only=only)
    harness = Harness(test)
    started = time.time()
    try:
        for name in only:
            before_a, before_f = test.assertions, test.failures
            test.section(name)
            print(f"[group] {name}", flush=True)
            try:
                GROUPS[name](test, harness)
            except Exception as exc:  # noqa: BLE001 - 分组异常必须显式失败，不能吞
                test.failures += 1
                test.problems.append(f"FAIL [{name}] 分组异常 {type(exc).__name__}: {exc}")
                print(f"  FAIL [{name}] 分组异常 {type(exc).__name__}: {exc}", flush=True)
            test.per_group[name] = (test.assertions - before_a, test.failures - before_f)
            print(f"[group] {name}: 断言 {test.per_group[name][0]} 条，失败 {test.per_group[name][1]} 条", flush=True)
    finally:
        harness.close()
    print()
    for name, (count, failed) in test.per_group.items():
        print(f"  {name:22} {count:4} 条  {failed:3} 失败  {'ok' if failed == 0 else 'FAIL'}")
    print(f"合计 {test.assertions} 条断言，{len(only)}/{len(GROUPS)} 组，{test.failures} 条失败，"
          f"用时 {time.time() - started:.1f}s")
    if test.problems:
        print("\n".join(test.problems[:80]))
    return 0 if test.failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
