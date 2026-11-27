"""访客预约门户（零安装、零注册、不留邮箱的浏览器通道）。

**为什么要这一条通道**：外部访客不在 POPOPX 网络上，也不该被要求装客户端、注册账号
或留下邮箱才能约一次会面。所以 Studio 只发一条 **HMAC 签名的、带过期与访问次数预算的
一次性链接** ``<base>/book/<token>``：令牌本身就是授权凭据，服务端不建会话、不发 Cookie、
不引用任何第三方资源；页面是一个自包含的 HTML 字符串，任何手机浏览器都能打开。

流程（任务 3 通道 B）：

1. 主人（或后台）调用 :meth:`GuestPortal.issue` 铸造链接 —— 令牌里只放
   ``{v,lid,iat,exp,mus,dur}``，主人身份与日历内容一个字节都不进令牌；
2. 访客打开链接 → :meth:`GuestPortal.resolve` 按「签名 → 版本 → 过期 → 撤销 → 次数 →
   领取」的顺序校验，并 **原子地** 记一次访问；
3. 访客在页面上说时间偏好 → :meth:`GuestPortal.message` 找注入的 ``availability`` 要
   **脱敏后的空闲时段**（它没返回就诚实说「暂时无法确认空档」，绝不编造时段），
   收敛到唯一时段后写 ``pending`` 提案（``source="guest"``），并调用注入的
   ``card_pusher`` 把 ``::POPOPX_ECO::`` 确认卡片推给主人；
4. 主人点确认（提案 ``approved``）之后，访客侧才能用 :meth:`GuestPortal.ics` 取到
   标准 RFC 5545 邀请；``VEVENT`` 只带会议房间链接或「POPOPX Chat 通话」说明，
   绝不含主人真实地址、真名、邮箱或完整日程。

安全边界写死在本模块里，而不是指望调用方自觉：

* **验签优先**：先 ``hmac.compare_digest`` 再解析业务字段，攻击者可控的 JSON 永远走不到
  判定分支；编码必须规范（无 padding、可回编码、键集恰好等于 ``TOKEN_PAYLOAD_KEYS``），
  任何一处不符都是 ``malformed``。
* **防重放**：数据库是持久事实来源，但「读 uses → 判预算 → 写 uses」并不是一个动作，两个
  并发协程会同时穿过。因此 ``_ClaimLedger`` 在 ``threading.Lock`` 内对同一 ``link_id``
  做一次性 check-and-set，检查与写入之间没有 await、也没有线程切换点。
* **收紧而非放宽**：预算取 ``min(令牌 mus, 库里 max_uses)``，时长同理 —— 事后把库里的次数
  改大不能让已用完的单次令牌复活，管理员收紧也立刻生效。
* **撤销即时生效**：撤销只看库里的 ``status``，每次校验都重读，不缓存任何授权结论。
* **对外可见性**：页面文案 21 语种齐全且占位符完全一致，``ar`` 整页 ``dir="rtl"``；访客输入一律 HTML 转义；页面不含
  任何外链、不含 ``<script>``、不含原始令牌（表单 ``action=""`` 即回到当前 URL）。

本模块不联网、不 spawn 进程，也不 import A2A / Mac Node / Needle 运行时 —— 空档来源、
话术生成、卡片推送全是注入点，自检用替身即可跑满全部分支。
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import inspect
import json
import re
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timedelta
from datetime import timezone as fixed_tz
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import quote, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

try:  # pragma: no cover - 只有本机 tz 数据库残缺时才会走到
    from zoneinfo import ZoneInfoKeyError as _ZoneKeyError
except ImportError:  # pragma: no cover
    _ZoneKeyError = KeyError  # type: ignore[misc,assignment]

from . import ics
from .config import DEFAULT_HOST, Settings, is_loopback_http_url
from .database import Database, LedgerError, new_guest_link_id
from .eco_cards import EcoCardError, EcoLimits, confirmation_card
from .i18n import (
    FALLBACK_LOCALE,
    LOCALES,
    LOCALE_LABELS,
    is_rtl,
    normalize_locale,
    parse_accept_language,
)

# --------------------------------------------------------------------- 公共常量

TOKEN_VERSION = 1
LINK_PATH_PREFIX = "/book/"
MAX_MESSAGE_CHARS = 2000
MAX_REPLY_CHARS = 1200
MAX_TOPIC_CHARS = 120
MAX_LABEL_CHARS = 60
TOKEN_MASK_CHARS = 8
TOKEN_MASK = "…"

#: ``reason`` → HTTP 状态码，路由层一行 ``status = GUEST_ERRORS[exc.reason]`` 即可。
GUEST_ERRORS: Dict[str, int] = {
    "disabled": 404,  # 门户整体关闭：与「不存在」同码，不透露该功能是否存在
    "unknown_token": 404,
    "bad_signature": 403,
    "expired": 410,
    "revoked": 410,
    "exhausted": 410,
    "replayed": 409,
    "rate_limited": 429,
    "malformed": 400,
    "unavailable": 503,
}
REASONS: Tuple[str, ...] = tuple(GUEST_ERRORS)

SIGNATURE_HEX_CHARS = 64
TOKEN_SEGMENT_SEP = "."
TOKEN_PAYLOAD_KEYS: Tuple[str, ...] = ("v", "lid", "iat", "exp", "mus", "dur")
_TOKEN_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]{1,512}$")
_SIGNATURE_RE = re.compile(r"^[0-9a-f]{%d}$" % SIGNATURE_HEX_CHARS)
_LINK_ID_RE = re.compile(r"^[A-Za-z0-9_-]{3,64}$")

# 限流：真人约一次会面大约 3–5 轮，60 秒 12 条宽松到不可能误伤，又足以让脚本刷不动；
# 5 秒 4 条挡住粘贴式连发。键表有上限，令牌枚举洪水不能把内存吃掉。
RATE_LIMIT_WINDOW_SECONDS = 60.0
RATE_LIMIT_WINDOW_MESSAGES = 12
RATE_LIMIT_BURST_SECONDS = 5.0
RATE_LIMIT_BURST_MESSAGES = 4
RATE_LIMIT_MAX_KEYS = 2048
CLAIM_LEDGER_MAX = 4096
SESSION_BINDINGS_MAX = 4096
# 一次访问（打开页面）之后允许继续这段会话的时间窗：够访客把话说完、拿到 .ics，
# 又不至于让一条用完的单次链接长期被同一个人当永久入口。
SESSION_WINDOW_SECONDS = 4 * 3600.0

LINKS_PAGE_LIMIT = 200
VISITOR_REF_CHARS = 24
NONCE_BYTES = 16
MAX_SLOTS_SHOWN = 6
DEFAULT_SLOT_MINUTES = 60
DEFAULT_ISSUE_TTL_HOURS = 72
CARD_TTL_SECONDS = 1800.0
CARD_TTL_FLOOR_SECONDS = 30.0
MIN_DURATION_MINUTES = 5
MAX_DURATION_MINUTES = 1440
MAX_TTL_HOURS = 24 * 90
MIN_ISSUE_TTL_SECONDS = 60.0
MEETING_ROOM_PLACEHOLDER = "{room}"
MEETING_ROOM_CHARS = 22
ICS_FORMAT_LABEL = "iCalendar/.ics"
MESSAGE_VIEW_LIMIT = 40

#: ``message()`` 返回的 ``status`` 取值。
STATUS_UNAVAILABLE = "unavailable"
STATUS_OPEN = "open"
STATUS_PROPOSED = "proposed"
STATUS_CONFIRMED = "confirmed"

_ROOM_PATH_RE = re.compile(r"[^A-Za-z0-9_-]+")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# 前导的 ``@`` 属于地址本身（``@handle@host.tld`` 是 SMP 的写法），必须一起吃掉，否则掩完还剩一个
# ``@``，看着像掩了、其实给出了「这是一个账号」的形状。
_EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])@?[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_CJK_RE = re.compile(r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7af]")
_WEEKDAY_ABBR = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_WEEKDAY_FULL_EN = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
_WEEKDAY_ZH = ("周一", "周二", "周三", "周四", "周五", "周六", "周日")
_WEEKDAY_JA = ("月曜", "火曜", "水曜", "木曜", "金曜", "土曜", "日曜")
_CJK_INDEX = dict(zip("一二三四五六七八九十", range(1, 11)))

GuestErrorReason = str


class GuestError(RuntimeError):
    """访客链路上唯一的失败类型；``reason`` 决定 HTTP 状态码与页面文案。"""

    def __init__(self, reason: GuestErrorReason, detail: str = "") -> None:
        self.reason = reason if reason in GUEST_ERRORS else "malformed"
        self.detail = str(detail or "")[:400]
        self.http_status = GUEST_ERRORS.get(self.reason, 400)
        super().__init__(f"{self.reason}: {self.detail}" if self.detail else self.reason)


# ------------------------------------------------------------------- 令牌原语


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(segment: str) -> bytes:
    """严格 base64url（无 padding）解码并要求可回编码。

    不检查规范性的话，同一份 JSON 会有多种字节写法，令牌的「指纹」就会随编码方式漂移，
    而且会让同一个链接出现两条可分别计数的字符串。
    """
    if not _TOKEN_SEGMENT_RE.match(segment):
        raise GuestError("malformed", "令牌段含非法字符")
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except Exception as exc:  # noqa: BLE001 - binascii/ValueError 一律折算成 400
        raise GuestError("malformed", f"base64 无法解码：{type(exc).__name__}") from exc
    if _b64url_encode(raw) != segment:
        raise GuestError("malformed", "base64 非规范形式")
    return raw


def _coerce_int(value: Any, name: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GuestError("malformed", f"{name} 必须是整数，收到 {value!r}")
    number = float(value)
    if number != int(number) or not minimum <= number <= maximum:
        raise GuestError("malformed", f"{name}={value!r} 超出 {minimum}–{maximum}")
    return int(number)


def normalise_payload(payload: Any) -> Dict[str, Any]:
    """校验并规范化 ``{v,lid,iat,exp,mus,dur}``：键集必须 **恰好** 等于预期。"""
    if not isinstance(payload, Mapping):
        raise GuestError("malformed", "令牌负载必须是 JSON 对象")
    keys = {str(key) for key in payload}
    if keys != set(TOKEN_PAYLOAD_KEYS):
        missing = sorted(set(TOKEN_PAYLOAD_KEYS) - keys)
        extra = sorted(keys - set(TOKEN_PAYLOAD_KEYS))
        raise GuestError("malformed", f"令牌字段不符，缺少 {missing}，多余 {extra}")
    lid = str(payload["lid"] or "")
    if not _LINK_ID_RE.match(lid):
        raise GuestError("malformed", f"链接 id 非法：{lid!r}")
    version = _coerce_int(payload["v"], "v", minimum=0, maximum=255)
    issued = _coerce_int(payload["iat"], "iat", minimum=0, maximum=4102444800)
    expires = _coerce_int(payload["exp"], "exp", minimum=0, maximum=4102444800)
    if expires <= issued:
        raise GuestError("malformed", "exp 必须晚于 iat")
    mus = _coerce_int(payload["mus"], "mus", minimum=1, maximum=1000)
    dur = _coerce_int(payload["dur"], "dur", minimum=MIN_DURATION_MINUTES, maximum=MAX_DURATION_MINUTES)
    return {"v": version, "lid": lid, "iat": issued, "exp": expires, "mus": mus, "dur": dur}


def _canonical_body(payload: Mapping[str, Any]) -> bytes:
    ordered = {key: payload[key] for key in TOKEN_PAYLOAD_KEYS}
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False).encode(
        "utf-8"
    )


def token_signature(secret: str, segment: str) -> str:
    """``hmac-sha256(secret, base64url 段)`` 的小写十六进制。"""
    key = str(secret or "").encode("utf-8")
    if not key:
        raise GuestError("unavailable", "缺少访客签名密钥")
    return hmac.new(key, segment.encode("ascii"), hashlib.sha256).hexdigest()


def sign_token(secret: str, payload: Mapping) -> str:
    """``<base64url(compact json)>.<lowercase hex hmac-sha256>``。

    签名覆盖的是 **传输中的 base64url 段本身**，不是解码后的 JSON：这样验签方不必再规范化
    一遍序列化（任何键序/空白差异都会让合法令牌失效）。
    """
    normalised = normalise_payload(payload)
    segment = _b64url_encode(_canonical_body(normalised))
    return f"{segment}{TOKEN_SEGMENT_SEP}{token_signature(secret, segment)}"


def verify_token(secret: str, token: str) -> Dict[str, Any]:
    """验签并返回规范化负载；顺序是形状 → 签名（常数时间）→ 对象性 → 字段 → 版本。"""
    if not isinstance(token, str) or not token.strip():
        raise GuestError("malformed", "令牌为空")
    segment, _, digest = token.strip().partition(TOKEN_SEGMENT_SEP)
    if token.strip().count(TOKEN_SEGMENT_SEP) != 1:
        raise GuestError("malformed", "令牌必须是 <段>.<签名> 两段")
    if not _SIGNATURE_RE.match(digest):
        raise GuestError("malformed", f"签名必须是 {SIGNATURE_HEX_CHARS} 位小写十六进制")
    body = _b64url_decode(segment)
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise GuestError("malformed", f"令牌 JSON 无法解析：{type(exc).__name__}") from exc
    if not hmac.compare_digest(token_signature(secret, segment), digest):
        raise GuestError("bad_signature", "HMAC 不匹配（密钥不同或字段被改）")
    if not isinstance(decoded, dict):
        raise GuestError("malformed", "令牌负载不是 JSON 对象")
    payload = normalise_payload(decoded)
    if payload["v"] != TOKEN_VERSION:
        raise GuestError("malformed", f"未知令牌版本 {payload['v']}（本版本 {TOKEN_VERSION}）")
    return payload


def token_mask(token: str, chars: int = TOKEN_MASK_CHARS) -> str:
    """对外可显示的令牌指纹：**最多** 只保留 ``TOKEN_MASK_CHARS`` 个字符。

    ``TOKEN_MASK_CHARS`` 是「对外最多露出多少」的红线，不是一个可以调大的显示参数：日志里
    多写几个字符，就等于把这条唯一凭据的前缀送进了可被翻看的文件，所以超范围的值一律收紧。
    """
    text = str(token or "")
    try:
        keep = int(chars)
    except (TypeError, ValueError):
        keep = TOKEN_MASK_CHARS
    keep = max(0, min(keep, TOKEN_MASK_CHARS))
    return (text[:keep] + TOKEN_MASK) if text else ""


# ------------------------------------------------------------------- 时段模型


@dataclass(frozen=True)
class FreeSlot:
    """一条 **脱敏后** 的空闲时段：只有时间边界，没有任何日程标题、地点或事件细节。"""

    start_ts: float
    end_ts: float
    zone: str = "UTC"
    note: str = ""

    @property
    def minutes(self) -> int:
        return max(0, int(round((self.end_ts - self.start_ts) / 60.0)))

    def start(self, zone: Optional[fixed_tz] = None) -> datetime:
        return datetime.fromtimestamp(self.start_ts, zone or resolve_zone(self.zone))

    def end(self, zone: Optional[fixed_tz] = None) -> datetime:
        return datetime.fromtimestamp(self.end_ts, zone or resolve_zone(self.zone))

    def contains(self, moment: float) -> bool:
        return self.start_ts <= float(moment) < self.end_ts

    def label(self, duration_minutes: int = 0) -> str:
        """给访客看的空档标签（本地墙上时间 + 区名，永不出现主人身份）。"""
        return self.wall_clock(duration_minutes)

    def wall_clock(self, duration_minutes: int = 0) -> str:
        zone = resolve_zone(self.zone)
        start = self.start(zone)
        minutes = int(duration_minutes) if duration_minutes else self.minutes
        end = start + timedelta(minutes=max(1, minutes or self.minutes))
        return "%s %s %s-%s (%s)" % (
            start.strftime("%Y-%m-%d"),
            _WEEKDAY_ABBR[start.weekday()],
            start.strftime("%H:%M"),
            end.strftime("%H:%M"),
            self.zone,
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "start_ts": self.start_ts,
            "end_ts": self.end_ts,
            "minutes": self.minutes,
            "zone": self.zone,
            "label": self.label(),
        }


def resolve_zone(name: str) -> fixed_tz:
    """把 ``Asia/Shanghai`` 或 ``+08:00`` 解析成 tzinfo；不可用时退回 UTC。

    绝不猜时区：猜错等于把会面排到另一天，所以宁可退回 UTC 并在标签里带上区名。
    """
    raw = str(name or "").strip()
    if not raw:
        return fixed_tz.utc
    try:
        zone = ZoneInfo(raw)
    except (ZoneInfoNotFoundError, _ZoneKeyError, ValueError, OSError):
        zone = None
    if zone is not None:
        return zone  # type: ignore[return-value]
    offset = re.fullmatch(r"(?:UTC|GMT)?\s*([+-])(\d{1,2}):?(\d{2})?", raw, re.IGNORECASE)
    if offset:
        sign = 1 if offset.group(1) == "+" else -1
        hours, minutes = int(offset.group(2)), int(offset.group(3) or 0)
        if hours <= 14 and minutes < 60:
            return fixed_tz(sign * timedelta(hours=hours, minutes=minutes))
    return fixed_tz.utc


def _to_epoch(value: Any, zone: fixed_tz, *, end: bool = False, duration: int = 0) -> float:
    """接受 epoch 秒/毫秒、ISO 8601 字符串与 ``datetime``，统一成 epoch 秒。"""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        return number / 1000.0 if number > 1e11 else number
    if isinstance(value, datetime):
        return value.timestamp() if value.tzinfo else value.replace(tzinfo=zone).timestamp()
    text = str(value or "").strip()
    if not text:
        return 0.0
    if re.fullmatch(r"-?\d+(\.\d+)?", text):
        number = float(text)
        return number / 1000.0 if number > 1e11 else number
    date_only = bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", text))
    for candidate in (text.replace("Z", "+00:00"), text.replace("Z", "+00:00").replace(" ", "T", 1)):
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        moment = parsed.timestamp() if parsed.tzinfo else parsed.replace(tzinfo=zone).timestamp()
        # 只给日期的一端（``2027-01-16``）在日历里是「这一天」：作为结束边界必须补上时长，
        # 否则首尾同点，整条空档会在 ``end <= start`` 那一步被当成脏数据丢掉。
        if date_only and end and duration:
            return moment + max(1, duration) * 60.0
        return moment
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        moment = parsed.replace(tzinfo=zone).timestamp()
        if fmt == "%Y-%m-%d" and duration:
            return moment + (max(1, duration) * 60.0 if end else 0.0)
        return moment
    return 0.0


def normalise_slots(
    raw: Any,
    *,
    timezone: str = "",
    duration_minutes: int = DEFAULT_SLOT_MINUTES,
    now: float = 0.0,
    limit: int = MAX_SLOTS_SHOWN,
) -> List[FreeSlot]:
    """把任意 ``availability`` 返回值收敛成 ``List[FreeSlot]``。

    只认时间边界：上游即便把日程标题、地点、参会人塞进字段里，这里也一律丢弃 —— 这就是
    「脱敏空闲时段」的落点，而不是信任上游记得脱敏。
    """
    if raw is None:
        return []
    if isinstance(raw, Mapping):
        for key in ("slots", "free", "free_slots", "availability", "items", "data"):
            if key in raw:
                raw = raw[key]
                break
        else:
            raw = [raw]
    if isinstance(raw, (str, bytes)):
        raw = [raw]
    if not isinstance(raw, Iterable):
        return []
    zone_name = str(timezone or "").strip() or "UTC"
    zone = resolve_zone(zone_name)
    duration = max(MIN_DURATION_MINUTES, int(duration_minutes or DEFAULT_SLOT_MINUTES))
    collected: List[FreeSlot] = []
    for item in list(raw)[: 4 * max(1, int(limit))]:
        start = end = 0.0
        item_zone = zone_name
        if isinstance(item, FreeSlot):
            start, end, item_zone = float(item.start_ts), float(item.end_ts), (item.zone or zone_name)
        elif isinstance(item, Mapping):
            start = _to_epoch(
                item.get("start", item.get("from", item.get("begin", item.get("start_ts", 0)))), zone, duration=duration
            )
            end = _to_epoch(
                item.get("end", item.get("to", item.get("until", item.get("end_ts", 0)))), zone, end=True, duration=duration
            )
        elif isinstance(item, (list, tuple)) and item:
            start = _to_epoch(item[0], zone, duration=duration)
            end = _to_epoch(item[1], zone, end=True, duration=duration) if len(item) > 1 else 0.0
        else:
            start = _to_epoch(item, zone, duration=duration)
        if not end:
            end = start + duration * 60.0
        if start <= 0 or end <= start:
            continue
        if now and end <= float(now):
            continue  # 过去的空档没有意义，也不该暴露给访客
        collected.append(FreeSlot(round(start, 3), round(end, 3), item_zone, ""))
    collected.sort(key=lambda slot: slot.start_ts)
    unique: List[FreeSlot] = []
    for slot in collected:
        if unique and abs(slot.start_ts - unique[-1].start_ts) < 1.0:
            continue
        unique.append(slot)
    return unique[: max(1, int(limit))]


# ------------------------------------------------------------------ 内部机制


class _ClaimLedger:
    """同一 ``link_id`` 的访问领取表（进程内、锁内 check-and-set）。

    数据库的 ``uses`` 是持久事实来源，但「读 uses → 判预算 → 写 uses」不是一个动作：门户的
    DB 读写走 ``asyncio.to_thread``，两个并发 ``resolve`` 确实会同时读到 ``uses=0``。领取在
    这里一次性完成，因此单次令牌即使 ``asyncio.gather`` 双发也只被消耗一次。被淘汰的键不会
    放松限制：淘汰后 ``resolve`` 依然会看到库里已经 ``exhausted``。
    """

    def __init__(self, limit: int = CLAIM_LEDGER_MAX) -> None:
        self._lock = threading.Lock()
        self._limit = max(16, int(limit))
        self._claims: "OrderedDict[str, int]" = OrderedDict()

    def claim(self, key: str, budget: int, db_uses: int) -> str:
        """返回 ``granted`` / ``replayed`` / ``exhausted``。"""
        cap = max(1, int(budget))
        stored = max(0, int(db_uses))
        with self._lock:
            ledger = int(self._claims.get(key, 0))
            spent = max(ledger, stored)
            if spent >= cap:
                return "exhausted" if stored >= cap else "replayed"
            self._claims[key] = spent + 1
            self._claims.move_to_end(key)
            while len(self._claims) > self._limit:
                self._claims.popitem(last=False)
            return "granted"

    def release(self, key: str) -> None:
        """领取后 DB 写入失败时回滚，免得把自己的一次额度白烧掉。"""
        with self._lock:
            current = int(self._claims.get(key, 0))
            if current <= 1:
                self._claims.pop(key, None)
            else:
                self._claims[key] = current - 1

    def count(self, key: str) -> int:
        with self._lock:
            return int(self._claims.get(key, 0))

    def forget(self, key: str) -> None:
        with self._lock:
            self._claims.pop(key, None)

    def seed(self, key: str, used: int) -> None:
        with self._lock:
            self._claims[key] = max(0, int(used))
            self._claims.move_to_end(key)

    def __len__(self) -> int:
        with self._lock:
            return len(self._claims)


class _RateLimiter:
    """按 ``(link_id, visitor)`` 键的滑动窗口 + 突发窗口，纯内存。

    门户只绑回环或本机反代，攻击面是一条能被枚举的 URL；这里不追求精确计费，只求
    「刷不动」，所以 ``max_keys`` 触顶就淘汰最旧键，保证内存不随令牌洪水增长。
    """

    def __init__(
        self,
        *,
        window_seconds: float = RATE_LIMIT_WINDOW_SECONDS,
        window_hits: int = RATE_LIMIT_WINDOW_MESSAGES,
        burst_seconds: float = RATE_LIMIT_BURST_SECONDS,
        burst_hits: int = RATE_LIMIT_BURST_MESSAGES,
        max_keys: int = RATE_LIMIT_MAX_KEYS,
    ) -> None:
        self.window_seconds = float(window_seconds)
        self.window_hits = max(1, int(window_hits))
        self.burst_seconds = float(burst_seconds)
        self.burst_hits = max(1, int(burst_hits))
        self.max_keys = max(8, int(max_keys))
        self._lock = threading.Lock()
        self._hits: "OrderedDict[str, List[float]]" = OrderedDict()

    def hit(self, key: str, now: float) -> float:
        """记录一次命中；返回需要等待的秒数，``0`` 表示放行。"""
        moment = float(now)
        horizon = max(self.window_seconds, self.burst_seconds)
        with self._lock:
            stamps = [item for item in self._hits.get(key, []) if moment - item <= horizon]
            recent = [item for item in stamps if moment - item <= self.window_seconds]
            burst = [item for item in stamps if moment - item <= self.burst_seconds]
            if len(recent) >= self.window_hits:
                self._hits[key] = recent
                self._hits.move_to_end(key)
                return max(0.1, recent[0] + self.window_seconds - moment)
            if len(burst) >= self.burst_hits:
                self._hits[key] = recent
                self._hits.move_to_end(key)
                return max(0.1, burst[0] + self.burst_seconds - moment)
            recent.append(moment)
            self._hits[key] = recent
            self._hits.move_to_end(key)
            while len(self._hits) > self.max_keys:
                self._hits.popitem(last=False)
            return 0.0

    def reset(self, key: str = "") -> None:
        with self._lock:
            if key:
                self._hits.pop(key, None)
            else:
                self._hits.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._hits)


class _Sessions:
    """「一次访问 = 一段会话」的登记表：键是 ``(link_id, 访客指纹)``，到期时间被链接本身的
    ``expires_at`` 夹住。

    为什么要这张表：``max_uses`` 计的是 **访问**（访客打开 ``/book/<token>``），不是 HTTP
    请求数。单次令牌如果连「打开页面 → 说时间 → 拿 .ics」都撑不住，产品就是坏的；但如果
    「会话内继续」不对指纹设限，用尽的令牌就能被第二个人接着聊。所以继续对话的前提是
    **同一个人**（HMAC(link|最后一跳 IP|UA)，原始 IP / UA 一个字节都不落库）。

    进程重启后登记表为空，用尽的链接只能请主人再发一条 —— 这是刻意的 fail-closed：
    重启不该让一次令牌变成多次。
    """

    def __init__(self, limit: int = SESSION_BINDINGS_MAX) -> None:
        self._lock = threading.Lock()
        self._limit = max(16, int(limit))
        self._open: "OrderedDict[str, float]" = OrderedDict()

    @staticmethod
    def _key(link_id: str, digest: str) -> str:
        return f"{link_id}|{digest}"

    def open(self, link_id: str, digest: str, *, now: float, until: float) -> float:
        """开启 / 续期一段会话，返回新的到期时刻。"""
        horizon = max(float(now), float(until))
        key = self._key(link_id, digest)
        with self._lock:
            self._open[key] = horizon
            self._open.move_to_end(key)
            while len(self._open) > self._limit:
                self._open.popitem(last=False)
        return horizon

    def live(self, link_id: str, digest: str, moment: float) -> bool:
        key = self._key(link_id, digest)
        with self._lock:
            until = self._open.get(key, 0.0)
            if until > float(moment):
                return True
            if until:
                self._open.pop(key, None)
            return False

    def forget(self, link_id: str) -> int:
        """撤销 / 换令牌时清掉这条链接的所有会话，不留「老访客还能继续」的尾巴。"""
        prefix = f"{link_id}|"
        with self._lock:
            doomed = [key for key in self._open if key.startswith(prefix)]
            for key in doomed:
                self._open.pop(key, None)
        return len(doomed)

    def count(self, link_id: str = "") -> int:
        prefix = f"{link_id}|" if link_id else ""
        with self._lock:
            if not prefix:
                return len(self._open)
            return sum(1 for key in self._open if key.startswith(prefix))

    def __len__(self) -> int:
        with self._lock:
            return len(self._open)


def _clean(value: Any, limit: int) -> str:
    text = _CONTROL_CHARS.sub(" ", str(value if value is not None else ""))
    return text.strip()[: max(0, int(limit))]


def mask_owner(text: Any, needles: Sequence[str]) -> str:
    """把主人身份痕迹从对外文案里抹掉：真实地址、永久链接、真名、Bot 令牌、邮箱。

    这是产品承诺（访客永远看不到主人怎么被联系到），所以由代码兜底，而不是指望上游脱敏。

    邮箱必须 **先** 掩：真名往往是邮箱本地部分的前缀（``Elliot`` ⊂ ``elliot@gmail.com``），
    先按 needle 替换会把邮箱截成 ``[masked]@gmail.com`` —— 剩下的 ``@gmail.com`` 既是主人
    身份，又因为开头是 ``[`` 而再也匹配不上 ``_EMAIL_RE``，兜底就失效了。最后一遍兜底
    同样不能省：needle 替换本身可能拼出新的邮箱形状。
    """
    out = _EMAIL_RE.sub("[masked]", str(text or ""))
    for needle in needles:
        token = str(needle or "").strip()
        # 两三个拉丁字母当 needle 一定误伤（``ab`` ⊂ ``abc``），但两个汉字往往就是一个完整姓名，
        # 长度阈值不能只看字符数。
        if len(token) < 3 and not _CJK_RE.search(token):
            continue
        if token.lower() in out.lower():
            out = re.sub(re.escape(token), "[masked]", out, flags=re.IGNORECASE)
    return _EMAIL_RE.sub("[masked]", out)


def _relative_action(value: Any) -> str:
    """表单 ``action`` 只允许同源相对路径；空串（POST 回当前 URL）最安全。"""
    raw = str(value if value is not None else "").strip()
    if not raw:
        return ""
    if raw.startswith("//") or "://" in raw or raw.lower().startswith(("javascript:", "data:", "mailto:", "vbscript:")):
        return ""
    if not raw.startswith("/") and not re.fullmatch(r"[A-Za-z0-9._/?#=&%-]{1,512}", raw):
        return ""
    return raw


_INDEX_TAIL = r"(?:[).、,，:：]|号|个|条|项|番)?(?:时段|时间|天)?"


def _bare_index(folded: str) -> int:
    """把「1 / #2 / 选 3 / 第二个 / 第一个时段」折成序号，认不出返回 0。

    先抹掉空格：手机上「第 二 个」和「第二个」是同一个意思。中文序号必须认——访客页面列的是
    ``1) 2) 3)``，但中文母语的人回一句「第一个时段」比回一个孤零零的数字更常见。只认 **整句
    就是序号** 的回复：句子一长，「第三个」指的是列表还是日程就不该由门户猜，回落到重列候选。
    """
    tight = re.sub(r"\s+", "", str(folded or "").strip().casefold())
    match = re.fullmatch(r"(?:#|no\.?|option|opt|选|第)?(\d{1,2})" + _INDEX_TAIL, tight)
    if match:
        return int(match.group(1))
    match = re.fullmatch(r"(?:第)?([一二三四五六七八九十])" + _INDEX_TAIL, tight)
    if match:
        return _CJK_INDEX[match.group(1)]
    return 0


def _slot_key_hit(folded: str, compact: str, slot: FreeSlot, duration_minutes: int) -> bool:
    """访客是否用「日期 / 时刻 / 星期 / 标签原文」指到了这一格。"""
    start, end = slot.start(), slot.end()
    weekday = start.weekday()
    keys = {
        start.strftime("%Y-%m-%d"),
        start.strftime("%m-%d"),
        start.strftime("%H:%M"),
        end.strftime("%H:%M"),
        "%s-%s" % (start.strftime("%H:%M"), end.strftime("%H:%M")),
        slot.label(duration_minutes),
        _WEEKDAY_ABBR[weekday],
        _WEEKDAY_FULL_EN[weekday],
        _WEEKDAY_ZH[weekday],
        _WEEKDAY_JA[weekday],
        "%d点" % start.hour,
        "%d时" % start.hour,
    }
    if start.hour > 12:
        keys.add("%dpm" % (start.hour - 12))
    elif 0 < start.hour < 12:
        keys.add("%dam" % start.hour)
    for key in keys:
        needle = str(key).casefold()
        if needle and (needle in folded or re.sub(r"\s+", "", needle) in compact):
            return True
    return False


def _explicit_moments(text: str, zone: fixed_tz) -> List[float]:
    """从 ``2026-05-01`` / ``15:00`` 这类写法里还原绝对时刻，用于时段包含判断。"""
    moments: List[float] = []
    date = re.search(r"(\d{4})-(\d{1,2})-(\d{1,2})", text)
    clock = re.search(r"(\d{1,2})[:.](\d{2})", text)
    if not date:
        return moments
    try:
        base = datetime(int(date.group(1)), int(date.group(2)), int(date.group(3)), tzinfo=zone)
    except ValueError:
        return moments
    if not clock:
        return [base.timestamp(), (base + timedelta(hours=12)).timestamp()]
    hour, minute = int(clock.group(1)), int(clock.group(2))
    if hour < 24 and minute < 60:
        moments.append(base.replace(hour=hour, minute=minute).timestamp())
    return moments


def _match_slot(text: str, slots: Sequence[FreeSlot], *, duration_minutes: int) -> Tuple[List[FreeSlot], str]:
    """把访客的一句话落到 **唯一** 时段；落不到就返回空列表让调用方重新列候选。

    优先级：只有一格 → 纯序号 → 引用我给它的标签 → 日期/时刻/星期词。
    """
    if not slots:
        return [], "no_slots"
    folded = str(text or "").strip().casefold()
    compact = re.sub(r"\s+", "", folded)
    if len(slots) == 1:
        return [slots[0]], "only_slot"
    number = _bare_index(folded)
    if 1 <= number <= len(slots):
        return [slots[number - 1]], "index"
    for slot in slots:
        if _slot_key_hit(folded, compact, slot, duration_minutes):
            return [slot], "key"
    moments = _explicit_moments(compact, resolve_zone(slots[0].zone))
    if moments:
        hits = [slot for slot in slots if any(slot.contains(moment) for moment in moments)]
        if len(hits) == 1:
            return hits, "moment"
        if len(hits) > 1:
            return hits, "ambiguous"
    return [], "no_match"


def _slot_list(slots: Sequence[FreeSlot], duration: int) -> str:
    """编号列表：编号就是访客下一句要回的序号。"""
    if not slots:
        return "（无）"
    return "  ".join(
        "%d) %s" % (index, slot.label(min(max(1, int(duration)), slot.minutes) or max(1, int(duration))))
        for index, slot in enumerate(slots, start=1)
    )


# --------------------------------------------------------------------- 页面文案

PAGE_KEYS: Tuple[str, ...] = (
    "title",
    "brand",
    "tagline",
    "promise",
    "steps",
    "expires",
    "ask_label",
    "ask_placeholder",
    "send",
    "ready",
    "ics_button",
    "error",
    "lang_label",
    "privacy",
    "r_unavailable",
    "r_slots",
    "r_proposed",
    "c_title",
    "c_body",
    "c_call",
    "c_yes",
    "c_no",
    "c_alt",
)

PAGE_STRINGS: Dict[str, Dict[str, str]] = {
    "en": {
        "title": "Book a meeting",
        "brand": "POPOPX Booking",
        "tagline": "Just write the time that suits you. No account, nothing to install, no fee.",
        "promise": "No account · Nothing to install · No fee",
        "steps": "1 Tell your time · 2 The owner confirms · 3 Download a calendar invite",
        "expires": "This link works until {expires}",
        "ask_label": "When would you like to meet?",
        "ask_placeholder": "For example: next Wednesday after 15:00",
        "send": "Send to the assistant",
        "ready": "Confirmed: {title}",
        "ics_button": "Download the {format} calendar invite",
        "error": "This booking link is not available: {reason}",
        "lang_label": "Interface language",
        "privacy": "The other side only sees your time preference, never your contact details.",
        "r_unavailable": "I cannot check the owner's free slots right now, so I only note your preference "
        "and will not invent a time. Please try again in a moment.",
        "r_slots": "Free slots (only the gaps, no other events): {list} Reply with the number you prefer.",
        "r_proposed": "Sent {slot} to the owner for confirmation. Once it is approved you get a {format} "
        "invite right here.",
        "c_title": "Meeting request from a guest link",
        "c_body": "{topic} · {slot} · {duration} min · visitor identity is masked",
        "c_call": "call in POPOPX Chat (no extra account needed)",
        "c_yes": "Confirm",
        "c_no": "Decline",
        "c_alt": "Other time",
    },
    "zh-Hans": {
        "title": "预约会面",
        "brand": "POPOPX 预约",
        "tagline": "只要写下你方便的时间即可。无需账号、无需安装、不收费。",
        "promise": "无需账号 · 无需安装 · 不收费",
        "steps": "① 说明时间 → ② 主人确认 → ③ 下载日历邀请",
        "expires": "此链接有效期至 {expires}",
        "ask_label": "你想约在什么时候？",
        "ask_placeholder": "例如：下周三下午 3 点后",
        "send": "发送给助手",
        "ready": "已确认：{title}",
        "ics_button": "下载 {format} 日历邀请",
        "error": "无法使用这次预约链接：{reason}",
        "lang_label": "界面语言",
        "privacy": "对方只会看到你的时间偏好，看不到你的联系方式。",
        "r_unavailable": "我暂时无法确认主人的空闲时段，因此只记下你的时间偏好，不编造空档。请稍后再试。",
        "r_slots": "以下是空闲时段（只给出空档，不含其它日程）：{list} 回复序号即可。",
        "r_proposed": "已把「{slot}」推给主人确认；主人确认后你会在这里收到 {format} 日历邀请。",
        "c_title": "访客链接的会面请求",
        "c_body": "{topic} · {slot} · {duration} 分钟 · 访客身份已脱敏",
        "c_call": "在 POPOPX Chat 内通话（无需另注册账号）",
        "c_yes": "确认",
        "c_no": "婉拒",
        "c_alt": "换个时间",
    },
    "zh-Hant": {
        "title": "預約會面",
        "brand": "POPOPX 預約",
        "tagline": "只要寫下你方便的時間。無需帳號、無需安裝、不收費。",
        "promise": "無需帳號 · 無需安裝 · 不收費",
        "steps": "① 說明時間 → ② 主人確認 → ③ 下載日曆邀請",
        "expires": "此連結有效至 {expires}",
        "ask_label": "你想約在什麼時候？",
        "ask_placeholder": "例如：下週三下午 3 點後",
        "send": "傳送給助理",
        "ready": "已確認：{title}",
        "ics_button": "下載 {format} 日曆邀請",
        "error": "無法使用此預約連結：{reason}",
        "lang_label": "介面語言",
        "privacy": "對方只會看到你的時間偏好，看不到你的聯絡方式。",
        "r_unavailable": "我暫時無法核對主人的空檔時段，因此只記錄你的時間偏好，不編造空檔。請稍後再試。",
        "r_slots": "以下為空檔時段（僅顯示空檔，不含其他日程）：{list} 回覆序號即可。",
        "r_proposed": "已將「{slot}」推送給主人確認；主人確認後你會在此收到 {format} 日曆邀請。",
        "c_title": "來自訪客連結的會面請求",
        "c_body": "{topic} · {slot} · {duration} 分鐘 · 訪客身分已脫敏",
        "c_call": "在 POPOPX Chat 內通話（無需另註冊帳號）",
        "c_yes": "確認",
        "c_no": "婉拒",
        "c_alt": "換個時間",
    },
    "ja": {
        "title": "面会の予約",
        "brand": "POPOPX 予約",
        "tagline": "ご都合のよい時間を入力するだけです。アカウント不要・インストール不要・無料。",
        "promise": "アカウント不要 · インストール不要 · 無料",
        "steps": "① 時間を伝える → ② 相手が確認 → ③ カレンダー招待を取得",
        "expires": "このリンクは {expires} まで有効です",
        "ask_label": "いつ会いましょうか？",
        "ask_placeholder": "例：来週の水曜 15 時以降",
        "send": "アシスタントに送信",
        "ready": "確定しました：{title}",
        "ics_button": "{format} カレンダー招待をダウンロード",
        "error": "この予約リンクは利用できません：{reason}",
        "lang_label": "表示言語",
        "privacy": "相手に伝わるのは希望する時間だけで、連絡先は公開されません。",
        "r_unavailable": "現在オーナーの空き時間を確認できないため、ご希望を記録するに留め、時間は作りません。"
        "少しして改めてお試しください。",
        "r_slots": "空き枠（隙間のみ、他の予定は含まず）：{list} 番号でお答えください。",
        "r_proposed": "「{slot}」をオーナーの確認用に送信しました。承認されるとここで {format} 招待を取得できます。",
        "c_title": "ゲストリンクからの面会依頼",
        "c_body": "{topic} · {slot} · {duration} 分 · 訪問者の身分は伏せられています",
        "c_call": "POPOPX Chat 内の通話（追加アカウント不要）",
        "c_yes": "確認",
        "c_no": "お断り",
        "c_alt": "別の日時",
    },
    "ar": {
        "title": "حجز اجتماع",
        "brand": "حجز POPOPX",
        "tagline": "اكتب فقط الوقت الذي يناسبك. بلا حساب، بلا تثبيت، بلا رسوم.",
        "promise": "بلا حساب · بلا تثبيت · بلا رسوم",
        "steps": "1 أخبرنا بوقتك · 2 يؤكد المالك · 3 نزّل دعوة التقويم",
        "expires": "يعمل هذا الرابط حتى {expires}",
        "ask_label": "متى تود الاجتماع؟",
        "ask_placeholder": "مثال: الأربعاء القادم بعد الساعة 15:00",
        "send": "أرسل إلى المساعد",
        "ready": "تم التأكيد: {title}",
        "ics_button": "نزّل دعوة تقويم {format}",
        "error": "رابط الحجز هذا غير متاح: {reason}",
        "lang_label": "لغة الواجهة",
        "privacy": "يرى الطرف الآخر تفضيل الوقت فقط، ولا يرى بيانات الاتصال الخاصة بك أبدًا.",
        "r_unavailable": "لا أستطيع التحقق من أوقات المالك المتاحة الآن، لذا أسجل تفضيلك فقط ولا أختلق وقتًا. حاول مرة أخرى بعد قليل.",
        "r_slots": "الأوقات المتاحة (الفجوات فقط، دون أحداث أخرى): {list} أرسل رقم الخيار الذي تفضله.",
        "r_proposed": "أرسلت {slot} إلى المالك للتأكيد. بعد الموافقة ستصلك دعوة {format} هنا.",
        "c_title": "طلب اجتماع من رابط زائر",
        "c_body": "{topic} · {slot} · {duration} دقيقة · هوية الزائر مقنّعة",
        "c_call": "مكالمة في POPOPX Chat (بلا حساب إضافي)",
        "c_yes": "تأكيد",
        "c_no": "رفض",
        "c_alt": "وقت آخر",
    },
    "bg": {
        "title": "Запазване на среща",
        "brand": "POPOPX Запазване",
        "tagline": "Просто напишете кога ви е удобно. Без акаунт, без инсталация, без такса.",
        "promise": "Без акаунт · Без инсталация · Без такса",
        "steps": "1 Посочете час · 2 Собственикът потвърди · 3 Изтеглете покана",
        "expires": "Връзката е валидна до {expires}",
        "ask_label": "Кога бихте искали среща?",
        "ask_placeholder": "Напр.: следващата сряда след 15:00",
        "send": "Изпрати до асистента",
        "ready": "Потвърдено: {title}",
        "ics_button": "Изтегляне на {format} покана",
        "error": "Тази връзка за записване не е достъпна: {reason}",
        "lang_label": "Език на интерфейса",
        "privacy": "Отсрещната страна вижда само часа, не и контактите ви.",
        "r_unavailable": "Сега не мога да проверя свободното време на собственика, затова само записвам "
        "желанието ви и не измислям час. Опитайте след малко.",
        "r_slots": "Свободни часове (само свободното време, без други събития): {list} Отговорете с номер.",
        "r_proposed": "Изпратих «{slot}» на собственика за потвърждение. След одобрение ще получите {format} "
        "покана тук.",
        "c_title": "Молба за среща от гост-връзка",
        "c_body": "{topic} · {slot} · {duration} мин · посетителят е анонимен",
        "c_call": "разговор в POPOPX Chat (без допълнителен акаунт)",
        "c_yes": "Потвърди",
        "c_no": "Откажи",
        "c_alt": "Друг час",
    },
    "cs": {
        "title": "Rezervace setkání",
        "brand": "POPOPX Rezervace",
        "tagline": "Stačí napsat, kdy vám to vyhovuje. Bez účtu, bez instalace, bez poplatku.",
        "promise": "Bez účtu · Bez instalace · Bez poplatku",
        "steps": "1 Uveďte čas · 2 Majitel potvrdí · 3 Stáhněte pozvánku",
        "expires": "Tento odkaz platí do {expires}",
        "ask_label": "Kdy se chcete sejít?",
        "ask_placeholder": "Např.: příští středu od 15:00",
        "send": "Odeslat asistentovi",
        "ready": "Potvrzeno: {title}",
        "ics_button": "Stáhnout {format} pozvánku",
        "error": "Tento rezervační odkaz není dostupný: {reason}",
        "lang_label": "Jazyk rozhraní",
        "privacy": "Druhá strana vidí jen váš čas, nikdy vaše kontakty.",
        "r_unavailable": "Volné časy majitele teď nemohu ověřit, takže si vaše přání jen zapisuji a nic "
        "nevymýšlím. Zkuste to prosím za chvíli.",
        "r_slots": "Volné termíny (jen mezery, žádné jiné události): {list} Odpovězte číslem.",
        "r_proposed": "Poslal jsem «{slot}» majiteli k potvrzení. Po schválení tu dostanete {format} pozvánku.",
        "c_title": "Žádost o setkání z odkazu hosta",
        "c_body": "{topic} · {slot} · {duration} min · návštěvník je skrytý",
        "c_call": "hovor v POPOPX Chat (bez dalšího účtu)",
        "c_yes": "Potvrdit",
        "c_no": "Odmítnout",
        "c_alt": "Jindy",
    },
    "de": {
        "title": "Termin buchen",
        "brand": "POPOPX Buchung",
        "tagline": "Einfach schreiben, wann es Ihnen passt. Kein Konto, keine Installation, keine Gebühr.",
        "promise": "Kein Konto · Keine Installation · Keine Gebühr",
        "steps": "1 Zeit nennen · 2 Inhaber bestätigt · 3 Einladung herunterladen",
        "expires": "Dieser Link gültig bis {expires}",
        "ask_label": "Wann möchten Sie sich treffen?",
        "ask_placeholder": "Zum Beispiel: nächsten Mittwoch nach 15 Uhr",
        "send": "An den Assistenten senden",
        "ready": "Bestätigt: {title}",
        "ics_button": "{format}-Einladung herunterladen",
        "error": "Dieser Buchungslink ist nicht verfügbar: {reason}",
        "lang_label": "Sprache der Oberfläche",
        "privacy": "Die Gegenseite sieht nur Ihre Zeitangabe, nie Ihre Kontaktdaten.",
        "r_unavailable": "Die freien Zeiten kann ich gerade nicht prüfen, daher notiere ich nur Ihren Wunsch "
        "und erfinde keinen Termin. Bitte später erneut versuchen.",
        "r_slots": "Freie Zeitfenster (nur Lücken, keine anderen Termine): {list} Antworten Sie mit der Nummer.",
        "r_proposed": "Ich habe «{slot}» zur Bestätigung an den Inhaber gesendet. Nach der Freigabe erhalten "
        "Sie hier die {format}-Einladung.",
        "c_title": "Treffensanfrage per Gastlink",
        "c_body": "{topic} · {slot} · {duration} Minuten · Besucherdaten maskiert",
        "c_call": "Anruf in POPOPX Chat (kein zusätzliches Konto)",
        "c_yes": "Bestätigen",
        "c_no": "Ablehnen",
        "c_alt": "Anderer Termin",
    },
    "es": {
        "title": "Reservar una reunión",
        "brand": "POPOPX Reservas",
        "tagline": "Solo escribe cuándo te viene bien. Sin cuenta, sin instalar nada, sin coste.",
        "promise": "Sin cuenta · Sin instalación · Sin coste",
        "steps": "1 Indica tu hora · 2 La persona titular confirma · 3 Descarga la invitación",
        "expires": "Este enlace es válido hasta {expires}",
        "ask_label": "¿Cuándo quieres reunirte?",
        "ask_placeholder": "Por ejemplo: el próximo miércoles después de las 15:00",
        "send": "Enviar al asistente",
        "ready": "Confirmado: {title}",
        "ics_button": "Descargar invitación {format}",
        "error": "Este enlace de reserva no está disponible: {reason}",
        "lang_label": "Idioma de la interfaz",
        "privacy": "La otra parte solo ve tu horario, nunca tus datos de contacto.",
        "r_unavailable": "Ahora mismo no puedo comprobar los huecos libres, así que solo anoto tu preferencia "
        "y no invento ninguna hora. Vuelve a intentarlo en un momento.",
        "r_slots": "Huecos libres (solo huecos, sin otros eventos): {list} Responde con el número que prefieras.",
        "r_proposed": "He enviado «{slot}» a la persona titular para su confirmación. Al aprobarla recibirás "
        "aquí la invitación {format}.",
        "c_title": "Solicitud de reunión por enlace de invitado",
        "c_body": "{topic} · {slot} · {duration} min · visitante sin identificar",
        "c_call": "llamada en POPOPX Chat (sin otra cuenta)",
        "c_yes": "Confirmar",
        "c_no": "Rechazar",
        "c_alt": "Otra hora",
    },
    "fi": {
        "title": "Varaa tapaaminen",
        "brand": "POPOPX Varaus",
        "tagline": "Kirjoita vain sopiva aikasi. Ei tiliä, ei asennusta, ei maksua.",
        "promise": "Ei tiliä · Ei asennusta · Ei maksua",
        "steps": "1 Kerro aikasi · 2 Omistaja vahvistaa · 3 Lataa kutsu",
        "expires": "Tämä linkki on voimassa {expires} asti",
        "ask_label": "Milloin haluaisit tavata?",
        "ask_placeholder": "Esimerkiksi ensi keskiviikko kello 15 jälkeen",
        "send": "Lähetä avustajalle",
        "ready": "Vahvistettu: {title}",
        "ics_button": "Lataa {format}-kutsu",
        "error": "Tätä varauslinkkiä ei voi käyttää: {reason}",
        "lang_label": "Käyttöliittymän kieli",
        "privacy": "Vastaava osapuoli näkee vain aikatoiveesi, ei yhteystietojasi.",
        "r_unavailable": "En juuri nyt pysty tarkistamaan omistajan tyhjiä aikoja, joten merkitsen vain "
        "toiveesi enkä keksi aikaa. Yritä hetken kuluttua uudelleen.",
        "r_slots": "Vapaat ajat (vain aukot, ei muita tapahtumia): {list} Vastaa numerolla.",
        "r_proposed": "Lähetin ehdon «{slot}» omistajan vahvistettavaksi. Hyväksynnän jälkeen saat tähän "
        "{format}-kutsun.",
        "c_title": "Tapaamispyyntö vieraan linkistä",
        "c_body": "{topic} · {slot} · {duration} min · vieras peitetty",
        "c_call": "puhelu POPOPX Chatissa (ei uutta tiliä)",
        "c_yes": "Vahvista",
        "c_no": "Hylkää",
        "c_alt": "Muu aika",
    },
    "fr": {
        "title": "Réserver un rendez-vous",
        "brand": "POPOPX Réservation",
        "tagline": "Écrivez simplement vos disponibilités. Sans compte, sans installation, sans frais.",
        "promise": "Sans compte · Sans installation · Sans frais",
        "steps": "1 Indiquez une heure · 2 Le propriétaire confirme · 3 Téléchargez l'invitation",
        "expires": "Ce lien est valable jusqu'au {expires}",
        "ask_label": "Quand souhaitez-vous vous rencontrer ?",
        "ask_placeholder": "Par exemple : mercredi prochain après 15 h",
        "send": "Envoyer à l'assistant",
        "ready": "Créneau confirmé : {title}",
        "ics_button": "Télécharger l'invitation {format}",
        "error": "Ce lien de réservation n'est pas disponible : {reason}",
        "lang_label": "Langue de l'interface",
        "privacy": "L'autre partie ne voit que vos disponibilités, jamais vos coordonnées.",
        "r_unavailable": "Je ne peux pas vérifier les créneaux libres pour l'instant ; je note votre "
        "préférence sans inventer d'horaire. Réessayez dans un moment.",
        "r_slots": "Créneaux libres (uniquement les plages, aucun autre événement) : {list} Répondez par le numéro.",
        "r_proposed": "J'ai soumis «{slot}» au propriétaire pour confirmation. Dès son accord, vous recevrez "
        "ici l'invitation {format}.",
        "c_title": "Demande de rendez-vous par lien invité",
        "c_body": "{topic} · {slot} · {duration} min · visiteur masqué",
        "c_call": "appel dans POPOPX Chat (sans autre compte)",
        "c_yes": "Confirmer",
        "c_no": "Refuser",
        "c_alt": "Autre créneau",
    },
    "hu": {
        "title": "Találkozó foglalása",
        "brand": "POPOPX foglalás",
        "tagline": "Csak írja le, mikor érne rá. Fiók nélkül, telepítés nélkül, díj nélkül.",
        "promise": "Fiók nélkül · Telepítés nélkül · Díj nélkül",
        "steps": "1 Adja meg az időt · 2 A tulajdonos megerősíti · 3 Töltse le a meghívót",
        "expires": "A link eddig érvényes: {expires}",
        "ask_label": "Mikor szeretne találkozni?",
        "ask_placeholder": "Például: jövő szerdán 15 óra után",
        "send": "Küldés az asszisztensnek",
        "ready": "Megerősítve: {title}",
        "ics_button": "{format} meghívó letöltése",
        "error": "Ez a foglalási link nem elérhető: {reason}",
        "lang_label": "A felület nyelve",
        "privacy": "A másik fél csak az időpontot látja, elérhetőségeit nem.",
        "r_unavailable": "Most nem tudom ellenőrizni a tulajdonos szabad időpontjait, ezért csak a kérését "
        "jegyzem meg, és nem találok ki időpontot. Próbálja később.",
        "r_slots": "Szabad időablakok (csak a lyukak, egyéb események nélkül): {list} Válaszoljon a sorszámmal.",
        "r_proposed": "Elküldtem «{slot}» a tulajdonosnak megerősítésre. Jóváhagyás után itt kapja meg a "
        "{format} meghívót.",
        "c_title": "Találkozókérelem vendéglinkről",
        "c_body": "{topic} · {slot} · {duration} perc · a látogató takarva",
        "c_call": "hívás a POPOPX Chatben (extra fiók nélkül)",
        "c_yes": "Megerősítés",
        "c_no": "Elutasítás",
        "c_alt": "Más időpont",
    },
    "it": {
        "title": "Prenota un incontro",
        "brand": "POPOPX Prenotazione",
        "tagline": "Scrivi solo quando sei disponibile. Senza account, senza installazione, senza costi.",
        "promise": "Senza account · Senza installazione · Senza costi",
        "steps": "1 Indica l'orario · 2 Il titolare conferma · 3 Scarica l'invito",
        "expires": "Questo link è valido fino al {expires}",
        "ask_label": "Quando vorresti incontrarti?",
        "ask_placeholder": "Ad esempio: mercoledì prossimo dopo le 15:00",
        "send": "Invia all'assistente",
        "ready": "Orario confermato: {title}",
        "ics_button": "Scarica l'invito {format}",
        "error": "Questo link di prenotazione non è disponibile: {reason}",
        "lang_label": "Lingua dell'interfaccia",
        "privacy": "L'altra parte vede solo la tua preferenza oraria, mai i tuoi contatti.",
        "r_unavailable": "Al momento non posso verificare gli orari liberi del titolare, quindi annoto solo "
        "la tua preferenza senza inventare orari. Riprova tra poco.",
        "r_slots": "Orari liberi (solo gli spazi, nessun altro evento): {list} Rispondi con il numero.",
        "r_proposed": "Ho inviato «{slot}» al titolare per la conferma. Dopo l'approvazione riceverai qui "
        "l'invito {format}.",
        "c_title": "Richiesta di incontro da link ospite",
        "c_body": "{topic} · {slot} · {duration} min · ospite mascherato",
        "c_call": "chiamata in POPOPX Chat (senza altri account)",
        "c_yes": "Conferma",
        "c_no": "Rifiuta",
        "c_alt": "Altro orario",
    },
    "ko": {
        "title": "회의 예약",
        "brand": "POPOPX 예약",
        "tagline": "편한 시간을 적기만 하세요. 계정도, 설치도, 비용도 없습니다.",
        "promise": "계정 없음 · 설치 없음 · 비용 없음",
        "steps": "1 시간 알려주기 · 2 소유자 확인 · 3 캘린더 초대 내려받기",
        "expires": "이 링크는 {expires}까지 유효합니다",
        "ask_label": "언제 만나고 싶으신가요?",
        "ask_placeholder": "예: 다음 주 수요일 15:00 이후",
        "send": "도우미에게 보내기",
        "ready": "확정됨: {title}",
        "ics_button": "{format} 캘린더 초대 내려받기",
        "error": "이 예약 링크를 사용할 수 없습니다: {reason}",
        "lang_label": "인터페이스 언어",
        "privacy": "상대방은 시간 선호만 보고, 연락처 정보는 절대 보지 못합니다.",
        "r_unavailable": "지금은 소유자의 빈 시간을 확인할 수 없어 시간 선호만 기록하며, 시간을 임의로 만들지 않습니다. 잠시 후 다시 시도해 주세요.",
        "r_slots": "빈 시간(다른 일정은 제외한 틈만 표시): {list} 원하는 번호로 답장하세요.",
        "r_proposed": "{slot}을(를) 소유자에게 확인 요청으로 보냈습니다. 승인되면 이곳에서 {format} 초대를 받습니다.",
        "c_title": "방문자 링크의 회의 요청",
        "c_body": "{topic} · {slot} · {duration}분 · 방문자 신원 비식별",
        "c_call": "POPOPX Chat에서 통화(추가 계정 불필요)",
        "c_yes": "확인",
        "c_no": "거절",
        "c_alt": "다른 시간",
    },
    "nl": {
        "title": "Afspraak boeken",
        "brand": "POPOPX Boeking",
        "tagline": "Typ gewoon wanneer het je uitkomt. Geen account, niets te installeren, geen kosten.",
        "promise": "Geen account · Geen installatie · Geen kosten",
        "steps": "1 Geef je tijd · 2 Eigenaar bevestigt · 3 Download de uitnodiging",
        "expires": "Deze link is geldig tot {expires}",
        "ask_label": "Wanneer wil je afspreken?",
        "ask_placeholder": "Bijvoorbeeld: volgende woensdag na 15:00",
        "send": "Versturen naar de assistent",
        "ready": "Bevestigd: {title}",
        "ics_button": "{format}-uitnodiging downloaden",
        "error": "Deze boekingslink is niet beschikbaar: {reason}",
        "lang_label": "Taal van de interface",
        "privacy": "De andere partij ziet alleen je tijdswens, nooit je contactgegevens.",
        "r_unavailable": "Ik kan de vrije momenten van de eigenaar nu niet opvragen, dus noteer ik alleen je "
        "voorkeur en verzin ik geen tijd. Probeer het zo opnieuw.",
        "r_slots": "Vrije momenten (alleen de gaten, geen andere afspraken): {list} Antwoord met het nummer.",
        "r_proposed": "Ik heb «{slot}» naar de eigenaar gestuurd ter bevestiging. Na goedkeuring krijg je hier "
        "de {format}-uitnodiging.",
        "c_title": "Afspraakverzoek via gastlink",
        "c_body": "{topic} · {slot} · {duration} min · bezoeker gemaskeerd",
        "c_call": "gesprek in POPOPX Chat (geen extra account)",
        "c_yes": "Bevestigen",
        "c_no": "Weigeren",
        "c_alt": "Ander moment",
    },
    "pl": {
        "title": "Zarezerwuj spotkanie",
        "brand": "POPOPX Rezerwacja",
        "tagline": "Po prostu napisz, kiedy ci pasuje. Bez konta, bez instalacji, bez opłat.",
        "promise": "Bez konta · Bez instalacji · Bez opłat",
        "steps": "1 Podaj godzinę · 2 Właściciel potwierdza · 3 Pobierz zaproszenie",
        "expires": "Ten link działa do {expires}",
        "ask_label": "Kiedy chcesz się spotkać?",
        "ask_placeholder": "Na przykład: w przyszłą środę po 15:00",
        "send": "Wyślij do asystenta",
        "ready": "Potwierdzono: {title}",
        "ics_button": "Pobierz zaproszenie {format}",
        "error": "Ten link rezerwacyjny jest niedostępny: {reason}",
        "lang_label": "Język interfejsu",
        "privacy": "Druga strona widzi tylko twoją godzinę, nigdy dane kontaktowe.",
        "r_unavailable": "Teraz nie mogę sprawdzić wolnych terminów właściciela, więc tylko zapisuję twoją "
        "preferencję i nic nie zmyślam. Spróbuj za chwilę.",
        "r_slots": "Wolne okna (tylko przerwy, bez innych wydarzeń): {list} Odpowiedz numerem.",
        "r_proposed": "Wysłałem «{slot}» do potwierdzenia właścicielowi. Po akceptacji dostaniesz tutaj "
        "zaproszenie {format}.",
        "c_title": "Prośba o spotkanie z linku gościa",
        "c_body": "{topic} · {slot} · {duration} min · gość zamaskowany",
        "c_call": "rozmowa w POPOPX Chat (bez dodatkowego konta)",
        "c_yes": "Potwierdź",
        "c_no": "Odrzuć",
        "c_alt": "Inny termin",
    },
    "pt-BR": {
        "title": "Agendar uma reunião",
        "brand": "POPOPX Agendamento",
        "tagline": "Basta escrever o horário que funciona para você. Sem conta, sem instalação, sem taxa.",
        "promise": "Sem conta · Sem instalação · Sem taxa",
        "steps": "1 Informe seu horário · 2 O proprietário confirma · 3 Baixe o convite de agenda",
        "expires": "Este link funciona até {expires}",
        "ask_label": "Quando você gostaria de se encontrar?",
        "ask_placeholder": "Por exemplo: próxima quarta após as 15:00",
        "send": "Enviar ao assistente",
        "ready": "Confirmado: {title}",
        "ics_button": "Baixar o convite de agenda {format}",
        "error": "Este link de agendamento não está disponível: {reason}",
        "lang_label": "Idioma da interface",
        "privacy": "A outra parte vê apenas sua preferência de horário, nunca seus dados de contato.",
        "r_unavailable": "Não consigo consultar os horários livres do proprietário agora, então apenas anoto sua preferência e não invento um horário. Tente novamente em instantes.",
        "r_slots": "Horários livres (apenas as lacunas, sem outros eventos): {list} Responda com o número que preferir.",
        "r_proposed": "Enviei {slot} ao proprietário para confirmação. Assim que for aprovado, você recebe um convite {format} aqui mesmo.",
        "c_title": "Pedido de reunião de um link de visitante",
        "c_body": "{topic} · {slot} · {duration} min · identidade do visitante mascarada",
        "c_call": "chamada no POPOPX Chat (sem conta adicional)",
        "c_yes": "Confirmar",
        "c_no": "Recusar",
        "c_alt": "Outro horário",
    },
    "ru": {
        "title": "Записаться на встречу",
        "brand": "POPOPX Запись",
        "tagline": "Просто напишите удобное время. Без аккаунта, без установки, без оплаты.",
        "promise": "Без аккаунта · Без установки · Без оплаты",
        "steps": "1 Укажите время · 2 Владелец подтвердит · 3 Скачайте приглашение",
        "expires": "Ссылка действует до {expires}",
        "ask_label": "Когда вам удобно встретиться?",
        "ask_placeholder": "Например: в следующую среду после 15:00",
        "send": "Отправить ассистенту",
        "ready": "Подтверждено: {title}",
        "ics_button": "Скачать приглашение {format}",
        "error": "Эта ссылка недоступна: {reason}",
        "lang_label": "Язык интерфейса",
        "privacy": "Собеседник видит только желаемое время, но не ваши контакты.",
        "r_unavailable": "Сейчас я не могу проверить свободные окна владельца, поэтому только записываю вашу "
        "просьбу и не выдумываю время. Попробуйте чуть позже.",
        "r_slots": "Свободные окна (только промежутки, без остальных событий): {list} Ответьте номером.",
        "r_proposed": "Отправил «{slot}» владельцу на подтверждение. После одобрения вы получите здесь "
        "приглашение {format}.",
        "c_title": "Запрос на встречу по гостевой ссылке",
        "c_body": "{topic} · {slot} · {duration} мин · посетитель скрыт",
        "c_call": "звонок в POPOPX Chat (без дополнительного аккаунта)",
        "c_yes": "Подтвердить",
        "c_no": "Отклонить",
        "c_alt": "Другое время",
    },
    "th": {
        "title": "จองเวลาพบปะ",
        "brand": "POPOPX การจอง",
        "tagline": "เพียงพิมพ์เวลาที่คุณสะดวก ไม่ต้องมีบัญชี ไม่ต้องติดตั้ง และไม่เสียค่าใช้จ่าย",
        "promise": "ไม่มีบัญชี · ไม่ต้องติดตั้ง · ไม่มีค่าใช้จ่าย",
        "steps": "1 บอกเวลา · 2 เจ้าของยืนยัน · 3 ดาวน์โหลดคำเชิญ",
        "expires": "ลิงก์นี้ใช้ได้ถึง {expires}",
        "ask_label": "ต้องการพบเวลาใด",
        "ask_placeholder": "เช่น พุธหน้าหลัง 15:00",
        "send": "ส่งถึงผู้ช่วย",
        "ready": "ยืนยันแล้ว: {title}",
        "ics_button": "ดาวน์โหลดคำเชิญ {format}",
        "error": "ใช้ลิงก์จองนี้ไม่ได้: {reason}",
        "lang_label": "ภาษาของส่วนติดต่อ",
        "privacy": "อีกฝ่ายเห็นเฉพาะเวลาที่คุณสะดวก ไม่เห็นข้อมูลติดต่อของคุณ",
        "r_unavailable": "ขณะนี้ตรวจสอบช่วงเวลาที่ว่างของเจ้าของไม่ได้ จึงบันทึกความประสงค์ของคุณไว้เท่านั้น "
        "และจะไม่แต่งเวลาขึ้นมา กรุณาลองใหม่ภายหลัง",
        "r_slots": "ช่วงเวลาที่ว่าง (แสดงเฉพาะช่องว่าง ไม่แสดงกำหนดการอื่น): {list} ตอบด้วยหมายเลขที่คุณเลือก",
        "r_proposed": "ส่ง «{slot}» ให้เจ้าของยืนยันแล้ว เมื่ออนุมัติแล้วคุณจะได้รับคำเชิญ {format} ที่นี่",
        "c_title": "คำขอนัดพบจากลิงก์ผู้มาเยือน",
        "c_body": "{topic} · {slot} · {duration} นาที · ปิดบังตัวตนผู้มาเยือน",
        "c_call": "โทรใน POPOPX Chat (ไม่ต้องมีบัญชีเพิ่ม)",
        "c_yes": "ยืนยัน",
        "c_no": "ปฏิเสธ",
        "c_alt": "เวลาอื่น",
    },
    "tr": {
        "title": "Görüşme planlayın",
        "brand": "POPOPX Randevu",
        "tagline": "Yalnızca uygun saatinizi yazın. Hesap yok, kurulum yok, ücret yok.",
        "promise": "Hesap yok · Kurulum yok · Ücret yok",
        "steps": "1 Saatinizi belirtin · 2 Sahibi onaylar · 3 Daveti indirin",
        "expires": "Bu bağlantının geçerlilik sonu: {expires}",
        "ask_label": "Ne zaman görüşmek istersiniz?",
        "ask_placeholder": "Örneğin: gelecek çarşamba 15:00 sonrası",
        "send": "Asistana gönder",
        "ready": "Onaylandı: {title}",
        "ics_button": "{format} davetini indir",
        "error": "Bu randevu bağlantısı kullanılamıyor: {reason}",
        "lang_label": "Arayüz dili",
        "privacy": "Karşı taraf yalnızca saat tercihinizi görür, iletişim bilgilerinizi görmez.",
        "r_unavailable": "Sahibinin boş zamanlarını şu anda denetleyemiyorum; bu yüzden yalnızca isteğinizi "
        "not alıyorum, saat uydurmuyorum. Birazdan yeniden deneyin.",
        "r_slots": "Boş zaman aralıkları (yalnız boşluklar, başka etkinlik yok): {list} Tercih ettiğiniz "
        "numara ile yanıtlayın.",
        "r_proposed": "Onay için sahibine «{slot}» gönderdim. Onaylandığında {format} davetini burada alırsınız.",
        "c_title": "Misafir bağlantısından görüşme isteği",
        "c_body": "{topic} · {slot} · {duration} dk · ziyaretçi gizlendi",
        "c_call": "POPOPX Chat içinde arama (ek hesap yok)",
        "c_yes": "Onayla",
        "c_no": "Reddet",
        "c_alt": "Başka zaman",
    },
    "uk": {
        "title": "Запис на зустріч",
        "brand": "POPOPX Запис",
        "tagline": "Просто напишіть зручний час. Без акаунта, без встановлення, без оплати.",
        "promise": "Без акаунта · Без встановлення · Без оплати",
        "steps": "1 Вкажіть час · 2 Власник підтвердить · 3 Завантажте запрошення",
        "expires": "Посилання дійсне до {expires}",
        "ask_label": "Коли вам зручно зустрітися?",
        "ask_placeholder": "Наприклад: наступної середи після 15:00",
        "send": "Надіслати асистенту",
        "ready": "Підтверджено: {title}",
        "ics_button": "Завантажити запрошення {format}",
        "error": "Це посилання недоступне: {reason}",
        "lang_label": "Мова інтерфейсу",
        "privacy": "Співрозмовник бачить лише бажаний час, а не ваші контакти.",
        "r_unavailable": "Зараз я не можу перевірити вільні вікна власника, тому лише записую ваше бажання "
        "і не вигадаю часу. Спробуйте трохи згодом.",
        "r_slots": "Вільні проміжки (лише прогалини, без інших подій): {list} Відповійте номером.",
        "r_proposed": "Надіслав «{slot}» власнику на підтвердження. Після схвалення ви отримаєте тут "
        "запрошення {format}.",
        "c_title": "Запит на зустріч із гостьового посилання",
        "c_body": "{topic} · {slot} · {duration} хв · відвідувач прихований",
        "c_call": "розмова в POPOPX Chat (без додаткового акаунта)",
        "c_yes": "Підтвердити",
        "c_no": "Відхилити",
        "c_alt": "Інший час",
    },
}


def page_text(locale: str, key: str, **values: Any) -> str:
    """取一条页面文案；未知语种按 :func:`normalize_locale` 的规则回退到 ``en``。"""
    if key not in PAGE_KEYS:
        raise KeyError(f"页面字典没有键 {key!r}")
    table = PAGE_STRINGS.get(locale) or {}
    text = table.get(key) or PAGE_STRINGS[FALLBACK_LOCALE].get(key) or key
    if values:
        try:
            return text.format(**values)
        except (KeyError, IndexError):
            return text
    return text


def page_parity(locale: str) -> List[str]:
    """*locale* 与 ``en`` 之间的缺键/多键/空文案/占位符漂移清单（空列表即完全一致）。"""
    base = PAGE_STRINGS[FALLBACK_LOCALE]
    table = PAGE_STRINGS.get(locale, {})
    problems: List[str] = []
    for key in PAGE_KEYS:
        if key not in table:
            problems.append(f"{locale}: 缺少键 {key}")
        elif not str(table[key]).strip():
            problems.append(f"{locale}: 键 {key} 为空")
    for key in sorted(set(table) - set(PAGE_KEYS)):
        problems.append(f"{locale}: 多余键 {key}")
    for key, value in base.items():
        want = set(re.findall(r"\{(\w+)\}", value))
        got = set(re.findall(r"\{(\w+)\}", str(table.get(key, ""))))
        if want != got:
            problems.append(f"{locale}: {key} 占位符 {sorted(got)} != {sorted(want)}")
    return problems


_PAGE_CSS = """
:root{--bg:#0b0f16;--panel:#121826;--line:#1f2a3d;--ink:#e7edf7;--dim:#93a1b8;--accent:#4fd1c5;--warn:#f0b429}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue","Noto Sans",sans-serif}
.wrap{max-width:34rem;margin:0 auto;padding:2.25rem 1.15rem 3rem}
.brand{margin:0 0 .2rem;font-size:.8rem;letter-spacing:.09em;text-transform:uppercase;color:var(--accent)}
h1{margin:0 0 .25rem;font-size:1.5rem;line-height:1.3}
h2{margin:0 0 .35rem;font-size:1.05rem}
.tagline{margin:0 0 1rem;color:var(--dim)}
.meta{margin:.2rem 0;color:var(--dim);font-size:.85rem}
.promise{display:flex;flex-wrap:wrap;gap:.4rem;list-style:none;margin:0 0 1.25rem;padding:0;font-size:.8rem}
.promise li{border:1px solid var(--line);border-radius:999px;padding:.2rem .6rem;color:var(--accent)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:.75rem;padding:1rem 1.05rem;margin:0 0 1rem}
.card.error{border-color:#5b2130;background:#1a1015;color:#ffd7de}
.steps{margin:.6rem 0 0;padding:0;color:var(--dim);font-size:.85rem}
ol.thread{list-style:none;margin:0 0 1rem;padding:0;display:grid;gap:.55rem}
li.turn{border-inline-start:3px solid var(--line);padding-block:.1rem;padding-inline-start:.7rem;font-size:.95rem;white-space:pre-wrap;overflow-wrap:anywhere;unicode-bidi:plaintext}
li.turn.visitor{border-inline-start-color:var(--accent)}
li.turn.bot{border-inline-start-color:var(--line)}
li.turn.owner{border-inline-start-color:var(--warn)}
label{display:block;margin:0 0 .35rem;font-size:.9rem;color:var(--dim)}
textarea,select{width:100%;margin:0 0 .75rem;padding:.6rem .7rem;border-radius:.5rem;border:1px solid var(--line);background:#0e1420;color:var(--ink);font:inherit}
textarea{min-height:5.5rem;resize:vertical}
button{font:inherit;border:0;border-radius:.5rem;padding:.65rem 1.05rem;background:var(--accent);color:#04231f;font-weight:600}
footer{margin-top:1.25rem;color:var(--dim);font-size:.8rem}
@media (max-width:22rem){h1{font-size:1.25rem}}
""".strip()

CSS_SOURCE = _PAGE_CSS
CSS_HASH = "sha256-" + base64.b64encode(hashlib.sha256(_PAGE_CSS.encode("utf-8")).digest()).decode("ascii")
CSP_DIRECTIVES: Tuple[str, ...] = (
    "default-src 'self'",
    "script-src 'none'",
    f"style-src '{CSS_HASH}'",
    "img-src 'self'",
    "font-src 'self'",
    "connect-src 'none'",
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
)
CSP_POLICY = "; ".join(CSP_DIRECTIVES)
NOINDEX_META = "noindex, nofollow, noarchive, nosnippet, noimageindex"


def _e(value: Any) -> str:
    """转义后再进 HTML：访客说的话永远只是文本。"""
    return html.escape(_clean(value, MAX_MESSAGE_CHARS * 2), quote=True)


def render_page(
    token_link: Optional[Mapping[str, Any]] = None,
    *,
    locale: str = "",
    error: str = "",
    form: Optional[Mapping[str, Any]] = None,
) -> str:
    """自包含预约页：零外链、零脚本、零 Cookie、零原始令牌。

    *token_link* 就是 :meth:`GuestPortal.resolve` 的返回值（或其任意子集）；``form`` 可以带
    ``action`` / ``nonce``，但 ``action`` 只接受同源相对路径，默认空串表示「POST 回当前 URL」，
    因此页面里根本不会出现任何能被 ``Referer`` 带走的地址。
    """
    data: Dict[str, Any] = dict(token_link or {})
    resolved = normalize_locale(locale) or FALLBACK_LOCALE
    lang_attr = resolved if resolved in LOCALES else FALLBACK_LOCALE
    dir_attr = "rtl" if is_rtl(lang_attr) else "ltr"
    source = (form if isinstance(form, Mapping) else {}) or {}
    action = _relative_action(source.get("action", data.get("action", "")))
    needles = [str(item) for item in (data.get("needles") or []) if str(item)]
    nonce = str(source.get("nonce", data.get("csrf", "")) or "")
    nonce = nonce if re.fullmatch(r"[A-Za-z0-9_-]{8,128}", nonce) else ""
    reason = _clean(error, 180)
    topic = mask_owner(data.get("topic", ""), needles) or page_text(resolved, "title")
    expires_text = _format_moment(data.get("expires_at", 0))
    ready = bool(data.get("ics_ready") or data.get("status") == STATUS_CONFIRMED)
    messages = data.get("messages") if isinstance(data.get("messages"), (list, tuple)) else []

    parts: List[str] = [
        "<!doctype html>",
        f'<html lang="{_e(lang_attr)}" dir="{_e(dir_attr)}">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f'<meta http-equiv="Content-Security-Policy" content="{_e(CSP_POLICY)}">',
        f'<meta name="robots" content="{_e(NOINDEX_META)}">',
        f'<meta http-equiv="X-Robots-Noindex" content="{_e(NOINDEX_META)}">',
        '<meta name="referrer" content="no-referrer">',
        '<meta http-equiv="Referrer-Policy" content="no-referrer">',
        f"<title>{_e(page_text(resolved, 'brand'))} · {_e(topic)}</title>",
        f"<style>{_PAGE_CSS}</style>",
        "</head>",
        "<body>",
        '<main class="wrap">',
        f'<p class="brand">{_e(page_text(resolved, "brand"))}</p>',
        f"<h1>{_e(page_text(resolved, 'title'))}</h1>",
        f'<p class="tagline">{_e(page_text(resolved, "tagline"))}</p>',
        f'<ul class="promise"><li>{_e(page_text(resolved, "promise"))}</li></ul>',
    ]
    if reason:
        parts.append(
            f'<section class="card error"><h2>{_e(page_text(resolved, "error", reason=reason))}</h2></section>'
        )
    parts.append('<section class="card">')
    parts.append(f"<h2>{_e(topic)}</h2>")
    label = mask_owner(data.get("label", ""), needles)
    if label:
        parts.append(f'<p class="meta">{_e(label)}</p>')
    if expires_text:
        parts.append(f'<p class="meta">{_e(page_text(resolved, "expires", expires=expires_text))}</p>')
    if isinstance(data.get("remaining"), int):
        parts.append(
            f'<p class="meta">{_e(str(int(data["remaining"])) + " / " + str(int(data.get("max_uses") or 0)))}</p>'
        )
    parts.append(f'<p class="steps">{_e(page_text(resolved, "steps"))}</p>')
    parts.append("</section>")

    if messages:
        parts.append('<ol class="thread">')
        for item in list(messages)[-40:]:
            if isinstance(item, Mapping):
                role = str(item.get("role", "bot"))
                body = mask_owner(item.get("text", ""), needles)
            else:
                role, body = "bot", mask_owner(item, needles)
            role_attr = role if role in ("visitor", "bot", "owner") else "bot"
            parts.append(f'<li class="turn {_e(role_attr)}">{_e(body)}</li>')
        parts.append("</ol>")

    if ready:
        parts.append(
            '<section class="card"><h2>'
            + _e(page_text(resolved, "ready", title=topic))
            + "</h2>"
            + f'<form method="post" action="{_e(action)}" accept-charset="utf-8" referrerpolicy="no-referrer">'
            + (f'<input type="hidden" name="nonce" value="{_e(nonce)}">' if nonce else "")
            + '<button type="submit" name="__op" value="ics">'
            + _e(page_text(resolved, "ics_button", format=ICS_FORMAT_LABEL))
            + "</button></form></section>"
        )

    options = "".join(
        f'<option value="{_e(code)}"{" selected" if code == lang_attr else ""}>'
        f"{_e(LOCALE_LABELS.get(code, code))}</option>"
        for code in LOCALES
    )
    parts.append(
        f'<form class="card" method="post" action="{_e(action)}" accept-charset="utf-8" referrerpolicy="no-referrer">'
    )
    if nonce:
        parts.append(f'<input type="hidden" name="nonce" value="{_e(nonce)}">')
    parts.append(f'<label for="ppx-ask">{_e(page_text(resolved, "ask_label"))}</label>')
    parts.append(
        f'<textarea id="ppx-ask" name="message" rows="4" maxlength="{MAX_MESSAGE_CHARS}" required dir="auto" '
        f'placeholder="{_e(page_text(resolved, "ask_placeholder"))}"></textarea>'
    )
    parts.append(f'<label for="ppx-lang">{_e(page_text(resolved, "lang_label"))}</label>')
    parts.append(f'<select id="ppx-lang" name="locale">{options}</select>')
    parts.append(
        f'<button type="submit" name="__op" value="message">{_e(page_text(resolved, "send"))}</button>'
    )
    parts.append("</form>")
    parts.append(f'<footer>{_e(page_text(resolved, "privacy"))}</footer>')
    parts.append("</main></body></html>")
    return "\n".join(parts)


def _format_moment(value: Any) -> str:
    try:
        moment = float(value or 0)
    except (TypeError, ValueError):
        return ""
    if moment <= 0:
        return ""
    return datetime.fromtimestamp(moment, fixed_tz.utc).strftime("%Y-%m-%d %H:%M UTC")


# --------------------------------------------------------------------------- 门户

Availability = Callable[[str, str, str], Any]
Responder = Callable[[str, str, Dict[str, Any]], Any]
CardPusher = Callable[[str, Dict[str, Any]], Any]


@dataclass
class GuestPortal:
    """访客一次性链接的铸造、校验、对话与日历邀请导出。

    ``availability`` / ``responder`` / ``card_pusher`` 都是注入点（同步或异步可调用对象皆可），
    因此本模块既不 import A2A 也不 import Mac Node，自检里也不需要任何网络或子进程。
    """

    db: Database
    settings: Settings
    availability: Optional[Availability] = dc_field(default=None, kw_only=True)
    responder: Optional[Responder] = dc_field(default=None, kw_only=True)
    card_pusher: Optional[CardPusher] = dc_field(default=None, kw_only=True)
    clock: Callable[[], float] = dc_field(default=time.time, kw_only=True)
    now: Optional[Callable[[], float]] = dc_field(default=None, kw_only=True)

    def __post_init__(self) -> None:
        if not callable(self.clock):
            self.clock = time.time
        if callable(self.now):
            self.clock = self.now
        self._claims = _ClaimLedger()
        self._limiter = _RateLimiter()
        self._sessions = _Sessions()
        self._audit_failures: List[str] = []
        self._owner_cache: Dict[str, List[str]] = {}

    # ----------------------------------------------------------- 基础设施
    def _ts(self) -> float:
        return float(self.clock())

    async def _io(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """SQLite 驱动是同步的，放线程池里跑：两个并发 ``resolve`` 因此真的会交错。

        这正是 :class:`_ClaimLedger` 存在的理由 —— 只有真会交错，防重放才有意义。
        """
        return await asyncio.to_thread(fn, *args, **kwargs)

    def _secret(self) -> str:
        secret = str(self.settings.ensure_guest_secret() or "")
        if not secret:
            raise GuestError("unavailable", "guest 密钥为空")
        return secret

    def _enabled(self) -> None:
        if not bool(getattr(self.settings, "guest_enabled", True)):
            raise GuestError("disabled", "GUEST_ENABLED=0")

    def _audit(
        self,
        event: str,
        *,
        bot_id: str = "",
        link_id: str = "",
        proposal_id: str = "",
        detail: str = "",
        level: str = "info",
        data: Optional[Dict[str, Any]] = None,
        stage: str = "guest",
    ) -> None:
        try:
            self.db.log_negotiation(
                stage,
                event,
                bot_id=bot_id,
                level=level,
                proposal_id=proposal_id,
                link_id=link_id,
                detail=_clean(detail, 400),
                data=dict(data or {}),
            )
        except (LedgerError, ValueError) as exc:
            # 审计写失败不改变访客判定，但原因必须留在内存里可被自检/日志看到。
            note = f"guest 审计写入失败 {event}: {type(exc).__name__}: {exc}"
            if len(self._audit_failures) < 64:
                self._audit_failures.append(note)

    def _owner_secrets(self, bot_id: str) -> List[str]:
        """主人侧绝不能出现在访客输出里的字符串（地址、真名、永久链接、Bot 令牌、邮箱）。"""
        if bot_id in self._owner_cache:
            return list(self._owner_cache[bot_id])
        needles: List[str] = []
        try:
            bot = self.db.get_bot(bot_id) or {}
        except (LedgerError, ValueError) as exc:
            self._audit(
                "owner_lookup_failed",
                bot_id=bot_id,
                level="warn",
                detail=f"{type(exc).__name__}: {exc}",
            )
            bot = {}
        for key in ("contact_address", "permanent_link", "display_name", "name", "bot_token"):
            value = str(bot.get(key, "") or "")
            if value:
                needles.append(value)
            if "@" in value:
                local = value.split("@")[0]
                if len(local) >= 3:
                    needles.append(local)
        self._owner_cache[bot_id] = needles
        return list(needles)

    def _bot_locale(self, bot_id: str) -> str:
        try:
            bot = self.db.get_bot(bot_id) or {}
        except (LedgerError, ValueError):
            bot = {}
        return (
            normalize_locale(str(bot.get("default_locale", "") or ""))
            or normalize_locale(str(self.settings.default_locale or ""))
            or FALLBACK_LOCALE
        )

    # -------------------------------------------------------- 对外地址构造
    def _validated_base(self, raw: str, *, allow_path: bool) -> str:
        """只接受回环 http(s)，或带主机名的 https —— 一次性令牌绝不该走明文公网 HTTP。"""
        candidate = str(raw or "").strip()
        if candidate and is_loopback_http_url(candidate):
            return candidate.rstrip("/")
        parts = urlsplit(candidate)
        host = parts.hostname or ""
        path = parts.path or ""
        if (
            parts.scheme.lower() == "https"
            and host
            and not parts.username
            and not parts.password
            and not parts.query
            and not parts.fragment
            and (allow_path or path in ("", "/"))
        ):
            return candidate.rstrip("/")
        raise GuestError(
            "unavailable",
            f"{candidate!r} 被拒绝：明文 http 只允许回环地址，对外必须 https 且不带凭据/查询串"
            + ("" if allow_path else "，且不能带路径（预约路径由本模块拼接）"),
        )

    def public_base(self) -> str:
        """访客可见的站点前缀：``guest_public_base`` 优先，否则 ``http://<host>:<port>``。"""
        raw = str(getattr(self.settings, "guest_public_base", "") or "").strip()
        if raw:
            return self._validated_base(raw, allow_path=False)
        host = str(self.settings.host or DEFAULT_HOST).strip() or DEFAULT_HOST
        if "://" in host or "/" in host or host.startswith("."):
            raise GuestError("unavailable", f"STUDIO_HOST={host!r} 不能用作访客地址")
        if ":" in host and not host.startswith("["):
            host = "[%s]" % host
        try:
            port = int(self.settings.port)
        except (TypeError, ValueError) as exc:
            raise GuestError("unavailable", f"STUDIO_PORT={self.settings.port!r} 非法") from exc
        if not 1 <= port <= 65535:
            raise GuestError("unavailable", f"STUDIO_PORT={port} 超出合法端口范围")
        return f"http://{host}:{port}"

    def booking_url(self, token: str) -> str:
        return self.public_base() + LINK_PATH_PREFIX + str(token or "")[:1024]

    # ----------------------------------------------------------------- 铸造
    async def issue(
        self,
        bot_id: str,
        *,
        ttl_hours: Optional[float] = None,
        max_uses: int = 1,
        duration_minutes: Optional[int] = None,
        topic: str = "",
        label: str = "",
        timezone: str = "",
        created_by: str = "",
    ) -> Dict[str, Any]:
        """铸造一条预约链接；返回的 ``token`` 是唯一凭据，不再往别处复制。"""
        self._enabled()
        bot_id = _clean(bot_id, 64)
        if not bot_id:
            raise GuestError("malformed", "缺少 bot_id")
        try:
            bot = await self._io(self.db.get_bot, bot_id)
        except (LedgerError, ValueError) as exc:
            raise GuestError("unavailable", f"账本读取失败：{type(exc).__name__}") from exc
        if not bot:
            raise GuestError("unavailable", f"Bot {bot_id} 不存在")

        try:
            uses = int(max_uses)
        except (TypeError, ValueError) as exc:
            raise GuestError("malformed", f"max_uses={max_uses!r} 非法") from exc
        if not 1 <= uses <= 1000:
            raise GuestError("malformed", "max_uses 必须在 1–1000 之间")

        if ttl_hours is None:
            ttl = float(
                getattr(self.settings, "guest_default_ttl_hours", DEFAULT_ISSUE_TTL_HOURS) or DEFAULT_ISSUE_TTL_HOURS
            )
        else:
            try:
                ttl = float(ttl_hours)
            except (TypeError, ValueError) as exc:
                raise GuestError("malformed", f"ttl_hours={ttl_hours!r} 非法") from exc
        if not 0 < ttl <= MAX_TTL_HOURS:
            raise GuestError("malformed", f"ttl_hours={ttl} 超出 0–{MAX_TTL_HOURS}")

        duration = int(duration_minutes) if duration_minutes else DEFAULT_SLOT_MINUTES
        if not MIN_DURATION_MINUTES <= duration <= MAX_DURATION_MINUTES:
            raise GuestError(
                "malformed", f"duration_minutes={duration} 超出 {MIN_DURATION_MINUTES}–{MAX_DURATION_MINUTES}"
            )

        zone_name = str(timezone or "").strip()
        if zone_name and resolve_zone(zone_name) is fixed_tz.utc and zone_name not in {"UTC", "Etc/UTC", "GMT", "Z"}:
            raise GuestError("malformed", f"无法解析时区 {zone_name!r}")

        base = self.public_base()  # 先校验前缀，避免铸出一个 URL 已经坏掉的链接
        moment = self._ts()
        link_id = new_guest_link_id()
        expires_at = moment + ttl * 3600.0
        if expires_at <= moment + MIN_ISSUE_TTL_SECONDS:
            # 令牌里的 exp 是秒精度整数：太短的 TTL 会被截成「还没到期」，不如直接拒绝。
            raise GuestError("malformed", f"ttl_hours={ttl:g} 太短，至少 {MIN_ISSUE_TTL_SECONDS / 3600:.4f} 小时")
        token = sign_token(
            self._secret(),
            {
                "v": TOKEN_VERSION,
                "lid": link_id,
                "iat": int(moment),
                "exp": int(expires_at),
                "mus": uses,
                "dur": duration,
            },
        )
        try:
            row = await self._io(
                self.db.create_guest_link,
                bot_id,
                token,
                link_id=link_id,
                label=_clean(label, MAX_LABEL_CHARS),
                topic=_clean(topic, MAX_TOPIC_CHARS),
                max_uses=uses,
                duration_minutes=duration,
                timezone=zone_name,
                expires_at=expires_at,
                created_by=_clean(created_by, 64),
            )
        except LedgerError as exc:
            raise GuestError("unavailable", f"访客链接落库失败：{exc}") from exc
        self._audit(
            "issued",
            bot_id=bot_id,
            link_id=row["link_id"],
            detail=f"ttl={ttl:g}h uses={uses} dur={duration}",
            data={"expires_at": expires_at},
        )
        return {
            "link_id": row["link_id"],
            "token": token,
            "url": base + LINK_PATH_PREFIX + token,
            "expires_at": float(row["expires_at"]),
            "max_uses": int(row["max_uses"]),
            "duration_minutes": int(row["duration_minutes"]),
        }

    # ----------------------------------------------------------------- 校验
    async def _authorize(
        self,
        token: str,
        *,
        consume: bool,
        visitor_hash: str = "",
        headers: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
        """「签名 → 过期/撤销 → 预算 → 领取」，任何一步失败都抛 :class:`GuestError`。

        返回 ``(令牌负载, 链接行, 访客指纹)``。``consume=True`` 是访客**打开页面**：那一下才是
        被 ``max_uses`` 计数的访问；``consume=False``（发言、取 .ics）只在同一段会话内被接受，
        预算用尽后换个人接不上话（见 :class:`_Sessions`）。
        """
        self._enabled()
        payload = verify_token(self._secret(), token)
        link_id = str(payload["lid"])
        try:
            row = await self._io(self.db.get_guest_link, link_id)
        except (LedgerError, ValueError) as exc:
            raise GuestError("unavailable", f"账本读取失败：{type(exc).__name__}") from exc
        if not row:
            raise GuestError("unknown_token", f"链接 {link_id} 不存在")
        if not hmac.compare_digest(str(row.get("token", "")), str(token)):
            # 签名有效但库里的令牌不是它：令牌被挪用到别的链接，或该行已被换过令牌。
            raise GuestError("unknown_token", "令牌与链接记录不匹配")

        bot_id = str(row.get("bot_id", ""))
        status = str(row.get("status", ""))
        if status == "revoked":
            self._audit("rejected_revoked", bot_id=bot_id, link_id=link_id, level="warn", detail="revoked")
            raise GuestError("revoked", "链接已被撤销")
        if status == "expired":
            raise GuestError("expired", "链接已过期")

        moment = self._ts()
        exp = min(float(payload["exp"]), float(row.get("expires_at") or payload["exp"]))
        if exp <= moment:
            await self._mark_expired()
            self._audit("rejected_expired", bot_id=bot_id, link_id=link_id, level="warn", detail=f"exp={exp:.0f}")
            raise GuestError("expired", "链接已过期")

        budget = min(int(payload["mus"]), max(1, int(row.get("max_uses") or 1)))
        uses = int(row.get("uses") or 0)
        digest, known = self._visitor_identity(visitor_hash, headers, link_id)
        horizon = min(moment + SESSION_WINDOW_SECONDS, exp)
        spent = uses >= budget or status == "exhausted"
        if spent:
            # 「打开页面」才是被预算约束的那一下；同一个访客之后的发言与取 .ics 属于同一段会话。
            # 判定不了是谁（没有任何身份依据）时按凭据本身放行，但换个浏览器/IP 的人接不上话。
            if consume or not await self._same_visitor(link_id, digest, known):
                self._audit(
                    "rejected_exhausted",
                    bot_id=bot_id,
                    link_id=link_id,
                    level="warn",
                    detail=f"{uses}/{budget} known={known}",
                )
                raise GuestError("exhausted", f"已用 {uses}/{budget} 次")
            self._sessions.open(link_id, digest, now=moment, until=horizon)
            return payload, row, digest
        if consume or uses == 0:
            verdict = self._claims.claim(link_id, budget, uses)
            if verdict != "granted":
                self._audit(
                    "rejected_" + verdict,
                    bot_id=bot_id,
                    link_id=link_id,
                    level="warn",
                    detail=f"ledger={self._claims.count(link_id)} db={uses}/{budget}",
                )
                raise GuestError(verdict, "本次访问已被并发领取" if verdict == "replayed" else "访问次数已用尽")
            try:
                updated = await self._io(self.db.record_guest_use, link_id, visitor_hash=digest)
            except (LedgerError, ValueError) as exc:
                self._claims.release(link_id)
                raise GuestError("unavailable", f"访问计数失败：{type(exc).__name__}") from exc
            if not updated:
                self._claims.release(link_id)
                raise GuestError("unknown_token", "链接记录已消失")
            row = updated
        self._sessions.open(link_id, digest, now=moment, until=horizon)
        return payload, row, digest

    async def _same_visitor(self, link_id: str, digest: str, known: bool) -> bool:
        """会话延续判定：进程内的登记表优先，账本里的访客消息作为重启后的兜底。"""
        if not known:
            return True
        if self._sessions.live(link_id, digest, self._ts()):
            return True
        try:
            rows = await self._io(self.db.list_guest_messages, link_id, limit=MESSAGE_VIEW_LIMIT)
        except (LedgerError, ValueError) as exc:
            self._audit(
                "session_evidence_failed",
                link_id=link_id,
                level="warn",
                detail=f"{type(exc).__name__}",
            )
            return False
        seen = {str(row.get("visitor_hash") or "") for row in rows}
        return digest in seen or not any(seen)

    async def _mark_expired(self) -> None:
        try:
            await self._io(self.db.mark_guest_links_expired, now=self._ts())
        except (LedgerError, TypeError, ValueError):
            return  # 维护性写操作失败不影响判定：是否过期是按 expires_at 现算的

    # --------------------------------------------------------------- 入口页
    async def resolve(
        self,
        token: str,
        *,
        visitor_hash: str = "",
        headers: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """访客打开 ``/book/<token>``：校验并原子地记一次访问，返回脱敏视图 + 页面 nonce。

        ``headers`` 只用于算访客指纹（最后一跳 IP + User-Agent 的 HMAC），原始值一律不留存；
        路由层把它原样传进来，后续 ``message`` / ``ics`` 才能认出「还是同一个人」。
        """
        payload, row, _digest = await self._authorize(
            token, consume=True, visitor_hash=visitor_hash, headers=headers
        )
        view = self._display(row)
        view["csrf"] = secrets.token_urlsafe(NONCE_BYTES)
        view["action"] = ""
        view["duration_minutes"] = min(int(payload["dur"]), int(row.get("duration_minutes") or payload["dur"]))
        view["messages"] = await self._io(self.db.list_guest_messages, view["link_id"], limit=MESSAGE_VIEW_LIMIT)
        view["confirmed"] = await self._is_confirmed(row)
        view["ics_ready"] = view["confirmed"]
        self._audit(
            "visited",
            bot_id=view["bot_id"],
            link_id=view["link_id"],
            detail=f"{view['uses']}/{view['max_uses']}",
        )
        return view

    def _display(self, row: Mapping[str, Any]) -> Dict[str, Any]:
        """脱敏视图：令牌永远只暴露前 8 个字符，主人写的主题也过一遍身份掩码。"""
        bot_id = str(row.get("bot_id", ""))
        max_uses = int(row.get("max_uses") or 1)
        uses = int(row.get("uses") or 0)
        needles = self._owner_secrets(bot_id)
        return {
            "link_id": str(row.get("link_id", "")),
            "bot_id": bot_id,
            "token_mask": token_mask(str(row.get("token", ""))),
            "label": mask_owner(row.get("label", ""), needles),
            "topic": mask_owner(row.get("topic", ""), needles),
            "status": str(row.get("status", "")),
            "max_uses": max_uses,
            "uses": uses,
            "remaining": max(0, max_uses - uses),
            "duration_minutes": int(row.get("duration_minutes") or DEFAULT_SLOT_MINUTES),
            "timezone": str(row.get("timezone", "") or ""),
            "proposal_id": str(row.get("proposal_id", "") or ""),
            "created_at": float(row.get("created_at") or 0),
            "created_by": mask_owner(row.get("created_by", ""), needles),
            "expires_at": float(row.get("expires_at") or 0),
            "last_used_at": float(row.get("last_used_at") or 0),
            "revoked_at": float(row.get("revoked_at") or 0),
        }

    async def _is_confirmed(self, row: Mapping[str, Any]) -> bool:
        proposal_id = str(row.get("proposal_id", "") or "")
        if not proposal_id:
            return False
        try:
            proposal = await self._io(self.db.get_proposal, proposal_id)
        except (LedgerError, ValueError) as exc:
            self._audit(
                "proposal_lookup_failed",
                bot_id=str(row.get("bot_id", "")),
                link_id=str(row.get("link_id", "")),
                proposal_id=proposal_id,
                level="warn",
                detail=type(exc).__name__,
            )
            return False
        if not proposal or proposal.get("status") != "approved":
            return False
        return float(proposal.get("end_ts") or 0) > float(proposal.get("start_ts") or 0) > 0

    # ----------------------------------------------------------------- 对话
    async def message(
        self,
        token: str,
        text: str,
        *,
        visitor_hash: str = "",
        headers: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """访客说时间偏好 → 取脱敏空档 → 收敛后建 ``pending`` 提案并把卡片推给主人。"""
        clean = _clean(text, MAX_MESSAGE_CHARS)
        if not clean:
            raise GuestError("malformed", "消息为空")
        if len(str(text)) > MAX_MESSAGE_CHARS * 2:
            raise GuestError("malformed", f"消息超过 {MAX_MESSAGE_CHARS} 字符")
        _, row, vhash = await self._authorize(
            token, consume=False, visitor_hash=visitor_hash, headers=headers
        )
        bot_id = str(row["bot_id"])
        link_id = str(row["link_id"])
        retry_after = self._limiter.hit(f"{link_id}|{vhash}", self._ts())
        if retry_after:
            self._audit(
                "rate_limited",
                bot_id=bot_id,
                link_id=link_id,
                level="warn",
                detail=f"retry={retry_after:.1f}s",
            )
            raise GuestError("rate_limited", f"请稍后 {int(retry_after) + 1} 秒再发送")

        locale = self._locale_from(headers, bot_id)
        needles = self._owner_secrets(bot_id)
        duration = int(row.get("duration_minutes") or DEFAULT_SLOT_MINUTES)
        zone_name = str(row.get("timezone") or "") or "UTC"

        try:
            await self._io(
                self.db.append_guest_message,
                bot_id,
                link_id,
                "visitor",
                clean,
                proposal_id="",
                status="ok",
                visitor_hash=vhash,
            )
        except (LedgerError, ValueError) as exc:
            raise GuestError("unavailable", f"访客消息写入失败：{type(exc).__name__}") from exc

        slots, how = await self._free_slots(bot_id, clean, zone_name, duration)
        chosen: Optional[FreeSlot] = None
        if slots:
            picked, how = _match_slot(clean, slots, duration_minutes=duration)
            chosen = picked[0] if len(picked) == 1 else None

        proposal_id = ""
        pushed = False
        if not slots:
            status = STATUS_UNAVAILABLE
            reply = page_text(locale, "r_unavailable")
        elif chosen is None:
            status = STATUS_OPEN
            reply = page_text(locale, "r_slots", list=_slot_list(slots, duration))
        else:
            status = STATUS_PROPOSED
            proposal_id, reply, pushed = await self._propose(row, chosen, vhash, locale, needles)
            if not pushed:
                status = STATUS_UNAVAILABLE

        reply = self._polish_reply(reply, bot_id, clean, status, locale, row, slots, needles)
        reply = mask_owner(reply, needles)[:MAX_REPLY_CHARS]
        try:
            await self._io(
                self.db.append_guest_message,
                bot_id,
                link_id,
                "bot",
                reply,
                proposal_id=proposal_id,
                status="ok" if status != STATUS_UNAVAILABLE else "skipped",
                visitor_hash=vhash,
            )
        except (LedgerError, ValueError) as exc:
            self._audit(
                "bot_message_failed",
                bot_id=bot_id,
                link_id=link_id,
                proposal_id=proposal_id,
                level="error",
                detail=type(exc).__name__,
            )
        self._audit(
            "turn",
            bot_id=bot_id,
            link_id=link_id,
            proposal_id=proposal_id,
            level="warn" if status == STATUS_UNAVAILABLE else "info",
            detail=f"{status}/{how}",
            data={"slots": len(slots), "locale": locale},
        )
        return {
            "reply": reply,
            "proposal_id": proposal_id,
            "status": status,
            "expires_at": float(row.get("expires_at") or 0),
        }

    async def _free_slots(
        self,
        bot_id: str,
        text: str,
        zone_name: str,
        duration: int,
    ) -> Tuple[List[FreeSlot], str]:
        """向注入的空档来源要脱敏时段；拿不到就诚实返回空列表，绝不编造。"""
        if self.availability is None:
            return [], "no_source"
        try:
            raw = self.availability(bot_id, text, zone_name)
            if inspect.isawaitable(raw):
                raw = await raw
        except Exception as exc:  # noqa: BLE001 - 上游任何异常都必须降级成「暂时无法确认空档」
            self._audit(
                "availability_error",
                bot_id=bot_id,
                level="warn",
                detail=f"{type(exc).__name__}: {str(exc)[:180]}",
            )
            return [], f"raised:{type(exc).__name__}"
        slots = normalise_slots(raw, timezone=zone_name, duration_minutes=duration, now=self._ts())
        return (slots, "") if slots else ([], "empty")

    async def _propose(
        self,
        row: Mapping[str, Any],
        slot: FreeSlot,
        visitor_hash: str,
        locale: str,
        needles: Sequence[str],
    ) -> Tuple[str, str, bool]:
        """建提案 → 造 ECO 卡片 → 绑定链接 → 推给主人，返回 ``(proposal_id, 访客文案, 已送达)``。"""
        bot_id = str(row["bot_id"])
        link_id = str(row["link_id"])
        minutes = min(int(row.get("duration_minutes") or slot.minutes), slot.minutes) or slot.minutes
        owner_locale = self._bot_locale(bot_id)
        topic = mask_owner(row.get("topic", ""), needles) or page_text(owner_locale, "title")
        ttl = max(
            CARD_TTL_FLOOR_SECONDS,
            min(CARD_TTL_SECONDS, float(row.get("expires_at") or 0) - self._ts()),
        )
        start_ts = slot.start_ts
        end_ts = min(slot.end_ts, slot.start_ts + max(MIN_DURATION_MINUTES, int(minutes)) * 60.0)
        try:
            proposal = await self._io(
                self.db.create_proposal,
                bot_id,
                "create",
                source="guest",
                timezone=slot.zone,
                start_ts=start_ts,
                end_ts=end_ts,
                duration_minutes=int(minutes),
                summary=_clean(topic, MAX_TOPIC_CHARS),
                link_id=link_id,
                counterparty="guest+" + str(visitor_hash)[:VISITOR_REF_CHARS],
                payload={
                    "source": "guest",
                    "link_id": link_id,
                    "visitor_ref": str(visitor_hash)[:VISITOR_REF_CHARS],
                    "slot": slot.as_dict(),
                    "expires_at": self._ts() + ttl,
                    "masked": True,
                    "locale": locale,
                },
            )
        except LedgerError as exc:
            self._audit("proposal_failed", bot_id=bot_id, link_id=link_id, level="error", detail=str(exc)[:200])
            return "", page_text(locale, "r_unavailable"), False

        proposal_id = str(proposal["proposal_id"])
        body = page_text(
            owner_locale,
            "c_body",
            topic=topic,
            slot=FreeSlot(start_ts, end_ts, slot.zone).wall_clock(int(minutes)),
            duration=int(minutes),
        )
        card_title = _clean(page_text(owner_locale, "c_title"), EcoLimits.card_title_chars)
        try:
            card, frame = confirmation_card(
                proposal_id,
                title=card_title,
                body=_clean(body, EcoLimits.card_body_chars),
                visible_text=card_title,
                ttl_seconds=ttl,
                decline_label=_clean(page_text(owner_locale, "c_no"), EcoLimits.field_label_chars),
                alt_label=_clean(page_text(owner_locale, "c_alt"), EcoLimits.field_label_chars),
                approve_label=_clean(page_text(owner_locale, "c_yes"), EcoLimits.field_label_chars),
            )
            payload = dict(proposal.get("payload") or {})
            payload.update({"card": card, "card_text": frame})
            proposal = await self._io(
                self.db.update_proposal,
                proposal_id,
                card_id=str(card["id"]),
                payload=payload,
            )
            await self._io(self.db.set_link_proposal, link_id, proposal_id)
        except (LedgerError, EcoCardError, ValueError) as exc:
            self._audit(
                "card_build_failed",
                bot_id=bot_id,
                link_id=link_id,
                proposal_id=proposal_id,
                level="error",
                detail=f"{type(exc).__name__}: {str(exc)[:180]}",
            )
            return proposal_id, page_text(locale, "r_unavailable"), False

        pushed = await self._push(bot_id, proposal)
        self._audit(
            "proposal_created",
            bot_id=bot_id,
            link_id=link_id,
            proposal_id=proposal_id,
            level="info" if pushed else "error",
            detail=slot.label(int(minutes)),
            data={"duration": int(minutes), "pushed": pushed},
        )
        if not pushed:
            return proposal_id, page_text(locale, "r_unavailable"), False
        return proposal_id, page_text(locale, "r_proposed", slot=slot.label(int(minutes)), format=ICS_FORMAT_LABEL), True

    async def _push(self, bot_id: str, proposal: Dict[str, Any]) -> bool:
        """推送确认卡片；注入点缺失或抛错都算失败，但原因必须进审计。"""
        if self.card_pusher is None:
            self._audit(
                "card_not_pushed",
                bot_id=bot_id,
                link_id=str(proposal.get("link_id", "")),
                proposal_id=str(proposal.get("proposal_id", "")),
                level="warn",
                detail="card_pusher 未注入",
            )
            return False
        try:
            result = self.card_pusher(bot_id, proposal)
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:  # noqa: BLE001 - 卡片推送失败不能打断访客链路，但必须记原因
            self._audit(
                "card_push_error",
                bot_id=bot_id,
                link_id=str(proposal.get("link_id", "")),
                proposal_id=str(proposal.get("proposal_id", "")),
                level="error",
                detail=f"{type(exc).__name__}: {str(exc)[:180]}",
            )
            return False
        if isinstance(result, tuple):
            return bool(result[0]) if result else True
        return True if result is None else bool(result)

    def _polish_reply(
        self,
        reply: str,
        bot_id: str,
        visitor_text: str,
        status: str,
        locale: str,
        row: Mapping[str, Any],
        slots: Sequence[FreeSlot],
        needles: Sequence[str] = (),
    ) -> str:
        """允许注入 ``responder`` 改写话术；它说错话（抛错、返回协程、返回空）就退回模板。

        大模型写出来的话**必须就地过一遍掩码**再采用：身份兜底是产品承诺，不能指望上游
        自己记得。正因为掩码就在这一步，判定条件只剩「这段话有没有内容」，而不是「这段话
        里有没有出现邮箱」——后者会把一句好文案整段丢掉，访客只能看到模板。
        """
        if self.responder is None:
            return reply
        context = {
            "link_id": str(row.get("link_id", "")),
            "topic": str(row.get("topic", "")),
            "status": status,
            "locale": locale,
            "timezone": str(row.get("timezone", "") or "UTC"),
            "slots": [slot.as_dict() for slot in slots],
            "proposal_id": str(row.get("proposal_id", "") or ""),
            "duration_minutes": int(row.get("duration_minutes") or DEFAULT_SLOT_MINUTES),
        }
        try:
            produced = self.responder(bot_id, visitor_text, context)
            if inspect.isawaitable(produced):
                # 这一步在同步段里，不能 await：保留模板话术，别把访客文案赌在一个协程上。
                produced.close() if inspect.iscoroutine(produced) else None
                return reply
            text = mask_owner(_clean(produced, MAX_REPLY_CHARS), needles)
        except Exception as exc:  # noqa: BLE001 - 话术生成失败退回模板，并记录原因
            self._audit(
                "responder_error",
                bot_id=bot_id,
                link_id=str(row.get("link_id", "")),
                level="warn",
                detail=f"{type(exc).__name__}: {str(exc)[:180]}",
            )
            return reply
        if not text.strip():
            return reply
        return text

    def _locale_from(self, headers: Optional[Mapping[str, Any]], bot_id: str) -> str:
        """页面/话术语种：访客浏览器说的优先，其次显式 ``locale``，最后才是 Bot 的默认语种。

        ``detect_locale`` 在「什么都没匹配上」时会直接给 ``en``，那会把主人设好的语种盖掉，
        所以这里按 q 值自己走一遍，剩下的一律回落到 Bot 配置。
        """
        for tag in parse_accept_language(_header(headers, "accept-language")):
            picked = normalize_locale(tag)
            if picked:
                return picked
        explicit = normalize_locale(_header(headers, "locale"))
        if explicit:
            return explicit
        return self._bot_locale(bot_id)

    def _visitor_identity(
        self, explicit: str, headers: Optional[Mapping[str, Any]], link_id: str
    ) -> Tuple[str, bool]:
        """返回 ``(访客指纹, 是否有判定依据)``；账本里只存摘要，原始 IP / UA 一律不落库。

        指纹是 ``HMAC(secret, link|最后一跳 IP|UA)`` 的前若干字符：同一个浏览器下次再来还是
        同一个值，但拿到链接的另一个人几乎不可能算出同一个值。没有任何依据（既没头也没显式
        指纹）时给一个稳定的「匿名」值并把 ``known`` 置假 —— 判定「是不是同一个人」必须诚实，
        不能把「无从判定」当成「不是同一个人」，也不能反过来。
        """
        given = _clean(explicit, VISITOR_REF_CHARS * 3)
        if re.fullmatch(r"[A-Za-z0-9_.:-]{4,72}", given):
            digest = hmac.new(self._secret().encode("utf-8"), f"visitor|{given}".encode("utf-8"), hashlib.sha256)
            return digest.hexdigest()[:VISITOR_REF_CHARS], True
        ip = _client_ip(headers)
        agent = _header(headers, "user-agent")[:120]
        if not ip and not agent:
            return hashlib.sha256(f"anon|{link_id}".encode("utf-8")).hexdigest()[:VISITOR_REF_CHARS], False
        seed = "|".join([str(link_id), ip, agent])
        digest = hmac.new(self._secret().encode("utf-8"), seed.encode("utf-8"), hashlib.sha256)
        return digest.hexdigest()[:VISITOR_REF_CHARS], True

    # ------------------------------------------------------------- 日历导出
    async def ics(
        self,
        token: str,
        *,
        visitor_hash: str = "",
        headers: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[str, str]:
        """已确认的预约才有 ``.ics``；未确认一律 ``unavailable``（访客不能自己造日程）。"""
        _, row, _digest = await self._authorize(
            token, consume=False, visitor_hash=visitor_hash, headers=headers
        )
        bot_id = str(row["bot_id"])
        link_id = str(row["link_id"])
        proposal_id = str(row.get("proposal_id", "") or "")
        proposal = await self._io(self.db.get_proposal, proposal_id) if proposal_id else None
        if not proposal or proposal.get("status") != "approved":
            self._audit(
                "ics_refused",
                stage="ics",
                bot_id=bot_id,
                link_id=link_id,
                proposal_id=proposal_id,
                level="warn",
                detail="proposal=" + (str(proposal.get("status")) if proposal else "none"),
            )
            raise GuestError("unavailable", "主人尚未确认，日历邀请不可用")
        start_ts = float(proposal.get("start_ts") or 0)
        end_ts = float(proposal.get("end_ts") or 0)
        if start_ts <= 0 or end_ts <= start_ts:
            raise GuestError("unavailable", "提案缺少合法的起止时间")

        needles = self._owner_secrets(bot_id)
        locale = self._bot_locale(bot_id)
        zone_name = str(proposal.get("timezone") or row.get("timezone") or "") or "UTC"
        duration = int(proposal.get("duration_minutes") or round((end_ts - start_ts) / 60.0)) or DEFAULT_SLOT_MINUTES
        topic = mask_owner(row.get("topic", ""), needles) or page_text(locale, "title")
        wall = FreeSlot(start_ts, end_ts, zone_name).wall_clock(duration)
        room = self._meeting_room(link_id, proposal_id, bot_id=bot_id, locale=locale)
        summary = mask_owner(f"{page_text(locale, 'title')} · {topic}", needles)[:MAX_TOPIC_CHARS]
        # 描述里只放「墙上时间 + 这条预约是什么」：privacy 那句是对主人说的，
        # 放进访客的日历邀请会变成反向承诺，所以不进 .ics。
        description = mask_owner("%s\n%s" % (wall, page_text(locale, "c_title")), needles)
        event = {
            "uid": ics.event_uid("popopx-guest", link_id),
            "summary": summary,
            "start_ts": start_ts,
            "end_ts": end_ts,
            "description": description,
            "location": room["location"],
            "url": room["url"],
            "status": "CONFIRMED",
            "sequence": 0,
            "transp": "OPAQUE",
            "categories": ("POPOPX",),
            "dtstamp": self._ts(),
        }
        try:
            text = ics.build_calendar([event], method="PUBLISH", calendar_name=page_text(locale, "brand"))
        except ValueError as exc:
            raise GuestError("unavailable", f"日历生成失败：{exc}") from exc
        filename = ics.ics_filename(summary, start_ts)
        self._audit(
            "ics_ready",
            stage="ics",
            bot_id=bot_id,
            link_id=link_id,
            proposal_id=proposal_id,
            detail=filename,
            data={"room": bool(room["url"]), "start_ts": start_ts, "end_ts": end_ts},
        )
        return filename, text

    def _meeting_room(self, link_id: str, proposal_id: str, *, bot_id: str, locale: str) -> Dict[str, str]:
        """有 ``meeting_base_url`` 就给「HMAC 盲化房间号」，否则退回 POPOPX Chat 通话说明。

        绝不发明域名：基址不合法时按「未配置」处理并记一条 warn —— 访客拿到的是诚实的
        通话说明，而不是一个并不存在的会议地址。
        """
        chat_call = page_text(locale, "c_call")
        raw = str(getattr(self.settings, "meeting_base_url", "") or "").strip()
        if not raw:
            return {"url": "", "location": chat_call}
        try:
            base = self._validated_base(raw, allow_path=True)
        except GuestError as exc:
            self._audit(
                "meeting_base_rejected",
                stage="ics",
                bot_id=bot_id,
                link_id=link_id,
                level="warn",
                detail=exc.detail,
            )
            return {"url": "", "location": chat_call}
        digest = hmac.new(
            self._secret().encode("utf-8"), f"room|{link_id}|{proposal_id}".encode("utf-8"), hashlib.sha256
        ).digest()
        room = _ROOM_PATH_RE.sub("", _b64url_encode(digest))[:MEETING_ROOM_CHARS]
        if MEETING_ROOM_PLACEHOLDER in base:
            url = base.replace(MEETING_ROOM_PLACEHOLDER, room)
        else:
            url = f"{base.rstrip('/')}/{quote(room, safe='')}"
        return {"url": url, "location": chat_call}

    # --------------------------------------------------------------- 管理面
    async def revoke(self, bot_id: str, link_id: str) -> Dict[str, Any]:
        """撤销：库里改状态 + 丢掉进程内领取记录，下一次校验立即被拒。"""
        self._enabled()
        wanted = _clean(bot_id, 64)
        target = _clean(link_id, 64)
        try:
            row = await self._io(self.db.get_guest_link, target)
        except (LedgerError, ValueError) as exc:
            raise GuestError("unavailable", f"账本读取失败：{type(exc).__name__}") from exc
        if not row or (wanted and str(row.get("bot_id", "")) != wanted):
            raise GuestError("unknown_token", f"链接 {target} 不属于 {wanted}")
        try:
            updated = await self._io(self.db.revoke_guest_link, target)
        except LedgerError as exc:
            raise GuestError("unavailable", f"撤销失败：{exc}") from exc
        if not updated:
            raise GuestError("unknown_token", f"链接 {target} 不存在")
        self._claims.forget(target)
        self._sessions.forget(target)
        self._limiter.reset()
        self._audit("revoked", bot_id=wanted, link_id=target, detail="owner revoke")
        return self._display(updated)

    async def link_url(self, bot_id: str, link_id: str) -> Dict[str, Any]:
        """逐条取回完整预约链接：列表里只有掩码，凭据必须一次只换回一条并留下审计。

        访客凭据本身不落进「一次请求给出一整页」的列表响应里 —— 控制台翻页、XHR 记录、
        代理日志都可能长期保留那份文本；要转发就明确点一下，这一条才带出完整令牌。
        """
        self._enabled()
        wanted = _clean(bot_id, 64)
        target = _clean(link_id, 64)
        try:
            row = await self._io(self.db.get_guest_link, target)
        except (LedgerError, ValueError) as exc:
            raise GuestError("unavailable", f"账本读取失败：{type(exc).__name__}") from exc
        if not row or (wanted and str(row.get("bot_id", "")) != wanted):
            raise GuestError("unknown_token", f"链接 {target} 不属于 {wanted}")
        status = str(row.get("status", ""))
        if status == "revoked":
            raise GuestError("revoked", "链接已被撤销")
        if status == "expired" or (0 < float(row.get("expires_at") or 0) <= self._ts()):
            await self._mark_expired()
            raise GuestError("expired", "链接已过期")
        token = str(row.get("token", ""))
        if not token:
            raise GuestError("unavailable", "链接记录里没有令牌")
        view = self._display(row)
        view["confirmed"] = await self._is_confirmed(row)
        view["ics_ready"] = view["confirmed"]
        url = self.public_base() + LINK_PATH_PREFIX + token
        self._audit(
            "url_reveal",
            bot_id=wanted,
            link_id=target,
            detail=f"mask={view['token_mask']}",
            data={"status": status},
        )
        return {**view, "url": url}

    async def links(self, bot_id: Optional[str] = None, *, include_expired: bool = False) -> List[Dict[str, Any]]:
        """列出链接（令牌只显示前 8 个字符）；默认过滤掉已过期。"""
        self._enabled()
        await self._mark_expired()
        wanted = _clean(bot_id or "", 64)
        try:
            rows = await self._io(
                self.db.list_guest_links,
                wanted or None,
                status=None,
                limit=LINKS_PAGE_LIMIT,
            )
        except (LedgerError, ValueError) as exc:
            raise GuestError("unavailable", f"账本读取失败：{type(exc).__name__}") from exc
        moment = self._ts()
        out: List[Dict[str, Any]] = []
        for row in rows:
            view = self._display(row)
            if not include_expired and (view["status"] == "expired" or 0 < view["expires_at"] <= moment):
                continue
            view["confirmed"] = await self._is_confirmed(row)
            view["ics_ready"] = view["confirmed"]
            out.append(view)
        return out

    def render(
        self,
        token_link: Mapping[str, Any],
        *,
        locale: str = "",
        error: str = "",
        form: Optional[Mapping[str, Any]] = None,
    ) -> str:
        """页面渲染入口（与 :func:`render_page` 等价，方便路由层只依赖实例）。

        ``needles`` 在这里现取而不是塞进 :meth:`_display`：路由层如果把视图直接 JSON 序列化回
        访客，也只会拿到脱敏字段，拿不到「掩码用的原始身份串」这份清单本身。
        """
        wanted = normalize_locale(locale) or self._default_locale()
        data: Dict[str, Any] = dict(token_link)
        bot_id = str(data.get("bot_id", "") or "")
        if bot_id:
            data["needles"] = self._owner_secrets(bot_id)
        return render_page(data, locale=wanted, error=error, form=form)

    def _default_locale(self) -> str:
        return normalize_locale(str(getattr(self.settings, "default_locale", "") or "")) or FALLBACK_LOCALE


def _header(headers: Optional[Mapping[str, Any]], name: str) -> str:
    if not headers:
        return ""
    try:
        lowered = {str(key).lower(): value for key, value in headers.items()}
    except (AttributeError, TypeError):
        return ""
    value = lowered.get(str(name).lower(), "")
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    return _clean(value, 300)


def _client_ip(headers: Optional[Mapping[str, Any]]) -> str:
    """XFF 取 **最后一跳**（由我们自己的回环监听追加），退化到 X-Real-IP / peer。"""
    xff = _header(headers, "x-forwarded-for")
    if xff:
        return xff.split(",")[-1].strip()[:64]
    for key in ("x-real-ip", "peer", "client"):
        value = _header(headers, key)
        if value:
            return value[:64]
    return ""


def page(token_link: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> str:
    """模块级别名：路由层 ``HTMLResponse(guest_portal.page(view, locale=...))`` 即可。"""
    return render_page(token_link, **kwargs)


__all__ = [
    "CARD_TTL_SECONDS",
    "CLAIM_LEDGER_MAX",
    "CSP_DIRECTIVES",
    "CSP_POLICY",
    "CSS_HASH",
    "DEFAULT_SLOT_MINUTES",
    "GUEST_ERRORS",
    "ICS_FORMAT_LABEL",
    "LINKS_PAGE_LIMIT",
    "LINK_PATH_PREFIX",
    "MAX_LABEL_CHARS",
    "MAX_MESSAGE_CHARS",
    "MAX_REPLY_CHARS",
    "MAX_TOPIC_CHARS",
    "MEETING_ROOM_PLACEHOLDER",
    "NOINDEX_META",
    "PAGE_KEYS",
    "PAGE_STRINGS",
    "RATE_LIMIT_BURST_MESSAGES",
    "RATE_LIMIT_BURST_SECONDS",
    "RATE_LIMIT_MAX_KEYS",
    "RATE_LIMIT_WINDOW_MESSAGES",
    "RATE_LIMIT_WINDOW_SECONDS",
    "REASONS",
    "STATUS_CONFIRMED",
    "STATUS_OPEN",
    "STATUS_PROPOSED",
    "STATUS_UNAVAILABLE",
    "TOKEN_MASK",
    "TOKEN_MASK_CHARS",
    "TOKEN_PAYLOAD_KEYS",
    "TOKEN_VERSION",
    "FreeSlot",
    "GuestError",
    "GuestPortal",
    "card_text_of",
    "mask_owner",
    "normalise_slots",
    "page",
    "page_parity",
    "page_text",
    "render_page",
    "resolve_zone",
    "sign_token",
    "token_mask",
    "verify_token",
]


def card_text_of(proposal: Optional[Mapping[str, Any]]) -> str:
    """从提案里取出可直接发送的 ``::POPOPX_ECO::`` 帧文本（推送方只需这一行）。"""
    if not proposal:
        return ""
    payload = proposal.get("payload")
    if not isinstance(payload, Mapping):
        return ""
    return str(payload.get("card_text", "") or "")
