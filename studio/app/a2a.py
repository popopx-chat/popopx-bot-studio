"""通道 A：两个 POPOPX 替身机器人在 E2EE SMP 队列上协商会面时间。

产品约束是「**只交换掩码候选时段**」：对端 Bot 永远拿不到主人的完整日历、日程标题、
参会人、地点、备注、文件名。这条约束不能靠约定，只能靠代码结构保证，所以本模块有三道
独立的闸：

1. :func:`mask_slots` 用**白名单投影**重建时段对象（只可能留下 ``start/end/tz/free/ref``），
   上游就算传进来一个 ``title`` 也活不过这一行；
2. :func:`encode_frame` 在签名之前递归检查帧体，出现 :data:`FORBIDDEN_KEYS` 里任何键名
   直接拒绝发送 —— 宁可不发，也不发一条带日程正文的帧；
3. :func:`intersect_slots` 的输入输出都是绝对 epoch，墙上时间只作为**文本**呈现，
   跨时区与夏令时因此不可能算错（见下）。

帧格式：``::POPOPX_A2A::<base64url(json)>.<base64url(hmac-sha256)>``。单个 token、无空白、
无 ``::``，与 ``::CB::`` 上行帧同一套客户端规则（见 :mod:`app.eco_cards`）。签名用**对端
会话密钥**（``key_provider`` 由编排层注入，即 SMP 通道本来就有的 E2EE 密钥），校验一律
:func:`hmac.compare_digest`，并叠上加版本号、时间窗与 nonce 重放防护。这里不再引入新的
信任根：能在 SMP 队列里写出这条队列的，本来就只有已配对的对方。

协商状态机落在 ``a2a_negotiations`` 行上（``open → converged/rejected/expired/aborted``），
每个状态迁移写一条 ``db.log_negotiation("a2a", ...)``，detail 只允许出现 id、计数和原因码。
``converged`` 之后**只产出一条 ``pending`` 提案**，日历一个字节都不写；写日历发生在主人
在 ``::POPOPX_ECO::`` 卡片上点确认、编排层调用
:meth:`app.mac_node_bridge.MacNodeBridge.approve` 之后。

改期：``converged`` 行允许被 :meth:`Negotiator.counter` 显式重开（旧提案置
``superseded``、再起一轮），而 ``expired/rejected/aborted`` 行一律拒绝复活 —— 重开必须是
一次显式动作，不能是收到一帧就悄悄续命。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import (
    Any,
    Awaitable,
    Callable,
    Deque,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .database import Database
from .eco_cards import confirmation_card

A2A_PREFIX = "::POPOPX_A2A::"
A2A_VERSION = 1
FRAME_KINDS = ("offer", "accept", "counter", "confirm", "decline", "sync")

#: 掩码时段允许出现的键（白名单，不是黑名单）。
MASKED_KEYS = ("start", "end", "tz", "free", "ref")
#: 帧体里出现这些键名即拒发。列表本身不是安全边界 —— 边界是 :func:`mask_slots` 的白名单
#: 投影与 :func:`_guard_body` 的递归检查，这里只是把「绝不外传日历正文」写成可读的证据。
FORBIDDEN_KEYS = frozenset(
    {
        "alarm",
        "attendee",
        "attendees",
        "categories",
        "comment",
        "comments",
        "contact",
        "description",
        "email",
        "exdate",
        "file",
        "filename",
        "location",
        "note",
        "notes",
        "organizer",
        "path",
        "phone",
        "rrule",
        "rsvp",
        "sequence",
        "status",
        "subject",
        "summary",
        "title",
        "uid",
        "url",
        "valarm",
        "vcalendar",
        "vevent",
    }
)

MAX_MASKED_SLOTS = 32
MAX_INTERSECTION = 8
MAX_FRAME_CHARS = 4096
DEFAULT_STEP_MINUTES = 30
DEFAULT_FRAME_TTL_SECONDS = 900.0
DEFAULT_CLOCK_SKEW_SECONDS = 120.0
ID_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
#: 与 ``database._ID_RE`` 同形：接下对端起手时，协商号要直接当本机主键用。
_LOCAL_ID_RE = re.compile(r"^[a-z0-9_-]{3,64}$")

#: ``sender(bot_id, peer_identity, text)``：编排层把它接到网关，本模块绝不 import 网关。
Sender = Callable[[str, str, str], Awaitable[Any]]
KeyProvider = Callable[[str], Any]

REASONS = (
    "frame",
    "signature",
    "version",
    "expired",
    "replay",
    "leaky_field",
    "unknown_negotiation",
    "wrong_bot",
    "wrong_peer",
    "closed",
    "not_converged",
    "no_slots",
    "limit",
    "send_failed",
)


class A2AError(ValueError):
    """帧层面的拒绝。``reason`` 取自 :data:`REASONS`，消息里永不含密钥。"""

    def __init__(self, reason: str, detail: str = "") -> None:
        if reason not in REASONS:
            raise ValueError(f"非法 A2A 拒绝原因 {reason!r}，应为 {list(REASONS)}")
        super().__init__(f"[{reason}] {detail}" if detail else f"[{reason}]")
        self.reason = reason
        self.detail = detail


# ------------------------------------------------------------------- 重放防护
class NonceCache:
    """有界的已见 nonce 集合：FIFO 逐出，避免协商久了内存无上限。"""

    def __init__(self, maxlen: int = 4096):
        self.maxlen = max(16, int(maxlen))
        self._seen: Set[str] = set()
        self._order: Deque[str] = deque()

    def __contains__(self, nonce: object) -> bool:
        return str(nonce or "") in self._seen

    def __len__(self) -> int:
        return len(self._seen)

    def add(self, nonce: str) -> None:
        token = str(nonce or "")
        if not token or token in self._seen:
            return
        self._seen.add(token)
        self._order.append(token)
        while len(self._order) > self.maxlen:
            self._seen.discard(self._order.popleft())

    def clear(self) -> None:
        self._seen.clear()
        self._order.clear()


_DEFAULT_NONCES = NonceCache()


# ------------------------------------------------------------------ 掩码与时区
def _opaque(value: Any, *, limit: int = 64) -> str:
    """一个不含空白、不含 ``::``、字符集受限的 token。不合格返回空串。"""
    text = str(value if value is not None else "").strip()
    if not text or len(text) > limit:
        return ""
    if "::" in text or any(ch.isspace() for ch in text):
        return ""
    if any(ch not in ID_CHARS for ch in text):
        return ""
    return text


def _zone(zone_id: str) -> ZoneInfo:
    try:
        return ZoneInfo(str(zone_id or "").strip())
    except (ZoneInfoNotFoundError, ValueError):
        raise A2AError("no_slots", f"时区 {zone_id!r} 不可用") from None


def _pair(raw: Any) -> Optional[Tuple[float, float]]:
    """从一条时段记录里取出 ``(start, end)``；非正或倒挂一律丢。"""
    if isinstance(raw, Mapping):
        start, end = raw.get("start"), raw.get("end")
    elif isinstance(raw, (list, tuple)) and len(raw) == 2:
        start, end = raw[0], raw[1]
    else:
        return None
    try:
        lo, hi = float(start), float(end)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(lo) or not math.isfinite(hi) or lo <= 0 or hi <= lo:
        return None
    return lo, hi


def mask_slots(slots: Iterable[Any], *, timezone: str) -> List[Dict[str, Any]]:
    """把任意来源的时段列表投影成 ``[{start,end,tz,free}]``（可选 ``ref``）。

    白名单投影：输出字典是从零构造的，输入的 ``title``/``attendees``/``location`` 之类的键
    没有代码路径能进入结果 —— 这是「绝不外传完整日历」的结构性保证，而不是约定。
    ``free`` 取记录自身的标记（``busy`` 为真即 ``False``），缺省视为空闲。
    """
    zone = str(timezone or "").strip()
    out: List[Dict[str, Any]] = []
    taken: Set[Tuple[float, float]] = set()
    for raw in slots or ():
        bounds = _pair(raw)
        if bounds is None:
            continue
        start, end = bounds
        if (start, end) in taken:
            continue
        taken.add((start, end))
        flag = raw.get("free") if isinstance(raw, Mapping) else None
        if isinstance(raw, Mapping) and raw.get("busy"):
            flag = False
        item: Dict[str, Any] = {"start": start, "end": end, "tz": zone,
                                "free": bool(flag) if isinstance(flag, bool) else True}
        ref = _opaque(raw.get("ref")) if isinstance(raw, Mapping) else ""
        if ref:
            item["ref"] = ref
        out.append(item)
        if len(out) >= MAX_MASKED_SLOTS:
            break
    out.sort(key=lambda slot: (slot["start"], slot["end"]))
    return out


def free_slots(slots: Iterable[Any]) -> List[Dict[str, Any]]:
    """掩码投影之后只留空闲段：对外发出去的候选永远是 ``free is True``。"""
    return [item for item in slots or () if isinstance(item, Mapping) and item.get("free") is not False]


def free_from_busy(
    busy: Iterable[Any],
    *,
    window: Tuple[float, float],
    timezone: str,
    min_minutes: int = 15,
) -> List[Dict[str, Any]]:
    """由 :meth:`app.mac_node_bridge.MacNodeBridge.availability` 的掩码忙表反推空闲段。

    桥只回 ``{start,end,busy:true}``（不含任何日程内容），这里做窗口裁剪与补集：
    忙闲之间剩下的每一段都是候选，短于 ``min_minutes`` 的碎片丢掉，免得拿 5 分钟空档去约会议。
    """
    lo, hi = float(window[0]), float(window[1])
    if hi <= lo:
        return []
    floor = max(0.0, float(min_minutes) * 60.0)
    gaps: List[Tuple[float, float]] = []
    cursor = lo
    for start, end in _merge(_ranges(busy)):
        if end <= lo:
            continue
        if start >= hi:
            break
        if start > cursor:
            gaps.append((cursor, min(start, hi)))
        cursor = max(cursor, end)
        if cursor >= hi:
            break
    if cursor < hi:
        gaps.append((cursor, hi))
    rows = [{"start": a, "end": b, "tz": str(timezone or ""), "free": True}
            for a, b in gaps if b - a >= floor]
    return rows[:MAX_MASKED_SLOTS]


def wall_text(ts: float, zone_id: str) -> str:
    """epoch 秒 -> ``YYYY-MM-DD HH:MM``（该时区当时的墙上时间）。"""
    return datetime.fromtimestamp(float(ts), _zone(zone_id)).strftime("%Y-%m-%d %H:%M")


def utc_text(ts: float) -> str:
    return datetime.fromtimestamp(float(ts), timezone.utc).strftime("%Y-%m-%d %H:%M")


def _merge(ranges: Sequence[Tuple[float, float]]) -> List[Tuple[float, float]]:
    if not ranges:
        return []
    ordered = sorted((float(lo), float(hi)) for lo, hi in ranges)
    merged: List[List[float]] = [list(ordered[0])]
    for lo, hi in ordered[1:]:
        if lo <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return [(lo, hi) for lo, hi in merged]


def _overlaps(
    left: Sequence[Tuple[float, float]], right: Sequence[Tuple[float, float]]
) -> List[Tuple[float, float]]:
    pairs: List[Tuple[float, float]] = []
    for a_lo, a_hi in left:
        for b_lo, b_hi in right:
            lo, hi = max(a_lo, b_lo), min(a_hi, b_hi)
            if hi > lo:
                pairs.append((lo, hi))
    return _merge(pairs)


def _blocked_hit(start: float, end: float, blocked: Sequence[Tuple[float, float]]) -> bool:
    return any(start < hi and end > lo for lo, hi in blocked)


def _office_fit(hour: float) -> float:
    """以 13:00 为中心的白天贴合度：7 点与 19 点归零，深夜为负数被夹到 0。"""
    return max(0.0, 1.0 - abs(hour - 13.0) / 6.0)


def _local_hours(ts: float, zone: ZoneInfo) -> float:
    local = datetime.fromtimestamp(ts, zone)
    return local.hour + local.minute / 60.0


def _candidate_starts(
    lo: float,
    hi: float,
    zone: ZoneInfo,
    step_seconds: int,
    duration_seconds: float,
    blocked: Sequence[Tuple[float, float]],
    limit: int,
) -> List[float]:
    """在 *zone* 的墙上时钟格里取候选起点，再逐日锚定 —— 这正是 DST 处理的核心。

    如果只在绝对 epoch 上等步长切，夏令时切换之后候选点会漂出整点/半点（09:00 变成
    08:30），人看到的就不是自己日历上的时间。逐日从当地零点重新锚定，切换当天被跳过或
    重复的那个墙钟点由 :func:`wall_text` 的标签去重处理。
    """
    out: List[float] = []
    labels: Set[str] = set()
    day = datetime.fromtimestamp(lo, zone).date()
    guard = 0
    while guard < 400:
        guard += 1
        midnight = datetime(day.year, day.month, day.day, tzinfo=zone)
        anchor = midnight.timestamp()
        if anchor > hi:
            break
        first = 0 if anchor >= lo else int(math.ceil((lo - anchor) / step_seconds))
        index = first
        while index * step_seconds <= hi - anchor - duration_seconds:
            start = anchor + index * step_seconds
            index += 1
            if start < lo or start + duration_seconds > hi:
                continue
            label = datetime.fromtimestamp(start, zone).strftime("%Y-%m-%d %H:%M")
            if label in labels:
                continue
            if _blocked_hit(start, start + duration_seconds, blocked):
                continue
            labels.add(label)
            out.append(start)
            if len(out) >= limit:
                return out
        day = day + timedelta(days=1)
    return out


def intersect_slots(
    owner_slots: Iterable[Any],
    peer_slots: Iterable[Any],
    *,
    duration_minutes: int,
    owner_tz: str,
    peer_tz: str,
    window: Optional[Tuple[float, float]] = None,
    blocked: Sequence[Dict[str, Any]] = (),
    step_minutes: int = DEFAULT_STEP_MINUTES,
) -> List[Dict[str, Any]]:
    """两侧掩码时段的交集：绝对 epoch + 各自时区的墙上时间文本，按分数与早晚排序。

    ``blocked`` 是本机（主人）已有的忙区间，来自 Mac Node 的掩码忙闲表；交集里凡是与
    它重叠的候选都被剔掉。``window`` 进一步把结果限制在协商窗口内。
    """
    try:
        duration = int(duration_minutes)
    except (TypeError, ValueError) as exc:
        raise A2AError("no_slots", f"duration_minutes 非法：{duration_minutes!r}") from exc
    if duration <= 0:
        raise A2AError("no_slots", "会议时长必须为正")
    owner_zone = _zone(owner_tz)
    peer_zone = _zone(peer_tz)
    overlap = _overlaps(_ranges(owner_slots), _ranges(peer_slots))
    if window is not None:
        lo, hi = float(window[0]), float(window[1])
        overlap = _merge([(max(a, lo), min(b, hi)) for a, b in overlap if min(b, hi) > max(a, lo)])
    if not overlap:
        return []
    blocked_ranges = _ranges(blocked)
    step_seconds = max(5, int(step_minutes or DEFAULT_STEP_MINUTES)) * 60
    duration_seconds = duration * 60.0
    scored: List[Tuple[float, float, Dict[str, Any]]] = []
    labels: Set[str] = set()
    for lo, hi in overlap:
        if hi - lo < duration_seconds:
            continue
        for start in _candidate_starts(lo, hi, owner_zone, step_seconds, duration_seconds, blocked_ranges, 200):
            end = start + duration_seconds
            owner_label = datetime.fromtimestamp(start, owner_zone).strftime("%Y-%m-%d %H:%M")
            if owner_label in labels:
                continue
            labels.add(owner_label)
            slack = min(start - lo, hi - end)
            span = max(1.0, hi - lo - duration_seconds)
            fit = _office_fit(_local_hours(start, owner_zone)) + _office_fit(_local_hours(start, peer_zone))
            score = int(round(40.0 * min(1.0, max(0.0, slack) / span) + 30.0 * fit))
            scored.append(
                (
                    -float(score),
                    start,
                    {
                        "start": start,
                        "end": end,
                        "duration_minutes": duration,
                        "tz": [str(owner_tz), str(peer_tz)],
                        "owner_text": owner_label,
                        "peer_text": datetime.fromtimestamp(start, peer_zone).strftime("%Y-%m-%d %H:%M"),
                        "utc_text": utc_text(start),
                        "score": score,
                    },
                )
            )
    scored.sort(key=lambda row: (row[0], row[1]))
    return [row[2] for row in scored[:MAX_INTERSECTION]]


def _ranges(slots: Iterable[Any]) -> List[Tuple[float, float]]:
    rows: List[Tuple[float, float]] = []
    for raw in slots or ():
        bounds = _pair(raw)
        if bounds is not None:
            rows.append(bounds)
    return _merge(rows)


# ------------------------------------------------------------------------ 编解码
def _key_bytes(key: Any) -> bytes:
    if isinstance(key, bytes):
        raw = key
    elif isinstance(key, bytearray):
        raw = bytes(key)
    else:
        raw = str(key or "").encode("utf-8")
    if not raw:
        raise A2AError("signature", "会话密钥为空，无法签名")
    return raw


def _b64e(blob: bytes) -> str:
    return base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")


def _b64d(token: str) -> bytes:
    padding = "=" * (-len(token) % 4)
    try:
        return base64.urlsafe_b64decode(token + padding)
    except (ValueError, TypeError) as exc:
        raise A2AError("frame", "帧体不是合法 base64url") from exc


def _guard_body(payload: Any, *, depth: int = 0) -> None:
    """递归拒绝任何疑似日历正文的键名（第二道闸，白名单投影之外的兜底）。"""
    if depth > 6:
        raise A2AError("leaky_field", "帧体嵌套过深")
    if isinstance(payload, Mapping):
        for raw_key, value in payload.items():
            key = str(raw_key or "").strip().lower()
            if key in FORBIDDEN_KEYS:
                raise A2AError("leaky_field", f"帧体含被禁止的键 {key!r}")
            _guard_body(value, depth=depth + 1)
    elif isinstance(payload, (list, tuple)):
        for value in payload:
            _guard_body(value, depth=depth + 1)


def encode_frame(
    kind: str,
    body: Mapping[str, Any],
    *,
    negotiation_id: str,
    sender: str,
    key: Any,
    nonce: Optional[str] = None,
    ts: Optional[float] = None,
) -> str:
    """``<A2A_PREFIX><payload_b64url>.<hmac_b64url>``：单 token、无空白、无 ``::``。"""
    verb = str(kind or "").strip()
    if verb not in FRAME_KINDS:
        raise A2AError("frame", f"未知帧类型 {kind!r}，应为 {list(FRAME_KINDS)}")
    if not isinstance(body, Mapping):
        raise A2AError("frame", "帧体必须是 JSON 对象")
    identity = _opaque(negotiation_id)
    if not identity:
        raise A2AError("frame", f"negotiation_id 非法：{negotiation_id!r}")
    who = _opaque(sender, limit=160)
    if not who:
        raise A2AError("frame", f"sender 非法：{sender!r}")
    token = _opaque(nonce, limit=32) or secrets.token_urlsafe(9)
    _guard_body(body)
    payload = {
        "b": dict(body),
        "k": verb,
        "n": identity,
        "r": token,
        "s": who,
        "t": int(time.time() if ts is None else float(ts)),
        "v": A2A_VERSION,
    }
    try:
        text = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise A2AError("frame", f"帧体无法序列化：{exc}") from exc
    blob = _b64e(text.encode("utf-8"))
    signature = _b64e(hmac.new(_key_bytes(key), blob.encode("ascii"), hashlib.sha256).digest())
    frame = f"{A2A_PREFIX}{blob}.{signature}"
    if len(frame) > MAX_FRAME_CHARS:
        raise A2AError("frame", f"帧长 {len(frame)} 字符，超过内部预算 {MAX_FRAME_CHARS}")
    if any(ch.isspace() for ch in frame) or "::" in frame[len(A2A_PREFIX):]:
        raise A2AError("frame", "帧必须是一个不含空白与 :: 的 token")
    return frame


def decode_frame(
    text: Any,
    *,
    key: Any,
    now: Optional[float] = None,
    seen: Optional[Any] = None,
    ttl_seconds: float = DEFAULT_FRAME_TTL_SECONDS,
    skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
) -> Dict[str, Any]:
    """验签、验版本、验时效、验重放；任一不过抛 :class:`A2AError`。

    先比 HMAC（常量时间）再解 JSON：一个签名不对的帧不会把任何内容送进状态机。
    """
    trimmed = str(text or "").strip()
    if not trimmed.startswith(A2A_PREFIX):
        raise A2AError("frame", "缺少 ::POPOPX_A2A:: 前缀")
    token = trimmed[len(A2A_PREFIX):]
    if not token or any(ch.isspace() for ch in token) or "::" in token:
        raise A2AError("frame", "帧 token 含空白或 ::")
    blob, sep, signature = token.rpartition(".")
    if not sep or not blob or not signature:
        raise A2AError("frame", "帧缺少签名段")
    expected = _b64e(hmac.new(_key_bytes(key), blob.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, signature):
        raise A2AError("signature", "HMAC 校验失败（密钥不符或帧被篡改）")
    try:
        payload = json.loads(_b64d(blob).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise A2AError("frame", "帧体不是合法 JSON") from exc
    if not isinstance(payload, dict):
        raise A2AError("frame", "帧体不是 JSON 对象")
    if int(payload.get("v") or 0) != A2A_VERSION:
        raise A2AError("version", f"帧版本 {payload.get('v')!r} 不受支持")
    verb = str(payload.get("k") or "")
    if verb not in FRAME_KINDS:
        raise A2AError("frame", f"未知帧类型 {verb!r}")
    identity = _opaque(payload.get("n"))
    if not identity:
        raise A2AError("frame", "帧缺少合法 negotiation_id")
    nonce = _opaque(payload.get("r"), limit=32)
    if not nonce:
        raise A2AError("frame", "帧缺少合法 nonce")
    try:
        issued = int(payload.get("t"))
    except (TypeError, ValueError):
        raise A2AError("frame", "帧缺少合法时间戳") from None
    moment = time.time() if now is None else float(now)
    if issued - moment > skew_seconds:
        raise A2AError("expired", f"帧时间戳超前 {issued - moment:.0f}s，拒绝接受")
    if issued + max(1.0, float(ttl_seconds)) < moment:
        raise A2AError("expired", "帧已超过时效窗口")
    registry = seen if seen is not None else _DEFAULT_NONCES
    if nonce in registry:
        raise A2AError("replay", f"nonce {nonce} 已被使用")
    registry.add(nonce)
    body = payload.get("b")
    if body is not None and not isinstance(body, dict):
        raise A2AError("frame", "帧体必须是 JSON 对象")
    return {
        "kind": verb,
        "body": dict(body or {}),
        "negotiation_id": identity,
        "sender": str(payload.get("s") or ""),
        "ts": float(issued),
        "nonce": nonce,
        "version": A2A_VERSION,
    }


def peek_negotiation_id(text: Any) -> str:
    """从**未验签**的帧里只取 negotiation_id，用于挑选候选密钥。

    这里返回的值不允许驱动任何状态迁移：唯一的用法是去 ``db.get_negotiation`` 拿一行，
    再用那一行的会话密钥去 :func:`decode_frame` 验签。验签不过就什么都不是。
    """
    trimmed = str(text or "").strip()
    if not trimmed.startswith(A2A_PREFIX):
        return ""
    token = trimmed[len(A2A_PREFIX):].rpartition(".")[0]
    if not token:
        return ""
    try:
        payload = json.loads(_b64d(token).decode("utf-8"))
    except (A2AError, ValueError, UnicodeDecodeError):
        return ""
    if not isinstance(payload, dict):
        return ""
    return _opaque(payload.get("n"))


# ---------------------------------------------------------------------- 协商状态机
@dataclass
class NegotiationResult:
    """一次 :meth:`Negotiator.inbound` 的结论。"""

    handled: bool
    accepted: bool = False
    status: str = ""
    negotiation_id: str = ""
    proposal: Optional[Dict[str, Any]] = None
    reason: str = ""
    round: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "handled": self.handled,
            "accepted": self.accepted,
            "status": self.status,
            "negotiation_id": self.negotiation_id,
            "proposal": self.proposal,
            "reason": self.reason,
            "round": self.round,
        }


class Negotiator:
    """通道 A 的协商器：状态在 ``a2a_negotiations``，帧在 SMP，密钥由编排层给。"""

    def __init__(
        self,
        db: Database,
        *,
        bridge: Any = None,
        sender: Optional[Sender] = None,
        clock: Callable[[], float] = time.time,
        max_rounds: int = 6,
        session_ttl_seconds: float = 3600.0,
        key_provider: Optional[KeyProvider] = None,
        nonces: Optional[Any] = None,
        identity: Optional[Callable[[str], str]] = None,
    ) -> None:
        self.db = db
        self.bridge = bridge
        self.sender = sender
        self.clock = clock
        self.max_rounds = max(1, int(max_rounds))
        self.session_ttl = max(30.0, float(session_ttl_seconds))
        self.key_provider = key_provider
        self.nonces = nonces if nonces is not None else NonceCache()
        self.identity_provider = identity
        self._keys: Dict[str, bytes] = {}
        self._identities: Dict[str, str] = {}
        self._aliases: Dict[Tuple[str, str], str] = {}
        self.outbox: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------- 身份
    def _wire_id(self, row: Mapping[str, Any]) -> str:
        """这一行在对端使用的协商号：镜像接管时可能与本机主键不同。"""
        local = str(row.get("negotiation_id") or "")
        return self._aliases.get((str(row.get("bot_id") or ""), local), local)
    def set_identity(self, bot_id: str, identity: str) -> None:
        """登记本 Bot 在对端眼里是谁：对端行里的 ``peer_identity`` 必须等于这个字符串。"""
        clean = _opaque(identity, limit=160)
        owner = str(bot_id or "").strip()
        if not owner:
            raise A2AError("frame", "缺少 bot_id，无法登记本方身份")
        if clean:
            self._identities[owner] = clean

    def identity_for(self, bot_id: str) -> str:
        """本方在帧里的发送者标识：provider 优先，其次显式登记，最后回落 ``bot_id``。"""
        owner = str(bot_id or "").strip()
        if self.identity_provider is not None:
            offered = _opaque(self.identity_provider(owner), limit=160)
            if offered:
                return offered
        return self._identities.get(owner) or owner

    # ------------------------------------------------------------------- 密钥
    def set_key(self, peer_identity: str, key: Any) -> None:
        """编排层把 SMP 会话密钥交进来（同一身份后来者可覆盖）。"""
        clean = _opaque(peer_identity, limit=160)
        if not clean:
            raise A2AError("frame", f"peer_identity 非法：{peer_identity!r}")
        self._keys[clean] = _key_bytes(key)

    def key_for(self, peer_identity: str) -> bytes:
        clean = str(peer_identity or "").strip()
        if not clean:
            raise A2AError("wrong_peer", "协商缺少 peer_identity，无法取会话密钥")
        if self.key_provider is not None:
            return _key_bytes(self.key_provider(clean))
        held = self._keys.get(clean)
        if held is not None:
            return held
        generated = secrets.token_bytes(32)
        self._keys[clean] = generated
        return generated

    # ------------------------------------------------------------------- 审计
    def _log(
        self,
        event: str,
        *,
        row: Optional[Mapping[str, Any]] = None,
        bot_id: str = "",
        level: str = "info",
        detail: str = "",
        data: Optional[Dict[str, Any]] = None,
        proposal_id: str = "",
        negotiation_id: str = "",
    ) -> None:
        ledger_id = str((row or {}).get("negotiation_id") or negotiation_id or "")
        owner = bot_id or str((row or {}).get("bot_id") or "")
        try:
            self.db.log_negotiation(
                "a2a",
                event,
                bot_id=owner,
                level=level,
                proposal_id=proposal_id,
                negotiation_id=ledger_id,
                detail=detail[:500],
                data=dict(data or {}),
            )
        except Exception:  # noqa: BLE001 - 审计不可用绝不让协商失败
            pass

    async def _deliver(self, row: Mapping[str, Any], text: str, kind: str) -> bool:
        bot_id = str(row.get("bot_id") or "")
        peer = str(row.get("peer_identity") or "")
        self.outbox.append({"bot_id": bot_id, "peer_identity": peer, "text": text, "kind": kind})
        if self.sender is None:
            return True
        try:
            await self.sender(bot_id, peer, text)
            return True
        except Exception as exc:  # noqa: BLE001 - 发送失败留在审计里，不让异常冒泡
            self._log("send_failed", row=row, level="warn", detail=f"{kind} {type(exc).__name__}")
            return False

    def _frame(self, row: Mapping[str, Any], kind: str, body: Dict[str, Any]) -> str:
        return encode_frame(
            kind,
            body,
            negotiation_id=self._wire_id(row),
            sender=self.identity_for(str(row.get("bot_id") or "")),
            key=self.key_for(str(row.get("peer_identity") or "")),
            ts=self.clock(),
        )

    # -------------------------------------------------------------------- 起手
    async def start(
        self,
        bot_id: str,
        peer_identity: str,
        *,
        owner_slots: Iterable[Any],
        duration_minutes: int,
        owner_tz: str,
        peer_tz: str,
        window: Tuple[float, float],
        label: str = "",
        owner_identity: str = "",
    ) -> Dict[str, Any]:
        """开一次协商：落一行 ``open``、把掩码候选时段作为 ``offer`` 发给对端。"""
        peer = _opaque(peer_identity, limit=160)
        if not peer:
            raise A2AError("wrong_peer", f"peer_identity 非法：{peer_identity!r}")
        masked = free_slots(mask_slots(owner_slots, timezone=owner_tz))
        if not masked:
            raise A2AError("no_slots", "掩码后没有可用候选时段")
        try:
            lo, hi = float(window[0]), float(window[1])
        except (TypeError, ValueError, IndexError) as exc:
            raise A2AError("no_slots", f"协商窗口非法：{window!r}") from exc
        if hi <= lo:
            raise A2AError("no_slots", "协商窗口结束必须晚于开始")
        duration = int(duration_minutes)
        if duration <= 0:
            raise A2AError("no_slots", "会议时长必须为正")

        stale = self.db.find_open_negotiation(bot_id, peer)
        if stale is not None:
            self.db.update_negotiation(str(stale["negotiation_id"]), status="aborted", last_error="restarted")
            self._log("aborted", row=stale, detail="同一对端重开协商，旧行置 aborted")

        now = self.clock()
        row = self.db.create_negotiation(
            bot_id,
            peer,
            peer_label=str(label or "")[:80],
            channel="a2a",
            owner_timezone=str(owner_tz or ""),
            peer_timezone=str(peer_tz or ""),
            window_start=lo,
            window_end=hi,
            duration_minutes=duration,
            expires_at=now + self.session_ttl,
            owner_slots=masked,
        )
        record = dict(row)
        if owner_identity:
            self.set_identity(bot_id, owner_identity)
        frame = self._frame(
            record,
            "offer",
            {"slots": masked, "dur": duration, "tz": str(owner_tz or ""), "win": [lo, hi],
             "step": DEFAULT_STEP_MINUTES},
        )
        self.db.update_negotiation(str(row["negotiation_id"]), round=1)
        record["round"] = 1
        await self._deliver(record, frame, "offer")
        self._log("offer", row=record, detail=f"offer {len(masked)} 段 / {duration} 分钟",
                  data={"slots": len(masked), "duration_minutes": duration,
                        "owner_tz": str(owner_tz or ""), "peer_tz": str(peer_tz or "")})
        return {
            "negotiation_id": str(row["negotiation_id"]),
            "frame": frame,
            "status": "open",
            "round": 1,
            "slots": masked,
            "bot_id": bot_id,
            "peer_identity": peer,
        }

    # -------------------------------------------------------------- 忙闲与交集
    async def _blocked(self, row: Mapping[str, Any]) -> List[Dict[str, Any]]:
        """本机忙区间（掩码）：逐日问 Mac Node，窗口跨几天就问几天（上限 14 天，避免长轮询）。

        桥不可用或没注入就交空表 —— 宁可不剔候选，也不编造一个不存在的忙区间。
        """
        if self.bridge is None or not hasattr(self.bridge, "availability"):
            return []
        zone = _zone(str(row["owner_timezone"]))
        start = datetime.fromtimestamp(float(row["window_start"]), zone).date()
        end = datetime.fromtimestamp(float(row["window_end"]), zone).date()
        days = min(14, max(1, (end - start).days + 1))
        out: List[Dict[str, Any]] = []
        for offset in range(days):
            day = start + timedelta(days=offset)
            try:
                rows = await self.bridge.availability(
                    day.isoformat(),
                    timezone=str(row["owner_timezone"]),
                    bot_id=str(row["bot_id"]),
                )
            except Exception:  # noqa: BLE001 - 降级：没有忙闲也要能继续协商
                continue
            out.extend(dict(item) for item in rows or [] if isinstance(item, Mapping))
        return out

    def _intersect(self, row: Mapping[str, Any], peer_slots: Sequence[Any], blocked: Sequence[Dict[str, Any]]):
        return intersect_slots(
            row["owner_slots"],
            peer_slots,
            duration_minutes=int(row["duration_minutes"]),
            owner_tz=str(row["owner_timezone"]),
            peer_tz=str(row["peer_timezone"]),
            window=(float(row["window_start"]), float(row["window_end"])),
            blocked=blocked,
        )

    def _existing_pending(self, row: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        pid = str(row.get("proposal_id") or "")
        if not pid:
            return None
        record = self.db.get_proposal(pid)
        if record is not None and record.get("status") == "pending":
            return record
        return None

    async def _converge(
        self,
        row: Mapping[str, Any],
        intersection: Sequence[Dict[str, Any]],
        *,
        round_value: int,
        blocked: Sequence[Dict[str, Any]],
    ) -> Dict[str, Any]:
        best = dict(intersection[0])
        nid = str(row["negotiation_id"])
        already = self._existing_pending(row)
        if already is not None:
            # 同一轮重复收敛不再造第二条提案：卡片与账本都必须是一对一。
            self.db.update_negotiation(nid, status="converged", round=round_value,
                                       intersection=list(intersection), agreed_slot=best)
            self._log("converged_duplicate", row=row, detail=f"沿用已有提案 {already['proposal_id']}",
                      proposal_id=str(already["proposal_id"]))
            return already
        payload: Dict[str, Any] = {
            "masked": True,
            "owner_text": str(best.get("owner_text") or ""),
            "peer_text": str(best.get("peer_text") or ""),
            "utc_text": str(best.get("utc_text") or ""),
            "peer_timezone": str(row.get("peer_timezone") or ""),
            "owner_timezone": str(row.get("owner_timezone") or ""),
            "score": int(best.get("score") or 0),
            "alternatives": [
                {"start": item["start"], "end": item["end"], "owner_text": item["owner_text"]}
                for item in intersection[1:4]
            ],
            "blocked": len(blocked),
            "round": round_value,
            "expires_at": float(row.get("expires_at") or 0),
        }
        proposal = self.db.create_proposal(
            str(row["bot_id"]),
            "create",
            source="a2a",
            counterparty=str(row.get("peer_identity") or ""),
            timezone=str(row.get("owner_timezone") or ""),
            start_ts=float(best["start"]),
            end_ts=float(best["end"]),
            duration_minutes=int(row["duration_minutes"]),
            summary="",
            payload=payload,
            negotiation_id=nid,
        )
        self.db.update_negotiation(
            nid,
            status="converged",
            round=round_value,
            intersection=list(intersection),
            agreed_slot=best,
            proposal_id=str(proposal["proposal_id"]),
        )
        record = dict(row)
        record["round"] = round_value
        frame = self._frame(record, "accept", {"slot": {"start": best["start"], "end": best["end"],
                                                        "tz": str(row.get("owner_timezone") or "")},
                                               "dur": int(row["duration_minutes"])})
        await self._deliver(record, frame, "accept")
        self._log("converged", row=record, detail=f"收敛于 {best.get('owner_text')}（对端 {best.get('peer_text')}）",
                  data={"owner_text": str(best.get("owner_text") or ""), "round": round_value},
                  proposal_id=str(proposal["proposal_id"]))
        return proposal

    async def _counter_back(self, row: Mapping[str, Any], round_value: int) -> str:
        """交集为空时把主人剩余的掩码时段再发一轮。"""
        record = dict(row)
        record["round"] = round_value
        slots = [dict(item) for item in row.get("owner_slots") or [] if isinstance(item, Mapping)]
        frame = self._frame(record, "counter", {"slots": slots, "dur": int(row["duration_minutes"]),
                                                "tz": str(row.get("owner_timezone") or ""),
                                                "why": "no_intersection"})
        await self._deliver(record, frame, "counter")
        self._log("counter", row=record, detail=f"第 {round_value} 轮反提案 {len(slots)} 段",
                  data={"round": round_value, "slots": len(slots)})
        return frame

    # ------------------------------------------------------------------ 入站帧
    def _accepted_slot(
        self, row: Mapping[str, Any], body: Mapping[str, Any], blocked: Sequence[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """对端 ``accept`` 里带的时段：必须落在**我们自己发出去的**掩码时段内才采信。"""
        bounds = _pair(body.get("slot")) or _pair({"start": body.get("s"), "end": body.get("e")})
        if bounds is None:
            return None
        start = bounds[0]
        duration = int(row["duration_minutes"]) * 60.0
        end = start + duration
        if start < float(row["window_start"]) or end > float(row["window_end"]):
            return None
        offered = _ranges(row.get("owner_slots") or [])
        if not any(lo <= start and end <= hi + 1.0 for lo, hi in offered):
            return None
        if _blocked_hit(start, end, _ranges(blocked)):
            return None
        owner_zone = _zone(str(row["owner_timezone"]))
        peer_zone = _zone(str(row["peer_timezone"]))
        return {
            "start": start,
            "end": end,
            "duration_minutes": int(row["duration_minutes"]),
            "tz": [str(row["owner_timezone"]), str(row["peer_timezone"])],
            "owner_text": datetime.fromtimestamp(start, owner_zone).strftime("%Y-%m-%d %H:%M"),
            "peer_text": datetime.fromtimestamp(start, peer_zone).strftime("%Y-%m-%d %H:%M"),
            "utc_text": utc_text(start),
            "score": 0,
        }

    def _candidate_rows(self, bot_id: str, text: str, peer_identity: str) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        peeked = peek_negotiation_id(text)
        if peeked:
            direct = self.db.get_negotiation(peeked)
            if direct is not None and str(direct.get("bot_id")) == str(bot_id):
                rows.append(direct)
            mirrored = self._mirror_of(bot_id, peeked)
            if mirrored is not None and all(
                r["negotiation_id"] != mirrored["negotiation_id"] for r in rows
            ):
                rows.append(mirrored)
        if peer_identity:
            open_row = self.db.find_open_negotiation(bot_id, str(peer_identity))
            if open_row is not None and all(r["negotiation_id"] != open_row["negotiation_id"] for r in rows):
                rows.append(open_row)
        for row in self.db.list_negotiations(bot_id, limit=50):
            if str(row.get("status")) in ("open", "converged") and all(
                r["negotiation_id"] != row["negotiation_id"] for r in rows
            ):
                rows.append(row)
        return rows

    async def _adopt(
        self,
        bot_id: str,
        peer_identity: str,
        frame: Mapping[str, Any],
        *,
        owner_tz: str,
        slots: Optional[Iterable[Any]],
        label: str,
    ) -> Tuple[Optional[Dict[str, Any]], str]:
        """把对端起手的 ``offer`` 接成本机的一行协商（沿用同一个协商号）。"""
        peer = _opaque(peer_identity, limit=160)
        if not peer:
            return None, "wrong_peer"
        if str(frame.get("kind")) != "offer":
            return None, "unknown_negotiation"
        nid = str(frame.get("negotiation_id") or "")
        if not _LOCAL_ID_RE.match(nid):
            # 协商号要当本机主键用，形状必须和 Database._ID_RE 同形；畸形 id 直接丢。
            return None, "frame"
        external = nid
        if self.db.get_negotiation(nid) is not None:
            # 同一个账本里这个主键已被占用（同一 Studio 的两个本地 Bot 互谈：一边起手、一边接管）。
            # 换成本机镜像主键，线上仍沿用对端的号 —— 别名记在内存，行本身可持久复查。
            nid = "ng_" + hashlib.sha256(f"ppx-a2a-mirror\0{external}\0{bot_id}".encode("utf-8")).hexdigest()[:12]
            if self.db.get_negotiation(nid) is not None:
                return None, "frame"
        body = frame.get("body") or {}
        window = body.get("win")
        try:
            lo, hi = float(window[0]), float(window[1])
            duration = int(body["dur"])
        except (AttributeError, IndexError, KeyError, TypeError, ValueError):
            return None, "no_slots"
        if hi <= lo or duration <= 0:
            return None, "no_slots"
        zone = str(owner_tz or "").strip()
        if not zone:
            return None, "no_slots"
        try:
            _zone(zone)
        except A2AError:
            return None, "no_slots"
        rows = slots
        if rows is None:
            rows = free_from_busy(
                await self._blocked({"window_start": lo, "window_end": hi, "owner_timezone": zone,
                                     "bot_id": bot_id}),
                window=(lo, hi),
                timezone=zone,
            )
        masked = free_slots(mask_slots(rows, timezone=zone))
        if not masked:
            return None, "no_slots"
        peer_slots = free_slots(mask_slots(body.get("slots") or [], timezone=str(body.get("tz") or "")))
        self.db.create_negotiation(
            bot_id,
            peer,
            negotiation_id=nid,
            peer_label=str(label or "")[:80],
            channel="a2a",
            owner_timezone=zone,
            peer_timezone=str(body.get("tz") or ""),
            window_start=lo,
            window_end=hi,
            duration_minutes=duration,
            expires_at=self.clock() + self.session_ttl,
            owner_slots=masked,
        )
        self.db.update_negotiation(nid, round=1, peer_slots=peer_slots)
        if nid != external:
            self._aliases[(bot_id, nid)] = external
        record = self.db.get_negotiation(nid)
        return record, ""

    def _mirror_of(self, bot_id: str, wire_id: str) -> Optional[Dict[str, Any]]:
        """别名反查：镜像行的本机主键与线上协商号不同（同一账本里两个 Bot 互谈）。"""
        for (owner, local), external in self._aliases.items():
            if owner == str(bot_id) and external == wire_id:
                return self.db.get_negotiation(local)
        return None

    async def inbound(
        self,
        bot_id: str,
        text: Any,
        *,
        peer_identity: str = "",
        owner_tz: str = "",
        slots: Optional[Iterable[Any]] = None,
        label: str = "",
    ) -> Dict[str, Any]:
        """处理一行入站文本。非 A2A 帧返回 ``handled=False``，交回上层按普通消息处理。

        未知协商号 + ``offer`` + ``peer_identity`` 是**对端起手**的唯一形态：这时才允许用
        ``owner_tz`` / ``slots``（或桥的掩码忙表反推）就地接下一行，双方从此共用同一个协商号。
        没有这些上下文就照旧拒绝 —— 绝不让一个陌生 id 凭空造出状态。
        """
        trimmed = str(text or "").strip()
        if not trimmed.startswith(A2A_PREFIX):
            return NegotiationResult(False, reason="not_a2a").as_dict()

        frame: Optional[Dict[str, Any]] = None
        row: Optional[Dict[str, Any]] = None
        failure = ""
        for candidate in self._candidate_rows(bot_id, trimmed, peer_identity):
            try:
                decoded = decode_frame(
                    trimmed,
                    key=self.key_for(str(candidate.get("peer_identity") or "")),
                    now=self.clock(),
                    seen=self.nonces,
                )
            except A2AError as exc:
                failure = exc.reason
                continue
            frame, row = decoded, candidate
            break
        if frame is None and peer_identity:
            try:
                frame = decode_frame(
                    trimmed,
                    key=self.key_for(peer_identity),
                    now=self.clock(),
                    seen=self.nonces,
                )
            except A2AError as exc:
                failure = failure or exc.reason
        if frame is None:
            self._log(
                "rejected",
                bot_id=bot_id,
                level="warn",
                detail=f"入站帧未通过校验：{failure or 'signature'}",
                negotiation_id=peek_negotiation_id(trimmed),
            )
            return NegotiationResult(True, reason=failure or "signature",
                                     negotiation_id=peek_negotiation_id(trimmed)).as_dict()

        nid = str(frame["negotiation_id"])
        if row is None:
            row, adopt_reason = await self._adopt(
                bot_id, peer_identity, frame, owner_tz=owner_tz, slots=slots, label=label
            )
            if row is None:
                self._log("rejected", bot_id=bot_id, level="warn",
                          detail=f"入站帧无法落账：{adopt_reason}", negotiation_id=nid)
                return NegotiationResult(True, reason=adopt_reason, negotiation_id=nid).as_dict()
            self._log("adopt", row=row, detail=f"接下对端 offer（{len(row['owner_slots'])} 段掩码时段）",
                      negotiation_id=nid)
        if self._wire_id(row) != nid:
            # 帧里的号既不是本机主键、也不是已登记的别名 —— 说明扫到的行不是它指向的那一行。
            self._log("rejected", row=row, level="warn", detail="帧内协商号与本机账本不匹配",
                      negotiation_id=nid)
            return NegotiationResult(True, reason="unknown_negotiation", negotiation_id=nid).as_dict()
        nid = str(row["negotiation_id"])
        if str(row.get("bot_id")) != str(bot_id):
            self._log("rejected", row=row, bot_id=bot_id, level="warn", detail="协商属于其它 Bot", negotiation_id=nid)
            return NegotiationResult(True, reason="wrong_bot", negotiation_id=nid,
                                    status=str(row.get("status") or "")).as_dict()
        if str(frame["sender"]) != str(row.get("peer_identity") or ""):
            self._log("rejected", row=row, level="warn",
                      detail="帧发送方与协商归属的对方不一致", negotiation_id=nid)
            return NegotiationResult(True, reason="wrong_peer", negotiation_id=nid,
                                    status=str(row.get("status") or ""), round=int(row.get("round") or 0)).as_dict()
        if str(row.get("status")) in ("expired", "rejected", "aborted"):
            self._log("ignored", row=row, level="warn", detail=f"协商已是 {row['status']}，不再迁移",
                      negotiation_id=nid)
            return NegotiationResult(True, reason="closed", negotiation_id=nid,
                                    status=str(row.get("status") or ""),
                                    round=int(row.get("round") or 0)).as_dict()
        deadline = float(row.get("expires_at") or 0)
        if deadline and deadline <= self.clock():
            self.db.update_negotiation(nid, status="expired", last_error="ttl")
            pending = self._existing_pending(row)
            if pending is not None:
                self.db.update_proposal(str(pending["proposal_id"]), status="expired")
            self._log("expired", row=row, level="warn", detail="会话已过 TTL，帧不再驱动状态机",
                      negotiation_id=nid)
            return NegotiationResult(True, reason="closed", negotiation_id=nid,
                                    status="expired", round=int(row.get("round") or 0)).as_dict()

        kind = str(frame["kind"])
        body = frame["body"]
        if kind == "decline":
            self.db.update_negotiation(nid, status="rejected", round=int(row.get("round") or 0) + 1,
                                       last_error=_opaque(body.get("why"), limit=32) or "peer_declined")
            pending = self._existing_pending(row)
            if pending is not None:
                self.db.update_proposal(str(pending["proposal_id"]), status="declined")
            self._log("declined", row=row, level="warn",
                      detail=f"对端拒绝（{self.db.get_negotiation(nid)['last_error']}）", negotiation_id=nid)
            return NegotiationResult(True, True, status="rejected", negotiation_id=nid,
                                     reason="peer_declined").as_dict()
        if kind == "accept" and str(row.get("status")) == "converged":
            # 双方都已收敛：再回一条 accept 只会来回刷屏，直接把既有提案交回去。
            self._log("accept_echo", row=row, detail="对端 accept 命中已收敛行，不再外发",
                      negotiation_id=nid, proposal_id=str(row.get("proposal_id") or ""))
            return NegotiationResult(True, True, status="converged", negotiation_id=nid,
                                     proposal=self.db.get_proposal(str(row.get("proposal_id") or ""))
                                     if row.get("proposal_id") else None,
                                     round=int(row.get("round") or 0)).as_dict()

        peer_slots = free_slots(mask_slots(body.get("slots") or [], timezone=str(row.get("peer_timezone") or "")))
        round_value = int(row.get("round") or 0) + 1
        if kind == "sync" and not peer_slots:
            self.db.update_negotiation(nid, round=round_value)
            frame_text = await self._counter_back({**row, "round": round_value}, round_value)
            self._log("sync", row=row, detail="对端请求同步，回发当前掩码时段", negotiation_id=nid)
            return NegotiationResult(True, True, status=str(row.get("status") or ""), negotiation_id=nid,
                                     round=round_value).as_dict() | {"frame": frame_text}

        if not peer_slots and kind != "accept":
            self.db.update_negotiation(nid, round=round_value, peer_slots=[], intersection=[],
                                       last_error="empty_peer_slots")
            self._log("counter", row=row, level="warn", detail="对端掩码时段为空，重新索取", negotiation_id=nid)
            if round_value >= self.max_rounds:
                self.db.update_negotiation(nid, status="aborted", last_error="rounds_exhausted")
                self._log("aborted", row=row, level="warn", detail=f"轮次耗尽（{round_value}）", negotiation_id=nid)
                return NegotiationResult(True, True, status="aborted", negotiation_id=nid,
                                         reason="limit", round=round_value).as_dict()
            return NegotiationResult(True, True, status="open", negotiation_id=nid,
                                     round=round_value).as_dict()

        blocked = await self._blocked(row)
        intersection: List[Dict[str, Any]] = []
        if kind == "accept":
            # 收敛的权威永远是本机算出的交集：对端的 accept 只表示同意，
            # 不允许借它塞进一个新数字（那等于让对端挑我们的日历）。
            stored = [dict(item) for item in (row.get("intersection") or []) if isinstance(item, Mapping)]
            trusted = self._accepted_slot(row, body, blocked)
            intersection = stored[:1] if stored else ([trusted] if trusted else [])
        else:
            try:
                intersection = self._intersect(row, peer_slots, blocked)
            except A2AError as exc:
                self.db.update_negotiation(nid, round=round_value, last_error=exc.reason)
                self._log("rejected", row=row, level="warn", detail=f"交集计算失败：{exc.reason}",
                          negotiation_id=nid)
                return NegotiationResult(True, False, status=str(row.get("status") or ""),
                                         negotiation_id=nid, reason=exc.reason,
                                         round=round_value).as_dict()

        if intersection:
            proposal = await self._converge(row, intersection, round_value=round_value, blocked=blocked)
            return NegotiationResult(True, True, status="converged", negotiation_id=nid,
                                     proposal=proposal, round=round_value).as_dict()

        if round_value >= self.max_rounds:
            self.db.update_negotiation(nid, status="aborted", round=round_value, peer_slots=peer_slots,
                                       intersection=[], last_error="rounds_exhausted")
            self._log("aborted", row=row, level="warn",
                      detail=f"{self.max_rounds} 轮内未收敛，协商中止", negotiation_id=nid)
            return NegotiationResult(True, True, status="aborted", negotiation_id=nid,
                                     reason="limit", round=round_value).as_dict()

        self.db.update_negotiation(nid, round=round_value, peer_slots=peer_slots, intersection=[])
        await self._counter_back(row, round_value)
        return NegotiationResult(True, True, status="open", negotiation_id=nid, round=round_value).as_dict()

    # ------------------------------------------------------------------ 主动口
    async def counter(self, negotiation_id: str, *, slots: Iterable[Any], reason: str = "") -> Dict[str, Any]:
        """主人给出新的掩码时段；对 ``converged`` 行即显式重开（旧提案 ``superseded``）。"""
        row = self.db.get_negotiation(str(negotiation_id))
        if row is None:
            return {"ok": False, "reason": "unknown_negotiation", "status": ""}
        status = str(row.get("status") or "")
        if status in ("expired", "rejected", "aborted"):
            self._log("reopen_refused", row=row, level="warn", detail=f"{status} 的协商不可复活",
                      negotiation_id=str(row["negotiation_id"]))
            return {"ok": False, "reason": "closed", "status": status,
                    "negotiation_id": str(row["negotiation_id"])}
        masked = free_slots(mask_slots(slots, timezone=str(row.get("owner_timezone") or "")))
        if not masked:
            return {"ok": False, "reason": "no_slots", "status": status,
                    "negotiation_id": str(row["negotiation_id"])}
        nid = str(row["negotiation_id"])
        superseded = ""
        pending = self._existing_pending(row)
        if pending is not None:
            superseded = str(pending["proposal_id"])
            self.db.update_proposal(superseded, status="superseded")
        round_value = int(row.get("round") or 0) + 1
        record = dict(row)
        record["round"] = round_value
        self.db.update_negotiation(
            nid,
            status="open",
            round=round_value,
            owner_slots=masked,
            intersection=[],
            agreed_slot={},
            proposal_id="",
            expires_at=self.clock() + self.session_ttl,
            last_error="",
        )
        body: Dict[str, Any] = {"slots": masked, "dur": int(row["duration_minutes"]),
                                "tz": str(row.get("owner_timezone") or "")}
        why = _opaque(reason, limit=32)
        if why:
            body["why"] = why
        frame = self._frame(record, "counter", body)
        await self._deliver(record, frame, "counter")
        self._log("reopen" if superseded else "counter", row=record,
                  detail=f"第 {round_value} 轮本方时段 {len(masked)} 段"
                         + (f"，旧提案 {superseded} 置 superseded" if superseded else ""),
                  data={"round": round_value, "slots": len(masked), "superseded": bool(superseded)},
                  proposal_id=superseded, negotiation_id=nid)
        return {"ok": True, "reason": "", "status": "open", "negotiation_id": nid, "frame": frame,
                "round": round_value, "reopened": bool(superseded), "slots": masked}

    async def confirm(self, negotiation_id: str) -> Dict[str, Any]:
        """把已收敛的时段确认给对端（写日历发生在编排层的 ``bridge.approve``，不在这里）。"""
        row = self.db.get_negotiation(str(negotiation_id))
        if row is None:
            return {"ok": False, "reason": "unknown_negotiation", "status": ""}
        if str(row.get("status")) != "converged":
            return {"ok": False, "reason": "not_converged", "status": str(row.get("status") or ""),
                    "negotiation_id": str(row["negotiation_id"])}
        agreed = dict(row.get("agreed_slot") or {})
        if not agreed:
            return {"ok": False, "reason": "no_slots", "status": "converged",
                    "negotiation_id": str(row["negotiation_id"])}
        nid = str(row["negotiation_id"])
        frame = self._frame(row, "confirm", {"slot": {"start": agreed.get("start"), "end": agreed.get("end"),
                                                      "tz": str(row.get("owner_timezone") or "")},
                                             "dur": int(row["duration_minutes"])})
        await self._deliver(row, frame, "confirm")
        proposal = self.db.get_proposal(str(row.get("proposal_id") or "")) if row.get("proposal_id") else None
        self._log("confirm", row=row, detail=f"本方确认 {agreed.get('owner_text')}", negotiation_id=nid,
                  proposal_id=str(row.get("proposal_id") or ""))
        return {"ok": True, "reason": "", "status": "converged", "negotiation_id": nid, "frame": frame,
                "proposal": proposal}

    async def decline(self, negotiation_id: str, reason: str = "") -> Dict[str, Any]:
        """本方拒绝：协商置 ``rejected``，挂着的待确认提案置 ``declined``。"""
        row = self.db.get_negotiation(str(negotiation_id))
        if row is None:
            return {"ok": False, "reason": "unknown_negotiation", "status": ""}
        nid = str(row["negotiation_id"])
        why = _opaque(reason, limit=32) or "owner_declined"
        pending = self._existing_pending(row)
        if pending is not None:
            self.db.update_proposal(str(pending["proposal_id"]), status="declined")
        self.db.update_negotiation(nid, status="rejected", last_error=why)
        frame = self._frame(row, "decline", {"dur": int(row["duration_minutes"]), "why": why})
        await self._deliver(row, frame, "decline")
        self._log("declined", row=row, level="warn", detail=f"本方拒绝（{why}）", negotiation_id=nid)
        return {"ok": True, "reason": "", "status": "rejected", "negotiation_id": nid, "frame": frame}

    async def expire_all(self) -> int:
        """把超过 TTL 的 ``open``/``converged`` 行置 ``expired``，并连带过期其 pending 提案。"""
        now = self.clock()
        expired = 0
        for status in ("open", "converged"):
            for row in self.db.list_negotiations(status=status, limit=500):
                deadline = float(row.get("expires_at") or 0)
                if deadline and deadline > now:
                    continue
                if not deadline and float(row.get("created_at") or 0) + self.session_ttl > now:
                    continue
                nid = str(row["negotiation_id"])
                self.db.update_negotiation(nid, status="expired", last_error="ttl")
                pending = self._existing_pending(row)
                if pending is not None:
                    self.db.update_proposal(str(pending["proposal_id"]), status="expired")
                self._log("expired", row=row, level="warn", detail="协商超时过期", negotiation_id=nid)
                expired += 1
        return expired

    # ------------------------------------------------------------------ 交接口
    def snapshot(self, negotiation_id: str) -> Dict[str, Any]:
        """给编排层/控制台的一行安全视图（只有时段边界与状态，没有日历正文）。"""
        row = self.db.get_negotiation(str(negotiation_id))
        if row is None:
            return {}
        return {
            "negotiation_id": str(row["negotiation_id"]),
            "status": str(row["status"]),
            "round": int(row.get("round") or 0),
            "peer_identity": str(row.get("peer_identity") or ""),
            "peer_label": str(row.get("peer_label") or ""),
            "owner_timezone": str(row.get("owner_timezone") or ""),
            "peer_timezone": str(row.get("peer_timezone") or ""),
            "duration_minutes": int(row.get("duration_minutes") or 0),
            "owner_slots": len(row.get("owner_slots") or []),
            "peer_slots": len(row.get("peer_slots") or []),
            "intersection": list(row.get("intersection") or []),
            "agreed_slot": dict(row.get("agreed_slot") or {}),
            "proposal_id": str(row.get("proposal_id") or ""),
            "expires_at": float(row.get("expires_at") or 0),
            "last_error": str(row.get("last_error") or ""),
        }


def proposal_summary(peer_label: str, slot: Mapping[str, Any], *, tz: str = "") -> str:
    """给编排层填 ``proposal.summary`` 的中性文案生成器。

    Mac Node 的 ``proposeCreate`` 要求 ``title`` 非空，而本模块绝不编造日程主题；
    因此只提供「与谁 / 何时」这一条纯时间信息，本地化文案仍归 :mod:`app.i18n`。
    """
    who = str(peer_label or "").strip()[:60] or "POPOPX"
    when = str((slot or {}).get("owner_text") or "").strip()
    zone = str(tz or (slot or {}).get("tz") or "").strip()
    parts = [who]
    if when:
        parts.append(when)
    if zone:
        parts.append(zone)
    return " · ".join(parts)


def proposal_card(
    db: Database,
    proposal: Mapping[str, Any],
    *,
    title: str,
    body: str = "",
    fields: Optional[Sequence[Mapping[str, Any]]] = None,
    visible_text: str = "",
    approve_label: str = "",
    decline_label: str = "",
    alt_label: str = "",
    ttl_seconds: float = 1800.0,
) -> Tuple[Dict[str, Any], str]:
    """把提案包成 ``::POPOPX_ECO::`` 确认卡片，并把 ``card_id`` 记回账本。

    帧的构造完全交给 :mod:`app.eco_cards`（唯一权威编解码），本模块只负责落 ``card_id``，
    这样主人点确认后的 ``::CB::ppxok_<proposal_id>`` 能被反查回同一条提案。
    """
    pid = str((proposal or {}).get("proposal_id") or "")
    if not pid:
        raise A2AError("frame", "提案缺少 proposal_id，无法生成确认卡片")
    card, text = confirmation_card(
        pid,
        title=title,
        body=body,
        visible_text=visible_text,
        fields=fields,
        ttl_seconds=ttl_seconds,
        approve_label=approve_label,
        decline_label=decline_label,
        alt_label=alt_label,
    )
    db.update_proposal(pid, card_id=str(card["id"]))
    return card, text


__all__ = [
    "A2A_PREFIX",
    "A2A_VERSION",
    "DEFAULT_FRAME_TTL_SECONDS",
    "DEFAULT_STEP_MINUTES",
    "FORBIDDEN_KEYS",
    "FRAME_KINDS",
    "MASKED_KEYS",
    "MAX_FRAME_CHARS",
    "MAX_INTERSECTION",
    "MAX_MASKED_SLOTS",
    "REASONS",
    "A2AError",
    "Negotiator",
    "NegotiationResult",
    "NonceCache",
    "decode_frame",
    "encode_frame",
    "free_from_busy",
    "free_slots",
    "intersect_slots",
    "mask_slots",
    "peek_negotiation_id",
    "proposal_card",
    "proposal_summary",
    "utc_text",
    "wall_text",
]
