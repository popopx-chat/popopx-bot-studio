"""替身机器人的编排层 —— Needle 3、偏好规则、Mac Node、A2A 协商、访客门户的唯一调用点。

分层规矩：:mod:`app.needle3_runtime`（意图抽取）、:mod:`app.agent_preferences`（主人偏好）、
:mod:`app.mac_node_bridge`（严格回环日历）、:mod:`app.a2a`（通道 A）、
:mod:`app.guest_portal`（通道 B）互不认识，只认自己的输入。把它们串起来、并且唯一
碰 ``services`` 的就是本模块：插件 :mod:`app.plugins.personal_agent` 与管理路由
:mod:`app.agent_admin` 都只调这里，所以「谁能动主人的日历」在整套代码里只有一处答案。

三条不可协商的边界：

* 日历只在主人点了 ``::POPOPX_ECO::`` 确认卡片之后才写，写的方式只有 Mac Node；
* 外发的时段一律是掩码时段，标题、邮箱、完整日程永不出门；
* 发送附件时路径收敛到该 Bot 自己的 ``files`` 目录，任意路径一律拒绝。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo

from .a2a import (
    A2A_PREFIX,
    ID_CHARS as A2A_ID_CHARS,
    Negotiator,
    free_from_busy,
    mask_slots,
    peek_negotiation_id,
    proposal_card,
    proposal_summary,
    wall_text,
)
from .agent_copy import render as render_copy
from .agent_preferences import PreferenceStore
from .bot_supervisor import BotPaths, parse_chat_ref
from .config import SECURE_FILE_MODE, Settings, load_settings
from .database import Database
from .eco_cards import (
    CALLBACK_ALT,
    CALLBACK_APPROVE,
    CALLBACK_DECLINE,
    is_uplink_text,
    parse_callback,
    status_card,
)
from .guest_portal import GuestPortal
from .ics import build_calendar, event_uid, ics_filename
from .i18n import normalize_locale, t as translate
from .mac_node_bridge import CACHE_SOURCE, MacNodeBridge, iso_utc
from .needle3_runtime import DEFAULT_DURATION_MINUTES, Extraction, NeedleRuntime, ToolCall
from .reasoner_bridge import ReasonerBridge

log = logging.getLogger("popopx.studio.agent")

PLUGIN_ID = "personal_agent"

GET_AVAILABILITY = "calendar.get_availability"
PROPOSE_CREATE = "calendar.propose_create"
PROPOSE_RESCHEDULE = "calendar.propose_reschedule"
PROPOSE_CANCEL = "calendar.propose_cancel"
SUMMARIZE_FILE = "workspace.summarize_file"
TOOL_NAMES = (GET_AVAILABILITY, PROPOSE_CREATE, PROPOSE_RESCHEDULE, PROPOSE_CANCEL, SUMMARIZE_FILE)

CARD_TTL_SECONDS = 1800.0
PEERS_FILE_NAME = "peers.json"
DEFAULT_MIN_CONFIDENCE = 0.55
DEFAULT_MAX_SLOTS = 4
DEFAULT_WINDOW_DAYS = 5
# 空闲段按这个步长切成候选：整天空闲时只给「段首」一个候选，工作时段过滤器会把它丢掉。
SLOT_STEP_MINUTES = 30
MAX_CANDIDATES = 120
_TIME_RE = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")
MAX_SUMMARY_BYTES = 256 * 1024
MAX_SUMMARY_ITEMS = 12
TITLE_MAX = 120
PEER_REF_MAX = 160

# 编排层的配置里只放行为开关：令牌、密钥、主机地址永远归 Settings，插件改不到。
DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": True,
    "owner_chat": "",
    "min_confidence": DEFAULT_MIN_CONFIDENCE,
    "max_slots": DEFAULT_MAX_SLOTS,
    "send_invite": True,
    "handle_a2a": True,
}

Sender = Callable[..., Awaitable[Any]]


# ------------------------------------------------------------------- 数据结构
@dataclass
class SlotResult:
    """一次「查空档」的完整结论：时段、来源、是否可信、被规则挡掉了多少。"""

    slots: List[Dict[str, Any]] = field(default_factory=list)
    source: str = "none"
    ok: bool = False
    reason: str = ""
    busy: int = 0
    rejected: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "slots": [dict(item) for item in self.slots],
            "source": self.source,
            "ok": self.ok,
            "reason": self.reason,
            "busy": self.busy,
            "rejected": self.rejected,
        }


@dataclass
class Peer:
    """一个已配对的对端：A2A 身份、HMAC 密钥、可选的会话引用。

    配对是**显式**的：没有这一行，任何 ``::POPOPX_A2A::`` 帧都只进审计而不进状态机，
    因为对端身份必须由传输层担保，不能由帧内容自证。
    """

    identity: str
    key: str = ""
    label: str = ""
    chat: str = ""

    @property
    def wire(self) -> str:
        """这条配对在 A2A 帧与账本里实际使用的身份（见 :func:`wire_identity`）。"""
        return wire_identity(self.identity)

    def as_dict(self, *, secret: bool = False) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "identity": self.identity,
            "wire_identity": self.wire,
            "label": self.label,
            "chat": self.chat,
            "derived": not self.key,
        }
        if secret:
            data["key"] = self.key
        return data


def build_sender(services: Any) -> Sender:
    """把 Studio 的发送面包成编排层唯一的出口（会话引用 → chat_type/chat_id）。"""

    async def send(
        bot_id: str,
        chat_ref: str,
        text: str = "",
        *,
        content: Optional[Dict[str, Any]] = None,
        file_path: str = "",
    ) -> Any:
        chat_type, chat_id = parse_chat_ref(chat_ref)
        if content is not None:
            return await services.send_content(
                bot_id, chat_type, chat_id, content, plugin_id=PLUGIN_ID, file_path=file_path
            )
        return await services.send_text(bot_id, chat_type, chat_id, text, plugin_id=PLUGIN_ID)

    return send


def _decision(kind: str, reply: str = "", *, status: str = "", **meta: Any) -> Dict[str, Any]:
    """插件返回值的唯一构造点（关键字与 ``PluginResult`` 一一对应）。"""
    return {
        "handled": True,
        "reply": reply,
        "reply_content": None,
        "forwards": [],
        "status": status or f"{PLUGIN_ID}:{kind}",
        "metadata": {"agent": kind, **meta},
    }


def _clean(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]


def _number(value: Any, fallback: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return float(fallback)
    if number != number or number in (float("inf"), float("-inf")):
        return float(fallback)
    return number


def _minutes(value: Any, fallback: int) -> int:
    minutes = int(_number(value, fallback))
    return minutes if 5 <= minutes <= 720 else fallback


def _wanted_ts(value: Any, lo: float, hi: float, zone: str) -> float:
    """把抽取到的 ``HH:MM`` 还原成窗口内的一个锚点，用来给候选排序。

    抽取给的是主人说的墙上时间，所以按查询时区还原；窗口里凑不出这个点就返回 ``0.0``，
    调用方据此「不按时间靠拢」，而不是把候选拧到一个不可能的时刻上。
    """
    hit = _TIME_RE.match(str(value or "").strip())
    if not hit:
        return 0.0
    try:
        base = datetime.fromtimestamp(float(lo), ZoneInfo(zone))
    except Exception:  # noqa: BLE001 - 时区已过硬校验，这里只防手写调用传进来的脏值
        return 0.0
    hour, minute = int(hit.group(1)), int(hit.group(2))
    for offset in range(8):
        anchor = (base + timedelta(days=offset)).replace(hour=hour, minute=minute, second=0, microsecond=0)
        stamp = anchor.timestamp()
        if lo <= stamp <= hi:
            return stamp
    return 0.0


def wire_identity(value: Any, *, limit: int = PEER_REF_MAX) -> str:
    """把任意对端标识收成 A2A 帧里能用的 opaque token。

    SMP 联系人地址带 ``@``，而 :data:`app.a2a.ID_CHARS` 只接本机 id 那套字符 —— 帧里的
    身份同时是账本主键与密钥派生的一部分，字符集不能在协议侧放宽。所以非法字符在编排层
    做一次确定性映射：合法的原样保留，其余换成 ``ppx-<sha256 前 24 位>``。真实地址仍然
    只留在本机 ``peers.json`` 里，映射后的 token 才是协商双方的共同标识。
    """
    text = str(value if value is not None else "").strip()
    if not text:
        return ""
    if len(text) <= limit and all(ch in A2A_ID_CHARS for ch in text):
        return text
    digest = hashlib.sha256(f"ppx-peer\0{text}".encode("utf-8")).hexdigest()
    return f"ppx-{digest[:24]}"


def _field(event: Any, key: str, default: str = "") -> str:
    """入站事件既可能是网关对象，也可能是字典（自检与第三方桥接），取值方式只写一遍。"""
    if isinstance(event, dict):
        return str(event.get(key, default) or default)
    return str(getattr(event, key, default) or default)


def slot_line(start: float, end: float, zone: str) -> str:
    """一个时段的墙上时间：同日只写一次日期，跨日才两段全写。"""
    left = wall_text(start, zone)
    right = wall_text(end, zone)
    if left[:10] == right[:10]:
        return f"{left}–{right[11:]}"
    return f"{left} – {right}"


def now_iso() -> str:
    """ peers.json 与错误记录里的人读时间戳，与节点桥共用同一种 ISO 格式。"""
    return iso_utc(time.time())


def json_safe(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, default=str)[:300]
    except (TypeError, ValueError):
        return str(value)[:300]


# --------------------------------------------------------------------- 运行时
class AgentRuntime:
    """一个进程只有一个 :class:`AgentRuntime`（挂在 ``StudioStack.agent`` 上）。

    构造本身不碰网络、不建目录、不加载权重：六个协作对象全部惰性构建，没有被用到的
    引擎在 ``--self-test`` 里永远不会被实例化。
    """

    def __init__(
        self,
        *,
        db: Optional[Database] = None,
        settings: Optional[Settings] = None,
        sender: Optional[Sender] = None,
        clock: Callable[[], float] = time.time,
        node_transport: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.db = db
        self.settings = settings if settings is not None else load_settings()
        self.sender = sender
        self.clock = clock
        self.node_transport = node_transport
        self._needle: Optional[NeedleRuntime] = None
        self._preferences: Optional[PreferenceStore] = None
        self._reasoner: Optional[ReasonerBridge] = None
        self._node: Optional[MacNodeBridge] = None
        self._portal: Optional[GuestPortal] = None
        self._negotiator: Optional[Negotiator] = None
        self._peers: Dict[str, Dict[str, Peer]] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._counts = {"handled": 0, "a2a": 0, "cards": 0, "approvals": 0, "ics": 0, "errors": 0}
        self.errors: List[Dict[str, Any]] = []

    # ------------------------------------------------------------ 协作对象
    @property
    def needle(self) -> NeedleRuntime:
        if self._needle is None:
            self._needle = NeedleRuntime(self.settings)
        return self._needle

    @property
    def preferences(self) -> PreferenceStore:
        if self._preferences is None:
            self._preferences = PreferenceStore(self.settings, clock=self.clock)
        return self._preferences

    @property
    def reasoner(self) -> ReasonerBridge:
        if self._reasoner is None:
            self._reasoner = ReasonerBridge(self.settings)
        return self._reasoner

    @property
    def node(self) -> MacNodeBridge:
        if self._node is None:
            self._node = MacNodeBridge(
                self.settings, transport=self.node_transport, db=self.db
            )
        return self._node

    @property
    def portal(self) -> GuestPortal:
        if self._portal is None:
            self._portal = GuestPortal(
                self.db,
                self.settings,
                availability=self._guest_availability,
                card_pusher=self._guest_card,
                clock=self.clock,
            )
        return self._portal

    @property
    def negotiator(self) -> Negotiator:
        if self._negotiator is None:
            self._negotiator = Negotiator(
                self.db,
                bridge=self.node,
                sender=self._send_peer_frame,
                clock=self.clock,
                key_provider=self.key_for_peer,
                identity=self.identity_for,
            )
        return self._negotiator

    def bind_loop(self) -> asyncio.AbstractEventLoop:
        """记下事件循环，让同步回调（访客门户推卡片）能把消息投回同一条链路。"""
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None
        return self._loop

    def close(self) -> None:
        """卸载权重；由 ``StudioStack.stop()`` 调用。"""
        if self._needle is not None:
            try:
                self._needle.unload()
            except Exception as exc:  # noqa: BLE001 - 关停路径上的异常只记录
                self._fail("unload", exc)

    # ------------------------------------------------------------ 配置与身份
    def config_for(self, bot_id: str, config: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """插件传下来的配置（已脱敏）优先，其次账本里该 Bot 的插件配置。"""
        merged = dict(DEFAULT_CONFIG)
        stored: Mapping[str, Any] = {}
        if self.db is not None:
            try:
                _enabled, stored = self.db.effective_plugin_config(PLUGIN_ID, bot_id) or (False, {})
            except Exception as exc:  # noqa: BLE001 - 配置读不到就退回默认，不能让消息卡死
                self._fail("plugin_config", exc)
        for source in (stored, config):
            for key, value in dict(source or {}).items():
                if key in DEFAULT_CONFIG and value is not None:
                    merged[key] = value
        merged["enabled"] = bool(merged["enabled"])
        merged["send_invite"] = bool(merged["send_invite"])
        merged["handle_a2a"] = bool(merged["handle_a2a"])
        merged["min_confidence"] = min(1.0, max(0.0, _number(merged["min_confidence"], DEFAULT_MIN_CONFIDENCE)))
        merged["max_slots"] = int(min(8, max(1, _number(merged["max_slots"], DEFAULT_MAX_SLOTS))))
        merged["owner_chat"] = self._owner_ref(merged["owner_chat"])
        return merged

    def _owner_ref(self, raw: Any) -> str:
        ref = _clean(raw, 32)
        if not ref:
            return ""
        try:
            chat_type, chat_id = parse_chat_ref(ref)
        except Exception:  # noqa: BLE001 - 坏引用等价于「没配主人会话」
            return ""
        return f"{'#' if chat_type == 'group' else '@'}{chat_id}"

    def owner_chat(self, bot_id: str, config: Optional[Mapping[str, Any]] = None) -> str:
        return str(self.config_for(bot_id, config)["owner_chat"])

    def bot(self, bot_id: str) -> Dict[str, Any]:
        if self.db is None or not bot_id:
            return {}
        try:
            return dict(self.db.get_bot(bot_id) or {})
        except Exception as exc:  # noqa: BLE001
            self._fail("get_bot", exc)
            return {}

    def locale_for(self, bot_id: str, prefs: Optional[Mapping[str, Any]] = None) -> str:
        row = prefs if prefs is not None else self.preferences.load(bot_id)
        return normalize_locale(str(row.get("locale") or "") or self.settings.default_locale)

    def zone_for(self, bot_id: str, prefs: Optional[Mapping[str, Any]] = None) -> str:
        row = prefs if prefs is not None else self.preferences.load(bot_id)
        zone = _clean(row.get("timezone"), 64)
        if zone and self._zone_ok(zone):
            return zone
        return "UTC"

    @staticmethod
    def _zone_ok(zone: str) -> bool:
        try:
            ZoneInfo(zone)
        except Exception:  # noqa: BLE001 - 含 ZoneInfoNotFoundError 与 tzdata 缺失
            return False
        return True

    # ------------------------------------------------------------ 对端配对
    def peers_path(self, bot_id: str) -> Path:
        return Path(self.settings.agent_dir(bot_id)) / PEERS_FILE_NAME

    def load_peers(self, bot_id: str, *, refresh: bool = False) -> Dict[str, Peer]:
        owner = _clean(bot_id, 64)
        if owner in self._peers and not refresh:
            return self._peers[owner]
        table: Dict[str, Peer] = {}
        try:
            raw = json.loads(self.peers_path(owner).read_text(encoding="utf-8"))
        except FileNotFoundError:
            raw = {}
        except (OSError, ValueError) as exc:
            self._fail("peers_read", exc)
            raw = {}
        entries = raw.get("peers") if isinstance(raw, Mapping) else None
        for item in list(entries or []):
            if not isinstance(item, Mapping):
                continue
            identity = _clean(item.get("identity"), PEER_REF_MAX)
            if not identity:
                continue
            table[identity] = Peer(
                identity=identity,
                key=_clean(item.get("key"), 128),
                label=_clean(item.get("label"), 80),
                chat=self._owner_ref(item.get("chat")),
            )
        self._peers[owner] = table
        return table

    def save_peers(self, bot_id: str, peers: Mapping[str, Peer]) -> None:
        owner = _clean(bot_id, 64)
        table = {str(key): value for key, value in peers.items()}
        self._peers[owner] = table
        payload = {
            "version": 1,
            "bot_id": owner,
            "updated_at": now_iso(),
            "peers": [peer.as_dict(secret=True) for peer in sorted(table.values(), key=lambda row: row.identity)],
        }
        path = self.peers_path(owner)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(f".{secrets.token_hex(4)}.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        tmp.chmod(SECURE_FILE_MODE)
        tmp.replace(path)

    def pair_peer(
        self,
        bot_id: str,
        identity: str,
        *,
        key: str = "",
        label: str = "",
        chat: str = "",
    ) -> Peer:
        clean_id = _clean(identity, PEER_REF_MAX)
        if not clean_id:
            raise ValueError("对端身份不能为空")
        clean_chat = self._owner_ref(chat)
        if chat and not clean_chat:
            raise ValueError(f"会话引用非法：{chat!r}")
        peers = self.load_peers(bot_id, refresh=True)
        peer = peers.get(clean_id) or Peer(identity=clean_id)
        peer.key = _clean(key, 128) or peer.key
        peer.label = _clean(label, 80) or peer.label
        peer.chat = clean_chat or peer.chat
        peers[clean_id] = peer
        self.save_peers(bot_id, peers)
        return peer

    def unpair_peer(self, bot_id: str, identity: str) -> bool:
        peers = self.load_peers(bot_id, refresh=True)
        hit = self.peer(bot_id, identity)
        if hit is None or hit.identity not in peers:
            return False
        del peers[hit.identity]
        self.save_peers(bot_id, peers)
        return True

    def peer(self, bot_id: str, identity_or_chat: str) -> Optional[Peer]:
        wanted = _clean(identity_or_chat, PEER_REF_MAX)
        if not wanted:
            return None
        peers = self.load_peers(bot_id)
        hit = peers.get(wanted)
        if hit is not None:
            return hit
        token = wire_identity(wanted)
        hit = next((item for item in peers.values() if wire_identity(item.identity) == token), None)
        if hit is not None:
            return hit
        return next((item for item in peers.values() if item.chat and item.chat == wanted), None)

    def peer_for_chat(self, bot_id: str, chat_ref: str) -> Optional[Peer]:
        return self.peer(bot_id, chat_ref)

    def identity_for_peer(self, bot_id: str, chat_ref: str) -> str:
        """入站帧的合法身份来源：只认配对表；没配对就返回空串，帧被拒。"""
        hit = self.peer_for_chat(bot_id, chat_ref)
        return hit.wire if hit else ""

    def peer_chat_for_identity(self, bot_id: str, identity: str) -> str:
        """外发帧的目的地：配对表里的 chat 优先，其次把身份本身当作会话引用。"""
        hit = self.peer(bot_id, identity)
        if hit is not None and hit.chat:
            return hit.chat
        wanted = _clean(identity, PEER_REF_MAX)
        return wanted if wanted[:1] in ("@", "#") and self._owner_ref(wanted) else ""

    def identity_for(self, bot_id: str) -> str:
        """本方在帧里的身份：自己的 SMP 联系人地址，退化为 bot_id。"""
        return _clean(self.bot(bot_id).get("contact_address"), 160) or _clean(bot_id, 160)

    def key_for_peer(self, peer_identity: str) -> bytes:
        """显式配对的密钥优先；没配密钥的双方各自从 A2A 主密钥派生，永不现场随机。

        派生用的是 :func:`wire_identity` 之后的身份，因此同一次配对在本机永远得到同一把
        钥匙。跨实例协商要真正验得上，得在配对时把会话密钥交换过去（``pair_peer(key=…)``）：
        ``STUDIO_A2A_SECRET`` 是每台安装各自生成的，两边不可能凭空算出同一个值。
        """
        wanted = _clean(peer_identity, PEER_REF_MAX)
        if not wanted:
            raise ValueError("缺少对端身份，无法取协商密钥")
        token = wire_identity(wanted)
        for table in self._peers.values():
            for peer in table.values():
                if peer.key and peer.wire == token:
                    return peer.key.encode("utf-8")
        seed = f"ppx-a2a\0{self.settings.ensure_a2a_secret()}\0{token}".encode("utf-8")
        return hashlib.sha256(seed).digest()

    def peer_label(self, bot_id: str, identity: str) -> str:
        hit = self.peer(bot_id, identity)
        if hit is not None and hit.label:
            return hit.label
        return _clean(identity, 40) or "POPOPX"

    # ---------------------------------------------------------------- 发送
    async def _send(
        self,
        bot_id: str,
        chat_ref: str,
        text: str = "",
        *,
        content: Optional[Dict[str, Any]] = None,
        file_path: str = "",
    ) -> bool:
        if self.sender is None or not chat_ref or (not text and content is None):
            return False
        try:
            await self.sender(bot_id, chat_ref, text, content=content, file_path=file_path)
            return True
        except Exception as exc:  # noqa: BLE001 - 一条消息发不出去不该让整条链路失败
            self._fail("send", exc, bot_id=bot_id)
            return False

    async def _send_peer_frame(self, bot_id: str, peer_identity: str, text: str) -> Dict[str, Any]:
        """:class:`app.a2a.Negotiator` 的 sender 出口：身份 → 会话引用。"""
        chat = self.peer_chat_for_identity(bot_id, peer_identity)
        if not chat:
            raise LookupError(f"对端 {peer_identity!r} 没有可用的会话引用")
        if not await self._send(bot_id, chat, text):
            raise RuntimeError("A2A 帧发送失败")
        self._counts["a2a"] += 1
        return {"bot_id": bot_id, "chat_ref": chat, "delivered": True}

    # ------------------------------------------------------------- 空档计算
    def _window(
        self,
        args: Mapping[str, Any],
        *,
        zone: str,
        prefs: Mapping[str, Any],
        now: float,
    ) -> Tuple[float, float]:
        day = _clean(args.get("date"), 10)
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
            anchor = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=ZoneInfo(zone))
            return anchor.timestamp(), anchor.timestamp() + 86400.0
        negotiation = dict(prefs.get("negotiation") or {})
        fallback = int(min(30, max(1, _number(negotiation.get("window_days"), DEFAULT_WINDOW_DAYS))))
        window_days = int(min(30, max(1, _number(args.get("window_days"), fallback))))
        return now, now + window_days * 86400.0

    async def free_slots(
        self,
        bot_id: str,
        args: Optional[Mapping[str, Any]] = None,
        *,
        prefs: Optional[Mapping[str, Any]] = None,
        timezone: str = "",
    ) -> SlotResult:
        """掩码忙表 → 空闲段 → 会议时长裁剪 → 主人偏好过滤 → 关键词排序 → 当日配额。"""
        args = dict(args or {})
        row = dict(prefs) if prefs is not None else dict(self.preferences.load(bot_id))
        zone = _clean(timezone or args.get("timezone"), 64) or self.zone_for(bot_id, row)
        if not self._zone_ok(zone):
            zone = self.zone_for(bot_id, row)
        duration = _minutes(args.get("duration_minutes"), DEFAULT_DURATION_MINUTES)
        now = float(self.clock())
        lo, hi = self._window(args, zone=zone, prefs=row, now=now)
        day = _clean(args.get("date"), 10)
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
            day = datetime.fromtimestamp(lo, ZoneInfo(zone)).date().isoformat()
        busy = await self.node.availability(day, timezone=zone, window=(lo, hi), bot_id=bot_id)
        truth = self.node.status()
        reason = _clean(truth.get("last_reason"), 60)
        # last_reason 清空才代表「这一刻从 Mac Node 现读」；有原因还带着数据，那是回退缓存。
        source = "mac_node" if not reason else (CACHE_SOURCE if busy else "none")
        if reason and not busy:
            return SlotResult([], source, False, reason, busy=0)
        candidates: List[Dict[str, Any]] = []
        step = SLOT_STEP_MINUTES * 60.0
        for gap in free_from_busy(busy, window=(lo, hi), timezone=zone, min_minutes=duration):
            gap_lo = float(gap["start"])
            last = float(gap["end"]) - duration * 60.0
            starts = [gap_lo] if gap_lo <= last else []
            grid = gap_lo + (-gap_lo) % step
            if grid <= gap_lo:
                grid += step
            while grid <= last:
                starts.append(grid)
                grid += step
            for start in starts:
                if len(candidates) >= MAX_CANDIDATES:
                    break
                candidates.append({
                    "start": float(start),
                    "end": float(start) + duration * 60.0,
                    "tz": zone,
                    "free": True,
                })
        # 抽取里带了明确钟点时，以它为锚点：偏好关键词仍是第一排序（rank 是稳定排序），
        # 关键词同分或无关键词时才体现「离主人说的时间最近」。
        wanted = _wanted_ts(args.get("time"), lo, hi, zone)
        if wanted:
            candidates.sort(key=lambda item: abs(float(item["start"]) - wanted))
        applied = self.preferences.apply(row, candidates, now=now, include_rejected=True)
        kept = [item for item in applied if not item.get("rejected")]
        ranked = self.preferences.rank(row, kept)
        within = self.preferences.daily_quota(row, ranked)
        slots = [
            {
                "start": float(item["start"]),
                "end": float(item["end"]),
                "tz": str(item.get("tz") or zone),
                "free": True,
            }
            for item in within
            if item.get("start") and item.get("end")
        ]
        return SlotResult(
            slots,
            source,
            bool(slots),
            "" if slots else (reason or "no_slots"),
            busy=len(list(busy or [])),
            rejected=len(applied) - len(kept),
        )

    def masked_slots(
        self,
        result: SlotResult,
        *,
        timezone: str,
        limit: int = DEFAULT_MAX_SLOTS,
    ) -> List[Dict[str, Any]]:
        """给对端的东西永远先过一遍掩码投影。"""
        return mask_slots(result.slots[: max(0, int(limit))], timezone=timezone)

    # ------------------------------------------------------------- 话术出口
    async def compose(self, kind: str, facts: Mapping[str, Any], locale: str) -> str:
        """大模型只负责措辞；未启用或失败时退回本地模板，永远有话说。

        :class:`ReasonerBridge` 自己已经把「开关关闭 / URL 非法 / 传输失败 / 响应没有正文」
        全部降级成模板，所以这里只需要再核对一次来源：模板也拿不到就留空串，
        让调用方看见「这句话确实没生成」，而不是编排层再编一句。
        """
        clean = dict(facts or {})
        result = await self.reasoner.outcome(kind, clean, locale=locale)
        text = _clean(result.text, 4000)
        if text:
            return text
        return _clean(render_copy(kind, clean, locale=self.reasoner.resolve_locale(locale)), 4000)

    # --------------------------------------------------------------- 主流程
    async def handle_message(
        self,
        bot_id: str,
        message: Any,
        config: Optional[Mapping[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """替身机器人对一条入站消息的全部判断；``None`` 表示「不归我管」。"""
        cfg = self.config_for(bot_id, config)
        text = _field(message, "text").strip()
        chat_ref = self._owner_ref(_field(message, "chat_ref") or _field(message, "chat_id"))
        if not cfg["enabled"] or not text.strip() or not chat_ref:
            return None
        self.bind_loop()

        # 机器回执（::CB:: / ::REF:: / ::SSO_SCAN::）只有编排层认得。放任它流到别的插件，
        # 机器人的话就会被当成主人说的话再回答一遍。
        if is_uplink_text(text):
            reply = await self.handle_callback(bot_id, text, chat_ref=chat_ref)
            self._counts["handled"] += 1
            return _decision("callback", reply)

        if text.strip().startswith(A2A_PREFIX):
            if not cfg["handle_a2a"]:
                return None
            out = await self.handle_a2a(bot_id, text, chat_ref=chat_ref, config=cfg)
            self._counts["handled"] += 1
            return _decision(
                "a2a",
                out.get("reply", ""),
                negotiation_id=out.get("negotiation_id", ""),
                reason=out.get("reason", ""),
            )

        prefs = self.preferences.load(bot_id)
        locale = self.locale_for(bot_id, prefs)
        zone = self.zone_for(bot_id, prefs)
        extraction = self.needle.extract(
            text, locale=locale, hints={"timezone": zone, "now": float(self.clock())}
        )
        self._audit_needle(bot_id, chat_ref, extraction)
        call = self._pick(extraction, cfg["min_confidence"])
        if call is None:
            return None
        actor = {
            "bot_id": bot_id,
            "chat_ref": chat_ref,
            "chat_type": _clean(_field(message, "chat_type", "direct"), 16) or "direct",
            "peer": _clean(_field(message, "sender_name") or _field(message, "sender"), 80) or chat_ref,
            "locale": locale,
            "zone": zone,
            "prefs": prefs,
            "config": cfg,
        }
        self._counts["handled"] += 1
        try:
            if call.name == GET_AVAILABILITY:
                return await self._answer_availability(call, actor)
            if call.name == PROPOSE_CREATE:
                return await self._propose_create(call, actor)
            if call.name == PROPOSE_RESCHEDULE:
                return await self._propose_change(call, actor, "reschedule")
            if call.name == PROPOSE_CANCEL:
                return await self._propose_change(call, actor, "cancel")
            if call.name == SUMMARIZE_FILE:
                return await self._summarize(call, actor)
        except Exception as exc:  # noqa: BLE001 - 编排失败就把这条消息交回普通链路
            self._fail("handle", exc, bot_id=bot_id)
        return None

    @staticmethod
    def _pick(extraction: Extraction, min_confidence: float) -> Optional[ToolCall]:
        """只接受本机已知工具、且置信度过线的抽取结果。"""
        for call in extraction.calls:
            if call.name in TOOL_NAMES and float(call.confidence) >= min_confidence:
                return call
        return None

    def _audit_needle(self, bot_id: str, chat_ref: str, extraction: Extraction) -> None:
        if self.db is None or not extraction.calls:
            return
        call = extraction.calls[0]
        self._audit(
            "needle",
            "extract",
            bot_id=bot_id,
            chat_ref=chat_ref,
            level="info" if not extraction.degraded else "warn",
            detail=f"{call.name} conf={float(call.confidence):.2f}",
            data={
                "engine": extraction.engine,
                "intent": extraction.intent,
                "calls": len(extraction.calls),
                "error": _clean(extraction.error, 200),
            },
            latency_ms=float(extraction.latency_ms or 0.0),
        )

    # -------------------------------------------------------- 各工具的处理
    async def _answer_availability(self, call: ToolCall, actor: Dict[str, Any]) -> Dict[str, Any]:
        cfg = actor["config"]
        result = await self.free_slots(actor["bot_id"], call.arguments, prefs=actor["prefs"])
        slots = result.slots[: cfg["max_slots"]]
        lines = [slot_line(float(item["start"]), float(item["end"]), str(item.get("tz") or actor["zone"])) for item in slots]
        facts = {
            "sender": actor["peer"],
            "duration": _minutes(call.arguments.get("duration_minutes"), DEFAULT_DURATION_MINUTES),
            "options": "\n".join(lines),
            "timezone": actor["zone"],
            "window": f"{int(_number(call.arguments.get('window_days'), DEFAULT_WINDOW_DAYS))}d",
        }
        reply = await self.compose("availability_answer" if slots else "availability_none", facts, actor["locale"])
        if result.source != "mac_node":
            self._audit(
                "calendar",
                "availability_degraded",
                bot_id=actor["bot_id"],
                level="warn",
                chat_ref=actor["chat_ref"],
                detail=f"来源 {result.source}，原因 {result.reason or '-'}",
                data={"busy": result.busy, "rejected": result.rejected},
            )
        return _decision("availability", reply, engine=call.engine, source=result.source, slots=len(slots))

    async def _propose_create(self, call: ToolCall, actor: Dict[str, Any]) -> Dict[str, Any]:
        args = dict(call.arguments)
        zone = _clean(args.get("timezone"), 64) or actor["zone"]
        duration = _minutes(args.get("duration_minutes"), DEFAULT_DURATION_MINUTES)
        title = _clean(args.get("title"), TITLE_MAX) or translate("admin", actor["locale"], "agent_card_title")
        result = await self.free_slots(
            actor["bot_id"], {**args, "timezone": zone, "duration_minutes": duration}, prefs=actor["prefs"]
        )
        if not result.slots:
            reply = await self.compose(
                "availability_none",
                {"sender": actor["peer"], "window": f"{int(_number(args.get('window_days'), DEFAULT_WINDOW_DAYS))}d"},
                actor["locale"],
            )
            return _decision("create_none", reply, source=result.source, reason=result.reason)
        start, end = _span(result.slots[0], duration)
        attendees = _attendees(args.get("attendees"))
        # 有明确同行人时，卡片与 .ics 都发给那个会话；否则只走主人会话。
        proposal = self._create_proposal(
            actor,
            "create",
            source="direct",
            zone=zone,
            start=start,
            end=end,
            duration=duration,
            summary=title,
            chat_ref=attendees[0] if attendees else _clean(actor.get("chat_ref"), 32),
            payload={
                "title": title,
                "attendees": attendees,
                "note": _clean(args.get("note"), 500),
                "engine": call.engine,
                "requested": dict(args),
                "candidates": len(result.slots),
            },
        )
        if proposal is None:
            return _decision("create_failed", translate("admin", actor["locale"], "agent_create_failed"))
        pid = str(proposal["proposal_id"])
        pushed = await self.push_proposal_card(
            actor["bot_id"], pid, title=title, peer=actor["peer"], zone=zone, locale=actor["locale"],
            config=actor.get("config"),
        )
        reply = await self.compose(
            "proposal_pending",
            {"title": title, "start": wall_text(start, zone), "end": wall_text(end, zone), "timezone": zone},
            actor["locale"],
        )
        if not pushed:
            reply = f"{reply}\n{translate('admin', actor['locale'], 'agent_need_owner')}"
        return _decision("create", reply, proposal_id=pid, card=pushed, source=result.source)

    async def _propose_change(self, call: ToolCall, actor: Dict[str, Any], action: str) -> Dict[str, Any]:
        args = dict(call.arguments)
        zone = _clean(args.get("timezone"), 64) or actor["zone"]
        ref = _clean(args.get("reference"), 128)
        target = await self._find_booking(actor["bot_id"], ref, zone, prefs=actor["prefs"])
        if target is None:
            return _decision(
                f"{action}_not_found",
                translate("admin", actor["locale"], "agent_booking_not_found", ref=ref or "-"),
                reference=ref,
                reason="not_found",
            )
        from_start = float(target.get("start") or self.clock())
        from_end = float(target.get("end") or from_start + DEFAULT_DURATION_MINUTES * 60.0)
        duration = _minutes(args.get("duration_minutes"), max(5, int((from_end - from_start) / 60)))
        title = _clean(target.get("summary") or ref, TITLE_MAX)
        if action == "cancel":
            to_start, to_end = 0.0, 0.0
            summary = f"{translate('admin', actor['locale'], 'agent_cancel_prefix')} {title}".strip()
        else:
            result = await self.free_slots(
                actor["bot_id"], {**args, "timezone": zone, "duration_minutes": duration}, prefs=actor["prefs"]
            )
            if not result.slots:
                reply = await self.compose(
                    "availability_none", {"sender": actor["peer"], "window": zone}, actor["locale"]
                )
                return _decision("reschedule_none", reply, reference=ref, reason=result.reason)
            to_start, to_end = _span(result.slots[0], duration)
            summary = title
        proposal = self._create_proposal(
            actor,
            action,
            source="direct",
            zone=zone,
            start=to_start,
            end=to_end,
            duration=duration,
            summary=summary,
            chat_ref="",
            node_event_id=_clean(target.get("event_id"), 128) or ref,
            payload={
                "title": title,
                "booking_ref_id": _clean(target.get("event_id"), 128) or ref,
                "from_start": from_start,
                "from_end": from_end,
                "engine": call.engine,
                "requested": dict(args),
            },
        )
        if proposal is None:
            return _decision(f"{action}_failed", translate("admin", actor["locale"], "agent_create_failed"))
        pid = str(proposal["proposal_id"])
        pushed = await self.push_proposal_card(
            actor["bot_id"], pid, title=summary, peer=actor["peer"], zone=zone, locale=actor["locale"],
            config=actor.get("config"),
        )
        # 提案还没被主人点头，话术只能是「待确认」，不能提前用法务实的改期/取消措辞。
        pending = {
            "title": title if action == "reschedule" else summary,
            "start": wall_text(to_start if action == "reschedule" else from_start, zone),
            "end": wall_text(to_end if action == "reschedule" else from_end, zone),
            "timezone": zone,
        }
        reply = await self.compose("proposal_pending", pending, actor["locale"])
        if not pushed:
            reply = f"{reply}\n{translate('admin', actor['locale'], 'agent_need_owner')}"
        return _decision(action, reply, proposal_id=pid, card=pushed)

    async def _find_booking(
        self, bot_id: str, ref: str, zone: str, *, prefs: Optional[Mapping[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """把 Needle 的引用回查成一条真实预订：后续提案绝不能指向不存在的事件。

        节点侧的忙表是掩码的（只有 start/end/busy，没有主题），所以「按标题找人」只能回到
        本机账本里查 —— 这也正好把可改可撤的范围限定在本 Studio 自己订下的会面。
        """
        if not ref:
            return None
        wanted = _clean(ref, 128)
        rows = await self.node.bookings(bot_id=bot_id)
        for item in list(rows or []):
            booking_ref = _clean(item.get("booking_ref_id"), 128)
            if booking_ref and (booking_ref == wanted or wanted in booking_ref):
                return {
                    "event_id": booking_ref,
                    "start": float(item.get("start") or 0),
                    "end": float(item.get("end") or 0),
                    "summary": "",
                }
        if self.db is None:
            return None
        try:
            proposals = self.db.list_proposals(bot_id, status="approved", limit=50)
        except Exception as exc:  # noqa: BLE001
            self._fail("list_proposals", exc, bot_id=bot_id)
            return None
        for row in list(proposals or []):
            summary = _clean(row.get("summary"), TITLE_MAX)
            payload = dict(row.get("payload") or {})
            booking_ref = _clean(row.get("node_event_id") or payload.get("booking_ref_id"), 128)
            if not booking_ref:
                continue
            if summary and (summary == wanted or wanted in summary):
                return {
                    "event_id": booking_ref,
                    "start": float(row.get("start_ts") or 0),
                    "end": float(row.get("end_ts") or 0),
                    "summary": summary,
                }
        return None

    async def _summarize(self, call: ToolCall, actor: Dict[str, Any]) -> Dict[str, Any]:
        args = dict(call.arguments)
        facts = summarize_workspace_file(
            self.settings,
            actor["bot_id"],
            str(args.get("file_ref") or args.get("file_name") or ""),
            max_items=int(min(MAX_SUMMARY_ITEMS, max(1, _number(args.get("max_items"), 6)))),
        )
        locale = actor["locale"]
        if not facts.get("ok"):
            files = ", ".join(facts.get("available") or []) or "-"
            reply = (
                f"{translate('admin', locale, 'agent_file_unreadable', reason=_clean(facts.get('reason'), 24))}\n"
                f"{translate('admin', locale, 'agent_file_available', files=files)}"
            )
            return _decision("summarize_empty", reply, reason=_clean(facts.get("reason"), 24))
        return _decision(
            "summarize",
            await self.compose("meeting_summary", facts, locale),
            file_name=facts["file_name"],
            items=int(facts.get("items") or 0),
        )

    # ------------------------------------------------------------- 提案与卡片
    def _create_proposal(
        self,
        actor: Mapping[str, Any],
        action: str,
        *,
        source: str,
        zone: str,
        start: float,
        end: float,
        duration: int,
        summary: str,
        chat_ref: str,
        payload: Dict[str, Any],
        node_event_id: str = "",
        negotiation_id: str = "",
    ) -> Optional[Dict[str, Any]]:
        if self.db is None:
            return None
        try:
            proposal = self.db.create_proposal(
                str(actor.get("bot_id") or ""),
                action,
                source=source,
                chat_type=str(actor.get("chat_type") or "direct"),
                chat_ref=chat_ref,
                counterparty=_clean(actor.get("peer"), 80),
                timezone=zone,
                start_ts=start,
                end_ts=end,
                duration_minutes=duration,
                summary=_clean(summary, TITLE_MAX),
                payload=payload,
                negotiation_id=negotiation_id,
            )
            if node_event_id:
                proposal = self.db.update_proposal(str(proposal["proposal_id"]), node_event_id=node_event_id)
            self._audit(
                "lifecycle",
                "proposal_created",
                bot_id=str(actor.get("bot_id") or ""),
                proposal_id=str(proposal["proposal_id"]),
                chat_ref=chat_ref,
                detail=f"{action} {slot_line(start, end, zone) if start else 'cancel'}",
                data={"source": source, "duration": duration},
            )
            return proposal
        except Exception as exc:  # noqa: BLE001 - 建不出提案就没有卡片，上层换文案
            self._fail("create_proposal", exc, bot_id=str(actor.get("bot_id") or ""))
            return None

    async def push_proposal_card(
        self,
        bot_id: str,
        proposal_id: str,
        *,
        title: str = "",
        peer: str = "",
        zone: str = "",
        locale: str = "",
        body: str = "",
        config: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """把确认卡片发往主人会话。没配对主人会话时宁可不发，也绝不发给陌生人。"""
        if self.db is None or not proposal_id:
            return False
        record = self.db.get_proposal(proposal_id)
        if record is None or str(record.get("bot_id")) != str(bot_id):
            return False
        row = self.preferences.load(bot_id)
        language = normalize_locale(locale or self.locale_for(bot_id, row))
        zone = zone or _clean(record.get("timezone"), 64) or self.zone_for(bot_id, row)
        start = float(record.get("start_ts") or 0)
        end = float(record.get("end_ts") or start)
        minutes = int(record.get("duration_minutes") or max(1, int((end - start) / 60)))
        heading = _clean(title or record.get("summary"), TITLE_MAX)
        card_title = _clean(translate("admin", language, "agent_card_title"), 120)
        card_body = body or translate(
            "admin",
            language,
            "agent_card_body",
            summary=heading,
            when=slot_line(start, end, zone) if start else translate("admin", language, "agent_cancel_prefix"),
            duration=minutes,
        )
        fields = [
            {
                "k": translate("admin", language, "agent_field_time"),
                "v": slot_line(start, end, zone) if start else translate("admin", language, "agent_cancel_prefix"),
            },
            {"k": translate("admin", language, "agent_field_duration"), "v": f"{minutes} min"},
            {"k": translate("admin", language, "agent_field_with"), "v": _clean(peer or record.get("counterparty") or "-", 60)},
            {"k": translate("admin", language, "agent_field_source"), "v": _clean(record.get("source"), 20) or "direct"},
            {"k": translate("admin", language, "agent_field_zone"), "v": _clean(zone, 40) or "UTC"},
        ]
        try:
            _card, frame = proposal_card(
                self.db,
                record,
                title=card_title,
                body=_clean(card_body, 2000),
                fields=fields,
                visible_text=card_title,
                approve_label=translate("admin", language, "agent_yes"),
                decline_label=translate("admin", language, "agent_no"),
                alt_label=translate("admin", language, "agent_alt"),
                ttl_seconds=CARD_TTL_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001 - 帧造不出来就如实失败，让上层换文案
            self._fail("proposal_card", exc, bot_id=bot_id)
            return False
        target = self.owner_chat(bot_id, config)
        if not target:
            self._audit(
                "card",
                "card_not_pushed",
                bot_id=bot_id,
                level="warn",
                proposal_id=proposal_id,
                detail="未配置主人会话（owner_chat），卡片无处可发",
            )
            return False
        if not await self._send(bot_id, target, frame):
            return False
        payload = dict(record.get("payload") or {})
        payload.update({"card_text": frame, "card_chat": target})
        try:
            self.db.update_proposal(proposal_id, payload=payload)
        except Exception as exc:  # noqa: BLE001 - 卡片已经发出去了，补记失败只留痕
            self._fail("card_payload", exc, bot_id=bot_id)
        self._counts["cards"] += 1
        self._audit("card", "card_pushed", bot_id=bot_id, proposal_id=proposal_id, chat_ref=target,
                    detail=f"卡片发往 {target}")
        return True

    async def handle_callback(self, bot_id: str, text: str, *, chat_ref: str = "") -> str:
        """处理主人点卡片带回来的 ``::CB::ppxok_<proposal_id>`` 一类单行回执。"""
        parsed = parse_callback(text)
        if parsed is None:
            return ""
        kind, ref = parsed
        if kind not in (CALLBACK_APPROVE, CALLBACK_DECLINE, CALLBACK_ALT):
            return ""
        if self.db is None:
            return ""
        record = self.db.get_proposal(ref)
        row = self.preferences.load(bot_id)
        language = self.locale_for(bot_id, row)
        if record is None or str(record.get("bot_id")) != str(bot_id):
            self._audit(
                "card",
                "callback_unknown",
                bot_id=bot_id,
                level="warn",
                chat_ref=chat_ref,
                proposal_id=ref,
                detail="回执指向不存在或不属于本 Bot 的提案",
            )
            return translate("admin", language, "agent_expired")
        if str(record.get("status")) != "pending":
            return translate("admin", language, "agent_already")
        if kind == CALLBACK_DECLINE:
            await self.approve(bot_id, ref, chat_ref=chat_ref, locale=language, decision="decline")
            return translate("admin", language, "agent_declined")
        if kind == CALLBACK_ALT:
            await self.approve(bot_id, ref, chat_ref=chat_ref, locale=language, decision="alternative")
            result = await self.free_slots(bot_id, {}, prefs=row)
            slots = result.slots[:DEFAULT_MAX_SLOTS]
            if not slots:
                return await self.compose(
                    "availability_none",
                    {"sender": _clean(record.get("counterparty"), 60) or "-", "window": self.zone_for(bot_id, row)},
                    language,
                )
            lines = [
                slot_line(float(item["start"]), float(item["end"]), str(item.get("tz") or self.zone_for(bot_id, row)))
                for item in slots
            ]
            return await self.compose(
                "availability_answer",
                {
                    "sender": _clean(record.get("counterparty"), 60) or "-",
                    "duration": int(record.get("duration_minutes") or DEFAULT_DURATION_MINUTES),
                    "options": "\n".join(lines),
                    "timezone": self.zone_for(bot_id, row),
                    "window": self.zone_for(bot_id, row),
                },
                language,
            )
        return await self.approve(bot_id, ref, chat_ref=chat_ref, locale=language)

    async def approve(
        self,
        bot_id: str,
        proposal_id: str,
        *,
        chat_ref: str = "",
        locale: str = "",
        decision: str = "approve",
    ) -> str:
        """写日历的唯一入口：先过 Mac Node，成功才谈邀请。``decision`` 让三个按钮共用一条链路。"""
        if self.db is None:
            return ""
        record = self.db.get_proposal(proposal_id)
        if record is None or str(record.get("bot_id")) != str(bot_id):
            return ""
        row = self.preferences.load(bot_id)
        language = normalize_locale(locale or self.locale_for(bot_id, row))
        zone = _clean(record.get("timezone"), 64) or self.zone_for(bot_id, row)
        start = float(record.get("start_ts") or 0)
        pid = str(record.get("proposal_id"))
        if decision == "decline":
            self.db.update_proposal(pid, status="declined")
            await self._close_card(bot_id, record, translate("admin", language, "agent_card_declined"))
            self._audit("lifecycle", "declined", bot_id=bot_id, proposal_id=pid, chat_ref=chat_ref)
            return translate("admin", language, "agent_declined")
        if decision == "alternative":
            self.db.update_proposal(pid, status="superseded")
            await self._close_card(bot_id, record, translate("admin", language, "agent_card_alternative"))
            self._audit("lifecycle", "alternative", bot_id=bot_id, proposal_id=pid, chat_ref=chat_ref)
            return ""

        outcome = await self.node.approve(dict(record))
        ok = bool(outcome.get("ok"))
        if ok:
            self._counts["approvals"] += 1
        self._audit(
            "mac_node",
            "approve" if ok else "approve_failed",
            bot_id=bot_id,
            level="info" if ok else "warn",
            proposal_id=pid,
            chat_ref=chat_ref,
            detail=f"{_clean(outcome.get('reason'), 40)} {json_safe(outcome.get('detail'))}"[:400],
            data={"ok": ok, "event_id": _clean(outcome.get("event_id"), 128)},
        )
        if not ok:
            await self._close_card(bot_id, record, translate("admin", language, "agent_card_failed"))
            return translate("admin", language, "agent_approve_failed",
                             reason=_clean(outcome.get("reason"), 40) or "-")
        fresh = self.db.get_proposal(pid) or record
        action = str(fresh.get("action") or "create")
        end = float(fresh.get("end_ts") or start)
        payload = dict(fresh.get("payload") or {})
        kind = {"reschedule": "reschedule_confirm", "cancel": "cancel_confirm"}.get(action, "create_confirm")
        reply = await self.compose(
            kind,
            {
                "title": _clean(fresh.get("summary"), TITLE_MAX),
                "start": wall_text(start, zone) if start else "-",
                "end": wall_text(end, zone) if end else "-",
                "from": wall_text(float(payload.get("from_start") or start), zone),
                "to": wall_text(start, zone) if start else "-",
                "timezone": zone,
            },
            language,
        )
        await self._close_card(
            bot_id,
            fresh,
            translate("admin", language, "agent_card_approved",
                      when=slot_line(start, end, zone) if start and action != "cancel" else wall_text(start, zone) if start else "-"),
        )
        if action != "cancel" and self.config_for(bot_id)["send_invite"]:
            if await self.deliver_invite(bot_id, fresh):
                reply = f"{reply}\n{translate('admin', language, 'agent_invite_sent', peer=_clean(fresh.get('counterparty'), 40) or '-')}"
        return reply

    async def _close_card(self, bot_id: str, record: Mapping[str, Any], title: str) -> bool:
        """把同一张卡片就地改成终态，主人不会再点到第二次按钮。"""
        payload = dict(record.get("payload") or {})
        chat = self.owner_chat(bot_id) or _clean(payload.get("card_chat"), 32)
        card_id = _clean(record.get("card_id"), 64)
        if not chat or not card_id:
            return False
        try:
            frame = status_card(
                {"id": card_id, "body": _clean(record.get("summary"), 2000)},
                title=_clean(title, 120),
            )
        except Exception as exc:  # noqa: BLE001
            self._fail("status_card", exc, bot_id=bot_id)
            return False
        return await self._send(bot_id, chat, frame)

    async def deliver_invite(self, bot_id: str, proposal: Mapping[str, Any]) -> bool:
        """把 .ics 邀请写进该 Bot 自己的 files 目录并发给对方（通道 A 与通道 B 共用）。"""
        if self.sender is None or self.db is None:
            return False
        pid = _clean(proposal.get("proposal_id"), 64)
        record = self.db.get_proposal(pid) if pid else dict(proposal or {})
        chat = _clean(record.get("chat_ref"), 32)
        if not chat:
            chat = self.peer_chat_for_identity(bot_id, _clean(record.get("counterparty"), PEER_REF_MAX))
        if not chat:
            self._audit("ics", "invite_no_recipient", bot_id=bot_id, level="warn", proposal_id=pid,
                        detail="提案没有可发送的会话")
            return False
        zone = _clean(record.get("timezone"), 64) or "UTC"
        start = float(record.get("start_ts") or 0)
        end = float(record.get("end_ts") or start + DEFAULT_DURATION_MINUTES * 60.0)
        payload = dict(record.get("payload") or {})
        title = _clean(record.get("summary") or payload.get("title"), TITLE_MAX) or "POPOPX meeting"
        link = _clean(payload.get("call_link") or self.meeting_link(bot_id, pid), 2048)
        locale = self.locale_for(bot_id)
        event = {
            "uid": event_uid("ppx-agent", pid or str(int(start))),
            "summary": title,
            "start_ts": start,
            "end_ts": end,
            "description": _clean(payload.get("note") or translate("admin", locale, "agent_invite_note"), 1000),
            "location": _clean(payload.get("location") or link, 500),
            "url": link,
            "categories": ("POPOPX",),
        }
        try:
            path = write_ics(self.settings, bot_id, title, start, build_calendar([event], calendar_name="POPOPX"))
        except Exception as exc:  # noqa: BLE001 - 落盘失败就不发附件，诚实返回
            self._fail("write_ics", exc, bot_id=bot_id)
            return False
        if pid:
            try:
                self.db.update_proposal(pid, ics_path=str(path))
            except Exception as exc:  # noqa: BLE001 - 文件已在磁盘上，记账失败只留痕
                self._fail("ics_path", exc, bot_id=bot_id)
        caption = f"{title} · {slot_line(start, end, zone)}"
        if not await self._send(bot_id, chat, content={"type": "file", "text": caption}, file_path=str(path)):
            self._audit("ics", "invite_failed", bot_id=bot_id, level="warn", proposal_id=pid, chat_ref=chat,
                        detail="文件发送失败")
            return False
        self._counts["ics"] += 1
        self._audit("ics", "invite_sent", bot_id=bot_id, proposal_id=pid, chat_ref=chat, detail=path.name)
        return True

    def meeting_link(self, bot_id: str, proposal_id: str) -> str:
        """会议地址：配了 ``meeting_base_url`` 才给，且永远带路径段，绝不给裸域名。"""
        base = _clean(self.settings.meeting_base_url, 512)
        if not base:
            return ""
        room = _clean(proposal_id, 64) or secrets.token_urlsafe(9)
        room = re.sub(r"[^A-Za-z0-9_.-]", "-", room)
        return f"{base.rstrip('/')}/{room}"

    # --------------------------------------------------------------- 通道 A
    async def handle_a2a(
        self,
        bot_id: str,
        text: str,
        *,
        chat_ref: str = "",
        config: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """处理一条 ``::POPOPX_A2A::`` 帧。未配对的对端只留审计，不进状态机。"""
        identity = self.identity_for_peer(bot_id, chat_ref)
        if not identity:
            self._audit(
                "a2a",
                "unpaired_frame",
                bot_id=bot_id,
                level="warn",
                chat_ref=chat_ref,
                negotiation_id=_clean(peek_negotiation_id(text), 64),
                detail="对端未配对，帧已忽略",
            )
            return {"handled": False, "reason": "unpaired", "negotiation_id": "", "reply": ""}
        row = self.preferences.load(bot_id)
        rounds = int(min(12, max(1, _number(dict(row.get("negotiation") or {}).get("rounds"), 6))))
        self.negotiator.max_rounds = rounds
        result = await self.negotiator.inbound(
            bot_id,
            text,
            peer_identity=identity,
            owner_tz=self.zone_for(bot_id, row),
            label=self.peer_label(bot_id, identity),
        )
        out: Dict[str, Any] = {
            "handled": bool(result.get("handled")),
            "reason": _clean(result.get("reason"), 40),
            "negotiation_id": _clean(result.get("negotiation_id"), 64),
            "status": _clean(result.get("status"), 32),
            "reply": "",
        }
        if not out["handled"]:
            return out
        locale = self.locale_for(bot_id, row)
        proposal = result.get("proposal")
        if isinstance(proposal, Mapping) and proposal.get("proposal_id"):
            pid = str(proposal["proposal_id"])
            out["proposal_id"] = pid
            zone = _clean(proposal.get("timezone"), 64) or self.zone_for(bot_id, row)
            peer = self.peer_label(bot_id, identity)
            summary = proposal_summary(peer, {"owner_text": slot_line(
                float(proposal.get("start_ts") or 0), float(proposal.get("end_ts") or 0), zone)}, tz=zone)
            pushed = await self.push_proposal_card(
                bot_id, pid, title=_clean(summary, TITLE_MAX), peer=peer, zone=zone, locale=locale
            )
            if pushed:
                out["reply"] = await self.compose(
                    "negotiation_converged",
                    {
                        "peer": peer,
                        "start": wall_text(float(proposal.get("start_ts") or 0), zone),
                        "duration": int(proposal.get("duration_minutes") or DEFAULT_DURATION_MINUTES),
                    },
                    locale,
                )
        elif out["status"] in ("rejected", "aborted"):
            out["reply"] = await self.compose(
                "negotiation_failed",
                {"peer": self.peer_label(bot_id, identity), "reason": out["reason"] or out["status"]},
                locale,
            )
        return out

    async def start_negotiation(
        self,
        bot_id: str,
        peer_identity: str,
        *,
        owner_slots: Sequence[Any] = (),
        duration_minutes: int = DEFAULT_DURATION_MINUTES,
        owner_tz: str = "",
        peer_tz: str = "",
        window: Sequence[float] = (),
        label: str = "",
        timezone: str = "",
        days: int = 0,
    ) -> Dict[str, Any]:
        """主人授权后主动起手（控制台「发起协商」与 ``calendar.propose_create`` 共用）。"""
        row = self.preferences.load(bot_id)
        negotiation = dict(row.get("negotiation") or {})
        zone = _clean(owner_tz or timezone, 64) or self.zone_for(bot_id, row)
        self.negotiator.max_rounds = int(min(12, max(1, _number(negotiation.get("rounds"), 6))))
        if not owner_slots:
            # 起手必须带自己的掩码空档：现算一次，绝不用编的。
            result = await self.free_slots(
                bot_id,
                {"timezone": zone, "duration_minutes": duration_minutes, "window_days": days or 0},
                prefs=row,
            )
            owner_slots = self.masked_slots(result, timezone=zone, limit=DEFAULT_MAX_SLOTS)
            if not owner_slots:
                return {"negotiation_id": "", "frame": "", "status": "no_slots", "reason": result.reason or "no_slots"}
        pair = [float(value) for value in tuple(window or ()) if str(value).strip() != ""]
        if len(pair) != 2:
            span = int(min(30, max(1, _number(negotiation.get("window_days") or days, DEFAULT_WINDOW_DAYS))))
            now = float(self.clock())
            pair = [now, now + span * 86400.0]
        identity = self.identity_for(bot_id)
        self.negotiator.set_identity(bot_id, identity)
        # SMP 地址里有 ``@``，a2a 的 id 字符集不允许：对端一律走 wire 形态。
        peer_row = self.peer(bot_id, peer_identity)
        wire = peer_row.wire if peer_row is not None else wire_identity(peer_identity)
        if not wire:
            return {"negotiation_id": "", "frame": "", "status": "no_peer", "reason": "empty_peer"}
        return await self.negotiator.start(
            bot_id,
            wire,
            owner_slots=list(owner_slots or []),
            duration_minutes=_minutes(duration_minutes, DEFAULT_DURATION_MINUTES),
            owner_tz=zone,
            peer_tz=_clean(peer_tz, 64),
            window=(pair[0], pair[1]),
            label=_clean(label or self.peer_label(bot_id, peer_identity), 80),
            owner_identity=identity,
        )

    async def expire(self) -> Dict[str, int]:
        """卡片与会话的 TTL 收尾：提案与协商分开计数。"""
        out = {"proposals": 0, "negotiations": 0}
        if self.db is not None:
            try:
                out["proposals"] = int(self.db.expire_proposals())
            except Exception as exc:  # noqa: BLE001
                self._fail("expire_proposals", exc)
        try:
            out["negotiations"] = int(await self.negotiator.expire_all())
        except Exception as exc:  # noqa: BLE001
            self._fail("expire_negotiations", exc)
        return out

    async def tick(self, context: Any = None) -> Dict[str, Any]:
        """插件的 ``on_tick`` 入口：卡片过期与会话过期各归各。"""
        out = await self.expire()
        out["handled"] = self._counts["handled"]
        return out

    # ----------------------------------------------------------- 通道 B 桥
    def _guest_availability(self, bot_id: str, text: str, zone_name: str) -> Awaitable[List[Dict[str, Any]]]:
        """访客门户要空档：走同一条掩码链路，只给 ``free`` 时段。"""

        async def run() -> List[Dict[str, Any]]:
            row = self.preferences.load(bot_id)
            zone = _clean(zone_name, 64) or self.zone_for(bot_id, row)
            result = await self.free_slots(bot_id, {"timezone": zone, "window_days": 3}, prefs=row)
            return [dict(item) for item in result.slots]

        return run()

    def _guest_card(self, bot_id: str, proposal: Dict[str, Any]) -> bool:
        """``card_pusher`` 是同步调的，而发送是异步的：有循环就跨线程投递，没有就自己跑一次。"""
        pid = _clean(proposal.get("proposal_id"), 64)
        frame = _clean(dict(proposal.get("payload") or {}).get("card_text"), 8192)
        chat = self.owner_chat(bot_id)
        if not frame or not chat:
            self._audit("card", "guest_card_dropped", bot_id=bot_id, level="warn", proposal_id=pid,
                        detail="缺少卡片帧或主人会话")
            return False
        loop = self._loop
        if loop is not None and loop.is_running():
            try:
                return bool(asyncio.run_coroutine_threadsafe(self._send(bot_id, chat, frame), loop).result(timeout=10.0))
            except Exception as exc:  # noqa: BLE001
                self._fail("guest_card", exc, bot_id=bot_id)
                return False
        try:
            return bool(asyncio.run(self._send(bot_id, chat, frame)))
        except Exception as exc:  # noqa: BLE001
            self._fail("guest_card", exc, bot_id=bot_id)
            return False

    # ------------------------------------------------------------- 状态出口
    def status(self) -> Dict[str, Any]:
        return {
            "plugin_id": PLUGIN_ID,
            "counts": dict(self._counts),
            "needle": dict(self.needle.status() or {}),
            "mac_node": dict(self.node.status() or {}),
            "reasoner": dict(self.reasoner.status() or {}),
            "peers": {
                bot_id: [peer.as_dict() for peer in sorted(table.values(), key=lambda row: row.identity)]
                for bot_id, table in sorted(self._peers.items())
            },
            "errors": list(self.errors[-10:]),
        }

    def bot_status(self, bot_id: str) -> Dict[str, Any]:
        row = self.preferences.load(bot_id)
        return {
            "bot_id": bot_id,
            "enabled": bool(self.config_for(bot_id)["enabled"]),
            "owner_chat": self.owner_chat(bot_id),
            "locale": self.locale_for(bot_id, row),
            "timezone": self.zone_for(bot_id, row),
            "preferences": self.preferences.summary(bot_id),
            "peers": [peer.as_dict() for peer in sorted(self.load_peers(bot_id).values(), key=lambda row: row.identity)],
            "proposals": self.db.proposal_stats(bot_id) if self.db is not None else {},
            "negotiations": self.db.negotiation_stats(bot_id) if self.db is not None else {},
            "links": self.db.link_stats(bot_id) if self.db is not None else {},
        }

    # ---------------------------------------------------------------- 记账
    def _audit(self, stage: str, event: str, **kwargs: Any) -> None:
        if self.db is None:
            return
        try:
            self.db.log_negotiation(stage, event, **kwargs)
        except Exception as exc:  # noqa: BLE001 - 审计失败不能反噬业务
            self._fail("audit", exc)

    def _fail(self, where: str, exc: BaseException, *, bot_id: str = "") -> None:
        self._counts["errors"] += 1
        entry: Dict[str, Any] = {"at": now_iso(), "where": where, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
        if bot_id:
            entry["bot_id"] = bot_id
        self.errors.append(entry)
        del self.errors[:-20]
        log.debug("替身机器人 %s 失败：%s", where, entry["error"])


# ------------------------------------------------------------------ 纯函数
def _span(slot: Mapping[str, Any], duration: int) -> Tuple[float, float]:
    start = float(slot.get("start") or 0)
    end = float(slot.get("end") or (start + duration * 60.0))
    if end <= start:
        return start, start + duration * 60.0
    return start, min(end, start + duration * 60.0)


def _attendees(raw: Any) -> List[str]:
    """同行人只认 ``@<id>`` / ``#<id>`` 这一种形状，别的都不算目的地。"""
    if isinstance(raw, str):
        items: Sequence[Any] = re.split(r"[,;、\s]+", raw)
    elif isinstance(raw, (list, tuple)):
        items = list(raw)
    else:
        items = []
    out: List[str] = []
    for item in items:
        value = _clean(item, 32)
        if value and value not in out:
            out.append(value)
    return out[:8]


def summarize_workspace_file(settings: Settings, bot_id: str, ref: str, *, max_items: int = 6) -> Dict[str, Any]:
    """只读该 Bot 自己 ``files`` 目录里的纯文本文件，路径逃逸一律拒绝。

    抽取层的 ``workspace_summarize_file`` 桩刻意「只声明引用、不打开文件」；真正读文件
    的是这里，所以路径必须自己收敛，不能相信上游给的形状。
    """
    root = BotPaths.for_bot(settings, bot_id).files_dir
    if not root.is_dir():
        return {"ok": False, "reason": "no_dir", "available": []}
    name = Path(_clean(ref, 260)).name
    if name:
        picked = root / name
        if not picked.is_file():
            picked = None
    else:
        newest = sorted((item for item in root.glob("*") if item.is_file()), key=lambda p: p.stat().st_mtime, reverse=True)
        picked = newest[0] if newest else None
    available = [item.name for item in sorted(root.glob("*")) if item.is_file()][:8]
    if picked is None:
        return {"ok": False, "reason": "not_found", "available": available}
    resolved = picked.resolve()
    if root.resolve() not in resolved.parents:
        return {"ok": False, "reason": "escaped", "available": available}
    if resolved.suffix.lower() not in SUMMARY_SUFFIXES:
        return {"ok": False, "reason": "binary", "file_name": resolved.name, "available": available}
    size = resolved.stat().st_size
    if size <= 0 or size > MAX_SUMMARY_BYTES:
        return {"ok": False, "reason": "size", "file_name": resolved.name, "available": available}
    try:
        body = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"ok": False, "reason": "unreadable", "file_name": resolved.name, "available": available}
    content = [line.strip() for line in body.splitlines() if line.strip()]
    bullets = re.compile(r"^(?:[-*+]\s+(?:\[[ xX]\]\s+)?|\d+[.)]\s+|>\s+|- )")
    headline = next((line for line in content if not line.startswith(("#", "-", "*", ">"))), "")
    if not headline:
        headline = next((line.lstrip("# ").strip() for line in content if line.lstrip("# ").strip()), "")
    actions: List[str] = []
    for line in content:
        if not bullets.match(line):
            continue
        item = re.sub(r"^[#>*\-\s\d.)\[\]]+", "", line).strip()
        if item and item not in actions:
            actions.append(item[:160])
        if len(actions) >= max_items:
            break
    return {
        "ok": True,
        "file_name": resolved.name,
        "kind": resolved.suffix.lstrip(".").lower() or "text",
        "headline": headline[:280],
        "actions": actions,
        "items": len(actions),
        "size_bytes": size,
        "available": available,
    }


def write_ics(settings: Settings, bot_id: str, title: str, start_ts: float, calendar: str) -> Path:
    """把 .ics 落到该 Bot 自己的 ``files/invites`` 下（目录 0700、文件 0600）。"""
    directory = BotPaths.for_bot(settings, bot_id).files_dir / "invites"
    directory.mkdir(parents=True, exist_ok=True)
    try:
        directory.chmod(0o700)
    except OSError:
        pass
    path = directory / ics_filename(title, start_ts)
    path.write_text(calendar, encoding="utf-8")
    path.chmod(SECURE_FILE_MODE)
    return path


__all__ = [
    "AgentRuntime",
    "CARD_TTL_SECONDS",
    "DEFAULT_CONFIG",
    "GET_AVAILABILITY",
    "PLUGIN_ID",
    "PROPOSE_CANCEL",
    "PROPOSE_CREATE",
    "PROPOSE_RESCHEDULE",
    "Peer",
    "SUMMARIZE_FILE",
    "SlotResult",
    "TOOL_NAMES",
    "build_sender",
    "slot_line",
    "summarize_workspace_file",
    "write_ics",
]
