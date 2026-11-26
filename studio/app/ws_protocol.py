"""Asynchronous client for the POPOPX Chat CLI WebSocket control API.

Wire format (verified against popopx-chat sources)::

    request   {"corrId": "<string>", "cmd": "<command string>"}
    response  {"corrId": "<same>",   "resp": {"type": "<tag>", ...}}
    event     {"resp": {"type": "<tag>", ...}}            # corrId absent/null

Citations: ``apps/popopx-chat/Server.hs:36-37`` (ChatSrvRequest), ``:118-132``
(dispatch), ``:115-117`` (unsolicited events), ``bots/api/COMMANDS.md`` for the
command syntax, ``Popopx/Chat/Library/Commands.hs:6763,6955,7021,7031`` for the
``/_send`` / ``/_create link`` / ``/_address`` / ``/_address_settings`` parsers.
The CLI binds 127.0.0.1 only (``Popopx/Messaging/Transport/Server.hs`` via
``runLocalTCPServer``) and provides no authentication, so this client must only
ever be pointed at loopback.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import random
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
GROUP_ROLES = ("owner", "admin", "moderator", "member", "observer")
# ``/_create link`` only accepts the two join roles; a public link must never
# hand out administration, so the wider GROUP_ROLES table is not usable here.
LINK_ROLES = ("observer", "member")
DEFAULT_TIMEOUT = 20.0
ERROR_TYPES = ("chatCmdError", "chatError")
ERROR_KEYS = ("error", "reason", "detail", "message")

_USER_ID_RE = re.compile(r"^[1-9][0-9]{0,18}$")


class WebSocketProtocolError(RuntimeError):
    """The CLI sent a frame that does not match the documented protocol."""


class CLICommandError(RuntimeError):
    """The CLI answered a command with a ``chatCmdError``/``chatError``."""

    def __init__(self, message: str, *, resp_type: str = "", payload: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.resp_type = resp_type
        self.payload = payload or {}


class CLITimeoutError(WebSocketProtocolError):
    """A command did not receive its correlated response in time."""


# ---------------------------------------------------------------------------
# command builders
# ---------------------------------------------------------------------------


def _require_user_id(user_id: Any) -> int:
    try:
        value = int(user_id)
    except (TypeError, ValueError) as exc:
        raise WebSocketProtocolError(f"userId 必须是整数，收到 {user_id!r}") from exc
    if not _USER_ID_RE.match(str(value)):
        raise WebSocketProtocolError(f"非法 userId {user_id!r}")
    return value


def _json_arg(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _chat_ref(chat_type: str, chat_id: Any) -> str:
    if not re.match(r"^[0-9]{1,19}$", str(chat_id)):
        raise WebSocketProtocolError(f"非法 chatId {chat_id!r}")
    if chat_type == "direct":
        return f"@{chat_id}"
    if chat_type == "group":
        return f"#{chat_id}"
    if chat_type == "local":
        return f"*{chat_id}"
    raise WebSocketProtocolError(f"非法 chatType {chat_type!r}，可选 direct/group/local")


def cmd_create_user(display_name: str, *, full_name: str = "", bio: str = "", peer_type: str = "bot") -> str:
    """``/_create user`` - provision the Bot's own profile.

    ``peerType`` is what makes the app render this participant as a bot, which
    is why it is set here instead of in a later profile update.
    """
    profile: Dict[str, Any] = {"displayName": display_name, "fullName": full_name or display_name}
    if bio:
        profile["shortDescr"] = bio
    if peer_type:
        profile["peerType"] = peer_type
    return f"/_create user {_json_arg({'profile': profile})}"


def cmd_show_active_user() -> str:
    """``/user`` - read the profile the CLI started with (no network usage)."""
    return "/user"


def cmd_list_users() -> str:
    """``/users`` - list every profile stored in this cli-data database."""
    return "/users"


def cmd_set_active_user(user_id: Any) -> str:
    """``/_user`` - make an existing profile the active one again."""
    return f"/_user {_require_user_id(user_id)}"


def cmd_update_profile(user_id: Any, profile: Dict[str, Any]) -> str:
    """``/_profile`` - set bot commands menu, avatar or bio."""
    return f"/_profile {_require_user_id(user_id)} {_json_arg(profile)}"


def cmd_show_address(user_id: Any) -> str:
    return f"/_show_address {_require_user_id(user_id)}"


def cmd_create_address(user_id: Any, *, pq_ratchet: Optional[bool] = None, server: str = "") -> str:
    """``/_address`` - create the long-term (permanent) POPOPX address."""
    flag = "" if pq_ratchet is None else f" pq_ratchet={'on' if pq_ratchet else 'off'}"
    tail = f" {server}" if server else ""
    return f"/_address {_require_user_id(user_id)}{tail}{flag}"


def cmd_delete_address(user_id: Any) -> str:
    return f"/_delete_address {_require_user_id(user_id)}"


def cmd_short_link_address(user_id: Any, *, pq_ratchet: Optional[bool] = None) -> str:
    flag = "" if pq_ratchet is None else f" pq_ratchet={'on' if pq_ratchet else 'off'}"
    return f"/_short_link_address {_require_user_id(user_id)}{flag}"


def build_address_settings(
    *,
    business_address: bool = False,
    auto_accept: bool = True,
    accept_incognito: bool = False,
    welcome_text: str = "",
) -> Dict[str, Any]:
    """Build the ``AddressSettings`` JSON accepted by ``/_address_settings``.

    ``accept_incognito`` must stay false for a bot: accepting a request
    incognito replaces the bot's own name and avatar with the requester's.
    The CLI rejects the business + incognito combination outright
    (``Library/Commands.hs:2551``), so fail before the round trip.
    """
    if business_address and accept_incognito:
        raise WebSocketProtocolError("businessAddress 为 true 时 acceptIncognito 必须为 false")
    settings: Dict[str, Any] = {
        "businessAddress": bool(business_address),
        "autoAccept": {"acceptIncognito": bool(accept_incognito)} if auto_accept else None,
        "autoReply": {"type": "text", "text": welcome_text} if welcome_text else None,
    }
    return settings


def cmd_address_settings(user_id: Any, settings: Dict[str, Any]) -> str:
    return f"/_address_settings {_require_user_id(user_id)} {_json_arg(settings)}"


def cmd_create_group(user_id: Any, display_name: str, *, full_name: str = "", description: str = "") -> str:
    profile: Dict[str, Any] = {"displayName": display_name, "fullName": full_name or display_name}
    if description:
        profile["description"] = description
        profile["shortDescr"] = description
    return f"/_group {_require_user_id(user_id)} {_json_arg(profile)}"


def cmd_create_group_link(group_id: Any, role: str = "member") -> str:
    """``/_create link`` - read-only (observer) or interactive (member) group link."""
    if role not in LINK_ROLES:
        raise WebSocketProtocolError(f"群链接角色 {role!r} 非法，可选 {LINK_ROLES}")
    if not re.match(r"^[0-9]{1,19}$", str(group_id)):
        raise WebSocketProtocolError(f"非法 groupId {group_id!r}")
    return f"/_create link #{group_id} {role}"


def cmd_send_message(
    chat_type: str,
    chat_id: Any,
    *,
    text: str = "",
    content: Optional[Dict[str, Any]] = None,
    quoted_item_id: Optional[int] = None,
    live: bool = False,
    ttl: Optional[int] = None,
    file_path: str = "",
) -> str:
    """``/_send`` with the ``json`` payload form.

    The JSON form is used instead of ``text <msg>`` because a composed message
    carries a real ``quotedItemId``, which the quote-reply routing needs, and
    because JSON escaping removes any ambiguity about newlines in the command.
    """
    if content is None:
        if not text:
            raise WebSocketProtocolError("发送内容不能为空")
        content = {"type": "text", "text": text}
    message: Dict[str, Any] = {"msgContent": content}
    if file_path:
        # ``ComposedMessage`` 的顶层可选 ``filePath``（Controller.hs ``v .:? "filePath"``）：
        # CLI 直接把本地文件作为 ``{"type":"file"}`` 发出去，Studio 不需要额外的文件通道。
        message["filePath"] = str(file_path)
    if quoted_item_id is not None:
        message["quotedItemId"] = int(quoted_item_id)
    flags = " live=on" if live else ""
    if ttl:
        flags += f" ttl={int(ttl)}"
    return f"/_send {_chat_ref(chat_type, chat_id)}{flags} json {_json_arg([message])}"


def cmd_send_plain_text(chat_type: str, chat_id: Any, text: str) -> str:
    """``/_send ... text <msg>`` - single line only; kept for parity with the docs."""
    if "\n" in text:
        raise WebSocketProtocolError("text 形式不支持换行，请改用 json 形式")
    return f"/_send {_chat_ref(chat_type, chat_id)} text {text}"


def cmd_list_contacts(user_id: Any) -> str:
    return f"/_contacts {_require_user_id(user_id)}"


def cmd_list_groups(user_id: Any, *, search: str = "") -> str:
    base = f"/_groups {_require_user_id(user_id)}"
    return f"{base} {search}" if search else base


def cmd_accept_contact(contact_request_id: Any) -> str:
    if not re.match(r"^[0-9]{1,19}$", str(contact_request_id)):
        raise WebSocketProtocolError(f"非法 contactRequestId {contact_request_id!r}")
    return f"/_accept {contact_request_id}"


# ---------------------------------------------------------------------------
# frames
# ---------------------------------------------------------------------------


def build_frame(corr_id: str, cmd: str) -> str:
    """Serialize one command frame; ``corrId`` and ``cmd`` are both required."""
    if not corr_id:
        raise WebSocketProtocolError("corrId 不能为空")
    if not isinstance(cmd, str) or not cmd:
        raise WebSocketProtocolError("cmd 必须是非空字符串")
    return json.dumps({"corrId": corr_id, "cmd": cmd}, ensure_ascii=False)


@dataclass
class Frame:
    """One decoded CLI frame."""

    kind: str  # "response" | "event" | "error"
    corr_id: Optional[str]
    resp_type: str
    payload: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @property
    def is_error(self) -> bool:
        return self.kind == "error"


def decode_frame(raw: str | bytes) -> Frame:
    """Decode a CLI frame without ever raising on undocumented fields.

    ``bots/README.md:183`` requires a bot to ignore unknown union tags and
    extra properties, so every lookup here is a ``.get`` with a fallback.
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise WebSocketProtocolError(f"CLI 返回了非法 JSON：{exc}") from exc
    if not isinstance(data, dict) or "resp" not in data:
        raise WebSocketProtocolError(f"CLI 帧缺少 resp 字段：{str(data)[:160]}")
    resp = data["resp"]
    corr_id = data.get("corrId")
    corr_id = str(corr_id) if corr_id not in (None, "") else None
    if not isinstance(resp, dict):
        raise WebSocketProtocolError(f"CLI resp 不是对象：{str(resp)[:160]}")
    resp_type = str(resp.get("type") or "")
    if resp_type in ERROR_TYPES:
        detail = flatten_error(resp.get("chatError") or resp)
        return Frame(kind="error", corr_id=corr_id, resp_type=resp_type, payload=resp, error=detail)
    kind = "response" if corr_id else "event"
    return Frame(kind=kind, corr_id=corr_id, resp_type=resp_type, payload=resp)


def _error_reason(payload: Any, depth: int = 0) -> str:
    """Find the innermost string under an ``error``/``reason`` style key."""
    if depth > 6:
        return ""
    if isinstance(payload, dict):
        shallow = ""
        for key, value in payload.items():
            name = str(key).lower()
            if isinstance(value, str) and value and (name in ERROR_KEYS or name.endswith("error")):
                shallow = shallow or value
            elif isinstance(value, (dict, list)):
                deeper = _error_reason(value, depth + 1)
                if deeper:
                    return deeper
        return shallow
    if isinstance(payload, list):
        for item in payload:
            deeper = _error_reason(item, depth + 1)
            if deeper:
                return deeper
    return ""


def flatten_error(payload: Any, depth: int = 0) -> str:
    """Render a nested ``ChatError`` union into one readable line.

    The CLI nests the real reason under ``error``/``reason`` keys while the
    wrapper tags (``chatCmdError``) carry no information, so the innermost
    reason wins; the generic flattening is only a fallback for payloads whose
    reason sits in an unexpected key.
    """
    reason = _error_reason(payload)
    if reason:
        return reason[:400]
    if depth > 4 or payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    if not isinstance(payload, dict):
        return json.dumps(payload, ensure_ascii=False)[:200]
    tag = str(payload.get("type") or "")
    parts = []
    for key, value in payload.items():
        if key == "type":
            continue
        if isinstance(value, (dict, list)):
            nested = flatten_error(value, depth + 1)
            if nested:
                parts.append(f"{key}={nested}")
        elif value is not None:
            parts.append(f"{key}={value}")
    if parts:
        return " ".join(str(part) for part in parts if part)[:400]
    return tag if tag in ERROR_TYPES else ""


# ---------------------------------------------------------------------------
# event normalization
# ---------------------------------------------------------------------------


@dataclass
class NormalizedEvent:
    """One inbound message reduced to the fields the engines need."""

    event_type: str
    user_id: Optional[int] = None
    direction: str = "in"
    chat_type: str = "direct"
    chat_id: Optional[int] = None
    chat_ref: str = ""
    chat_name: str = ""
    item_id: Optional[int] = None
    sender: str = ""
    sender_name: str = ""
    text: str = ""
    content_type: str = "text"
    ts: float = 0.0
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_incoming(self) -> bool:
        return self.direction == "in"

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _first(mapping: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, "", {}, []):
            return value
    return None


def _int_or_none(value: Any) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_ts(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                import datetime as _dt

                return _dt.datetime.strptime(value, fmt).timestamp()
            except ValueError:
                continue
    return time.time()


def normalize_new_chat_items(payload: Dict[str, Any]) -> List[NormalizedEvent]:
    """Flatten a ``newChatItems`` frame into one event per chat item."""
    events: List[NormalizedEvent] = []
    user_id = _int_or_none((_first(payload.get("user") or {}, "userId")))
    for entry in payload.get("chatItems") or []:
        if not isinstance(entry, dict):
            continue
        info = entry.get("chatInfo") or {}
        item = entry.get("chatItem") or {}
        chat_type = str(info.get("type") or "direct")
        chat_id: Optional[int] = None
        chat_name = ""
        if chat_type == "group":
            group_info = info.get("groupInfo") or {}
            chat_id = _int_or_none(_first(group_info, "groupId"))
            chat_name = str(
                _first(group_info.get("groupProfile") or {}, "displayName", "fullName")
                or group_info.get("localDisplayName")
                or ""
            )
        else:
            contact = info.get("contact") or {}
            chat_id = _int_or_none(_first(contact, "contactId"))
            chat_name = str(
                _first(contact.get("profile") or {}, "displayName", "fullName")
                or contact.get("localDisplayName")
                or ""
            )
        chat_dir = item.get("chatDir") or {}
        dir_type = str(chat_dir.get("type") or "")
        direction = "out" if dir_type.endswith("Snd") else "in"
        meta = item.get("meta") or {}
        content = item.get("content") or {}
        content_type = str(content.get("type") or "text")
        text = str(_first(content, "text", "description") or _first(meta, "itemText") or "")
        sender_name = ""
        sender = ""
        group_member = chat_dir.get("groupMember") or {}
        if isinstance(group_member, dict) and group_member:
            sender = str(_first(group_member, "groupMemberId", "memberId") or "")
            sender_name = str(
                _first(group_member.get("memberProfile") or {}, "displayName", "fullName")
                or group_member.get("localDisplayName")
                or chat_name
            )
        if not sender_name and direction == "in":
            sender_name = chat_name
        events.append(
            NormalizedEvent(
                event_type="newChatItems",
                user_id=user_id,
                direction=direction,
                chat_type="group" if chat_type.startswith("group") or chat_type == "channel" else "direct",
                chat_id=chat_id,
                chat_ref=f"#{chat_id}" if chat_id is not None and chat_type.startswith("group") else (f"@{chat_id}" if chat_id is not None else ""),
                chat_name=chat_name,
                item_id=_int_or_none(_first(meta, "itemId")),
                sender=sender,
                sender_name=sender_name,
                text=text,
                content_type=content_type,
                ts=_parse_ts(_first(meta, "itemTs", "createdAt")),
                raw=entry,
            )
        )
    return events


def normalize_event(frame: Frame) -> List[NormalizedEvent]:
    """Turn any CLI event frame into zero or more :class:`NormalizedEvent`."""
    payload = frame.payload
    resp_type = frame.resp_type
    if resp_type == "newChatItems":
        return normalize_new_chat_items(payload)
    user_id = _int_or_none(_first(payload.get("user") or {}, "userId"))
    if resp_type == "receivedContactRequest":
        request = payload.get("contactRequest") or {}
        return [
            NormalizedEvent(
                event_type=resp_type,
                user_id=user_id,
                chat_type="direct",
                item_id=_int_or_none(_first(request, "contactRequestId")),
                sender=str(_first(request, "agentInvitationId", "xContactId") or ""),
                sender_name=str(_first(request.get("profile") or {}, "displayName", "fullName") or ""),
                text=str(_first(request, "welcomeMessage", "receivedMessage") or ""),
                ts=time.time(),
                raw=payload,
            )
        ]
    if resp_type == "contactConnected":
        contact = payload.get("contact") or {}
        return [
            NormalizedEvent(
                event_type=resp_type,
                user_id=user_id,
                chat_type="direct",
                chat_id=_int_or_none(_first(contact, "contactId")),
                chat_ref=f"@{_int_or_none(_first(contact, 'contactId')) or ''}",
                chat_name=str(_first(contact.get("profile") or {}, "displayName", "fullName") or ""),
                sender_name=str(_first(contact.get("profile") or {}, "displayName", "fullName") or ""),
                ts=time.time(),
                raw=payload,
            )
        ]
    if resp_type in ("contactDisabled", "contactDeleted", "groupMemberDeleted"):
        return [NormalizedEvent(event_type=resp_type, user_id=user_id, ts=time.time(), raw=payload)]
    return []


# ---------------------------------------------------------------------------
# response extractors
# ---------------------------------------------------------------------------


def _find_link_keys(payload: Any, found: Dict[str, str], depth: int = 0) -> None:
    if depth > 5 or not isinstance(payload, (dict, list)):
        return
    if isinstance(payload, list):
        for entry in payload:
            _find_link_keys(entry, found, depth + 1)
        return
    for key, value in payload.items():
        if key in ("connFullLink", "connShortLink") and isinstance(value, str) and value:
            found.setdefault(key, value)
        elif isinstance(value, (dict, list)):
            _find_link_keys(value, found, depth + 1)


def extract_created_link(payload: Dict[str, Any]) -> Tuple[str, str]:
    """Return ``(full_link, short_link)`` from any address/link response.

    The link lives at different depths depending on the command
    (``connLinkContact`` for ``/_address``, one level deeper inside
    ``contactLink`` for ``/_show_address`` and ``groupLink``), so the keys are
    searched rather than addressed.
    """
    found: Dict[str, str] = {}
    _find_link_keys(payload, found)
    return found.get("connFullLink", ""), found.get("connShortLink", "")


def extract_user_id(payload: Dict[str, Any]) -> Optional[int]:
    return _int_or_none(_first(payload.get("user") or {}, "userId"))


def extract_user_name(payload: Dict[str, Any]) -> str:
    """Name of a ``User`` object, or of the ``user`` wrapped in a ``usersList`` entry."""
    user = payload.get("user")
    if not isinstance(user, dict):
        user = payload if isinstance(payload, dict) else {}
    profile = user.get("profile")
    name = _first(user, "localDisplayName") or ""
    if not name and isinstance(profile, dict):
        name = _first(profile, "displayName", "fullName") or ""
    return str(name or "")


def extract_address_settings(payload: Dict[str, Any]) -> Dict[str, Any]:
    container = _first(payload, "contactLink", "connLinkContact") or {}
    if isinstance(container, dict):
        settings = container.get("addressSettings")
        if isinstance(settings, dict):
            return settings
    settings = payload.get("addressSettings")
    return settings if isinstance(settings, dict) else {}


def extract_group_id(payload: Dict[str, Any]) -> Optional[int]:
    group_info = payload.get("groupInfo") or {}
    return _int_or_none(_first(group_info, "groupId"))


# ---------------------------------------------------------------------------
# reconnect policy
# ---------------------------------------------------------------------------


@dataclass
class ReconnectPolicy:
    """Exponential backoff with jitter, capped at *max_delay* seconds."""

    base_delay: float = 1.0
    factor: float = 2.0
    max_delay: float = 60.0
    jitter: float = 0.25
    attempts: int = 0

    def next_delay(self) -> float:
        delay = min(self.max_delay, self.base_delay * (self.factor ** self.attempts))
        self.attempts += 1
        if self.jitter:
            delay *= 1.0 + random.uniform(-self.jitter, self.jitter)
        return max(0.1, round(delay, 3))

    def reset(self) -> None:
        self.attempts = 0

    def __iter__(self):
        while True:
            yield self.next_delay()


# ---------------------------------------------------------------------------
# client
# ---------------------------------------------------------------------------


class CLIWebSocketClient:
    """One loopback WebSocket connection to a ``popopx-cli`` instance."""

    def __init__(
        self,
        port: int,
        *,
        host: str = "127.0.0.1",
        path: str = "/",
        timeout: float = DEFAULT_TIMEOUT,
        connect_timeout: float = 10.0,
        max_frame_bytes: int = 16 * 1024 * 1024,
        on_event: Optional[Callable[[Frame], Awaitable[None]]] = None,
    ):
        if host not in LOOPBACK_HOSTS:
            raise WebSocketProtocolError(
                f"CLI 控制通道只允许回环地址，拒绝 {host!r}（严禁监听 0.0.0.0）"
            )
        if not 1 <= int(port) <= 65535:
            raise WebSocketProtocolError(f"非法端口 {port!r}")
        self.host = host
        self.port = int(port)
        self.path = path
        self.timeout = float(timeout)
        self.connect_timeout = float(connect_timeout)
        self.max_frame_bytes = int(max_frame_bytes)
        self.on_event = on_event
        self._ws: Any = None
        self._reader: Optional[asyncio.Task] = None
        self._pending: Dict[str, asyncio.Future] = {}
        self._counter = 0
        self._closed = False
        self.events_received = 0
        self.commands_sent = 0

    # -------------------------------------------------------------- lifecycle
    @property
    def url(self) -> str:
        return f"ws://{self.host}:{self.port}{self.path}"

    @property
    def connected(self) -> bool:
        return self._ws is not None and not self._closed

    async def connect(self) -> None:
        import websockets  # imported lazily so the pure codec helpers stay usable

        self._closed = False
        self._ws = await asyncio.wait_for(
            websockets.connect(
                self.url,
                max_size=self.max_frame_bytes,
                open_timeout=self.connect_timeout,
                close_timeout=self.connect_timeout,
                ping_interval=20,
                ping_timeout=20,
            ),
            timeout=self.connect_timeout,
        )
        self._reader = asyncio.create_task(self._read_loop(), name=f"cli-reader-{self.port}")

    async def close(self) -> None:
        self._closed = True
        if self._reader is not None:
            self._reader.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._reader
            self._reader = None
        if self._ws is not None:
            with contextlib.suppress(Exception):
                await self._ws.close()
            self._ws = None
        for future in list(self._pending.values()):
            if not future.done():
                future.set_exception(WebSocketProtocolError("连接已关闭"))
        self._pending.clear()

    async def __aenter__(self) -> "CLIWebSocketClient":
        await self.connect()
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.close()

    # ---------------------------------------------------------------- reader
    async def _read_loop(self) -> None:
        import websockets

        try:
            async for message in self._ws:
                frame = decode_frame(message)
                # ``decode_frame`` gives a correlated ``chatCmdError`` kind="error", so
                # matching only "response" here would leave ``is_error`` below dead and
                # every CLI-side failure waiting out the full timeout.
                if frame.corr_id and frame.kind in ("response", "error"):
                    future = self._pending.pop(frame.corr_id, None)
                    if future is None or future.done():
                        continue
                    if frame.is_error:
                        future.set_exception(
                            CLICommandError(frame.error or "CLI 返回错误", resp_type=frame.resp_type, payload=frame.payload)
                        )
                    else:
                        future.set_result(frame)
                    continue
                self.events_received += 1
                if self.on_event is not None:
                    await self.on_event(frame)
        except (websockets.exceptions.WebSocketException, OSError, asyncio.IncompleteReadError) as exc:
            self._fail_pending(WebSocketProtocolError(f"CLI 连接中断：{exc}"))
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # a malformed frame must not kill the gateway
            self._fail_pending(WebSocketProtocolError(f"CLI 帧解析失败：{exc}"))

    def _fail_pending(self, error: Exception) -> None:
        for future in list(self._pending.values()):
            if not future.done():
                future.set_exception(error)
        self._pending.clear()

    # --------------------------------------------------------------- commands
    def next_corr_id(self, prefix: str = "c") -> str:
        self._counter += 1
        return f"{prefix}{int(time.time() * 1000):x}-{self._counter}"

    async def send_command(self, cmd: str, *, timeout: Optional[float] = None) -> Frame:
        """Send one command frame and await its correlated response."""
        if self._ws is None or self._closed:
            raise WebSocketProtocolError(f"CLI {self.url} 未连接")
        corr_id = self.next_corr_id()
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self._pending[corr_id] = future
        try:
            await self._ws.send(build_frame(corr_id, cmd))
            self.commands_sent += 1
            return await asyncio.wait_for(future, timeout if timeout is not None else self.timeout)
        except asyncio.TimeoutError as exc:
            raise CLITimeoutError(f"命令超时（{self.timeout:.0f}s）：{cmd[:72]}") from exc
        finally:
            self._pending.pop(corr_id, None)

    async def request(self, cmd: str, *, timeout: Optional[float] = None) -> Dict[str, Any]:
        frame = await self.send_command(cmd, timeout=timeout)
        return frame.payload

    async def expect_types(self, cmd: str, allowed: Iterable[str], *, timeout: Optional[float] = None) -> Dict[str, Any]:
        allowed_types = tuple(allowed)
        payload = await self.request(cmd, timeout=timeout)
        resp_type = str(payload.get("type") or "")
        if resp_type not in allowed_types:
            raise WebSocketProtocolError(
                f"CLI 返回了未预期的响应类型 {resp_type!r}（期望 {allowed_types}）"
            )
        return payload

    # ------------------------------------------------------- high-level verbs
    async def get_active_user(self, *, timeout: Optional[float] = None) -> Optional[int]:
        """The active profile's userId, or None when cli-data holds no profile yet.

        An empty database answers ``/user`` with ``chatCmdError``; builds that
        reply ``activeUser`` with a null ``user`` are read the same way. Command
        errors are the only thing swallowed here - a dropped connection still
        raises, because guessing "no user" on a transport failure is how two
        profiles get created for one Bot.
        """
        try:
            payload = await self.request(cmd_show_active_user(), timeout=timeout)
        except CLICommandError:
            return None
        return extract_user_id(payload)

    async def list_users(self, *, timeout: Optional[float] = None) -> List[Dict[str, Any]]:
        try:
            payload = await self.expect_types(cmd_list_users(), ("usersList",), timeout=timeout)
        except CLICommandError:
            return []
        users = payload.get("users") or []
        return list(users) if isinstance(users, list) else []

    async def ensure_user(self, display_name: str, *, full_name: str = "", bio: str = "") -> int:
        """Return the Bot's userId, creating the profile only when none exists.

        ``/_create user`` answers ``UserExists`` the moment cli-data already holds
        a profile (popopx-chat ``bots/api/COMMANDS.md``, CreateActiveUser), so
        every path that re-runs provisioning - ``boot()`` after a reboot,
        ``restart_bot``, restoring a cold backup - has to reuse it. Whether to
        create is decided by ``/users``, never by matching error wording, and an
        existing profile keeps its own name: renaming a Bot is never pushed down.
        """
        user_id = await self.get_active_user()
        if user_id is not None:
            return user_id
        known = [entry for entry in await self.list_users() if extract_user_id(entry) is not None]
        if known:
            # One profile per isolated cli-data dir, so any hit belongs to this
            # Bot; the name match only wins the tie-break.
            wanted = next((e for e in known if extract_user_name(e) == display_name), known[0])
            existing = int(extract_user_id(wanted) or 0)
            payload = await self.expect_types(cmd_set_active_user(existing), ("activeUser",))
            return extract_user_id(payload) or existing
        payload = await self.expect_types(
            cmd_create_user(display_name, full_name=full_name, bio=bio), ("activeUser",)
        )
        user_id = extract_user_id(payload)
        if user_id is None:
            raise WebSocketProtocolError("创建 Bot 用户后未返回 userId")
        return user_id

    async def create_address(self, user_id: int) -> Tuple[str, str]:
        payload = await self.expect_types(
            cmd_create_address(user_id), ("userContactLinkCreated", "userContactLinkUpdated")
        )
        return extract_created_link(payload)

    async def show_address(self, user_id: int) -> Tuple[str, str, Dict[str, Any]]:
        payload = await self.request(cmd_show_address(user_id))
        if payload.get("type") == "userContactLink":
            return (*extract_created_link(payload), extract_address_settings(payload))
        return "", "", {}

    async def apply_address_settings(self, user_id: int, settings: Dict[str, Any]) -> Dict[str, Any]:
        return await self.expect_types(
            cmd_address_settings(user_id, settings),
            ("userContactLinkUpdated", "userContactLink"),
        )

    async def create_group(self, user_id: int, name: str) -> Optional[int]:
        payload = await self.expect_types(cmd_create_group(user_id, name), ("groupCreated",))
        return extract_group_id(payload)

    async def create_group_link(self, group_id: int, role: str = "member") -> Tuple[str, str]:
        payload = await self.expect_types(
            cmd_create_group_link(group_id, role), ("groupLinkCreated", "groupLink")
        )
        return extract_created_link(payload)

    async def send_text(
        self,
        chat_type: str,
        chat_id: int,
        text: str,
        *,
        quoted_item_id: Optional[int] = None,
    ) -> List[NormalizedEvent]:
        payload = await self.request(
            cmd_send_message(chat_type, chat_id, text=text, quoted_item_id=quoted_item_id)
        )
        return normalize_new_chat_items(payload) if payload.get("type") == "newChatItems" else []

    async def send_content(
        self,
        chat_type: str,
        chat_id: int,
        content: Dict[str, Any],
        *,
        quoted_item_id: Optional[int] = None,
        file_path: str = "",
    ) -> Dict[str, Any]:
        return await self.request(
            cmd_send_message(
                chat_type,
                chat_id,
                content=content,
                quoted_item_id=quoted_item_id,
                file_path=file_path,
            )
        )

    async def list_contacts(self, user_id: int) -> List[Dict[str, Any]]:
        payload = await self.expect_types(cmd_list_contacts(user_id), ("contactsList",))
        contacts = payload.get("contacts") or []
        return list(contacts) if isinstance(contacts, list) else []

    async def list_groups(self, user_id: int) -> List[Dict[str, Any]]:
        payload = await self.expect_types(cmd_list_groups(user_id), ("groupsList",))
        groups = payload.get("groups") or []
        return list(groups) if isinstance(groups, list) else []

    async def accept_contact(self, contact_request_id: int) -> Dict[str, Any]:
        return await self.expect_types(cmd_accept_contact(contact_request_id), ("acceptingContactRequest",))
