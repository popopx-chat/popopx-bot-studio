"""``::POPOPX_ECO::`` 服务卡片与 ``::CB::`` 回执行的编解码。

替身机器人的「先卡片、后落库」流程完全依赖这段协议：Bot 把动态确认卡片推进主人
的 POPOPX Chat 会话，主人点「确认」后客户端回一行 ``::CB::<payload>``，Studio 再把
提案状态改为已批准并调用 Mac Node 落地日历。

线上格式逐字符对齐客户端实现，而不是凭印象发明：

* ``PopopxEcoModels.kt`` / ``PopopxEcoModels.swift`` —— 帧标记、限制值、JSON 短键名
  （``t/m/card/id/v/title/ut/et/fields/actions``）、``isSane`` 校验；
* ``PopopxEcoParser.parse`` 要求标记之后的整段**不含换行**，因此 ``sh/mc/ku`` 帧不能
  与任何自然语言同行；
* ``parseVisibleCard`` 按空白切分后**从最后一个 token 往回找**，所以带可见文案的卡片
  只能是「新建」模式（``m:"c"``），且帧必须是最后一个 token —— 本模块用 ``\\u0020``
  转义 JSON 里所有空格来保证这一点；
* ``PopopxEcoUplink.isSendablePayload``：回执 payload 非空、≤512 字符、**无空白、无
  ``::``**，否则客户端根本不发送这一行。

校验失败一律抛 :class:`EcoCardError`：宁可发送前报错，也不要发出一条手机端静默丢弃的
帧（那等于主人的确认卡片凭空消失）。
"""

from __future__ import annotations

import json
import re
import secrets
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

ECO_MARKER = "::POPOPX_ECO::"
CALLBACK_PREFIX = "::CB::"
REFERENCE_PREFIX = "::REF::"
SSO_SCAN_PREFIX = "::SSO_SCAN::"
UPLINK_PREFIXES = (CALLBACK_PREFIX, REFERENCE_PREFIX, SSO_SCAN_PREFIX)

FRAME_TYPES = ("sh", "mc", "sc", "ku")
CARD_STYLES = ("standard", "receipt", "security")
ACTION_KINDS = ("callback", "pay_credits", "open_url", "open_channel", "send_cmd", "none")
ACTION_STYLES = ("primary", "secondary", "destructive")

# 卡片动作回执的 payload 前缀（::CB:: 之后那一段的第一个 token）。
CALLBACK_APPROVE = "ppxok"
CALLBACK_DECLINE = "ppxno"
CALLBACK_ALT = "ppxalt"
CALLBACK_KINDS = (CALLBACK_APPROVE, CALLBACK_DECLINE, CALLBACK_ALT)

_REF_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class EcoCardError(ValueError):
    """客户端会静默丢弃这一帧/这一行，因此拒绝发送。"""


class EcoLimits:
    """``PopopxEcoLimits`` 的实测值（按字符计数，不是字节）。"""

    frame_chars = 8192
    card_id_chars = 64
    card_title_chars = 120
    card_body_chars = 2000
    field_label_chars = 80
    field_value_chars = 240
    payload_chars = 512
    url_chars = 2048
    max_fields = 8
    max_actions = 4


def now_ms() -> int:
    return int(time.time() * 1000)


def compact_json(payload: Mapping[str, Any]) -> str:
    """客户端 ``JSONEncoder()`` 的等价序列化：短键、不排序、不转义非 ASCII、禁 NaN。"""
    try:
        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise EcoCardError(f"卡片 JSON 无法序列化：{exc}") from exc
    if "\n" in text or "\r" in text:
        raise EcoCardError("ECO 帧必须是单行")
    return text


def escape_whitespace(text: str) -> str:
    """把空格写成 ``\\u0020``，让整帧仍然是一个空白分隔的 token。"""
    return text.replace(" ", "\\u0020")


def _text(value: Any, rule: str, limit: int, *, required: bool = True) -> str:
    if value is None:
        if required:
            raise EcoCardError(f"{rule} 缺少取值")
        return ""
    if not isinstance(value, str):
        raise EcoCardError(f"{rule} 必须是字符串，收到 {type(value).__name__}")
    if required and not value.strip():
        raise EcoCardError(f"{rule} 不能为空或纯空白")
    if len(value) > limit:
        raise EcoCardError(f"{rule} 长 {len(value)} 字符，超过客户端上限 {limit}")
    return value


def _positive_int(value: Any, rule: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EcoCardError(f"{rule} 必须是整数，收到 {value!r}")
    if value <= 0:
        raise EcoCardError(f"{rule} 必须为正数，收到 {value}")
    return value


def new_card_id(prefix: str = "ppx") -> str:
    card_id = f"{prefix}_{secrets.token_hex(6)}"
    if len(card_id) > EcoLimits.card_id_chars:
        raise EcoCardError("卡片 id 超过客户端上限")
    return card_id


def build_action(
    *,
    action_id: str,
    title: str,
    kind: str,
    style: str = "primary",
    payload: str = "",
    url: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """一个卡片按钮（``PopopxEcoAction`` 的线上形状）。"""
    if kind not in ACTION_KINDS:
        raise EcoCardError(f"动作类型 {kind!r} 不在协议内，客户端会整帧丢弃")
    if style not in ACTION_STYLES:
        raise EcoCardError(f"按钮样式 {style!r} 非法：{list(ACTION_STYLES)}")
    if kind == "none":
        raise EcoCardError("callback 卡片不允许 action=none")
    action: Dict[str, Any] = {
        "id": _text(action_id, "action_id", EcoLimits.payload_chars),
        "title": _text(title, "action_title", EcoLimits.field_label_chars),
        "action": kind,
        "style": style,
    }
    if kind in ("callback", "send_cmd"):
        action["payload"] = callback_payload(payload) if kind == "callback" else _text(
            payload, "action_payload", EcoLimits.payload_chars
        )
    elif kind == "open_url":
        text = _text(url, "action_url", EcoLimits.url_chars)
        if not text.startswith(("http://", "https://")) or not re.split(r"[/?#]", text.split("://", 1)[1], maxsplit=1)[0]:
            raise EcoCardError(f"action_url 必须是带主机的绝对 http(s) 地址：{url!r}")
        action["url"] = text
    else:  # open_channel / pay_credits 由上层按需拼装，此处不发明字段
        raise EcoCardError(f"替身机器人卡片不支持动作类型 {kind!r}")
    if confirm:
        action["confirm"] = True
    return action


def callback_payload(payload: Any) -> str:
    """校验 ``::CB::`` 之后的 payload：单 token、无空白、无 ``::``、≤512 字符。"""
    text = _text(payload, "callback_payload", EcoLimits.payload_chars)
    if any(char.isspace() for char in text):
        raise EcoCardError("callback payload 不能含空白（客户端不会发送这一行）")
    if "::" in text:
        raise EcoCardError("callback payload 不能含 ::（客户端不会发送这一行）")
    return text


def build_card(
    card_id: str,
    title: str,
    *,
    style: str = "standard",
    body: str = "",
    fields: Optional[Sequence[Mapping[str, Any]]] = None,
    actions: Optional[Sequence[Mapping[str, Any]]] = None,
    expires_at_ms: Optional[int] = None,
    updated_at_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """``PopopxServiceCard``：``id/v/title/ut`` 缺一不渲染。"""
    if style not in CARD_STYLES:
        raise EcoCardError(f"卡片样式 {style!r} 非法：{list(CARD_STYLES)}")
    card: Dict[str, Any] = {
        "id": _text(card_id, "card_id", EcoLimits.card_id_chars),
        "v": style,
        "title": _text(title, "card_title", EcoLimits.card_title_chars),
        "ut": _positive_int(updated_at_ms if updated_at_ms is not None else now_ms(), "card_updated_at_ms"),
    }
    if body:
        card["body"] = _text(body, "card_body", EcoLimits.card_body_chars)
    if fields:
        if len(fields) > EcoLimits.max_fields:
            raise EcoCardError(f"卡片字段 {len(fields)} 条，超过客户端上限 {EcoLimits.max_fields}")
        built: List[Dict[str, Any]] = []
        for raw in fields:
            entry = {
                "k": _text(raw.get("k", raw.get("label")), "field_label", EcoLimits.field_label_chars),
                "v": _text(raw.get("v", raw.get("value")), "field_value", EcoLimits.field_value_chars),
            }
            if raw.get("mono"):
                entry["mono"] = True
            built.append(entry)
        card["fields"] = built
    if actions:
        if len(actions) > EcoLimits.max_actions:
            raise EcoCardError(f"卡片按钮 {len(actions)} 个，超过客户端上限 {EcoLimits.max_actions}")
        built_actions = [
            dict(action) if "action" in action and "id" in action else build_action(**dict(action))
            for action in actions
        ]
        ids = [str(action["id"]) for action in built_actions]
        if len(set(ids)) != len(ids):
            raise EcoCardError(f"卡片按钮 id 必须唯一，收到 {ids}")
        card["actions"] = built_actions
    if expires_at_ms is not None:
        card["et"] = _positive_int(expires_at_ms, "card_expires_at_ms")
    return card


def encode_frame(payload: Mapping[str, Any], *, visible_text: Optional[str] = None) -> str:
    """把帧负载包成要发送的消息文本（含 8192 字符预算检查）。"""
    frame_type = payload.get("t")
    if frame_type not in FRAME_TYPES:
        raise EcoCardError(f"未知 ECO 帧类型 {frame_type!r}")
    if frame_type != "sc" and visible_text:
        raise EcoCardError(f"{frame_type!r} 帧必须独占整条消息，不能带可见文案")
    if frame_type == "sc" and visible_text and payload.get("m") != "c":
        raise EcoCardError("只有新建卡片可以带可见文案；更新帧必须独立成一条")

    body = compact_json(payload)
    if visible_text or frame_type == "sc":
        # 卡片帧永远转义空格：可见卡片是靠「从末尾按空白切分回找」定位的，帧里出现
        # 一个可读空格就等于让手机端找不到这张卡片（control 帧不受影响，但同一份编码
        # 两种用途，宁可总是单 token）。
        body = escape_whitespace(body)
    frame = ECO_MARKER + body
    if len(frame) > EcoLimits.frame_chars:
        raise EcoCardError(f"帧长 {len(frame)} 字符，超过客户端 {EcoLimits.frame_chars} 上限")
    if visible_text is None:
        return frame
    text = _text(visible_text, "visible_text", EcoLimits.card_body_chars, required=False)
    if not text:
        return frame
    # 卡片是从最后一个 token 往回找的，所以帧必须排在末尾。
    message = "%s\n%s" % (text.rstrip(), frame)
    if len(message) > EcoLimits.frame_chars:
        raise EcoCardError(f"文案加帧共 {len(message)} 字符，超过 {EcoLimits.frame_chars} 上限")
    return message


def frame_service_card(
    card: Mapping[str, Any],
    *,
    update: bool = False,
    visible_text: Optional[str] = None,
) -> str:
    """``update=True`` 按 ``cardId`` 原位替换同一张卡片（确认后就地变成已完成）。"""
    return encode_frame({"t": "sc", "m": "u" if update else "c", "card": card}, visible_text=visible_text)


# --------------------------------------------------------------------- 确认卡片
def callback_for(kind: str, ref: str) -> str:
    if kind not in CALLBACK_KINDS:
        raise EcoCardError(f"未知回执类型 {kind!r}")
    token = _text(ref, "callback_ref", 128)
    if not _REF_RE.match(token):
        raise EcoCardError(f"回执引用只能含 [A-Za-z0-9_.-]：{ref!r}")
    return callback_payload(f"{kind}_{token}")


def parse_callback(text: Any) -> Optional[Tuple[str, str]]:
    """从入站消息里解析 ``::CB::<kind>_<ref>``，返回 ``(kind, ref)`` 或 ``None``。

    客户端把这一行原样发出（无空白、无 ``::``），因此这里只做前缀与形状校验；
    未知类型返回 ``None`` 让上层按普通消息处理，而不是报错。
    """
    if not isinstance(text, str):
        return None
    trimmed = text.strip()
    if not trimmed.startswith(CALLBACK_PREFIX):
        return None
    payload = trimmed[len(CALLBACK_PREFIX):].strip()
    if not payload or "::" in payload or any(char.isspace() for char in payload):
        return None
    if len(payload) > EcoLimits.payload_chars:
        return None
    kind, _, ref = payload.partition("_")
    if kind not in CALLBACK_KINDS or not _REF_RE.match(ref):
        return None
    return kind, ref


def confirmation_card(
    proposal_id: str,
    *,
    card_id: str = "",
    title: str,
    body: str = "",
    visible_text: str = "",
    fields: Optional[Sequence[Mapping[str, Any]]] = None,
    ttl_seconds: float = 1800.0,
    decline_label: str = "",
    alt_label: str = "",
    approve_label: str = "",
) -> Tuple[Dict[str, Any], str]:
    """造一张待确认卡片，返回 ``(card, 卡片消息文本)``。

    三个按钮分别对应 ``ppxok/ppxno/ppxalt`` 回执；主人没点之前，日历一个字节都不会写。
    消息带一段可见文案（否则整条消息会被当作 control 帧而不显示气泡），帧排在末尾。
    """
    identifier = card_id or new_card_id("ppxpr")
    ttl = max(30.0, float(ttl_seconds))
    expires_ms = now_ms() + int(ttl * 1000)
    actions = [
        {
            "action_id": "approve",
            "title": approve_label or "确认",
            "kind": "callback",
            "style": "primary",
            "payload": callback_for(CALLBACK_APPROVE, proposal_id),
        }
    ]
    if decline_label:
        actions.append(
            {
                "action_id": "decline",
                "title": decline_label,
                "kind": "callback",
                "style": "secondary",
                "payload": callback_for(CALLBACK_DECLINE, proposal_id),
            }
        )
    if alt_label:
        actions.append(
            {
                "action_id": "alternative",
                "title": alt_label,
                "kind": "callback",
                "style": "secondary",
                "payload": callback_for(CALLBACK_ALT, proposal_id),
            }
        )
    card = build_card(
        identifier,
        title,
        style="standard",
        body=body,
        fields=fields,
        actions=actions,
        expires_at_ms=expires_ms,
    )
    return card, frame_service_card(card, visible_text=visible_text or body or title)


def status_card(card: Mapping[str, Any], *, title: str, body: str = "", style: str = "standard") -> str:
    """把同一张卡片就地改写成终态（已确认 / 已取消 / 已过期）。"""
    updated = build_card(
        str(card.get("id") or new_card_id("ppxpr")),
        title,
        style=style,
        body=body or str(card.get("body") or ""),
        fields=[dict(field) for field in card.get("fields") or []] or None,
        updated_at_ms=now_ms(),
    )
    return frame_service_card(updated, update=True)


def decode_message(text: Any) -> Optional[Dict[str, Any]]:
    """按客户端规则解析一条消息里的 ECO 帧（自检与回环测试用）。"""
    if not isinstance(text, str) or ECO_MARKER not in text:
        return None
    index = text.rfind(ECO_MARKER)
    remainder = text[index + len(ECO_MARKER):]
    if "\n" in remainder or "\r" in remainder:
        return None
    token = remainder.split()[-1] if remainder.split() else remainder
    try:
        payload = json.loads(token)
    except ValueError:
        return None
    if not isinstance(payload, dict) or payload.get("t") not in FRAME_TYPES:
        return None
    return {"frame": payload, "card": payload.get("card"), "mode": payload.get("m"), "t": payload.get("t")}


def is_uplink_text(text: Any) -> bool:
    """判断一条入站文本是否是机器回执行（不得当成主人说的话转发出去）。"""
    if not isinstance(text, str):
        return False
    trimmed = text.strip()
    prefix = next((item for item in UPLINK_PREFIXES if trimmed.startswith(item)), "")
    if not prefix:
        return False
    payload = trimmed[len(prefix):]
    return bool(payload) and len(payload) <= EcoLimits.payload_chars and not any(
        char.isspace() for char in payload
    ) and "::" not in payload


__all__ = [
    "ACTION_KINDS",
    "ACTION_STYLES",
    "CALLBACK_ALT",
    "CALLBACK_APPROVE",
    "CALLBACK_DECLINE",
    "CALLBACK_PREFIX",
    "CARD_STYLES",
    "ECO_MARKER",
    "EcoCardError",
    "EcoLimits",
    "REFERENCE_PREFIX",
    "SSO_SCAN_PREFIX",
    "build_action",
    "build_card",
    "callback_for",
    "callback_payload",
    "compact_json",
    "confirmation_card",
    "decode_message",
    "encode_frame",
    "escape_whitespace",
    "frame_service_card",
    "is_uplink_text",
    "new_card_id",
    "parse_callback",
    "status_card",
]
