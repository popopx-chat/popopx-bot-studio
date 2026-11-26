"""``python3 -m app.selftest_guest``：访客预约门户（任务 3 通道 B）的离线自检。

分组键名 ``guest_portal`` 由编排层注册进 :data:`app.selftest.SEL_TEST_GROUPS`；也可以单独跑。
分组本身没有副作用：只碰 :meth:`app.selftest.Harness.database` 开的临时账本与临时数据目录，
不写真实 ``var/studio``，不改任何全局表，其他分组读到的东西一个字节都不会变。

离线纪律：**不开 socket、不起服务、不 spawn 进程**。空档来源、话术生成、卡片推送全是注入的
替身，所以断言打在 :mod:`app.guest_portal` 的真实判定路径上（签名 → 过期 → 撤销 → 预算 →
领取 → 会话 → 提案 → 卡片 → .ics），而不是打在替身身上。

钉住的产品与安全承诺（任何一条退化都应该在这里红掉）：

* 令牌是唯一凭据：篡改一位、换密钥重签、字段多一个/少一个、版本不对、签名不是 64 位小写
  十六进制、base64 不规范或根本不是 JSON —— 各自的 ``reason`` 必须精确；
* 单次链接 **一次访问 = 一段会话**：第二次打开被拒，但同一个人「开页 → 说时间 → 拿 .ics」
  走得通；换个浏览器/IP 的人接不上这段话；并发双发只消耗一次额度；
* 撤销立即生效、过期立即生效、``min(令牌, 库里)`` 只会收紧；
* 访客侧永远看不到主人身份：真实地址、真名、Bot 令牌、邮箱、事件标题、完整日程都不行；
* 没确认就不给 .ics；给了就是合法 RFC 5545（CRLF、75 octet 折行、UTC 时间戳）且不含
  ORGANIZER/ATTENDEE；
* 页面零外链、零脚本、零 Cookie、零原始令牌，CSP 用 ``sha256`` 钉住样式而不是
  ``'unsafe-inline'``，18 语种占位符完全一致。
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import inspect
import itertools
import json
import re
from datetime import datetime, timezone as utc_zone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .config import ConfigError, Settings
from .database import Database
from .eco_cards import ECO_MARKER, decode_message
from .guest_portal import (
    CARD_TTL_SECONDS,
    CLAIM_LEDGER_MAX,
    CSP_DIRECTIVES,
    CSP_POLICY,
    CSS_HASH,
    DEFAULT_ISSUE_TTL_HOURS,
    GUEST_ERRORS,
    ICS_FORMAT_LABEL,
    LINK_PATH_PREFIX,
    MAX_DURATION_MINUTES,
    MAX_LABEL_CHARS,
    MAX_MESSAGE_CHARS,
    MAX_REPLY_CHARS,
    MAX_TOPIC_CHARS,
    MEETING_ROOM_CHARS,
    MEETING_ROOM_PLACEHOLDER,
    MIN_DURATION_MINUTES,
    NOINDEX_META,
    PAGE_KEYS,
    PAGE_STRINGS,
    RATE_LIMIT_BURST_MESSAGES,
    RATE_LIMIT_WINDOW_MESSAGES,
    REASONS,
    SESSION_WINDOW_SECONDS,
    SIGNATURE_HEX_CHARS,
    TOKEN_MASK,
    TOKEN_MASK_CHARS,
    TOKEN_PAYLOAD_KEYS,
    TOKEN_VERSION,
    FreeSlot,
    GuestError,
    GuestPortal,
    card_text_of,
    mask_owner,
    normalise_slots,
    page_parity,
    page_text,
    render_page,
    resolve_zone,
    sign_token,
    token_mask,
    token_signature,
    verify_token,
)
from .i18n import LOCALES
from .selftest import Harness, SelfTest

_SECRET = "selftest-guest-secret"
_OWNER_NAME = "张三"
_OWNER_ADDRESS = "@zhang@popopx.im"
_OWNER_EMAIL = "zhang@example.org"
_OWNER_LINK = "https://popopx.im/a#abc"
_OWNER_TOKEN = "owner-bot-token-never-leaves"
_START = 1_800_000_000.0  # 固定假时钟基准：断言不依赖真实时间
_IDENTITY = (_OWNER_NAME, _OWNER_ADDRESS, _OWNER_EMAIL, _OWNER_LINK, _OWNER_TOKEN)

_COUNTER = itertools.count(1)
_B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


class _Clock:
    """可拨的假时钟：门户里每一个「现在」都来自它，所以过期/时效判定完全可复现。"""

    def __init__(self, start: float = _START) -> None:
        self.value = float(start)

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> float:
        self.value += float(seconds)
        return self.value


class _Rig:
    """一套隔离现场：临时账本 + 一个主人 + 可替换的空档源/推送替身 + 假时钟。"""

    def __init__(
        self,
        h: Harness,
        *,
        availability: str = "default",
        pusher: str = "ok",
        responder: Optional[Callable[..., Any]] = None,
        **env: Any,
    ) -> None:
        self.index = next(_COUNTER)
        self.clock = _Clock()
        self.pushes: List[Tuple[str, str]] = []
        self.availability_calls: List[Tuple[str, str]] = []
        self.slot_start = self.clock.value + 86_400.0
        self.slots: List[Any] = [
            {"start": self.slot_start, "end": self.slot_start + 4 * 3600.0},
            {"start": self.slot_start + 86_400.0, "end": self.slot_start + 86_400.0 + 3 * 3600.0},
        ]
        env.setdefault("GUEST_SECRET", _SECRET)
        self.settings: Settings = h.settings(**env)
        self.db: Database = h.database(f"guest{self.index}")
        self.bot_id = self.db.create_bot(
            f"guestbot{self.index}",
            5350 + self.index,
            display_name=_OWNER_NAME,
            bot_token=_OWNER_TOKEN,
            default_locale="zh-Hans",
        )["id"]
        self.db.update_bot(self.bot_id, contact_address=_OWNER_ADDRESS, permanent_link=_OWNER_LINK)
        self.bot_name = f"guestbot{self.index}"
        self.portal = GuestPortal(
            self.db,
            self.settings,
            availability=self._availability(availability),
            responder=responder,
            card_pusher=self._pusher(pusher),
            clock=self.clock,
        )

    def _availability(self, mode: str) -> Optional[Callable[[str, str, str], Any]]:
        if mode == "none":
            return None

        def source(bot_id: str, text: str, zone: str) -> Any:
            self.availability_calls.append((bot_id, text))
            if mode == "raise":
                raise RuntimeError("上游日历服务不可用")
            if mode == "empty":
                return []
            if mode == "titles":
                return [
                    {
                        "start": slot["start"],
                        "end": slot["end"],
                        "title": f"{_OWNER_NAME} 与 {_OWNER_EMAIL} 的秘密会议",
                        "location": _OWNER_LINK,
                        "organizer": _OWNER_ADDRESS,
                    }
                    for slot in self.slots
                ]
            if mode == "past":
                return [{"start": self.clock.value - 7200.0, "end": self.clock.value - 3600.0}]
            if mode == "pairs":
                return [[slot["start"], slot["end"]] for slot in self.slots]
            if mode == "wrapped":
                return {"free_slots": [{"from": slot["start"], "until": slot["end"]} for slot in self.slots]}
            return list(self.slots)

        return source

    def _pusher(self, mode: str) -> Optional[Callable[[str, Dict[str, Any]], Any]]:
        if mode == "none":
            return None

        def push(bot_id: str, proposal: Dict[str, Any]) -> Any:
            self.pushes.append((bot_id, str(proposal["proposal_id"])))
            if mode == "raise":
                raise RuntimeError("通道未就绪")
            if mode == "false":
                return False
            if mode == "async":

                async def deliver() -> bool:
                    return True

                return deliver()
            return True

        return push

    # 常用动作 ---------------------------------------------------------------
    def issue(self, **kwargs: Any) -> Dict[str, Any]:
        kwargs.setdefault("topic", "谈合作")
        return _run(self.portal.issue, self.bot_id, **kwargs)

    def open(self, token: str, *, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        return _run(self.portal.resolve, token, headers=headers if headers is not None else _visitor())

    def say(self, token: str, text: str, *, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        return _run(self.portal.message, token, text, headers=headers if headers is not None else _visitor())

    def invite(self, token: str, *, headers: Optional[Dict[str, str]] = None) -> Tuple[str, str]:
        return _run(self.portal.ics, token, headers=headers if headers is not None else _visitor())

    def approve(self, proposal_id: str) -> Dict[str, Any]:
        return self.db.update_proposal(proposal_id, status="approved")


def _call(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """调用同步或异步方法：异步的一律在一次性事件循环里跑完（不共享循环状态）。"""
    result = fn(*args, **kwargs)
    return asyncio.run(result) if inspect.isawaitable(result) else result


def _reason(t: SelfTest, label: str, want: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> bool:
    """跑一次门户调用，核对 :class:`GuestError` 的 ``reason`` 精确等于预期。"""
    try:
        _call(fn, *args, **kwargs)
    except GuestError as exc:
        return t.check(label, exc.reason == want, f"收到 {exc.reason}（期望 {want}）：{exc.detail}")
    except Exception as exc:  # noqa: BLE001 - 抛错类型不对本身就是失败
        return t.check(label, False, f"期望 GuestError/{want}，收到 {type(exc).__name__}: {exc}")
    return t.check(label, False, "期望抛错，实际未抛错")


def _rejects(t: SelfTest, label: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> bool:
    """只核对「门户拒绝了」，不钉死 reason。

    随机翻一个 base64 字符同时踩到两件事：字节变了（签名不匹配）或写法不再规范
    （``_b64url_decode`` 先于验签）。两者都是正确的拒绝，钉死哪一个反而是把实现细节
    写进断言里；真正需要精确 reason 的用例在别处用合法构造覆盖。
    """
    try:
        _call(fn, *args, **kwargs)
    except GuestError as exc:
        return t.check(label, exc.reason in {"malformed", "bad_signature"}, f"收到 {exc.reason}：{exc.detail}")
    except Exception as exc:  # noqa: BLE001
        return t.check(label, False, f"期望 GuestError，收到 {type(exc).__name__}: {exc}")
    return t.check(label, False, "期望拒绝，实际放行")


# ------------------------------------------------------------------ 现场脚手架
def _run(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """同步执行一个协程方法（门户对外方法全是 async，因为 DB 走 ``to_thread``）。"""
    return _call(fn, *args, **kwargs)


async def _gather(*coros: Any) -> List[Any]:
    """并发投递：返回结果或异常对象，绝不吞掉失败。"""
    return list(await asyncio.gather(*coros, return_exceptions=True))


def _visitor(index: int = 0, *, agent: str = "Mozilla/5.0 (selftest)") -> Dict[str, str]:
    """一个「访客」= 一个可识别的浏览器：IP + UA 决定指纹。"""
    return {
        "user-agent": agent,
        "x-forwarded-for": f"203.0.113.{10 + index}",
        "accept-language": "en-US,en;q=0.9",
    }


def _bump(text: str, *, count: int = 1) -> str:
    """把字符串里最后一个字母数字翻掉：只改一个比特的伪造方式。"""
    chars = list(text)
    for position in range(len(chars) - 1, -1, -1):
        if chars[position].isalnum():
            replacement = "a" if chars[position] != "a" else "b"
            chars[position] = replacement
            count -= 1
            if count == 0:
                break
    return "".join(chars)


def _segment_for(payload: Any, secret: str = _SECRET) -> str:
    """手工签一个「字段随便写」的令牌，用来验证 verify_token 的字段审查顺序。"""
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    segment = base64.urlsafe_b64encode(body).decode("ascii").rstrip("=")
    return f"{segment}.{token_signature(secret, segment)}"


def _clean_of(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "", text)


def _lines(text: str) -> List[str]:
    return text.split("\r\n")


def _unfolded(content: str) -> List[str]:
    """RFC 5545 反折行：以空格开头的行接回上一行。"""
    out: List[str] = []
    for line in _lines(content):
        if line.startswith(" ") and out:
            out[-1] += line[1:]
        else:
            out.append(line)
    return out


def _ics_seconds(line: str) -> int:
    """``DTSTART:20270116T080000Z`` → 当天秒数；解析不出来返回 -1 让断言自己红。"""
    match = re.search(r"T(\d{2})(\d{2})(\d{2})Z", line)
    if not match:
        return -1
    return int(match.group(1)) * 3600 + int(match.group(2)) * 60 + int(match.group(3))


def _identity_hits(blob: str) -> List[str]:
    return [needle for needle in _IDENTITY if needle in blob]


# --------------------------------------------------------------------------- 1
def _token_primitives(t: SelfTest) -> None:
    payload = {
        "v": TOKEN_VERSION,
        "lid": "gl_selftest01",
        "iat": int(_START),
        "exp": int(_START) + 3600,
        "mus": 2,
        "dur": 45,
    }
    token = sign_token(_SECRET, payload)
    segment, _, digest = token.partition(".")
    t.eq("令牌常量版本", TOKEN_VERSION, 1)
    t.eq("路径前缀", LINK_PATH_PREFIX, "/book/")
    t.eq("消息上限", MAX_MESSAGE_CHARS, 2000)
    t.eq("令牌字段集合", tuple(sorted(TOKEN_PAYLOAD_KEYS)), tuple(sorted(("v", "lid", "iat", "exp", "mus", "dur"))))
    t.eq("令牌恰好一个分隔点", token.count("."), 1)
    t.check("签名是 64 位小写十六进制", re.fullmatch(r"[0-9a-f]{64}", digest) is not None, digest)
    t.check("base64 段不带 padding", "=" not in segment and "+" not in segment and "/" not in segment, segment[:40])
    decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)).decode("utf-8")
    t.eq("负载是紧凑且按键排序的 JSON", decoded, '{"dur":45,"exp":1800003600,"iat":1800000000,"lid":"gl_selftest01","mus":2,"v":1}')
    t.eq("签名覆盖 base64 段本身", digest, token_signature(_SECRET, segment))
    t.eq("验签回环得到原负载", verify_token(_SECRET, token), payload)
    t.eq("同负载同令牌（确定性）", sign_token(_SECRET, payload), token)
    t.eq("键序不影响签名", verify_token(_SECRET, sign_token(_SECRET, dict(reversed(list(payload.items()))))), payload)
    t.check("令牌里没有主人身份", not _identity_hits(token), token[:40])
    t.eq("掩码长度", len(token_mask(token)), TOKEN_MASK_CHARS + 1)
    t.eq("掩码内容", token_mask(token), token[:TOKEN_MASK_CHARS] + TOKEN_MASK)
    t.eq("空令牌掩码", token_mask(""), "")
    t.eq("掩码不泄露签名", TOKEN_MASK in token_mask(token) and "." not in token_mask(token), True)
    # 过期不由 verify_token 判定：这是「签名有效但链接已过期」能被分成两种 reason 的前提
    stale = sign_token(_SECRET, {**payload, "exp": int(_START) - 1, "iat": int(_START) - 2})
    t.eq("verify 不看时钟（过期交给门户）", verify_token(_SECRET, stale)["exp"], int(_START) - 1)
    t.eq("每个 reason 都有状态码", sorted(GUEST_ERRORS), sorted(REASONS))
    t.check("状态码都是 4xx/5xx", all(400 <= code < 600 for code in GUEST_ERRORS.values()), str(GUEST_ERRORS))
    t.eq("未知 reason 折算成 malformed", GuestError("没这个东西").reason, "malformed")
    t.eq("未知 reason 的状态码", GuestError("没这个东西").http_status, 400)
    t.eq("关闭门户对访客表现为不存在", GUEST_ERRORS["disabled"], GUEST_ERRORS["unknown_token"])
    t.eq("空密钥拒绝签名", _reason(t, "空密钥", "unavailable", sign_token, "", payload), True)


def _token_tampering(t: SelfTest) -> None:
    payload = {
        "v": TOKEN_VERSION,
        "lid": "gl_selftest01",
        "iat": int(_START),
        "exp": int(_START) + 3600,
        "mus": 1,
        "dur": 60,
    }
    token = sign_token(_SECRET, payload)
    segment, _, digest = token.partition(".")
    t.eq("改一个字符的签名", _reason(t, "签名被改", "bad_signature", verify_token, _SECRET, segment + "." + _bump(digest)), True)
    # 换成另一份「合法但不同」的负载、保留原签名段：形状与规范性都过关，只能栽在 HMAC 上
    elsewhere = sign_token(_SECRET, {**payload, "dur": payload["dur"] - 1})
    t.check("对照负载段确实不同", elsewhere.partition(".")[0] != segment, elsewhere[:24])
    t.eq("顶着原签名换负载", _reason(t, "负载被换", "bad_signature", verify_token, _SECRET, elsewhere.partition(".")[0] + "." + digest), True)
    t.eq("改一个比特的负载", _rejects(t, "负载段翻字符", verify_token, _SECRET, _bump(segment) + "." + digest), True)
    t.eq("换密钥重签", _reason(t, "密钥不同", "bad_signature", verify_token, "另一个密钥", token), True)
    t.eq("签名字母大小写不合法", _reason(t, "大写签名", "malformed", verify_token, _SECRET, segment + "." + digest.upper()), True)
    t.eq("签名长度不足", _reason(t, "短签名", "malformed", verify_token, _SECRET, segment + "." + digest[:-1]), True)
    t.eq("签名不是十六进制", _reason(t, "非十六进制", "malformed", verify_token, _SECRET, segment + "." + "z" * SIGNATURE_HEX_CHARS), True)
    t.eq("多一段", _reason(t, "三段", "malformed", verify_token, _SECRET, token + ".0"), True)
    t.eq("没有签名段", _reason(t, "缺签名", "malformed", verify_token, _SECRET, segment), True)
    t.eq("空签名段", _reason(t, "空签名", "malformed", verify_token, _SECRET, segment + "."), True)
    t.eq("空令牌", _reason(t, "空令牌", "malformed", verify_token, _SECRET, ""), True)
    t.eq("只有空白", _reason(t, "空白令牌", "malformed", verify_token, _SECRET, "   "), True)
    t.eq("非字符串令牌", _reason(t, "非字符串", "malformed", verify_token, _SECRET, None), True)
    t.eq("段里带 padding", _reason(t, "padding", "malformed", verify_token, _SECRET, segment + "=" + "." + digest), True)
    t.eq("段里有非法字符", _reason(t, "非法字符", "malformed", verify_token, _SECRET, _bump(segment, count=0)[:10] + "*." + digest), True)
    padded = base64.urlsafe_b64encode(b"{}").decode("ascii")
    t.check("带 = 的段被拒", _reason(t, "规范检查", "malformed", verify_token, _SECRET, padded + "." + digest), True)
    canonical_body, variant_body = _non_canonical_pair()
    t.ne("非规范写法与规范写法字符串不同", variant_body, canonical_body)
    t.eq("两种写法解出同一份字节", base64.urlsafe_b64decode(variant_body + "=="), base64.urlsafe_b64decode(canonical_body + "=="))
    t.eq("规范写法走得到验签这一步", _reason(t, "规范编码", "bad_signature", verify_token, _SECRET, canonical_body + "." + "0" * SIGNATURE_HEX_CHARS), True)
    t.eq("同一字节的另一种 base64 写法", _reason(t, "非规范编码", "malformed", verify_token, _SECRET, variant_body + "." + token_signature(_SECRET, variant_body)), True)
    garbage = base64.urlsafe_b64encode(binascii.a2b_hex("00ff1ead")).decode("ascii").rstrip("=")
    t.eq("段不是 UTF-8 JSON", _reason(t, "二进制段", "malformed", verify_token, _SECRET, garbage + "." + token_signature(_SECRET, garbage)), True)
    not_json = base64.urlsafe_b64encode(b"plain text").decode("ascii").rstrip("=")
    t.eq("段不是 JSON", _reason(t, "纯文本段", "malformed", verify_token, _SECRET, not_json + "." + token_signature(_SECRET, not_json)), True)
    for label, body in (
        ("JSON 数组", [1, 2, 3]),
        ("JSON 字符串", "token"),
        ("JSON 数字", 12),
        ("JSON null", None),
    ):
        signed = _segment_for(body)
        t.eq(f"负载不是对象（{label}）", _reason(t, f"对象性 {label}", "malformed", verify_token, _SECRET, signed), True)
    t.eq("负载缺字段", _reason(t, "缺字段", "malformed", verify_token, _SECRET, _segment_for({k: v for k, v in payload.items() if k != "mus"})), True)
    t.eq("负载多字段", _reason(t, "多字段", "malformed", verify_token, _SECRET, _segment_for({**payload, "role": "owner"})), True)
    t.eq("版本不符", _reason(t, "版本", "malformed", verify_token, _SECRET, _segment_for({**payload, "v": TOKEN_VERSION + 1})), True)
    t.eq("exp 不晚于 iat", _reason(t, "时间倒置", "malformed", verify_token, _SECRET, _segment_for({**payload, "exp": payload["iat"]})), True)
    t.eq("lid 非法字符", _reason(t, "非法 lid", "malformed", verify_token, _SECRET, _segment_for({**payload, "lid": "GL!!!"})), True)
    t.eq("lid 太短", _reason(t, "lid 太短", "malformed", verify_token, _SECRET, _segment_for({**payload, "lid": "ab"})), True)
    t.eq("mus 为 0", _reason(t, "mus=0", "malformed", verify_token, _SECRET, _segment_for({**payload, "mus": 0})), True)
    t.eq("mus 超上限", _reason(t, "mus=1001", "malformed", verify_token, _SECRET, _segment_for({**payload, "mus": 1001})), True)
    t.eq("dur 过小", _reason(t, "dur=1", "malformed", verify_token, _SECRET, _segment_for({**payload, "dur": 1})), True)
    t.eq("dur 过大", _reason(t, "dur=9999", "malformed", verify_token, _SECRET, _segment_for({**payload, "dur": 9999})), True)
    t.eq("布尔冒充整数", _reason(t, "布尔 v", "malformed", verify_token, _SECRET, _segment_for({**payload, "v": True})), True)
    t.eq("字符串冒充整数", _reason(t, "字符串 exp", "malformed", verify_token, _SECRET, _segment_for({**payload, "exp": "1900000000"})), True)
    t.eq("浮点 exp 被拒", _reason(t, "浮点 exp", "malformed", verify_token, _SECRET, _segment_for({**payload, "exp": payload["exp"] + 0.5})), True)


def _non_canonical_pair(raw: bytes = b'{"v":1}') -> Tuple[str, str]:
    """返回 ``(规范段, 同一份字节的非规范写法)``。

    base64url 的最后一组只有在字节数为 3 的倍数时才是满位：``n % 3 == 1`` 留 4 个空闲位，
    ``n % 3 == 2`` 留 2 个。改这些低位得到的字符串解码结果完全相同，但不是规范形式——
    门户必须拒绝，否则同一链接会有多条可分别计数的字符串。
    """
    canonical = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    slack = len(canonical) * 6 - 8 * len(raw)
    if slack <= 0:
        raise AssertionError("构造样本没有空闲位，换 raw 长度")
    last = _B64URL_ALPHABET.index(canonical[-1])
    for alt in range(64):
        if alt != last and (alt >> slack) == (last >> slack):
            return canonical, canonical[:-1] + _B64URL_ALPHABET[alt]
    raise AssertionError("找不到同前缀的另一种写法")


# --------------------------------------------------------------------------- 2
def _issuance(t: SelfTest, h: Harness) -> None:
    rig = _Rig(h)
    issued = rig.issue(topic="谈合作 " + _OWNER_ADDRESS, label="给 A 公司", max_uses=3, duration_minutes=30, ttl_hours=2)
    t.check("issue 返回键齐全", set(issued) >= {"link_id", "token", "url", "expires_at", "max_uses", "duration_minutes"}, str(sorted(issued)))
    t.eq("URL 前缀", issued["url"][: len("http://127.0.0.1:8090" + LINK_PATH_PREFIX)], "http://127.0.0.1:8090" + LINK_PATH_PREFIX)
    t.eq("URL 尾部就是令牌", issued["url"].rsplit(LINK_PATH_PREFIX, 1)[1], issued["token"])
    t.eq("TTL 精确到秒", round(issued["expires_at"] - _START), 2 * 3600)
    t.eq("时长落库", issued["duration_minutes"], 30)
    t.eq("次数落库", issued["max_uses"], 3)
    t.eq("库里链接状态", rig.db.get_guest_link(token=issued["token"])["status"], "active")
    t.eq("库里 uses", rig.db.get_guest_link(token=issued["token"])["uses"], 0)
    t.eq("默认 TTL 来自 settings", (rig.issue()["expires_at"] - _START) / 3600, float(rig.settings.guest_default_ttl_hours))
    t.eq("默认 TTL 常量", DEFAULT_ISSUE_TTL_HOURS, rig.settings.guest_default_ttl_hours)
    t.eq("默认时长", rig.issue()["duration_minutes"], 60)
    t.eq("签名可自校验", verify_token(_SECRET, issued["token"])["mus"], 3)
    t.eq("令牌里的 lid 与 link_id 一致", verify_token(_SECRET, issued["token"])["lid"], issued["link_id"])
    t.eq("非法 bot", _reason(t, "不存在的 Bot", "unavailable", rig.portal.issue, "bot_不存在"), True)
    t.eq("缺 bot_id", _reason(t, "空 bot_id", "malformed", rig.portal.issue, ""), True)
    t.eq("max_uses=0", _reason(t, "零次数", "malformed", rig.portal.issue, rig.bot_id, max_uses=0), True)
    t.eq("max_uses 超上限", _reason(t, "一万次", "malformed", rig.portal.issue, rig.bot_id, max_uses=1001), True)
    t.eq("时长过小", _reason(t, "时长小", "malformed", rig.portal.issue, rig.bot_id, duration_minutes=1), True)
    t.eq("时长过大", _reason(t, "时长大", "malformed", rig.portal.issue, rig.bot_id, duration_minutes=MAX_DURATION_MINUTES + 1), True)
    t.eq("TTL 非数字", _reason(t, "TTL 非数字", "malformed", rig.portal.issue, rig.bot_id, ttl_hours="两天"), True)
    t.eq("TTL 过长", _reason(t, "TTL 过长", "malformed", rig.portal.issue, rig.bot_id, ttl_hours=10_000), True)
    t.eq("TTL 太短被拒", _reason(t, "TTL 太短", "malformed", rig.portal.issue, rig.bot_id, ttl_hours=0.0001), True)
    t.eq("时区不可解析", _reason(t, "怪时区", "malformed", rig.portal.issue, rig.bot_id, timezone="Mars/Olympus"), True)
    t.eq("合法时区可解析", rig.issue(timezone="Asia/Shanghai")["link_id"][:3], "gl_")
    t.eq("UTC 偏移时区可解析", rig.issue(timezone="+05:30")["duration_minutes"], 60)
    # 主题/标签里的邮箱与主人身份都被掩掉
    view = rig.open(issued["token"])
    t.check("主题里的邮箱被掩码", _OWNER_ADDRESS not in view["topic"] and "[masked]" in view["topic"], view["topic"])
    t.eq("标签保留但过掩码", view["label"], "给 A 公司")
    t.eq("视图不含原始令牌", issued["token"] not in json.dumps(view, ensure_ascii=False), True)
    t.eq("视图只有掩码令牌", view["token_mask"], token_mask(issued["token"]))
    t.check("视图不携带掩码清单", "needles" not in view, str(sorted(view)))
    t.eq("视图里没有主人身份", _identity_hits(json.dumps(view, ensure_ascii=False)), [])

    closed = _Rig(h, GUEST_ENABLED="0")
    t.eq("门户关闭时 issue 拒绝", _reason(t, "关闭", "disabled", closed.portal.issue, closed.bot_id), True)
    t.eq("门户关闭时 resolve 也拒绝", _reason(t, "关闭 resolve", "disabled", closed.portal.resolve, "随便"), True)

    plain = _Rig(h, GUEST_PUBLIC_BASE_URL="http://book.example.org")
    t.eq("公网明文 http 被拒", _reason(t, "明文公网", "unavailable", plain.portal.issue, plain.bot_id), True)
    secure = _Rig(h, GUEST_PUBLIC_BASE_URL="https://book.example.org/")
    t.eq("https 公网前缀可用", secure.issue()["url"][:30], "https://book.example.org/book/")
    credentialed = _Rig(h, GUEST_PUBLIC_BASE_URL="https://u:p@book.example.org")
    t.eq("带凭据的前缀被拒", _reason(t, "带凭据", "unavailable", credentialed.portal.issue, credentialed.bot_id), True)
    query = _Rig(h, GUEST_PUBLIC_BASE_URL="https://book.example.org/?x=1")
    t.eq("带查询串的前缀被拒", _reason(t, "带查询", "unavailable", query.portal.issue, query.bot_id), True)
    pathed = _Rig(h, GUEST_PUBLIC_BASE_URL="https://book.example.org/sub")
    t.eq("带路径的前缀被拒（路径由本模块拼）", _reason(t, "带路径", "unavailable", pathed.portal.issue, pathed.bot_id), True)
    # ``STUDIO_HOST`` 是绑定地址，写成 URL 属于配置层错误：设置阶段就抛，不留到铸造时
    t.raises("host 写成 URL 被配置层拒绝", ConfigError, h.settings, STUDIO_HOST="http://127.0.0.1")
    ipv6 = _Rig(h, STUDIO_HOST="::1")
    t.eq("IPv6 host 加方括号", ipv6.portal.public_base(), "http://[::1]:8090")


def _secret_handling(t: SelfTest, h: Harness) -> None:
    first = _Rig(h, GUEST_SECRET=None)
    second = GuestPortal(first.db, first.settings, clock=first.clock)
    issued = first.issue()
    t.eq("密钥落在数据目录文件里", first.settings.guest_key_file.is_file(), True)
    t.eq("密钥文件权限 0600", first.settings.guest_key_file.stat().st_mode & 0o777, 0o600)
    t.check("ensure_guest_secret 与 settings.guest_secret 一致", bool(first.settings.guest_secret))
    t.eq("另一个实例（等同重启）能验同一个令牌", verify_token(second.settings.ensure_guest_secret(), issued["token"])["lid"], issued["link_id"])
    t.eq("第二个实例可以打开同一条链接", second.resolve.__name__, "resolve")
    view = _run(second.resolve, issued["token"], headers=_visitor())
    t.eq("重启后仍能读到来访记录", view["uses"], 1)
    t.check("密钥本身不出现在任何访客输出", _SECRET not in json.dumps(view, ensure_ascii=False))


# --------------------------------------------------------------------------- 3
def _visits_and_replay(t: SelfTest, h: Harness) -> None:
    rig = _Rig(h)
    single = rig.issue(max_uses=1)
    token = single["token"]
    opened = rig.open(token)
    t.eq("单次链接打开后 uses", opened["uses"], 1)
    t.eq("单次链接打开后剩余", opened["remaining"], 0)
    t.eq("库里状态翻成 exhausted", rig.db.get_guest_link(token=token)["status"], "exhausted")
    t.eq("第二次被拒", _reason(t, "二次打开", "exhausted", rig.portal.resolve, token, headers=_visitor(3)), True)
    t.eq("第三次仍是被拒（不是 500）", _reason(t, "三次打开", "exhausted", rig.portal.resolve, token, headers=_visitor(4)), True)
    t.eq("预算不会被拒开消耗", rig.db.get_guest_link(token=token)["uses"], 1)
    # 同一个人：开页 → 说话 → 拿邀请，全程不需要第二次额度
    said = rig.say(token, "第一个时段")
    t.eq("同一访客可以继续对话", said["status"], "proposed")
    rig.approve(said["proposal_id"])
    name, _ = rig.invite(token)
    t.check("同一访客可以取 .ics", name.endswith(".ics"), name)

    multi = rig.issue(max_uses=3)
    for step in range(3):
        view = rig.open(multi["token"], headers=_visitor(step))
        t.eq(f"多次链接第 {step + 1} 次可用", view["uses"], step + 1)
    t.eq("多次链接第 4 次被拒", _reason(t, "多次用尽", "exhausted", rig.portal.resolve, multi["token"], headers=_visitor(9)), True)
    t.eq("用尽后状态", rig.db.get_guest_link(token=multi["token"])["status"], "exhausted")

    race = rig.issue(max_uses=1)
    results = _run(_gather, race["token"], race=rig)
    kinds = [type(item).__name__ for item in results]
    t.eq("并发双发只有一个成功", kinds.count("dict"), 1)
    t.eq("另一个是 GuestError", kinds.count("GuestError"), 1)
    loser = [item for item in results if isinstance(item, GuestError)]
    t.check("并发失败方拿到重放/用尽", loser and loser[0].reason in ("replayed", "exhausted"), str(loser))
    t.eq("并发双发只记一次", rig.db.get_guest_link(token=race["token"])["uses"], 1)

    revoked = rig.issue(max_uses=2)
    rig.open(revoked["token"])
    after = _run(rig.portal.revoke, rig.bot_id, revoked["link_id"])
    t.eq("撤销后状态", after["status"], "revoked")
    t.eq("撤销仍只暴露掩码令牌", after["token_mask"], token_mask(revoked["token"]))
    t.eq("撤销后打开被拒", _reason(t, "撤销 resolve", "revoked", rig.portal.resolve, revoked["token"], headers=_visitor()), True)
    t.eq("撤销后发言被拒", _reason(t, "撤销 message", "revoked", rig.portal.message, revoked["token"], "还在吗"), True)
    t.eq("撤销后取邀请被拒", _reason(t, "撤销 ics", "revoked", rig.portal.ics, revoked["token"]), True)
    t.eq("撤销不消耗额度", rig.db.get_guest_link(token=revoked["token"])["uses"], 1)
    t.eq("撤销别人的链接被拒", _reason(t, "跨 Bot 撤销", "unknown_token", rig.portal.revoke, "bot_别的", revoked["link_id"]), True)
    t.eq("撤销不存在的链接", _reason(t, "撤销不存在", "unknown_token", rig.portal.revoke, rig.bot_id, "gl_不存在"), True)

    gone = rig.issue(ttl_hours=1)
    rig.clock.advance(2 * 3600)
    t.eq("过期后打开被拒", _reason(t, "过期 resolve", "expired", rig.portal.resolve, gone["token"], headers=_visitor()), True)
    t.eq("过期后发言被拒", _reason(t, "过期 message", "expired", rig.portal.message, gone["token"], "改天"), True)
    t.eq("过期后取邀请被拒", _reason(t, "过期 ics", "expired", rig.portal.ics, gone["token"]), True)
    t.eq("过期状态被写回库里", rig.db.get_guest_link(token=gone["token"])["status"], "expired")

    # 收紧而非放宽：把库里的预算改大不能让已用完的令牌复活；改小则立即生效
    tight = rig.issue(max_uses=1)
    rig.open(tight["token"], headers=_visitor(1))
    rig.db.conn.execute("UPDATE guest_links SET max_uses = 9 WHERE link_id = ?", (tight["link_id"],))
    rig.db.conn.commit()
    fresh = GuestPortal(rig.db, rig.settings, availability=lambda *_a: rig.slots, clock=rig.clock)
    t.eq("预算放大不复活令牌", _reason(t, "放大预算", "exhausted", fresh.resolve, tight["token"], headers=_visitor(2)), True)
    loose = rig.issue(max_uses=5)
    rig.db.conn.execute("UPDATE guest_links SET max_uses = 1 WHERE link_id = ?", (loose["link_id"],))
    rig.db.conn.commit()
    t.eq("库里收紧立即生效（1/1）", rig.open(loose["token"], headers=_visitor(5))["remaining"], 0)
    t.eq("收紧后第二次打开被拒", _reason(t, "收紧后", "exhausted", fresh.resolve, loose["token"], headers=_visitor(6)), True)

    forged = rig.issue()
    stolen = verify_token(_SECRET, forged["token"])
    other = sign_token("另一个密钥", stolen)
    # 换密钥重签：HMAC 先失败，门户一次库都不查，所以攻击者拿不到「这条链接存在吗」的判据
    t.eq("别处签的合法令牌", _reason(t, "跨密钥", "bad_signature", rig.portal.resolve, other, headers=_visitor()), True)
    t.eq(
        "跨密钥且 lid 不存在也是同一个拒绝",
        _reason(
            t,
            "跨密钥陌生 lid",
            "bad_signature",
            rig.portal.resolve,
            sign_token("另一个密钥", {**stolen, "lid": "gl_zzzzzzzz"}),
            headers=_visitor(),
        ),
        True,
    )
    swapped = sign_token(_SECRET, {**stolen, "lid": "gl_zzzzzzzz"})
    t.eq("签名有效但换过 lid", _reason(t, "换 lid", "unknown_token", rig.portal.resolve, swapped, headers=_visitor()), True)
    t.eq("根本不是令牌形状", _reason(t, "形状不对", "malformed", rig.portal.resolve, "不是一-个令牌"), True)


async def _gather(token: str, race: _Rig) -> List[Any]:
    """两个访客同时点同一条单次链接：领取必须是原子的。"""
    return list(
        await __import__("asyncio").gather(
            race.portal.resolve(token, headers=_visitor(20)),
            race.portal.resolve(token, headers=_visitor(21)),
            return_exceptions=True,
        )
    )


# --------------------------------------------------------------------------- 4
def _conversation(t: SelfTest, h: Harness) -> None:
    rig = _Rig(h)
    issued = rig.issue(topic="谈合作", duration_minutes=30, timezone="Asia/Shanghai")
    token = issued["token"]
    rig.open(token)
    result = rig.say(token, "第一个时段")
    t.eq("收敛到唯一时段", result["status"], "proposed")
    chosen_slot = FreeSlot(rig.slot_start, rig.slot_start + 30 * 60.0, "Asia/Shanghai")
    t.check("回复里给出选中的时段", chosen_slot.label(30) in result["reply"], result["reply"])
    t.check("回复带 .ics 说明", ICS_FORMAT_LABEL in result["reply"], result["reply"])
    t.check("expires_at 回给路由层", result["expires_at"] > _START, str(result["expires_at"]))
    messages = rig.db.list_guest_messages(issued["link_id"])
    t.eq("一轮对话写两条", len(messages), 2)
    t.eq("第一条是访客说的", messages[0]["role"], "visitor")
    t.eq("第二条是 Bot 回的", messages[1]["role"], "bot")
    t.eq("访客原话落库", messages[0]["text"], "第一个时段")
    t.check("访客指纹入库", len(messages[0]["visitor_hash"]) > 8, messages[0]["visitor_hash"])
    t.eq("Bot 回复挂上提案 id", messages[1]["proposal_id"], result["proposal_id"])
    pending = [row for row in rig.db.list_proposals(rig.bot_id, status="pending") if row["source"] == "guest"]
    t.eq("恰好一条 pending 的 guest 提案", len(pending), 1)
    proposal = rig.db.get_proposal(result["proposal_id"])
    t.eq("提案来源", proposal["source"], "guest")
    t.eq("提案动作", proposal["action"], "create")
    t.eq("提案状态", proposal["status"], "pending")
    t.eq("提案绑定链接", proposal["link_id"], issued["link_id"])
    t.eq("提案时长", proposal["duration_minutes"], 30)
    t.eq("提案起止合法", proposal["end_ts"] > proposal["start_ts"], True)
    t.eq("时段起点被采用", proposal["start_ts"], rig.slot_start)
    t.eq("提案时区", proposal["timezone"], "Asia/Shanghai")
    t.check("对话方是掩码引用", str(proposal["counterparty"]).startswith("guest+"), str(proposal["counterparty"]))
    t.eq("提案摘要不含主人身份", _identity_hits(proposal["summary"]), [])
    t.eq("卡片推送恰好一次", len(rig.pushes), 1)
    t.eq("推给正确的 Bot", rig.pushes[0][0], rig.bot_id)
    frame = card_text_of(proposal)
    t.check("卡片帧带 ECO 标记", ECO_MARKER in frame, frame[:40])
    t.check("帧前只有一行可见气泡文案", "\n" not in frame.partition(ECO_MARKER)[0].rstrip(), frame[:60])
    t.check("卡片正文不含主人身份", _identity_hits(frame) == [], frame[:120])
    t.eq("卡片 id 落库", proposal["card_id"][:5], "ppxpr")
    parsed = decode_message(frame)
    t.check("卡片可被解回", parsed is not None, str(parsed)[:80])
    t.eq("链接绑上提案", rig.db.get_guest_link(token=token)["proposal_id"], result["proposal_id"])
    t.eq("空档源被问到", len(rig.availability_calls), 1)
    t.eq("问的是这个 Bot", rig.availability_calls[0][0], rig.bot_id)
    reopened = rig.open(token) if False else None
    t.eq("resolve 之外的调用不额外计费", reopened, None)

    # 序号 / 时刻 / 日期三种说法都能收敛
    for label, phrase in (("序号", "2"), ("标签原文", rig.slots[0]["start"] and "第二个"), ("含糊", "哪天都行")):
        another = rig.issue(topic="再谈")
        rig.open(another["token"])
        outcome = rig.say(another["token"], phrase)
        t.check(f"{label}说法有明确结果", outcome["status"] in ("proposed", "open"), str(outcome["status"]))
    numbered = rig.issue(topic="选第二个")
    rig.open(numbered["token"])
    chosen = rig.say(numbered["token"], "2")
    t.eq("序号 2 命中第二个时段", rig.db.get_proposal(chosen["proposal_id"])["start_ts"], rig.slot_start + 86_400.0)

    empty = rig.issue()
    t.eq("空消息被拒", _reason(t, "空消息", "malformed", rig.portal.message, empty["token"], "   "), True)
    t.eq("超长消息被拒", _reason(t, "超长", "malformed", rig.portal.message, empty["token"], "啊" * (MAX_MESSAGE_CHARS * 2 + 1)), True)
    t.eq("控制字符被清", len(_run(rig.portal.message, empty["token"], "周三\x00\x0b下午")["reply"]) > 0, True)
    stored = rig.db.list_guest_messages(empty["link_id"])[-2]["text"]
    t.check("落库文本无控制字符", "\x00" not in stored and "\x0b" not in stored, repr(stored[:30]))

    nosource = _Rig(h, availability="none")
    quiet = nosource.issue()
    nosource.open(quiet["token"])
    fallen = nosource.say(quiet["token"], "随时都行")
    t.eq("没有空档源时状态诚实", fallen["status"], "unavailable")
    t.eq("没有空档源时不建提案", fallen["proposal_id"], "")
    t.eq("没有空档源时不推卡片", len(nosource.pushes), 0)
    t.check("降级话术不编时间", "09:" not in fallen["reply"] and "14:" not in fallen["reply"], fallen["reply"])

    boom = _Rig(h, availability="raise")
    broken = boom.issue()
    boom.open(broken["token"])
    t.eq("空档源抛错也降级", boom.say(broken["token"], "随时")["status"], "unavailable")
    past = _Rig(h, availability="past")
    old = past.issue()
    past.open(old["token"])
    t.eq("过去的空档不算空档", past.say(old["token"], "上周")["status"], "unavailable")

    nopush = _Rig(h, pusher="none")
    silent = nopush.issue()
    nopush.open(silent["token"])
    stuck = nopush.say(silent["token"], "第一个")
    t.eq("没有推送方时不谎称已送达", stuck["status"], "unavailable")
    t.check("提案仍然留在账上待处理", stuck["proposal_id"] != "", stuck["proposal_id"])
    t.eq("未推送的提案仍是 pending", nopush.db.get_proposal(stuck["proposal_id"])["status"], "pending")
    failing = _Rig(h, pusher="raise")
    fiasco = failing.issue()
    failing.open(fiasco["token"])
    t.eq("推送抛错不炸访客链路", failing.say(fiasco["token"], "第一个")["status"], "unavailable")
    denied = _Rig(h, pusher="false")
    nope = denied.issue()
    denied.open(nope["token"])
    t.eq("推送返回 False 也算未送达", denied.say(nope["token"], "第一个")["status"], "unavailable")
    awaited = _Rig(h, pusher="async")
    later = awaited.issue()
    awaited.open(later["token"])
    t.eq("异步推送被 await", awaited.say(later["token"], "第一个")["status"], "proposed")
    t.eq("异步推送计数", len(awaited.pushes), 1)

    visitor_mail = rig.issue(topic="带邮箱的访客")
    rig.open(visitor_mail["token"])
    leaked = rig.say(visitor_mail["token"], f"我邮箱 {_OWNER_EMAIL}，直接发我")
    t.check("回复里的邮箱被掩码", _OWNER_EMAIL not in leaked["reply"], leaked["reply"])
    logged = rig.db.list_guest_messages(visitor_mail["link_id"])
    t.check("访客原话按原样留账（只有出参被掩）", _OWNER_EMAIL in logged[0]["text"], logged[0]["text"])
    t.check("Bot 回账也是掩码后的", _OWNER_EMAIL not in logged[1]["text"], logged[1]["text"])

    def rude(bot_id: str, text: str, context: Dict[str, Any]) -> str:
        return f"照办，另外主人是 {_OWNER_ADDRESS}"

    polished = _Rig(h, responder=rude)
    ask = polished.issue()
    polished.open(ask["token"])
    answered = polished.say(ask["token"], "第一个")
    t.check("注入话术生效", answered["reply"].startswith("照办"), answered["reply"])
    t.check("注入话术说错话也被兜住", _OWNER_ADDRESS not in answered["reply"], answered["reply"])

    def leaker(bot_id: str, text: str, context: Dict[str, Any]) -> str:
        return f"请发到 {_OWNER_EMAIL}"

    risky = _Rig(h, responder=leaker)
    ask2 = risky.issue()
    risky.open(ask2["token"])
    t.check("带邮箱的话术退回模板", risky.say(ask2["token"], "第一个")["reply"] != "请发到 " + _OWNER_EMAIL, "")

    def sleepy(bot_id: str, text: str, context: Dict[str, Any]) -> Any:
        async def slow() -> str:
            return "不该在这里 await"

        return slow()

    stalled = _Rig(h, responder=sleepy)
    ask3 = stalled.issue()
    stalled.open(ask3["token"])
    t.check("协程话术不会挂住门户", stalled.say(ask3["token"], "第一个")["status"], "proposed")

    def raiser(bot_id: str, text: str, context: Dict[str, Any]) -> str:
        raise ValueError("话术引擎挂了")

    angry = _Rig(h, responder=raiser)
    ask4 = angry.issue()
    angry.open(ask4["token"])
    t.eq("话术抛错退回模板", angry.say(ask4["token"], "第一个")["status"], "proposed")


# --------------------------------------------------------------------------- 5
def _rate_limit_and_sessions(t: SelfTest, h: Harness) -> None:
    rig = _Rig(h)
    issued = rig.issue(max_uses=5)
    token = issued["token"]
    rig.open(token)
    codes: List[str] = []
    for step in range(RATE_LIMIT_BURST_MESSAGES + 3):
        try:
            rig.say(token, f"第 {step + 1} 次说")
            codes.append("ok")
        except GuestError as exc:
            codes.append(exc.reason)
    t.eq("突发窗口内被限流", codes.count("rate_limited"), len(codes) - RATE_LIMIT_BURST_MESSAGES)
    t.eq("限流前正常答复", codes[:RATE_LIMIT_BURST_MESSAGES], ["ok"] * RATE_LIMIT_BURST_MESSAGES)
    rig.clock.advance(120.0)
    t.check("窗口滑过后恢复", rig.say(token, "过两分钟再说")["status"] in ("proposed", "open"), "仍被限流")
    t.eq("限流键数受上限约束", len(rig.portal._limiter) <= 2048, True)

    shared = rig.issue(max_uses=1)
    rig.open(shared["token"], headers=_visitor(31))
    rig.say(shared["token"], "第一个", headers=_visitor(31))
    t.check(
        "同访客会话延续可用",
        rig.say(shared["token"], "改成 30 分钟", headers=_visitor(31))["status"] in ("proposed", "open"),
        "同一个人被当成陌生访客拒了",
    )
    t.eq("会话延续不再计费", rig.db.get_guest_link(token=shared["token"])["uses"], 1)
    t.eq("换浏览器接不上话", _reason(t, "陌生访客", "exhausted", rig.portal.message, shared["token"], "把邀请给我", headers=_visitor(32)), True)
    t.eq("换 IP 也算陌生人", _reason(t, "换 IP", "exhausted", rig.portal.message, shared["token"], "把邀请给我",
                                    headers={"user-agent": "Mozilla/5.0 (selftest)", "x-forwarded-for": "198.51.100.9", "accept-language": "en"}), True)

    revived = GuestPortal(
        rig.db,
        rig.settings,
        availability=lambda *_a: rig.slots,
        card_pusher=lambda *_a: True,
        clock=rig.clock,
    )
    t.eq(
        "新实例（等同重启）里同访客仍可续",
        _run(revived.message, shared["token"], "第一个时段", headers=_visitor(31))["status"],
        "proposed",
    )
    t.eq("新实例里陌生访客仍被拒", _reason(t, "重启后陌生", "exhausted", revived.message, shared["token"], "把邀请给我", headers=_visitor(33)), True)

    anon = _Rig(h)
    quiet = anon.issue(max_uses=1)
    anon.open(quiet["token"], headers={})
    t.eq("完全没有身份信息时不误伤本人", anon.say(quiet["token"], "第一个", headers={})["status"], "proposed")

    ledger = _LedgerProbes(t)
    t.eq("领取表：第一次 granted", ledger.claim("k", 2, 0), "granted")
    t.eq("领取表：第二次仍 granted", ledger.claim("k", 2, 1), "granted")
    t.eq("领取表：库里已到预算即 exhausted", ledger.claim("k", 2, 2), "exhausted")
    t.eq("领取表：账本领先库时判重放", ledger.claim("fresh", 1, 0), "granted")
    t.eq("领取表：并发落败判重放", ledger.claim("fresh", 1, 0), "replayed")
    t.eq("领取表：计数", ledger.count("fresh"), 1)
    ledger.release("fresh")
    t.eq("领取表：回滚后可再领", ledger.count("fresh"), 0)
    ledger.forget("k")
    t.eq("领取表：forget 清空", ledger.count("k"), 0)
    ledger.seed("s", 3)
    t.eq("领取表：seed 对齐库", ledger.count("s"), 3)
    for step in range(CLAIM_LEDGER_MAX + 50):
        ledger.claim(f"bulk{step}", 5, 0)
    t.eq("领取表有上限（不被枚举撑爆）", len(ledger) <= CLAIM_LEDGER_MAX, True)

    limiter = _RateProbes(t)
    hits = [limiter.hit("one", _START + step) for step in range(RATE_LIMIT_BURST_MESSAGES + 2)]
    # 双层窗口：突发 5 秒 4 条、持续 60 秒 12 条。每秒一条时先撞突发墙，滑过去再按秒放行
    t.eq("突发窗口内放行", hits[:RATE_LIMIT_BURST_MESSAGES], [0.0] * RATE_LIMIT_BURST_MESSAGES)
    t.check("突发窗口第 5 条给出 retry_after", hits[RATE_LIMIT_BURST_MESSAGES] > 0, str(hits[RATE_LIMIT_BURST_MESSAGES]))
    slow = [limiter.hit("slow", _START + step * 4.0) for step in range(RATE_LIMIT_WINDOW_MESSAGES + 2)]
    t.eq("持续窗口内放行", slow[:RATE_LIMIT_WINDOW_MESSAGES], [0.0] * RATE_LIMIT_WINDOW_MESSAGES)
    t.check("持续窗口越界被限", slow[RATE_LIMIT_WINDOW_MESSAGES] > 0, str(slow[RATE_LIMIT_WINDOW_MESSAGES]))
    t.eq("换键互不影响", limiter.hit("two", _START), 0.0)
    limiter.reset("one")
    t.eq("按键重置", limiter.hit("one", _START), 0.0)


class _LedgerProbes:
    """只为把 :class:`guest_portal._ClaimLedger` 的判定顺序钉住，不参与门户流程。"""

    def __init__(self, t: SelfTest) -> None:
        from .guest_portal import _ClaimLedger

        self._ledger = _ClaimLedger(limit=64)
        t.check("领取表可实例化", self._ledger is not None)

    def claim(self, key: str, budget: int, uses: int) -> str:
        return self._ledger.claim(key, budget, uses)

    def release(self, key: str) -> None:
        self._ledger.release(key)

    def forget(self, key: str) -> None:
        self._ledger.forget(key)

    def seed(self, key: str, used: int) -> None:
        self._ledger.seed(key, used)

    def count(self, key: str) -> int:
        return self._ledger.count(key)

    def __len__(self) -> int:
        return len(self._ledger)


class _RateProbes:
    def __init__(self, t: SelfTest) -> None:
        from .guest_portal import _RateLimiter

        self._limiter = _RateLimiter(max_keys=32)
        t.check("限流表可实例化", self._limiter is not None)

    def hit(self, key: str, moment: float) -> float:
        return self._limiter.hit(key, moment)

    def reset(self, key: str = "") -> None:
        self._limiter.reset(key)


def _session_probe(t: SelfTest) -> None:
    from .guest_portal import _Sessions

    table = _Sessions(limit=32)
    table.open("gl_a", "face1", now=_START, until=_START + 60)
    t.eq("会话：命中", table.live("gl_a", "face1", _START), True)
    t.eq("会话：换脸不命中", table.live("gl_a", "face2", _START), False)
    t.eq("会话：到期不命中", table.live("gl_a", "face1", _START + 61), False)
    t.eq("会话：到期后条目被清", table.count("gl_a"), 0)
    for step in range(40):
        table.open(f"gl_{step}", f"face{step}", now=_START, until=_START + 3600)
    t.eq("会话表有上限", len(table) <= 32, True)
    table.open("gl_z", "facez", now=_START, until=_START + 3600)
    t.eq("会话：按链接清空", table.forget("gl_z"), 1)
    t.eq("清空后不命中", table.live("gl_z", "facez", _START), False)
    t.eq("会话窗口是正数", SESSION_WINDOW_SECONDS > 0, True)


# --------------------------------------------------------------------------- 6
def _calendar(t: SelfTest, h: Harness) -> None:
    rig = _Rig(h)
    issued = rig.issue(topic="面谈", duration_minutes=45, timezone="Europe/Berlin")
    token = issued["token"]
    rig.open(token)
    said = rig.say(token, "第一个")
    t.eq("确认前取 .ics 被拒", _reason(t, "未确认", "unavailable", rig.portal.ics, token, headers=_visitor()), True)
    proposal = rig.approve(said["proposal_id"])
    t.eq("批准后提案状态", proposal["status"], "approved")
    filename, content = rig.invite(token)
    t.check("文件名是 .ics", filename.endswith(".ics") and filename.startswith("popopx-meeting-"), filename)
    t.check("以 VCALENDAR 开头", content.startswith("BEGIN:VCALENDAR\r\n"), content[:24])
    t.check("以 VCALENDAR 结尾", content.rstrip("\r\n").endswith("END:VCALENDAR"), content[-24:])
    t.check("行分隔只有 CRLF", "\n" not in content.replace("\r\n", ""), "存在裸 LF")
    t.check("每行不超过 75 个八位字节", all(len(line.encode("utf-8")) <= 75 for line in _lines(content)), str(max(len(line.encode("utf-8")) for line in _lines(content))))
    unfolded = _unfolded(content)
    keys = [line.split(":", 1)[0].split(";")[0] for line in unfolded]
    for required in ("VERSION", "PRODID", "CALSCALE", "UID", "DTSTAMP", "DTSTART", "DTEND"):
        t.contains("日历含 " + required, " | ".join(keys), required)
    # BEGIN/END:VEVENT 是整行而不是属性名，从 keys 里找永远找不到
    t.check("日历含 BEGIN:VEVENT", any(line == "BEGIN:VEVENT" for line in unfolded), " | ".join(keys))
    t.check("日历含 END:VEVENT", any(line == "END:VEVENT" for line in unfolded), " | ".join(keys))
    t.eq("不含 ORGANIZER", any(line.startswith("ORGANIZER") for line in unfolded), False)
    t.eq("不含 ATTENDEE", any(line.startswith("ATTENDEE") for line in unfolded), False)
    t.eq("不含主人身份", _identity_hits(content), [])
    t.check("不含 Bot 名", rig.bot_name not in content, rig.bot_name)
    stamp = [line for line in unfolded if line.startswith("DTSTART")][0]
    t.check("DTSTART 是 UTC Z 形式", re.fullmatch(r"DTSTART:\d{8}T\d{6}Z", stamp) is not None, stamp)
    t.check("DTEND 是 UTC Z 形式", any(re.fullmatch(r"DTEND:\d{8}T\d{6}Z", line) for line in unfolded), "没有 DTEND")
    end_line = [line for line in unfolded if line.startswith("DTEND")][0]
    start_line = stamp
    t.eq("时长 45 分钟", _ics_seconds(end_line) - _ics_seconds(start_line), 45 * 60)
    t.eq("UID 带链接指纹", [line for line in unfolded if line.startswith("UID")][0].count(issued["link_id"]), 1)
    t.check("STATUS 是 CONFIRMED", any(line == "STATUS:CONFIRMED" for line in unfolded), "")
    summary = [line for line in unfolded if line.startswith("SUMMARY")][0]
    t.contains("摘要带主题", summary, "面谈")
    t.eq("没有 URL 行（未配置会议基址）", any(line.startswith("URL") for line in unfolded), False)
    location = [line for line in unfolded if line.startswith("LOCATION")][0]
    t.check("LOCATION 说明在 POPOPX Chat 内", "POPOPX" in location, location)

    with_url = _Rig(h, AGENT_MEETING_BASE_URL="http://127.0.0.1:8088/r/{room}")
    other = with_url.issue(topic="带房间")
    with_url.open(other["token"])
    second = with_url.say(other["token"], "第一个")
    with_url.approve(second["proposal_id"])
    _, content2 = with_url.invite(other["token"])
    lines2 = _unfolded(content2)
    url_line = [line for line in lines2 if line.startswith("URL:")]
    t.eq("配置了基址就给出 URL", len(url_line), 1)
    parts = urlsplit(url_line[0][4:])
    t.eq("会议域名来自配置", parts.hostname, "127.0.0.1")
    t.eq("占位符被替换成房间号", "{" + "room}" not in url_line[0], True)
    room = parts.path.rsplit("/", 1)[-1]
    t.eq("房间号长度", len(room), MEETING_ROOM_CHARS)
    t.check("房间号是 base64url 字符", _clean_of(room) == room, room)
    t.check("房间号不含链接 id", issued["link_id"] not in url_line[0], url_line[0])
    t.check("房间号不含提案 id", second["proposal_id"] not in url_line[0], url_line[0])
    t.check("房间号不是原样 link_id", room != other["link_id"], room)
    again_name, again = with_url.invite(other["token"])
    t.eq("同一链接的房间号稳定", _unfolded(again)[0:1], _unfolded(content2)[0:1])
    t.check("再次取用得到同一 UID", f"UID:{_uid_of(content2)}" in again, again_name)

    bad_base = _Rig(h, AGENT_MEETING_BASE_URL="http://meet.example.org/{room}")
    third = bad_base.issue(topic="明文公网")
    bad_base.open(third["token"])
    said3 = bad_base.say(third["token"], "第一个")
    bad_base.approve(said3["proposal_id"])
    _, content3 = bad_base.invite(third["token"])
    t.eq("非法会议基址不产出 URL", any(line.startswith("URL:") for line in _unfolded(content3)), False)
    audited = bad_base.db.conn.execute("SELECT event, detail FROM negotiation_audit WHERE stage = 'ics'").fetchall()
    t.check("非法基址被记进审计", any("meeting_base_rejected" in " ".join(map(str, row)) for row in audited), str(audited)[:120])

    truncated = _Rig(h, AGENT_MEETING_BASE_URL="https://meet.example.org")
    fourth = truncated.issue(topic="无占位符")
    truncated.open(fourth["token"])
    said4 = truncated.say(fourth["token"], "第一个")
    truncated.approve(said4["proposal_id"])
    _, content4 = truncated.invite(fourth["token"])
    line4 = [line for line in _unfolded(content4) if line.startswith("URL:")][0]
    t.check("无占位符时拼成子路径", line4[4:].startswith("https://meet.example.org/") and len(line4.split("/")[-1]) == MEETING_ROOM_CHARS, line4)

    declined = _Rig(h)
    fifth = declined.issue(topic="被拒")
    declined.open(fifth["token"])
    got = declined.say(fifth["token"], "第一个")
    declined.db.update_proposal(got["proposal_id"], status="declined")
    t.eq("被拒后取 .ics 仍被拒", _reason(t, "declined", "unavailable", declined.portal.ics, fifth["token"], headers=_visitor()), True)
    broken = declined.db.update_proposal(got["proposal_id"], status="approved", start_ts=0.0, end_ts=0.0)
    t.eq("批准但时间被抹平也不给 .ics", _reason(t, "坏时间", "unavailable", declined.portal.ics, fifth["token"], headers=_visitor()), True)
    t.check("broken update 返回记录", broken["status"], "approved")


def _uid_of(content: str) -> str:
    for line in _unfolded(content):
        if line.startswith("UID:"):
            return line[4:]
    return ""


# --------------------------------------------------------------------------- 7
def _page(t: SelfTest, h: Harness) -> None:
    rig = _Rig(h)
    issued = rig.issue(topic="谈合作", max_uses=3)
    view = rig.open(issued["token"])
    html = rig.render = render_page(view, locale="zh-Hans")
    t.check("页面是完整 HTML", html.startswith("<!doctype html>") and html.rstrip().endswith("</html>"), html[:40])
    t.check("页面里不出现原始令牌", issued["token"] not in html, issued["token"][:32])
    t.check("页面里不出现签名段", issued["token"].partition(".")[2] not in html, html[:60])
    t.contains("带 CSP meta", html, 'http-equiv="Content-Security-Policy"')
    t.check("CSP 无 unsafe-inline", "unsafe-inline" not in html, html[:80])
    t.check("CSP 无 unsafe-eval", "unsafe-eval" not in CSP_POLICY, CSP_POLICY)
    t.check("script-src 为 none", "script-src 'none'" in CSP_DIRECTIVES, str(CSP_DIRECTIVES))
    t.check("style-src 用 sha256 钉住", f"style-src 'sha256-" in CSP_POLICY, CSP_POLICY)
    t.check("form-action 限同源", "form-action 'self'" in CSP_DIRECTIVES, "")
    t.check("base-uri 为 none", "base-uri 'none'" in CSP_DIRECTIVES, "")
    t.check("frame-ancestors 为 none", "frame-ancestors 'none'" in CSP_DIRECTIVES, "")
    t.check("connect-src 为 none", "connect-src 'none'" in CSP_DIRECTIVES, "")
    t.eq("无外链 src", re.search(r'src\s*=\s*"[^"]', html) is not None, False)
    t.check("无外链 href", "href=" not in html, "")
    t.check("无 <script", "<script" not in html.lower(), "")
    t.check("无 iframe", "<iframe" not in html.lower(), "")
    t.check("表单 action 为空串", 'action=""' in html, html[html.find("<form") : html.find("<form") + 120])
    t.contains("带 noindex", html, NOINDEX_META)
    t.check("带 referrer 策略", 'name="referrer" content="no-referrer"' in html, "")
    t.check("无 Cookie 相关属性", "set-cookie" not in html.lower(), "")
    t.check("语种属性", '<html lang="zh-Hans"' in html, "")
    t.contains("标题带主题", html, "谈合作")
    t.check("有输入区", "<textarea" in html and 'name="message"' in html, "")
    t.eq(" maxlength 与常量一致", f'maxlength="{MAX_MESSAGE_CHARS}"' in html, True)
    t.eq("语言下拉给出全部语种", html.count("<option value="), len(LOCALES))
    t.check("不索要邮箱/账号", ("type=\"email\"" not in html) and ("password" not in html.lower()), "")
    style = re.search(r"<style>(.*?)</style>", html, re.S)
    t.check("页面确有内联样式块", style is not None, "")
    if style:
        import base64 as _b64
        digest = _b64.b64encode(hashlib.sha256(style.group(1).encode("utf-8")).digest()).decode("ascii")
        t.eq("样式哈希与 CSP 一致", f"sha256-{digest}", CSS_HASH)
    evil = render_page({**view, "topic": "<script>alert(1)</script>", "label": '<img src=x onerror="1">'}, locale="en")
    t.check("主题里的脚本被转义", "<script>alert(1)</script>" not in evil, "")
    t.contains("转义后的尖括号", evil, "&lt;script&gt;")
    t.check("标签里的 img 被转义", "<img src=x" not in evil, "")
    threaded = render_page({**view, "messages": [{"role": "visitor", "text": "<b>粗体</b>"}, "纯字符串也安全"]}, locale="en")
    t.check("访客文本不会成为标记", "<b>粗体</b>" not in threaded, "")
    t.contains("访客文本被转义", threaded, "&lt;b&gt;")
    errored = render_page(view, locale="en", error="已用 3/3 次")
    t.contains("错误原因上屏", errored, "已用 3/3 次")
    t.check("错误不泄露令牌", issued["token"] not in errored, "")
    hostile_action = render_page(view, locale="en", form={"action": "https://evil.example/steal"})
    t.check("外部 action 被丢弃", "evil.example" not in hostile_action, "")
    for tricky in ("//evil.example", "javascript:alert(1)", "data:text/html", "mailto:a@b.c"):
        t.check(f"action 拒绝 {tricky}", tricky not in render_page(view, form={"action": tricky}, locale="en"), tricky)
    relative = render_page(view, form={"action": "/book/next"}, locale="en")
    t.contains("相对 action 保留", relative, 'action="/book/next"')
    nonce_view = {**view, "csrf": "abc123456789"}
    t.contains("合法 nonce 上屏", render_page(nonce_view, locale="en"), 'name="nonce" value="abc123456789"')
    forged = render_page({**view, "csrf": "<bad>"}, locale="en")
    form_head = forged.partition("<form")[2].partition("<textarea")[0]
    t.check("畸形 nonce 被丢", 'name="nonce"' not in form_head, form_head[:80])
    ready = render_page({**view, "ics_ready": True}, locale="en")
    t.contains("确认后给出 .ics 按钮", ready, ICS_FORMAT_LABEL)
    t.check("确认前没有 .ics 按钮", ICS_FORMAT_LABEL not in render_page(view, locale="en"), "未确认就给了下载入口")
    t.check("实例 render 与模块函数一致", rig.render == render_page(view, locale="zh-Hans"), "两条渲染路径不一致")
    masked_view = _run(rig.portal.render, view, locale="en")
    t.eq("实例 render 不额外泄露", _identity_hits(masked_view), [])

    for locale in LOCALES:
        rendered = render_page(view, locale=locale)
        t.check(f"{locale} 可渲染", rendered.startswith("<!doctype html>") and f'lang="{locale}' in rendered, rendered[:60])
        t.check(f"{locale} 无 unsafe-inline", "unsafe-inline" not in rendered, rendered[:60])
        t.check(f"{locale} 无原始令牌", issued["token"] not in rendered, issued["token"][:24])
    t.eq("语种数量", len(LOCALES), 18)
    t.eq("未知语种回退", render_page(view, locale="qq-ZZ")[:200].count('lang="en"'), 1)

    for locale in LOCALES:
        problems = page_parity(locale)
        t.eq(f"{locale} 文案与 en 完全对齐", problems, [])
    t.eq("文案键数", len(PAGE_KEYS), len(PAGE_STRINGS["en"]))
    t.check("每个语种的 promise 不含邮箱", all("@" not in PAGE_STRINGS[loc]["promise"] for loc in LOCALES), "")
    t.check("每个语种都写明无需账号", all(PAGE_STRINGS[loc]["promise"] for loc in LOCALES), "")
    t.check("每个语种的 brand 带 POPOPX", all("POPOPX" in PAGE_STRINGS[loc]["brand"] for loc in LOCALES), "")
    t.check("每个语种的 c_call 带 POPOPX", all("POPOPX" in PAGE_STRINGS[loc]["c_call"] for loc in LOCALES), "")
    # 示例必须「像人话」：24 小时制冒号写法在中文/日语里反而别扭，所以只钉住「给了一个具体时刻」，
    # 不钉死格式。
    t.check(
        "每个语种的 ask_placeholder 给了示例时刻",
        all(re.search(r"\d", PAGE_STRINGS[loc]["ask_placeholder"]) for loc in LOCALES),
        "",
    )
    t.check("每个语种的 c_body 都带三个占位符", all(set(re.findall(r"\{(\w+)\}", PAGE_STRINGS[loc]["c_body"])) == {"topic", "slot", "duration"} for loc in LOCALES), "")
    t.eq("page_text 未注册键报错", _raises(t, KeyError, page_text, "en", "不存在"), True)
    t.eq("page_text 占位符填充", page_text("en", "expires", expires="2026-01-01"), PAGE_STRINGS["en"]["expires"].format(expires="2026-01-01"))
    t.eq("page_text 多余参数不炸", page_text("en", "title", 随便=1), PAGE_STRINGS["en"]["title"])
    t.eq("page_text 未知语种回退到 en", page_text("qq", "title"), PAGE_STRINGS["en"]["title"])


def _raises(t: SelfTest, exc_type: type, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> bool:
    try:
        fn(*args, **kwargs)
    except exc_type:
        return t.check(f"{getattr(fn, '__name__', fn)} 抛 {exc_type.__name__}", True)
    except Exception as exc:  # noqa: BLE001
        return t.check(f"{getattr(fn, '__name__', fn)} 抛 {exc_type.__name__}", False, f"{type(exc).__name__}: {exc}")
    return t.check(f"{getattr(fn, '__name__', fn)} 抛 {exc_type.__name__}", False, "未抛错")


# --------------------------------------------------------------------------- 8
def _slot_projection(t: SelfTest) -> None:
    base = _START + 86_400.0
    raw = [
        {"start": base, "end": base + 3600.0, "title": f"{_OWNER_NAME} 的秘密会", "location": _OWNER_LINK, "attendees": [_OWNER_EMAIL]},
        {"from": base + 7200.0, "until": base + 10_800.0},
        [base + 3 * 3600.0, base + 4 * 3600.0],
        FreeSlot(base + 5 * 3600.0, base + 6 * 3600.0, "UTC", "不该出现的备注"),
    ]
    slots = normalise_slots(raw, timezone="UTC", duration_minutes=30, now=_START)
    t.eq("混合格式收敛为 4 格", len(slots), 4)
    t.check("时段按起点排序", [slot.start_ts for slot in slots] == sorted(slot.start_ts for slot in slots), str(slots[:2]))
    blob = json.dumps([slot.as_dict() for slot in slots], ensure_ascii=False)
    t.eq("事件标题/地点/参会人被丢弃", _identity_hits(blob), [])
    t.check("备注不外泄", "不该出现的备注" not in blob, blob[:80])
    t.eq("重复起点被去重", len(normalise_slots([{"start": base, "end": base + 60}, {"start": base, "end": base + 120}], now=_START)), 1)
    t.eq("上限生效", len(normalise_slots([{"start": base + step * 600.0, "end": base + step * 600.0 + 600.0} for step in range(20)], now=_START, limit=3)), 3)
    t.eq("过去的时段被丢掉", len(normalise_slots([{"start": _START - 3600.0, "end": _START - 1800.0}], now=_START)), 0)
    t.eq("None 输入", normalise_slots(None), [])
    t.eq("标量字符串输入", len(normalise_slots("2027-01-16 14:00", timezone="UTC")), 1)
    t.eq("字典直接包一格", len(normalise_slots({"start": base, "end": base + 60}, now=_START)), 1)
    t.eq("坏输入不炸", normalise_slots(12345), [])
    wrapped = normalise_slots({"slots": [{"start": base, "end": base + 60}]}, now=_START)
    t.eq("信封式返回可解包", len(wrapped), 1)
    ms = normalise_slots([{"start": base * 1000, "end": (base + 1800.0) * 1000}], now=_START)
    t.eq("毫秒时间戳被换算", ms[0].minutes, 30)
    iso = normalise_slots([{"start": "2027-01-16T14:00", "end": "2027-01-16T15:30", "tz": "UTC"}], timezone="UTC", now=_START)
    t.eq("ISO 字符串可解", iso[0].minutes, 90)
    day = normalise_slots([{"start": "2027-01-16", "end": "2027-01-16"}], timezone="UTC", duration_minutes=45, now=_START)
    t.eq("整天按 duration 补齐", day[0].minutes, 45)

    slot = FreeSlot(base, base + 3600.0, "Asia/Shanghai")
    t.eq("FreeSlot 时长", slot.minutes, 60)
    t.eq("contains 命中", slot.contains(base), True)
    t.eq("contains 不含右端点", slot.contains(base + 3600.0), False)
    t.contains("标签带区名", slot.label(30), "Asia/Shanghai")
    t.eq("标签时长用 duration 而非整格", slot.label(30).split(" ")[2], "16:00-16:30")
    t.check("墙钟标签形如 日期 星期 时间-时间 (区名)", re.search(r"\d{4}-\d{2}-\d{2} \w{3} \d{2}:\d{2}-\d{2}:\d{2} \(", slot.label(30)) is not None, slot.label(30))
    t.eq("as_dict 键", sorted(slot.as_dict()), ["end_ts", "label", "minutes", "start_ts", "zone"])
    zone = resolve_zone("Asia/Shanghai")
    # ZoneInfo.utcoffset(None) 返回 None：具名区必须给一个真实时刻才能问偏移
    moment = datetime.fromtimestamp(_START, utc_zone.utc)
    t.eq("区名解析偏移", zone.utcoffset(moment).total_seconds() / 3600.0, 8.0)
    t.eq("固定偏移解析", resolve_zone("+05:30").utcoffset(moment).total_seconds() / 3600.0, 5.5)
    t.eq("坏区名退回 UTC（不猜）", resolve_zone("Mars/Olympus").utcoffset(moment).total_seconds(), 0.0)
    t.eq("空区名退回 UTC", resolve_zone("").utcoffset(moment).total_seconds(), 0.0)


def _masking_and_helpers(t: SelfTest) -> None:
    needles = [_OWNER_ADDRESS, _OWNER_NAME, _OWNER_LINK, _OWNER_TOKEN, "abc"]
    t.eq("真实地址被掩", mask_owner(f"联系 {_OWNER_ADDRESS} 即可", needles), "联系 [masked] 即可")
    t.eq("真名被掩", mask_owner(_OWNER_NAME, needles), "[masked]")
    t.eq("大小写无关", mask_owner("@ZHANG@POPOPX.IM", needles), "[masked]")
    t.eq("邮箱一律被掩", mask_owner(f"发 {_OWNER_EMAIL}", needles), "发 [masked]")
    t.eq("短 needle 不误伤", mask_owner("abc def", ["ab"]), "abc def")
    t.eq("空输入安全", mask_owner(None, needles), "")
    t.eq("掩码幂等", mask_owner(mask_owner("x " + _OWNER_EMAIL, needles), needles), "x [masked]")

    from .guest_portal import _clean, _relative_action, _slot_list, _match_slot

    t.eq("_clean 去控制字符", _clean("a\x00b\x0cc", 10), "a b c")
    t.eq("_clean 截断", len(_clean("啊" * 300, MAX_TOPIC_CHARS)), MAX_TOPIC_CHARS)
    t.eq("_relative_action 接受相对", _relative_action("/book/x"), "/book/x")
    t.eq("_relative_action 拒绝协议", _relative_action("HTTPS://x.example"), "")
    t.eq("_relative_action 拒绝协议相对", _relative_action("//x.example"), "")
    slots = normalise_slots([{"start": _START + 3600, "end": _START + 7200}, {"start": _START + 9000, "end": _START + 12000}], now=_START)
    picked, how = _match_slot("2", slots, duration_minutes=60)
    t.eq("序号命中", picked[0].start_ts, slots[1].start_ts)
    t.check("命中方式有说明", how != "", how)
    t.eq("含糊说法不强行收敛", _match_slot("随便哪天", slots, duration_minutes=60)[0], [])
    t.eq("越界序号不命中", _match_slot("9", slots, duration_minutes=60)[0], [])
    t.contains("列表文本带序号", _slot_list(slots, 60), "1)")
    t.eq("常量：回复上限", MAX_REPLY_CHARS > MAX_TOPIC_CHARS, True)
    t.eq("常量：卡片 TTL", CARD_TTL_SECONDS > 0, True)
    t.eq("常量：时长下限", MIN_DURATION_MINUTES, 5)
    t.eq("常量：标签/主题上限", (MAX_LABEL_CHARS, MAX_TOPIC_CHARS), (60, 120))


def _admin_surface(t: SelfTest, h: Harness) -> None:
    rig = _Rig(h)
    first = rig.issue(topic="A", max_uses=1)
    second = rig.issue(topic="B", ttl_hours=0.02)
    rig.open(first["token"])
    # 审计要覆盖「访客说了一句话」这条主路径：只有 issue + open 的现场不会有 turn/提案
    rig.say(first["token"], "第一个时段")
    rows = _run(rig.portal.links, rig.bot_id)
    t.eq("列表包含两条", len(rows), 2)
    t.eq("令牌全部掩码", {row["token_mask"] for row in rows}, {token_mask(first["token"]), token_mask(second["token"])})
    t.check("列表里没有完整令牌", all(first["token"] != row.get("token") and "token" not in row for row in rows), str(sorted(rows[0])))
    t.eq("掩码长度", len(rows[0]["token_mask"]), TOKEN_MASK_CHARS + 1)
    t.check("列表只有掩码令牌，没有第二份清单", rows[0]["token_mask"], token_mask(first["token"]) if rows[0]["link_id"] == first["link_id"] else token_mask(second["token"]))
    t.eq("列表没有主人身份", _identity_hits(json.dumps(rows, ensure_ascii=False)), [])
    rig.clock.advance(120.0)  # second 的 ttl_hours=0.02 = 72 秒，此刻已经过期
    live = _run(rig.portal.links, rig.bot_id)
    t.eq("过期默认被过滤", [row["link_id"] for row in live].count(second["link_id"]), 0)
    t.eq("include_expired 默认关闭", [row["link_id"] for row in _run(rig.portal.links, rig.bot_id, include_expired=False)].count(second["link_id"]), 0)
    late = GuestPortal(rig.db, rig.settings, clock=_Clock(_START + 7200))
    t.check("拨到未来并显式要求才看到过期项", any(row["link_id"] == second["link_id"] for row in _run(late.links, rig.bot_id, include_expired=True)), "")
    other = _Rig(h, STUDIO_DATA_DIR=None)
    t.eq("按 bot 过滤", _run(other.portal.links, other.bot_id), [])
    revoked = _run(rig.portal.revoke, rig.bot_id, first["link_id"])
    t.eq("revoke 返回脱敏视图", revoked["status"], "revoked")
    t.eq("revoke 后状态被清除", _run(rig.portal.links, rig.bot_id)[0]["status"], "revoked")
    audit = list(rig.db.conn.execute("SELECT stage, event FROM negotiation_audit WHERE stage IN ('guest','ics') ORDER BY ts"))
    events = {row[1] for row in audit}
    for expected in ("issued", "visited", "turn", "proposal_created", "revoked"):
        t.contains("审计含 " + expected, " | ".join(sorted(events)), expected)
    t.check("审计阶段合法", all(row[0] in ("guest", "ics") for row in audit), "")
    t.eq("审计失败清单为空", rig.portal._audit_failures, [])


# --------------------------------------------------------------------------- 9
def group_guest_portal(test: SelfTest, h: Harness) -> None:
    t = test
    _token_primitives(t)
    _token_tampering(t)
    _issuance(t, h)
    _secret_handling(t, h)
    _visits_and_replay(t, h)
    _conversation(t, h)
    _rate_limit_and_sessions(t, h)
    _session_probe(t)
    _calendar(t, h)
    _page(t, h)
    _slot_projection(t)
    _masking_and_helpers(t)
    _admin_surface(t, h)
    # 收尾兜底：门户的实例化契约（注入点可省、时钟可换）
    bare = GuestPortal(_Rig(h).db, _Rig(h).settings)
    t.check("注入点全部可选", bare.availability is None and bare.card_pusher is None and bare.responder is None, "")
    t.eq("时钟默认 time.time", bare.clock.__name__, "time")
    swapped = GuestPortal(bare.db, bare.settings, now=lambda: 123.0)
    t.eq("now 别名生效", swapped._ts(), 123.0)
    t.eq("不可调用时钟退回 time.time", GuestPortal(bare.db, bare.settings, clock="不是函数").clock.__name__, "time")


GROUPS: Dict[str, Callable[[SelfTest, Harness], None]] = {
    "guest_portal": group_guest_portal,
}


def main() -> int:
    """单独跑本组：``python3 -m app.selftest_guest``。"""
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
