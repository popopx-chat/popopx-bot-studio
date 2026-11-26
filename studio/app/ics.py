"""RFC 5545 ``.ics`` 生成器（确认后的日程发给双方，访客侧可直接下载）。

只输出 **UTC（Z 结尾）** 的起止时间：这样任何客户端都不会因为缺少 VTIMEZONE 定义
而把会议排错一小时，而本地墙上时间会写进 ``SUMMARY``/``DESCRIPTION`` 文案里。

行折叠、CRLF、``TEXT`` 转义都是 RFC 5545 的硬要求（:rfc:`5545#3.1`），不是风格偏好：
少一个 CRLF，Apple 日历会直接拒绝整个文件。
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any, Iterable, List, Mapping, Optional, Sequence

MAX_OCTETS = 75
PRODID = "-//POPOPX//Bot Studio Personal Agent 1.0//EN"
_LINE_RE = re.compile(r"\r\n|\r|\n")
_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def escape_text(value: Any) -> str:
    """``TEXT`` 值转义：反斜杠最先处理，换行统一成 ``\\n``。"""
    text = "" if value is None else str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace(";", "\\;").replace(",", "\\,")
    # 函数式替换：字符串形式的 "\\n" 会被 re 二次解释成真正的换行，那会把一条
    # CONTENT LINE 截断，Apple 日历直接拒绝整个文件。
    return _LINE_RE.sub(lambda _match: "\\n", text)


def fold(line: str) -> str:
    """按 75 **字节** 折行，续行以一个空格开头（多字节字符不会被切开）。"""
    raw = line.encode("utf-8")
    if len(raw) <= MAX_OCTETS:
        return line
    chunks: List[str] = []
    current = ""
    budget = MAX_OCTETS
    for char in line:
        size = len(char.encode("utf-8"))
        if len(current.encode("utf-8")) + size > budget:
            chunks.append(current)
            current = char
            budget = MAX_OCTETS - 1  # 续行首字符是空格
        else:
            current += char
    if current:
        chunks.append(current)
    return "\r\n ".join(chunks)


def stamp(ts: float) -> str:
    """Epoch 秒 -> ``YYYYMMDDTHHMMSSZ``。"""
    return datetime.fromtimestamp(float(ts), timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def event_uid(prefix: str, ref: str) -> str:
    clean = _UNSAFE_NAME.sub("_", f"{prefix}{ref}".strip("_")) or "popopx"
    return f"{clean}@bot-studio.popopx"


def build_event(
    *,
    uid: str,
    summary: str,
    start_ts: float,
    end_ts: float,
    description: str = "",
    location: str = "",
    organizer: str = "",
    organizer_name: str = "",
    url: str = "",
    status: str = "CONFIRMED",
    sequence: int = 0,
    transp: str = "OPAQUE",
    categories: Sequence[str] = (),
    dtstamp: Optional[float] = None,
) -> List[str]:
    """一个 ``VEVENT`` 的属性行（调用方负责包 BEGIN/END）。"""
    if float(end_ts) <= float(start_ts):
        raise ValueError("VEVENT 结束时间必须晚于开始时间")
    if status not in ("CONFIRMED", "TENTATIVE", "CANCELLED"):
        raise ValueError(f"非法 VEVENT 状态 {status!r}")
    lines = [
        "BEGIN:VEVENT",
        f"UID:{escape_text(uid)}",
        f"DTSTAMP:{stamp(dtstamp if dtstamp is not None else time.time())}",
        f"DTSTART:{stamp(start_ts)}",
        f"DTEND:{stamp(end_ts)}",
        f"SUMMARY:{escape_text(summary)}",
        f"STATUS:{status}",
        f"SEQUENCE:{max(0, int(sequence))}",
        f"TRANSP:{transp if transp in ('OPAQUE', 'TRANSPARENT') else 'OPAQUE'}",
    ]
    if description:
        lines.append(f"DESCRIPTION:{escape_text(description)}")
    if location:
        lines.append(f"LOCATION:{escape_text(location)}")
    if organizer:
        lines.append(f"ORGANIZER:{escape_text(organizer)}")
    if url:
        lines.append(f"URL:{escape_text(url)}")
    if categories:
        lines.append(f"CATEGORIES:{escape_text(','.join(str(item) for item in categories))}")
    lines.append("END:VEVENT")
    return [line for line in lines if line]


def build_calendar(
    events: Iterable[Mapping[str, Any]],
    *,
    method: str = "PUBLISH",
    calendar_name: str = "POPOPX",
    prodid: str = PRODID,
    refresh_interval_minutes: int = 0,
) -> str:
    """组装整份日历；``events`` 是 :func:`build_event` 的关键字参数字典。"""
    if method not in ("PUBLISH", "REQUEST", "CANCEL", "REPLY", "ADD"):
        raise ValueError(f"非法 METHOD {method!r}")
    body: List[str] = [
        "BEGIN:VCALENDAR",
        f"PRODID:{escape_text(prodid)}",
        "VERSION:2.0",
        "CALSCALE:GREGORIAN",
        f"METHOD:{method}",
        f"X-WR-CALNAME:{escape_text(calendar_name)}",
    ]
    if refresh_interval_minutes > 0:
        body.append(f"REFRESH-INTERVAL;VALUE=DURATION:PT{int(refresh_interval_minutes)}M")
        body.append(f"X-PUBLISHED-TTL:PT{int(refresh_interval_minutes)}M")
    for event in events:
        body.extend(build_event(**dict(event)))
    body.append("END:VCALENDAR")
    return "\r\n".join(fold(line) for line in body) + "\r\n"


def ics_filename(summary: str, start_ts: float) -> str:
    """下载用的安全文件名。"""
    stamp_text = datetime.fromtimestamp(float(start_ts), timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = _UNSAFE_NAME.sub("-", str(summary or "meeting")).strip("-")[:48] or "meeting"
    return f"popopx-{stem}-{stamp_text}.ics"


__all__ = [
    "MAX_OCTETS",
    "PRODID",
    "build_calendar",
    "build_event",
    "escape_text",
    "event_uid",
    "fold",
    "ics_filename",
    "stamp",
]
