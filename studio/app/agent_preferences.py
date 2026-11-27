"""每个 Bot 独立目录里的替身偏好规则（固定屏蔽时段 / 缓冲 / 关键词优先级）。

主人的作息不是全局配置，而是**每台 Bot 各一份、可随时编辑**的规则集：Studio 把它写在
``settings.agent_dir(bot_id)/preferences.json``，也就是该 Bot 的隔离目录内 —— 与
``cli-data``、冷备包同生命周期，导出一个 Bot 就把它的替身偏好一起带走，删除 Bot 也不会
在别处留下残余。目录 0700、文件 0600：这份 JSON 里能看出主人每天几点在做什么，属于
个人数据，不能是同机其它用户可读的 0644。

三件事由本模块负责，而且都由 :class:`PreferenceError` 明确拒绝，绝不「猜一个能用的」：

1. **校验**：``HH:MM`` 写法、ISO 星期（1–7）、负缓冲、把关键词写成字符串、未知字段——
   全部拒绝。后台表单一次只提交一部分字段，所以校验的是**补丁**，落库的是深合并结果。
2. **解释**：:meth:`PreferenceStore.apply` 把候选时段（``start``/``end`` 是 epoch 秒，
   ``tz`` 是 IANA 名）按工作时、固定屏蔽段、会前会后缓冲、单场时长上限过一遍。**判定一
   律在时段自己的时区里做墙上时间比较**——跨时区约会议时，用 UTC 的小时数比较工作时是
   错的（UTC 9:00 在柏林是 10:00 上班、在上海是 17:00 下班）。
3. **排序**：:meth:`PreferenceStore.rank` 按关键词权重降序、命中黑名单直接剔除，平局
   保持输入顺序（Python 的稳定排序），这样主人把「同一权重」的候选排出来就不会看到
   每次刷新换一次顺序。

时钟通过 ``clock`` 注入（默认 :func:`time.time`），因此自检里写入的 ``updated_at`` 是
可以逐字节断言的。
"""

from __future__ import annotations

import copy
import json
import os
import re
import time
from datetime import date, datetime, timedelta, timezone as dt_timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo

from .config import SECURE_DIR_MODE, SECURE_FILE_MODE, Settings
from .i18n import LOCALES, normalize_locale

PREFERENCES_FILENAME = "preferences.json"
SCHEMA_VERSION = 1
ISO_WEEKDAYS = (1, 2, 3, 4, 5, 6, 7)  # 1=周一 … 7=周日，与 ``date.isoweekday()`` 一致
WEEKDAY_NAMES = {1: "周一", 2: "周二", 3: "周三", 4: "周四", 5: "周五", 6: "周六", 7: "周日"}
MAX_BUFFER_MINUTES = 240
MAX_KEYWORD_WEIGHT = 5
MIN_KEYWORD_WEIGHT = 1
MAX_KEYWORDS = 40
MAX_PERIOD_ID = 24
MAX_SLOT_MINUTES = 24 * 60
_TIME_RE = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")
_MIDNIGHT_END_RE = re.compile(r"^24:00$")
_DATE_RE = re.compile(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$")
_TERM_RE = re.compile(r"^[^\s].{0,39}$")

# 一份「开箱即用」的替身偏好：工作日 09:00–18:00、午休与晚餐屏蔽、会前后各 15 分钟缓冲、
# 单场不超过 2 小时、协商最多 3 轮、任何落地都必须主人点确认。
DEFAULT_PREFERENCES: Dict[str, Any] = {
    "version": SCHEMA_VERSION,
    "timezone": "Asia/Shanghai",
    "locale": "",
    "working_hours": {
        "days": [1, 2, 3, 4, 5],
        "start": "09:00",
        "end": "18:00",
        "respect_working_hours": True,
    },
    "buffers": {
        "before_minutes": 15,
        "after_minutes": 15,
        "protect_lunch": True,
    },
    "blocked_periods": [
        {"id": "lunch", "name": "午休", "days": [1, 2, 3, 4, 5], "start": "12:30", "end": "13:30", "date_from": "", "date_to": ""},
        {"id": "evening", "name": "晚间家庭时间", "days": [1, 2, 3, 4, 5], "start": "19:00", "end": "21:00", "date_from": "", "date_to": ""},
    ],
    "keywords": {
        "boost": [
            {"term": "roadmap", "weight": 4},
            {"term": "合同", "weight": 5},
            {"term": "复盘", "weight": 3},
        ],
        "block": ["线下", "投资", "代投"],
        "match_fields": ["title", "summary", "text"],
    },
    "meeting": {
        "default_duration_minutes": 60,
        "max_meeting_minutes": 120,
        "min_gap_minutes": 30,
        "max_per_day": 4,
    },
    "negotiation": {
        "rounds": 3,
        "window_days": 14,
        "auto_confirm": False,
        "require_owner_approval": True,
    },
    "copy": {"tone": "concise", "sign_off": "", "locale_override": ""},
    "recovered_from": "",
    "updated_at": 0.0,
}

_TOP_LEVEL = tuple(DEFAULT_PREFERENCES)


class PreferenceError(RuntimeError):
    """偏好补丁非法、或落盘失败时抛出（调用方把原因直接回显给后台表单）。"""


# ------------------------------------------------------------------ 值校验


def _mapping(value: Any, label: str) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PreferenceError(f"{label} 必须是对象，收到 {type(value).__name__}")
    return dict(value)


def _known_keys(raw: Mapping[str, Any], allowed: Sequence[str], label: str) -> None:
    unknown = sorted(set(raw) - set(allowed))
    if unknown:
        raise PreferenceError(f"{label} 含未知字段 {unknown}，允许：{list(allowed)}")


def _clock_text(value: Any, label: str, *, allow_midnight: bool = False) -> str:
    if not isinstance(value, str):
        raise PreferenceError(f"{label} 必须是 HH:MM 字符串，收到 {value!r}")
    text = value.strip()
    if allow_midnight and _MIDNIGHT_END_RE.match(text):
        # 24:00 只作为「一天结束」的写法允许出现在结束位：写 23:59 会在午夜前留一分钟缝。
        return "24:00"
    match = _TIME_RE.match(text)
    if not match:
        raise PreferenceError(f"{label}={value!r} 不是 HH:MM（24 小时制）")
    return f"{int(match.group(1)):02d}:{int(match.group(2)):02d}"


def _minutes(value: Any, label: str, *, maximum: int = MAX_SLOT_MINUTES, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PreferenceError(f"{label} 必须是整数分钟数，收到 {value!r}")
    if value < minimum:
        raise PreferenceError(f"{label}={value} 不能小于 {minimum}")
    if value > maximum:
        raise PreferenceError(f"{label}={value} 超过上限 {maximum}")
    return int(value)


def _integer(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PreferenceError(f"{label} 必须是整数，收到 {value!r}")
    if not minimum <= value <= maximum:
        raise PreferenceError(f"{label}={value} 超出允许范围 {minimum}–{maximum}")
    return int(value)


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise PreferenceError(f"{label} 必须是布尔值，收到 {value!r}")
    return value


def _day_list(value: Any, label: str, *, allow_empty: bool = False) -> List[int]:
    if not isinstance(value, (list, tuple)):
        raise PreferenceError(f"{label} 必须是 1–7 的数组（1=周一），收到 {type(value).__name__}")
    days: List[int] = []
    for raw in value:
        day = _integer(raw, f"{label} 元素", minimum=1, maximum=7)
        if day not in days:
            days.append(day)
    if not days and not allow_empty:
        raise PreferenceError(f"{label} 不能为空")
    return sorted(days)


def _timezone_name(value: Any, label: str) -> str:
    name = str(value or "").strip()
    if not name:
        raise PreferenceError(f"{label} 不能为空")
    try:
        ZoneInfo(name)
    except Exception as exc:  # noqa: BLE001 - KeyError/ValueError 都只说明这个名字不可用
        raise PreferenceError(f"{label}={name!r} 不是本机可解析的 IANA 时区：{exc}") from exc
    return name


def _iso_date(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _DATE_RE.match(text):
        raise PreferenceError(f"{label}={value!r} 必须是 YYYY-MM-DD")
    try:
        date.fromisoformat(text)
    except ValueError as exc:
        raise PreferenceError(f"{label}={value!r} 不是真实日期") from exc
    return text


def _terms(value: Any, label: str) -> List[str]:
    if not isinstance(value, (list, tuple)):
        raise PreferenceError(f"{label} 必须是字符串数组，收到 {type(value).__name__}")
    if len(value) > MAX_KEYWORDS:
        raise PreferenceError(f"{label} 最多 {MAX_KEYWORDS} 条，收到 {len(value)} 条")
    out: List[str] = []
    for raw in value:
        if not isinstance(raw, str):
            raise PreferenceError(f"{label} 每一项必须是字符串，收到 {raw!r}")
        term = raw.strip()
        if not term:
            raise PreferenceError(f"{label} 不能含空字符串")
        if not _TERM_RE.match(term):
            raise PreferenceError(f"{label}={term!r} 长度需在 1–40 字符之间")
        if term not in out:
            out.append(term)
    return out


def _boost_list(value: Any, label: str) -> List[Dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        raise PreferenceError(f"{label} 必须是数组（字符串或 {{term, weight}} 对象），收到 {type(value).__name__}")
    if len(value) > MAX_KEYWORDS:
        raise PreferenceError(f"{label} 最多 {MAX_KEYWORDS} 条，收到 {len(value)} 条")
    rows: List[Dict[str, Any]] = []
    seen: set = set()
    for raw in value:
        if isinstance(raw, str):
            term, weight = raw.strip(), 3
        elif isinstance(raw, Mapping):
            entry = _mapping(raw, f"{label} 元素")
            _known_keys(entry, ("term", "weight"), f"{label} 元素")
            if "term" not in entry:
                raise PreferenceError(f"{label} 元素缺少 term")
            if not isinstance(entry["term"], str):
                # 词面是要拿去子串匹配标题的字符串；对象 str() 出来的是 "{'n': 1}"，
                # 看着像一条规则，实际永远匹配不到，等于静默丢掉用户的偏好。
                raise PreferenceError(f"{label} 元素的 term 必须是字符串，收到 {entry['term']!r}")
            term = entry["term"].strip()
            weight = _integer(
                entry.get("weight", 3), f"{label}[{term}].weight",
                minimum=MIN_KEYWORD_WEIGHT, maximum=MAX_KEYWORD_WEIGHT,
            )
        else:
            raise PreferenceError(f"{label} 元素必须是字符串或对象，收到 {raw!r}")
        if not _TERM_RE.match(term):
            raise PreferenceError(f"{label} 词面 {term!r} 需为 1–40 个非空字符")
        if term.lower() in seen:
            raise PreferenceError(f"{label} 词面重复：{term!r}")
        seen.add(term.lower())
        rows.append({"term": term, "weight": weight})
    return rows


def _validate_blocked_period(raw: Any, index: int) -> Dict[str, Any]:
    label = f"blocked_periods[{index}]"
    entry = _mapping(raw, label)
    allowed = ("id", "name", "days", "start", "end", "date_from", "date_to")
    _known_keys(entry, allowed, label)
    for key in ("days", "start", "end"):
        if key not in entry:
            raise PreferenceError(f"{label} 缺少 {key}")
    period_id = str(entry.get("id") or "").strip() or f"blocked{index + 1}"
    if len(period_id) > MAX_PERIOD_ID:
        # id 会原样进审计行和拒绝原因里，太长会把面板那一列挤没。
        raise PreferenceError(f"{label}.id 最长 {MAX_PERIOD_ID} 个字符，收到 {len(period_id)} 个")
    period = {
        "id": period_id,
        "name": str(entry.get("name") or "").strip()[:60],
        "days": _day_list(entry["days"], f"{label}.days"),
        "start": _clock_text(entry["start"], f"{label}.start"),
        "end": _clock_text(entry["end"], f"{label}.end", allow_midnight=True),
        "date_from": _iso_date(entry.get("date_from", ""), f"{label}.date_from") if entry.get("date_from") else "",
        "date_to": _iso_date(entry.get("date_to", ""), f"{label}.date_to") if entry.get("date_to") else "",
    }
    if period["start"] >= period["end"]:
        raise PreferenceError(f"{label} 起止颠倒：{period['start']}–{period['end']}")
    if period["date_from"] and period["date_to"] and period["date_from"] > period["date_to"]:
        raise PreferenceError(f"{label} 生效区间颠倒：{period['date_from']} > {period['date_to']}")
    return period


def _validate_patch(patch: Any) -> Dict[str, Any]:
    """Normalize a partial update; every rejection names the offending field."""
    if patch is None:
        return {}
    raw = _mapping(patch, "偏好补丁")
    _known_keys(raw, _TOP_LEVEL, "偏好补丁")
    clean: Dict[str, Any] = {}

    if "version" in raw:
        clean["version"] = _integer(raw["version"], "version", minimum=SCHEMA_VERSION, maximum=SCHEMA_VERSION)
    if "timezone" in raw:
        clean["timezone"] = _timezone_name(raw["timezone"], "timezone")
    if "locale" in raw:
        text = str(raw["locale"] or "").strip()
        if text:
            normalized = normalize_locale(text)
            if not normalized:
                raise PreferenceError(f"locale={text!r} 不在 {len(LOCALES)} 语种支持列表内")
            clean["locale"] = normalized
        else:
            clean["locale"] = ""
    if "recovered_from" in raw:
        clean["recovered_from"] = str(raw["recovered_from"] or "")[:200]
    if "updated_at" in raw:
        clean["updated_at"] = float(raw["updated_at"])

    if "working_hours" in raw:
        hours = _mapping(raw["working_hours"], "working_hours")
        _known_keys(hours, ("days", "start", "end", "respect_working_hours"), "working_hours")
        row: Dict[str, Any] = {}
        if "days" in hours:
            row["days"] = _day_list(hours["days"], "working_hours.days")
        if "start" in hours:
            row["start"] = _clock_text(hours["start"], "working_hours.start")
        if "end" in hours:
            row["end"] = _clock_text(hours["end"], "working_hours.end", allow_midnight=True)
        if "start" in row and "end" in row and row["start"] >= row["end"]:
            raise PreferenceError(f"working_hours 起止颠倒：{row['start']}–{row['end']}")
        if "respect_working_hours" in hours:
            row["respect_working_hours"] = _boolean(hours["respect_working_hours"], "working_hours.respect_working_hours")
        clean["working_hours"] = row

    if "buffers" in raw:
        buffers = _mapping(raw["buffers"], "buffers")
        _known_keys(buffers, ("before_minutes", "after_minutes", "protect_lunch"), "buffers")
        row = {}
        for key in ("before_minutes", "after_minutes"):
            if key in buffers:
                row[key] = _minutes(buffers[key], f"buffers.{key}", maximum=MAX_BUFFER_MINUTES)
        if "protect_lunch" in buffers:
            row["protect_lunch"] = _boolean(buffers["protect_lunch"], "buffers.protect_lunch")
        clean["buffers"] = row

    if "blocked_periods" in raw:
        periods = raw["blocked_periods"]
        if not isinstance(periods, (list, tuple)):
            raise PreferenceError(f"blocked_periods 必须是数组，收到 {type(periods).__name__}")
        rows = [_validate_blocked_period(item, index) for index, item in enumerate(periods)]
        ids = [str(row["id"]) for row in rows]
        if len(set(ids)) != len(ids):
            raise PreferenceError(f"blocked_periods 的 id 必须唯一，收到 {ids}")
        clean["blocked_periods"] = rows

    if "keywords" in raw:
        keywords = _mapping(raw["keywords"], "keywords")
        _known_keys(keywords, ("boost", "block", "match_fields"), "keywords")
        row = {}
        if "boost" in keywords:
            row["boost"] = _boost_list(keywords["boost"], "keywords.boost")
        if "block" in keywords:
            row["block"] = _terms(keywords["block"], "keywords.block")
        if "match_fields" in keywords:
            fields = _terms(keywords["match_fields"], "keywords.match_fields")
            unknown = sorted(set(fields) - {"title", "summary", "text", "attendees", "notes"})
            if unknown:
                raise PreferenceError(f"keywords.match_fields 含未知字段 {unknown}")
            row["match_fields"] = fields
        clean["keywords"] = row

    if "meeting" in raw:
        meeting = _mapping(raw["meeting"], "meeting")
        _known_keys(meeting, ("default_duration_minutes", "max_meeting_minutes", "min_gap_minutes", "max_per_day"), "meeting")
        row = {}
        for key, minimum, maximum in (
            ("default_duration_minutes", 1, MAX_SLOT_MINUTES),
            ("max_meeting_minutes", 1, MAX_SLOT_MINUTES),
            ("min_gap_minutes", 0, MAX_BUFFER_MINUTES),
        ):
            if key in meeting:
                row[key] = _minutes(meeting[key], f"meeting.{key}", maximum=maximum, minimum=minimum)
        if "max_per_day" in meeting:
            row["max_per_day"] = _integer(meeting["max_per_day"], "meeting.max_per_day", minimum=0, maximum=64)
        default = row.get("default_duration_minutes")
        cap = row.get("max_meeting_minutes")
        if default and cap and default > cap:
            raise PreferenceError(f"meeting.default_duration_minutes={default} 不能大于 max_meeting_minutes={cap}")
        clean["meeting"] = row

    if "negotiation" in raw:
        negotiation = _mapping(raw["negotiation"], "negotiation")
        _known_keys(negotiation, ("rounds", "window_days", "auto_confirm", "require_owner_approval"), "negotiation")
        row = {}
        if "rounds" in negotiation:
            row["rounds"] = _integer(negotiation["rounds"], "negotiation.rounds", minimum=0, maximum=10)
        if "window_days" in negotiation:
            row["window_days"] = _integer(negotiation["window_days"], "negotiation.window_days", minimum=1, maximum=90)
        for key in ("auto_confirm", "require_owner_approval"):
            if key in negotiation:
                row[key] = _boolean(negotiation[key], f"negotiation.{key}")
        if negotiation.get("require_owner_approval") is False:
            raise PreferenceError("negotiation.require_owner_approval 必须为 true：日程最终确认只能由主人亲自点")
        if row.get("auto_confirm") and negotiation.get("require_owner_approval", True):
            # 小模型只抽取、日历落地必须主人确认，是产品裁定；auto_confirm 只能对
            # 已经关掉审批要求的历史 Bot 生效，两者同时为真等于绕过确认卡片。
            raise PreferenceError(
                "negotiation.auto_confirm 与 require_owner_approval 互斥：开启自动确认必须先关闭主人审批"
            )
        clean["negotiation"] = row

    if "copy" in raw:
        copy_row = _mapping(raw["copy"], "copy")
        _known_keys(copy_row, ("tone", "sign_off", "locale_override"), "copy")
        row = {}
        if "tone" in copy_row:
            tone = str(copy_row["tone"] or "").strip().lower()
            if tone not in {"concise", "formal", "friendly", "terse"}:
                raise PreferenceError(f"copy.tone={copy_row['tone']!r} 需是 concise/formal/friendly/terse")
            row["tone"] = tone
        if "sign_off" in copy_row:
            row["sign_off"] = str(copy_row["sign_off"] or "").strip()[:80]
        if "locale_override" in copy_row:
            text = str(copy_row["locale_override"] or "").strip()
            if text:
                normalized = normalize_locale(text)
                if not normalized:
                    raise PreferenceError(f"copy.locale_override={text!r} 不在 {len(LOCALES)} 语种支持列表内")
            row["locale_override"] = normalized if text else ""
        clean["copy"] = row

    return clean


def _merge(base: Dict[str, Any], patch: Mapping[str, Any]) -> Dict[str, Any]:
    """Recursive dict merge; lists are replaced wholesale (a reordered list *is* a choice)."""
    merged = copy.deepcopy(base)
    for key, value in patch.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def defaults() -> Dict[str, Any]:
    """A detached copy of the default preference shape."""
    return copy.deepcopy(DEFAULT_PREFERENCES)


def _to_epoch(day: date, hhmm: str, zone: ZoneInfo) -> float:
    hour, minute = (int(part) for part in hhmm.split(":"))
    # 用偏移而不是 replace：结束位允许写成 24:00（当天午夜），replace 会直接 ValueError。
    base = datetime(day.year, day.month, day.day, tzinfo=zone)
    return (base + timedelta(hours=hour, minutes=minute)).timestamp()


def _slot_instant(slot: Mapping[str, Any], key: str) -> Optional[float]:
    raw = slot.get(key)
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    return float(raw)


def _slot_zone(slot: Mapping[str, Any], fallback: str) -> ZoneInfo:
    name = str(slot.get("tz") or slot.get("timezone") or "").strip()
    if name:
        try:
            return ZoneInfo(name)
        except Exception:  # noqa: BLE001 - unknown zone falls back to the Bot's own zone
            # 时区名来自对端 Bot 或访客链接，写错了不能整条链路报错：退回本 Bot 的时区，
            # 并由调用方在返回里看到 tz 被替换的痕迹。
            pass
    try:
        return ZoneInfo(fallback)
    except Exception:  # noqa: BLE001 - the stored zone was validated on write
        return ZoneInfo("UTC")


# ---------------------------------------------------------------------- 存储


class PreferenceStore:
    """``<agent dir>/preferences.json`` 的读写与规则解释器（每 Bot 一份）。"""

    def __init__(self, settings: Settings, *, clock: Callable[[], float] = time.time) -> None:
        self.settings = settings
        self.clock = clock
        self.recoveries: Dict[str, str] = {}

    # ------------------------------------------------------------------ paths
    def path_for(self, bot_id: str) -> Path:
        return self.settings.agent_dir(bot_id) / PREFERENCES_FILENAME

    def _ensure_dir(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        for directory in (path, *list(path.parents)[:2]):
            try:
                os.chmod(directory, SECURE_DIR_MODE)
            except OSError:
                # 只读文件系统或别人拥有的目录：记一条启动告警，让 owner 能看见，
                # 但不因此拒绝服务——偏好仍然可用，只是可能不安全。
                warning = f"替身偏好目录 {directory} 无法收紧为 0{SECURE_DIR_MODE:o}"
                if warning not in self.settings.startup_warnings:
                    self.settings.startup_warnings.append(warning)

    # ------------------------------------------------------------------- read
    def load(self, bot_id: str) -> Dict[str, Any]:
        """Return the Bot's preferences, creating and persisting defaults on first use."""
        path = self.path_for(bot_id)
        self._ensure_dir(path.parent)
        if not path.exists():
            fresh = defaults()
            fresh["updated_at"] = float(self.clock())
            fresh["timezone"] = self._default_timezone()
            self._write(path, fresh)
            self.recoveries[bot_id] = ""
            return fresh
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return self._recover(bot_id, path, f"{type(exc).__name__}: {exc}")
        if not isinstance(raw, dict):
            return self._recover(bot_id, path, f"顶层不是对象：{type(raw).__name__}")
        try:
            normalized = self._normalize_stored(raw)
        except (PreferenceError, TypeError, ValueError) as exc:
            # 落盘文件是外部可编辑的：解释不动的任何一个字段都算损坏，走恢复而不是把
            # 异常抛给一条正在回复的消息。
            return self._recover(bot_id, path, str(exc))
        self.recoveries[bot_id] = ""
        return normalized

    def _default_timezone(self) -> str:
        configured = str(getattr(self.settings, "timezone", "") or "").strip()
        if configured:
            try:
                ZoneInfo(configured)
                return configured
            except Exception:  # noqa: BLE001 - fall through to the zone this machine is in
                pass
        local = datetime.now().astimezone().tzname() or ""
        try:
            name = str(datetime.now().astimezone().tzinfo)
        except Exception:  # noqa: BLE001
            name = ""
        for candidate in (name, local):
            try:
                ZoneInfo(candidate)
                return candidate
            except Exception:  # noqa: BLE001 - "UTC+08:00" style names are not IANA zones
                continue
        return str(DEFAULT_PREFERENCES["timezone"])

    def _recover(self, bot_id: str, path: Path, reason: str) -> Dict[str, Any]:
        """Corrupt file → defaults, kept readable, with the reason recorded."""
        fresh = defaults()
        fresh["recovered_from"] = reason[:200]
        fresh["updated_at"] = float(self.clock())
        self.recoveries[bot_id] = reason
        try:
            backup = path.with_suffix(".corrupt")
            payload = path.read_bytes()[:65536]
            self._ensure_dir(backup.parent)
            with os.fdopen(os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, SECURE_FILE_MODE), "wb") as handle:
                handle.write(payload)
        except OSError as exc:
            fresh["recovered_from"] = f"{reason}；原文件未能备份：{exc}"
        self._write(path, fresh)
        return fresh

    def _normalize_stored(self, raw: Mapping[str, Any]) -> Dict[str, Any]:
        """Trust-but-verify what is already on disk (an editor may have broken it)."""
        stored_version = raw.get("version")
        if stored_version != SCHEMA_VERSION:
            # 版本号不是当前代际（或被抹掉）时，其余字段无从解释；走恢复路径留痕，
            # 而不是把它当成 v{SCHEMA_VERSION} 硬夹——那会把上一代的键名读成这一代的值。
            raise PreferenceError(f"version={stored_version!r} 与当前 {SCHEMA_VERSION} 不一致")
        merged = _merge(defaults(), {key: value for key, value in raw.items() if key in _TOP_LEVEL})
        merged["version"] = SCHEMA_VERSION
        merged["recovered_from"] = str(raw.get("recovered_from") or "")[:200]
        merged["updated_at"] = float(raw.get("updated_at") or 0.0)
        return self.validate(merged)

    # ------------------------------------------------------------------ write
    def save(self, bot_id: str, patch: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Validate *patch*, deep-merge it onto the stored copy, persist atomically."""
        current = self.load(bot_id)
        clean = self.validate(patch or {})
        merged = _merge(current, clean)
        merged["recovered_from"] = ""
        merged["updated_at"] = float(self.clock())
        merged["version"] = SCHEMA_VERSION
        self._write(self.path_for(bot_id), merged)
        return merged

    def reset(self, bot_id: str) -> Dict[str, Any]:
        """Throw the Bot's rules away and go back to shipped defaults (persisted)."""
        fresh = defaults()
        fresh["timezone"] = self._default_timezone()
        fresh["updated_at"] = float(self.clock())
        self._write(self.path_for(bot_id), fresh)
        self.recoveries[bot_id] = ""
        return fresh

    def _write(self, path: Path, payload: Mapping[str, Any]) -> None:
        self._ensure_dir(path.parent)
        text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
        tmp = path.with_name(path.name + ".tmp")
        # 先写临时文件再 os.replace：并发保存时主人不会读到半份 JSON。
        descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, SECURE_FILE_MODE)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(text)
            os.chmod(tmp, SECURE_FILE_MODE)
            os.replace(tmp, path)
        except OSError:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise
        os.chmod(path, SECURE_FILE_MODE)

    # ---------------------------------------------------------------- validate
    def validate(self, patch: Any) -> Dict[str, Any]:
        """Public validation entry point: returns the normalized patch or raises."""
        return _validate_patch(patch)

    def validate_full(self, prefs: Any) -> Dict[str, Any]:
        """Validate a *complete* preference document (used by the admin console)."""
        merged = _merge(defaults(), _mapping(prefs, "偏好全量"))
        return self.validate({key: value for key, value in merged.items() if key in _TOP_LEVEL})

    # ------------------------------------------------------------- scheduling
    def blocked_windows(self, prefs: Mapping[str, Any], day: str) -> List[Dict[str, Any]]:
        """Fixed blocked periods that apply to ``YYYY-MM-DD`` as epoch ranges."""
        anchor = date.fromisoformat(_iso_date(day, "day"))
        zone = _slot_zone({"tz": str(prefs.get("timezone") or "")}, "UTC")
        rows: List[Dict[str, Any]] = []
        for period in prefs.get("blocked_periods") or []:
            if anchor.isoweekday() not in set(period.get("days") or []):
                continue
            start_iso, end_iso = str(period.get("date_from") or ""), str(period.get("date_to") or "")
            if start_iso and anchor.isoformat() < start_iso:
                continue
            if end_iso and anchor.isoformat() > end_iso:
                continue
            start = _to_epoch(anchor, str(period["start"]), zone)
            end = _to_epoch(anchor, str(period["end"]), zone)
            if end <= start:
                continue
            rows.append({
                "id": str(period.get("id") or ""),
                "name": str(period.get("name") or period.get("id") or "屏蔽时段"),
                "date": anchor.isoformat(),
                "start": start,
                "end": end,
                "start_text": str(period["start"]),
                "end_text": str(period["end"]),
                "timezone": zone.key,
            })
        rows.sort(key=lambda row: row["start"])
        return rows

    def working_window(self, prefs: Mapping[str, Any], day: str) -> Optional[Tuple[float, float]]:
        """That day's working-hours window, or ``None`` when it is a non-working day."""
        hours = prefs.get("working_hours") or {}
        anchor = date.fromisoformat(_iso_date(day, "day"))
        if anchor.isoweekday() not in set(hours.get("days") or []):
            return None
        zone = _slot_zone({"tz": str(prefs.get("timezone") or "")}, "UTC")
        start = _to_epoch(anchor, str(hours.get("start") or "09:00"), zone)
        end = _to_epoch(anchor, str(hours.get("end") or "18:00"), zone)
        return (start, end) if end > start else None

    def apply(
        self,
        prefs: Mapping[str, Any],
        slots: Sequence[Mapping[str, Any]],
        *,
        now: Optional[float] = None,
        include_rejected: bool = False,
    ) -> List[Dict[str, Any]]:
        """Filter/adjust candidate slots against blocked periods, hours and buffers.

        Every comparison happens on the *slot's own* wall clock, so a Berlin slot and a
        Shanghai slot are judged by their own working day, not by a shared UTC hour.
        """
        reference = float(now if now is not None else self.clock())
        hours = prefs.get("working_hours") or {}
        buffers = prefs.get("buffers") or {}
        meeting = prefs.get("meeting") or {}
        before = _minutes(buffers.get("before_minutes", 0), "buffers.before_minutes", maximum=MAX_BUFFER_MINUTES)
        after = _minutes(buffers.get("after_minutes", 0), "buffers.after_minutes", maximum=MAX_BUFFER_MINUTES)
        cap = int(meeting.get("max_meeting_minutes") or MAX_SLOT_MINUTES)
        kept: List[Dict[str, Any]] = []
        rejected: List[Dict[str, Any]] = []
        for raw in slots or ():
            if not isinstance(raw, Mapping):
                # 候选池来自对端 Bot / 访客链接，元素可能根本不是对象：跳过坏的那一个，
                # 不能让一条脏数据把整轮协商打挂（dict("字符串") 会直接抛 ValueError）。
                rejected.append({"rejected": f"候选不是对象：{type(raw).__name__}"})
                continue
            slot = dict(raw)
            start, end = _slot_instant(slot, "start"), _slot_instant(slot, "end")
            if start is None or end is None:
                rejected.append({**slot, "rejected": "缺少 start/end 时间戳"})
                continue
            if end <= start:
                rejected.append({**slot, "rejected": "结束时间不晚于开始时间"})
                continue
            if end <= reference:
                rejected.append({**slot, "rejected": "时段已过去"})
                continue
            zone = _slot_zone(slot, str(prefs.get("timezone") or "UTC"))
            local_start = datetime.fromtimestamp(start, zone)
            local_end = datetime.fromtimestamp(end, zone)
            if cap and (end - start) / 60.0 > cap:
                # 超过单场上限就裁到上限，并把痕迹留在返回里，而不是静默丢掉整条。
                end = start + cap * 60.0
                local_end = datetime.fromtimestamp(end, zone)
                slot["capped_minutes"] = cap
            if local_end.date() != local_start.date():
                rejected.append({**slot, "rejected": "跨天的候选时段需要主人另行确认"})
                continue
            day = local_start.date().isoformat()
            if hours.get("respect_working_hours", True):
                window = self._working_window_in(prefs, local_start.date(), zone)
                if window is None:
                    rejected.append({**slot, "rejected": f"{WEEKDAY_NAMES[local_start.isoweekday()]}不是工作日"})
                    continue
                open_at, close_at = window
                padded_start, padded_end = start - before * 60.0, end + after * 60.0
                if padded_start < open_at or padded_end > close_at:
                    rejected.append({
                        **slot,
                        "rejected": f"含缓冲后超出工作时间 {hours.get('start')}-{hours.get('end')}"
                        f"（需 {local_start.strftime('%H:%M')}-{local_end.strftime('%H:%M')}"
                        f"±{before}/{after} 分钟）",
                    })
                    continue
            clash = self._blocked_clash(prefs, local_start.date(), zone, start, end)
            if clash:
                rejected.append({**slot, "rejected": f"命中固定屏蔽时段「{clash}」"})
                continue
            slot["tz"] = zone.key
            slot["end"] = end
            slot["start_text"] = local_start.strftime("%H:%M")
            slot["end_text"] = local_end.strftime("%H:%M")
            slot["weekday"] = local_start.isoweekday()
            slot["duration_minutes"] = int(round((end - start) / 60.0))
            slot["buffered"] = True
            slot["buffer_minutes"] = before + after
            slot["kept"] = True
            kept.append(slot)
        if include_rejected:
            return kept + rejected
        return kept

    def _working_window_in(self, prefs: Mapping[str, Any], day: date, zone: ZoneInfo) -> Optional[Tuple[float, float]]:
        hours = prefs.get("working_hours") or {}
        if day.isoweekday() not in set(hours.get("days") or []):
            return None
        start = _to_epoch(day, str(hours.get("start") or "09:00"), zone)
        end = _to_epoch(day, str(hours.get("end") or "18:00"), zone)
        return (start, end) if end > start else None

    def _blocked_clash(self, prefs: Mapping[str, Any], day: date, zone: ZoneInfo, start: float, end: float) -> str:
        for period in prefs.get("blocked_periods") or []:
            if day.isoweekday() not in set(period.get("days") or []):
                continue
            start_iso, end_iso = str(period.get("date_from") or ""), str(period.get("date_to") or "")
            if start_iso and day.isoformat() < start_iso:
                continue
            if end_iso and day.isoformat() > end_iso:
                continue
            blocked_start = _to_epoch(day, str(period["start"]), zone)
            blocked_end = _to_epoch(day, str(period["end"]), zone)
            if blocked_end <= blocked_start:
                continue
            if start < blocked_end and end > blocked_start:
                return str(period.get("name") or period.get("id") or "屏蔽时段")
        return ""

    def rank(self, prefs: Mapping[str, Any], slots: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        """Order slots by keyword weight (higher first, ties keep input order)."""
        keywords = prefs.get("keywords") or {}
        boosts = [_normalize_boost(row) for row in keywords.get("boost") or [] if str(row).strip() != "" or isinstance(row, Mapping)]
        blocked = [term.lower() for term in keywords.get("block") or [] if str(term).strip()]
        fields = list(keywords.get("match_fields") or DEFAULT_PREFERENCES["keywords"]["match_fields"])
        ranked: List[Dict[str, Any]] = []
        for index, raw in enumerate(slots or ()):
            slot = dict(raw)
            haystack = _slot_text(slot, fields)
            blacklisted = [term for term in blocked if term and term in haystack]
            if blacklisted:
                slot["dropped_by_keyword"] = blacklisted
                continue
            matched: List[str] = []
            weight = 0
            for term, value in boosts:
                if term.lower() in haystack:
                    matched.append(term)
                    weight += value
            slot["score"] = weight
            slot["matched_keywords"] = matched
            slot["_order"] = index
            ranked.append(slot)
        ranked.sort(key=lambda slot: -int(slot["score"]))  # stable: equal weights keep input order
        for slot in ranked:
            slot.pop("_order", None)
        return ranked

    def daily_quota(self, prefs: Mapping[str, Any], slots: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        """Enforce ``meeting.max_per_day`` after ranking (per local calendar day)."""
        limit = int((prefs.get("meeting") or {}).get("max_per_day") or 0)
        if limit <= 0:
            return [dict(slot) for slot in slots or ()]
        seen: Dict[str, int] = {}
        kept: List[Dict[str, Any]] = []
        for slot in slots or ():
            day = _slot_day_key(slot)
            seen[day] = seen.get(day, 0) + 1
            if seen[day] > limit:
                slot = {**slot, "over_quota": True}
                continue
            kept.append({**slot, "rank_of_day": seen[day]})
        return kept

    def summary(self, bot_id: str) -> Dict[str, Any]:
        """Compact view for the admin console (never echoes personal keyword text)."""
        prefs = self.load(bot_id)
        return {
            "bot_id": bot_id,
            "path": str(self.path_for(bot_id)),
            "timezone": prefs.get("timezone"),
            "locale": prefs.get("locale"),
            "working_days": (prefs.get("working_hours") or {}).get("days"),
            "working_hours": f"{(prefs.get('working_hours') or {}).get('start')}-{(prefs.get('working_hours') or {}).get('end')}",
            "blocked_periods": len(prefs.get("blocked_periods") or []),
            "boost_terms": len((prefs.get("keywords") or {}).get("boost") or []),
            "block_terms": len((prefs.get("keywords") or {}).get("block") or []),
            "buffers": dict(prefs.get("buffers") or {}),
            "meeting": dict(prefs.get("meeting") or {}),
            "negotiation": dict(prefs.get("negotiation") or {}),
            "recovered_from": prefs.get("recovered_from") or "",
            "updated_at": prefs.get("updated_at"),
            "mode": _mode_text(self.path_for(bot_id)),
        }


def _normalize_boost(row: Any) -> Tuple[str, int]:
    if isinstance(row, Mapping):
        return str(row.get("term") or "").strip(), int(row.get("weight") or 0)
    return str(row or "").strip(), 3


def _slot_text(slot: Mapping[str, Any], fields: Sequence[str]) -> str:
    parts: List[str] = []
    for field in fields:
        value = slot.get(field)
        if isinstance(value, (list, tuple)):
            parts.extend(str(item) for item in value)
        elif value is not None:
            parts.append(str(value))
    if not parts:  # 没有显式字段时退回整个 slot 的 JSON 文本：标题可能就在嵌套里
        parts.append(json.dumps({k: v for k, v in slot.items() if not k.startswith("_")}, ensure_ascii=False))
    return " ".join(parts).lower()


def _slot_day_key(slot: Mapping[str, Any]) -> str:
    start = _slot_instant(slot, "start")
    if start is None:
        return str(slot.get("date") or "unknown")
    zone = _slot_zone(slot, "UTC")
    return datetime.fromtimestamp(start, zone).date().isoformat()


def _mode_text(path: Path) -> int | str:
    try:
        return oct(os.stat(path).st_mode & 0o777)
    except OSError:
        return "missing"


__all__ = [
    "DEFAULT_PREFERENCES",
    "ISO_WEEKDAYS",
    "MAX_BUFFER_MINUTES",
    "PREFERENCES_FILENAME",
    "SCHEMA_VERSION",
    "PreferenceError",
    "PreferenceStore",
    "defaults",
]
