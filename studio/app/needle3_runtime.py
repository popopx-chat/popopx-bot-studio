"""Needle 3 端侧工具调用运行时（小引擎 Dispatcher）——只抽取，永不落库。

替身机器人的 24/7 链路是「双引擎」：**小模型抽取意图，大模型只写话术**。本模块是前
一半：一条自由文本进来，毫秒级产出 5 个工具调用之一（或若干个），结果再交给日历数据与
:mod:`app.agent_preferences` 去解释。三条硬边界直接来自产品裁定：

* 小模型**只抽取**。五个工具函数全部是只读回声桩——它们把抽到的参数记下来交给上层，
  绝不写日历、绝不读文件内容。真正的写入发生在主人点了 ``::CB::ppxok`` 之后，由
  Mac Node 执行（卡片流程见 :mod:`app.eco_cards`）。
* 权重**必须**先过 :func:`app.needle_assets.ensure_weights` 的 SHA-256 门禁，运行期
  绝不下载（部署后零外网模型下载）。校验失败、SDK 未安装、加载抛错，一律降级到本模块
  自带的确定性抽取器，并把原因记进 ``status()``——**永不**向调用方抛异常：一条消息
  解析失败不该让整条会话链路断掉。
* 引擎真身、降级原因、抽取次数都在 :meth:`NeedleRuntime.status` 里，后台一眼能看出
  「这台机器到底有没有在用端侧模型」。

确定性回退抽取器不是占位实现：中英双语的约会议 / 问空档 / 改期 / 取消 / 看纪要句式、
相对日期（明天、周四、next week）、钟点（下午三点、3pm、15:00）、时长（半小时、
45 min）与时区提示都会解析成结构化参数。相对日期通过 ``hints={"now": ...}`` 注入时钟，
因此自检结果与跑测试的那一天无关，可以逐字段复现。
"""

from __future__ import annotations

import functools
import importlib.util
import re
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone as dt_timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo, available_timezones

from . import needle_assets
from .config import Settings

TOOL_NAMES: Tuple[str, ...] = (
    "calendar.get_availability",
    "calendar.propose_create",
    "calendar.propose_reschedule",
    "calendar.propose_cancel",
    "workspace.summarize_file",
)

# 逻辑工具名 -> 意图标签（``Extraction.intent`` 的取值来源）。
INTENT_FOR_TOOL: Dict[str, str] = {
    "calendar.get_availability": "availability",
    "calendar.propose_create": "create",
    "calendar.propose_reschedule": "reschedule",
    "calendar.propose_cancel": "cancel",
    "workspace.summarize_file": "summarize",
}
INTENTS: Tuple[str, ...] = ("empty", "none", "mixed") + tuple(sorted(set(INTENT_FOR_TOOL.values())))

ENGINE_NEEDLE = "needle3"
ENGINE_FALLBACK = "fallback"
MAX_INPUT_CHARS = 4000
DEFAULT_DURATION_MINUTES = 60
MAX_CONFIDENCE = 0.95
# 只读桩的固定返回值：出现副作用的可能性为零，上层拿到的是「抽到了什么」。
EXTRACT_ONLY: Mapping[str, str] = {"status": "extract_only"}

TOOL_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "calendar.get_availability": {
        "description": "List free slots for the owner on a day/window. Read-only: never books.",
        "parameters": {
            "date": "str=YYYY-MM-DD",
            "time": "str=HH:MM",
            "duration_minutes": "int",
            "timezone": "str=IANA",
            "window_days": "int",
        },
    },
    "calendar.propose_create": {
        "description": "Propose a new meeting. Creates a pending card, writes nothing.",
        "parameters": {
            "date": "str=YYYY-MM-DD",
            "time": "str=HH:MM",
            "duration_minutes": "int",
            "timezone": "str=IANA",
            "title": "str",
            "attendees": "list[str]",
        },
    },
    "calendar.propose_reschedule": {
        "description": "Propose moving an existing event. Requires owner confirmation.",
        "parameters": {
            "reference": "str",
            "from_date": "str=YYYY-MM-DD",
            "date": "str=YYYY-MM-DD",
            "time": "str=HH:MM",
            "duration_minutes": "int",
            "timezone": "str=IANA",
        },
    },
    "calendar.propose_cancel": {
        "description": "Propose cancelling an existing event. Requires owner confirmation.",
        "parameters": {
            "reference": "str",
            "date": "str=YYYY-MM-DD",
            "time": "str=HH:MM",
            "timezone": "str=IANA",
        },
    },
    "workspace.summarize_file": {
        "description": "Summarise a referenced file. Declares a reference only, never opens it.",
        "parameters": {
            "file_ref": "str",
            "file_name": "str",
            "kind": "str",
            "max_items": "int",
        },
    },
}

# ---------------------------------------------------------------- 只读工具桩
# 这些签名是给端侧引擎看的（cactus 读取函数签名与 docstring 来选工具）。函数体刻意
# 不做任何 I/O：写日历、读文件都发生在确认之后，由上层模块执行。


def calendar_get_availability(
    date: str = "",
    time: str = "",
    duration_minutes: int = 0,
    timezone: str = "",
    window_days: int = 0,
) -> Mapping[str, str]:
    """List free slots for the owner on a day/window. Read-only: never books."""
    return EXTRACT_ONLY


def calendar_propose_create(
    date: str = "",
    time: str = "",
    duration_minutes: int = 0,
    timezone: str = "",
    title: str = "",
    attendees: Optional[List[str]] = None,
) -> Mapping[str, str]:
    """Propose a new meeting. Creates a pending card, writes nothing."""
    return EXTRACT_ONLY


def calendar_propose_reschedule(
    reference: str = "",
    from_date: str = "",
    date: str = "",
    time: str = "",
    duration_minutes: int = 0,
    timezone: str = "",
) -> Mapping[str, str]:
    """Propose moving an existing event. Requires owner confirmation."""
    return EXTRACT_ONLY


def calendar_propose_cancel(
    reference: str = "",
    date: str = "",
    time: str = "",
    timezone: str = "",
) -> Mapping[str, str]:
    """Propose cancelling an existing event. Requires owner confirmation."""
    return EXTRACT_ONLY


def workspace_summarize_file(
    file_ref: str = "",
    file_name: str = "",
    kind: str = "",
    max_items: int = 0,
) -> Mapping[str, str]:
    """Summarise a referenced file. Declares a reference only, never opens it."""
    return EXTRACT_ONLY


TOOL_STUBS: Dict[str, Callable[..., Mapping[str, str]]] = {
    "calendar.get_availability": calendar_get_availability,
    "calendar.propose_create": calendar_propose_create,
    "calendar.propose_reschedule": calendar_propose_reschedule,
    "calendar.propose_cancel": calendar_propose_cancel,
    "workspace.summarize_file": workspace_summarize_file,
}


@dataclass
class _Recorder:
    """Collects the arguments the on-device engine hands to a read-only tool stub.

    The cactus SDK *executes* whichever tool it selects, so the stubs have to be
    side-effect-free; the recorded call is the extraction we actually want. This is
    the "只抽取" ruling made executable.
    """

    calls: List[Tuple[str, Dict[str, Any]]] = field(default_factory=list)

    def record(self, tool: str, arguments: Mapping[str, Any]) -> None:
        self.calls.append((tool, dict(arguments)))

    def drain(self) -> List[Tuple[str, Dict[str, Any]]]:
        taken, self.calls = list(self.calls), []
        return taken


class NeedleAgent:
    """Resident cactus agent, held open across messages.

    ``cactus.Cactus`` is documented as a context manager whose ``run()`` returns
    ``{"results": [...]}``. Re-entering it per message would re-map the 35 MB weight
    file each time and blow the millisecond budget, so we enter once, keep the
    context, and close it from :meth:`NeedleRuntime.unload`.
    """

    def __init__(self, context: Any, agent: Any, recorder: _Recorder) -> None:
        self._context = context
        self._agent = agent
        self.recorder = recorder
        self.close_error = ""

    def run(self, text: str) -> Mapping[str, Any]:
        raw = self._agent.run(text)
        return raw if isinstance(raw, Mapping) else {"results": raw}

    def take_calls(self) -> List[Tuple[str, Dict[str, Any]]]:
        return self.recorder.drain()

    def close(self) -> None:
        context, self._context = self._context, None
        self._agent = None
        if context is None:
            return
        try:
            context.__exit__(None, None, None)
        except Exception as exc:  # noqa: BLE001 - teardown failure must not propagate
            # SDK 的关闭异常只影响资源回收，不影响任何一条消息的解析，留痕即可。
            self.close_error = f"{type(exc).__name__}: {exc}"


def sdk_available() -> Tuple[bool, str]:
    """Whether the optional ``cactus-compute`` package is importable (nothing imported)."""
    try:
        found = importlib.util.find_spec("cactus") is not None
    except (ImportError, ValueError) as exc:  # pragma: no cover - malformed sys.path edge
        return False, f"探测 cactus 包失败：{exc}"
    if not found:
        return False, "未安装 cactus-compute SDK"
    return True, ""


def _recorded_stub(dotted: str, recorder: _Recorder) -> Callable[..., Mapping[str, str]]:
    """Wrap a read-only stub so its arguments land in *recorder*.

    ``functools.wraps`` keeps ``__name__``/``__doc__``/``__wrapped__`` intact, which
    is what lets the engine still introspect the original signature.
    """
    original = TOOL_STUBS[dotted]

    @functools.wraps(original)
    def wrapper(**arguments: Any) -> Mapping[str, str]:
        recorder.record(dotted, arguments)
        return EXTRACT_ONLY

    wrapper.__name__ = dotted.replace(".", "_")
    return wrapper


def default_loader(weights_path: Path, tools: Sequence[Callable[..., Any]]) -> NeedleAgent:
    """Load *weights_path* with the real ``cactus-compute`` SDK.

    Only reached once :func:`sdk_available` reports the package, because cactus is
    deliberately **not** a pinned dependency (it pulls native engines). ``tools`` is
    the logical name list; each name becomes a recording wrapper around a stub.
    """
    import cactus  # noqa: PLC0415 - optional, guarded, engine-specific

    recorder = _Recorder()
    bound = [_recorded_stub(str(name), recorder) for name in tools]
    decorated = [cactus.tool(fn) if hasattr(cactus, "tool") else fn for fn in bound]
    context = cactus.Cactus(tools=decorated)
    return NeedleAgent(context, context.__enter__(), recorder)


# ------------------------------------------------------- 确定性回退抽取词典

_WEEKDAY_CN = {"一": 0, "二": 1, "三": 2, "四": 3, "五": 4, "六": 5, "日": 6, "天": 6}
_WEEKDAY_EN = {
    "monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3, "friday": 4,
    "saturday": 5, "sunday": 6,
    "mon": 0, "tues": 1, "tue": 1, "weds": 2, "wed": 2, "thurs": 3, "thur": 3, "thu": 3,
    "fri": 4, "sat": 5, "sun": 6,
}
_MONTH_CN = {
    "一": 1, "二": 2, "三": 3, "四": 4, "五": 5, "六": 6, "七": 7,
    "八": 8, "九": 9, "十": 10, "十一": 11, "十二": 12,
}
_MONTH_EN = {
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6, "july": 7,
    "august": 8, "september": 9, "october": 10, "november": 11, "december": 12,
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "jun": 6, "jul": 7, "aug": 8,
    "sept": 9, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}
_CN_NUM = {
    "零": 0, "一": 1, "二": 2, "两": 2, "三": 3, "四": 4, "五": 5,
    "六": 6, "七": 7, "八": 8, "九": 9, "十": 10,
}
_EN_NUM = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
}
# 中文时段词 -> 下午/晚上需要把 1–11 点抬到 24h 记法。
_MERIDIEM_CN = ("早上", "上午", "中午", "午后", "下午", "傍晚", "晚上", "夜里", "今晚")
_PM_MARKERS = {"下午", "傍晚", "晚上", "夜里", "今晚", "pm", "afternoon", "evening", "night"}
_OFFSET_CN = {"今天": 0, "明天": 1, "后天": 2, "大后天": 3, "昨天": -1, "前天": -2}
_RELATIVE_WORDS = (
    "今天", "明天", "后天", "大后天", "昨天", "前天", "本周", "这周", "下周", "周末", "今晚",
    "today", "tomorrow", "tonight", "yesterday", "weekend", "next week", "this week",
)
_TZ_HINTS: Dict[str, str] = {
    "北京": "Asia/Shanghai", "上海": "Asia/Shanghai", "杭州": "Asia/Shanghai",
    "深圳": "Asia/Shanghai", "广州": "Asia/Shanghai", "中国": "Asia/Shanghai", "国内": "Asia/Shanghai",
    "东京": "Asia/Tokyo", "日本": "Asia/Tokyo", "首尔": "Asia/Seoul", "韩国": "Asia/Seoul",
    "新加坡": "Asia/Singapore", "香港": "Asia/Hong_Kong", "台北": "Asia/Taipei",
    "柏林": "Europe/Berlin", "德国": "Europe/Berlin", "巴黎": "Europe/Paris",
    "伦敦": "Europe/London", "莫斯科": "Europe/Moscow", "伊斯坦布尔": "Europe/Istanbul",
    "纽约": "America/New_York", "波士顿": "America/New_York", "华盛顿": "America/New_York",
    "芝加哥": "America/Chicago", "洛杉矶": "America/Los_Angeles",
    "旧金山": "America/Los_Angeles", "西岸": "America/Los_Angeles", "东岸": "America/New_York",
}
# 英文城市/地区名。_norm 之后文本是小写的，所以这里全部用小写键，命中时带词界，
# 避免 "new castle time" 之类的片段被 "new york" 式子串误吃。
_TZ_HINTS_EN: Dict[str, str] = {
    "beijing": "Asia/Shanghai", "shanghai": "Asia/Shanghai", "china": "Asia/Shanghai",
    "shenzhen": "Asia/Shanghai", "guangzhou": "Asia/Shanghai", "hangzhou": "Asia/Shanghai",
    "taipei": "Asia/Taipei", "hong kong": "Asia/Hong_Kong", "singapore": "Asia/Singapore",
    "tokyo": "Asia/Tokyo", "japan": "Asia/Tokyo", "seoul": "Asia/Seoul", "korea": "Asia/Seoul",
    "india": "Asia/Kolkata", "mumbai": "Asia/Kolkata", "dubai": "Asia/Dubai",
    "sydney": "Australia/Sydney", "melbourne": "Australia/Melbourne",
    "berlin": "Europe/Berlin", "germany": "Europe/Berlin", "munich": "Europe/Berlin",
    "paris": "Europe/Paris", "france": "Europe/Paris", "madrid": "Europe/Madrid",
    "rome": "Europe/Rome", "amsterdam": "Europe/Amsterdam", "zurich": "Europe/Zurich",
    "stockholm": "Europe/Stockholm", "oslo": "Europe/Oslo", "copenhagen": "Europe/Copenhagen",
    "warsaw": "Europe/Warsaw", "vienna": "Europe/Vienna", "prague": "Europe/Prague",
    "athens": "Europe/Athens", "helsinki": "Europe/Helsinki", "dublin": "Europe/Dublin",
    "lisbon": "Europe/Lisbon", "moscow": "Europe/Moscow", "istanbul": "Europe/Istanbul",
    "london": "Europe/London", "uk": "Europe/London", "britain": "Europe/London",
    "new york": "America/New_York", "boston": "America/New_York", "washington": "America/New_York",
    "toronto": "America/Toronto", "montreal": "America/Toronto", "miami": "America/New_York",
    "chicago": "America/Chicago", "denver": "America/Denver",
    "los angeles": "America/Los_Angeles", "san francisco": "America/Los_Angeles",
    "seattle": "America/Los_Angeles", "california": "America/Los_Angeles",
    "pacific time": "America/Los_Angeles", "eastern time": "America/New_York",
    "mountain time": "America/Denver", "central time": "America/Chicago",
}
_TZ_HINTS_EN_RE = re.compile(
    r"\b(" + "|".join(sorted((re.escape(k) for k in _TZ_HINTS_EN), key=len, reverse=True)) + r")\b"
)
_TZ_ABBR: Dict[str, str] = {
    "utc": "UTC", "gmt": "Etc/GMT", "cet": "Europe/Berlin", "cest": "Europe/Berlin",
    "bst": "Europe/London", "wet": "Europe/Lisbon", "eet": "Europe/Athens",
    "est": "America/New_York", "edt": "America/New_York", "cst": "America/Chicago",
    "cdt": "America/Chicago", "mst": "America/Denver", "mdt": "America/Denver",
    "pst": "America/Los_Angeles", "pdt": "America/Los_Angeles", "jst": "Asia/Tokyo",
    "kst": "Asia/Seoul", "ist": "Asia/Kolkata", "aest": "Australia/Sydney",
    "sgt": "Asia/Singapore", "hkt": "Asia/Hong_Kong", "msk": "Europe/Moscow",
}
_ATTENDEE_STOP_CN = {
    "你", "我", "他", "她", "它", "我们", "你们", "他们", "大家", "谁", "客户", "团队",
    "一下", "他/她", "别人", "同事", "老板", "谁谁",
}
_ATTENDEE_STOP = {
    "you", "us", "me", "them", "him", "her", "the", "a", "an", "somebody", "someone",
    "team", "client", "customer", "everyone", "anyone", "who", "what", "work", "call",
    "meeting", "lunch", "coffee", "dinner", "sync", "chat", "a-call",
}
_FILE_EXT = r"(?:pdf|md|markdown|txt|text|doc|docx|xls|xlsx|csv|json|ics|ifb|ppt|pptx|opus|m4a|mp3)"

# 句式词典。命中即产生一个工具意图；用「短语」而不是整句匹配，因为真实聊天语序极不稳定
# （「帮我约个会」/「会帮你约一下」/「book a meeting」）。文本进来时已小写归一。
PATTERNS: Dict[str, Tuple[str, ...]] = {
    "availability": (
        "有空", "有空档", "有空的时间", "没空", "方便", "档期", "排期", "几点有",
        "什么时候有", "何时有", "有没有时间", "时间安排", "空下来", "哪天", "哪一天",
        "有无空", "排得开", "有档期", "什么时段", "哪个时段", "有没有档期",
        "可以吗", "行吗", "行不行", "合适吗", "有时间吗", "有没有空", "能不能来",
        "free", "available", "availability", "any time", "work for you", "works for you",
        "fit your schedule", "open slot", "calendar open", "when are you", "do you have time",
        "spare time", "convenient", "are you around", "which day", "any openings",
        "suits you", "what time are you", "calendar look", "your availability",
        "availability for", "how is your day", "how's your day", "any window",
    ),
    "create": (
        "约个会", "约个", "约一下", "约会议", "约时间", "约见", "见面", "开个会", "开会",
        "建个日程", "加个日程", "订个时间", "定个时间", "安排", "敲定", "排上", "订个",
        "定个", "开个", "视频", "语音", "碰个头", "见个面", "面谈", "约谈", "碰一下", "对一下",
        "book", "schedule", "set up", "arrange", "pencil", "lock in", "put in the calendar",
        "create a meeting", "new meeting", "add an event", "make an appointment",
        "find a slot", "find some time", "let's meet", "get together", "block out", "reserve",
        "meeting", "meet", "call", "sync", "catch up", "hop on", "sit down", "let's talk",
        "make time", "put time on",
    ),
    "reschedule": (
        "改到", "改期", "换到", "挪到", "调到", "推迟", "推到", "延到", "延后", "提前到", "改天",
        "重约", "改约", "重新约", "换个时间", "换时间", "改时间", "时间改", "往后挪", "往前挪",
        "顺延", "再约一次", "拖到",
        "reschedule", "resched", "move it", "move to", "move the", "move our", "move this",
        "push it", "push back", "push out", "push the", "bring forward", "postpone", "delay",
        "bump", "slide", "shift to", "shift the", "put off", "rain check", "another time",
        "different day", "pick a new time",
    ),
    "cancel": (
        "取消", "不开了", "不用开", "取消掉", "撤掉", "推掉", "不约了", "去掉", "别开",
        "算了吧", "释放时间", "不开这个",
        "cancel", "call off", "scrap", "drop the", "no longer need", "scratch",
        "pull it", "delete the meeting", "remove the", "is off", "off for today",
    ),
    "summarize": (
        "纪要", "总结一下", "总结", "看下这份", "看一下这份", "看看这份", "帮我看下", "帮我看一下",
        "摘要", "要点", "重点", "梳理", "过一遍", "读一下", "看一下文件", "文档", "附件",
        "这份文件", "这个文件", "那份记录", "笔记", "会议记录",
        "summarize", "summary", "recap", "tl;dr", "tldr", "key points", "action items",
        "this file", "that file", "the notes", "these notes", "the minutes", "attachment",
        "transcript", "read the doc", "review the doc", "digest",
    ),
}

# 断续句式：中文习惯把动词和宾语拆开（「开 60 分钟的会」「把时间改到下周」「约个 30 分钟的视频」），
# 子串词典在这种语序上必然落空，而英文靠词序本身就能被短语覆盖，所以只给中文补这一层。
# 允许跨越空格与数字（_norm 会在中西文接缝插空格），但禁止跨越句读，防止「开了会，然后取消」
# 这类句子把命中拖过句界；长度上限同样是为了不跨句。
_BREAK_CHARS = "，。！？；：、,!?;:~\n"


def _gap(prefix: str, middle: int, *suffixes: str) -> re.Pattern[str]:
    """``prefix`` + up to *middle* non-punctuation chars + one of *suffixes*."""
    tail = "|".join(re.escape(item) for item in suffixes)
    return re.compile(prefix + rf"[^{_BREAK_CHARS}]{{0,{middle}}}(?:{tail})")


PATTERN_REGEXES: Dict[str, Tuple[re.Pattern[str], ...]] = {
    "availability": (_gap("有", 4, "空", "没有时间", "档期"), _gap("没", 2, "空", "时间")),
    "create": (
        # 只允许「开……会」这种跨距形式：「开个/订个/定个」已经收在子串词典里，
        # 若在这里放开到「开……个」，「打开一个文档」就会被误判成建会。
        _gap("开", 12, "会"),
        _gap("约", 12, "时间", "一下", "个", "见", "会"),
        _gap("安排", 10, "会", "面谈", "时间", "一下"),
        _gap("订", 6, "时间", "个"),
        _gap("定", 6, "时间", "个"),
    ),
    "reschedule": (
        _gap("改", 8, "到", "成", "时间"),
        _gap("换", 8, "到", "成", "时间"),
        _gap("挪", 8, "到", "去", "时间"),
        _gap("调", 8, "到", "成", "时间"),
        _gap("推", 8, "到", "迟"),
        _gap("延", 8, "到", "后"),
    ),
    "cancel": (_gap("不", 4, "开了", "用开", "约了", "去了"), _gap("取", 2, "消", "掉")),
    "summarize": (
        _gap("总", 4, "结"),
        _gap("看", 8, "这份", "这个", "那份", "那个"),
        _gap("过", 4, "一遍", "一下这份"),
    ),
}

# 一句话命中多个工具时，primary 取这条顺序里最靠前的一个：破坏性递减（取消 > 改期），
# 然后先答「你没空/有空」这种只读问题，再才提出新建。把只读的可用性查询排在建会之前，
# 是因为「are you free for a call tomorrow?」这类句子同时命中两个词典——此时正确的动作是
# 查档期并把候选时段做成待确认卡片，而不是直接抛一个新建提案。
_TOOL_PRIORITY: Tuple[str, ...] = (
    "calendar.propose_cancel",
    "calendar.propose_reschedule",
    "calendar.get_availability",
    "calendar.propose_create",
    "workspace.summarize_file",
)

# 只说明「有个会」而不说明「要新建」的说法：「取消明天的会」里的「会」是既有日程，
# 破坏性动词命中时靠这些词撑起来的 create 意图要丢掉（见 _matched_tools）。
_WEAK_CREATE_NOUNS: frozenset = frozenset({
    "开会", "开个会", "见面", "见个面", "碰个头", "碰一下", "面谈", "约谈", "对一下",
    "视频", "语音", "meeting", "meet", "call", "sync", "catch up", "hop on", "sit down",
    "let's meet", "let's talk", "get together",
})


@dataclass
class ToolCall:
    """One structured tool invocation the Dispatcher extracted from a message."""

    name: str
    arguments: Dict[str, Any]
    confidence: float = 0.0
    engine: str = ENGINE_NEEDLE

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "arguments": dict(self.arguments),
            "confidence": round(float(self.confidence), 4),
            "engine": self.engine,
        }


@dataclass
class Extraction:
    """What one inbound message turned into: intent, calls, engine truth, latency."""

    intent: str
    calls: List[ToolCall] = field(default_factory=list)
    engine: str = ENGINE_FALLBACK
    degraded: bool = True
    latency_ms: float = 0.0
    error: str = ""
    text: str = ""

    @property
    def primary(self) -> Optional[ToolCall]:
        """The call the pipeline should act on first (``None`` for no-tool chatter)."""
        return self.calls[0] if self.calls else None

    @property
    def tool(self) -> str:
        return self.primary.name if self.primary else ""

    def arguments(self, name: str = "") -> Dict[str, Any]:
        """Arguments of *name* (or of the primary call) — empty when absent."""
        if not name:
            return dict(self.primary.arguments) if self.primary else {}
        for call in self.calls:
            if call.name == name:
                return dict(call.arguments)
        return {}

    def as_dict(self) -> Dict[str, Any]:
        return {
            "intent": self.intent,
            "engine": self.engine,
            "degraded": self.degraded,
            "latency_ms": round(float(self.latency_ms), 3),
            "error": self.error,
            "text": self.text,
            "calls": [call.as_dict() for call in self.calls],
        }


# --------------------------------------------------------------- 解析小工具


# 日期/时长单位字：数字与这些字之间允许被 _norm 插开（"3 月 3 日"），再折叠回去喂给日期语法。
# 刻意不含任何标点，避免把已经折成半角的 "," 再改回全角，影响下游的子串匹配。
_DATE_UNITS = "年月日号点分秒周天月"


def _norm(text: str) -> str:
    """Fold the noise out of an inbound chat line without losing intent.

    A space is inserted wherever CJK meets an ASCII word character: Python's ``\\b``
    treats 汉字 as a word character, so ``我next 3 days`` silently fails every English
    regex that is anchored with a word boundary.

    The insertion is then undone for date units (``3 月 3 日`` -> ``3月3日``), because
    that is exactly how a phone IME writes a Chinese date and the date grammar below
    expects the digit and the unit to be adjacent.
    """
    lowered = str(text or "").strip().lower()
    lowered = re.sub(r"[\r\n\t]+", " ", lowered)
    lowered = lowered.replace("？", "?").replace("！", "!").replace("，", ",")
    lowered = re.sub(r"([\u3400-\u9fff])([a-z0-9])", r"\1 \2", lowered)
    lowered = re.sub(r"([a-z0-9])([\u3400-\u9fff])", r"\1 \2", lowered)
    lowered = re.sub(rf"(\d)\s+(?=[{_DATE_UNITS}])", r"\1", lowered)
    lowered = re.sub(rf"([{_DATE_UNITS}])\s+(\d)", r"\1\2", lowered)
    return re.sub(r"\s{2,}", " ", lowered).strip()


def _cn_number(token: str) -> Optional[int]:
    token = (token or "").strip()
    if not token:
        return None
    if token.isdigit():
        return int(token)
    if token == "十":
        return 10
    if len(token) == 2 and token.startswith("十"):
        return 10 + _CN_NUM.get(token[1], 0)
    if len(token) == 2 and token.endswith("十"):
        return _CN_NUM.get(token[0], 0) * 10
    if len(token) == 3 and "十" in token:
        return _CN_NUM.get(token[0], 0) * 10 + _CN_NUM.get(token[2], 0)
    return _CN_NUM.get(token)


def _resolve_clock(hour: int, marker: str) -> int:
    """Turn a bare hour plus a day-part marker into a 24h clock."""
    if marker in _PM_MARKERS:
        return hour + 12 if 1 <= hour < 12 else hour
    if marker in {"中午", "noon", "正午"}:
        return 12 if hour <= 1 else hour
    return hour


def _first_pm_marker(text: str) -> str:
    for marker in _MERIDIEM_CN:
        if marker in text:
            return "下午" if marker in _PM_MARKERS else marker
    if re.search(r"\b(?:pm|evening|afternoon|night)\b", text):
        return "pm"
    if re.search(r"\b(?:noon|midday)\b", text):
        return "noon"
    return ""


_ZONES: Optional[frozenset] = None


def _known_zones() -> frozenset:
    global _ZONES  # noqa: PLW0603 - tzdir 在进程生命周期内不变，只扫一次
    if _ZONES is None:
        _ZONES = frozenset(available_timezones())
    return _ZONES


def is_valid_timezone(name: str) -> bool:
    """Whether *name* is a canonical IANA zone this machine can actually resolve.

    这里用 ``available_timezones()`` 精确比对而不是 ``ZoneInfo(name)``：后者在 macOS 上对
    ``utc`` 这类小写名也宽容通过（tzdata 目录大小写不敏感），而把这种名字写进 .ics 或
    协商报文，对端解析就会失败。排期只接受规范拼写。
    """
    candidate = str(name or "").strip()
    if not candidate:
        return False
    return candidate in _known_zones()


def _find_timezone(text: str, hint: str = "") -> str:
    """Resolve the zone the *user* meant, strongest evidence first.

    文本已经过 :func:`_norm` 转小写，所以显式 IANA 名要先还原大小写再查表：``europe/berlin``
    在 ``zoneinfo`` 里是查不到的，直接丢进去会让一条明明写明了时区的消息退回默认时区。
    """
    slash = re.search(r"\b([a-z][a-z]+/[a-z_]+(?:/[a-z_]+)?)\b", text)
    if slash:
        candidate = "/".join(part.capitalize() for part in slash.group(1).split("/"))
        if is_valid_timezone(candidate):
            return candidate
    for city, zone in _TZ_HINTS.items():
        if city in text:
            return zone
    english = _TZ_HINTS_EN_RE.search(text)
    if english:
        return _TZ_HINTS_EN[english.group(1)]
    offset = re.search(r"\b(utc|gmt)\s*([+-]\d{1,2})?\b", text)
    if offset:
        if offset.group(2):
            value = int(offset.group(2))
            if -14 <= value <= 14:
                return "UTC" if value == 0 else f"Etc/GMT{-value:+d}"
            return ""
        return "UTC" if offset.group(1) == "utc" else "Etc/GMT"
    for token in re.findall(r"\b[a-z]{3,4}\b", text):
        zone = _TZ_ABBR.get(token)
        if zone:
            return zone
    return hint


_CN_CLOCK_RE = re.compile(r"(\d{1,2}|十[一二三四五六七八九]?|[一二三四五六七八九十两]+)\s*(?:点|時|时)(?:半|整|钟)?")
_WEEKDAY_RE = re.compile(r"(?:本周|这周|下周|周|星期|礼拜)([一二三四五六日天])")
_EN_WEEKDAY_RE = re.compile(r"\b(?:this |on |next |by )?(monday|tuesday|wednesday|thursday|friday|saturday|sunday|mon|tue[sd]?|wed[sd]?|thu[sr]?|fri|sat|sun)\b")

# 「改到 / moved to / to <weekday>」这一类介词锚点：改期句子要靠它区分原日期和目标日期。
_RESCHEDULE_TO_RE = re.compile(
    r"(?:改到|改成|改至|改为|换到|换成|挪到|挪至|调到|调至|推迟到|推至|推到|延到|延至|提前到|移到|移到了"
    r"|改期到|改约到|顺延到|重约到|改到)"
    r"|\b(?:moved|move|moving|pushed|push|pushing|shifted|shift|rescheduled|reschedule|postponed|postpone"
    r"|bumped|bump|slid|slide|delayed|delay|put|set)\s+(?:it|the\s+\w+\s+)?to\b"
    r"|\bto\s+(?=(?:next\s+|this\s+|on\s+|next\s+week\s+|this\s+week\s+)?"
    r"(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday|tomorrow|today|tonight"
    r"|mon|tue[sd]?|wed[sd]?|thu[sr]?|fri|sat|sun)\b)"
)


def _resolve_datetime(
    text: str,
    now: datetime,
    *,
    allow_today: bool = True,
) -> Tuple[Optional[date], Optional[str], bool, float]:
    """Return ``(day, "HH:MM", time_was_explicit, day_confidence)``.

    Relative words resolve against the injected *now*, never the wall clock, which
    is what keeps the fallback deterministic (and honest about its uncertainty).
    """
    today = now.date()
    picked: Optional[date] = None
    day_conf = 0.0

    absolute = re.search(r"\b(20\d{2})-(\d{1,2})-(\d{1,2})\b", text)
    if absolute:
        try:
            picked = date(int(absolute.group(1)), int(absolute.group(2)), int(absolute.group(3)))
            day_conf = 0.95
        except ValueError:
            picked = None
    if picked is None:
        cn_md = re.search(r"(\d{1,2}|十一|十二|一|二|三|四|五|六|七|八|九|十)月(\d{1,2}|十[一二三四五六七八九]?|[一二三四五六七八九十]+)[日号]", text)
        if cn_md:
            head = cn_md.group(1)
            month = _MONTH_CN.get(head) or (int(head) if head.isdigit() else None)
            day = _cn_number(cn_md.group(2))
            if month and day:
                picked, day_conf = _safe_date(today.year, month, day, today), 0.8
    if picked is None:
        en_named = re.search(r"\b(" + "|".join(_MONTH_EN) + r")\.?\s+(\d{1,2})\b", text)
        if en_named:
            picked, day_conf = _safe_date(today.year, _MONTH_EN[en_named.group(1)], int(en_named.group(2)), today), 0.75
    if picked is None:
        en_numeric = re.search(r"\b(\d{1,2})/(\d{1,2})(?:/(\d{2,4}))?\b", text)
        if en_numeric:
            month, day = int(en_numeric.group(1)), int(en_numeric.group(2))
            year = int(en_numeric.group(3) or today.year)
            if year < 100:
                year += 2000
            if 1 <= month <= 12:
                picked, day_conf = _safe_date(year, month, day, today), 0.7

    for token, offset in _OFFSET_CN.items():
        if token in text:
            picked, day_conf = today + timedelta(days=offset), 0.85
            break
    else:
        if re.search(r"\bthe day after tomorrow\b", text):
            picked, day_conf = today + timedelta(days=2), 0.85
        elif re.search(r"\btomorrow\b", text):
            picked, day_conf = today + timedelta(days=1), 0.85
        elif re.search(r"\btonight\b", text):
            picked, day_conf = today, 0.8
        elif re.search(r"\btoday\b", text):
            picked, day_conf = today, 0.8
        elif re.search(r"\byesterday\b", text):
            picked, day_conf = today - timedelta(days=1), 0.8

    next_week = re.search(r"下周([一二三四五六日天])?", text) or re.search(
        r"\bnext\s+(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b", text
    )
    if next_week:
        token = next_week.group(1)
        weekday = _WEEKDAY_CN.get(token or "")
        if weekday is None:
            weekday = _WEEKDAY_EN.get(token or "")
        base = today + timedelta(days=7)
        picked = _shift_to_weekday(base, now.weekday() if weekday is None else weekday, allow_today=True)
        day_conf = 0.8
    if picked is None:
        cn_weekday = _WEEKDAY_RE.search(text)
        weekday = _WEEKDAY_CN.get(cn_weekday.group(1)) if cn_weekday else None
        if weekday is None:
            en_weekday = _EN_WEEKDAY_RE.search(text)
            if en_weekday:
                weekday = _WEEKDAY_EN.get(en_weekday.group(1))
        if weekday is not None:
            picked = _shift_to_weekday(today, weekday, allow_today=allow_today)
            day_conf = 0.8
    if picked is None:
        if re.search(r"周末", text) or re.search(r"\b(?:this )?weekend\b", text):
            picked, day_conf = _shift_to_weekday(today, 5), 0.7

    marker = _first_pm_marker(text)
    hour: Optional[int] = None
    minute = 0
    explicit = False
    # 这里不能用 \b：_norm 会把中文日期单位与紧随的数字重新粘住（"明天 2:30" → "明天2:30"），
    # 而 汉字与数字都是 \w，粘住之后 \b 不再成立，一条写明钟点的消息就会丢掉 time 字段。
    # 数字前后各加一条数字环视，既保住原来「不吃长数字片段」的语义，又允许紧贴的汉字。
    digital = re.search(r"(?<!\d)(\d{1,2}):(\d{2})(?!\d)", text)
    ampm = re.search(r"(?<!\d)(\d{1,2})(?::(\d{2}))?\s*(am|pm)(?![a-z0-9])", text)
    relative_now = re.search(
        r"(?:半|30)\s*分钟后|\bin half an hour\b|\bin (\d{1,2}) minutes?\b|(?:稍后|待会儿|一会儿)", text
    )
    if relative_now and not digital and not ampm:
        shift = 30 if re.search(r"半|30|half", relative_now.group(0) or "") else None
        if shift is None:
            shift = int(relative_now.group(1) or 0) or None
        if shift and 1 <= shift <= 720:
            landed = now + timedelta(minutes=shift)
            return landed.date(), landed.strftime("%H:%M"), True, 0.85
    if ampm:
        hour, minute, marker = int(ampm.group(1)), int(ampm.group(2) or 0), ampm.group(3)
        explicit = True
    elif digital:
        hour, minute = int(digital.group(1)), int(digital.group(2))
        explicit = True
    else:
        cn_clock = _CN_CLOCK_RE.search(text)
        if cn_clock:
            value = _cn_number(cn_clock.group(1))
            if value is not None and 0 <= value <= 24:
                hour = value % 24
                minute = 30 if str(cn_clock.group(0)).endswith("半") else 0
                explicit = True
        word_clock = re.search(r"\b(" + "|".join(_EN_NUM) + r")\s*(am|pm|o'?clock)\b", text)
        if hour is None and word_clock:
            hour, minute, marker = _EN_NUM[word_clock.group(1)], 0, word_clock.group(2)
            explicit = True
    if hour is None and marker in {"中午", "noon"}:
        hour, minute, explicit = 12, 0, True
    if hour is not None:
        hour = _resolve_clock(hour, marker)
        if not 0 <= hour <= 23:
            hour, explicit = None, False
    clock = f"{hour:02d}:{minute:02d}" if hour is not None else ""
    return picked, (clock or None), explicit, day_conf


def _safe_date(year: int, month: int, day: int, today: date) -> date:
    """A bare ``5月9日``/``May 9`` means the *next* occurrence, not a past date."""
    try:
        candidate = date(year, month, day)
    except ValueError:
        return today
    if candidate < today:
        try:
            return date(year + 1, month, day)
        except ValueError:
            return candidate
    return candidate


def _shift_to_weekday(base: date, weekday: int, *, allow_today: bool = False) -> date:
    delta = (weekday - base.weekday()) % 7
    if delta == 0 and not allow_today:
        delta = 7
    return base + timedelta(days=delta)


def _duration_minutes(text: str, hint: Any) -> Tuple[Optional[int], float]:
    """Explicit meeting length -> ``(minutes, confidence)``."""
    cn_minutes = re.search(r"(\d{1,3}|十[一二三四五六七八九]?|[一二三四五六七八九十两]+)\s*(?:分钟|mins?)", text)
    if cn_minutes:
        value = _cn_number(cn_minutes.group(1))
        if value and 5 <= value <= 720:
            return value, 0.9
    if re.search(r"半(?:个)?(?:小时|钟头)", text) or re.search(r"\bhalf an? hour\b", text):
        return 30, 0.85
    cn_hours = re.search(r"(\d{1,2}|[一二三四五六七八九十两]+)\s*(?:个)?(?:小时|hrs?)", text)
    if cn_hours:
        value = _cn_number(cn_hours.group(1))
        if value and 1 <= value <= 12:
            return value * 60, 0.9
    en_minutes = re.search(r"\b(\d{1,3})\s*(?:minutes?|mins?)\b", text)
    if en_minutes:
        value = int(en_minutes.group(1))
        if 5 <= value <= 720:
            return value, 0.9
    en_hours = re.search(r"\b(\d{1,2}|one|two|three|four|an?)\s*(?:hours?|hrs?)\b", text)
    if en_hours:
        raw = en_hours.group(1)
        value = int(raw) if raw.isdigit() else (_EN_NUM.get(raw, 1) if raw in {"an", "a", "one"} else _EN_NUM.get(raw, 0))
        if 1 <= value <= 12:
            return value * 60, 0.9
    if isinstance(hint, bool):
        return None, 0.0
    if isinstance(hint, (int, float)) and 1 <= float(hint) <= 1440:
        return int(hint), 0.5
    return None, 0.0


def _file_reference(text: str) -> Tuple[str, str, float]:
    """Name or placeholder of the file the sender points at — the file is never opened."""
    named = re.search(rf"[^\s/\\]+?\.{_FILE_EXT}\b", text)
    if named:
        name = named.group(0).strip("\"'.,()[]{}")
        return "named", name, 0.9
    quoted = re.search(r"[\"'“”「」『』]([^\"'“”「」『』]{2,80})[\"'“”「」『』]", text)
    if quoted:
        return "quoted", quoted.group(1).strip(), 0.75
    for token, kind in (
        ("纪要", "minutes"), ("会议记录", "minutes"), ("minutes", "minutes"),
        ("transcript", "transcript"), ("笔记", "notes"), ("记录", "notes"),
        ("notes", "notes"), ("附件", "attachment"), ("attachment", "attachment"),
        ("文档", "document"), ("document", "document"), ("文件", "file"), ("file", "file"),
    ):
        if token in text:
            return "placeholder", kind, 0.6
    return "placeholder", "unspecified", 0.35


def _title(text: str) -> str:
    """Pull a meeting title out of 「」/quotes/an explicit noun phrase (never invented)."""
    bracketed = re.search(r"[「『\"']([^」』\"']{2,40})[」』\"']", text)
    if bracketed:
        return bracketed.group(1).strip()
    named = re.search(
        r"(?:约|开|安排|定|订|建)(?:个|一下|一个)?([^\s,。？!个一二三四五六七八九十两\d]{2,20})(?:会|会议|碰头|同步|面谈|沟通)",
        text,
    )
    if named:
        return f"{named.group(1)}会"
    english = re.search(
        r"\b(?:book|schedule|set up|arrange|create|add)\s+(?:a|an|the)?\s*([a-z][a-z -]{1,24}?)?\s*"
        r"(meeting|call|sync|appointment|session|interview|standup)\b",
        text,
    )
    if english:
        # 头名里不允许出现数字，否则 "book a 45 minute call" 会把时长当成主题。
        head = re.sub(r"^(?:a|an|the|some|any)\s+", "", (english.group(1) or "").strip())
        tail = english.group(2)
        return f"{head} {tail}".strip() if head else tail
    # 主题写在动词后面是中文的常态（「约个会 讨论合同细节」），英文用 about/re: 引出。
    topic = re.search(
        r"(?:讨论|谈谈|谈一下|聊聊|聊一下|聊|过一下|对齐|沟通|关于)\s*"
        r"([^\s,。；;！？!?，]{2,24})",
        text,
    )
    if topic:
        return topic.group(1).strip()
    about = re.search(
        r"\b(?:about|regarding|on|for)\s+(?:the\s+|our\s+|my\s+)?"
        r"([a-z][a-z0-9 -]{1,28}?)(?=\s+(?:tomorrow|today|tonight|next|this|on|at|in|please)\b|$|[,.!?;:])",
        text,
    )
    if about:
        return about.group(1).strip()
    return ""


# 中文习惯把「明天下午的站会」整段塞在动词后面，_reference 的捕获组会连日期与时段一起吃掉，
# 产出的 reference 是「明天的站」——既不是事件名，又会原样回显在主人的确认卡片上。这里的口径：
# 只剥「日期/时段 + 的」这种明确的所有格前缀（"昨天的季度复盘" -> "季度复盘"），没有「的」就
# 不动刀，避免把「周日轮值」这种以星期开头的真名字削掉一半；整段都是日期/时段时一律留空，
# 让 _reference 继续走词表兜底——宁可缺名字，也不回显一个错名字。
_CN_REF_WORDS = (
    "大后天|后天|前天|今天|明天|昨天|下下周|下周[一二三四五六日天]?|本周[一二三四五六日天]?"
    "|这周[一二三四五六日天]?|星期[一二三四五六日天]|礼拜[一二三四五六日天]|周[一二三四五六日天]"
    "|早上|上午|中午|午后|下午|傍晚|晚上|夜里|今晚"
)
_CN_REF_PREFIX_RE = re.compile(rf"^(?:{_CN_REF_WORDS}的?)+的")
_CN_REF_ALL_DATE_RE = re.compile(rf"^(?:{_CN_REF_WORDS}|的)+$")


def _strip_cn_date(token: str) -> str:
    """「明天的站」/「明天下午」→ 空串；「昨天的季度复盘」→「季度复盘」。"""
    value = str(token or "").strip()
    value = _CN_REF_PREFIX_RE.sub("", value, count=1).strip()
    if len(value) < 2 or _CN_REF_ALL_DATE_RE.match(value):
        return ""
    return value


def _reference(text: str) -> str:
    """Which existing event is being moved/cancelled (best effort, never guessed)."""
    # 引号里的东西就是事件名，优先级最高：中英文书名号/直角引号/直引号一律照收。
    quoted = re.search(r"[「『《“\"'【]([^」』》”\"'】]{2,28})[」』》”\"'】]", text)
    named = re.search(
        r"(?:取消|改到|换到|延到|改约|挪到|调到|推掉|撤掉|去掉|推到)(?:一下|掉)?"
        r"([^，,。?!;:、\s]{2,20}?)(?:的)?(?:会|会议|日程|安排|面谈|碰头|沟通)",
        text,
    )
    # 「move the roadmap review to friday」这类句子先按「动词 … 到新时间」整段吃下，再把开头的
    # 日期所有格和冠词剔掉；名词锚定的写法留作后备，覆盖 "cancel tomorrow's standup" 这种
    # 没有介词尾巴的句子。两条都要过 _strip_article，否则 "push the sync to" 会捞到一个 "the"。
    english_phrase = re.search(
        r"\b(?:cancel|move|reschedule|push|shift|drop|postpone|bring)\s+"
        r"(?:the\s+|my\s+|our\s+|this\s+)?([a-z0-9' -]{2,28}?)\s+(?:to|at|on|for|from)\b",
        text,
    )
    english = re.search(
        r"\b(?:cancel|move|reschedule|push|shift|drop)\s+(?:the\s+|my\s+|our\s+)?([a-z0-9' -]{2,28}?)\s+"
        r"(?:meeting|call|sync|appointment|standup|review|retro|session|check-in|catch-up)\b",
        text,
    )
    for candidate in (
        (quoted.group(1) if quoted else "").strip(),
        _strip_cn_date(named.group(1)) if named else "",
        _strip_article(_strip_leading_date(_strip_possessive(english_phrase.group(1)))) if english_phrase else "",
        _strip_article(_strip_possessive(english.group(1))) if english else "",
    ):
        if candidate and not _is_date_word(candidate):
            return candidate
    for token in ("站会", "standup", "周会", "weekly", "1:1", "one on one"):
        if token in text:
            return token
    return ""


_REFERENCE_STOP = {
    "", "it", "this", "that", "these", "those", "there", "today", "tomorrow", "yesterday",
    "next", "week", "meeting", "call", "event", "appointment", "the", "a", "an", "up",
    "会议", "日程", "时间", "一下", "个",
}


def _strip_article(token: str) -> str:
    """Drop a leading article; ``it``/``today`` alone is a pronoun, never an event name."""
    value = str(token or "").strip()
    stripped = re.sub(r"^(?:the|a|an|this|that|my|our|your|his|her|their)\b\s*", "", value).strip()
    return "" if stripped in _REFERENCE_STOP else stripped


def _strip_leading_date(token: str) -> str:
    """``tomorrow's standup`` -> ``standup``: a leading date is not part of the name."""
    value = str(token or "").strip()
    for word in _RELATIVE_WORDS:
        for prefix in (f"{word}'s ", f"{word} ", f"the {word} "):
            if value.startswith(prefix):
                return value[len(prefix) :].strip()
    return re.sub(r"^(?:next|this|on)\s+", "", value).strip()


def _strip_possessive(token: str) -> str:
    """``friday's meeting`` names a date, not an event: drop the possessive first."""
    return str(token or "").strip().rstrip("'s ").strip()


def _is_date_word(token: str) -> bool:
    value = str(token or "").strip()
    if value in _RELATIVE_WORDS:
        return True
    return bool(_WEEKDAY_RE.fullmatch(value) or _EN_WEEKDAY_RE.fullmatch(value))


# 同行人只从「锚点 + 由连接符串起来的名字段」里取：中文没有词界，贪婪匹配会把「明天下午」
# 一并吃进第二段，所以每段先按日期/时段/动词截断，再过停用词与星期词。宁可少一个人，
# 也不要在主人的确认卡片上凭空多出一个人。
_ATTENDEE_ANCHOR_RE = re.compile(r"(?:邀请|邀约|拉上|叫上|喊上|约|和|跟|与|把|\bwith\b)")
_ATTENDEE_CUT_RE = re.compile(
    r"(?:大后天|后天|明天|今天|昨天|前天|下下周|下周|本周|这周|上周|星期|礼拜|周[一二三四五六日天]"
    r"|早上|上午|中午|午后|下午|傍晚|晚上|夜里|今晚|凌晨|\d{1,2}\s*[:：]\s*\d{2}"
    r"|\d{1,2}\s*(?:点|小时|分钟|天|周)|\b(?:am|pm)\b"
    r"|\b(?:tomorrow|today|tonight|monday|tuesday|wednesday|thursday|friday|saturday|sunday"
    r"|next|this|on|at|in|by|for|about|regarding|please|o'clock)\b"
    r"|开会|开个|开|见面|见个面|见|碰头|碰|同步|聊聊|聊|谈谈|谈|视频|语音|电话|吃|对一下|过一下|一起|讨论|沟通)"
)
_ATTENDEE_SPLIT_RE = re.compile(r"(?:和|跟|与|、|,|，|\s+|\band\b)+")
_ATTENDEE_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9'.\-]{1,23}|[一-鿿]{2,3}")
MAX_ATTENDEES = 12


def _attendees(text: str) -> List[str]:
    """Names dragged into the meeting by "和 X"/"with X"; pronouns are not names."""
    out: List[str] = []
    for anchor in _ATTENDEE_ANCHOR_RE.finditer(text):
        tail = text[anchor.end() : anchor.end() + 60]
        cut = _ATTENDEE_CUT_RE.search(tail)
        if cut:
            tail = tail[: cut.start()]
        for raw in _ATTENDEE_SPLIT_RE.split(tail):
            token = raw.strip(" .,-'\"()（）[]【】「」《》")
            if not token or not _ATTENDEE_TOKEN_RE.fullmatch(token):
                continue
            if token in _ATTENDEE_STOP_CN or token.lower() in _ATTENDEE_STOP or _is_date_word(token):
                continue
            # _norm 把拉丁字母转成了小写，卡片上要还回人名的写法。
            display = token.capitalize() if token.isascii() else token
            if display not in out:
                out.append(display)
            if len(out) >= MAX_ATTENDEES:
                return out
    return out


def _window_days(text: str) -> Optional[int]:
    cn = re.search(r"(?:未来|接下来|这|后|下)\s*(\d{1,2}|[一二三四五六七八九十两]+)\s*(?:天|日)", text)
    if cn:
        value = _cn_number(cn.group(1))
        if value and 1 <= value <= 30:
            return value
    en = re.search(r"\b(?:next|within|in|over)\s+(?:the\s+)?(\d{1,2})\s*(?:business\s+)?days?\b", text)
    if en:
        value = int(en.group(1))
        if 1 <= value <= 30:
            return value
    if re.search(r"\bthis week\b|本周|这周", text):
        return 7
    if re.search(r"\bnext week\b|下周", text):
        return 7
    return None


def _as_zone(tz_name: str) -> dt_timezone:
    name = str(tz_name or "").strip()
    if name:
        try:
            return ZoneInfo(name)
        except Exception:  # noqa: BLE001 - unusable zone string, fall back to a fixed offset
            pass
    return dt_timezone(timedelta(hours=8))


def _as_now(value: Any, tz_name: str) -> datetime:
    """Coerce an injected clock into an aware datetime (``hints={"now": ...}``)."""
    zone = _as_zone(tz_name)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=zone)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, 9, 0, tzinfo=zone)
    if isinstance(value, bool):
        return datetime(2026, 5, 11, 9, 30, tzinfo=zone)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), zone)
    if isinstance(value, str) and value.strip():
        raw = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(raw)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=zone)
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d", "%H:%M"):
                try:
                    return datetime.strptime(raw, fmt).replace(tzinfo=zone)
                except ValueError:
                    continue
    return datetime(2026, 5, 11, 9, 30, tzinfo=zone)


def _phrase_matcher(phrase: str) -> Callable[[str], bool]:
    """Boundary-aware matcher.

    英文短语必须带词界，否则 ``schedule`` 会在 ``reschedule`` 里命中、``call`` 会在
    ``callback`` 里命中——把改期句子误判成建会句子。中文没有词界概念（``_norm`` 只在中西文
    接缝插空格），继续用子串匹配。
    """
    value = str(phrase or "")
    if not value:
        return lambda text: False
    if value.isascii():
        pattern = re.compile(rf"(?<![a-z0-9]){re.escape(value)}(?![a-z0-9])")
        return lambda text: pattern.search(text) is not None
    return lambda text: value in text


# 短语命中器在建表期编译一次：每条消息都要跑上百个短语，逐次 re.compile 会把回退路径的
# 亚毫秒延迟推高一个量级。
_MATCHERS: Dict[str, Tuple[Tuple[str, Callable[[str], bool]], ...]] = {
    intent: tuple((phrase, _phrase_matcher(phrase)) for phrase in phrases)
    for intent, phrases in PATTERNS.items()
}


def _matched_tools(text: str) -> List[Tuple[str, float]]:
    """Which tools the phrasing hints at, plus the strength of that hint."""
    hits: List[Tuple[str, float]] = []
    evidence: Dict[str, List[str]] = {}
    for intent, tool in (
        ("cancel", "calendar.propose_cancel"),
        ("reschedule", "calendar.propose_reschedule"),
        ("create", "calendar.propose_create"),
        ("availability", "calendar.get_availability"),
        ("summarize", "workspace.summarize_file"),
    ):
        matched = [phrase for phrase, hit in _MATCHERS[intent] if hit(text)]
        for pattern in PATTERN_REGEXES[intent]:
            found = pattern.search(text)
            if found:
                matched.append(found.group(0))
        if not matched:
            continue
        evidence[intent] = matched
        longest = max(len(phrase) for phrase in matched)
        strength = 0.6 + min(0.25, 0.02 * len(matched)) + (0.08 if longest >= 3 else 0.0)
        hits.append((tool, round(min(strength, MAX_CONFIDENCE), 4)))
    # 「取消明天的会」里的「会」是被取消的对象，不是新建请求：破坏性动词命中、而 create 只由
    # 裸名词撑腰时，不再多提一个建会提案，否则一句话会同时给出两个互相矛盾的动作。
    if evidence.get("cancel") or evidence.get("reschedule"):
        create = evidence.get("create") or []
        if create and all(phrase in _WEAK_CREATE_NOUNS for phrase in create):
            hits = [row for row in hits if row[0] != "calendar.propose_create"]
    hits.sort(key=lambda row: _TOOL_PRIORITY.index(row[0]))
    return hits


# ------------------------------------------------------------------- 运行时


class NeedleRuntime:
    """Small-engine dispatcher: chat text in, structured calendar/workspace calls out."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        *,
        asset_root: Optional[Path] = None,
        force_fallback: bool = False,
        loader: Optional[Callable[[Path, Sequence[Any]], Any]] = None,
    ) -> None:
        self.settings = settings
        explicit_root = Path(asset_root).expanduser() if asset_root is not None else None
        if explicit_root is None:
            configured = str(getattr(settings, "needle_asset_dir", "") or "").strip()
            explicit_root = Path(configured).expanduser() if configured else None
        self.asset_root: Path = explicit_root or needle_assets.default_asset_root()
        self.force_fallback = bool(force_fallback)
        self.loader: Callable[[Path, Sequence[Any]], Any] = loader or default_loader
        # 注入 loader 即等于自带引擎（自检、嵌入式集成、未来的其它 runtime）：此时跳过
        # cactus 可用性门禁，否则 needle3 分支除了作者谁也测不到。生产默认仍是广接。
        self._external_engine = loader is not None and loader is not default_loader
        self.timeout_seconds = float(getattr(settings, "needle_timeout_seconds", 2.0) or 2.0)
        self._engine = ""
        self._agent: Any = None
        self._load_error = ""
        # force_fallback 是策略性降级，构造时就要在面板上讲清楚，而不是等第一次 load() 之后。
        self._degraded_reason = "needle3 已被显式禁用（force_fallback）" if self.force_fallback else ""
        self._weights_path: Optional[Path] = None
        self._asset_ok = False
        self._asset_sha256 = ""
        self._asset_bytes = 0
        self._sdk_available = False
        self._sdk_note = ""
        self._extractions = 0
        self._fallback_extractions = 0
        self._needle_extractions = 0
        self._truncated_inputs = 0
        self._unload_error = ""

    # ------------------------------------------------------------------ status
    def status(self) -> Dict[str, Any]:
        """Runtime truth, including the honest "we are on the deterministic path" flag."""
        return {
            "engine": self._engine or ENGINE_FALLBACK,
            "asset_ok": self._asset_ok,
            "asset_sha256": self._asset_sha256,
            "asset_bytes": self._asset_bytes,
            "asset_root": str(self.asset_root),
            "weights_path": str(self._weights_path) if self._weights_path else "",
            "sdk_available": self._sdk_available,
            "sdk_note": self._sdk_note,
            "external_engine": self._external_engine,
            "load_error": self._load_error,
            "degraded_reason": self._degraded_reason,
            "unload_error": self._unload_error,
            "extractions": self._extractions,
            "needle_extractions": self._needle_extractions,
            "fallback_extractions": self._fallback_extractions,
            "truncated_inputs": self._truncated_inputs,
            "degraded": self._engine != ENGINE_NEEDLE,
            "tools": list(TOOL_NAMES),
            "timeout_seconds": self.timeout_seconds,
        }

    @property
    def engine(self) -> str:
        return self._engine or ENGINE_FALLBACK

    # -------------------------------------------------------------------- load
    def load(self) -> str:
        """Integrity-gate the bundled weights, then try the SDK; never raises."""
        if self._engine:
            return self._engine
        if self.force_fallback:
            self._degrade("needle3 已被显式禁用（force_fallback）")
            return ENGINE_FALLBACK
        try:
            weights = needle_assets.ensure_weights(self.asset_root)
        except needle_assets.NeedleAssetError as exc:
            self._degrade(f"权重完整性校验未通过：{exc}")
            return ENGINE_FALLBACK
        except Exception as exc:  # noqa: BLE001 - an unreadable asset dir is a degraded start
            # 权限、符号链接断裂、目录被删都会到这里；结论一样：不加载，走确定性抽取。
            self._degrade(f"权重目录不可用：{type(exc).__name__}: {exc}")
            return ENGINE_FALLBACK
        self._weights_path = weights
        self._asset_ok = True
        # ensure_weights 已经逐字节比对过，清单里的 pin 值即等于实测值，不必再哈希一次 35MB。
        self._asset_sha256, self._asset_bytes = self._pinned()
        available, note = sdk_available()
        self._sdk_available = available
        self._sdk_note = note
        if not available and not self._external_engine:
            self._degrade(note or "端侧 SDK 不可用")
            return ENGINE_FALLBACK
        try:
            agent = self.loader(weights, list(TOOL_NAMES))
        except Exception as exc:  # noqa: BLE001 - every third-party engine failure degrades
            # cactus 的异常类型无法在不装 SDK 的前提下枚举，只能广接并留痕：加载失败必须
            # 变成 fallback，而不是让一条消息把 Studio 打挂。
            self._degrade(f"端侧引擎加载失败：{type(exc).__name__}: {exc}")
            return ENGINE_FALLBACK
        if not callable(getattr(agent, "run", None)):
            self._degrade(f"加载器返回的对象没有可调用的 run()：{type(agent).__name__}")
            return ENGINE_FALLBACK
        self._agent = agent
        self._engine = ENGINE_NEEDLE
        self._degraded_reason = ""
        self._load_error = ""
        return ENGINE_NEEDLE

    def _pinned(self) -> Tuple[str, int]:
        try:
            weights = needle_assets.load_manifest(self.asset_root).weights
        except needle_assets.NeedleAssetError as exc:
            self._degrade_reason = f"清单复核失败：{exc}"
            return "", 0
        except Exception as exc:  # noqa: BLE001 - see the note in load()
            self._degrade_reason = f"清单复核异常：{type(exc).__name__}: {exc}"
            return "", 0
        return weights.sha256, int(weights.bytes)

    def _degrade(self, reason: str) -> None:
        self._engine = ENGINE_FALLBACK
        self._agent = None
        self._degraded_reason = reason
        self._load_error = reason

    # ------------------------------------------------------------------ unload
    def unload(self) -> None:
        """Release the resident engine. Idempotent, and it never raises."""
        agent, self._agent = self._agent, None
        self._engine = ""
        self._asset_ok = False
        self._asset_sha256 = ""
        self._asset_bytes = 0
        self._weights_path = None
        self._unload_error = ""
        if agent is None:
            self._degraded_reason = "端侧引擎未加载或已卸载"
            return
        try:
            agent.close()
        except Exception as exc:  # noqa: BLE001 - teardown is best effort by contract
            self._unload_error = f"{type(exc).__name__}: {exc}"
        self._degraded_reason = self._unload_error or "端侧引擎已卸载"

    # ----------------------------------------------------------------- extract
    def extract(
        self,
        text: str,
        *,
        locale: str = "",
        hints: Optional[Dict[str, Any]] = None,
    ) -> Extraction:
        """Dispatch *text* into structured tool calls (synchronous, millisecond-scale)."""
        if not self._engine:
            self.load()
        started = time.perf_counter()
        raw = "" if text is None else str(text)
        if len(raw) > MAX_INPUT_CHARS:
            self._truncated_inputs += 1
            raw = raw[:MAX_INPUT_CHARS]
        passed: Mapping[str, Any] = hints if isinstance(hints, Mapping) else {}
        try:
            extraction = self._extract_sdk(raw, locale=locale, hints=passed)
        except Exception as exc:  # noqa: BLE001 - one bad message must not break the pipeline
            # 端侧引擎在 run() 里抛错时，本条改用确定性抽取器重算，原因留在 error 字段：
            # 降级只影响置信度与引擎名，不影响这条消息还能不能被处理。
            self._degrade(f"端侧推理失败，本条改用确定性抽取：{type(exc).__name__}: {exc}")
            extraction = self._extract_fallback(raw, locale=locale, hints=passed)
            extraction.error = self._degraded_reason
        extraction.latency_ms = round((time.perf_counter() - started) * 1000.0, 3)
        extraction.text = raw
        self._extractions += 1
        if extraction.engine == ENGINE_NEEDLE:
            self._needle_extractions += 1
        else:
            self._fallback_extractions += 1
        return extraction

    def _extract_sdk(self, text: str, *, locale: str, hints: Mapping[str, Any]) -> Extraction:
        if self._engine != ENGINE_NEEDLE or self._agent is None:
            return self._extract_fallback(text, locale=locale, hints=hints)
        self._agent.run(text)
        recorded = list(self._agent.take_calls()) if callable(getattr(self._agent, "take_calls", None)) else []
        calls: List[ToolCall] = []
        for dotted, arguments in recorded:
            name = str(dotted)
            if name not in TOOL_NAMES:
                continue
            calls.append(
                ToolCall(
                    name=name,
                    arguments=self._clean_arguments(name, arguments, hints),
                    confidence=MAX_CONFIDENCE,
                    engine=ENGINE_NEEDLE,
                )
            )
        if not calls:
            # 引擎没落到任何工具上：这是「这句话没有可执行意图」，不是解析失败，因此
            # 不降级、不记 error，只把原文留给上层（大模型可以自己判断）。
            return Extraction(intent="none", calls=[], engine=ENGINE_NEEDLE, degraded=False, text=text)
        return self._finish(calls, text, engine=ENGINE_NEEDLE, degraded=False)

    @staticmethod
    def _clean_arguments(dotted: str, arguments: Mapping[str, Any], hints: Mapping[str, Any]) -> Dict[str, Any]:
        """Keep only the schema's keys — the engine may hallucinate extras."""
        allowed = set(TOOL_SCHEMAS[dotted]["parameters"])
        cleaned = {
            str(key): value
            for key, value in dict(arguments or {}).items()
            if str(key) in allowed and value not in (None, "", [], {}, 0)
        }
        if dotted != "calendar.get_availability" and not cleaned.get("timezone"):
            hint_zone = str(hints.get("timezone") or "").strip()
            if hint_zone:
                cleaned["timezone"] = hint_zone
        return cleaned

    # ------------------------------------------------- deterministic extractor
    def _extract_fallback(self, text: str, *, locale: str, hints: Mapping[str, Any]) -> Extraction:
        normalized = _norm(text)
        if not normalized:
            return Extraction(intent="empty", calls=[], engine=ENGINE_FALLBACK, degraded=True, text="")
        zone_hint = str(hints.get("timezone") or "").strip()
        now = _as_now(hints.get("now"), zone_hint)
        zone = _find_timezone(normalized, zone_hint)
        if not is_valid_timezone(zone):
            zone = zone_hint if is_valid_timezone(zone_hint) else ""
        duration, duration_conf = _duration_minutes(normalized, hints.get("duration_minutes"))
        window = _window_days(normalized)
        calls: List[ToolCall] = []
        for dotted, strength in _matched_tools(normalized):
            arguments = self._arguments_for(
                dotted,
                normalized,
                now=now,
                zone=zone,
                duration=duration,
                duration_conf=duration_conf,
                window=window,
            )
            calls.append(
                ToolCall(
                    name=dotted,
                    arguments=arguments,
                    confidence=min(strength, MAX_CONFIDENCE),
                    engine=ENGINE_FALLBACK,
                )
            )
        if not calls:
            return Extraction(intent="none", calls=[], engine=ENGINE_FALLBACK, degraded=True, text=text)
        return self._finish(calls, text, engine=ENGINE_FALLBACK, degraded=True)

    def _arguments_for(
        self,
        dotted: str,
        text: str,
        *,
        now: datetime,
        zone: str,
        duration: Optional[int],
        duration_conf: float,
        window: Optional[int],
    ) -> Dict[str, Any]:
        day, clock, explicit_time, day_conf = _resolve_datetime(text, now)
        if dotted == "workspace.summarize_file":
            kind, value, ref_conf = _file_reference(text)
            arguments: Dict[str, Any] = {
                "file_ref": kind,
                "kind": value,
                # 显式留痕：小模型只声明引用，正文由授权后的 workspace 侧读取。
                "reads_contents": False,
                "reference_confidence": round(ref_conf, 4),
            }
            if kind == "named":
                arguments["file_name"] = value
            arguments["max_items"] = window if window and 1 <= window <= 10 else 5
            if zone:
                arguments["timezone"] = zone
            return arguments
        arguments = {}
        if day is not None:
            arguments["date"] = day.isoformat()
            arguments["date_confidence"] = round(day_conf, 4)
        if clock:
            arguments["time"] = clock
            arguments["time_explicit"] = bool(explicit_time)
        if zone:
            arguments["timezone"] = zone
        if dotted == "calendar.get_availability":
            if window:
                arguments["window_days"] = window
            elif re.search(r"哪几|哪天|什么时候|何时|when|which day|any day|what time", text):
                arguments["window_days"] = 7
            if duration:
                arguments["duration_minutes"] = duration
                arguments["duration_explicit"] = duration_conf >= 0.8
        elif dotted == "calendar.propose_create":
            arguments["duration_minutes"] = duration or DEFAULT_DURATION_MINUTES
            arguments["duration_explicit"] = bool(duration and duration_conf >= 0.8)
            title = _title(text)
            if title:
                arguments["title"] = title
            attendees = _attendees(text)
            if attendees:
                arguments["attendees"] = attendees
        elif dotted == "calendar.propose_reschedule":
            reference = _reference(text)
            if reference:
                arguments["reference"] = reference
            if duration:
                arguments["duration_minutes"] = duration
                arguments["duration_explicit"] = duration_conf >= 0.8
            origin, target = _reschedule_days(text, now)
            if target is not None:
                # 方向纠正优先于默认取值：改期句里的目标日期一定写在「改到/moved to」后面。
                arguments["date"] = target.isoformat()
                arguments["date_confidence"] = 0.9
            if origin is not None:
                arguments["from_date"] = origin.isoformat()
            elif (fallback_origin := _original_day(text, now)) is not None:
                arguments["from_date"] = fallback_origin.isoformat()
        elif dotted == "calendar.propose_cancel":
            reference = _reference(text)
            if reference:
                arguments["reference"] = reference
        return arguments

    @staticmethod
    def _finish(calls: List[ToolCall], text: str, *, engine: str, degraded: bool) -> Extraction:
        intents = sorted({INTENT_FOR_TOOL.get(call.name, "none") for call in calls})
        intent = intents[0] if len(intents) == 1 else ("mixed" if intents else "none")
        return Extraction(
            intent=intent,
            calls=calls,
            engine=engine,
            degraded=degraded,
            text=text,
        )


def _reschedule_days(text: str, now: datetime) -> Tuple[Optional[date], Optional[date]]:
    """``(origin, target)`` for 「周五的会改到周四」/「move it to friday」.

    改期句子里同时出现两个日期，而 :func:`_resolve_datetime` 只能取「最先出现的那个」——
    对「周五的会改到周四」就会把原日期当成新日期，方向整个反掉。所以这里按「改到/moved to」
    这个介词锚点把句子切成两半，前半找原日期、后半找目标日期，命中即覆盖默认取值。
    """
    cue = _RESCHEDULE_TO_RE.search(text)
    if not cue:
        return None, None
    tail = text[cue.end() :].strip()
    head = text[: cue.start()].strip()
    target = _resolve_datetime(tail, now)[0] if tail else None
    origin = _resolve_datetime(head, now)[0] if head else None
    if target is None or target == origin:
        # 「从周五改到周五」或介词锚点后面根本没写日期时不硬猜，交回默认取值。
        return None, None
    return origin, target


def _original_day(text: str, now: datetime) -> Optional[date]:
    """「周五的会改到周四」-> from_date 是周五；只在原文点名原日期时才填。"""
    if not re.search(
        r"(?:原来|原本|之前|本来|was|originally|moved from)|\bfrom\b|从[^,，。;；]{0,8}(?:改|挪|调|换|推|延|移)",
        text,
    ):
        return None
    anchor = re.search(r"([一二三四五六日天]|今天|明天|昨天|monday|tuesday|wednesday|thursday|friday)", text)
    if not anchor:
        return None
    token = anchor.group(1)
    weekday = _WEEKDAY_CN.get(token)
    if weekday is None:
        weekday = _WEEKDAY_EN.get(token)
    if weekday is None:
        offset = _OFFSET_CN.get(token)
        return now.date() + timedelta(days=offset) if offset is not None else None
    return _shift_to_weekday(now.date(), weekday)


def extract(
    text: str,
    *,
    settings: Optional[Settings] = None,
    locale: str = "",
    hints: Optional[Dict[str, Any]] = None,
    runtime: Optional[NeedleRuntime] = None,
) -> Extraction:
    """One-shot wrapper; builds a deterministic runtime when none is supplied."""
    shared = runtime or NeedleRuntime(settings, force_fallback=True)
    return shared.extract(text, locale=locale, hints=hints)


__all__ = [
    "DEFAULT_DURATION_MINUTES",
    "ENGINE_FALLBACK",
    "ENGINE_NEEDLE",
    "EXTRACT_ONLY",
    "INTENTS",
    "INTENT_FOR_TOOL",
    "MAX_INPUT_CHARS",
    "PATTERNS",
    "TOOL_NAMES",
    "TOOL_SCHEMAS",
    "TOOL_STUBS",
    "Extraction",
    "NeedleAgent",
    "NeedleRuntime",
    "ToolCall",
    "default_loader",
    "extract",
    "is_valid_timezone",
    "sdk_available",
]
