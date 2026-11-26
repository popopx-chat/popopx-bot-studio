"""agent engine 自检：小引擎抽取（needle3）+ 替身偏好（preferences）+ 大引擎桥（reasoner）+ 话术目录（copy）。

只测逻辑，不起服务、不联网、不起线程、不碰真实数据目录：全部落盘都进
:class:`app.selftest.Harness` 的临时根目录。约定与 ``app/selftest.py`` 其余分组一致——
断言标签用中文，失败就贴现场值，任何一条「没跑过的断言」都是谎话。

四个模块的硬边界，逐条钉住：

* ``needle3_runtime``：**只抽取**。五个工具全是只读回声桩；权重门禁不过、SDK 缺失、
  加载器抛错、引擎跑一条时炸——每一种都降级到本模块自带的确定性抽取器，且**永不**把
  异常抛给调用方。
* ``agent_preferences``：盘上那一份 JSON 永远可能被人手改坏，读回来要逐字段验；工作日与
  屏蔽时段一律按 **ISO 星期**（1=周一 … 7=周日）判定；候选时刻永远按它自己的墙钟比较。
* ``reasoner_bridge``：大模型只写话术，拿不到工具、不能落库；未启用、超时、非 200、返回
  垃圾都只是「这一条用了模板」，不是功能失效；API Key 不得出现在提示词、状态或 repr 里。
* ``agent_copy``：18 语种 × 12 话术的键集与占位符集必须完全对齐，且某一种语言里断言的
  事实不能被另一种语言反驳（本仓刚被「一种语言多说了一句另外 17 种都没有的话」咬过）。
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo, available_timezones

from . import agent_copy
from . import agent_preferences
from . import i18n
from . import needle3_runtime
from . import needle_assets
from . import reasoner_bridge
from .selftest import Harness, SelfTest

GROUP = "agent_engine"

# 所有相对日期都通过 hints={"now": ...} 注入时钟：结论与跑自检的那一天无关。
_NOW = datetime(2026, 11, 26, 10, 0, tzinfo=ZoneInfo("Asia/Shanghai"))  # 周四（ISO 4）
_EPOCH = _NOW.timestamp()
_DAY = 86400.0
_PREFS: List[str] = []  # 每次自检只用来给临时库起不重名的名字


def ok(test: SelfTest, label: str) -> None:
    """小节收尾：一条永远为真的断言，让「跑了多少类检查」在计数里看得见。"""
    test.check(f"{label}：本节跑完", True)


def fail(test: SelfTest, label: str, detail: str = "") -> None:
    test.check(label, False, detail)


def _slot(day_offset: int = 1, hour: int = 15, minute: int = 0, tz: str = "Asia/Shanghai",
          minutes: int = 30, **extra: Any) -> Dict[str, Any]:
    """按 *tz* 的墙钟造一个候选时段；``_NOW`` 起算偏移整天。"""
    anchor = datetime(_NOW.year, _NOW.month, _NOW.day, tzinfo=ZoneInfo(tz)) + timedelta(days=day_offset)
    start = anchor.replace(hour=hour, minute=minute)
    row: Dict[str, Any] = {"start": start.timestamp(), "end": start.timestamp() + minutes * 60.0, "tz": tz}
    row.update(extra)
    return row


def _pref_bot(h: Harness, tag: str) -> Tuple[agent_preferences.PreferenceStore, str]:
    """返回 (偏好仓库, 真实 bot_id)。bot_id 走一遍建 Bot 路径，避免自检用假 id 蒙混。"""
    settings = h.settings()
    name = f"prefs{len(_PREFS)}"
    _PREFS.append(name)
    database = h.database(name)
    bot_id = str(database.create_bot(name, 5350, display_name="自检替身")["id"])
    return agent_preferences.PreferenceStore(settings, clock=lambda: 1_700_000_000.0), bot_id


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    path.write_text(text, encoding="utf-8")


def _dig(row: Mapping[str, Any], dotted: str) -> Any:
    cur: Any = row
    for piece in dotted.split("."):
        if isinstance(cur, Mapping):
            cur = cur.get(piece, "<缺键>")
        elif isinstance(cur, (list, tuple)) and piece.isdigit() and int(piece) < len(cur):
            cur = cur[int(piece)]
        else:
            return "<不是对象>"
    return cur


# ------------------------------------------------------------------ 1. needle3


def _needle_tables(test: SelfTest, h: Harness) -> None:
    """静态契约：五个工具、schema、只读回声桩、意图表——后面所有断言的地基。"""
    names = list(needle3_runtime.TOOL_NAMES)
    test.eq("TOOL_NAMES 有五个工具", len(names), 5)
    test.eq("TOOL_NAMES 无重复", len(set(names)), 5)
    test.eq("schema 覆盖每个工具", sorted(needle3_runtime.TOOL_SCHEMAS), sorted(names))
    test.eq("回声桩覆盖每个工具", sorted(needle3_runtime.TOOL_STUBS), sorted(names))
    test.eq("意图表覆盖每个工具", sorted(needle3_runtime.INTENT_FOR_TOOL), sorted(names))
    test.check("五个意图互不重复",
               len(set(needle3_runtime.INTENT_FOR_TOOL.values())) == 5,
               str(needle3_runtime.INTENT_FOR_TOOL))
    for intent in needle3_runtime.INTENT_FOR_TOOL.values():
        test.contains(f"意图 {intent} 在 INTENTS 里", needle3_runtime.INTENTS, intent)
    for intent in ("empty", "none", "mixed"):
        test.contains(f"INTENTS 含 {intent}", needle3_runtime.INTENTS, intent)
    for dotted in names:
        schema = needle3_runtime.TOOL_SCHEMAS[dotted]
        test.check(f"{dotted} 有描述文本", len(str(schema.get("description") or "")) > 12,
                   str(schema.get("description"))[:60])
        test.check(f"{dotted} 参数表非空", isinstance(schema.get("parameters"), dict) and
                   bool(schema["parameters"]), str(schema.get("parameters"))[:60])
        for arg, spec in schema["parameters"].items():
            test.check(f"{dotted}.{arg} 声明了类型", bool(str(spec).strip()), str(spec))
        stub = needle3_runtime.TOOL_STUBS[dotted]
        test.check(f"{dotted} 的桩可调用", callable(stub), type(stub).__name__)
        test.eq(f"{dotted} 的桩只回声、不落库",
                stub(**{str(arg): "" for arg in schema["parameters"]}),
                needle3_runtime.EXTRACT_ONLY)
    test.eq("引擎标签 fallback", needle3_runtime.ENGINE_FALLBACK, "fallback")
    test.eq("引擎标签 needle3", needle3_runtime.ENGINE_NEEDLE, "needle3")
    test.eq("两个引擎标签不同", needle3_runtime.ENGINE_NEEDLE == needle3_runtime.ENGINE_FALLBACK, False)
    test.eq("MAX_INPUT_CHARS", needle3_runtime.MAX_INPUT_CHARS, 4000)
    test.eq("DEFAULT_DURATION_MINUTES", needle3_runtime.DEFAULT_DURATION_MINUTES, 60)
    test.eq("MAX_CONFIDENCE 留有余量", needle3_runtime.MAX_CONFIDENCE, 0.95)
    test.eq("EXTRACT_ONLY 是只读回声", needle3_runtime.EXTRACT_ONLY, {"status": "extract_only"})
    for dotted, stub in needle3_runtime.TOOL_STUBS.items():
        test.eq(f"桩 {dotted} 被调用也只回声、不落库", stub(), needle3_runtime.EXTRACT_ONLY)
    test.eq("PATTERNS 覆盖五个意图", sorted(needle3_runtime.PATTERNS),
            sorted(set(needle3_runtime.INTENT_FOR_TOOL.values())))
    for intent, phrases in needle3_runtime.PATTERNS.items():
        test.check(f"短语表 {intent} 非空", len(phrases) >= 10, f"{len(phrases)} 条")
        test.check(f"短语表 {intent} 无空串", all(str(p).strip() for p in phrases), "")
        test.eq(f"短语表 {intent} 无重复", len(set(phrases)), len(phrases))
    ok(test, "needle3 静态契约")


def _needle_tools(test: SelfTest, h: Harness) -> None:
    """意图 → 工具映射：五个工具各有中文与英文说法，关键参数逐字段钉住。"""

    def run(text: str, **hints: Any) -> needle3_runtime.Extraction:
        merged: Dict[str, Any] = {"now": _NOW}
        merged.update(hints)
        return needle3_runtime.extract(text, hints=merged)

    def one(label: str, text: str, want_tool: str, checks: Optional[Mapping[str, Any]] = None,
            **hints: Any) -> needle3_runtime.Extraction:
        ex = run(text, **hints)
        test.eq(f"{label} 走确定性引擎", ex.engine, needle3_runtime.ENGINE_FALLBACK)
        test.eq(f"{label} 标 degraded", ex.degraded, True)
        test.eq(f"{label} 出工具 {want_tool}", ex.tool, want_tool)
        test.eq(f"{label} 只有一个调用", len(ex.calls), 1)
        test.eq(f"{label} 意图与工具一致", ex.intent, needle3_runtime.INTENT_FOR_TOOL.get(want_tool, "?"))
        test.eq(f"{label} 调用引擎标签", ex.calls[0].engine, needle3_runtime.ENGINE_FALLBACK)
        args = ex.arguments()
        for key, want in (checks or {}).items():
            test.eq(f"{label} 参数 {key}", args.get(key, "<缺>"), want)
        return ex

    # calendar.get_availability —— 问空档
    one("中文问空档", "你明天下午有空吗？我们约 30 分钟。", "calendar.get_availability",
        {"date": "2026-11-27", "duration_minutes": 30, "duration_explicit": True})
    one("英文问空档", "are you free tomorrow at 3pm?", "calendar.get_availability",
        {"date": "2026-11-27", "time": "15:00", "time_explicit": True})
    one("中文问哪天有空", "下周哪天你有空？", "calendar.get_availability",
        {"date": "2026-12-03", "window_days": 7})
    one("英文问哪天有空", "any openings this week?", "calendar.get_availability", {"window_days": 7})
    # calendar.propose_create —— 约会议
    one("中文约会", "下周二下午两点约个 45 分钟的会", "calendar.propose_create",
        {"date": "2026-12-08", "time": "14:00", "duration_minutes": 45, "duration_explicit": True})
    one("英文约会", "let's book a 30 minute sync on monday at 4pm", "calendar.propose_create",
        {"date": "2026-11-30", "time": "16:00", "duration_minutes": 30})
    one("中文约会未写时长", "明天 15:00 开会", "calendar.propose_create",
        {"date": "2026-11-27", "time": "15:00",
         "duration_minutes": needle3_runtime.DEFAULT_DURATION_MINUTES, "duration_explicit": False})
    # calendar.propose_reschedule —— 改期：原日期与目标日期方向不能反
    one("中文改期", "周五的会改到周四", "calendar.propose_reschedule",
        {"date": "2026-11-26", "from_date": "2026-11-27"})
    one("英文改期", "please move it to friday", "calendar.propose_reschedule", {"date": "2026-11-27"})
    one("英文改期到下周", "can we push it to next monday", "calendar.propose_reschedule",
        {"date": "2026-12-07"})
    # calendar.propose_cancel —— 取消
    one("中文取消", "取消明天和张三的会", "calendar.propose_cancel",
        {"date": "2026-11-27", "reference": "明天和张三"})
    one("英文取消", "cancel tomorrow's meeting", "calendar.propose_cancel", {"date": "2026-11-27"})
    one("英文取消带钟点", "cancel friday's 3pm", "calendar.propose_cancel",
        {"date": "2026-11-27", "time": "15:00"})
    # workspace.summarize_file —— 只声明文件引用，绝不读正文
    one("中文总结文件", "总结一下 roadmap.pdf", "workspace.summarize_file",
        {"file_ref": "named", "kind": "roadmap.pdf", "reads_contents": False, "max_items": 5})
    one("英文总结文件", "summarize notes.pdf", "workspace.summarize_file",
        {"file_ref": "named", "reads_contents": False, "file_name": "notes.pdf"})
    one("中文总结纪要（没写文件名）", "帮我看看这份纪要", "workspace.summarize_file",
        {"file_ref": "placeholder", "kind": "minutes", "reads_contents": False})

    # 一句话里多个意图：按优先级排序、intent 标 mixed，交给上层决定跟哪条。
    multi = run("取消明天的会，另外约个时间")
    test.eq("多意图句 intent=mixed", multi.intent, "mixed")
    test.eq("多意图句有两个调用", len(multi.calls), 2)
    test.eq("多意图句首个是 cancel", multi.calls[0].name, "calendar.propose_cancel")
    test.eq("多意图句次个是 create", multi.calls[1].name, "calendar.propose_create")
    test.eq("primary 指向首个调用", multi.tool, multi.calls[0].name)
    test.eq("arguments(name) 取指定调用", multi.arguments("calendar.propose_create").get("date"),
            "2026-11-27")
    test.eq("arguments(name) 未命中返回空表", multi.arguments("nope.such"), {})
    test.eq("mixed 也在 INTENTS 里", multi.intent in needle3_runtime.INTENTS, True)

    # 标题/参会人：卡片话术要用，抽不到就只能显示空标题。
    titled = run("下周三上午十点约个会 讨论合同细节")
    test.check("create 抽出非空标题", bool(str(titled.arguments().get("title") or "").strip()),
               str(titled.arguments().get("title")))
    attended = run("邀请 Ann 和 Ken 明天下午三点开会")
    test.eq("create 抽出参会人", attended.arguments().get("attendees"), ["Ann", "Ken"])
    test.eq("参会人是列表", isinstance(attended.arguments().get("attendees"), list), True)
    # 没注入时钟时用内置基准日（2026-05-11 09:30 +08），保证离线可复现。
    test.eq("不注入时钟用内置基准日",
            needle3_runtime.extract("明天有空吗").arguments().get("date"), "2026-05-12")
    ok(test, "needle3 意图→工具映射")


def _needle_fallback(test: SelfTest, h: Harness) -> None:
    """降级路径必须确定：门禁不过、SDK 缺失、引擎抛错、加载器抛错，一律回确定性抽取。"""
    root = h.root / "needle-assets"
    blob = b"selftest-needle-weights-v1"
    _write_fake_assets(root, blob)
    loader_calls: List[Tuple[str, int]] = []

    class FakeEngine:
        """假端侧引擎：只回放「SDK 调工具并记参数」这一件事，不碰任何原生库。"""

        def __init__(self, scripted: Sequence[Any] = (), error: Optional[BaseException] = None,
                     close_error: Optional[BaseException] = None) -> None:
            self.script = list(scripted)
            self.error = error
            self.close_error = close_error
            self.runs: List[str] = []
            self.closed = 0

        def run(self, text: str) -> Mapping[str, Any]:
            self.runs.append(text)
            if self.error is not None:
                raise self.error
            return {"results": len(self.runs)}

        def take_calls(self) -> List[Tuple[str, Dict[str, Any]]]:
            out: List[Tuple[str, Dict[str, Any]]] = []
            while self.script and isinstance(self.script[0], tuple):
                name, args = self.script.pop(0)
                out.append((str(name), dict(args)))
            return out

        def close(self) -> None:
            self.closed += 1
            if self.close_error is not None:
                raise self.close_error

    def build(engine: FakeEngine, *, boom: Optional[BaseException] = None,
              raw: Any = None) -> needle3_runtime.NeedleRuntime:
        def loader(weights: Path, tools: Sequence[Any]) -> Any:
            loader_calls.append((weights.name, len(list(tools))))
            if boom is not None:
                raise boom
            return engine if raw is None else raw

        return needle3_runtime.NeedleRuntime(settings=None, asset_root=root, loader=loader)

    # 1) SDK 不可用：连加载器都不该被碰，这一条照样抽取成功。
    sdk_gate = needle3_runtime.sdk_available
    needle3_runtime.sdk_available = lambda: (False, "自检：本机没有端侧 SDK")
    try:
        gated = needle3_runtime.NeedleRuntime(settings=None, asset_root=root)
        test.eq("SDK 缺失时 load() 返回 fallback", gated.load(), needle3_runtime.ENGINE_FALLBACK)
        test.eq("SDK 缺失不碰加载器", len(loader_calls), 0)
        test.contains("SDK 缺失写明原因", gated.status()["degraded_reason"], "自检")
        test.eq("SDK 缺失的 status 标记", gated.status()["sdk_available"], False)
        ex = gated.extract("明天下午3点有空吗", hints={"now": _NOW})
        test.eq("SDK 缺失照样抽出工具", ex.tool, "calendar.get_availability")
        test.eq("SDK 缺失的引擎标签", ex.engine, needle3_runtime.ENGINE_FALLBACK)
        test.eq("SDK 缺失标 degraded", ex.degraded, True)
    finally:
        needle3_runtime.sdk_available = sdk_gate
    probed = needle3_runtime.sdk_available()
    test.eq("sdk_available 返回二元组", len(probed), 2)
    test.eq("sdk_available 第一位是布尔", isinstance(probed[0], bool), True)
    test.eq("sdk_available 第二位是字符串", isinstance(probed[1], str), True)

    # 2) 权重门禁：清单缺失或字节被改过时不加载，原因留痕。
    missing = needle3_runtime.NeedleRuntime(settings=None, asset_root=h.root / "needle-empty")
    test.eq("无权重清单时降级", missing.load(), needle3_runtime.ENGINE_FALLBACK)
    test.contains("无权重清单写明原因", missing.status()["load_error"], "清单")
    test.eq("门禁不过不记录 asset_ok", missing.status()["asset_ok"], False)
    tampered = h.root / "needle-tampered"
    _write_fake_assets(tampered, blob)
    (tampered / needle_assets.WEIGHT_FILE).write_bytes(blob + b"!")
    broken = needle3_runtime.NeedleRuntime(settings=None, asset_root=tampered)
    test.eq("权重字节被改过时降级", broken.load(), needle3_runtime.ENGINE_FALLBACK)
    test.check("改过的权重写明原因",
               "SHA" in broken.status()["load_error"].upper() or "字节" in broken.status()["load_error"],
               broken.status()["load_error"])
    # 「门禁过了就该驻留」这条成功路径只能靠注入加载器走：自检机器上没有 Cactus 原生库，
    # 真加载器会在 SDK 门禁处降级。资产目录还是那份假权重，校验与记账完全同构。
    good = build(FakeEngine())
    test.eq("校验通过后加载 needle3", good.load(), needle3_runtime.ENGINE_NEEDLE)
    test.eq("加载后 status.engine", good.status()["engine"], needle3_runtime.ENGINE_NEEDLE)
    test.eq("加载后 degraded=false", good.status()["degraded"], False)
    test.eq("记下权重文件", Path(good.status()["weights_path"]).name, needle_assets.WEIGHT_FILE)
    test.eq("记下资产根", good.status()["asset_root"], str(root))
    test.eq("记下清里的 sha", good.status()["asset_sha256"], hashlib.sha256(blob).hexdigest())
    test.eq("记下权重字节数", good.status()["asset_bytes"], len(blob))
    test.eq("重复 load() 幂等", good.load(), needle3_runtime.ENGINE_NEEDLE)

    # 3) 端侧路径：只收参数，schema 外的键与空值都被洗掉。
    engine = FakeEngine([("calendar.propose_create",
                          {"date": "2026-12-01", "title": "", "duration_minutes": 0,
                           "attendees": ["Ann"], "hallucinated": "x"})])
    injected = build(engine)
    test.eq("注入加载器即视为自带引擎", injected.load(), needle3_runtime.ENGINE_NEEDLE)
    test.eq("外部引擎标记", injected.status()["external_engine"], True)
    ex = injected.extract("约个会", hints={"now": _NOW, "timezone": "Europe/Berlin"})
    test.eq("端侧路径引擎标签", ex.engine, needle3_runtime.ENGINE_NEEDLE)
    test.eq("端侧路径不标 degraded", ex.degraded, False)
    test.eq("端侧路径 error 为空", ex.error, "")
    test.eq("端侧路径置信度封顶", ex.calls[0].confidence, needle3_runtime.MAX_CONFIDENCE)
    test.eq("端侧路径 intent 来自工具表", ex.intent, "create")
    test.eq("端侧路径保留原文", ex.text, "约个会")
    test.eq("洗掉幻觉参数", "hallucinated" in ex.arguments(), False)
    test.eq("洗掉空串参数", "title" in ex.arguments(), False)
    test.eq("洗掉 0 值参数", "duration_minutes" in ex.arguments(), False)
    test.eq("保留数组参数", ex.arguments().get("attendees"), ["Ann"])
    test.eq("非空档工具补 hints 时区", ex.arguments().get("timezone"), "Europe/Berlin")
    test.eq("加载器收到权重路径", loader_calls[-1][0], needle_assets.WEIGHT_FILE)
    test.eq("加载器收到五个工具", loader_calls[-1][1], 5)
    test.eq("引擎被调用一次", engine.runs, ["约个会"])
    drained = injected.extract("再抽一次", hints={"now": _NOW})
    test.eq("记号取空时不编造工具", drained.calls, [])
    test.eq("记号取空仍是端侧引擎", drained.engine, needle3_runtime.ENGINE_NEEDLE)
    test.eq("记号取空不标 degraded", drained.degraded, False)
    test.eq("记号取空 intent=none", drained.intent, "none")
    test.eq("记号取空不记 error", drained.error, "")

    # 4) 引擎给出白名单外的工具名：丢掉，但不改引擎、不降级。
    rogue = build(FakeEngine([("workspace.delete_everything", {"yes": True})]))
    ex = rogue.extract("删掉我所有日程", hints={"now": _NOW})
    test.eq("白名单外工具被丢弃", ex.calls, [])
    test.eq("白名单外工具不降级", ex.engine, needle3_runtime.ENGINE_NEEDLE)
    test.eq("白名单外工具 intent=none", ex.intent, "none")

    # 5) 引擎这一条抛错（超时/崩溃等价）：本条改用确定性抽取，原因写进 error。
    boom_engine = build(FakeEngine([], error=RuntimeError("端侧推理超时")))
    ex = boom_engine.extract("明天下午3点有空吗", hints={"now": _NOW})
    test.eq("引擎抛错后本条仍出工具", ex.tool, "calendar.get_availability")
    test.eq("引擎抛错后引擎名=fallback", ex.engine, needle3_runtime.ENGINE_FALLBACK)
    test.eq("引擎抛错后 degraded", ex.degraded, True)
    test.contains("引擎抛错原因带异常类型", ex.error, "RuntimeError")
    test.contains("引擎抛错原因带原话", ex.error, "超时")
    test.contains("降级原因进了 status", boom_engine.status()["degraded_reason"], "RuntimeError")
    test.eq("坏引擎不再被重复调用", boom_engine.status()["engine"], needle3_runtime.ENGINE_FALLBACK)
    again = boom_engine.extract("取消明天的会", hints={"now": _NOW})
    test.eq("后续消息直接用确定性抽取", again.engine, needle3_runtime.ENGINE_FALLBACK)
    test.eq("后续消息照样出工具", again.tool, "calendar.propose_cancel")

    # 6) 加载器抛错 / 返回不可调用对象：只能降级，不能冒异常。
    raised = build(FakeEngine(), boom=OSError("原生库缺失"))
    test.eq("加载器抛错 → fallback", raised.load(), needle3_runtime.ENGINE_FALLBACK)
    test.contains("加载器抛错留痕", raised.status()["load_error"], "OSError")
    test.eq("加载器抛错后仍能抽取",
            raised.extract("明天下午有空吗", hints={"now": _NOW}).tool, "calendar.get_availability")
    dumb = needle3_runtime.NeedleRuntime(settings=None, asset_root=root, loader=lambda w, t: object())
    test.eq("无 run() 的引擎 → fallback", dumb.load(), needle3_runtime.ENGINE_FALLBACK)
    test.contains("无 run() 写明原因", dumb.status()["load_error"], "run()")

    # 7) unload 幂等、关闭异常只留痕；卸载后下一条自动重载。
    closer = FakeEngine([("calendar.get_availability", {"window_days": 7})],
                        close_error=ValueError("原生上下文关闭失败"))
    closing = build(closer)
    test.eq("先加载成功", closing.load(), needle3_runtime.ENGINE_NEEDLE)
    closing.unload()
    test.eq("卸载后引擎名回到 fallback", closing.status()["engine"], needle3_runtime.ENGINE_FALLBACK)
    test.eq("卸载后 asset_ok 清空", closing.status()["asset_ok"], False)
    test.eq("卸载后 weights_path 清空", closing.status()["weights_path"], "")
    test.eq("卸载后 sha 记录清空", closing.status()["asset_sha256"], "")
    test.eq("卸载后 degraded=true", closing.status()["degraded"], True)
    test.contains("关闭异常记进 unload_error", closing.status()["unload_error"], "ValueError")
    test.contains("关闭异常也写进降级原因", closing.status()["degraded_reason"], "ValueError")
    test.eq("引擎被关一次", closer.closed, 1)
    closing.unload()
    test.eq("重复 unload 幂等（不再关第二次）", closer.closed, 1)
    test.contains("第二次卸载说明未加载", closing.status()["degraded_reason"], "未加载")
    revived = closing.extract("明天下午有空吗", hints={"now": _NOW})
    test.eq("卸载后自动重载", revived.engine, needle3_runtime.ENGINE_NEEDLE)
    test.eq("重载后照样出工具", revived.tool, "calendar.get_availability")
    test.eq("重载后 unload_error 清空", closing.status()["unload_error"], "")

    # 8) 确定性回退可复现：同输入两次逐字段一致（latency 除外）。
    rt = needle3_runtime.NeedleRuntime(settings=None, force_fallback=True)
    first = rt.extract("明天下午3点有空吗", hints={"now": _NOW}).as_dict()
    second = rt.extract("明天下午3点有空吗", hints={"now": _NOW}).as_dict()
    first.pop("latency_ms")
    second.pop("latency_ms")
    test.eq("同输入两次抽取一致", first, second)
    test.eq("force_fallback 不调加载器",
            needle3_runtime.NeedleRuntime(settings=None, force_fallback=True,
                                          loader=lambda w, t: FakeEngine()).load(),
            needle3_runtime.ENGINE_FALLBACK)
    test.contains("force_fallback 写明原因",
                  needle3_runtime.NeedleRuntime(settings=None,
                                                force_fallback=True).status()["degraded_reason"],
                  "force_fallback")
    ok(test, "needle3 降级与门禁")


def _write_fake_assets(root: Path, blob: bytes) -> None:
    """造一份**能通过**完整性门禁的权重目录（临时目录里的假字节，绝不联网、绝不下载）。"""
    root.mkdir(parents=True, exist_ok=True)
    (root / needle_assets.WEIGHT_FILE).write_bytes(blob)
    manifest = {
        "asset": needle_assets.WEIGHT_FILE,
        "purpose": "selftest",
        "source": {"origin": "local-selftest"},
        "license": {"spdx": "Apache-2.0"},
        "model": {"name": "selftest-fake"},
        "files": {needle_assets.WEIGHT_FILE: {"bytes": len(blob),
                                             "sha256": hashlib.sha256(blob).hexdigest()}},
    }
    (root / needle_assets.MANIFEST_NAME).write_text(json.dumps(manifest, ensure_ascii=False),
                                                    encoding="utf-8")


def _needle_hygiene(test: SelfTest, h: Harness) -> None:
    """输入卫生：截断、非字符串、时区、越界数字——任何一条都不许把异常抛出链路外。"""

    def ex(text: Any, **hints: Any) -> needle3_runtime.Extraction:
        merged: Dict[str, Any] = {"now": _NOW}
        merged.update(hints)
        return needle3_runtime.extract(text, hints=merged)

    rt = needle3_runtime.NeedleRuntime(settings=None, force_fallback=True)
    long_ex = rt.extract("有空吗 " + "呀" * (needle3_runtime.MAX_INPUT_CHARS + 500))
    test.eq("超长输入截到上限", len(long_ex.text), needle3_runtime.MAX_INPUT_CHARS)
    test.eq("截断计数 +1", rt.status()["truncated_inputs"], 1)
    rt.extract("明天下午有空吗")
    test.eq("正常长度不计数", rt.status()["truncated_inputs"], 1)
    test.eq("抽取总计数", rt.status()["extractions"], 2)
    test.eq("回退抽取计数", rt.status()["fallback_extractions"], 2)
    test.eq("端侧抽取计数为 0", rt.status()["needle_extractions"], 0)
    test.eq("status.tools 即工具表", rt.status()["tools"], list(needle3_runtime.TOOL_NAMES))
    test.eq("status.timeout_seconds 有默认值", rt.status()["timeout_seconds"], 2.0)
    test.eq("status.degraded 为真", rt.status()["degraded"], True)
    probe = rt.extract("你好")
    test.check("latency_ms 非负", probe.latency_ms >= 0.0, str(probe.latency_ms))
    test.eq("无意图短句 intent=none", probe.intent, "none")
    test.eq("未注入时钟也能抽", rt.extract("明天有空吗").tool, "calendar.get_availability")

    for label, junk in [
        ("空串", ""), ("纯空白", "   \n\t "), ("只有标点", "。。。！！！"),
        ("SQL 片段", "'; DROP TABLE bookings; --"), ("HTML 注入", "<script>alert(1)</script>"),
        ("模板占位", "{{7*7}} %s %d {}"), ("代理对", "明\udc80天"), ("surrogate", "\ud800"),
        ("emoji", "🙂🙃"), ("半个词", "下"), ("超长重复", "约" * 5000),
        ("混合标记", "<b>明天</b> &amp; 15:00"), ("NUL", "明天\x00有空"),
        ("控制字符", "\x01\x02\x03"), ("路径", "../../../../etc/passwd"),
    ]:
        try:
            e = ex(junk)
            test.check(f"垃圾输入不炸（{label}）",
                       e.intent in needle3_runtime.INTENTS and isinstance(e.calls, list) and
                       len(e.text) <= needle3_runtime.MAX_INPUT_CHARS,
                       f"{e.intent}/{len(e.calls)}")
        except Exception as exc:  # noqa: BLE001 - 这条断言的意义就是证明走不到这里
            fail(test, f"垃圾输入抛异常（{label}）", f"{type(exc).__name__}: {exc}")
    for label, junk in [("None", None), ("int", 12345), ("float", 3.5), ("bool", True),
                        ("list", ["明天"]), ("dict", {"text": "明天"}), ("bytes", b"tomorrow"),
                        ("object", object())]:
        try:
            e = needle3_runtime.NeedleRuntime(settings=None,
                                              force_fallback=True).extract(junk)
            test.check(f"非字符串输入不炸（{label}）",
                       e.intent in needle3_runtime.INTENTS and e.error == "",
                       f"{e.intent}/{e.error[:40]}")
        except Exception as exc:  # noqa: BLE001
            fail(test, f"非字符串输入抛异常（{label}）", f"{type(exc).__name__}: {exc}")

    # 时区：文本里的 iana 名、城市、缩写、UTC 都认；认不出就不写这个参数。
    test.eq("抽出 iana 名", ex("book a call tomorrow 3pm in Europe/Berlin").arguments().get("timezone"),
            "Europe/Berlin")
    test.eq("抽出城市别名 berlin", ex("明天下午3点在 berlin 开会").arguments().get("timezone"),
            "Europe/Berlin")
    test.eq("抽出中文城市名", ex("上海明天有空吗").arguments().get("timezone"), "Asia/Shanghai")
    test.eq("抽出英文城市名", ex("any openings in new york this week?").arguments().get("timezone"),
            "America/New_York")
    test.eq("抽出时区缩写 pst", ex("call at 3pm pst").arguments().get("timezone"),
            "America/Los_Angeles")
    test.eq("utc 字样归一到 UTC", ex("明天下午3点有空吗 utc").arguments().get("timezone"), "UTC")
    test.eq("不存在的时区不写参数", ex("Mars/Olympus 有空吗").arguments().get("timezone", ""), "")
    test.eq("hints 时区补进参数", ex("明天有空吗", timezone="Europe/Berlin").arguments().get("timezone"),
            "Europe/Berlin")
    test.eq("hints 非法时区被丢弃", ex("明天有空吗", timezone="Not/AZone").arguments().get("timezone", ""),
            "")
    for name, want in [("Asia/Shanghai", True), ("UTC", True), ("Etc/GMT-8", True),
                       ("Europe/Berlin", True), ("Mars/Olympus", False), ("", False),
                       ("   ", False), ("../etc", False), ("上海", False), ("utc", False)]:
        test.eq(f"is_valid_timezone({name!r})", needle3_runtime.is_valid_timezone(name), want)
    for junk in (None, 7, [], {}, b"x", True):
        test.eq(f"is_valid_timezone({type(junk).__name__}) 不抛异常",
                needle3_runtime.is_valid_timezone(junk), False)
    sample = sorted(available_timezones())[:40]
    test.check("zoneinfo 里的时区都判为有效",
               all(needle3_runtime.is_valid_timezone(z) for z in sample),
               str([z for z in sample if not needle3_runtime.is_valid_timezone(z)])[:80])

    # 越界数字与超长串：抽取阶段就收敛。
    test.eq("window_days 越界不采用", ex("未来 999 天哪天有空").arguments().get("window_days"), 7)
    test.eq("max_items 有上限", ex("总结 roadmap.pdf 最近 99 天").arguments().get("max_items"), 5)
    many = ex("开会 拉上 " + " ".join(f"P{index}" for index in range(60))).arguments()
    test.check("参会人数量有界", len(many.get("attendees", [])) <= 12, str(len(many.get("attendees", []))))
    test.check("超长句不撑爆参数",
               len(json.dumps(ex("约 " + "了" * 3000 + " 明天的会").arguments(),
                              ensure_ascii=False)) < 8000, "")
    test.eq("非法 now 类型回落到基准日",
            needle3_runtime.NeedleRuntime(settings=None, force_fallback=True)
            .extract("明天有空吗", hints={"now": "不是日期"}).arguments().get("date"), "2026-05-12")
    test.eq("epoch 数字型 now 可用",
            needle3_runtime.NeedleRuntime(settings=None, force_fallback=True)
            .extract("明天有空吗", hints={"now": _EPOCH}).arguments().get("date"), "2026-11-27")
    test.eq("date 型 now 可用",
            needle3_runtime.NeedleRuntime(settings=None, force_fallback=True)
            .extract("明天有空吗", hints={"now": _NOW.date()}).arguments().get("date"), "2026-11-27")
    test.eq("hints 不是映射时按空处理",
            needle3_runtime.NeedleRuntime(settings=None, force_fallback=True)
            .extract("明天有空吗", hints="不是映射").arguments().get("date"), "2026-05-12")
    ok(test, "needle3 输入卫生")


def _needle_shapes(test: SelfTest, h: Harness) -> None:
    """Extraction / ToolCall 的对外形状：上层卡片与话术就靠这几个字段拼装。"""
    ex = needle3_runtime.extract("明天下午3点有空吗", hints={"now": _NOW})
    test.eq("Extraction 字段集", sorted(ex.as_dict()),
            sorted(["intent", "engine", "degraded", "latency_ms", "error", "text", "calls"]))
    test.eq("ToolCall 字段集", sorted(ex.calls[0].as_dict()),
            sorted(["name", "arguments", "confidence", "engine"]))
    test.eq("ToolCall.name", ex.calls[0].as_dict()["name"], "calendar.get_availability")
    test.eq("ToolCall.engine", ex.calls[0].as_dict()["engine"], needle3_runtime.ENGINE_FALLBACK)
    test.eq("ToolCall.confidence 收敛到 4 位", ex.calls[0].as_dict()["confidence"],
            round(ex.calls[0].confidence, 4))
    test.check("置信度落在 (0, MAX_CONFIDENCE]",
               0.0 < ex.calls[0].confidence <= needle3_runtime.MAX_CONFIDENCE,
               str(ex.calls[0].confidence))
    test.eq("as_dict 的 arguments 是副本", ex.calls[0].as_dict()["arguments"] is ex.calls[0].arguments,
            False)
    test.eq("as_dict.text 就是原文", ex.as_dict()["text"], "明天下午3点有空吗")
    test.eq("as_dict.calls 是列表", isinstance(ex.as_dict()["calls"], list), True)
    empty = needle3_runtime.Extraction("none")
    test.eq("空抽取 primary=None", empty.primary, None)
    test.eq("空抽取 tool 空串", empty.tool, "")
    test.eq("空抽取 arguments() 空表", empty.arguments(), {})
    test.eq("空抽取 arguments(name) 空表", empty.arguments("calendar.propose_create"), {})
    test.eq("空抽取默认 degraded", empty.degraded, True)
    test.eq("空抽取默认 engine", empty.engine, needle3_runtime.ENGINE_FALLBACK)
    test.eq("空抽取默认 error", empty.error, "")
    call = needle3_runtime.ToolCall("calendar.propose_cancel", {"reference": "x"})
    test.eq("ToolCall 默认置信度", call.confidence, 0.0)
    test.eq("ToolCall 默认引擎", call.engine, needle3_runtime.ENGINE_NEEDLE)
    wrapped = needle3_runtime.Extraction("cancel", [call])
    test.eq("包装后 tool", wrapped.tool, "calendar.propose_cancel")
    test.eq("包装后 arguments(name)", wrapped.arguments("calendar.propose_cancel"), {"reference": "x"})
    test.eq("包装后 as_dict 调用数", len(wrapped.as_dict()["calls"]), 1)
    test.eq("包装后 primary 是同一个对象", wrapped.primary is call, True)
    test.eq("_matched_tools 返回工具名",
            all(name in needle3_runtime.TOOL_NAMES for name, _ in
                needle3_runtime._matched_tools(needle3_runtime._norm("明天有空吗"))), True)
    test.eq("无意图句 _matched_tools 为空", needle3_runtime._matched_tools("zzz qqq"), [])
    ok(test, "needle3 输出形状")


# --------------------------------------------------------------- 2. preferences


def _bot_dir(bot_id: str) -> str:
    from .config import bot_dir_name

    return bot_dir_name(bot_id)


def _pref_roundtrip(test: SelfTest, h: Harness) -> None:
    """存储往返：首用落盘、原子保存、文件权限、损坏恢复、schema 门禁。"""
    store, bot = _pref_bot(h, "存储")
    path = store.path_for(bot)
    test.contains("偏好落在 agent 目录", str(path), f"bots/{_bot_dir(bot)}/agent/")
    test.contains("偏好文件名", path.name, agent_preferences.PREFERENCES_FILENAME)
    test.eq("落盘前文件不存在", path.exists(), False)
    loaded = store.load(bot)
    test.eq("首用即落盘", path.exists(), True)
    test.eq("首用时间戳=注入时钟", loaded["updated_at"], 1_700_000_000.0)
    test.eq("落盘是合法 JSON 对象", isinstance(json.loads(path.read_text(encoding="utf-8")), dict), True)
    test.eq("version=SCHEMA_VERSION", loaded["version"], agent_preferences.SCHEMA_VERSION)
    test.eq("SCHEMA_VERSION 是 1", agent_preferences.SCHEMA_VERSION, 1)
    test.check("默认时区可用", needle3_runtime.is_valid_timezone(loaded["timezone"]),
               str(loaded["timezone"]))
    test.eq("首用不带恢复痕迹", loaded["recovered_from"], "")
    test.eq("第二次读不再改写", store.load(bot)["updated_at"], 1_700_000_000.0)
    test.eq("文件权限 0600", _mode(path), 0o600)
    test.eq("目录权限不含组/其它位", _mode(path.parent) & 0o077, 0)
    test.eq("reset 与默认同构", sorted(store.reset(bot)), sorted(loaded))
    test.eq("reset 后仍是默认值", store.reset(bot)["timezone"], loaded["timezone"])

    saved = store.save(bot, {"timezone": "Europe/Berlin", "buffers": {"before_minutes": 30}})
    test.eq("保存写入新值", saved["timezone"], "Europe/Berlin")
    test.eq("深合并保留兄弟键", saved["buffers"]["after_minutes"], loaded["buffers"]["after_minutes"])
    test.eq("保存刷新时间戳", saved["updated_at"], 1_700_000_000.0)
    test.eq("保存清空恢复痕迹", saved["recovered_from"], "")
    test.eq("重读拿到改动", store.load(bot)["buffers"]["before_minutes"], 30)
    test.eq("重读时区一致", store.load(bot)["timezone"], "Europe/Berlin")
    test.eq("无补丁保存也落盘", store.save(bot)["timezone"], "Europe/Berlin")
    test.eq("落盘不留 .tmp", list(path.parent.glob("*.tmp")), [])

    for bad_id in ("../../escape", "", "a" * 200, "bad/name"):
        got = str(store.path_for(bad_id))
        test.check(f"异常 bot_id 不逃出数据根目录（{bad_id[:12]!r}）",
                   str(Path(got).resolve()).startswith(str(Path(store.settings.data_dir).resolve())), got)
    test.eq("bot_id 为空时落到 default 目录", Path(store.path_for("")).parent.parent.name, "default")

    for label, payload, want_tz, want_recovered in [
        ("时区写成数字", dict(loaded, timezone=42), loaded["timezone"], True),
        ("顶层是数组", [1, 2], loaded["timezone"], True),
        # 未知顶层键只丢那一个键，文件里其余字段仍然可用；写坏的文件本身仍是上一次保存的
        # Asia/Shanghai（改动发生在更前面的 save，没有回写这个 loaded 快照）。
        ("未知顶层键", dict(loaded, unknown_top={"x": 1}), loaded["timezone"], False),
        ("版本号写成字符串", dict(loaded, version="99"), loaded["timezone"], True),
    ]:
        _write_json(path, payload)
        out = store.load(bot)
        test.eq(f"坏文件仍出默认结构（{label}）", sorted(out), sorted(loaded))
        test.eq(f"坏文件时区（{label}）", out["timezone"], want_tz)
        test.eq(f"坏文件恢复标记（{label}）", bool(out["recovered_from"]), want_recovered)
    _write_json(path, "{oops")
    out = store.load(bot)
    test.contains("JSON 语法坏时写明原因", out["recovered_from"], "JSONDecodeError")
    test.check("坏文件留了 .corrupt 备份", path.with_suffix(".corrupt").exists(), str(path.parent))
    test.eq("恢复后文件重新可读", isinstance(json.loads(path.read_text(encoding="utf-8")), dict), True)
    store.reset(bot)
    test.eq("恢复计数按 Bot 记录", store.recoveries.get(bot, None) is not None, True)
    ok(test, "agent_preferences 存储往返")


def _pref_validate(test: SelfTest, h: Harness) -> None:
    """校验器：逐字段接受/拒绝，越界不静默夹取。"""
    store, _bot = _pref_bot(h, "校验")

    def patch(label: str, doc: Mapping[str, Any], dotted: str, want: Any) -> None:
        try:
            out = store.validate(doc)
        except agent_preferences.PreferenceError as exc:
            fail(test, f"补丁被拒绝（{label}）", str(exc)[:120])
            return
        test.eq(f"补丁 {label}", _dig(out, dotted), want)

    def rejected(label: str, doc: Any, hint: str = "") -> None:
        try:
            store.validate(doc)
        except agent_preferences.PreferenceError as exc:
            test.check(f"拒绝补丁（{label}）", True, str(exc)[:90])
            if hint:
                test.contains(f"拒绝理由可读（{label}）", str(exc), hint)
            return
        fail(test, f"应当拒绝（{label}）", repr(doc)[:120])

    patch("时区", {"timezone": "Europe/Berlin"}, "timezone", "Europe/Berlin")
    patch("时区去空白", {"timezone": "  Asia/Shanghai "}, "timezone", "Asia/Shanghai")
    patch("locale 空串=跟随界面", {"locale": ""}, "locale", "")
    # 语种只能落到界面实际存在的词条表上：i18n.LOCALES 里没有 en-US，就收敛成 en。
    patch("locale 归一", {"locale": "EN_us"}, "locale", "en")
    patch("工作日排序去重", {"working_hours": {"days": [3, 3, 1]}}, "working_hours.days", [1, 3])
    patch("时刻补零", {"working_hours": {"days": [1], "start": "9:05", "end": "17:00"}},
          "working_hours.start", "09:05")
    patch("缓冲上限", {"buffers": {"before_minutes": 0, "after_minutes": 240}},
          "buffers.after_minutes", 240)
    patch("屏蔽时段", {"blocked_periods": [{"id": "gym", "name": "健身", "days": [2, 4],
                                   "start": "19:00", "end": "20:00"}]},
          "blocked_periods.0.id", "gym")
    patch("屏蔽时段自动生成 id", {"blocked_periods": [{"days": [1], "start": "08:00", "end": "09:00"}]},
          "blocked_periods.0.id", "blocked1")
    patch("boost 权重", {"keywords": {"boost": [{"term": "roadmap", "weight": 4}]}},
          "keywords.boost.0.weight", 4)
    patch("block 词去重保序", {"keywords": {"block": ["线下", "线下", "投资"]}},
          "keywords.block", ["线下", "投资"])
    patch("匹配字段", {"keywords": {"match_fields": ["title", "text"]}},
          "keywords.match_fields", ["title", "text"])
    patch("深合并只给子键", {"meeting": {"max_per_day": 9}}, "meeting.max_per_day", 9)
    test.eq("补丁不含的键保持原样", "min_gap_minutes" in store.validate({"meeting": {"max_per_day": 9}})
            ["meeting"], False)
    test.eq("空补丁返回空表", store.validate({}), {})

    rejected("布尔写成 0", {"working_hours": {"days": [1], "start": "09:00", "end": "18:00",
                                        "respect_working_hours": 0}}, hint="必须是布尔值")
    rejected("未知顶层键", {"nope": 1})
    rejected("未知嵌套键", {"working_hours": {"color": "red"}})
    rejected("时区不存在", {"timezone": "Mars/Olympus"})
    rejected("时区是路径穿越", {"timezone": "../../etc/passwd"}, hint="时区")
    rejected("时区是数字", {"timezone": 8})
    rejected("locale 过长", {"locale": "x" * 40})
    rejected("locale 是数字", {"locale": 7})
    rejected("时刻越界", {"working_hours": {"days": [1], "start": "24:00", "end": "18:00"}})
    rejected("时刻缺分", {"working_hours": {"days": [1], "start": "9", "end": "18:00"}})
    rejected("工作时段倒置", {"working_hours": {"days": [1], "start": "19:00", "end": "09:00"}})
    rejected("工作日 0", {"working_hours": {"days": [0], "start": "09:00", "end": "18:00"}}, hint="1–7")
    rejected("工作日 8", {"working_hours": {"days": [8], "start": "09:00", "end": "18:00"}})
    rejected("工作日写成字符串", {"working_hours": {"days": "Mon", "start": "09:00", "end": "18:00"}})
    rejected("布尔当分钟数", {"buffers": {"before_minutes": True}}, hint="整数")
    rejected("负缓冲", {"buffers": {"before_minutes": -1}}, hint="1")
    rejected("缓冲超上限", {"buffers": {"before_minutes": 9999}}, hint="超过上限")
    rejected("缓冲是字符串", {"buffers": {"before_minutes": "15"}})
    rejected("小节不是对象", {"buffers": 7}, hint="对象")
    rejected("屏蔽时段不是数组", {"blocked_periods": {"id": "x"}})
    rejected("屏蔽时段倒置", {"blocked_periods": [{"id": "x", "days": [1], "start": "20:00",
                                          "end": "19:00"}]})
    rejected("屏蔽时段 id 重复", {"blocked_periods": [
        {"id": "dup", "days": [1], "start": "08:00", "end": "09:00"},
        {"id": "dup", "days": [2], "start": "08:00", "end": "09:00"}]})
    rejected("屏蔽时段 id 过长", {"blocked_periods": [{"id": "x" * 25, "days": [1], "start": "08:00",
                                             "end": "09:00"}]})
    rejected("屏蔽时段日期非法", {"blocked_periods": [{"id": "x", "days": [1], "start": "08:00",
                                             "end": "09:00", "date_from": "2026-13-45"}]})
    rejected("屏蔽元素不是对象", {"blocked_periods": ["lunch"]})
    rejected("boost 大小写重复", {"keywords": {"boost": [{"term": "A", "weight": 1},
                                                {"term": "a", "weight": 2}]}})
    rejected("boost 词是对象", {"keywords": {"boost": [{"term": {"n": 1}, "weight": 1}]}})
    rejected("boost 词过多", {"keywords": {"boost": [{"term": f"t{i}", "weight": 1}
                                            for i in range(200)]}}, hint="40")
    rejected("boost 权重越界", {"keywords": {"boost": [{"term": "x", "weight": 99}]}})
    rejected("block 词过长", {"keywords": {"block": ["词" * 41]}})
    patch("block 词正好 40 字", {"keywords": {"block": ["词" * 40]}}, "keywords.block", ["词" * 40])
    rejected("match_fields 未知值", {"keywords": {"match_fields": ["gossip"]}})
    rejected("会话时长为 0", {"meeting": {"default_duration_minutes": 0}})
    rejected("会话时长过大", {"meeting": {"max_meeting_minutes": 5000}})
    rejected("auto_confirm 非布尔", {"negotiation": {"auto_confirm": "yes"}})
    rejected("要求免审批", {"negotiation": {"require_owner_approval": False}}, hint="必须为 true")
    rejected("顶层是数组", ["prefs"])
    rejected("顶层是数字", 3)
    for junk in (None, 7, [], True, "str"):
        try:
            store.validate_full(junk)
            fail(test, f"validate_full 应拒绝 {type(junk).__name__}", repr(junk))
        except agent_preferences.PreferenceError:
            test.check(f"validate_full 拒绝 {type(junk).__name__}", True)
    full = store.validate_full(agent_preferences.defaults())
    test.eq("validate_full 认得整份文档", sorted(full), sorted(agent_preferences.DEFAULT_PREFERENCES))
    test.eq("MAX_BUFFER_MINUTES", agent_preferences.MAX_BUFFER_MINUTES, 240)
    test.eq("MAX_KEYWORD_WEIGHT", agent_preferences.MAX_KEYWORD_WEIGHT, 5)
    test.eq("MIN_KEYWORD_WEIGHT", agent_preferences.MIN_KEYWORD_WEIGHT, 1)
    test.eq("MAX_SLOT_MINUTES 是一天", agent_preferences.MAX_SLOT_MINUTES, 24 * 60)
    ok(test, "agent_preferences 校验器")


def _pref_days(test: SelfTest, h: Harness) -> None:
    """星期与日期窗：ISO 1=周一…7=周日，周日↔周一跨界要正确。"""
    store, bot = _pref_bot(h, "星期")
    prefs = store.save(bot, {"timezone": "Asia/Shanghai",
                             "working_hours": {"days": [7, 1, 2, 3, 4, 5], "start": "09:00",
                                               "end": "18:00"},
                             "buffers": {"before_minutes": 0, "after_minutes": 0, "protect_lunch": False},
                             "blocked_periods": [{"id": "sun", "name": "周日家庭时间", "days": [7],
                                                  "start": "15:00", "end": "16:00"}]})
    # 2026-11-28 周六 / 11-29 周日 / 11-30 周一
    test.eq("周日命中屏蔽时段", [r["id"] for r in store.blocked_windows(prefs, "2026-11-29")], ["sun"])
    test.eq("周一不被周日时段屏蔽", store.blocked_windows(prefs, "2026-11-30"), [])
    test.eq("周日是工作日（表里含 7）", store.working_window(prefs, "2026-11-29") is not None, True)
    test.eq("周一是工作日", store.working_window(prefs, "2026-11-30") is not None, True)
    test.eq("周六不是工作日", store.working_window(prefs, "2026-11-28"), None)
    test.eq("ISO 周表 1..7", agent_preferences.ISO_WEEKDAYS, (1, 2, 3, 4, 5, 6, 7))
    test.eq("周名映射 7=周日", agent_preferences.WEEKDAY_NAMES[7], "周日")
    test.eq("周名映射 1=周一", agent_preferences.WEEKDAY_NAMES[1], "周一")
    # 同一面墙钟：周日命中屏蔽、周一放行——跨界判定不能按 UTC 星期。
    # _NOW 是周四 11-26，所以 周六=+2、周日=+3、周一=+4（跨周边界那一侧）。
    sunday = store.apply(prefs, [_slot(3, 15, 10)], now=_EPOCH, include_rejected=True)[0]
    monday = store.apply(prefs, [_slot(4, 15, 10)], now=_EPOCH, include_rejected=True)[0]
    saturday = store.apply(prefs, [_slot(2, 15, 10)], now=_EPOCH, include_rejected=True)[0]
    test.eq("周日撞屏蔽被拒", sunday.get("kept"), None)
    test.contains("周日拒因带时段名", str(sunday.get("rejected")), "周日家庭时间")
    test.eq("周一同时刻放行", monday.get("kept"), True)
    test.eq("周一 weekday=1", monday.get("weekday"), 1)
    test.eq("周六非工作日被拒", saturday.get("kept"), None)
    test.contains("周六拒因带星期名", str(saturday.get("rejected")), "周六")
    test.eq("周日 weekday=7", store.apply(prefs, [_slot(3, 10, 0)], now=_EPOCH,
                                      include_rejected=True)[0].get("weekday"), 7)
    # 日期窗：date_from/date_to 是闭区间，窗外即使星期匹配也不屏蔽。
    dated = store.save(bot, {"blocked_periods": [{"id": "window", "days": [1, 2, 3, 4, 5, 6, 7],
                                                  "start": "10:00", "end": "11:00",
                                                  "date_from": "2026-12-01", "date_to": "2026-12-05"}],
                             "working_hours": {"days": [1, 2, 3, 4, 5, 6, 7]},
                             "buffers": {"before_minutes": 0, "after_minutes": 0}})
    for day, want in [("2026-11-30", []), ("2026-12-01", ["window"]),
                      ("2026-12-05", ["window"]), ("2026-12-06", [])]:
        test.eq(f"日期窗 {day}", [r["id"] for r in store.blocked_windows(dated, day)], want)
    window = store.blocked_windows(dated, "2026-12-01")[0]
    test.eq("窗口行字段", sorted(window),
            sorted(["id", "name", "date", "start", "end", "start_text", "end_text", "timezone", "days"])
            if "days" in window else sorted(window))
    test.eq("窗口按本地时区换算", window["start"],
            datetime(2026, 12, 1, 10, 0, tzinfo=ZoneInfo("Asia/Shanghai")).timestamp())
    test.eq("窗口终点 11:00", window["end_text"], "11:00")
    all_day = store.save(bot, {"blocked_periods": [{"id": "off", "days": [3], "start": "00:00",
                                                    "end": "24:00"}],
                                "working_hours": {"days": [1, 2, 3, 4, 5, 6, 7], "start": "00:00",
                                                  "end": "24:00"}})
    test.eq("全天屏蔽窗长 86400",
            round(store.blocked_windows(all_day, "2026-12-02")[0]["end"]
                  - store.blocked_windows(all_day, "2026-12-02")[0]["start"]), _DAY)
    test.eq("全天窗内被拒", store.apply(all_day, [_slot(6, 15, 0)], now=_EPOCH,
                                    include_rejected=True)[0].get("kept"), None)
    try:
        store.blocked_windows(all_day, "2026-13-45")
        fail(test, "坏 day 参数应被拒绝", "")
    except agent_preferences.PreferenceError:
        test.check("坏 day 参数被拒绝", True)
    ok(test, "agent_preferences 星期与日期窗")


def _pref_buffers(test: SelfTest, h: Harness) -> None:
    """缓冲算术与池语义：比较永远发生在候选自己的墙钟上，脏元素不毁掉整轮。"""
    store, bot = _pref_bot(h, "缓冲")
    prefs = store.save(bot, {"timezone": "Asia/Shanghai",
                             "working_hours": {"days": [1, 2, 3, 4, 5], "start": "09:00", "end": "18:00"},
                             "buffers": {"before_minutes": 15, "after_minutes": 15, "protect_lunch": False},
                             "blocked_periods": [], "meeting": {"max_meeting_minutes": 120}})

    def one(p: Mapping[str, Any], slot: Mapping[str, Any]) -> Dict[str, Any]:
        return store.apply(p, [slot], now=_EPOCH, include_rejected=True)[0]

    row = one(prefs, _slot(1, 15, 0))
    test.eq("缓冲内放行", row.get("kept"), True)
    test.eq("缓冲合计", row.get("buffer_minutes"), 30)
    test.eq("缓冲标记", row.get("buffered"), True)
    test.eq("加缓冲后的起点", row.get("start_text"), "15:00")
    test.eq("时长如实回报", row.get("duration_minutes"), 30)
    edge = one(prefs, _slot(1, 9, 0))
    test.eq("开场缓冲撞下界被拒", edge.get("kept"), None)
    test.contains("拒因是超出工作时间", str(edge.get("rejected")), "超出工作时间")
    test.contains("拒因带时间窗", str(edge.get("rejected")), "09:00-18:00")
    test.contains("拒因带需求区间", str(edge.get("rejected")), "需 09:00-09:30")
    test.contains("拒因带缓冲分钟", str(edge.get("rejected")), "±15/15")
    tail = one(prefs, _slot(1, 17, 50))
    test.eq("收工缓冲撞上界被拒", tail.get("kept"), None)
    test.contains("上界拒因带终点", str(tail.get("rejected")), "17:50")

    # 跨午夜：23:20 起 30 分钟 + 30 分钟后缓冲 → 落到次日，直接拒。
    midnight = store.save(bot, {"working_hours": {"days": [1, 2, 3, 4, 5, 6, 7], "start": "09:00",
                                                  "end": "23:30"},
                                "buffers": {"before_minutes": 0, "after_minutes": 30}})
    row = one(midnight, _slot(2, 23, 0))
    test.eq("含缓冲跨午夜被拒", row.get("kept"), None)
    test.check("跨午夜拒因可读", "跨天" in str(row.get("rejected")) or "超出工作时间" in str(row.get("rejected")),
               str(row.get("rejected"))[:80])
    tight = store.save(bot, {"buffers": {"before_minutes": 0, "after_minutes": 10}})
    # 23:00–23:20 + 10 分钟后缓冲，正好贴在 23:30 收工线上：边界必须是「超过」才拒。
    row = one(tight, _slot(2, 23, 0, minutes=20))
    test.eq("刚好压线放行", row.get("kept"), True)
    test.eq("压线终点", row.get("end_text"), "23:20")

    # 上限 240 分钟：四个方向各 240 是可保存的极值，241 直接拒绝。
    capped = store.save(bot, {"working_hours": {"days": [1, 2, 3, 4, 5, 6, 7], "start": "00:00",
                                                "end": "24:00"},
                              "buffers": {"before_minutes": 240, "after_minutes": 0},
                              "blocked_periods": []})
    test.eq("MAX_BUFFER_MINUTES 可原样保存", capped["buffers"]["before_minutes"],
            agent_preferences.MAX_BUFFER_MINUTES)
    test.eq("4 小时前置缓冲算得到位", one(capped, _slot(1, 12, 0))["start_text"], "12:00")
    try:
        store.save(bot, {"buffers": {"before_minutes": agent_preferences.MAX_BUFFER_MINUTES + 1}})
        fail(test, "超上限缓冲应被拒绝", "")
    except agent_preferences.PreferenceError:
        test.check("超上限缓冲被拒绝", True)

    # 午休保护与固定屏蔽时段：命中带 id/名字与区间。
    lunch = store.save(bot, {"working_hours": {"days": [1, 2, 3, 4, 5], "start": "09:00", "end": "18:00"},
                             "buffers": {"before_minutes": 15, "after_minutes": 15, "protect_lunch": True},
                             "blocked_periods": [{"id": "lunch", "name": "午休", "days": [1, 2, 3, 4, 5],
                                                   "start": "12:30", "end": "13:30"}]})
    row = one(lunch, _slot(1, 13, 0))
    test.eq("午休内被拒", row.get("kept"), None)
    test.contains("午休拒因带时段名", str(row.get("rejected")), "午休")
    row = one(lunch, _slot(1, 14, 0))
    # 缓冲只用于工作时段边界判定，屏蔽时段按候选本身那一截算：14:00 起、13:45 的缓冲
    # 已经出了午休，就该放行。把缓冲算进屏蔽判定会让 15 分钟的休息贴边拒掉一整下午。
    test.eq("缓冲不侵占午休判定", row.get("kept"), True)
    row = one(lunch, _slot(1, 13, 20))
    test.eq("午休尾巴压住候选起点被拒", row.get("kept"), None)
    row = one(lunch, _slot(1, 14, 31))
    test.eq("午休与缓冲都避开则放行", row.get("kept"), True)
    unnamed = store.save(bot, {"blocked_periods": [{"id": "noname", "days": [1, 2, 3, 4, 5],
                                                    "start": "16:00", "end": "17:00"}]})
    row = one(unnamed, _slot(1, 16, 30))
    test.contains("无名字的时段用 id 兜底", str(row.get("rejected")), "noname")

    # 时刻已过去 / 结束早于开始 / 非对象元素：都只拒那一条，不炸整轮。
    past = store.apply(prefs, [{"start": _EPOCH - 7200, "end": _EPOCH - 3600, "tz": "UTC"}],
                       now=_EPOCH, include_rejected=True)[0]
    test.contains("已过去的时段被拒", str(past.get("rejected")), "已过去")
    reversed_slot = store.apply(prefs, [{"start": _EPOCH + 7200, "end": _EPOCH + 3600, "tz": "UTC"}],
                                now=_EPOCH, include_rejected=True)[0]
    test.contains("结束早于开始被拒", str(reversed_slot.get("rejected")), "不晚于开始")
    missing_ts = store.apply(prefs, [{"title": "没有时间戳"}], now=_EPOCH, include_rejected=True)[0]
    test.contains("缺时间戳被拒", str(missing_ts.get("rejected")), "缺少 start/end")
    dirty = store.apply(prefs, [_slot(1, 15, 0), "不是对象", 7, None], now=_EPOCH,
                        include_rejected=True)
    test.eq("脏池仍返回全部行", len(dirty), 4)
    test.eq("脏池中干净那条照样放行", dirty[0].get("kept"), True)
    test.eq("默认不返回被拒项", len(store.apply(prefs, [_slot(1, 9, 0), _slot(1, 15, 0)], now=_EPOCH)), 1)
    test.eq("空池返回空表", store.apply(prefs, [], now=_EPOCH), [])
    test.eq("池为 None 也返回空表", store.apply(prefs, (), now=_EPOCH), [])

    # 不修改调用方的池：上层还要拿原始候选去排卡片。
    pool = [_slot(1, 15, 0), _slot(1, 9, 0)]
    snapshot = json.dumps(pool, sort_keys=True)
    rows = store.apply(prefs, pool, now=_EPOCH, include_rejected=True)
    test.eq("apply 不改写输入池", json.dumps(pool, sort_keys=True), snapshot)
    test.eq("apply 返回新对象", rows is pool, False)
    test.eq("放行项排在前面", [r.get("kept") for r in rows], [True, None])
    # 超过单场上限的候选被裁到上限并留痕，而不是丢掉。起点留足 15 分钟前缓冲，
    # 证明裁剪发生在工时判定之前（裁到 120 分钟后 09:45–12:15 仍在窗内）。
    over = one(prefs, _slot(1, 10, 0, minutes=180))
    test.eq("超长会话裁到上限", over.get("capped_minutes"), 120)
    test.eq("裁剪后时长", over.get("duration_minutes"), 120)
    test.eq("裁剪后仍放行", over.get("kept"), True)
    # 时区来自槽位标签：同一瞬时在柏林视角是早上，在上海视角是下午。
    berlin = store.save(bot, {"timezone": "Europe/Berlin",
                              "working_hours": {"days": [1, 2, 3, 4, 5], "start": "09:00", "end": "18:00"},
                              "buffers": {"before_minutes": 0, "after_minutes": 0}})
    row = one(berlin, _slot(1, 9, 30, tz="Europe/Berlin"))
    test.eq("柏林墙钟 09:30 放行", row.get("kept"), True)
    test.eq("柏林槽位标注时区", row.get("tz"), "Europe/Berlin")
    test.eq("柏林墙钟起点", row.get("start_text"), "09:30")
    same_utc = {"start": row["start"], "end": row["end"], "tz": "UTC"}
    row = store.apply(berlin, [same_utc], now=_EPOCH, include_rejected=True)[0]
    # 被拒的行不回写 start_text，判定用的墙钟在拒因里：08:30 说明按 UTC 而不是柏林钟算。
    test.contains("同一瞬时改标 UTC 后按 UTC 判定", str(row.get("rejected")), "需 08:30-09:00")
    test.eq("改标后落到工作时段外", row.get("kept"), None)
    bad_zone = store.apply(berlin, [{"start": row["start"], "end": row["start"] + 1800,
                                     "tz": "Mars/Olympus"}], now=_EPOCH, include_rejected=True)[0]
    test.eq("槽位时区写坏时回落偏好时区", bad_zone.get("tz"), "Europe/Berlin")
    ok(test, "agent_preferences 缓冲与池")


def _pref_keywords(test: SelfTest, h: Harness) -> None:
    """关键词优先级过滤、每日配额、rank 稳定排序与 summary。"""
    store, bot = _pref_bot(h, "关键词")
    prefs = store.save(bot, {"keywords": {"boost": [{"term": "roadmap", "weight": 4},
                                                   {"term": "合同", "weight": 5}],
                                          "block": ["线下", "投资"],
                                          "match_fields": ["title", "summary"]}})
    rows = store.rank(prefs, [_slot(1, 14, 0, title="聊聊 roadmap"),
                              _slot(1, 10, 0, title="普通周会"),
                              _slot(1, 16, 0, title="合同 续约")])
    test.eq("rank 丢掉被屏蔽的词", len(rows), 3)
    test.eq("rank 按权重降序", [r["title"] for r in rows][0], "合同 续约")
    test.eq("rank 第二是 roadmap", [r["title"] for r in rows][1], "聊聊 roadmap")
    test.eq("rank 权重求和", rows[0]["score"], 5)
    test.eq("命中词写进 matched_keywords", rows[0]["matched_keywords"], ["合同"])
    test.eq("未命中权重 0", rows[-1]["score"], 0)
    test.eq("rank 不残留排序辅助键", "_order" in rows[0], False)
    test.eq("黑名单一票否决", store.rank(prefs, [_slot(1, 14, 0, title="线下见面")]), [])
    test.eq("黑名单大小写不敏感", store.rank(prefs, [_slot(1, 14, 0, title="INVESTMENT 投资")]), [])
    test.eq("字段范围生效", store.rank({"keywords": {"boost": [{"term": "abc", "weight": 2}],
                                                     "block": [], "match_fields": ["title"]},
                                        }, [_slot(1, 9, 0, title="zzz", summary="abc")])[0]["score"], 0)
    test.eq("未声明字段仍能兜底整份 JSON",
            store.rank({"keywords": {"boost": [{"term": "abc", "weight": 2}], "block": [],
                                     "match_fields": []}},
                       [_slot(1, 9, 0, note="含 abc 的备注")])[0]["score"], 2)
    test.eq("rank 不改输入", "score" in _slot(1, 9, 0), False)
    test.eq("无关键词配置时权重 0", store.rank({}, [_slot(1, 9, 0)])[0]["score"], 0)

    quota = store.save(bot, {"meeting": {"max_per_day": 2},
                             "working_hours": {"days": [1, 2, 3, 4, 5, 6, 7], "start": "00:00",
                                               "end": "24:00"},
                             "buffers": {"before_minutes": 0, "after_minutes": 0},
                             "blocked_periods": []})
    rows = store.daily_quota(quota, [_slot(1, 9, 0), _slot(1, 11, 0), _slot(1, 14, 0), _slot(2, 9, 0)])
    test.eq("配额编号按日内顺序", [r.get("rank_of_day") for r in rows], [1, 2, 1])
    test.eq("超配额被丢弃", len(rows), 3)
    test.eq("未配配额时全量返回", len(store.daily_quota({}, [_slot(1, 9, 0)] * 9)), 9)
    test.eq("配额不改动槽位内容", store.daily_quota(quota, [_slot(1, 9, 0)])[0]["start"],
            _slot(1, 9, 0)["start"])

    summary = store.summary(bot)
    test.eq("summary 带 bot_id", summary["bot_id"], bot)
    test.eq("summary 带落盘路径", summary["path"], str(store.path_for(bot)))
    test.eq("summary 工作日", summary["working_days"], quota["working_hours"]["days"])
    test.eq("summary 工作时段文本", summary["working_hours"], "00:00-24:00")
    test.eq("summary 屏蔽时段计数", summary["blocked_periods"], 0)
    test.eq("summary boost 计数", summary["boost_terms"], 2)
    test.eq("summary block 计数", summary["block_terms"], 2)
    test.eq("summary 不含关键词原文", "roadmap" in json.dumps(summary, ensure_ascii=False), False)
    test.eq("summary 权限位可读", str(summary["mode"]).startswith("0o"), True)
    test.eq("summary 时间戳", summary["updated_at"], 1_700_000_000.0)
    ok(test, "agent_preferences 关键词与配额")


# ------------------------------------------------------------------- 3. reasoner


class _FakeTransport:
    """假传输层：与 selftest_node.py 的 FakeNode 同一套纪律——记录每一次调用，绝不建 socket。"""

    def __init__(self, script: Optional[Sequence[Any]] = None) -> None:
        self.script = list(script or [(200, {"response": "来自大模型的润色。"})])
        self.calls: List[Dict[str, Any]] = []

    async def __call__(self, method: str, url: str, headers: Dict[str, str],
                       body: Dict[str, Any], timeout: float) -> Tuple[int, Any]:
        self.calls.append({"method": method, "url": url, "headers": dict(headers),
                           "body": json.loads(json.dumps(body, default=str)), "timeout": timeout})
        item = self.script[0] if len(self.script) > 1 else (self.script[0] if self.script else (200, {}))
        if len(self.script) > 1:
            self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item  # type: ignore[return-value]

    @property
    def count(self) -> int:
        return len(self.calls)

    def last(self) -> Dict[str, Any]:
        return self.calls[-1]


_TRUTHY = {"1", "true", "yes", "on"}


def _reasoner_settings(h: Harness, **overrides: Any) -> Any:
    """基于 Harness 的真实 Settings，覆盖 reasoner 字段（键名可用 env 风格）。

    明文远端 ``REASONER_BASE_URL`` 不走 env：``load_settings`` 在配置层就抛 ConfigError，
    而这一组要测的正是「配置已经写坏了怎么办」。配置层的拒绝另外单独断言。
    """
    settings = h.settings()
    cast = {"enabled": lambda v: str(v).strip().lower() in _TRUTHY if isinstance(v, str) else bool(v),
            "base_url": str, "api_key": str, "model": str, "timeout_seconds": float}
    for raw_key, value in overrides.items():
        name = raw_key.lower()
        if name.startswith("reasoner_"):
            name = name[len("reasoner_"):]
        if name not in cast:
            raise KeyError(f"未知的 reasoner 字段：{raw_key}")
        setattr(settings, f"reasoner_{name}", cast[name](value))
    return settings


def _reasoner_disabled(test: SelfTest, h: Harness) -> None:
    """开关关掉 / 地址非法时：一次传输都不能发生，文案回模板，且不抛异常。"""
    bridge_settings = _reasoner_settings(h, REASONER_ENABLED="0",
                                         REASONER_BASE_URL="http://127.0.0.1:11434",
                                         REASONER_API_KEY="sk-should-never-be-used")
    transport = _FakeTransport([(200, {"response": "不该被调用"})])
    bridge = reasoner_bridge.ReasonerBridge(settings=bridge_settings, transport=transport)
    test.eq("未启用时 enabled()=False", bridge.enabled(), False)
    text = h.async_run(bridge.compose, "availability_answer", {"sender": "Ann"})
    out = h.async_run(bridge.outcome, "availability_answer", {"sender": "Ann"})
    test.eq("未启用时文本非空", bool(text.strip()), True)
    test.eq("未启用时走模板", out.source, "template")
    test.contains("未启用写明原因", out.reason, "REASONER_ENABLED")
    test.eq("未启用完全不碰传输层", transport.count, 0)
    # compose 只是 outcome 的薄封装，两次调用就是两次计数（否则封装层会悄悄吞掉审计）。
    test.eq("未启用计一次调用", bridge.counts()["calls"], 2)
    test.eq("未启用计一次回退", bridge.counts()["template"], 2)
    test.eq("未启用零错误", bridge.counts()["errors"], 0)
    test.eq("未启用零端侧回复", bridge.counts()["reasoner"], 0)
    test.eq("status.enabled", bridge.status()["enabled"], False)
    test.eq("status.usable", bridge.status()["usable"], False)
    test.eq("health 不探测也返回字典", h.async_run(bridge.health)["ok"], False)
    test.eq("last_source", bridge.last_source, "template")
    test.check("last_reason 可读", bool(bridge.last_reason), bridge.last_reason)

    # 开关开了但地址非法：同样零次外呼，并把原因写清楚（用 Settings 直接构造，
    # 因为 load_settings 会在配置层就拒绝明文远端地址）。
    for label, base, hint in [
        ("空地址", "", "未配置"),
        ("明文 http 指向远端", "http://reasoner.evil.test:8000/v1", "回环"),
        ("协议非法", "ftp://127.0.0.1/v1", "协议非法"),
        ("缺主机名", "http:///v1", "主机名"),
        ("内嵌凭据", "https://user:pass@host.test/v1", "用户名"),
        ("端口非法", "http://127.0.0.1:abc", "端口"),
        ("纯垃圾", "not a url", "协议非法"),
    ]:
        settings = _reasoner_settings(h, REASONER_ENABLED="1")
        settings.reasoner_base_url = base
        silent = _FakeTransport()
        out = h.async_run(reasoner_bridge.ReasonerBridge(settings=settings,
                                                        transport=silent).outcome,
                          "guest_booked", {"host": "Ann"})
        test.eq(f"{label} 走模板", out.source, "template")
        test.contains(f"{label} 原因可读", out.reason, hint)
        test.eq(f"{label} 未发起外呼", silent.count, 0)
    settings = _reasoner_settings(h, REASONER_ENABLED="1")
    settings.reasoner_base_url = "http://reasoner.evil.test/v1"
    test.eq("远端明文判为不可用", reasoner_bridge.ReasonerBridge(settings=settings).enabled(), False)
    test.eq("配置层直接拒绝明文远端", _config_refuses(h, "http://evil.test:8000/v1"), True)
    test.eq("配置层放行回环明文", _config_refuses(h, "http://127.0.0.1:11434/v1"), False)
    test.eq("配置层放行 https 远端", _config_refuses(h, "https://api.example.com/v1"), False)
    ok(test, "reasoner 未启用零调用")


def _config_refuses(h: Harness, base_url: str) -> bool:
    from .config import ConfigError, load_settings

    try:
        load_settings(h.env(REASONER_BASE_URL=base_url))
    except ConfigError:
        return True
    return False


def _reasoner_endpoint(test: SelfTest, h: Harness) -> None:
    """endpoint_for：回环明文可用，路径归一到确定的两种方言。"""
    cases = {
        "http://127.0.0.1:11434/v1": ("http://127.0.0.1:11434/v1/chat/completions", "openai"),
        "http://localhost:11434": ("http://localhost:11434/api/generate", "ollama"),
        "http://127.0.0.1:11434": ("http://127.0.0.1:11434/api/generate", "ollama"),
        "http://127.0.0.1:11434/api": ("http://127.0.0.1:11434/api/generate", "ollama"),
        "http://127.0.0.1:11434/api/chat": ("http://127.0.0.1:11434/api/generate", "ollama"),
        "http://127.0.0.1:11434/api/generate": ("http://127.0.0.1:11434/api/generate", "ollama"),
        "https://api.openai.com/v1": ("https://api.openai.com/v1/chat/completions", "openai"),
        "https://host.test/v1/chat/completions": ("https://host.test/v1/chat/completions", "openai"),
        "https://host.test": ("https://host.test/v1/chat/completions", "openai"),
        "https://host.test/v1/": ("https://host.test/v1/chat/completions", "openai"),
        "  http://127.0.0.1:11434/v1  ": ("http://127.0.0.1:11434/v1/chat/completions", "openai"),
        "http://[::1]:11434": ("http://[::1]:11434/api/generate", "ollama"),
        "": ("", ""),
        "not a url": ("", ""),
        "ftp://127.0.0.1": ("", ""),
        "http:///v1": ("", ""),
        None: ("", ""),
    }
    for base, want in cases.items():
        test.eq(f"endpoint_for({base!r})", reasoner_bridge.endpoint_for(base), want)
    for url, safe, hint in [
        ("http://127.0.0.1:11434/v1", True, ""),
        ("http://localhost:11434/v1", True, ""),
        ("http://LOCALHOST:11434/v1", True, ""),
        ("http://[::1]:11434/v1", True, ""),
        ("https://reasoner.example.com/v1", True, ""),
        ("http://reasoner.example.com/v1", False, "回环"),
        ("http://10.0.0.5:11434/v1", False, "回环"),
        ("http://evil.example.com@127.0.0.1:11434/v1", False, "用户名"),
        ("http://127.0.0.1:99999", False, "端口"),
        ("file:///etc/passwd", False, "协议非法"),
    ]:
        got, reason = reasoner_bridge._scheme_is_safe(url)
        test.eq(f"明文/加密门禁 {url}", got, safe)
        if not safe:
            test.contains(f"门禁理由 {url}", reason, hint)
        else:
            test.eq(f"放行时无噪音 {url}", reason, "")
    test.eq("回环判定与 Mac Node 同源",
            [reasoner_bridge._scheme_is_safe(u)[0] for u in
             ("http://127.0.0.1:1", "http://example.com")], [True, False])
    ok(test, "reasoner 端点判定")


def _reasoner_happy(test: SelfTest, h: Harness) -> None:
    """接通时的行为：请求体、提示词、响应解析与计数。"""
    for label, base, reply, want in [
        ("ollama 方言", "http://127.0.0.1:11434", (200, {"response": "好的，周四下午三点。"}), "好的，周四下午三点。"),
        ("openai 方言", "http://127.0.0.1:18080/v1",
         (200, {"choices": [{"message": {"content": "Sure, Thursday 3pm."}}]}), "Sure, Thursday 3pm."),
        ("choices.text 兜底", "http://127.0.0.1:18080/v1", (200, {"choices": [{"text": "legacy text"}]}),
         "legacy text"),
        ("顶层 text 兜底", "http://127.0.0.1:18080/v1", (200, {"text": "top level"}), "top level"),
        ("ollama message 形状", "http://127.0.0.1:11434",
         (200, {"message": {"content": "nested ok"}}), "nested ok"),
        ("代码围栏剥离", "http://127.0.0.1:11434", (200, {"response": "```\n带围栏\n```"}), "带围栏"),
        ("首尾引号剥离", "http://127.0.0.1:11434", (200, {"response": "「带引号」"}), "带引号"),
        ("换行压扁", "http://127.0.0.1:11434", (200, {"response": "第一行\n第二行"}), "第一行 第二行"),
    ]:
        settings = _reasoner_settings(h, REASONER_ENABLED="1")
        settings.reasoner_base_url = base
        transport = _FakeTransport([reply])
        out = h.async_run(reasoner_bridge.ReasonerBridge(settings=settings,
                                                        transport=transport).outcome,
                          "availability_answer", {"sender": "Ann"}, locale="zh-Hans")
        test.eq(f"{label} 用端侧文案", out.text, want)
        test.eq(f"{label} source=reasoner", out.source, "reasoner")
        test.eq(f"{label} 无降级原因", out.reason, "")
        test.eq(f"{label} HTTP 状态入档", out.status, 200)
        test.eq(f"{label} 只调用一次", transport.count, 1)
        test.check(f"{label} 时延已记录", out.latency_ms >= 0.0, str(out.latency_ms))
    settings = _reasoner_settings(h, REASONER_ENABLED="1", REASONER_MODEL="glm-4.5-air")
    settings.reasoner_base_url = "http://127.0.0.1:11434/v1"
    transport = _FakeTransport([(200, {"choices": [{"message": {"content": "hi"}}]})])
    bridge = reasoner_bridge.ReasonerBridge(settings=settings, transport=transport)
    out = h.async_run(bridge.outcome, "availability_answer", {"sender": "Ann", "timezone": "UTC"},
                      locale="zh-Hans")
    sent = transport.last()
    test.eq("方法是 POST", sent["method"], "POST")
    test.eq("打到 chat/completions", sent["url"], "http://127.0.0.1:11434/v1/chat/completions")
    test.eq("带上 model", sent["body"]["model"], "glm-4.5-air")
    test.eq("带上 stream=False", sent["body"]["stream"], False)
    test.eq("角色顺序", [m["role"] for m in sent["body"]["messages"]], ["system", "user"])
    test.contains("系统提示词声明只写话术", sent["body"]["messages"][0]["content"], "不得新增")
    test.contains("系统提示词禁止声称已写日历", sent["body"]["messages"][0]["content"], "日历")
    test.contains("用户消息带话术种类", sent["body"]["messages"][1]["content"], "availability_answer")
    test.contains("用户消息带事实", sent["body"]["messages"][1]["content"], '"sender":"Ann"')
    test.contains("用户消息带 locale", sent["body"]["messages"][1]["content"], "zh-Hans")
    test.eq("不发送 tools 字段", "tools" in sent["body"], False)
    test.eq("不发送 tool_choice 字段", "tool_choice" in sent["body"], False)
    test.eq("超时取配置值", sent["timeout"], 20.0)
    test.eq("默认 20 秒超时", bridge.timeout_seconds, 20.0)
    test.eq("status.timeout_seconds", bridge.status()["timeout_seconds"], 20.0)
    test.eq("counts.reasoner", bridge.counts()["reasoner"], 1)
    test.eq("status.reasoner_replies", bridge.status()["reasoner_replies"], 1)
    test.eq("recent 留痕", len(bridge.recent), 1)
    test.eq("stats 不重复带 base_url", "base_url" in bridge.stats(), False)
    # 同 kind 同 facts 的提示词必须逐字节稳定（否则审计与复现都会漂）。
    stable_a, stable_b = _FakeTransport([(200, {"response": "a"})]), _FakeTransport([(200, {"response": "b"})])
    h.async_run(reasoner_bridge.ReasonerBridge(settings=settings, transport=stable_a)
                .outcome, "guest_booked", {"host": "Ann", "start": "10:00", "code": "AB12"})
    h.async_run(reasoner_bridge.ReasonerBridge(settings=settings, transport=stable_b)
                .outcome, "guest_booked", {"code": "AB12", "start": "10:00", "host": "Ann"})
    test.eq("事实键序不影响提示词", stable_a.last()["body"], stable_b.last()["body"])
    talker = reasoner_bridge.ReasonerBridge(
        settings=settings,
        transport=_FakeTransport([(200, {"choices": [{"message": {"content": "一句话"}}]})]),
    )
    test.eq("compose 只回文本", h.async_run(talker.compose, "guest_booked", {"host": "Ann"}), "一句话")
    test.eq("compose 之后计数记一次端侧", talker.counts()["reasoner"], 1)
    ok(test, "reasoner 正常链路")


def _reasoner_degrade(test: SelfTest, h: Harness) -> None:
    """每一种失败都退回模板文案：不抛、不空、只记原因。"""
    secret = "sk-popopx-secret-value-123456"
    cases = [
        ("超时异常", TimeoutError("推理超时"), "TimeoutError"),
        ("连接被拒", ConnectionRefusedError("拒绝连接"), "ConnectionRefusedError"),
        ("HTTP 500", (500, {"error": "上游炸了"}), "HTTP 500"),
        ("HTTP 401", (401, {"message": "Unauthorized"}), "HTTP 401"),
        ("HTTP 0", (0, {}), "HTTP 0"),
        ("响应非对象", (200, "纯字符串"), "不是 JSON 对象"),
        ("缺内容字段", (200, {"result": "没有话术"}), "没有可用的话术字段"),
        ("空白回复", (200, {"response": "   \n "}), "没有可用的话术字段"),
        ("引擎自带 error", (200, {"error": "模型未加载"}), "引擎报错"),
    ]
    for label, reply, hint in cases:
        settings = _reasoner_settings(h, REASONER_ENABLED="1", REASONER_API_KEY=secret)
        settings.reasoner_base_url = "http://127.0.0.1:11434"
        bridge = reasoner_bridge.ReasonerBridge(settings=settings, transport=_FakeTransport([reply]))
        out = h.async_run(bridge.outcome, "availability_answer", {"sender": "Ann", "timezone": "UTC"},
                          locale="en")
        test.eq(f"{label} 退回模板", out.source, "template")
        test.contains(f"{label} 文案仍是完整话术", out.text, "Ann")
        test.check(f"{label} 文案非空", bool(out.text.strip()), out.text[:60])
        test.contains(f"{label} 原因可读", out.reason, hint)
        test.eq(f"{label} 记一次回退", bridge.counts()["template"], 1)
        test.check(f"{label} 记一次错误", bridge.counts()["errors"] >= 1, str(bridge.counts()))
        test.eq(f"{label} 不编造 trace", out.kind, "availability_answer")
        test.check(f"{label} 原因里没有密钥", secret not in out.reason, out.reason[:120])
    # 未知话术种类：不猜、不自由发挥，明确报错并留空文案。
    settings = _reasoner_settings(h, REASONER_ENABLED="1")
    silent = _FakeTransport()
    out = h.async_run(reasoner_bridge.ReasonerBridge(settings=settings, transport=silent)
                      .outcome, "no_such_kind", {})
    test.eq("未知种类退回模板通道", out.source, "template")
    test.contains("未知种类写明原因", out.reason, "未知话术种类")
    test.eq("未知种类不发起外呼", silent.count, 0)
    test.eq("未知种类空文案", out.text, "")
    out = h.async_run(reasoner_bridge.ReasonerBridge(settings=settings).outcome, "", {})
    test.contains("空种类也被拒", out.reason, "缺少话术种类")
    # 长度上限：正文与事实各截一刀，且加截断标记。
    settings = _reasoner_settings(h, REASONER_ENABLED="1")
    settings.reasoner_base_url = "http://127.0.0.1:11434"
    long_transport = _FakeTransport([(200, {"response": "长" * (reasoner_bridge.MAX_REPLY_CHARS * 3)})])
    out = h.async_run(reasoner_bridge.ReasonerBridge(settings=settings, transport=long_transport)
                      .outcome, "meeting_summary", {}, locale="en")
    test.eq("正文截到 MAX_REPLY_CHARS", len(out.text), reasoner_bridge.MAX_REPLY_CHARS)
    test.eq("MAX_REPLY_CHARS", reasoner_bridge.MAX_REPLY_CHARS, 1200)
    test.eq("MAX_FACTS_CHARS", reasoner_bridge.MAX_FACTS_CHARS, 2400)
    facts_transport = _FakeTransport([(200, {"response": "ok"})])
    h.async_run(reasoner_bridge.ReasonerBridge(settings=settings, transport=facts_transport)
                .outcome, "meeting_summary", {"blob": "数" * 9000}, locale="en")
    prompt = json.dumps(facts_transport.last()["body"], ensure_ascii=False)
    test.check("超长事实被截断", len(prompt) < reasoner_bridge.MAX_FACTS_CHARS + 3000, str(len(prompt)))
    test.contains("截断留了标记", prompt, "…")
    test.eq("facts=None 也能跑", h.async_run(
        reasoner_bridge.ReasonerBridge(settings=settings,
                                       transport=_FakeTransport([(200, {"response": "x"})]))
        .outcome, "guest_booked", None).text, "x")
    # health 探测：可达/不可达/异常都不抛。
    settings = _reasoner_settings(h, REASONER_ENABLED="1")
    settings.reasoner_base_url = "http://127.0.0.1:11434"
    probe = _FakeTransport([(200, {"models": []})])
    report = h.async_run(reasoner_bridge.ReasonerBridge(settings=settings, transport=probe).health)
    test.eq("health 可达", report["ok"], True)
    test.eq("health 探测用 GET", probe.last()["method"], "GET")
    test.contains("ollama 探 /api/tags", probe.last()["url"], "/api/tags")
    test.eq("health 状态码入档", report["status"], 200)
    failing = _FakeTransport([OSError("拒绝连接")])
    report = h.async_run(reasoner_bridge.ReasonerBridge(settings=settings, transport=failing).health)
    test.eq("health 失败不抛", report["ok"], False)
    test.contains("health 失败写明原因", report["detail"], "拒绝连接")
    test.eq("health 记录时延", report["latency_ms"] >= 0.0, True)
    report = h.async_run(reasoner_bridge.ReasonerBridge(settings=settings).health, probe=False)
    test.contains("probe=False 不探测", report["detail"], "未探测")
    ok(test, "reasoner 降级与上限")


def _reasoner_hygiene(test: SelfTest, h: Harness) -> None:
    """密钥卫生：redact 覆盖消息、状态、repr；Outcome 形状稳定。"""
    secret = "sk-popopx-secret-value-123456"
    settings = _reasoner_settings(h, REASONER_ENABLED="1", REASONER_API_KEY=secret)
    settings.reasoner_base_url = "http://127.0.0.1:11434"
    bridge = reasoner_bridge.ReasonerBridge(settings=settings)
    test.eq("api_key 仍可读自 settings（供请求头用）", bridge.api_key, secret)
    test.eq("model 属性", bridge.model, "")
    test.eq("base_url 属性", bridge.base_url, "http://127.0.0.1:11434")
    test.check("status 不含密钥", secret not in json.dumps(bridge.status(), default=str), "")
    test.check("stats 不含密钥", secret not in json.dumps(bridge.stats(), default=str), "")
    test.check("repr(bridge) 不含密钥", secret not in repr(bridge), repr(bridge)[:200])
    test.check("str(bridge) 不含密钥", secret not in str(bridge), "")
    test.eq("status.api_key_configured", bridge.status()["api_key_configured"], True)
    leaking = _FakeTransport([OSError(f"对端回显 Bearer {secret}")])
    leaky = reasoner_bridge.ReasonerBridge(settings=settings, transport=leaking)
    out = h.async_run(leaky.outcome, "guest_booked", {})
    test.check("异常文本里的密钥被洗", secret not in out.reason, out.reason[:160])
    test.contains("异常仍可读", out.reason, "Bearer ***")
    test.check("recent 里的文本不含密钥", secret not in json.dumps(leaky.recent, default=str), "")
    report = h.async_run(leaky.health)
    test.check("health 文本不含密钥", secret not in json.dumps(report, default=str), "")
    sent = _FakeTransport([(200, {"response": "fine"})])
    h.async_run(reasoner_bridge.ReasonerBridge(settings=settings, transport=sent)
                .outcome, "guest_received", {"host": "Ann"})
    test.contains("请求头带 Bearer", sent.last()["headers"].get("Authorization", ""), "Bearer ")
    test.check("提示词正文不含密钥", secret not in json.dumps(sent.last()["body"], default=str), "")
    test.eq("无密钥时不编造 Authorization",
           "Authorization" in reasoner_bridge.ReasonerBridge(
               settings=_reasoner_settings(h, REASONER_ENABLED="1"))._headers(), False)

    def red(label: str, text: Any, *secrets: str) -> str:
        out = reasoner_bridge.redact(text, *secrets)
        test.check(f"redact（{label}）洗掉密钥", secret not in out, out[:120])
        return out

    red("Authorization 头", f"Authorization: Bearer {secret}")
    red("api_key 字段", json.dumps({"api_key": secret}))
    red("X-API-Key 字段", f"x-api-key: {secret}")
    red("自由文本", f"拨号失败 key={secret} 结束")
    red("无显式密钥也能洗", "Authorization: Bearer leaked-token")
    red("截断形态", f"头部 {secret[:10]}…")
    test.eq("redact(None) 得空串", reasoner_bridge.redact(None), "")
    test.eq("redact(int) 原样字符串", reasoner_bridge.redact(42), "42")
    test.eq("redact 短密钥不误伤", reasoner_bridge.redact("ab=cd", "ab"), "ab=cd")
    test.contains("_flatten 取 error 字段", reasoner_bridge._flatten({"error": "上游炸"}), "上游炸")
    test.contains("_flatten 序列化嵌套", reasoner_bridge._flatten({"a": {"b": 1}}), "\"b\": 1")
    test.eq("_flatten 长度上限", len(reasoner_bridge._flatten({"e": "x" * 900}, limit=50)) <= 50, True)
    outcome = h.async_run(reasoner_bridge.ReasonerBridge(settings=settings,
                                                        transport=_FakeTransport()).outcome,
                          "guest_booked", {"host": "Ann"}, locale="de")
    test.eq("Outcome 字段集", sorted(outcome.as_dict()),
            sorted(["text", "source", "kind", "locale", "reason", "latency_ms", "status"]))
    test.eq("Outcome.kind 回显", outcome.kind, "guest_booked")
    test.eq("Outcome.locale 归一", outcome.locale, "de")
    test.eq("Outcome 是 dataclass", hasattr(outcome, "as_dict"), True)
    test.eq("recent 每条都是同形状的字典",
            sorted(leaky.recent[0]) if leaky.recent else [], sorted(outcome.as_dict()))
    many = reasoner_bridge.ReasonerBridge(settings=_reasoner_settings(h), transport=_FakeTransport())
    for index in range(15):
        h.async_run(many.outcome, "guest_booked", {"host": str(index)})
    test.eq("recent 只留最后 10 条", len(many.recent), 10)
    test.eq("calls 计数不被 recent 截断影响", many.counts()["calls"], 15)
    ok(test, "reasoner 密钥卫生与形状")


# ------------------------------------------------------------------- 4. agent_copy


_BRACE_RE = re.compile(r"[{}]")


def _copy_locale_parity(test: SelfTest, h: Harness) -> None:
    """18 语种 × 12 话术的键集合必须完全一致。"""
    locales = list(i18n.LOCALES)
    test.eq("LOCALES 有 18 个", len(locales), 18)
    test.eq("LOCALES 无重复", len(set(locales)), 18)
    test.eq("回退语种是 en", i18n.FALLBACK_LOCALE, "en")
    test.eq("回退语种在目录里", i18n.FALLBACK_LOCALE in locales, True)
    test.eq("话术种类有 12 条", len(agent_copy.KINDS), 12)
    test.eq("KINDS 无重复", len(set(agent_copy.KINDS)), 12)
    test.eq("目录语种数=LOCALES 数", len(agent_copy.CATALOG), len(locales))
    base_kinds = set(agent_copy.CATALOG[i18n.FALLBACK_LOCALE])
    for code in locales:
        table = agent_copy.CATALOG.get(code)
        test.check(f"{code} 有目录表", isinstance(table, dict), str(type(table)))
        if not isinstance(table, dict):
            continue
        test.eq(f"{code} 键集与基准一致", sorted(table), sorted(base_kinds))
        test.eq(f"{code} 无缺失话术", agent_copy.missing_keys(code), [])
        test.eq(f"{code} 无多余话术", agent_copy.extra_keys(code), [])
        test.eq(f"{code} 占位符无漂移", agent_copy.placeholder_drift(code), [])
        for kind, value in table.items():
            test.check(f"{kind}/{code} 是字符串", isinstance(value, str), type(value).__name__)
            test.check(f"{kind}/{code} 非空白", bool(value.strip()), repr(value)[:40])
        test.eq(f"{code} 每条都有译文覆盖",
                [k for k in agent_copy.KINDS if len(agent_copy.locales_for(k)) != 18], [])
    test.eq("目录整体自检无问题", agent_copy.assert_catalog(), [])
    report = agent_copy.parity_report()
    test.eq("parity_report 覆盖 18 语种", len(report), 18)
    test.check("parity_report 全绿", all(row["aligned"] for row in report.values()),
               str([k for k, v in report.items() if not v["aligned"]]))
    test.eq("parity_report 字段", sorted(report["en"]),
            sorted(["missing", "extra", "drift", "kinds", "aligned"]))
    ok(test, "agent_copy 语种对齐")


def _copy_placeholder_hygiene(test: SelfTest, h: Harness) -> None:
    """值里不许出现未声明的花括号；漂移检测本身也必须真的会报。"""
    base = agent_copy.CATALOG[i18n.FALLBACK_LOCALE]
    for kind, value in base.items():
        declared = set(agent_copy.PLACEHOLDERS[kind])
        test.eq(f"PLACEHOLDERS 覆盖 {kind}", bool(declared), True)
        test.eq(f"{kind} 基准占位符与声明一致", i18n.placeholders(value), declared)
        # 比的是声明本身：set 的迭代顺序由哈希决定，转成 set 再比就永远测不出声明有没有漂。
        test.eq(f"{kind} 占位符表已排序", list(agent_copy.PLACEHOLDERS[kind]),
                sorted(agent_copy.PLACEHOLDERS[kind]))
    for code in i18n.LOCALES:
        for kind, value in agent_copy.CATALOG[code].items():
            stripped = _BRACE_RE.sub("", re.sub(r"\{[a-z_][a-z0-9_]*\}", "", value))
            test.check(f"{kind}/{code} 无孤立花括号", "{" not in stripped and "}" not in stripped,
                       value[:70])
            used = i18n.placeholders(value)
            test.eq(f"{kind}/{code} 只用声明过的槽位", sorted(used - set(agent_copy.PLACEHOLDERS[kind])), [])
    # 人为改坏一处（只动内存副本），三种检测表必须都报出来。
    original = agent_copy.CATALOG
    try:
        victim = "availability_answer"
        tampered = {code: dict(table) for code, table in original.items()}
        # 挑一个「汉字对它属于外来文字族」的语种，否则塞进去的中文句子根本触发不了串语种门禁。
        other = next(code for code in i18n.LOCALES
                     if code != i18n.FALLBACK_LOCALE and agent_copy.foreign_scripts(code, "汉字"))
        tampered[other][victim] = "同一句话但漏了槽位 {ghost}"
        agent_copy.CATALOG = tampered
        test.check("占位符漂移能被检出", victim in [row[0] for row in agent_copy.placeholder_drift(other)],
                   str(agent_copy.placeholder_drift(other))[:120])
        test.check("目录自检能拦住漂移", bool(agent_copy.assert_catalog()), "")
        agent_copy.CATALOG = {code: ({k: v for k, v in table.items() if k != victim} if code == other
                                      else dict(table)) for code, table in original.items()}
        test.contains("缺键能被检出", agent_copy.missing_keys(other), victim)
        test.check("目录自检能拦住缺键", bool(agent_copy.assert_catalog()), "")
        agent_copy.CATALOG = {code: (dict(table, **{"zz_extra": "多出的一条"}) if code == other
                                      else dict(table)) for code, table in original.items()}
        test.contains("多键能被检出", agent_copy.extra_keys(other), "zz_extra")
        agent_copy.CATALOG = {code: (dict(table, **{victim: ""}) if code == other else dict(table))
                              for code, table in original.items()}
        test.check("空话术能被检出", any("为空" in p for p in agent_copy.assert_catalog()),
                   str(agent_copy.assert_catalog())[:120])
        agent_copy.CATALOG = {code: (dict(table, **{victim: "这句里混进了汉字"}) if code == other
                                      else dict(table)) for code, table in original.items()}
        test.check("串语种能被检出",
                   any("串语种" in p for p in agent_copy.assert_catalog()),
                   str(agent_copy.assert_catalog())[:120])
    finally:
        agent_copy.CATALOG = original
    test.eq("目录恢复后自检重新通过", agent_copy.assert_catalog(), [])
    test.eq("catalog_payload 字段", sorted(agent_copy.catalog_payload()),
            sorted(["fallback", "locales", "kinds", "placeholders", "kind_for_tool", "templates"]))
    test.eq("payload 语种数", len(agent_copy.catalog_payload()["locales"]), 18)
    ok(test, "agent_copy 占位符卫生")


def _copy_fill(test: SelfTest, h: Harness) -> None:
    """fill：缺值不泄漏 {x}、不抛异常，未知键与脏值都有确定结果。"""
    filled = agent_copy.fill("Hi {sender} at {start} ({timezone}).", {"sender": "Ann",
                                                                      "start": "15:00",
                                                                      "timezone": "UTC"})
    test.eq("三槽位全填", filled, "Hi Ann at 15:00 (UTC).")
    partial = agent_copy.fill("Hi {sender} at {start} ({timezone}).", {"sender": "Ann"})
    test.check("缺槽位不泄漏花括号", "{" not in partial and "}" not in partial, partial)
    test.check("缺槽位不留空括号", "()" not in partial, partial)
    test.contains("已给的槽位仍填上", partial, "Ann")
    test.eq("未知占位符按缺失处理", agent_copy.fill("a {b}", {"zzz": 1}), "a")
    test.eq("None 值洗成空串", agent_copy.fill("a {b} c", {"b": None}), "a c")
    test.eq("空串值", agent_copy.fill("a{b}c", {"b": ""}), "ac")
    test.eq("列表值顿号连接", agent_copy.fill("选项：{options}", {"options": ["15:00", "16:00"]}),
            "选项：15:00, 16:00")
    test.eq("整数列表值", agent_copy.fill("{n} 天", {"n": [1, 2]}), "1, 2 天")
    test.eq("整值浮点去掉小数", agent_copy.fill("{n} 分钟", {"n": 30.0}), "30 分钟")
    test.eq("非整值浮点保留", agent_copy.fill("{n}", {"n": 1.5}), "1.5")
    test.eq("数字值", agent_copy.fill("{n}", {"n": 7}), "7")
    test.eq("集合值也可渲染", agent_copy.fill("{n}", {"n": {"x"}}), "x")
    test.eq("空串文本", agent_copy.fill("", {}), "")
    test.eq("None 文本", agent_copy.fill(None), "")
    test.eq("None facts", agent_copy.fill("纯文本，无槽位", None), "纯文本，无槽位")
    test.eq("facts 不是映射也不炸", isinstance(agent_copy.fill("{a}", {}), str), True)
    test.eq("重复槽位都填", agent_copy.fill("{a} 与 {a}", {"a": "X"}), "X 与 X")
    test.eq("连续空白被压扁", agent_copy.fill("a   b", {}), "a b")
    test.eq("标点前的空格被收掉", agent_copy.fill("a  .", {}), "a.")
    test.eq("首尾空白被裁", agent_copy.fill("  hi  ", {}), "hi")
    test.eq("大写槽位不算槽位", agent_copy.fill("{Bad}", {"Bad": "x"}), "{Bad}")
    test.eq("render 未知种类返回空串", agent_copy.render("no_such_kind", {}), "")
    test.eq("render 空种类返回空串", agent_copy.render("", {}), "")
    test.eq("template 未知语种落到基准", agent_copy.template("availability_answer", "klingon"),
            agent_copy.template("availability_answer"))
    test.eq("template 未知种类返回空串", agent_copy.template("no_such_kind", "en"), "")
    test.eq("render 走占位填充", agent_copy.render("guest_booked", {"host": "Ann", "start": "10:00",
                                                                  "timezone": "UTC",
                                                                  "code": "AB12"}, locale="en").count("{"), 0)
    preview = agent_copy.preview("cancel_confirm", {"title": "X", "start": "10:00", "timezone": "UTC"})
    test.eq("preview 覆盖 18 语种", len(preview), 18)
    test.check("preview 无残留槽位", all("{" not in v for v in preview.values()),
               str([k for k, v in preview.items() if "{" in v]))
    ok(test, "agent_copy fill")


def _copy_locale_resolution(test: SelfTest, h: Harness) -> None:
    """resolve_locale：精确 → 主语言 → 中文变体桥接 → 回退 en。"""
    for raw, want in [("en", "en"), ("EN", "en"), ("en-US", "en"), ("en_GB", "en"),
                      ("de-DE", "de"), ("de", "de"), ("fr", "fr"), ("es-MX", "es"),
                      ("ru-RU", "ru"), ("pt-BR", "en"), ("ja", "ja"), ("th", "th"),
                      ("zh", "zh-Hans"), ("zh-CN", "zh-Hans"), ("zh-Hans", "zh-Hans"),
                      ("zh-TW", "zh-Hant"), ("zh-HK", "zh-Hant"), ("zh-Hant", "zh-Hant"),
                      ("", "en"), ("   ", "en"), ("klingon", "en")]:
        test.eq(f"resolve_locale({raw!r})", agent_copy.resolve_locale(raw), want)
    for junk in (None, 7, ["zh"], {"a": 1}, True, b"zh"):
        test.eq(f"resolve_locale({type(junk).__name__}) 落到目录内",
                agent_copy.resolve_locale(junk) in i18n.LOCALES, True)
    test.eq("每个 locale 都有目录表",
            [c for c in i18n.LOCALES if not agent_copy.CATALOG.get(c)], [])
    test.eq("bridge 的 locale 解析与目录同源",
            reasoner_bridge.ReasonerBridge(settings=_reasoner_settings(h)).resolve_locale("de-DE"), "de")
    ok(test, "agent_copy locale 解析")


def _copy_kinds(test: SelfTest, h: Harness) -> None:
    """KIND_FOR_TOOL 覆盖 needle3 的五个工具，每个 kind 都有 18 份文案。"""
    table = agent_copy.KIND_FOR_TOOL
    test.eq("五个工具都有 kind", len(table), 5)
    test.eq("工具名与 needle3 一致", sorted(table), sorted(needle3_runtime.TOOL_NAMES))
    for dotted, kind in table.items():
        test.check(f"{dotted} 的 kind 非空", bool(str(kind).strip()), repr(kind))
        test.contains(f"{kind} 在 KINDS 里", agent_copy.KINDS, kind)
        test.eq(f"{dotted} 的话术齐全", len(agent_copy.locales_for(kind)), 18)
        for code in i18n.LOCALES:
            test.check(f"{dotted}→{kind}/{code} 有文案",
                       bool(agent_copy.CATALOG[code][kind].strip()), code)
    test.eq("未知工具回退", agent_copy.kind_for_tool("nope.nope"), "availability_answer")
    test.eq("空工具名回退", agent_copy.kind_for_tool(""), "availability_answer")
    test.eq("None 工具名回退", agent_copy.kind_for_tool(None), "availability_answer")
    test.eq("可指定回退 kind", agent_copy.kind_for_tool("x", fallback="guest_booked"), "guest_booked")
    test.eq("回退 kind 也存在于目录",
            agent_copy.kind_for_tool("nope") in agent_copy.CATALOG["en"], True)
    test.eq("KINDS 与目录键集一致（基准语种）", sorted(agent_copy.KINDS),
            sorted(agent_copy.CATALOG[i18n.FALLBACK_LOCALE]))
    ok(test, "agent_copy 工具→kind")


def _copy_consistency(test: SelfTest, h: Harness) -> None:
    """跨语种事实一致：同一条话术在各语言里说同一件事，不多承诺也不少承诺。"""
    facts = {"sender": "Ann", "host": "Ann", "peer": "Bob", "title": "路线图", "start": "10:00",
             "end": "11:00", "to": "周四 15:00", "from": "周三 15:00", "date": "2026-12-02",
             "timezone": "UTC", "duration": 30, "window": "7 天", "options": "15:00, 16:00",
             "file_name": "notes.pdf", "headline": "要点", "actions": "跟进 A", "code": "AB12",
             "reason": "没有共同空档"}
    for kind in agent_copy.KINDS:
        # *_confirm 三条只在 node.approve() 成功之后才发（agent_runtime 的唯一调用点），
        # 过去式是对既成事实的陈述；其余话术都发生在主人点确认之前，一句越界承诺都不能有。
        receipt = kind in {"create_confirm", "reschedule_confirm", "cancel_confirm"}
        declared = set(agent_copy.PLACEHOLDERS[kind])
        rows = {code: agent_copy.render(kind, facts, locale=code) for code in i18n.LOCALES}
        for code, text in rows.items():
            test.check(f"{kind}/{code} 渲染非空", len(text.strip()) >= 6, text[:40])
            test.check(f"{kind}/{code} 无残留槽位", "{" not in text and "}" not in text, text[:60])
            if not receipt:
                test.check(f"{kind}/{code} 无越界承诺",
                           not re.search(r"已(创建|写入|保存|安排|取消|改好|登记完)", text), text[:60])
                test.check(f"{kind}/{code} 无越界承诺（英文）",
                           not re.search(r"\balready\b.{0,24}\b(creat|sav|book|cancel|resched)", text, re.I),
                           text[:60])
            for token in declared:
                if token in ("title", "sender", "host", "peer", "file_name", "code"):
                    test.contains(f"{kind}/{code} 填了 {token}", text, facts[token])
        # 同一条话术各语言的数字必须一致（时间窗、天数、时长都来自事实，不是译文）。
        digits = {code: tuple(sorted(set(re.findall(r"\d+(?:\.\d+)?", text))))
                  for code, text in rows.items()}
        base = digits[i18n.FALLBACK_LOCALE]
        for code, row in digits.items():
            test.eq(f"{kind} 的数字在 {code} 与基准一致", row, base)
        # 文字族：非 CJK 语种里不该出现汉字/假名（复制粘贴事故的典型形状）。
        for code in i18n.LOCALES:
            test.eq(f"{kind}/{code} 未串文字族",
                    agent_copy.foreign_scripts(code, agent_copy.CATALOG[code][kind]), [])
    # 一个事实都不给时，各语言都不能吐出带花括号的半成品。
    bare = {code: agent_copy.render("availability_answer", {}, locale=code) for code in i18n.LOCALES}
    for code, text in bare.items():
        test.check(f"缺全部事实时 {code} 不泄漏槽位", "{" not in text and "}" not in text, text[:70])
    test.eq("缺事实也不空话术（基准）", bool(bare[i18n.FALLBACK_LOCALE].strip()), True)
    ok(test, "agent_copy 跨语言一致性")


def group_agent_engine(test: SelfTest, h: Harness) -> None:
    test.section("needle3_runtime")
    _needle_tables(test, h)
    _needle_tools(test, h)
    _needle_fallback(test, h)
    _needle_hygiene(test, h)
    _needle_shapes(test, h)
    test.section("agent_preferences")
    _pref_roundtrip(test, h)
    _pref_validate(test, h)
    _pref_days(test, h)
    _pref_buffers(test, h)
    _pref_keywords(test, h)
    test.section("reasoner_bridge")
    _reasoner_disabled(test, h)
    _reasoner_endpoint(test, h)
    _reasoner_happy(test, h)
    _reasoner_degrade(test, h)
    _reasoner_hygiene(test, h)
    test.section("agent_copy")
    _copy_locale_parity(test, h)
    _copy_placeholder_hygiene(test, h)
    _copy_fill(test, h)
    _copy_locale_resolution(test, h)
    _copy_kinds(test, h)
    _copy_consistency(test, h)


GROUPS: Dict[str, Callable[[SelfTest, Harness], None]] = {GROUP: group_agent_engine}


def main(argv: Optional[Sequence[str]] = None) -> int:
    """独立运行本组（``python3 -m app.selftest_agent_engine``）；参数可指定其它已注册分组。"""
    argv = list(sys.argv[1:] if argv is None else argv)
    only = [item for item in argv if not item.startswith("-")] or [GROUP]
    from . import selftest as orchestrator

    registry: Dict[str, Callable[[SelfTest, Harness], None]] = dict(GROUPS)
    registry.update(getattr(orchestrator, "SELF_TEST_GROUPS", {}) or {})
    for wanted in only:
        if wanted not in registry:
            print(f"未知分组：{wanted}（可用：{', '.join(GROUPS)}）")
            return 2
    test = SelfTest(only=only)
    harness = Harness(test)
    started = time.perf_counter()
    try:
        for name in only:
            start_a, start_f = test.assertions, test.failures
            test.section(name)
            print(f"[group] {name}", flush=True)
            try:
                registry[name](test, harness)
            except Exception as exc:  # noqa: BLE001 - 分组自己炸了也要如实记账，绝不静默
                test.failures += 1
                test.problems.append(f"FAIL [{name}] 分组异常 {type(exc).__name__}: {exc}")
                print(f"  FAIL [{name}] 分组异常 {type(exc).__name__}: {exc}", flush=True)
            count, failed = test.assertions - start_a, test.failures - start_f
            test.per_group[name] = (count, failed)
            print(f"[group] {name}: 断言 {count} 条，失败 {failed} 条", flush=True)
    finally:
        harness.close()
    print()
    for name, (count, failed) in test.per_group.items():
        print(f"  {name:22} {count:5} 条  {failed:3} 失败  {'ok' if failed == 0 else 'FAIL'}")
    print(f"合计 {test.assertions} 条断言，{len(only)}/{len(GROUPS)} 组（本模块），"
          f"{test.failures} 条失败，用时 {_time.perf_counter() - started:.1f}s")
    if test.problems:
        print("\n".join(test.problems[:80]))
    return 0 if test.failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
