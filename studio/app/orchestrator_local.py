"""编排能力的本机实现：五个只读投影，逐个接到真实引擎上。

本模块是 :mod:`app.orchestrator` 的**执行体**侧。编排器决定"能不能派"，这里决定
"派下去之后到底读什么"。两条铁律：

1. **只读目标 Bot 自己的隔离配置**。``rules.enabled_rules(bot_id)`` /
   ``router.enabled_rules(bot_id)`` / ``db.cached_busy(bot_id, …)`` /
   ``PreferenceStore.load(bot_id)`` 都以 ``target_bot_id`` 为键，所以 Bot B 的规则
   永远不可能被 Bot A 的缓存串味；实现里不存在"先切全局状态再算"的写法。
2. **返回结论，不返回原料**。回复只给规则编号与长度、路由只给目标类型与计数、
   忙闲只给掩码补集、画像走显式字段白名单。令牌、``smp`` 地址、常驻链接、日程标题、
   联系人标识在这些函数的返回值里没有路径 —— 结果会被写进 ``agent_tasks.result_json``，
   任何"顺手把整行带回"的写法都是往账本里塞密钥。

引擎异常一律抛 :class:`~app.orchestrator.OrchestratorError` 并由编排层归一成
``failed``；这里绝不自建第二套异常路径。
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

from . import needle3_runtime
from .mac_node_bridge import CACHE_SOURCE
from .orchestrator import Orchestrator, OrchestratorError
from .rule_engine import InboundMessage

__all__ = ("attach_local_capabilities",)

#: ``calendar.availability`` 的回看天数与上限：一次投影最多 14 天，够用且不放大账本。
AVAILABILITY_DEFAULT_DAYS = 7
AVAILABILITY_MAX_DAYS = 14
#: 忙闲掩码的时间颗粒（秒）。48 格一天，够画"哪天几点是满的"，又不暴露会议边界。
MASK_SLOT_SECONDS = 1800
#: ``reply.compose`` 的可渲染文本上限：只证明"真能拼出来"，不把正文写进账本。
RENDER_MAX_CHARS = 2000


def _day(value: Any, *, today: Optional[date] = None) -> date:
    """把 ``YYYY-MM-DD`` 解析成日期；``""`` / ``today`` 表示今天。"""
    text = str(value or "").strip()
    base = today or datetime.now().date()
    if not text or text.lower() in {"today", "今天"}:
        return base
    try:
        return date.fromisoformat(text)
    except ValueError as exc:
        raise OrchestratorError("bad_args", f"day {text!r} 不是 YYYY-MM-DD") from exc


def _int(value: Any, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(number, high))


def _zone_offset(moment: datetime) -> int:
    """带时区的午夜相对 UTC 的分钟偏移；朴素时间按 0 处理。"""
    return int((moment.utcoffset() or timedelta(0)).total_seconds() // 60)


def _slots(
    busy: List[Dict[str, Any]], *, zone: Optional[ZoneInfo], day: date
) -> Tuple[List[Dict[str, Any]], int]:
    """把 ``[{start,end,busy}]`` 区间折成一天里的 48 个半小时槽，并给出忙槽数。

    没有时区就不折算：跨时区的"忙"折成 UTC 槽会指向错误的那半天，与其画一张假图，
    不如只回 ``total``。
    """
    if zone is None:
        return [], sum(1 for row in busy if row.get("busy", True))
    midnight = datetime(day.year, day.month, day.day, tzinfo=zone)
    span = 86400
    cells = [0] * (span // MASK_SLOT_SECONDS)
    for row in busy:
        if not row.get("busy", True):
            continue
        start, end = float(row.get("start") or 0.0), float(row.get("end") or 0.0)
        if end <= start:
            continue
        first = max(0, int((start - midnight.timestamp()) // MASK_SLOT_SECONDS))
        last = min(len(cells), int((end - midnight.timestamp() - 1) // MASK_SLOT_SECONDS) + 1)
        for index in range(first, last):
            cells[index] = 1
    return [{"t": i, "busy": cells[i]} for i in range(len(cells)) if cells[i]], sum(cells)


def _tz(text: str) -> Optional[ZoneInfo]:
    try:
        return ZoneInfo(str(text or "").strip()) if str(text or "").strip() else None
    except Exception:  # noqa: BLE001 - 坏时区名只是不折算，不值得让整条投影失败
        return None


def attach_local_capabilities(orchestrator: Orchestrator, *, stack: Any) -> Orchestrator:
    """把五个只读投影注册进 ``orchestrator``，返回同一个对象方便链式装配。

    每个实现都从 ``stack`` 拿现成的引擎（``rules`` / ``router`` / ``db`` /
    ``settings``），因此门户上"已可用"三个字对应的是同一份运行时对象，
    不是复制出来的第二套逻辑。
    """
    db = stack.db
    settings = stack.settings

    def profile(context: Mapping[str, Any]) -> Dict[str, Any]:
        """目标 Bot 的隔离画像：只挑非敏感列，令牌与地址没有路径出去。"""
        bot_id = str(context.get("bot_id") or "")
        bot = db.get_bot(bot_id)
        if bot is None:
            raise OrchestratorError("unknown_target", bot_id)
        include_counts = bool(context["args"].get("include_counts", True))
        out: Dict[str, Any] = {
            "bot_id": bot["id"],
            "name": bot.get("name", ""),
            "display_name": bot.get("display_name", ""),
            "status": bot.get("status", ""),
            "default_locale": bot.get("default_locale", "") or "",
            "timezone": str(_prefs(bot_id).get("timezone") or ""),
        }
        if include_counts:
            stats = db.message_stats(bot_id)
            out["reply_rules"] = len(db.list_reply_rules(bot_id, enabled_only=True))
            out["routing_rules"] = len(db.list_routing_rules(bot_id, enabled_only=True))
            out["messages_in"] = int(stats.get("incoming") or 0)
            out["messages_out"] = int(stats.get("outgoing") or 0)
            out["active_tasks"] = db.count_active_tasks(bot_id)
        return out

    def _prefs(bot_id: str) -> Dict[str, Any]:
        runtime = getattr(stack, "agent", None)
        store = getattr(runtime, "preferences", None) if runtime is not None else None
        if store is None:
            return {}
        try:
            return store.load(bot_id)
        except Exception:  # noqa: BLE001 - 画像里少一个时区字段不值得整条失败
            return {}

    def compose(context: Mapping[str, Any]) -> Dict[str, Any]:
        """目标 Bot 的回复引擎会怎么回这句话（用 ``preview``，绝不动冷却）。"""
        bot_id = str(context.get("bot_id") or "")
        text = str(context["args"].get("text") or "")
        engine = getattr(stack, "rules", None)
        if engine is None:
            raise OrchestratorError("executor_error", "回复引擎尚未装配")
        sender = str(context["args"].get("sender_name") or "")
        chat_type = str(context["args"].get("chat_type") or "direct")
        decision = engine.preview(bot_id, text, sender=sender or "preview")
        out: Dict[str, Any] = {
            "matched": bool(decision.matched),
            "status": decision.status,
            "rule_id": decision.rule_id,
            "suppressed_by": decision.suppressed_by,
            "has_reply": bool(decision.reply),
            "reply_chars": len(decision.reply or ""),
        }
        if decision.matched and decision.reply:
            out["renders"] = len(decision.reply) <= RENDER_MAX_CHARS
        return out

    def routing(context: Mapping[str, Any]) -> Dict[str, Any]:
        """目标 Bot 的路由规则干跑：只看会打到哪类目标，不开工单、不发送。"""
        bot_id = str(context.get("bot_id") or "")
        args = context["args"]
        engine = getattr(stack, "router", None)
        if engine is None:
            raise OrchestratorError("executor_error", "路由引擎尚未装配")
        chat_type = str(args.get("chat_type") or "direct")
        message = InboundMessage(
            bot_id=bot_id,
            text=str(args.get("text") or ""),
            chat_type=chat_type,
            chat_ref=str(args.get("chat_ref") or ""),
            sender=str(args.get("sender") or "preview"),
        )
        # 干跑靠"备份—还原"冷却表实现，不去改 RouterEngine.plan 的签名：
        # 编排探测绝不能把真实会话的转发冷却算进账。
        snapshot = dict(engine._cooldowns)
        try:
            decision = engine.plan(message)
        finally:
            engine._cooldowns = snapshot
        kinds: Dict[str, int] = {}
        for plan in decision.plans:
            kinds[plan.target_type] = kinds.get(plan.target_type, 0) + 1
        return {
            "forwarded": bool(decision.forwarded),
            "status": decision.status,
            "matched_rules": list(decision.matched_rules),
            "plan_count": len(decision.plans),
            "by_target_type": kinds,
            "would_open_ticket": bool(chat_type == "direct" and any(
                plan.target_type == "group" for plan in decision.plans
            )),
        }

    def availability(context: Mapping[str, Any]) -> Dict[str, Any]:
        """目标 Bot 忙闲缓存的掩码空档：48 个半小时槽里哪些被占，不含任何日程正文。"""
        bot_id = str(context.get("bot_id") or "")
        args = context["args"]
        days = _int(args.get("days"), AVAILABILITY_DEFAULT_DAYS, 1, AVAILABILITY_MAX_DAYS)
        zone = _tz(str(args.get("timezone") or "")) or _tz(str(_prefs(bot_id).get("timezone") or ""))
        start = _day(args.get("day"))
        rows: List[Dict[str, Any]] = []
        for offset in range(days):
            day = start + timedelta(days=offset)
            record = db.cached_busy(bot_id, day.isoformat(), source=CACHE_SOURCE)
            if record is None:
                rows.append({"day": day.isoformat(), "cached": False})
                continue
            busy = [
                {"start": float(item.get("start") or 0.0),
                 "end": float(item.get("end") or 0.0),
                 "busy": bool(item.get("busy", True))}
                for item in (record.get("busy") or [])
                if isinstance(item, Mapping)
            ]
            used_zone = zone or _tz(str(record.get("timezone") or ""))
            masked, busy_slots = _slots(busy, zone=used_zone, day=day)
            midnight = datetime(day.year, day.month, day.day, tzinfo=used_zone) if used_zone else None
            rows.append({
                "day": day.isoformat(),
                "cached": True,
                "timezone": getattr(used_zone, "key", "") or str(record.get("timezone") or ""),
                "intervals": len(busy),
                "busy_slots": busy_slots,
                "free_slots": (86400 // MASK_SLOT_SECONDS) - busy_slots,
                "mask": masked,
                "offset_minutes": _zone_offset(midnight) if midnight else 0,
            })
        return {"bot_id": bot_id, "days": rows, "slot_seconds": MASK_SLOT_SECONDS,
                "from": start.isoformat(), "span": days}

    def summarize(context: Mapping[str, Any]) -> Dict[str, Any]:
        """用目标 Bot 自己的端侧抽取器解析这句话，返回它选的工具与槽位。"""
        bot_id = str(context.get("bot_id") or "")
        text = str(context["args"].get("text") or "")
        bot = db.get_bot(bot_id)
        locale = str((bot or {}).get("default_locale") or "")
        extraction = needle3_runtime.extract(text, settings=settings, locale=locale)
        return {
            "intent": extraction.intent,
            "tool": extraction.tool,
            "engine": extraction.engine,
            "degraded": bool(extraction.degraded),
            "latency_ms": round(float(extraction.latency_ms), 3),
            "calls": [call.as_dict() for call in extraction.calls],
            "error": extraction.error,
        }

    orchestrator.register("ledger.profile", profile)
    orchestrator.register("reply.compose", compose)
    orchestrator.register("router.plan", routing)
    orchestrator.register("calendar.availability", availability)
    orchestrator.register("workspace.summarize", summarize)
    return orchestrator
