"""``popopx.agent.task.v1`` 结构化任务卡片：在标准 ECO ``sc`` 帧里嵌一个 ``task`` 扩展。

兼容策略是"两层同时给"：

* **新客户端**读帧顶层（与 ``card`` 平级）的 ``task`` 对象，按 ``kind`` 渲染原生进度条、
  审批面板、多选卡与结果摘要 —— 字段是机器可读的，不依赖文案；
* **旧客户端**照旧渲染 ``card`` 里的 ``fields`` / ``actions``，所有文案由调用方用
  :mod:`app.agent_copy` 按 21 种语言渲染后传进来，因此老版本看到的是完整本地化卡片，
  而不是一条看不懂的 JSON。

帧形状、8192 字符预算、卡片 id/标题/正文/字段/按钮上限全部复用 :mod:`app.eco_cards`
的实测常量：这里不发明新的上限，也绝不为了塞进扩展字段而放宽协议。审批按钮复用
``::CB::ppxok|ppxno_<task_id>``，多选按钮复用 ``ppxalt_<task_id>.<option>`` ——
和提案卡片同一套回执通道，客户端不需要为新卡片学第二种回执格式。
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .eco_cards import (
    CALLBACK_ALT,
    CALLBACK_APPROVE,
    CALLBACK_DECLINE,
    EcoCardError,
    EcoLimits,
    build_action,
    build_card,
    callback_for,
    encode_frame,
    new_card_id,
    now_ms,
)

#: 扩展对象里的协议版本号。客户端只认这个值，改形状必须换版本。
TASK_SCHEMA = "popopx.agent.task.v1"

#: 四型卡片。``progress`` 进度、``approval`` 审批、``choice`` 多选、``result`` 结果。
TASK_KINDS = ("progress", "approval", "choice", "result")

CHOICE_MAX_OPTIONS = EcoLimits.max_actions
SUMMARY_MAX_CHARS = 240
SCOPE_MAX_CHARS = 240
QUESTION_MAX_CHARS = 240
LABEL_MAX_CHARS = 80


def _clip(value: Any, limit: int) -> str:
    return str(value if value is not None else "").strip()[:limit]


def _int(value: Any, *, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return minimum
    return max(minimum, min(number, maximum))


def _option_id(raw: Any, index: int) -> str:
    """选项 id 只能含 ``[A-Za-z0-9_-]``：回执 ref 允许点号，但点号在本协议里当分隔符用。"""
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    text = "".join(char for char in _clip(raw, 32) if char in allowed)
    return text or f"opt{index + 1}"


def task_payload(task: Mapping[str, Any], kind: str) -> Dict[str, Any]:
    """扩展对象的公共骨架：版本、任务号、存储状态、派生结果与留存模式。"""
    if kind not in TASK_KINDS:
        raise EcoCardError(f"未知任务卡片类型 {kind!r}：{list(TASK_KINDS)}")
    task_id = _clip(task.get("id"), 64)
    if not task_id:
        raise EcoCardError("任务卡片缺少 task_id")
    return {
        "schema": TASK_SCHEMA,
        "task_id": task_id,
        "status": _clip(task.get("status"), 32),
        "outcome": _clip(task.get("outcome"), 16),
        "kind": kind,
        "retention_mode": _clip(task.get("retention_mode"), 32),
    }


def progress_payload(progress: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    source = progress if isinstance(progress, Mapping) else {}
    total = _int(source.get("total"), minimum=0, maximum=10000)
    step = _int(source.get("step"), minimum=0, maximum=10000)
    percent = _int(source.get("percent"), minimum=0, maximum=100)
    if not percent and total > 0:
        percent = min(100, int(round(step * 100.0 / total)))
    return {
        "step": step,
        "total": total,
        "percent": percent,
        "label": _clip(source.get("label"), LABEL_MAX_CHARS),
    }


def result_payload(
    summary: str = "", *, latency_ms: float = 0.0, task: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "summary": _clip(summary, SUMMARY_MAX_CHARS),
        "latency_ms": round(float(latency_ms or 0.0), 3),
    }
    if task is not None:
        payload["outcome"] = _clip(task.get("outcome"), 16)
        payload["retention_mode"] = _clip(task.get("retention_mode"), 32)
    return payload


def _frame(
    card: Mapping[str, Any],
    extension: Mapping[str, Any],
    *,
    update: bool = False,
    visible_text: str = "",
) -> str:
    payload: Dict[str, Any] = {"t": "sc", "m": "u" if update else "c", "card": dict(card)}
    payload["task"] = dict(extension)
    # 客户端规定更新帧必须独占整条消息：在旧卡片上改字会留下两条对不上的气泡。
    return encode_frame(payload, visible_text=None if update else (visible_text or None))


def _fields(fields: Optional[Sequence[Mapping[str, Any]]]) -> Optional[List[Dict[str, Any]]]:
    return [dict(field) for field in fields] if fields else None


def task_progress_card(
    task: Mapping[str, Any],
    *,
    title: str,
    body: str = "",
    fields: Optional[Sequence[Mapping[str, Any]]] = None,
    progress: Optional[Mapping[str, Any]] = None,
    card_id: str = "",
    visible_text: str = "",
) -> Tuple[Dict[str, Any], str]:
    """进度卡：``task.progress`` 给客户端画进度条，``fields`` 是给旧客户端的本地化兜底。"""
    extension = task_payload(task, "progress")
    extension["progress"] = progress_payload(progress)
    card = build_card(
        card_id or new_card_id("ppxtk"),
        title,
        style="standard",
        body=body,
        fields=_fields(fields),
    )
    return card, _frame(card, extension, visible_text=visible_text or body)


def task_approval_card(
    task: Mapping[str, Any],
    *,
    title: str,
    body: str = "",
    fields: Optional[Sequence[Mapping[str, Any]]] = None,
    scope: str = "",
    approve_label: str,
    reject_label: str,
    ttl_seconds: float = 1800.0,
    card_id: str = "",
    visible_text: str = "",
) -> Tuple[Dict[str, Any], str]:
    """审批卡：把**权限范围**写进 ``task.approval.scope``，批准按钮才允许续跑。"""
    extension = task_payload(task, "approval")
    task_id = str(extension["task_id"])
    extension["approval"] = {
        "scope": _clip(scope, SCOPE_MAX_CHARS),
        "approve": callback_for(CALLBACK_APPROVE, task_id),
        "reject": callback_for(CALLBACK_DECLINE, task_id),
    }
    ttl = max(30.0, float(ttl_seconds))
    card = build_card(
        card_id or new_card_id("ppxtk"),
        title,
        style="security",
        body=body,
        fields=_fields(fields),
        actions=[
            {
                "action_id": "approve",
                "title": approve_label,
                "kind": "callback",
                "style": "primary",
                "payload": extension["approval"]["approve"],
            },
            {
                "action_id": "reject",
                "title": reject_label,
                "kind": "callback",
                "style": "destructive",
                "payload": extension["approval"]["reject"],
            },
        ],
        expires_at_ms=now_ms() + int(ttl * 1000),
    )
    return card, _frame(card, extension, visible_text=visible_text or body)


def task_choice_card(
    task: Mapping[str, Any],
    *,
    title: str,
    body: str = "",
    question: str = "",
    options: Sequence[Mapping[str, Any]],
    multi: bool = False,
    fields: Optional[Sequence[Mapping[str, Any]]] = None,
    card_id: str = "",
    visible_text: str = "",
) -> Tuple[Dict[str, Any], str]:
    """多选/单选卡：每个选项一个 ``ppxalt_<task_id>.<option>`` 回执，最多 4 个（按钮上限）。"""
    extension = task_payload(task, "choice")
    task_id = str(extension["task_id"])
    wanted = list(options or [])
    if not wanted:
        raise EcoCardError("选择卡至少要一个选项")
    if len(wanted) > CHOICE_MAX_OPTIONS:
        raise EcoCardError(f"选择卡选项 {len(wanted)} 个，超过按钮上限 {CHOICE_MAX_OPTIONS}")
    built: List[Dict[str, str]] = []
    actions: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(wanted):
        option_id = _option_id(raw.get("id"), index)
        if option_id in seen:
            raise EcoCardError(f"选项 id 重复：{option_id}")
        seen.add(option_id)
        label = _clip(raw.get("label") or raw.get("title"), LABEL_MAX_CHARS)
        if not label:
            raise EcoCardError(f"选项 {option_id} 缺少文案")
        built.append({"id": option_id, "label": label})
        actions.append(
            build_action(
                action_id=option_id,
                title=label,
                kind="callback",
                style="secondary",
                payload=callback_for(CALLBACK_ALT, f"{task_id}.{option_id}"),
            )
        )
    extension["choice"] = {
        "question": _clip(question or body, QUESTION_MAX_CHARS),
        "options": built,
        "multi": bool(multi),
    }
    card = build_card(
        card_id or new_card_id("ppxtk"),
        title,
        style="standard",
        body=body,
        fields=_fields(fields),
        actions=actions,
    )
    return card, _frame(card, extension, visible_text=visible_text or body)


def task_result_card(
    task: Mapping[str, Any],
    *,
    title: str,
    body: str = "",
    summary: str = "",
    fields: Optional[Sequence[Mapping[str, Any]]] = None,
    latency_ms: float = 0.0,
    card_id: str = "",
    update: bool = False,
    visible_text: str = "",
) -> Tuple[Dict[str, Any], str]:
    """结果卡：``task.result`` 带摘要、耗时、结果与留存标签；``update=True`` 就地改写审批卡。"""
    extension = task_payload(task, "result")
    extension["result"] = result_payload(summary, latency_ms=latency_ms, task=task)
    card = build_card(
        card_id or new_card_id("ppxtk"),
        title,
        style="standard",
        body=body,
        fields=_fields(fields),
    )
    return card, _frame(card, extension, update=update, visible_text=visible_text or body)


__all__ = (
    "CHOICE_MAX_OPTIONS",
    "TASK_KINDS",
    "TASK_SCHEMA",
    "progress_payload",
    "result_payload",
    "task_approval_card",
    "task_choice_card",
    "task_payload",
    "task_progress_card",
    "task_result_card",
)
