"""跨 Agent 任务编排：同一工作台内把一个子任务派给兄弟 Bot，再聚合回传。

和 :mod:`app.a2a` 的分工要先说清楚，否则两个模块看着像重复建设：

* :mod:`app.a2a` 处理的是**远端**——两个已配对的替身机器人隔着 E2EE SMP 队列交换
  掩码时段，帧要签名、要防重放、要防日历正文外流；
* 本模块处理的是**本机工作台**——同一 ``studio`` 进程里已经存在的若干 Bot，各自有
  独立 CLI 沙箱、独立规则表、独立偏好与独立时区。发起方看不见兄弟 Bot 的这些状态，
  所以"派活给它的替身、拿回它的结论"这件事本身是有信息量的，不是自问自答。

三条结构约束，不靠调用方自觉：

1. **默认拒绝**：没有 :meth:`app.database.Database.find_grant` 命中的授权行，任务在
   落库之前就 ``refused``，reason 是 ``no_grant``。授权按 ``(origin, target, capability)``
   三元组建，``capability`` 支持显式通配 ``*``。
2. **只读**：本模块能派的能力全部是目标 Bot 自身状态的**只读投影**（它会怎么回、它会怎么
   转、它这几天有没有空、它会把这句话抽成什么、它的账本画像）。注册新能力时
   ``writes=True`` 一律拒收 —— 编排器绝不写日历、绝不发消息、绝不动别人的规则。
   真正的副作用仍旧只在主人点确认后由 :mod:`app.mac_node_bridge` 发生。
3. **可回放**：一次编排（含扇出的每一个子任务）共用一个 ``correlation_id``，每次迁移写
   一条 ``db.log_negotiation("orchestrator", ...)``，detail 只允许出现 id、计数和原因码 ——
   和 ``a2a`` 同一套纪律。派活的因果链按时间正序取回（:meth:`replay`）。

熔断：``asyncio.wait_for`` 到点就断，被断的任务落在 ``timeout``，取消落在 ``cancelled``；
``succeeded`` 之后不再迁移。跳数超预算、祖先链里出现自己（A→B→A）、目标并发额度占满，
都在派发前掐掉，理由进审计。

本模块不 import 网关，也不 import 监督器：能力由 :meth:`Orchestrator.register` 注入
（见 :mod:`app.agent_runtime`），因此自检可以直接塞假能力进来跑状态机。
"""

from __future__ import annotations

import asyncio
import inspect
import json
import re
import time
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .database import (
    GRANT_WILDCARD,
    MAX_TASK_CONCURRENCY,
    MAX_TASK_HOPS,
    TASK_RESULT_MAX_CHARS,
    TASK_TIMEOUT_MAX_SECONDS,
    TASK_TIMEOUT_MIN_SECONDS,
    Database,
    LedgerError,
    new_thread_id,
)

#: 编排器的稳定原因码。审计与 ``error_code`` 只写这些，绝不写正文。
REASONS = (
    "no_grant",
    "hop_budget",
    "cycle",
    "busy",
    "unknown_capability",
    "unknown_origin",
    "unknown_target",
    "self_dispatch",
    "bad_args",
    "timeout",
    "cancelled",
    "executor_error",
    "not_cancellable",
    "no_targets",
    "fanout_limit",
    "not_found",
)

#: 单个能力允许声明的入参上限（字符数）。扇出时按最紧的一条算总预算。
ARG_TEXT_MAX = 2000
ARG_FIELD_MAX = 256
ARG_LIST_MAX = 32
ARG_INT_MIN, ARG_INT_MAX = 0, 400

FANOUT_MAX_DEFAULT = 8
#: 扇出的整体预算上限。单个子任务另有自己的授权超时，两层各管各的。
FANOUT_BUDGET_MAX_SECONDS = 900.0

#: 内置能力的入参规格。``required`` 缺一项就是 ``bad_args``，多一项未知键也是 ——
#: 未知键往往意味着调用方拼错了名字，静默吞掉只会让结果看着像"它真的这么回"。
CAPABILITY_SPECS: Dict[str, Dict[str, Any]] = {
    "reply.compose": {
        "required": ("text",),
        "optional": ("sender_name", "chat_type"),
        "writes": False,
        "reads": ("reply_rules", "default_locale"),
        "summary": "目标 Bot 按自己的规则表与语言决定会回什么（不发送）。",
    },
    "router.plan": {
        "required": ("text",),
        "optional": ("chat_type", "chat_ref", "sender"),
        "writes": False,
        "reads": ("routing_rules", "tickets"),
        "summary": "目标 Bot 按自己的路由规则会怎么转这条消息（干跑，不开工单）。",
    },
    "calendar.availability": {
        "required": (),
        "optional": ("days", "timezone", "day"),
        "writes": False,
        "reads": ("calendar_cache",),
        "summary": "目标 Bot 本地忙闲缓存里的掩码空档，绝不含日程正文。",
    },
    "workspace.summarize": {
        "required": ("text",),
        "optional": ("max_items",),
        "writes": False,
        "reads": ("needle3",),
        "summary": "用目标 Bot 自己的端侧抽取器解析这句话，返回它选的工具与槽位。",
    },
    "ledger.profile": {
        "required": (),
        "optional": ("include_counts",),
        "writes": False,
        "reads": ("bots", "reply_rules", "routing_rules"),
        "summary": "目标 Bot 的隔离画像：语言、时区、规则与路由条数（不含令牌与地址）。",
    },
}

#: ``executor(context) -> Mapping``。context 里只有 bot_id / capability / args /
#: correlation_id / hops / deadline_at，能力实现拿不到数据库句柄以外的编排状态。
Executor = Callable[[Dict[str, Any]], Any]

Result = Dict[str, Any]


class OrchestratorError(RuntimeError):
    """编排被拒或失败。``code`` 是 :data:`REASONS` 里的稳定值。"""

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in REASONS:
            code = "executor_error"
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = _scrub(detail)


def _clean(value: Any, limit: int) -> str:
    return str(value if value is not None else "").strip()[:limit]


def _brief(exc: BaseException, limit: int = 180) -> str:
    """异常摘要：类型名 + 打码后的短消息，供 ``detail`` 与审计使用。

    ``str(exc)`` 会原样带上实现内部拼的字符串，最常见的两种是地址与令牌（``KeyError``
    打出 ``smp1.popopx.im/a#…``、``ValueError`` 打出 ``token=…``）。这两样正是编排层
    承诺不进账本的东西，所以先按形状替换再截断 —— 顺序不能反，截断后再打码会留下半条密钥。
    """
    text = _scrub(str(exc))
    head = type(exc).__name__ if not text else f"{type(exc).__name__}: {text}"
    return head[:limit]


#: 打码形状：带标签的密钥、URL（连 scheme 一起吞）、**不带 scheme 的主机+路径**、
#: Bearer/sk- 令牌、长 base64/hex 串。
#: 裸主机那条不能省：引擎内部抛的错常是 ``smp1.popopx.im/a#key=…`` 这种省掉 scheme 的写法，
#: 只按 ``scheme://`` 匹配等于给它开了后门。三段点分才认定，避免把 ``a.b`` 之类的普通词打掉。
_SCRUB_PATTERNS = (
    re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|key)\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)\b(?:smp|https?|popopx|wss?|socks\d?)://\S+"),
    re.compile(r"(?i)\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+){2,}(?::\d+)?(?:[/?#]\S*)?"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{6,}"),
    re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}"),
)


def _scrub(text: str) -> str:
    """按形状（不是按字段名清单）替换敏感片段，返回单行摘要。"""
    out = text.replace("\x00", " ").replace("\n", " ").strip()
    for pattern in _SCRUB_PATTERNS:
        out = pattern.sub("[已打码]", out)
    return out


def validate_args(capability: str, args: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """按 :data:`CAPABILITY_SPECS` 校验并归一入参；不合规一律 :class:`OrchestratorError`。

    返回的是**重建**过的字典（只含规格里声明过的键），下游因此不可能拿到调用方偷偷塞进来的
    多余字段 —— 这一点对 ``calendar.availability`` 尤其要紧，它后面接的是掩码投影。
    """
    spec = CAPABILITY_SPECS.get(capability)
    if spec is None:
        raise OrchestratorError("unknown_capability", capability)
    source = dict(args or {})
    allowed = set(spec["required"]) | set(spec["optional"])
    unknown = sorted(set(source) - allowed)
    if unknown:
        raise OrchestratorError("bad_args", f"{capability} 不接受参数 {unknown}")
    missing = [key for key in spec["required"] if not str(source.get(key) or "").strip()]
    if missing:
        raise OrchestratorError("bad_args", f"{capability} 缺少参数 {missing}")
    out: Dict[str, Any] = {}
    for key, value in source.items():
        if key not in allowed:
            continue
        if isinstance(value, bool):
            out[key] = value
        elif isinstance(value, int):
            if not ARG_INT_MIN <= value <= ARG_INT_MAX:
                raise OrchestratorError("bad_args", f"{key} 超出 {ARG_INT_MIN}..{ARG_INT_MAX}")
            out[key] = value
        elif isinstance(value, (list, tuple)):
            if len(value) > ARG_LIST_MAX:
                raise OrchestratorError("bad_args", f"{key} 条目超过 {ARG_LIST_MAX}")
            out[key] = [_clean(item, ARG_FIELD_MAX) for item in value if _clean(item, ARG_FIELD_MAX)]
        elif isinstance(value, str):
            limit = ARG_TEXT_MAX if key == "text" else ARG_FIELD_MAX
            if len(value) > limit:
                raise OrchestratorError("bad_args", f"{key} 超过 {limit} 字符")
            out[key] = value.strip()
        else:
            raise OrchestratorError("bad_args", f"{key} 类型不支持 {type(value).__name__}")
    return out


class Orchestrator:
    """本机 Bot 之间的受策略约束任务派发与结果聚合。"""

    def __init__(
        self,
        db: Database,
        *,
        max_fanout: int = FANOUT_MAX_DEFAULT,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.db = db
        self.clock = clock
        self.monotonic = monotonic
        self.max_fanout = max(1, min(int(max_fanout), FANOUT_MAX_DEFAULT))
        self._executors: Dict[str, Executor] = {}
        self._inflight: Dict[str, asyncio.Task] = {}
        self._cancelled: set[str] = set()
        #: 观测计数，只用于面板与自检，不作为权限依据。
        self.stats: Dict[str, int] = {
            "dispatched": 0,
            "succeeded": 0,
            "failed": 0,
            "timeout": 0,
            "refused": 0,
            "cancelled": 0,
            "fanout": 0,
        }

    # ------------------------------------------------------------------ wiring
    def register(self, capability: str, executor: Executor, *, writes: bool = False) -> None:
        """注册一个能力实现。``writes=True`` 直接拒：编排器只做只读投影。"""
        name = _clean(capability, 64)
        spec = CAPABILITY_SPECS.get(name)
        if spec is None:
            raise OrchestratorError("unknown_capability", f"未声明的能力 {name!r}")
        if writes or spec.get("writes"):
            raise OrchestratorError("bad_args", f"能力 {name} 声明了写副作用，编排器拒绝承载")
        if not callable(executor):
            raise OrchestratorError("bad_args", f"能力 {name} 的执行体不可调用")
        self._executors[name] = executor

    def unregister(self, capability: str) -> bool:
        return self._executors.pop(_clean(capability, 64), None) is not None

    def registered(self) -> List[str]:
        return sorted(self._executors)

    def capabilities(self) -> List[Result]:
        """面板要的可派清单：已注册的才 ``available``，没接上实现的列出来但不可派。"""
        rows: List[Result] = []
        for name, spec in sorted(CAPABILITY_SPECS.items()):
            rows.append(
                {
                    "capability": name,
                    "available": name in self._executors,
                    "required": list(spec["required"]),
                    "optional": list(spec["optional"]),
                    "reads": list(spec.get("reads", ())),
                    "writes": bool(spec.get("writes")),
                    "summary": spec.get("summary", ""),
                }
            )
        return rows

    def snapshot(self, bot_id: Optional[str] = None) -> Result:
        """编排面板的一屏数据：能力、授权、近期任务、计数。"""
        return {
            "capabilities": self.capabilities(),
            "grants": self.db.list_grants(origin_bot_id=bot_id) if bot_id else self.db.list_grants(),
            "tasks": self.db.list_tasks(bot_id=bot_id, limit=50),
            "stats": dict(self.stats),
            "ledger": self.db.task_stats(bot_id),
            "inflight": sorted(self._inflight),
            "limits": {
                "max_hops": MAX_TASK_HOPS,
                "max_concurrent": MAX_TASK_CONCURRENCY,
                "max_fanout": self.max_fanout,
                "timeout_min_seconds": TASK_TIMEOUT_MIN_SECONDS,
                "timeout_max_seconds": TASK_TIMEOUT_MAX_SECONDS,
            },
        }

    # -------------------------------------------------------------- dispatch
    async def dispatch(
        self,
        origin_bot_id: str,
        target_bot_id: str,
        capability: str,
        args: Optional[Mapping[str, Any]] = None,
        *,
        correlation_id: str = "",
        parent_id: str = "",
        hops: int = 1,
    ) -> Result:
        """受策略约束地派发一个子任务，等它跑完（或熔断）后返回任务记录。

        所有拒绝都发生在**写 ``agent_tasks`` 之前**，除了 ``no_grant``/``hop_budget``/
        ``cycle``/``busy`` 这四条也写一条 refused 行 —— 它们值得留在任务账本里，
        因为"谁试图派给谁、被哪条闸挡下"本身就是审计要回答的问题。
        """
        origin = _clean(origin_bot_id, 64)
        target = _clean(target_bot_id, 64)
        name = _clean(capability, 64)
        thread = _clean(correlation_id, 64) or self._inherit_thread(parent_id) or new_thread_id()

        if not self.db.get_bot(origin):
            raise OrchestratorError("unknown_origin", origin)
        if not self.db.get_bot(target):
            raise OrchestratorError("unknown_target", target)
        if origin == target:
            raise OrchestratorError("self_dispatch", origin)
        if name not in self._executors:
            raise OrchestratorError(
                "unknown_capability", name if name in CAPABILITY_SPECS else f"未注册 {name}"
            )
        payload = validate_args(name, args)

        refusal = self._policy_refusal(origin, target, name, payload, hops=hops, parent_id=parent_id)
        if refusal is not None:
            code, detail = refusal
            task = self.db.create_task(
                correlation_id=thread,
                origin_bot_id=origin,
                target_bot_id=target,
                capability=name,
                parent_id=parent_id,
                args=payload,
                status="refused",
                hops=hops,
                timeout_seconds=self._grant_timeout(origin, target, name),
            )
            self.db.update_task(
                task["id"],
                error_code=code,
                detail=detail[:180],
                started_at=self.clock(),
                finished_at=self.clock(),
            )
            self.stats["refused"] += 1
            self._audit("refused", "warn", task, detail=code)
            return self.db.get_task(task["id"]) or task

        timeout = self._grant_timeout(origin, target, name)
        task = self.db.create_task(
            correlation_id=thread,
            origin_bot_id=origin,
            target_bot_id=target,
            capability=name,
            parent_id=parent_id,
            args=payload,
            status="queued",
            hops=hops,
            timeout_seconds=timeout,
        )
        task_id = str(task["id"])
        self.stats["dispatched"] += 1
        self._audit("dispatch", "info", task, detail="queued")

        started = self.monotonic()
        self.db.update_task(task_id, status="running", started_at=self.clock())
        running = self.db.get_task(task_id) or task
        # 能力实现单独跑在一个子 Task 上：cancel() 只断这一条，发起方（请求协程）
        # 仍然活着，能把 cancelled 收尾写回账本再正常返回。
        inner = asyncio.ensure_future(self._invoke(running, payload))
        self._inflight[task_id] = inner
        try:
            outcome = await asyncio.wait_for(inner, timeout=timeout)
        except asyncio.TimeoutError:
            self.stats["timeout"] += 1
            elapsed = (self.monotonic() - started) * 1000.0
            final = self.db.update_task(
                task_id,
                status="timeout",
                error_code="timeout",
                detail=f"{timeout:.3f}s",
                finished_at=self.clock(),
                latency_ms=round(elapsed, 3),
            )
            self._audit("timeout", "warn", final or running, detail="timeout")
            return final or running
        except asyncio.CancelledError:
            if task_id in self._cancelled:
                self.stats["cancelled"] += 1
                elapsed = (self.monotonic() - started) * 1000.0
                final = self.db.update_task(
                    task_id,
                    status="cancelled",
                    error_code="cancelled",
                    detail="operator",
                    finished_at=self.clock(),
                    latency_ms=round(elapsed, 3),
                )
                self._audit("cancelled", "warn", final or running, detail="cancelled")
                return final or running
            raise
        except OrchestratorError as exc:
            return self._settle_failed(task_id, running, exc, started)
        except Exception as exc:  # noqa: BLE001 - 能力实现的任何异常都不能冒到调用方
            return self._settle_failed(
                task_id, running, OrchestratorError("executor_error", _brief(exc)), started
            )
        finally:
            self._inflight.pop(task_id, None)
            self._cancelled.discard(task_id)

        if not isinstance(outcome, Mapping):
            return self._settle_failed(
                task_id,
                running,
                OrchestratorError("executor_error", f"能力返回 {type(outcome).__name__}，需要映射"),
                started,
            )
        elapsed = (self.monotonic() - started) * 1000.0
        try:
            blob = _dump_result(outcome)
        except OrchestratorError as exc:
            # 体积闸在 await 之后抛：不在这里收口的话，这一行会永远停在 running。
            return self._settle_failed(task_id, running, exc, started)
        final = self.db.update_task(
            task_id,
            status="succeeded",
            error_code="",
            detail="",
            result_json=blob,
            finished_at=self.clock(),
            latency_ms=round(elapsed, 3),
        )
        self.stats["succeeded"] += 1
        self._audit("succeeded", "info", final or running, detail="ok")
        return final or running

    async def fanout(
        self,
        origin_bot_id: str,
        targets: Sequence[str],
        capability: str,
        args: Optional[Mapping[str, Any]] = None,
        *,
        correlation_id: str = "",
        parent_id: str = "",
        hops: int = 1,
        budget_seconds: float = 0.0,
    ) -> Result:
        """并发派给多个兄弟 Bot，等全部落定后给一份聚合。

        聚合口径照 :mod:`app.open_api` 的播报来：部分成功不算失败，但 ``partial`` 必须为真，
        并逐目标给出状态 —— 绝不把一个 ``timeout`` 混进 ``succeeded`` 里报总数了事。
        """
        wanted: List[str] = []
        for raw in targets or ():
            item = _clean(raw, 64)
            if item and item not in wanted:
                wanted.append(item)
        if not wanted:
            raise OrchestratorError("no_targets", "扇出至少要一个目标")
        if len(wanted) > self.max_fanout:
            raise OrchestratorError("fanout_limit", f"{len(wanted)} > {self.max_fanout}")
        name = _clean(capability, 64)
        thread = _clean(correlation_id, 64) or new_thread_id()
        # 先校验一次入参，避免 N 个目标各自抛同一个错、审计里留下 N 条同样的拒。
        validate_args(name, args)
        self.stats["fanout"] += 1
        self._audit_raw("fanout", "info", origin=origin_bot_id, thread=thread, detail=f"{len(wanted)} targets")

        jobs = [
            self.dispatch(
                origin_bot_id,
                target,
                name,
                args,
                correlation_id=thread,
                parent_id=parent_id,
                hops=hops,
            )
            for target in wanted
        ]
        gather = asyncio.gather(*jobs, return_exceptions=True)
        ceiling = (
            float(budget_seconds)
            if budget_seconds
            else min(FANOUT_BUDGET_MAX_SECONDS, 1.0 + max(
                (float(self._grant_timeout(origin_bot_id, target, name)) for target in wanted),
                default=TASK_TIMEOUT_MAX_SECONDS,
            ))
        )
        try:
            settled = await asyncio.wait_for(asyncio.shield(gather), timeout=ceiling)
        except asyncio.TimeoutError:
            gather.cancel()
            settled = [
                OrchestratorError("timeout", f"扇出预算 {ceiling:.3f}s 用尽") for _ in wanted
            ]
        rows: List[Result] = []
        counts: Dict[str, int] = {}
        for target, item in zip(wanted, settled):
            if isinstance(item, OrchestratorError):
                record = {"target_bot_id": target, "status": "refused", "error_code": item.code,
                          "detail": item.detail[:180], "result": {}}
            elif isinstance(item, Exception):
                record = {"target_bot_id": target, "status": "failed", "error_code": "executor_error",
                          "detail": _brief(item), "result": {}}
            else:
                record = {
                    "target_bot_id": target,
                    "task_id": item.get("id", ""),
                    "status": item.get("status", "failed"),
                    "error_code": item.get("error_code", ""),
                    "detail": item.get("detail", ""),
                    "latency_ms": item.get("latency_ms", 0.0),
                    "result": item.get("result", {}),
                }
            counts[record["status"]] = counts.get(record["status"], 0) + 1
            rows.append(record)
        done = counts.get("succeeded", 0)
        aggregate = {
            "correlation_id": thread,
            "capability": name,
            "origin_bot_id": _clean(origin_bot_id, 64),
            "targets": rows,
            "counts": counts,
            "total": len(rows),
            "succeeded": done,
            "partial": 0 < done < len(rows),
            "budget_seconds": round(ceiling, 3),
        }
        self._audit_raw(
            "aggregated", "info" if done else "warn",
            origin=origin_bot_id, thread=thread,
            detail=f"{done}/{len(rows)} ok",
        )
        return aggregate

    # ---------------------------------------------------------------- control
    def cancel(self, task_id: str) -> Result:
        """取消一个仍在跑的任务。已落定的任务不可取消，也不回改历史。"""
        wanted = _clean(task_id, 64)
        task = self.db.get_task(wanted)
        if task is None:
            raise OrchestratorError("not_found", wanted)
        if task.get("status") != "running":
            raise OrchestratorError("not_cancellable", f"状态 {task.get('status')} 不可取消")
        holder = self._inflight.get(wanted)
        self._cancelled.add(wanted)
        if holder is None:
            # 没有在本进程里挂着协程（例如重启后遗留的 running 行）：直接落终态收口。
            self.stats["cancelled"] += 1
            final = self.db.update_task(
                wanted, status="cancelled", error_code="cancelled",
                detail="orphan", finished_at=self.clock(),
            )
            self._audit("cancelled", "warn", final or task, detail="cancelled")
            return final or task
        holder.cancel()
        return self.db.get_task(wanted) or task

    def replay(self, correlation_id: str, *, limit: int = 500) -> Result:
        """按关联号回放整条编排链：任务树 + 审计序列，时间正序。"""
        thread = _clean(correlation_id, 64)
        if not thread:
            raise OrchestratorError("bad_args", "replay 需要 correlation_id")
        tasks = self.db.list_tasks(correlation_id=thread, limit=limit)
        audit = self.db.audit_replay(thread, limit=limit)
        if not tasks and not audit:
            raise OrchestratorError("not_found", thread)
        by_capability: Dict[str, int] = {}
        for row in tasks:
            by_capability[row["capability"]] = by_capability.get(row["capability"], 0) + 1
        return {
            "correlation_id": thread,
            "tasks": tasks,
            "tree": self._tree(tasks),
            "audit": audit,
            "events": len(audit),
            "capabilities": by_capability,
            "statuses": {s: sum(1 for t in tasks if t["status"] == s) for s in
                         {t["status"] for t in tasks}},
            "span_ms": round(
                (max((t.get("finished_at") or 0.0 for t in tasks), default=0.0)
                 - min((t.get("created_at") or 0.0 for t in tasks), default=0.0)) * 1000.0,
                3,
            ),
        }

    # ----------------------------------------------------------------- policy
    def _grant_timeout(self, origin: str, target: str, capability: str) -> float:
        grant = None
        try:
            grant = self.db.find_grant(origin, target, capability)
        except LedgerError:
            grant = None
        return float(grant["timeout_seconds"]) if grant else TASK_TIMEOUT_MIN_SECONDS

    def _policy_refusal(
        self, origin: str, target: str, capability: str, args: Mapping[str, Any],
        *, hops: int, parent_id: str,
    ) -> Optional[Tuple[str, str]]:
        """返回 ``(reason_code, detail)`` 表示拒绝；``None`` 表示放行。"""
        grant = self.db.find_grant(origin, target, capability)
        if grant is None:
            return ("no_grant", f"{origin}→{target}:{capability} 无生效授权")
        if hops > int(grant["max_hops"]):
            return ("hop_budget", f"hops {hops} > {grant['max_hops']}")
        if int(grant["max_hops"]) > MAX_TASK_HOPS:
            return ("hop_budget", f"授权跳数 {grant['max_hops']} 超全局 {MAX_TASK_HOPS}")
        chain = self._ancestry(parent_id)
        # 栈上的 Bot = 链上每一跳的发起方与接收方。新目标只要已经在栈上就是回环：
        # 只比"目标对目标"会漏掉最典型的 A→B→A（A 在链上是发起方，不是接收方）。
        stack = {node for hop in chain for node in hop}
        if target in stack:
            return ("cycle", f"{target} 已在祖先链 {len(chain)} 跳内")
        running = self.db.count_active_tasks(target, capability)
        if running >= int(grant["max_concurrent"]):
            return ("busy", f"{running}/{grant['max_concurrent']} running")
        return None

    def _inherit_thread(self, parent_id: str) -> str:
        """调用方没给关联号时沿用父任务的 —— 一条链共用一个号，回放才拼得出整棵树。

        没有这条继承，``replay`` 只能看见被点名的那一跳，子链散落在各自的线程里；
        而"跨 Agent 调用可审计"要回答的恰恰是整条链。父行读不到就当没有，另起新号。
        """
        wanted = _clean(parent_id, 64)
        if not wanted:
            return ""
        row = self.db.get_task(wanted)
        return str(row.get("correlation_id") or "") if row else ""

    def _ancestry(self, parent_id: str) -> List[Tuple[str, str]]:
        """沿 ``parent_id`` 上溯，返回 ``(origin, target)`` 序列；带跳数上限防死循环。"""
        chain: List[Tuple[str, str]] = []
        seen: set[str] = set()
        cursor = _clean(parent_id, 64)
        while cursor and cursor not in seen and len(chain) < MAX_TASK_HOPS:
            seen.add(cursor)
            row = self.db.get_task(cursor)
            if row is None:
                break
            chain.append((str(row.get("origin_bot_id") or ""), str(row.get("target_bot_id") or "")))
            cursor = str(row.get("parent_id") or "")
        return chain

    def _tree(self, tasks: Sequence[Mapping[str, Any]]) -> List[Result]:
        """把同一关联号下的扁平任务列表还原成森林；父行不在本次结果里的算一棵根。"""
        index: Dict[str, Result] = {}
        roots: List[Result] = []
        for row in tasks:
            index[str(row.get("id") or "")] = {
                "task_id": row.get("id", ""),
                "origin_bot_id": row.get("origin_bot_id", ""),
                "target_bot_id": row.get("target_bot_id", ""),
                "capability": row.get("capability", ""),
                "status": row.get("status", ""),
                "error_code": row.get("error_code", ""),
                "children": [],
            }
        for row in tasks:
            node = index[str(row.get("id") or "")]
            parent = str(row.get("parent_id") or "")
            if parent and parent in index:
                index[parent]["children"].append(node)
            else:
                roots.append(node)
        return roots

    # ------------------------------------------------------------------ audit
    def _audit(self, event: str, level: str, task: Mapping[str, Any], *, detail: str = "") -> None:
        self.db.log_negotiation(
            "orchestrator",
            event,
            bot_id=str(task.get("origin_bot_id") or ""),
            level=level,
            correlation_id=str(task.get("correlation_id") or ""),
            chat_ref=str(task.get("target_bot_id") or ""),
            detail=detail[:180],
            data={"task_id": str(task.get("id") or ""), "capability": str(task.get("capability") or ""),
                  "hops": int(task.get("hops") or 1)},
            latency_ms=float(task.get("latency_ms") or 0.0),
        )

    def _audit_raw(self, event: str, level: str, *, origin: str, thread: str, detail: str) -> None:
        self.db.log_negotiation(
            "orchestrator", event, bot_id=_clean(origin, 64), level=level,
            correlation_id=thread, detail=detail[:180],
        )

    # --------------------------------------------------------------- executor
    async def _invoke(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> Any:
        executor = self._executors.get(str(task.get("capability") or ""))
        if executor is None:  # 注册与派发之间被 unregister 掉了
            raise OrchestratorError("unknown_capability", str(task.get("capability") or ""))
        context = {
            "task_id": str(task.get("id") or ""),
            "bot_id": str(task.get("target_bot_id") or ""),
            "origin_bot_id": str(task.get("origin_bot_id") or ""),
            "capability": str(task.get("capability") or ""),
            "args": dict(payload),
            "correlation_id": str(task.get("correlation_id") or ""),
            "hops": int(task.get("hops") or 1),
            "deadline_seconds": float(task.get("timeout_seconds") or 0.0),
        }
        try:
            outcome = executor(context)
        except OrchestratorError:
            raise
        except Exception as exc:  # noqa: BLE001 - 同步实现抛错也归一成 executor_error
            raise OrchestratorError("executor_error", _brief(exc)) from exc
        if inspect.isawaitable(outcome):
            outcome = await outcome
        return outcome

    def _settle_failed(
        self, task_id: str, running: Mapping[str, Any], exc: OrchestratorError, started: float
    ) -> Result:
        self.stats["failed"] += 1
        elapsed = (self.monotonic() - started) * 1000.0
        final = self.db.update_task(
            task_id,
            status="failed",
            error_code=exc.code,
            detail=exc.detail[:180],
            finished_at=self.clock(),
            latency_ms=round(elapsed, 3),
        )
        self._audit("failed", "error", final or running, detail=exc.code)
        return final or running


def _dump_result(outcome: Mapping[str, Any]) -> str:
    """结果落库前的唯一出口：序列化 + 体积闸。超限直接判失败，不截断半截 JSON。"""
    try:
        blob = json.dumps(dict(outcome), ensure_ascii=False, default=str, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise OrchestratorError("executor_error", f"结果无法序列化 {_brief(exc)}") from exc
    if len(blob) > TASK_RESULT_MAX_CHARS:
        raise OrchestratorError(
            "executor_error", f"结果 {len(blob)} 字符超过 {TASK_RESULT_MAX_CHARS} 上限"
        )
    return blob


__all__ = (
    "CAPABILITY_SPECS",
    "FANOUT_BUDGET_MAX_SECONDS",
    "FANOUT_MAX_DEFAULT",
    "GRANT_WILDCARD",
    "Orchestrator",
    "OrchestratorError",
    "REASONS",
    "validate_args",
)
