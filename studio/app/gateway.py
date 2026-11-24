"""消息网关：把 CLI 事件、插件总线、自动回复与路由引擎串成一条流水线。

数据流：

``popopx-cli --(ws event)--> BotSupervisor.handle_event --> BotGateway.process``

``process`` 依次尝试：插件总线 -> 零代码规则 -> 路由转发，并把结果写回
``message_logs`` 供后台与 Open API 读取。任何一步抛错都只影响当前消息，
网关本身绝不中断。
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple

from .bot_supervisor import BotSupervisor, BotSupervisorError
from .database import Database
from .plugin_manager import PASS, PluginManager
from .router_engine import RouterEngine
from .rule_engine import InboundMessage, RuleEngine
from .ws_protocol import CLICommandError, NormalizedEvent, WebSocketProtocolError

SEND_TYPES = ("newChatItems", "contactConnected", "receivedContactRequest")
MAX_UPDATES = 500


@dataclass
class ProcessResult:
    """What the pipeline decided for one inbound event."""

    bot_id: str
    handled_by: str = ""
    replied: bool = False
    forwarded: int = 0
    status: str = "ignored"
    reply_text: str = ""
    plans: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "bot_id": self.bot_id,
            "handled_by": self.handled_by,
            "replied": self.replied,
            "forwarded": self.forwarded,
            "status": self.status,
            "reply_text": self.reply_text,
            "plans": self.plans,
            "error": self.error,
        }


class UpdateBuffer:
    """Per-Bot ring buffer backing ``GET /getUpdates``."""

    def __init__(self, maxlen: int = MAX_UPDATES):
        self.maxlen = maxlen
        self._items: Dict[str, Deque[Dict[str, Any]]] = {}
        self._next = 1

    def add(self, bot_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        update = {"update_id": self._next, "bot_id": bot_id, **payload}
        self._next += 1
        self._items.setdefault(bot_id, deque(maxlen=self.maxlen)).append(update)
        return update

    def take(self, bot_id: str, *, offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        items = list(self._items.get(bot_id, ()))
        if offset:
            items = [item for item in items if int(item["update_id"]) > offset]
        return items[-int(limit):] if limit else items

    def latest(self, bot_id: str) -> int:
        items = self._items.get(bot_id)
        return int(items[-1]["update_id"]) if items else 0

    def __len__(self) -> int:
        return sum(len(items) for items in self._items.values())


class BotGateway:
    """Event pipeline shared by the WebSocket supervisor, the admin API and plugins."""

    def __init__(
        self,
        settings: Any,
        database: Database,
        supervisor: BotSupervisor,
        rules: RuleEngine,
        router: RouterEngine,
        plugins: Optional[PluginManager] = None,
        *,
        max_updates: int = MAX_UPDATES,
    ):
        self.settings = settings
        self.db = database
        self.supervisor = supervisor
        self.rules = rules
        self.router = router
        self.plugins = plugins
        self.updates = UpdateBuffer(maxlen=max_updates)
        self.delivered = 0
        self.errors: List[str] = []
        self.started_at = time.time()
        self._sends: Dict[str, int] = {}

    # ------------------------------------------------------------- ingestion
    async def handle_event(self, bot_id: str, event: NormalizedEvent) -> None:
        """``BotSupervisor.on_event`` entry point for every normalized CLI event."""
        if event.event_type == "newChatItems":
            await self.process(bot_id, event)
            return
        if event.event_type in ("receivedContactRequest", "contactConnected"):
            self.updates.add(bot_id, {"event": event.event_type, "chat_ref": event.chat_ref, "text": event.text})
            if self.plugins is not None:
                await self.plugins.handle_event(event, bot_id=bot_id)

    async def process(self, bot_id: str, event: NormalizedEvent) -> ProcessResult:
        """Run one inbound message through plugins, rules and routing."""
        result = ProcessResult(bot_id=bot_id)
        if event.direction != "in" or not event.text.strip():
            result.status = "skipped"
            return result
        message = InboundMessage(
            bot_id=bot_id,
            text=event.text,
            chat_type="group" if event.chat_type == "group" else "direct",
            chat_ref=event.chat_ref,
            sender=event.sender or event.chat_ref,
            sender_name=event.sender_name or event.chat_name or event.sender,
            ts=event.ts or time.time(),
            raw=dict(event.raw),
        )
        self.db.log_message(
            bot_id,
            "in",
            chat_type=message.chat_type,
            chat_ref=message.chat_ref,
            sender=message.sender,
            text=message.text[:2000],
            status="ok",
        )
        self.updates.add(
            bot_id,
            {
                "event": "message",
                "chat_type": message.chat_type,
                "chat_ref": message.chat_ref,
                "sender": message.sender,
                "sender_name": message.sender_name,
                "text": message.text,
                "ts": message.ts,
            },
        )
        if self.plugins is not None:
            try:
                outcomes = await self.plugins.handle_message(message, bot_id=bot_id)
            except Exception as exc:
                result.error = f"插件总线异常 {type(exc).__name__}: {exc}"
                self.errors.append(result.error)
                outcomes = []
            for plugin_id, outcome in outcomes:
                if not outcome.handled:
                    continue
                result.handled_by = plugin_id
                reply = outcome.reply or str((outcome.reply_content or {}).get("text") or "")
                if reply:
                    result.replied = await self._send(
                        bot_id, message.chat_ref, reply, quoted_item_id=event.item_id
                    )
                    result.reply_text = reply
                for forward in outcome.forwards or []:
                    target = str(forward.get("chat_ref") or forward.get("target") or "")
                    body = str(forward.get("text") or "")
                    if target and body and await self._send(bot_id, target, body):
                        result.forwarded += 1
                result.status = "plugin" if result.replied or result.forwarded else "plugin_handled"
                return result

        decision = self.rules.evaluate(message)
        if decision.rule_id is not None:
            self.db.register_rule_hit(int(decision.rule_id))
        route = self.router.plan(message)
        # A routed enquiry already reaches the support group, so the catch-all
        # "没有理解" reply would only add noise on top of the ticket receipt.
        suppress_default = bool(route.matched_rules) and decision.trigger_type == "default"
        if decision.should_send and decision.reply and not suppress_default:
            sent = await self._send(bot_id, message.chat_ref, decision.reply, quoted_item_id=event.item_id)
            result.replied = sent
            result.handled_by = "rules"
            result.reply_text = decision.reply
            result.status = decision.status
        elif suppress_default:
            result.status = "routed"

        if route.matched_rules:
            result.plans = [plan.as_dict() for plan in route.plans]
            for plan in route.plans:
                if await self._send(
                    bot_id, plan.target_ref, plan.text, quoted_item_id=event.item_id if plan.quote else None
                ):
                    result.forwarded += 1
            if route.reply_to_sender and not result.replied:
                if await self._send(bot_id, message.chat_ref, route.reply_to_sender):
                    result.replied = True
            if route.forwarded:
                result.status = "forwarded"
                result.handled_by = result.handled_by or "router"
        if not result.replied and not result.forwarded and result.status == "ignored":
            result.status = route.status or "no_match"
        self.db.log_message(
            bot_id,
            "out",
            chat_type=message.chat_type,
            chat_ref=message.chat_ref,
            sender=message.sender,
            text=(result.reply_text or f"forwarded={result.forwarded}")[:2000],
            status="ok" if (result.replied or result.forwarded) else result.status,
        )
        return result

    async def deliver(self, bot_id: str, chat_ref: str, text: str, *, quoted_item_id: Optional[int] = None) -> bool:
        """Public send used by the Open API and by plugins."""
        return await self._send(bot_id, chat_ref, text, quoted_item_id=quoted_item_id)

    async def _send(self, bot_id: str, chat_ref: str, text: str, *, quoted_item_id: Optional[int] = None) -> bool:
        if not chat_ref or not text:
            return False
        try:
            await self.supervisor.send_text(bot_id, chat_ref, text, quoted_item_id=quoted_item_id)
        except (BotSupervisorError, WebSocketProtocolError, CLICommandError, OSError, asyncio.TimeoutError) as exc:
            note = f"发送失败 {chat_ref}: {type(exc).__name__}: {exc}"[:300]
            self.errors.append(note)
            self.errors[:] = self.errors[-50:]
            self.db.log_message(bot_id, "out", chat_ref=chat_ref, text=text[:2000], status="error", error=note)
            return False
        self.delivered += 1
        self._sends[bot_id] = self._sends.get(bot_id, 0) + 1
        return True

    # -------------------------------------------------------- operator reply
    async def operator_reply(self, bot_id: str, group_ref: str, text: str, *, operator: str = "") -> Dict[str, Any]:
        """Turn ``#Txxxx 回答`` typed in a support group into a direct message."""
        record, body = self.router.reply_to_ticket(bot_id, text, sender=operator)
        if record is None:
            return {"delivered": False, "reason": "未找到工单编号"}
        chat_ref = str(record.get("chat_ref") or "")
        if not chat_ref:
            return {"delivered": False, "reason": "工单缺少原始会话"}
        ok = await self._send(bot_id, chat_ref, body)
        self.updates.add(
            bot_id,
            {
                "event": "ticket_answered",
                "chat_ref": chat_ref,
                "ticket_id": record.get("ticket_id", ""),
                "text": body,
                "ts": time.time(),
            },
        )
        return {"delivered": ok, "chat_ref": chat_ref, "ticket_id": record.get("ticket_id", ""), "text": body}

    # ----------------------------------------------------------------- misc
    def get_updates(self, bot_id: str, *, offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        return self.updates.take(bot_id, offset=offset, limit=limit)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "delivered": self.delivered,
            "queued_updates": len(self.updates),
            "errors": self.errors[-10:],
            "uptime": time.time() - self.started_at,
            "sends_by_bot": dict(self._sends),
        }


__all__ = ["BotGateway", "ProcessResult", "UpdateBuffer", "MAX_UPDATES"]
