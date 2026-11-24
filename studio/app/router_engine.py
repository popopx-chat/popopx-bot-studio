"""Message routing engine.

The engine is a pure planner: it turns one inbound message into zero or more
:class:`ForwardPlan` objects. Executing a plan (sending over the CLI websocket)
is the caller's job, which keeps routing decisions testable offline.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .database import Database
from .rule_engine import InboundMessage, default_context, interpolate

MAX_TICKETS = 2048
TICKET_PREFIX = "#T"
TICKET_HEX_LEN = 6

#: An operator answer: the ticket token, an optional separator, then the body.
TICKET_REPLY_RE = re.compile(
    r"^\s*(?P<ticket>#?T[0-9A-Fa-f]{%d})(?![0-9A-Za-z])[:：,，]?\s*(?P<body>.*)$"
    % TICKET_HEX_LEN,
    re.IGNORECASE | re.DOTALL,
)


class RouterError(ValueError):
    """Raised for an unusable routing definition."""


@dataclass
class ForwardPlan:
    """One outbound message the caller must deliver."""

    rule_id: int
    target_type: str
    target_ref: str
    text: str
    quote: bool = False
    quoted_ref: str = ""
    ticket_id: str = ""
    reason: str = "matched"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "target_type": self.target_type,
            "target_ref": self.target_ref,
            "text": self.text,
            "quote": self.quote,
            "quoted_ref": self.quoted_ref,
            "ticket_id": self.ticket_id,
            "reason": self.reason,
        }


@dataclass
class RouteDecision:
    plans: List[ForwardPlan] = field(default_factory=list)
    status: str = "no_match"
    matched_rules: List[int] = field(default_factory=list)
    reply_to_sender: str = ""

    @property
    def forwarded(self) -> bool:
        return bool(self.plans)


def parse_targets(target_ref: str) -> List[str]:
    """Split a routing target into individual refs (``a,b`` or ``["a","b"]``)."""
    raw = (target_ref or "").strip()
    if not raw:
        return []
    if raw.startswith("["):
        try:
            values = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RouterError(f"转发目标 JSON 不可解析：{exc}") from exc
        return [str(value).strip() for value in values if str(value).strip()]
    return [part.strip() for part in re.split(r"[,;]", raw) if part.strip()]


def new_ticket_id() -> str:
    return f"{TICKET_PREFIX}{secrets.token_hex(TICKET_HEX_LEN // 2).upper()}"


class TicketRegistry:
    """Bounded map from a group ticket back to the originating direct chat."""

    def __init__(self, limit: int = MAX_TICKETS):
        self.limit = max(16, int(limit))
        self._items: "OrderedDict[Tuple[str, str], Dict[str, Any]]" = OrderedDict()

    def open_ticket(
        self,
        *,
        bot_id: str,
        group_ref: str,
        chat_ref: str,
        sender: str,
        sender_name: str = "",
        summary: str = "",
    ) -> str:
        token = secrets.token_hex(TICKET_HEX_LEN // 2).upper()
        key = (bot_id, token)
        self._items[key] = {
            "ticket_id": f"{TICKET_PREFIX}{token}",
            "group_ref": group_ref,
            "chat_ref": chat_ref,
            "sender": sender,
            "sender_name": sender_name or sender,
            "summary": summary,
            "opened_at": time.time(),
            "answers": 0,
        }
        self._items.move_to_end(key)
        while len(self._items) > self.limit:
            self._items.popitem(last=False)
        return f"{TICKET_PREFIX}{token}"

    @staticmethod
    def _normalize(token: str) -> str:
        """Accept ``#TABC12``, ``TABC12`` or ``ABC12`` and return the hex part."""
        cleaned = (token or "").strip().lstrip("#").upper()
        if cleaned.startswith(TICKET_PREFIX[1:]):  # "T"
            cleaned = cleaned[1:]
        return cleaned

    def resolve(self, bot_id: str, token: str) -> Optional[Dict[str, Any]]:
        key = (bot_id, self._normalize(token))
        record = self._items.get(key)
        if record is not None:
            self._items.move_to_end(key)
        return record

    def mark_answered(self, bot_id: str, token: str) -> Optional[Dict[str, Any]]:
        record = self.resolve(bot_id, token)
        if record is not None:
            record["answers"] = int(record["answers"]) + 1
            record["answered_at"] = time.time()
        return record

    def open_tickets(self, bot_id: Optional[str] = None) -> List[Dict[str, Any]]:
        records = []
        for (bot, token), record in self._items.items():
            if bot_id is not None and bot != bot_id:
                continue
            records.append({"bot_id": bot, "token": token, **record})
        return records

    def __len__(self) -> int:
        return len(self._items)


class RouterEngine:
    """Evaluate routing rules and build the delivery plans."""

    def __init__(
        self,
        database: Database,
        *,
        bot_name: str = "",
        clock: Callable[[], float] = time.time,
        tickets: Optional[TicketRegistry] = None,
        default_template: str = "[{source_type}] {sender_name}: {text}",
    ):
        self.db = database
        self.bot_name = bot_name
        self._clock = clock
        self.tickets = tickets if tickets is not None else TicketRegistry()
        self.default_template = default_template
        self._cooldowns: Dict[Tuple[str, int, str], float] = {}
        self._rules_cache: Optional[Dict[str, List[Dict[str, Any]]]] = None

    def invalidate_cache(self) -> None:
        self._rules_cache = {}

    def enabled_rules(self, bot_id: str, *, force: bool = False) -> List[Dict[str, Any]]:
        """Routing rules of one Bot, cached per Bot id so Bot B never inherits
        Bot A's cached plan set."""
        cached = (self._rules_cache or {}).get(bot_id)
        if cached is not None and not force:
            return cached
        rows = self.db.list_routing_rules(bot_id, enabled_only=True)
        if self._rules_cache is None:
            self._rules_cache = {}
        self._rules_cache[bot_id] = rows
        if len(self._rules_cache) > 256:
            self._rules_cache.pop(next(iter(self._rules_cache)), None)
        return rows

    # -------------------------------------------------------------- matching
    def _source_matches(self, rule: Dict[str, Any], message: InboundMessage) -> bool:
        source_type = str(rule["source_type"])
        if source_type == "any":
            return True
        if source_type != message.chat_type:
            return False
        source_ref = str(rule["source_ref"] or "").strip()
        if not source_ref:
            return True
        return message.chat_ref.casefold() == source_ref.casefold()

    def _keyword_matches(self, rule: Dict[str, Any], message: InboundMessage) -> bool:
        mode = str(rule.get("keyword_mode") or "any")
        if mode == "any":
            return True
        keywords = rule.get("keywords") or []
        if isinstance(keywords, str):
            keywords = json.loads(keywords or "[]")
        if not keywords:
            return False
        text = message.normalized
        lowered = text.casefold()
        if mode == "contains":
            return any(str(kw).casefold() in lowered for kw in keywords)
        if mode == "exact":
            return any(lowered == str(kw).casefold() for kw in keywords)
        if mode == "regex":
            for keyword in keywords:
                try:
                    if re.search(str(keyword), text, re.IGNORECASE):
                        return True
                except re.error as exc:
                    raise RouterError(f"路由正则不可用：{exc}") from exc
            return False
        return False

    def _cooldown_active(self, bot_id: str, rule_id: int, sender: str, now: float) -> bool:
        key = (bot_id, rule_id, sender)
        expires_at = self._cooldowns.get(key)
        if expires_at is None:
            return False
        if expires_at <= now:
            self._cooldowns.pop(key, None)
            return False
        return True

    # ------------------------------------------------------------------ plan
    def plan(self, message: InboundMessage) -> RouteDecision:
        """Return every delivery plan triggered by *message*."""
        now = self._clock()
        decision = RouteDecision()
        bot = self.db.get_bot(message.bot_id)
        bot_name = self.bot_name or (bot["name"] if bot else "")
        context = default_context(
            sender_name=message.sender_name,
            sender=message.sender,
            bot_name=bot_name,
            text=message.normalized,
            chat_ref=message.chat_ref,
            chat_type=message.chat_type,
            now=now,
        )
        for rule in self.enabled_rules(message.bot_id):
            if not self._source_matches(rule, message):
                continue
            if not self._keyword_matches(rule, message):
                continue
            rule_id = int(rule["id"])
            if self._cooldown_active(message.bot_id, rule_id, message.sender, now):
                decision.status = "cooldown"
                continue
            seconds = int(rule.get("cooldown_seconds") or 0)
            if seconds > 0:
                self._cooldowns[(message.bot_id, rule_id, message.sender)] = now + seconds
            decision.matched_rules.append(rule_id)

            targets = (
                self._broadcast_targets(message.bot_id, rule)
                if rule["target_type"] == "broadcast"
                else parse_targets(str(rule["target_ref"]))
            )
            if not targets:
                decision.status = "no_target"
                continue

            scoped = dict(context)
            scoped["source_type"] = message.chat_type
            scoped["source_ref"] = message.chat_ref
            template = str(rule.get("template") or "") or self.default_template
            ticket_id = ""
            if rule["target_type"] == "group" and message.chat_type == "direct":
                ticket_id = self.tickets.open_ticket(
                    bot_id=message.bot_id,
                    group_ref=targets[0],
                    chat_ref=message.chat_ref or message.sender,
                    sender=message.sender,
                    sender_name=message.sender_name,
                    summary=message.normalized[:160],
                )
                scoped["ticket_id"] = ticket_id
            for target in targets:
                scoped["target_ref"] = target
                text = interpolate(template, scoped)
                if ticket_id and TICKET_PREFIX not in text:
                    text = f"[{ticket_id}] {text}"
                decision.plans.append(
                    ForwardPlan(
                        rule_id=rule_id,
                        # A broadcast expands to concrete group deliveries; only the
                        # plan target the caller can actually address.
                        target_type="contact" if rule["target_type"] == "contact" else "group",
                        target_ref=target,
                        text=text,
                        quote=bool(rule.get("quote_reply")) and message.chat_type == "direct",
                        quoted_ref=message.chat_ref or message.sender,
                        ticket_id=ticket_id,
                    )
                )
            ack = str(rule.get("name") or "")
            if rule["target_type"] == "group" and message.chat_type == "direct":
                decision.reply_to_sender = decision.reply_to_sender or interpolate(
                    "已收到您的咨询 {ticket_id}，已转交客服群组处理。" if ticket_id else "已转交客服群组处理。",
                    {"ticket_id": ticket_id, "bot_name": bot_name, **scoped},
                )
        if decision.plans:
            decision.status = "forwarded"
        elif decision.status == "no_match" and not decision.matched_rules:
            decision.status = "no_match"
        return decision

    def _broadcast_targets(self, bot_id: str, rule: Dict[str, Any]) -> List[str]:
        """Expand a broadcast rule into every group the Bot is a member of."""
        explicit = parse_targets(str(rule["target_ref"]))
        if explicit:
            return explicit
        return self.known_groups(bot_id)

    def known_groups(self, bot_id: str) -> List[str]:
        """Distinct ``#<gid>`` refs previously observed for this Bot.

        Sorted so that a broadcast expands into a stable delivery order
        regardless of which group happened to message most recently.
        """
        rows = self.db.recent_logs(bot_id, limit=500)
        groups = set()
        for row in rows:
            ref = str(row["chat_ref"] or "")
            if str(row["chat_type"]) == "group" and ref.startswith("#"):
                groups.add(ref)
        return sorted(groups)

    # -------------------------------------------------------- operator reply
    def reply_to_ticket(self, bot_id: str, text: str, *, sender: str = "") -> Tuple[Optional[Dict[str, Any]], str]:
        """Resolve an operator answer into a direct-chat delivery.

        The ticket token must lead the message (``#T1a2b3c 已处理``). Requiring
        it up front keeps a passing mention in normal chat from being delivered
        to the customer, and stops the Bot from answering the forwarded message
        it posted into the group itself (that one starts with ``[#T…]``).
        """
        match = TICKET_REPLY_RE.match(text or "")
        if not match:
            return None, ""
        token = match.group("ticket")
        record = self.tickets.resolve(bot_id, token)
        if record is None:
            return None, ""
        body = match.group("body").strip()
        if not body:
            return None, ""
        self.tickets.mark_answered(bot_id, token)
        return {
            "chat_ref": record["chat_ref"],
            "sender_name": record["sender_name"],
            "ticket_id": record["ticket_id"],
        }, interpolate(
            body, {"ticket_id": token.upper(), "operator": sender, "text": body}
        )

    def stats(self, bot_id: Optional[str] = None) -> Dict[str, Any]:
        return {
            "open_tickets": len(self.tickets.open_tickets(bot_id)),
            "rules": len(self.db.list_routing_rules(bot_id or "", enabled_only=False)),
        }
