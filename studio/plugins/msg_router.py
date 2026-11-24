"""msg_router — 跨会话/跨群组路由与工单桥接（prompt.md §3.8）.

Complement, never compete: ``RouterEngine`` already owns the ``routing_rules``
ledger (it opens ``#T……`` tickets for direct→group rules and answers them through
``BotGateway.operator_reply``). This plugin adds *plugin-scoped* routes declared
in its own config, and it stands down whenever a ledger rule would act on the same
message — the bus stops at the first ``handled`` result, so an eager plugin would
otherwise hide the operator's routing table.

Ticket ids use their own prefix (default ``TK-``) so ``router_engine.TICKET_REPLY_RE``
(``#?T`` + 6 hex) can never claim one, and an operator message quoting a core
ticket falls straight through to the core path.

The ledger has no tickets table (schema v4: bots / reply_rules / message_logs /
routing_rules / plugin_configs), so — exactly like the core registry — ticket state
lives in bounded in-memory maps and is rebuilt by nothing after a restart.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

from app.plugin_manager import PASS, PluginResult, StudioPlugin
from app.rule_engine import default_context, interpolate

log = logging.getLogger("popopx.studio.plugin.msg_router")

PLUGIN_ID = "msg_router"
MAX_TEXT = 4000
CORE_TICKET_LIKE = ("T", "#T")  # prefixes the core regex would also match


class Inbound:
    """``InboundMessage`` from the bus, or a dict from a test — same reader for both."""

    __slots__ = ("bot_id", "chat_type", "chat_ref", "text", "sender", "sender_name", "ts", "raw")

    def __init__(self, bot_id: str = "", chat_type: str = "direct", chat_ref: str = "", text: str = "",
                 sender: str = "", sender_name: str = "", ts: float = 0.0, raw: Optional[Dict[str, Any]] = None):
        self.bot_id = bot_id
        self.chat_type = chat_type
        self.chat_ref = chat_ref
        self.text = text
        self.sender = sender
        self.sender_name = sender_name
        self.ts = ts
        self.raw = raw or {}

    @classmethod
    def of(cls, event: Any) -> "Inbound":
        def pick(key: str, default: Any = "") -> Any:
            return event.get(key, default) if isinstance(event, dict) else getattr(event, key, default)

        return cls(
            bot_id=str(pick("bot_id", "")),
            chat_type=str(pick("chat_type", "direct") or "direct"),
            chat_ref=str(pick("chat_ref", "") or pick("chat_id", "")),
            text=str(pick("text", "") or "").strip(),
            sender=str(pick("sender", "")),
            sender_name=str(pick("sender_name", "") or pick("sender", "")),
            ts=float(pick("ts", 0.0) or 0.0),
            raw=dict(pick("raw", {}) or {}),
        )


def as_list(value: Any) -> List[Any]:
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return []
        try:
            value = json.loads(raw)
        except (ValueError, TypeError):
            return [part.strip() for part in re.split(r"[,;]", raw) if part.strip()]
    if isinstance(value, dict):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return []


def as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on", "y")
    return default


def as_number(value: Any, default: float) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return default
    return default


def split_targets(value: Any) -> List[str]:
    """Accept ``"#a,#b"``, ``["#a"]`` or ``[{"chat_ref": "#a", "chat_type": "group"}]``."""
    refs: List[str] = []
    for item in as_list(value):
        if isinstance(item, dict):
            ref = str(item.get("chat_ref") or item.get("target") or item.get("id") or "").strip()
        else:
            ref = str(item).strip()
        if ref and ref not in refs:
            refs.append(ref)
    return refs


def target_kinds(value: Any) -> Dict[str, str]:
    kinds: Dict[str, str] = {}
    for item in as_list(value):
        if isinstance(item, dict):
            ref = str(item.get("chat_ref") or item.get("target") or "").strip()
            if ref:
                kinds[ref] = str(item.get("chat_type") or item.get("type") or "group")
    return kinds


class MsgRouterPlugin(StudioPlugin):
    plugin_id = "msg_router"
    name = "消息路由与工单桥 / Msg router"
    version = "1.0.0"
    description = "插件级跨会话/跨群路由：客户单聊按关键词建工单转群，群内以工单号回帖自动转回客户"
    priority = 65
    scope = "message"

    config_fields = [
        {"key": "enabled", "type": "bool", "label": "启用插件 / Master switch"},
        {"key": "defer_to_core", "type": "bool", "label": "优先让 routing_rules 处理（防重复转发）"},
        {"key": "routes", "type": "json", "label": "路由规则 [{name,keywords,mode,source,targets,template,receipt}]，targets 留空则投递到 Bot 已知的群组（如 [\"#42\"]）"},
        {"key": "ticket_prefix", "type": "text", "label": "工单前缀（勿用 T/#T）"},
        {"key": "ticket_ttl_hours", "type": "number", "label": "工单有效期（小时）"},
        {"key": "max_tickets", "type": "number", "label": "内存工单上限"},
        {"key": "route_group_replies", "type": "bool", "label": "群内回帖转回客户"},
        {"key": "ack_in_group", "type": "bool", "label": "回帖后在群里确认"},
        {"key": "group_template", "type": "textarea", "label": "群内通知模板"},
        {"key": "customer_receipt", "type": "textarea", "label": "客户回执模板"},
        {"key": "customer_answer_template", "type": "textarea", "label": "转回客户的回帖模板"},
        {"key": "route_cooldown_seconds", "type": "number", "label": "同一发送人路由冷却（秒）"},
    ]

    default_config = {
        "enabled": True,
        "defer_to_core": True,
        "routes": [
            {
                "name": "售后",
                "keywords": ["退款", "坏了", "broken", "refund"],
                "mode": "contains",
                "source": "direct",
                "targets": [],
                "template": "[{ticket_id}] {sender_name}（{chat_ref}）：{text}",
                "receipt": "已建立工单 {ticket_id}，客服会在此会话回复。",
            },
            {
                "name": "商务",
                "keywords": ["报价", "合作", "price"],
                "mode": "contains",
                "source": "direct",
                "targets": [],
                "template": "[{ticket_id}] 商务咨询 · {sender_name}：{text}",
                "receipt": "商务咨询已转给值班同学，工单号 {ticket_id}。",
            },
        ],
        "ticket_prefix": "TK-",
        "ticket_ttl_hours": 72,
        "max_tickets": 1024,
        "route_group_replies": True,
        "ack_in_group": True,
        "group_template": "[{ticket_id}] {sender_name}：{text}",
        "customer_receipt": "已收到工单 {ticket_id}，已转交群组处理。",
        "customer_answer_template": "{answer}\n—— 客服回复（工单 {ticket_id}）",
        "route_cooldown_seconds": 0,
    }

    def __init__(self) -> None:
        super().__init__()
        self._tickets: "OrderedDict[Tuple[str, str], Dict[str, Any]]" = OrderedDict()
        self._cooldowns: Dict[Tuple[str, str, str], float] = {}
        self._offline: Dict[str, float] = {}
        self._opened = 0
        self._relayed = 0
        self._expired = 0

    # ------------------------------------------------------------- lifecycle
    async def on_load(self, context: Any) -> None:
        self.context = context
        log.info("[msg_router] loaded: %d route(s), prefix=%s",
                 len(as_list(context.config_value("routes"))), self._prefix(context))

    async def on_enable(self, context: Any) -> None:
        self.context = context
        log.info("[msg_router] enabled (%d routes)", len(self._routes(context)))

    async def on_disable(self, context: Any) -> None:
        log.info("[msg_router] disabled: opened=%d relayed=%d expired=%d",
                 self._opened, self._relayed, self._expired)

    async def on_unload(self) -> None:
        self._tickets.clear()
        self._cooldowns.clear()

    # ---------------------------------------------------------------- dispatch
    async def on_message(self, event: Any, context: Any) -> PluginResult:
        if not as_bool(context.config_value("enabled", True), True):
            return PASS
        message = Inbound.of(event)
        if not message.text or not message.bot_id:
            return PASS
        if message.chat_type == "group":
            return await self._from_group(message, context)
        return await self._from_customer(message, context)

    # ---------------------------------------------------- customer -> group(s)
    async def _from_customer(self, message: Inbound, context: Any) -> PluginResult:
        route = self._match_route(message, context)
        if route is None:
            return PASS
        if as_bool(context.config_value("defer_to_core", True), True) and self._core_routes(message, context):
            log.debug("[msg_router] %s claimed by routing_rules, standing down", message.chat_ref)
            return PASS
        if not self._client_online(message.bot_id, context):
            return PASS
        now = float(context.clock())
        name = str(route.get("name") or "route")
        key = (message.bot_id, name, message.sender)
        cooldown = max(0.0, as_number(context.config_value("route_cooldown_seconds"), 0.0))
        if cooldown and now < self._cooldowns.get(key, 0.0):
            self._log(message, context, status="cooldown", text=f"{name}: cooldown")
            return PASS
        self._cooldowns[key] = now + cooldown
        if len(self._cooldowns) > 4096:
            self._cooldowns.pop(next(iter(self._cooldowns)), None)

        targets = split_targets(route.get("targets")) or self._known_groups(message.bot_id, context)
        if not targets:
            targets = self._known_groups(message.bot_id, context)
        if not targets:
            self._log(message, context, status="no_match", text=f"{name}: no target")
            return PASS
        kinds = target_kinds(route.get("targets"))
        ticket = self._open(message, context, name, targets[0])
        vars_ = self._vars(message, context, ticket)
        vars_["route"] = name
        template = str(route.get("template") or context.config_value("group_template")
                       or self.default_config["group_template"])
        notice = interpolate(template, vars_)[:MAX_TEXT]
        forwards = [{"chat_ref": ref, "chat_type": kinds.get(ref, "group"),
                     "text": notice if ref == targets[0] else self._relabel(notice, ticket, ref),
                     "ticket_id": ticket, "rule": name} for ref in targets]
        receipt = interpolate(str(route.get("receipt") or context.config_value("customer_receipt")
                                  or self.default_config["customer_receipt"]), vars_)
        self._opened += 1
        log.info("[msg_router] %s: %s -> %d target(s) ticket=%s", name, message.chat_ref, len(targets), ticket)
        return PluginResult(handled=True, reply=receipt[:MAX_TEXT], forwards=forwards, status="forwarded",
                            metadata={"plugin": PLUGIN_ID, "route": name, "ticket_id": ticket,
                                      "targets": targets})

    def _relabel(self, notice: str, ticket: str, ref: str) -> str:
        """Every target must carry the ticket token so an answer can be quoted back."""
        if ticket in notice:
            return notice
        return f"[{ticket}] {notice}"

    # ------------------------------------------------------- group -> customer
    async def _from_group(self, message: Inbound, context: Any) -> PluginResult:
        if not as_bool(context.config_value("route_group_replies", True), True):
            return PASS
        ticket, body = self._parse_ticket(message.text, context)
        if not ticket or not body:
            return PASS
        record = self._resolve(message.bot_id, ticket)
        if record is None:
            return PASS  # not ours: a core #T…… ticket, or a passing mention
        if record.get("closed"):
            return PASS
        record["answers"] = int(record.get("answers", 0)) + 1
        record["answered_at"] = float(context.clock())
        vars_ = self._vars(message, context, record["ticket_id"])
        vars_["answer"] = body
        text = interpolate(str(context.config_value("customer_answer_template")
                               or self.default_config["customer_answer_template"]), vars_)[:MAX_TEXT]
        forwards = [{"chat_ref": record["chat_ref"], "chat_type": "direct", "text": text or body,
                     "ticket_id": record["ticket_id"], "rule": "operator-reply"}]
        self._relayed += 1
        ack = f"已转达 {record['ticket_id']}" if as_bool(context.config_value("ack_in_group"), True) else ""
        log.info("[msg_router] %s -> customer %s (ticket %s)", message.chat_ref, record["chat_ref"],
                 record["ticket_id"])
        return PluginResult(handled=True, reply=ack, forwards=forwards, status="forwarded",
                            metadata={"plugin": PLUGIN_ID, "ticket_id": record["ticket_id"],
                                      "customer": record["chat_ref"]})

    # ------------------------------------------------------------------ timer
    async def on_tick(self, context: Any) -> None:
        ttl = max(0.0, as_number(context.config_value("ticket_ttl_hours"), 72.0) * 3600.0)
        if ttl <= 0:
            return
        now = float(context.clock())
        stale = [key for key, record in self._tickets.items() if now - float(record["opened_at"]) > ttl]
        for key in stale:
            self._tickets.pop(key, None)
        self._expired += len(stale)
        if stale:
            log.info("[msg_router] expired %d ticket(s), %d open", len(stale), len(self._tickets))

    # --------------------------------------------------------------- internals
    def _routes(self, context: Any) -> List[Dict[str, Any]]:
        return [item for item in as_list(context.config_value("routes")) if isinstance(item, dict)]

    def _match_route(self, message: Inbound, context: Any) -> Optional[Dict[str, Any]]:
        lowered = message.text.casefold()
        for route in self._routes(context):
            source = str(route.get("source") or "direct").strip().casefold()
            if source not in ("any", message.chat_type):
                continue
            keywords = [str(kw).casefold() for kw in as_list(route.get("keywords")) if str(kw).strip()]
            if not keywords:
                return route  # a rule without keywords is a catch-all for its source type
            mode = str(route.get("mode") or "contains").strip().casefold()
            for keyword in keywords:
                try:
                    if mode == "regex" and re.search(keyword, message.text, re.IGNORECASE):
                        return route
                    if mode == "exact" and lowered == keyword:
                        return route
                    if mode not in ("regex", "exact") and keyword in lowered:
                        return route
                except re.error as exc:
                    log.warning("[msg_router] bad keyword regex %r: %s", keyword, exc)
        return None

    def _core_routes(self, message: Inbound, context: Any) -> bool:
        """True when a ``routing_rules`` row would forward this message."""
        try:
            rules = context.db.list_routing_rules(message.bot_id, enabled_only=True)
        except Exception as exc:
            log.debug("[msg_router] list_routing_rules failed: %s", exc)
            return False
        lowered = message.text.casefold()
        for rule in rules or []:
            source_type = str(rule.get("source_type") or "any")
            if source_type != "any" and source_type != message.chat_type:
                continue
            source_ref = str(rule.get("source_ref") or "").strip().casefold()
            if source_ref and source_ref != message.chat_ref.casefold():
                continue
            mode = str(rule.get("keyword_mode") or "any")
            if mode == "any":
                return True
            keywords = as_list(rule.get("keywords"))
            for keyword in keywords:
                probe = str(keyword)
                try:
                    if mode == "regex" and re.search(probe, message.text, re.IGNORECASE):
                        return True
                    if mode == "exact" and lowered == probe.casefold():
                        return True
                    if mode == "contains" and probe.casefold() in lowered:
                        return True
                except re.error:
                    continue
        return False

    def _client_online(self, bot_id: str, context: Any) -> bool:
        """Nothing can be delivered without the CLI websocket, and the core pipeline
        would fail the same way — so pass and let the rules engine answer instead."""
        try:
            clients = list(context.services.clients() or [])
        except Exception as exc:
            log.debug("[msg_router] clients() failed: %s", exc)
            return True
        if bot_id in clients:
            return True
        now = float(context.clock())
        if now - self._offline.get(bot_id, 0.0) > 60:
            self._offline[bot_id] = now
            self._log_raw(context, bot_id, status="error", text="msg_router: 无已连接的 CLI 客户端",
                          error="client offline")
        return False

    def _prefix(self, context: Any) -> str:
        raw = str(context.config_value("ticket_prefix", self.default_config["ticket_prefix"]) or "").strip()
        if not raw or raw.upper() in CORE_TICKET_LIKE:
            return "TK-"  # the core reads #T/ T + 6 hex; anything else is unambiguous
        return raw if raw.endswith(("-", "_", ":")) else raw + "-"

    def _parse_ticket(self, text: str, context: Any) -> Tuple[str, str]:
        """``TK-1A2B3C 已处理`` → ("1A2B3C", "已处理"). The token must lead the message."""
        prefix = self._prefix(context).upper().rstrip("-_:")
        pattern = re.compile(r"^\s*#?" + re.escape(prefix) + r"[-_:]?\s*([0-9A-Fa-f]{4,12})\b[:：,，]?\s*(.*)$",
                             re.IGNORECASE | re.DOTALL)
        match = pattern.match(text or "")
        if not match:
            return "", ""
        return match.group(1).upper(), match.group(2).strip()

    def _open(self, message: Inbound, context: Any, route: str, group_ref: str) -> str:
        token = secrets.token_hex(3).upper()
        limit = max(16, int(as_number(context.config_value("max_tickets"), 1024.0)))
        self._tickets[(message.bot_id, token)] = {
            "ticket_id": f"{token}",
            "prefix": self._prefix(context),
            "bot_id": message.bot_id,
            "group_ref": group_ref,
            "chat_ref": message.chat_ref or message.sender,
            "sender": message.sender,
            "sender_name": message.sender_name or message.sender,
            "route": route,
            "summary": message.text[:160],
            "opened_at": float(context.clock()),
            "answers": 0,
        }
        self._tickets.move_to_end((message.bot_id, token))
        while len(self._tickets) > limit:
            self._tickets.popitem(last=False)
        return token

    def _resolve(self, bot_id: str, token: str) -> Optional[Dict[str, Any]]:
        key = (bot_id, token.upper())
        record = self._tickets.get(key)
        if record is not None:
            self._tickets.move_to_end(key)
        return record

    def open_tickets(self, bot_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Read-only view for the admin panel / self-test."""
        return [dict(record) for (bot, _), record in self._tickets.items()
                if bot_id is None or bot == bot_id]

    def _vars(self, message: Inbound, context: Any, ticket: str) -> Dict[str, str]:
        bot_name = ""
        try:
            bot = context.db.get_bot(message.bot_id) or {}
            bot_name = str(bot.get("display_name") or bot.get("name") or "")
        except Exception as exc:
            log.debug("[msg_router] get_bot failed: %s", exc)
        prefix = self._prefix(context)
        vars_ = default_context(sender_name=message.sender_name, sender=message.sender, bot_name=bot_name,
                                text=message.text, chat_ref=message.chat_ref, chat_type=message.chat_type,
                                now=float(context.clock()))
        vars_["ticket_id"] = f"{prefix}{ticket}".upper()
        vars_["ticket_short"] = str(ticket)
        vars_["answer"] = ""
        vars_["route"] = ""
        return vars_

    @staticmethod
    def _known_groups(bot_id: str, context: Any) -> List[str]:
        seen: List[str] = []
        try:
            rows = context.db.recent_logs(bot_id, limit=500)
        except Exception as exc:
            log.warning("[msg_router] recent_logs failed: %s", exc)
            return seen
        for row in rows or []:
            ref = str(row.get("chat_ref") or "")
            if str(row.get("chat_type") or "") == "group" and ref.startswith("#") and ref not in seen:
                seen.append(ref)
        return sorted(seen)

    def _log(self, message: Inbound, context: Any, *, status: str, text: str) -> None:
        self._log_raw(context, message.bot_id, status=status, text=text, chat_type=message.chat_type,
                      chat_ref=message.chat_ref, sender=message.sender)

    def _log_raw(self, context: Any, bot_id: str, *, status: str, text: str, chat_type: str = "",
                 chat_ref: str = "", sender: str = "", error: str = "") -> None:
        """Only decisions the gateway cannot see are logged here; sends themselves are audited by the bus."""
        try:
            context.services.log_message(bot_id, "out", chat_type=chat_type, chat_ref=chat_ref, sender=sender,
                                         text=text[:2000], plugin_id=PLUGIN_ID, status=status, error=error)
        except Exception as exc:
            log.warning("[msg_router] log_message failed: %s", exc)
