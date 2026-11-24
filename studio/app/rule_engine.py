"""Zero-code auto reply and command engine.

Rules live in the ledger; this module only decides, for one inbound message,
which rule answers it and whether the answer is throttled.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from .database import Database, LedgerError

TRIGGER_RANK = {"exact": 0, "prefix": 1, "regex": 2, "default": 3}
HELP_HEADER = "🤖 POPOPX Bot 指令菜单"
START_HEADER = "👋 欢迎使用"


class RuleError(ValueError):
    """Raised for an unusable rule definition."""


def interpolate(template: str, context: Mapping[str, Any]) -> str:
    """Replace ``{placeholder}`` tokens without evaluating expressions.

    ``str.format`` is deliberately avoided: a rule author writing
    ``{sender_name}`` next to a literal ``{`` would otherwise crash the engine.
    """
    if not template:
        return ""

    def replace(match: re.Match) -> str:
        key = match.group(1)
        if key not in context:
            return match.group(0)
        value = context[key]
        return "" if value is None else str(value)

    return re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", replace, template)


def default_context(
    *,
    sender_name: str = "",
    sender: str = "",
    bot_name: str = "",
    text: str = "",
    chat_ref: str = "",
    chat_type: str = "direct",
    now: Optional[float] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> Dict[str, str]:
    """Build the interpolation variables available to every template."""
    stamp = time.localtime(now if now is not None else time.time())
    context = {
        "sender_name": sender_name or sender,
        "sender": sender,
        "bot_name": bot_name,
        "text": text,
        "chat_ref": chat_ref,
        "chat_type": chat_type,
        "time": time.strftime("%H:%M:%S", stamp),
        "date": time.strftime("%Y-%m-%d", stamp),
        "datetime": time.strftime("%Y-%m-%d %H:%M:%S", stamp),
        "weekday": time.strftime("%A", stamp),
    }
    if extra:
        context.update({str(k): str(v) for k, v in extra.items()})
    return context


@dataclass
class RuleDecision:
    """Outcome of evaluating one inbound message."""

    matched: bool
    rule_id: Optional[int] = None
    trigger_type: str = ""
    reply: str = ""
    status: str = "no_match"
    suppressed_by: str = ""
    context: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def should_send(self) -> bool:
        return self.matched and bool(self.reply) and self.status == "ok"


@dataclass
class InboundMessage:
    """Normalized inbound message consumed by the engines."""

    bot_id: str
    text: str
    chat_type: str = "direct"
    chat_ref: str = ""
    sender: str = ""
    sender_name: str = ""
    ts: float = field(default_factory=time.time)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def normalized(self) -> str:
        return (self.text or "").strip()

    @property
    def first_word(self) -> str:
        parts = self.normalized.split(None, 1)
        return parts[0].lower() if parts else ""


@dataclass
class ThrottleState:
    window_start: float
    hits: int


class RuleEngine:
    """Match inbound text against the ledger rules of one Bot."""

    def __init__(
        self,
        database: Database,
        *,
        bot_name: str = "",
        welcome_text: str = "",
        sender_rate_limit: int = 0,
        sender_rate_window_seconds: int = 60,
        clock: Callable[[], float] = time.time,
    ):
        self.db = database
        self.bot_name = bot_name
        self.welcome_text = welcome_text
        self.sender_rate_limit = int(sender_rate_limit)
        self.sender_rate_window_seconds = max(1, int(sender_rate_window_seconds))
        self._clock = clock
        self._cooldowns: Dict[Tuple[str, int, str], float] = {}
        self._sender_state: Dict[Tuple[str, str], ThrottleState] = {}
        self._commands: Dict[str, Callable[[InboundMessage, Dict[str, str]], str]] = {}
        self._compile_cache: Dict[int, re.Pattern] = {}
        self._rules_cache: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}
        self._rules_ttl = 2.0
        self._rules_cache_limit = 256
        self.register_builtin_commands()

    # ------------------------------------------------------------------ rules
    def invalidate_cache(self) -> None:
        self._rules_cache.clear()

    def enabled_rules(self, bot_id: str, *, force: bool = False) -> List[Dict[str, Any]]:
        """Rules of one Bot, cached per Bot id: a shared cache would hand Bot B
        Bot A's replies for the length of the TTL."""
        now = self._clock()
        cached = self._rules_cache.get(bot_id)
        if cached is not None and not force and now - cached[0] < self._rules_ttl:
            return cached[1]
        rules = self.db.list_reply_rules(bot_id, enabled_only=True)
        ordered = sorted(
            rules,
            key=lambda rule: (
                TRIGGER_RANK.get(str(rule["trigger_type"]), 99),
                int(rule["priority"]),
                int(rule["id"]),
            ),
        )
        for rule in ordered:
            if rule["trigger_type"] == "regex":
                self._compile_cache[int(rule["id"])] = self._compile_pattern(str(rule["pattern"]))
        self._rules_cache[bot_id] = (now, ordered)
        if len(self._rules_cache) > self._rules_cache_limit:
            self._rules_cache.pop(next(iter(self._rules_cache)), None)
        return ordered

    @staticmethod
    def _compile_pattern(pattern: str) -> re.Pattern:
        try:
            return re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise RuleError(f"正则表达式不可用：{exc}") from exc

    def _matches(self, rule: Dict[str, Any], message: InboundMessage) -> bool:
        kind = str(rule["trigger_type"])
        pattern = str(rule["pattern"])
        text = message.normalized
        if kind == "default":
            return True
        if kind == "exact":
            return text.casefold() == pattern.casefold()
        if kind == "prefix":
            return text.casefold().startswith(pattern.casefold())
        if kind == "regex":
            compiled = self._compile_cache.get(int(rule["id"])) or self._compile_pattern(pattern)
            return compiled.search(text) is not None
        return False

    def _captures(self, rule: Dict[str, Any], message: InboundMessage) -> Dict[str, str]:
        if rule["trigger_type"] != "regex":
            return {}
        compiled = self._compile_cache.get(int(rule["id"]))
        if compiled is None:
            return {}
        match = compiled.search(message.normalized)
        if not match:
            return {}
        captured: Dict[str, str] = {}
        for name, value in (match.groupdict() or {}).items():
            captured[name] = value if value is not None else ""
        for index, value in enumerate(match.groups(), start=1):
            captured[f"group_{index}"] = value if value is not None else ""
        if match.group(0):
            captured["matched"] = match.group(0)
        return captured

    # --------------------------------------------------------------- throttling
    def _cooldown_active(self, bot_id: str, rule_id: int, sender: str, now: float) -> bool:
        key = (bot_id, rule_id, sender)
        expires_at = self._cooldowns.get(key)
        if expires_at is None:
            return False
        if expires_at <= now:
            self._cooldowns.pop(key, None)
            return False
        return True

    def _set_cooldown(self, bot_id: str, rule_id: int, sender: str, seconds: int, now: float) -> None:
        if seconds <= 0:
            return
        self._cooldowns[(bot_id, rule_id, sender)] = now + seconds
        if len(self._cooldowns) > 4096:
            for key, expiry in list(self._cooldowns.items()):
                if expiry <= now:
                    self._cooldowns.pop(key, None)

    def _sender_over_limit(self, bot_id: str, sender: str, now: float) -> bool:
        if self.sender_rate_limit <= 0:
            return False
        key = (bot_id, sender)
        state = self._sender_state.get(key)
        if state is None or now - state.window_start >= self.sender_rate_window_seconds:
            self._sender_state[key] = ThrottleState(window_start=now, hits=1)
            return False
        state.hits += 1
        return state.hits > self.sender_rate_limit

    def reset_throttling(self, bot_id: Optional[str] = None) -> None:
        if bot_id is None:
            self._cooldowns.clear()
            self._sender_state.clear()
            return
        self._cooldowns = {k: v for k, v in self._cooldowns.items() if k[0] != bot_id}
        self._sender_state = {k: v for k, v in self._sender_state.items() if k[0] != bot_id}

    # ---------------------------------------------------------------- commands
    def register_builtin_commands(self) -> None:
        self._commands["/help"] = self._render_help
        self._commands["/start"] = self._render_start
        self._commands["/menu"] = self._render_help

    def register_command(self, name: str, handler: Callable[[InboundMessage, Dict[str, str]], str]) -> None:
        key = name.lower()
        if not key.startswith("/"):
            raise RuleError(f"指令名 {name!r} 必须以 / 开头")
        self._commands[key] = handler

    def command_names(self) -> List[str]:
        return sorted(self._commands)

    def slash_rules(self, bot_id: str) -> List[Dict[str, Any]]:
        return [rule for rule in self.enabled_rules(bot_id) if str(rule["pattern"]).startswith("/")]

    def _render_help(self, message: InboundMessage, context: Dict[str, str]) -> str:
        lines = [HELP_HEADER]
        for rule in self.slash_rules(message.bot_id):
            pattern = str(rule["pattern"])
            summary = str(rule["name"] or "").strip()
            first_line = str(rule["reply_text"]).strip().splitlines()
            summary = summary or (first_line[0] if first_line else "")
            lines.append(f"{pattern}  {summary}".rstrip())
        if len(lines) == 1:
            lines.append("（暂无自定义指令，请在后台添加前缀或精确规则）")
        return "\n".join(lines)

    def _render_start(self, message: InboundMessage, context: Dict[str, str]) -> str:
        body = self.welcome_text or "本 Bot 已就绪。"
        return (
            f"{START_HEADER} {context.get('bot_name') or 'Bot'}\n"
            f"{interpolate(body, context)}\n\n输入 /help 查看可用指令。"
        )

    # ------------------------------------------------------------------- entry
    def evaluate(self, message: InboundMessage) -> RuleDecision:
        """Return the decision for *message*; never raises for bad rules."""
        now = self._clock()
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
        if self._sender_over_limit(message.bot_id, message.sender, now):
            return RuleDecision(
                matched=False,
                status="rate_limited",
                suppressed_by="sender_rate_limit",
                context=context,
            )

        command = message.first_word
        handler = self._commands.get(command)
        if handler is not None:
            try:
                reply = handler(message, context)
            except Exception as exc:  # a broken handler must not kill the bus
                return RuleDecision(
                    matched=True,
                    status="error",
                    suppressed_by="command_handler",
                    reply="",
                    context=context,
                    metadata={"error": f"{type(exc).__name__}: {exc}"},
                )
            return RuleDecision(
                matched=True,
                trigger_type="command",
                reply=reply,
                status="ok",
                context=context,
                metadata={"command": command},
            )

        for rule in self.enabled_rules(message.bot_id):
            if not self._matches(rule, message):
                continue
            rule_id = int(rule["id"])
            if self._cooldown_active(message.bot_id, rule_id, message.sender, now):
                return RuleDecision(
                    matched=True,
                    rule_id=rule_id,
                    trigger_type=str(rule["trigger_type"]),
                    status="cooldown",
                    suppressed_by="rule_cooldown",
                    context=context,
                )
            scoped_context = dict(context)
            scoped_context.update(self._captures(rule, message))
            reply = interpolate(str(rule["reply_text"]), scoped_context)
            self._set_cooldown(
                message.bot_id, rule_id, message.sender, int(rule["cooldown_seconds"] or 0), now
            )
            return RuleDecision(
                matched=True,
                rule_id=rule_id,
                trigger_type=str(rule["trigger_type"]),
                reply=reply,
                status="ok",
                context=scoped_context,
                metadata={"priority": int(rule["priority"]), "name": str(rule["name"])},
            )

        return RuleDecision(matched=False, status="no_match", context=context)

    def preview(self, bot_id: str, text: str, *, sender: str = "preview") -> RuleDecision:
        """Evaluate without touching cooldown or throttle state (admin debug)."""
        snapshot_cooldowns = dict(self._cooldowns)
        snapshot_senders = dict(self._sender_state)
        try:
            return self.evaluate(InboundMessage(bot_id=bot_id, text=text, sender=sender))
        finally:
            self._cooldowns = snapshot_cooldowns
            self._sender_state = snapshot_senders

    def export_rules(self, bot_id: str) -> List[Dict[str, Any]]:
        return self.db.list_reply_rules(bot_id)

    def import_rules(self, bot_id: str, rules: Iterable[Dict[str, Any]]) -> int:
        imported = 0
        for rule in rules:
            try:
                self.db.upsert_reply_rule(
                    bot_id,
                    name=str(rule.get("name", "")),
                    trigger_type=str(rule.get("trigger_type", "exact")),
                    pattern=str(rule.get("pattern", "")),
                    reply_text=str(rule.get("reply_text", "")),
                    cooldown_seconds=int(rule.get("cooldown_seconds", 0)),
                    enabled=bool(rule.get("enabled", True)),
                    priority=int(rule.get("priority", 100)),
                )
            except LedgerError:
                continue
            imported += 1
        self.invalidate_cache()
        return imported
