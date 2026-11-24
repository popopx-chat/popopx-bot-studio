"""auto_reply — 关键词问答、多级指令菜单、定时公告（prompt.md §3.8）.

Rules live in this plugin's own config (``plugin_configs.config`` JSON, edited in
the Web UI and merged by ``PluginManager._context``); nothing here writes to the
``reply_rules`` table, which belongs to the zero-code core engine.

The bus runs plugins *before* ``RuleEngine``/``RouterEngine`` and stops the chain
at the first ``handled`` result, so a plugin that answers too eagerly would
shadow the operator's own rules. ``defer_to_core`` keeps the plugin honest: when
the ledger already claims the message, this plugin passes.

Time always comes from ``context.clock()`` so the self-test can drive the
announcement timer without sleeping.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from app.plugin_manager import PASS, PluginResult, StudioPlugin
from app.rule_engine import default_context, interpolate

log = logging.getLogger("popopx.studio.plugin.auto_reply")

PLUGIN_ID = "auto_reply"
MAX_TEXT = 4000  # CLI text ceiling
BUILTIN_COMMANDS = ("help", "start", "menu")


class Inbound:
    """The bus hands us an ``InboundMessage``; tests hand us a dict.

    A plain class, not a dataclass: ``load_plugin_module`` execs this file without
    registering it in ``sys.modules``, and ``dataclasses`` needs that lookup.
    """

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
            if isinstance(event, dict):
                return event.get(key, default)
            return getattr(event, key, default)

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
    """Config JSON may arrive as a list, a dict or a raw string."""
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


def command_word(text: str) -> Tuple[str, str]:
    """``/menu services`` -> ("menu", "services"); ``/start@Bot x`` -> ("start", "x")."""
    body = text.lstrip()
    if not body.startswith("/"):
        return "", ""
    parts = body[1:].split(None, 1)
    if not parts:
        return "", ""
    head = parts[0].split("@", 1)[0].casefold()
    return head, (parts[1].strip() if len(parts) > 1 else "")


class AutoReplyPlugin(StudioPlugin):
    plugin_id = "auto_reply"
    name = "智能问答与公告 / Auto reply"
    version = "1.0.0"
    description = "关键词与指令自动回复、多级指令菜单、定时公告群发（规则存插件 config，UI 可编辑）"
    priority = 60
    scope = "message"

    config_fields = [
        {"key": "enabled", "type": "bool", "label": "启用插件 / Master switch"},
        {"key": "defer_to_core", "type": "bool", "label": "优先让零代码规则处理（防抢占）"},
        {"key": "help_text", "type": "textarea", "label": "/help 文案"},
        {"key": "start_text", "type": "textarea", "label": "/start 欢迎语"},
        {"key": "menu_header", "type": "text", "label": "菜单标题"},
        {"key": "commands", "type": "json", "label": "指令菜单 [{command,parent,reply,hint}]"},
        {"key": "keywords", "type": "json", "label": "关键词问答 [{keyword,reply,regex}]"},
        {"key": "match_whole_message", "type": "bool", "label": "关键词需整句匹配"},
        {"key": "min_keyword_chars", "type": "number", "label": "最短关键词长度"},
        {"key": "max_replies_per_chat", "type": "number", "label": "单会话响应上限（0=不限）"},
        {"key": "window_seconds", "type": "number", "label": "限频窗口（秒）"},
        {"key": "announce_enabled", "type": "bool", "label": "启用定时公告"},
        {"key": "announce_bots", "type": "json", "label": "公告 Bot 列表（空=全部 Bot）"},
        {"key": "announce_text", "type": "textarea", "label": "公告内容"},
        {"key": "announce_interval_minutes", "type": "number", "label": "公告间隔（分钟）"},
        {"key": "announce_targets", "type": "json", "label": "公告目标（空=本 Bot 已知群组）"},
        {"key": "announce_startup_grace_seconds", "type": "number", "label": "启动宽限（秒）"},
    ]

    default_config = {
        "enabled": True,
        "defer_to_core": True,
        "help_text": "可用指令：\n/menu 主菜单\n/start 欢迎语",
        "start_text": "你好 {sender_name}，这里是 {bot_name}，发送 /menu 查看菜单。",
        "menu_header": "{bot_name} 菜单",
        "commands": [
            {"command": "services", "parent": "menu", "reply": "服务：安装 / 配置 / 故障排查", "hint": "服务列表"},
            {"command": "staff", "parent": "menu", "reply": "当前值班：alice、bob", "hint": "值班人员"},
            {"command": "faq", "parent": "menu", "reply": "常见问题：发送 /menu faq 查看", "hint": "常见问题"},
            {"command": "pricing", "parent": "services", "reply": "价目表：基础 ¥0 / 标准 ¥99", "hint": "价目表"},
            {"command": "install", "parent": "services", "reply": "安装指引见 README.en.md", "hint": "安装"},
            {"command": "shipping", "parent": "faq", "reply": "发货：48 小时内", "hint": "发货"},
            {"command": "refund", "parent": "faq", "reply": "退款：7 天无理由", "hint": "退款"},
            {"command": "order", "parent": "", "arg": True, "reply": "订单 {arg} 正在处理。", "hint": "查订单"},
        ],
        "keywords": [
            {"keyword": "帮助", "reply": "需要帮助？发送 /menu 查看菜单，或描述具体问题。"},
            {"keyword": "help", "reply": "Send /menu for the command list, or describe the issue."},
            {"keyword": "价格", "reply": "价目表见 /menu services pricing。"},
            {"keyword": "营业时间", "reply": "工作时间 09:00–18:00，今天是 {weekday}。"},
            {"keyword": "人工", "regex": False, "reply": "正在转人工（工单由 msg_router 插件创建）。"},
            {"keyword": "^(在吗|在么|hello)$", "regex": True, "reply": "在的，请说。"},
        ],
        "match_whole_message": False,
        "min_keyword_chars": 2,
        "max_replies_per_chat": 0,
        "window_seconds": 60,
        "announce_enabled": False,
        "announce_bots": [],
        "announce_text": "",
        "announce_interval_minutes": 60,
        "announce_targets": [],
        "announce_startup_grace_seconds": 0,
    }

    def __init__(self) -> None:
        super().__init__()
        self._next_due: Dict[str, float] = {}
        self._announced = 0
        self._hits: Dict[str, List[float]] = {}
        self._tree: Optional[Dict[str, List[Dict[str, Any]]]] = None

    # ------------------------------------------------------------- lifecycle
    async def on_load(self, context: Any) -> None:
        self.context = context
        self._tree = None
        log.info("[auto_reply] loaded: %d commands, %d keywords",
                 len(as_list(context.config_value("commands"))), len(as_list(context.config_value("keywords"))))

    async def on_enable(self, context: Any) -> None:
        self.context = context
        self._tree = self._build_tree(context)
        log.info("[auto_reply] enabled (%d roots)", len(self._tree.get("", [])))

    async def on_disable(self, context: Any) -> None:
        log.info("[auto_reply] disabled after %d announcement(s)", self._announced)

    async def on_unload(self) -> None:
        self._hits.clear()
        self._next_due.clear()
        self._tree = None

    # ---------------------------------------------------------------- dispatch
    async def on_message(self, event: Any, context: Any) -> PluginResult:
        if not as_bool(context.config_value("enabled", True), True):
            return PASS
        message = Inbound.of(event)
        if not message.text:
            return PASS
        if as_bool(context.config_value("defer_to_core", True), True) and self._core_owns(message, context):
            return PASS
        if not self._allow(message, context):
            return PASS

        vars_ = self._vars(message, context)
        word, rest = command_word(message.text)
        if word:
            return self._on_command(word, rest, message, context, vars_)
        return self._on_keyword(message, context, vars_)

    async def on_tick(self, context: Any) -> None:
        """The bus ticks globally (``bot_id=""``), so the timer is evaluated per Bot.

        Each Bot's own merged config decides whether it announces, which is what
        makes ``plugin_configs`` rows with a ``bot_id`` meaningful here.
        """
        now = float(context.clock())
        for bot_id in self._candidate_bots(context):
            _, cfg = self._bot_config(bot_id, context)
            if not as_bool(cfg.get("announce_enabled"), False):
                continue
            text = str(cfg.get("announce_text") or "").strip()
            if not text:
                continue
            interval = max(60.0, as_number(cfg.get("announce_interval_minutes"), 60.0) * 60.0)
            grace = max(0.0, as_number(cfg.get("announce_startup_grace_seconds"), 0.0))
            due = self._next_due.get(bot_id)
            if due is None:
                # Arming waits a full interval unless the operator asked for an
                # earlier first broadcast via the grace window.
                self._next_due[bot_id] = now + (grace or interval)
                log.info("[auto_reply] %s: announcement armed, interval=%.0fs grace=%.0fs",
                         bot_id, interval, grace)
                continue
            if now < due:
                continue
            self._next_due[bot_id] = now + interval
            await self._broadcast(text, cfg, bot_id, context)

    # ---------------------------------------------------------------- commands
    def _on_command(self, word: str, rest: str, message: Inbound, context: Any, vars_: Dict[str, str]) -> PluginResult:
        tree = self._tree or self._build_tree(context)
        if word in BUILTIN_COMMANDS and not rest:
            if word == "help":
                body = str(context.config_value("help_text") or self.default_config["help_text"])
                return self._reply(interpolate(body, vars_), message, "/help")
            if word == "start":
                body = str(context.config_value("start_text") or self.default_config["start_text"])
                return self._reply(interpolate(body, vars_), message, "/start")
            return self._reply(self._render_menu("menu", tree, vars_, context), message, "/menu")
        node, arg = self._resolve(tree, word, rest)
        if node is None:
            return PASS
        path = " ".join(self._path(tree, node))
        if self._children(tree, node) and not arg:
            return self._reply(self._render_menu(str(node["command"]), tree, vars_, context), message, "/" + path)
        if as_bool(node.get("arg"), False):
            vars_["arg"] = arg or str(node.get("default_arg") or "<参数>")
        body = interpolate(str(node.get("reply") or ""), vars_)
        return self._reply(body, message, "/" + path) if body else PASS

    def _resolve(self, tree: Dict[str, List[Dict[str, Any]]], word: str,
                 rest: str) -> Tuple[Optional[Dict[str, Any]], str]:
        """Return (node, leftover argument).

        A root match wins and consumes as many path segments as it can descend;
        the remainder is the argument. With no root match the deepest word is
        looked up anywhere, so ``/menu services`` works even though ``menu`` is a
        menu name and not an entry of its own.
        """
        raw = rest.split()
        segments = [part.casefold() for part in raw]
        head = word.casefold()
        roots = [root for root in tree.get("", []) if root["command"] == head]
        if not roots:
            tail = segments[-1] if segments else head
            found = [node for nodes in tree.values() for node in nodes if node["command"] == tail]
            if not found:
                return None, ""
            return found[0], " ".join(raw[:-1] if raw else [])
        node = roots[0]
        index = 0
        while index < len(segments):
            child = next((item for item in self._children(tree, node) if item["command"] == segments[index]), None)
            if child is None:
                break
            node, index = child, index + 1
        return node, " ".join(raw[index:])

    def _children(self, tree: Dict[str, List[Dict[str, Any]]], node: Dict[str, Any]) -> List[Dict[str, Any]]:
        return tree.get(str(node.get("command") or "").casefold(), [])

    def _path(self, tree: Dict[str, List[Dict[str, Any]]], node: Dict[str, Any]) -> List[str]:
        parts = [str(node.get("command") or "")]
        parent = str(node.get("parent") or "")
        guard = 0
        while parent and guard < 6:
            parts.append(parent)
            found = next((item for item in tree.get("", []) if item["command"] == parent), None)
            if found is None:
                found = next((item for items in tree.values() for item in items if item["command"] == parent), None)
            parent = str(found.get("parent") or "") if found else ""
            guard += 1
        return [part for part in reversed(parts) if part]

    def _build_tree(self, context: Any) -> Dict[str, List[Dict[str, Any]]]:
        tree: Dict[str, List[Dict[str, Any]]] = {}
        for raw in as_list(context.config_value("commands")):
            if not isinstance(raw, dict):
                continue
            command = str(raw.get("command") or "").strip().lstrip("/").split()[0]
            if not command:
                continue
            node = dict(raw)
            node["command"] = command.casefold()
            node["parent"] = str(raw.get("parent") or "").strip().casefold()
            tree.setdefault(node["parent"], []).append(node)
        return tree

    def _render_menu(self, parent: str, tree: Dict[str, List[Dict[str, Any]]],
                     vars_: Dict[str, str], context: Any) -> str:
        """Menu entries are config rows, so a reply may itself list sub-commands."""
        children = tree.get(parent.casefold(), [])
        header = interpolate(str(context.config_value("menu_header") or self.default_config["menu_header"]), vars_)
        lines = [f"{header} — {parent}" if header else parent]
        for child in children:
            hint = str(child.get("hint") or "").strip() or (str(child.get("reply") or "").strip().splitlines() or [""])[0]
            lines.append(f"• /{' '.join(self._path(tree, child))}" + (f"  {hint[:60]}" if hint else ""))
            for sub in self._children(tree, child)[:5]:
                lines.append(f"    – /{' '.join(self._path(tree, sub))}")
        if len(lines) == 1:
            lines.append("（此菜单暂无条目）")
        return "\n".join(lines)[:MAX_TEXT]

    # ---------------------------------------------------------------- keywords
    def _on_keyword(self, message: Inbound, context: Any, vars_: Dict[str, str]) -> PluginResult:
        needle = message.text.casefold()
        whole = as_bool(context.config_value("match_whole_message"), False)
        floor = max(1, int(as_number(context.config_value("min_keyword_chars"), 2.0)))
        best: Optional[Tuple[int, Dict[str, Any]]] = None
        for raw in as_list(context.config_value("keywords")):
            if not isinstance(raw, dict):
                continue
            keyword = str(raw.get("keyword") or "").strip()
            reply = str(raw.get("reply") or "").strip()
            if not keyword or not reply:
                continue
            if as_bool(raw.get("regex"), False):
                try:
                    if not re.search(keyword, message.text, re.IGNORECASE):
                        continue
                except re.error as exc:
                    log.warning("[auto_reply] bad regex %r: %s", keyword, exc)
                    continue
            else:
                probe = keyword.casefold()
                if len(probe) < floor:
                    continue
                if (needle == probe) if whole else (probe not in needle):
                    continue
            if best is None or len(keyword) > best[0]:  # the most specific keyword wins
                best = (len(keyword), raw)
        if best is None:
            return PASS
        vars_["keyword"] = str(best[1].get("keyword") or "")
        return self._reply(interpolate(str(best[1].get("reply") or ""), vars_)[:MAX_TEXT],
                           message, f"keyword:{best[1].get('keyword')}")

    def _reply(self, text: str, message: Inbound, via: str) -> PluginResult:
        """The bus sends ``reply`` to ``chat_ref`` and logs it, so we only report the decision."""
        text = (text or "").strip()
        if not text:
            return PASS
        log.info("[auto_reply] %s -> %s/%s via %s", message.bot_id, message.chat_type, message.chat_ref, via)
        return PluginResult(handled=True, reply=text, status="ok",
                            metadata={"plugin": PLUGIN_ID, "matched_via": via})

    # ------------------------------------------------------------- announcements
    async def _broadcast(self, text: str, cfg: Dict[str, Any], bot_id: str, context: Any) -> int:
        targets = self._target_rows(as_list(cfg.get("announce_targets")), bot_id, context)
        body = self._announce_body(text, cfg, bot_id, context)[:MAX_TEXT]
        delivered = 0
        for chat_type, chat_ref in targets:
            status, error = "ok", ""
            try:
                result = await context.services.send_text(bot_id, chat_type, chat_ref, body,
                                                          plugin_id=PLUGIN_ID)
                if isinstance(result, dict) and not result.get("ok", True):
                    status, error = "error", str(result.get("error") or "send rejected")[:300]
            except Exception as exc:  # a dead client must not stop the other chats
                status, error = "error", f"{type(exc).__name__}: {exc}"[:300]
            try:
                context.services.log_message(bot_id, "out", chat_type=chat_type, chat_ref=chat_ref,
                                             text=body, plugin_id=PLUGIN_ID, status=status, error=error)
            except Exception as exc:
                log.warning("[auto_reply] log_message failed: %s", exc)
            delivered += int(status == "ok")
        self._announced += delivered
        log.info("[auto_reply] %s: announcement to %d/%d chats", bot_id, delivered, len(targets))
        return delivered

    def _announce_body(self, text: str, cfg: Dict[str, Any], bot_id: str, context: Any) -> str:
        bot_name = ""
        try:
            bot = context.db.get_bot(bot_id) or {}
            bot_name = str(bot.get("display_name") or bot.get("name") or "")
        except Exception as exc:
            log.debug("[auto_reply] get_bot failed: %s", exc)
        vars_ = default_context(sender_name="", sender="", bot_name=bot_name, text="", chat_ref="",
                                chat_type="group", now=float(context.clock()))
        vars_["bot_id"] = bot_id
        return interpolate(text, vars_)

    def _candidate_bots(self, context: Any) -> List[str]:
        """Configured Bot list first, else every Bot in the ledger."""
        wanted = [str(item).strip() for item in as_list(context.config_value("announce_bots")) if str(item).strip()]
        if wanted:
            return wanted
        try:
            rows = context.db.list_bots()
        except Exception as exc:
            log.debug("[auto_reply] list_bots failed: %s", exc)
            rows = []
        out: List[str] = []
        for row in rows or []:
            bot_id = str(row.get("id") or "").strip()
            if not bot_id:
                continue
            _, merged = self._bot_config(bot_id, context)
            if as_bool(merged.get("announce_enabled"), False) and str(merged.get("announce_text") or "").strip():
                out.append(bot_id)
        return out

    def _bot_config(self, bot_id: str, context: Any) -> Tuple[bool, Dict[str, Any]]:
        try:
            enabled, merged = context.db.effective_plugin_config(PLUGIN_ID, bot_id)
            if isinstance(merged, dict) and merged:
                return bool(enabled), {**self.default_config, **merged}
            return bool(enabled), dict(self.default_config)
        except Exception as exc:
            log.debug("[auto_reply] effective_plugin_config(%s) failed: %s", bot_id, exc)
            return self.enabled, dict(context.config or {})

    def _target_rows(self, configured: List[Any], bot_id: str, context: Any) -> List[Tuple[str, str]]:
        rows: List[Tuple[str, str]] = []
        for item in configured:
            if isinstance(item, dict):
                ref = str(item.get("chat_ref") or item.get("chat_id") or item.get("id") or "").strip()
                if ref:
                    rows.append((str(item.get("chat_type") or "group"), ref))
            elif str(item).strip():
                rows.append(("group", str(item).strip()))
        if rows:
            return rows
        return [(row[0], row[1]) for row in self._known_groups(bot_id, context)]

    @staticmethod
    def _known_groups(bot_id: str, context: Any) -> List[Tuple[str, str]]:
        """No chats table exists in the ledger, so group targets are derived from history."""
        seen: Dict[str, str] = {}
        try:
            rows = context.db.recent_logs(bot_id, limit=500)
        except Exception as exc:
            log.warning("[auto_reply] recent_logs failed: %s", exc)
            return []
        for row in rows:
            if str(row.get("chat_type") or "") != "group":
                continue
            ref = str(row.get("chat_ref") or "")
            if ref.startswith("#"):
                seen[ref] = "group"
        return sorted((chat_type, chat_ref) for chat_ref, chat_type in seen.items())

    # ------------------------------------------------------------------ guards
    def _vars(self, message: Inbound, context: Any) -> Dict[str, str]:
        bot_name = ""
        try:
            bot = context.db.get_bot(message.bot_id) if message.bot_id else None
            bot_name = str((bot or {}).get("name") or "")
        except Exception as exc:
            log.debug("[auto_reply] get_bot failed: %s", exc)
        vars_ = default_context(sender_name=message.sender_name, sender=message.sender, bot_name=bot_name,
                                text=message.text, chat_ref=message.chat_ref, chat_type=message.chat_type,
                                now=float(context.clock()))
        word, rest = command_word(message.text)
        vars_["command"] = word
        vars_["arg"] = rest
        vars_["keyword"] = ""
        return vars_

    def _core_owns(self, message: Inbound, context: Any) -> bool:
        """True when a ledger ``reply_rule`` would answer this message — then we stand down."""
        try:
            rules = context.db.list_reply_rules(message.bot_id, enabled_only=True)
        except Exception as exc:
            log.debug("[auto_reply] list_reply_rules failed: %s", exc)
            return False
        word, _ = command_word(message.text)
        lowered = message.text.casefold()
        for rule in rules or []:
            pattern = str(rule.get("pattern") or "").strip().casefold()
            kind = str(rule.get("trigger_type") or "")
            if not pattern:
                continue
            if kind == "exact" and lowered == pattern:
                return True
            if kind == "prefix" and (lowered == pattern or lowered.startswith(pattern + " ")
                                     or (word and pattern == "/" + word)):
                return True
            if kind == "regex":
                try:
                    if re.search(pattern, message.text, re.IGNORECASE):
                        return True
                except re.error:
                    continue
        return False

    def _allow(self, message: Inbound, context: Any) -> bool:
        limit = int(as_number(context.config_value("max_replies_per_chat"), 0.0))
        if limit <= 0:
            return True
        now = float(context.clock())
        window = max(1.0, as_number(context.config_value("window_seconds"), 60.0))
        key = f"{message.bot_id}:{message.chat_ref or message.sender}"
        stamps = [stamp for stamp in self._hits.get(key, []) if now - stamp < window]
        if len(stamps) >= limit:
            self._hits[key] = stamps
            return False
        stamps.append(now)
        self._hits[key] = stamps
        if len(self._hits) > 2048:
            self._hits.pop(next(iter(self._hits)), None)
        return True
