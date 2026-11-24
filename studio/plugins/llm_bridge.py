"""llm_bridge — OpenAI 兼容对话助手（prompt.md §3.8）.

POSTs ``{base_url}/chat/completions`` with a Bearer key through ``httpx``
(``httpx==0.28.1`` in studio/requirements.txt). Per-chat rolling context is kept
in memory and trimmed to ``max_context_messages`` turns.

Priority 80 puts this plugin *last*: the deterministic ones get first refusal and
the model is only paid for when nothing else answered. ``defer_to_core`` extends
the same courtesy to the zero-code ``reply_rules`` ledger.

Degradation is the contract: missing config, a refused endpoint, a non-2xx answer,
a timeout or a malformed body all end in ``PASS`` (or a friendly notice when
``on_error`` is ``notice``). Nothing here may raise into the bus.
"""

from __future__ import annotations

import logging
import re
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.plugin_manager import PASS, PluginResult, StudioPlugin

log = logging.getLogger("popopx.studio.plugin.llm_bridge")

PLUGIN_ID = "llm_bridge"
MAX_REPLY = 3500  # leave room for the CLI frame
MAX_CHATS = 512
LOOPBACK = ("127.", "localhost", "::1", "[::1]", "0.0.0.0")
Role = str


class History:
    """Bounded per-chat transcript; a plain class because ``dataclasses`` needs
    the module to be registered in ``sys.modules``, which the path loader skips."""

    __slots__ = ("_items", "turn_cap", "chat_cap")

    def __init__(self, turn_cap: int = 20, chat_cap: int = MAX_CHATS) -> None:
        self._items: "OrderedDict[Tuple[str, str], List[Dict[str, str]]]" = OrderedDict()
        self.turn_cap = max(2, int(turn_cap))
        self.chat_cap = max(8, int(chat_cap))

    def get(self, key: Tuple[str, str]) -> List[Dict[str, str]]:
        rows = self._items.get(key)
        if rows is not None:
            self._items.move_to_end(key)
        return list(rows) if rows else []

    def append(self, key: Tuple[str, str], role: Role, content: str) -> None:
        rows = self._items.setdefault(key, [])
        rows.append({"role": role, "content": content})
        del rows[self.turn_cap:]
        self._items.move_to_end(key)
        while len(self._items) > self.chat_cap:
            self._items.popitem(last=False)

    def replace(self, key: Tuple[str, str], rows: List[Dict[str, str]]) -> None:
        self._items[key] = [dict(row) for row in rows][-self.turn_cap:]
        self._items.move_to_end(key)
        while len(self._items) > self.chat_cap:
            self._items.popitem(last=False)

    def forget(self, key: Tuple[str, str]) -> None:
        self._items.pop(key, None)

    def clear(self) -> None:
        self._items.clear()

    def __len__(self) -> int:
        return len(self._items)


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


def host_of(url: str) -> str:
    match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:?#]+)", url.strip())
    return (match.group(1) if match else "").lower()


def is_loopback(url: str) -> bool:
    host = host_of(url)
    return any(host == name.rstrip(".") or host.startswith(name) for name in LOOPBACK)


def read_field(event: Any, *names: str, default: str = "") -> str:
    for name in names:
        value = event.get(name, None) if isinstance(event, dict) else getattr(event, name, None)
        if value not in (None, ""):
            return str(value)
    return default


def extract_text(data: Any) -> str:
    """Pull the answer out of a chat-completions body, tolerating shape drift."""
    if not isinstance(data, dict):
        return ""
    choices = data.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0] if isinstance(choices[0], dict) else {}
        message = first.get("message") if isinstance(first, dict) else None
        if isinstance(message, dict) and message.get("content"):
            return str(message["content"]).strip()
        if first.get("text"):
            return str(first["text"]).strip()
    for key in ("output_text", "content", "answer", "result"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


class LLMBridgePlugin(StudioPlugin):
    plugin_id = "llm_bridge"
    name = "AI 助手 / LLM bridge"
    version = "1.0.0"
    description = "OpenAI 兼容 /chat/completions 桥接，自定义 Base URL/Key/Model/System Prompt 与会话上下文记忆"
    priority = 80
    scope = "message"

    config_fields = [
        {"key": "enabled", "type": "bool", "label": "启用插件 / Master switch"},
        {"key": "base_url", "type": "text", "label": "Base URL（默认本机回环 Ollama）"},
        {"key": "api_key", "type": "password", "label": "API Key（Bearer）"},
        {"key": "model", "type": "text", "label": "模型名"},
        {"key": "system_prompt", "type": "textarea", "label": "System Prompt"},
        {"key": "temperature", "type": "number", "label": "Temperature"},
        {"key": "max_context_messages", "type": "number", "label": "上下文轮数"},
        {"key": "max_input_chars", "type": "number", "label": "单条输入截断（字）"},
        {"key": "timeout_seconds", "type": "number", "label": "请求超时（秒）"},
        {"key": "require_api_key", "type": "bool", "label": "缺少 API Key 时跳过"},
        {"key": "loopback_only", "type": "bool", "label": "仅允许回环端点（§1 隔离加固）"},
        {"key": "only_direct", "type": "bool", "label": "只处理单聊"},
        {"key": "defer_to_core", "type": "bool", "label": "已有 reply_rule 命中时跳过"},
        {"key": "on_error", "type": "select", "label": "失败策略",
         "options": [{"value": "pass", "label": "静默跳过"}, {"value": "notice", "label": "回复降级提示"}]},
        {"key": "error_notice", "type": "textarea", "label": "降级提示文案"},
    ]

    default_config = {
        "enabled": True,
        "base_url": "http://127.0.0.1:11434/v1",
        "api_key": "",
        "model": "",
        "system_prompt": "你是 POPOPX Bot Studio 的客服助手，用简洁中文回答，不知道就直说。",
        "temperature": 0.7,
        "max_context_messages": 10,
        "max_input_chars": 2000,
        "timeout_seconds": 20,
        "require_api_key": True,
        "loopback_only": False,
        "only_direct": True,
        "defer_to_core": True,
        "on_error": "pass",
        "error_notice": "AI 助手暂时不可用，稍后再试；紧急情况请发送「人工」。",
    }

    def __init__(self) -> None:
        super().__init__()
        self._history = History()
        self._client: Optional[httpx.AsyncClient] = None
        self._calls = 0
        self._failures = 0

    # ------------------------------------------------------------- lifecycle
    async def on_load(self, context: Any) -> None:
        self.context = context
        base = str(context.config_value("base_url", self.default_config["base_url"]) or "")
        log.info("[llm_bridge] loaded: base=%s loopback=%s model=%r", base or "-", is_loopback(base),
                 str(context.config_value("model", "") or ""))

    async def on_enable(self, context: Any) -> None:
        self.context = context

    async def on_disable(self, context: Any) -> None:
        log.info("[llm_bridge] disabled after %d call(s), %d failure(s)", self._calls, self._failures)

    async def on_unload(self) -> None:
        self._history.clear()
        client, self._client = self._client, None
        if client is not None:
            try:
                await client.aclose()
            except Exception as exc:  # shutdown must not fail the gateway
                log.debug("[llm_bridge] client close failed: %s", exc)

    # ---------------------------------------------------------------- dispatch
    async def on_message(self, event: Any, context: Any) -> PluginResult:
        if not as_bool(context.config_value("enabled", True), True):
            return PASS
        bot_id = read_field(event, "bot_id")
        chat_ref = read_field(event, "chat_ref", "chat_id")
        sender = read_field(event, "sender")
        text = read_field(event, "text").strip()
        chat_type = read_field(event, "chat_type", default="direct")
        if not text or not bot_id or not (chat_ref or sender):
            return PASS
        if as_bool(context.config_value("only_direct", True), True) and chat_type != "direct":
            return PASS
        missing = self._missing_config(context)
        if missing:
            log.debug("[llm_bridge] skipped, missing config: %s", ",".join(missing))
            return PASS
        if as_bool(context.config_value("defer_to_core", True), True) and self._core_answers(bot_id, text, context):
            return PASS

        cap = max(2, int(as_number(context.config_value("max_context_messages"), 10.0)))
        limit = max(64, int(as_number(context.config_value("max_input_chars"), 2000.0)))
        key = (bot_id, chat_ref or sender)
        self._history.turn_cap = cap
        history = self._history.get(key)
        history.append({"role": "user", "content": text[:limit]})
        history = history[-cap:]
        messages: List[Dict[str, str]] = []
        system = str(context.config_value("system_prompt", "") or "").strip()
        if system:
            messages.append({"role": "system", "content": system})
        messages.extend(history)

        try:
            answer = await self._complete(messages, context)
        except httpx.TimeoutException as exc:
            return self._failed(key, history, context, f"timeout {type(exc).__name__}")
        except httpx.HTTPStatusError as exc:
            return self._failed(key, history, context, f"http {exc.response.status_code}")
        except (httpx.HTTPError, OSError, ValueError) as exc:
            return self._failed(key, history, context, f"{type(exc).__name__}: {exc}")
        except Exception as exc:  # a third-party transport must never reach the bus
            return self._failed(key, history, context, f"unexpected {type(exc).__name__}: {exc}")

        if not answer:
            return self._failed(key, history, context, "empty completion")
        history.append({"role": "assistant", "content": answer})
        self._history.replace(key, history[-cap:])
        self._calls += 1
        return PluginResult(handled=True, reply=answer[:MAX_REPLY], status="ok",
                            metadata={"plugin": PLUGIN_ID, "turns": len(history), "context": cap})

    async def _complete(self, messages: List[Dict[str, str]], context: Any) -> str:
        base = str(context.config_value("base_url", "") or "").rstrip("/")
        url = f"{base}/chat/completions"
        api_key = str(context.config_value("api_key", "") or "").strip()
        timeout = max(1.0, as_number(context.config_value("timeout_seconds"), 20.0))
        payload = {
            "model": str(context.config_value("model", "") or ""),
            "messages": messages,
            "temperature": as_number(context.config_value("temperature"), 0.7),
            "stream": False,
        }
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        client = self._client
        if client is None or client.is_closed:
            # trust_env=False: an ambient SOCKS/HTTP proxy would both leak the Bearer
            # key and make the client fail in ways the operator cannot debug.
            client = httpx.AsyncClient(timeout=timeout, trust_env=False)
            self._client = client
        response = await client.post(url, json=payload, headers=headers)
        if response.status_code >= 400:
            detail = (response.text or "")[:200]
            log.warning("[llm_bridge] %s -> HTTP %d %s", url, response.status_code, detail)
            response.raise_for_status()
        try:
            data = response.json()
        except ValueError as exc:
            raise ValueError(f"响应不是 JSON: {exc}") from exc
        error = data.get("error") if isinstance(data, dict) else None
        if error:
            raise ValueError(f"上游返回错误: {str(error)[:200]}")
        return extract_text(data)

    def _failed(self, key: Tuple[str, str], history: List[Dict[str, str]], context: Any, why: str) -> PluginResult:
        self._failures += 1
        self._history.forget(key)  # the user turn never reached the model; keep the transcript honest
        self._log_error(context, key, why)
        log.warning("[llm_bridge] %s: %s", key[1], why)
        if str(context.config_value("on_error", "pass")) == "notice":
            notice = str(context.config_value("error_notice") or self.default_config["error_notice"])
            if notice.strip():
                return PluginResult(handled=True, reply=notice[:MAX_REPLY], status="ok",
                                    metadata={"plugin": PLUGIN_ID, "error": why[:200]})
        return PASS

    def _log_error(self, context: Any, key: Tuple[str, str], why: str) -> None:
        try:
            context.services.log_message(key[0], "out", chat_type="direct", chat_ref=key[1],
                                         text="llm_bridge", plugin_id=PLUGIN_ID, status="error",
                                         error=why[:300])
        except Exception as exc:
            log.debug("[llm_bridge] log_message failed: %s", exc)

    def _missing_config(self, context: Any) -> List[str]:
        missing: List[str] = []
        base = str(context.config_value("base_url", "") or "").strip()
        if not base or not base.lower().startswith(("http://", "https://")):
            missing.append("base_url")
        elif as_bool(context.config_value("loopback_only"), False) and not is_loopback(base):
            missing.append("base_url(非回环，loopback_only)")
        if not str(context.config_value("model", "") or "").strip():
            missing.append("model")
        if as_bool(context.config_value("require_api_key", True), True) \
                and not str(context.config_value("api_key", "") or "").strip():
            missing.append("api_key")
        return missing

    def _core_answers(self, bot_id: str, text: str, context: Any) -> bool:
        """Stand down when the ledger already replies to this text."""
        try:
            rules = context.db.list_reply_rules(bot_id, enabled_only=True)
        except Exception as exc:
            log.debug("[llm_bridge] list_reply_rules failed: %s", exc)
            return False
        needle = text.casefold()
        for rule in rules or []:
            pattern = str(rule.get("pattern") or "").strip().casefold()
            kind = str(rule.get("trigger_type") or "")
            if not pattern:
                continue
            if kind == "exact" and needle == pattern:
                return True
            if kind == "prefix" and needle.startswith(pattern):
                return True
            if kind == "regex":
                try:
                    if re.search(pattern, text, re.IGNORECASE):
                        return True
                except re.error:
                    continue
        return False
