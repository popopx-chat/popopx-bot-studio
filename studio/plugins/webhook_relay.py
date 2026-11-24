"""webhook_relay — 外部告警入站推送与出站事件回调（prompt.md §3.8）.

Inbound. ``main.py`` mounts ``POST /api/v1/hooks/{bot_id}/{secret}`` and hands the
body to ``PluginManager.handle_hook``, which calls
``on_hook(bot_id, secret, payload, context)`` for every enabled plugin in priority
order and stops at the first non-``pass`` result. So the *secret is the selector*:
with no ``hook_secret`` configured this plugin passes and another hook plugin may
claim the URL; with one configured and a mismatched secret it answers
``unauthorized``, which the route renders as 401 instead of a generic 404.

Outbound. Each inbound message is POSTed to the Bot's own ``bots.webhook_url``
(schema v4 migration 3, signed ``X-Popopx-Signature: sha256=<hmac>`` with
``bots.webhook_secret``). Delivery runs as a tracked ``asyncio`` task bounded by
``queue_size`` — a dead endpoint may drop an event, it may never stall the chain.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
from collections import OrderedDict, deque
from typing import Any, Deque, Dict, List, Optional, Tuple

import httpx

from app.plugin_manager import PASS, PluginResult, StudioPlugin

log = logging.getLogger("popopx.studio.plugin.webhook_relay")

PLUGIN_ID = "webhook_relay"
MAX_TEXT = 3800
#: The ticket notices the router plugins post into a group look like ``[#T1A2B3C] …``
#: or ``[TK-1A2B3C] …``; relaying them back out as customer alerts would echo.
TICKET_NOTICE_RE = re.compile(r"^\s*\[#?(?:TK|T)[-_]?[0-9A-Fa-f]{4,12}\]", re.IGNORECASE)
SEVERITY_RANK = {"": 0, "debug": 0, "info": 1, "information": 1, "notice": 1, "warning": 2,
                 "warn": 2, "error": 3, "critical": 4, "crit": 4, "fatal": 4, "emergency": 5}
TEXT_KEYS = ("text", "message", "alert", "summary", "msg", "title", "descriptor", "description")
SEVERITY_KEYS = ("severity", "level", "priority", "status", "state")
SOURCE_KEYS = ("source", "service", "monitor", "rule", "alertname", "alert_name", "host", "project")
URL_RE = re.compile(r"^https?://[^\s\"'<>]{4,}", re.I)
MAX_URLS = 5
#: ``@``/``#``/``*`` are the CLI's own contact/group/local reference prefixes.
REF_PREFIXES = {"@": "direct", "#": "group", "*": "local"}


class Inbound:
    """Same reader as the other plugins: an ``InboundMessage`` from the bus or a dict from a test."""

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


def normalize_payload(payload: Any) -> Tuple[Optional[Dict[str, Any]], str]:
    """The route may hand us a dict or a raw body; anything else is not an alert."""
    if isinstance(payload, dict):
        return payload, ""
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8", "replace")
    if isinstance(payload, str):
        raw = payload.strip()
        if not raw:
            return None, "empty body"
        try:
            data = json.loads(raw)
        except ValueError as exc:
            return None, f"JSON 解析失败：{exc}"
        return (data, "") if isinstance(data, dict) else (None, "顶层不是对象")
    return None, f"不支持的 payload 类型 {type(payload).__name__}"


def alert_fields(data: Dict[str, Any]) -> Tuple[str, str, str]:
    """(text, severity, source) from whatever the monitoring system sent."""
    body = ""
    for key in TEXT_KEYS:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            body = value.strip()
            break
    extra: Dict[str, Any] = {}
    nested = data.get("alert") or data.get("data") or {}
    if isinstance(nested, dict):
        extra.update(nested)
        for key in TEXT_KEYS:
            value = nested.get(key)
            if isinstance(value, str) and value.strip():
                body = body or value.strip()
                break
    severity = ""
    for scope in (data, extra):
        for key in SEVERITY_KEYS:
            value = scope.get(key)
            if isinstance(value, (str, int, float)) and str(value).strip():
                severity = str(value).strip().lower()
                break
        if severity:
            break
    source = ""
    for scope in (data, extra):
        for key in SOURCE_KEYS:
            value = scope.get(key)
            if isinstance(value, str) and value.strip():
                source = value.strip()
                break
        if source:
            break
    labels = data.get("labels")
    if isinstance(labels, dict):
        source = source or str(labels.get("alertname") or labels.get("service") or "").strip()
        severity = severity or str(labels.get("severity") or "").strip().lower()
    return body, severity, source


def severity_rank(value: str) -> int:
    return SEVERITY_RANK.get(str(value or "").strip().lower(), 3)


def extract_urls(value: Any, depth: int = 0, out: Optional[List[str]] = None) -> List[str]:
    """Alertmanager-style ``generatorURL``/``annotations`` links, up to ``MAX_URLS``."""
    urls = out if out is not None else []
    if depth > 5 or len(urls) >= MAX_URLS:
        return urls
    if isinstance(value, str):
        for match in URL_RE.finditer(value):
            url = match.group(0).rstrip(").,;'\"")
            if url not in urls:
                urls.append(url)
        return urls
    if isinstance(value, dict):
        for item in value.values():
            extract_urls(item, depth + 1, urls)
    elif isinstance(value, (list, tuple)):
        for item in value:
            extract_urls(item, depth + 1, urls)
    return urls


def render(bot_id: str, source: str, severity: str, body: str, urls: List[str]) -> str:
    head = f"🔔 告警 · {source}" if source else "🔔 告警"
    if severity:
        head = f"{head} [{severity}]"
    lines = [head, f"Bot {bot_id}", body[:MAX_TEXT]]
    lines += [f"详情 {url}" for url in urls]
    return "\n".join(line for line in lines if line)


class WebhookRelayPlugin(StudioPlugin):
    plugin_id = "webhook_relay"
    name = "Webhook 中转 / Relay"
    version = "1.0.0"
    description = "外部监控 POST /api/v1/hooks/<bot>/<secret> 告警推送到群组/联系人；入站消息回调 Bot 的 webhook_url"
    priority = 40
    scope = "message"

    config_fields = [
        {"key": "enabled", "type": "bool", "label": "启用插件 / Master switch"},
        {"key": "hook_secret", "type": "password", "label": "入站密钥（URL 里的那一段）"},
        {"key": "hook_targets", "type": "json", "label": "推送目标 [{chat_type,chat_ref}]"},
        {"key": "min_severity", "type": "select", "label": "最低告警级别",
         "options": [{"value": "debug", "label": "全部"}, {"value": "info", "label": "info+"},
                     {"value": "warning", "label": "warning+"}, {"value": "error", "label": "error+"},
                     {"value": "critical", "label": "critical 及以上"}]},
        {"key": "dedup_window_seconds", "type": "number", "label": "相同告警抑制窗口（秒）"},
        {"key": "max_alerts_per_hour", "type": "number", "label": "每小时告警上限（0=不限）"},
        {"key": "title_prefix", "type": "text", "label": "标题前缀"},
        {"key": "notify_inbound", "type": "bool", "label": "出站回调：推送入站消息"},
        {"key": "notify_filters", "type": "json", "label": "出站过滤 [{chat_type,keywords}]（空=全部）"},
        {"key": "skip_ticket_notices", "type": "bool", "label": "出站回调：忽略工单通知回声"},
        {"key": "outbound_timeout_seconds", "type": "number", "label": "出站超时（秒）"},
        {"key": "queue_size", "type": "number", "label": "出站并发上限"},
    ]

    default_config = {
        "enabled": True,
        "hook_secret": "",
        "hook_targets": [],
        "min_severity": "debug",
        "dedup_window_seconds": 120,
        "max_alerts_per_hour": 60,
        "title_prefix": "",
        "notify_inbound": False,
        "notify_filters": [],
        "skip_ticket_notices": True,
        "outbound_timeout_seconds": 5,
        "queue_size": 64,
    }

    def __init__(self) -> None:
        super().__init__()
        self._inflight: "set[asyncio.Task]" = set()
        self._seen: "OrderedDict[str, float]" = OrderedDict()
        self._pushed: Deque[float] = deque(maxlen=4096)
        self._hook_hits = 0
        self._pushed_total = 0
        self._posted = 0
        self._post_errors = 0
        self._dropped = 0
        self._last_error = ""
        self._bot_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}

    # ------------------------------------------------------------- lifecycle
    async def on_load(self, context: Any) -> None:
        self.context = context
        log.info("[webhook_relay] loaded: %d target(s), secret=%s",
                 len(as_list(context.config_value("hook_targets"))),
                 "set" if str(context.config_value("hook_secret", "") or "") else "unset")

    async def on_enable(self, context: Any) -> None:
        self.context = context

    async def on_disable(self, context: Any) -> None:
        log.info("[webhook_relay] disabled: %d hook(s), %d group push(es), %d webhook post(s), "
                 "%d error(s), %d drop(s)", self._hook_hits, self._pushed_total, self._posted,
                 self._post_errors, self._dropped)

    async def on_unload(self) -> None:
        for task in list(self._inflight):
            task.cancel()
        self._inflight.clear()
        self._seen.clear()
        self._bot_cache.clear()

    # --------------------------------------------------------- inbound alerts
    async def on_hook(self, bot_id: str, secret: str, payload: Any, context: Any) -> PluginResult:
        if not as_bool(context.config_value("enabled", True), True):
            return PASS
        expected = str(context.config_value("hook_secret", "") or "").strip()
        if not expected:
            log.warning("[webhook_relay] hook called for bot %s but hook_secret is empty", bot_id)
            return PASS
        if not secret or not hmac.compare_digest(secret.strip(), expected):
            # A configured secret that does not match is ours to refuse: main.py maps
            # ``unauthorized`` to 401 instead of the bus's 404 no_plugin. An unset
            # secret above still passes, so another hook plugin can own the URL.
            return PluginResult(handled=False, status="unauthorized",
                                metadata={"plugin": PLUGIN_ID, "reason": "密钥不匹配"})
        if not str(bot_id or "").strip():
            return self._reject(context, bot_id, "missing bot_id")

        data, why = normalize_payload(payload)
        if data is None:
            return self._reject(context, bot_id, why)
        body, severity, source = alert_fields(data)
        if not body:
            return self._reject(context, bot_id, "payload 没有可用文本")
        floor = str(context.config_value("min_severity", "debug") or "debug")
        if severity_rank(severity) < severity_rank(floor):
            return self._reject(context, bot_id, f"severity {severity} < {floor}")
        if not self._not_flooded(context) or not self._not_duplicate(body, context):
            return PluginResult(handled=True, status="suppressed",
                                metadata={"plugin": PLUGIN_ID, "reason": "dedup_or_limit"})

        title = str(context.config_value("title_prefix", "") or "").strip()
        text = render(bot_id, source, severity, body, extract_urls(data))
        if title:
            text = f"{title} {text}"
        delivered, failures = await self._push(text, bot_id, context)
        self._hook_hits += 1
        if not delivered and failures:
            return PluginResult(handled=True, status="error",
                                metadata={"plugin": PLUGIN_ID, "error": failures[0], "targets": len(failures)})
        return PluginResult(handled=True, status="ok", reply="",
                            metadata={"plugin": PLUGIN_ID, "severity": severity or "", "source": source or "",
                                      "delivered": delivered, "failed": len(failures)})

    async def _push(self, text: str, bot_id: str, context: Any) -> Tuple[int, List[str]]:
        """Send to every configured target; the caller of ``handle_hook`` gets the tally."""
        targets = self._targets(context, bot_id)
        if not targets:
            log.warning("[webhook_relay] no hook_targets for bot %s", bot_id)
            return 0, ["no_target"]
        ok, errors = 0, []
        for chat_type, chat_ref in targets:
            status, error = "ok", ""
            try:
                result = await context.services.send_text(bot_id, chat_type, chat_ref, text,
                                                           plugin_id=PLUGIN_ID)
                if isinstance(result, dict) and not result.get("ok", True):
                    status, error = "error", str(result.get("error") or "send rejected")[:300]
            except Exception as exc:  # a dead CLI client is a failed delivery, not a crash
                status, error = "error", f"{type(exc).__name__}: {exc}"[:300]
            try:
                context.services.log_message(bot_id, "out", chat_type=chat_type, chat_ref=chat_ref,
                                             text=text[:2000], plugin_id=PLUGIN_ID, status=status, error=error)
            except Exception as exc:
                log.debug("[webhook_relay] log_message failed: %s", exc)
            if status == "ok":
                ok += 1
            else:
                errors.append(f"{chat_ref}: {error}")
        self._pushed_total += ok
        return ok, errors

    def _targets(self, context: Any, bot_id: str) -> List[Tuple[str, str]]:
        rows: List[Tuple[str, str]] = []
        for item in as_list(context.config_value("hook_targets")):
            if isinstance(item, dict):
                ref = str(item.get("chat_ref") or item.get("chat_id") or item.get("target") or "").strip()
                if not ref:
                    continue
                kind = REF_PREFIXES.get(ref[:1]) or str(item.get("chat_type") or "group")
                rows.append((kind, ref))
            elif str(item).strip():
                ref = str(item).strip()
                rows.append((REF_PREFIXES.get(ref[:1]) or "group", ref))
        return rows

    def _reject(self, context: Any, bot_id: str, why: str) -> PluginResult:
        """Claim the hook with an error so the route can report it instead of probing the next plugin."""
        log.warning("[webhook_relay] hook rejected for bot %s: %s", bot_id, why)
        return PluginResult(handled=True, status="error", metadata={"plugin": PLUGIN_ID, "reason": why[:300]})

    def _not_duplicate(self, body: str, context: Any) -> bool:
        window = max(0.0, as_number(context.config_value("dedup_window_seconds"), 120.0))
        if window <= 0:
            return True
        token = hashlib.sha256(body[:2000].encode("utf-8", "replace")).hexdigest()[:32]
        now = float(context.clock())
        while self._seen and now - next(iter(self._seen.values())) > window:
            self._seen.popitem(last=False)
        if token in self._seen:
            return False
        self._seen[token] = now
        return True

    def _not_flooded(self, context: Any) -> bool:
        cap = int(as_number(context.config_value("max_alerts_per_hour"), 0.0))
        if cap <= 0:
            return True
        now = float(context.clock())
        while self._pushed and now - self._pushed[0] > 3600:
            self._pushed.popleft()
        if len(self._pushed) >= cap:
            log.warning("[webhook_relay] alert budget exhausted (%d/h)", cap)
            return False
        self._pushed.append(now)
        return True

    # -------------------------------------------------------- outbound hooks
    async def on_message(self, event: Any, context: Any) -> PluginResult:
        """Mirror the message to the Bot's own webhook; never claims it."""
        if not as_bool(context.config_value("enabled", True), True) \
                or not as_bool(context.config_value("notify_inbound", False), False):
            return PASS
        message = Inbound.of(event)
        if not message.text or not message.bot_id:
            return PASS
        if as_bool(context.config_value("skip_ticket_notices", True), True) and TICKET_NOTICE_RE.match(message.text):
            return PASS  # a ticket notice we (or the router) just posted would echo back as an "alert"
        if not self._passes_filter(message, context):
            return PASS
        url, secret = self._bot_endpoint(message.bot_id, context)
        if not url:
            return PASS
        payload = json.dumps({
            "event": "message",
            "bot_id": message.bot_id,
            "chat_type": message.chat_type,
            "chat_ref": message.chat_ref,
            "sender": message.sender,
            "sender_name": message.sender_name,
            "text": message.text[:4000],
            "ts": message.ts or float(context.clock()),
        }, ensure_ascii=False, separators=(",", ":"))
        timeout = max(1.0, as_number(context.config_value("outbound_timeout_seconds"), 5.0))
        self._notify(message.bot_id, message.chat_ref, url, payload, secret, timeout, context)
        return PASS

    def _notify(self, bot_id: str, chat_ref: str, url: str, payload: str, secret: str,
                timeout: float, context: Any) -> int:
        """Fire the POST as a tracked task: slow endpoints must not stall the dispatch chain."""
        if len(self._inflight) >= max(1, int(as_number(context.config_value("queue_size"), 64.0))):
            self._dropped += 1
            return 0
        try:
            task = asyncio.get_running_loop().create_task(self._post(bot_id, chat_ref, url, payload, secret, timeout))
        except RuntimeError as exc:  # no loop, e.g. a sync self-test harness
            log.debug("[webhook_relay] notify skipped: %s", exc)
            return 0
        self._inflight.add(task)
        task.add_done_callback(self._inflight.discard)
        return 1

    async def _post(self, bot_id: str, chat_ref: str, url: str, payload: str, secret: str,
                    timeout: float) -> str:
        raw = payload.encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "popopx-bot-studio/1.0"}
        if secret:
            headers["X-Popopx-Signature"] = "sha256=" + hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
        status, error = "ok", ""
        try:
            async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
                response = await client.post(url, content=raw, headers=headers)
            if response.status_code >= 400:
                status, error = "error", f"HTTP {response.status_code}"
        except Exception as exc:  # an unreachable endpoint is a failed delivery, not a crash
            status, error = "error", f"{type(exc).__name__}: {exc}"[:300]
        if status == "ok":
            self._posted += 1
        else:
            self._post_errors += 1
            self._last_error = error
            log.warning("[webhook_relay] %s -> %s: %s", bot_id, url, error)
            try:
                context = self.context
                if context is not None:
                    context.services.log_message(bot_id, "out", chat_type="direct", chat_ref=chat_ref,
                                                 text=f"webhook {url}"[:2000], plugin_id=PLUGIN_ID,
                                                 status="error", error=error)
            except Exception as exc:
                log.debug("[webhook_relay] log_message failed: %s", exc)
        return status

    def _passes_filter(self, message: Inbound, context: Any) -> bool:
        rows = [item for item in as_list(context.config_value("notify_filters")) if isinstance(item, dict)]
        if not rows:
            return True
        lowered = message.text.casefold()
        for row in rows:
            chat_type = str(row.get("chat_type") or "").strip().casefold()
            if chat_type and chat_type != message.chat_type:
                continue
            keywords = [str(kw).casefold() for kw in as_list(row.get("keywords")) if str(kw).strip()]
            if not keywords or any(kw in lowered for kw in keywords):
                return True
        return False

    def _bot_endpoint(self, bot_id: str, context: Any) -> Tuple[str, str]:
        """``bots.webhook_url`` / ``bots.webhook_secret``, cached 10s to keep hot rows off the ledger."""
        now = float(context.clock())
        cached = self._bot_cache.get(bot_id)
        if cached and now - cached[0] < 10:
            return cached[1]
        try:
            row = context.db.get_bot(bot_id) or {}
            url = str(row.get("webhook_url") or "").strip()
            value = (url, str(row.get("webhook_secret") or "").strip())
        except Exception as exc:
            log.debug("[webhook_relay] get_bot(%s) failed: %s", bot_id, exc)
            return "", ""
        if len(self._bot_cache) > 256:
            self._bot_cache.pop(next(iter(self._bot_cache)), None)
        self._bot_cache[bot_id] = (now, value)
        return value
