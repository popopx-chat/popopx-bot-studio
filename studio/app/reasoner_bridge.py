"""大引擎（Reasoner）桥：只写话术，永不碰工具、永不落库。

双引擎的分工在这里被硬性收口：小引擎 :mod:`app.needle3_runtime` 负责把自由文本抽成
结构化工具调用，**本模块只负责把已经算清楚的事实写成一段人话**。因此它接收的是
``kind + facts``（提案号、时段、时区、被筛掉的候选数……），而不是原始聊天记录；它能
影响的只有措辞，改不了任何时间数值，也调不了任何工具。

三条不可退让的工程约束：

1. **话术永远有**。``compose`` 承诺不抛异常：未开启、URL 非法、明文 http 指向非回环、
   超时、非 200、返回体不是 JSON 对象、内容字段缺失——每一种都落到
   :mod:`app.agent_copy` 的确定性模板，并把原因记进 :attr:`last_reason` 与
   :meth:`stats`，后台能看到「为什么这句是模板」。
2. **API Key 只在内存里**。密钥只从 :class:`app.config.Settings` 读取，绝不进
   :meth:`status`、绝不进日志、绝不进异常文本：所有出网的错误字符串都先过
   :func:`redact`。明文 ``http`` 只允许回环（``127.x``/``localhost``/``::1``），
   因为桥会带上 Authorization，指向公网明文等于把令牌外送。
3. **不发裸请求**。传输层是可注入的 ``transport(method, url, headers, json, timeout)``，
   默认实现用已经钉住的 ``httpx``；自检注入替身，因此整套门禁在离线机器上跑得住。

Ollama（``/api/generate``，``{"response": ...}``）与 OpenAI 兼容端点
（``/v1/chat/completions``，``{"choices": [{"message": {"content": ...}}]}``）两种响应
形状都要支持，具体走哪一种由 ``REASONER_BASE_URL`` 的路径决定，不靠猜端口。
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

from . import agent_copy
from .config import Settings, is_loopback_http_url
from .i18n import FALLBACK_LOCALE, normalize_locale

TRANSPORT = Callable[[str, str, Dict[str, str], Dict[str, Any], float], Awaitable[Tuple[int, Any]]]
MAX_FACTS_CHARS = 2400
MAX_REPLY_CHARS = 1200
SYSTEM_PROMPT = (
    "你是 POPOPX 替身机器人的措辞引擎。你只把给定的事实写成一段自然语言回复："
    "不得新增、修改或猜测任何时间、日期、时区、时长、人名或地点；不得声称已经写入日历、"
    "读取文件或发送邀请——那些动作由用户确认后由系统执行。只输出这段话术本身，"
    "不要前缀、不要引号、不要解释、不要列表标记。"
)
_FENCE_RE = re.compile(r"^\s*```[a-zA-Z0-9_+-]*[ \t]*\n?|\n?[ \t]*```[ \t]*\s*$")
# 模型很爱给话术套引号，中文引号还是成对的，只比首尾字符相同会漏掉「」这类。
_QUOTE_PAIRS = (('"', '"'), ("'", "'"), ("“", "”"), ("‘", "’"), ("「", "」"), ("『", "』"))
# 密钥渗进错误串的形态远不止「header: 值」：`Authorization: Bearer sk-…`、JSON 的
# `"api_key": "sk-…"`、环境变量的 `REASONER_API_KEY = 'sk-…'`、还有没有键名的裸 `key=sk-…`。
# 键名规则连值一起吞（允许引号、允许 Bearer/Basic 前缀），形状规则再兜住没有键名的令牌本体，
# 两道都跑完才允许这段文本进日志、审计或后台。
_SECRET_KEY_RE = re.compile(
    r"""(?ix)
    (?P<prefix>
        (?:[A-Za-z0-9]+[_-])?
        (?:authorization|x-api-key|api[_ -]?key|apikey|access[_ -]?token|refresh[_ -]?token
         |token|secret|passwd|password|key)
        \s*["']?\s*[:=]\s*
        (?:bearer[ \t]+|basic[ \t]+|token[ \t]+)?
        ["']?
    )
    [^\s"',;)}]+
    """
)
_SECRET_SHAPE_RE = re.compile(r"\b(?:sk|ghp|gho|ghs|xoxb|xapp|glpat|pt)-[A-Za-z0-9_-]{6,}\b")


def redact(text: Any, *secrets: str) -> str:
    """Strip every known secret out of *text* before anyone can log it."""
    out = str(text if text is not None else "")
    for secret in secrets:
        value = str(secret or "")
        if len(value) >= 4:
            out = out.replace(value, "***")
            # 令牌常被截断引用（Bearer abcd…），把前缀形态一起去掉，避免留半截可猜。
            out = out.replace(value[:8], "***")
    out = _SECRET_KEY_RE.sub(lambda match: f'{match.group("prefix")}***', out)
    return _SECRET_SHAPE_RE.sub("***", out)


OLLAMA_DEFAULT_PORT = 11434  # 本仓 .env.example 与 plugins/llm_bridge.py 都用这个本机回环端口


def endpoint_for(base_url: str) -> Tuple[str, str]:
    """Return ``(url, kind)`` for *base_url*; kind is ``ollama`` or ``openai``.

    只做路径归一，不猜端口之外的东西。运维写哪种形态都能收敛到一个确定请求地址：

    * ``…/api/generate`` / ``…/api/chat`` / ``…/api`` → Ollama 原生
    * ``…/v1`` / ``…/chat/completions`` / 裸 ``https://host`` → OpenAI 兼容
    * 裸地址（无路径）→ 端口是 11434 就按 Ollama 原生（任何版本都有 ``/api/generate``），
      否则按 OpenAI 兼容（.env.example 推荐的 ``/v1`` 写法）

    协议不在 http/https 之内，或没有主机名，直接返回空串：调用方据此降级到模板，
    绝不拿一个畸形 URL 去开连接。
    """
    raw = str(base_url or "").strip().rstrip("/")
    if not raw:
        return "", ""
    parts = urlsplit(raw)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return "", ""
    path = (parts.path or "").rstrip("/")
    lowered = path.lower()
    if lowered.endswith("/chat/completions"):
        return raw, "openai"
    if lowered.endswith("/v1"):
        return raw + "/chat/completions", "openai"
    if lowered.endswith("/api/chat"):
        return raw[: -len("/api/chat")] + "/api/generate", "ollama"
    if lowered.endswith("/api/generate"):
        return raw, "ollama"
    if lowered.endswith("/api"):
        return raw + "/generate", "ollama"
    if lowered in {"", "/"}:
        try:
            port = parts.port
        except ValueError:  # 端口写成非法值：交给 _scheme_is_safe 之外的降级路径处理
            port = None
        if port == OLLAMA_DEFAULT_PORT:
            return raw + "/api/generate", "ollama"
        return raw + "/v1/chat/completions", "openai"
    if "/api" in lowered:
        return raw + "/generate", "ollama"
    return raw + "/v1/chat/completions", "openai"


def _scheme_is_safe(base_url: str) -> Tuple[bool, str]:
    """``https`` anywhere; ``http`` only to a literal loopback host."""
    candidate = str(base_url or "").strip()
    if not candidate:
        return False, "未配置 REASONER_BASE_URL"
    parts = urlsplit(candidate)
    if parts.scheme not in {"http", "https"}:
        return False, f"REASONER_BASE_URL 协议非法：{parts.scheme or '(空)'}"
    if not parts.netloc or not parts.hostname:
        # http:///v1 这种「有协议没主机」的串，报「协议非法」会把人引到完全错误的方向。
        return False, "REASONER_BASE_URL 缺少主机名"
    try:
        if parts.port is not None and not 0 < parts.port < 65536:
            return False, "REASONER_BASE_URL 端口超出合法范围"
    except ValueError:
        # config.is_loopback_http_url 对畸形端口是宽松的（按字符串前缀判断），
        # 这里必须自己收紧：非法端口拼进请求地址只会让 httpx 抛栈，不如直接降级。
        return False, "REASONER_BASE_URL 端口不是数字"
    if parts.username or parts.password:
        # userinfo 会改写真正连到谁（http://x@127.0.0.1 仍是回环，但凭据已经进了请求），
        # 所以必须排在回环/明文判定之前，且任何方案都不接受内嵌凭据。
        return False, "REASONER_BASE_URL 不允许内嵌用户名或密码"
    if parts.scheme == "http" and not is_loopback_http_url(candidate):
        return False, "明文 http 只允许回环地址（127.0.0.1/localhost/::1），远端必须用 https"
    return True, ""


def _flatten(payload: Any, *, limit: int = 400) -> str:
    """Collapse an engine error body into one short, secret-free line."""
    if isinstance(payload, Mapping):
        for key in ("error", "message", "detail", "stderr"):
            if payload.get(key):
                return _flatten(payload[key], limit=limit)
        payload = json.dumps(payload, ensure_ascii=False)[:limit]
    elif isinstance(payload, (list, tuple)):
        payload = " ".join(str(item) for item in payload[:4])
    text = redact(payload)
    return re.sub(r"\s+", " ", text).strip()[:limit]


@dataclass
class ReasonerOutcome:
    """What one ``compose`` call actually did — template or model, and why."""

    text: str
    source: str  # "reasoner" | "template"
    kind: str
    locale: str
    reason: str = ""
    latency_ms: float = 0.0
    status: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "source": self.source,
            "kind": self.kind,
            "locale": self.locale,
            "reason": self.reason,
            "latency_ms": round(float(self.latency_ms), 3),
            "status": self.status,
        }


@dataclass
class ReasonerBridge:
    """Talks to the big model, returns only copy. Never raises to the caller."""

    # ``settings`` 里带着 reasoner_api_key：自动生成的 repr 会把整份配置（含密钥）打进日志，
    # 因此这个字段不进 repr——status()/stats()/recent 已经是脱敏视图，调试够用。
    settings: Optional[Settings] = field(default=None, repr=False)
    transport: Optional[TRANSPORT] = None
    copy: Any = None
    clock: Callable[[], float] = field(default=time.perf_counter)

    def __post_init__(self) -> None:
        self.copy = self.copy or agent_copy
        self._calls = 0
        self._hits = 0
        self._fallbacks = 0
        self._errors = 0
        self.last_reason = ""
        self.last_source = ""
        self.recent: List[Dict[str, Any]] = []

    # ---------------------------------------------------------------- config
    @property
    def base_url(self) -> str:
        return str(getattr(self.settings, "reasoner_base_url", "") or "").strip()

    @property
    def model(self) -> str:
        return str(getattr(self.settings, "reasoner_model", "") or "").strip()

    @property
    def api_key(self) -> str:
        return str(getattr(self.settings, "reasoner_api_key", "") or "").strip()

    @property
    def timeout_seconds(self) -> float:
        value = getattr(self.settings, "reasoner_timeout_seconds", 20.0)
        try:
            seconds = float(value)
        except (TypeError, ValueError):
            return 20.0
        return seconds if 0.5 <= seconds <= 300.0 else 20.0

    def enabled(self) -> bool:
        """Configured *and* safe: switch on, URL present, scheme allowed."""
        if not bool(getattr(self.settings, "reasoner_enabled", False)):
            return False
        safe, _reason = _scheme_is_safe(self.base_url)
        return bool(safe and endpoint_for(self.base_url)[0])

    def resolve_locale(self, locale: str = "") -> str:
        return (
            normalize_locale(locale)
            or normalize_locale(str(getattr(self.settings, "default_locale", "") or ""))
            or FALLBACK_LOCALE
        )

    def status(self) -> Dict[str, Any]:
        """Dashboard view. The API key is reported as a boolean and never as a value."""
        url, kind = endpoint_for(self.base_url)
        safe, reason = _scheme_is_safe(self.base_url)
        return {
            "enabled": bool(getattr(self.settings, "reasoner_enabled", False)),
            "usable": self.enabled(),
            "endpoint": url,
            "endpoint_kind": kind,
            "model": self.model,
            "base_url": self.base_url,
            "timeout_seconds": self.timeout_seconds,
            "api_key_configured": bool(self.api_key),
            "scheme_ok": safe,
            "scheme_reason": reason,
            "calls": self._calls,
            "reasoner_replies": self._hits,
            "template_fallbacks": self._fallbacks,
            "errors": self._errors,
            "last_reason": self.last_reason,
            "last_source": self.last_source,
            "kinds": list(agent_copy.KINDS),
        }

    def stats(self) -> Dict[str, Any]:
        """Counter view used by the admin console (same redaction guarantees)."""
        payload = self.status()
        payload.pop("base_url", None)
        payload.pop("model", None)
        return payload

    # ---------------------------------------------------------------- headers
    def _safe(self, text: Any) -> str:
        """Route any engine-supplied error text through redaction with *this* key.

        密钥只存在于 settings 对象里，一旦第三方异常把 header 或 URL 原样回填，它就会
        顺着 reason 字符串进日志、进后台状态。所以每一条对外错误串都必须经过这里，而不是
        让调用点各自记得传密钥——传漏一次的代价是不可接受的。
        """
        return redact(text, self.api_key)

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _payload(
        self, kind: str, facts: Mapping[str, Any], locale: str, endpoint_kind: str
    ) -> Dict[str, Any]:
        """Build the request body for either engine dialect. Same facts, same cap."""
        prompt = self._prompt(kind, facts, locale)
        if endpoint_kind == "ollama":
            # /api/generate 的 system 字段并非所有代理层都实现，因此约束同时写进 prompt 正文，
            # 保证「不得编造时间/不得声称已写日历」这条边界不会因为转发器吞字段而失效。
            return {
                "model": self.model,
                "system": SYSTEM_PROMPT,
                "prompt": f"{SYSTEM_PROMPT}\n\n{prompt}",
                "stream": False,
                "raw": False,
                "options": {"temperature": 0.4, "num_predict": 240},
            }
        return {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.4,
            "max_tokens": 320,
            "stream": False,
        }

    def _prompt(self, kind: str, facts: Mapping[str, Any], locale: str) -> str:
        """Serialize the facts the small engine already resolved, verbatim and bounded."""
        template = self.copy.template(kind, FALLBACK_LOCALE)
        slim = _fact_text(facts)
        return (
            f"语言：{locale}\n"
            f"话术种类：{kind}\n"
            f"参考骨架（仅供理解结构，必须改写成本地语言，不要照抄）：{template}\n"
            f"事实（唯一可用的信息来源）：{slim}\n"
            "请只输出一句可以直接发给对方的回复。"
        )

    def _extract_reply(self, kind: str, payload: Any) -> Tuple[str, str]:
        """Pull the copy out of either response shape; ``(text, error)``."""
        if not isinstance(payload, Mapping):
            return "", f"响应体不是 JSON 对象：{type(payload).__name__}"
        if payload.get("error"):
            return "", f"引擎报错：{_flatten(payload.get('error'))}"
        candidates: List[Any] = []
        if kind == "ollama":
            candidates.append(payload.get("response"))
            message = payload.get("message")
            if isinstance(message, Mapping):
                candidates.append(message.get("content"))
        else:
            choices = payload.get("choices")
            if isinstance(choices, Sequence) and not isinstance(choices, (str, bytes)) and choices:
                first = choices[0]
                if isinstance(first, Mapping):
                    message = first.get("message")
                    if isinstance(message, Mapping):
                        candidates.append(message.get("content"))
                    candidates.append(first.get("text"))
        candidates.append(payload.get("text"))
        for raw in candidates:
            text = _clean_reply(raw)
            if text:
                return text, ""
        return "", "响应里没有可用的话术字段"

    # ---------------------------------------------------------------- compose
    async def compose(self, kind: str, facts: Optional[Mapping[str, Any]] = None, *, locale: str = "") -> str:
        """Copy for *kind*; falls back to :mod:`app.agent_copy` on any failure."""
        return (await self.outcome(kind, facts, locale=locale)).text

    async def outcome(
        self,
        kind: str,
        facts: Optional[Mapping[str, Any]] = None,
        *,
        locale: str = "",
    ) -> ReasonerOutcome:
        """Same contract as :meth:`compose`, but exposing *why* the text came out."""
        self._calls += 1
        wanted_locale = self.resolve_locale(locale)
        payload_facts = dict(facts or {})
        template_text = self.copy.render(kind, payload_facts, locale=wanted_locale)
        started = self.clock()

        def finish(text: str, source: str, reason: str, status: int = 0) -> ReasonerOutcome:
            result = ReasonerOutcome(
                text=text or template_text,
                source=source,
                kind=kind,
                locale=wanted_locale,
                reason=reason,
                latency_ms=(self.clock() - started) * 1000.0,
                status=status,
            )
            if source == "template":
                self._fallbacks += 1
            self.last_reason = reason
            self.last_source = source
            self.recent.append(result.as_dict())
            del self.recent[:-10]
            return result

        if not kind:
            self._errors += 1
            return finish("", "template", "缺少话术种类")
        if kind not in self.copy.KINDS:
            # 没有模板兜底的种类说明调用方拼错了：让模型自由发挥会产生一句无从核对的话，
            # 不如明确报错并返回空串，错误在自检/后台里可见。
            self._errors += 1
            return finish("", "template", f"未知话术种类：{kind}")
        if not bool(getattr(self.settings, "reasoner_enabled", False)):
            return finish("", "template", "REASONER_ENABLED 未开启")
        url, endpoint_kind = endpoint_for(self.base_url)
        safe, reason = _scheme_is_safe(self.base_url)
        if not safe or not url:
            self._errors += 1
            return finish("", "template", reason or "REASONER_BASE_URL 非法")
        transport = self.transport or self._default_transport
        request_body = self._payload(kind, payload_facts, wanted_locale, endpoint_kind)
        try:
            status, payload = await transport("POST", url, self._headers(), request_body, self.timeout_seconds)
        except Exception as exc:  # noqa: BLE001 - every transport failure degrades to template
            # 传输层的异常类型来自第三方（超时、连接被拒、TLS、JSON 解析），我们无法穷举，
            # 因此广接并强制过 redact：绝不让密钥或堆栈顺着错误字符串外溢。
            self._errors += 1
            return finish(
                "", "template", f"调用失败：{type(exc).__name__}: {self._safe(exc) or '（无错误信息）'}"
            )
        if int(status or 0) != 200:
            # 非 200 是运维要看见的错误（401 通常是密钥写错），只计回退会让后台一直显示健康。
            self._errors += 1
            detail = self._safe(_flatten(payload))
            return finish(
                "",
                "template",
                f"引擎返回 HTTP {int(status or 0)}{('：' + detail) if detail else ''}",
                status=int(status or 0),
            )
        text, error = self._extract_reply(endpoint_kind, payload)
        if error or not text:
            # _extract_reply 保证「没有正文」必然带原因，这里的 not text 只是同一条不变量的双保险。
            self._errors += 1
            return finish("", "template", self._safe(error) or "引擎返回空话术", status=int(status or 0))
        self._hits += 1
        return finish(text, "reasoner", "", status=int(status or 0))

    async def health(self, *, probe: bool = True) -> Dict[str, Any]:
        """Reachability probe for the admin console; never raises, never leaks."""
        base = self.status()
        base.update(
            {"ok": False, "reachable": False, "probe": bool(probe), "latency_ms": 0.0, "status": 0, "detail": ""}
        )
        if not base["usable"]:
            base["detail"] = base["scheme_reason"] or "推理引擎未启用或地址非法"
            return base
        if not probe:
            base["detail"] = "未探测（probe=False）"
            return base
        url, kind = base["endpoint"], base["endpoint_kind"]
        probe_url, probe_body = (
            (urlunsplit(urlsplit(url)._replace(path="/api/tags")), {})
            if kind == "ollama"
            else (urlunsplit(urlsplit(url)._replace(path="/v1/models")), {})
        )
        started = self.clock()
        try:
            status, payload = await (self.transport or self._default_transport)(
                "GET", probe_url, self._headers(), probe_body, self.timeout_seconds
            )
        except Exception as exc:  # noqa: BLE001 - an unreachable engine is a health finding, not a crash
            base["detail"] = f"{type(exc).__name__}: {self._safe(exc) or '（无错误信息）'}"
            base["latency_ms"] = round((self.clock() - started) * 1000.0, 3)
            return base
        base["latency_ms"] = round((self.clock() - started) * 1000.0, 3)
        base["status"] = int(status or 0)
        base["reachable"] = int(status or 0) == 200
        base["ok"] = base["reachable"]
        base["detail"] = (
            "可用" if base["reachable"] else f"HTTP {int(status or 0)}：{self._safe(_flatten(payload))}"
        )
        return base

    # ------------------------------------------------------------- httpx path
    async def _default_transport(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        payload: Dict[str, Any],
        timeout: float,
    ) -> Tuple[int, Any]:
        """Real outbound call, only for a loopback/https endpoint. Never used in tests."""
        safe, reason = _scheme_is_safe(url)
        if not safe:
            raise ReasonerTransportError(reason)
        import httpx  # noqa: PLC0415 - pinned dependency, imported lazily so tests stay socket-free

        body_payload = None if method.upper() == "GET" else payload
        try:
            # trust_env=False 是隔离要求，不是风格偏好：环境变量里的 HTTP_PROXY/ALL_PROXY 会把
            # 这条携带 Authorization 的请求转手交给第三方代理，等于替身会话内容出本机；
            # 代理值是 socks:// 时还会直接抛 socksio ImportError。回环请求本就不该经过代理。
            # follow_redirects=False 同理：本机服务返回一个指向公网的 302，若自动跟随就等于
            # 把 Bearer 令牌亲手送到那个外部地址（SSRF + 凭据外送），这里让它降级为模板话术。
            async with httpx.AsyncClient(timeout=timeout, trust_env=False, follow_redirects=False) as client:
                response = await client.request(method, url, headers=headers, json=body_payload)
        except httpx.TimeoutException as exc:
            raise ReasonerTransportError(f"推理引擎超时（{timeout:.1f}s）") from exc
        except httpx.HTTPError as exc:
            raise ReasonerTransportError(self._safe(exc) or type(exc).__name__) from exc
        try:
            body: Any = response.json()
        except ValueError as exc:
            raise ReasonerTransportError(f"响应不是合法 JSON：{self._safe(exc)}") from exc
        return int(response.status_code), body

    def counts(self) -> Dict[str, int]:
        return {"calls": self._calls, "reasoner": self._hits, "template": self._fallbacks, "errors": self._errors}


class ReasonerTransportError(RuntimeError):
    """Transport-level refusal (bad scheme, timeout, non-JSON body)."""


def _fact_text(facts: Mapping[str, Any]) -> str:
    """Compact, bounded, key-sorted JSON so identical facts render identically."""
    try:
        text = json.dumps(dict(facts or {}), ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str)
    except (TypeError, ValueError):
        text = str(facts)
    return text[:MAX_FACTS_CHARS] + ("…" if len(text) > MAX_FACTS_CHARS else "")


def _clean_reply(raw: Any) -> str:
    """Normalise a model reply into one sendable line. Empty/whitespace-only → ``''``."""
    if raw is None:
        return ""
    if isinstance(raw, (Mapping, list, tuple)):
        raw = json.dumps(raw, ensure_ascii=False)
    text = _FENCE_RE.sub("", str(raw)).strip()
    for left, right in _QUOTE_PAIRS:
        if len(text) >= 2 and text[0] == left and text[-1] == right:
            text = text[1:-1].strip()
            break
    # 话术是一句能直接发出去的气泡文本：换行折叠成空格，多余空白压扁，尾部截断。
    text = re.sub(r"\s+", " ", text).strip()
    return text[:MAX_REPLY_CHARS].strip()


__all__ = [
    "MAX_FACTS_CHARS",
    "MAX_REPLY_CHARS",
    "SYSTEM_PROMPT",
    "ReasonerBridge",
    "ReasonerOutcome",
    "ReasonerTransportError",
    "endpoint_for",
    "redact",
]
