"""通道 B 的访客页与控制台 ``/api/agent/*`` 管理路由。

两条通道的信任边界完全不同，因此这个模块清清楚楚分成两半：

* **公开一半**（``/book/<token>``）：访客没有任何凭据，能看到的只有门户自己愿意给出的
  脱敏视图。令牌、IP、User-Agent 只在本请求内存活——不写日志、不进 URL 回显、不落账本。
* **管理一半**（``/api/agent/*``）：全部挂在 ``require_admin`` 之后，给主人看的是自己的
  数据（含可直接转发的预约链接）。列表里的令牌一律只剩前 8 位掩码。

路由层只做「取参 → 调协作对象 → 转成 HTTP」：排期、掩码、签名判定、落地写日历全部在
:mod:`app.guest_portal` / :mod:`app.agent_runtime` 里，本模块不复制任何业务规则。
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections import OrderedDict
from typing import Any, Dict, Mapping, Optional
from urllib.parse import parse_qs, quote

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import Response

from .agent_preferences import PreferenceError
from .database import AUDIT_STAGES, LedgerError
from .guest_portal import CSP_POLICY, LINK_PATH_PREFIX, GuestError, token_mask
from .i18n import LOCALES, normalize_locale
from .mac_node_bridge import MacNodeError
from .orchestrator import MAX_TASK_CONCURRENCY, MAX_TASK_HOPS, OrchestratorError

ADMIN_PREFIX = "/api/agent"
NONCE_CHARS = 24
NONCE_KEY_CHARS = 32
NONCE_JAR_MAX = 512
FORM_OP_MESSAGE = "message"
FORM_OP_ICS = "ics"
ICS_MEDIA_TYPE = "text/calendar; charset=utf-8"
MAX_BODY_BYTES = 64 * 1024


class _NonceJar:
    """一次性表单令牌登记表：GET 发、POST 销，进程内最多 ``NONCE_JAR_MAX`` 条。

    访客页零 Cookie、零脚本，跨站伪造表单只能靠这个 nonce 挡——访客必须先真正打开过页面
    （那一下才计入访问额度并绑定会话），提交才可能被接受。
    """

    def __init__(self, limit: int = NONCE_JAR_MAX) -> None:
        self.limit = max(8, int(limit))
        self._seen: "OrderedDict[str, str]" = OrderedDict()

    def issue(self, key: str) -> str:
        nonce = secrets.token_urlsafe(NONCE_CHARS)
        self._seen[key] = nonce
        self._seen.move_to_end(key)
        while len(self._seen) > self.limit:
            self._seen.popitem(last=False)
        return nonce

    def match(self, key: str, nonce: str) -> bool:
        wanted = self._seen.get(key, "")
        if not wanted or not nonce:
            return False
        return secrets.compare_digest(wanted, str(nonce)[:128])

    def drop(self, key: str) -> None:
        self._seen.pop(key, None)

    def __len__(self) -> int:
        return len(self._seen)


_NONCES = _NonceJar()


def _clean(value: Any, limit: int) -> str:
    return str(value if value is not None else "").strip()[:limit]


def _token_key(token: str) -> str:
    """nonce 的键：只存令牌摘要，进程内绝不保留完整令牌本身。"""
    return hashlib.sha256(f"ppx-book\0{_clean(token, 4096)}".encode("utf-8")).hexdigest()[:NONCE_KEY_CHARS]


def _request_headers(request: Request) -> Dict[str, str]:
    """交给门户算访客指纹的头：附加 ``peer`` 作为最后一跳，原始头本身不外传。"""
    headers = {str(key).lower(): str(value) for key, value in request.headers.items()}
    client = getattr(request, "client", None)
    peer = _clean(getattr(client, "host", ""), 64)
    if peer:
        headers["peer"] = peer
    return headers


def _locale_of(request: Request, form: Optional[Mapping[str, Any]] = None) -> str:
    wanted = normalize_locale(_clean((form or {}).get("locale"), 32)) or normalize_locale(
        request.query_params.get("locale", "")
    )
    return wanted if wanted in LOCALES else ""


def _guest_headers(extra: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    """访客响应头：不缓存、不带引用、不索引；CSP 由门户钉住样式哈希。"""
    headers = {
        "Cache-Control": "no-store, max-age=0",
        "Referrer-Policy": "no-referrer",
        "X-Robots-Tag": "noindex, nofollow",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": CSP_POLICY,
    }
    headers.update(dict(extra or {}))
    return headers


def _html(body: str, status: int = 200, extra: Optional[Mapping[str, str]] = None) -> Response:
    return Response(body, status_code=status, media_type="text/html; charset=utf-8", headers=_guest_headers(extra))


def _ics_response(filename: str, body: str) -> Response:
    safe = _clean(filename, 120) or "invitation.ics"
    ascii_name = (safe.encode("ascii", "ignore").decode("ascii").replace('"', "")) or "invitation.ics"
    disposition = f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{quote(safe)}'
    return Response(body, media_type=ICS_MEDIA_TYPE, headers=_guest_headers({"Content-Disposition": disposition}))


def _int(value: Any, fallback: int, *, low: int, high: int) -> int:
    try:
        number = int(round(float(value)))
    except (TypeError, ValueError):
        number = fallback
    return max(low, min(high, number))


def _float(value: Any, fallback: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return fallback
    if number != number or number in (float("inf"), float("-inf")):
        return fallback
    return number


# ------------------------------------------------------------------- 公开通道
def add_book_routes(app: FastAPI) -> None:
    """``/book/<token>``：访客打开、发言、下载 .ics，全部同源在这一个前缀下。"""
    from .main import stack_of  # noqa: PLC0415 - main 顶层导入本模块，反向引用只能延后

    def portal_of(request: Request) -> Any:
        runtime = getattr(stack_of(request), "agent", None)
        if runtime is None:
            raise HTTPException(
                status_code=503, detail={"ok": False, "error_code": 503, "description": "替身机器人运行时未装配"}
            )
        return runtime.portal

    def page(
        portal: Any,
        view: Mapping[str, Any],
        *,
        locale: str,
        error: str = "",
        nonce: str = "",
        status: int = 200,
    ) -> Response:
        return _html(
            portal.render(view, locale=locale, error=error, form={"action": "", "nonce": nonce}), status
        )

    @app.get(LINK_PATH_PREFIX.rstrip("/"), include_in_schema=False)
    async def book_without_token(request: Request) -> Response:
        portal = portal_of(request)
        return page(portal, {"messages": []}, locale=_locale_of(request), error="missing_token", status=400)

    @app.get(LINK_PATH_PREFIX + "{token}", include_in_schema=False)
    async def book_page(token: str, request: Request) -> Response:
        portal = portal_of(request)
        locale = _locale_of(request)
        key = _token_key(token)
        try:
            view = await portal.resolve(token, headers=_request_headers(request))
        except GuestError as exc:
            _NONCES.drop(key)
            return page(
                portal, _fallback_view(request, token), locale=locale, error=exc.reason, status=exc.http_status
            )
        view["csrf"] = _NONCES.issue(key)
        return page(portal, view, locale=locale, nonce=view["csrf"])

    @app.post(LINK_PATH_PREFIX + "{token}", include_in_schema=False)
    async def book_submit(token: str, request: Request) -> Response:
        """同一个 URL 收两种表单：``__op=message`` 说话，``__op=ics`` 下载日历邀请。"""
        portal = portal_of(request)
        key = _token_key(token)
        form = await _form(request)
        locale = _locale_of(request, form)
        if not _NONCES.match(key, _clean(form.get("nonce"), 128)):
            # 不匹配就换发新 nonce：老表单永久失效，但真访客刷新这一页还能继续说话。
            view = _fallback_view(request, token)
            view["csrf"] = _NONCES.issue(key)
            return page(
                portal, view, locale=locale, error="stale_form", nonce=view["csrf"], status=409
            )
        headers = _request_headers(request)
        try:
            if _clean(form.get("__op"), 16) == FORM_OP_ICS:
                filename, body = await portal.ics(token, headers=headers)
                return _ics_response(filename, body)
            reply = await portal.message(token, _clean(form.get("message"), 4000), headers=headers)
        except GuestError as exc:
            view = _fallback_view(request, token)
            view["csrf"] = _NONCES.issue(key)
            return page(
                portal, view, locale=locale, error=exc.reason, nonce=view["csrf"], status=exc.http_status
            )
        except LedgerError:
            return page(
                portal, _fallback_view(request, token), locale=locale, error="ledger_unavailable", status=503
            )
        view = _fallback_view(request, token)
        view["csrf"] = _NONCES.issue(key)
        view["ics_ready"] = bool(view.get("ics_ready")) or bool(_clean(reply.get("proposal_id"), 64))
        return page(portal, view, locale=locale, nonce=view["csrf"])

    @app.get(LINK_PATH_PREFIX + "{token}/invite.ics", include_in_schema=False)
    async def book_invite(token: str, request: Request) -> Response:
        """直链下载：仍然要求同一段会话与「主人已确认」，不额外消耗访问额度。"""
        portal = portal_of(request)
        try:
            filename, body = await portal.ics(token, headers=_request_headers(request))
        except GuestError as exc:
            return page(
                portal,
                _fallback_view(request, token),
                locale=_locale_of(request),
                error=exc.reason,
                status=exc.http_status,
            )
        return _ics_response(filename, body)


def _row_for(request: Request, token: str) -> Dict[str, Any]:
    """按令牌回查链接行（只为重新渲染页面，绝不回显令牌本身）。"""
    from .main import stack_of  # noqa: PLC0415

    try:
        row = stack_of(request).db.get_guest_link(token=_clean(token, 4096))
    except (LedgerError, ValueError):
        return {}
    return dict(row or {})


def _fallback_view(request: Request, token: str) -> Dict[str, Any]:
    """表单提交后重新渲染用的视图：字段名与 :meth:`GuestPortal.resolve` 对齐。"""
    row = _row_for(request, token)
    if not row:
        return {"messages": []}
    row["token_mask"] = token_mask(_clean(row.get("token"), 4096))
    row.pop("token", None)
    row["remaining"] = max(0, int(row.get("max_uses") or 1) - int(row.get("uses") or 0))
    row["messages"] = _messages(request, str(row.get("link_id", "")))
    row["ics_ready"] = _ics_ready(request, row)
    row["confirmed"] = row["ics_ready"]
    return row


def _messages(request: Request, link_id: str) -> list:
    from .main import stack_of  # noqa: PLC0415

    if not link_id:
        return []
    try:
        return list(stack_of(request).db.list_guest_messages(link_id, limit=40))
    except (LedgerError, ValueError):
        return []


def _ics_ready(request: Request, row: Mapping[str, Any]) -> bool:
    from .main import stack_of  # noqa: PLC0415

    pid = _clean(row.get("proposal_id"), 64)
    if not pid:
        return False
    try:
        proposal = stack_of(request).db.get_proposal(pid)
    except (LedgerError, ValueError):
        return False
    if not proposal or str(proposal.get("status")) != "approved":
        return False
    return float(proposal.get("end_ts") or 0) > float(proposal.get("start_ts") or 0) > 0


async def _form(request: Request) -> Dict[str, Any]:
    """解析访客表单：只用标准库解 ``x-www-form-urlencoded``。

    仓库刻意不依赖 ``python-multipart``（``request.form()`` 缺它就直接抛错），而访客页是零脚本
    的原生表单，本来就只有 urlencoded 一种形状；multipart 留一次尽力解析，失败当空表单。
    """
    raw = await request.body()
    if not raw or len(raw) > MAX_BODY_BYTES:
        return {}
    ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if ctype == "application/x-www-form-urlencoded":
        text = raw.decode("utf-8", "replace")
        pairs = parse_qs(text, keep_blank_values=True)
        return {key: values[0] for key, values in pairs.items() if values}
    if ctype == "multipart/form-data":
        try:
            data = await request.form()
        except (RuntimeError, OSError, ValueError):
            return {}
        return {str(key): value for key, value in data.items()}
    return {}


# ------------------------------------------------------------------- 管理通道
def add_admin_routes(app: FastAPI) -> None:
    """控制台三块面板的数据面：路由引擎与偏好、访客链接、全生命周期审计。"""
    from .main import (  # noqa: PLC0415 - 与 main 互相引用，辅助函数在装配期才取
        body_of,
        fail,
        ok,
        require_admin,
        stack_of,
    )

    def runtime_of(request: Request) -> Any:
        runtime = getattr(stack_of(request), "agent", None)
        if runtime is None:
            raise HTTPException(
                status_code=503, detail={"ok": False, "error_code": 503, "description": "替身机器人运行时未装配"}
            )
        return runtime

    def need_bot(request: Request, bot_id: str) -> str:
        clean = _clean(bot_id, 64)
        if not clean:
            raise HTTPException(status_code=400, detail={"ok": False, "error_code": 400, "description": "缺少 bot_id"})
        try:
            bot = stack_of(request).db.get_bot(clean)
        except (LedgerError, ValueError) as exc:
            raise HTTPException(
                status_code=503, detail={"ok": False, "error_code": 503, "description": f"账本读取失败：{exc}"}
            ) from exc
        if not bot:
            raise HTTPException(
                status_code=404, detail={"ok": False, "error_code": 404, "description": f"Bot {clean} 不存在"}
            )
        return clean

    def ledger(request: Request) -> Any:
        return stack_of(request).db

    @app.get(f"{ADMIN_PREFIX}/summary")
    async def agent_summary(request: Request, bot_id: str = "", _=Depends(require_admin)) -> Dict[str, Any]:
        runtime = runtime_of(request)
        owner = _clean(bot_id, 64)
        settings = stack_of(request).settings
        try:
            base = runtime.portal.public_base()
        except GuestError as exc:
            base = ""
            reason = exc.reason
        else:
            reason = ""
        payload: Dict[str, Any] = {
            "runtime": runtime.status(),
            "funnel": ledger(request).negotiation_funnel(owner or None),
            "node": runtime.node.status(),
            "guest": {
                "enabled": bool(settings.guest_enabled),
                "public_base": base,
                "prefix": LINK_PATH_PREFIX,
                "reason": reason,
            },
            # 面板的 stage 下拉必须由账本的 CHECK 约束供数，不能在前后各抄一份清单。
            "stages": list(AUDIT_STAGES),
        }
        if owner:
            payload["bot"] = runtime.bot_status(owner)
        return ok(payload)

    @app.get(f"{ADMIN_PREFIX}/engine")
    async def agent_engine(request: Request, _=Depends(require_admin)) -> Dict[str, Any]:
        runtime = runtime_of(request)
        needle = runtime.needle.status()
        return ok({"needle": needle, "reasoner": runtime.reasoner.status(), "tools": list(needle.get("tools") or [])})

    @app.post(f"{ADMIN_PREFIX}/engine")
    async def agent_engine_action(request: Request, _=Depends(require_admin)) -> Any:
        runtime = runtime_of(request)
        body = await body_of(request)
        action = _clean(body.get("action"), 16).lower()
        needle = runtime.needle
        if action not in ("load", "unload", "reload"):
            return fail(400, "action 只能是 load / unload / reload")
        try:
            if action == "unload":
                needle.unload()
            else:
                if action == "reload":
                    needle.unload()
                needle.load()
        except Exception as exc:  # noqa: BLE001 - 权重问题原样回报，绝不粉饰成成功
            return fail(503, f"引擎操作失败：{type(exc).__name__}: {str(exc)[:200]}")
        return ok({"action": action, "engine": needle.engine, "needle": needle.status()})

    @app.post(f"{ADMIN_PREFIX}/extract")
    async def agent_extract(request: Request, _=Depends(require_admin)) -> Any:
        """控制台「拿这句话试一下路由」：只做抽取，不写日历、不发消息、不落提案。"""
        runtime = runtime_of(request)
        body = await body_of(request)
        text = _clean(body.get("text"), 2000)
        if not text:
            return fail(400, "text 不能为空")
        owner = _clean(body.get("bot_id"), 64)
        row = runtime.preferences.load(owner) if owner else {}
        zone = _clean(body.get("timezone"), 64) or (runtime.zone_for(owner, row) if owner else "")
        locale = normalize_locale(_clean(body.get("locale"), 32)) or runtime.locale_for(owner, row)
        hints = {
            "timezone": zone,
            "now": time.time(),
            "duration_minutes": _int(body.get("duration_minutes"), 60, low=5, high=480),
        }
        extraction = runtime.needle.extract(text, locale=locale, hints=hints)
        return ok({"bot_id": owner, "locale": locale, "timezone": zone, "extraction": extraction.as_dict()})

    # --------------------------------------------------------------- 偏好规则
    @app.get(ADMIN_PREFIX + "/prefs/{bot_id}")
    async def agent_prefs_read(bot_id: str, request: Request, _=Depends(require_admin)) -> Any:
        runtime = runtime_of(request)
        owner = need_bot(request, bot_id)
        return ok({
            "bot_id": owner,
            "preferences": runtime.preferences.load(owner),
            "summary": runtime.preferences.summary(owner),
        })

    @app.post(ADMIN_PREFIX + "/prefs/{bot_id}")
    async def agent_prefs_write(bot_id: str, request: Request, _=Depends(require_admin)) -> Any:
        runtime = runtime_of(request)
        owner = need_bot(request, bot_id)
        body = await body_of(request)
        raw = body.get("preferences")
        patch = raw if isinstance(raw, dict) else body
        try:
            saved = runtime.preferences.save(owner, patch)
        except PreferenceError as exc:
            return fail(400, f"偏好校验未通过：{exc}")
        except (OSError, ValueError) as exc:
            return fail(503, f"偏好写入失败：{type(exc).__name__}")
        return ok({"bot_id": owner, "preferences": saved, "summary": runtime.preferences.summary(owner)})

    @app.post(ADMIN_PREFIX + "/prefs/{bot_id}/reset")
    async def agent_prefs_reset(bot_id: str, request: Request, _=Depends(require_admin)) -> Any:
        runtime = runtime_of(request)
        owner = need_bot(request, bot_id)
        try:
            return ok({"bot_id": owner, "preferences": runtime.preferences.reset(owner)})
        except (OSError, PreferenceError, ValueError) as exc:
            return fail(503, f"偏好重置失败：{type(exc).__name__}")

    # --------------------------------------------------------------- 对端配对
    @app.get(f"{ADMIN_PREFIX}/peers")
    async def agent_peers(request: Request, bot_id: str = "", _=Depends(require_admin)) -> Any:
        runtime = runtime_of(request)
        owner = need_bot(request, bot_id)
        peers = [peer.as_dict() for peer in runtime.load_peers(owner, refresh=True).values()]
        return ok({"bot_id": owner, "peers": peers, "self_identity": runtime.identity_for(owner)})

    @app.post(f"{ADMIN_PREFIX}/peers")
    async def agent_peer_pair(request: Request, _=Depends(require_admin)) -> Any:
        runtime = runtime_of(request)
        body = await body_of(request)
        owner = need_bot(request, _clean(body.get("bot_id"), 64))
        try:
            peer = runtime.pair_peer(
                owner,
                _clean(body.get("identity"), 160),
                key=_clean(body.get("key"), 128),
                label=_clean(body.get("label"), 80),
                chat=_clean(body.get("chat"), 32),
            )
        except (ValueError, OSError) as exc:
            return fail(400, f"配对失败：{exc}")
        return ok({"bot_id": owner, "peer": peer.as_dict()})

    @app.post(f"{ADMIN_PREFIX}/peers/remove")
    async def agent_peer_remove(request: Request, _=Depends(require_admin)) -> Any:
        runtime = runtime_of(request)
        body = await body_of(request)
        owner = need_bot(request, _clean(body.get("bot_id"), 64))
        return ok({"bot_id": owner, "removed": runtime.unpair_peer(owner, _clean(body.get("identity"), 160))})

    # ----------------------------------------------------------- 提案与协商
    @app.get(f"{ADMIN_PREFIX}/proposals")
    async def agent_proposals(
        request: Request, bot_id: str = "", status: str = "", limit: int = 50, _=Depends(require_admin)
    ) -> Any:
        owner = _clean(bot_id, 64)
        try:
            rows = ledger(request).list_proposals(
                owner or None, status=_clean(status, 24) or None, limit=_int(limit, 50, low=1, high=500)
            )
        except (LedgerError, ValueError) as exc:
            return fail(503, f"账本读取失败：{type(exc).__name__}")
        return ok({"proposals": rows, "stats": ledger(request).proposal_stats(owner or None)})

    @app.post(ADMIN_PREFIX + "/proposals/{proposal_id}/decision")
    async def agent_proposal_decision(proposal_id: str, request: Request, _=Depends(require_admin)) -> Any:
        """主人在控制台确认或否决：与卡片回执走完全同一条落地链路，绝不另开一条。"""
        runtime = runtime_of(request)
        body = await body_of(request)
        pid = _clean(proposal_id, 64)
        decision = _clean(body.get("decision"), 16).lower() or "approve"
        if decision not in ("approve", "confirm", "yes", "decline", "reject", "no", "alternative"):
            return fail(400, "decision 只能是 approve / decline / alternative")
        try:
            record = ledger(request).get_proposal(pid)
        except (LedgerError, ValueError) as exc:
            return fail(503, f"账本读取失败：{type(exc).__name__}")
        if not record:
            return fail(404, f"提案 {pid} 不存在")
        bot_id = _clean(record.get("bot_id"), 64)
        chat_ref = _clean(body.get("chat_ref"), 32)
        locale = _clean(body.get("locale"), 16)
        if decision in ("approve", "confirm", "yes"):
            reply = await runtime.approve(bot_id, pid, chat_ref=chat_ref, locale=locale)
        elif decision in ("decline", "reject", "no"):
            reply = await runtime.approve(bot_id, pid, chat_ref=chat_ref, locale=locale, decision="decline")
        else:
            reply = await runtime.approve(bot_id, pid, chat_ref=chat_ref, locale=locale, decision="alternative")
        after = ledger(request).get_proposal(pid) or {}
        return ok({"proposal_id": pid, "reply": reply, "status": after.get("status"), "proposal": after})

    @app.get(f"{ADMIN_PREFIX}/negotiations")
    async def agent_negotiations(
        request: Request, bot_id: str = "", status: str = "", limit: int = 50, _=Depends(require_admin)
    ) -> Any:
        owner = _clean(bot_id, 64)
        try:
            rows = ledger(request).list_negotiations(
                owner or None, status=_clean(status, 24) or None, limit=_int(limit, 50, low=1, high=500)
            )
        except (LedgerError, ValueError) as exc:
            return fail(503, f"账本读取失败：{type(exc).__name__}")
        return ok({"negotiations": rows, "stats": ledger(request).negotiation_stats(owner or None)})

    @app.post(f"{ADMIN_PREFIX}/negotiate")
    async def agent_negotiate(request: Request, _=Depends(require_admin)) -> Any:
        """主人授权后由本机主动向对端 Bot 起手（通道 A）。"""
        runtime = runtime_of(request)
        body = await body_of(request)
        owner = need_bot(request, _clean(body.get("bot_id"), 64))
        peer = _clean(body.get("peer") or body.get("peer_identity"), 160)
        if not peer:
            return fail(400, "缺少 peer（对端身份或会话引用）")
        window = body.get("window")
        out = await runtime.start_negotiation(
            owner,
            peer,
            duration_minutes=_int(body.get("duration_minutes"), 60, low=5, high=480),
            owner_tz=_clean(body.get("owner_tz") or body.get("timezone"), 64),
            peer_tz=_clean(body.get("peer_tz"), 64),
            window=[_float(item, 0.0) for item in list(window or [])] if isinstance(window, (list, tuple)) else (),
            label=_clean(body.get("label"), 80),
            days=_int(body.get("days"), 0, low=0, high=30),
        )
        return ok({"bot_id": owner, "peer": peer, **out})

    @app.get(f"{ADMIN_PREFIX}/audit")
    async def agent_audit(
        request: Request,
        bot_id: str = "",
        stage: str = "",
        level: str = "",
        proposal_id: str = "",
        limit: int = 120,
        _=Depends(require_admin),
    ) -> Any:
        owner = _clean(bot_id, 64)
        wanted = _clean(stage, 24)
        if wanted and wanted not in AUDIT_STAGES:
            return fail(400, f"stage 只能是 {'/'.join(AUDIT_STAGES)}")
        try:
            rows = ledger(request).recent_negotiations(
                owner or None,
                limit=_int(limit, 120, low=1, high=1000),
                stage=wanted or None,
                level=_clean(level, 12) or None,
                proposal_id=_clean(proposal_id, 64) or None,
            )
        except (LedgerError, ValueError) as exc:
            return fail(503, f"账本读取失败：{type(exc).__name__}")
        return ok({"audit": rows, "funnel": ledger(request).negotiation_funnel(owner or None)})

    # --------------------------------------------------------------- 访客链接
    @app.get(f"{ADMIN_PREFIX}/guest/links")
    async def agent_guest_links(
        request: Request, bot_id: str = "", include_expired: bool = False, _=Depends(require_admin)
    ) -> Any:
        runtime = runtime_of(request)
        owner = _clean(bot_id, 64)
        portal = runtime.portal
        try:
            links = await portal.links(owner or None, include_expired=bool(include_expired))
        except GuestError as exc:
            return fail(exc.http_status, f"读取失败：{exc.detail}")
        except (LedgerError, ValueError) as exc:
            return fail(503, f"账本读取失败：{type(exc).__name__}")
        # 列表响应里每行都是 :meth:`GuestPortal.link_url` 之外的脱敏视图：只有掩码指纹，没有令牌。
        return ok({
            "links": links,
            "stats": ledger(request).link_stats(owner or None),
            "public_base": portal.public_base(),
            "prefix": LINK_PATH_PREFIX,
        })

    @app.post(f"{ADMIN_PREFIX}/guest/links")
    async def agent_guest_issue(request: Request, _=Depends(require_admin)) -> Any:
        runtime = runtime_of(request)
        body = await body_of(request)
        owner = need_bot(request, _clean(body.get("bot_id"), 64))
        raw_ttl = body.get("ttl_hours")
        try:
            link = await runtime.portal.issue(
                owner,
                ttl_hours=_float(raw_ttl, 24.0) if raw_ttl not in (None, "") else None,
                max_uses=_int(body.get("max_uses"), 1, low=1, high=1000),
                duration_minutes=_int(body.get("duration_minutes"), 60, low=5, high=480),
                topic=_clean(body.get("topic"), 120),
                label=_clean(body.get("label"), 80),
                timezone=_clean(body.get("timezone"), 64),
                created_by=_clean(body.get("created_by"), 80),
            )
        except GuestError as exc:
            return fail(exc.http_status, f"签发失败：{exc.detail}")
        except (LedgerError, ValueError) as exc:
            return fail(503, f"签发失败：{type(exc).__name__}")
        return ok({"bot_id": owner, "link": link})

    @app.post(ADMIN_PREFIX + "/guest/links/{link_id}/revoke")
    async def agent_guest_revoke(link_id: str, request: Request, _=Depends(require_admin)) -> Any:
        runtime = runtime_of(request)
        body = await body_of(request)
        _NONCES.drop(_token_key(_clean(body.get("token"), 4096)))
        try:
            result = await runtime.portal.revoke(_clean(body.get("bot_id"), 64), _clean(link_id, 64))
        except GuestError as exc:
            return fail(exc.http_status, f"撤销失败：{exc.detail}")
        except (LedgerError, ValueError) as exc:
            return fail(503, f"撤销失败：{type(exc).__name__}")
        return ok({"link_id": _clean(link_id, 64), "link": result})

    @app.post(ADMIN_PREFIX + "/guest/links/{link_id}/url")
    async def agent_guest_link_url(link_id: str, request: Request, _=Depends(require_admin)) -> Any:
        """控制台「取链接」：一次只换回一条完整预约链接，并在审计里留下这次换回。"""
        runtime = runtime_of(request)
        body = await body_of(request)
        try:
            result = await runtime.portal.link_url(_clean(body.get("bot_id"), 64), _clean(link_id, 64))
        except GuestError as exc:
            return fail(exc.http_status, f"取链接失败：{exc.detail}")
        except (LedgerError, ValueError) as exc:
            return fail(503, f"取链接失败：{type(exc).__name__}")
        return ok({"link_id": _clean(link_id, 64), "link": result})

    # ----------------------------------------------------------------- 节点桥
    @app.get(f"{ADMIN_PREFIX}/node")
    async def agent_node(request: Request, _=Depends(require_admin)) -> Any:
        """只要本地状态：不发任何请求，控制台轮询这条不会打扰节点。"""
        runtime = runtime_of(request)
        return ok({"node": runtime.node.status()})

    @app.post(f"{ADMIN_PREFIX}/node/probe")
    async def agent_node_probe(request: Request, _=Depends(require_admin)) -> Any:
        """显式探活：唯一一条会真的去连回环节点的管理路由。"""
        runtime = runtime_of(request)
        try:
            health = await runtime.node.health()
            snapshot = await runtime.node.snapshot()
        except MacNodeError as exc:
            return fail(502, f"节点不可达：{exc.detail or type(exc).__name__}")
        except (OSError, ValueError) as exc:
            return fail(502, f"节点不可达：{type(exc).__name__}")
        return ok({"health": health, "snapshot": snapshot, "node": runtime.node.status()})


    # ------------------------------------------------------------- 跨 Agent 编排
    def orchestrator_of(request: Request) -> Any:
        orch = getattr(stack_of(request), "orchestrator", None)
        if orch is None:
            raise HTTPException(
                status_code=503,
                detail={"ok": False, "error_code": 503, "description": "编排器未装配"},
            )
        return orch

    def orch_fail(exc: OrchestratorError) -> Any:
        """把稳定的原因码翻成 HTTP 语义；被策略**拒绝**是 200 + refused 行，不是错误。"""
        code = exc.code
        status = 404 if code in ("unknown_origin", "unknown_target", "not_found") else (
            409 if code == "not_cancellable" else 400
        )
        return fail(status, f"{code}: {exc.detail}" if exc.detail else code)

    @app.get(f"{ADMIN_PREFIX}/orch")
    async def orch_snapshot(
        request: Request, bot_id: str = "", _=Depends(require_admin)
    ) -> Any:
        """一屏数据：可派能力、生效授权、近期任务与计数。"""
        clean = _clean(bot_id, 64)
        if clean:
            need_bot(request, clean)
        return ok(orchestrator_of(request).snapshot(clean or None))

    @app.get(f"{ADMIN_PREFIX}/orch/grants")
    async def orch_grants(
        request: Request, bot_id: str = "", target_bot_id: str = "",
        enabled_only: bool = False, _=Depends(require_admin)
    ) -> Any:
        rows = orchestrator_of(request).db.list_grants(
            origin_bot_id=_clean(bot_id, 64) or None,
            target_bot_id=_clean(target_bot_id, 64) or None,
            enabled_only=bool(enabled_only),
        )
        return ok({"grants": rows, "total": len(rows)})

    @app.post(f"{ADMIN_PREFIX}/orch/grants")
    async def orch_grant_add(request: Request, _=Depends(require_admin)) -> Any:
        """写一条授权。默认拒绝的反面：没有这一步，任何跨 Agent 派活都会被拒。"""
        body = await body_of(request)
        orch = orchestrator_of(request)
        origin = need_bot(request, _clean(body.get("origin_bot_id") or body.get("bot_id"), 64))
        target = need_bot(request, _clean(body.get("target_bot_id"), 64))
        capability = _clean(body.get("capability"), 64)
        if not capability:
            return fail(400, "capability 必填")
        try:
            row = orch.db.grant_agent_task(
                origin,
                target,
                capability,
                max_hops=_int(body.get("max_hops"), 1, low=1, high=MAX_TASK_HOPS),
                max_concurrent=_int(body.get("max_concurrent"), 4, low=1, high=MAX_TASK_CONCURRENCY),
                timeout_seconds=_float(body.get("timeout_seconds"), 20.0),
                enabled=str(body.get("enabled", "true")).lower() not in ("0", "false", "no"),
            )
        except LedgerError as exc:
            return fail(400, f"授权写入失败：{exc}")
        return ok({"grant": row})

    @app.post(ADMIN_PREFIX + "/orch/grants/{grant_id}/toggle")
    async def orch_grant_toggle(
        request: Request, grant_id: int, enabled: str = "false", _=Depends(require_admin)
    ) -> Any:
        row = orchestrator_of(request).db.set_grant_enabled(
            int(grant_id), str(enabled).lower() not in ("0", "false", "no")
        )
        if row is None:
            return fail(404, f"授权 {grant_id} 不存在")
        return ok({"grant": row})

    @app.post(ADMIN_PREFIX + "/orch/grants/{grant_id}/delete")
    async def orch_grant_delete(request: Request, grant_id: int, _=Depends(require_admin)) -> Any:
        """删除授权。任务与审计行**保留**：撤回的是权限，不是历史。"""
        return ok({"deleted": orchestrator_of(request).db.delete_grant(int(grant_id))})

    @app.post(f"{ADMIN_PREFIX}/orch/dispatch")
    async def orch_dispatch(request: Request, _=Depends(require_admin)) -> Any:
        """真实派发一次：走完整策略闸、超时熔断与落库，不是模拟。"""
        body = await body_of(request)
        orch = orchestrator_of(request)
        try:
            task = await orch.dispatch(
                _clean(body.get("origin_bot_id") or body.get("bot_id"), 64),
                _clean(body.get("target_bot_id"), 64),
                _clean(body.get("capability"), 64),
                body.get("args") if isinstance(body.get("args"), Mapping) else {},
                correlation_id=_clean(body.get("correlation_id"), 64),
                parent_id=_clean(body.get("parent_id"), 64),
                hops=_int(body.get("hops"), 1, low=1, high=MAX_TASK_HOPS),
            )
        except OrchestratorError as exc:
            return orch_fail(exc)
        return ok({"task": task})

    @app.post(f"{ADMIN_PREFIX}/orch/fanout")
    async def orch_fanout(request: Request, _=Depends(require_admin)) -> Any:
        body = await body_of(request)
        orch = orchestrator_of(request)
        raw = body.get("targets")
        targets = list(raw) if isinstance(raw, (list, tuple)) else [
            item for item in _clean(raw, 4096).replace(";", ",").split(",") if item.strip()
        ]
        try:
            aggregate = await orch.fanout(
                _clean(body.get("origin_bot_id") or body.get("bot_id"), 64),
                targets,
                _clean(body.get("capability"), 64),
                body.get("args") if isinstance(body.get("args"), Mapping) else {},
                correlation_id=_clean(body.get("correlation_id"), 64),
                budget_seconds=_float(body.get("budget_seconds"), 0.0),
            )
        except OrchestratorError as exc:
            return orch_fail(exc)
        return ok({"fanout": aggregate})

    @app.get(f"{ADMIN_PREFIX}/orch/tasks")
    async def orch_tasks(
        request: Request, bot_id: str = "", status: str = "", capability: str = "",
        correlation_id: str = "", limit: int = 50, _=Depends(require_admin)
    ) -> Any:
        rows = orchestrator_of(request).db.list_tasks(
            bot_id=_clean(bot_id, 64) or None,
            status=_clean(status, 16) or None,
            capability=_clean(capability, 64) or None,
            correlation_id=_clean(correlation_id, 64) or None,
            limit=_int(limit, 50, low=1, high=500),
        )
        return ok({"tasks": rows, "total": len(rows)})

    @app.get(ADMIN_PREFIX + "/orch/tasks/{task_id}")
    async def orch_task(request: Request, task_id: str, _=Depends(require_admin)) -> Any:
        orch = orchestrator_of(request)
        row = orch.db.get_task(_clean(task_id, 64))
        if row is None:
            return fail(404, f"任务 {task_id} 不存在")
        return ok({"task": row, "children": orch.db.task_children(row["id"])})

    @app.post(ADMIN_PREFIX + "/orch/tasks/{task_id}/cancel")
    async def orch_task_cancel(request: Request, task_id: str, _=Depends(require_admin)) -> Any:
        try:
            return ok({"task": orchestrator_of(request).cancel(_clean(task_id, 64))})
        except OrchestratorError as exc:
            return orch_fail(exc)

    @app.get(f"{ADMIN_PREFIX}/orch/replay")
    async def orch_replay(
        request: Request, correlation_id: str, limit: int = 200, _=Depends(require_admin)
    ) -> Any:
        """按关联号回放整条链：任务树 + 时间正序的审计序列。"""
        try:
            return ok(orchestrator_of(request).replay(
                _clean(correlation_id, 64), limit=_int(limit, 200, low=1, high=500)
            ))
        except OrchestratorError as exc:
            return orch_fail(exc)


__all__ = [
    "ADMIN_PREFIX",
    "AUDIT_STAGES",
    "NONCE_JAR_MAX",
    "_NonceJar",
    "add_admin_routes",
    "add_book_routes",
]
