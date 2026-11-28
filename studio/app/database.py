"""SQLite ledger for Bot Studio.

The ledger is the single source of truth for bots, reply rules, routing rules,
plugin configuration and the audit log. It is versioned: ``schema_migrations``
records every applied step so an install can be upgraded in place.
"""

from __future__ import annotations

import json
import math
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import date
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .config import SECURE_FILE_MODE

SCHEMA_VERSION = 7

_ID_RE = re.compile(r"^[a-z0-9_-]{3,64}$")
TRIGGER_TYPES = ("exact", "prefix", "regex", "default")
SOURCE_TYPES = ("direct", "group", "any")
TARGET_TYPES = ("group", "contact", "broadcast")
BOT_STATUSES = ("draft", "stopped", "running", "error", "deleted")
DIRECTIONS = ("in", "out")
LOG_STATUSES = ("ok", "cooldown", "skipped", "error", "forwarded", "no_match")
PROPOSAL_ACTIONS = ("create", "reschedule", "cancel")
PROPOSAL_STATUSES = ("pending", "approved", "declined", "expired", "failed", "superseded")
PROPOSAL_SOURCES = ("a2a", "guest", "direct", "operator")
NEGOTIATION_STATUSES = ("open", "converged", "rejected", "expired", "aborted")
GUEST_LINK_STATUSES = ("active", "exhausted", "revoked", "expired")
GUEST_ROLES = ("visitor", "bot", "owner")
#: 跨 Agent 编排的任务生命周期（schema v7）：``created → authorized → scheduled →
#: allocated → running → awaiting_user → completed → workspace_cleanup``。成功终态是
#: ``workspace_cleanup``（执行完成且清理回调已跑）；``failed`` / ``cancelled`` 是失败与
#: 取消终态。``refused`` 保留为策略闸在派发前就落定的终态（无授权、跳数/成环、并发超预算），
#: 使"被哪条闸挡下"在账本里始终是一个完整状态而不是一条错误码。
TASK_STATUSES = (
    "created",
    "authorized",
    "scheduled",
    "allocated",
    "running",
    "awaiting_user",
    "completed",
    "workspace_cleanup",
    "failed",
    "cancelled",
    "refused",
)
#: 任务结果的留存模式。``zero_retention`` 的结果在落库前被抹除，``ephemeral`` 随任务
#: 结束失效，``user_owned`` 留在主人自己的工作区。
RETENTION_MODES = ("zero_retention", "ephemeral", "user_owned")
#: 授权范围里 ``capability`` 允许的通配值：一条授权覆盖全部已注册能力。
GRANT_WILDCARD = "*"
GRANT_CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9_.\-]{2,63}$")
#: 跳数上限。1 表示"只许直接派一层"，编排层靠它把 A→B→A 的环在写库之前就掐掉。
MAX_TASK_HOPS = 3
MAX_TASK_CONCURRENCY = 32
TASK_TIMEOUT_MIN_SECONDS = 0.5
TASK_TIMEOUT_MAX_SECONDS = 300.0
TASK_RESULT_MAX_CHARS = 200000
AUDIT_STAGES = (
    "needle",
    "preference",
    "reasoner",
    "mac_node",
    "a2a",
    "card",
    "guest",
    "ics",
    "lifecycle",
    "orchestrator",
)
AUDIT_LEVELS = ("info", "warn", "error")


class LedgerError(RuntimeError):
    """Raised when a ledger write violates a uniqueness or integrity rule."""


BOT_FIELDS = (
    "id",
    "name",
    "display_name",
    "port",
    "status",
    "contact_address",
    "permanent_link",
    "bot_token",
    "auto_accept",
    "accept_incognito",
    "welcome_text",
    "smp_servers",
    "webhook_url",
    "webhook_secret",
    "last_error",
    "default_locale",
    "created_at",
    "updated_at",
)

_MIGRATIONS: Tuple[Tuple[int, str, Tuple[str, ...]], ...] = (
    (
        1,
        "基础表：bots / reply_rules / message_logs",
        (
            """
            CREATE TABLE IF NOT EXISTS bots (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL DEFAULT '',
                port INTEGER NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'draft',
                contact_address TEXT NOT NULL DEFAULT '',
                permanent_link TEXT NOT NULL DEFAULT '',
                bot_token TEXT NOT NULL UNIQUE,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS reply_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                trigger_type TEXT NOT NULL CHECK (trigger_type IN ('exact','prefix','regex','default')),
                pattern TEXT NOT NULL DEFAULT '',
                reply_text TEXT NOT NULL DEFAULT '',
                cooldown_seconds INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 100,
                created_at REAL NOT NULL,
                UNIQUE (bot_id, trigger_type, pattern)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS message_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id TEXT NOT NULL,
                direction TEXT NOT NULL CHECK (direction IN ('in','out')),
                chat_type TEXT NOT NULL DEFAULT '',
                chat_ref TEXT NOT NULL DEFAULT '',
                sender TEXT NOT NULL DEFAULT '',
                text TEXT NOT NULL DEFAULT '',
                rule_id INTEGER,
                plugin_id TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'ok',
                error TEXT NOT NULL DEFAULT '',
                ts REAL NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_message_logs_bot_ts ON message_logs (bot_id, ts)",
            "CREATE INDEX IF NOT EXISTS idx_reply_rules_bot ON reply_rules (bot_id, enabled, priority)",
        ),
    ),
    (
        2,
        "路由与插件表：routing_rules / plugin_configs",
        (
            """
            CREATE TABLE IF NOT EXISTS routing_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                source_type TEXT NOT NULL CHECK (source_type IN ('direct','group','any')),
                source_ref TEXT NOT NULL DEFAULT '',
                keyword_mode TEXT NOT NULL DEFAULT 'any',
                keywords TEXT NOT NULL DEFAULT '[]',
                target_type TEXT NOT NULL CHECK (target_type IN ('group','contact','broadcast')),
                target_ref TEXT NOT NULL DEFAULT '',
                template TEXT NOT NULL DEFAULT '',
                quote_reply INTEGER NOT NULL DEFAULT 0,
                cooldown_seconds INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS plugin_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id TEXT NOT NULL DEFAULT '',
                plugin_id TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                config TEXT NOT NULL DEFAULT '{}',
                updated_at REAL NOT NULL,
                UNIQUE (bot_id, plugin_id)
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_routing_rules_bot ON routing_rules (bot_id, enabled)",
        ),
    ),
    (
        3,
        "Bot 运行期字段、出站 Webhook 与规则命中计数",
        (
            "ALTER TABLE bots ADD COLUMN auto_accept INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE bots ADD COLUMN accept_incognito INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE bots ADD COLUMN welcome_text TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE bots ADD COLUMN smp_servers TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE bots ADD COLUMN webhook_url TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE bots ADD COLUMN webhook_secret TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE bots ADD COLUMN last_error TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE reply_rules ADD COLUMN hits INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE reply_rules ADD COLUMN last_hit_at REAL NOT NULL DEFAULT 0",
        ),
    ),
    (
        4,
        "Bot 默认语言（欢迎语模板按此填充）",
        (
            "ALTER TABLE bots ADD COLUMN default_locale TEXT NOT NULL DEFAULT ''",
        ),
    ),
    (
        5,
        "替身机器人：日历提案 / A2A 协商 / 访客一次性链接 / 协商审计 / 忙闲缓存",
        (
            """
            CREATE TABLE IF NOT EXISTS agent_proposals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proposal_id TEXT NOT NULL UNIQUE,
                bot_id TEXT NOT NULL,
                action TEXT NOT NULL CHECK (action IN ('create','reschedule','cancel')),
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','approved','declined','expired','failed','superseded')),
                source TEXT NOT NULL DEFAULT 'a2a'
                    CHECK (source IN ('a2a','guest','direct','operator')),
                card_id TEXT NOT NULL DEFAULT '',
                chat_type TEXT NOT NULL DEFAULT '',
                chat_ref TEXT NOT NULL DEFAULT '',
                counterparty TEXT NOT NULL DEFAULT '',
                timezone TEXT NOT NULL DEFAULT '',
                start_ts REAL NOT NULL DEFAULT 0,
                end_ts REAL NOT NULL DEFAULT 0,
                duration_minutes INTEGER NOT NULL DEFAULT 0,
                summary TEXT NOT NULL DEFAULT '',
                payload TEXT NOT NULL DEFAULT '{}',
                negotiation_id TEXT NOT NULL DEFAULT '',
                link_id TEXT NOT NULL DEFAULT '',
                ticket_id TEXT NOT NULL DEFAULT '',
                ics_path TEXT NOT NULL DEFAULT '',
                node_event_id TEXT NOT NULL DEFAULT '',
                error TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                decided_at REAL NOT NULL DEFAULT 0
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_agent_proposals_bot_ts ON agent_proposals (bot_id, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_agent_proposals_status ON agent_proposals (status, updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_agent_proposals_card ON agent_proposals (card_id)",
            """
            CREATE TABLE IF NOT EXISTS a2a_negotiations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                negotiation_id TEXT NOT NULL UNIQUE,
                bot_id TEXT NOT NULL,
                peer_identity TEXT NOT NULL DEFAULT '',
                peer_label TEXT NOT NULL DEFAULT '',
                channel TEXT NOT NULL DEFAULT 'a2a' CHECK (channel IN ('a2a','guest')),
                status TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open','converged','rejected','expired','aborted')),
                round INTEGER NOT NULL DEFAULT 0,
                owner_timezone TEXT NOT NULL DEFAULT '',
                peer_timezone TEXT NOT NULL DEFAULT '',
                window_start REAL NOT NULL DEFAULT 0,
                window_end REAL NOT NULL DEFAULT 0,
                duration_minutes INTEGER NOT NULL DEFAULT 60,
                owner_slots TEXT NOT NULL DEFAULT '[]',
                peer_slots TEXT NOT NULL DEFAULT '[]',
                intersection TEXT NOT NULL DEFAULT '[]',
                agreed_slot TEXT NOT NULL DEFAULT '{}',
                proposal_id TEXT NOT NULL DEFAULT '',
                last_error TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                expires_at REAL NOT NULL DEFAULT 0
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_a2a_negotiations_bot ON a2a_negotiations (bot_id, status, updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_a2a_negotiations_peer ON a2a_negotiations (bot_id, peer_identity)",
            """
            CREATE TABLE IF NOT EXISTS guest_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                link_id TEXT NOT NULL UNIQUE,
                bot_id TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                label TEXT NOT NULL DEFAULT '',
                topic TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','exhausted','revoked','expired')),
                max_uses INTEGER NOT NULL DEFAULT 1,
                uses INTEGER NOT NULL DEFAULT 0,
                duration_minutes INTEGER NOT NULL DEFAULT 60,
                timezone TEXT NOT NULL DEFAULT '',
                proposal_id TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                created_by TEXT NOT NULL DEFAULT '',
                expires_at REAL NOT NULL,
                last_used_at REAL NOT NULL DEFAULT 0,
                revoked_at REAL NOT NULL DEFAULT 0
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_guest_links_bot_status ON guest_links (bot_id, status, expires_at)",
            """
            CREATE TABLE IF NOT EXISTS guest_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id TEXT NOT NULL,
                link_id TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('visitor','bot','owner')),
                text TEXT NOT NULL DEFAULT '',
                proposal_id TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'ok',
                visitor_hash TEXT NOT NULL DEFAULT '',
                ts REAL NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_guest_messages_link ON guest_messages (link_id, ts)",
            """
            CREATE TABLE IF NOT EXISTS negotiation_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id TEXT NOT NULL DEFAULT '',
                stage TEXT NOT NULL CHECK (stage IN
                    ('needle','preference','reasoner','mac_node','a2a','card','guest','ics','lifecycle')),
                event TEXT NOT NULL,
                level TEXT NOT NULL DEFAULT 'info' CHECK (level IN ('info','warn','error')),
                proposal_id TEXT NOT NULL DEFAULT '',
                negotiation_id TEXT NOT NULL DEFAULT '',
                link_id TEXT NOT NULL DEFAULT '',
                chat_ref TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                data TEXT NOT NULL DEFAULT '{}',
                latency_ms REAL NOT NULL DEFAULT 0,
                ts REAL NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_negotiation_audit_bot_ts ON negotiation_audit (bot_id, ts)",
            "CREATE INDEX IF NOT EXISTS idx_negotiation_audit_proposal ON negotiation_audit (proposal_id, ts)",
            """
            CREATE TABLE IF NOT EXISTS calendar_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id TEXT NOT NULL,
                day TEXT NOT NULL,
                timezone TEXT NOT NULL DEFAULT '',
                busy TEXT NOT NULL DEFAULT '[]',
                source TEXT NOT NULL DEFAULT 'mac_node',
                fetched_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                UNIQUE (bot_id, day, source)
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_calendar_cache_expiry ON calendar_cache (expires_at)",
        ),
    ),
    (
        6,
        "跨 Agent 编排：策略授权、任务账本、审计关联回放",
        (
            """
            CREATE TABLE IF NOT EXISTS agent_task_grants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                origin_bot_id TEXT NOT NULL,
                target_bot_id TEXT NOT NULL,
                capability TEXT NOT NULL,
                max_hops INTEGER NOT NULL DEFAULT 1,
                max_concurrent INTEGER NOT NULL DEFAULT 4,
                timeout_seconds REAL NOT NULL DEFAULT 20,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                UNIQUE (origin_bot_id, target_bot_id, capability)
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_agent_task_grants_origin "
            "ON agent_task_grants (origin_bot_id, enabled)",
            """
            CREATE TABLE IF NOT EXISTS agent_tasks (
                id TEXT PRIMARY KEY,
                correlation_id TEXT NOT NULL,
                parent_id TEXT NOT NULL DEFAULT '',
                origin_bot_id TEXT NOT NULL,
                target_bot_id TEXT NOT NULL,
                capability TEXT NOT NULL,
                args_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL CHECK (status IN
                    ('queued','running','succeeded','failed','timeout','refused','cancelled')),
                result_json TEXT NOT NULL DEFAULT '',
                error_code TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                hops INTEGER NOT NULL DEFAULT 1,
                timeout_seconds REAL NOT NULL DEFAULT 20,
                created_at REAL NOT NULL,
                started_at REAL NOT NULL DEFAULT 0,
                finished_at REAL NOT NULL DEFAULT 0,
                latency_ms REAL NOT NULL DEFAULT 0
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_origin ON agent_tasks (origin_bot_id, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_parent ON agent_tasks (parent_id)",
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_correlation "
            "ON agent_tasks (correlation_id, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_target ON agent_tasks (target_bot_id, status)",
            """
            CREATE TABLE IF NOT EXISTS negotiation_audit_v6 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id TEXT NOT NULL DEFAULT '',
                stage TEXT NOT NULL CHECK (stage IN
                    ('needle','preference','reasoner','mac_node','a2a','card','guest','ics','lifecycle',
                     'orchestrator')),
                event TEXT NOT NULL,
                level TEXT NOT NULL DEFAULT 'info' CHECK (level IN ('info','warn','error')),
                proposal_id TEXT NOT NULL DEFAULT '',
                negotiation_id TEXT NOT NULL DEFAULT '',
                link_id TEXT NOT NULL DEFAULT '',
                chat_ref TEXT NOT NULL DEFAULT '',
                correlation_id TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                data TEXT NOT NULL DEFAULT '{}',
                latency_ms REAL NOT NULL DEFAULT 0,
                ts REAL NOT NULL
            )
            """,
            "INSERT INTO negotiation_audit_v6 (id, bot_id, stage, event, level, proposal_id, "
            "negotiation_id, link_id, chat_ref, correlation_id, detail, data, latency_ms, ts) "
            "SELECT id, bot_id, stage, event, level, proposal_id, negotiation_id, link_id, "
            "chat_ref, '', detail, data, latency_ms, ts FROM negotiation_audit",
            "DROP TABLE negotiation_audit",
            "ALTER TABLE negotiation_audit_v6 RENAME TO negotiation_audit",
            "CREATE INDEX IF NOT EXISTS idx_negotiation_audit_bot_ts ON negotiation_audit (bot_id, ts)",
            "CREATE INDEX IF NOT EXISTS idx_negotiation_audit_proposal ON negotiation_audit (proposal_id, ts)",
            "CREATE INDEX IF NOT EXISTS idx_negotiation_audit_correlation "
            "ON negotiation_audit (correlation_id, ts)",
        ),
    ),
    (
        7,
        "任务生命周期：11 态状态机、执行画像、审批与工作区清理",
        (
            "ALTER TABLE agent_task_grants ADD COLUMN require_approval INTEGER NOT NULL DEFAULT 0",
            "DROP TABLE IF EXISTS agent_tasks_v7",
            """
            CREATE TABLE agent_tasks_v7 (
                id TEXT PRIMARY KEY,
                correlation_id TEXT NOT NULL,
                parent_id TEXT NOT NULL DEFAULT '',
                origin_bot_id TEXT NOT NULL,
                target_bot_id TEXT NOT NULL,
                capability TEXT NOT NULL,
                args_json TEXT NOT NULL DEFAULT '{}',
                profile_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL CHECK (status IN
                    ('created','authorized','scheduled','allocated','running','awaiting_user',
                     'completed','workspace_cleanup','failed','cancelled','refused')),
                retention_mode TEXT NOT NULL DEFAULT '',
                approval_required INTEGER NOT NULL DEFAULT 0,
                approved_at REAL NOT NULL DEFAULT 0,
                result_json TEXT NOT NULL DEFAULT '',
                error_code TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                hops INTEGER NOT NULL DEFAULT 1,
                timeout_seconds REAL NOT NULL DEFAULT 20,
                created_at REAL NOT NULL,
                started_at REAL NOT NULL DEFAULT 0,
                finished_at REAL NOT NULL DEFAULT 0,
                cleanup_at REAL NOT NULL DEFAULT 0,
                cleanup_detail TEXT NOT NULL DEFAULT '',
                latency_ms REAL NOT NULL DEFAULT 0
            )
            """,
            # 旧七个状态逐一映射：queued→scheduled、succeeded→completed、timeout→failed
            # （error_code 补成 timeout），其余原样 —— 历史行的语义一条都不丢。
            """
            INSERT INTO agent_tasks_v7 (id, correlation_id, parent_id, origin_bot_id,
                target_bot_id, capability, args_json, profile_json, status, retention_mode,
                approval_required, approved_at, result_json, error_code, detail, hops,
                timeout_seconds, created_at, started_at, finished_at, cleanup_at,
                cleanup_detail, latency_ms)
            SELECT id, correlation_id, parent_id, origin_bot_id, target_bot_id,
                capability, args_json, '{}',
                CASE status
                    WHEN 'queued' THEN 'scheduled'
                    WHEN 'succeeded' THEN 'completed'
                    WHEN 'timeout' THEN 'failed'
                    ELSE status
                END,
                '', 0, 0, result_json,
                CASE WHEN status = 'timeout' AND error_code = '' THEN 'timeout' ELSE error_code END,
                detail, hops, timeout_seconds, created_at, started_at, finished_at, 0, '',
                latency_ms
            FROM agent_tasks
            """,
            "DROP TABLE agent_tasks",
            "ALTER TABLE agent_tasks_v7 RENAME TO agent_tasks",
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_origin ON agent_tasks (origin_bot_id, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_parent ON agent_tasks (parent_id)",
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_correlation "
            "ON agent_tasks (correlation_id, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_target ON agent_tasks (target_bot_id, status)",
        ),
    ),
)


def new_bot_id(prefix: str = "bot") -> str:
    """Return an identifier that is safe in a filesystem path and a URL."""
    for _ in range(16):
        candidate = f"{prefix}_{secrets.token_hex(4)}"
        if _ID_RE.match(candidate):
            return candidate
    raise LedgerError("无法生成合法 bot id")


def new_bot_token() -> str:
    """Return a developer API token usable as ``/bot<token>/getMe``."""
    return f"{secrets.randbelow(90000000) + 10000000}:{secrets.token_hex(16)}"


def new_proposal_id() -> str:
    """Identifier for one calendar proposal awaiting owner confirmation."""
    return f"pr_{secrets.token_hex(6)}"


def new_negotiation_id() -> str:
    return f"ng_{secrets.token_hex(6)}"


def new_task_id() -> str:
    return f"tk_{secrets.token_hex(6)}"


def new_thread_id() -> str:
    """一次编排（含扇出的所有子任务）共用一个关联号，审计回放按它取。"""
    return f"th_{secrets.token_hex(6)}"


def new_guest_link_id() -> str:
    return f"gl_{secrets.token_hex(5)}"


def _json_dump(value: Any, *, label: str) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise LedgerError(f"{label}不可序列化：{exc}") from exc


def _json_load(raw: Any, default: Any) -> Any:
    if raw in (None, ""):
        return default
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return default
    return value if isinstance(value, type(default)) else default


def _rows(cursor: sqlite3.Cursor) -> List[Dict[str, Any]]:
    return [dict(row) for row in cursor.fetchall()]


class Database:
    """Thread-safe wrapper around the ledger connection."""

    def __init__(self, path: Path | str, *, busy_timeout_ms: int = 5000):
        self.path = Path(path)
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(
            str(self.path), check_same_thread=False, isolation_level=None
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout = %d" % int(busy_timeout_ms))
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA synchronous = NORMAL")
        self._harden_file_modes()

    def _harden_file_modes(self) -> None:
        """账本里存着全部 Bot 令牌，旁挂的 -wal/-shm 也必须只有属主可读。"""
        for candidate in (self.path, self.path.parent / (self.path.name + "-wal"),
                          self.path.parent / (self.path.name + "-shm")):
            try:
                if candidate.is_file():
                    os.chmod(candidate, SECURE_FILE_MODE)
            except OSError:
                pass

    # ---------------------------------------------------------------- schema
    def schema_version(self) -> int:
        self._ensure_migrations_table()
        with self._lock:
            row = self.conn.execute(
                "SELECT MAX(version) AS version FROM schema_migrations"
            ).fetchone()
        return int(row["version"] or 0) if row and row["version"] is not None else 0

    def _ensure_migrations_table(self) -> None:
        with self._lock:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at REAL NOT NULL,
                    description TEXT NOT NULL DEFAULT ''
                )
                """
            )

    def migrate(self, *, target_version: int = SCHEMA_VERSION) -> List[int]:
        """Apply pending migrations up to *target_version*; return applied ids."""
        self._ensure_migrations_table()
        applied: List[int] = []
        with self._lock:
            for version, description, statements in _MIGRATIONS:
                if version > target_version:
                    break
                done = self.conn.execute(
                    "SELECT 1 FROM schema_migrations WHERE version = ?", (version,)
                ).fetchone()
                if done:
                    continue
                self.conn.execute("BEGIN")
                try:
                    for statement in statements:
                        self.conn.execute(statement)
                    self.conn.execute(
                        "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)",
                        (version, time.time(), description),
                    )
                except Exception:
                    self.conn.execute("ROLLBACK")
                    raise
                self.conn.execute("COMMIT")
                applied.append(version)
        return applied

    def journal_mode(self) -> str:
        with self._lock:
            return str(self.conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()

    def foreign_keys_enabled(self) -> bool:
        with self._lock:
            return bool(self.conn.execute("PRAGMA foreign_keys").fetchone()[0])

    def table_names(self) -> List[str]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        return [str(row["name"]) for row in rows]

    def columns(self, table: str) -> List[str]:
        if not re.match(r"^[a-z_]+$", table):
            raise LedgerError(f"非法表名 {table!r}")
        with self._lock:
            rows = self.conn.execute(f"PRAGMA table_info({table})").fetchall()
        return [str(row["name"]) for row in rows]

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # ------------------------------------------------------------------ bots
    def next_free_port(self, base: int, maximum: int) -> int:
        """Return the lowest unused CLI websocket port in ``[base, maximum]``."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT port FROM bots WHERE status != 'deleted' ORDER BY port"
            ).fetchall()
        used = {int(row["port"]) for row in rows}
        for port in range(base, maximum + 1):
            if port not in used:
                return port
        raise LedgerError(f"端口区间 {base}-{maximum} 已耗尽，请提高 BOT_WS_PORT_MAX")

    def create_bot(
        self,
        name: str,
        port: int,
        *,
        display_name: str = "",
        bot_token: Optional[str] = None,
        smp_servers: str = "",
        default_locale: str = "",
    ) -> Dict[str, Any]:
        name = (name or "").strip()
        if not _ID_RE.match(name):
            raise LedgerError(f"Bot 名称 {name!r} 仅允许小写字母、数字、下划线与短横线（3-64）")
        bot_id = new_bot_id(f"bot_{name[:20].strip('_-') or 'x'}".lower())
        token = bot_token or new_bot_token()
        now = time.time()
        # 名字与端口连已删除的行一起占用：软删除仍保留 cli-data 目录与端口，
        # 复用会让旧数据被新 Bot 接管。先查再报错，管理台才看不到 SQLite 原文。
        with self._lock:
            clash = self.conn.execute(
                "SELECT name, port FROM bots WHERE name = ? OR port = ? ORDER BY name = ? DESC",
                (name, int(port), name),
            ).fetchone()
        if clash is not None:
            taken = "名称" if clash["name"] == name else "端口"
            raise LedgerError(f"Bot {taken} {name if taken == '名称' else port!r} 已被占用")
        try:
            with self._lock:
                self.conn.execute(
                    """
                    INSERT INTO bots (id, name, display_name, port, status, bot_token,
                                      smp_servers, default_locale, created_at, updated_at)
                    VALUES (?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?)
                    """,
                    (bot_id, name, display_name or name, port, token, smp_servers,
                     default_locale, now, now),
                )
        except sqlite3.IntegrityError as exc:
            raise LedgerError(f"创建 Bot {name!r} 失败：{exc}") from exc
        bot = self.get_bot(bot_id)
        assert bot is not None
        return bot

    def get_bot(self, bot_id: str, *, include_deleted: bool = False) -> Optional[Dict[str, Any]]:
        with self._lock:
            sql = "SELECT * FROM bots WHERE id = ?"
            if not include_deleted:
                sql += " AND status != 'deleted'"
            row = self.conn.execute(sql, (bot_id,)).fetchone()
        return dict(row) if row else None

    def get_bot_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM bots WHERE name = ? AND status != 'deleted'", (name,)
            ).fetchone()
        return dict(row) if row else None

    def get_bot_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM bots WHERE bot_token = ? AND status != 'deleted'", (token,)
            ).fetchone()
        return dict(row) if row else None

    def get_bot_by_port(self, port: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM bots WHERE port = ? AND status != 'deleted'", (int(port),)
            ).fetchone()
        return dict(row) if row else None

    def list_bots(self) -> List[Dict[str, Any]]:
        with self._lock:
            return _rows(
                self.conn.execute(
                    "SELECT * FROM bots WHERE status != 'deleted' ORDER BY port"
                )
            )

    def update_bot(self, bot_id: str, **fields: Any) -> Dict[str, Any]:
        unknown = set(fields) - set(BOT_FIELDS)
        if unknown:
            raise LedgerError(f"bots 不接受字段 {sorted(unknown)}")
        if not fields:
            bot = self.get_bot(bot_id, include_deleted=True)
            if bot is None:
                raise LedgerError(f"Bot {bot_id} 不存在")
            return bot
        if "status" in fields and fields["status"] not in BOT_STATUSES:
            raise LedgerError(f"非法 Bot 状态 {fields['status']!r}")
        assignments = ", ".join(f"{key} = ?" for key in fields)
        params = list(fields.values()) + [time.time(), bot_id]
        with self._lock:
            cursor = self.conn.execute(
                f"UPDATE bots SET {assignments}, updated_at = ? WHERE id = ?", params
            )
            if cursor.rowcount == 0:
                raise LedgerError(f"Bot {bot_id} 不存在")
        bot = self.get_bot(bot_id, include_deleted=True)
        assert bot is not None
        return bot

    def delete_bot(self, bot_id: str, *, hard: bool = False) -> None:
        with self._lock:
            if hard:
                self.conn.execute("DELETE FROM bots WHERE id = ?", (bot_id,))
                for table in (
                    "reply_rules",
                    "routing_rules",
                    "plugin_configs",
                    "agent_proposals",
                    "a2a_negotiations",
                    "guest_links",
                    "guest_messages",
                    "negotiation_audit",
                    "calendar_cache",
                ):
                    self.conn.execute(f"DELETE FROM {table} WHERE bot_id = ?", (bot_id,))
            else:
                self.conn.execute(
                    "UPDATE bots SET status = 'deleted', updated_at = ? WHERE id = ?",
                    (time.time(), bot_id),
                )

    def bot_summary(self) -> Dict[str, int]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT status, COUNT(*) AS total FROM bots GROUP BY status"
            ).fetchall()
        summary = {str(row["status"]): int(row["total"]) for row in rows}
        summary["total"] = sum(summary.values())
        return summary

    # ----------------------------------------------------------- reply rules
    def upsert_reply_rule(
        self,
        bot_id: str,
        *,
        rule_id: Optional[int] = None,
        name: str = "",
        trigger_type: str,
        pattern: str = "",
        reply_text: str,
        cooldown_seconds: int = 0,
        enabled: bool = True,
        priority: int = 100,
    ) -> Dict[str, Any]:
        if trigger_type not in TRIGGER_TYPES:
            raise LedgerError(f"非法触发类型 {trigger_type!r}，可选 {TRIGGER_TYPES}")
        if trigger_type == "regex" and pattern:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise LedgerError(f"正则表达式不可用：{exc}") from exc
        if trigger_type != "default" and not pattern:
            raise LedgerError(f"{trigger_type} 规则必须提供 pattern")
        if not reply_text.strip():
            raise LedgerError("回复内容不能为空")
        if cooldown_seconds < 0:
            raise LedgerError("冷却时间不能为负数")
        now = time.time()
        with self._lock:
            if rule_id is None:
                try:
                    cursor = self.conn.execute(
                        """
                        INSERT INTO reply_rules (bot_id, name, trigger_type, pattern, reply_text,
                                                 cooldown_seconds, enabled, priority, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT (bot_id, trigger_type, pattern) DO UPDATE SET
                            name = excluded.name,
                            reply_text = excluded.reply_text,
                            cooldown_seconds = excluded.cooldown_seconds,
                            enabled = excluded.enabled,
                            priority = excluded.priority
                        """,
                        (
                            bot_id,
                            name,
                            trigger_type,
                            pattern,
                            reply_text,
                            int(cooldown_seconds),
                            1 if enabled else 0,
                            int(priority),
                            now,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise LedgerError(f"写入回复规则失败：{exc}") from exc
                # UPSERT 走 DO UPDATE 分支时不更新 last_insert_rowid()：新连接上
                # 它是 0，必须回查冲突行，否则改一条已存在的规则会读不回来。
                if not int(cursor.lastrowid or 0):
                    row = self.conn.execute(
                        "SELECT id FROM reply_rules WHERE bot_id=? AND trigger_type=? AND pattern=?",
                        (bot_id, trigger_type, pattern),
                    ).fetchone()
                    rule_id = int(row["id"]) if row is not None else 0
                else:
                    rule_id = int(cursor.lastrowid)
            else:
                self.conn.execute(
                    """
                    UPDATE reply_rules SET name = ?, trigger_type = ?, pattern = ?, reply_text = ?,
                                           cooldown_seconds = ?, enabled = ?, priority = ?
                    WHERE id = ?
                    """,
                    (
                        name,
                        trigger_type,
                        pattern,
                        reply_text,
                        int(cooldown_seconds),
                        1 if enabled else 0,
                        int(priority),
                        int(rule_id),
                    ),
                )
        rule = self.get_reply_rule(rule_id)
        if rule is None:
            raise LedgerError("回复规则写入后无法读回")
        return rule

    def get_reply_rule(self, rule_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM reply_rules WHERE id = ?", (int(rule_id),)).fetchone()
        return dict(row) if row else None

    def list_reply_rules(self, bot_id: str, *, enabled_only: bool = False) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM reply_rules WHERE bot_id = ?"
        if enabled_only:
            sql += " AND enabled = 1"
        sql += " ORDER BY priority, id"
        with self._lock:
            return _rows(self.conn.execute(sql, (bot_id,)))

    def delete_reply_rule(self, rule_id: int) -> bool:
        with self._lock:
            return self.conn.execute("DELETE FROM reply_rules WHERE id = ?", (int(rule_id),)).rowcount > 0

    def register_rule_hit(self, rule_id: int) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE reply_rules SET hits = hits + 1, last_hit_at = ? WHERE id = ?",
                (time.time(), int(rule_id)),
            )

    # -------------------------------------------------------- routing rules
    def upsert_routing_rule(
        self,
        bot_id: str,
        *,
        rule_id: Optional[int] = None,
        name: str = "",
        source_type: str = "any",
        source_ref: str = "",
        keyword_mode: str = "any",
        keywords: Sequence[str] = (),
        target_type: str = "group",
        target_ref: str = "",
        template: str = "",
        quote_reply: bool = False,
        cooldown_seconds: int = 0,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        if source_type not in SOURCE_TYPES:
            raise LedgerError(f"非法来源类型 {source_type!r}")
        if target_type not in TARGET_TYPES:
            raise LedgerError(f"非法目标类型 {target_type!r}")
        if keyword_mode not in ("any", "contains", "exact", "regex"):
            raise LedgerError(f"非法关键词模式 {keyword_mode!r}")
        if keyword_mode != "any":
            if not keywords:
                raise LedgerError(f"关键词模式 {keyword_mode!r} 必须提供至少一个关键词")
            if keyword_mode == "regex":
                for keyword in keywords:
                    try:
                        re.compile(keyword)
                    except re.error as exc:
                        raise LedgerError(f"路由正则不可用：{exc}") from exc
        if not target_ref and target_type != "broadcast":
            raise LedgerError("转发目标不能为空")
        payload = json.dumps(list(keywords), ensure_ascii=False)
        now = time.time()
        with self._lock:
            if rule_id is None:
                cursor = self.conn.execute(
                    """
                    INSERT INTO routing_rules (bot_id, name, source_type, source_ref, keyword_mode,
                                               keywords, target_type, target_ref, template,
                                               quote_reply, cooldown_seconds, enabled, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        bot_id,
                        name,
                        source_type,
                        source_ref,
                        keyword_mode,
                        payload,
                        target_type,
                        target_ref,
                        template,
                        1 if quote_reply else 0,
                        int(cooldown_seconds),
                        1 if enabled else 0,
                        now,
                    ),
                )
                rule_id = int(cursor.lastrowid or 0)
            else:
                self.conn.execute(
                    """
                    UPDATE routing_rules SET name = ?, source_type = ?, source_ref = ?,
                        keyword_mode = ?, keywords = ?, target_type = ?, target_ref = ?,
                        template = ?, quote_reply = ?, cooldown_seconds = ?, enabled = ?
                    WHERE id = ?
                    """,
                    (
                        name,
                        source_type,
                        source_ref,
                        keyword_mode,
                        payload,
                        target_type,
                        target_ref,
                        template,
                        1 if quote_reply else 0,
                        int(cooldown_seconds),
                        1 if enabled else 0,
                        int(rule_id),
                    ),
                )
        rule = self.get_routing_rule(rule_id)
        if rule is None:
            raise LedgerError("路由规则写入后无法读回")
        return rule

    def get_routing_rule(self, rule_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM routing_rules WHERE id = ?", (int(rule_id),)).fetchone()
        if not row:
            return None
        rule = dict(row)
        rule["keywords"] = json.loads(rule["keywords"] or "[]")
        return rule

    def list_routing_rules(self, bot_id: str, *, enabled_only: bool = False) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM routing_rules WHERE bot_id = ?"
        if enabled_only:
            sql += " AND enabled = 1"
        sql += " ORDER BY id"
        with self._lock:
            rows = _rows(self.conn.execute(sql, (bot_id,)))
        for row in rows:
            row["keywords"] = json.loads(row["keywords"] or "[]")
        return rows

    def delete_routing_rule(self, rule_id: int) -> bool:
        with self._lock:
            return self.conn.execute("DELETE FROM routing_rules WHERE id = ?", (int(rule_id),)).rowcount > 0

    # ------------------------------------------------------- plugin configs
    def set_plugin_config(
        self,
        plugin_id: str,
        config: Dict[str, Any],
        *,
        bot_id: str = "",
        enabled: Optional[bool] = None,
    ) -> Dict[str, Any]:
        if not isinstance(config, dict):
            raise LedgerError("插件配置必须是 JSON 对象")
        try:
            payload = json.dumps(config, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise LedgerError(f"插件配置不可序列化：{exc}") from exc
        current = self.get_plugin_config(plugin_id, bot_id=bot_id)
        flag = (1 if enabled else 0) if enabled is not None else (current["enabled"] if current else 0)
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO plugin_configs (bot_id, plugin_id, enabled, config, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (bot_id, plugin_id) DO UPDATE SET
                    enabled = excluded.enabled,
                    config = excluded.config,
                    updated_at = excluded.updated_at
                """,
                (bot_id or "", plugin_id, flag, payload, time.time()),
            )
        saved = self.get_plugin_config(plugin_id, bot_id=bot_id)
        assert saved is not None
        return saved

    def get_plugin_config(self, plugin_id: str, *, bot_id: str = "") -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM plugin_configs WHERE plugin_id = ? AND bot_id = ?",
                (plugin_id, bot_id or ""),
            ).fetchone()
        if not row:
            return None
        record = dict(row)
        record["config"] = json.loads(record["config"] or "{}")
        return record

    def list_plugin_configs(self, bot_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if bot_id is None:
            sql = "SELECT * FROM plugin_configs ORDER BY plugin_id, bot_id"
            params: Tuple[Any, ...] = ()
        else:
            sql = "SELECT * FROM plugin_configs WHERE bot_id = ? ORDER BY plugin_id"
            params = (bot_id,)
        with self._lock:
            rows = _rows(self.conn.execute(sql, params))
        for row in rows:
            row["config"] = json.loads(row["config"] or "{}")
        return rows

    def effective_plugin_config(
        self, plugin_id: str, bot_id: str
    ) -> Tuple[bool, Dict[str, Any]]:
        """Merge the global plugin defaults with a per-Bot override."""
        global_row = self.get_plugin_config(plugin_id, bot_id="")
        bot_row = self.get_plugin_config(plugin_id, bot_id=bot_id)
        merged: Dict[str, Any] = {}
        enabled = False
        if global_row:
            merged.update(global_row["config"])
            enabled = bool(global_row["enabled"])
        if bot_row:
            merged.update(bot_row["config"])
            enabled = bool(bot_row["enabled"])
        return enabled, merged

    # ------------------------------------------------------------- message log
    def log_message(
        self,
        bot_id: str,
        direction: str,
        *,
        chat_type: str = "",
        chat_ref: str = "",
        sender: str = "",
        text: str = "",
        rule_id: Optional[int] = None,
        plugin_id: str = "",
        status: str = "ok",
        error: str = "",
    ) -> int:
        if direction not in DIRECTIONS:
            raise LedgerError(f"非法消息方向 {direction!r}")
        if status not in LOG_STATUSES:
            raise LedgerError(f"非法日志状态 {status!r}")
        with self._lock:
            cursor = self.conn.execute(
                """
                INSERT INTO message_logs (bot_id, direction, chat_type, chat_ref, sender, text,
                                          rule_id, plugin_id, status, error, ts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    bot_id,
                    direction,
                    chat_type,
                    chat_ref,
                    sender,
                    text,
                    rule_id,
                    plugin_id,
                    status,
                    error,
                    time.time(),
                ),
            )
        return int(cursor.lastrowid or 0)

    def recent_logs(self, bot_id: Optional[str] = None, *, limit: int = 50) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        if bot_id is None:
            sql = "SELECT * FROM message_logs ORDER BY ts DESC LIMIT ?"
            params: Tuple[Any, ...] = (limit,)
        else:
            sql = "SELECT * FROM message_logs WHERE bot_id = ? ORDER BY ts DESC LIMIT ?"
            params = (bot_id, limit)
        with self._lock:
            return _rows(self.conn.execute(sql, params))

    def message_stats(self, bot_id: Optional[str] = None) -> Dict[str, Any]:
        conditions: List[str] = []
        params: List[Any] = []
        if bot_id is not None:
            conditions.append("bot_id = ?")
            params.append(bot_id)
        totals_where = ("WHERE " + " AND ".join(conditions) + " ") if conditions else ""
        with self._lock:
            totals = _rows(
                self.conn.execute(
                    f"SELECT direction, status, COUNT(*) AS total FROM message_logs {totals_where}"
                    "GROUP BY direction, status",
                    params,
                )
            )
            plugin_conditions = ["plugin_id != ''", *conditions]
            top_plugins = _rows(
                self.conn.execute(
                    "SELECT plugin_id, COUNT(*) AS total FROM message_logs WHERE "
                    + " AND ".join(plugin_conditions)
                    + " GROUP BY plugin_id ORDER BY total DESC LIMIT 10",
                    params,
                )
            )
        breakdown: Dict[str, int] = {}
        incoming = outgoing = 0
        for row in totals:
            key = f"{row['direction']}:{row['status']}"
            breakdown[key] = int(row["total"])
            if row["direction"] == "in":
                incoming += int(row["total"])
            else:
                outgoing += int(row["total"])
        return {
            "incoming": incoming,
            "outgoing": outgoing,
            "breakdown": breakdown,
            "top_plugins": {str(r["plugin_id"]): int(r["total"]) for r in top_plugins},
        }

    def message_trend(self, bot_id: Optional[str] = None, *, days: int = 7) -> List[Dict[str, Any]]:
        days = max(1, min(int(days), 90))
        clause = "WHERE ts >= strftime('%s','now') - ? * 86400"
        params: List[Any] = [days * 86400]
        if bot_id is not None:
            clause += " AND bot_id = ?"
            params.append(bot_id)
        with self._lock:
            return _rows(
                self.conn.execute(
                    "SELECT strftime('%Y-%m-%d', ts, 'unixepoch') AS day, COUNT(*) AS total "
                    f"FROM message_logs {clause} GROUP BY day ORDER BY day",
                    params,
                )
            )


    # ------------------------------------------------------- agent proposals
    PROPOSAL_FIELDS = (
        "status",
        "card_id",
        "chat_type",
        "chat_ref",
        "counterparty",
        "timezone",
        "start_ts",
        "end_ts",
        "duration_minutes",
        "summary",
        "payload",
        "negotiation_id",
        "link_id",
        "ticket_id",
        "ics_path",
        "node_event_id",
        "error",
        "decided_at",
    )
    PROPOSAL_DECIDED = ("approved", "declined", "failed", "superseded")

    def create_proposal(
        self,
        bot_id: str,
        action: str,
        *,
        source: str = "a2a",
        proposal_id: Optional[str] = None,
        chat_type: str = "",
        chat_ref: str = "",
        counterparty: str = "",
        timezone: str = "",
        start_ts: float = 0.0,
        end_ts: float = 0.0,
        duration_minutes: int = 0,
        summary: str = "",
        payload: Optional[Dict[str, Any]] = None,
        negotiation_id: str = "",
        link_id: str = "",
        ticket_id: str = "",
    ) -> Dict[str, Any]:
        if action not in PROPOSAL_ACTIONS:
            raise LedgerError(f"非法提案动作 {action!r}")
        if source not in PROPOSAL_SOURCES:
            raise LedgerError(f"非法提案来源 {source!r}")
        identifier = proposal_id or new_proposal_id()
        if not _ID_RE.match(identifier):
            raise LedgerError(f"提案 id 非法：{identifier!r}")
        now = time.time()
        with self._lock:
            try:
                self.conn.execute(
                    """
                    INSERT INTO agent_proposals (proposal_id, bot_id, action, status, source, card_id,
                        chat_type, chat_ref, counterparty, timezone, start_ts, end_ts, duration_minutes,
                        summary, payload, negotiation_id, link_id, ticket_id, error, created_at, updated_at)
                    VALUES (?, ?, ?, 'pending', ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?)
                    """,
                    (
                        identifier,
                        bot_id,
                        action,
                        source,
                        chat_type,
                        chat_ref,
                        counterparty,
                        timezone,
                        float(start_ts),
                        float(end_ts),
                        int(duration_minutes),
                        summary,
                        _json_dump(payload or {}, label="提案负载"),
                        negotiation_id,
                        link_id,
                        ticket_id,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:  # proposal_id 撞 UNIQUE
                raise LedgerError(f"创建提案失败：{exc}") from exc
        record = self.get_proposal(identifier)
        assert record is not None
        return record

    def get_proposal(self, proposal_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM agent_proposals WHERE proposal_id = ?", (proposal_id,)
            ).fetchone()
        return _proposal_record(row) if row else None

    def find_proposal_by_card(self, card_id: str) -> Optional[Dict[str, Any]]:
        if not card_id:
            return None
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM agent_proposals WHERE card_id = ? ORDER BY updated_at DESC LIMIT 1",
                (card_id,),
            ).fetchone()
        return _proposal_record(row) if row else None

    def list_proposals(
        self,
        bot_id: Optional[str] = None,
        *,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        clauses: List[str] = []
        params: List[Any] = []
        if bot_id is not None:
            clauses.append("bot_id = ?")
            params.append(bot_id)
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        params.append(limit)
        with self._lock:
            rows = _rows(
                self.conn.execute(
                    f"SELECT * FROM agent_proposals {where}ORDER BY created_at DESC LIMIT ?", params
                )
            )
        return [_proposal_record(row) for row in rows]

    def update_proposal(self, proposal_id: str, **fields: Any) -> Dict[str, Any]:
        unknown = set(fields) - set(self.PROPOSAL_FIELDS)
        if unknown:
            raise LedgerError(f"agent_proposals 不接受字段 {sorted(unknown)}")
        status = fields.get("status")
        if status is not None and status not in PROPOSAL_STATUSES:
            raise LedgerError(f"非法提案状态 {status!r}")
        if "payload" in fields and not isinstance(fields["payload"], dict):
            raise LedgerError("提案负载必须是 JSON 对象")
        if not fields:
            record = self.get_proposal(proposal_id)
            if record is None:
                raise LedgerError(f"提案 {proposal_id} 不存在")
            return record
        if status in self.PROPOSAL_DECIDED and not fields.get("decided_at"):
            fields["decided_at"] = time.time()
        assignments = ", ".join(f"{key} = ?" for key in fields)
        params = [
            _json_dump(fields[key], label=f"提案 {key}") if key == "payload" else fields[key]
            for key in fields
        ]
        params += [time.time(), proposal_id]
        with self._lock:
            cursor = self.conn.execute(
                f"UPDATE agent_proposals SET {assignments}, updated_at = ? WHERE proposal_id = ?",
                params,
            )
            if cursor.rowcount == 0:
                raise LedgerError(f"提案 {proposal_id} 不存在")
        record = self.get_proposal(proposal_id)
        assert record is not None
        return record

    def expire_proposals(self, *, now: Optional[float] = None) -> int:
        """Pending proposals past their card window (or older than a day) expire."""
        moment = time.time() if now is None else float(now)
        with self._lock:
            cursor = self.conn.execute(
                """
                UPDATE agent_proposals SET status = 'expired', updated_at = ?, decided_at = ?
                WHERE status = 'pending'
                  AND ((json_extract(payload, '$.expires_at') > 0
                        AND json_extract(payload, '$.expires_at') <= ?)
                       OR created_at < ? - 86400)
                """,
                (moment, moment, moment, moment),
            )
        return int(cursor.rowcount or 0)

    def proposal_stats(self, bot_id: Optional[str] = None) -> Dict[str, Any]:
        clauses: List[str] = []
        params: List[Any] = []
        if bot_id is not None:
            clauses.append("bot_id = ?")
            params.append(bot_id)
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        with self._lock:
            rows = _rows(
                self.conn.execute(
                    f"SELECT action, status, COUNT(*) AS total FROM agent_proposals {where}"
                    "GROUP BY action, status",
                    params,
                )
            )
        breakdown: Dict[str, int] = {}
        totals: Dict[str, int] = {"pending": 0, "approved": 0, "declined": 0, "expired": 0, "failed": 0, "superseded": 0}
        for row in rows:
            total = int(row["total"])
            breakdown[f"{row['action']}:{row['status']}"] = total
            if row["status"] in totals:
                totals[row["status"]] += total
        return {"breakdown": breakdown, "totals": totals, **totals}

    # --------------------------------------------------------- A2A negotiations
    NEGOTIATION_FIELDS = (
        "peer_label",
        "channel",
        "status",
        "round",
        "owner_timezone",
        "peer_timezone",
        "window_start",
        "window_end",
        "duration_minutes",
        "owner_slots",
        "peer_slots",
        "intersection",
        "agreed_slot",
        "proposal_id",
        "last_error",
        "expires_at",
    )
    NEGOTIATION_JSON = ("owner_slots", "peer_slots", "intersection", "agreed_slot")

    def create_negotiation(
        self,
        bot_id: str,
        peer_identity: str,
        *,
        negotiation_id: Optional[str] = None,
        peer_label: str = "",
        channel: str = "a2a",
        owner_timezone: str = "",
        peer_timezone: str = "",
        window_start: float = 0.0,
        window_end: float = 0.0,
        duration_minutes: int = 60,
        expires_at: float = 0.0,
        owner_slots: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        if channel not in ("a2a", "guest"):
            raise LedgerError(f"非法协商通道 {channel!r}")
        identifier = negotiation_id or new_negotiation_id()
        if not _ID_RE.match(identifier):
            raise LedgerError(f"协商 id 非法：{identifier!r}")
        now = time.time()
        with self._lock:
            try:
                self.conn.execute(
                    """
                    INSERT INTO a2a_negotiations (negotiation_id, bot_id, peer_identity, peer_label, channel,
                        status, round, owner_timezone, peer_timezone, window_start, window_end, duration_minutes,
                        owner_slots, peer_slots, intersection, agreed_slot, proposal_id, last_error,
                        created_at, updated_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, 'open', 0, ?, ?, ?, ?, ?, ?, '[]', '[]', '{}', '', '', ?, ?, ?)
                    """,
                    (
                        identifier,
                        bot_id,
                        peer_identity,
                        peer_label,
                        channel,
                        owner_timezone,
                        peer_timezone,
                        float(window_start),
                        float(window_end),
                        int(duration_minutes),
                        _json_dump(list(owner_slots or []), label="候选时段"),
                        now,
                        now,
                        float(expires_at),
                    ),
                )
            except sqlite3.IntegrityError as exc:  # negotiation_id 撞 UNIQUE
                raise LedgerError(f"创建协商失败：{exc}") from exc
        record = self.get_negotiation(identifier)
        assert record is not None
        return record

    def get_negotiation(self, negotiation_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM a2a_negotiations WHERE negotiation_id = ?", (negotiation_id,)
            ).fetchone()
        return _negotiation_record(row) if row else None

    def find_open_negotiation(self, bot_id: str, peer_identity: str) -> Optional[Dict[str, Any]]:
        if not peer_identity:
            return None
        with self._lock:
            row = self.conn.execute(
                """
                SELECT * FROM a2a_negotiations
                WHERE bot_id = ? AND peer_identity = ? AND status = 'open'
                  AND (expires_at = 0 OR expires_at > ?)
                ORDER BY updated_at DESC LIMIT 1
                """,
                (bot_id, peer_identity, time.time()),
            ).fetchone()
        return _negotiation_record(row) if row else None

    def list_negotiations(
        self,
        bot_id: Optional[str] = None,
        *,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        clauses: List[str] = []
        params: List[Any] = []
        if bot_id is not None:
            clauses.append("bot_id = ?")
            params.append(bot_id)
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        params.append(limit)
        with self._lock:
            rows = _rows(
                self.conn.execute(
                    f"SELECT * FROM a2a_negotiations {where}ORDER BY created_at DESC LIMIT ?", params
                )
            )
        return [_negotiation_record(row) for row in rows]

    def update_negotiation(self, negotiation_id: str, **fields: Any) -> Dict[str, Any]:
        unknown = set(fields) - set(self.NEGOTIATION_FIELDS)
        if unknown:
            raise LedgerError(f"a2a_negotiations 不接受字段 {sorted(unknown)}")
        if "status" in fields and fields["status"] not in NEGOTIATION_STATUSES:
            raise LedgerError(f"非法协商状态 {fields['status']!r}")
        if not fields:
            record = self.get_negotiation(negotiation_id)
            if record is None:
                raise LedgerError(f"协商 {negotiation_id} 不存在")
            return record
        params: List[Any] = []
        for key, value in fields.items():
            if key in self.NEGOTIATION_JSON and not isinstance(value, str):
                params.append(_json_dump(value, label=f"协商 {key}"))
            else:
                params.append(value)
        assignments = ", ".join(f"{key} = ?" for key in fields)
        params += [time.time(), negotiation_id]
        with self._lock:
            cursor = self.conn.execute(
                f"UPDATE a2a_negotiations SET {assignments}, updated_at = ? WHERE negotiation_id = ?",
                params,
            )
            if cursor.rowcount == 0:
                raise LedgerError(f"协商 {negotiation_id} 不存在")
        record = self.get_negotiation(negotiation_id)
        assert record is not None
        return record

    def negotiation_stats(self, bot_id: Optional[str] = None) -> Dict[str, Any]:
        clauses: List[str] = []
        params: List[Any] = []
        if bot_id is not None:
            clauses.append("bot_id = ?")
            params.append(bot_id)
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        with self._lock:
            rows = _rows(
                self.conn.execute(
                    f"SELECT status, COUNT(*) AS total, AVG(round) AS rounds "
                    f"FROM a2a_negotiations {where}GROUP BY status",
                    params,
                )
            )
        stats: Dict[str, Any] = {"total": 0, "avg_rounds": 0.0}
        rounds, rounds_seen = 0.0, 0
        for row in rows:
            total = int(row["total"])
            stats[str(row["status"])] = total
            stats["total"] += total
            if row["rounds"] is not None:
                rounds += float(row["rounds"]) * total
                rounds_seen += total
        if rounds_seen:
            stats["avg_rounds"] = round(rounds / rounds_seen, 2)
        return stats

    # ------------------------------------------------------------ guest links
    def create_guest_link(
        self,
        bot_id: str,
        token: str,
        *,
        link_id: Optional[str] = None,
        label: str = "",
        topic: str = "",
        max_uses: int = 1,
        duration_minutes: int = 60,
        timezone: str = "",
        expires_at: float = 0.0,
        created_by: str = "",
    ) -> Dict[str, Any]:
        if not token:
            raise LedgerError("访客链接缺少 token")
        if not 1 <= int(max_uses) <= 1000:
            raise LedgerError("访客链接可用次数必须在 1–1000 之间")
        identifier = link_id or new_guest_link_id()
        if not _ID_RE.match(identifier):
            raise LedgerError(f"访客链接 id 非法：{identifier!r}")
        with self._lock:
            try:
                self.conn.execute(
                    """
                    INSERT INTO guest_links (link_id, bot_id, token, label, topic, status, max_uses, uses,
                        duration_minutes, timezone, proposal_id, created_at, created_by, expires_at,
                        last_used_at, revoked_at)
                    VALUES (?, ?, ?, ?, ?, 'active', ?, 0, ?, ?, '', ?, ?, ?, 0, 0)
                    """,
                    (
                        identifier,
                        bot_id,
                        token,
                        label,
                        topic,
                        int(max_uses),
                        int(duration_minutes),
                        timezone,
                        time.time(),
                        created_by,
                        float(expires_at),
                    ),
                )
            except sqlite3.IntegrityError as exc:  # token/link_id 撞 UNIQUE：重复签发
                raise LedgerError(f"创建访客链接失败：{exc}") from exc
        record = self.get_guest_link(identifier)
        assert record is not None
        return record

    def get_guest_link(self, link_id: str = "", *, token: str = "") -> Optional[Dict[str, Any]]:
        if link_id:
            sql, params = "SELECT * FROM guest_links WHERE link_id = ?", (link_id,)
        elif token:
            sql, params = "SELECT * FROM guest_links WHERE token = ?", (token,)
        else:
            return None
        with self._lock:
            row = self.conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    def list_guest_links(
        self,
        bot_id: Optional[str] = None,
        *,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        clauses: List[str] = []
        params: List[Any] = []
        if bot_id is not None:
            clauses.append("bot_id = ?")
            params.append(bot_id)
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        params.append(limit)
        with self._lock:
            rows = _rows(
                self.conn.execute(
                    f"SELECT * FROM guest_links {where}ORDER BY created_at DESC LIMIT ?", params
                )
            )
        return rows

    def record_guest_use(self, link_id: str, *, visitor_hash: str = "") -> Optional[Dict[str, Any]]:
        """Count one visit and flip the link to ``exhausted`` once its budget is spent."""
        with self._lock:
            self.conn.execute(
                """
                UPDATE guest_links
                SET uses = uses + 1, last_used_at = ?,
                    status = CASE WHEN uses + 1 >= max_uses AND status = 'active'
                                  THEN 'exhausted' ELSE status END
                WHERE link_id = ? AND status IN ('active','exhausted')
                """,
                (time.time(), link_id),
            )
        return self.get_guest_link(link_id)

    def revoke_guest_link(self, link_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            self.conn.execute(
                "UPDATE guest_links SET status = 'revoked', revoked_at = ? WHERE link_id = ?",
                (time.time(), link_id),
            )
        return self.get_guest_link(link_id)

    def mark_guest_links_expired(self, *, now: Optional[float] = None) -> int:
        moment = time.time() if now is None else float(now)
        with self._lock:
            cursor = self.conn.execute(
                "UPDATE guest_links SET status = 'expired' WHERE status = 'active' "
                "AND expires_at > 0 AND expires_at <= ?",
                (moment,),
            )
        return int(cursor.rowcount or 0)

    def link_stats(self, bot_id: Optional[str] = None) -> Dict[str, Any]:
        clauses: List[str] = []
        params: List[Any] = []
        if bot_id is not None:
            clauses.append("bot_id = ?")
            params.append(bot_id)
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        with self._lock:
            rows = _rows(
                self.conn.execute(
                    f"SELECT status, COUNT(*) AS total, COALESCE(SUM(uses), 0) AS uses "
                    f"FROM guest_links {where}GROUP BY status",
                    params,
                )
            )
        stats: Dict[str, Any] = {"total": 0, "visits": 0}
        for row in rows:
            stats[str(row["status"])] = int(row["total"])
            stats["total"] += int(row["total"])
            stats["visits"] += int(row["uses"])
        return stats

    def set_link_proposal(self, link_id: str, proposal_id: str) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE guest_links SET proposal_id = ? WHERE link_id = ?",
                (proposal_id, link_id),
            )

    def append_guest_message(
        self,
        bot_id: str,
        link_id: str,
        role: str,
        text: str,
        *,
        proposal_id: str = "",
        status: str = "ok",
        visitor_hash: str = "",
    ) -> int:
        if role not in GUEST_ROLES:
            raise LedgerError(f"非法访客会话角色 {role!r}")
        with self._lock:
            cursor = self.conn.execute(
                """
                INSERT INTO guest_messages (bot_id, link_id, role, text, proposal_id, status,
                    visitor_hash, ts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (bot_id, link_id, role, text[:2000], proposal_id, status, visitor_hash, time.time()),
            )
        return int(cursor.lastrowid or 0)

    def list_guest_messages(self, link_id: str, *, limit: int = 200) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._lock:
            rows = _rows(
                self.conn.execute(
                    "SELECT * FROM (SELECT * FROM guest_messages WHERE link_id = ? "
                    "ORDER BY ts DESC LIMIT ?) ORDER BY ts ASC",
                    (link_id, limit),
                )
            )
        return rows

    # ---------------------------------------------------------- negotiation log
    def log_negotiation(
        self,
        stage: str,
        event: str,
        *,
        bot_id: str = "",
        level: str = "info",
        proposal_id: str = "",
        negotiation_id: str = "",
        link_id: str = "",
        chat_ref: str = "",
        correlation_id: str = "",
        detail: str = "",
        data: Optional[Dict[str, Any]] = None,
        latency_ms: float = 0.0,
    ) -> int:
        if stage not in AUDIT_STAGES:
            raise LedgerError(f"非法审计阶段 {stage!r}")
        if level not in AUDIT_LEVELS:
            raise LedgerError(f"非法审计级别 {level!r}")
        with self._lock:
            cursor = self.conn.execute(
                """
                INSERT INTO negotiation_audit (bot_id, stage, event, level, proposal_id, negotiation_id,
                    link_id, chat_ref, correlation_id, detail, data, latency_ms, ts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    bot_id or "",
                    stage,
                    event,
                    level,
                    proposal_id,
                    negotiation_id,
                    link_id,
                    chat_ref,
                    correlation_id or "",
                    detail[:500],
                    _json_dump(data or {}, label="审计数据"),
                    float(latency_ms),
                    time.time(),
                ),
            )
        return int(cursor.lastrowid or 0)

    def recent_negotiations(
        self,
        bot_id: Optional[str] = None,
        *,
        limit: int = 100,
        stage: Optional[str] = None,
        level: Optional[str] = None,
        proposal_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        clauses: List[str] = []
        params: List[Any] = []
        if bot_id is not None:
            clauses.append("bot_id = ?")
            params.append(bot_id)
        if stage is not None:
            clauses.append("stage = ?")
            params.append(stage)
        if level is not None:
            clauses.append("level = ?")
            params.append(level)
        if proposal_id is not None:
            clauses.append("proposal_id = ?")
            params.append(proposal_id)
        if correlation_id is not None:
            clauses.append("correlation_id = ?")
            params.append(correlation_id)
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        params.append(limit)
        with self._lock:
            rows = _rows(
                self.conn.execute(
                    f"SELECT * FROM negotiation_audit {where}ORDER BY ts DESC LIMIT ?", params
                )
            )
        for row in rows:
            row["data"] = _json_load(row.get("data"), {})
        return rows

    def audit_replay(self, correlation_id: str, *, limit: int = 500) -> List[Dict[str, Any]]:
        """回放一条编排线程上的全部审计，按时间正序 —— 派活的因果顺序不能倒着读。

        只按 ``correlation_id`` 取，不按 bot 取：一次扇出会横跨发起方与被派方多个 Bot，
        按 Bot 过滤正好把要看的跨 Agent 那段切掉。
        """
        wanted = (correlation_id or "").strip()
        if not wanted:
            raise LedgerError("回放需要 correlation_id")
        limit = max(1, min(int(limit), 2000))
        with self._lock:
            rows = _rows(
                self.conn.execute(
                    "SELECT * FROM negotiation_audit WHERE correlation_id = ? "
                    "ORDER BY ts ASC, id ASC LIMIT ?",
                    (wanted, limit),
                )
            )
        for row in rows:
            row["data"] = _json_load(row.get("data"), {})
        return rows

    def negotiation_funnel(self, bot_id: Optional[str] = None) -> Dict[str, Any]:
        clauses: List[str] = []
        params: List[Any] = []
        if bot_id is not None:
            clauses.append("bot_id = ?")
            params.append(bot_id)
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        error_clauses = [*clauses, "level = 'error'"]
        with self._lock:
            by_stage = _rows(
                self.conn.execute(
                    f"SELECT stage, COUNT(*) AS total FROM negotiation_audit {where}"
                    "GROUP BY stage ORDER BY stage",
                    params,
                )
            )
            errors = _rows(
                self.conn.execute(
                    "SELECT stage, COUNT(*) AS total FROM negotiation_audit "
                    f"WHERE {' AND '.join(error_clauses)} GROUP BY stage",
                    params,
                )
            )
        return {
            "stages": {str(row["stage"]): int(row["total"]) for row in by_stage},
            "errors": {str(row["stage"]): int(row["total"]) for row in errors},
        }

    # ---------------------------------------------------------- calendar cache
    def cache_busy(
        self,
        bot_id: str,
        day: str,
        busy: Sequence[Dict[str, Any]],
        *,
        timezone: str = "",
        source: str = "mac_node",
        ttl_seconds: float = 900.0,
    ) -> None:
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", str(day)):
            raise LedgerError(f"忙闲缓存日期非法：{day!r}")
        try:
            date.fromisoformat(str(day))
        except ValueError as exc:
            raise LedgerError(f"忙闲缓存日期非法：{day!r}") from exc
        now = time.time()
        payload = _json_dump([dict(item) for item in busy], label="忙闲区间")
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO calendar_cache (bot_id, day, timezone, busy, source, fetched_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (bot_id, day, source) DO UPDATE SET
                    timezone = excluded.timezone,
                    busy = excluded.busy,
                    fetched_at = excluded.fetched_at,
                    expires_at = excluded.expires_at
                """,
                (bot_id, day, timezone, payload, source, now, now + max(1.0, float(ttl_seconds))),
            )

    def cached_busy(
        self,
        bot_id: str,
        day: str,
        *,
        source: str = "mac_node",
        now: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        moment = time.time() if now is None else float(now)
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM calendar_cache WHERE bot_id = ? AND day = ? AND source = ?",
                (bot_id, day, source),
            ).fetchone()
        if not row:
            return None
        record = dict(row)
        if float(record["expires_at"]) <= moment:
            return None
        record["busy"] = _json_load(record["busy"], [])
        return record

    def purge_calendar_cache(self, *, now: Optional[float] = None) -> int:
        moment = time.time() if now is None else float(now)
        with self._lock:
            cursor = self.conn.execute(
                "DELETE FROM calendar_cache WHERE expires_at <= ?", (moment,)
            )
        return int(cursor.rowcount or 0)

    # ------------------------------------------------------ cross-agent tasks
    def grant_agent_task(
        self,
        origin_bot_id: str,
        target_bot_id: str,
        capability: str,
        *,
        max_hops: int = 1,
        max_concurrent: int = 4,
        timeout_seconds: float = 20.0,
        enabled: bool = True,
        require_approval: bool = False,
    ) -> Dict[str, Any]:
        """写入或更新一条跨 Agent 派活授权；同 (origin,target,capability) 幂等覆盖。

        授权是**默认拒绝**的：没有这行，编排层一律 ``refused``，不存在"没配就等于能派"。
        ``require_approval`` 让该授权下的任务在 ``running`` 前先停在 ``awaiting_user``，
        等主人批准后才继续 —— 它是额外的闸，不是放行券：批准也绕不过授权本身。
        """
        origin = _require_agent_id(origin_bot_id, "origin_bot_id")
        target = _require_agent_id(target_bot_id, "target_bot_id")
        scope = _require_capability(capability)
        hops = max(1, min(int(max_hops), MAX_TASK_HOPS))
        concurrent = max(1, min(int(max_concurrent), MAX_TASK_CONCURRENCY))
        seconds = _clamp_task_timeout(timeout_seconds)
        approval = 1 if require_approval else 0
        moment = time.time()
        with self._lock:
            existing = self.conn.execute(
                "SELECT id FROM agent_task_grants "
                "WHERE origin_bot_id = ? AND target_bot_id = ? AND capability = ?",
                (origin, target, scope),
            ).fetchone()
            if existing is None:
                cursor = self.conn.execute(
                    """
                    INSERT INTO agent_task_grants (origin_bot_id, target_bot_id, capability,
                        max_hops, max_concurrent, timeout_seconds, enabled, require_approval,
                        created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        origin,
                        target,
                        scope,
                        hops,
                        concurrent,
                        seconds,
                        1 if enabled else 0,
                        approval,
                        moment,
                        moment,
                    ),
                )
                grant_id = int(cursor.lastrowid or 0)
            else:
                grant_id = int(existing["id"])
                self.conn.execute(
                    "UPDATE agent_task_grants SET max_hops = ?, max_concurrent = ?, "
                    "timeout_seconds = ?, enabled = ?, require_approval = ?, updated_at = ? "
                    "WHERE id = ?",
                    (hops, concurrent, seconds, 1 if enabled else 0, approval, moment, grant_id),
                )
        row = self.get_grant(grant_id)
        if row is None:
            raise LedgerError("授权写入后读不到")
        return row

    def get_grant(self, grant_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM agent_task_grants WHERE id = ?", (int(grant_id),)
            ).fetchone()
        return dict(row) if row else None

    def find_grant(self, origin_bot_id: str, target_bot_id: str, capability: str) -> Optional[Dict[str, Any]]:
        """取生效授权：精确能力优先，其次通配。禁用行永不返回。"""
        origin = _require_agent_id(origin_bot_id, "origin_bot_id")
        target = _require_agent_id(target_bot_id, "target_bot_id")
        scope = _require_capability(capability)
        with self._lock:
            rows = _rows(
                self.conn.execute(
                    "SELECT * FROM agent_task_grants WHERE origin_bot_id = ? AND target_bot_id = ? "
                    "AND capability IN (?, ?) AND enabled = 1",
                    (origin, target, scope, GRANT_WILDCARD),
                )
            )
        for row in rows:
            if row["capability"] == scope:
                return row
        for row in rows:
            if row["capability"] == GRANT_WILDCARD:
                return row
        return None

    def list_grants(
        self,
        *,
        origin_bot_id: Optional[str] = None,
        target_bot_id: Optional[str] = None,
        enabled_only: bool = False,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        if origin_bot_id is not None:
            clauses.append("origin_bot_id = ?")
            params.append(origin_bot_id)
        if target_bot_id is not None:
            clauses.append("target_bot_id = ?")
            params.append(target_bot_id)
        if enabled_only:
            clauses.append("enabled = 1")
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        with self._lock:
            rows = _rows(
                self.conn.execute(
                    f"SELECT * FROM agent_task_grants {where}ORDER BY origin_bot_id, target_bot_id, capability",
                    params,
                )
            )
        return rows

    def set_grant_enabled(self, grant_id: int, enabled: bool) -> Optional[Dict[str, Any]]:
        with self._lock:
            cursor = self.conn.execute(
                "UPDATE agent_task_grants SET enabled = ?, updated_at = ? WHERE id = ?",
                (1 if enabled else 0, time.time(), int(grant_id)),
            )
        if not cursor.rowcount:
            return None
        return self.get_grant(grant_id)

    def delete_grant(self, grant_id: int) -> bool:
        with self._lock:
            cursor = self.conn.execute("DELETE FROM agent_task_grants WHERE id = ?", (int(grant_id),))
        return bool(cursor.rowcount)

    def create_task(
        self,
        *,
        correlation_id: str,
        origin_bot_id: str,
        target_bot_id: str,
        capability: str,
        parent_id: str = "",
        args: Optional[Dict[str, Any]] = None,
        status: str = "created",
        hops: int = 1,
        timeout_seconds: float = 20.0,
        profile: Optional[Dict[str, Any]] = None,
        retention_mode: str = "",
        approval_required: bool = False,
    ) -> Dict[str, Any]:
        if status not in TASK_STATUSES:
            raise LedgerError(f"非法任务状态 {status!r}")
        if retention_mode and retention_mode not in RETENTION_MODES:
            raise LedgerError(f"非法留存模式 {retention_mode!r}")
        task_id = new_task_id()
        moment = time.time()
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO agent_tasks (id, correlation_id, parent_id, origin_bot_id, target_bot_id,
                    capability, args_json, profile_json, status, retention_mode, approval_required,
                    hops, timeout_seconds, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    correlation_id,
                    parent_id or "",
                    _require_agent_id(origin_bot_id, "origin_bot_id"),
                    _require_agent_id(target_bot_id, "target_bot_id"),
                    _require_capability(capability),
                    _json_dump(args or {}, label="任务入参"),
                    _json_dump(profile or {}, label="执行画像"),
                    status,
                    retention_mode,
                    1 if approval_required else 0,
                    max(1, min(int(hops), MAX_TASK_HOPS)),
                    _clamp_task_timeout(timeout_seconds),
                    moment,
                ),
            )
        row = self.get_task(task_id)
        if row is None:
            raise LedgerError("任务写入后读不到")
        return row

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM agent_tasks WHERE id = ?", (task_id,)).fetchone()
        return _task_record(row) if row else None

    def task_children(self, parent_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            rows = _rows(
                self.conn.execute(
                    "SELECT * FROM agent_tasks WHERE parent_id = ? ORDER BY created_at, id", (parent_id,)
                )
            )
        return [_task_record(row) for row in rows]

    def update_task(self, task_id: str, **fields: Any) -> Optional[Dict[str, Any]]:
        """只允许改这几个列；``id`` / ``correlation_id`` / ``created_at`` 不可动。"""
        allowed = {
            "status",
            "result_json",
            "error_code",
            "detail",
            "started_at",
            "finished_at",
            "latency_ms",
            "args_json",
            "approved_at",
            "cleanup_at",
            "cleanup_detail",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise LedgerError(f"任务字段不可写: {sorted(unknown)}")
        if "status" in fields and fields["status"] not in TASK_STATUSES:
            raise LedgerError(f"非法任务状态 {fields['status']!r}")
        if not fields:
            return self.get_task(task_id)
        assignments = ", ".join(f"{key} = ?" for key in fields)
        with self._lock:
            cursor = self.conn.execute(
                f"UPDATE agent_tasks SET {assignments} WHERE id = ?", [*fields.values(), task_id]
            )
        if not cursor.rowcount:
            return None
        return self.get_task(task_id)

    def list_tasks(
        self,
        *,
        bot_id: Optional[str] = None,
        status: Optional[str] = None,
        capability: Optional[str] = None,
        correlation_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        clauses: List[str] = []
        params: List[Any] = []
        if bot_id is not None:
            clauses.append("(origin_bot_id = ? OR target_bot_id = ?)")
            params.extend([bot_id, bot_id])
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if capability is not None:
            clauses.append("capability = ?")
            params.append(capability)
        if correlation_id is not None:
            clauses.append("correlation_id = ?")
            params.append(correlation_id)
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        params.append(limit)
        with self._lock:
            rows = _rows(
                self.conn.execute(
                    f"SELECT * FROM agent_tasks {where}ORDER BY created_at DESC, id DESC LIMIT ?", params
                )
            )
        return [_task_record(row) for row in rows]

    def count_active_tasks(self, target_bot_id: str, capability: Optional[str] = None) -> int:
        """并发预算口径：``running`` 与 ``awaiting_user`` 都占额度。

        等审批的任务并没有释放它持有的分配，若不计入，一个挂起任务就能靠"再派一个"绕过
        ``max_concurrent``。``created``/``scheduled`` 等尚未占位的状态不计。
        """
        sql = (
            "SELECT COUNT(*) FROM agent_tasks WHERE target_bot_id = ? "
            "AND status IN ('running', 'awaiting_user')"
        )
        params: List[Any] = [target_bot_id]
        if capability is not None:
            sql += " AND capability = ?"
            params.append(capability)
        with self._lock:
            return int(self.conn.execute(sql, params).fetchone()[0])

    def task_stats(self, bot_id: Optional[str] = None) -> Dict[str, Any]:
        clauses: List[str] = []
        params: List[Any] = []
        if bot_id is not None:
            clauses.append("(origin_bot_id = ? OR target_bot_id = ?)")
            params.extend([bot_id, bot_id])
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        with self._lock:
            by_status = _rows(
                self.conn.execute(
                    f"SELECT status, COUNT(*) AS total FROM agent_tasks {where}"
                    "GROUP BY status ORDER BY status",
                    params,
                )
            )
            by_capability = _rows(
                self.conn.execute(
                    f"SELECT capability, COUNT(*) AS total, AVG(latency_ms) AS avg_latency_ms "
                    f"FROM agent_tasks {where}GROUP BY capability ORDER BY capability",
                    params,
                )
            )
            grant_sql = "SELECT COUNT(*) FROM agent_task_grants WHERE enabled = 1"
            if bot_id is not None:
                grant_sql += " AND (origin_bot_id = ? OR target_bot_id = ?)"
            grants = int(self.conn.execute(grant_sql, params if bot_id is not None else ()).fetchone()[0])
        return {
            "by_status": {row["status"]: int(row["total"]) for row in by_status},
            "by_capability": [
                {
                    "capability": row["capability"],
                    "total": int(row["total"]),
                    "avg_latency_ms": round(float(row["avg_latency_ms"] or 0.0), 3),
                }
                for row in by_capability
            ],
            "active_grants": grants,
            "total": sum(int(row["total"]) for row in by_status),
        }

    # ------------------------------------------------------------- agent total
    def agent_snapshot(self, bot_id: Optional[str] = None) -> Dict[str, Any]:
        """One aggregated view for the console: proposals, negotiations, links, audit."""
        return {
            "proposals": self.proposal_stats(bot_id),
            "negotiations": self.negotiation_stats(bot_id),
            "guest_links": self.link_stats(bot_id),
            "funnel": self.negotiation_funnel(bot_id),
            "recent": self.recent_negotiations(bot_id, limit=20),
        }


def _proposal_record(row: Any) -> Dict[str, Any]:
    record = dict(row)
    record["payload"] = _json_load(record.get("payload"), {})
    return record


def _require_agent_id(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _ID_RE.match(text):
        raise LedgerError(f"{label} 不是合法 Bot id")
    return text


def _require_capability(value: Any) -> str:
    text = str(value or "").strip()
    if text == GRANT_WILDCARD:
        return text
    if not GRANT_CAPABILITY_RE.match(text):
        raise LedgerError(f"能力名 {text!r} 非法：小写字母开头，允许 a-z0-9_.-，长度 3..64")
    return text


def _clamp_task_timeout(value: Any) -> float:
    try:
        seconds = float(value)
    except (TypeError, ValueError) as exc:
        raise LedgerError(f"超时必须是数字，收到 {value!r}") from exc
    if not math.isfinite(seconds):
        raise LedgerError("超时必须是有限数字")
    return max(TASK_TIMEOUT_MIN_SECONDS, min(seconds, TASK_TIMEOUT_MAX_SECONDS))


def _task_record(row: Any) -> Dict[str, Any]:
    """行 → 对外记录。两个 JSON 列在这里解码，并派生 ``outcome``。

    ``outcome`` 把 11 个存储状态收敛成调用方关心的四值结果：
    ``completed``/``workspace_cleanup`` → ``succeeded``；``failed``/``refused`` →
    ``failed``；``cancelled`` → ``cancelled``；其余（进行中、等审批）→ ``pending``。
    存储状态保留"卡在哪一步"，``outcome`` 回答"最后成没成"，二者不互相顶替。
    """
    record = dict(row)
    record["args"] = _json_load(record.pop("args_json", ""), {})
    record["profile"] = _json_load(record.pop("profile_json", ""), {})
    raw = record.pop("result_json", "") or ""
    record["result"] = _json_load(raw, {}) if raw else {}
    record["approval_required"] = bool(record.get("approval_required"))
    record["outcome"] = task_outcome(str(record.get("status") or ""))
    return record


def task_outcome(status: str) -> str:
    """存储状态 → 派生结果（见 :func:`_task_record`）。未知状态按 ``pending`` 处理。"""
    if status in ("completed", "workspace_cleanup"):
        return "succeeded"
    if status in ("failed", "refused"):
        return "failed"
    if status == "cancelled":
        return "cancelled"
    return "pending"


def _negotiation_record(row: Any) -> Dict[str, Any]:
    record = dict(row)
    record["owner_slots"] = _json_load(record.get("owner_slots"), [])
    record["peer_slots"] = _json_load(record.get("peer_slots"), [])
    record["intersection"] = _json_load(record.get("intersection"), [])
    record["agreed_slot"] = _json_load(record.get("agreed_slot"), {})
    return record


def connect(settings_db_path: Path | str, *, target_version: int = SCHEMA_VERSION) -> Database:
    """Open *and* migrate the ledger at *settings_db_path*."""
    database = Database(settings_db_path)
    database.migrate(target_version=target_version)
    return database
