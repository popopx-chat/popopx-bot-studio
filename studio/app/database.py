"""SQLite ledger for Bot Studio.

The ledger is the single source of truth for bots, reply rules, routing rules,
plugin configuration and the audit log. It is versioned: ``schema_migrations``
records every applied step so an install can be upgraded in place.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .config import SECURE_FILE_MODE

SCHEMA_VERSION = 4

_ID_RE = re.compile(r"^[a-z0-9_-]{3,64}$")
TRIGGER_TYPES = ("exact", "prefix", "regex", "default")
SOURCE_TYPES = ("direct", "group", "any")
TARGET_TYPES = ("group", "contact", "broadcast")
BOT_STATUSES = ("draft", "stopped", "running", "error", "deleted")
DIRECTIONS = ("in", "out")
LOG_STATUSES = ("ok", "cooldown", "skipped", "error", "forwarded", "no_match")


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
                for table in ("reply_rules", "routing_rules", "plugin_configs"):
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


def connect(settings_db_path: Path | str, *, target_version: int = SCHEMA_VERSION) -> Database:
    """Open *and* migrate the ledger at *settings_db_path*."""
    database = Database(settings_db_path)
    database.migrate(target_version=target_version)
    return database
