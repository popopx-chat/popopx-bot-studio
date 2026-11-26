"""Studio runtime configuration.

Loads ``.env`` style configuration, validates the loopback-only networking
invariant and reports files whose permissions are wider than 0600.
"""

from __future__ import annotations

import os
import re
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from .i18n import FALLBACK_LOCALE, normalize_locale

DEFAULT_PORT = 8090
DEFAULT_HOST = "127.0.0.1"
DEFAULT_CLI_BIN_PATH = "/usr/local/bin/popopx-cli"
DEFAULT_WS_PORT_BASE = 5230
DEFAULT_CLI_WS_PORT_MAX = 5299
DEFAULT_MAC_NODE_PORT = 18920
DEFAULT_MAC_NODE_URL = f"http://127.0.0.1:{DEFAULT_MAC_NODE_PORT}"
DEFAULT_GUEST_TTL_HOURS = 72
SECURE_FILE_MODE = 0o600
SECURE_DIR_MODE = 0o700

_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
_UNSAFE_ID = re.compile(r"[^A-Za-z0-9_.-]+")
_LOOPBACK_NAMES = {"localhost", "::1", "ip6-localhost", "ip6-loopback"}
_TRUE_VALUES = {"1", "true", "yes", "on"}


class ConfigError(RuntimeError):
    """Raised when the environment cannot produce a safe Studio config."""


def parse_env_text(text: str) -> Dict[str, str]:
    """Parse ``KEY=value`` lines, honouring quotes and ``#`` comments."""
    values: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _ENV_LINE.match(line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            values[key] = value[1:-1]
            continue
        # Unquoted values may carry a trailing comment.
        if "#" in value:
            value = value.split("#", 1)[0].strip()
        values[key] = value
    return values


def load_env_file(path: Path, environ: Dict[str, str] | None = None) -> Dict[str, str]:
    """Return the pairs from *path* that *environ* does not already define."""
    env = os.environ if environ is None else environ
    if not path.is_file():
        return {}
    parsed = parse_env_text(path.read_text(encoding="utf-8"))
    return {k: v for k, v in parsed.items() if k not in env}


def find_env_file(start: Optional[Path] = None) -> Optional[Path]:
    """Locate the ``.env`` shipped next to the repository root or in *start*."""
    explicit = os.environ.get("STUDIO_ENV_FILE")
    if explicit:
        candidate = Path(explicit).expanduser()
        return candidate if candidate.is_file() else None
    base = (start or Path(__file__).resolve().parent).resolve()
    for directory in [base, *base.parents][:6]:
        candidate = directory / ".env"
        if candidate.is_file():
            return candidate
    cwd_candidate = Path.cwd() / ".env"
    return cwd_candidate if cwd_candidate.is_file() else None


def is_loopback_host(host: str) -> bool:
    """True for addresses that cannot be reached from another machine."""
    lowered = host.strip().strip("[]").lower()
    if lowered in _LOOPBACK_NAMES:
        return True
    if lowered.startswith("127."):
        parts = lowered.split(".")
        return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    if lowered.startswith("::1"):
        return True
    return False


def is_loopback_http_url(url: str) -> bool:
    """True only for ``http(s)`` URLs whose host is loopback.

    The Mac Node connector uses this as its SSRF gate: anything that is not a
    literal loopback name or address is refused before a socket is opened.
    """
    candidate = str(url or "").strip()
    if not candidate:
        return False
    parts = urlsplit(candidate)
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        return False
    if parts.username or parts.password:
        return False
    host = parts.hostname or ""
    return is_loopback_host(host)


def mode_of(path: Path) -> Optional[int]:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None


def bot_dir_name(bot_id: str) -> str:
    """Sanitize a Bot identifier before it becomes a directory name.

    ``bot_id`` normally comes from :func:`app.database.new_bot_id` and is already
    safe, but the agent modules hand this straight to ``mkdir``.
    """
    cleaned = _UNSAFE_ID.sub("_", str(bot_id or "").strip())[:80].strip(".")
    return cleaned or "default"


def permission_warnings(
    paths: Iterable[Tuple[str, Optional[Path]]],
    *,
    expected: int = SECURE_FILE_MODE,
) -> List[str]:
    """Describe every path whose mode is wider than *expected*.

    ``label`` keeps the warning actionable for an operator who has never seen
    the file layout before.
    """
    warnings: List[str] = []
    for label, path in paths:
        if path is None:
            continue
        mode = mode_of(path)
        if mode is None:
            continue
        if mode & ~expected:
            warnings.append(
                f"{label} {path} 权限为 0{mode:o}（应为 0{expected:o}），"
                f"请执行 chmod {expected:o} '{path}'"
            )
    return warnings


def default_data_dir() -> Path:
    override = os.environ.get("STUDIO_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    root = Path(__file__).resolve().parents[2]
    return (root / "var" / "studio").resolve()


@dataclass
class Settings:
    """Immutable view of the Studio environment."""

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    admin_token: str = ""
    data_dir: Path = field(default_factory=default_data_dir)
    cli_bin_path: Path = field(default_factory=lambda: Path(DEFAULT_CLI_BIN_PATH))
    ws_port_base: int = DEFAULT_WS_PORT_BASE
    ws_port_max: int = DEFAULT_CLI_WS_PORT_MAX
    cli_smp_servers: Optional[str] = None
    default_locale: str = "en"
    env_file: Optional[Path] = None
    allow_lan: bool = False
    agent_enabled: bool = True
    needle_asset_dir: Optional[str] = None
    needle_timeout_seconds: float = 2.0
    reasoner_enabled: bool = False
    reasoner_base_url: str = ""
    reasoner_model: str = ""
    reasoner_api_key: str = ""
    reasoner_timeout_seconds: float = 20.0
    mac_node_enabled: bool = False
    mac_node_url: str = DEFAULT_MAC_NODE_URL
    mac_node_token: str = ""
    mac_node_timeout_seconds: float = 8.0
    guest_enabled: bool = True
    guest_secret: str = ""
    guest_public_base: str = ""
    guest_default_ttl_hours: int = DEFAULT_GUEST_TTL_HOURS
    agent_a2a_secret: str = ""
    meeting_base_url: str = ""
    startup_warnings: List[str] = field(default_factory=list)

    @property
    def state_file(self) -> Path:
        return self.data_dir / "studio.state.json"

    @property
    def guest_key_file(self) -> Path:
        return self.data_dir / "guest.key"

    @property
    def a2a_key_file(self) -> Path:
        return self.data_dir / "a2a.key"

    def _read_key(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8").strip() if path.is_file() else ""
        except OSError:
            return ""

    def _write_key(self, path: Path, generated: str, label: str) -> str:
        """0600 独占落盘；并发里晚到者以磁盘上的值为准，绝不各写一份。"""
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, SECURE_FILE_MODE)
            try:
                os.write(descriptor, generated.encode("utf-8"))
            finally:
                os.close(descriptor)
            os.chmod(path, SECURE_FILE_MODE)
        except FileExistsError:
            return self._read_key(path) or generated
        except OSError as exc:
            self.startup_warnings.append(f"{label}密钥无法写入 {path}：{exc}，本次运行使用内存密钥")
        return generated

    def _ensure_key(self, path: Path, label: str) -> str:
        """密钥只落在数据目录里，不经过管理 API：拿到控制台令牌的人也伪造不了它。"""
        return self._read_key(path) or self._write_key(path, secrets.token_urlsafe(32), label)

    def ensure_guest_secret(self) -> str:
        """Return the HMAC key for guest links, creating ``guest.key`` on demand.

        The key never travels through the admin API, so a link survives a restart
        and cannot be forged by anyone holding only the console token.
        """
        if not self.guest_secret:
            self.guest_secret = self._ensure_key(self.guest_key_file, "访客链接")
        return self.guest_secret

    def ensure_a2a_secret(self) -> str:
        """A2A 帧的 HMAC 主密钥，落在独立的 ``a2a.key`` 里。

        与访客令牌分文件：轮换其中一条通道不会让另一条通道的历史签名失效，
        而 A2A 的按对端密钥就是这把主密钥与对方身份派生出来的（见 :mod:`app.a2a`）。
        """
        if not self.agent_a2a_secret:
            self.agent_a2a_secret = self._ensure_key(self.a2a_key_file, "A2A 协商")
        return self.agent_a2a_secret

    @property
    def db_file(self) -> Path:
        return self.data_dir / "studio.db"

    @property
    def bots_dir(self) -> Path:
        return self.data_dir / "bots"

    @property
    def backups_dir(self) -> Path:
        return self.data_dir / "backups"

    def cli_data_dir(self, bot_id: str) -> Path:
        return self.bots_dir / bot_dir_name(bot_id) / "cli-data"

    def wrapper_path(self, bot_id: str) -> Path:
        return self.bots_dir / bot_dir_name(bot_id) / "run-cli.sh"

    def pid_file(self, bot_id: str) -> Path:
        return self.bots_dir / bot_dir_name(bot_id) / "cli.pid"

    def agent_dir(self, bot_id: str) -> Path:
        """Per-Bot 替身机器人隔离目录（偏好规则与协商缓存）。"""
        return self.bots_dir / bot_dir_name(bot_id) / "agent"

    def ensure_directories(self) -> None:
        for directory in (self.data_dir, self.bots_dir, self.backups_dir):
            directory.mkdir(parents=True, exist_ok=True)
            mode = mode_of(directory)
            if mode is None or not (mode & ~SECURE_DIR_MODE):
                continue
            # 账本与冷备都落在这里，权限位一旦放宽，本机其它用户就能读到全部 Bot 令牌。
            try:
                os.chmod(directory, SECURE_DIR_MODE)
                self.startup_warnings.append(
                    f"数据目录 {directory} 原权限 0{mode:o}，已收紧为 0{SECURE_DIR_MODE:o}"
                )
            except OSError as exc:
                self.startup_warnings.append(
                    f"数据目录 {directory} 权限为 0{mode:o}（应为 0{SECURE_DIR_MODE:o}），收紧失败：{exc}"
                )

    def security_warnings(self) -> List[str]:
        """Permission findings for ``.env`` and the on-disk state artifacts."""
        pairs: List[Tuple[str, Optional[Path]]] = [
            ("配置文件", self.env_file),
            ("状态文件", self.state_file if self.state_file.exists() else None),
            ("SQLite 密钥文件", self.data_dir / "studio.key" if (self.data_dir / "studio.key").exists() else None),
        ]
        if self.guest_key_file.exists():
            pairs.append(("访客链接密钥文件", self.guest_key_file))
        if self.a2a_key_file.exists():
            pairs.append(("A2A 协商密钥文件", self.a2a_key_file))
        findings = permission_warnings(pairs)
        if self.bots_dir.is_dir():
            # 目录位是 0710/0700 级别，用 0600 去比对会把 x 位误报成越权。
            findings.extend(
                permission_warnings(
                    ((f"替身机器人隔离目录 {path.name}", path) for path in sorted(self.bots_dir.glob("*/agent"))),
                    expected=SECURE_DIR_MODE,
                )
            )
        return findings


def _int_env(env: Dict[str, str], key: str, default: int) -> int:
    raw = env.get(key)
    if raw is None or raw == "":
        return default
    try:
        return int(str(raw).strip())
    except ValueError as exc:
        raise ConfigError(f"{key} 必须是整数，当前值 {raw!r}") from exc


def _bool_env(env: Dict[str, str], key: str, default: bool) -> bool:
    raw = env.get(key)
    if raw is None or str(raw).strip() == "":
        return default
    return str(raw).strip().lower() in _TRUE_VALUES


def _float_env(env: Dict[str, str], key: str, default: float, *, minimum: float, maximum: float) -> float:
    raw = env.get(key)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        value = float(str(raw).strip())
    except ValueError as exc:
        raise ConfigError(f"{key} 必须是数字，当前值 {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{key}={value} 超出允许范围 {minimum}–{maximum}")
    return value


def load_settings(
    environ: Dict[str, str] | None = None,
    *,
    env_file: Optional[Path] = None,
) -> Settings:
    """Build *Settings* from ``os.environ`` plus the first ``.env`` found."""
    env = dict(os.environ if environ is None else environ)
    resolved_env_file = env_file if env_file is not None else find_env_file()
    if resolved_env_file is not None:
        for key, value in load_env_file(resolved_env_file, env).items():
            env.setdefault(key, value)

    host = (env.get("STUDIO_HOST") or DEFAULT_HOST).strip() or DEFAULT_HOST
    allow_lan = (env.get("STUDIO_ALLOW_LAN") or "").strip().lower() in {"1", "true", "yes", "on"}
    if not is_loopback_host(host) and not allow_lan:
        raise ConfigError(
            f"STUDIO_HOST={host} 非回环地址；Studio 默认只监听 127.0.0.1，"
            "如确需对外暴露请显式设置 STUDIO_ALLOW_LAN=1"
        )

    data_dir = Path(env.get("STUDIO_DATA_DIR") or default_data_dir()).expanduser().resolve()
    cli_bin = Path(env.get("CLI_BIN_PATH") or DEFAULT_CLI_BIN_PATH).expanduser()
    port = _int_env(env, "STUDIO_PORT", DEFAULT_PORT)
    if not 1 <= port <= 65535:
        raise ConfigError(f"STUDIO_PORT={port} 超出合法端口范围")
    ws_port_base = _int_env(env, "BOT_WS_PORT_BASE", DEFAULT_WS_PORT_BASE)
    ws_port_max = _int_env(env, "BOT_WS_PORT_MAX", DEFAULT_CLI_WS_PORT_MAX)
    if ws_port_max < ws_port_base:
        raise ConfigError("BOT_WS_PORT_MAX 必须不小于 BOT_WS_PORT_BASE")

    admin_token = (env.get("STUDIO_ADMIN_TOKEN") or "").strip()
    smp_servers = (env.get("BOT_SMP_SERVERS") or "").strip() or None
    raw_locale = (env.get("STUDIO_LOCALE") or "").strip()
    locale = normalize_locale(raw_locale) or FALLBACK_LOCALE

    mac_node_url = (env.get("MAC_NODE_URL") or DEFAULT_MAC_NODE_URL).strip() or DEFAULT_MAC_NODE_URL
    mac_node_enabled = _bool_env(env, "MAC_NODE_ENABLED", False)
    if mac_node_enabled and not is_loopback_http_url(mac_node_url):
        # 桥接器持有 Mac Node 令牌，指向非回环地址等于把令牌外送，一律拒绝启动。
        raise ConfigError(
            f"MAC_NODE_URL={mac_node_url} 非回环地址；Mac Node 桥只允许 "
            "http://127.0.0.1:18920 或 http://localhost:18920"
        )
    reasoner_base_url = (env.get("REASONER_BASE_URL") or "").strip()
    if reasoner_base_url:
        parts = urlsplit(reasoner_base_url)
        plain_remote = parts.scheme == "http" and not is_loopback_host(parts.hostname or "")
        if parts.scheme not in {"http", "https"} or not parts.netloc or plain_remote:
            raise ConfigError(
                f"REASONER_BASE_URL={reasoner_base_url} 无效：明文 http 只允许回环地址，"
                "远端推理服务必须使用 https"
            )

    settings = Settings(
        host=host,
        port=port,
        admin_token=admin_token,
        data_dir=data_dir,
        cli_bin_path=cli_bin,
        ws_port_base=ws_port_base,
        ws_port_max=ws_port_max,
        cli_smp_servers=smp_servers,
        default_locale=locale,
        env_file=resolved_env_file if resolved_env_file and resolved_env_file.is_file() else None,
        allow_lan=allow_lan,
        agent_enabled=_bool_env(env, "AGENT_ENABLED", True),
        needle_asset_dir=(env.get("NEEDLE3_ASSET_DIR") or "").strip() or None,
        needle_timeout_seconds=_float_env(
            env, "NEEDLE3_TIMEOUT_SECONDS", 2.0, minimum=0.05, maximum=120.0
        ),
        reasoner_enabled=_bool_env(env, "REASONER_ENABLED", False),
        reasoner_base_url=reasoner_base_url,
        reasoner_model=(env.get("REASONER_MODEL") or "").strip(),
        reasoner_api_key=(env.get("REASONER_API_KEY") or "").strip(),
        reasoner_timeout_seconds=_float_env(
            env, "REASONER_TIMEOUT_SECONDS", 20.0, minimum=0.5, maximum=300.0
        ),
        mac_node_enabled=mac_node_enabled,
        mac_node_url=mac_node_url,
        mac_node_token=(env.get("MAC_NODE_TOKEN") or "").strip(),
        mac_node_timeout_seconds=_float_env(
            env, "MAC_NODE_TIMEOUT_SECONDS", 8.0, minimum=0.2, maximum=120.0
        ),
        guest_enabled=_bool_env(env, "GUEST_ENABLED", True),
        guest_secret=(env.get("GUEST_SECRET") or "").strip(),
        guest_public_base=(env.get("GUEST_PUBLIC_BASE_URL") or "").strip(),
        guest_default_ttl_hours=_int_env(env, "GUEST_DEFAULT_TTL_HOURS", DEFAULT_GUEST_TTL_HOURS),
        agent_a2a_secret=(env.get("AGENT_A2A_SECRET") or "").strip(),
        meeting_base_url=(env.get("AGENT_MEETING_BASE_URL") or "").strip(),
    )
    if raw_locale and locale != raw_locale:
        settings.startup_warnings.append(
            f"STUDIO_LOCALE={raw_locale} 不在 18 语种支持列表内，已回退到 {locale}"
        )
    settings.startup_warnings.extend(settings.security_warnings())
    if not admin_token:
        settings.startup_warnings.append(
            "未设置 STUDIO_ADMIN_TOKEN：管理路由将全部返回 401，请运行 start_macos.sh 或在 .env 中写入令牌"
        )
    if not settings.cli_bin_path.exists():
        settings.startup_warnings.append(
            f"未找到 CLI 二进制 {settings.cli_bin_path}：Bot 生命周期操作将降级为离线模式，"
            "请运行 install_ubuntu22.sh / install_macos.sh 或设置 CLI_BIN_PATH"
        )
    if settings.guest_enabled and not settings.guest_secret:
        settings.startup_warnings.append(
            f"未设置 GUEST_SECRET：访客一次性链接将使用 {settings.guest_key_file} 中自动生成的密钥"
        )
    if settings.reasoner_enabled and not settings.reasoner_base_url:
        settings.startup_warnings.append(
            "REASONER_ENABLED=1 但未设置 REASONER_BASE_URL：话术生成将只用模板回退"
        )
    if settings.agent_enabled and not settings.mac_node_enabled:
        settings.startup_warnings.append(
            "MAC_NODE_ENABLED 未开启：日历落地（创建/改期/取消）只生成待确认卡片，不会写入 Mac 日历"
        )
    return settings
