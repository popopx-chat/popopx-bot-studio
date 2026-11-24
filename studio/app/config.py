"""Studio runtime configuration.

Loads ``.env`` style configuration, validates the loopback-only networking
invariant and reports files whose permissions are wider than 0600.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .i18n import FALLBACK_LOCALE, normalize_locale

DEFAULT_PORT = 8090
DEFAULT_HOST = "127.0.0.1"
DEFAULT_CLI_BIN_PATH = "/usr/local/bin/popopx-cli"
DEFAULT_WS_PORT_BASE = 5230
DEFAULT_CLI_WS_PORT_MAX = 5299
SECURE_FILE_MODE = 0o600
SECURE_DIR_MODE = 0o700

_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
_LOOPBACK_NAMES = {"localhost", "::1", "ip6-localhost", "ip6-loopback"}


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


def mode_of(path: Path) -> Optional[int]:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None


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
    startup_warnings: List[str] = field(default_factory=list)

    @property
    def state_file(self) -> Path:
        return self.data_dir / "studio.state.json"

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
        return self.bots_dir / bot_id / "cli-data"

    def wrapper_path(self, bot_id: str) -> Path:
        return self.bots_dir / bot_id / "run-cli.sh"

    def pid_file(self, bot_id: str) -> Path:
        return self.bots_dir / bot_id / "cli.pid"

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
        return permission_warnings(pairs)


def _int_env(env: Dict[str, str], key: str, default: int) -> int:
    raw = env.get(key)
    if raw is None or raw == "":
        return default
    try:
        return int(str(raw).strip())
    except ValueError as exc:
        raise ConfigError(f"{key} 必须是整数，当前值 {raw!r}") from exc


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
    return settings
